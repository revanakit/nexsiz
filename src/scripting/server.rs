//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::server
//!
//! Description
//! -----------
//! Unix-domain socket RPC server that exposes the campaign-control surface
//! defined by handler.rs. Accepts concurrent client connections, routes each
//! line-delimited JSON request to RpcContext::handle_line, and implements the
//! special reverse-RPC loop used when a Python client registers as a live
//! oracle.
//!
//! Core responsibilities
//! ---------------------
//! - Bind a non-blocking UnixListener on the configured path (default or
//!   NEXSIZ_RPC_SOCK / --rpc-sock).
//! - Spawn a dedicated accept thread that hands each accepted stream to a
//!   short-lived client-handler thread.
//! - Forward ordinary requests to the handler and write the JSON response
//!   back to the client.
//! - Detect the register_oracle command and transition the connection into
//!   oracle mode (run_oracle_mode), where the engine pushes is_interesting
//!   requests and the Python side answers them.
//! - Clean up the socket path on Drop and honour the shared stop AtomicBool.
//!
//! Platform constraints
//! --------------------
//! - Full implementation is cfg(unix) only. On non-Unix platforms
//!   RpcServer::start returns an explicit error string; the rest of the
//!   fuzzer remains fully usable without RPC.
//! - This is intentional: Unix domain sockets are the operator feature for
//!   Linux/macOS campaign steering. Windows builds stay lean.
//!
//! Concurrency model
//! -----------------
//! - One long-lived accept thread ("nexsiz-rpc").
//! - One short-lived client thread per accepted connection
//!   ("nexsiz-rpc-client").
//! - All shared state lives inside the Arc<RpcContext> passed from the Engine.
//! - Cooperative shutdown is driven by the same AtomicBool used by workers
//!   and the Engine; the accept loop polls it every 50 ms.
//!
//! Oracle-mode reverse-RPC
//! -----------------------
//! - After a successful register_oracle the connection leaves the normal
//!   request/response path and enters a tight poll loop:
//!     1. Drain pending OracleRequest messages from the bridge channel and
//!        write them to the Python client.
//!     2. Read Python responses (50 ms read timeout) and deliver them back
//!        to the OracleBridge via deliver_response.
//! - On disconnect, timeout, or stop flag the mode is exited and the bridge
//!   is unregistered, restoring the default oracle.
//!
//! Lifecycle & cleanup
//! -------------------
//! - Drop implementation sets the stop flag, removes the socket file, and
//!   joins the accept thread.
//! - Client threads exit cleanly on EOF, write error, or stop signal.
//! - No global state is left behind after the server is dropped.
//!
//! Design notes
//! ------------
//! - Non-blocking accept + short sleeps keep the accept loop responsive
//!   without busy-waiting.
//! - Read/write timeouts on client streams prevent a single stalled Python
//!   process from blocking the whole RPC surface.
//! - The server never owns campaign logic; it is a pure transport + mode
//!   switcher that delegates everything to RpcContext and the bridges.
//!
//! See Also
//! --------
//! - handler.rs         : command dispatch and RpcContext
//! - oracle_bridge.rs   : request/response channel used by oracle mode
//! - engine.rs          : owns the RpcServer instance for the campaign lifetime

use crate::scripting::handler::RpcContext;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

/// Background RPC server. Owns the listen socket path (Unix only).
pub struct RpcServer {
    path: String,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl RpcServer {
    /// Start the Unix-domain RPC listener. Non-Unix → Err with clear message.
    pub fn start(path: &str, ctx: Arc<RpcContext>, stop: Arc<AtomicBool>) -> Result<Self, String> {
        #[cfg(unix)]
        {
            return start_unix(path, ctx, stop);
        }
        #[cfg(not(unix))]
        {
            let _ = (path, ctx, stop);
            Err("RPC campaign control requires Unix domain sockets (not available on this platform)".into())
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_file(&self.path);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

// ─── Unix implementation ─────────────────────────────────────────────────────

#[cfg(unix)]
fn start_unix(path: &str, ctx: Arc<RpcContext>, stop: Arc<AtomicBool>) -> Result<RpcServer, String> {
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    let _ = std::fs::remove_file(path);
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(path).map_err(|e| format!("bind {}: {}", path, e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {}", e))?;

    let path_owned = path.to_string();
    let stop_flag = Arc::clone(&stop);

    let join = thread::Builder::new()
        .name("nexsiz-rpc".into())
        .spawn(move || {
            accept_loop(listener, ctx, stop_flag);
        })
        .map_err(|e| format!("spawn rpc thread: {}", e))?;

    Ok(RpcServer {
        path: path_owned,
        stop,
        join: Some(join),
    })
}

#[cfg(unix)]
fn accept_loop(
    listener: std::os::unix::net::UnixListener,
    ctx: Arc<RpcContext>,
    stop: Arc<AtomicBool>,
) {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let stream: UnixStream = stream;
                let ctx = Arc::clone(&ctx);
                let stop = Arc::clone(&stop);
                let _ = thread::Builder::new()
                    .name("nexsiz-rpc-client".into())
                    .spawn(move || handle_client(stream, ctx, stop));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(unix)]
fn handle_client(
    stream: std::os::unix::net::UnixStream,
    ctx: Arc<RpcContext>,
    stop: Arc<AtomicBool>,
) {
    use crate::scripting::handler::HandleOutcome;
    use crate::scripting::json::{self, JsonValue};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let reader_stream: UnixStream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;

    let mut line = String::new();
    while !stop.load(Ordering::Relaxed) {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match ctx.handle_line(trimmed) {
                    HandleOutcome::Response(response) => {
                        if writer.write_all(response.as_bytes()).is_err() {
                            break;
                        }
                        let _ = writer.flush();
                    }
                    HandleOutcome::EnterOracleMode => {
                        let ack = {
                            let mut m = std::collections::HashMap::new();
                            m.insert("ok".into(), JsonValue::Bool(true));
                            m.insert(
                                "result".into(),
                                json::obj(vec![("registered", json::b(true))]),
                            );
                            json::stringify(&JsonValue::Object(m)) + "\n"
                        };
                        if writer.write_all(ack.as_bytes()).is_err() {
                            break;
                        }
                        let _ = writer.flush();

                        // Short read timeout so we can interleave channel polls
                        let _ = reader.get_ref().set_read_timeout(Some(Duration::from_millis(50)));
                        let _ = writer.set_read_timeout(Some(Duration::from_millis(50)));

                        run_oracle_mode(&mut reader, &mut writer, &ctx, &stop);
                        break;
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

/// Reverse-RPC loop: engine pushes is_interesting requests; Python answers.
#[cfg(unix)]
fn run_oracle_mode<R: std::io::BufRead, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    ctx: &RpcContext,
    stop: &AtomicBool,
) {
    use crate::scripting::json;
    use std::time::Duration;

    let rx = ctx.oracle_bridge.register();
    *ctx.oracle_name.lock().unwrap() = "python".into();

    let mut line = String::new();
    while !stop.load(Ordering::Relaxed) && ctx.oracle_bridge.is_active() {
        // 1. Forward pending engine requests to Python
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(req) => {
                if writer.write_all(req.line.as_bytes()).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // 2. Read Python responses (50ms timeout on the stream)
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(resp) = json::parse(trimmed) {
                    if let Some(id) = resp.get_u64("id") {
                        let interesting = resp
                            .get("result")
                            .and_then(|r| r.get("interesting"))
                            .and_then(|v| v.as_bool())
                            .or_else(|| resp.get("result").and_then(|v| v.as_bool()))
                            .unwrap_or(false);
                        ctx.oracle_bridge.deliver_response(id, interesting);
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // no response yet
            }
            Err(_) => break,
        }
    }

    ctx.oracle_bridge.unregister();
    *ctx.oracle_name.lock().unwrap() = "default".into();
}
