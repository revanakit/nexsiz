//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::server
//!
//! Unix domain socket RPC server (+ oracle-mode reverse-RPC loop).

use crate::scripting::handler::{HandleOutcome, RpcContext};
use crate::scripting::json::{self, JsonValue};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Background RPC server. Owns the listen socket path.
pub struct RpcServer {
    path: String,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl RpcServer {
    pub fn start(path: &str, ctx: Arc<RpcContext>, stop: Arc<AtomicBool>) -> Result<Self, String> {
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

        Ok(Self {
            path: path_owned,
            stop,
            join: Some(join),
        })
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

fn accept_loop(listener: UnixListener, ctx: Arc<RpcContext>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
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

fn handle_client(stream: UnixStream, ctx: Arc<RpcContext>, stop: Arc<AtomicBool>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let reader_stream = match stream.try_clone() {
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
fn run_oracle_mode<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    ctx: &RpcContext,
    stop: &AtomicBool,
) {
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
