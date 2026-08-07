//! nxs-auto-repro — official existence script
//!
//! Contract id: crash/auto-repro
//! Purpose    : Deterministic replay of a discovered crash / hang input
//!              against the live target. Prefers the minimised variant when
//!              present. Confirms behavioural failure (connection reset,
//!              refused, premature close, timeout under load).
//!
//! Exit 2     : Crash / hang is reproducible → escalate.
//! Exit 0     : Input no longer triggers the observed failure.
//! Exit 1     : Operational (file missing, unreachable, bad args).
//! Exit 3     : Internal timeout exhausted.
//!
//! Design notes (red-team grade):
//! - Pure TCP path (no higher-level protocol interpretation) so it stays
//!   model-agnostic and fast.
//! - Short, bounded timeouts; never hangs the operator.
//! - Writes report.json when --out is supplied.
//! - Zero side effects beyond the single replay connection.

use nxs_lib::{
    args::Args,
    exit::ExitCode,
    meta::{self, Meta},
    report::Report,
};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const NXS_ID: &str = "crash/auto-repro";
const NXS_VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 8;

fn main() {
    let args = Args::parse();

    if args.help {
        print_help();
        ExitCode::Ok.exit();
    }
    if args.version {
        println!("{} {} (id={})", env!("CARGO_PKG_NAME"), NXS_VERSION, NXS_ID);
        ExitCode::Ok.exit();
    }

    if let Err(e) = args.validate_required() {
        eprintln!("error: {}", e);
        ExitCode::Error.exit();
    }

    let meta = meta::load_or_exit(&args.meta);
    run(&args, &meta);
}

fn run(args: &Args, meta: &Meta) {
    let timeout_secs = args.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS);
    let timeout = Duration::from_secs(timeout_secs);

    // Resolve inputs (prefer minimised).
    let input_path = match meta.effective_input_path(&args.crash, &args.minimized) {
        Some(p) => p,
        None => {
            eprintln!("error: no crash / minimised path resolved");
            ExitCode::Error.exit();
        }
    };

    let target = match meta.effective_target(&args.target) {
        Some(t) => t,
        None => {
            eprintln!("error: no target resolved");
            ExitCode::Error.exit();
        }
    };

    let event = meta.effective_event(&args.event);
    let crash_id = meta.crash_id().map(str::to_string);

    args.log(&format!(
        "id={} event={} target={} input={}",
        NXS_ID,
        event,
        target,
        input_path.display()
    ));

    let payload = match fs::read(&input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {}: {}", input_path.display(), e);
            ExitCode::Error.exit();
        }
    };
    args.log(&format!("payload_len={}", payload.len()));

    // --- Behavioural replay -------------------------------------------------
    let start = Instant::now();
    let outcome = replay(&target, &payload, timeout, args.verbose);
    let elapsed = start.elapsed();

    args.log(&format!(
        "outcome={:?} elapsed_ms={}",
        outcome,
        elapsed.as_millis()
    ));

    // --- Report -------------------------------------------------------------
    let mut report = Report::new(NXS_ID, NXS_VERSION)
        .with_target(&target)
        .with_crash_id(crash_id.clone());

    let exit = match outcome {
        ReplayOutcome::ConfirmedCrash { detail } => {
            report = report
                .with_exit_hint(ExitCode::Escalate)
                .with_summary(format!("Repro confirmed: {}", detail));
            report.add_finding(detail);
            ExitCode::Escalate
        }
        ReplayOutcome::ConfirmedHang { detail } => {
            report = report
                .with_exit_hint(ExitCode::Escalate)
                .with_summary(format!("Hang confirmed: {}", detail));
            report.add_finding(detail);
            ExitCode::Escalate
        }
        ReplayOutcome::Clean => {
            report = report
                .with_exit_hint(ExitCode::Ok)
                .with_summary("Input no longer triggers observable failure");
            ExitCode::Ok
        }
        ReplayOutcome::Unreachable { detail } => {
            report = report
                .with_exit_hint(ExitCode::Error)
                .with_summary(format!("Target unreachable: {}", detail));
            ExitCode::Error
        }
        ReplayOutcome::Timeout => {
            report = report
                .with_exit_hint(ExitCode::Timeout)
                .with_summary("Internal timeout exhausted during replay");
            ExitCode::Timeout
        }
    };

    if let Some(out) = &args.out {
        let repro_dir = out.join("repro");
        if let Err(e) = fs::create_dir_all(&repro_dir) {
            eprintln!("warn: mkdir {}: {}", repro_dir.display(), e);
        } else {
            let dest = repro_dir.join("input.bin");
            if fs::copy(&input_path, &dest).is_ok() {
                report.add_artifact("repro/input.bin");
            }
        }

        match report.write(out) {
            Ok(p) => args.log(&format!("report written {}", p.display())),
            Err(e) => eprintln!("warn: {}", e),
        }
    }

    if let Ok(line) = serde_json::to_string(&report) {
        println!("{}", line);
    }

    exit.exit();
}

// ---------------------------------------------------------------------------
// Core replay engine
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ReplayOutcome {
    ConfirmedCrash { detail: String },
    ConfirmedHang { detail: String },
    Clean,
    Unreachable { detail: String },
    Timeout,
}

fn replay(target: &str, payload: &[u8], timeout: Duration, verbose: bool) -> ReplayOutcome {
    let stream = match TcpStream::connect_timeout(
        &match target.parse() {
            Ok(a) => a,
            Err(_) => match resolve_addr(target) {
                Ok(a) => a,
                Err(e) => return ReplayOutcome::Unreachable { detail: e },
            },
        },
        timeout,
    ) {
        Ok(s) => s,
        Err(e) => {
            let detail = e.to_string();
            if is_crash_like(&detail) {
                return ReplayOutcome::ConfirmedCrash { detail };
            }
            return ReplayOutcome::Unreachable { detail };
        }
    };

    if let Err(e) = stream.set_read_timeout(Some(timeout)) {
        if verbose {
            eprintln!("[nxs] set_read_timeout: {}", e);
        }
    }
    if let Err(e) = stream.set_write_timeout(Some(timeout)) {
        if verbose {
            eprintln!("[nxs] set_write_timeout: {}", e);
        }
    }

    let mut stream = stream;

    if let Err(e) = stream.write_all(payload) {
        let detail = e.to_string();
        if is_crash_like(&detail) {
            return ReplayOutcome::ConfirmedCrash { detail };
        }
        return ReplayOutcome::Unreachable { detail };
    }
    let _ = stream.flush();

    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(0) => ReplayOutcome::ConfirmedCrash {
            detail: "connection closed by peer after payload (EOF)".into(),
        },
        Ok(n) => {
            if verbose {
                eprintln!("[nxs] received {} bytes", n);
            }
            ReplayOutcome::Clean
        }
        Err(e) => {
            let detail = e.to_string();
            if is_timeout(&detail) {
                ReplayOutcome::ConfirmedHang {
                    detail: format!("no response within {:?} after payload", timeout),
                }
            } else if is_crash_like(&detail) {
                ReplayOutcome::ConfirmedCrash { detail }
            } else {
                ReplayOutcome::Unreachable { detail }
            }
        }
    }
}

fn resolve_addr(target: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    target
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {}", target))
}

fn is_crash_like(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("connection reset")
        || m.contains("broken pipe")
        || m.contains("connection refused")
        || m.contains("forcibly closed")
        || m.contains("connection aborted")
}

fn is_timeout(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("timed out") || m.contains("timeout") || m.contains("would block")
}

fn print_help() {
    eprintln!(
        r#"nxs-auto-repro {ver} (id={id})

Deterministic replay of a crash / hang input against a live target.
Prefers the minimised variant when available.

USAGE:
    nxs-auto-repro --crash <path> --target <host:port> [OPTIONS]
    nxs-auto-repro --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Live target
    --event <type>         crash | hang | … (default: crash)
    --model <name>         Protocol model (informational)
    --minimized <path>     Prefer this over --crash
    --meta <path>          Nexsiz metadata JSON (or - for stdin)
    --out <dir>            Write report.json + repro artefacts
    --timeout <secs>       Internal timeout (default: {def})
    -v, --verbose          Human log on stderr
    -h, --help             This help
    --version              Version + stable id

EXIT CODES:
    0  Input no longer triggers failure
    1  Operational error
    2  Crash / hang confirmed → escalate
    3  Internal timeout
    4  Interrupted
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
    );
}
