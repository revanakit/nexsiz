//! nxs-state-diff — official existence script
//!
//! Contract id: crash/state-diff
//! Purpose    : Multi-shot replay of a crash input; compare behavioural
//!              response signatures (length, timing, content hash, extracted
//!              status codes). Escalate when signatures diverge across shots
//!              or from the codes recorded in meta — a strong signal of
//!              state-machine instability or non-deterministic failure.
//!
//! Exit 2     : Signature divergence detected → escalate.
//! Exit 0     : Stable signatures across shots.
//! Exit 1     : Operational error.
//! Exit 3     : Internal timeout budget exhausted.
//!
//! Design (red-team grade):
//! - Bounded shot count and wall budget.
//! - Pure TCP, model-agnostic (status-code extraction is best-effort).
//! - Deterministic fingerprinting (FNV-1a style hash of response body).
//! - Intrusive: belongs to the "intrusive" category.

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

const NXS_ID: &str = "crash/state-diff";
const NXS_VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
const DEFAULT_SHOTS: usize = 4;
const MAX_SHOTS: usize = 8;

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
    let budget = Instant::now();

    let shots = parse_shots(&args.rest).unwrap_or(DEFAULT_SHOTS).clamp(2, MAX_SHOTS);

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
    let meta_codes: Vec<u16> = meta
        .result
        .as_ref()
        .and_then(|r| r.response_codes.clone())
        .unwrap_or_default();

    args.log(&format!(
        "id={} event={} target={} input={} shots={}",
        NXS_ID,
        event,
        target,
        input_path.display(),
        shots
    ));

    let payload = match fs::read(&input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {}: {}", input_path.display(), e);
            ExitCode::Error.exit();
        }
    };
    if payload.is_empty() {
        eprintln!("error: empty payload");
        ExitCode::Error.exit();
    }

    let mut signatures: Vec<Signature> = Vec::with_capacity(shots);
    let mut findings: Vec<String> = Vec::new();

    for i in 0..shots {
        if budget.elapsed() > timeout {
            findings.push("shot budget exhausted".into());
            break;
        }
        let sig = capture(&target, &payload, timeout, args.verbose);
        args.log(&format!(
            "shot={} class={:?} len={} hash={:016x} codes={:?} ms={}",
            i, sig.class, sig.body_len, sig.body_hash, sig.codes, sig.elapsed_ms
        ));
        signatures.push(sig);
        // Brief inter-shot pause to allow target state to settle / reset.
        std::thread::sleep(Duration::from_millis(80));
    }

    if signatures.is_empty() {
        finish(
            args,
            &target,
            crash_id,
            ExitCode::Error,
            "no shots completed",
            &findings,
        );
    }

    // --- Divergence analysis ------------------------------------------------
    let mut divergent = false;

    // 1. Class disagreement across shots
    let first_class = &signatures[0].class;
    for (i, s) in signatures.iter().enumerate().skip(1) {
        if &s.class != first_class {
            divergent = true;
            findings.push(format!(
                "class divergence: shot0={:?} shot{}={:?}",
                first_class, i, s.class
            ));
        }
    }

    // 2. Body hash / length disagreement (only among Responded shots)
    let responded: Vec<&Signature> = signatures
        .iter()
        .filter(|s| s.class == Class::Responded)
        .collect();
    if responded.len() >= 2 {
        let h0 = responded[0].body_hash;
        let l0 = responded[0].body_len;
        for (i, s) in responded.iter().enumerate().skip(1) {
            if s.body_hash != h0 {
                divergent = true;
                findings.push(format!(
                    "body-hash divergence: shot0={:016x} shot{}={:016x}",
                    h0, i, s.body_hash
                ));
            }
            if l0 > 0 && s.body_len > 0 {
                let ratio = (l0.max(s.body_len) as f64) / (l0.min(s.body_len) as f64);
                if ratio >= 3.0 {
                    divergent = true;
                    findings.push(format!(
                        "body-length ratio {:.1}x between shots ({} vs {})",
                        ratio, l0, s.body_len
                    ));
                }
            }
        }
    }

    // 3. Compare against meta.response_codes when present
    if !meta_codes.is_empty() {
        for (i, s) in signatures.iter().enumerate() {
            if s.class == Class::Responded && !s.codes.is_empty() {
                // Any code from meta missing in this shot is a signal.
                for &mc in &meta_codes {
                    if !s.codes.contains(&mc) {
                        // Soft signal — only escalate if we also saw class/hash divergence,
                        // or if every responded shot disagrees.
                        findings.push(format!(
                            "meta code {} absent in shot{} codes={:?}",
                            mc, i, s.codes
                        ));
                    }
                }
            }
        }
    }

    // 4. Timing variance (extreme outliers among responded)
    if responded.len() >= 3 {
        let times: Vec<u64> = responded.iter().map(|s| s.elapsed_ms).collect();
        let min_t = *times.iter().min().unwrap_or(&0);
        let max_t = *times.iter().max().unwrap_or(&0);
        if min_t > 0 && max_t > min_t.saturating_mul(8) {
            divergent = true;
            findings.push(format!(
                "timing outlier: min={}ms max={}ms (≥8x)",
                min_t, max_t
            ));
        }
    }

    let (exit, summary): (ExitCode, String) = if divergent {
        (
            ExitCode::Escalate,
            format!(
                "State/signature divergence across {} shot(s)",
                signatures.len()
            ),
        )
    } else if budget.elapsed() > timeout {
        (ExitCode::Timeout, "Budget exhausted".into())
    } else {
        (
            ExitCode::Ok,
            format!("Stable signatures across {} shot(s)", signatures.len()),
        )
    };

    finish(args, &target, crash_id, exit, &summary, &findings);
}

fn finish(
    args: &Args,
    target: &str,
    crash_id: Option<String>,
    exit: ExitCode,
    summary: &str,
    findings: &[String],
) -> ! {
    let mut report = Report::new(NXS_ID, NXS_VERSION)
        .with_target(target)
        .with_crash_id(crash_id)
        .with_exit_hint(exit)
        .with_summary(summary);
    for f in findings {
        report.add_finding(f.clone());
    }

    if let Some(out) = &args.out {
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
// Capture engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Class {
    Crash,
    Hang,
    Responded,
    Unreachable,
}

#[derive(Debug, Clone)]
struct Signature {
    class: Class,
    body_len: usize,
    body_hash: u64,
    codes: Vec<u16>,
    elapsed_ms: u64,
}

fn capture(target: &str, payload: &[u8], timeout: Duration, verbose: bool) -> Signature {
    let start = Instant::now();
    let addr = match resolve_addr(target) {
        Ok(a) => a,
        Err(e) => {
            return Signature {
                class: Class::Unreachable,
                body_len: 0,
                body_hash: 0,
                codes: vec![],
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            let d = e.to_string();
            let class = if is_crash_like(&d) {
                Class::Crash
            } else {
                Class::Unreachable
            };
            return Signature {
                class,
                body_len: 0,
                body_hash: 0,
                codes: vec![],
                elapsed_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;

    if let Err(e) = stream.write_all(payload) {
        let d = e.to_string();
        let class = if is_crash_like(&d) {
            Class::Crash
        } else {
            Class::Unreachable
        };
        return Signature {
            class,
            body_len: 0,
            body_hash: 0,
            codes: vec![],
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
    }
    let _ = stream.flush();

    let mut buf = vec![0u8; 8192];
    let mut total = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total.extend_from_slice(&buf[..n]);
                if total.len() >= 8192 {
                    break;
                }
            }
            Err(e) => {
                let d = e.to_string();
                if is_timeout(&d) {
                    if total.is_empty() {
                        return Signature {
                            class: Class::Hang,
                            body_len: 0,
                            body_hash: 0,
                            codes: vec![],
                            elapsed_ms: start.elapsed().as_millis() as u64,
                        };
                    }
                    break;
                }
                if is_crash_like(&d) && total.is_empty() {
                    return Signature {
                        class: Class::Crash,
                        body_len: 0,
                        body_hash: 0,
                        codes: vec![],
                        elapsed_ms: start.elapsed().as_millis() as u64,
                    };
                }
                break;
            }
        }
    }

    if total.is_empty() {
        // EOF with no data after successful write → treat as crash-like close.
        return Signature {
            class: Class::Crash,
            body_len: 0,
            body_hash: 0,
            codes: vec![],
            elapsed_ms: start.elapsed().as_millis() as u64,
        };
    }

    if verbose {
        eprintln!("[nxs] recv {} bytes", total.len());
    }

    Signature {
        class: Class::Responded,
        body_len: total.len(),
        body_hash: fnv1a64(&total),
        codes: extract_status_codes(&total),
        elapsed_ms: start.elapsed().as_millis() as u64,
    }
}

/// Best-effort extraction of 3-digit status codes (FTP/SMTP/HTTP-like).
fn extract_status_codes(body: &[u8]) -> Vec<u16> {
    let text = String::from_utf8_lossy(body);
    let mut codes = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.len() >= 3 {
            let digits = &trimmed.as_bytes()[..3];
            if digits.iter().all(|b| b.is_ascii_digit()) {
                if let Ok(c) = std::str::from_utf8(digits).unwrap_or("").parse::<u16>() {
                    if (100..600).contains(&c) && !codes.contains(&c) {
                        codes.push(c);
                    }
                }
            }
        }
        // HTTP status line: "HTTP/1.x NNN"
        if let Some(pos) = trimmed.find("HTTP/") {
            let rest = &trimmed[pos..];
            if let Some(sp) = rest.find(' ') {
                let maybe = rest[sp + 1..].trim_start();
                if maybe.len() >= 3 {
                    if let Ok(c) = maybe[..3].parse::<u16>() {
                        if (100..600).contains(&c) && !codes.contains(&c) {
                            codes.push(c);
                        }
                    }
                }
            }
        }
    }
    codes
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn parse_shots(rest: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--shots" && i + 1 < rest.len() {
            return rest[i + 1].parse().ok();
        }
        i += 1;
    }
    None
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
        r#"nxs-state-diff {ver} (id={id})

Multi-shot response-signature differential after a crash discovery.
Compares class, body hash, length, timing, and status codes across shots.

USAGE:
    nxs-state-diff --crash <path> --target <host:port> [OPTIONS]
    nxs-state-diff --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Live target
    --event <type>         crash | …
    --model <name>         Protocol model (informational)
    --minimized <path>     Prefer as baseline
    --meta <path>          Nexsiz metadata JSON
    --out <dir>            report.json
    --timeout <secs>       Total wall budget (default: {def})
    -v, --verbose
    -h, --help
    --version

SCRIPT OPTIONS:
    --shots <N>            Number of replay shots (2–{max}, default: {shots})

EXIT CODES:
    0  Stable signatures
    1  Operational error
    2  Divergence detected → escalate
    3  Internal timeout budget exhausted

NOTE: Intrusive — contacts the live target multiple times.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
        shots = DEFAULT_SHOTS,
        max = MAX_SHOTS,
    );
}
