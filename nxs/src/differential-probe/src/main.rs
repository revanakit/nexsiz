//! nxs-differential-probe — official existence script
//!
//! Contract id: crash/differential-probe
//! Purpose    : After a crash is discovered, run a *bounded* set of controlled
//!              variants against the live target and compare behavioural
//!              signatures. Escalate (exit 2) when a variant reveals a new
//!              anomaly (different crash class, hang, or divergent response).
//!
//! Exit 2     : Differential anomaly detected → escalate.
//! Exit 0     : Baseline and variants behave consistently (or target down).
//! Exit 1     : Operational error.
//! Exit 3     : Internal timeout budget exhausted.
//!
//! Design (red-team grade):
//! - Hard cap on number of probes and total wall time.
//! - Pure TCP, model-agnostic.
//! - Variants are deliberate and documented (no random mutation storm).
//! - Intrusive: belongs to the "intrusive" category, not "safe".

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

const NXS_ID: &str = "crash/differential-probe";
const NXS_VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 12;
const MAX_PROBES: usize = 6;

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
        NXS_ID, event, target, input_path.display()
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

    // --- Baseline -----------------------------------------------------------
    let baseline = probe(&target, &payload, timeout, args.verbose);
    args.log(&format!("baseline={:?}", baseline.class));

    if budget.elapsed() > timeout {
        finish(args, &target, crash_id, ExitCode::Timeout, "budget exhausted before variants", &[]);
    }

    // --- Controlled variants ------------------------------------------------
    let variants = build_variants(&payload);
    let mut findings: Vec<String> = Vec::new();
    let mut anomaly = false;

    for (name, var) in variants.iter().take(MAX_PROBES) {
        if budget.elapsed() > timeout {
            findings.push("probe budget exhausted".into());
            break;
        }
        let outcome = probe(&target, var, timeout, args.verbose);
        args.log(&format!("variant={} outcome={:?}", name, outcome.class));

        if is_anomaly(&baseline, &outcome) {
            anomaly = true;
            let detail = format!(
                "variant '{}': baseline={:?} → variant={:?} ({})",
                name, baseline.class, outcome.class, outcome.detail
            );
            findings.push(detail);
        }
    }

    // Explicit String keeps both arms consistent under rustc type inference.
    let (exit, summary): (ExitCode, String) = if anomaly {
        (
            ExitCode::Escalate,
            format!("Differential anomaly on {} variant(s)", findings.len()),
        )
    } else {
        (
            ExitCode::Ok,
            "No differential anomaly relative to baseline".into(),
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
// Probe engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Class {
    Crash,
    Hang,
    Responded,
    Unreachable,
}

#[derive(Debug)]
struct ProbeResult {
    class: Class,
    detail: String,
    response_len: usize,
}

fn probe(target: &str, payload: &[u8], timeout: Duration, verbose: bool) -> ProbeResult {
    let addr = match resolve_addr(target) {
        Ok(a) => a,
        Err(e) => {
            return ProbeResult {
                class: Class::Unreachable,
                detail: e,
                response_len: 0,
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
            return ProbeResult {
                class,
                detail: d,
                response_len: 0,
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
        return ProbeResult {
            class,
            detail: d,
            response_len: 0,
        };
    }
    let _ = stream.flush();

    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(0) => ProbeResult {
            class: Class::Crash,
            detail: "EOF after payload".into(),
            response_len: 0,
        },
        Ok(n) => {
            if verbose {
                eprintln!("[nxs] recv {} bytes", n);
            }
            ProbeResult {
                class: Class::Responded,
                detail: format!("recv {}", n),
                response_len: n,
            }
        }
        Err(e) => {
            let d = e.to_string();
            if is_timeout(&d) {
                ProbeResult {
                    class: Class::Hang,
                    detail: format!("timeout after send ({:?})", timeout),
                    response_len: 0,
                }
            } else if is_crash_like(&d) {
                ProbeResult {
                    class: Class::Crash,
                    detail: d,
                    response_len: 0,
                }
            } else {
                ProbeResult {
                    class: Class::Unreachable,
                    detail: d,
                    response_len: 0,
                }
            }
        }
    }
}

fn is_anomaly(base: &ProbeResult, other: &ProbeResult) -> bool {
    // Same class → not interesting for differential purposes.
    if base.class == other.class {
        // Responded with very different size can still be a signal.
        if base.class == Class::Responded {
            let a = base.response_len;
            let b = other.response_len;
            if a > 0 && b > 0 {
                let ratio = (a.max(b) as f64) / (a.min(b) as f64);
                return ratio >= 4.0;
            }
        }
        return false;
    }
    // Baseline was crash/hang and variant responds cleanly → possible state recovery,
    // still useful but we treat class change as anomaly.
    // Baseline responded and variant crashes/hangs → clear anomaly.
    matches!(
        (&base.class, &other.class),
        (Class::Responded, Class::Crash)
            | (Class::Responded, Class::Hang)
            | (Class::Crash, Class::Hang)
            | (Class::Hang, Class::Crash)
            | (Class::Crash, Class::Responded)
            | (Class::Hang, Class::Responded)
    )
}

fn build_variants(payload: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    let n = payload.len();

    // 1. Truncate to 50%
    if n > 2 {
        v.push(("truncate_half".into(), payload[..n / 2].to_vec()));
    }
    // 2. Truncate to 1 byte
    if n > 1 {
        v.push(("truncate_1".into(), payload[..1].to_vec()));
    }
    // 3. Append null byte
    {
        let mut p = payload.to_vec();
        p.push(0);
        v.push(("append_null".into(), p));
    }
    // 4. Prepend null byte
    {
        let mut p = vec![0u8];
        p.extend_from_slice(payload);
        v.push(("prepend_null".into(), p));
    }
    // 5. Flip first length-like byte if present (simple heuristic)
    if n >= 4 {
        let mut p = payload.to_vec();
        p[0] = p[0].wrapping_add(0x80);
        v.push(("flip_high_bit_0".into(), p));
    }
    // 6. Double the payload (length inflation)
    if n > 0 && n < 4096 {
        let mut p = payload.to_vec();
        p.extend_from_slice(payload);
        v.push(("double".into(), p));
    }

    v
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
        r#"nxs-differential-probe {ver} (id={id})

Bounded differential behavioural probe after a crash discovery.

USAGE:
    nxs-differential-probe --crash <path> --target <host:port> [OPTIONS]
    nxs-differential-probe --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Baseline input
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

EXIT CODES:
    0  No differential anomaly
    1  Operational error
    2  Anomaly detected → escalate
    3  Internal timeout budget exhausted

NOTE: Intrusive — contacts the live target multiple times. Use category
      "intrusive" or explicit id; not part of the default safe set.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
    );
}
