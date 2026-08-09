//! nxs-timeout-analyzer — official nexsiz existence script
//!
//! Contract id: hang/timeout-analyzer
//! Purpose    : Characterise a hang input with several timed probes.
//!              Distinguishes soft/network timeout from a hard service hang
//!              (no response across repeated attempts).
//!
//! Exit 2     : Hard hang confirmed → escalate.
//! Exit 0     : Soft timeout / intermittent / target recovered.
//! Exit 1     : Operational error.
//! Exit 3     : Analyzer budget exhausted without a clear classification.
//!
//! Design (red-team grade):
//! - Fixed probe count and per-probe timeout; never unbounded.
//! - Pure TCP; no protocol parsing required.
//! - Writes structured latency samples into report findings.

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

const NXS_ID: &str = "hang/timeout-analyzer";
const NXS_VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
const PROBES: usize = 4;
const PER_PROBE_SECS: u64 = 3;

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
    let wall = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));
    let per = Duration::from_secs(PER_PROBE_SECS);
    let start = Instant::now();

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

    let mut samples: Vec<Sample> = Vec::with_capacity(PROBES);
    for i in 0..PROBES {
        if start.elapsed() > wall {
            break;
        }
        let s = one_probe(&target, &payload, per, args.verbose);
        args.log(&format!(
            "probe[{}] class={:?} ms={}",
            i,
            s.class,
            s.elapsed_ms
        ));
        samples.push(s);
        // brief inter-probe gap
        std::thread::sleep(Duration::from_millis(50));
    }

    if samples.is_empty() {
        finish(
            args,
            &target,
            crash_id,
            ExitCode::Timeout,
            "no probes completed within budget",
            &[],
        );
    }

    let classification = classify(&samples);
    let mut findings: Vec<String> = samples
        .iter()
        .enumerate()
        .map(|(i, s)| {
            format!(
                "probe[{}] {:?} {}ms — {}",
                i, s.class, s.elapsed_ms, s.detail
            )
        })
        .collect();
    findings.push(format!("classification={:?}", classification));

    // Explicit String annotation prevents rustc from inferring unsized `str`
    // when every arm uses `.into()` without further type context.
    let (exit, summary): (ExitCode, String) = match classification {
        Class::HardHang => (
            ExitCode::Escalate,
            "Hard hang confirmed across repeated probes".into(),
        ),
        Class::SoftTimeout => (
            ExitCode::Ok,
            "Soft / intermittent timeout — not a hard hang".into(),
        ),
        Class::Recovered => (
            ExitCode::Ok,
            "Target responded on one or more probes — recovered".into(),
        ),
        Class::Unreachable => (
            ExitCode::Error,
            "Target unreachable for all probes".into(),
        ),
        Class::Mixed => (
            ExitCode::Ok,
            "Mixed outcomes — inconclusive for hard hang".into(),
        ),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    HardHang,
    SoftTimeout,
    Recovered,
    Unreachable,
    Mixed,
}

#[derive(Debug)]
struct Sample {
    class: SampleClass,
    elapsed_ms: u128,
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SampleClass {
    Hang,
    Crash,
    Responded,
    Unreachable,
}

fn one_probe(target: &str, payload: &[u8], timeout: Duration, verbose: bool) -> Sample {
    let t0 = Instant::now();
    let addr = match resolve_addr(target) {
        Ok(a) => a,
        Err(e) => {
            return Sample {
                class: SampleClass::Unreachable,
                elapsed_ms: t0.elapsed().as_millis(),
                detail: e,
            };
        }
    };

    let stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            let d = e.to_string();
            let class = if is_crash_like(&d) {
                SampleClass::Crash
            } else if is_timeout(&d) {
                SampleClass::Hang
            } else {
                SampleClass::Unreachable
            };
            return Sample {
                class,
                elapsed_ms: t0.elapsed().as_millis(),
                detail: d,
            };
        }
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;

    if let Err(e) = stream.write_all(payload) {
        let d = e.to_string();
        let class = if is_crash_like(&d) {
            SampleClass::Crash
        } else {
            SampleClass::Unreachable
        };
        return Sample {
            class,
            elapsed_ms: t0.elapsed().as_millis(),
            detail: d,
        };
    }
    let _ = stream.flush();

    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(0) => Sample {
            class: SampleClass::Crash,
            elapsed_ms: t0.elapsed().as_millis(),
            detail: "EOF".into(),
        },
        Ok(n) => {
            if verbose {
                eprintln!("[nxs] recv {}", n);
            }
            Sample {
                class: SampleClass::Responded,
                elapsed_ms: t0.elapsed().as_millis(),
                detail: format!("recv {}", n),
            }
        }
        Err(e) => {
            let d = e.to_string();
            let class = if is_timeout(&d) {
                SampleClass::Hang
            } else if is_crash_like(&d) {
                SampleClass::Crash
            } else {
                SampleClass::Unreachable
            };
            Sample {
                class,
                elapsed_ms: t0.elapsed().as_millis(),
                detail: d,
            }
        }
    }
}

fn classify(samples: &[Sample]) -> Class {
    let hangs = samples
        .iter()
        .filter(|s| s.class == SampleClass::Hang)
        .count();
    let responded = samples
        .iter()
        .filter(|s| s.class == SampleClass::Responded)
        .count();
    let unreachable = samples
        .iter()
        .filter(|s| s.class == SampleClass::Unreachable)
        .count();
    let n = samples.len();

    if hangs == n {
        Class::HardHang
    } else if responded > 0 && hangs > 0 {
        Class::SoftTimeout
    } else if responded > 0 {
        Class::Recovered
    } else if unreachable == n {
        Class::Unreachable
    } else if hangs >= (n + 1) / 2 {
        // majority hang
        Class::HardHang
    } else {
        Class::Mixed
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
        r#"nxs-timeout-analyzer {ver} (id={id})

Multi-shot hang / timeout classification.

USAGE:
    nxs-timeout-analyzer --crash <path> --target <host:port> [OPTIONS]
    nxs-timeout-analyzer --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Hang input
    --target <host:port>   Live target
    --event <type>         hang | …
    --model <name>
    --minimized <path>
    --meta <path>
    --out <dir>
    --timeout <secs>       Wall budget (default: {def})
    -v, --verbose
    -h, --help
    --version

EXIT CODES:
    0  Soft timeout / recovered / mixed
    1  Operational error / unreachable
    2  Hard hang confirmed → escalate
    3  Budget exhausted without classification
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
    );
}
