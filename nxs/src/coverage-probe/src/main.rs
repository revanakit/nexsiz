//! nxs-coverage-probe — official nexsiz existence script
//!
//! Contract id: crash/coverage-probe
//! Purpose    : After a crash, exercise the input and a bounded set of
//!              controlled variants; collect unique behavioural fingerprints.
//!              Escalate when multiple distinct interesting path classes are
//!              observed (proxy for "new coverage / new path" without an
//!              in-process edge map inside the NXS process).
//!
//! Exit 2     : Path diversity / interesting multi-class behaviour → escalate.
//! Exit 0     : Single stable behavioural class.
//! Exit 1     : Operational error.
//! Exit 3     : Internal timeout budget exhausted.
//!
//! Design (red-team grade):
//! - Hard cap on variants and wall time.
//! - Pure TCP, model-agnostic.
//! - Fingerprint = (Class, body_hash) — cheap, deterministic.
//! - Uses meta.coverage_hits as a soft prior (logged, not sole trigger).
//! - Intrusive category.

use nxs_lib::{
    args::Args,
    exit::ExitCode,
    meta::{self, Meta},
    report::Report,
};
use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const NXS_ID: &str = "crash/coverage-probe";
const NXS_VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 14;
const MAX_VARIANTS: usize = 7;

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
    let meta_cov = meta
        .result
        .as_ref()
        .and_then(|r| r.coverage_hits)
        .unwrap_or(0);

    args.log(&format!(
        "id={} event={} target={} input={} meta_cov_hits={}",
        NXS_ID,
        event,
        target,
        input_path.display(),
        meta_cov
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

    // Baseline + controlled variants
    let mut probes: Vec<(String, Vec<u8>)> = vec![("baseline".into(), payload.clone())];
    probes.extend(build_variants(&payload).into_iter().take(MAX_VARIANTS - 1));

    let mut fingerprints: HashSet<(u8, u64)> = HashSet::new(); // (class_tag, hash)
    let mut class_counts: [usize; 4] = [0; 4]; // Crash, Hang, Responded, Unreachable
    let mut findings: Vec<String> = Vec::new();
    let mut interesting_classes = 0usize;

    for (name, data) in &probes {
        if budget.elapsed() > timeout {
            findings.push("probe budget exhausted".into());
            break;
        }
        let fp = probe(&target, data, timeout, args.verbose);
        let tag = class_tag(&fp.class);
        class_counts[tag as usize] += 1;
        let key = (tag, fp.body_hash);
        let is_new = fingerprints.insert(key);

        args.log(&format!(
            "probe={} class={:?} hash={:016x} new={}",
            name, fp.class, fp.body_hash, is_new
        ));

        if matches!(fp.class, Class::Crash | Class::Hang | Class::Responded) && is_new {
            interesting_classes += 1;
            if is_new && name != "baseline" {
                findings.push(format!(
                    "new fingerprint from '{}': class={:?} hash={:016x}",
                    name, fp.class, fp.body_hash
                ));
            }
        }
    }

    // Escalation criteria:
    //  - ≥2 distinct interesting fingerprints, OR
    //  - meta indicated coverage and we still observe ≥1 crash/hang + ≥1 responded
    let multi_path = fingerprints.len() >= 2 && interesting_classes >= 2;
    let cov_prior = meta_cov > 0
        && class_counts[0] + class_counts[1] > 0
        && class_counts[2] > 0;

    let escalate = multi_path || cov_prior;

    if cov_prior && !multi_path {
        findings.push(format!(
            "meta coverage_hits={} with mixed live classes (crash/hang + responded)",
            meta_cov
        ));
    }

    let (exit, summary): (ExitCode, String) = if escalate {
        (
            ExitCode::Escalate,
            format!(
                "Path diversity: {} unique fingerprints, classes={:?}",
                fingerprints.len(),
                class_counts
            ),
        )
    } else if budget.elapsed() > timeout {
        (ExitCode::Timeout, "Budget exhausted".into())
    } else {
        (
            ExitCode::Ok,
            format!(
                "Single behavioural family ({} fingerprint(s))",
                fingerprints.len()
            ),
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
// Probe + variants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Class {
    Crash,
    Hang,
    Responded,
    Unreachable,
}

fn class_tag(c: &Class) -> u8 {
    match c {
        Class::Crash => 0,
        Class::Hang => 1,
        Class::Responded => 2,
        Class::Unreachable => 3,
    }
}

struct ProbeFp {
    class: Class,
    body_hash: u64,
}

fn probe(target: &str, payload: &[u8], timeout: Duration, verbose: bool) -> ProbeFp {
    let addr = match resolve_addr(target) {
        Ok(a) => a,
        Err(_) => {
            return ProbeFp {
                class: Class::Unreachable,
                body_hash: 0,
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
            return ProbeFp {
                class,
                body_hash: 0,
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
        return ProbeFp {
            class,
            body_hash: 0,
        };
    }
    let _ = stream.flush();

    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(0) => ProbeFp {
            class: Class::Crash,
            body_hash: 0,
        },
        Ok(n) => {
            if verbose {
                eprintln!("[nxs] recv {} bytes", n);
            }
            ProbeFp {
                class: Class::Responded,
                body_hash: fnv1a64(&buf[..n]),
            }
        }
        Err(e) => {
            let d = e.to_string();
            if is_timeout(&d) {
                ProbeFp {
                    class: Class::Hang,
                    body_hash: 0,
                }
            } else if is_crash_like(&d) {
                ProbeFp {
                    class: Class::Crash,
                    body_hash: 0,
                }
            } else {
                ProbeFp {
                    class: Class::Unreachable,
                    body_hash: 0,
                }
            }
        }
    }
}

fn build_variants(payload: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    let n = payload.len();

    if n > 4 {
        v.push(("truncate_75".into(), payload[..(n * 3) / 4].to_vec()));
    }
    if n > 2 {
        v.push(("truncate_half".into(), payload[..n / 2].to_vec()));
    }
    {
        let mut p = payload.to_vec();
        p.push(0);
        v.push(("append_null".into(), p));
    }
    if n >= 2 {
        let mut p = payload.to_vec();
        p.swap(0, n - 1);
        v.push(("swap_ends".into(), p));
    }
    if n >= 4 {
        let mut p = payload.to_vec();
        p[n / 2] ^= 0xff;
        v.push(("xor_mid".into(), p));
    }
    if n > 0 && n < 2048 {
        let mut p = payload.to_vec();
        p.extend_from_slice(&payload[..n.min(64)]);
        v.push(("append_prefix64".into(), p));
    }

    v
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
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
        r#"nxs-coverage-probe {ver} (id={id})

Bounded path-diversity behavioural probe after a crash discovery.
Collects fingerprints (class + body hash) from baseline + controlled variants.

USAGE:
    nxs-coverage-probe --crash <path> --target <host:port> [OPTIONS]
    nxs-coverage-probe --meta <path> [OPTIONS]

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
    0  Single behavioural family
    1  Operational error
    2  Path diversity / mixed classes → escalate
    3  Internal timeout budget exhausted

NOTE: Intrusive — contacts the live target multiple times. Does not require
      an in-process coverage map; uses behavioural fingerprints as proxy.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
    );
}
