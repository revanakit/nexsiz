//! nxs-chain-repro — official existence script (Phase 0 + Phase 1)
//!
//! Contract id: crash/chain-repro
//! Purpose    : After a crash is discovered, perform a bounded sequence of
//!              deterministic shots against the live target. Observe whether
//!              the failure is stable, whether behaviour escalates (crash →
//!              hang, crash → unexpected success), and whether responses
//!              contain info-leak indicators. Prefer the minimised input.
//!
//! Exit 2     : Chain / escalation indicator present (reproducible crash +
//!              leak, class transition, or strong info-leak signal).
//! Exit 0     : No chain indicator; input no longer interesting or target
//!              stable without leak.
//! Exit 1     : Operational error.
//! Exit 3     : Internal timeout budget exhausted.
//!
//! Design (red-team grade):
//! - Pure TCP path; light protocol awareness driven by --model / meta.model.
//! - Hard caps on shot count and wall-clock budget.
//! - Info-leak prioritisation over pure crash reproduction.
//! - Zero external crates beyond nxs-lib + serde_json.
//! - Intrusive: belongs to "intrusive", not "safe" / "default".

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

const NXS_ID: &str = "crash/chain-repro";
const NXS_VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
const DEFAULT_SHOTS: usize = 5;
const MAX_SHOTS: usize = 12;
const MAX_RESPONSE: usize = 8192;

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

    let shots = parse_shots(&args.rest).clamp(1, MAX_SHOTS);

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
    let model = meta
        .effective_model(&args.model)
        .unwrap_or_else(|| "generic".into())
        .to_lowercase();
    let crash_id = meta.crash_id().map(str::to_string);

    args.log(&format!(
        "id={} event={} model={} target={} input={} shots={}",
        NXS_ID,
        event,
        model,
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
    args.log(&format!("payload_len={}", payload.len()));

    // --- Sequential shots ---------------------------------------------------
    let mut results: Vec<ShotResult> = Vec::with_capacity(shots);
    let mut findings: Vec<String> = Vec::new();

    for i in 0..shots {
        if budget.elapsed() > timeout {
            findings.push(format!("shot budget exhausted after {}", i));
            break;
        }
        let r = shot(&target, &payload, timeout, &model, args.verbose);
        args.log(&format!(
            "shot={} class={:?} resp_len={} leak={}",
            i + 1,
            r.class,
            r.response_len,
            r.leak_score
        ));
        results.push(r);
    }

    if results.is_empty() {
        finish(
            args,
            &target,
            crash_id,
            ExitCode::Timeout,
            "no shots completed within budget",
            &findings,
            None,
        );
    }

    // --- Chain / escalation analysis ----------------------------------------
    let analysis = analyse_chain(&results, &model);
    for f in &analysis.findings {
        findings.push(f.clone());
    }

    let (exit, summary) = if analysis.escalate {
        (
            ExitCode::Escalate,
            format!(
                "Chain indicator: {} (shots={}, max_leak={})",
                analysis.reason,
                results.len(),
                analysis.max_leak
            ),
        )
    } else {
        (
            ExitCode::Ok,
            format!(
                "No chain escalation (shots={}, max_leak={})",
                results.len(),
                analysis.max_leak
            ),
        )
    };

    let extra = serde_json::json!({
        "shots": results.len(),
        "model": model,
        "max_leak_score": analysis.max_leak,
        "classes": results.iter().map(|r| format!("{:?}", r.class)).collect::<Vec<_>>(),
        "leak_scores": results.iter().map(|r| r.leak_score).collect::<Vec<_>>(),
    });

    finish(args, &target, crash_id, exit, &summary, &findings, Some(extra));
}

fn finish(
    args: &Args,
    target: &str,
    crash_id: Option<String>,
    exit: ExitCode,
    summary: &str,
    findings: &[String],
    extra: Option<serde_json::Value>,
) -> ! {
    let mut report = Report::new(NXS_ID, NXS_VERSION)
        .with_target(target)
        .with_crash_id(crash_id)
        .with_exit_hint(exit)
        .with_summary(summary);
    for f in findings {
        report.add_finding(f.clone());
    }
    if let Some(e) = extra {
        report.extra = Some(e);
    }

    if let Some(out) = &args.out {
        let repro_dir = out.join("repro");
        let _ = fs::create_dir_all(&repro_dir);
        // artefacts are optional; report is mandatory when --out given
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
// Shot engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Class {
    Crash,
    Hang,
    Responded,
    Unreachable,
}

#[derive(Debug)]
struct ShotResult {
    class: Class,
    detail: String,
    response: Vec<u8>,
    response_len: usize,
    leak_score: u32,
}

fn shot(
    target: &str,
    payload: &[u8],
    timeout: Duration,
    model: &str,
    verbose: bool,
) -> ShotResult {
    let addr = match resolve_addr(target) {
        Ok(a) => a,
        Err(e) => {
            return ShotResult {
                class: Class::Unreachable,
                detail: e,
                response: Vec::new(),
                response_len: 0,
                leak_score: 0,
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
            return ShotResult {
                class,
                detail: d,
                response: Vec::new(),
                response_len: 0,
                leak_score: 0,
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
        return ShotResult {
            class,
            detail: d,
            response: Vec::new(),
            response_len: 0,
            leak_score: 0,
        };
    }
    let _ = stream.flush();

    let mut buf = vec![0u8; MAX_RESPONSE];
    match stream.read(&mut buf) {
        Ok(0) => ShotResult {
            class: Class::Crash,
            detail: "EOF after payload".into(),
            response: Vec::new(),
            response_len: 0,
            leak_score: 0,
        },
        Ok(n) => {
            buf.truncate(n);
            if verbose {
                eprintln!("[nxs] recv {} bytes", n);
            }
            let leak = score_leak(&buf, model);
            ShotResult {
                class: Class::Responded,
                detail: format!("recv {}", n),
                response: buf,
                response_len: n,
                leak_score: leak,
            }
        }
        Err(e) => {
            let d = e.to_string();
            if is_timeout(&d) {
                ShotResult {
                    class: Class::Hang,
                    detail: format!("timeout after send ({:?})", timeout),
                    response: Vec::new(),
                    response_len: 0,
                    leak_score: 0,
                }
            } else if is_crash_like(&d) {
                ShotResult {
                    class: Class::Crash,
                    detail: d,
                    response: Vec::new(),
                    response_len: 0,
                    leak_score: 0,
                }
            } else {
                ShotResult {
                    class: Class::Unreachable,
                    detail: d,
                    response: Vec::new(),
                    response_len: 0,
                    leak_score: 0,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Info-leak scoring (prioritised)
// ---------------------------------------------------------------------------

fn score_leak(data: &[u8], model: &str) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut score: u32 = 0;
    let text = String::from_utf8_lossy(data).to_lowercase();

    // Size anomaly: large unexpected payload is a strong signal
    if data.len() >= 1024 {
        score += 3;
    } else if data.len() >= 256 {
        score += 1;
    }

    // Path / absolute path indicators
    if text.contains("/home/")
        || text.contains("/root/")
        || text.contains("/var/")
        || text.contains("/etc/")
        || text.contains("c:\\")
        || text.contains("\\users\\")
        || text.contains("/tmp/")
    {
        score += 4;
    }

    // Credential / secret-like patterns
    if text.contains("password")
        || text.contains("passwd")
        || text.contains("secret")
        || text.contains("api_key")
        || text.contains("apikey")
        || text.contains("token=")
        || text.contains("authorization:")
        || text.contains("private key")
    {
        score += 5;
    }

    // Null bytes inside what should be text protocol → possible memory leak
    let null_count = data.iter().filter(|&&b| b == 0).count();
    if matches!(model, "ftp" | "smtp" | "http") && null_count > 0 {
        score += 3 + (null_count.min(5) as u32);
    }

    // High-entropy / binary content in text protocols
    if matches!(model, "ftp" | "smtp" | "http") {
        let non_print = data
            .iter()
            .filter(|&&b| b < 0x09 || (b > 0x0d && b < 0x20) || b > 0x7e)
            .count();
        if non_print > data.len() / 4 {
            score += 3;
        }
    }

    // Protocol-specific success-after-crash signals
    match model {
        "ftp" => {
            // 230 User logged in, 250 Requested file action okay, 200 Command okay
            if text.contains("230 ") || text.contains("250 ") || text.contains("200 ") {
                score += 2;
            }
            // Multi-line or unusually long FTP reply
            if data.iter().filter(|&&b| b == b'\n').count() > 4 {
                score += 1;
            }
        }
        "smtp" => {
            if text.contains("250 ") || text.contains("220 ") || text.contains("235 ") {
                score += 2;
            }
        }
        "http" => {
            if text.starts_with("http/1.") {
                if text.contains(" 200 ") || text.contains(" 201 ") || text.contains(" 204 ") {
                    score += 2;
                }
                // Server / X- headers that might leak version or path
                if text.contains("server:") || text.contains("x-powered-by:") {
                    score += 1;
                }
            }
        }
        _ => {
            // Generic / binary: look for length-prefix inconsistency or repeated patterns
            if data.len() >= 4 {
                let claimed = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if claimed > 0 && claimed < data.len().saturating_mul(4) && claimed != data.len() - 4
                {
                    score += 2; // length field does not match body
                }
            }
        }
    }

    score
}

// ---------------------------------------------------------------------------
// Chain analysis
// ---------------------------------------------------------------------------

struct ChainAnalysis {
    escalate: bool,
    reason: String,
    max_leak: u32,
    findings: Vec<String>,
}

fn analyse_chain(results: &[ShotResult], _model: &str) -> ChainAnalysis {
    let mut findings = Vec::new();
    let max_leak = results.iter().map(|r| r.leak_score).max().unwrap_or(0);
    let crash_count = results.iter().filter(|r| r.class == Class::Crash).count();
    let hang_count = results.iter().filter(|r| r.class == Class::Hang).count();
    let responded_count = results
        .iter()
        .filter(|r| r.class == Class::Responded)
        .count();

    // Strong info-leak on any shot
    if max_leak >= 5 {
        findings.push(format!("strong info-leak signal (score={})", max_leak));
        return ChainAnalysis {
            escalate: true,
            reason: "info-leak".into(),
            max_leak,
            findings,
        };
    }

    // Reproducible crash + any leak signal
    if crash_count >= 2 && max_leak >= 2 {
        findings.push(format!(
            "reproducible crash ({} shots) with leak score {}",
            crash_count, max_leak
        ));
        return ChainAnalysis {
            escalate: true,
            reason: "crash+leak".into(),
            max_leak,
            findings,
        };
    }

    // Class transition: crash → hang or hang → responded (possible state change)
    let mut prev: Option<&Class> = None;
    for r in results {
        if let Some(p) = prev {
            match (p, &r.class) {
                (Class::Crash, Class::Hang) => {
                    findings.push("class transition Crash → Hang".into());
                    return ChainAnalysis {
                        escalate: true,
                        reason: "crash-to-hang".into(),
                        max_leak,
                        findings,
                    };
                }
                (Class::Hang, Class::Responded) if r.leak_score >= 2 => {
                    findings.push("class transition Hang → Responded with leak".into());
                    return ChainAnalysis {
                        escalate: true,
                        reason: "hang-to-leak".into(),
                        max_leak,
                        findings,
                    };
                }
                (Class::Crash, Class::Responded) if r.leak_score >= 3 => {
                    findings.push("class transition Crash → Responded with significant leak".into());
                    return ChainAnalysis {
                        escalate: true,
                        reason: "crash-to-leak".into(),
                        max_leak,
                        findings,
                    };
                }
                _ => {}
            }
        }
        prev = Some(&r.class);
    }

    // Consistent hang (harder than single-shot)
    if hang_count >= 2 && responded_count == 0 && crash_count == 0 {
        findings.push(format!("consistent hang across {} shots", hang_count));
        return ChainAnalysis {
            escalate: true,
            reason: "consistent-hang".into(),
            max_leak,
            findings,
        };
    }

    // Mild leak on multiple shots still interesting
    if max_leak >= 3 && results.iter().filter(|r| r.leak_score >= 2).count() >= 2 {
        findings.push("repeated moderate leak signals".into());
        return ChainAnalysis {
            escalate: true,
            reason: "repeated-leak".into(),
            max_leak,
            findings,
        };
    }

    ChainAnalysis {
        escalate: false,
        reason: "none".into(),
        max_leak,
        findings,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_shots(rest: &[String]) -> usize {
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--shots" && i + 1 < rest.len() {
            if let Ok(n) = rest[i + 1].parse::<usize>() {
                return n;
            }
        }
        i += 1;
    }
    DEFAULT_SHOTS
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
        r#"nxs-chain-repro {ver} (id={id})

Multi-shot deterministic chain observation with info-leak prioritisation.
Supports light protocol awareness for FTP / SMTP / HTTP / generic binary.

USAGE:
    nxs-chain-repro --crash <path> --target <host:port> [OPTIONS]
    nxs-chain-repro --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Live target
    --event <type>         crash | hang | … (default: crash)
    --model <name>         ftp | smtp | http | generic (affects leak heuristics)
    --minimized <path>     Prefer this over --crash
    --meta <path>          Nexsiz metadata JSON (or - for stdin)
    --out <dir>            Write report.json
    --timeout <secs>       Total wall budget (default: {def})
    -v, --verbose          Human log on stderr
    -h, --help
    --version

SCRIPT OPTIONS:
    --shots <n>            Number of sequential shots (default: {shots}, max: {max})

EXIT CODES:
    0  No chain / escalation indicator
    1  Operational error
    2  Chain indicator (leak / class transition / consistent hang) → escalate
    3  Internal timeout budget exhausted

NOTE: Intrusive — contacts the live target multiple times.
      Place in category "intrusive" or invoke by explicit id.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
        shots = DEFAULT_SHOTS,
        max = MAX_SHOTS,
    );
}
