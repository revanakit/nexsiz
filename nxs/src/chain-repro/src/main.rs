//! nxs-chain-repro — official existence script (Phase 0–2)
//!
//! Contract id: crash/chain-repro
//! Purpose    : After a crash is discovered, perform a bounded sequence of
//!              shots against the live target. Shot 0 is the original input
//!              (prefer minimised). Subsequent shots apply deliberate
//!              controlled mutations. Observe stability, class transitions,
//!              response divergence, and info-leak growth.
//!
//! Exit 2     : Chain / escalation indicator present.
//! Exit 0     : No chain indicator.
//! Exit 1     : Operational error.
//! Exit 3     : Internal timeout budget exhausted.
//!
//! Design (red-team grade):
//! - Pure TCP; light protocol awareness via --model / meta.model.
//! - Controlled variants only (no random mutation storm).
//! - Info-leak prioritisation + differential response comparison.
//! - Hard caps on shot count and wall-clock budget.
//! - Zero external crates beyond nxs-lib + serde_json.
//! - Intrusive category.

use nxs_lib::{
    args::Args,
    exit::ExitCode,
    meta::{self, Meta},
    report::Report,
};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

const NXS_ID: &str = "crash/chain-repro";
const NXS_VERSION: &str = "1.1.0";
const DEFAULT_TIMEOUT_SECS: u64 = 18;
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

    // Build the shot plan: baseline + controlled variants
    let plan = build_shot_plan(&payload, shots, &model);
    args.log(&format!("plan_variants={}", plan.len()));

    // --- Sequential shots ---------------------------------------------------
    let mut results: Vec<ShotResult> = Vec::with_capacity(plan.len());
    let mut findings: Vec<String> = Vec::new();

    for (i, (name, body)) in plan.iter().enumerate() {
        if budget.elapsed() > timeout {
            findings.push(format!("shot budget exhausted after {}", i));
            break;
        }
        let r = shot(&target, body, timeout, &model, args.verbose);
        args.log(&format!(
            "shot={} variant={} class={:?} resp_len={} status={:?} leak={}",
            i,
            name,
            r.class,
            r.response_len,
            r.status_code,
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
            &[],
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
                "Chain indicator: {} (shots={}, max_leak={}, div={})",
                analysis.reason,
                results.len(),
                analysis.max_leak,
                analysis.max_divergence
            ),
        )
    } else {
        (
            ExitCode::Ok,
            format!(
                "No chain escalation (shots={}, max_leak={}, div={})",
                results.len(),
                analysis.max_leak,
                analysis.max_divergence
            ),
        )
    };

    let extra = serde_json::json!({
        "shots": results.len(),
        "model": model,
        "max_leak_score": analysis.max_leak,
        "max_divergence": analysis.max_divergence,
        "variants": plan.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
        "classes": results.iter().map(|r| format!("{:?}", r.class)).collect::<Vec<_>>(),
        "leak_scores": results.iter().map(|r| r.leak_score).collect::<Vec<_>>(),
        "status_codes": results.iter().map(|r| r.status_code).collect::<Vec<_>>(),
        "response_lens": results.iter().map(|r| r.response_len).collect::<Vec<_>>(),
    });

    // Collect high-leak responses for artefact writing
    let leak_artefacts: Vec<(usize, &ShotResult)> = results
        .iter()
        .enumerate()
        .filter(|(_, r)| r.leak_score >= 3 && !r.response.is_empty())
        .collect();

    finish(
        args,
        &target,
        crash_id,
        exit,
        &summary,
        &findings,
        Some(extra),
        &leak_artefacts,
    );
}

fn finish(
    args: &Args,
    target: &str,
    crash_id: Option<String>,
    exit: ExitCode,
    summary: &str,
    findings: &[String],
    extra: Option<serde_json::Value>,
    leak_artefacts: &[(usize, &ShotResult)],
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

        // Save high-leak responses as artefacts
        for (idx, r) in leak_artefacts {
            let name = format!("leak-shot{:02}.bin", idx);
            let path = repro_dir.join(&name);
            if fs::write(&path, &r.response).is_ok() {
                report.add_artifact(format!("repro/{}", name));
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
// Shot plan — baseline + controlled variants
// ---------------------------------------------------------------------------

fn build_shot_plan(payload: &[u8], max_shots: usize, model: &str) -> Vec<(String, Vec<u8>)> {
    let mut plan = Vec::with_capacity(max_shots);

    // Shot 0: original (baseline)
    plan.push(("baseline".into(), payload.to_vec()));

    let n = payload.len();

    // 1. Truncate to ~50%
    if plan.len() < max_shots && n > 4 {
        plan.push(("truncate_half".into(), payload[..n / 2].to_vec()));
    }

    // 2. Truncate to first 1–4 bytes (protocol header only)
    if plan.len() < max_shots && n > 1 {
        let keep = n.min(4);
        plan.push(("truncate_header".into(), payload[..keep].to_vec()));
    }

    // 3. Append null / CRLF depending on model
    if plan.len() < max_shots {
        let mut p = payload.to_vec();
        match model {
            "ftp" | "smtp" => p.extend_from_slice(b"\r\n"),
            "http" => p.extend_from_slice(b"\r\n\r\n"),
            _ => p.push(0),
        }
        plan.push(("append_term".into(), p));
    }

    // 4. Prepend null / extra length byte
    if plan.len() < max_shots {
        let mut p = Vec::with_capacity(n + 1);
        p.push(0);
        p.extend_from_slice(payload);
        plan.push(("prepend_null".into(), p));
    }

    // 5. Flip high bit of first byte (length / flags)
    if plan.len() < max_shots && n >= 1 {
        let mut p = payload.to_vec();
        p[0] = p[0].wrapping_add(0x80);
        plan.push(("flip_high_0".into(), p));
    }

    // 6. Inflate claimed length (binary / length-prefix models)
    if plan.len() < max_shots && n >= 4 && matches!(model, "generic" | "binary" | "mqtt" | "dns") {
        let mut p = payload.to_vec();
        // BE length at offset 0 — set to a large value
        p[0] = 0x00;
        p[1] = 0x10; // claim ~4 KiB
        plan.push(("inflate_len_be".into(), p));
    }

    // 7. Double payload (length inflation)
    if plan.len() < max_shots && n > 0 && n < 2048 {
        let mut p = payload.to_vec();
        p.extend_from_slice(payload);
        plan.push(("double".into(), p));
    }

    // 8. Protocol-specific: strip trailing terminator
    if plan.len() < max_shots && matches!(model, "ftp" | "smtp" | "http") && n > 2 {
        let mut p = payload.to_vec();
        while p.last() == Some(&b'\n') || p.last() == Some(&b'\r') {
            p.pop();
        }
        if p.len() < n {
            plan.push(("strip_term".into(), p));
        }
    }

    // Fill remaining slots with original if still short (stability check)
    while plan.len() < max_shots {
        plan.push((format!("baseline_repeat_{}", plan.len()), payload.to_vec()));
    }

    plan.truncate(max_shots);
    plan
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
    status_code: Option<u16>,
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
                status_code: None,
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
                status_code: None,
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
            status_code: None,
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
            status_code: None,
        },
        Ok(n) => {
            buf.truncate(n);
            if verbose {
                eprintln!("[nxs] recv {} bytes", n);
            }
            let status = extract_status(&buf, model);
            let leak = score_leak(&buf, model, status);
            ShotResult {
                class: Class::Responded,
                detail: format!("recv {}", n),
                response: buf,
                response_len: n,
                leak_score: leak,
                status_code: status,
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
                    status_code: None,
                }
            } else if is_crash_like(&d) {
                ShotResult {
                    class: Class::Crash,
                    detail: d,
                    response: Vec::new(),
                    response_len: 0,
                    leak_score: 0,
                    status_code: None,
                }
            } else {
                ShotResult {
                    class: Class::Unreachable,
                    detail: d,
                    response: Vec::new(),
                    response_len: 0,
                    leak_score: 0,
                    status_code: None,
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol status extraction
// ---------------------------------------------------------------------------

fn extract_status(data: &[u8], model: &str) -> Option<u16> {
    let text = String::from_utf8_lossy(data);
    match model {
        "ftp" | "smtp" => {
            // First three digits at start of line
            for line in text.lines() {
                let t = line.trim_start();
                if t.len() >= 3 {
                    if let Ok(code) = t[..3].parse::<u16>() {
                        if (100..600).contains(&code) {
                            return Some(code);
                        }
                    }
                }
            }
            None
        }
        "http" => {
            // HTTP/1.x <code>
            let lower = text.to_lowercase();
            if let Some(pos) = lower.find("http/1.") {
                let rest = &text[pos..];
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(code) = parts[1].parse::<u16>() {
                        return Some(code);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Info-leak scoring (Phase 2 — stronger)
// ---------------------------------------------------------------------------

fn score_leak(data: &[u8], model: &str, status: Option<u16>) -> u32 {
    if data.is_empty() {
        return 0;
    }
    let mut score: u32 = 0;
    let text = String::from_utf8_lossy(data).to_lowercase();

    // Size anomaly
    if data.len() >= 2048 {
        score += 4;
    } else if data.len() >= 1024 {
        score += 3;
    } else if data.len() >= 256 {
        score += 1;
    }

    // Path indicators
    if text.contains("/home/")
        || text.contains("/root/")
        || text.contains("/var/")
        || text.contains("/etc/")
        || text.contains("/tmp/")
        || text.contains("c:\\")
        || text.contains("\\users\\")
        || text.contains("\\windows\\")
    {
        score += 4;
    }

    // Credential / secret-like
    if text.contains("password")
        || text.contains("passwd")
        || text.contains("secret")
        || text.contains("api_key")
        || text.contains("apikey")
        || text.contains("token=")
        || text.contains("authorization:")
        || text.contains("private key")
        || text.contains("begin rsa")
        || text.contains("begin openssh")
    {
        score += 5;
    }

    // Null bytes in text protocols → memory disclosure signal
    let null_count = data.iter().filter(|&&b| b == 0).count();
    if matches!(model, "ftp" | "smtp" | "http") && null_count > 0 {
        score += 3 + (null_count.min(6) as u32);
    }

    // High non-printable ratio in text protocols
    if matches!(model, "ftp" | "smtp" | "http") {
        let non_print = data
            .iter()
            .filter(|&&b| b < 0x09 || (b > 0x0d && b < 0x20) || b > 0x7e)
            .count();
        if non_print > data.len() / 5 {
            score += 3;
        }
    }

    // Protocol success codes after a crash context are interesting
    if let Some(code) = status {
        match model {
            "ftp" => {
                if matches!(code, 200 | 230 | 250 | 257) {
                    score += 2;
                }
                if data.iter().filter(|&&b| b == b'\n').count() > 5 {
                    score += 1;
                }
            }
            "smtp" => {
                if matches!(code, 220 | 250 | 235 | 354) {
                    score += 2;
                }
            }
            "http" => {
                if matches!(code, 200 | 201 | 204 | 301 | 302) {
                    score += 2;
                }
                if text.contains("server:") || text.contains("x-powered-by:") {
                    score += 1;
                }
            }
            _ => {}
        }
    }

    // Generic / binary length-prefix inconsistency
    if matches!(model, "generic" | "binary" | "mqtt" | "dns") && data.len() >= 4 {
        let claimed_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let claimed_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        for claimed in [claimed_be, claimed_le] {
            if claimed > 0 && claimed < data.len().saturating_mul(8) && claimed != data.len().saturating_sub(4)
            {
                score += 2;
                break;
            }
        }
    }

    score
}

// ---------------------------------------------------------------------------
// Chain analysis (Phase 2 — differential + transition)
// ---------------------------------------------------------------------------

struct ChainAnalysis {
    escalate: bool,
    reason: String,
    max_leak: u32,
    max_divergence: u32,
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

    // Response length divergence between consecutive responded shots
    let mut max_div: u32 = 0;
    let responded: Vec<&ShotResult> = results
        .iter()
        .filter(|r| r.class == Class::Responded && r.response_len > 0)
        .collect();
    for w in responded.windows(2) {
        let a = w[0].response_len;
        let b = w[1].response_len;
        if a > 0 && b > 0 {
            let ratio = (a.max(b) as f64) / (a.min(b) as f64);
            if ratio >= 3.0 {
                let div = (ratio as u32).min(20);
                if div > max_div {
                    max_div = div;
                }
                findings.push(format!(
                    "response length divergence {} → {} (ratio≈{:.1})",
                    a, b, ratio
                ));
            }
        }
        // Status code change is also a signal
        if let (Some(sa), Some(sb)) = (w[0].status_code, w[1].status_code) {
            if sa != sb {
                findings.push(format!("status code change {} → {}", sa, sb));
                max_div = max_div.max(2);
            }
        }
    }

    // 1. Strong info-leak
    if max_leak >= 5 {
        findings.push(format!("strong info-leak signal (score={})", max_leak));
        return ChainAnalysis {
            escalate: true,
            reason: "info-leak".into(),
            max_leak,
            max_divergence: max_div,
            findings,
        };
    }

    // 2. Significant response divergence across chain
    if max_div >= 4 {
        findings.push(format!("significant response divergence (div={})", max_div));
        return ChainAnalysis {
            escalate: true,
            reason: "response-divergence".into(),
            max_leak,
            max_divergence: max_div,
            findings,
        };
    }

    // 3. Reproducible crash + leak
    if crash_count >= 2 && max_leak >= 2 {
        findings.push(format!(
            "reproducible crash ({} shots) with leak score {}",
            crash_count, max_leak
        ));
        return ChainAnalysis {
            escalate: true,
            reason: "crash+leak".into(),
            max_leak,
            max_divergence: max_div,
            findings,
        };
    }

    // 4. Class transitions
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
                        max_divergence: max_div,
                        findings,
                    };
                }
                (Class::Hang, Class::Responded) if r.leak_score >= 2 => {
                    findings.push("class transition Hang → Responded with leak".into());
                    return ChainAnalysis {
                        escalate: true,
                        reason: "hang-to-leak".into(),
                        max_leak,
                        max_divergence: max_div,
                        findings,
                    };
                }
                (Class::Crash, Class::Responded) if r.leak_score >= 3 => {
                    findings.push("class transition Crash → Responded with significant leak".into());
                    return ChainAnalysis {
                        escalate: true,
                        reason: "crash-to-leak".into(),
                        max_leak,
                        max_divergence: max_div,
                        findings,
                    };
                }
                (Class::Responded, Class::Crash) | (Class::Responded, Class::Hang) => {
                    // Baseline responded, later variant crashes/hangs → differential signal
                    findings.push(format!(
                        "class transition Responded → {:?}",
                        r.class
                    ));
                    return ChainAnalysis {
                        escalate: true,
                        reason: "responded-to-failure".into(),
                        max_leak,
                        max_divergence: max_div,
                        findings,
                    };
                }
                _ => {}
            }
        }
        prev = Some(&r.class);
    }

    // 5. Consistent hang
    if hang_count >= 2 && responded_count == 0 && crash_count == 0 {
        findings.push(format!("consistent hang across {} shots", hang_count));
        return ChainAnalysis {
            escalate: true,
            reason: "consistent-hang".into(),
            max_leak,
            max_divergence: max_div,
            findings,
        };
    }

    // 6. Repeated moderate leak
    if max_leak >= 3 && results.iter().filter(|r| r.leak_score >= 2).count() >= 2 {
        findings.push("repeated moderate leak signals".into());
        return ChainAnalysis {
            escalate: true,
            reason: "repeated-leak".into(),
            max_leak,
            max_divergence: max_div,
            findings,
        };
    }

    // 7. Mild divergence + any leak still interesting
    if max_div >= 2 && max_leak >= 2 {
        findings.push("combined divergence + leak signal".into());
        return ChainAnalysis {
            escalate: true,
            reason: "div+leak".into(),
            max_leak,
            max_divergence: max_div,
            findings,
        };
    }

    ChainAnalysis {
        escalate: false,
        reason: "none".into(),
        max_leak,
        max_divergence: max_div,
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

Multi-shot chain observation with controlled variants and info-leak prioritisation.
Shot 0 = original (prefer minimised). Later shots apply deliberate mutations.
Supports FTP / SMTP / HTTP status extraction + generic binary length-prefix checks.

USAGE:
    nxs-chain-repro --crash <path> --target <host:port> [OPTIONS]
    nxs-chain-repro --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Live target
    --event <type>         crash | hang | … (default: crash)
    --model <name>         ftp | smtp | http | generic (affects variants + leak heuristics)
    --minimized <path>     Prefer this over --crash
    --meta <path>          Nexsiz metadata JSON (or - for stdin)
    --out <dir>            Write report.json + high-leak artefacts
    --timeout <secs>       Total wall budget (default: {def})
    -v, --verbose          Human log on stderr
    -h, --help
    --version

SCRIPT OPTIONS:
    --shots <n>            Number of sequential shots including baseline (default: {shots}, max: {max})

EXIT CODES:
    0  No chain / escalation indicator
    1  Operational error
    2  Chain indicator (leak / divergence / class transition / consistent hang) → escalate
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
