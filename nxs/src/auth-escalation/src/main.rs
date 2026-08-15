//! nxs-auth-escalation — official nexsiz existence script
//!
//! Contract id : crash/auth-escalation
//! Purpose     : Protocol-aware post-anomaly privilege / command escalation
//!               probe. After a crash or interesting event, attempts sequences
//!               that normally require higher privilege or an authenticated
//!               elevated state.
//!
//! Primary     : FTP, SMTP, HTTP
//! Fallback    : generic (minimal)
//!
//! Exit 2      : Unauthorized-looking elevated success observed → escalate.
//! Exit 0      : No escalation signal.
//! Exit 1      : Operational error.
//! Exit 3      : Internal timeout budget exhausted.
//!
//! Phase 2     : Confidence scoring, per-shot artefacts, rich report.extra
//!
//! Design (red-team grade):
//! - Bounded probe set and wall budget.
//! - Pure TCP (stdlib only + nxs-lib).
//! - Conservative signals; prefer clear success codes.
//! - Intrusive category.
//! - Distinct from auth-bypass: elevated commands / paths after anomaly.

use nxs_lib::{
    args::Args,
    exit::ExitCode,
    meta::{self, Meta},
    report::Report,
};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

const NXS_ID: &str = "crash/auth-escalation";
const NXS_VERSION: &str = "1.1.0";
const DEFAULT_TIMEOUT_SECS: u64 = 20;
const MAX_PROBES: usize = 12;

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
    let model = meta
        .effective_model(&args.model)
        .unwrap_or_else(|| "generic".into())
        .to_lowercase();

    args.log(&format!(
        "id={} event={} target={} input={} model={}",
        NXS_ID,
        event,
        target,
        input_path.display(),
        model
    ));

    let payload = match fs::read(&input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {}: {}", input_path.display(), e);
            ExitCode::Error.exit();
        }
    };

    let probes = build_escalation_probes(&model, &payload);
    let mut findings: Vec<String> = Vec::new();
    let mut shots: Vec<ShotRecord> = Vec::new();
    let mut artifact_paths: Vec<String> = Vec::new();
    let mut escalated = false;
    let mut max_confidence = Confidence::None;

    // Optional artefact directory
    let shots_dir = args.out.as_ref().map(|o| o.join("shots"));
    if let Some(ref dir) = shots_dir {
        let _ = fs::create_dir_all(dir);
    }

    for (idx, (name, data)) in probes.iter().take(MAX_PROBES).enumerate() {
        if budget.elapsed() > timeout {
            findings.push("probe budget exhausted".into());
            break;
        }

        let outcome = probe(&target, data, timeout, args.verbose);
        let conf = score_confidence(&model, name, &outcome);
        let signal = conf != Confidence::None;

        args.log(&format!(
            "probe={} class={:?} codes={:?} conf={:?} detail={}",
            name, outcome.class, outcome.codes, conf, outcome.detail
        ));

        // Persist request/response artefact when --out is set
        if let Some(ref dir) = shots_dir {
            if let Ok(rel) = save_shot_artifact(dir, idx, name, data, &outcome) {
                artifact_paths.push(rel);
            }
        }

        shots.push(ShotRecord {
            name: name.clone(),
            class: format!("{:?}", outcome.class),
            codes: outcome.codes.clone(),
            confidence: conf.as_str().to_string(),
            detail: outcome.detail.clone(),
            signal,
        });

        if signal {
            escalated = true;
            if conf > max_confidence {
                max_confidence = conf;
            }
            findings.push(format!(
                "[{}] escalation on '{}': codes={:?} ({})",
                conf.as_str(),
                name,
                outcome.codes,
                outcome.detail
            ));
        }
    }

    let elapsed_ms = budget.elapsed().as_millis() as u64;
    let signal_count = shots.iter().filter(|s| s.signal).count();

    let (exit, summary): (ExitCode, String) = if escalated {
        (
            ExitCode::Escalate,
            format!(
                "Auth-escalation signal(s) on model '{}' (confidence={}, signals={}/{})",
                model,
                max_confidence.as_str(),
                signal_count,
                shots.len()
            ),
        )
    } else if budget.elapsed() > timeout {
        (ExitCode::Timeout, "Budget exhausted".into())
    } else {
        (
            ExitCode::Ok,
            format!("No auth-escalation signal (model='{}')", model),
        )
    };

    finish(
        args,
        &target,
        crash_id,
        exit,
        &summary,
        &findings,
        &shots,
        &artifact_paths,
        &model,
        max_confidence,
        signal_count,
        elapsed_ms,
    );
}

fn finish(
    args: &Args,
    target: &str,
    crash_id: Option<String>,
    exit: ExitCode,
    summary: &str,
    findings: &[String],
    shots: &[ShotRecord],
    artifact_paths: &[String],
    model: &str,
    max_confidence: Confidence,
    signal_count: usize,
    elapsed_ms: u64,
) -> ! {
    let mut report = Report::new(NXS_ID, NXS_VERSION)
        .with_target(target)
        .with_crash_id(crash_id)
        .with_exit_hint(exit)
        .with_summary(summary);

    for f in findings {
        report.add_finding(f.clone());
    }
    for a in artifact_paths {
        report.add_artifact(a.clone());
    }

    // Rich structured extra (Phase 2)
    report.extra = Some(json!({
        "model": model,
        "confidence": max_confidence.as_str(),
        "signal_count": signal_count,
        "shot_count": shots.len(),
        "elapsed_ms": elapsed_ms,
        "shots": shots,
    }));

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
// Phase 2 types: confidence + shot record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Confidence {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl Confidence {
    fn as_str(self) -> &'static str {
        match self {
            Confidence::None => "none",
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct ShotRecord {
    name: String,
    class: String,
    codes: Vec<u16>,
    confidence: String,
    detail: String,
    signal: bool,
}

/// Score how strong an escalation signal is for this probe outcome.
fn score_confidence(model: &str, probe_name: &str, outcome: &ProbeOutcome) -> Confidence {
    if outcome.class != Class::Responded {
        return Confidence::None;
    }
    let codes = &outcome.codes;

    match model {
        "ftp" | "grammar-ftp" | "g-ftp" => {
            if !(probe_name.contains("site")
                || probe_name.contains("retr")
                || probe_name.contains("list")
                || probe_name.contains("cwd")
                || probe_name.contains("elevated"))
            {
                return Confidence::None;
            }
            // SITE EXEC / CHMOD / RETR passwd|shadow with 200/250 → high
            if (probe_name.contains("exec")
                || probe_name.contains("chmod")
                || probe_name.contains("passwd")
                || probe_name.contains("shadow"))
                && codes.iter().any(|c| matches!(*c, 200 | 250))
            {
                return Confidence::High;
            }
            if codes.iter().any(|c| matches!(*c, 200 | 250 | 257)) {
                return Confidence::Medium;
            }
            Confidence::None
        }
        "smtp" | "grammar-smtp" | "g-smtp" => {
            if !(probe_name.contains("vrfy")
                || probe_name.contains("expn")
                || probe_name.contains("mail"))
            {
                return Confidence::None;
            }
            // VRFY/EXPN root/admin returning 250 is strong
            if (probe_name.contains("root") || probe_name.contains("admin"))
                && codes.iter().any(|c| *c == 250)
            {
                return Confidence::High;
            }
            if codes.iter().any(|c| matches!(*c, 250 | 252)) {
                return Confidence::Medium;
            }
            Confidence::None
        }
        "http" | "grammar-http" | "g-http" => {
            let elevated_path = probe_name.contains("admin")
                || probe_name.contains("status")
                || probe_name.contains("info")
                || probe_name.contains("manager");
            let dangerous_method = probe_name.contains("put")
                || probe_name.contains("delete")
                || probe_name.contains("trace");
            let basic = probe_name.contains("basic");

            if elevated_path && codes.iter().any(|c| matches!(*c, 200 | 204)) {
                return Confidence::High;
            }
            if dangerous_method && codes.iter().any(|c| matches!(*c, 200 | 201 | 204)) {
                return Confidence::High;
            }
            if basic && codes.iter().any(|c| matches!(*c, 200 | 204)) {
                return Confidence::Medium;
            }
            if (elevated_path || dangerous_method || basic)
                && codes
                    .iter()
                    .any(|c| matches!(*c, 200 | 201 | 204 | 301 | 302 | 307))
            {
                return Confidence::Medium;
            }
            if (probe_name.contains("options") || probe_name.contains("trace"))
                && codes.iter().any(|c| *c == 200)
            {
                return Confidence::Low;
            }
            Confidence::None
        }
        _ => {
            if (probe_name.contains("root") || probe_name.contains("admin"))
                && codes.iter().any(|c| matches!(*c, 200 | 230 | 250))
            {
                return Confidence::Low;
            }
            Confidence::None
        }
    }
}

/// Write request + response metadata for one shot under out/shots/.
fn save_shot_artifact(
    dir: &Path,
    idx: usize,
    name: &str,
    request: &[u8],
    outcome: &ProbeOutcome,
) -> Result<String, String> {
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    let base = format!("{:02}_{}", idx, safe);

    let req_path = dir.join(format!("{}.req", base));
    fs::write(&req_path, request).map_err(|e| e.to_string())?;

    let meta_path = dir.join(format!("{}.json", base));
    let meta = json!({
        "name": name,
        "class": format!("{:?}", outcome.class),
        "codes": outcome.codes,
        "detail": outcome.detail,
        "request_len": request.len(),
    });
    fs::write(
        &meta_path,
        serde_json::to_string_pretty(&meta).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;

    Ok(format!("shots/{}.req", base))
}

// ---------------------------------------------------------------------------
// Escalation probe construction — FTP / SMTP / HTTP
// ---------------------------------------------------------------------------

fn build_escalation_probes(model: &str, original: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    v.push(("original".into(), original.to_vec()));

    match model {
        "ftp" | "grammar-ftp" | "g-ftp" => {
            v.push((
                "ftp_site_help".into(),
                b"USER anonymous\r\nPASS guest\r\nSITE HELP\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "ftp_site_exec".into(),
                b"USER anonymous\r\nPASS guest\r\nSITE EXEC id\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "ftp_site_chmod".into(),
                b"USER anonymous\r\nPASS guest\r\nSITE CHMOD 777 /\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "ftp_retr_passwd".into(),
                b"USER anonymous\r\nPASS guest\r\nRETR /etc/passwd\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "ftp_retr_shadow".into(),
                b"USER anonymous\r\nPASS guest\r\nRETR /etc/shadow\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "ftp_list_root".into(),
                b"USER anonymous\r\nPASS guest\r\nLIST /\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "ftp_list_etc".into(),
                b"USER anonymous\r\nPASS guest\r\nCWD /etc\r\nLIST\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "ftp_cwd_traversal".into(),
                b"USER anonymous\r\nPASS guest\r\nCWD /\r\nCWD ../\r\nCWD ../../\r\nPWD\r\nQUIT\r\n"
                    .to_vec(),
            ));
            if !original.is_empty() {
                let mut p = original.to_vec();
                if !p.ends_with(b"\n") {
                    p.extend_from_slice(b"\r\n");
                }
                p.extend_from_slice(b"SITE HELP\r\nLIST /\r\nRETR /etc/passwd\r\n");
                v.push(("ftp_orig_then_elevated".into(), p));
            }
        }
        "smtp" | "grammar-smtp" | "g-smtp" => {
            v.push((
                "smtp_vrfy_root".into(),
                b"EHLO localhost\r\nVRFY root\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "smtp_vrfy_admin".into(),
                b"EHLO localhost\r\nVRFY admin\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "smtp_expn_root".into(),
                b"EHLO localhost\r\nEXPN root\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "smtp_expn_admin".into(),
                b"EHLO localhost\r\nEXPN admin\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "smtp_mail_root".into(),
                b"EHLO localhost\r\nMAIL FROM:<root@localhost>\r\nRCPT TO:<postmaster>\r\nDATA\r\nSubject: test\r\n\r\ntest\r\n.\r\nQUIT\r\n"
                    .to_vec(),
            ));
            v.push((
                "smtp_mail_empty_from".into(),
                b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<postmaster>\r\nQUIT\r\n".to_vec(),
            ));
            if !original.is_empty() {
                let mut p = original.to_vec();
                if !p.ends_with(b"\n") {
                    p.extend_from_slice(b"\r\n");
                }
                p.extend_from_slice(b"VRFY root\r\nEXPN root\r\nVRFY admin\r\n");
                v.push(("smtp_orig_then_vrfy".into(), p));
            }
        }
        "http" | "grammar-http" | "g-http" => {
            v.push((
                "http_admin".into(),
                b"GET /admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            v.push((
                "http_admin_slash".into(),
                b"GET /admin/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            v.push((
                "http_server_status".into(),
                b"GET /server-status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_server_info".into(),
                b"GET /server-info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_manager".into(),
                b"GET /manager/html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_put".into(),
                b"PUT /test_nxs.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest"
                    .to_vec(),
            ));
            v.push((
                "http_delete".into(),
                b"DELETE /test_nxs.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_options".into(),
                b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            v.push((
                "http_trace".into(),
                b"TRACE / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            v.push((
                "http_basic_admin".into(),
                b"GET /admin HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_basic_root".into(),
                b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic cm9vdDpyb290\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            if !original.is_empty() {
                v.push(("http_original".into(), original.to_vec()));
            }
        }
        _ => {
            if !original.is_empty() {
                v.push(("generic_original".into(), original.to_vec()));
            }
            v.push((
                "generic_root".into(),
                b"USER root\r\nPASS root\r\n".to_vec(),
            ));
        }
    }
    v
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

struct ProbeOutcome {
    class: Class,
    codes: Vec<u16>,
    detail: String,
}

fn probe(target: &str, payload: &[u8], timeout: Duration, verbose: bool) -> ProbeOutcome {
    let addr = match resolve_addr(target) {
        Ok(a) => a,
        Err(e) => {
            return ProbeOutcome {
                class: Class::Unreachable,
                codes: vec![],
                detail: e,
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
            return ProbeOutcome {
                class,
                codes: vec![],
                detail: d,
            };
        }
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut stream = stream;

    {
        let mut banner = [0u8; 1024];
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let _ = stream.read(&mut banner);
        let _ = stream.set_read_timeout(Some(timeout));
    }

    if let Err(e) = stream.write_all(payload) {
        let d = e.to_string();
        let class = if is_crash_like(&d) {
            Class::Crash
        } else {
            Class::Unreachable
        };
        return ProbeOutcome {
            class,
            codes: vec![],
            detail: d,
        };
    }
    let _ = stream.flush();

    let mut total = Vec::new();
    let mut buf = [0u8; 4096];
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
                        return ProbeOutcome {
                            class: Class::Hang,
                            codes: vec![],
                            detail: format!("timeout ({:?})", timeout),
                        };
                    }
                    break;
                }
                if is_crash_like(&d) && total.is_empty() {
                    return ProbeOutcome {
                        class: Class::Crash,
                        codes: vec![],
                        detail: d,
                    };
                }
                break;
            }
        }
    }

    if total.is_empty() {
        return ProbeOutcome {
            class: Class::Crash,
            codes: vec![],
            detail: "EOF after payload".into(),
        };
    }

    if verbose {
        eprintln!("[nxs] recv {} bytes", total.len());
    }

    let codes = extract_status_codes(&total);
    ProbeOutcome {
        class: Class::Responded,
        codes,
        detail: format!("recv {}", total.len()),
    }
}

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
        r#"nxs-auth-escalation {ver} (id={id})

Protocol-aware post-anomaly privilege / command escalation probe.
Primary targets: FTP, SMTP, HTTP.
Phase 2: confidence scoring + per-shot artefacts + rich report.

USAGE:
    nxs-auth-escalation --crash <path> --target <host:port> [OPTIONS]
    nxs-auth-escalation --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Live target
    --event <type>         crash | …
    --model <name>         Protocol model (ftp|smtp|http|…)
    --minimized <path>     Prefer as baseline
    --meta <path>          Nexsiz metadata JSON
    --out <dir>            report.json + shots/
    --timeout <secs>       Total wall budget (default: {def})
    -v, --verbose
    -h, --help
    --version

EXIT CODES:
    0  No auth-escalation signal
    1  Operational error
    2  Escalation signal observed → escalate
    3  Internal timeout budget exhausted

NOTE: Intrusive. Distinct from auth-bypass.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
    );
}
