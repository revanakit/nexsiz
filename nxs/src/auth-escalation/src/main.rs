//! nxs-auth-escalation — official nexsiz existence script
//!
//! Contract id : crash/auth-escalation
//! Purpose     : Protocol-aware post-anomaly privilege / command escalation
//!               probe. After a crash or interesting event, attempts sequences
//!               that normally require higher privilege or an authenticated
//!               state. Covers every model currently supported by Nexsiz.
//!
//! Exit 2      : Unauthorized-looking elevated success observed → escalate.
//! Exit 0      : No escalation signal.
//! Exit 1      : Operational error.
//! Exit 3      : Internal timeout budget exhausted.
//!
//! Phase 0     : Scaffold + contract compliance + model dispatcher.
//!               Real escalation heuristics land in Phase 1.
//!
//! Design (red-team grade):
//! - Bounded probe set and wall budget.
//! - Pure TCP (stdlib only + nxs-lib).
//! - Model-driven: ftp / smtp / http / dns / mqtt / smb / binary-lp / generic.
//! - Conservative signals; prefer clear success codes / banners.
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

const NXS_ID: &str = "crash/auth-escalation";
const NXS_VERSION: &str = "0.1.0";
const DEFAULT_TIMEOUT_SECS: u64 = 20;
const MAX_PROBES: usize = 10;

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

    // Phase 0: dispatcher is live; probes are still light / placeholder.
    // Phase 1 will replace build_escalation_probes with full heuristics.
    let probes = build_escalation_probes(&model, &payload);
    let mut findings: Vec<String> = Vec::new();
    let mut escalated = false;

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

        if is_escalation_signal(&model, name, &outcome) {
            escalated = true;
            findings.push(format!(
                "escalation signal on '{}': class={:?} codes={:?} ({})",
                name, outcome.class, outcome.codes, outcome.detail
            ));
        }
    }

    let (exit, summary): (ExitCode, String) = if escalated {
        (
            ExitCode::Escalate,
            format!("Auth-escalation signal(s) on model '{}'", model),
        )
    } else if budget.elapsed() > timeout {
        (ExitCode::Timeout, "Budget exhausted".into())
    } else {
        (
            ExitCode::Ok,
            format!("No auth-escalation signal (model='{}')", model),
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
// Escalation probe construction (Phase 0 — structure + light probes)
// Phase 1 will expand each arm with full privilege/command sequences.
// ---------------------------------------------------------------------------

fn build_escalation_probes(model: &str, original: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();

    // Always keep original as baseline reference.
    v.push(("original".into(), original.to_vec()));

    match model {
        // -----------------------------------------------------------------
        // FTP family
        // -----------------------------------------------------------------
        "ftp" | "grammar-ftp" | "g-ftp" => {
            // SITE (often restricted)
            v.push((
                "ftp_site_help".into(),
                b"USER anonymous\r\nPASS guest\r\nSITE HELP\r\nQUIT\r\n".to_vec(),
            ));
            // Sensitive path retrieval
            v.push((
                "ftp_retr_passwd".into(),
                b"USER anonymous\r\nPASS guest\r\nRETR /etc/passwd\r\nQUIT\r\n".to_vec(),
            ));
            // CWD traversal
            v.push((
                "ftp_cwd_root".into(),
                b"USER anonymous\r\nPASS guest\r\nCWD /\r\nCWD ../\r\nPWD\r\nQUIT\r\n".to_vec(),
            ));
            // Append privileged command after original
            if !original.is_empty() {
                let mut p = original.to_vec();
                if !p.ends_with(b"\n") {
                    p.extend_from_slice(b"\r\n");
                }
                p.extend_from_slice(b"SITE EXEC id\r\nLIST /\r\n");
                v.push(("ftp_orig_then_site".into(), p));
            }
        }

        // -----------------------------------------------------------------
        // SMTP family
        // -----------------------------------------------------------------
        "smtp" | "grammar-smtp" | "g-smtp" => {
            v.push((
                "smtp_vrfy_root".into(),
                b"EHLO localhost\r\nVRFY root\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "smtp_expn_admin".into(),
                b"EHLO localhost\r\nEXPN admin\r\nQUIT\r\n".to_vec(),
            ));
            v.push((
                "smtp_mail_relay".into(),
                b"EHLO localhost\r\nMAIL FROM:<root@localhost>\r\nRCPT TO:<postmaster>\r\nDATA\r\n.\r\nQUIT\r\n"
                    .to_vec(),
            ));
            if !original.is_empty() {
                let mut p = original.to_vec();
                if !p.ends_with(b"\n") {
                    p.extend_from_slice(b"\r\n");
                }
                p.extend_from_slice(b"VRFY root\r\nEXPN root\r\n");
                v.push(("smtp_orig_then_vrfy".into(), p));
            }
        }

        // -----------------------------------------------------------------
        // HTTP family
        // -----------------------------------------------------------------
        "http" | "grammar-http" | "g-http" => {
            v.push((
                "http_admin".into(),
                b"GET /admin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            v.push((
                "http_server_status".into(),
                b"GET /server-status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_put_test".into(),
                b"PUT /test.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest\r\n"
                    .to_vec(),
            ));
            v.push((
                "http_options".into(),
                b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            ));
            if !original.is_empty() {
                v.push(("http_original".into(), original.to_vec()));
            }
        }

        // -----------------------------------------------------------------
        // DNS (limited auth surface; still probe unusual opcodes / TSIG-ish)
        // -----------------------------------------------------------------
        "dns" | "grammar-dns" | "g-dns" => {
            // Phase 0: keep original + a simple additional query pattern.
            // Real TSIG / UPDATE escalation logic → Phase 1.
            if !original.is_empty() {
                v.push(("dns_original".into(), original.to_vec()));
            }
            // Minimal additional A query for localhost (safe probe)
            // (length-prefixed TCP DNS)
            let q = b"\x00\x1e\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09localhost\x00\x00\x01\x00\x01";
            v.push(("dns_localhost_a".into(), q.to_vec()));
        }

        // -----------------------------------------------------------------
        // MQTT
        // -----------------------------------------------------------------
        "mqtt" | "grammar-mqtt" | "g-mqtt" => {
            // CONNECT with admin-ish credentials + SUBSCRIBE to $SYS
            // Simplified fixed-header style probes (Phase 1 will refine).
            v.push((
                "mqtt_connect_admin".into(),
                b"\x10\x18\x00\x04MQTT\x04\x02\x00\x3c\x00\x05admin\x00\x05admin".to_vec(),
            ));
            if !original.is_empty() {
                let mut p = original.to_vec();
                // Append a SUBSCRIBE to $SYS/# (very rough placeholder)
                p.extend_from_slice(b"\x82\x0b\x00\x01\x00\x06$SYS/#\x00");
                v.push(("mqtt_orig_then_sys".into(), p));
            }
        }

        // -----------------------------------------------------------------
        // SMB / CIFS
        // -----------------------------------------------------------------
        "smb" | "cifs" | "grammar-smb" | "g-smb" => {
            // Phase 0: keep original + very light negotiate-style probe.
            // Full Session Setup / Tree Connect escalation → Phase 1.
            if !original.is_empty() {
                v.push(("smb_original".into(), original.to_vec()));
            }
            // Minimal NetBIOS + SMB negotiate placeholder (will be replaced)
            v.push((
                "smb_negotiate_placeholder".into(),
                b"\x00\x00\x00\x2f\xffSMB\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            ));
        }

        // -----------------------------------------------------------------
        // Binary length-prefix (BE / LE)
        // -----------------------------------------------------------------
        "binary-lp" | "lp" | "binary-lp-le" | "lp-le" => {
            // Phase 0: original + simple command-like suffixes.
            if !original.is_empty() {
                v.push(("binary_original".into(), original.to_vec()));
            }
            // Attempt common elevated-looking opcodes / strings
            v.push(("binary_admin_cmd".into(), b"\x00\x0aADMIN\x00EXEC".to_vec()));
            v.push(("binary_root_cmd".into(), b"\x00\x08ROOT\x00ID".to_vec()));
            if !original.is_empty() {
                let mut p = original.to_vec();
                p.extend_from_slice(b"\x00\x04PRIV");
                v.push(("binary_orig_then_priv".into(), p));
            }
        }

        // -----------------------------------------------------------------
        // Generic / fallback
        // -----------------------------------------------------------------
        _ => {
            if !original.is_empty() {
                v.push(("generic_original".into(), original.to_vec()));
            }
            // Classic auth + privileged command patterns
            v.push((
                "generic_root_pass".into(),
                b"USER root\r\nPASS root\r\nID\r\n".to_vec(),
            ));
            v.push((
                "generic_admin_basic".into(),
                b"Authorization: Basic YWRtaW46YWRtaW4=\r\n\r\n".to_vec(),
            ));
            if !original.is_empty() {
                let mut p = original.to_vec();
                if !p.ends_with(b"\n") {
                    p.extend_from_slice(b"\r\n");
                }
                p.extend_from_slice(b"PRIV\r\nADMIN\r\n");
                v.push(("generic_orig_then_priv".into(), p));
            }
        }
    }

    v
}

// ---------------------------------------------------------------------------
// Escalation signal detection (Phase 0 — conservative)
// Phase 1 will tighten per-protocol success criteria.
// ---------------------------------------------------------------------------

fn is_escalation_signal(model: &str, probe_name: &str, outcome: &ProbeOutcome) -> bool {
    if outcome.class != Class::Responded {
        return false;
    }
    let codes = &outcome.codes;

    match model {
        "ftp" | "grammar-ftp" | "g-ftp" => {
            // 200/250 after SITE / RETR / privileged CWD is interesting
            if probe_name.contains("site")
                || probe_name.contains("retr")
                || probe_name.contains("cwd")
            {
                return codes.iter().any(|c| matches!(*c, 200 | 250 | 257));
            }
            false
        }
        "smtp" | "grammar-smtp" | "g-smtp" => {
            // 250/252 on VRFY/EXPN/MAIL can indicate weak config
            if probe_name.contains("vrfy")
                || probe_name.contains("expn")
                || probe_name.contains("mail")
                || probe_name.contains("relay")
            {
                return codes.iter().any(|c| matches!(*c, 250 | 252));
            }
            false
        }
        "http" | "grammar-http" | "g-http" => {
            // 200/204 on admin / server-status / PUT is elevated signal
            if probe_name.contains("admin")
                || probe_name.contains("status")
                || probe_name.contains("put")
            {
                return codes
                    .iter()
                    .any(|c| matches!(*c, 200 | 204 | 201 | 301 | 302));
            }
            false
        }
        "mqtt" | "grammar-mqtt" | "g-mqtt" => {
            // CONNACK success (rough) or any clear success code
            // Phase 1 will parse MQTT properly.
            codes.iter().any(|c| *c == 0 || *c == 200)
                || outcome.detail.contains("recv") && probe_name.contains("admin")
        }
        "dns" | "grammar-dns" | "g-dns" => {
            // Phase 0: almost never escalate on DNS alone
            false
        }
        "smb" | "cifs" | "grammar-smb" | "g-smb" => {
            // Phase 0 placeholder — no strong signal yet
            false
        }
        "binary-lp" | "lp" | "binary-lp-le" | "lp-le" => {
            // Any clear 2xx-style or success banner after priv command
            codes.iter().any(|c| matches!(*c, 200 | 230 | 250))
        }
        _ => {
            // Generic: elevated-looking success codes after priv probes
            if probe_name.contains("root")
                || probe_name.contains("admin")
                || probe_name.contains("priv")
            {
                return codes.iter().any(|c| matches!(*c, 200 | 230 | 250 | 257));
            }
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Probe engine (shared with auth-bypass style)
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

    // Drain optional banner
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
Covers all Nexsiz models: ftp, smtp, http, dns, mqtt, smb, binary-lp, generic.

USAGE:
    nxs-auth-escalation --crash <path> --target <host:port> [OPTIONS]
    nxs-auth-escalation --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Live target
    --event <type>         crash | …
    --model <name>         Protocol model (ftp|smtp|http|dns|mqtt|smb|binary-lp|generic)
    --minimized <path>     Prefer as baseline
    --meta <path>          Nexsiz metadata JSON
    --out <dir>            report.json
    --timeout <secs>       Total wall budget (default: {def})
    -v, --verbose
    -h, --help
    --version

EXIT CODES:
    0  No auth-escalation signal
    1  Operational error
    2  Escalation signal observed → escalate
    3  Internal timeout budget exhausted

NOTE: Intrusive — contacts the live target multiple times with privilege probes.
Phase 0 scaffold; full heuristics arrive in Phase 1.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
        def = DEFAULT_TIMEOUT_SECS,
    );
}
