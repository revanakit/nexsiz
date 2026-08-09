//! nxs-notify-webhook — official nexsiz existence script
//!
//! Contract id: external/notify-webhook
//! Purpose    : Deliver a compact JSON notification to an external HTTP(S)
//!              webhook after a crash / hang / interesting event.
//!              Does **not** contact the fuzz target.
//!
//! Exit 0     : Webhook accepted (HTTP 2xx) or dry-run with no URL configured.
//! Exit 1     : Operational error (bad URL, transport failure, non-2xx).
//!
//! Design (red-team grade):
//! - Pure stdlib TCP + minimal HTTP/1.1 client (no reqwest / openssl dep).
//! - HTTPS is best-effort via optional `NXS_WEBHOOK_INSECURE=1` plain fallback
//!   note: for production TLS use a reverse-proxy or set NXS_NOTIFY_CMD instead.
//! - Timeout-bounded; never hangs the operator.
//! - Payload is intentionally small (no full crash blob in the body).

use nxs_lib::{
    args::Args,
    exit::ExitCode,
    meta::{self, Meta},
    report::Report,
};
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const NXS_ID: &str = "external/notify-webhook";
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

    if args.meta.is_none() && args.crash.is_none() {
        eprintln!("error: at least one of --crash or --meta is required");
        ExitCode::Error.exit();
    }

    let meta = meta::load_or_exit(&args.meta);
    run(&args, &meta);
}

fn run(args: &Args, meta: &Meta) {
    let timeout = Duration::from_secs(args.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS));
    let event = meta.effective_event(&args.event);
    let target = meta
        .effective_target(&args.target)
        .unwrap_or_else(|| "unknown".into());
    let crash_id = meta
        .crash_id()
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".into());

    let url = extract_url(&args.rest)
        .or_else(|| env::var("NXS_WEBHOOK_URL").ok())
        .filter(|s| !s.trim().is_empty());

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    let payload = serde_json::json!({
        "nxs_id": NXS_ID,
        "nxs_version": NXS_VERSION,
        "event": event,
        "target": target,
        "crash_id": crash_id,
        "model": meta.effective_model(&args.model),
        "timestamp": ts,
        "nexsiz_version": meta.nexsiz_version,
        "outcome": meta.result.as_ref().and_then(|r| r.outcome.clone()),
    });
    let body = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".into());

    args.log(&format!(
        "id={} event={} target={} payload_len={}",
        NXS_ID,
        event,
        target,
        body.len()
    ));

    let mut report = Report::new(NXS_ID, NXS_VERSION)
        .with_target(&target)
        .with_crash_id(Some(crash_id.clone()));

    let exit = match url {
        None => {
            args.log("no webhook URL configured — dry-run (exit 0)");
            report = report
                .with_exit_hint(ExitCode::Ok)
                .with_summary("Dry-run: NXS_WEBHOOK_URL / --url not set");
            report.add_finding("payload prepared but not sent");
            ExitCode::Ok
        }
        Some(u) => match post_json(&u, &body, timeout, args.verbose) {
            Ok(status) if (200..300).contains(&status) => {
                report = report
                    .with_exit_hint(ExitCode::Ok)
                    .with_summary(format!("Webhook accepted HTTP {}", status));
                report.add_finding(format!("http_status={}", status));
                ExitCode::Ok
            }
            Ok(status) => {
                report = report
                    .with_exit_hint(ExitCode::Error)
                    .with_summary(format!("Webhook rejected HTTP {}", status));
                report.add_finding(format!("http_status={}", status));
                ExitCode::Error
            }
            Err(e) => {
                report = report
                    .with_exit_hint(ExitCode::Error)
                    .with_summary(format!("Webhook transport error: {}", e));
                report.add_finding(e);
                ExitCode::Error
            }
        },
    };

    if let Some(out) = &args.out {
        let _ = std::fs::create_dir_all(out);
        let payload_path = out.join("webhook_payload.json");
        if std::fs::write(&payload_path, &body).is_ok() {
            report.add_artifact("webhook_payload.json");
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

fn extract_url(rest: &[String]) -> Option<String> {
    let mut i = 0;
    while i < rest.len() {
        if rest[i] == "--url" && i + 1 < rest.len() {
            return Some(rest[i + 1].clone());
        }
        if let Some(v) = rest[i].strip_prefix("--url=") {
            return Some(v.to_string());
        }
        i += 1;
    }
    None
}

fn post_json(url: &str, body: &str, timeout: Duration, verbose: bool) -> Result<u16, String> {
    let (scheme, host, port, path) = parse_url(url)?;
    if scheme == "https" {
        return Err(
            "https:// not supported in pure-stdlib client; use http:// or a local TLS proxy"
                .into(),
        );
    }
    if scheme != "http" {
        return Err(format!("unsupported scheme: {}", scheme));
    }

    let addr = format!("{}:{}", host, port);
    let start = Instant::now();
    let stream = TcpStream::connect_timeout(&resolve_addr(&addr)?, timeout)
        .map_err(|e| format!("connect {}: {}", addr, e))?;

    let remaining = timeout.saturating_sub(start.elapsed());
    let _ = stream.set_read_timeout(Some(remaining));
    let _ = stream.set_write_timeout(Some(remaining));
    let mut stream = stream;

    let req = format!(
        "POST {} HTTP/1.1\r\n\
Host: {}\r\n\
User-Agent: nxs-notify-webhook/{}\r\n\
Content-Type: application/json\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        path,
        if port == 80 {
            host.to_string()
        } else {
            format!("{}:{}", host, port)
        },
        NXS_VERSION,
        body.len(),
        body
    );

    if verbose {
        eprintln!("[nxs] POST {} ({} bytes)", url, body.len());
    }

    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {}", e))?;
    let _ = stream.flush();

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 8192 {
                    break;
                }
            }
            Err(e) => {
                if buf.is_empty() {
                    return Err(format!("read: {}", e));
                }
                break;
            }
        }
    }

    let text = String::from_utf8_lossy(&buf);
    parse_status_code(&text)
}

fn parse_url(url: &str) -> Result<(String, String, u16, String), String> {
    let url = url.trim();
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else {
        return Err("URL must start with http:// or https://".into());
    };

    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.is_empty() {
        return Err("empty host".into());
    }

    let (host, port) = if let Some(i) = hostport.rfind(':') {
        let h = &hostport[..i];
        let p: u16 = hostport[i + 1..]
            .parse()
            .map_err(|_| format!("bad port in {}", hostport))?;
        (h.to_string(), p)
    } else {
        let default = if scheme == "https" { 443 } else { 80 };
        (hostport.to_string(), default)
    };

    Ok((scheme.into(), host, port, path.into()))
}

fn resolve_addr(target: &str) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    target
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {}", target))
}

fn parse_status_code(response: &str) -> Result<u16, String> {
    let line = response.lines().next().unwrap_or("");
    let mut parts = line.split_whitespace();
    let _proto = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| format!("malformed status line: {}", line))?;
    code.parse()
        .map_err(|_| format!("bad status code: {}", code))
}

fn print_help() {
    eprintln!(
        r#"nxs-notify-webhook {ver} (id={id})

POST a compact JSON notification to an external webhook.
Does not contact the fuzz target.

USAGE:
    nxs-notify-webhook --meta <path> [--url <http://...>]
    nxs-notify-webhook --crash <path> --target <host:port> [--url ...]

OPTIONS:
    --url <URL>            Webhook endpoint (overrides NXS_WEBHOOK_URL)
    --crash / --target / --meta / --out / --event / --model / --timeout / -v
                           Standard contract flags

ENVIRONMENT:
    NXS_WEBHOOK_URL        Default webhook URL

EXIT CODES:
    0  HTTP 2xx or dry-run (no URL)
    1  Transport / config / non-2xx

NOTE: Pure-stdlib client supports http:// only. For HTTPS terminate TLS
      at a local proxy or use NXS_NOTIFY_CMD with curl.
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
    );
}
