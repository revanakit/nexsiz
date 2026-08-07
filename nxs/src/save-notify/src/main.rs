//! nxs-save-notify — official existence script
//!
//! Contract id: crash/save-notify
//! Purpose    : Persist crash / hang artefacts into a stable archive tree and
//!              optionally fire an external notification hook (NXS_NOTIFY_CMD).
//!
//! Exit 0     : Archive written successfully.
//! Exit 1     : Operational error (missing input, cannot write).
//! Exit 2     : Reserved (policy-dependent external confirmation; not used by default).
//!
//! Design (red-team grade):
//! - Zero network contact with the target (safe category).
//! - Deterministic layout under --out/archive/.
//! - Optional hook is best-effort; failure does not fail the NXS.
//! - Writes report.json when --out is supplied.

use nxs_lib::{
    args::Args,
    exit::ExitCode,
    meta::{self, Meta},
    report::Report,
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const NXS_ID: &str = "crash/save-notify";
const NXS_VERSION: &str = "1.0.0";

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
    let input_path = match meta.effective_input_path(&args.crash, &args.minimized) {
        Some(p) => p,
        None => {
            eprintln!("error: no crash / minimised path resolved");
            ExitCode::Error.exit();
        }
    };

    let target = meta
        .effective_target(&args.target)
        .unwrap_or_else(|| "unknown".into());
    let event = meta.effective_event(&args.event);
    let crash_id = meta.crash_id().map(str::to_string).unwrap_or_else(|| {
        input_path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into())
    });

    args.log(&format!(
        "id={} event={} target={} input={}",
        NXS_ID,
        event,
        target,
        input_path.display()
    ));

    if !input_path.is_file() {
        eprintln!("error: input not found: {}", input_path.display());
        ExitCode::Error.exit();
    }

    let mut report = Report::new(NXS_ID, NXS_VERSION)
        .with_target(&target)
        .with_crash_id(Some(crash_id.clone()));

    // --- Archive ------------------------------------------------------------
    let out_root = args.out.clone().unwrap_or_else(|| PathBuf::from("."));
    let archive_dir = out_root.join("archive").join(&crash_id);
    if let Err(e) = fs::create_dir_all(&archive_dir) {
        eprintln!("error: mkdir {}: {}", archive_dir.display(), e);
        ExitCode::Error.exit();
    }

    let mut copied = Vec::new();

    let dest_input = archive_dir.join("input.bin");
    if let Err(e) = fs::copy(&input_path, &dest_input) {
        eprintln!("error: copy input: {}", e);
        ExitCode::Error.exit();
    }
    copied.push(format!("archive/{}/input.bin", crash_id));
    report.add_artifact(format!("archive/{}/input.bin", crash_id));

    if let Some(ref crash) = args.crash {
        if crash != &input_path && crash.is_file() {
            let dest = archive_dir.join("crash.bin");
            if fs::copy(crash, &dest).is_ok() {
                report.add_artifact(format!("archive/{}/crash.bin", crash_id));
                copied.push(format!("archive/{}/crash.bin", crash_id));
            }
        }
    }
    if let Some(ref min) = args.minimized {
        if min != &input_path && min.is_file() {
            let dest = archive_dir.join("minimized.bin");
            if fs::copy(min, &dest).is_ok() {
                report.add_artifact(format!("archive/{}/minimized.bin", crash_id));
                copied.push(format!("archive/{}/minimized.bin", crash_id));
            }
        }
    }

    if let Some(ref mp) = args.meta {
        if mp.is_file() {
            let dest = archive_dir.join("meta.json");
            if fs::copy(mp, &dest).is_ok() {
                report.add_artifact(format!("archive/{}/meta.json", crash_id));
            }
        }
    }

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let marker = serde_json::json!({
        "nxs_id": NXS_ID,
        "nxs_version": NXS_VERSION,
        "event": event,
        "target": target,
        "crash_id": crash_id,
        "timestamp": ts,
        "artifacts": copied,
    });
    let marker_path = archive_dir.join("notify.json");
    if let Ok(s) = serde_json::to_string_pretty(&marker) {
        let _ = fs::write(&marker_path, s);
        report.add_artifact(format!("archive/{}/notify.json", crash_id));
    }

    args.log(&format!(
        "archived {} files under {}",
        report.artifacts.len(),
        archive_dir.display()
    ));

    if let Ok(hook) = env::var("NXS_NOTIFY_CMD") {
        if !hook.trim().is_empty() {
            args.log("invoking NXS_NOTIFY_CMD");
            let status = Command::new("sh")
                .arg("-c")
                .arg(&hook)
                .env("NXS_EVENT", &event)
                .env("NXS_TARGET", &target)
                .env("NXS_CRASH_ID", &crash_id)
                .env("NXS_INPUT", input_path.to_string_lossy().as_ref())
                .env("NXS_ARCHIVE", archive_dir.to_string_lossy().as_ref())
                .status();
            match status {
                Ok(s) if s.success() => {
                    report.add_finding("external notify hook succeeded");
                }
                Ok(s) => {
                    report.add_finding(format!("external notify hook exit {}", s));
                }
                Err(e) => {
                    report.add_finding(format!("external notify hook failed: {}", e));
                }
            }
        }
    }

    // Capture length *before* the consuming builder chain to avoid E0382.
    let artifact_count = report.artifacts.len();
    report = report
        .with_exit_hint(ExitCode::Ok)
        .with_summary(format!(
            "Archived crash {} ({} artefacts)",
            crash_id,
            artifact_count
        ));

    if let Some(out) = &args.out {
        match report.write(out) {
            Ok(p) => args.log(&format!("report written {}", p.display())),
            Err(e) => eprintln!("warn: {}", e),
        }
    }

    if let Ok(line) = serde_json::to_string(&report) {
        println!("{}", line);
    }

    ExitCode::Ok.exit();
}

fn print_help() {
    eprintln!(
        r#"nxs-save-notify {ver} (id={id})

Archive crash / hang artefacts and optionally invoke an external notify hook.

USAGE:
    nxs-save-notify --crash <path> --target <host:port> [OPTIONS]
    nxs-save-notify --meta <path> [OPTIONS]

GLOBAL OPTIONS (contract):
    --crash <path>         Input that caused the event
    --target <host:port>   Target (recorded in artefacts)
    --event <type>         crash | hang | …
    --model <name>         Protocol model (informational)
    --minimized <path>     Prefer this over --crash for archive primary
    --meta <path>          Nexsiz metadata JSON
    --out <dir>            Archive + report.json root
    --timeout <secs>       Ignored (no network)
    -v, --verbose          Human log on stderr
    -h, --help             This help
    --version              Version + stable id

ENVIRONMENT:
    NXS_NOTIFY_CMD         Shell command invoked after archive (best-effort).
                           Receives NXS_EVENT, NXS_TARGET, NXS_CRASH_ID,
                           NXS_INPUT, NXS_ARCHIVE.

EXIT CODES:
    0  Archive written
    1  Operational error
"#,
        ver = NXS_VERSION,
        id = NXS_ID,
    );
}
