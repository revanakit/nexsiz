//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 09/08/2026
//! Module  : nexsiz::src::nxs::reaper
//!
//! Asynchronous NXS exit-code reaper.
//!
//! Keeps the fuzzing hot-path non-blocking while still honouring the design
//! requirement to observe exit codes and escalate on exit 2 (secondary finding).
//!
//! Architecture:
//!   - Spawn returns a `Child` immediately.
//!   - Child is handed to a background reaper thread via an unbounded channel.
//!   - Reaper polls with `try_wait` (no blocking wait on the fuzzer threads).
//!   - On exit:
//!       * logs the code
//!       * if code == 2 → records a secondary finding (JSONL + atomic counter)
//!
//! Exit-code mapping:
//!   - Normal exit → `status.code()` (Unix and Windows)
//!   - Unix signal death → mapped to exit 4 (Interrupted / cancelled per CONTRACT)
//!   - Windows: no POSIX signals; if `status.code()` is None (rare, e.g. still
//!     running edge cases already filtered by try_wait) → treat as exit 1
//!
//! The reaper is started once (lazy) when the first NXS is submitted.
//! Process-local only; no shared state across processes.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Campaign-wide secondary finding counter (exit code 2).
pub static SECONDARY_FINDINGS: AtomicU64 = AtomicU64::new(0);

/// Metadata that travels with the Child so the reaper can produce useful logs.
struct Tracked {
    nxs_id: String,
    event: String,
    crash_id: String,
    out_dir: Option<PathBuf>,
    /// Parent campaign output_dir (for secondary findings file).
    campaign_out: PathBuf,
    child: Child,
    started: Instant,
}

static TX: OnceLock<Sender<Tracked>> = OnceLock::new();

/// Ensure the background reaper is running. Idempotent.
fn ensure_reaper() {
    if TX.get().is_some() {
        return;
    }
    let (tx, rx) = channel::<Tracked>();
    // Ignore race — only one thread will succeed the set.
    if TX.set(tx).is_err() {
        return;
    }
    thread::Builder::new()
        .name("nxs-reaper".into())
        .spawn(move || reaper_loop(rx))
        .expect("failed to spawn nxs-reaper thread");
}

/// Hand a freshly spawned Child to the async reaper.
///
/// `campaign_out` is the top-level Nexsiz output directory (used for the
/// secondary-findings JSONL).
pub fn submit(
    nxs_id: &str,
    event: &str,
    crash_id: &str,
    out_dir: Option<&str>,
    campaign_out: &str,
    child: Child,
) {
    ensure_reaper();
    if let Some(tx) = TX.get() {
        let tracked = Tracked {
            nxs_id: nxs_id.to_string(),
            event: event.to_string(),
            crash_id: crash_id.to_string(),
            out_dir: out_dir.map(PathBuf::from),
            campaign_out: PathBuf::from(campaign_out),
            child,
            started: Instant::now(),
        };
        // Non-blocking send; if the channel is somehow closed we just drop.
        let _ = tx.send(tracked);
    }
}

fn reaper_loop(rx: Receiver<Tracked>) {
    let mut pending: Vec<Tracked> = Vec::with_capacity(32);
    let poll = Duration::from_millis(250);

    loop {
        // Drain newly submitted children (non-blocking).
        loop {
            match rx.try_recv() {
                Ok(t) => pending.push(t),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Channel closed → drain remaining then exit.
                    while let Ok(t) = rx.try_recv() {
                        pending.push(t);
                    }
                    // Final wait with short timeout so we don't hang forever.
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while !pending.is_empty() && Instant::now() < deadline {
                        reap_once(&mut pending);
                        thread::sleep(poll);
                    }
                    return;
                }
            }
        }

        if pending.is_empty() {
            // Idle: block briefly waiting for the next submission so we don't spin.
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(t) => pending.push(t),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
            continue;
        }

        reap_once(&mut pending);
        thread::sleep(poll);
    }
}

fn reap_once(pending: &mut Vec<Tracked>) {
    pending.retain_mut(|t| {
        match t.child.try_wait() {
            Ok(Some(status)) => {
                handle_exit(t, status);
                false // remove from pending
            }
            Ok(None) => true, // still running
            Err(e) => {
                eprintln!(
                    "[nexsiz/nxs] reaper: try_wait failed for {} ({}): {}",
                    t.nxs_id, t.crash_id, e
                );
                false
            }
        }
    });
}

fn handle_exit(t: &Tracked, status: ExitStatus) {
    let code = status.code().unwrap_or_else(|| {
        // Signal termination on Unix → treat as non-success operational.
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                eprintln!(
                    "[nexsiz/nxs] {} (event={} crash={}) terminated by signal {}",
                    t.nxs_id, t.event, t.crash_id, sig
                );
                return 4; // Interrupted / cancelled per CONTRACT
            }
        }
        // Windows (and any other non-Unix): no POSIX signals. A missing
        // exit code after try_wait reported Some(status) is unexpected;
        // map to operational failure.
        1
    });

    let elapsed_ms = t.started.elapsed().as_millis();

    // Always log the observed exit code (design requirement).
    eprintln!(
        "[nexsiz/nxs] exit {} → {} (event={} crash={} elapsed={}ms)",
        t.nxs_id, code, t.event, t.crash_id, elapsed_ms
    );

    // CONTRACT exit 2 = further vulnerability / exploit-assist → secondary finding.
    if code == 2 {
        let prev = SECONDARY_FINDINGS.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[nexsiz/nxs] SECONDARY FINDING #{} from {} (event={} crash={})",
            prev + 1,
            t.nxs_id,
            t.event,
            t.crash_id
        );
        record_secondary_finding(t, code, elapsed_ms);
    }

    // Optional: write a tiny exit sidecar next to the NXS out dir if present.
    if let Some(ref dir) = t.out_dir {
        let sidecar = dir.join("exit_code");
        let _ = fs::write(&sidecar, format!("{}
", code));
    }
}

fn record_secondary_finding(t: &Tracked, code: i32, elapsed_ms: u128) {
    let findings_dir = t.campaign_out.join("nxs-findings");
    if let Err(e) = fs::create_dir_all(&findings_dir) {
        eprintln!("[nexsiz/nxs] cannot create nxs-findings: {}", e);
        return;
    }
    let path = findings_dir.join("secondary.jsonl");

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);

    // Minimal JSON line — forward-compatible, no serde.
    let line = format!(
        "{{\"timestamp\":{:.3},\"nxs_id\":\"{}\",\"event\":\"{}\",\"crash_id\":\"{}\",\"exit_code\":{},\"elapsed_ms\":{},\"kind\":\"secondary\"}}\n",
        ts,
        escape(&t.nxs_id),
        escape(&t.event),
        escape(&t.crash_id),
        code,
        elapsed_ms
    );

    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            if let Err(e) = f.write_all(line.as_bytes()) {
                eprintln!("[nexsiz/nxs] write secondary finding failed: {}", e);
            }
        }
        Err(e) => eprintln!("[nexsiz/nxs] open secondary.jsonl failed: {}", e),
    }
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out
}

/// Snapshot of secondary findings observed so far (for status / final stats).
pub fn secondary_count() -> u64 {
    SECONDARY_FINDINGS.load(Ordering::Relaxed)
}
