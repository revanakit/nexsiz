//! NEXSIZ – Snapshot / restore abstraction for target process state
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Phase 1: Foundation.
//!   - SnapshotProvider trait
//!   - NullSnapshot          (zero cost, default)
//!   - ProcessRestartSnapshot (kill + respawn via target_cmd)
//!   - CriuSnapshot          (feature "criu" — shell-out to criu)
//!
//! Design goals:
//!   - Pure-stdlib default path
//!   - Zero behaviour change when snapshot is disabled
//!   - Single ownership of process lifecycle when enabled
//!   - Extensible for Phase 2 desocketing / Phase 3 cost-aware scheduling

mod null;
mod process;

#[cfg(feature = "criu")]
mod criu;

pub use null::NullSnapshot;
pub use process::ProcessRestartSnapshot;

#[cfg(feature = "criu")]
pub use criu::CriuSnapshot;

use crate::common::error::{NexsizError, Result};
use std::path::PathBuf;

/// Capability contract for any snapshot backend.
///
/// Lifecycle expected by Engine:
///   1. `prepare()`          – spawn / attach, reach initial ready state
///   2. `take_snapshot()`    – capture clean state (may be a no-op for ProcessRestart)
///   3. … fuzzing …
///   4. on crash / hang → `restore()` then continue
///   5. campaign end   → `terminate()`
pub trait SnapshotProvider: Send + Sync {
    fn name(&self) -> &str;

    /// Whether this provider is actually performing snapshot work.
    fn is_enabled(&self) -> bool;

    /// Initial setup: spawn target (if needed) and reach a known-good state.
    fn prepare(&mut self) -> Result<()>;

    /// Capture current process state as the restore point.
    /// For ProcessRestart this is typically a no-op marker.
    /// For CRIU this performs `criu dump`.
    fn take_snapshot(&mut self) -> Result<()>;

    /// Restore target to the last successful snapshot.
    fn restore(&mut self) -> Result<()>;

    /// True if the managed process is still alive (best-effort).
    fn is_alive(&self) -> bool;

    /// True if the process exited abnormally since last check (crash indicator).
    fn crashed(&self) -> bool;

    /// Force-kill the managed process (campaign teardown).
    fn terminate(&mut self);

    /// Optional path where snapshot images live (CRIU).
    fn image_dir(&self) -> Option<&PathBuf> {
        None
    }
}

/// Resolve the concrete provider from config.
///
/// Rules:
///   - snapshot == false          → NullSnapshot
///   - backend == "null"          → NullSnapshot
///   - backend == "process"       → ProcessRestartSnapshot (requires target_cmd)
///   - backend == "criu"          → CriuSnapshot when feature enabled, else ProcessRestart
///   - no target_cmd              → NullSnapshot (with warning)
pub fn resolve_snapshot(
    enabled: bool,
    backend: &str,
    target_cmd: Option<&str>,
    output_dir: &str,
) -> Box<dyn SnapshotProvider> {
    if !enabled {
        return Box::new(NullSnapshot::new());
    }

    let backend = backend.to_ascii_lowercase();
    match backend.as_str() {
        "null" | "none" | "off" => Box::new(NullSnapshot::new()),

        "criu" => {
            #[cfg(feature = "criu")]
            {
                if let Some(cmd) = target_cmd {
                    match CriuSnapshot::new(cmd, output_dir) {
                        Ok(s) => return Box::new(s),
                        Err(e) => {
                            eprintln!(
                                "[nexsiz] warning: CRIU provider failed ({}), falling back to process restart",
                                e
                            );
                        }
                    }
                } else {
                    eprintln!(
                        "[nexsiz] warning: snapshot_backend=criu requires target_cmd; falling back to null"
                    );
                    return Box::new(NullSnapshot::new());
                }
            }
            #[cfg(not(feature = "criu"))]
            {
                eprintln!(
                    "[nexsiz] warning: snapshot_backend=criu requested but binary built without `criu` feature; \
                     falling back to process restart. Rebuild with: cargo build --release --features criu"
                );
            }
            // fall through to process
            if let Some(cmd) = target_cmd {
                match ProcessRestartSnapshot::new(cmd) {
                    Ok(s) => Box::new(s),
                    Err(e) => {
                        eprintln!(
                            "[nexsiz] warning: process snapshot failed ({}), using null",
                            e
                        );
                        Box::new(NullSnapshot::new())
                    }
                }
            } else {
                Box::new(NullSnapshot::new())
            }
        }

        // default / "process"
        _ => {
            if let Some(cmd) = target_cmd {
                match ProcessRestartSnapshot::new(cmd) {
                    Ok(s) => Box::new(s),
                    Err(e) => {
                        eprintln!(
                            "[nexsiz] warning: process snapshot failed ({}), using null",
                            e
                        );
                        Box::new(NullSnapshot::new())
                    }
                }
            } else {
                eprintln!(
                    "[nexsiz] warning: snapshot=true but no target_cmd; snapshot disabled (null)"
                );
                Box::new(NullSnapshot::new())
            }
        }
    }
}

/// Convenience helper used by Engine after a crash is observed.
pub fn maybe_restore(provider: &mut dyn SnapshotProvider) -> Result<()> {
    if !provider.is_enabled() {
        return Ok(());
    }
    provider.restore()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_is_disabled() {
        let n = NullSnapshot::new();
        assert!(!n.is_enabled());
        assert_eq!(n.name(), "null");
    }

    #[test]
    fn resolve_disabled_returns_null() {
        let p = resolve_snapshot(false, "process", Some("sleep 10"), "output");
        assert!(!p.is_enabled());
    }
}
