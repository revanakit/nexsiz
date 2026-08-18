//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::snapshot::mod
//!
//! Purpose:
//!   Provide the SnapshotProvider trait and runtime resolver for concrete snapshot
//!   backends. This module centralises snapshot lifecycle management, backend
//!   selection, and the small convenience helper used by the Engine to attempt
//!   a restore after a crash is observed.
//!
//! Key responsibilities:
//!   - Define the SnapshotProvider capability contract (thread-safe: Send + Sync).
//!   - Implement resolution logic that maps configuration (enabled flag,
//!     backend name, optional target command, output directory) to a concrete
//!     provider instance (Null, ProcessRestart, optional CRIU when enabled).
//!   - Provide clear fallback behaviour and warning messages when a requested
//!     backend is unavailable or fails to initialize.
//!   - Expose a minimal helper (maybe_restore) consumed by the Engine to trigger
//!     restores when appropriate.
//!
//! SnapshotProvider lifecycle (expected by the Engine):
//!   1. prepare()       — arrange the target process and reach a known-good state
//!   2. take_snapshot() — capture the restore point (no-op for some backends)
//!   3. ...fuzzing...   — normal iterative fuzzing work occurs here
//!   4. restore()       — re-instate the last snapshot on crash/hang, then bump epoch
//!   5. terminate()    — force teardown at campaign end
//!
//! Behavioural & configuration notes:
//!   - When `enabled == false` or backend == "null", a NullSnapshot is used and
//!     operations become no-ops; this preserves behaviour when snapshotting is
//!     explicitly disabled.
//!   - The "process" backend performs process-level restart snapshots and
//!     requires a target_cmd; failures to initialize a provider fall back to
//!     NullSnapshot with a stderr warning to aid runtime diagnostics.
//!   - The "criu" backend is compiled only when the `criu` cargo feature is
//!     enabled; when requested but not available the code falls back to the
//!     process restart implementation and emits an informative warning.
//!   - Providers should implement best-effort liveness and crash detection via
//!     is_alive() and crashed() respectively; these signals are advisory and
//!     may be backend-dependent.
//!
//! Thread-safety & ownership:
//!   - SnapshotProvider implementors are Send + Sync to allow safe sharing from
//!     Engine-managed worker threads while keeping process lifecycle ownership
//!     centralised in the Engine.
//!
//! Testing and maintenance:
//!   - Unit tests in this module validate basic resolution and the NullSnapshot
//!     behaviour. Implementations should expose deterministic and testable
//!     behaviour for prepare/take_snapshot/restore to make integration tests
//!     reliable.

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
///   4. on crash / hang → `restore()` then bump restore_epoch
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
