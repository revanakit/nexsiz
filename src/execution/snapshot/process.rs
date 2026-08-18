//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::snapshot::process
//!
//!
//! Purpose:
//! A simple SnapshotProvider that implements snapshot semantics by killing and
//! respawning the target process instead of capturing an in-memory image. This
//! backend is appropriate for targets that reach a usable state quickly after
//! start (for example, many network daemons) and when full process checkpointing
//! is not available or desired.
//!
//! High-level behavior:
//! - prepare(): ensure any previous child is terminated, spawn a fresh process,
//!   and mark the provider ready.
//! - take_snapshot(): no memory image is produced; the provider records a
//!   logical "clean point" after a successful prepare/restore so callers may
//!   treat subsequent restores as a revert to that clean start state.
//! - restore(): perform a kill + respawn cycle to return the target to the
//!   known-good start state.
//! - is_alive()/crashed(): best-effort checks using the locally-held Child
//!   handle; when no Child is held these return false (no process managed).
//!
//! Responsibilities & invariants:
//! - Manage the target process lifecycle using a Mutex-protected Option<Child>
//!   so the provider can be safely queried from multiple contexts.
//! - Use short, conservative sleeps after spawn to give processes time to bind
//!   sockets and become ready; these reduce race conditions but are intentionally
//!   small to keep test throughput high.
//! - Map spawn failures and invalid configuration (empty command) to NexsizError
//!   variants so callers can surface configuration/execution problems.
//!
//! Design notes & rationale:
//! - This provider favors determinism and simplicity: kills and respawns are
//!   reliable across environments compared to environment-sensitive checkpoint
//!   tooling, at the cost of requiring full process restart between restores.
//! - Counters and complex image lifecycle are omitted by design — this is a
//!   pragmatic fallback for environments where CRIU or other snapshotting is
//!   unavailable or unnecessary for the target workload.
//! - The implementation uses saturating/robust state transitions: terminate()
//!   always clears the Child and resets ready/has_snapshot flags to avoid stale
//!   state across runs.
//!
//! Testing & extension:
//! - Unit tests should validate constructor validation (empty command), prepare/
//!   restore flow, and is_alive/crashed semantics using short-lived commands.
//! - To provide richer snapshot semantics, implement a SnapshotProvider that
//!   creates and restores persistent images (see criu.rs for an example).
//!
//! See also: SnapshotProvider trait and other snapshot backends in this module
//! (criu.rs, null.rs) for alternative snapshot strategies and trade-offs.

use super::SnapshotProvider;
use crate::common::error::{NexsizError, Result};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct ProcessRestartSnapshot {
    cmd: String,
    child: Arc<Mutex<Option<Child>>>,
    /// True after a successful prepare / restore cycle.
    ready: bool,
    /// Snapshot marker — ProcessRestart does not dump memory; this only
    /// records that a clean point was established.
    has_snapshot: bool,
}

impl ProcessRestartSnapshot {
    pub fn new(cmd: &str) -> Result<Self> {
        if cmd.trim().is_empty() {
            return Err(NexsizError::Config("empty target_cmd for process snapshot".into()));
        }
        Ok(Self {
            cmd: cmd.to_string(),
            child: Arc::new(Mutex::new(None)),
            ready: false,
            has_snapshot: false,
        })
    }

    fn spawn_child(&self) -> Result<Child> {
        let parts: Vec<&str> = self.cmd.split_whitespace().collect();
        if parts.is_empty() {
            return Err(NexsizError::Config("empty target_cmd".into()));
        }
        let mut c = Command::new(parts[0]);
        if parts.len() > 1 {
            c.args(&parts[1..]);
        }
        c.stdout(Stdio::null()).stderr(Stdio::null());
        let child = c
            .spawn()
            .map_err(|e| NexsizError::Execution(format!("failed to spawn target: {}", e)))?;
        // Brief settle so the process can bind sockets etc.
        thread::sleep(Duration::from_millis(250));
        Ok(child)
    }

    fn kill_current(&self) {
        let mut guard = self.child.lock().unwrap();
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl SnapshotProvider for ProcessRestartSnapshot {
    fn name(&self) -> &str {
        "process"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    fn prepare(&mut self) -> Result<()> {
        self.kill_current();
        let child = self.spawn_child()?;
        *self.child.lock().unwrap() = Some(child);
        self.ready = true;
        Ok(())
    }

    fn take_snapshot(&mut self) -> Result<()> {
        if !self.ready {
            self.prepare()?;
        }
        // No memory dump; just mark that a clean point exists.
        self.has_snapshot = true;
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        // Kill + respawn is the restore strategy for this backend.
        self.kill_current();
        let child = self.spawn_child()?;
        *self.child.lock().unwrap() = Some(child);
        self.ready = true;
        // Snapshot marker remains valid (same clean start state).
        self.has_snapshot = true;
        Ok(())
    }

    fn is_alive(&self) -> bool {
        let mut guard = self.child.lock().unwrap();
        match guard.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(None) => true,
                Ok(Some(_)) => {
                    let _ = guard.take();
                    false
                }
                Err(_) => false,
            },
            None => false,
        }
    }

    fn crashed(&self) -> bool {
        let mut guard = self.child.lock().unwrap();
        match guard.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(status)) => {
                    let abnormal = !status.success();
                    let _ = guard.take();
                    abnormal
                }
                _ => false,
            },
            None => false,
        }
    }

    fn terminate(&mut self) {
        self.kill_current();
        self.ready = false;
        self.has_snapshot = false;
    }
}

impl Drop for ProcessRestartSnapshot {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_name() {
        let p = ProcessRestartSnapshot::new("sleep 0.05").unwrap();
        assert_eq!(p.name(), "process");
        assert!(p.is_enabled());
    }
}
