//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::snapshot::criu
//!
//! Summary:
//! This module provides a SnapshotProvider implementation that invokes the
//! external `criu` binary to perform process CRIU dump/restore operations for
//! target processes spawned by the fuzzer. It manages the target process
//! lifecycle (spawn, kill), stores CRIU image files under the configured
//! output directory, and converts criu outcomes into the SnapshotProvider
//! contract used by the rest of the system.
//!
//! High-level behavior:
//! - prepare(): ensure a fresh working directory, (re)spawn the target process
//!   and mark the provider ready to take a dump.
//! - take_snapshot(): run `criu dump -D <image_dir> ... --leave-running` against
//!   the currently owned pid, leaving the process running and persisting an
//!   image set for later restore.
//! - restore(): if an image exists, kill any locally-owned process, then call
//!   `criu restore -D <image_dir> ... -d` to recreate the process tree as a
//!   daemon; when no image exists, prepare() is used as a fallback spawn.
//! - is_alive()/crashed(): best-effort liveness / crash detection using the
//!   locally-held Child handle when available; after a restore the provider may
//!   no longer retain a Child and therefore relies on image & ready flags.
//!
//! Requirements & operational notes:
//! - The `criu` binary must be installed and available on PATH. The constructor
//!   performs an availability check (`criu --version`) and returns a config
//!   error if not present.
//! - Restoring with CRIU typically requires elevated privileges (root or a set
//!   of Linux capabilities such as CAP_SYS_ADMIN and CAP_SYS_PTRACE) and kernel
//!   features that match the checkpointed process environment. The caller
//!   should ensure the running environment supports criu usage.
//! - CRIU behavior is platform- and kernel-version-sensitive; images are not
//!   necessarily portable across hosts or kernel upgrades — expect restore
//!   failures in such cases and treat them as Execution errors.
//!
//! Image lifecycle & persistence:
//! - Image files are stored under <output_dir>/snapshot/criu/ by default.
//! - prepare() clears any previous images and spawns a fresh target.
//! - take_snapshot() clears the image directory before creating a new dump.
//! - terminate() intentionally leaves images on disk to allow post-mortem
//!   inspection unless explicit cleanup is requested by higher-level code.
//!
//! Concurrency & process management:
//! - The implementation tracks the spawned process via a Mutex-protected
//!   Option<Child> to allow safe access from multiple callers (is_alive/crashed).
//!  - After a successful CRIU restore the module does not retain a Child handle
//!   (criu becomes the process parent); therefore pid is unknown and liveness
//!   checks fall back to the has_snapshot/ready indicators.
//!
//! Error handling & semantics:
//! - I/O and criu failures are mapped to the crate's NexsizError variants and
//!   returned to callers; non-zero criu exit codes are treated as Execution
//!   errors and surface the exit code in the message.
//! - Small sleeps are used to allow spawned/restored processes to settle; these
//!   are conservative and intended to avoid races with bind/listen operations.
//!
//! Design rationale and safety:
//! - This provider intentionally performs best-effort cleanup and conservative
//!   restore behavior: on irrecoverable errors the code falls back to respawn
//!   (prepare) rather than attempting risky in-place fixes.
//! - The implementation minimizes stdout noise by redirecting criu stdout to
//!   /dev/null while preserving stderr for diagnostic messages; consider logging
//!   or piping stderr for debugging in development runs.
//!
//! Testing & extension:
//! - Unit tests should validate constructor failures (missing criu), correct
//!   image dir handling, and the provider's SnapshotProvider contract.
//! - Integration tests that exercise real dumps/restores must be run on a host
//!   with CRIU installed and appropriate privileges; these tests are environment
//!   sensitive and may be skipped in CI unless the runner supports criu.
//!
//! See also: SnapshotProvider trait (prepare/take_snapshot/restore/is_alive/...)
//! and the execution connector and process spawning helpers used elsewhere in
//! the project.

use super::SnapshotProvider;
use crate::common::error::{NexsizError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

pub struct CriuSnapshot {
    cmd: String,
    image_dir: PathBuf,
    child: Arc<Mutex<Option<Child>>>,
    pid: Option<u32>,
    has_snapshot: bool,
    ready: bool,
}

impl CriuSnapshot {
    pub fn new(cmd: &str, output_dir: &str) -> Result<Self> {
        if cmd.trim().is_empty() {
            return Err(NexsizError::Config("empty target_cmd for CRIU snapshot".into()));
        }
        // Quick availability check
        let status = Command::new("criu")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => {}
            _ => {
                return Err(NexsizError::Config(
                    "criu binary not found or not executable (install criu and ensure it is on PATH)"
                        .into(),
                ));
            }
        }

        let image_dir = PathBuf::from(output_dir).join("snapshot").join("criu");
        fs::create_dir_all(&image_dir).map_err(NexsizError::Io)?;

        Ok(Self {
            cmd: cmd.to_string(),
            image_dir,
            child: Arc::new(Mutex::new(None)),
            pid: None,
            has_snapshot: false,
            ready: false,
        })
    }

    fn spawn_child(&mut self) -> Result<()> {
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
        let pid = child.id();
        *self.child.lock().unwrap() = Some(child);
        self.pid = Some(pid);
        // Settle time for bind / listen
        thread::sleep(Duration::from_millis(300));
        Ok(())
    }

    fn kill_current(&mut self) {
        let mut guard = self.child.lock().unwrap();
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.pid = None;
    }

    fn run_criu_dump(&self, pid: u32) -> Result<()> {
        // Leave running processes, dump into image_dir
        let status = Command::new("criu")
            .args([
                "dump",
                "-t",
                &pid.to_string(),
                "-D",
                self.image_dir.to_str().unwrap_or("."),
                "--shell-job",
                "-j",
                "--leave-running",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|e| NexsizError::Execution(format!("criu dump failed to start: {}", e)))?;

        if !status.success() {
            return Err(NexsizError::Execution(format!(
                "criu dump exited with {:?}",
                status.code()
            )));
        }
        Ok(())
    }

    fn run_criu_restore(&self) -> Result<()> {
        // Restore into a new process tree. We do not keep a Child handle
        // after restore because criu becomes the parent; we track via pid file
        // if present, otherwise best-effort.
        let status = Command::new("criu")
            .args([
                "restore",
                "-D",
                self.image_dir.to_str().unwrap_or("."),
                "--shell-job",
                "-j",
                "-d", // restore as daemon
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .map_err(|e| NexsizError::Execution(format!("criu restore failed to start: {}", e)))?;

        if !status.success() {
            return Err(NexsizError::Execution(format!(
                "criu restore exited with {:?}",
                status.code()
            )));
        }
        // Give restored process a moment
        thread::sleep(Duration::from_millis(200));
        Ok(())
    }

    fn clear_images(&self) -> Result<()> {
        if self.image_dir.exists() {
            for entry in fs::read_dir(&self.image_dir).map_err(NexsizError::Io)? {
                let entry = entry.map_err(NexsizError::Io)?;
                let path = entry.path();
                if path.is_file() {
                    let _ = fs::remove_file(path);
                }
            }
        }
        Ok(())
    }
}

impl SnapshotProvider for CriuSnapshot {
    fn name(&self) -> &str {
        "criu"
    }

    fn is_enabled(&self) -> bool {
        true
    }

    fn prepare(&mut self) -> Result<()> {
        self.kill_current();
        self.clear_images()?;
        self.spawn_child()?;
        self.ready = true;
        self.has_snapshot = false;
        Ok(())
    }

    fn take_snapshot(&mut self) -> Result<()> {
        if !self.ready {
            self.prepare()?;
        }
        let pid = self.pid.ok_or_else(|| {
            NexsizError::Execution("no pid available for criu dump".into())
        })?;
        self.clear_images()?;
        self.run_criu_dump(pid)?;
        self.has_snapshot = true;
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        if !self.has_snapshot {
            // No dump yet → fall back to clean respawn
            return self.prepare();
        }
        // Kill any residual process we still own
        self.kill_current();
        self.run_criu_restore()?;
        self.ready = true;
        // pid is unknown after daemon restore; is_alive becomes best-effort
        self.pid = None;
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
            // After criu restore we may not hold a Child; assume alive if snapshot exists
            None => self.has_snapshot && self.ready,
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
        // Leave images on disk for post-mortem inspection
    }

    fn image_dir(&self) -> Option<&PathBuf> {
        Some(&self.image_dir)
    }
}

impl Drop for CriuSnapshot {
    fn drop(&mut self) {
        self.terminate();
    }
}
