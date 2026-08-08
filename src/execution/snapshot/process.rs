//! Process-restart snapshot provider.
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Captures no memory image. On restore we kill the child and respawn
//! `target_cmd`. Suitable for targets that reach a usable state quickly
//! after start (e.g. many network daemons). Phase 2 will add desocketing
//! so protocol state can be restored without full TCP teardown.

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
