//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//! Author  : Revana
//! Date    : 04/08/2026
//! Optional local process monitoring for targets launched as child processes.
//! Detects crashes via non-zero exit / signal termination.

use crate::common::error::{NexsizError, Result};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Manages an optional target child process.
pub struct ProcessMonitor {
    child: Arc<Mutex<Option<Child>>>,
    cmd: String,
}

impl ProcessMonitor {
    /// Spawn the target command. Returns None if no command is configured.
    pub fn spawn(cmd: &str) -> Result<Self> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
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

        // Brief settle time
        thread::sleep(Duration::from_millis(200));

        Ok(Self {
            child: Arc::new(Mutex::new(Some(child))),
            cmd: cmd.to_string(),
        })
    }

    /// Check whether the process is still alive.
    /// Returns Ok(true) if running, Ok(false) if exited, Err on I/O issues.
    pub fn is_alive(&self) -> Result<bool> {
        let mut guard = self.child.lock().unwrap();
        match guard.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(None) => Ok(true),
                Ok(Some(status)) => {
                    // Process has exited
                    let _ = guard.take();
                    if status.success() {
                        Ok(false)
                    } else {
                        // Non-zero or signalled → treat as crash-like death
                        Ok(false)
                    }
                }
                Err(e) => Err(NexsizError::Execution(format!("wait error: {}", e))),
            },
            None => Ok(false),
        }
    }

    /// Returns true if the process exited abnormally (crash indicator).
    pub fn crashed(&self) -> bool {
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

    pub fn cmd(&self) -> &str {
        &self.cmd
    }

    /// Kill the child if still running.
    pub fn terminate(&self) {
        let mut guard = self.child.lock().unwrap();
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_sleep_and_check() {
        // Use a very short-lived process
        let mon = ProcessMonitor::spawn("sleep 0.1");
        // May fail on platforms without sleep; just ensure API works
        if let Ok(m) = mon {
            thread::sleep(Duration::from_millis(300));
            let _ = m.is_alive();
            m.terminate();
        }
    }
}
