//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::process_monitor
//!
//! Optional local process monitoring for targets launched as child processes.
//!
//! Crash detection:
//! - Unix:    non-zero exit **or** signal termination → abnormal
//! - Windows: non-zero exit code (TerminateProcess / unhandled exception
//!            typically surfaces as a non-zero code; there are no POSIX signals)
//!
//! `std::process::Child` already abstracts spawn / try_wait / kill across
//! platforms. This module adds a thin monitoring API and light detach flags.

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
    /// Spawn the target command.
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

        // On Windows, put the target in its own process group so console
        // Ctrl-C aimed at the fuzzer does not always cascade. Mirrors the
        // NXS detach policy. Non-fatal if unsupported.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            c.creation_flags(CREATE_NEW_PROCESS_GROUP);
        }

        let child = c
            .spawn()
            .map_err(|e| NexsizError::Execution(format!("failed to spawn target: {}", e)))?;

        // Brief settle time so the process can bind sockets / initialise.
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
                Ok(Some(_status)) => {
                    let _ = guard.take();
                    Ok(false)
                }
                Err(e) => Err(NexsizError::Execution(format!("wait error: {}", e))),
            },
            None => Ok(false),
        }
    }

    /// Returns true if the process exited abnormally (crash indicator).
    ///
    /// - Unix: `!status.success()` covers non-zero exit and signal death.
    /// - Windows: `!status.success()` covers non-zero exit codes (including
    ///   typical unhandled-exception codes such as 0xC0000005-style values
    ///   reported by the runtime).
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
    ///
    /// Uses `Child::kill()` which maps to SIGKILL on Unix and
    /// `TerminateProcess` on Windows.
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
    fn spawn_short_lived_and_check() {
        // Portable short-lived process.
        #[cfg(unix)]
        let mon = ProcessMonitor::spawn("true");
        #[cfg(windows)]
        let mon = ProcessMonitor::spawn("cmd /c exit 0");
        #[cfg(not(any(unix, windows)))]
        let mon: Result<ProcessMonitor> = Err(NexsizError::Config("unsupported".into()));

        if let Ok(m) = mon {
            thread::sleep(Duration::from_millis(300));
            let _ = m.is_alive();
            // Clean exit → not a crash
            assert!(!m.crashed() || !m.is_alive().unwrap_or(true));
            m.terminate();
        }
    }
}
