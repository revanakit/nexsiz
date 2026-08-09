//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 04/08/2026
//! Module  : nexsiz::src::monitor::logger
//!
//! Structured event logging and real-time console status reporting for fuzzing campaigns.
//!
//! Overview
//! Provides unified logging infrastructure for all fuzzing events with dual output channels:
//! - File Logging: Persistent structured logs written to `nexsiz.log` with timestamp-based
//!   severity levels for post-execution analysis and debugging.
//! - Console Output: Real-time event stream for interactive monitoring and campaign
//!   status visibility.
//!
//! Event Types
//! - INFO: General informational messages (campaign start, configuration, etc.)
//! - WARN: Non-fatal warnings requiring attention but not blocking execution
//! - STAT: Campaign statistics and status updates (periodic summaries)
//! - CRASH: Critical fault events with seed ID, execution state, elapsed time, and error context
//! - HANG: Timeout events indicating target unresponsiveness or resource exhaustion
//! - FIND: Interesting inputs discovered (new coverage or state transitions); verbose-only
//!
//! Log Output Format
//! [LEVEL] message
//! [INFO] Fuzzing campaign started
//! [CRASH] id=42 state=0x1234567890abcdef elapsed=1234ms err=Some("Segmentation fault")
//! [FIND] id=1337 new_state=true new_cov=true codes=[200,500,404] resp0="HTTP/1.1 5..."
//!
//! Verbosity Levels
//! - Quiet Mode (`verbose=false`): Only CRASH, HANG, STAT, WARN, and INFO events logged
//! - Verbose Mode (`verbose=true`): All events including FIND (interesting discoveries) logged
//!
//! Thread Safety
//! All log operations are serialized through a `Mutex<File>` to ensure consistent writes
//! in multi-threaded fuzzing contexts. Console output is flushed immediately for real-time
//! visibility.
//!
//! File Handling
//! - Log file is opened in append mode; previous logs are preserved across campaign restarts
//! - Located at `{output_dir}/nexsiz.log` with auto-creation if missing
//! - Failed writes are silently ignored to prevent campaign interruption

use crate::common::error::Result;
use crate::common::types::ExecutionResult;
use crate::common::utils::truncate_bytes;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

pub struct Logger {
    verbose: bool,
    log_file: Mutex<File>,
}

impl Logger {
    pub fn new(output_dir: &str, verbose: bool) -> Result<Self> {
        let path = Path::new(output_dir).join("nexsiz.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            verbose,
            log_file: Mutex::new(file),
        })
    }

    fn write(&self, level: &str, msg: &str) {
        let line = format!("[{}] {}\n", level, msg);
        if let Ok(mut f) = self.log_file.lock() {
            let _ = f.write_all(line.as_bytes());
        }
        // Also print to stdout for interactive use
        print!("{}", line);
        let _ = std::io::stdout().flush();
    }

    pub fn info(&self, msg: &str) {
        self.write("INFO", msg);
    }

    pub fn warn(&self, msg: &str) {
        self.write("WARN", msg);
    }

    pub fn status(&self, msg: &str) {
        self.write("STAT", msg);
    }

    pub fn crash(&self, result: &ExecutionResult) {
        self.write(
            "CRASH",
            &format!(
                "id={} state={:016x} elapsed={:?} err={:?}",
                result.seed_id, result.state_hash, result.elapsed, result.error
            ),
        );
    }

    pub fn hang(&self, result: &ExecutionResult) {
        self.write(
            "HANG",
            &format!(
                "id={} state={:016x} elapsed={:?}",
                result.seed_id, result.state_hash, result.elapsed
            ),
        );
    }

    pub fn interesting(&self, result: &ExecutionResult) {
        if self.verbose {
            let codes: Vec<String> = result.response_codes.iter().map(|c| c.to_string()).collect();
            self.write(
                "FIND",
                &format!(
                    "id={} new_state={} new_cov={} codes=[{}] resp0={}",
                    result.seed_id,
                    result.new_state,
                    result.new_coverage,
                    codes.join(","),
                    result
                        .responses
                        .first()
                        .map(|r| truncate_bytes(r, 16))
                        .unwrap_or_default()
                ),
            );
        }
    }
}
