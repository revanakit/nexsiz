//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//! Author  : Revana
//! Date    : 04/08/2026
//! Structured logging and simple console status.

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
