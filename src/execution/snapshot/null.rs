//! Null snapshot provider — zero cost, no process management.
//! Author  : Revana
//! Date    : 08/08/2026

use super::SnapshotProvider;
use crate::common::error::Result;

#[derive(Debug, Default)]
pub struct NullSnapshot;

impl NullSnapshot {
    pub fn new() -> Self {
        Self
    }
}

impl SnapshotProvider for NullSnapshot {
    fn name(&self) -> &str {
        "null"
    }

    fn is_enabled(&self) -> bool {
        false
    }

    fn prepare(&mut self) -> Result<()> {
        Ok(())
    }

    fn take_snapshot(&mut self) -> Result<()> {
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        Ok(())
    }

    fn is_alive(&self) -> bool {
        true // optimistic; we do not manage a process
    }

    fn crashed(&self) -> bool {
        false
    }

    fn terminate(&mut self) {}
}
