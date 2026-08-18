//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::snapshot::null
//!
//! Purpose:
//! A deterministic, no-op SnapshotProvider used to represent the disabled or
//! opt-out state for snapshotting within the fuzzer. This provider performs no
//! process management, produces no images, and intentionally never fails with
//! I/O errors — it exists to simplify caller logic when snapshot functionality
//! is not required or must be stubbed in tests.
//!
//! Responsibilities:
//! - Implement the SnapshotProvider contract with safe, side-effect-free
//!   operations: prepare(), take_snapshot(), restore(), terminate() are all
//!   no-ops and return success.
//! - Signal disabled status via is_enabled() -> false so higher-level logic can
//!   fall back to respawn/prepare behaviour.
//! - Provide an optimistic is_alive() to avoid false negatives when no process
//!   is managed by this provider.
//!
//! Semantics:
//! - name() -> "null"
//! - is_enabled() -> false (explicitly indicates no snapshot work will be done)
//! - prepare/take_snapshot/restore/terminate -> Ok(()) / no-op
//! - is_alive() -> true (the provider does not manage a process handle)
//! - crashed() -> false
//!
//! Design notes & usage:
//! - Use NullSnapshot for unit tests, CI environments without snapshot support,
//!   or when the operator intentionally disables snapshotting for a run.
//! - Because it performs no I/O, NullSnapshot cannot detect real process state
//!   and should not be used where snapshot semantics or image persistence are
//!   required.
//! - To add snapshot behaviour, implement SnapshotProvider with concrete
//!   process management and image lifecycle (see criu.rs for an example).
//!
//! See also: SnapshotProvider trait and other providers in this module
//! (criu.rs) for real snapshot lifecycle implementations.

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
