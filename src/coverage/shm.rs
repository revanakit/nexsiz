//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::coverage::shm
//!
//! Compatibility layer for POSIX Shared-Memory Coverage Map.
//!
//! (2026-08-13)**: The canonical implementation has moved to
//! `crate::platform` (LinuxSharedMemory). This module now provides a thin
//! adapter so existing call sites that still reference `coverage::shm::ShmMap`
//! continue to compile. New code should use:
//!
//! ```ignore
//! platform::current().create_coverage_map(id)
//! ```
//!
//! The adapter will be removed once all call sites have migrated.

use crate::platform::{self, SharedMemory};

/// Compatibility handle. Prefer `platform::SharedMemory` in new code.
pub struct ShmMap {
    inner: Box<dyn SharedMemory>,
}

impl ShmMap {
    /// Open or create a named SHM region (delegates to platform layer).
    pub fn open(id: Option<&str>) -> Result<Self, String> {
        let inner = platform::current()
            .create_coverage_map(id)
            .map_err(|e| e.to_string())?;
        Ok(Self { inner })
    }

    pub fn name(&self) -> &str {
        self.inner.name()
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.inner.snapshot()
    }

    pub fn get(&self, idx: usize) -> u8 {
        self.inner.get(idx)
    }
}
