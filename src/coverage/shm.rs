//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::coverage::shm
//!
//!
//! Purpose
//! -------
//! Compatibility shim providing a backward-compatible handle (`ShmMap`) for the
//! legacy POSIX shared-memory coverage map API. This module delegates all
//! operations to the platform abstraction layer (`crate::platform::SharedMemory`)
//! so existing call sites that reference `coverage::shm::ShmMap` continue to
//! compile and behave as before while the canonical implementation lives in
//! `crate::platform`.
//!
//! Guarantees & Semantics
//! ----------------------
//! - This type is a thin adapter: it does not implement coverage storage
//!   itself but forwards calls to a boxed `SharedMemory` implementation supplied
//!   by the platform layer.
//! - Error propagation follows the platform implementation; `open` returns a
//!   `Result<ShmMap, String>` where the error is the platform error converted
//!   to a string.
//! - Not intended for new code. Treat this module as a transitional compatibility
//!   layer that will be removed once all users migrate to the platform API.
//!
//! Migration / Recommended Usage
//! ---------------------------
//! Instead of using this adapter directly in new code, call into the platform
//! API which exposes the canonical coverage map factory. Example:
//!
//! ```ignore
//! // preferred: create a platform-native coverage map
//! platform::current().create_coverage_map(id)?
//! ```
//!
//! Deprecation Notice
//! ------------------
//! As of 2026-08-13 this module is deprecated in favor of `crate::platform`'s
//! implementations (e.g. `LinuxSharedMemory`). Keep usage here only to support
//! legacy call sites; remove references and migrate to `platform::current()`
//! as part of ongoing refactoring.

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
