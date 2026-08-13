//! Linux platform implementation (Phase 0 stub).
//!
//! The real POSIX SHM logic currently lives in `coverage::shm`.
//! In Phase 1 it will be moved behind the `SharedMemory` trait defined here.

use super::{PlatformError, PlatformServices, SharedMemory, COVERAGE_MAP_SIZE};

pub struct LinuxPlatform;

impl PlatformServices for LinuxPlatform {
    fn create_coverage_map(
        &self,
        _id: Option<&str>,
    ) -> Result<Box<dyn SharedMemory>, PlatformError> {
        // Phase 0: not yet wired. Phase 1 will call into the existing ShmMap.
        Err(PlatformError(
            "Linux coverage map not yet migrated to platform layer (Phase 1)".into(),
        ))
    }
}

// Keep COVERAGE_MAP_SIZE in sync with the rest of the crate.
#[allow(dead_code)]
pub const MAP_SIZE: usize = COVERAGE_MAP_SIZE;
