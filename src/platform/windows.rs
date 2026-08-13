//! Windows platform implementation (Phase 0 stub).
//!
//! Phase 2 will implement shared memory via CreateFileMapping / MapViewOfFile.

use super::{PlatformError, PlatformServices, SharedMemory};

pub struct WindowsPlatform;

impl PlatformServices for WindowsPlatform {
    fn create_coverage_map(
        &self,
        _id: Option<&str>,
    ) -> Result<Box<dyn SharedMemory>, PlatformError> {
        Err(PlatformError(
            "Windows coverage map not yet implemented (Phase 2)".into(),
        ))
    }
}
