//! Platform abstraction layer for Nexsiz.
//!
//! This module isolates OS-specific primitives (shared memory, process group
//! semantics, etc.) so that the rest of the fuzzer remains portable.
//!
//! Phase 0 (2026-08-13): traits + skeleton only.
//! Phase 1 will move the existing Linux SHM implementation behind these traits
//! and add a Windows File Mapping implementation.

use std::fmt;

/// Size of the AFL-style coverage map (must stay in sync with coverage::MAP_SIZE).
pub const COVERAGE_MAP_SIZE: usize = 65536;

/// Error type for platform operations.
#[derive(Debug)]
pub struct PlatformError(pub String);

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "platform error: {}", self.0)
    }
}

impl std::error::Error for PlatformError {}

impl From<String> for PlatformError {
    fn from(s: String) -> Self {
        PlatformError(s)
    }
}

impl From<&str> for PlatformError {
    fn from(s: &str) -> Self {
        PlatformError(s.to_string())
    }
}

/// Shared-memory coverage region.
///
/// Implementations must provide a process-shareable byte array of
/// `COVERAGE_MAP_SIZE` bytes that external agents (Frida, etc.) can write to.
pub trait SharedMemory: Send + Sync {
    /// Human-readable name of the region (for logging / agent configuration).
    fn name(&self) -> &str;

    /// Zero the entire region (called at the start of each execution).
    fn clear(&self);

    /// Snapshot the current contents into an owned buffer.
    fn snapshot(&self) -> Vec<u8>;

    /// Read a single slot (bounds-checked; returns 0 on OOB).
    fn get(&self, idx: usize) -> u8;

    /// Raw mutable pointer for advanced / FFI use. Callers must respect
    /// the length of `COVERAGE_MAP_SIZE`.
    ///
    /// # Safety
    /// The returned pointer is valid for the lifetime of `self` and points to
    /// a region of exactly `COVERAGE_MAP_SIZE` bytes.
    unsafe fn as_mut_ptr(&self) -> *mut u8;
}

/// Platform services that differ across operating systems.
pub trait PlatformServices: Send + Sync {
    /// Create or attach to a coverage shared-memory region.
    ///
    /// `id` may be used to disambiguate multiple concurrent campaigns.
    fn create_coverage_map(
        &self,
        id: Option<&str>,
    ) -> Result<Box<dyn SharedMemory>, PlatformError>;
}

// ---------------------------------------------------------------------------
// Platform selection
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

/// Return the platform services for the current target.
pub fn current() -> &'static dyn PlatformServices {
    #[cfg(target_os = "linux")]
    {
        &linux::LinuxPlatform
    }
    #[cfg(target_os = "windows")]
    {
        &windows::WindowsPlatform
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        // Fallback for other Unix-like targets (macOS, etc.) — will be
        // expanded in later phases. For now we reuse the Linux path where
        // POSIX SHM is available.
        compile_error!("Nexsiz platform layer: unsupported target_os (only linux/windows for now)");
    }
}
