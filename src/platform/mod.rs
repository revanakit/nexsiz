//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 14/08/2026
//! Module  : nexsiz::src::platform::mod
//!
//! Platform abstraction layer for Nexsiz — OS-specific primitives and contracts.
//!
//! This module defines the portable interface and invariants for platform-level
//! services used by the fuzzer (shared memory coverage regions, process/group
//! semantics, file-mapping backends, etc.). It intentionally isolates all
//! operating-system dependencies behind the `SharedMemory` and
//! `PlatformServices` traits so the core fuzzer logic remains cross-platform.
//!
//! Key responsibilities:
//! - Provide a stable, process-shareable coverage region of size
//!   `COVERAGE_MAP_SIZE` and guarantee the `SharedMemory` contract.
//! - Offer platform-specific implementations (Linux POSIX SHM, Windows file
//!   mappings) behind a uniform `create_coverage_map` factory.
//! - Document lifecycle, concurrency, and security expectations for callers
//!   interacting with the raw coverage region.
//!
//! Important invariants and semantics:
//! - COVERAGE_MAP_SIZE must remain in sync with the runtime coverage consumer
//!   (e.g., coverage::MAP_SIZE). Implementations must expose exactly that many
//!   bytes and treat the region as a raw byte array.
//! - The shared region is intended for single-byte reads/writes from multiple
//!   processes; this layer does NOT provide inter-process synchronization.
//!   Higher-level synchronization (if required) is the caller's responsibility.
//! - Newly created regions should be zero-initialized; implementations must
//!   ensure proper sizing (ftruncate / SetEndOfFile) before mapping.
//!
//! Security and deployment notes:
//! - Default permissions should limit access (e.g., 0o600 on POSIX). Avoid
//!   predictable global names in multi-tenant or untrusted environments.
//! - Implementations may intentionally avoid unlinking shared objects on Drop
//!   to allow reattachment by external agents; explicit cleanup must be done by
//!   an external controller when permanent removal is desired.
//!
//! Extensibility:
//! - Add platform backends by implementing `SharedMemory` + `PlatformServices`
//!   and gating them behind cfg(target_os = "...") in this module.
//!
//! Naming conventions for external agents:
//! - Linux:   `/nexsiz-cov` or `/nexsiz-cov-<id>`
//! - Windows: `Local\nexsiz-cov` or `Local\nexsiz-cov-<id>`

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
        // expanded in later phases.
        compile_error!("Nexsiz platform layer: unsupported target_os (only linux/windows for now)");
    }
}
