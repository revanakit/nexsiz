//! Windows named file-mapping coverage provider.
//!
//! This module provides the Windows-specific PlatformServices implementation
//! using named file mappings (CreateFileMappingW / MapViewOfFile) as the
//! backing store for the shared coverage region. This is the grey-box coverage
//! collection path for Windows targets.
//!
//! Primary responsibilities:
//! - Create or attach to a named, pagefile-backed file mapping sized to
//!   COVERAGE_MAP_SIZE bytes.
//! - Ensure newly-created mappings are zero-initialized prior to use.
//! - Map the region with read/write access so multiple processes or external
//!   agents (e.g. Frida) can concurrently read/update the coverage map.
//! - Export WindowsSharedMemory implementing SharedMemory and WindowsPlatform
//!   implementing PlatformServices.
//!
//! Naming and namespace semantics:
//! - Default object name: `Local\nexsiz-cov`
//! - Campaign-specific: `Local\nexsiz-cov-<id>`
//! - The `Local\` prefix places objects in the current session namespace and
//!   avoids elevation; use `Global\` only when cross-session sharing is
//!   explicitly required.
//!
//! Concurrency and safety model:
//! - Treat the coverage region as a raw byte array intended for single-byte
//!   reads/writes. This module intentionally accepts AFL-style races from
//!   concurrent external writers and does not provide inter-process
//!   synchronization. Higher-level synchronization, if required, must be
//!   implemented by the caller or campaign coordinator.
//! - WindowsSharedMemory is marked Send + Sync because access is limited to
//!   byte-level operations; callers must observe the concurrency assumptions.
//!
//! Lifecycle and cleanup semantics:
//! - CreateFileMappingW may return ERROR_ALREADY_EXISTS during races — such
//!   cases are treated as attach-to-existing (race-safe pattern).
//! - On Drop: UnmapViewOfFile and CloseHandle are invoked to release per-process
//!   resources. The named kernel object is intentionally NOT destroyed here so
//!   external agents and subsequent runs can reattach; explicit unlinking must
//!   be performed by an external controller when permanent cleanup is desired.
//!
//! Security and deployment notes:
//! - Mappings created by this module are pagefile-backed by default (INVALID_HANDLE_VALUE).
//! - Access control is governed by Windows ACLs; avoid predictable names in
//!   multi-tenant or untrusted deployments and perform explicit access control
//!   outside this module when necessary.
//!
//! Error handling and diagnostics:
//! - Windows API failures are converted into PlatformError including GetLastError
//!   codes to aid operator/developer diagnostics.

use super::{PlatformError, PlatformServices, SharedMemory, COVERAGE_MAP_SIZE};
use std::ptr;

/// Windows platform services.
pub struct WindowsPlatform;

impl PlatformServices for WindowsPlatform {
    fn create_coverage_map(
        &self,
        id: Option<&str>,
    ) -> Result<Box<dyn SharedMemory>, PlatformError> {
        let map = WindowsSharedMemory::open(id)?;
        Ok(Box::new(map))
    }
}

// ---------------------------------------------------------------------------
// Minimal Windows API surface (no external crate)
// ---------------------------------------------------------------------------

#[allow(non_snake_case)]
mod ffi {
    use std::os::raw::{c_void, c_ulong};

    pub type HANDLE = *mut c_void;
    pub type BOOL = i32;
    pub type DWORD = c_ulong;
    pub type SIZE_T = usize;

    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const NULL: HANDLE = ptr::null_mut();
    pub const PAGE_READWRITE: DWORD = 0x04;
    pub const FILE_MAP_ALL_ACCESS: DWORD = 0x000F_001F;
    pub const ERROR_ALREADY_EXISTS: DWORD = 183;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateFileMappingW(
            hFile: HANDLE,
            lpFileMappingAttributes: *mut c_void,
            flProtect: DWORD,
            dwMaximumSizeHigh: DWORD,
            dwMaximumSizeLow: DWORD,
            lpName: *const u16,
        ) -> HANDLE;

        pub fn OpenFileMappingW(
            dwDesiredAccess: DWORD,
            bInheritHandle: BOOL,
            lpName: *const u16,
        ) -> HANDLE;

        pub fn MapViewOfFile(
            hFileMappingObject: HANDLE,
            dwDesiredAccess: DWORD,
            dwFileOffsetHigh: DWORD,
            dwFileOffsetLow: DWORD,
            dwNumberOfBytesToMap: SIZE_T,
        ) -> *mut c_void;

        pub fn UnmapViewOfFile(lpBaseAddress: *const c_void) -> BOOL;

        pub fn CloseHandle(hObject: HANDLE) -> BOOL;

        pub fn GetLastError() -> DWORD;
    }

    use std::ptr;
}

/// Named File Mapping coverage region (Windows).
pub struct WindowsSharedMemory {
    name: String,
    ptr: *mut u8,
    len: usize,
    handle: ffi::HANDLE,
}

// SAFETY: The mapping is process-shared; we only perform single-byte reads/
// writes and rely on the fuzzer's single-threaded reset/collect barriers.
// Concurrent writes from Frida are AFL-style races and are accepted.
unsafe impl Send for WindowsSharedMemory {}
unsafe impl Sync for WindowsSharedMemory {}

impl WindowsSharedMemory {
    /// Open or create a named file mapping of COVERAGE_MAP_SIZE bytes.
    pub fn open(id: Option<&str>) -> Result<Self, PlatformError> {
        // Build a Windows object name. Prefer Local\ so no elevation is required.
        let name = match id {
            Some(s) if !s.is_empty() => {
                // Strip leading / or \ if the caller passed a POSIX-style name
                let cleaned = s.trim_start_matches(|c| c == '/' || c == '\\');
                if cleaned.starts_with("Local\\") || cleaned.starts_with("Global\\") {
                    cleaned.to_string()
                } else if cleaned.starts_with("nexsiz-cov") {
                    format!("Local\\{}", cleaned)
                } else {
                    format!("Local\\nexsiz-cov-{}", cleaned)
                }
            }
            _ => "Local\\nexsiz-cov".to_string(),
        };

        let wide_name = to_wide(&name);

        // Try to open an existing mapping first (same pattern as Linux).
        let mut handle = unsafe {
            ffi::OpenFileMappingW(ffi::FILE_MAP_ALL_ACCESS, 0, wide_name.as_ptr())
        };

        let created;
        if handle.is_null() {
            // Create a new pagefile-backed mapping.
            // INVALID_HANDLE_VALUE (-1) = pagefile-backed (not a real file).
            handle = unsafe {
                ffi::CreateFileMappingW(
                    ffi::INVALID_HANDLE_VALUE,
                    ptr::null_mut(),
                    ffi::PAGE_READWRITE,
                    0, // high size
                    COVERAGE_MAP_SIZE as ffi::DWORD,
                    wide_name.as_ptr(),
                )
            };

            if handle.is_null() {
                return Err(PlatformError(format!(
                    "CreateFileMappingW({}) failed: error {}",
                    name,
                    unsafe { ffi::GetLastError() }
                )));
            }

            // ERROR_ALREADY_EXISTS means another process won the race and the
            // handle still refers to the existing object — treat as attach.
            created = unsafe { ffi::GetLastError() } != ffi::ERROR_ALREADY_EXISTS;
        } else {
            created = false;
        }

        let view = unsafe {
            ffi::MapViewOfFile(
                handle,
                ffi::FILE_MAP_ALL_ACCESS,
                0,
                0,
                COVERAGE_MAP_SIZE,
            )
        };

        if view.is_null() {
            let err = unsafe { ffi::GetLastError() };
            unsafe { ffi::CloseHandle(handle) };
            return Err(PlatformError(format!(
                "MapViewOfFile({}) failed: error {}",
                name, err
            )));
        }

        if created {
            unsafe {
                ptr::write_bytes(view as *mut u8, 0, COVERAGE_MAP_SIZE);
            }
        }

        Ok(Self {
            name,
            ptr: view as *mut u8,
            len: COVERAGE_MAP_SIZE,
            handle,
        })
    }
}

impl SharedMemory for WindowsSharedMemory {
    fn name(&self) -> &str {
        &self.name
    }

    fn clear(&self) {
        unsafe {
            ptr::write_bytes(self.ptr, 0, self.len);
        }
    }

    fn snapshot(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.len];
        unsafe {
            ptr::copy_nonoverlapping(self.ptr, out.as_mut_ptr(), self.len);
        }
        out
    }

    fn get(&self, idx: usize) -> u8 {
        if idx >= self.len {
            return 0;
        }
        unsafe { *self.ptr.add(idx) }
    }

    unsafe fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for WindowsSharedMemory {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                ffi::UnmapViewOfFile(self.ptr as *const _);
            }
            if !self.handle.is_null() {
                ffi::CloseHandle(self.handle);
            }
            // Intentionally do NOT destroy the named object so external agents
            // and subsequent campaign runs can reattach.
        }
    }
}

/// Convert a Rust &str to a null-terminated UTF-16 buffer for Win32 APIs.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0u16)).collect()
}
