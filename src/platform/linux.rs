//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::platfrom::linux
//!
//! Linux POSIX shared-memory coverage provider.
//!
//! This module implements linux-specific PlatformServices by providing a
//! POSIX shared-memory backed coverage map using shm_open(3) / ftruncate(2) / mmap(2).
//! It is the production path for grey-box coverage collection on Linux and other
//! POSIX-compatible systems that support POSIX shared memory.
//!
//! Responsibilities:
//! - Create or open a named shared memory object sized to COVERAGE_MAP_SIZE.
//! - Ensure newly-created regions are zero-initialized and sized via ftruncate.
//! - Map the region with PROT_READ | PROT_WRITE and MAP_SHARED so multiple
//!   processes can observe and update the coverage map concurrently.
//! - Expose a LinuxSharedMemory type that implements the SharedMemory trait
//!   and a LinuxPlatform that implements PlatformServices.
//!
//! Concurrency and safety model:
//! - The coverage region is treated as a raw byte array; callers may perform
//!   single-byte reads/writes. This code deliberately accepts AFL-style races
//!   from concurrent external writers and does not provide inter-process
//!   synchronization. Higher-level synchronization (if required) must be
//!   provided by the consumer.
//! - LinuxSharedMemory is marked Send + Sync because access is limited to
//!   raw byte operations; users must respect the above concurrency assumptions.
//!
//! Lifecycle and cleanup semantics:
//! - On Drop the mapping is munmap(2)ed and the descriptor closed.
//! - The shared memory object is intentionally NOT shm_unlink(3)'d on Drop so
//!   other processes or subsequent runs can reattach to the same name. If
//!   permanent cleanup is desired, unlink must be performed explicitly by an
//!   external actor.
//!
//! Error handling and security:
//! - System call failures are returned as PlatformError with OS diagnostics.
//! - When creating shared memory the module uses mode 0o600 (owner read/write)
//!   to limit access; avoid exposing predictable names in untrusted environments.

use super::{PlatformError, PlatformServices, SharedMemory, COVERAGE_MAP_SIZE};
use std::ffi::CString;
use std::ptr;

/// Linux platform services.
pub struct LinuxPlatform;

impl PlatformServices for LinuxPlatform {
    fn create_coverage_map(
        &self,
        id: Option<&str>,
    ) -> Result<Box<dyn SharedMemory>, PlatformError> {
        let map = LinuxSharedMemory::open(id)?;
        Ok(Box::new(map))
    }
}

/// POSIX shared-memory coverage region (Linux).
pub struct LinuxSharedMemory {
    name: String,
    ptr: *mut u8,
    len: usize,
    fd: i32,
    /// True if we created the object.
    created: bool,
}

// SAFETY: SHM is process-shared; we only touch bytes through single-byte
// ops and synchronize via the fuzzer's single-threaded collect/reset barriers.
// External agents write concurrently — AFL-style races are accepted.
unsafe impl Send for LinuxSharedMemory {}
unsafe impl Sync for LinuxSharedMemory {}

impl LinuxSharedMemory {
    /// Open or create a named SHM region of COVERAGE_MAP_SIZE bytes.
    pub fn open(id: Option<&str>) -> Result<Self, PlatformError> {
        let name = match id {
            Some(s) if !s.is_empty() => {
                if s.starts_with('/') {
                    s.to_string()
                } else {
                    format!("/nexsiz-cov-{}", s)
                }
            }
            _ => "/nexsiz-cov".to_string(),
        };

        let c_name = CString::new(name.as_str())
            .map_err(|e| PlatformError(e.to_string()))?;

        // Try open existing first
        let mut created = false;
        let mut fd = unsafe {
            libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0o600)
        };

        if fd < 0 {
            // Create
            fd = unsafe {
                libc::shm_open(
                    c_name.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )
            };
            if fd < 0 {
                // Race: another process created it — open again
                fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0o600) };
                if fd < 0 {
                    return Err(PlatformError(format!(
                        "shm_open({}) failed: {}",
                        name,
                        std::io::Error::last_os_error()
                    )));
                }
            } else {
                created = true;
                if unsafe { libc::ftruncate(fd, COVERAGE_MAP_SIZE as libc::off_t) } != 0 {
                    unsafe {
                        libc::close(fd);
                        libc::shm_unlink(c_name.as_ptr());
                    }
                    return Err(PlatformError(format!(
                        "ftruncate({}) failed: {}",
                        name,
                        std::io::Error::last_os_error()
                    )));
                }
            }
        }

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                COVERAGE_MAP_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(PlatformError(format!(
                "mmap({}) failed: {}",
                name,
                std::io::Error::last_os_error()
            )));
        }

        if created {
            unsafe {
                ptr::write_bytes(ptr as *mut u8, 0, COVERAGE_MAP_SIZE);
            }
        }

        Ok(Self {
            name,
            ptr: ptr as *mut u8,
            len: COVERAGE_MAP_SIZE,
            fd,
            created,
        })
    }
}

impl SharedMemory for LinuxSharedMemory {
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

impl Drop for LinuxSharedMemory {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                libc::munmap(self.ptr as *mut libc::c_void, self.len);
            }
            if self.fd >= 0 {
                libc::close(self.fd);
            }
            // Intentionally do NOT shm_unlink so external agents and
            // subsequent campaign runs can reattach to the same name.
            let _ = self.created;
        }
    }
}
