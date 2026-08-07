//! NEXSIZ – POSIX shared-memory coverage map (Linux)
//! Author  : Revana
//! Date    : 05/08/2026
//!
//! Layout (identical to AFL / SharedMapCoverage):
//!   65536 bytes, each byte = saturating hit count for one edge slot.
//!
//! Name convention:
//!   /nexsiz-cov           (default)
//!   /nexsiz-cov-<id>      (when an id is supplied)
//!
//! Nexsiz is the creator/owner; external agents (Frida, LD_PRELOAD, …)
//! open the same name with O_RDWR and write hits. reset() zeroes the region;
//! collect() snapshots it into the in-process virgin/seen logic.

use crate::coverage::provider::MAP_SIZE;
use std::ffi::CString;
use std::ptr;

/// Handle to a mapped POSIX shared-memory coverage region.
pub struct ShmMap {
    name: String,
    ptr: *mut u8,
    len: usize,
    fd: i32,
    /// True if we created the object (responsible for unlink on drop is optional).
    created: bool,
}

// SAFETY: SHM is process-shared; we only touch bytes through volatile/atomic-like
// single-byte ops and synchronize via the fuzzer's single-threaded collect/reset
// barriers between executions. External agents write concurrently — which is the
// intended AFL-style race (hits may be lost under contention; acceptable).
unsafe impl Send for ShmMap {}
unsafe impl Sync for ShmMap {}

impl ShmMap {
    /// Open or create a named SHM region of MAP_SIZE bytes.
    pub fn open(id: Option<&str>) -> Result<Self, String> {
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

        let c_name = CString::new(name.as_str()).map_err(|e| e.to_string())?;

        // Try open existing first
        let mut created = false;
        let mut fd = unsafe {
            libc::shm_open(
                c_name.as_ptr(),
                libc::O_RDWR,
                0o600,
            )
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
                fd = unsafe {
                    libc::shm_open(c_name.as_ptr(), libc::O_RDWR, 0o600)
                };
                if fd < 0 {
                    return Err(format!(
                        "shm_open({}) failed: {}",
                        name,
                        std::io::Error::last_os_error()
                    ));
                }
            } else {
                created = true;
                if unsafe { libc::ftruncate(fd, MAP_SIZE as libc::off_t) } != 0 {
                    unsafe {
                        libc::close(fd);
                        libc::shm_unlink(c_name.as_ptr());
                    }
                    return Err(format!(
                        "ftruncate({}) failed: {}",
                        name,
                        std::io::Error::last_os_error()
                    ));
                }
            }
        }

        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                MAP_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return Err(format!(
                "mmap({}) failed: {}",
                name,
                std::io::Error::last_os_error()
            ));
        }

        if created {
            unsafe {
                ptr::write_bytes(ptr as *mut u8, 0, MAP_SIZE);
            }
        }

        Ok(Self {
            name,
            ptr: ptr as *mut u8,
            len: MAP_SIZE,
            fd,
            created,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Zero the entire coverage region (call at start of each execution).
    pub fn clear(&self) {
        unsafe {
            ptr::write_bytes(self.ptr, 0, self.len);
        }
    }

    /// Snapshot current SHM contents into a Vec.
    pub fn snapshot(&self) -> Vec<u8> {
        let mut out = vec![0u8; self.len];
        unsafe {
            ptr::copy_nonoverlapping(self.ptr, out.as_mut_ptr(), self.len);
        }
        out
    }

    /// Read a single slot.
    #[inline]
    pub fn get(&self, idx: usize) -> u8 {
        if idx >= self.len {
            return 0;
        }
        unsafe { *self.ptr.add(idx) }
    }
}

impl Drop for ShmMap {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                libc::munmap(self.ptr as *mut libc::c_void, self.len);
            }
            if self.fd >= 0 {
                libc::close(self.fd);
            }
            // Intentionally do NOT shm_unlink here so external agents and
            // subsequent campaign runs can reattach to the same name.
            // Operator can `rm /dev/shm/nexsiz-cov*` if needed.
            let _ = self.created;
        }
    }
}
