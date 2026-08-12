//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 12/08/2026
//! Module  : nexsiz::src::coverage::shm
//!
//! POSIX Shared-Memory Coverage Map (Linux)
//! ---------------------------------------
//! Provides a thin, low-overhead wrapper around a POSIX shm-backed coverage
//! bitmap compatible with AFL-style instrumentation. The region layout and
//! semantics match classic map-based coverage collectors: a MAP_SIZE (64 KiB)
//! byte array where each slot stores a saturating per-edge hit count.
//!
//! Naming and attachment:
//! - Default name: /nexsiz-cov
//! - With explicit id: /nexsiz-cov-<id>  (leading '/' accepted)
//! - External instrumentation agents (Frida, LD_PRELOAD, helper daemons) may
//!   open the same name and write hit counts concurrently.
//!
//! Behaviour and guarantees:
//! - On first creation the region is truncated to MAP_SIZE and zero-initialised.
//! - mmap is used with MAP_SHARED and PROT_READ|PROT_WRITE to expose the bytes.
//! - clear() zeroes the entire region before a run; snapshot() copies the
//!   current contents into an in-process Vec<u8> for analysis/merging.
//! - get(idx) reads a single byte slot (bounds-checked to return 0 on OOB).
//! - Drop closes and unmaps the descriptor but intentionally does NOT call
//!   shm_unlink so other processes and future fuzzer runs can reattach to the
//!   same name; cleaning up /dev/shm is left to the operator.
//!
//! Concurrency, safety and performance:
//! - The implementation marks ShmMap Send+Sync because the underlying bytes
//!   are process-shared; external writers may mutate slots concurrently.
//! - The design accepts AFL-like races: lost updates under contention are
//!   tolerated, and callers should use the fuzzer's single-threaded reset/collect
//!   barriers to provide higher-level synchronization where required.
//! - Hot-path operations avoid locking and use simple byte reads/writes to
//!   minimise instrumentation overhead; heavy merging or bookkeeping should be
//!   performed off the hot path.
//!
//! Error semantics and robustness:
//! - open() tries to attach to an existing region first, then creates with
//!   O_CREAT|O_EXCL and gracefully handles races by retrying the open path.
//! - Failures from shm_open, ftruncate, mmap, or fcntl-like calls are surfaced
//!   as descriptive Err(String) values to let callers decide recovery strategies.
//!
//! Implementation guidance:
//! - Keep resource acquisition (ftruncate/mmap) local to the provider; avoid
//!   performing unrelated work while holding descriptors or mappings.
//! - Avoid automatic unlinking on drop to prevent surprising teardown of
//!   external instrumentation workflows; provide an explicit operator-facing
//!   helper if unlink semantics are ever required.

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
