//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 09/08/2026
//! Module  : nexsiz::src::common::utils
//! 
//! Module purpose
//! - Collection of lightweight utilities used across the codebase: a small deterministic PRNG,
//!   fast non-cryptographic hashing, time helpers, and byte formatting/manipulation helpers.
//!
//! Public responsibilities
//! - XorShift64: a compact, deterministic xorshift64* PRNG intended for reproducible experiments,
//!   fuzz scheduling and non-cryptographic randomness. NOT suitable for cryptographic uses.
//! - hash_bytes / hash_combine: fast, non-cryptographic hashing for coverage and state-tracking.
//! - Timer / format_duration: simple wall-clock timing and human-friendly duration formatting for logs.
//! - hex_encode / truncate_bytes: concise byte buffer formatting for debug/log output.
//! - clamp: generic utility to constrain values to a given range.
//!
//! Design notes & guarantees
//! - Performance: implemented for low latency and minimal allocations — safe to call frequently in hot loops.
//! - Determinism: XorShift64 yields reproducible sequences when initialized with the same seed.
//! - Threading: XorShift64 stores internal state and is not thread-safe by itself; clone per-thread if needed.
//! - Hash stability: DefaultHasher (std) is used for speed. Hash values are intended for internal
//!   coverage/state-tracking and may vary across std versions/targets — do not rely on cross-platform stability.
//!
//! Usage guidance
//! - For reproducible fuzz runs, create XorShift64 with a fixed seed. Use from_entropy() only for non-deterministic runs.
//! - For security-sensitive randomness or cryptographic purposes, use a dedicated cryptographic RNG from a vetted crate.
//! - Use hash_bytes for quick buffer summaries in coverage/state logic; use a stronger/fixed algorithm when long-term
//!   fingerprint stability is required.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Simple deterministic xorshift64* PRNG (no external crate needed).
#[derive(Clone, Debug)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    pub fn new(seed: u64) -> Self {
        // Avoid zero state
        let state = if seed == 0 { 0xdeadbeefcafebabe } else { seed };
        Self { state }
    }

    pub fn from_entropy() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x123456789abcdef0);
        Self::new(seed)
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    #[inline]
    pub fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }

    #[inline]
    pub fn next_bool(&mut self, prob: f64) -> bool {
        if prob <= 0.0 {
            return false;
        }
        if prob >= 1.0 {
            return true;
        }
        (self.next_u64() as f64 / u64::MAX as f64) < prob
    }

    /// Choose a random index with optional bias toward lower values (for energy scheduling).
    pub fn choose_biased(&mut self, len: usize) -> usize {
        if len <= 1 {
            return 0;
        }
        // Square-root bias
        let r = (self.next_u64() as f64 / u64::MAX as f64).sqrt();
        (r * len as f64) as usize
    }
}

/// Fast non-cryptographic hash for coverage / state tracking.
#[inline]
pub fn hash_bytes(data: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    hasher.finish()
}

/// Combine two hashes (order-sensitive).
#[inline]
pub fn hash_combine(a: u64, b: u64) -> u64 {
    a.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(b)
}

/// Pretty-print a duration for logging.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Simple wall-clock timer.
pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Clamp a value into [min, max].
#[inline]
pub fn clamp<T: PartialOrd>(v: T, min: T, max: T) -> T {
    if v < min {
        min
    } else if v > max {
        max
    } else {
        v
    }
}

/// Hex encode a byte slice (for logging small buffers).
pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Truncate a byte slice for display.
pub fn truncate_bytes(data: &[u8], max: usize) -> String {
    if data.len() <= max {
        hex_encode(data)
    } else {
        format!("{}\u{2026}", hex_encode(&data[..max]))
    }
}
