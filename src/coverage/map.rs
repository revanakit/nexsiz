//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//! 
//! Author  : Revana
//! Date    : 09-07-2026
//! Module  : nexsiz::src::coverage::map
//!
//! High-performance edge coverage tracking system with hybrid feedback support.
//!
//! Overview
//! Provides a 64 KiB edge map with per-edge hit-count buckets for tracking code execution
//! paths during fuzzing. Supports both in-process and POSIX shared-memory (SHM) modes for
//! seamless integration with external instrumentation agents (e.g., Frida, LD_PRELOAD).
//!
//! Architecture
//!
//! Execution Modes
//! - In-Process Mode (default): Standalone edge tracking when SHM is unavailable.
//!   Suitable for statically instrumented targets or when external agents are not needed.
//!
//! - POSIX SHM Mode (Linux): Attaches to a shared-memory region written by external
//!   instrumentation agents. Provides unified feedback by merging remote hits with local
//!   synthetic edges on each collection cycle.
//!
//! Feedback Generation
//! - SHM Synchronization: External agent hits are pulled into the in-process map at
//!   collection time. Max semantics preserve synthetic response edges.
//!
//! - Synthetic Response Edges: Always injected (hybrid mode). Edges are derived from:
//!   - Response status code chains (sequential hashing)
//!   - Response body fingerprints (first 32 bytes)
//!   - Execution outcome classification (5 distinct outcome classes)
//!
//! - Virgin Map Tracking: Maintains persistent record of all edges ever observed.
//!   First hit increments the unique edge counter; subsequent hits reuse virgin entry.
//!
//! Performance Notes
//! - All bucket updates use `Ordering::Relaxed` atomics (single-threaded collection model).
//! - SHM snapshot is taken once per collection; edge injection happens after.
//! - Map hash is computed incrementally during virgin map scan for compact representation.
//!
//! Data Flow
//!
//! Reset → [SHM Clear + In-Process Clear]
//!   ↓
//! Execution → [External Agent writes to SHM]
//!   ↓
//! Collect → Pull SHM → Inject Response Edges → Scan Virgin → Return Feedback

use crate::common::types::ExecutionResult;
use crate::common::utils::{hash_bytes, hash_combine};
use crate::coverage::provider::{CoverageFeedback, CoverageProvider, MAP_SIZE};
use crate::coverage::shm::ShmMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;

/// High-performance coverage map provider.
pub struct SharedMapCoverage {
    /// Current execution bitmap (cleared every reset).
    current: Vec<AtomicU8>,
    /// Global virgin/seen map – first hit of an edge is recorded here.
    virgin: Mutex<Vec<u8>>,
    /// Running total of unique edges ever seen.
    total_edges: AtomicU64,
    /// Optional POSIX shared-memory region (external agent writes here).
    shm: Option<ShmMap>,
    /// Whether to merge synthetic response edges (always true for hybrid).
    inject_response: bool,
}

impl SharedMapCoverage {
    pub fn new() -> Self {
        Self::with_shm_id(None)
    }

    /// Create with optional SHM id (`None` → try default `/nexsiz-cov`).
    /// If SHM open fails, falls back to pure in-process map (still functional).
    pub fn with_shm_id(id: Option<&str>) -> Self {
        let mut current = Vec::with_capacity(MAP_SIZE);
        current.resize_with(MAP_SIZE, || AtomicU8::new(0));

        let shm = match ShmMap::open(id) {
            Ok(m) => {
                eprintln!("[nexsiz] coverage SHM attached: {}", m.name());
                Some(m)
            }
            Err(e) => {
                // Non-fatal: in-process map still works
                if id.is_some() {
                    eprintln!("[nexsiz] coverage SHM unavailable ({}); using in-process map", e);
                }
                None
            }
        };

        Self {
            current,
            virgin: Mutex::new(vec![0u8; MAP_SIZE]),
            total_edges: AtomicU64::new(0),
            shm,
            inject_response: true,
        }
    }

    pub fn with_shm(id: impl Into<String>) -> Self {
        Self::with_shm_id(Some(&id.into()))
    }

    /// SHM name if attached.
    pub fn shm_name(&self) -> Option<&str> {
        self.shm.as_ref().map(|s| s.name())
    }

    #[inline]
    fn hit_edge(&self, edge: usize) {
        let idx = edge % MAP_SIZE;
        let cell = &self.current[idx];
        let _ = cell.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(1))
        });
    }

    fn inject_response_edges(&self, result: &ExecutionResult) {
        let mut prev = 0u64;
        for &code in &result.response_codes {
            let edge = hash_combine(prev, code as u64) as usize;
            self.hit_edge(edge);
            prev = code as u64;
        }

        for resp in &result.responses {
            let slice = if resp.len() > 32 { &resp[..32] } else { resp };
            if !slice.is_empty() {
                let h = hash_bytes(slice);
                self.hit_edge(h as usize);
                self.hit_edge(hash_combine(h, result.state_hash) as usize);
            }
        }

        let outcome_edge = match result.outcome {
            crate::common::types::OutcomeClass::Ok => 0xA11,
            crate::common::types::OutcomeClass::ConnectionReset => 0xDEAD,
            crate::common::types::OutcomeClass::Hang => 0xA4E6,
            crate::common::types::OutcomeClass::Crash => 0xC0A5,
            crate::common::types::OutcomeClass::Error => 0xE770,
        };
        self.hit_edge(outcome_edge);
    }

    /// Pull hits from SHM into the in-process current map.
    fn pull_shm(&self) {
        if let Some(ref shm) = self.shm {
            let snap = shm.snapshot();
            for (i, &hits) in snap.iter().enumerate() {
                if hits > 0 {
                    let cell = &self.current[i];
                    // Take max so local synthetic edges are preserved
                    let _ = cell.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.max(hits))
                    });
                }
            }
        }
    }
}

impl Default for SharedMapCoverage {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageProvider for SharedMapCoverage {
    fn name(&self) -> &str {
        if self.shm.is_some() {
            "map+shm"
        } else {
            "map"
        }
    }

    fn reset(&self) {
        for cell in &self.current {
            cell.store(0, Ordering::Relaxed);
        }
        if let Some(ref shm) = self.shm {
            shm.clear();
        }
    }

    fn collect(&self, result: &ExecutionResult) -> CoverageFeedback {
        // Import external agent hits first
        self.pull_shm();

        if self.inject_response {
            self.inject_response_edges(result);
        }

        let mut new_edges = 0u32;
        let mut hit_edges = 0u32;
        let mut map_hash = 0u64;

        {
            let mut virgin = self.virgin.lock().unwrap();
            for i in 0..MAP_SIZE {
                let hits = self.current[i].load(Ordering::Relaxed);
                if hits > 0 {
                    hit_edges += 1;
                    map_hash = hash_combine(map_hash, (i as u64) << 8 | hits as u64);
                    if virgin[i] == 0 {
                        virgin[i] = 1;
                        new_edges += 1;
                        self.total_edges.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        CoverageFeedback {
            new_edges,
            hit_edges,
            map_hash,
            interesting: new_edges > 0,
        }
    }

    fn map_snapshot(&self) -> Option<Vec<u8>> {
        let mut snap = vec![0u8; MAP_SIZE];
        for (i, cell) in self.current.iter().enumerate() {
            snap[i] = cell.load(Ordering::Relaxed);
        }
        Some(snap)
    }

    fn total_edges(&self) -> u64 {
        self.total_edges.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ExecutionResult, OutcomeClass};
    use std::time::Duration;

    fn sample_result(codes: Vec<i32>, body: &[u8]) -> ExecutionResult {
        ExecutionResult {
            seed_id: 1,
            success: true,
            responses: vec![body.to_vec()],
            response_codes: codes,
            elapsed: Duration::from_millis(1),
            new_coverage: false,
            new_state: false,
            crash: false,
            hang: false,
            error: None,
            state_hash: 0xabc,
            outcome: OutcomeClass::Ok,
            coverage_hits: 0,
            coverage_map_hash: 0,
        }
    }

    #[test]
    fn map_detects_new_edges() {
        let cov = SharedMapCoverage::new();
        cov.reset();
        let r1 = sample_result(vec![220], b"welcome");
        let fb1 = cov.collect(&r1);
        assert!(fb1.new_edges > 0);
        assert!(fb1.interesting);

        cov.reset();
        let fb2 = cov.collect(&r1);
        assert_eq!(fb2.new_edges, 0);
        assert!(!fb2.interesting);
    }

    #[test]
    fn different_response_produces_new_edges() {
        let cov = SharedMapCoverage::new();
        cov.reset();
        let _ = cov.collect(&sample_result(vec![220], b"a"));
        cov.reset();
        let fb = cov.collect(&sample_result(vec![530], b"error"));
        assert!(fb.new_edges > 0);
    }
}
