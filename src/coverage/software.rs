//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Module: nexsiz::src::coverage::software
//!
//! Software / Response-Edge Coverage Provider
//! -----------------------------------------
//! A lightweight, instrumentation-free coverage backend that converts protocol
//! responses and observable outcomes into a compact set of synthetic "edges".
//! This hybrid approach is intended for remote or closed targets where
//! in-process instrumentation (SHM/mmap) is infeasible, while still offering
//! stronger feedback than pure black-box response codes.
//!
//! Core behaviour:
//! - Extracts deterministic edge identifiers from: a response-code chain,
//!   truncated response-body fingerprints (first 48 bytes), and a combined
//!   outcome/state hash. These items are combined using stable hashing utilities.
//! - Maintains a global seen-edge set (HashSet<u64>) protected by a Mutex to
//!   detect novelty across executions; per-execution state is otherwise
//!   stateless and reset() is a no-op.
//! - Reports CoverageFeedback containing new_edges, hit_edges, a compact map_hash,
//!   and whether the execution was interesting (introduced new edges).
//!
//! Concurrency & performance:
//! - The seen set is guarded by a Mutex and the total unique-edge count is
//!   tracked with an AtomicU64. collect() holds the lock only while merging
//!   the small edge vector, keeping the critical section short.
//! - Hashing and set-insertion are the main cost; this design avoids heavy
//!   instrumentation overhead and is suitable for high-latency remote targets.
//!
//! Design rationale and guarantees:
//! - Deterministic edge derivation: the same ExecutionResult should yield the
//!   same vector of edges (subject to hash collisions of the chosen hash funcs).
//! - Idempotent per-edge accounting: repeated collects for the same observed
//!   edges will not increment the global unique count after the first insertion.
//! - The provider sacrifices fine-grained code coverage for deployability and
//!   robustness against targets where binary instrumentation cannot be used.
//!
//! Implementation notes:
//! - Keep the fingerprint size (48 bytes) and response-code combination logic
//!   stable to allow meaningful comparisons across runs and experiments.
//! - Consider hash quality and collision risk when tuning hash_bytes/hash_combine.
//! - If needed, offload heavy aggregation or telemetry to a non-blocking thread
//!   to keep collect() responsive in the hot path.
//!
//! Testing:
//! - Unit tests validate novelty detection, repeated collection semantics, and
//!   basic edge-extraction invariants.

use crate::common::types::ExecutionResult;
use crate::common::utils::{hash_bytes, hash_combine};
use crate::coverage::provider::{CoverageFeedback, CoverageProvider};
use std::collections::HashSet;
use std::sync::Mutex;

pub struct SoftwareCoverage {
    seen: Mutex<HashSet<u64>>,
    total: std::sync::atomic::AtomicU64,
}

impl SoftwareCoverage {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn edges_from_result(result: &ExecutionResult) -> Vec<u64> {
        let mut edges = Vec::new();

        // Response-code chain
        let mut prev = 0u64;
        for &c in &result.response_codes {
            let e = hash_combine(prev, c as u64);
            edges.push(e);
            prev = c as u64;
        }

        // Body fingerprints (first 48 bytes)
        for resp in &result.responses {
            let slice = if resp.len() > 48 { &resp[..48] } else { resp };
            if !slice.is_empty() {
                edges.push(hash_bytes(slice));
            }
        }

        // Outcome + state mix
        edges.push(hash_combine(
            result.state_hash,
            result.outcome as u64,
        ));

        edges
    }
}

impl Default for SoftwareCoverage {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageProvider for SoftwareCoverage {
    fn name(&self) -> &str {
        "software"
    }

    fn reset(&self) {
        // Software provider is stateless per-execution; global seen set persists.
    }

    fn collect(&self, result: &ExecutionResult) -> CoverageFeedback {
        let edges = Self::edges_from_result(result);
        let mut new_edges = 0u32;
        let hit_edges = edges.len() as u32;
        let mut map_hash = 0u64;

        {
            let mut seen = self.seen.lock().unwrap();
            for e in edges {
                map_hash = hash_combine(map_hash, e);
                if seen.insert(e) {
                    new_edges += 1;
                    self.total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    fn total_edges(&self) -> u64 {
        self.total.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{ExecutionResult, OutcomeClass};
    use std::time::Duration;

    fn r(codes: Vec<i32>, body: &[u8]) -> ExecutionResult {
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
            state_hash: 42,
            outcome: OutcomeClass::Ok,
            coverage_hits: 0,
            coverage_map_hash: 0,
        }
    }

    #[test]
    fn software_detects_novelty() {
        let cov = SoftwareCoverage::new();
        let fb1 = cov.collect(&r(vec![220], b"hi"));
        assert!(fb1.interesting);
        let fb2 = cov.collect(&r(vec![220], b"hi"));
        assert!(!fb2.interesting);
        let fb3 = cov.collect(&r(vec![530], b"fail"));
        assert!(fb3.interesting);
    }
}
