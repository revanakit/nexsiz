//! NEXSIZ – Software / response-edge coverage provider
//! Author  : Revana
//! Date    : 05/08/2026
//!
//! Lightweight hybrid provider that turns protocol responses into a
//! compact edge set without any binary instrumentation.
//! Ideal for remote targets where SHM injection is impossible.
//! Still far stronger than pure response-code black-box.

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
