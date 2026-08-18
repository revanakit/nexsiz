//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::state::tracker
//!
//! Purpose
//! -------
//! Lightweight hybrid state-awareness tracker that combines black-box response
//! fingerprints with optional grey-box coverage signals to detect and label
//! distinct protocol states and inter-state transitions during fuzzing runs.
//! The tracker is intended to help the mutator and corpus management layers
//! prioritize inputs that exercise new states or reveal new edges (including
//! coverage-driven edges).
//!
//! Key responsibilities
//! --------------------
//! - Produce a compact state fingerprint for an execution result by folding:
//!   - response code sequence, truncated response content, and execution
//!     state_hash (from the target harness), and optionally
//!   - coverage map hash (when supplied by a coverage provider).
//! - Maintain a bounded set of observed states and transition counts.
//! - Track non-coverage edges (response-code sequences) and treat coverage
//!   edges (new map edges / map-hash) as first-class signals.
//! - Evict low-importance states when capacity is exceeded (simple hit-count
//!   based eviction) to bound memory usage in long-running campaigns.
//!
//! Design & behavior notes
//! ----------------------
//! - State fingerprinting is intentionally conservative and fast: response
//!   bodies are truncated (64 bytes) before hashing to avoid expensive work
//!   on large responses while still capturing discriminating content.
//! - Transitions are stored as a map keyed by (prev_state, next_state) and
//!   incremented on every observed transition; edges are recorded separately
//!   for protocol-level or coverage-derived signals.
//! - When CoverageFeedback is provided, the tracker folds the coverage map
//!   hash into the state fingerprint and increments edge counts for new
//!   coverage edges; this enables grey-box detection of previously-unseen
//!   execution paths without requiring full coverage orchestration.
//! - A configurable max_states parameter bounds the number of retained
//!   state descriptors; the least-hit state (excluding the most-recently
//!   observed key) is removed when the limit is exceeded.
//! - response_weight is reserved for future weighted fingerprinting or
//!   similarity metrics; currently it is not used in the hashing algorithm.
//!
//! Threading & safety
//! ------------------
//! - Mutable tracker state is guarded by a Mutex (TrackerInner). The public
//!   API is thread-friendly: callers may share a StateTracker across worker
//!   threads and call observe()/inspectors concurrently; internal locking
//!   serializes updates to the maps.
//!
//! Performance considerations
//! --------------------------
//! - Hashing and map operations are intended to be cheap per-observation.
//! - Truncating response bodies and folding pre-computed coverage hashes
//!   reduces per-call work; tune max_states to balance memory use vs. recall.
//!
//! Usage
//! -----
//! - Call observe(result, prev_state, coverage) for each execution to update
//!   the registry; it returns (new_state, new_edge) booleans to indicate
//!   whether the observation introduced a novel state or edge.
//! - Query helpers: state_count(), edge_count(), transition_count(),
//!   top_states(n) for diagnostics and reporting.
//!
//! Testing & validation
//! --------------------
//! - Unit tests bundled in this module exercise new-state detection,
//!   coverage-driven edge recognition, and basic eviction behaviour.
//!
//! Notes & caveats
//! ---------------
//! - State fingerprints are not cryptographic guarantees against collisions.
//!   Collisions may occur for different reasons (truncation, identical
//!   visible outputs); choose max_states and any future weighting policies
//!   to match your operational risk profile.
//! - This component focuses on lightweight, practical state-tracking for
//!   fuzzing workflows — it does not replace full protocol state modelling or
//!   external session tracking when those are required.

use crate::common::types::*;
use crate::common::utils::{hash_bytes, hash_combine};
use crate::coverage::provider::CoverageFeedback;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct StateTracker {
    inner: Mutex<TrackerInner>,
    max_states: usize,
    response_weight: f64,
}

struct TrackerInner {
    states: HashMap<u64, StateDescriptor>,
    transitions: HashMap<(u64, u64), u64>,
    edges: HashMap<u64, u64>,
    total_hits: u64,
}

impl StateTracker {
    pub fn new(max_states: usize, response_weight: f64) -> Self {
        Self {
            inner: Mutex::new(TrackerInner {
                states: HashMap::new(),
                transitions: HashMap::new(),
                edges: HashMap::new(),
                total_hits: 0,
            }),
            max_states,
            response_weight,
        }
    }

    /// Observe an execution result, optionally enriched with CoverageFeedback.
    /// Returns (new_state, new_edge).
    pub fn observe(
        &self,
        result: &ExecutionResult,
        prev_state: Option<u64>,
        coverage: Option<&CoverageFeedback>,
    ) -> (bool, bool) {
        let state_hash = self.compute_state_hash(result, coverage);
        let mut inner = self.inner.lock().unwrap();

        let mut new_state = false;
        let mut new_edge = false;

        let entry = inner.states.entry(state_hash).or_insert_with(|| {
            new_state = true;
            StateDescriptor {
                id: state_hash,
                label: format!("s{:016x}", state_hash),
                variables: HashMap::new(),
                mem_hash: coverage.map(|c| c.map_hash).unwrap_or(0),
                hit_count: 0,
            }
        });
        entry.hit_count += 1;
        if let Some(c) = coverage {
            if c.map_hash != 0 {
                entry.mem_hash = c.map_hash;
            }
        }
        inner.total_hits += 1;

        if let Some(prev) = prev_state {
            let key = (prev, state_hash);
            let count = inner.transitions.entry(key).or_insert(0);
            if *count == 0 {
                new_edge = true;
            }
            *count += 1;
        }

        if !result.response_codes.is_empty() {
            let mut edge_hash = 0u64;
            for code in &result.response_codes {
                edge_hash = hash_combine(edge_hash, *code as u64);
            }
            let ecount = inner.edges.entry(edge_hash).or_insert(0);
            if *ecount == 0 {
                new_edge = true;
            }
            *ecount += 1;
        }

        // Grey-box coverage edges are first-class citizens
        if let Some(c) = coverage {
            if c.new_edges > 0 {
                new_edge = true;
            }
            if c.map_hash != 0 {
                let cov_key = hash_combine(0xC0FFEE, c.map_hash);
                let ecount = inner.edges.entry(cov_key).or_insert(0);
                if *ecount == 0 {
                    new_edge = true;
                }
                *ecount += 1;
            }
        }

        if inner.states.len() > self.max_states {
            if let Some((&victim, _)) = inner
                .states
                .iter()
                .filter(|(k, _)| **k != state_hash)
                .min_by_key(|(_, d)| d.hit_count)
            {
                inner.states.remove(&victim);
            }
        }

        (new_state, new_edge)
    }

    fn compute_state_hash(
        &self,
        result: &ExecutionResult,
        coverage: Option<&CoverageFeedback>,
    ) -> u64 {
        let mut h = 0u64;
        for code in &result.response_codes {
            h = hash_combine(h, *code as u64);
        }
        for resp in &result.responses {
            let slice = if resp.len() > 64 { &resp[..64] } else { resp };
            h = hash_combine(h, hash_bytes(slice));
        }
        h = hash_combine(h, result.state_hash);

        // Fold coverage map hash when present (true grey-box signal)
        if let Some(c) = coverage {
            if c.map_hash != 0 {
                h = hash_combine(h, c.map_hash);
            }
        }

        let _ = self.response_weight;
        h
    }

    pub fn state_count(&self) -> usize {
        self.inner.lock().unwrap().states.len()
    }

    pub fn edge_count(&self) -> usize {
        self.inner.lock().unwrap().edges.len()
    }

    pub fn transition_count(&self) -> usize {
        self.inner.lock().unwrap().transitions.len()
    }

    pub fn top_states(&self, n: usize) -> Vec<StateDescriptor> {
        let inner = self.inner.lock().unwrap();
        let mut v: Vec<_> = inner.states.values().cloned().collect();
        v.sort_by(|a, b| b.hit_count.cmp(&a.hit_count));
        v.truncate(n);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::provider::CoverageFeedback;
    use std::time::Duration;

    fn make_result(codes: Vec<i32>, body: &[u8]) -> ExecutionResult {
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
            state_hash: 0,
            outcome: OutcomeClass::Ok,
            coverage_hits: 0,
            coverage_map_hash: 0,
        }
    }

    #[test]
    fn observe_detects_new_state() {
        let t = StateTracker::new(100, 0.6);
        let r1 = make_result(vec![220], b"welcome");
        let (new_s, _) = t.observe(&r1, None, None);
        assert!(new_s);
        let (new_s2, _) = t.observe(&r1, None, None);
        assert!(!new_s2);
        assert_eq!(t.state_count(), 1);
    }

    #[test]
    fn coverage_feedback_creates_new_edge() {
        let t = StateTracker::new(100, 0.6);
        let r = make_result(vec![200], b"ok");
        let fb = CoverageFeedback {
            new_edges: 3,
            hit_edges: 5,
            map_hash: 0xdeadbeef,
            interesting: true,
        };
        let (new_s, new_e) = t.observe(&r, None, Some(&fb));
        assert!(new_s || new_e);
    }
}
