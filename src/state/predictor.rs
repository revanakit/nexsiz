//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::state::predictor
//!
//! Purpose
//! -------
//! Lightweight, production-ready adaptive predictor for protocol state
//! transitions observed during fuzzing. The predictor records observed (from ->
//! to) state transitions and provides simple frequency-based queries useful
//! for prioritization, rarity scoring, and transition-interest heuristics.
//!
//! Key responsibilities
//! --------------------
//! - Record directed state transitions and maintain per-source frequency maps.
//! - Provide best-effort prediction of the next state for a given source state
//!   by selecting the most frequently observed successor.
//! - Offer a simple rarity metric in [0.0, 1.0] to quantify how commonly a
//!   particular transition has been observed relative to total observations.
//! - Expose a compact "interesting" predicate for low-frequency (rare) transitions.
//!
//! Design & behavior notes
//! ----------------------
//! - The predictor uses in-memory HashMaps keyed by 64-bit state identifiers
//!   (u64) and stores counts as u64. This is intended to be fast and memory
//!   efficient for typical fuzzing workloads.
//! - Predictions are frequency-based (maximum count). No probabilistic or
//!   Markov-chain smoothing is applied — this keeps semantics simple and
//!   deterministic for prioritization logic.
//! - Rarity is computed as count / total_observations; this gives a global
//!   notion of uncommon transitions but does not normalize per-source state.
//!
//! Threading & safety
//! ------------------
//! - Internal mutable state is protected by a Mutex. StatePredictor is safe to
//!   share across worker threads for concurrent observe()/predict() calls.
//! - Locking is coarse-grained (single Mutex) which is acceptable given the
//!   small critical sections; tune or replace with sharded maps if contention
//!   becomes measurable in high-concurrency scenarios.
//!
//! Usage
//! -----
//! - Call observe(from, to) to record an observed transition.
//! - Call predict(from) to get the most-likely successor state (Option<u64>).
//! - Use rarity(from, to) or is_interesting_transition(from, to) to guide
//!   prioritization and exploration strategies.
//!
//! Testing & validation
//! --------------------
//! - Unit tests validate basic counting semantics, prediction, rarity ordering,
//!   and the interesting-transition threshold behavior.
//!
//! Notes & caveats
//! ---------------
//! - This component is intentionally simple and heuristic-driven. For richer
//!   predictive behavior consider weighting by recency, per-source normalization,
//!   or probabilistic models outside this module.
//! - The predictor does not persist state; it is an in-memory aide for per-run
//!   decision-making. Persist/restore logic can be added at a higher layer if
//!   long-term learning is desired.

use std::collections::HashMap;
use std::sync::Mutex;

pub struct StatePredictor {
    inner: Mutex<PredictorInner>,
}

struct PredictorInner {
    transitions: HashMap<u64, HashMap<u64, u64>>,
    total_observations: u64,
}

impl StatePredictor {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(PredictorInner {
                transitions: HashMap::new(),
                total_observations: 0,
            }),
        }
    }

    pub fn observe(&self, from: u64, to: u64) {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner.transitions.entry(from).or_default();
        *entry.entry(to).or_insert(0) += 1;
        inner.total_observations += 1;
    }

    pub fn predict(&self, from: u64) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        let map = inner.transitions.get(&from)?;
        map.iter().max_by_key(|(_, &cnt)| cnt).map(|(&to, _)| to)
    }

    /// Rarity in [0.0, 1.0]; 0.0 = never seen / rarest, 1.0 = very common.
    pub fn rarity(&self, from: u64, to: u64) -> f64 {
        let inner = self.inner.lock().unwrap();
        let total = inner.total_observations.max(1) as f64;
        match inner.transitions.get(&from) {
            Some(map) => {
                let count = *map.get(&to).unwrap_or(&0) as f64;
                (count / total).min(1.0)
            }
            None => 0.0,
        }
    }

    pub fn is_interesting_transition(&self, from: u64, to: u64) -> bool {
        self.rarity(from, to) < 0.05
    }

    pub fn observation_count(&self) -> u64 {
        self.inner.lock().unwrap().total_observations
    }
}

impl Default for StatePredictor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rarity_and_predict() {
        let p = StatePredictor::new();
        p.observe(1, 2);
        p.observe(1, 2);
        p.observe(1, 3);
        assert!(p.rarity(1, 2) > p.rarity(1, 3));
        assert_eq!(p.predict(1), Some(2));
        assert!(p.is_interesting_transition(1, 99));
        assert_eq!(p.observation_count(), 3);
    }
}
