//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//! Author  : Revana
//! Date    : 04/08/2026
//! Adaptive state transition predictor.

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
