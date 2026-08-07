//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//! Author  : Revana
//! Date    : 04/08/2026
//! Corpus management: seed queue, energy + rarity-guided scheduling, deduplication.

use crate::common::types::*;
use crate::common::utils::XorShift64;
use crate::input::model::content_hash;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

/// Thread-safe corpus / seed queue.
pub struct Corpus {
    inner: Mutex<CorpusInner>,
}

struct CorpusInner {
    /// All known test cases by id
    entries: HashMap<SeedId, TestCase>,
    /// Ordered queue for scheduling (ids)
    queue: VecDeque<SeedId>,
    /// Content hashes already seen (dedup)
    seen: HashSet<u64>,
    /// Next id to assign
    next_id: SeedId,
    /// Total interesting finds
    interesting_count: u64,
}

impl Corpus {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CorpusInner {
                entries: HashMap::new(),
                queue: VecDeque::new(),
                seen: HashSet::new(),
                next_id: 1,
                interesting_count: 0,
            }),
        }
    }

    /// Add initial seeds. Returns number of unique seeds accepted.
    pub fn add_seeds(&self, seeds: Vec<TestCase>) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let mut added = 0;
        for mut seed in seeds {
            let h = content_hash(&seed);
            if inner.seen.contains(&h) {
                continue;
            }
            seed.id = inner.next_id;
            inner.next_id += 1;
            inner.seen.insert(h);
            inner.queue.push_back(seed.id);
            inner.entries.insert(seed.id, seed);
            added += 1;
        }
        added
    }

    /// Add a new (mutated) test case if it is unique. Returns the assigned id
    /// when accepted, or None when discarded as duplicate.
    pub fn add_if_new(&self, mut tc: TestCase) -> Option<SeedId> {
        let h = content_hash(&tc);
        let mut inner = self.inner.lock().unwrap();
        if inner.seen.contains(&h) {
            return None;
        }
        tc.id = inner.next_id;
        inner.next_id += 1;
        inner.seen.insert(h);
        if tc.interesting {
            inner.interesting_count += 1;
            inner.queue.push_front(tc.id);
        } else {
            inner.queue.push_back(tc.id);
        }
        let id = tc.id;
        inner.entries.insert(id, tc);
        Some(id)
    }

    /// Select the next seed using energy-weighted sampling.
    /// Higher energy seeds are more likely to be chosen.
    pub fn schedule(&self, rng: &mut XorShift64) -> Option<TestCase> {
        let inner = self.inner.lock().unwrap();
        if inner.queue.is_empty() {
            return None;
        }

        // Build energy-weighted selection
        let mut total_energy = 0.0f64;
        let mut energies: Vec<(usize, f64)> = Vec::with_capacity(inner.queue.len());
        for (i, &id) in inner.queue.iter().enumerate() {
            let e = inner
                .entries
                .get(&id)
                .map(|tc| tc.energy.max(0.01))
                .unwrap_or(0.01);
            total_energy += e;
            energies.push((i, e));
        }

        if total_energy <= 0.0 {
            let idx = rng.choose_biased(inner.queue.len());
            let id = inner.queue[idx];
            return inner.entries.get(&id).cloned();
        }

        // Roulette-wheel selection
        let r = (rng.next_u64() as f64 / u64::MAX as f64) * total_energy;
        let mut acc = 0.0;
        let mut chosen_idx = 0;
        for &(i, e) in &energies {
            acc += e;
            if acc >= r {
                chosen_idx = i;
                break;
            }
        }

        let id = inner.queue[chosen_idx];
        inner.entries.get(&id).cloned()
    }

    /// Mark a seed as interesting and boost its energy.
    pub fn mark_interesting(&self, id: SeedId, new_state: Option<u64>) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(tc) = inner.entries.get_mut(&id) {
            tc.interesting = true;
            tc.energy *= 1.5;
            if let Some(s) = new_state {
                tc.last_state = Some(s);
            }
            if let Some(pos) = inner.queue.iter().position(|&x| x == id) {
                inner.queue.remove(pos);
                inner.queue.push_front(id);
            }
            inner.interesting_count += 1;
        }
    }

    /// Apply a rarity-based energy boost (called after StatePredictor feedback).
    /// `rarity` is in [0.0, 1.0]; lower = rarer = higher boost.
    pub fn apply_rarity_boost(&self, id: SeedId, rarity: f64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(tc) = inner.entries.get_mut(&id) {
            // Rarer transitions get larger multipliers (up to 3x)
            let boost = 1.0 + (1.0 - rarity.min(1.0)).powi(2) * 2.0;
            tc.energy = (tc.energy * boost).min(100.0);
        }
    }

    /// Directly set energy (for tests / advanced schedulers).
    pub fn set_energy(&self, id: SeedId, energy: f64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(tc) = inner.entries.get_mut(&id) {
            tc.energy = energy.max(0.01);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    pub fn queue_len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    pub fn interesting_count(&self) -> u64 {
        self.inner.lock().unwrap().interesting_count
    }

    pub fn next_id(&self) -> SeedId {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_id;
        inner.next_id += 1;
        id
    }

    /// Retrieve a test case by id (for minimization / replay).
    pub fn get(&self, id: SeedId) -> Option<TestCase> {
        self.inner.lock().unwrap().entries.get(&id).cloned()
    }
}

impl Default for Corpus {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared corpus handle.
pub type SharedCorpus = Arc<Corpus>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{Field, FieldType, Message, TestCase};

    fn make_tc(id: SeedId, payload: &[u8]) -> TestCase {
        let mut msg = Message::new("t");
        msg.add_field(Field::new("p", FieldType::Binary, payload.to_vec()));
        TestCase::new(id, vec![msg])
    }

    #[test]
    fn add_seeds_dedup() {
        let c = Corpus::new();
        let seeds = vec![make_tc(0, b"abc"), make_tc(0, b"abc"), make_tc(0, b"def")];
        assert_eq!(c.add_seeds(seeds), 2);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn schedule_returns_seed() {
        let c = Corpus::new();
        c.add_seeds(vec![make_tc(0, b"x")]);
        let mut rng = XorShift64::new(42);
        assert!(c.schedule(&mut rng).is_some());
    }

    #[test]
    fn energy_boost_and_rarity() {
        let c = Corpus::new();
        c.add_seeds(vec![make_tc(0, b"a")]);
        let id = 1; // first assigned id
        c.mark_interesting(id, Some(0x1234));
        c.apply_rarity_boost(id, 0.0); // very rare
        let tc = c.get(id).unwrap();
        assert!(tc.energy > 1.5);
        assert!(tc.interesting);
    }

    #[test]
    fn add_if_new_rejects_duplicate() {
        let c = Corpus::new();
        c.add_seeds(vec![make_tc(0, b"same")]);
        let mut tc = make_tc(0, b"same");
        tc.interesting = true;
        assert!(c.add_if_new(tc).is_none());
    }
}
