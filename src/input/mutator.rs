//! NEXSIZ – Hierarchical mutator engine with protocol-aware integrity
//! Author  : Revana
//! Date    : 06/08/2026
//!
//! Integrity repair is OPTIONAL inside the mutator. Production workers
//! centralise repair ownership in the worker loop (IntegrityBridge |
//! model-name fallback) so Python bridges never double-repair.

use crate::common::types::*;
use crate::common::utils::XorShift64;
use crate::input::integrity;
use crate::input::model::ProtocolModel;

/// Main mutator state.
#[derive(Debug)]
pub struct Mutator {
    rng: XorShift64,
    model: ProtocolModel,
    max_mutations: usize,
    hierarchical_prob: f64,
    field_prob: f64,
    dict_prob: f64,
    repair: bool,
}

impl Mutator {
    pub fn new(
        seed: u64,
        model: ProtocolModel,
        max_mutations: usize,
        hierarchical_prob: f64,
        field_prob: f64,
        dict_prob: f64,
        repair: bool,
    ) -> Self {
        Self {
            rng: XorShift64::new(seed),
            model,
            max_mutations,
            hierarchical_prob,
            field_prob,
            dict_prob,
            repair,
        }
    }

    /// Force repair on/off (worker uses this when integrity ownership changes).
    pub fn set_repair(&mut self, repair: bool) {
        self.repair = repair;
    }

    pub fn repair_enabled(&self) -> bool {
        self.repair
    }

    pub fn model_name(&self) -> &str {
        &self.model.name
    }

    /// Merge extra dictionary tokens (from MutatorBridge). Deduplicates.
    pub fn extend_dictionary(&mut self, extra: &[Vec<u8>]) {
        for t in extra {
            if !t.is_empty() && !self.model.dictionary.iter().any(|d| d == t) {
                self.model.dictionary.push(t.clone());
            }
        }
    }

    pub fn dictionary_len(&self) -> usize {
        self.model.dictionary.len()
    }

    pub fn mutate(&mut self, parent: &TestCase, new_id: SeedId) -> TestCase {
        let mut child = parent.clone();
        child.id = new_id;
        child.parent = Some(parent.id);
        child.depth = parent.depth.saturating_add(1);
        child.interesting = false;
        child.energy = 1.0;
        child.last_state = None;

        let n_muts = 1 + self.rng.next_usize(self.max_mutations);
        for _ in 0..n_muts {
            if self.rng.next_bool(self.hierarchical_prob) && child.messages.len() > 1 {
                self.mutate_sequence(&mut child);
            } else if self.rng.next_bool(self.field_prob) {
                self.mutate_field_level(&mut child);
            } else {
                self.mutate_message_level(&mut child);
            }
        }

        if self.repair {
            integrity::prepare_for_send(&mut child, &self.model.name);
        }

        child
    }

    fn mutate_sequence(&mut self, tc: &mut TestCase) {
        if tc.messages.is_empty() {
            return;
        }
        match self.rng.next_usize(4) {
            0 => {
                let idx = self.rng.next_usize(tc.messages.len());
                let msg = tc.messages[idx].clone();
                let insert_at = self.rng.next_usize(tc.messages.len() + 1);
                tc.messages.insert(insert_at, msg);
            }
            1 => {
                if tc.messages.len() > 1 {
                    let idx = self.rng.next_usize(tc.messages.len());
                    tc.messages.remove(idx);
                }
            }
            2 => {
                if tc.messages.len() >= 2 {
                    let i = self.rng.next_usize(tc.messages.len());
                    let j = self.rng.next_usize(tc.messages.len());
                    tc.messages.swap(i, j);
                }
            }
            _ => {
                if tc.messages.len() > 2 {
                    let cut = 1 + self.rng.next_usize(tc.messages.len() - 1);
                    tc.messages.truncate(cut);
                }
            }
        }
    }

    fn mutate_message_level(&mut self, tc: &mut TestCase) {
        if tc.messages.is_empty() {
            return;
        }
        let midx = self.rng.next_usize(tc.messages.len());
        let msg = &mut tc.messages[midx];
        if msg.fields.is_empty() {
            return;
        }
        match self.rng.next_usize(3) {
            0 => {
                let fidx = self.rng.next_usize(msg.fields.len());
                if !msg.fields[fidx].protected {
                    let field = msg.fields[fidx].clone();
                    let insert_at = self.rng.next_usize(msg.fields.len() + 1);
                    msg.fields.insert(insert_at, field);
                }
            }
            1 => {
                if msg.fields.len() > 1 {
                    let candidates: Vec<usize> = msg
                        .fields
                        .iter()
                        .enumerate()
                        .filter(|(_, f)| !f.protected)
                        .map(|(i, _)| i)
                        .collect();
                    if !candidates.is_empty() {
                        let fidx = candidates[self.rng.next_usize(candidates.len())];
                        msg.fields.remove(fidx);
                    }
                }
            }
            _ => {
                let fidx = self.rng.next_usize(msg.fields.len());
                if !msg.fields[fidx].protected && !self.model.dictionary.is_empty() {
                    let dict_item =
                        &self.model.dictionary[self.rng.next_usize(self.model.dictionary.len())];
                    msg.fields[fidx].data = dict_item.clone();
                }
            }
        }
    }

    fn mutate_field_level(&mut self, tc: &mut TestCase) {
        if tc.messages.is_empty() {
            return;
        }
        let midx = self.rng.next_usize(tc.messages.len());
        let msg = &mut tc.messages[midx];
        if msg.fields.is_empty() {
            return;
        }

        let candidates: Vec<usize> = msg
            .fields
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.protected && !f.data.is_empty())
            .map(|(i, _)| i)
            .collect();

        if candidates.is_empty() {
            return;
        }

        let fidx = candidates[self.rng.next_usize(candidates.len())];
        let field = &mut msg.fields[fidx];

        if self.rng.next_bool(self.dict_prob) && !self.model.dictionary.is_empty() {
            let dict_item =
                &self.model.dictionary[self.rng.next_usize(self.model.dictionary.len())];
            match self.rng.next_usize(3) {
                0 => field.data = dict_item.clone(),
                1 => {
                    let off = self.rng.next_usize(field.data.len() + 1);
                    let mut new_data = Vec::with_capacity(field.data.len() + dict_item.len());
                    new_data.extend_from_slice(&field.data[..off]);
                    new_data.extend_from_slice(dict_item);
                    new_data.extend_from_slice(&field.data[off..]);
                    field.data = new_data;
                }
                _ => field.data.extend_from_slice(dict_item),
            }
            return;
        }

        match self.rng.next_usize(8) {
            0 => self.bit_flip(field),
            1 => self.byte_flip(field),
            2 => self.arithmetic(field),
            3 => self.interesting_byte(field),
            4 => self.delete_bytes(field),
            5 => self.insert_bytes(field),
            6 => self.overwrite_bytes(field),
            _ => self.random_bytes(field),
        }
    }

    fn bit_flip(&mut self, field: &mut Field) {
        if field.data.is_empty() {
            return;
        }
        let byte_idx = self.rng.next_usize(field.data.len());
        let bit = self.rng.next_usize(8) as u8;
        field.data[byte_idx] ^= 1u8 << bit;
    }

    fn byte_flip(&mut self, field: &mut Field) {
        if field.data.is_empty() {
            return;
        }
        let idx = self.rng.next_usize(field.data.len());
        field.data[idx] ^= 0xff;
    }

    fn arithmetic(&mut self, field: &mut Field) {
        if field.data.is_empty() {
            return;
        }
        let idx = self.rng.next_usize(field.data.len());
        let delta = (self.rng.next_u32() % 35) as i8 - 17;
        field.data[idx] = field.data[idx].wrapping_add(delta as u8);
    }

    fn interesting_byte(&mut self, field: &mut Field) {
        if field.data.is_empty() {
            return;
        }
        const INTERESTING: [u8; 9] = [0x00, 0x01, 0x7f, 0x80, 0xff, 0x20, 0x0a, 0x0d, 0x09];
        let idx = self.rng.next_usize(field.data.len());
        field.data[idx] = INTERESTING[self.rng.next_usize(INTERESTING.len())];
    }

    fn delete_bytes(&mut self, field: &mut Field) {
        if field.data.len() < 2 {
            return;
        }
        let len = 1 + self.rng.next_usize(field.data.len() / 2);
        let start = self.rng.next_usize(field.data.len().saturating_sub(len) + 1);
        field.data.drain(start..start + len);
    }

    fn insert_bytes(&mut self, field: &mut Field) {
        let len = 1 + self.rng.next_usize(8);
        let mut bytes = vec![0u8; len];
        for b in &mut bytes {
            *b = self.rng.next_u32() as u8;
        }
        let off = self.rng.next_usize(field.data.len() + 1);
        let mut new_data = Vec::with_capacity(field.data.len() + len);
        new_data.extend_from_slice(&field.data[..off]);
        new_data.extend_from_slice(&bytes);
        new_data.extend_from_slice(&field.data[off..]);
        field.data = new_data;
    }

    fn overwrite_bytes(&mut self, field: &mut Field) {
        if field.data.is_empty() {
            return;
        }
        let len = 1 + self.rng.next_usize(std::cmp::min(8, field.data.len()));
        let start = self.rng.next_usize(field.data.len().saturating_sub(len) + 1);
        for i in 0..len {
            field.data[start + i] = self.rng.next_u32() as u8;
        }
    }

    fn random_bytes(&mut self, field: &mut Field) {
        let len = if field.data.is_empty() {
            1 + self.rng.next_usize(16)
        } else {
            field.data.len()
        };
        field.data = (0..len).map(|_| self.rng.next_u32() as u8).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::model::ProtocolModel;

    fn sample_tc() -> TestCase {
        let mut msg = Message::new("m");
        msg.add_field(Field::new("cmd", FieldType::Command, b"USER".to_vec()));
        msg.add_field(Field::new("sp", FieldType::Binary, b" ".to_vec()).protected());
        msg.add_field(Field::new("arg", FieldType::String, b"anon".to_vec()));
        msg.add_field(Field::new("crlf", FieldType::Binary, b"\r\n".to_vec()).protected());
        TestCase::new(1, vec![msg])
    }

    #[test]
    fn mutate_produces_child() {
        let model = ProtocolModel::ftp();
        let mut mutator = Mutator::new(42, model, 4, 0.2, 0.7, 0.3, true);
        let parent = sample_tc();
        let child = mutator.mutate(&parent, 2);
        assert_eq!(child.id, 2);
        assert_eq!(child.parent, Some(1));
        assert_eq!(child.depth, 1);
        assert!(!child.messages.is_empty());
    }

    #[test]
    fn extend_dictionary_dedup() {
        let model = ProtocolModel::generic();
        let mut mutator = Mutator::new(1, model, 1, 0.0, 1.0, 1.0, false);
        let before = mutator.dictionary_len();
        mutator.extend_dictionary(&[b"ZZZ".to_vec(), b"ZZZ".to_vec()]);
        assert_eq!(mutator.dictionary_len(), before + 1);
    }

    #[test]
    fn set_repair_toggle() {
        let model = ProtocolModel::generic();
        let mut mutator = Mutator::new(1, model, 1, 0.0, 1.0, 0.0, true);
        assert!(mutator.repair_enabled());
        mutator.set_repair(false);
        assert!(!mutator.repair_enabled());
    }
}
