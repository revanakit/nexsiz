//! NEXSIZ – Hierarchical mutator engine with protocol-aware integrity
//! Author  : Revana
//! Date    : 07/08/2026
//!
//! Integrity repair is OPTIONAL inside the mutator. Production workers
//! centralise repair ownership in the worker loop (IntegrityBridge |
//! model-name fallback) so Python bridges never double-repair.
//!
//! Phase 2: field-aware mutation — FieldSpec size / values / protected.
//! Phase 3: directed field scheduling + MessageSpec template synthesis.
//!   - Weighted field selection (Command/String/Payload preferred)
//!   - Synthesise messages from MessageSpec when useful
//!   - Zero behaviour change when model.messages is empty

use crate::common::types::*;
use crate::common::utils::XorShift64;
use crate::input::integrity;
use crate::input::model::{FieldSpec, MessageSpec, ProtocolModel};

/// Relative weight for field-type directed scheduling.
/// Higher → more likely to be chosen for mutation.
fn field_type_weight(ftype: &FieldType) -> u32 {
    match ftype {
        FieldType::Command => 10,
        FieldType::String => 9,
        FieldType::Payload => 8,
        FieldType::Binary => 6,
        FieldType::Numeric => 5,
        FieldType::Custom(_) => 4,
        FieldType::Length => 1,   // rarely mutate; integrity repair owns it
        FieldType::Checksum => 0, // never schedule destructive mutation
    }
}

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
    /// Probability of synthesising / splicing a MessageSpec template (Phase 3).
    template_prob: f64,
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
            // Default: modest template usage when specs exist
            template_prob: 0.12,
        }
    }

    pub fn with_template_prob(mut self, p: f64) -> Self {
        self.template_prob = p.clamp(0.0, 1.0);
        self
    }

    pub fn set_template_prob(&mut self, p: f64) {
        self.template_prob = p.clamp(0.0, 1.0);
    }

    pub fn set_repair(&mut self, repair: bool) {
        self.repair = repair;
    }

    pub fn repair_enabled(&self) -> bool {
        self.repair
    }

    pub fn model_name(&self) -> &str {
        &self.model.name
    }

    pub fn extend_dictionary(&mut self, extra: &[Vec<u8>]) {
        self.model.extend_dictionary(extra);
    }

    pub fn dictionary_len(&self) -> usize {
        self.model.dictionary.len()
    }

    pub fn set_model(&mut self, model: ProtocolModel) {
        self.model = model;
    }

    pub fn mutate(&mut self, parent: &TestCase, new_id: SeedId) -> TestCase {
        let mut child = parent.clone();
        child.id = new_id;
        child.parent = Some(parent.id);
        child.depth = parent.depth.saturating_add(1);
        child.interesting = false;
        child.energy = 1.0;
        child.last_state = None;

        // Phase 3: occasionally splice a synthesised template message
        if !self.model.messages.is_empty() && self.rng.next_bool(self.template_prob) {
            self.splice_template(&mut child);
        }

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

        self.enforce_size_constraints(&mut child);

        if self.repair {
            integrity::prepare_for_send(&mut child, &self.model.name);
        }

        child
    }

    // ── Phase 3: template synthesis ──────────────────────────────────────────

    /// Build a concrete Message from a MessageSpec (fills values / sizes).
    pub fn synthesise_from_spec(&mut self, spec: &MessageSpec) -> Message {
        let mut msg = Message::new(spec.name.clone());
        for fs in &spec.fields {
            let data = self.materialise_field(fs);
            let mut field = Field::new(fs.name.clone(), fs.ftype.clone(), data);
            if let Some(sz) = fs.size {
                field = field.with_size(sz);
            }
            if fs.protected {
                field = field.protected();
            }
            msg.add_field(field);
        }
        msg
    }

    fn materialise_field(&mut self, fs: &FieldSpec) -> Vec<u8> {
        // Prefer explicit values
        if !fs.values.is_empty() {
            let idx = self.rng.next_usize(fs.values.len());
            let mut data = fs.values[idx].clone();
            if let Some(sz) = fs.size {
                enforce_len(&mut data, sz);
            }
            return data;
        }

        // Size-driven defaults
        if let Some(sz) = fs.size {
            return match fs.ftype {
                FieldType::Length | FieldType::Numeric | FieldType::Checksum => vec![0u8; sz],
                FieldType::Command if !self.model.dictionary.is_empty() => {
                    let d = self.model.dictionary[self.rng.next_usize(self.model.dictionary.len())]
                        .clone();
                    let mut out = d;
                    enforce_len(&mut out, sz);
                    out
                }
                _ => (0..sz).map(|_| self.rng.next_u32() as u8).collect(),
            };
        }

        // Variable-length: dictionary or short random
        if !self.model.dictionary.is_empty() && self.rng.next_bool(0.6) {
            return self.model.dictionary[self.rng.next_usize(self.model.dictionary.len())].clone();
        }
        let len = 1 + self.rng.next_usize(16);
        (0..len).map(|_| self.rng.next_u32() as u8).collect()
    }

    /// Insert or replace a message in the test case with a synthesised template.
    fn splice_template(&mut self, tc: &mut TestCase) {
        if self.model.messages.is_empty() {
            return;
        }
        let spec = &self.model.messages[self.rng.next_usize(self.model.messages.len())].clone();
        let msg = self.synthesise_from_spec(spec);

        if tc.messages.is_empty() {
            tc.messages.push(msg);
            return;
        }

        match self.rng.next_usize(3) {
            0 => {
                // Replace random existing message
                let idx = self.rng.next_usize(tc.messages.len());
                tc.messages[idx] = msg;
            }
            1 => {
                // Insert at random position
                let at = self.rng.next_usize(tc.messages.len() + 1);
                tc.messages.insert(at, msg);
            }
            _ => {
                // Append
                tc.messages.push(msg);
            }
        }
    }

    // ── Sequence / message / field mutation ──────────────────────────────────

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
                if !msg.fields[fidx].protected
                    && !matches!(
                        msg.fields[fidx].ftype,
                        FieldType::Length | FieldType::Checksum
                    )
                {
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
                        .filter(|(_, f)| {
                            !f.protected
                                && !matches!(f.ftype, FieldType::Length | FieldType::Checksum)
                        })
                        .map(|(i, _)| i)
                        .collect();
                    if !candidates.is_empty() {
                        let fidx = candidates[self.rng.next_usize(candidates.len())];
                        msg.fields.remove(fidx);
                    }
                }
            }
            _ => {
                // Directed pick + value from spec / dictionary
                if let Some(fidx) = self.pick_weighted_field_index(msg) {
                    if let Some(val) = self.pick_spec_value(&msg.fields[fidx].name) {
                        msg.fields[fidx].data = val;
                    } else if !self.model.dictionary.is_empty() {
                        let dict_item = &self.model.dictionary
                            [self.rng.next_usize(self.model.dictionary.len())];
                        msg.fields[fidx].data = dict_item.clone();
                    }
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

        // Phase 3: weighted directed selection
        if let Some(fidx) = self.pick_weighted_field_index(msg) {
            self.mutate_one_field(&mut msg.fields[fidx]);
            return;
        }

        // Fallback: any non-protected non-empty field
        let fallback: Vec<usize> = msg
            .fields
            .iter()
            .enumerate()
            .filter(|(_, f)| !f.protected && !f.data.is_empty())
            .map(|(i, _)| i)
            .collect();
        if fallback.is_empty() {
            return;
        }
        let fidx = fallback[self.rng.next_usize(fallback.len())];
        self.mutate_one_field(&mut msg.fields[fidx]);
    }

    /// Weighted random field index. Skips protected, empty, and Checksum fields.
    /// Returns None if no eligible field.
    fn pick_weighted_field_index(&mut self, msg: &Message) -> Option<usize> {
        let mut weights: Vec<(usize, u32)> = Vec::new();
        let mut total = 0u32;

        for (i, f) in msg.fields.iter().enumerate() {
            if f.protected || f.data.is_empty() {
                continue;
            }
            let w = field_type_weight(&f.ftype);
            if w == 0 {
                continue;
            }
            weights.push((i, w));
            total += w;
        }

        if total == 0 || weights.is_empty() {
            return None;
        }

        let mut pick = self.rng.next_u32() % total;
        for &(idx, w) in &weights {
            if pick < w {
                return Some(idx);
            }
            pick -= w;
        }
        Some(weights[0].0)
    }

    fn mutate_one_field(&mut self, field: &mut Field) {
        if self.rng.next_bool(self.dict_prob) {
            if let Some(val) = self.pick_spec_value(&field.name) {
                field.data = val;
                return;
            }
            if !self.model.dictionary.is_empty() {
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
        }

        let fixed = field.size;
        match self.rng.next_usize(8) {
            0 => self.bit_flip(field),
            1 => self.byte_flip(field),
            2 => self.arithmetic(field),
            3 => self.interesting_byte(field),
            4 if fixed.is_none() => self.delete_bytes(field),
            5 if fixed.is_none() => self.insert_bytes(field),
            6 => self.overwrite_bytes(field),
            _ => {
                if let Some(sz) = fixed {
                    self.random_bytes_fixed(field, sz);
                } else {
                    self.random_bytes(field);
                }
            }
        }
    }

    fn pick_spec_value(&mut self, field_name: &str) -> Option<Vec<u8>> {
        let name_l = field_name.to_ascii_lowercase();
        for msg in &self.model.messages {
            for fs in &msg.fields {
                if fs.name.to_ascii_lowercase() == name_l && !fs.values.is_empty() {
                    let idx = self.rng.next_usize(fs.values.len());
                    return Some(fs.values[idx].clone());
                }
            }
        }
        None
    }

    fn enforce_size_constraints(&self, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            for field in &mut msg.fields {
                if let Some(sz) = field.size {
                    enforce_len(&mut field.data, sz);
                    continue;
                }
                let name_l = field.name.to_ascii_lowercase();
                for mspec in &self.model.messages {
                    for fs in &mspec.fields {
                        if fs.name.to_ascii_lowercase() == name_l {
                            if let Some(sz) = fs.size {
                                enforce_len(&mut field.data, sz);
                            }
                            break;
                        }
                    }
                }
            }
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

    fn random_bytes_fixed(&mut self, field: &mut Field, size: usize) {
        field.data = (0..size).map(|_| self.rng.next_u32() as u8).collect();
    }
}

fn enforce_len(data: &mut Vec<u8>, size: usize) {
    if data.len() > size {
        data.truncate(size);
    } else if data.len() < size {
        data.resize(size, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::model::{FieldSpec, MessageSpec, ProtocolModel};

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

    #[test]
    fn enforce_fixed_size() {
        let mut model = ProtocolModel::generic();
        model.messages = vec![MessageSpec::new("frame")
            .field(FieldSpec::new("len", FieldType::Length).with_size(2))];
        let mut mutator = Mutator::new(7, model, 3, 0.0, 1.0, 0.0, false);
        let mut msg = Message::new("frame");
        msg.add_field(Field::new("len", FieldType::Length, vec![0, 0, 0, 0]).with_size(2));
        let parent = TestCase::new(1, vec![msg]);
        let child = mutator.mutate(&parent, 2);
        assert_eq!(child.messages[0].fields[0].data.len(), 2);
    }

    #[test]
    fn synthesise_from_dns_spec() {
        let model = ProtocolModel::dns();
        let mut mutator = Mutator::new(99, model.clone(), 1, 0.0, 0.0, 0.0, false);
        assert!(!model.messages.is_empty());
        let msg = mutator.synthesise_from_spec(&model.messages[0]);
        assert_eq!(msg.name, "query");
        assert!(!msg.fields.is_empty());
        // tcp_len should be size 2
        assert_eq!(msg.fields[0].data.len(), 2);
    }

    #[test]
    fn template_splice_adds_message() {
        let model = ProtocolModel::mqtt();
        let mut mutator = Mutator::new(11, model, 1, 0.0, 0.0, 0.0, false).with_template_prob(1.0);
        let parent = TestCase::new(1, vec![]);
        let child = mutator.mutate(&parent, 2);
        // With empty parent and template_prob=1, splice should produce at least one message
        assert!(!child.messages.is_empty());
    }

    #[test]
    fn weighted_prefers_command_over_checksum() {
        // Build a message with only Command + Checksum; pick should never land on Checksum
        let mut msg = Message::new("t");
        msg.add_field(Field::new("cmd", FieldType::Command, b"\x10".to_vec()));
        msg.add_field(Field::new("chk", FieldType::Checksum, vec![0, 0, 0, 0]));
        let model = ProtocolModel::generic();
        let mut mutator = Mutator::new(3, model, 1, 0.0, 1.0, 0.0, false);
        for _ in 0..20 {
            let idx = mutator.pick_weighted_field_index(&msg);
            assert_eq!(idx, Some(0)); // only Command is eligible
        }
    }
}
