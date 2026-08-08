//! NEXSIZ – Hierarchical mutator with directed scheduling, templates, energy feedback
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Phase 2: field-aware mutation — FieldSpec size / values / protected.
//! Phase 3: directed field scheduling + MessageSpec/SequenceSpec templates +
//!          field energy feedback from interesting outcomes.

use crate::common::types::*;
use crate::common::utils::XorShift64;
use crate::input::integrity;
use crate::input::model::{FieldSpec, MessageSpec, ProtocolModel};
use std::collections::HashMap;

fn field_type_weight(ftype: &FieldType) -> u32 {
    match ftype {
        FieldType::Command => 10,
        FieldType::String => 9,
        FieldType::Payload => 8,
        FieldType::Binary => 6,
        FieldType::Numeric => 5,
        FieldType::Custom(_) => 4,
        FieldType::Length => 1,
        FieldType::Checksum => 0,
    }
}

#[derive(Debug)]
pub struct Mutator {
    rng: XorShift64,
    model: ProtocolModel,
    max_mutations: usize,
    hierarchical_prob: f64,
    field_prob: f64,
    dict_prob: f64,
    repair: bool,
    template_prob: f64,
    field_energy: HashMap<String, u32>,
    last_touched: Vec<String>,
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
            template_prob: 0.12,
            field_energy: HashMap::new(),
            last_touched: Vec::new(),
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

    /// Boost energy for fields touched in the last mutation.
    pub fn on_interesting(&mut self) {
        for name in self.last_touched.clone() {
            let e = self.field_energy.entry(name).or_insert(0);
            *e = (*e).saturating_add(2).min(64);
        }
    }

    fn touch(&mut self, name: &str) {
        self.last_touched.push(name.to_string());
    }

    pub fn mutate(&mut self, parent: &TestCase, new_id: SeedId) -> TestCase {
        self.last_touched.clear();

        let mut child = parent.clone();
        child.id = new_id;
        child.parent = Some(parent.id);
        child.depth = parent.depth.saturating_add(1);
        child.interesting = false;
        child.energy = 1.0;
        child.last_state = None;

        if (!self.model.messages.is_empty() || !self.model.sequences.is_empty())
            && self.rng.next_bool(self.template_prob)
        {
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

    pub fn synthesise_sequence(&mut self, seq_name: &str) -> Vec<Message> {
        let steps: Vec<String> = self
            .model
            .sequences
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(seq_name))
            .map(|s| s.steps.clone())
            .unwrap_or_default();
        let mut out = Vec::new();
        for step in steps {
            if let Some(spec) = self.model.find_message(&step).cloned() {
                out.push(self.synthesise_from_spec(&spec));
            }
        }
        out
    }

    fn materialise_field(&mut self, fs: &FieldSpec) -> Vec<u8> {
        if !fs.values.is_empty() {
            let idx = self.rng.next_usize(fs.values.len());
            let mut data = fs.values[idx].clone();
            if let Some(sz) = fs.size {
                enforce_len(&mut data, sz);
            }
            return data;
        }
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
        if !self.model.dictionary.is_empty() && self.rng.next_bool(0.6) {
            return self.model.dictionary[self.rng.next_usize(self.model.dictionary.len())].clone();
        }
        let len = 1 + self.rng.next_usize(16);
        (0..len).map(|_| self.rng.next_u32() as u8).collect()
    }

    fn splice_template(&mut self, tc: &mut TestCase) {
        if !self.model.sequences.is_empty() && self.rng.next_bool(0.55) {
            let seq = self.model.sequences[self.rng.next_usize(self.model.sequences.len())].clone();
            let msgs = self.synthesise_sequence(&seq.name);
            if !msgs.is_empty() {
                if tc.messages.is_empty() || self.rng.next_bool(0.5) {
                    tc.messages = msgs;
                } else {
                    tc.messages.extend(msgs);
                }
                return;
            }
        }

        if self.model.messages.is_empty() {
            return;
        }
        let spec = self.model.messages[self.rng.next_usize(self.model.messages.len())].clone();
        let msg = self.synthesise_from_spec(&spec);

        if tc.messages.is_empty() {
            tc.messages.push(msg);
            return;
        }
        match self.rng.next_usize(3) {
            0 => {
                let idx = self.rng.next_usize(tc.messages.len());
                tc.messages[idx] = msg;
            }
            1 => {
                let at = self.rng.next_usize(tc.messages.len() + 1);
                tc.messages.insert(at, msg);
            }
            _ => tc.messages.push(msg),
        }
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
                if let Some(fidx) = self.pick_weighted_field_index(msg) {
                    let name = msg.fields[fidx].name.clone();
                    if let Some(val) = self.pick_spec_value(&name) {
                        msg.fields[fidx].data = val;
                    } else if !self.model.dictionary.is_empty() {
                        let dict_item = &self.model.dictionary
                            [self.rng.next_usize(self.model.dictionary.len())];
                        msg.fields[fidx].data = dict_item.clone();
                    }
                    self.touch(&name);
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

        if let Some(fidx) = self.pick_weighted_field_index(msg) {
            let name = msg.fields[fidx].name.clone();
            self.mutate_one_field(&mut msg.fields[fidx]);
            self.touch(&name);
            return;
        }

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
        let name = msg.fields[fidx].name.clone();
        self.mutate_one_field(&mut msg.fields[fidx]);
        self.touch(&name);
    }

    fn pick_weighted_field_index(&mut self, msg: &Message) -> Option<usize> {
        let mut weights: Vec<(usize, u32)> = Vec::new();
        let mut total = 0u32;

        for (i, f) in msg.fields.iter().enumerate() {
            if f.protected || f.data.is_empty() {
                continue;
            }
            let mut w = field_type_weight(&f.ftype);
            if w == 0 {
                continue;
            }
            let energy = self.field_energy.get(&f.name).copied().unwrap_or(0);
            w = w.saturating_mul(1 + energy);
            weights.push((i, w));
            total = total.saturating_add(w);
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

    #[test]
    fn energy_boosts_after_interesting() {
        let model = ProtocolModel::ftp();
        let mut m = Mutator::new(1, model, 2, 0.0, 1.0, 0.0, false);
        m.last_touched = vec!["cmd".into()];
        m.on_interesting();
        assert_eq!(m.field_energy.get("cmd"), Some(&2));
    }

    #[test]
    fn synthesise_ftp_login_sequence() {
        let model = ProtocolModel::ftp();
        let mut m = Mutator::new(5, model, 1, 0.0, 0.0, 0.0, false);
        let msgs = m.synthesise_sequence("login");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].name, "user");
        assert_eq!(msgs[1].name, "pass");
    }

    #[test]
    fn template_prob_one_fills_empty() {
        let model = ProtocolModel::mqtt();
        let mut m = Mutator::new(11, model, 1, 0.0, 0.0, 0.0, false).with_template_prob(1.0);
        let child = m.mutate(&TestCase::new(1, vec![]), 2);
        assert!(!child.messages.is_empty());
    }
}
