//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::libafl_mutator
//!

use crate::common::types::{Field, FieldType, Message, TestCase};
use crate::input::model::ProtocolModel;
use crate::input::mutator::Mutator as NexsizMutator;
use libafl::corpus::CorpusId;
use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl::mutators::{MutationResult, Mutator};
use libafl::state::HasRand;
use libafl_bolts::rands::Rand;
use libafl_bolts::{AsSlice, Named};
use std::borrow::Cow;
use std::marker::PhantomData;

fn bytes_to_testcase(id: u64, data: &[u8]) -> TestCase {
    if data.windows(2).any(|w| w == b"\r\n") {
        let mut messages = Vec::new();
        for (i, chunk) in data.split_inclusive(|&b| b == b'\n').enumerate() {
            if chunk.is_empty() || chunk == b"\n" || chunk == b"\r\n" {
                continue;
            }
            let mut msg = Message::new(format!("m{}", i));
            if let Some(sp) = chunk.iter().position(|&b| b == b' ') {
                let (cmd, rest) = chunk.split_at(sp);
                msg.add_field(Field::new("cmd", FieldType::Command, cmd.to_vec()));
                if rest.len() > 1 {
                    msg.add_field(Field::new("sp", FieldType::Binary, b" ".to_vec()).protected());
                    let arg = if rest.ends_with(b"\r\n") {
                        &rest[1..rest.len() - 2]
                    } else if rest.ends_with(b"\n") {
                        &rest[1..rest.len() - 1]
                    } else {
                        &rest[1..]
                    };
                    if !arg.is_empty() {
                        msg.add_field(Field::new("arg", FieldType::String, arg.to_vec()));
                    }
                    if rest.ends_with(b"\r\n") {
                        msg.add_field(
                            Field::new("crlf", FieldType::Binary, b"\r\n".to_vec()).protected(),
                        );
                    }
                }
            } else {
                msg.add_field(Field::new("raw", FieldType::Binary, chunk.to_vec()));
            }
            messages.push(msg);
        }
        if messages.is_empty() {
            let mut msg = Message::new("m0");
            msg.add_field(Field::new("raw", FieldType::Binary, data.to_vec()));
            messages.push(msg);
        }
        TestCase::new(id, messages)
    } else {
        let mut msg = Message::new("m0");
        msg.add_field(Field::new("raw", FieldType::Binary, data.to_vec()));
        TestCase::new(id, vec![msg])
    }
}

#[derive(Debug)]
pub struct NexsizHierarchicalMutator<S> {
    inner: NexsizMutator,
    next_id: u64,
    name: Cow<'static, str>,
    _phantom: PhantomData<S>,
}

impl<S> NexsizHierarchicalMutator<S> {
    pub fn from_protocol(seed: u64, protocol: &str) -> Self {
        let model = match protocol.to_lowercase().as_str() {
            "ftp" => ProtocolModel::ftp(),
            "http" => ProtocolModel::http(),
            "smtp" => ProtocolModel::smtp(),
            _ => ProtocolModel::generic(),
        };
        Self {
            inner: NexsizMutator::new(seed, model, 8, 0.15, 0.70, 0.25, true),
            next_id: 1,
            name: Cow::Borrowed("NexsizHierarchicalMutator"),
            _phantom: PhantomData,
        }
    }
}

impl<S> Named for NexsizHierarchicalMutator<S> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Mutator<BytesInput, S> for NexsizHierarchicalMutator<S>
where
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BytesInput,
    ) -> Result<MutationResult, libafl::Error> {
        let binding = input.target_bytes();
        let data = binding.as_slice().to_vec();
        drop(binding);

        if data.is_empty() {
            let seed_byte = state.rand_mut().next() as u8;
            *input = BytesInput::new(vec![seed_byte]);
            return Ok(MutationResult::Mutated);
        }

        self.next_id = self.next_id.wrapping_add(1);
        let parent = bytes_to_testcase(self.next_id, &data);
        let child = self.inner.mutate(&parent, self.next_id.wrapping_add(1));
        let new_bytes = child.serialize();

        if new_bytes == data {
            if new_bytes.is_empty() {
                *input = BytesInput::new(vec![state.rand_mut().next() as u8]);
            } else {
                let mut buf = new_bytes;
                let idx = (state.rand_mut().next() as usize) % buf.len();
                buf[idx] ^= 0x01;
                *input = BytesInput::new(buf);
            }
        } else {
            *input = BytesInput::new(new_bytes);
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _new_corpus_id: Option<CorpusId>,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}
