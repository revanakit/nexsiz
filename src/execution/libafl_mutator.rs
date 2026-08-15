//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::libafl_mutator
//!
//! Purpose:
//!   Provides a LibAFL-compatible hierarchical mutator that adapts raw
//!   byte-oriented BytesInput into NEXSIZ TestCase structures, performs
//!   semantic/hierarchical mutations using the internal NexsizMutator, and
//!   serializes the mutated TestCase back into bytes for execution.
//!
//! Responsibilities:
//!   - Convert raw byte buffers into NEXSIZ TestCase(s) with message/field
//!     structure (see bytes_to_testcase).
//!   - Drive NexsizMutator to produce hierarchical, protocol-aware mutations.
//!   - Provide a Mutator<BytesInput, S> impl compatible with LibAFL's fuzzer
//!     loop, including a deterministic per-mutation id generator (next_id).
//!   - Apply simple fallbacks when the hierarchical mutator returns unchanged
//!     output (random seed byte or single-bit flip) to ensure the input corpus
//!     is progressed.
//!
//! Key types & functions:
//!   - bytes_to_testcase(id, data): Parse input bytes into a TestCase. If the
//!     payload contains CRLF-delimited lines, each line is converted to a
//!     Message with semantic fields where possible:
//!       * If a space separates a command and arguments, fields `cmd` (Command),
//!         `sp` (protected single-space separator), optional `arg` (String),
//!         and optional `crlf` (protected CRLF) are created.
//!       * Otherwise the whole chunk is stored as a `raw` Binary field.
//!     If no CRLFs are found, the entire payload becomes a single `raw` field.
//!
//!   - NexsizHierarchicalMutator<S>:
//!       * Wraps `inner: NexsizMutator` (semantic mutator) and exposes it as a
//!         libafl Mutator for BytesInput.
//!       * Constructor: from_protocol(seed, protocol) chooses a ProtocolModel
//!         (ftp/http/smtp/generic) and initializes NexsizMutator with the
//!         configured hyperparameters (depth/hyperprobs). These parameters
//!         control mutation depth, mutation probabilities and integrity repair.
//!       * Mutation flow:
//!           1. Convert input bytes → parent TestCase (bytes_to_testcase).
!//            2. Call inner.mutate(parent, next_id+1) to obtain a mutated
//!               TestCase (child).
//!            3. Serialize child → new_bytes and replace the BytesInput contents.
//!            4. If new_bytes == original, apply a deterministic fallback:
//!               - If empty: replace with a single pseudorandom seed byte.
//!               - Else: flip a single bit at a pseudorandom index.
//!
//! Compatibility & traits:
//!   - Implements libafl::mutators::Mutator<BytesInput, S> where S: HasRand.
//!   - Implements libafl_bolts::Named for runtime identification in LibAFL
//!     mutator pipelines.
//!   - post_exec() is a no-op; corpus bookkeeping is handled externally.
//!
//! Determinism, safety & performance notes:
//!   - The mutator maintains a wrapping u64 `next_id` used to generate unique
//!     ids per mutation; these are used as seeds/ids passed to the hierarchical
//!     mutator to preserve reproducibility where required.
//!   - Randomness is sourced from the libafl state (HasRand). No unsafe code
//!     or global mutable state is required here.
//!   - The implementation clones/serializes buffers when converting between
//!     BytesInput and TestCase; this is acceptable for typical fuzzing workloads
//!     but can be optimized later if profiling demands it.
//!
//! See also:
//!   - crate::input::mutator::Mutator (NexsizMutator) for the internal
//!     hierarchical/semantic mutation logic and integrity repair heuristics.
//!   - crate::input::model::ProtocolModel for protocol-specific field schemas.
    
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
