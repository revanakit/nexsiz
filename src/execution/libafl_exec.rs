//! NEXSIZ – LibAFL Executor (0.15.x)
//! Author  : Revana
//! Date    : 05/08/2026
//!
//! CRITICAL: LibAFL 0.15 ObserversTuple is implemented for `()` and `(Head, Tail)`
//! where Tail is itself an ObserversTuple. A bare `(Obs,)` is NOT valid.
//! Always construct observer lists with `tuple_list!(obs)` → `(Obs, ())`.

use crate::common::config::TargetConfig;
use crate::common::types::{ExecutionResult, OutcomeClass, TestCase};
use crate::execution::connector::{execute_tcp, execute_udp, TcpConnector, UdpConnector};
use crate::execution::reuse::ReusePolicy;
use libafl::executors::{Executor, ExitKind, HasObservers};
use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl::observers::Observer;
use libafl::state::HasExecutions;
use libafl_bolts::tuples::{tuple_list, RefIndexable};
use libafl_bolts::{AsSlice, Named};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Debug;
use std::time::Duration;

pub const RESPONSE_MAP_SIZE: usize = 1 << 16;

/// Coverage / state observer for network responses.
/// Must implement Serialize + Deserialize for Evaluator bounds in LibAFL 0.15.
#[derive(Debug, Serialize, Deserialize)]
pub struct ResponseStateObserver {
    name: Cow<'static, str>,
    map: Vec<u8>,
    pub last_state_hash: u64,
    #[serde(skip)]
    pub last_outcome: OutcomeClass,
}

impl ResponseStateObserver {
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            map: vec![0u8; RESPONSE_MAP_SIZE],
            last_state_hash: 0,
            last_outcome: OutcomeClass::Ok,
        }
    }

    #[inline]
    pub fn map_mut(&mut self) -> &mut [u8] {
        &mut self.map
    }

    pub fn observe_result(&mut self, result: &ExecutionResult) {
        self.last_state_hash = result.state_hash;
        self.last_outcome = result.outcome;

        let mut idx = 0u64;
        for &code in &result.response_codes {
            idx = idx.wrapping_mul(31).wrapping_add(code as u64);
        }
        idx = idx.wrapping_mul(31).wrapping_add(result.state_hash);
        // Also fold grey-box coverage hash when present
        if result.coverage_map_hash != 0 {
            idx = idx.wrapping_mul(31).wrapping_add(result.coverage_map_hash);
        }
        let slot = (idx as usize) % RESPONSE_MAP_SIZE;
        let cell = &mut self.map[slot];
        *cell = cell.saturating_add(1);

        if result.crash
            || result.outcome == OutcomeClass::Crash
            || result.outcome == OutcomeClass::ConnectionReset
        {
            let crash_slot = RESPONSE_MAP_SIZE - 2;
            self.map[crash_slot] = self.map[crash_slot].saturating_add(1);
        }
        if result.hang || result.outcome == OutcomeClass::Hang {
            let hang_slot = RESPONSE_MAP_SIZE - 1;
            self.map[hang_slot] = self.map[hang_slot].saturating_add(1);
        }
    }
}

impl Named for ResponseStateObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for ResponseStateObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), libafl::Error> {
        self.map.fill(0);
        self.last_state_hash = 0;
        self.last_outcome = OutcomeClass::Ok;
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), libafl::Error> {
        Ok(())
    }
}

fn bytes_to_testcase(id: u64, data: &[u8]) -> TestCase {
    use crate::common::types::{Field, FieldType, Message};

    if data.windows(2).any(|w| w == b"\r\n") {
        let mut messages = Vec::new();
        for (i, chunk) in data.split_inclusive(|&b| b == b'\n').enumerate() {
            if chunk.is_empty() || chunk == b"\n" || chunk == b"\r\n" {
                continue;
            }
            let mut msg = Message::new(format!("m{}", i));
            msg.add_field(Field::new("raw", FieldType::Binary, chunk.to_vec()));
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

/// Canonical observer list type used throughout the LibAFL path.
/// `tuple_list!(ResponseStateObserver)` expands to `(ResponseStateObserver, ())`.
pub type NexsizObservers = (ResponseStateObserver, ());

#[derive(Debug)]
pub struct NexsizNetworkExecutor {
    target: TargetConfig,
    tcp: TcpConnector,
    udp: UdpConnector,
    reuse: ReusePolicy,
    pub observers: NexsizObservers,
    exec_count: u64,
}

impl NexsizNetworkExecutor {
    pub fn new(target: TargetConfig, observers: NexsizObservers) -> Self {
        let addr = target.socket_addr();
        let timeout = target.timeout;
        Self {
            tcp: TcpConnector::new(addr, timeout),
            udp: UdpConnector::new(addr, timeout),
            reuse: ReusePolicy::new(target.max_reuse_messages, 3),
            target,
            observers,
            exec_count: 0,
        }
    }

    fn execute_input(&mut self, input: &BytesInput) -> ExitKind {
        self.exec_count = self.exec_count.wrapping_add(1);
        let binding = input.target_bytes();
        let bytes = binding.as_slice();
        let owned = bytes.to_vec();
        let tc = bytes_to_testcase(self.exec_count, &owned);
        let is_udp = self.target.protocol.eq_ignore_ascii_case("udp");
        let do_reuse = !is_udp && self.reuse.should_reuse();

        if !is_udp && !do_reuse {
            self.reuse.on_reconnect();
            let _ = self.tcp.connect();
        }

        let result = if is_udp {
            execute_udp(&mut self.udp, &tc, 4096).unwrap_or_else(|e| ExecutionResult {
                seed_id: tc.id,
                success: false,
                responses: vec![],
                response_codes: vec![],
                elapsed: Duration::from_millis(0),
                new_coverage: false,
                new_state: false,
                crash: false,
                hang: false,
                error: Some(e.to_string()),
                state_hash: 0,
                outcome: OutcomeClass::Error,
                coverage_hits: 0,
                coverage_map_hash: 0,
            })
        } else {
            match execute_tcp(&mut self.tcp, &tc, do_reuse, 4096) {
                Ok(r) => {
                    self.reuse.update(&r);
                    r
                }
                Err(e) => {
                    let r = ExecutionResult {
                        seed_id: tc.id,
                        success: false,
                        responses: vec![],
                        response_codes: vec![],
                        elapsed: Duration::from_millis(0),
                        new_coverage: false,
                        new_state: false,
                        crash: false,
                        hang: false,
                        error: Some(e.to_string()),
                        state_hash: 0,
                        outcome: OutcomeClass::Error,
                        coverage_hits: 0,
                        coverage_map_hash: 0,
                    };
                    self.reuse.update(&r);
                    r
                }
            }
        };

        // observers.0 is ResponseStateObserver; observers.1 is ()
        self.observers.0.observe_result(&result);

        match result.outcome {
            OutcomeClass::Crash | OutcomeClass::ConnectionReset => ExitKind::Crash,
            OutcomeClass::Hang => ExitKind::Timeout,
            _ => ExitKind::Ok,
        }
    }
}

impl<EM, Z, S> Executor<EM, BytesInput, S, Z> for NexsizNetworkExecutor
where
    S: HasExecutions,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &BytesInput,
    ) -> Result<ExitKind, libafl::Error> {
        *state.executions_mut() += 1;
        Ok(self.execute_input(input))
    }
}

impl HasObservers for NexsizNetworkExecutor {
    type Observers = NexsizObservers;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

pub fn build_default_executor(target: TargetConfig) -> NexsizNetworkExecutor {
    let observer = ResponseStateObserver::new("response_state");
    // tuple_list! produces (ResponseStateObserver, ()) — the form ObserversTuple requires.
    NexsizNetworkExecutor::new(target, tuple_list!(observer))
}
