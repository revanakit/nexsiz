//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::libafl_exec
//!
//! Purpose:
//!   Implements a LibAFL-compatible network executor that adapts NEXSIZ's
//!   stateful message TestCase model to LibAFL's BytesInput executor API.
//!   This module is responsible for:
//!     - Translating raw input bytes into NEXSIZ TestCase(s).
//!     - Driving TCP/UDP connectors and applying the configured reuse policy.
//!     - Folding behavioural \"response\" observations into a process-global
//!       hitcount-style map exposed via StdMapObserver for feedback and
//!       triage (behavioural coverage / response clustering).
//!
//! Key types and exports:
//!   - ResponseMapObserver: StdMapObserver<'static, u8, false> — canonical
//!     hitcounts-style map observer used by feedbacks.
//!   - NexsizObservers: tuple containing the single response map observer.
//!   - NexsizNetworkExecutor: Executor implementation that executes
//!     BytesInput by sending network messages and updating observers.
//!   - make_response_observer(): creates a process-lifetime response map and
//!     returns a StdMapObserver pointing to it.
//!   - build_default_executor(): constructs an executor with a fresh observer.
//!   - build_executor_with_observer(): constructs an executor from an existing
//!     StdMapObserver (useful when sharing the same observer instance with
//!     feedbacks like MaxMapFeedback).
//!
//! Important implementation notes & compatibility (LibAFL 0.15):
//!   - Observers tuple shape: libafl expects observers as a nested tuple:
//!     `()` or `(Head, Tail)` where Tail is itself an ObserversTuple. Use
//!     `tuple_list!(obs)` so the resulting type matches `(Obs, ())`.
//!   - StdMapObserver and MaxMapFeedback: MaxMapFeedback resolves its map
//!     observer by name inside the executor's observer list. The StdMapObserver
//!     instance passed to MaxMapFeedback::new MUST be the same instance (same
//!     name) that is later moved into the executor. Using a distinct or detached
//!     observer will lead to an unwrap panic at evaluation time.
//!   - Lifetime & safety: make_response_observer() intentionally leaks a
//!     boxed slice to produce a `'static` mutable pointer for StdMapObserver.
//!     This is deliberate: a single, process-global map is sufficient for the
//!     single-core LibAFL path. The leak is documented and the observer is
//!     created via unsafe from_mut_ptr — do not change this contract without
//!     ensuring the observer instance and its backing memory remain valid.
//!   - Map semantics: map stores u8 hitcounts (non-differential). Special
//!     reserved slots near the map end are used to aggregate crashes/hangs.
//!
//! Behavioural folding (observe_into_map):
//!   - Response codes and state/coverage hashes are folded into a 64-bit
//!     accumulator and reduced modulo the map size to produce a slot index.
//!   - The accumulator combines response_codes, state_hash and optionally
//!     coverage_map_hash to create a compact behavioural signature.
//!
//! Safety & robustness:
//!   - The module converts network errors into a canonical ExecutionResult and
//!     updates the reuse policy accordingly; no panics should be triggered by
//!     normal network failures.
//!   - The only explicit unsafe is the StdMapObserver::from_mut_ptr call which
//!     relies on the leaked backing array staying valid for the process lifetime.
//!
//! See also:
//!   - crate::execution::connector for TCP/UDP send/receive helpers.
//!   - crate::execution::reuse for connection reuse policy and heuristics.
//!   - LibAFL docs for details on Executor, Observer, and feedback wiring.

use crate::common::config::TargetConfig;
use crate::common::types::{ExecutionResult, OutcomeClass, TestCase};
use crate::execution::connector::{execute_tcp, execute_udp, TcpConnector, UdpConnector};
use crate::execution::reuse::ReusePolicy;
use libafl::executors::{Executor, ExitKind, HasObservers};
use libafl::inputs::{BytesInput, HasTargetBytes};
use libafl::observers::{MapObserver, Observer, StdMapObserver};
use libafl::state::HasExecutions;
use libafl_bolts::tuples::{tuple_list, RefIndexable};
use libafl_bolts::{AsSlice, Named};
use std::time::Duration;

pub const RESPONSE_MAP_SIZE: usize = 1 << 16;

/// Canonical observer: hitcounts map (u8), non-differential.
pub type ResponseMapObserver = StdMapObserver<'static, u8, false>;

/// Canonical observer list: single StdMapObserver named "response_map".
/// `tuple_list!(obs)` expands to `(Obs, ())`.
pub type NexsizObservers = (ResponseMapObserver, ());

/// Build a process-lifetime response map and a StdMapObserver over it.
///
/// The map is leaked so the observer can carry a `'static` lifetime and be
/// moved freely into the executor / feedback without borrow issues. One map
/// per process is fine for the single-core LibAFL path.
pub fn make_response_observer() -> ResponseMapObserver {
    let map: &'static mut [u8] =
        Box::leak(vec![0u8; RESPONSE_MAP_SIZE].into_boxed_slice());
    // Safety: map is leaked, never freed, never moved — satisfies from_mut_ptr contract.
    unsafe { StdMapObserver::from_mut_ptr("response_map", map.as_mut_ptr(), RESPONSE_MAP_SIZE) }
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

/// Fold an ExecutionResult into the response map (hitcounts-style).
fn observe_into_map(map: &mut [u8], result: &ExecutionResult) {
    let mut idx = 0u64;
    for &code in &result.response_codes {
        idx = idx.wrapping_mul(31).wrapping_add(code as u64);
    }
    idx = idx.wrapping_mul(31).wrapping_add(result.state_hash);
    if result.coverage_map_hash != 0 {
        idx = idx.wrapping_mul(31).wrapping_add(result.coverage_map_hash);
    }
    let slot = (idx as usize) % map.len().max(1);
    map[slot] = map[slot].saturating_add(1);

    if result.crash
        || result.outcome == OutcomeClass::Crash
        || result.outcome == OutcomeClass::ConnectionReset
    {
        let crash_slot = map.len().saturating_sub(2);
        map[crash_slot] = map[crash_slot].saturating_add(1);
    }
    if result.hang || result.outcome == OutcomeClass::Hang {
        let hang_slot = map.len().saturating_sub(1);
        map[hang_slot] = map[hang_slot].saturating_add(1);
    }
}

#[derive(Debug)]
pub struct NexsizNetworkExecutor {
    target: TargetConfig,
    tcp: TcpConnector,
    udp: UdpConnector,
    reuse: ReusePolicy,
    pub observers: NexsizObservers,
    exec_count: u64,
    last_outcome: OutcomeClass,
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
            last_outcome: OutcomeClass::Ok,
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

        self.last_outcome = result.outcome;

        // Write behavioural coverage into the StdMapObserver map.
        // observers.0 is StdMapObserver; MapObserver::map_mut gives &mut [u8].
        {
            let map = self.observers.0.map_mut();
            observe_into_map(map, &result);
        }

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

/// Build executor with a fresh response-map observer.
/// Prefer `build_executor_with_observer` when the same observer must also be
/// passed to MaxMapFeedback::new (canonical wiring).
pub fn build_default_executor(target: TargetConfig) -> NexsizNetworkExecutor {
    let observer = make_response_observer();
    NexsizNetworkExecutor::new(target, tuple_list!(observer))
}

/// Build executor from an already-constructed StdMapObserver.
/// Used by the runner so MaxMapFeedback and the executor share one instance.
pub fn build_executor_with_observer(
    target: TargetConfig,
    observer: ResponseMapObserver,
) -> NexsizNetworkExecutor {
    NexsizNetworkExecutor::new(target, tuple_list!(observer))
}

// Silence unused-import noise when Observer trait methods are only used via
// the StdMapObserver impl in libafl itself.
#[allow(dead_code)]
fn _observer_trait_bound<O: Observer<(), ()> + MapObserver + Named>(_: &O) {}
