//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::oracle_bridge
//!
//! Description
//! -----------
//! Reverse-RPC bridge that lets a Python process act as a live is_interesting
//! oracle. When a client calls register_oracle the connection enters oracle
//! mode; thereafter every ExecutionResult that reaches the BridgedOracle is
//! serialised, pushed to Python, and answered with a boolean. Timeouts and
//! disconnects fall back to the configured native oracle so the campaign never
//! stalls.
//!
//! Core responsibilities
//! ---------------------
//! - Maintain a single active reverse-RPC channel (mpsc + Condvar).
//! - Assign monotonic request IDs and wait for matching responses with a
//!   bounded timeout (DEFAULT_ORACLE_TIMEOUT_MS, overridable).
//! - Expose hits / misses counters for observability.
//! - Provide BridgedOracle – an Oracle implementation that prefers the Python
//!   answer when the bridge is active and otherwise delegates to a fallback.
//! - Serialise ExecutionResult into a compact JSON subset understood by the
//!   Python side (utf8 / base64 encoding for response bodies).
//!
//! Reverse-RPC flow
//! ----------------
//! 1. Python client issues register_oracle → server enters oracle mode and
//!    calls OracleBridge::register(), obtaining a Receiver<OracleRequest>.
//! 2. Engine / workers call BridgedOracle::is_interesting → OracleBridge::query.
//! 3. query builds a JSON line {id, method:"is_interesting", params:…}, sends
//!    it through the channel, then waits on the Condvar for a response or
//!    timeout.
//! 4. The oracle-mode thread in server.rs writes the line to Python, reads the
//!    answer, and calls deliver_response(id, interesting).
//! 5. On timeout, disconnect, or inactive bridge the query returns None and
//!    BridgedOracle falls back to the native oracle.
//!
//! Concurrency & safety
//! --------------------
//! - active flag is an AtomicBool (Relaxed is sufficient – the worst case is
//!   one extra fallback call).
//! - Request channel is guarded by Mutex<Option<Sender>> so register/unregister
//!   are race-free.
//! - Response map + Condvar implement a classic wait/notify pattern; the map
//!   is cleared of timed-out entries by the waiter itself.
//! - Only one Python oracle client is supported at a time (by design). A new
//!   register replaces the previous channel.
//!
//! Timeout & fallback semantics
//! ----------------------------
//! - Default timeout is 100 ms. This is intentionally aggressive so a slow
//!   or stuck Python process cannot drag campaign throughput down.
//! - Crash / hang / ConnectionReset outcomes short-circuit to true before any
//!   Python round-trip (safety net).
//! - On any failure path (inactive, send error, timeout) the miss counter is
//!   incremented and the fallback oracle is used.
//!
//! Design notes
//! ------------
//! - Pure push of the result; Python never pulls. This keeps the hot path
//!   simple and avoids introducing a second control plane.
//! - The JSON schema is deliberately minimal and matches the subset handled
//!   by the local json.rs module (no serde dependency).
//! - BridgedOracle implements the same Oracle trait used by the rest of the
//!   engine, so the rest of the code stays unaware of the Python path.
//!
//! See Also
//! --------
//! - server.rs          : oracle-mode accept/read/write loop
//! - handler.rs         : register_oracle command that triggers the mode switch
//! - monitor/oracle.rs  : Oracle trait and native implementations

use crate::common::types::{ExecutionResult, OutcomeClass};
use crate::monitor::oracle::Oracle;
use crate::scripting::json::{self, JsonValue};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Default timeout for a single Python is_interesting call.
pub const DEFAULT_ORACLE_TIMEOUT_MS: u64 = 100;

/// Request pushed from the engine to the oracle-mode client thread.
pub(crate) struct OracleRequest {
    pub id: u64,
    /// Full JSON line to write to the Python socket (already includes \n).
    pub line: String,
}

/// Shared bridge between the engine and one registered Python oracle client.
pub struct OracleBridge {
    active: AtomicBool,
    req_tx: Mutex<Option<Sender<OracleRequest>>>,
    responses: Mutex<HashMap<u64, bool>>,
    cv: Condvar,
    next_id: AtomicU64,
    timeout: Duration,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl OracleBridge {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            req_tx: Mutex::new(None),
            responses: Mutex::new(HashMap::new()),
            cv: Condvar::new(),
            next_id: AtomicU64::new(1),
            timeout: Duration::from_millis(DEFAULT_ORACLE_TIMEOUT_MS),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout = Duration::from_millis(ms.max(10));
        self
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Called by the RPC client thread after `register_oracle`.
    pub fn register(&self) -> Receiver<OracleRequest> {
        let (tx, rx) = mpsc::channel();
        {
            let mut slot = self.req_tx.lock().unwrap();
            *slot = Some(tx);
        }
        self.active.store(true, Ordering::Relaxed);
        rx
    }

    pub fn unregister(&self) {
        self.active.store(false, Ordering::Relaxed);
        let mut slot = self.req_tx.lock().unwrap();
        *slot = None;
        self.cv.notify_all();
    }

    pub fn deliver_response(&self, id: u64, interesting: bool) {
        {
            let mut map = self.responses.lock().unwrap();
            map.insert(id, interesting);
        }
        self.cv.notify_all();
    }

    /// Query Python. Returns Some(bool) on success, None on timeout/inactive/error.
    pub fn query(&self, result: &ExecutionResult) -> Option<bool> {
        if !self.is_active() {
            return None;
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let params = execution_result_to_json(result);
        let mut req_obj = HashMap::new();
        req_obj.insert("id".into(), JsonValue::Number(id as f64));
        req_obj.insert("method".into(), json::s("is_interesting"));
        req_obj.insert("params".into(), params);
        let line = json::stringify(&JsonValue::Object(req_obj)) + "\n";

        {
            let slot = self.req_tx.lock().unwrap();
            match slot.as_ref() {
                Some(tx) => {
                    if tx.send(OracleRequest { id, line }).is_err() {
                        self.misses.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                }
                None => {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        }

        let deadline = std::time::Instant::now() + self.timeout;
        let mut map = self.responses.lock().unwrap();
        loop {
            if let Some(val) = map.remove(&id) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(val);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let wait = deadline - now;
            let (guard, timeout_result) = self.cv.wait_timeout(map, wait).unwrap();
            map = guard;
            if timeout_result.timed_out() {
                if let Some(val) = map.remove(&id) {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(val);
                }
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
    }
}

impl Default for OracleBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Oracle that prefers Python when the bridge is active, otherwise fallback.
pub struct BridgedOracle {
    bridge: Arc<OracleBridge>,
    fallback: Box<dyn Oracle>,
}

impl BridgedOracle {
    pub fn new(bridge: Arc<OracleBridge>, fallback: Box<dyn Oracle>) -> Self {
        Self { bridge, fallback }
    }
}

impl Oracle for BridgedOracle {
    fn name(&self) -> &str {
        if self.bridge.is_active() {
            "python"
        } else {
            self.fallback.name()
        }
    }

    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        if result.crash
            || result.hang
            || matches!(
                result.outcome,
                OutcomeClass::Crash | OutcomeClass::ConnectionReset | OutcomeClass::Hang
            )
        {
            return true;
        }

        match self.bridge.query(result) {
            Some(v) => v,
            None => self.fallback.is_interesting(result),
        }
    }
}

pub fn execution_result_to_json(r: &ExecutionResult) -> JsonValue {
    let responses: Vec<JsonValue> = r
        .responses
        .iter()
        .map(|b| match std::str::from_utf8(b) {
            Ok(s) => json::obj(vec![("encoding", json::s("utf8")), ("data", json::s(s))]),
            Err(_) => json::obj(vec![
                ("encoding", json::s("base64")),
                ("data", json::s(b64_encode(b))),
            ]),
        })
        .collect();

    let codes: Vec<JsonValue> = r
        .response_codes
        .iter()
        .map(|c| json::n(*c as f64))
        .collect();

    json::obj(vec![
        ("seed_id", json::n(r.seed_id as f64)),
        ("success", json::b(r.success)),
        ("responses", JsonValue::Array(responses)),
        ("response_codes", JsonValue::Array(codes)),
        ("elapsed_ms", json::n(r.elapsed.as_millis() as f64)),
        ("new_coverage", json::b(r.new_coverage)),
        ("new_state", json::b(r.new_state)),
        ("crash", json::b(r.crash)),
        ("hang", json::b(r.hang)),
        (
            "error",
            match &r.error {
                Some(e) => json::s(e.clone()),
                None => JsonValue::Null,
            },
        ),
        ("state_hash", json::n(r.state_hash as f64)),
        ("outcome", json::s(outcome_str(r.outcome))),
        ("coverage_hits", json::n(r.coverage_hits as f64)),
        ("coverage_map_hash", json::n(r.coverage_map_hash as f64)),
    ])
}

fn outcome_str(o: OutcomeClass) -> &'static str {
    match o {
        OutcomeClass::Ok => "ok",
        OutcomeClass::ConnectionReset => "connection_reset",
        OutcomeClass::Hang => "hang",
        OutcomeClass::Crash => "crash",
        OutcomeClass::Error => "error",
    }
}

fn b64_encode(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        i += 3;
    }
    let rest = data.len() - i;
    if rest == 1 {
        let n = (data[i] as u32) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_result() -> ExecutionResult {
        ExecutionResult {
            seed_id: 42,
            success: true,
            responses: vec![b"OK".to_vec()],
            response_codes: vec![200],
            elapsed: Duration::from_millis(3),
            new_coverage: false,
            new_state: false,
            crash: false,
            hang: false,
            error: None,
            state_hash: 0xabc,
            outcome: OutcomeClass::Ok,
            coverage_hits: 0,
            coverage_map_hash: 0,
        }
    }

    #[test]
    fn serialize_result() {
        let j = execution_result_to_json(&sample_result());
        assert_eq!(j.get_u64("seed_id"), Some(42));
        assert_eq!(j.get_str("outcome"), Some("ok"));
    }

    #[test]
    fn inactive_query_returns_none() {
        let b = OracleBridge::new();
        assert!(b.query(&sample_result()).is_none());
    }
}
