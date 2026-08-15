//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::reuse
//!
//! Purpose:
//!   Decision engine for connection reuse and protocol-level "desocket"
//!   reset strategies. This module encapsulates heuristics that allow the
//!   fuzzer to reuse an existing TCP session for multiple messages when it is
//!   safe to do so, reducing expensive reconnect/handshake overhead for
//!   stateful protocols (e.g., FTP, SMTP, HTTP-like services).
//!
//! Key responsibilities:
//!   - Track per-connection metrics (messages sent, consecutive failures) and
//!     maintain a SocketState that distinguishes Clean vs Polluted sessions.
//!   - Maintain a set of response codes considered "safe to continue" and use
//!     them together with failure counters to decide whether to reuse a
//!     connection or force a reset.
//!   - Expose simple API used by workers:
//!       * update(&ExecutionResult) — fold execution outcome into policy state
//!       * should_reuse() -> bool — whether next test may reuse the connection
//!       * needs_desocket() -> bool — whether a protocol-level reset is preferred
//!       * force_reset(), on_reconnect(), on_desocket_ok(), on_desocket_fallback()
//!         — lifecycle control hooks for reconnect/desocket paths.
//!
//! Behavioural summary:
//!   - After each execution, update() increments messages_on_conn, updates the
//!     SocketState, and inspects the ExecutionResult for crashes, hangs, errors,
//!     or "safe" response codes. Failures mark the connection polluted and
//!     increment a failure counter that influences reuse decisions.
//!   - Reuse is allowed only when the connection is currently considered
//!     reusable, failures are below the configured threshold, the socket state
//!     reports reusable, and the per-connection message budget has not been
//!     exhausted.
//!   - When the socket becomes polluted, the policy prefers a protocol-level
//!     desocket reset (Phase 2) when applicable; falling back to a full TCP
//!     reconnect is supported and resets internal counters accordingly.
//!
//! Configuration & defaults:
//!   - ReusePolicy::new(max_messages, max_failures) builds a policy with a
//!     configurable message budget and failure tolerance. Default() maps to
//!     new(32, 3).
//!   - The implementation seeds an internal safe_codes HashSet with common
//!     service "OK"/greeting reply codes (e.g., 200, 220, 230, 250, 331...) and
//!     also populates the full 200..300 success range to be permissive for
//!     HTTP-like services. Adjust this set for protocol-specific deployments.
//!
//! Integration notes & invariants:
//!   - This policy is orthogonal to the network IO layer; it consumes
//!     ExecutionResult instances produced by connector code and provides a
//!     boolean decision to the executor whether to reuse an existing socket.
//!   - The socket_state field (crate::execution::desocket::SocketState) carries
//!     additional phase-2 logic and should be consulted when implementing
//!     desocket vs. reconnect workflows.
//!   - update() must be invoked after every attempt that used the connection
//!     so internal counters remain consistent with actual network traffic.
//!
//! Performance & safety:
//!   - No unsafe code; uses standard collections and plain integer counters.
//!   - Lightweight and intended to run in hot paths — avoid heavy-weight
//!     operations inside update(). Tune max_messages to balance reuse benefit
//!     vs. state staleness for your target protocol.
//!
//! See also:
//!   - crate::execution::desocket for SocketState / desocket reset semantics.
//!   - crate::common::types::ExecutionResult for fields inspected by update().


use crate::common::types::ExecutionResult;
use crate::execution::desocket::{SocketState, SocketStateKind};
use std::collections::HashSet;

/// Decision engine for connection reuse + desocket.
#[derive(Debug, Clone)]
pub struct ReusePolicy {
    /// Maximum number of messages that may be sent on a reused connection
    pub max_messages: usize,
    /// Maximum consecutive failures before forcing a reconnect
    pub max_failures: u32,
    /// Response codes that are considered "safe to continue"
    pub safe_codes: HashSet<i32>,
    /// Current consecutive failure counter
    failures: u32,
    /// Messages sent on the current connection
    messages_on_conn: usize,
    /// Whether the current connection is considered reusable (legacy flag)
    reusable: bool,
    /// Phase 2 socket state
    pub socket_state: SocketState,
}

impl ReusePolicy {
    pub fn new(max_messages: usize, max_failures: u32) -> Self {
        let mut safe_codes = HashSet::new();
        // Common "ready / ok" codes across FTP, SMTP, HTTP-ish services
        for c in [200, 220, 221, 230, 250, 331, 350, 354, 150, 226, 211, 214] {
            safe_codes.insert(c);
        }
        // Also accept generic success-ish ranges
        for c in 200..300 {
            safe_codes.insert(c);
        }
        Self {
            max_messages,
            max_failures,
            safe_codes,
            failures: 0,
            messages_on_conn: 0,
            reusable: false,
            socket_state: SocketState::new(),
        }
    }

    /// Called after every execution to update internal state.
    pub fn update(&mut self, result: &ExecutionResult) {
        self.messages_on_conn += result.responses.len().max(1);
        self.socket_state.on_message_sent();

        if result.crash || result.hang || result.error.is_some() {
            self.failures += 1;
            self.reusable = false;
            self.socket_state.mark_polluted();
            return;
        }

        // Check whether the last response codes look safe
        let last_codes_safe = result
            .response_codes
            .last()
            .map(|c| self.safe_codes.contains(c))
            .unwrap_or(false);

        if last_codes_safe && self.failures == 0 {
            self.reusable = true;
            self.socket_state.mark_clean();
        } else {
            self.reusable = false;
            self.socket_state.on_soft_failure();
        }

        if self.messages_on_conn >= self.max_messages {
            self.reusable = false;
            // Cap reached — treat as needing fresh connection, not necessarily polluted
            if self.socket_state.kind == SocketStateKind::Clean {
                // still clean but over budget → next cycle will reconnect
            }
        }
    }

    /// Should the next test case attempt to reuse the existing connection?
    pub fn should_reuse(&self) -> bool {
        self.reusable
            && self.failures < self.max_failures
            && self.socket_state.is_reusable()
            && self.messages_on_conn < self.max_messages
    }

    /// True when a protocol-level desocket reset is preferred over full reconnect.
    pub fn needs_desocket(&self) -> bool {
        self.socket_state.needs_desocket() && self.failures < self.max_failures
    }

    /// Force a reconnect on the next execution.
    pub fn force_reset(&mut self) {
        self.reusable = false;
        self.failures = 0;
        self.messages_on_conn = 0;
        self.socket_state.mark_disconnected();
    }

    /// Reset after a successful reconnect.
    pub fn on_reconnect(&mut self) {
        self.failures = 0;
        self.messages_on_conn = 0;
        self.reusable = false;
        self.socket_state.mark_disconnected();
        // will be re-evaluated after next successful exec
    }

    /// Called after a successful protocol-level desocket reset.
    pub fn on_desocket_ok(&mut self) {
        self.failures = 0;
        self.socket_state.mark_clean();
        self.reusable = true;
        // keep messages_on_conn — same TCP session
    }

    /// Called when desocket failed and we fell back to full reconnect.
    pub fn on_desocket_fallback(&mut self) {
        self.on_reconnect();
    }

    pub fn failure_count(&self) -> u32 {
        self.failures
    }

    pub fn socket_kind(&self) -> SocketStateKind {
        self.socket_state.kind
    }
}

impl Default for ReusePolicy {
    fn default() -> Self {
        Self::new(32, 3)
    }
}
