//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::state
//!
//! Purpose:
//! This module defines a compact, worker-local representation of TCP session
//! readiness used by the fuzzer to decide whether a live connection can be
//! reused or requires protocol-level recovery (desocket) or a full reconnect.
//!
//! Key types:
//! - SocketStateKind: coarse-grained readiness categories (Disconnected, Clean,
//!   Polluted) that capture the fuzzer's operational view of protocol state.
//! - SocketState: lightweight per-worker state tracking message counts and
//!   consecutive soft failures; provides helper methods to transition and
//!   query reuse-desocket decisions.
//!
//! Responsibilities:
//! - Provide clear, deterministic transitions for common connection outcomes
//!   (mark_disconnected, mark_clean, mark_polluted).
//! - Track metrics that influence reuse decisions:
//!     * messages_on_conn — number of messages exchanged on the current TCP session.
//!     * soft_failures — consecutive non-fatal anomalies (timeouts, unexpected codes).
//! - Expose predicate helpers:
//!     * is_reusable() — safe to reuse the connection for next test case.
//!     * needs_desocket() — prefer a protocol-level reset before reuse.
//!
//! Semantics and safety:
//! - The state is intentionally conservative: after repeated soft failures the
//!   connection is considered Polluted to avoid false reuse during fuzzing.
//! - SocketState is NOT a substitute for low-level socket health — callers
//!   should still consult TcpConnector for connection presence and I/O errors.
//!
//! Design notes / rationale:
//! - Keep the state model minimal and deterministic to simplify worker logic and
//!   make fuzzing sessions reproducible.
//! - Use saturating arithmetic for counters to avoid overflow in long-running
//!   fuzzing jobs.
//! - Favor fail-safe behavior: ambiguous outcomes should bias toward reconnecting
//!   rather than risking session reuse that may invalidate subsequent tests.
//!
//! Testing & extension:
//! - Unit tests should validate transition behaviour, saturation semantics, and
//!   predicate correctness. Integration tests can assert that higher-level
//!   recovery logic (desocket selection) reacts to SocketState transitions as expected.
//!
//! See also: desocket providers (builtin/spec/null) and TcpConnector for actual
//! I/O/timeout semantics and the ProtocolReset contract used by recovery logic.

/// Coarse connection readiness from the fuzzer’s point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocketStateKind {
    /// No live connection, or connection just opened / after full reconnect.
    #[default]
    Disconnected,
    /// TCP up, protocol handshake / login completed, safe to continue.
    Clean,
    /// TCP up but protocol state is unknown or polluted (deep mutation,
    /// unexpected response, post-crash before restore).
    Polluted,
}

/// Lightweight per-worker socket state.
#[derive(Debug, Clone)]
pub struct SocketState {
    pub kind: SocketStateKind,
    /// How many messages have been exchanged on the current TCP session.
    pub messages_on_conn: usize,
    /// Consecutive soft failures (timeouts / unexpected codes).
    pub soft_failures: u32,
}

impl Default for SocketState {
    fn default() -> Self {
        Self {
            kind: SocketStateKind::Disconnected,
            messages_on_conn: 0,
            soft_failures: 0,
        }
    }
}

impl SocketState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_disconnected(&mut self) {
        self.kind = SocketStateKind::Disconnected;
        self.messages_on_conn = 0;
        self.soft_failures = 0;
    }

    pub fn mark_clean(&mut self) {
        self.kind = SocketStateKind::Clean;
        self.soft_failures = 0;
    }

    pub fn mark_polluted(&mut self) {
        self.kind = SocketStateKind::Polluted;
    }

    pub fn on_message_sent(&mut self) {
        self.messages_on_conn = self.messages_on_conn.saturating_add(1);
    }

    pub fn on_soft_failure(&mut self) {
        self.soft_failures = self.soft_failures.saturating_add(1);
        if self.soft_failures >= 2 {
            self.kind = SocketStateKind::Polluted;
        }
    }

    /// True when we believe the connection is safe to reuse for the next test case.
    pub fn is_reusable(&self) -> bool {
        self.kind == SocketStateKind::Clean
    }

    /// True when a protocol-level reset (desocket) is preferable before the next case.
    pub fn needs_desocket(&self) -> bool {
        self.kind == SocketStateKind::Polluted
    }
}
