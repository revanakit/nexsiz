//! NEXSIZ – Intelligent Connection Reuse + Desocket awareness
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! The key idea: after a successful execution that leaves the target in a
//! known "safe" state, subsequent test cases that share a common safe
//! prefix can be sent on the same TCP connection, avoiding the costly
//! connect / handshake / authentication overhead.
//!
//! Phase 2: SocketState tracks Clean vs Polluted. When polluted, the
//! worker prefers a protocol-level desocket reset before falling back
//! to full TCP reconnect.

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
