//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::state
//!

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
