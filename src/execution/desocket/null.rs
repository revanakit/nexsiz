//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::null
//!
//! Description:
//! A noop "desocket" implementation that intentionally performs no protocol-
//! level reset or recovery. This provider exists to represent the disabled
//! or opt-out state for connection recovery logic: callers should treat the
//! connection as unchanged and, when reset() returns false, proceed with a
//! full reconnect if desired.
//!
//! Responsibilities:
//! - Provide a minimal, deterministic ProtocolReset implementation that never
//!   attempts I/O or state mutation.
//! - Serve as a stable default for configurations that require a desocket
//!   implementation but do not want any automatic recovery behavior.
//!
//! Semantics:
//! - name() -> "null"
//! - is_enabled() -> false (signals the policy is disabled by design)
//! - reset(conn) -> Ok(false) (no attempt to recover; caller should reconnect)
//!
//! Design notes:
//! - This implementation performs no network operations and therefore cannot
//!   fail with I/O errors; it only returns the protocol-level semantic result.
//! - Use this when you want deterministic behavior in tests, or when caller
//!   logic must unconditionally close/reopen connections rather than attempt
//!   protocol-specific soft recovery.
//!
//! Extension:
//! - To provide custom behavior, implement ProtocolReset with a type that
//!   performs protocol-aware probes and follows the conventions used elsewhere
//!   in the desocket module (name, is_enabled, reset, goodbye).
//!
//! See also: ProtocolReset trait and TcpConnector for expected contracts.

use super::ProtocolReset;
use crate::common::error::Result;
use crate::execution::connector::TcpConnector;

#[derive(Debug, Default)]
pub struct NullDesocket;

impl NullDesocket {
    pub fn new() -> Self {
        Self
    }
}

impl ProtocolReset for NullDesocket {
    fn name(&self) -> &str {
        "null"
    }

    fn is_enabled(&self) -> bool {
        false
    }

    fn reset(&self, _conn: &mut TcpConnector) -> Result<bool> {
        Ok(false)
    }
}
