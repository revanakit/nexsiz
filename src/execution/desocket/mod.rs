//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::desocket::mod
//!
//! Overview:
//! This module contains the "desocket" (protocol-level connection recovery)
//! subsystem used by the fuzzer to attempt orderly session recovery and to
//! decide whether a live TCP connection can be reused or must be re-established.
//! It centralizes provider selection, the ProtocolReset contract, and helper
//! utilities that coordinate soft resets and reconnects.
//!
//! Key concepts:
//! - ProtocolReset: trait that providers implement to perform protocol-aware
//!   reset probes over an existing TcpConnector (name/is_enabled/reset/goodbye).
//! - Built-in providers: protocol-specific, heuristic resets for common text
//!   protocols (FTP, SMTP, HTTP, MQTT) and length-prefixed binary heuristics.
//! - SpecDesocket: operator-driven provider that sends exact byte sequences
//!   specified in a DesocketSpec (useful for reproducible, model-driven reset).
//! - NullDesocket: a deterministic no-op provider representing "disabled" policy.
//! - SocketState: lightweight per-worker readiness tracking (Clean / Polluted /
//!   Disconnected) used to decide when to attempt desocketing.
//!
//! Responsibilities:
//! - Resolve an appropriate ProtocolReset implementation from a ProtocolModel
//!   or protocol name (resolve_desocket_from_model / resolve_desocket).
//! - Provide a safe helper (reset_or_reconnect) that attempts a soft reset and
//!   falls back to a full reconnect on soft failure or I/O errors.
//! - Export built-in and spec-driven providers for use by worker logic.
//!
//! Semantics:
//! - reset(conn) -> Result<bool, NexsizError>
//!     * Ok(true)  => connection appears reusable (no reconnect required).
//!     * Ok(false) => provider could not recover the session (caller should reconnect).
//!     * Err(_)    => hard I/O error occurred; connection is not usable.
//! - Providers declare is_enabled() to indicate whether they perform any work.
//! - goodbye() returns optional bytes a caller may send politely before closing.
//!
//! Design notes / rationale:
//! - Conservative, fail-safe defaults: ambiguous or repeated soft failures bias
//!   toward reconnecting to avoid contaminating subsequent test cases.
//! - Two resolution pathways: operator-specified DesocketSpec takes precedence,
//!   else a best-effort mapping of model names to built-in heuristics is used.
//! - Keep provider implementations focused and testable; network I/O is
//!   delegated to TcpConnector and converted into the boolean success contract.
//!
//! Usage & extension:
//! - To add a new provider implement ProtocolReset and expose a constructor
//!   (and register a name mapping in resolve_desocket if desired).
//! - Use SpecDesocket for deterministic, model-driven reset sequences; use
//!   BuiltinDesocket for common protocol heuristics; use NullDesocket to opt out.
//!
//! Testing & operational notes:
//! - Unit tests exercise resolution behaviour, naming, and trivial provider
//!   expectations; integration tests should validate probe sequences against
//!   real servers when available.
//!
//! See also: ProtocolReset trait, TcpConnector (I/O/timeout semantics),
//! desocket providers in this module (builtin, spec, null, binary) and
//! SocketState for worker-level readiness tracking.

mod binary;
mod builtin;
mod null;
mod spec;
mod state;

pub use binary::BinaryLpDesocket;
pub use builtin::BuiltinDesocket;
pub use null::NullDesocket;
pub use spec::SpecDesocket;
pub use state::{SocketState, SocketStateKind};

use crate::common::error::Result;
use crate::execution::connector::TcpConnector;
use crate::input::model::ProtocolModel;

/// Capability contract for protocol-level reset / desocket providers.
pub trait ProtocolReset: Send + Sync {
    fn name(&self) -> &str;

    /// Whether this provider actually performs reset work.
    fn is_enabled(&self) -> bool;

    /// Attempt to bring the remote protocol state back to a clean/ready
    /// condition over an *existing* TCP connection.
    ///
    /// Returns Ok(true) if reset succeeded and the connection is still usable.
    /// Returns Ok(false) if reset is not applicable / failed softly
    /// (caller should fall back to full reconnect).
    /// Returns Err only on hard I/O failures that already closed the stream.
    fn reset(&self, conn: &mut TcpConnector) -> Result<bool>;

    /// Optional bytes that can be sent as a “logout / goodbye” before close.
    fn goodbye(&self) -> Option<&[u8]> {
        None
    }
}

/// Preferred resolver: uses operator DesocketSpec when present on the model,
/// otherwise falls back to name-based built-ins / BinaryLp / Null.
pub fn resolve_desocket_from_model(model: &ProtocolModel) -> Box<dyn ProtocolReset> {
    if let Some(ref spec) = model.desocket {
        if !spec.sequences.is_empty() {
            return Box::new(SpecDesocket::from_spec(&model.name, spec));
        }
    }
    resolve_desocket(Some(&model.name))
}

/// Resolve a desocket provider from the active protocol model name.
///
/// Unknown / empty → NullDesocket (no-op).
pub fn resolve_desocket(model_name: Option<&str>) -> Box<dyn ProtocolReset> {
    let name = model_name.unwrap_or("").to_ascii_lowercase();
    match name.as_str() {
        "" | "generic" | "null" | "none" => Box::new(NullDesocket::new()),

        // Text / classic protocols
        "ftp" | "grammar-ftp" | "g-ftp" => Box::new(BuiltinDesocket::ftp()),
        "smtp" | "grammar-smtp" | "g-smtp" => Box::new(BuiltinDesocket::smtp()),
        "mqtt" | "grammar-mqtt" | "g-mqtt" => Box::new(BuiltinDesocket::mqtt()),
        "http" | "https" | "grammar-http" | "g-http" => Box::new(BuiltinDesocket::http()),

        // Length-prefixed binary heuristics
        "binary-lp" | "lp" | "binary" | "grammar-binary-lp" | "g-binary-lp" | "g-lp" => {
            Box::new(BinaryLpDesocket::be2())
        }
        "binary-lp-le" | "lp-le" | "binary-le" | "grammar-binary-lp-le" | "g-lp-le" => {
            Box::new(BinaryLpDesocket::le2())
        }
        "binary-lp4" | "lp4" | "binary-lp-4" => Box::new(BinaryLpDesocket::be4()),
        "binary-lp4-le" | "lp4-le" | "binary-lp-4-le" => Box::new(BinaryLpDesocket::le4()),

        _ => Box::new(NullDesocket::new()),
    }
}

/// Convenience: try protocol reset; on soft failure force full reconnect.
pub fn reset_or_reconnect(
    desocket: &dyn ProtocolReset,
    conn: &mut TcpConnector,
) -> Result<()> {
    if !desocket.is_enabled() {
        conn.close();
        return conn.connect();
    }
    match desocket.reset(conn) {
        Ok(true) => Ok(()),
        Ok(false) => {
            conn.close();
            conn.connect()
        }
        Err(_) => {
            conn.close();
            conn.connect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::model::{DesocketSpec, ProtocolModel};

    #[test]
    fn resolve_ftp() {
        let d = resolve_desocket(Some("ftp"));
        assert!(d.is_enabled());
        assert_eq!(d.name(), "ftp");
    }

    #[test]
    fn resolve_binary_lp() {
        let d = resolve_desocket(Some("binary-lp"));
        assert!(d.is_enabled());
        assert_eq!(d.name(), "binary-lp");
    }

    #[test]
    fn resolve_unknown_is_null() {
        let d = resolve_desocket(Some("custom-opaque"));
        assert!(!d.is_enabled());
        assert_eq!(d.name(), "null");
    }

    #[test]
    fn from_model_prefers_spec() {
        let mut m = ProtocolModel::generic();
        m.name = "my-custom".into();
        let mut spec = DesocketSpec::default();
        spec.sequences.push(vec![0x00, 0x00]);
        m.desocket = Some(spec);
        let d = resolve_desocket_from_model(&m);
        assert!(d.is_enabled());
        assert!(d.name().starts_with("spec:"));
    }

    #[test]
    fn from_model_falls_back_to_name() {
        let m = ProtocolModel::ftp();
        let d = resolve_desocket_from_model(&m);
        assert!(d.is_enabled());
        assert_eq!(d.name(), "ftp");
    }

    #[test]
    fn null_name() {
        let d = NullDesocket::new();
        assert_eq!(d.name(), "null");
        assert!(!d.is_enabled());
    }
}
