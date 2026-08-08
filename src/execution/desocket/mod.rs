//! NEXSIZ – Desocketing / protocol-level socket state isolation
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Snapshot / Desocketing track (complete + JSON-driven extension):
//!   Phase 2 – ProtocolReset trait, BuiltinDesocket, SocketState
//!   Phase 3 – restore_epoch coordination with workers, desocket counters,
//!             cost-aware energy on successful post-desocket interesting cases
//!   Phase 4 – Operator-defined DesocketSpec (JSON models) + BinaryLp heuristic
//!
//! Desocketing here means:
//!   1. Protocol-aware reset sequences (QUIT / RSET / DISCONNECT / …)
//!   2. SocketState tracking (clean vs polluted)
//!   3. Integration with ReusePolicy and post-snapshot-restore reconnect
//!   4. JSON-driven sequences (SpecDesocket) and length-prefixed heuristics

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
