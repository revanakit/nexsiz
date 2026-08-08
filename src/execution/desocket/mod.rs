//! NEXSIZ – Desocketing / protocol-level socket state isolation
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Snapshot / Desocketing track (complete):
//!   Phase 2 – ProtocolReset trait, BuiltinDesocket, SocketState
//!   Phase 3 – restore_epoch coordination with workers, desocket counters,
//!             cost-aware energy on successful post-desocket interesting cases
//!
//! Desocketing here means:
//!   1. Protocol-aware reset sequences (QUIT / RSET / DISCONNECT / …)
//!   2. SocketState tracking (clean vs polluted)
//!   3. Integration with ReusePolicy and post-snapshot-restore reconnect
//!   4. Heuristic length-prefixed binary reset (BinaryLpDesocket)

mod binary;
mod builtin;
mod null;
mod state;

pub use binary::BinaryLpDesocket;
pub use builtin::BuiltinDesocket;
pub use null::NullDesocket;
pub use state::{SocketState, SocketStateKind};

use crate::common::error::Result;
use crate::execution::connector::TcpConnector;

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

        // Length-prefixed binary (2-byte big-endian – most common)
        "binary-lp" | "lp" | "binary" | "grammar-binary-lp" | "g-binary-lp" | "g-lp" => {
            Box::new(BinaryLpDesocket::be2())
        }

        // 2-byte little-endian
        "binary-lp-le" | "lp-le" | "binary-le" | "grammar-binary-lp-le" | "g-lp-le" => {
            Box::new(BinaryLpDesocket::le2())
        }

        // 4-byte variants (explicit)
        "binary-lp4" | "lp4" | "binary-lp-4" => Box::new(BinaryLpDesocket::be4()),
        "binary-lp4-le" | "lp4-le" | "binary-lp-4-le" => Box::new(BinaryLpDesocket::le4()),

        // Everything else stays Null (opaque / custom JSON without LP hint)
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
    fn resolve_binary_lp_le() {
        let d = resolve_desocket(Some("binary-lp-le"));
        assert!(d.is_enabled());
        assert_eq!(d.name(), "binary-lp-le");
    }

    #[test]
    fn resolve_lp_alias() {
        let d = resolve_desocket(Some("lp"));
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
    fn null_name() {
        let d = NullDesocket::new();
        assert_eq!(d.name(), "null");
        assert!(!d.is_enabled());
    }
}
