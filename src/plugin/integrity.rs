//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::plugin::integrity
//!
//! Purpose:
//!   Protocol-aware integrity repairers for mutated messages. This module
//!   exposes a small, explicit API to fix protocol framing, length-prefixes,
//!   checksums and other semantic integrity fields after mutation so that
//!   generated test cases can be sent to targets with correct wire-level
//!   structure.
//!
//! Public API overview:
//!   - trait IntegrityRepair: common interface for all repairers (Send + Sync).
//!     Methods:
//!       - name() -> &str               -- canonical plugin name
//!       - repair_message(&mut Message) -- fix a single message in-place
//!       - repair_testcase(&mut TestCase) -- convenience to repair all messages
//!       - prepare_for_send(&mut TestCase) -- full prepare pipeline (semantic +
//!                                              protocol-specific heuristics)
//!   - resolve_integrity(name: Option<&str>) -> Box<dyn IntegrityRepair>
//!       -- map a name (or None) to a concrete repairer implementation.
//!   - resolve_integrity_for_protocol(integrity_name, protocol_name)
//!       -- choose integrity by explicit name or fall back to protocol model.
//!
//! Implementations included:
//!   - DefaultIntegrityRepair: generic semantic-length/checksum repair using
//!     core::input::integrity helpers.
//!   - NullIntegrityRepair: no-op (useful for raw/byte-level fuzzing).
//!   - HttpIntegrityRepair: HTTP-aware repairs (header/body split, Content-Length,
//!     CRLF normalization).
//!   - FtpIntegrityRepair, SmtpIntegrityRepair: CRLF and protocol terminator handling.
//!   - BinaryIntegrityRepair: length-prefix + CRC repair with endianness option
//!     (big-endian default; BinaryIntegrityRepair::le() for little-endian).
//!
//! Design notes and expectations:
//!   - Repairs are performed in-place and may normalize message buffers to match
//!     common network encodings (CRLF, header separators, length prefixes).
//!   - IntegrityRepair implementations are lightweight wrappers around the
//!     core::input::integrity helpers; side effects and exact heuristics live
//!     in that module (see crate::input::integrity).
//!   - prepare_for_send is intended to be the one-stop method prior to actually
//!     sending a TestCase to a target; it runs message-level repairs and may
//!     apply additional protocol-level transformations.
//!   - BinaryIntegrityRepair exposes an explicit endianness flag to support
//!     protocols that encode length fields in little-endian form.
//!
//! Testing:
//!   Unit tests in this module exercise name resolution and basic repair
//!   behaviors (length rewriting, Content-Length fixup, and endian-name mapping).

use crate::common::types::{Message, TestCase};
use crate::input::integrity as core;

/// Trait for repairing length / checksum / protocol framing after mutation.
pub trait IntegrityRepair: Send + Sync {
    fn name(&self) -> &str;

    /// Repair a single message in-place.
    fn repair_message(&self, msg: &mut Message);

    /// Repair every message in a test case.
    fn repair_testcase(&self, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            self.repair_message(msg);
        }
    }

    /// Full prepare-for-send pipeline (semantic + protocol-aware).
    fn prepare_for_send(&self, tc: &mut TestCase) {
        self.repair_testcase(tc);
    }
}

// ── Default (generic semantic fields only) ───────────────────────────────────

pub struct DefaultIntegrityRepair;

impl IntegrityRepair for DefaultIntegrityRepair {
    fn name(&self) -> &str {
        "default"
    }

    fn repair_message(&self, msg: &mut Message) {
        core::repair_message(msg);
    }

    fn prepare_for_send(&self, tc: &mut TestCase) {
        core::prepare_for_send(tc, "generic");
    }
}

// ── Null (no-op) ─────────────────────────────────────────────────────────────

pub struct NullIntegrityRepair;

impl IntegrityRepair for NullIntegrityRepair {
    fn name(&self) -> &str {
        "null"
    }

    fn repair_message(&self, _msg: &mut Message) {}
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

/// HTTP-aware repair: Content-Length recalculation, header/body split,
/// CRLF normalization, semantic Length/Checksum fields.
pub struct HttpIntegrityRepair;

impl IntegrityRepair for HttpIntegrityRepair {
    fn name(&self) -> &str {
        "http"
    }

    fn repair_message(&self, msg: &mut Message) {
        core::repair_message(msg);
    }

    fn prepare_for_send(&self, tc: &mut TestCase) {
        core::prepare_for_send(tc, "http");
    }
}

// ── FTP ──────────────────────────────────────────────────────────────────────

/// FTP-aware repair: CRLF line termination, semantic fields.
pub struct FtpIntegrityRepair;

impl IntegrityRepair for FtpIntegrityRepair {
    fn name(&self) -> &str {
        "ftp"
    }

    fn repair_message(&self, msg: &mut Message) {
        core::repair_message(msg);
    }

    fn prepare_for_send(&self, tc: &mut TestCase) {
        core::prepare_for_send(tc, "ftp");
    }
}

// ── SMTP ─────────────────────────────────────────────────────────────────────

/// SMTP-aware repair: CRLF termination, DATA terminator awareness.
pub struct SmtpIntegrityRepair;

impl IntegrityRepair for SmtpIntegrityRepair {
    fn name(&self) -> &str {
        "smtp"
    }

    fn repair_message(&self, msg: &mut Message) {
        core::repair_message(msg);
    }

    fn prepare_for_send(&self, tc: &mut TestCase) {
        core::prepare_for_send(tc, "smtp");
    }
}

// ── Binary / length-prefixed ─────────────────────────────────────────────────

/// Binary length-prefix + CRC-capable repair (BE by default).
pub struct BinaryIntegrityRepair {
    pub little_endian: bool,
}

impl BinaryIntegrityRepair {
    pub fn new() -> Self {
        Self {
            little_endian: false,
        }
    }

    pub fn le() -> Self {
        Self {
            little_endian: true,
        }
    }
}

impl Default for BinaryIntegrityRepair {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrityRepair for BinaryIntegrityRepair {
    fn name(&self) -> &str {
        if self.little_endian {
            "binary-le"
        } else {
            "binary"
        }
    }

    fn repair_message(&self, msg: &mut Message) {
        let endian = if self.little_endian {
            core::Endian::Little
        } else {
            core::Endian::Big
        };
        core::repair_message_ex(msg, endian, core::ChecksumAlgo::Crc32);
    }

    fn prepare_for_send(&self, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            self.repair_message(msg);
        }
        // Also apply binary length-prefix heuristic on single-field messages
        core::prepare_for_send(tc, "binary");
    }
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolve integrity plugin by name.
///
/// Accepted names:
///   null | none          → no repair
///   default              → generic semantic fields
///   http | https         → HTTP Content-Length + framing
///   ftp                  → FTP CRLF
///   smtp                 → SMTP CRLF + DATA terminator
///   binary | bin | dns | mqtt | smb | binary-lp
///                        → binary length-prefix + CRC32 (BE)
///   binary-le | bin-le | binary-lp-le | lp-le
///                        → same, little-endian
///
/// When `name` is None the caller should pass the protocol model name
/// so the right repairer is chosen automatically.
pub fn resolve_integrity(name: Option<&str>) -> Box<dyn IntegrityRepair> {
    match name.map(|s| s.to_lowercase()).as_deref() {
        Some("null") | Some("none") => Box::new(NullIntegrityRepair),
        Some("http") | Some("https") => Box::new(HttpIntegrityRepair),
        Some("ftp") => Box::new(FtpIntegrityRepair),
        Some("smtp") => Box::new(SmtpIntegrityRepair),
        // Binary / length-prefix family (includes new protocol models)
        Some("binary")
        | Some("bin")
        | Some("binary-lp")
        | Some("lp")
        | Some("dns")
        | Some("mqtt")
        | Some("smb")
        | Some("cifs") => Box::new(BinaryIntegrityRepair::new()),
        Some("binary-le")
        | Some("bin-le")
        | Some("binary-lp-le")
        | Some("lp-le") => Box::new(BinaryIntegrityRepair::le()),
        Some("default") | None => Box::new(DefaultIntegrityRepair),
        // Unknown name → default (safe)
        Some(_) => Box::new(DefaultIntegrityRepair),
    }
}

/// Convenience: choose integrity plugin from an explicit integrity name
/// or fall back to the protocol model name.
pub fn resolve_integrity_for_protocol(
    integrity_name: Option<&str>,
    protocol_name: Option<&str>,
) -> Box<dyn IntegrityRepair> {
    if let Some(n) = integrity_name {
        if !n.is_empty() && n != "default" {
            return resolve_integrity(Some(n));
        }
    }
    // Auto-select from protocol model
    resolve_integrity(protocol_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{Field, FieldType, Message};

    #[test]
    fn default_repairs_length() {
        let repair = DefaultIntegrityRepair;
        let mut msg = Message::new("t");
        msg.add_field(Field::new("len", FieldType::Length, vec![0, 0]));
        msg.add_field(Field::new("p", FieldType::Binary, vec![1, 2, 3]));
        repair.repair_message(&mut msg);
        assert_eq!(msg.fields[0].data, vec![0, 3]);
    }

    #[test]
    fn null_does_nothing() {
        let repair = NullIntegrityRepair;
        let mut msg = Message::new("t");
        msg.add_field(Field::new("len", FieldType::Length, vec![0xff]));
        repair.repair_message(&mut msg);
        assert_eq!(msg.fields[0].data, vec![0xff]);
    }

    #[test]
    fn http_plugin_repairs_content_length() {
        let repair = HttpIntegrityRepair;
        let mut tc = TestCase::new(1, {
            let mut m = Message::new("req");
            m.add_field(Field::new(
                "raw",
                FieldType::Binary,
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99\r\n\r\nAB".to_vec(),
            ));
            vec![m]
        });
        repair.prepare_for_send(&mut tc);
        let s = String::from_utf8_lossy(&tc.messages[0].fields[0].data);
        assert!(s.contains("Content-Length: 2"));
    }

    #[test]
    fn resolve_auto_from_protocol() {
        let r = resolve_integrity_for_protocol(None, Some("http"));
        assert_eq!(r.name(), "http");
        let r = resolve_integrity_for_protocol(Some("null"), Some("http"));
        assert_eq!(r.name(), "null");
        let r = resolve_integrity_for_protocol(None, Some("ftp"));
        assert_eq!(r.name(), "ftp");
        // New models auto-map to binary
        let r = resolve_integrity_for_protocol(None, Some("dns"));
        assert_eq!(r.name(), "binary");
        let r = resolve_integrity_for_protocol(None, Some("mqtt"));
        assert_eq!(r.name(), "binary");
        let r = resolve_integrity_for_protocol(None, Some("smb"));
        assert_eq!(r.name(), "binary");
    }

    #[test]
    fn binary_le_name() {
        assert_eq!(BinaryIntegrityRepair::le().name(), "binary-le");
    }
}
