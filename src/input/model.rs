//! NEXSIZ – Protocol model, seed parsing, and structured field trees
//! Author  : Revana
//! Date    : 07/08/2026
//!
//! Provides a lightweight way to represent protocol messages as sequences
//! of semantic fields. Seeds can be loaded as raw bytes or text lines.
//! Extended with optional field-tree specs for operator-defined models
//! and formal built-ins (DNS, MQTT, SMB, binary length-prefix).

use crate::common::error::{NexsizError, Result};
use crate::common::types::*;
use crate::common::utils::hash_bytes;
use std::fs;
use std::path::Path;

/// Endianness for length / checksum fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModelEndian {
    #[default]
    Big,
    Little,
}

/// Preferred checksum algorithm when a Checksum field is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModelChecksum {
    #[default]
    Auto, // choose by field width
    Additive,
    Xor,
    Crc16,
    Crc32,
    OnesComplement,
}

/// Description of a single semantic field inside a message template.
#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub name: String,
    pub ftype: FieldType,
    /// Fixed size in bytes (None = variable)
    pub size: Option<usize>,
    /// Whether aggressive mutation should skip this field
    pub protected: bool,
    /// Optional known interesting values for this field
    pub values: Vec<Vec<u8>>,
    /// Endian override for Length / Checksum / Numeric
    pub endian: Option<ModelEndian>,
}

impl FieldSpec {
    pub fn new(name: impl Into<String>, ftype: FieldType) -> Self {
        Self {
            name: name.into(),
            ftype,
            size: None,
            protected: false,
            values: Vec::new(),
            endian: None,
        }
    }

    pub fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    pub fn protected(mut self) -> Self {
        self.protected = true;
        self
    }

    pub fn values<I, B>(mut self, vals: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        self.values = vals.into_iter().map(|b| b.as_ref().to_vec()).collect();
        self
    }

    pub fn endian(mut self, e: ModelEndian) -> Self {
        self.endian = Some(e);
        self
    }
}

/// Template for one protocol message (ordered field specs).
#[derive(Debug, Clone)]
pub struct MessageSpec {
    pub name: String,
    pub fields: Vec<FieldSpec>,
}

impl MessageSpec {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
        }
    }

    pub fn field(mut self, f: FieldSpec) -> Self {
        self.fields.push(f);
        self
    }
}

/// Minimal protocol model used to guide mutation and integrity repair.
/// Backward-compatible: existing constructors still work; new fields have
/// sensible defaults so older code paths remain unchanged.
#[derive(Debug, Clone)]
pub struct ProtocolModel {
    pub name: String,
    /// Known interesting values for numeric / command fields
    pub dictionary: Vec<Vec<u8>>,
    /// Whether the protocol uses length-prefixed messages
    pub length_prefixed: bool,
    /// Whether messages end with a delimiter
    pub delimiter: Option<u8>,
    /// Default endian for length / checksum fields
    pub endian: ModelEndian,
    /// Preferred checksum algorithm
    pub checksum: ModelChecksum,
    /// Optional structured message templates (field trees)
    pub messages: Vec<MessageSpec>,
    /// Width of length prefix when length_prefixed is true (1/2/4)
    pub length_width: Option<usize>,
}

impl ProtocolModel {
    pub fn generic() -> Self {
        Self {
            name: "generic".to_string(),
            dictionary: vec![
                b"\x00".to_vec(),
                b"\xff".to_vec(),
                b"\x00\x00".to_vec(),
                b"\xff\xff".to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                b"\xff\xff\xff\xff".to_vec(),
                b"A".to_vec(),
                b"%n".to_vec(),
                b"%s".to_vec(),
                b"../".to_vec(),
                b"\r\n".to_vec(),
            ],
            length_prefixed: false,
            delimiter: None,
            endian: ModelEndian::Big,
            checksum: ModelChecksum::Auto,
            messages: Vec::new(),
            length_width: None,
        }
    }

    pub fn ftp() -> Self {
        let mut m = Self::generic();
        m.name = "ftp".to_string();
        m.dictionary.extend(vec![
            b"USER".to_vec(),
            b"PASS".to_vec(),
            b"LIST".to_vec(),
            b"RETR".to_vec(),
            b"STOR".to_vec(),
            b"QUIT".to_vec(),
            b"SYST".to_vec(),
            b"PWD".to_vec(),
            b"CWD".to_vec(),
            b"TYPE".to_vec(),
            b"PASV".to_vec(),
            b"PORT".to_vec(),
            b"anonymous".to_vec(),
            b"\r\n".to_vec(),
        ]);
        m.delimiter = Some(b'\n');
        m
    }

    pub fn http() -> Self {
        let mut m = Self::generic();
        m.name = "http".to_string();
        m.dictionary.extend(vec![
            b"GET".to_vec(),
            b"POST".to_vec(),
            b"PUT".to_vec(),
            b"DELETE".to_vec(),
            b"HEAD".to_vec(),
            b"OPTIONS".to_vec(),
            b"HTTP/1.0".to_vec(),
            b"HTTP/1.1".to_vec(),
            b"Host:".to_vec(),
            b"Content-Length:".to_vec(),
            b"Content-Type:".to_vec(),
            b"Connection:".to_vec(),
            b"Cookie:".to_vec(),
            b"\r\n".to_vec(),
            b"\r\n\r\n".to_vec(),
        ]);
        m.delimiter = Some(b'\n');
        m
    }

    pub fn smtp() -> Self {
        let mut m = Self::generic();
        m.name = "smtp".to_string();
        m.dictionary.extend(vec![
            b"HELO".to_vec(),
            b"EHLO".to_vec(),
            b"MAIL FROM:".to_vec(),
            b"RCPT TO:".to_vec(),
            b"DATA".to_vec(),
            b"QUIT".to_vec(),
            b"RSET".to_vec(),
            b"VRFY".to_vec(),
            b"\r\n".to_vec(),
            b".\r\n".to_vec(),
        ]);
        m.delimiter = Some(b'\n');
        m
    }

    // ── New formal models ────────────────────────────────────────────────────

    /// DNS (basic query). Length-prefix on TCP (2-byte BE), classic 12-byte header.
    pub fn dns() -> Self {
        let mut m = Self::generic();
        m.name = "dns".to_string();
        m.length_prefixed = true;
        m.length_width = Some(2);
        m.endian = ModelEndian::Big;
        m.dictionary.extend(vec![
            // Header flags / opcodes
            b"\x01\x00".to_vec(), // standard query
            b"\x00\x00".to_vec(),
            b"\x00\x01".to_vec(), // QDCOUNT=1
            // Common QTYPEs
            b"\x00\x01".to_vec(), // A
            b"\x00\x1c".to_vec(), // AAAA
            b"\x00\x0f".to_vec(), // MX
            b"\x00\x10".to_vec(), // TXT
            b"\x00\xff".to_vec(), // ANY
            // QCLASS
            b"\x00\x01".to_vec(), // IN
            // Interesting names
            b"\x03www\x07example\x03com\x00".to_vec(),
            b"\x00".to_vec(), // root
            b"\xff\xff".to_vec(),
        ]);
        m.messages = vec![
            MessageSpec::new("query")
                .field(FieldSpec::new("tcp_len", FieldType::Length).with_size(2).endian(ModelEndian::Big))
                .field(FieldSpec::new("txid", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("flags", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("qdcount", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("ancount", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("nscount", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("arcount", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("qname", FieldType::Binary))
                .field(FieldSpec::new("qtype", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("qclass", FieldType::Numeric).with_size(2)),
        ];
        m
    }

    /// MQTT 3.1.1 / 5.0 basic (fixed header + remaining length + variable header).
    pub fn mqtt() -> Self {
        let mut m = Self::generic();
        m.name = "mqtt".to_string();
        m.length_prefixed = true; // remaining length is variable-byte integer
        m.length_width = None; // special encoding
        m.endian = ModelEndian::Big;
        m.dictionary.extend(vec![
            // Packet types (upper nibble)
            b"\x10".to_vec(), // CONNECT
            b"\x20".to_vec(), // CONNACK
            b"\x30".to_vec(), // PUBLISH
            b"\x40".to_vec(), // PUBACK
            b"\x80".to_vec(), // SUBSCRIBE
            b"\x90".to_vec(), // SUBACK
            b"\xc0".to_vec(), // PINGREQ
            b"\xd0".to_vec(), // PINGRESP
            b"\xe0".to_vec(), // DISCONNECT
            // Protocol name / level
            b"MQTT".to_vec(),
            b"\x04".to_vec(), // 3.1.1
            b"\x05".to_vec(), // 5.0
            b"\x00".to_vec(),
            b"\xff".to_vec(),
            // Common topics / client ids
            b"test/topic".to_vec(),
            b"#".to_vec(),
            b"+".to_vec(),
            b"client".to_vec(),
        ]);
        m.messages = vec![
            MessageSpec::new("connect")
                .field(FieldSpec::new("fixed_hdr", FieldType::Command).with_size(1).values([b"\x10"]))
                .field(FieldSpec::new("remaining_len", FieldType::Length)) // variable-byte in real MQTT
                .field(FieldSpec::new("proto_name_len", FieldType::Length).with_size(2))
                .field(FieldSpec::new("proto_name", FieldType::String).values([b"MQTT"]))
                .field(FieldSpec::new("proto_level", FieldType::Numeric).with_size(1))
                .field(FieldSpec::new("connect_flags", FieldType::Numeric).with_size(1))
                .field(FieldSpec::new("keep_alive", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("client_id", FieldType::String)),
            MessageSpec::new("publish")
                .field(FieldSpec::new("fixed_hdr", FieldType::Command).with_size(1).values([b"\x30"]))
                .field(FieldSpec::new("remaining_len", FieldType::Length))
                .field(FieldSpec::new("topic_len", FieldType::Length).with_size(2))
                .field(FieldSpec::new("topic", FieldType::String))
                .field(FieldSpec::new("payload", FieldType::Binary)),
        ];
        m
    }

    /// SMB / NetBIOS session service skeleton (very common length-prefix + header).
    pub fn smb() -> Self {
        let mut m = Self::generic();
        m.name = "smb".to_string();
        m.length_prefixed = true;
        m.length_width = Some(4); // NetBIOS session length (BE, high byte often 0)
        m.endian = ModelEndian::Big;
        m.dictionary.extend(vec![
            // NetBIOS session types
            b"\x00".to_vec(), // session message
            b"\x81".to_vec(), // session request
            b"\x82".to_vec(), // positive response
            // SMB magic
            b"\xffSMB".to_vec(), // SMB1
            b"\xfeSMB".to_vec(), // SMB2/3
            // SMB2 commands
            b"\x00\x00".to_vec(), // Negotiate
            b"\x01\x00".to_vec(), // Session Setup
            b"\x03\x00".to_vec(), // Tree Connect
            b"\x05\x00".to_vec(), // Create
            b"\x08\x00".to_vec(), // Read
            b"\x09\x00".to_vec(), // Write
            b"\x0b\x00".to_vec(), // Close
            // Interesting paths / names
            b"\\".to_vec(),
            b"IPC$".to_vec(),
            b"C$".to_vec(),
            b"ADMIN$".to_vec(),
            b"\\x00".to_vec(),
        ]);
        m.messages = vec![
            MessageSpec::new("smb2")
                .field(FieldSpec::new("nbss_type", FieldType::Numeric).with_size(1).values([b"\x00"]))
                .field(FieldSpec::new("nbss_len", FieldType::Length).with_size(3)) // 24-bit in practice
                .field(FieldSpec::new("protocol_id", FieldType::Command).with_size(4).values([b"\xfeSMB"]))
                .field(FieldSpec::new("header_len", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("credit_charge", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("status", FieldType::Numeric).with_size(4))
                .field(FieldSpec::new("command", FieldType::Command).with_size(2))
                .field(FieldSpec::new("credits", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("flags", FieldType::Numeric).with_size(4))
                .field(FieldSpec::new("next_command", FieldType::Numeric).with_size(4))
                .field(FieldSpec::new("message_id", FieldType::Numeric).with_size(8))
                .field(FieldSpec::new("payload", FieldType::Binary)),
        ];
        m
    }

    /// Generic binary length-prefix (BE, 2-byte default).
    pub fn binary_lp() -> Self {
        let mut m = Self::generic();
        m.name = "binary-lp".to_string();
        m.length_prefixed = true;
        m.length_width = Some(2);
        m.endian = ModelEndian::Big;
        m.checksum = ModelChecksum::Crc32;
        m.messages = vec![
            MessageSpec::new("frame")
                .field(FieldSpec::new("len", FieldType::Length).with_size(2).endian(ModelEndian::Big))
                .field(FieldSpec::new("payload", FieldType::Binary))
                .field(FieldSpec::new("crc", FieldType::Checksum).with_size(4)),
        ];
        m
    }

    /// Generic binary length-prefix little-endian.
    pub fn binary_lp_le() -> Self {
        let mut m = Self::binary_lp();
        m.name = "binary-lp-le".to_string();
        m.endian = ModelEndian::Little;
        if let Some(msg) = m.messages.first_mut() {
            if let Some(f) = msg.fields.first_mut() {
                f.endian = Some(ModelEndian::Little);
            }
        }
        m
    }

    /// Convenience: merge extra dictionary tokens (dedup).
    pub fn extend_dictionary(&mut self, extra: &[Vec<u8>]) {
        for t in extra {
            if !t.is_empty() && !self.dictionary.iter().any(|d| d == t) {
                self.dictionary.push(t.clone());
            }
        }
    }
}

/// Load seed files from a directory and convert them into TestCases.
///
/// - Binary files (.bin, no extension) → single Binary payload message
/// - Text files (.txt) → one Message per non-empty line (treated as String/Command)
pub fn load_seeds_from_dir<P: AsRef<Path>>(dir: P, start_id: SeedId) -> Result<Vec<TestCase>> {
    let dir = dir.as_ref();
    if !dir.exists() {
        return Err(NexsizError::Config(format!(
            "Seed directory does not exist: {}",
            dir.display()
        )));
    }

    let mut seeds = Vec::new();
    let mut id = start_id;

    let entries = fs::read_dir(dir).map_err(NexsizError::Io)?;

    for entry in entries {
        let entry = entry.map_err(NexsizError::Io)?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let data = fs::read(&path).map_err(NexsizError::Io)?;
        if data.is_empty() {
            continue;
        }

        let tc = if path.extension().map(|e| e == "txt").unwrap_or(false) {
            // Text seed: each line becomes a message
            let text = String::from_utf8_lossy(&data);
            let mut messages = Vec::new();
            for line in text.lines() {
                let line = line.trim_end_matches(['\r', '\n']);
                if line.is_empty() {
                    continue;
                }
                let mut msg = Message::new("line");
                msg.add_field(Field::new(
                    "content",
                    FieldType::String,
                    line.as_bytes().to_vec(),
                ));
                // Append CRLF for text protocols
                msg.add_field(
                    Field::new("crlf", FieldType::Binary, b"\r\n".to_vec()).protected(),
                );
                messages.push(msg);
            }
            if messages.is_empty() {
                continue;
            }
            TestCase::new(id, messages)
        } else {
            // Binary seed: single payload message
            let mut msg = Message::new("raw");
            msg.add_field(Field::new("payload", FieldType::Binary, data));
            TestCase::new(id, vec![msg])
        };

        seeds.push(tc);
        id += 1;
    }

    if seeds.is_empty() {
        // Provide a minimal default seed so the fuzzer can still start
        let mut msg = Message::new("default");
        msg.add_field(Field::new(
            "payload",
            FieldType::Binary,
            b"NEXSIZ\r\n".to_vec(),
        ));
        seeds.push(TestCase::new(start_id, vec![msg]));
    }

    Ok(seeds)
}

/// Create a simple TestCase from raw bytes (used by mutator output).
pub fn testcase_from_bytes(id: SeedId, data: Vec<u8>, parent: Option<SeedId>) -> TestCase {
    let mut msg = Message::new("mutated");
    msg.add_field(Field::new("payload", FieldType::Binary, data));
    let mut tc = TestCase::new(id, vec![msg]);
    tc.parent = parent;
    tc
}

/// Compute a content hash for corpus deduplication.
pub fn content_hash(tc: &TestCase) -> u64 {
    hash_bytes(&tc.serialize())
}

// ── Simple grammar / model inference (pure stdlib) ─────────────────────────────

/// Lightweight inference of a ProtocolModel from raw seed bytes + optional
/// response samples. Detects common delimiters, length-prefix patterns, and
/// extracts printable tokens for the dictionary.
///
/// This is intentionally heuristic and conservative — it never claims to
/// recover a full formal grammar, only useful mutation hints.
pub fn infer_model_from_bytes(
    name: &str,
    seeds: &[&[u8]],
    responses: &[&[u8]],
) -> ProtocolModel {
    let mut model = ProtocolModel::generic();
    model.name = name.to_string();

    // Delimiter detection
    let mut crlf_hits = 0usize;
    let mut lf_hits = 0usize;
    for s in seeds.iter().chain(responses.iter()) {
        if s.windows(2).any(|w| w == b"\r\n") {
            crlf_hits += 1;
        } else if s.contains(&b'\n') {
            lf_hits += 1;
        }
    }
    if crlf_hits > 0 || lf_hits > 0 {
        model.delimiter = Some(b'\n');
    }

    // Length-prefix heuristic (first 1/2/4 bytes match remaining length)
    for s in seeds {
        if s.len() < 3 {
            continue;
        }
        // 2-byte BE
        if s.len() >= 3 {
            let be = u16::from_be_bytes([s[0], s[1]]) as usize;
            if be == s.len() - 2 || be == s.len() - 4 {
                model.length_prefixed = true;
                model.length_width = Some(2);
                model.endian = ModelEndian::Big;
                break;
            }
            let le = u16::from_le_bytes([s[0], s[1]]) as usize;
            if le == s.len() - 2 || le == s.len() - 4 {
                model.length_prefixed = true;
                model.length_width = Some(2);
                model.endian = ModelEndian::Little;
                break;
            }
        }
        // 4-byte BE
        if s.len() >= 5 {
            let be = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as usize;
            if be == s.len() - 4 {
                model.length_prefixed = true;
                model.length_width = Some(4);
                model.endian = ModelEndian::Big;
                break;
            }
        }
    }

    // Token extraction (printable ASCII runs ≥ 3 chars)
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    for s in seeds.iter().chain(responses.iter()) {
        let mut current = Vec::new();
        for &b in *s {
            if (0x20..=0x7e).contains(&b) {
                current.push(b);
            } else {
                if current.len() >= 3 && !tokens.iter().any(|t| t == &current) {
                    tokens.push(current.clone());
                }
                current.clear();
            }
        }
        if current.len() >= 3 && !tokens.iter().any(|t| t == &current) {
            tokens.push(current);
        }
    }
    // Cap dictionary growth
    for t in tokens.into_iter().take(64) {
        model.extend_dictionary(&[t]);
    }

    // Always keep classic interesting values
    model.extend_dictionary(&[
        b"\x00".to_vec(),
        b"\xff".to_vec(),
        b"\x00\x00".to_vec(),
        b"\xff\xff".to_vec(),
        b"\r\n".to_vec(),
    ]);

    model
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_model_has_length_prefix() {
        let m = ProtocolModel::dns();
        assert_eq!(m.name, "dns");
        assert!(m.length_prefixed);
        assert_eq!(m.length_width, Some(2));
        assert!(!m.messages.is_empty());
    }

    #[test]
    fn mqtt_model_has_commands() {
        let m = ProtocolModel::mqtt();
        assert!(m.dictionary.iter().any(|t| t == b"MQTT"));
        assert!(m.dictionary.iter().any(|t| t == b"\x10"));
    }

    #[test]
    fn smb_model_has_magic() {
        let m = ProtocolModel::smb();
        assert!(m.dictionary.iter().any(|t| t == b"\xfeSMB"));
        assert!(m.length_prefixed);
    }

    #[test]
    fn binary_lp_variants() {
        let be = ProtocolModel::binary_lp();
        let le = ProtocolModel::binary_lp_le();
        assert_eq!(be.name, "binary-lp");
        assert_eq!(le.name, "binary-lp-le");
        assert_eq!(be.endian, ModelEndian::Big);
        assert_eq!(le.endian, ModelEndian::Little);
    }

    #[test]
    fn infer_detects_crlf_and_tokens() {
        let seed = b"USER anonymous\r\nPASS guest\r\n";
        let m = infer_model_from_bytes("inferred-ftp", &[seed], &[]);
        assert_eq!(m.delimiter, Some(b'\n'));
        assert!(m.dictionary.iter().any(|t| t == b"USER"));
        assert!(m.dictionary.iter().any(|t| t == b"anonymous"));
    }

    #[test]
    fn infer_detects_length_prefix() {
        let mut seed = vec![0u8, 5];
        seed.extend_from_slice(b"HELLO");
        let m = infer_model_from_bytes("lp", &[&seed], &[]);
        assert!(m.length_prefixed);
        assert_eq!(m.length_width, Some(2));
    }
}
