//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 13/08/2026
//! Module  : nexsiz::src::input::model
//!
//! This module provides an in-memory, minimal but expressive representation of
//! network protocol structure used by the fuzzer core. It contains:
//!  - ProtocolModel: high-level protocol descriptors (dictionary, framing rules,
//!    message templates, sequences, and optional desocket/reset sequences).
//!  - MessageSpec / FieldSpec: typed field-level templates used to describe
//!    message layouts (commands, lengths, numeric fields, payloads, checksums).
//!  - Convenience constructors for common protocols (FTP, HTTP, DNS, MQTT, SMB,
//!    and configurable binary length-prefixed frames).
//!  - Seed and testcase helpers: load seeds from disk, build TestCase objects,
//!    compute content hashes, and infer simple models from sample byte slices.
//!
//! Design notes & guarantees
//! -------------------------
//!  - Representation is intentionally lightweight and focused on fuzzing-time
//!    operations: model instances are intended to be read/constructed by the
//!    fuzzer and its inference routines rather than as a canonical wire-spec.
//!  - Error handling uses the crate-local NexsizError and Result types; IO and
//!    parsing helpers return informative errors for configuration problems.
//!  - Dictionaries and token extraction are heuristics used for candidate
//!    tokenization and mutation guidance — they are not exhaustive protocol
//!    parsers and must not be relied upon as authoritative protocol validators.
//!
//! Public API highlights
//! ----------------------
//!  - ProtocolModel::generic() and protocol-specific constructors (ftp(), dns(),
//!    mqtt(), etc.) provide ready-to-use models for common protocols and tests.
//!  - extend_dictionary(), find_message(), and infer_model_from_bytes() support
//!    dynamic augmentation and lightweight model inference from observed traffic.
//!  - load_seeds_from_dir() converts disk-side seed files into TestCase objects
//!    (plain files map to raw payloads, .txt files are split into CRLF-delimited
//!    lines and wrapped as String fields).
//!
//! Stability and future work
//! -------------------------
//!  - Current API is stable for use by internal fuzzer components, but layout
//!    and semantics may evolve across major releases as Phase-3/4 features are
//!    implemented (SequenceSpec-driven flows, operator-defined DesocketSpec
//!    JSON models, etc.).
//!  - TODO: add serde support for importing/exporting models, richer checksum
//!    expressions, and pluggable tokenizers for non-ASCII protocols.

use crate::common::error::{NexsizError, Result};
use crate::common::types::*;
use crate::common::utils::hash_bytes;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModelEndian {
    #[default]
    Big,
    Little,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ModelChecksum {
    #[default]
    Auto,
    Additive,
    Xor,
    Crc16,
    Crc32,
    OnesComplement,
}

/// Operator-defined protocol-level reset sequences (JSON / external models).
#[derive(Debug, Clone, Default)]
pub struct DesocketSpec {
    /// Ordered list of byte sequences to try when resetting protocol state.
    pub sequences: Vec<Vec<u8>>,
    /// Optional goodbye / logout bytes sent before intentional close.
    pub goodbye: Option<Vec<u8>>,
    /// When true (default), any non-hard-close outcome after a sequence is success.
    /// When false, a non-empty response is required.
    pub success_on_response: bool,
}

impl DesocketSpec {
    pub fn new() -> Self {
        Self {
            sequences: Vec::new(),
            goodbye: None,
            success_on_response: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldSpec {
    pub name: String,
    pub ftype: FieldType,
    pub size: Option<usize>,
    pub protected: bool,
    pub values: Vec<Vec<u8>>,
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

/// Ordered multi-message flow referencing MessageSpec names.
#[derive(Debug, Clone)]
pub struct SequenceSpec {
    pub name: String,
    pub steps: Vec<String>,
}

impl SequenceSpec {
    pub fn new(name: impl Into<String>, steps: Vec<impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            steps: steps.into_iter().map(|s| s.into()).collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolModel {
    pub name: String,
    pub dictionary: Vec<Vec<u8>>,
    pub length_prefixed: bool,
    pub delimiter: Option<u8>,
    pub endian: ModelEndian,
    pub checksum: ModelChecksum,
    pub messages: Vec<MessageSpec>,
    pub length_width: Option<usize>,
    /// Multi-step message sequences (optional; Phase 3).
    pub sequences: Vec<SequenceSpec>,
    /// Operator-defined desocket / reset sequences (JSON models; Phase 4).
    pub desocket: Option<DesocketSpec>,
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
            sequences: Vec::new(),
            desocket: None,
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
        m.messages = vec![
            MessageSpec::new("user")
                .field(FieldSpec::new("cmd", FieldType::Command).values([b"USER".as_slice()]))
                .field(FieldSpec::new("sp", FieldType::Binary).values([b" ".as_slice()]).protected())
                .field(
                    FieldSpec::new("arg", FieldType::String)
                        .values([b"anonymous".as_slice(), b"guest".as_slice()]),
                )
                .field(
                    FieldSpec::new("crlf", FieldType::Binary)
                        .values([b"\r\n".as_slice()])
                        .protected(),
                ),
            MessageSpec::new("pass")
                .field(FieldSpec::new("cmd", FieldType::Command).values([b"PASS".as_slice()]))
                .field(FieldSpec::new("sp", FieldType::Binary).values([b" ".as_slice()]).protected())
                .field(
                    FieldSpec::new("arg", FieldType::String)
                        .values([b"guest".as_slice(), b"".as_slice()]),
                )
                .field(
                    FieldSpec::new("crlf", FieldType::Binary)
                        .values([b"\r\n".as_slice()])
                        .protected(),
                ),
            MessageSpec::new("pwd")
                .field(FieldSpec::new("cmd", FieldType::Command).values([b"PWD".as_slice()]))
                .field(
                    FieldSpec::new("crlf", FieldType::Binary)
                        .values([b"\r\n".as_slice()])
                        .protected(),
                ),
            MessageSpec::new("quit")
                .field(FieldSpec::new("cmd", FieldType::Command).values([b"QUIT".as_slice()]))
                .field(
                    FieldSpec::new("crlf", FieldType::Binary)
                        .values([b"\r\n".as_slice()])
                        .protected(),
                ),
        ];
        m.sequences = vec![
            SequenceSpec::new("login", vec!["user", "pass"]),
            SequenceSpec::new("session", vec!["user", "pass", "pwd", "quit"]),
        ];
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

    pub fn dns() -> Self {
        let mut m = Self::generic();
        m.name = "dns".to_string();
        m.length_prefixed = true;
        m.length_width = Some(2);
        m.endian = ModelEndian::Big;
        m.dictionary.extend(vec![
            b"\x01\x00".to_vec(),
            b"\x00\x00".to_vec(),
            b"\x00\x01".to_vec(),
            b"\x00\x01".to_vec(),
            b"\x00\x1c".to_vec(),
            b"\x00\x0f".to_vec(),
            b"\x00\x10".to_vec(),
            b"\x00\xff".to_vec(),
            b"\x00\x01".to_vec(),
            b"\x03www\x07example\x03com\x00".to_vec(),
            b"\x00".to_vec(),
            b"\xff\xff".to_vec(),
        ]);
        m.messages = vec![MessageSpec::new("query")
            .field(
                FieldSpec::new("tcp_len", FieldType::Length)
                    .with_size(2)
                    .endian(ModelEndian::Big),
            )
            .field(FieldSpec::new("txid", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("flags", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("qdcount", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("ancount", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("nscount", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("arcount", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("qname", FieldType::Binary))
            .field(FieldSpec::new("qtype", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("qclass", FieldType::Numeric).with_size(2))];
        m
    }

    pub fn mqtt() -> Self {
        let mut m = Self::generic();
        m.name = "mqtt".to_string();
        m.length_prefixed = true;
        m.length_width = None;
        m.endian = ModelEndian::Big;
        m.dictionary.extend(vec![
            b"\x10".to_vec(),
            b"\x20".to_vec(),
            b"\x30".to_vec(),
            b"\x40".to_vec(),
            b"\x80".to_vec(),
            b"\x90".to_vec(),
            b"\xc0".to_vec(),
            b"\xd0".to_vec(),
            b"\xe0".to_vec(),
            b"MQTT".to_vec(),
            b"\x04".to_vec(),
            b"\x05".to_vec(),
            b"\x00".to_vec(),
            b"\xff".to_vec(),
            b"test/topic".to_vec(),
            b"#".to_vec(),
            b"+".to_vec(),
            b"client".to_vec(),
        ]);
        m.messages = vec![
            MessageSpec::new("connect")
                .field(
                    FieldSpec::new("fixed_hdr", FieldType::Command)
                        .with_size(1)
                        .values([b"\x10".as_slice()]),
                )
                .field(FieldSpec::new("remaining_len", FieldType::Length))
                .field(FieldSpec::new("proto_name_len", FieldType::Length).with_size(2))
                .field(
                    FieldSpec::new("proto_name", FieldType::String).values([b"MQTT".as_slice()]),
                )
                .field(FieldSpec::new("proto_level", FieldType::Numeric).with_size(1))
                .field(FieldSpec::new("connect_flags", FieldType::Numeric).with_size(1))
                .field(FieldSpec::new("keep_alive", FieldType::Numeric).with_size(2))
                .field(FieldSpec::new("client_id", FieldType::String)),
            MessageSpec::new("publish")
                .field(
                    FieldSpec::new("fixed_hdr", FieldType::Command)
                        .with_size(1)
                        .values([b"\x30".as_slice()]),
                )
                .field(FieldSpec::new("remaining_len", FieldType::Length))
                .field(FieldSpec::new("topic_len", FieldType::Length).with_size(2))
                .field(FieldSpec::new("topic", FieldType::String))
                .field(FieldSpec::new("payload", FieldType::Binary)),
        ];
        m.sequences = vec![SequenceSpec::new(
            "connect-publish",
            vec!["connect", "publish"],
        )];
        m
    }

    pub fn smb() -> Self {
        let mut m = Self::generic();
        m.name = "smb".to_string();
        m.length_prefixed = true;
        m.length_width = Some(4);
        m.endian = ModelEndian::Big;
        m.dictionary.extend(vec![
            b"\x00".to_vec(),
            b"\x81".to_vec(),
            b"\x82".to_vec(),
            b"\xffSMB".to_vec(),
            b"\xfeSMB".to_vec(),
            b"\x00\x00".to_vec(),
            b"\x01\x00".to_vec(),
            b"\x03\x00".to_vec(),
            b"\x05\x00".to_vec(),
            b"\x08\x00".to_vec(),
            b"\x09\x00".to_vec(),
            b"\x0b\x00".to_vec(),
            b"\\".to_vec(),
            b"IPC$".to_vec(),
            b"C$".to_vec(),
            b"ADMIN$".to_vec(),
        ]);
        m.messages = vec![MessageSpec::new("smb2")
            .field(
                FieldSpec::new("nbss_type", FieldType::Numeric)
                    .with_size(1)
                    .values([b"\x00".as_slice()]),
            )
            .field(FieldSpec::new("nbss_len", FieldType::Length).with_size(3))
            .field(
                FieldSpec::new("protocol_id", FieldType::Command)
                    .with_size(4)
                    .values([b"\xfeSMB".as_slice()]),
            )
            .field(FieldSpec::new("header_len", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("credit_charge", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("status", FieldType::Numeric).with_size(4))
            .field(FieldSpec::new("command", FieldType::Command).with_size(2))
            .field(FieldSpec::new("credits", FieldType::Numeric).with_size(2))
            .field(FieldSpec::new("flags", FieldType::Numeric).with_size(4))
            .field(FieldSpec::new("next_command", FieldType::Numeric).with_size(4))
            .field(FieldSpec::new("message_id", FieldType::Numeric).with_size(8))
            .field(FieldSpec::new("payload", FieldType::Binary))];
        m
    }

    pub fn binary_lp() -> Self {
        let mut m = Self::generic();
        m.name = "binary-lp".to_string();
        m.length_prefixed = true;
        m.length_width = Some(2);
        m.endian = ModelEndian::Big;
        m.checksum = ModelChecksum::Crc32;
        m.messages = vec![MessageSpec::new("frame")
            .field(
                FieldSpec::new("len", FieldType::Length)
                    .with_size(2)
                    .endian(ModelEndian::Big),
            )
            .field(FieldSpec::new("payload", FieldType::Binary))
            .field(FieldSpec::new("crc", FieldType::Checksum).with_size(4))];
        m
    }

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

    pub fn extend_dictionary(&mut self, extra: &[Vec<u8>]) {
        for t in extra {
            if !t.is_empty() && !self.dictionary.iter().any(|d| d == t) {
                self.dictionary.push(t.clone());
            }
        }
    }

    pub fn find_message(&self, name: &str) -> Option<&MessageSpec> {
        let n = name.to_ascii_lowercase();
        self.messages
            .iter()
            .find(|m| m.name.to_ascii_lowercase() == n)
    }
}

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

    for entry in fs::read_dir(dir).map_err(NexsizError::Io)? {
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
            let mut msg = Message::new("raw");
            msg.add_field(Field::new("payload", FieldType::Binary, data));
            TestCase::new(id, vec![msg])
        };

        seeds.push(tc);
        id += 1;
    }

    if seeds.is_empty() {
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

pub fn testcase_from_bytes(id: SeedId, data: Vec<u8>, parent: Option<SeedId>) -> TestCase {
    let mut msg = Message::new("mutated");
    msg.add_field(Field::new("payload", FieldType::Binary, data));
    let mut tc = TestCase::new(id, vec![msg]);
    tc.parent = parent;
    tc
}

pub fn content_hash(tc: &TestCase) -> u64 {
    hash_bytes(&tc.serialize())
}

pub fn infer_model_from_bytes(
    name: &str,
    seeds: &[&[u8]],
    responses: &[&[u8]],
) -> ProtocolModel {
    let mut model = ProtocolModel::generic();
    model.name = name.to_string();

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

    for s in seeds {
        if s.len() < 3 {
            continue;
        }
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
    for t in tokens.into_iter().take(64) {
        model.extend_dictionary(&[t]);
    }
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
    fn ftp_has_login_sequence() {
        let m = ProtocolModel::ftp();
        assert!(m.sequences.iter().any(|s| s.name == "login"));
        assert!(m.find_message("user").is_some());
    }

    #[test]
    fn mqtt_has_connect_publish_sequence() {
        let m = ProtocolModel::mqtt();
        assert_eq!(m.sequences.len(), 1);
        assert_eq!(m.sequences[0].steps, vec!["connect", "publish"]);
    }

    #[test]
    fn infer_detects_crlf_and_tokens() {
        let seed = b"USER anonymous\r\nPASS guest\r\n";
        let m = infer_model_from_bytes("inferred-ftp", &[seed], &[]);
        assert_eq!(m.delimiter, Some(b'\n'));
        assert!(m.dictionary.iter().any(|t| t == b"USER"));
    }

    #[test]
    fn generic_has_no_desocket() {
        assert!(ProtocolModel::generic().desocket.is_none());
    }
}
