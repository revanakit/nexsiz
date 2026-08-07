//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//! Author  : Revana
//! Date    : 04/08/2026
//! Protocol model and seed parsing.
//! Provides a lightweight way to represent protocol messages as sequences
//! of semantic fields. Seeds can be loaded as raw bytes (treated as a single
//! Binary payload) or as simple text lines (one message per line).

use crate::common::error::{NexsizError, Result};
use crate::common::types::*;
use crate::common::utils::hash_bytes;
use std::fs;
use std::path::Path;

/// Minimal protocol model used to guide mutation and integrity repair.
#[derive(Debug, Clone)]
pub struct ProtocolModel {
    pub name: String,
    /// Known interesting values for numeric / command fields
    pub dictionary: Vec<Vec<u8>>,
    /// Whether the protocol uses length-prefixed messages
    pub length_prefixed: bool,
    /// Whether messages end with a delimiter
    pub delimiter: Option<u8>,
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

    let entries = fs::read_dir(dir)
        .map_err(|e| NexsizError::Io(e))?;

    for entry in entries {
        let entry = entry.map_err(|e| NexsizError::Io(e))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let data = fs::read(&path).map_err(|e| NexsizError::Io(e))?;
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
                msg.add_field(Field::new("content", FieldType::String, line.as_bytes().to_vec()));
                // Append CRLF for text protocols
                msg.add_field(Field::new("crlf", FieldType::Binary, b"\r\n".to_vec()).protected());
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
        msg.add_field(Field::new("payload", FieldType::Binary, b"NEXSIZ\r\n".to_vec()));
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
