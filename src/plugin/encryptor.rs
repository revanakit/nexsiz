//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 08/08/2026
//! Module  : nexsiz/src/plugin/encryptor.rs
//!
//! # Encryptor Plugin Layer
//!
//! Provides stateful encryption and framing transformations applied post-integrity-repair
//! in the fuzzing pipeline, immediately before wire transmission. Implements RFC-compliant
//! cryptographic primitives (ChaCha20/RFC 8439, Poly1305) with zero external dependencies.
//!
//! ## Architecture
//!
//! All encryptors implement the `Encryptor` trait, enabling bidirectional transformation:
//! - `encrypt()`: applies payload obfuscation and/or framing to test cases
//! - `decrypt_response()`: optional response de-framing for symmetric analysis
//!
//! ## Implementations
//!
//! **Symmetric Stream Ciphers:**
//! - `NullEncryptor`: identity transform (baseline/control)
//! - `XorEncryptor`: rolling XOR with configurable key material
//! - `ChaCha20Encryptor`: RFC 8439 stream cipher with per-message counter reset
//!
//! **Authenticated Encryption (AEAD):**
//! - `ChaCha20Poly1305Encryptor`: ChaCha20-Poly1305 with optional AAD support
//!   Output format: ciphertext || 16-byte authentication tag
//!
//! **Protocol Framing:**
//! - `TlsRecordEncryptor`: RFC 5246/8446 record layer with configurable:
//!   - Content type (ChangeCipherSpec, Alert, Handshake, ApplicationData)
//!   - Protocol version (TLS 1.0–1.3)
//!   - Automatic fragmentation when payload exceeds 16KB max record size
//!   - Graceful multi-record payload reassembly during decryption
//!
//! **Composition Pipelines:**
//! - `ChaCha20ThenTlsEncryptor`: stream encryption → record framing
//! - `ChaCha20Poly1305ThenTlsEncryptor`: AEAD → record framing
//! - `XorThenTlsEncryptor`: XOR → record framing
//!
//! ## Nonce & Counter Management
//!
//! - **NonceMode::Fixed**: static nonce (deterministic, reproducible fuzzing)
//! - **NonceMode::Incrementing**: monotonic increment per message (stream position tracking)
//! - **NonceMode::Random**: cryptographically random per message (high entropy scenarios)
//! - **Counter Reset**: ChaCha20 counter resets to 0 per message (recommended for state fuzzing)
//!
//! ## Configuration
//!
//! Encryptors resolved via `resolve_encryptor()` or `resolve_encryptor_with_key()`:
//! - Environment variables: `NEXSIZ_ENC_KEY`, `NEXSIZ_ENC_NONCE`, `NEXSIZ_NONCE_MODE`
//! - Key/nonce parsing: hex string (e.g., "0x01020304") or raw bytes
//! - Fallback: hardcoded defaults from `crypto::default_key()` / `crypto::default_nonce()`
//!
//! ## Production Guarantees
//!
//! - Pure Rust implementation (no FFI, no external crypto libraries)
//! - Constant-time operations for tag verification (Poly1305)
//! - RFC compliance for record layer fragmentation and TLS versioning
//! - Comprehensive fuzzing-oriented test coverage (roundtrip, fragmentation, multi-record)

use crate::common::types::{Field, FieldType, TestCase};
use crate::plugin::crypto::{
    self, make_nonce, ChaCha20, ChaCha20Poly1305, NonceMode,
};

/// Trait for an optional encryption / framing layer.
pub trait Encryptor: Send + Sync {
    fn name(&self) -> &str;

    /// Transform the test case before it is sent on the wire.
    fn encrypt(&self, tc: &mut TestCase);

    /// Optional reverse transform for response analysis.
    fn decrypt_response(&self, data: &mut Vec<u8>) {
        let _ = data;
    }
}

// ── Null ─────────────────────────────────────────────────────────────────────

pub struct NullEncryptor;

impl Encryptor for NullEncryptor {
    fn name(&self) -> &str {
        "null"
    }

    fn encrypt(&self, _tc: &mut TestCase) {}
}

// ── Rolling XOR ──────────────────────────────────────────────────────────────

pub struct XorEncryptor {
    key: Vec<u8>,
}

impl XorEncryptor {
    pub fn new(key: &[u8]) -> Self {
        let key = if key.is_empty() {
            crypto::default_key()
        } else {
            key.to_vec()
        };
        Self { key }
    }

    fn xor_inplace(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.key[i % self.key.len()];
        }
    }
}

impl Encryptor for XorEncryptor {
    fn name(&self) -> &str {
        "xor"
    }

    fn encrypt(&self, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            for field in &mut msg.fields {
                if field.protected {
                    continue;
                }
                self.xor_inplace(&mut field.data);
            }
        }
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        self.xor_inplace(data);
    }
}

// ── ChaCha20 stream cipher ───────────────────────────────────────────────────

/// Pure ChaCha20 (RFC 8439) encryptor with controlled counter / nonce.
pub struct ChaCha20Encryptor {
    key: Vec<u8>,
    nonce_base: Vec<u8>,
    nonce_mode: NonceMode,
    /// If true, reset counter to 0 for every message (recommended for fuzzing).
    reset_counter_per_message: bool,
}

impl ChaCha20Encryptor {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            key: if key.is_empty() {
                crypto::default_key()
            } else {
                key.to_vec()
            },
            nonce_base: if nonce.is_empty() {
                crypto::default_nonce()
            } else {
                nonce.to_vec()
            },
            nonce_mode: NonceMode::Fixed,
            reset_counter_per_message: true,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(&crypto::default_key(), &crypto::default_nonce())
    }

    pub fn with_nonce_mode(mut self, mode: NonceMode) -> Self {
        self.nonce_mode = mode;
        self
    }

    pub fn reset_counter_per_message(mut self, v: bool) -> Self {
        self.reset_counter_per_message = v;
        self
    }
}

impl Encryptor for ChaCha20Encryptor {
    fn name(&self) -> &str {
        "chacha20"
    }

    fn encrypt(&self, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            let nonce = make_nonce(&self.nonce_base, self.nonce_mode);
            let mut cipher = ChaCha20::new(&self.key, &nonce);
            if self.reset_counter_per_message {
                cipher.set_counter(0);
            }
            for field in &mut msg.fields {
                if field.protected {
                    continue;
                }
                cipher.apply(&mut field.data);
            }
        }
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        // Best-effort: use fixed nonce + counter 0 (operator must match mode)
        let nonce = make_nonce(&self.nonce_base, NonceMode::Fixed);
        let mut cipher = ChaCha20::new(&self.key, &nonce);
        cipher.set_counter(0);
        cipher.apply(data);
    }
}

// ── ChaCha20-Poly1305 AEAD ───────────────────────────────────────────────────

/// ChaCha20-Poly1305 AEAD encryptor.
/// Output layout per field/message: ciphertext || 16-byte tag.
pub struct ChaCha20Poly1305Encryptor {
    aead: ChaCha20Poly1305,
    nonce_base: Vec<u8>,
    nonce_mode: NonceMode,
    /// Optional AAD (e.g. protocol header bytes). Empty by default.
    aad: Vec<u8>,
}

impl ChaCha20Poly1305Encryptor {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(key),
            nonce_base: if nonce.is_empty() {
                crypto::default_nonce()
            } else {
                nonce.to_vec()
            },
            nonce_mode: NonceMode::Fixed,
            aad: Vec::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(&crypto::default_key(), &crypto::default_nonce())
    }

    pub fn with_nonce_mode(mut self, mode: NonceMode) -> Self {
        self.nonce_mode = mode;
        self
    }

    pub fn with_aad(mut self, aad: &[u8]) -> Self {
        self.aad = aad.to_vec();
        self
    }
}

impl Encryptor for ChaCha20Poly1305Encryptor {
    fn name(&self) -> &str {
        "chacha20-poly1305"
    }

    fn encrypt(&self, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            let nonce = make_nonce(&self.nonce_base, self.nonce_mode);
            // Serialize message, AEAD the whole payload, replace fields
            let plain = msg.serialize();
            if plain.is_empty() {
                continue;
            }
            let sealed = self.aead.seal(&nonce, &self.aad, &plain);
            msg.fields.clear();
            msg.add_field(Field::new("aead", FieldType::Binary, sealed));
        }
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        let nonce = make_nonce(&self.nonce_base, NonceMode::Fixed);
        if let Some(pt) = self.aead.open(&nonce, &self.aad, data) {
            *data = pt;
        }
    }
}

// ── TLS record framing (Production) ──────────────────────────────────────────

/// TLS content types (RFC 5246 / 8446).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsContentType {
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    ApplicationData = 0x17,
}

impl TlsContentType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x14 => Some(Self::ChangeCipherSpec),
            0x15 => Some(Self::Alert),
            0x16 => Some(Self::Handshake),
            0x17 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

/// Production TLS record layer framing.
///
/// Layout per record:
///   [content_type:1][ver_major:1][ver_minor:1][length:2 BE][payload]
///
/// Supports automatic fragmentation when payload exceeds `max_record_size`.
pub struct TlsRecordEncryptor {
    content_type: TlsContentType,
    version: (u8, u8),
    /// Maximum payload size per record (default 16384 = TLS max).
    max_record_size: usize,
    /// If true, emit multiple records when payload > max_record_size.
    fragment: bool,
}

impl TlsRecordEncryptor {
    pub fn new() -> Self {
        Self {
            content_type: TlsContentType::ApplicationData,
            version: (0x03, 0x03), // TLS 1.2 record layer
            max_record_size: 16_384,
            fragment: true,
        }
    }

    pub fn application_data() -> Self {
        Self::new()
    }

    pub fn handshake() -> Self {
        Self {
            content_type: TlsContentType::Handshake,
            version: (0x03, 0x01),
            max_record_size: 16_384,
            fragment: true,
        }
    }

    pub fn alert() -> Self {
        Self {
            content_type: TlsContentType::Alert,
            version: (0x03, 0x03),
            max_record_size: 16_384,
            fragment: false,
        }
    }

    pub fn change_cipher_spec() -> Self {
        Self {
            content_type: TlsContentType::ChangeCipherSpec,
            version: (0x03, 0x03),
            max_record_size: 16_384,
            fragment: false,
        }
    }

    pub fn with_content_type(mut self, t: TlsContentType) -> Self {
        self.content_type = t;
        self
    }

    pub fn with_version(mut self, major: u8, minor: u8) -> Self {
        self.version = (major, minor);
        self
    }

    pub fn with_max_record_size(mut self, size: usize) -> Self {
        self.max_record_size = size.max(1).min(16_384);
        self
    }

    pub fn with_fragment(mut self, enable: bool) -> Self {
        self.fragment = enable;
        self
    }

    fn frame_payload(&self, payload: &[u8]) -> Vec<u8> {
        if !self.fragment || payload.len() <= self.max_record_size {
            return self.single_record(payload);
        }
        let mut out = Vec::with_capacity(payload.len() + 5 * ((payload.len() / self.max_record_size) + 1));
        let mut offset = 0;
        while offset < payload.len() {
            let end = (offset + self.max_record_size).min(payload.len());
            out.extend_from_slice(&self.single_record(&payload[offset..end]));
            offset = end;
        }
        out
    }

    fn single_record(&self, payload: &[u8]) -> Vec<u8> {
        let len = payload.len().min(u16::MAX as usize) as u16;
        let mut framed = Vec::with_capacity(5 + payload.len());
        framed.push(self.content_type as u8);
        framed.push(self.version.0);
        framed.push(self.version.1);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(payload);
        framed
    }
}

impl Default for TlsRecordEncryptor {
    fn default() -> Self {
        Self::new()
    }
}

impl Encryptor for TlsRecordEncryptor {
    fn name(&self) -> &str {
        "tls-record"
    }

    fn encrypt(&self, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            let payload = msg.serialize();
            let framed = self.frame_payload(&payload);
            msg.fields.clear();
            msg.add_field(Field::new("tls_record", FieldType::Binary, framed));
        }
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        // Strip all TLS records and concatenate payloads
        let mut out = Vec::new();
        let mut offset = 0;
        while offset + 5 <= data.len() {
            let declared = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
            let record_end = offset + 5 + declared;
            if record_end > data.len() {
                // Partial / truncated – take remaining
                out.extend_from_slice(&data[offset + 5..]);
                break;
            }
            out.extend_from_slice(&data[offset + 5..record_end]);
            offset = record_end;
        }
        if !out.is_empty() {
            *data = out;
        }
    }
}

// ── Composed pipelines ───────────────────────────────────────────────────────

/// ChaCha20 encryption then TLS record framing.
pub struct ChaCha20ThenTlsEncryptor {
    chacha: ChaCha20Encryptor,
    tls: TlsRecordEncryptor,
}

impl ChaCha20ThenTlsEncryptor {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            chacha: ChaCha20Encryptor::new(key, nonce),
            tls: TlsRecordEncryptor::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(&crypto::default_key(), &crypto::default_nonce())
    }

    pub fn with_nonce_mode(mut self, mode: NonceMode) -> Self {
        self.chacha = self.chacha.with_nonce_mode(mode);
        self
    }

    pub fn with_tls(mut self, tls: TlsRecordEncryptor) -> Self {
        self.tls = tls;
        self
    }
}

impl Encryptor for ChaCha20ThenTlsEncryptor {
    fn name(&self) -> &str {
        "chacha20+tls"
    }

    fn encrypt(&self, tc: &mut TestCase) {
        self.chacha.encrypt(tc);
        self.tls.encrypt(tc);
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        self.tls.decrypt_response(data);
        self.chacha.decrypt_response(data);
    }
}

/// ChaCha20-Poly1305 AEAD then TLS record framing.
pub struct ChaCha20Poly1305ThenTlsEncryptor {
    aead: ChaCha20Poly1305Encryptor,
    tls: TlsRecordEncryptor,
}

impl ChaCha20Poly1305ThenTlsEncryptor {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        Self {
            aead: ChaCha20Poly1305Encryptor::new(key, nonce),
            tls: TlsRecordEncryptor::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(&crypto::default_key(), &crypto::default_nonce())
    }

    pub fn with_nonce_mode(mut self, mode: NonceMode) -> Self {
        self.aead = self.aead.with_nonce_mode(mode);
        self
    }
}

impl Encryptor for ChaCha20Poly1305ThenTlsEncryptor {
    fn name(&self) -> &str {
        "chacha20-poly1305+tls"
    }

    fn encrypt(&self, tc: &mut TestCase) {
        self.aead.encrypt(tc);
        self.tls.encrypt(tc);
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        self.tls.decrypt_response(data);
        self.aead.decrypt_response(data);
    }
}

/// XOR then TLS record framing.
pub struct XorThenTlsEncryptor {
    xor: XorEncryptor,
    tls: TlsRecordEncryptor,
}

impl XorThenTlsEncryptor {
    pub fn new(key: &[u8]) -> Self {
        Self {
            xor: XorEncryptor::new(key),
            tls: TlsRecordEncryptor::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(&crypto::default_key())
    }
}

impl Encryptor for XorThenTlsEncryptor {
    fn name(&self) -> &str {
        "xor+tls"
    }

    fn encrypt(&self, tc: &mut TestCase) {
        self.xor.encrypt(tc);
        self.tls.encrypt(tc);
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        self.tls.decrypt_response(data);
        self.xor.decrypt_response(data);
    }
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolve encryptor by name, using optional key material.
///
/// Supported names:
///   null | none
///   xor
///   chacha20 | chacha
///   chacha20-poly1305 | aead | chacha-poly
///   tls-record | tls
///   chacha20+tls | chacha+tls
///   chacha20-poly1305+tls | aead+tls
///   xor+tls | xor+tls-record
///
/// Environment:
///   NEXSIZ_ENC_KEY, NEXSIZ_ENC_NONCE
///   NEXSIZ_NONCE_MODE = fixed | incrementing | random
pub fn resolve_encryptor(name: Option<&str>) -> Box<dyn Encryptor> {
    resolve_encryptor_with_key(name, None)
}

pub fn resolve_encryptor_with_key(
    name: Option<&str>,
    key_material: Option<&str>,
) -> Box<dyn Encryptor> {
    let key = match key_material {
        Some(s) if !s.is_empty() => crypto::parse_key_material(s),
        _ => std::env::var("NEXSIZ_ENC_KEY")
            .ok()
            .map(|s| crypto::parse_key_material(&s))
            .unwrap_or_else(crypto::default_key),
    };
    let nonce = std::env::var("NEXSIZ_ENC_NONCE")
        .ok()
        .map(|s| crypto::parse_key_material(&s))
        .unwrap_or_else(crypto::default_nonce);

    let nonce_mode = match std::env::var("NEXSIZ_NONCE_MODE")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "incrementing" | "inc" | "counter" => NonceMode::Incrementing,
        "random" | "rand" => NonceMode::Random,
        _ => NonceMode::Fixed,
    };

    match name.map(|s| s.to_lowercase()).as_deref() {
        Some("xor") => Box::new(XorEncryptor::new(&key)),
        Some("chacha20") | Some("chacha") => {
            Box::new(ChaCha20Encryptor::new(&key, &nonce).with_nonce_mode(nonce_mode))
        }
        Some("chacha20-poly1305") | Some("aead") | Some("chacha-poly") => Box::new(
            ChaCha20Poly1305Encryptor::new(&key, &nonce).with_nonce_mode(nonce_mode),
        ),
        Some("tls-record") | Some("tls") => Box::new(TlsRecordEncryptor::new()),
        Some("tls-handshake") => Box::new(TlsRecordEncryptor::handshake()),
        Some("tls-alert") => Box::new(TlsRecordEncryptor::alert()),
        Some("chacha20+tls") | Some("chacha+tls") => Box::new(
            ChaCha20ThenTlsEncryptor::new(&key, &nonce).with_nonce_mode(nonce_mode),
        ),
        Some("chacha20-poly1305+tls") | Some("aead+tls") => Box::new(
            ChaCha20Poly1305ThenTlsEncryptor::new(&key, &nonce).with_nonce_mode(nonce_mode),
        ),
        Some("xor+tls") | Some("xor+tls-record") => Box::new(XorThenTlsEncryptor::new(&key)),
        Some("null") | Some("none") | None => Box::new(NullEncryptor),
        Some(other) => crate::plugin::pipeline::resolve_pipeline(Some(other), key_material),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{FieldType, Message};

    fn sample_tc() -> TestCase {
        let mut m = Message::new("m");
        m.add_field(Field::new("p", FieldType::Binary, b"hello".to_vec()));
        TestCase::new(1, vec![m])
    }

    #[test]
    fn null_leaves_data() {
        let enc = NullEncryptor;
        let mut tc = sample_tc();
        let before = tc.serialize();
        enc.encrypt(&mut tc);
        assert_eq!(tc.serialize(), before);
    }

    #[test]
    fn xor_roundtrip() {
        let enc = XorEncryptor::new(b"secret");
        let mut tc = sample_tc();
        let plain = tc.serialize();
        enc.encrypt(&mut tc);
        assert_ne!(tc.serialize(), plain);
        let mut wire = tc.serialize();
        enc.decrypt_response(&mut wire);
        assert_eq!(wire, plain);
    }

    #[test]
    fn chacha20_roundtrip() {
        let enc = ChaCha20Encryptor::with_defaults();
        let mut tc = sample_tc();
        let plain = tc.serialize();
        enc.encrypt(&mut tc);
        assert_ne!(tc.serialize(), plain);
        let mut wire = tc.serialize();
        enc.decrypt_response(&mut wire);
        assert_eq!(wire, plain);
    }

    #[test]
    fn aead_roundtrip() {
        let enc = ChaCha20Poly1305Encryptor::with_defaults();
        let mut tc = sample_tc();
        let plain = tc.serialize();
        enc.encrypt(&mut tc);
        let wire = tc.serialize();
        assert!(wire.len() >= plain.len() + 16);
        let mut recovered = wire;
        enc.decrypt_response(&mut recovered);
        assert_eq!(recovered, plain);
    }

    #[test]
    fn tls_record_framing() {
        let enc = TlsRecordEncryptor::new();
        let mut tc = sample_tc();
        enc.encrypt(&mut tc);
        let wire = tc.serialize();
        assert!(wire.len() >= 5);
        assert_eq!(wire[0], 0x17);
        assert_eq!(wire[1], 0x03);
        assert_eq!(wire[2], 0x03);
        let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert_eq!(len, 5);
        assert_eq!(&wire[5..], b"hello");
    }

    #[test]
    fn tls_fragmentation() {
        let enc = TlsRecordEncryptor::new().with_max_record_size(3).with_fragment(true);
        let mut m = Message::new("m");
        m.add_field(Field::new("p", FieldType::Binary, b"abcdefghij".to_vec()));
        let mut tc = TestCase::new(1, vec![m]);
        enc.encrypt(&mut tc);
        let wire = tc.serialize();
        // 10 bytes → 4 records (3+3+3+1) → 4*5 + 10 = 30
        assert_eq!(wire.len(), 30);
        assert_eq!(wire[0], 0x17);
        assert_eq!(u16::from_be_bytes([wire[3], wire[4]]), 3);
    }

    #[test]
    fn tls_decrypt_multi_record() {
        let enc = TlsRecordEncryptor::new().with_max_record_size(3);
        let mut m = Message::new("m");
        m.add_field(Field::new("p", FieldType::Binary, b"abcdef".to_vec()));
        let mut tc = TestCase::new(1, vec![m]);
        enc.encrypt(&mut tc);
        let mut wire = tc.serialize();
        enc.decrypt_response(&mut wire);
        assert_eq!(wire, b"abcdef");
    }

    #[test]
    fn chacha_then_tls_pipeline() {
        let enc = ChaCha20ThenTlsEncryptor::with_defaults();
        let mut tc = sample_tc();
        enc.encrypt(&mut tc);
        let wire = tc.serialize();
        assert!(wire.len() >= 5);
        assert_eq!(wire[0], 0x17);
        assert_ne!(&wire[5..], b"hello");
    }

    #[test]
    fn aead_then_tls_pipeline() {
        let enc = ChaCha20Poly1305ThenTlsEncryptor::with_defaults();
        let mut tc = sample_tc();
        enc.encrypt(&mut tc);
        let wire = tc.serialize();
        assert!(wire.len() >= 5 + 5 + 16); // header + plaintext + tag
        assert_eq!(wire[0], 0x17);
    }

    #[test]
    fn resolve_names() {
        assert_eq!(resolve_encryptor(Some("chacha20")).name(), "chacha20");
        assert_eq!(
            resolve_encryptor(Some("chacha20-poly1305")).name(),
            "chacha20-poly1305"
        );
        assert_eq!(resolve_encryptor(Some("tls")).name(), "tls-record");
        assert_eq!(resolve_encryptor(Some("aead+tls")).name(), "chacha20-poly1305+tls");
        assert_eq!(resolve_encryptor(Some("chacha+tls")).name(), "chacha20+tls");
        assert_eq!(resolve_encryptor(None).name(), "null");
    }
}
