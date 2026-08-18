//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::plugin::pipeline
//!
//! Purpose
//! -------
//! Modular, production-ready pipeline for protocol-layer cryptographic transforms
//! used by nexSIZ testcases. This module exposes:
//! - A small StreamCipher trait for length-preserving, in-place transforms.
//! - Built-in adapters: XOR, ChaCha20 stream, and an AEAD (ChaCha20-Poly1305)
//!   convenience wrapper.
//! - A composable PipelineEncryptor supporting ordered stages: Cipher, Aead,
//!   and TLS record framing / fragmentation.
//! - CryptoProfile builder and a small registry of builtin profiles for common
//!   operator workflows (null, xor, chacha20, aead, tls, and combined variants).
//!
//! Design goals & guarantees
//! -------------------------
//! - Separation of concerns: stream ciphers are length-preserving and operate
//!   in-place; AEAD operations that expand buffers are provided via Stage::Aead
//!   and the AeadCipher helper (seal/open) to avoid contract violations.
//! - Composition: stages are applied in-order on encrypt and best-effort reversed
//!   for decrypt_response (cipher application is symmetric; AEAD/TLS reversal is
//!   attempted when possible).
//! - Extensibility: implement StreamCipher + register via PipelineEncryptor to
//!   support custom transforms without modifying core logic.
//! - Safety: all shared state is encapsulated behind value types (Arc) and no
//!   unsafe code is required. Length-affecting operations are explicit to avoid
//!   accidental payload corruption.
//!
//! Operational notes
//! -----------------
//! - AEAD: use Stage::Aead or AeadCipher::seal/open; StreamCipher::apply for
//!   AeadCipher is intentionally a no-op to prevent silent buffer-size bugs.
//! - TLS framing: TlsFrame stage supports optional fragmentation and can be
//!   layered after stream transforms to emulate real record layering.
//! - Nonce management: profiles and individual ciphers support NonceMode
//!   (Fixed, Incrementing, Random). Tune via CryptoProfile or the
//!   NEXSIZ_NONCE_MODE environment variable.
//! - Key/nonce sourcing: resolve_pipeline loads key/nonce from the provided
//!   parameters or environment variables NEXSIZ_ENC_KEY / NEXSIZ_ENC_NONCE;
//!   parsing follows crypto::parse_key_material with sensible defaults.
//!
//! Performance & implementation details
//! -----------------------------------
//! - PipelineEncryptor applies per-field stream ciphers only to non-protected
//!   fields to respect protocol semantics and avoid encrypting metadata.
//! - AEAD sealing serializes each message and replaces fields with a single
//!   binary field containing ciphertext||tag — this simplifies downstream
//!   transmission but means AEAD is not field-aware.
//! - TLS decrypt_response performs a best-effort record stripping by parsing
//!   TLS record headers and concatenating application data when available.
//!
//! Configuration & usage
//! ---------------------
//! - Use resolve_pipeline(name, key_material) to obtain an Encryptor by name.
//! - Builtin profiles: null, xor, chacha20, chacha20-poly1305 (aead),
//!   tls-record, xor+tls, chacha20+tls, aead+tls, c2-stream, c2-aead.
//! - Freeform pipelines: accept expressions like "chacha20+tls" or "xor+tls".
//! - Environment knobs:
//!   - NEXSIZ_ENC_KEY: default key material (if not provided programmatically).
!//!   - NEXSIZ_ENC_NONCE: default nonce material.
//!   - NEXSIZ_NONCE_MODE: "fixed" (default), "incrementing"/"inc"/"counter", or "random".
//!
//! Testing
//! -------
//! - In-module unit tests exercise XOR idempotence, AEAD seal/open, TLS framing,
//!   profile building, and freeform pipeline parsing.
//!
//! Notes & caveats
//! ---------------
//! - This module focuses on transform composition and does not implement key
//!   management, remote handshake state, or secure storage — integrate with
//!   your secret management in production deployments.
//! - When combining stages, be explicit about which layers expect length changes
//!   (AEAD) vs. in-place transforms (stream ciphers) to avoid subtle bugs.

use crate::common::types::{Field, FieldType, TestCase};
use crate::plugin::crypto::{
    self, make_nonce, ChaCha20, ChaCha20Poly1305, NonceMode,
};
use crate::plugin::encryptor::{
    Encryptor, TlsContentType, TlsRecordEncryptor,
};
use std::sync::Arc;

// ── StreamCipher trait ───────────────────────────────────────────────────────

/// Generic stream / transform cipher interface.
/// Implement this trait to plug a custom protocol crypto without touching the core.
///
/// Note: transforms must be length-preserving (in-place on `&mut [u8]`).
/// Length-changing operations (e.g. AEAD seal that appends a tag) must use
/// [`Stage::Aead`] inside a [`PipelineEncryptor`], not this trait.
pub trait StreamCipher: Send + Sync {
    fn name(&self) -> &str;

    /// Transform data in-place (encrypt or decrypt – stream ciphers are usually symmetric).
    fn apply(&self, data: &mut [u8]);

    /// Optional: produce a fresh cipher instance for the next message (e.g. new nonce).
    fn rekey_hint(&self) {}
}

// ── Built-in StreamCipher adapters ───────────────────────────────────────────

pub struct XorCipher {
    key: Vec<u8>,
}

impl XorCipher {
    pub fn new(key: &[u8]) -> Self {
        let key = if key.is_empty() {
            crypto::default_key()
        } else {
            key.to_vec()
        };
        Self { key }
    }
}

impl StreamCipher for XorCipher {
    fn name(&self) -> &str {
        "xor"
    }

    fn apply(&self, data: &mut [u8]) {
        if self.key.is_empty() {
            return;
        }
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= self.key[i % self.key.len()];
        }
    }
}

pub struct ChaCha20Cipher {
    key: Vec<u8>,
    nonce_base: Vec<u8>,
    nonce_mode: NonceMode,
}

impl ChaCha20Cipher {
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
        }
    }

    pub fn with_nonce_mode(mut self, mode: NonceMode) -> Self {
        self.nonce_mode = mode;
        self
    }
}

impl StreamCipher for ChaCha20Cipher {
    fn name(&self) -> &str {
        "chacha20"
    }

    fn apply(&self, data: &mut [u8]) {
        let nonce = make_nonce(&self.nonce_base, self.nonce_mode);
        let mut cipher = ChaCha20::new(&self.key, &nonce);
        cipher.set_counter(0);
        cipher.apply(data);
    }
}

/// Marker / configuration holder for ChaCha20-Poly1305.
///
/// **Do not use via `StreamCipher::apply`.** AEAD seal grows the buffer
/// (ciphertext || 16-byte tag). Always select AEAD through:
/// - `Stage::Aead { ... }` in a `PipelineEncryptor`, or
/// - the dedicated `ChaCha20Poly1305Encryptor` / profile names `aead`, `chacha20-poly1305`.
///
/// `apply` is intentionally a no-op so accidental use cannot silently corrupt length.
pub struct AeadCipher {
    aead: ChaCha20Poly1305,
    nonce_base: Vec<u8>,
    nonce_mode: NonceMode,
    aad: Vec<u8>,
}

impl AeadCipher {
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

    pub fn with_nonce_mode(mut self, mode: NonceMode) -> Self {
        self.nonce_mode = mode;
        self
    }

    pub fn with_aad(mut self, aad: &[u8]) -> Self {
        self.aad = aad.to_vec();
        self
    }

    /// Convenience: seal into a new buffer (use this, not `StreamCipher::apply`).
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = make_nonce(&self.nonce_base, self.nonce_mode);
        self.aead.seal(&nonce, &self.aad, plaintext)
    }

    /// Convenience: open; returns `None` on tag failure.
    pub fn open(&self, data: &[u8]) -> Option<Vec<u8>> {
        let nonce = make_nonce(&self.nonce_base, NonceMode::Fixed);
        self.aead.open(&nonce, &self.aad, data)
    }
}

impl StreamCipher for AeadCipher {
    fn name(&self) -> &str {
        "chacha20-poly1305"
    }

    fn apply(&self, _data: &mut [u8]) {
        // Length-changing AEAD cannot fit the StreamCipher contract.
        // Callers must use Stage::Aead or AeadCipher::seal/open.
        #[cfg(debug_assertions)]
        eprintln!(
            "nexsiz: AeadCipher::apply is a no-op; use Stage::Aead or AeadCipher::seal()"
        );
    }
}

// ── Pipeline stages ──────────────────────────────────────────────────────────

/// A single stage in a composition pipeline.
pub enum Stage {
    /// Apply a StreamCipher in-place on every non-protected field.
    Cipher(Arc<dyn StreamCipher>),
    /// AEAD seal (replaces message payload with ciphertext||tag).
    Aead {
        key: Vec<u8>,
        nonce_base: Vec<u8>,
        nonce_mode: NonceMode,
        aad: Vec<u8>,
    },
    /// TLS record framing (with optional fragmentation).
    TlsFrame {
        content_type: TlsContentType,
        version: (u8, u8),
        max_record_size: usize,
        fragment: bool,
    },
}

impl Stage {
    pub fn cipher(c: Arc<dyn StreamCipher>) -> Self {
        Stage::Cipher(c)
    }

    pub fn aead(key: &[u8], nonce: &[u8]) -> Self {
        Stage::Aead {
            key: key.to_vec(),
            nonce_base: nonce.to_vec(),
            nonce_mode: NonceMode::Fixed,
            aad: Vec::new(),
        }
    }

    pub fn tls() -> Self {
        Stage::TlsFrame {
            content_type: TlsContentType::ApplicationData,
            version: (0x03, 0x03),
            max_record_size: 16_384,
            fragment: true,
        }
    }

    pub fn tls_handshake() -> Self {
        Stage::TlsFrame {
            content_type: TlsContentType::Handshake,
            version: (0x03, 0x01),
            max_record_size: 16_384,
            fragment: true,
        }
    }
}

// ── Pipeline Encryptor ───────────────────────────────────────────────────────

/// Generic composition pipeline: stages are applied in order on encrypt,
/// and reversed (best-effort) on decrypt_response.
pub struct PipelineEncryptor {
    name: String,
    stages: Vec<Stage>,
}

impl PipelineEncryptor {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            stages: Vec::new(),
        }
    }

    pub fn push(mut self, stage: Stage) -> Self {
        self.stages.push(stage);
        self
    }

    pub fn stages(&self) -> &[Stage] {
        &self.stages
    }

    fn apply_cipher_fields(cipher: &dyn StreamCipher, tc: &mut TestCase) {
        for msg in &mut tc.messages {
            for field in &mut msg.fields {
                if field.protected {
                    continue;
                }
                cipher.apply(&mut field.data);
            }
        }
    }

    fn apply_aead(
        key: &[u8],
        nonce_base: &[u8],
        nonce_mode: NonceMode,
        aad: &[u8],
        tc: &mut TestCase,
    ) {
        let aead = ChaCha20Poly1305::new(key);
        for msg in &mut tc.messages {
            let plain = msg.serialize();
            if plain.is_empty() {
                continue;
            }
            let nonce = make_nonce(nonce_base, nonce_mode);
            let sealed = aead.seal(&nonce, aad, &plain);
            msg.fields.clear();
            msg.add_field(Field::new("aead", FieldType::Binary, sealed));
        }
    }

    fn apply_tls(
        content_type: TlsContentType,
        version: (u8, u8),
        max_record_size: usize,
        fragment: bool,
        tc: &mut TestCase,
    ) {
        let tls = TlsRecordEncryptor::new()
            .with_content_type(content_type)
            .with_version(version.0, version.1)
            .with_max_record_size(max_record_size)
            .with_fragment(fragment);
        tls.encrypt(tc);
    }
}

impl Encryptor for PipelineEncryptor {
    fn name(&self) -> &str {
        &self.name
    }

    fn encrypt(&self, tc: &mut TestCase) {
        for stage in &self.stages {
            match stage {
                Stage::Cipher(c) => Self::apply_cipher_fields(c.as_ref(), tc),
                Stage::Aead {
                    key,
                    nonce_base,
                    nonce_mode,
                    aad,
                } => Self::apply_aead(key, nonce_base, *nonce_mode, aad, tc),
                Stage::TlsFrame {
                    content_type,
                    version,
                    max_record_size,
                    fragment,
                } => Self::apply_tls(*content_type, *version, *max_record_size, *fragment, tc),
            }
        }
    }

    fn decrypt_response(&self, data: &mut Vec<u8>) {
        for stage in self.stages.iter().rev() {
            match stage {
                Stage::Cipher(c) => c.apply(data),
                Stage::Aead {
                    key,
                    nonce_base,
                    aad,
                    ..
                } => {
                    let aead = ChaCha20Poly1305::new(key);
                    let nonce = make_nonce(nonce_base, NonceMode::Fixed);
                    if let Some(pt) = aead.open(&nonce, aad, data) {
                        *data = pt;
                    }
                }
                Stage::TlsFrame { .. } => {
                    let mut out = Vec::new();
                    let mut offset = 0;
                    while offset + 5 <= data.len() {
                        let declared =
                            u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
                        let record_end = offset + 5 + declared;
                        if record_end > data.len() {
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
        }
    }
}

// ── Crypto Profile ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CryptoProfile {
    pub name: String,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub nonce_mode: NonceMode,
    pub stages: Vec<String>,
    pub tls_content_type: TlsContentType,
    pub tls_max_record: usize,
    pub aad: Vec<u8>,
}

impl CryptoProfile {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            key: crypto::default_key(),
            nonce: crypto::default_nonce(),
            nonce_mode: NonceMode::Fixed,
            stages: vec!["null".into()],
            tls_content_type: TlsContentType::ApplicationData,
            tls_max_record: 16_384,
            aad: Vec::new(),
        }
    }

    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.key = key.to_vec();
        self
    }

    pub fn with_nonce(mut self, nonce: &[u8]) -> Self {
        self.nonce = nonce.to_vec();
        self
    }

    pub fn with_nonce_mode(mut self, mode: NonceMode) -> Self {
        self.nonce_mode = mode;
        self
    }

    pub fn with_stages(mut self, stages: &[&str]) -> Self {
        self.stages = stages.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_tls_content_type(mut self, t: TlsContentType) -> Self {
        self.tls_content_type = t;
        self
    }

    pub fn with_tls_max_record(mut self, size: usize) -> Self {
        self.tls_max_record = size;
        self
    }

    pub fn with_aad(mut self, aad: &[u8]) -> Self {
        self.aad = aad.to_vec();
        self
    }

    pub fn build(&self) -> PipelineEncryptor {
        let mut pipe = PipelineEncryptor::new(self.name.clone());
        for s in &self.stages {
            let stage = match s.to_lowercase().as_str() {
                "xor" => Stage::cipher(Arc::new(XorCipher::new(&self.key))),
                "chacha20" | "chacha" => Stage::cipher(Arc::new(
                    ChaCha20Cipher::new(&self.key, &self.nonce).with_nonce_mode(self.nonce_mode),
                )),
                "chacha20-poly1305" | "aead" | "chacha-poly" => Stage::Aead {
                    key: self.key.clone(),
                    nonce_base: self.nonce.clone(),
                    nonce_mode: self.nonce_mode,
                    aad: self.aad.clone(),
                },
                "tls" | "tls-record" => Stage::TlsFrame {
                    content_type: self.tls_content_type,
                    version: (0x03, 0x03),
                    max_record_size: self.tls_max_record,
                    fragment: true,
                },
                "tls-handshake" => Stage::TlsFrame {
                    content_type: TlsContentType::Handshake,
                    version: (0x03, 0x01),
                    max_record_size: self.tls_max_record,
                    fragment: true,
                },
                "null" | "none" | "" => continue,
                _ => continue,
            };
            pipe = pipe.push(stage);
        }
        if pipe.stages.is_empty() {
            pipe = PipelineEncryptor::new(self.name.clone());
        }
        pipe
    }
}

// ── Profile registry & helpers ───────────────────────────────────────────────

pub fn builtin_profile(name: &str) -> Option<CryptoProfile> {
    match name.to_lowercase().as_str() {
        "null" | "none" => Some(CryptoProfile::new("null").with_stages(&[])),
        "xor" => Some(CryptoProfile::new("xor").with_stages(&["xor"])),
        "chacha20" | "chacha" => Some(CryptoProfile::new("chacha20").with_stages(&["chacha20"])),
        "aead" | "chacha20-poly1305" => {
            Some(CryptoProfile::new("chacha20-poly1305").with_stages(&["aead"]))
        }
        "tls" | "tls-record" => Some(CryptoProfile::new("tls-record").with_stages(&["tls"])),
        "chacha20+tls" | "chacha+tls" => {
            Some(CryptoProfile::new("chacha20+tls").with_stages(&["chacha20", "tls"]))
        }
        "aead+tls" | "chacha20-poly1305+tls" => {
            Some(CryptoProfile::new("chacha20-poly1305+tls").with_stages(&["aead", "tls"]))
        }
        "xor+tls" => Some(CryptoProfile::new("xor+tls").with_stages(&["xor", "tls"])),
        "c2-stream" => Some(
            CryptoProfile::new("c2-stream")
                .with_stages(&["chacha20", "tls"])
                .with_nonce_mode(NonceMode::Incrementing),
        ),
        "c2-aead" => Some(
            CryptoProfile::new("c2-aead")
                .with_stages(&["aead", "tls"])
                .with_nonce_mode(NonceMode::Incrementing),
        ),
        _ => None,
    }
}

pub fn parse_pipeline_expr(expr: &str, key: &[u8], nonce: &[u8], mode: NonceMode) -> PipelineEncryptor {
    let parts: Vec<&str> = expr
        .split('+')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let mut profile = CryptoProfile::new(expr)
        .with_key(key)
        .with_nonce(nonce)
        .with_nonce_mode(mode)
        .with_stages(&parts);
    profile.stages = parts.iter().map(|s| s.to_string()).collect();
    profile.build()
}

pub fn resolve_pipeline(
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

    let name = match name {
        Some(n) if !n.is_empty() => n,
        _ => return Box::new(crate::plugin::encryptor::NullEncryptor),
    };

    if let Some(profile) = builtin_profile(name) {
        let p = profile
            .with_key(&key)
            .with_nonce(&nonce)
            .with_nonce_mode(nonce_mode);
        return Box::new(p.build());
    }

    if name.contains('+') {
        return Box::new(parse_pipeline_expr(name, &key, &nonce, nonce_mode));
    }

    Box::new(
        CryptoProfile::new(name)
            .with_key(&key)
            .with_nonce(&nonce)
            .with_nonce_mode(nonce_mode)
            .with_stages(&[name])
            .build(),
    )
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
    fn pipeline_xor_then_tls() {
        let pipe = PipelineEncryptor::new("xor+tls")
            .push(Stage::cipher(Arc::new(XorCipher::new(b"secret"))))
            .push(Stage::tls());
        let mut tc = sample_tc();
        pipe.encrypt(&mut tc);
        let wire = tc.serialize();
        assert!(wire.len() >= 5);
        assert_eq!(wire[0], 0x17);
        assert_ne!(&wire[5..], b"hello");
    }

    #[test]
    fn profile_c2_stream() {
        let profile = builtin_profile("c2-stream").expect("profile");
        let pipe = profile.build();
        assert_eq!(pipe.name(), "c2-stream");
        let mut tc = sample_tc();
        pipe.encrypt(&mut tc);
        let wire = tc.serialize();
        assert_eq!(wire[0], 0x17);
    }

    #[test]
    fn freeform_pipeline() {
        let pipe = parse_pipeline_expr(
            "chacha20+tls",
            &crypto::default_key(),
            &crypto::default_nonce(),
            NonceMode::Fixed,
        );
        let mut tc = sample_tc();
        pipe.encrypt(&mut tc);
        assert_eq!(tc.serialize()[0], 0x17);
    }

    #[test]
    fn resolve_pipeline_null() {
        let e = resolve_pipeline(None, None);
        assert_eq!(e.name(), "null");
    }

    #[test]
    fn resolve_pipeline_builtin() {
        let e = resolve_pipeline(Some("aead+tls"), None);
        assert_eq!(e.name(), "chacha20-poly1305+tls");
    }

    #[test]
    fn stream_cipher_xor() {
        let c = XorCipher::new(b"key");
        let mut d = b"test".to_vec();
        c.apply(&mut d);
        assert_ne!(d, b"test");
        c.apply(&mut d);
        assert_eq!(d, b"test");
    }

    #[test]
    fn aead_cipher_seal_open() {
        let c = AeadCipher::new(b"0123456789abcdef0123456789abcdef", b"nonce-nonce!");
        let sealed = c.seal(b"payload");
        assert!(sealed.len() >= 16);
        let pt = c.open(&sealed).expect("tag");
        assert_eq!(pt, b"payload");
    }
}
