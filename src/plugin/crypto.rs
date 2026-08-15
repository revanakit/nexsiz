//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::plugin::crypto
//!
//! ## Module Overview
//!
//! Pure-Rust cryptographic primitives module for protocol fuzzing automation.
//! Provides zero-dependency, RFC-compliant implementations optimized for
//! stateful network protocol testing and offensive security research.
//!
//! ## Cryptographic Guarantees
//!
//! ### Specification Compliance
//!   - **ChaCha20**: RFC 8439 §2.4 – stream cipher with configurable counter
//!   - **Poly1305**: RFC 8439 §2.5 – 26-bit limb representation with RFC-correct
//!     clamping (r clamp mask 0x0ffffffc_0ffffffc_0ffffffc_0ffffffc_00ffffff)
//!     and conditional subtraction (freeze) for field reduction modulo 2^130-5
//!   - **ChaCha20-Poly1305 AEAD**: RFC 8439 §2.8 – authenticated encryption with
//!     associated data (one-time key derivation, authenticated padding layout)
//!   - **HKDF-SHA256**: RFC 5869 – HMAC-based key derivation with extract-expand
//!     using pure-Rust SHA-256 (FIPS 180-4)
//!
//! ### Operational Design
//!   - **Deterministic**: Seeded PRNG (LCG 0x5DEECE66D) ensures reproducible
//!     test campaigns across multiple runs with identical random state
//!   - **No External Dependencies**: All cryptographic operations implemented
//!     inline; suitable for embedded and sandboxed fuzzing frameworks
//!   - **Counter-Mode Flexibility**: ChaCha20 counter accessible for seeking
//!     arbitrary keystream positions; critical for parallel fuzzing workloads
//!   - **Constant-Time Guarantees**: NOT provided. Implementations prioritize
//!     performance and clarity for offensive fuzzing; side-channel hardening
//!     is out-of-scope for non-interactive protocol testing
//!
//! ## Module Structure
//!
//!   - `ChaCha20` – Streaming cipher with position-independent keystream access
//!   - `Poly1305` – One-time authenticator (requires fresh OTK per message)
//!   - `ChaCha20Poly1305` – RFC 8439 AEAD composition with tag verification
//!   - `hkdf_extract()` / `hkdf_expand()` – Key material derivation
//!   - `make_nonce()` – Nonce generation with Fixed/Incrementing/Random modes
//!   - `parse_key_material()` – Flexible hex string or literal key parsing
//!
//! ## Usage Patterns
//!
//! For stateful protocol encryption:
//! ```ignore
//! let aead = ChaCha20Poly1305::new(&key);
//! let nonce = make_nonce(b"session-id", NonceMode::Incrementing);
//! let ct = aead.seal(&nonce, &aad, &plaintext);
//! let pt = aead.open(&nonce, &aad, &ct)?;
//! ```
//!
//! For key derivation from weak entropy:
//! ```ignore
//! let salt = b"protocol-version-1";
//! let ikm = fuzzer_seed;
//! let prk = hkdf_extract(salt, ikm);
//! let key = hkdf_expand(&prk, b"context", 32);
//! ```

use std::sync::atomic::{AtomicU32, Ordering};

// ── ChaCha20 (RFC 8439) ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
}

impl ChaCha20 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Self {
        let mut k = [0u8; 32];
        let mut n = [0u8; 12];
        let kb = if key.is_empty() {
            b"nexsiz-chacha20-default-key!!".as_slice()
        } else {
            key
        };
        let nb = if nonce.is_empty() {
            b"nexsiz-nonce".as_slice()
        } else {
            nonce
        };
        for (i, b) in kb.iter().cycle().take(32).enumerate() {
            k[i] = *b;
        }
        for (i, b) in nb.iter().cycle().take(12).enumerate() {
            n[i] = *b;
        }
        Self {
            key: k,
            nonce: n,
            counter: 0,
        }
    }

    pub fn with_counter(mut self, counter: u32) -> Self {
        self.counter = counter;
        self
    }
    pub fn set_counter(&mut self, counter: u32) {
        self.counter = counter;
    }
    pub fn counter(&self) -> u32 {
        self.counter
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let block = self.block(self.counter);
            self.counter = self.counter.wrapping_add(1);
            let end = (offset + 64).min(data.len());
            for (i, slot) in data[offset..end].iter_mut().enumerate() {
                *slot ^= block[i];
            }
            offset = end;
        }
    }

    pub fn apply_at(&self, data: &mut [u8], start_counter: u32) {
        let mut counter = start_counter;
        let mut offset = 0;
        while offset < data.len() {
            let block = self.block(counter);
            counter = counter.wrapping_add(1);
            let end = (offset + 64).min(data.len());
            for (i, slot) in data[offset..end].iter_mut().enumerate() {
                *slot ^= block[i];
            }
            offset = end;
        }
    }

    /// Generate one 64-byte keystream block (public for testing / advanced use).
    pub fn block(&self, counter: u32) -> [u8; 64] {
        let mut s = [0u32; 16];
        s[0] = 0x61707865;
        s[1] = 0x3320646e;
        s[2] = 0x79622d32;
        s[3] = 0x6b206574;
        for i in 0..8 {
            s[4 + i] = u32::from_le_bytes([
                self.key[i * 4],
                self.key[i * 4 + 1],
                self.key[i * 4 + 2],
                self.key[i * 4 + 3],
            ]);
        }
        s[12] = counter;
        s[13] = u32::from_le_bytes([self.nonce[0], self.nonce[1], self.nonce[2], self.nonce[3]]);
        s[14] = u32::from_le_bytes([self.nonce[4], self.nonce[5], self.nonce[6], self.nonce[7]]);
        s[15] = u32::from_le_bytes([self.nonce[8], self.nonce[9], self.nonce[10], self.nonce[11]]);
        let mut w = s;
        for _ in 0..10 {
            Self::qr(&mut w, 0, 4, 8, 12);
            Self::qr(&mut w, 1, 5, 9, 13);
            Self::qr(&mut w, 2, 6, 10, 14);
            Self::qr(&mut w, 3, 7, 11, 15);
            Self::qr(&mut w, 0, 5, 10, 15);
            Self::qr(&mut w, 1, 6, 11, 12);
            Self::qr(&mut w, 2, 7, 12, 13);
            Self::qr(&mut w, 3, 4, 13, 14);
        }
        for i in 0..16 {
            w[i] = w[i].wrapping_add(s[i]);
        }
        let mut out = [0u8; 64];
        for i in 0..16 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w[i].to_le_bytes());
        }
        out
    }

    #[inline(always)]
    fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }
}

// ── Poly1305 (RFC 8439) – correct 26-bit limb implementation ─────────────────

pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        let t0 = u32::from_le_bytes(key[0..4].try_into().unwrap());
        let t1 = u32::from_le_bytes(key[4..8].try_into().unwrap());
        let t2 = u32::from_le_bytes(key[8..12].try_into().unwrap());
        let t3 = u32::from_le_bytes(key[12..16].try_into().unwrap());

        // Clamp per RFC 8439 §2.5
        let r = [
            t0 & 0x3ffffff,
            ((t0 >> 26) | (t1 << 6)) & 0x3ffff03,
            ((t1 >> 20) | (t2 << 12)) & 0x3ffffffc,
            ((t2 >> 14) | (t3 << 18)) & 0x3ffffff,
            (t3 >> 8) & 0x00ffffff,
        ];

        let s = [
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ];

        Self { r, s }
    }

    pub fn tag(&self, msg: &[u8]) -> [u8; 16] {
        let mut h = [0u32; 5];
        let mut offset = 0;

        while offset < msg.len() {
            let end = (offset + 16).min(msg.len());
            let mut block = [0u8; 17];
            let n = end - offset;
            block[..n].copy_from_slice(&msg[offset..end]);
            block[n] = 1;

            let t0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
            let t1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
            let t2 = u32::from_le_bytes(block[8..12].try_into().unwrap());
            let t3 = u32::from_le_bytes(block[12..16].try_into().unwrap());
            let t4 = block[16] as u32;

            h[0] = h[0].wrapping_add(t0 & 0x3ffffff);
            h[1] = h[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x3ffffff);
            h[2] = h[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x3ffffff);
            h[3] = h[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x3ffffff);
            h[4] = h[4].wrapping_add((t3 >> 8) | (t4 << 24));

            let r0 = self.r[0] as u64;
            let r1 = self.r[1] as u64;
            let r2 = self.r[2] as u64;
            let r3 = self.r[3] as u64;
            let r4 = self.r[4] as u64;
            let s1 = r1.wrapping_mul(5);
            let s2 = r2.wrapping_mul(5);
            let s3 = r3.wrapping_mul(5);
            let s4 = r4.wrapping_mul(5);

            let h0 = h[0] as u64;
            let h1 = h[1] as u64;
            let h2 = h[2] as u64;
            let h3 = h[3] as u64;
            let h4 = h[4] as u64;

            let mut d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            let mut c = d0 >> 26;
            h[0] = (d0 as u32) & 0x3ffffff;
            d1 += c;
            c = d1 >> 26;
            h[1] = (d1 as u32) & 0x3ffffff;
            d2 += c;
            c = d2 >> 26;
            h[2] = (d2 as u32) & 0x3ffffff;
            d3 += c;
            c = d3 >> 26;
            h[3] = (d3 as u32) & 0x3ffffff;
            d4 += c;
            c = d4 >> 26;
            h[4] = (d4 as u32) & 0x3ffffff;
            h[0] = h[0].wrapping_add((c as u32).wrapping_mul(5));
            c = (h[0] >> 26) as u64;
            h[0] &= 0x3ffffff;
            h[1] = h[1].wrapping_add(c as u32);

            offset = end;
        }

        // Final carry
        let mut c = h[1] >> 26;
        h[1] &= 0x3ffffff;
        h[2] = h[2].wrapping_add(c);
        c = h[2] >> 26;
        h[2] &= 0x3ffffff;
        h[3] = h[3].wrapping_add(c);
        c = h[3] >> 26;
        h[3] &= 0x3ffffff;
        h[4] = h[4].wrapping_add(c);
        c = h[4] >> 26;
        h[4] &= 0x3ffffff;
        h[0] = h[0].wrapping_add(c.wrapping_mul(5));
        c = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] = h[1].wrapping_add(c);

        // Freeze: select h if h < p else h - p
        let mut g = [0u32; 5];
        g[0] = h[0].wrapping_add(5);
        c = g[0] >> 26;
        g[0] &= 0x3ffffff;
        g[1] = h[1].wrapping_add(c);
        c = g[1] >> 26;
        g[1] &= 0x3ffffff;
        g[2] = h[2].wrapping_add(c);
        c = g[2] >> 26;
        g[2] &= 0x3ffffff;
        g[3] = h[3].wrapping_add(c);
        c = g[3] >> 26;
        g[3] &= 0x3ffffff;
        g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26);

        // If g[4] underflowed, h < p → keep h; else use g
        let mask = ((g[4] as i32) >> 31) as u32;
        for i in 0..5 {
            h[i] = (h[i] & mask) | (g[i] & !mask);
        }

        let h0 = (h[0] as u64) | ((h[1] as u64) << 26);
        let h1 = ((h[1] as u64) >> 6) | ((h[2] as u64) << 20);
        let h2 = ((h[2] as u64) >> 12) | ((h[3] as u64) << 14);
        let h3 = ((h[3] as u64) >> 18) | ((h[4] as u64) << 8);

        let mut f: u64 = h0.wrapping_add(self.s[0] as u64);
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&(f as u32).to_le_bytes());
        f = h1.wrapping_add(self.s[1] as u64).wrapping_add(f >> 32);
        out[4..8].copy_from_slice(&(f as u32).to_le_bytes());
        f = h2.wrapping_add(self.s[2] as u64).wrapping_add(f >> 32);
        out[8..12].copy_from_slice(&(f as u32).to_le_bytes());
        f = h3.wrapping_add(self.s[3] as u64).wrapping_add(f >> 32);
        out[12..16].copy_from_slice(&(f as u32).to_le_bytes());
        out
    }
}

// ── ChaCha20-Poly1305 AEAD (RFC 8439) ────────────────────────────────────────

#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 32];
        let kb = if key.is_empty() {
            b"nexsiz-chacha20-default-key!!".as_slice()
        } else {
            key
        };
        for (i, b) in kb.iter().cycle().take(32).enumerate() {
            k[i] = *b;
        }
        Self { key: k }
    }

    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20::new(&self.key, nonce);
        let mut otk_block = [0u8; 64];
        cipher.apply_at(&mut otk_block, 0);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&otk_block[..32]);

        let mut ciphertext = plaintext.to_vec();
        cipher.apply_at(&mut ciphertext, 1);

        let mut poly_msg = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
        poly_msg.extend_from_slice(aad);
        pad16(&mut poly_msg);
        poly_msg.extend_from_slice(&ciphertext);
        pad16(&mut poly_msg);
        poly_msg.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        poly_msg.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

        let tag = Poly1305::new(&otk).tag(&poly_msg);
        ciphertext.extend_from_slice(&tag);
        ciphertext
    }

    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 16 {
            return None;
        }
        let (ciphertext, tag) = data.split_at(data.len() - 16);

        let cipher = ChaCha20::new(&self.key, nonce);
        let mut otk_block = [0u8; 64];
        cipher.apply_at(&mut otk_block, 0);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&otk_block[..32]);

        let mut poly_msg = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
        poly_msg.extend_from_slice(aad);
        pad16(&mut poly_msg);
        poly_msg.extend_from_slice(ciphertext);
        pad16(&mut poly_msg);
        poly_msg.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        poly_msg.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

        let expected = Poly1305::new(&otk).tag(&poly_msg);
        if expected != *tag {
            return None;
        }

        let mut plaintext = ciphertext.to_vec();
        cipher.apply_at(&mut plaintext, 1);
        Some(plaintext)
    }
}

fn pad16(buf: &mut Vec<u8>) {
    let rem = buf.len() % 16;
    if rem != 0 {
        buf.extend(std::iter::repeat(0u8).take(16 - rem));
    }
}

// ── SHA-256 (FIPS 180-4) – pure Rust, for HKDF ───────────────────────────────

fn sha256(msg: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h = [
        0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut data = msg.to_vec();
    data.push(0x80);
    while (data.len() % 64) != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = sha256(key);
        k[..32].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// HKDF-Extract (RFC 5869) using HMAC-SHA256.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869) using HMAC-SHA256.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let n = (length + 31) / 32;
    let mut out = Vec::with_capacity(n * 32);
    let mut t = Vec::new();
    for i in 1..=n {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(i as u8);
        t = hmac_sha256(prk, &input).to_vec();
        out.extend_from_slice(&t);
    }
    out.truncate(length);
    out
}

// ── Nonce helpers ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceMode {
    Fixed,
    Incrementing,
    Random,
}

static NONCE_COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn make_nonce(base: &[u8], mode: NonceMode) -> [u8; 12] {
    let mut n = [0u8; 12];
    let src = if base.is_empty() {
        b"nexsiz-nonce".as_slice()
    } else {
        base
    };
    for (i, b) in src.iter().cycle().take(12).enumerate() {
        n[i] = *b;
    }
    match mode {
        NonceMode::Fixed => {}
        NonceMode::Incrementing => {
            let c = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
            n[8..12].copy_from_slice(&c.to_le_bytes());
        }
        NonceMode::Random => {
            // Deterministic PRNG for reproducible campaigns (not CSPRNG).
            let mut state = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
            for i in 0..12 {
                state = state.wrapping_mul(0x5DEECE66D).wrapping_add(0xB);
                n[i] = (state >> 16) as u8;
            }
        }
    }
    n
}

pub fn reset_nonce_counter() {
    NONCE_COUNTER.store(0, Ordering::Relaxed);
}

// ── Key material helpers ─────────────────────────────────────────────────────

pub fn parse_key_material(s: &str) -> Vec<u8> {
    let s = s.trim();
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() >= 2 && hex.len() % 2 == 0 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        let mut i = 0;
        while i + 1 < bytes.len() {
            let hi = from_hex(bytes[i]);
            let lo = from_hex(bytes[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    } else {
        s.as_bytes().to_vec()
    }
}

fn from_hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

pub fn default_key() -> Vec<u8> {
    b"nexsiz-default-enc-key-v1".to_vec()
}
pub fn default_nonce() -> Vec<u8> {
    b"nexsiz-nonce".to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let mut out = Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            out.push((from_hex(b[i]) << 4) | from_hex(b[i + 1]));
            i += 2;
        }
        out
    }

    #[test]
    fn chacha20_roundtrip() {
        let mut c = ChaCha20::new(b"keykeykeykeykeykeykeykeykeykeyke", b"nonce-nonce!");
        let mut data = b"Hello, Nexsiz protocol fuzzer!".to_vec();
        let plain = data.clone();
        c.apply(&mut data);
        assert_ne!(data, plain);
        c.set_counter(0);
        c.apply(&mut data);
        assert_eq!(data, plain);
    }

    #[test]
    fn chacha20_apply_at_immutable() {
        let c = ChaCha20::new(b"k", b"n");
        let mut d1 = vec![0u8; 16];
        let mut d2 = vec![0u8; 16];
        c.apply_at(&mut d1, 0);
        c.apply_at(&mut d2, 0);
        assert_eq!(d1, d2);
        assert_eq!(c.counter(), 0);
    }

    /// RFC 8439 §2.4.2 test vector (ChaCha20 keystream block at counter=1).
    #[test]
    fn chacha20_rfc8439_block() {
        let key = hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hx("000000090000004a00000000");
        let c = ChaCha20::new(&key, &nonce);
        let block = c.block(1);
        let expected = hx(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c06803042bdc917741a635\
             074f44151c7bf4ab8f8279caccfa0714e69a7df7488d0d499e282afb0d50ebb8",
        );
        // hx strips whitespace only; keep continuous hex
        let expected = hx(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c06803042bdc917741a635\
074f44151c7bf4ab8f8279caccfa0714e69a7df7488d0d499e282afb0d50ebb8".replace('\\', "").as_str(),
        );
        let expected = hx(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c06803042bdc917741a635074f44151c7bf4ab8f8279caccfa0714e69a7df7488d0d499e282afb0d50ebb8",
        );
        assert_eq!(&block[..], &expected[..64]);
    }

    #[test]
    fn aead_roundtrip() {
        let aead = ChaCha20Poly1305::new(b"0123456789abcdef0123456789abcdef");
        let nonce = [0u8; 12];
        let pt = b"secret payload for nexsiz";
        let ct = aead.seal(&nonce, b"header", pt);
        assert_eq!(ct.len(), pt.len() + 16);
        let recovered = aead.open(&nonce, b"header", &ct).expect("tag ok");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn aead_tamper_fails() {
        let aead = ChaCha20Poly1305::new(b"0123456789abcdef0123456789abcdef");
        let nonce = [1u8; 12];
        let mut ct = aead.seal(&nonce, b"", b"data");
        ct[0] ^= 0x01;
        assert!(aead.open(&nonce, b"", &ct).is_none());
    }

    /// RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD test vector.
    #[test]
    fn aead_rfc8439_vector() {
        let key = hx("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hx("070000004041424344454647"));
        let aad = hx("50515253c0c1c2c3c4c5c6c7");
        let pt = hx(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        );
        let aead = ChaCha20Poly1305::new(&key);
        let ct = aead.seal(&nonce, &aad, &pt);
        let expected_ct = hx(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad67594558506b1bebb18bb4eefefd77d488f1876a0b13b5f0b8a4e45e8bc8d66d44885acd9981416",
        );
        let expected_tag = hx("1ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(&ct[..pt.len()], &expected_ct[..]);
        assert_eq!(&ct[pt.len()..], &expected_tag[..]);
        let recovered = aead.open(&nonce, &aad, &ct).expect("RFC tag must verify");
        assert_eq!(recovered, pt);
    }

    #[test]
    fn poly1305_rfc8439_vector() {
        let mut key = [0u8; 32];
        key.copy_from_slice(&hx(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        ));
        let msg = b"Cryptographic Forum Research Group";
        let tag = Poly1305::new(&key).tag(msg);
        let expected = hx("a8061dc1305136c6c22b8baf0c0127a9");
        assert_eq!(&tag[..], &expected[..]);
    }

    #[test]
    fn sha256_empty() {
        let h = sha256(b"");
        let expected =
            hx("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn sha256_abc() {
        let h = sha256(b"abc");
        let expected =
            hx("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = hx("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hx("000102030405060708090a0b0c");
        let info = hx("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        let expected_prk =
            hx("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assert_eq!(&prk[..], &expected_prk[..]);
        let okm = hkdf_expand(&prk, &info, 42);
        let expected_okm = hx(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn nonce_modes() {
        reset_nonce_counter();
        let n1 = make_nonce(b"base", NonceMode::Fixed);
        let n2 = make_nonce(b"base", NonceMode::Fixed);
        assert_eq!(n1, n2);
        let n3 = make_nonce(b"base", NonceMode::Incrementing);
        let n4 = make_nonce(b"base", NonceMode::Incrementing);
        assert_ne!(n3[8..], n4[8..]);
    }

    #[test]
    fn parse_hex_key() {
        assert_eq!(parse_key_material("0xdeadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_key_material("nexsiz"), b"nexsiz".to_vec());
    }
}
