//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::mutator_bridge
//!
//! Python Mutator hooks bridge (push extras – zero hot-path RPC)
//! 
//! Push model only: extra dictionary tokens are merged into each worker's
//! mutator. No reverse-RPC on the mutation hot path (avoids throughput
//! collapse and keeps integrity ownership unambiguous).
//!
//! Pre/post mutation *callbacks* that transform payloads are intentionally
//! omitted from v1 reverse-RPC – they would sit between mutate and repair
//! and risk double-repair if they also fixed framing. Dictionary / weight
//! hints cover the operational need without that hazard.

use crate::scripting::json::JsonValue;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

pub struct MutatorBridge {
    active: AtomicBool,
    extra_dictionary: RwLock<Vec<Vec<u8>>>,
    /// Generation counter – workers re-merge when this changes.
    generation: std::sync::atomic::AtomicU64,
}

impl MutatorBridge {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            extra_dictionary: RwLock::new(Vec::new()),
            generation: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn register(&self, dictionary: Vec<Vec<u8>>) {
        {
            let mut slot = self.extra_dictionary.write().unwrap();
            *slot = dictionary;
        }
        self.active.store(true, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Append tokens without clearing existing ones.
    pub fn extend(&self, tokens: Vec<Vec<u8>>) {
        {
            let mut slot = self.extra_dictionary.write().unwrap();
            for t in tokens {
                if !t.is_empty() && !slot.iter().any(|d| d == &t) {
                    slot.push(t);
                }
            }
        }
        self.active.store(true, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn unregister(&self) {
        self.active.store(false, Ordering::Relaxed);
        *self.extra_dictionary.write().unwrap() = Vec::new();
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dictionary(&self) -> Vec<Vec<u8>> {
        if !self.is_active() {
            return Vec::new();
        }
        self.extra_dictionary.read().unwrap().clone()
    }

    pub fn dictionary_len(&self) -> usize {
        if !self.is_active() {
            return 0;
        }
        self.extra_dictionary.read().unwrap().len()
    }
}

impl Default for MutatorBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse register_mutator params → dictionary tokens.
pub fn dictionary_from_params(params: &JsonValue) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    if let Some(JsonValue::Array(arr)) = params.get("extra_dictionary") {
        for item in arr {
            if let Some(b) = entry_to_bytes(item) {
                if !b.is_empty() && !out.iter().any(|d| d == &b) {
                    out.push(b);
                }
            }
        }
    }
    // Also accept "dictionary" alias
    if let Some(JsonValue::Array(arr)) = params.get("dictionary") {
        for item in arr {
            if let Some(b) = entry_to_bytes(item) {
                if !b.is_empty() && !out.iter().any(|d| d == &b) {
                    out.push(b);
                }
            }
        }
    }
    Ok(out)
}

fn entry_to_bytes(v: &JsonValue) -> Option<Vec<u8>> {
    match v {
        JsonValue::String(s) => Some(s.as_bytes().to_vec()),
        JsonValue::Object(_) => {
            let enc = v.get_str("encoding").unwrap_or("utf8");
            let data = v.get_str("data")?;
            match enc {
                "base64" | "b64" => b64_decode(data).ok(),
                _ => Some(data.as_bytes().to_vec()),
            }
        }
        JsonValue::Number(n) => Some(vec![(*n as u64).min(255) as u8]),
        _ => None,
    }
}

fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: i32 = 0;
    for c in input.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let val = TABLE
            .iter()
            .position(|&x| x == c as u8)
            .ok_or_else(|| format!("invalid base64 char: {}", c))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripting::json;

    #[test]
    fn register_extend() {
        let b = MutatorBridge::new();
        b.register(vec![b"USER".to_vec()]);
        assert_eq!(b.dictionary_len(), 1);
        b.extend(vec![b"PASS".to_vec(), b"USER".to_vec()]);
        assert_eq!(b.dictionary_len(), 2);
        b.unregister();
        assert!(!b.is_active());
    }

    #[test]
    fn parse_params() {
        let p = json::obj(vec![(
            "extra_dictionary",
            JsonValue::Array(vec![json::s("RETR"), json::s("STOR")]),
        )]);
        let d = dictionary_from_params(&p).unwrap();
        assert_eq!(d.len(), 2);
    }
}
