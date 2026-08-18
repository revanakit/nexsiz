//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::mutator_bridge
//!
//! Description
//! -----------
//! Push-only bridge that injects extra dictionary tokens into every worker's
//! Mutator at runtime. Designed so the mutation hot path never performs
//! reverse-RPC: workers simply observe a generation counter and re-merge the
//! extra dictionary when it changes. This preserves throughput and keeps
//! integrity-repair ownership unambiguous.
//!
//! Core responsibilities
//! ---------------------
//! - Hold a shared extra dictionary (Vec<Vec<u8>>) behind an AtomicBool +
//!   RwLock.
//! - Expose register (replace) and extend (append, deduplicating) operations.
//! - Maintain a monotonic generation counter; workers re-merge when the
//!   counter advances.
//! - Parse register_mutator params (extra_dictionary / dictionary aliases)
//!   into raw token bytes via dictionary_from_params.
//! - Provide status helpers (is_active, dictionary_len, generation) used by
//!   the RPC handler and Engine status reporting.
//!
//! Why push-only (no pre/post mutation callbacks)
//! ----------------------------------------------
//! - A reverse-RPC callback that transforms the payload after mutate() would
//!   sit between mutation and integrity repair. If the callback also fixed
//!   framing/checksums it would risk double-repair or ownership confusion.
//! - Dictionary / weight hints cover the practical operational need (inject
//!   protocol-specific tokens, bias toward interesting sequences) without
//!   introducing that hazard.
//! - The design keeps Mutator::mutate and the subsequent prepare_for_send
//!   path identical to the native case.
//!
//! Worker integration
//! ------------------
//! - Each worker caches the last observed generation.
//! - On every iteration it compares against mutator_bridge.generation();
//!   if different it calls mutator.extend_dictionary(&extra) and updates the
//!   local generation.
//! - Unregister clears the dictionary and bumps generation so workers drop
//!   the extras on the next cycle.
//!
//! Concurrency model
//! -----------------
//! - active: AtomicBool (Relaxed).
//! - extra_dictionary: RwLock; register/extend/unregister take the write lock.
//! - generation: AtomicU64, incremented on every mutating operation so that
//!   even an extend that adds nothing still forces workers to re-check.
//! - Safe for concurrent register from the RPC thread and reads from many
//!   worker threads.
//!
//! Params contract (register_mutator)
//! ----------------------------------
//! ```json
//! {
//!   "extra_dictionary": [ "USER", {"encoding":"base64","data":"…"}, 0x0a ],
//!   "dictionary": [ … ],          // alias for extra_dictionary
//!   "extend": true                // optional; default false → replace
//! }
//! ```
//! Tokens may be plain strings, {encoding,data} objects, or single-byte
//! numbers. Empty / invalid entries are skipped; duplicates are removed.
//!
//! Design notes
//! ------------
//! - No reverse-RPC on the mutation path is a hard invariant of v1.
//! - The bridge never owns a Mutator instance; it only supplies material that
//!   workers merge into their own mutators.
//! - Future weight / energy hints can be added alongside the dictionary
//!   without changing the generation-based re-merge protocol.
//!
//! See Also
//! --------
//! - handler.rs         : register_mutator / mutator_status commands
//! - input/mutator.rs   : Mutator::extend_dictionary consumer
//! - execution/worker.rs: generation check + re-merge loop

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
