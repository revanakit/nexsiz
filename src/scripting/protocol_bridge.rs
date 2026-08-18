//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::protocol_bridge
//!
//! Description
//! -----------
//! Push-style bridge that allows a Python client to inject a complete
//! ProtocolModel (dictionary, delimiter, length-prefix flag, optional
//! productions / sequence hints) into a running campaign. Once registered the
//! model is snapshotted by workers at spawn time; the hot mutation path stays
//! zero-overhead (no reverse-RPC per mutation).
//!
//! Core responsibilities
//! ---------------------
//! - Store a single Python-supplied ProtocolModel behind an AtomicBool +
//!   RwLock so registration is race-free and reads are cheap.
//! - Expose BridgedProtocol – a ProtocolPlugin that prefers the bridge model
//!   when active and otherwise falls back to the native plugin.
//! - Parse the register_protocol params object (JSON) into a fully-formed
//!   ProtocolModel via model_from_params, including dictionary expansion from
//!   productions and sequence_hints.
//! - Provide status helpers (name, dictionary_len, is_active) used by the
//!   RPC handler and by the Engine status line.
//!
//! Push design rationale
//! ---------------------
//! - Reverse-RPC on every mutation would destroy throughput and complicate
//!   integrity ownership. A one-shot push of the model keeps the worker loop
//!   identical to the native path after the initial snapshot.
//! - Live mid-campaign worker swap is intentionally out of scope for v1.
//!   Operators must register the model before (or very early in) the campaign,
//!   or restart workers in a future iteration that supports dynamic rebind.
//!
//! Params contract (register_protocol)
//! -----------------------------------
//! Expected JSON shape (all fields optional except where noted):
//! ```json
//! {
//!   "name": "myproto",
//!   "dictionary": [ {"encoding":"utf8","data":"USER"}, {"encoding":"base64","data":"…"}, "PASS" ],
//!   "length_prefixed": false,
//!   "delimiter": 10,
//!   "productions": [
//!      { "name": "cmd", "tokens": ["USER","PASS"], "suffix": "\r\n" }
//!   ],
//!   "sequence_hints": ["login", "cwd", "retr"]
//! }
//! ```
//! - sequence_hints are folded into the dictionary as utf8 tokens (keeps
//!   ProtocolModel unchanged while still guiding mutation).
//! - An empty dictionary is replaced by a minimal sensible set so the
//!   mutator always has material.
//!
//! Concurrency & ownership
//! -----------------------
//! - active flag is AtomicBool (Relaxed).
//! - model is protected by RwLock; register/unregister take the write lock,
//!   model() takes the read lock and clones.
//! - Only one model is live at a time; a new register overwrites the previous.
//!
//! Integration points
//! ------------------
//! - Engine snapshots the model (via protocol_bridge.model()) just before
//!   spawning workers.
//! - BridgedProtocol implements ProtocolPlugin so the rest of the plugin
//!   resolution path remains unaware of the Python origin.
//! - handler.rs routes register_protocol / unregister_protocol /
//!   protocol_status / get_protocol to this bridge.
//!
//! Design notes
//! ------------
//! - model_from_params is deliberately defensive: unknown encodings fall back
//!   to utf8, invalid entries are skipped, and a floor dictionary is always
//!   present.
//! - Desocket / message-spec / sequence-spec fields are left empty; a future
//!   extension can populate them without changing the bridge API.
//!
//! See Also
//! --------
//! - handler.rs         : register_protocol command surface
//! - input/model.rs     : ProtocolModel definition
//! - plugin/protocol.rs : ProtocolPlugin trait and native resolvers

use crate::input::model::{ModelChecksum, ModelEndian, ProtocolModel};
use crate::plugin::protocol::ProtocolPlugin;
use crate::scripting::json::JsonValue;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

/// Shared store for a Python-supplied protocol model.
pub struct ProtocolBridge {
    active: AtomicBool,
    model: RwLock<Option<ProtocolModel>>,
}

impl ProtocolBridge {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            model: RwLock::new(None),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn register(&self, model: ProtocolModel) {
        {
            let mut slot = self.model.write().unwrap();
            *slot = Some(model);
        }
        self.active.store(true, Ordering::Relaxed);
    }

    pub fn unregister(&self) {
        self.active.store(false, Ordering::Relaxed);
        let mut slot = self.model.write().unwrap();
        *slot = None;
    }

    /// Snapshot of the current model (if any).
    pub fn model(&self) -> Option<ProtocolModel> {
        if !self.is_active() {
            return None;
        }
        self.model.read().unwrap().clone()
    }

    pub fn name(&self) -> String {
        self.model
            .read()
            .unwrap()
            .as_ref()
            .map(|m| m.name.clone())
            .unwrap_or_else(|| "none".into())
    }

    pub fn dictionary_len(&self) -> usize {
        self.model
            .read()
            .unwrap()
            .as_ref()
            .map(|m| m.dictionary.len())
            .unwrap_or(0)
    }
}

impl Default for ProtocolBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// ProtocolPlugin that reads from the bridge (used when Python model is active).
pub struct BridgedProtocol {
    bridge: Arc<ProtocolBridge>,
    fallback: Box<dyn ProtocolPlugin>,
}

impl BridgedProtocol {
    pub fn new(bridge: Arc<ProtocolBridge>, fallback: Box<dyn ProtocolPlugin>) -> Self {
        Self { bridge, fallback }
    }
}

impl ProtocolPlugin for BridgedProtocol {
    fn name(&self) -> &str {
        // ProtocolPlugin::name returns &str – we need a stable string.
        // When active the real name lives in the model; expose a fixed tag here
        // and put the human name inside ProtocolModel.name.
        if self.bridge.is_active() {
            "python"
        } else {
            self.fallback.name()
        }
    }

    fn build_model(&self) -> ProtocolModel {
        if let Some(m) = self.bridge.model() {
            m
        } else {
            self.fallback.build_model()
        }
    }
}

/// Parse a register_protocol params object into a ProtocolModel.
///
/// Expected shape:
/// ```json
/// {
///   "name": "myproto",
///   "dictionary": [ {"encoding":"utf8","data":"USER"}, {"encoding":"base64","data":"..."}, "PASS" ],
///   "length_prefixed": false,
///   "delimiter": 10,
///   "productions": [
///      { "name": "cmd", "tokens": ["USER","PASS"], "suffix": "\r\n" }
///   ],
///   "sequence_hints": ["login", "cwd", "retr"]
/// }
/// ```
/// `sequence_hints` are folded into the dictionary as utf8 tokens for now
/// (keeps ProtocolModel unchanged while still guiding mutation).
pub fn model_from_params(params: &JsonValue) -> Result<ProtocolModel, String> {
    let name = params
        .get_str("name")
        .unwrap_or("python")
        .to_string();

    let mut dictionary: Vec<Vec<u8>> = Vec::new();

    // dictionary array
    if let Some(JsonValue::Array(arr)) = params.get("dictionary") {
        for item in arr {
            match dict_entry_to_bytes(item) {
                Some(b) if !b.is_empty() => {
                    if !dictionary.iter().any(|d| d == &b) {
                        dictionary.push(b);
                    }
                }
                _ => {}
            }
        }
    }

    // productions → expand tokens + suffixes into dictionary
    if let Some(JsonValue::Array(prods)) = params.get("productions") {
        for prod in prods {
            if let Some(JsonValue::Array(tokens)) = prod.get("tokens") {
                for t in tokens {
                    if let Some(b) = dict_entry_to_bytes(t) {
                        if !b.is_empty() && !dictionary.iter().any(|d| d == &b) {
                            dictionary.push(b);
                        }
                    }
                }
            }
            if let Some(suf) = prod.get("suffix").and_then(dict_entry_to_bytes) {
                if !suf.is_empty() && !dictionary.iter().any(|d| d == &suf) {
                    dictionary.push(suf);
                }
            }
        }
    }

    // sequence_hints → utf8 dictionary entries (mutation guidance)
    if let Some(JsonValue::Array(hints)) = params.get("sequence_hints") {
        for h in hints {
            if let Some(s) = h.as_str() {
                let b = s.as_bytes().to_vec();
                if !b.is_empty() && !dictionary.iter().any(|d| d == &b) {
                    dictionary.push(b);
                }
            }
        }
    }

    // Sensible minimum dictionary so mutator always has material
    if dictionary.is_empty() {
        dictionary.extend(vec![
            b"\x00".to_vec(),
            b"\xff".to_vec(),
            b"\r\n".to_vec(),
            b"A".to_vec(),
        ]);
    }

    let length_prefixed = params
        .get("length_prefixed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let delimiter = parse_delimiter(params.get("delimiter"));

    Ok(ProtocolModel {
        name,
        dictionary,
        length_prefixed,
        delimiter,
        endian: ModelEndian::Big,
        checksum: ModelChecksum::Auto,
        messages: Vec::new(),
        length_width: None,
        sequences: Vec::new(),
        desocket: None,
    })
}

fn dict_entry_to_bytes(v: &JsonValue) -> Option<Vec<u8>> {
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
        JsonValue::Number(n) => {
            // single byte value
            let b = (*n as u64).min(255) as u8;
            Some(vec![b])
        }
        _ => None,
    }
}

fn parse_delimiter(v: Option<&JsonValue>) -> Option<u8> {
    match v {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Number(n)) => Some((*n as u64).min(255) as u8),
        Some(JsonValue::String(s)) => {
            if s.is_empty() {
                None
            } else if s == "\n" || s == "\r\n" || s == "lf" {
                Some(b'\n')
            } else if s == "\r" || s == "cr" {
                Some(b'\r')
            } else {
                s.bytes().next()
            }
        }
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
    use crate::scripting::json::{self, JsonValue};

    #[test]
    fn parse_simple_dictionary() {
        let params = json::obj(vec![
            ("name", json::s("ftp-py")),
            (
                "dictionary",
                JsonValue::Array(vec![json::s("USER"), json::s("PASS"), json::s("\r\n")]),
            ),
            ("delimiter", json::n(10.0)),
        ]);
        let m = model_from_params(&params).unwrap();
        assert_eq!(m.name, "ftp-py");
        assert!(m.dictionary.iter().any(|d| d == b"USER"));
        assert_eq!(m.delimiter, Some(b'\n'));
    }

    #[test]
    fn parse_productions() {
        let prod = json::obj(vec![
            ("name", json::s("cmd")),
            (
                "tokens",
                JsonValue::Array(vec![json::s("RETR"), json::s("STOR")]),
            ),
            ("suffix", json::s("\r\n")),
        ]);
        let params = json::obj(vec![
            ("name", json::s("g")),
            ("productions", JsonValue::Array(vec![prod])),
        ]);
        let m = model_from_params(&params).unwrap();
        assert!(m.dictionary.iter().any(|d| d == b"RETR"));
        assert!(m.dictionary.iter().any(|d| d == b"\r\n"));
    }

    #[test]
    fn bridge_register_unregister() {
        let b = ProtocolBridge::new();
        assert!(!b.is_active());
        b.register(ProtocolModel::ftp());
        assert!(b.is_active());
        assert_eq!(b.name(), "ftp");
        b.unregister();
        assert!(!b.is_active());
    }
}
