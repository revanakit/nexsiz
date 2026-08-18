//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::encryptor_bridge
//!
//! Description
//! -----------
//! Push-style bridge that lets a Python client select the encryptor used by
//! workers and optionally supply key material. The name and key are stored;
//! workers resolve them to a concrete Encryptor via resolve_encryptor_with_key
//! at encrypt time. No reverse-RPC is performed on the hot path.
//!
//! Core responsibilities
//! ---------------------
//! - Hold the currently active encryptor name and optional key behind
//!   AtomicBool + RwLock pairs.
//! - Expose register / unregister / encryptor_name / key_material /
//!   display_name / encryptor helpers.
//! - Validate encryptor names against the known resolver set
//!   (validate_encryptor_name) so the RPC layer can reject invalid input early.
//! - Produce a Box<dyn Encryptor> on demand so workers can cache the concrete
//!   instance and only re-resolve when the name changes.
//!
//! Worker pickup semantics
//! -----------------------
//! - Workers cache the last seen encryptor name.
//! - On each iteration they compare against encryptor_bridge.encryptor_name();
//!   if different they re-resolve via encryptor() and update the cache.
//! - Registration therefore takes effect on the next worker cycle – live,
//!   with no restart required.
//! - When the bridge is inactive workers fall back to the native encryptor
//!   configured at campaign start (cfg.plugins.encryptor + enc_key).
//!
//! Concurrency model
//! -----------------
//! - active: AtomicBool (Relaxed).
//! - name / key: separate RwLocks; register/unregister take both write locks.
//! - Safe for concurrent register from the RPC thread and reads from many
//!   worker threads.
//!
//! Supported encryptors (validate_encryptor_name)
//! ----------------------------------------------
//! null | none | xor | chacha20 | chacha | chacha20-poly1305 | aead |
//! chacha-poly | tls-record | tls | tls-handshake | tls-alert |
//! chacha20+tls | chacha+tls | chacha20-poly1305+tls | aead+tls |
//! xor+tls | xor+tls-record
//!
//! Unknown names are rejected at the RPC boundary with a clear error.
//!
//! Design notes
//! ------------
//! - Zero reverse-RPC keeps the encrypt path as cheap as the native path.
//! - Key material is stored as an opaque string; interpretation is left to
//!   the concrete Encryptor implementation (hex, raw, etc.).
//! - The bridge never owns protocol-specific knowledge; it only stores a
//!   name that resolve_encryptor_with_key understands.
//!
//! See Also
//! --------
//! - handler.rs              : register_encryptor / encryptor_status commands
//! - plugin/encryptor.rs     : resolve_encryptor_with_key and Encryptor trait
//! - execution/worker.rs     : encryptor resolve + encrypt path that consumes
//!                             this bridge

use crate::plugin::encryptor::{resolve_encryptor_with_key, Encryptor};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

pub struct EncryptorBridge {
    active: AtomicBool,
    name: RwLock<Option<String>>,
    key: RwLock<Option<String>>,
}

impl EncryptorBridge {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            name: RwLock::new(None),
            key: RwLock::new(None),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn register(&self, name: String, key: Option<String>) {
        {
            *self.name.write().unwrap() = Some(name);
            *self.key.write().unwrap() = key;
        }
        self.active.store(true, Ordering::Relaxed);
    }

    pub fn unregister(&self) {
        self.active.store(false, Ordering::Relaxed);
        *self.name.write().unwrap() = None;
        *self.key.write().unwrap() = None;
    }

    pub fn encryptor_name(&self) -> Option<String> {
        if !self.is_active() {
            return None;
        }
        self.name.read().unwrap().clone()
    }

    pub fn key_material(&self) -> Option<String> {
        if !self.is_active() {
            return None;
        }
        self.key.read().unwrap().clone()
    }

    pub fn display_name(&self) -> String {
        self.encryptor_name()
            .unwrap_or_else(|| "none".into())
    }

    /// Build a concrete encryptor from the registered name/key (if any).
    pub fn encryptor(&self) -> Option<Box<dyn Encryptor>> {
        let name = self.encryptor_name()?;
        let key = self.key_material();
        Some(resolve_encryptor_with_key(
            Some(&name),
            key.as_deref(),
        ))
    }
}

impl Default for EncryptorBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate encryptor name against known resolvers.
pub fn validate_encryptor_name(name: &str) -> Result<String, String> {
    let n = name.to_lowercase();
    match n.as_str() {
        "null" | "none" | "xor" | "chacha20" | "chacha" | "chacha20-poly1305"
        | "aead" | "chacha-poly" | "tls-record" | "tls" | "tls-handshake"
        | "tls-alert" | "chacha20+tls" | "chacha+tls" | "chacha20-poly1305+tls"
        | "aead+tls" | "xor+tls" | "xor+tls-record" => Ok(n),
        other => Err(format!(
            "unknown encryptor '{}'; use null|xor|chacha20|chacha20-poly1305|tls-record|chacha20+tls|xor+tls|…",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_xor() {
        let b = EncryptorBridge::new();
        b.register("xor".into(), Some("secret".into()));
        assert!(b.is_active());
        assert_eq!(b.display_name(), "xor");
        let e = b.encryptor().unwrap();
        assert_eq!(e.name(), "xor");
    }

    #[test]
    fn validate() {
        assert!(validate_encryptor_name("ChaCha20").is_ok());
        assert!(validate_encryptor_name("bogus").is_err());
    }
}
