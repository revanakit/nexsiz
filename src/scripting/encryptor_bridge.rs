//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Files   : nexsiz/src/scripting/encryptor_bridge.rs
//!
//! Python selects an encryptor by name and optional key material.
//! Workers resolve via resolve_encryptor_with_key at encrypt time.
//! Zero reverse-RPC on the hot path.

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
