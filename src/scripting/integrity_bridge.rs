//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 06/08/2026
//! Files   : nexsiz/src/scripting/integrity_bridge.rs
//!
//! Python Integrity repair bridge (push strategy)
//! Python selects a repair strategy by name. Workers apply
//! resolve_integrity(strategy).prepare_for_send() after mutation.
//! Zero reverse-RPC on the hot path.

use crate::plugin::integrity::{resolve_integrity, IntegrityRepair};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

pub struct IntegrityBridge {
    active: AtomicBool,
    strategy: RwLock<Option<String>>,
}

impl IntegrityBridge {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            strategy: RwLock::new(None),
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    pub fn register(&self, strategy: String) {
        {
            let mut slot = self.strategy.write().unwrap();
            *slot = Some(strategy);
        }
        self.active.store(true, Ordering::Relaxed);
    }

    pub fn unregister(&self) {
        self.active.store(false, Ordering::Relaxed);
        *self.strategy.write().unwrap() = None;
    }

    pub fn strategy(&self) -> Option<String> {
        if !self.is_active() {
            return None;
        }
        self.strategy.read().unwrap().clone()
    }

    pub fn name(&self) -> String {
        self.strategy()
            .unwrap_or_else(|| "none".into())
    }

    /// Build a concrete repairer from the registered strategy (if any).
    pub fn repairer(&self) -> Option<Box<dyn IntegrityRepair>> {
        self.strategy()
            .map(|s| resolve_integrity(Some(&s)))
    }
}

impl Default for IntegrityBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate strategy name against known resolvers.
pub fn validate_strategy(name: &str) -> Result<String, String> {
    let n = name.to_lowercase();
    match n.as_str() {
        "null" | "none" | "default" | "http" | "https" | "ftp" | "smtp"
        | "binary" | "bin" | "binary-le" | "bin-le" => Ok(n),
        other => Err(format!(
            "unknown integrity strategy '{}'; use null|default|http|ftp|smtp|binary|binary-le",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_repairer() {
        let b = IntegrityBridge::new();
        assert!(!b.is_active());
        b.register("http".into());
        assert!(b.is_active());
        assert_eq!(b.name(), "http");
        let r = b.repairer().unwrap();
        assert_eq!(r.name(), "http");
        b.unregister();
        assert!(!b.is_active());
    }

    #[test]
    fn validate() {
        assert!(validate_strategy("HTTP").is_ok());
        assert!(validate_strategy("nope").is_err());
    }
}
