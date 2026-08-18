//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::integrity_bridge
//!
//! Description
//! -----------
//! Push-style bridge that lets a Python client select the integrity-repair
//! strategy used by workers after every mutation. The strategy is stored by
//! name; workers resolve it to a concrete IntegrityRepair implementation and
//! call prepare_for_send() on the hot path. No reverse-RPC is performed – the
//! only shared state is the strategy name itself.
//!
//! Core responsibilities
//! ---------------------
//! - Hold the currently active strategy name behind AtomicBool + RwLock.
//! - Expose register / unregister / strategy / name / repairer helpers.
//! - Validate strategy names against the known resolver set
//!   (validate_strategy) so the RPC layer can reject invalid input early.
//! - Produce a Box<dyn IntegrityRepair> on demand so workers can cache the
//!   concrete repairer and only re-resolve when the name changes.
//!
//! Single-owner repair model
//! -------------------------
//! - Exactly one repair path is active at any time:
//!     1. If IntegrityBridge is active → bridge.repairer().prepare_for_send()
//!     2. Else if cfg.repair_integrity → native integrity::prepare_for_send
//!     3. Else no repair (Mutator internal repair is disabled in production).
//! - This eliminates double-repair and keeps framing / checksum ownership
//!   unambiguous even when Python is steering the campaign.
//!
//! Worker pickup semantics
//! -----------------------
//! - Workers cache the last seen strategy string.
//! - On each iteration they compare against integrity_bridge.strategy();
//!   if different they re-resolve the repairer and update the cache.
//! - Registration therefore takes effect on the next worker cycle – live,
//!   with no restart required.
//!
//! Concurrency model
//! -----------------
//! - active: AtomicBool (Relaxed).
//! - strategy: RwLock<Option<String>>; register/unregister take the write
//!   lock, strategy() takes the read lock and clones.
//! - Safe for concurrent register from the RPC thread and reads from many
//!   worker threads.
//!
//! Supported strategies (validate_strategy)
//! ----------------------------------------
//! null | none | default | http | https | ftp | smtp | binary | bin |
//! binary-le | bin-le
//!
//! Unknown names are rejected at the RPC boundary with a clear error.
//!
//! Design notes
//! ------------
//! - The bridge never owns protocol-specific knowledge; it only stores a
//!   name that resolve_integrity understands.
//! - Zero reverse-RPC keeps the repair path as cheap as the native path.
//! - Future strategies can be added solely in the plugin layer without
//!   changing this bridge.
//!
//! See Also
//! --------
//! - handler.rs              : register_integrity / integrity_status commands
//! - plugin/integrity.rs     : resolve_integrity and IntegrityRepair trait
//! - execution/worker.rs     : apply_integrity helper that consumes this bridge
//! - input/integrity.rs      : native prepare_for_send fallback

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
