//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::plugin::registry
//!
//! Purpose
//! -------
//! Central registry and resolver for nexSIZ plugin components. This module
//! provides a small, ergonomic facade to construct a consistent set of runtime
//! plugins used by the fuzzing pipeline: protocol model providers, integrity
//! repair heuristics, interestingness oracles, and encryptors.
//!
//! Key responsibilities
//! --------------------
//! - Resolve plugin implementations by human-friendly names or file paths.
//! - Provide convenience constructors that wire together protocol-specific
//!   defaults (e.g., auto-selecting an integrity repair strategy for FTP).
//! - Offer a single PluginRegistry struct that bundles selected plugins for
//!   use by executor and mutator subsystems.
//! - Expose helpers to obtain the active ProtocolModel and a compact textual
//!   summary for logging and telemetry.
//!
//! Design & behavior notes
//! -----------------------
//! - Resolution is intentionally forgiving: unknown names fall back to safe
//!   defaults (generic protocol, default integrity, null encryptor) and
//!   non-fatal warnings are emitted when external models fail to load.
//! - The registry does not own long-running state; plugin instances are boxed
//!   trait objects appropriate for sharing across worker threads.
//! - Integrity resolution can be influenced by the chosen protocol — a
//!   convenient auto-selection helps operators avoid mismatched integrity
//!   strategies for well-known protocols.
//!
//! Threading & safety
//! ------------------
//! - PluginRegistry contains boxed trait objects (Send + Sync implementations
//!   are required by the plugin traits) and is safe to construct on the main
//!   thread and share immutable references with worker threads.
//!
//! Operational notes
//! -----------------
//! - Use PluginRegistry::from_names or from_names_with_key to create a set of
//!   plugins from CLI-style names; resolve_pipeline and resolve_protocol are
//!   used under the hood to map names to concrete implementations.
//! - Call protocol_model() to obtain a fresh ProtocolModel instance suitable
//!   for feeding into mutator and testcase generation logic.
//! - summary() returns a compact single-line descriptor useful for start-up
//!   logs and reproducibility metadata.
//!
//! Testing
//! -------
//! - The module contains unit tests validating default fallbacks, protocol-led
//!   integrity selection, explicit overrides, and encryptor name resolution.

use crate::plugin::encryptor::{resolve_encryptor_with_key, Encryptor};
use crate::plugin::integrity::{resolve_integrity_for_protocol, IntegrityRepair};
use crate::plugin::oracle::resolve_oracle;
use crate::plugin::protocol::{resolve_protocol, ProtocolPlugin};
use crate::monitor::oracle::Oracle;
use crate::input::model::ProtocolModel;

pub struct PluginRegistry {
    pub protocol: Box<dyn ProtocolPlugin>,
    pub integrity: Box<dyn IntegrityRepair>,
    pub oracle: Box<dyn Oracle>,
    pub encryptor: Box<dyn Encryptor>,
}

impl PluginRegistry {
    pub fn from_names(
        protocol: Option<&str>,
        integrity: Option<&str>,
        oracle: Option<&str>,
        encryptor: Option<&str>,
    ) -> Self {
        Self::from_names_with_key(protocol, integrity, oracle, encryptor, None)
    }

    pub fn from_names_with_key(
        protocol: Option<&str>,
        integrity: Option<&str>,
        oracle: Option<&str>,
        encryptor: Option<&str>,
        enc_key: Option<&str>,
    ) -> Self {
        let protocol_plugin = resolve_protocol(protocol);
        let integrity_plugin =
            resolve_integrity_for_protocol(integrity, Some(protocol_plugin.name()));

        Self {
            protocol: protocol_plugin,
            integrity: integrity_plugin,
            oracle: resolve_oracle(oracle),
            encryptor: resolve_encryptor_with_key(encryptor, enc_key),
        }
    }

    pub fn default_set() -> Self {
        Self::from_names(None, None, None, None)
    }

    pub fn protocol_model(&self) -> ProtocolModel {
        self.protocol.build_model()
    }

    pub fn summary(&self) -> String {
        format!(
            "protocol={} integrity={} oracle={} encryptor={}",
            self.protocol.name(),
            self.integrity.name(),
            self.oracle.name(),
            self.encryptor.name()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry() {
        let r = PluginRegistry::default_set();
        assert_eq!(r.protocol.name(), "generic");
        assert_eq!(r.integrity.name(), "default");
        assert_eq!(r.oracle.name(), "default");
        assert_eq!(r.encryptor.name(), "null");
    }

    #[test]
    fn named_ftp_auto_integrity() {
        let r = PluginRegistry::from_names(Some("ftp"), None, Some("strict"), None);
        assert_eq!(r.protocol.name(), "ftp");
        assert_eq!(r.integrity.name(), "ftp");
        assert_eq!(r.oracle.name(), "strict");
    }

    #[test]
    fn chacha_encryptor() {
        let r = PluginRegistry::from_names_with_key(
            Some("generic"),
            None,
            None,
            Some("chacha20"),
            Some("0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
        );
        assert_eq!(r.encryptor.name(), "chacha20");
    }

    #[test]
    fn explicit_integrity_overrides() {
        let r = PluginRegistry::from_names(Some("http"), Some("null"), None, None);
        assert_eq!(r.integrity.name(), "null");
    }
}
