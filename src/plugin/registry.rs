//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 08/08/2026
//! Files   : nexsiz/src/plugin/registry.rs
//!
//! NEXSIZ – Plugin registry
//! 

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
