//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 08/08/2026
//! Files   : nexsiz/src/plugin/mod.rs
//!
//! NEXSIZ – Plugin architecture
//! 
//! Minimal trait-based plugin system for extensibility without changing
//! default behaviour. Plugins are selected by name via Config / CLI.

pub mod protocol;
pub mod integrity;
pub mod oracle;
pub mod encryptor;
pub mod crypto;
pub mod pipeline;
pub mod registry;

pub use protocol::{ProtocolPlugin, BuiltinProtocol};
pub use integrity::{IntegrityRepair, DefaultIntegrityRepair};
pub use oracle::{
    OraclePlugin, DefaultOracleSet, DifferentialOracle, SanitizerOracle, DiffSanOracle,
    ExpandedOracle, resolve_oracle,
};
pub use encryptor::{Encryptor, NullEncryptor};
pub use pipeline::{
    StreamCipher, Stage, PipelineEncryptor, CryptoProfile,
    builtin_profile, parse_pipeline_expr, resolve_pipeline,
};
pub use registry::PluginRegistry;
