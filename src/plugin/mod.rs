//! NEXSIZ – Plugin architecture
//! Author  : Revana
//! Date    : 05/08/2026
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
