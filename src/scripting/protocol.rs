//! RPC protocol constants and helpers.
//! Author  : Revana
//! Date    : 06/08/2026

pub const PROTOCOL_VERSION: u32 = 1;

pub const METHODS: &[&str] = &[
    "ping",
    "version",
    "stats",
    "stop",
    "load_seeds",
    "add_seed_raw",
    "add_seed_structured",
    "export_corpus",
    "set_oracle",
    "set_model",
    "set_integrity",
    "set_encryptor",
    "get_config",
    "list_methods",
    "register_oracle",
    "unregister_oracle",
    "oracle_status",
    "register_protocol",
    "unregister_protocol",
    "protocol_status",
    "get_protocol",
    "register_integrity",
    "unregister_integrity",
    "integrity_status",
    "register_encryptor",
    "unregister_encryptor",
    "encryptor_status",
    "register_mutator",
    "unregister_mutator",
    "mutator_status",
];
