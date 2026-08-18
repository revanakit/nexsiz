//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::protocol
//!
//! Description
//! -----------
//! Canonical constants for the NEXSIZ RPC campaign-control protocol.
//! Defines the protocol version number and the authoritative list of
//! methods that the handler accepts. All other scripting modules treat
//! these values as the single source of truth for version negotiation and
//! method discovery.
//!
//! Core responsibilities
//! ---------------------
//! - Publish PROTOCOL_VERSION so clients can verify compatibility via the
//!   "version" RPC method.
//! - Publish METHODS – the complete, ordered catalogue of supported verbs
//!   used by "list_methods" and by the handler's dispatch table.
//! - Serve as the stable contract surface: adding a new RPC command requires
//!   updating this list and the corresponding arm in handler.rs.
//!
//! Protocol versioning
//! -------------------
//! - PROTOCOL_VERSION is currently 1.
//! - Bump only on breaking changes to request/response shapes or method
//!   semantics. Additive methods do not require a version bump provided
//!   older clients continue to function.
//!
//! Method catalogue (grouped by concern)
//! -------------------------------------
//! Lifecycle / introspection
//!   ping, version, list_methods, stats, stop, get_config
//!
//! Corpus management
//!   load_seeds, add_seed_raw, add_seed_structured, export_corpus
//!
//! Native plugin name recording (non-live)
//!   set_oracle, set_model, set_integrity, set_encryptor
//!
//! Live Python bridges
//!   register_oracle / unregister_oracle / oracle_status
//!   register_protocol / unregister_protocol / protocol_status / get_protocol
//!   register_integrity / unregister_integrity / integrity_status
//!   register_encryptor / unregister_encryptor / encryptor_status
//!   register_mutator / unregister_mutator / mutator_status
//!
//! Design notes
//! ------------
//! - METHODS is a static slice so list_methods can be answered without
//!   allocation beyond the response array itself.
//! - The handler still hard-codes the match arms; this list is the human-
//!   and client-visible contract, not an automatic dispatch table.
//! - Keeping the catalogue here (rather than deriving it from handler)
//!   avoids a circular dependency and makes the surface easy to audit.
//!
//! See Also
//! --------
//! - handler.rs         : dispatch table that implements each method
//! - server.rs          : transport that delivers the JSON lines
//! - json.rs            : request/response serialisation helpers

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
