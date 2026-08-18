//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::scripting::mod
//!
//! Description
//! -----------
//! Root of the NEXSIZ Python scripting / RPC campaign-control surface.
//! Provides an out-of-process control plane over a Unix-domain socket so an
//! operator (or Python client) can steer a live fuzzing campaign: inject
//! seeds, swap protocol models, attach a live is_interesting oracle, change
//! integrity/encryptor strategies, and push mutator dictionary extras – all
//! without recompilation or process restart.
//!
//! Submodule map
//! -------------
//! protocol          – PROTOCOL_VERSION + authoritative METHODS catalogue
//! json              – pure-stdlib JSON parse/stringify for the control plane
//! server            – UnixListener accept loop + oracle-mode reverse-RPC
//! handler           – RpcContext + command dispatch for every METHODS entry
//! oracle_bridge     – reverse-RPC is_interesting path + BridgedOracle
//! protocol_bridge   – push ProtocolModel store + BridgedProtocol
//! integrity_bridge  – push integrity strategy name + repairer factory
//! encryptor_bridge  – push encryptor name/key + encryptor factory
//! mutator_bridge    – push extra dictionary tokens + generation counter
//! seed_parse        – structured JSON seed → TestCase conversion
//!
//! Public re-exports
//! -----------------
//! The Engine and other crates interact with this module primarily through:
//! - RpcServer          (server)         – owned by Engine for campaign lifetime
//! - RpcContext         (handler)        – shared state handed to the server
//! - OracleBridge / BridgedOracle
//! - ProtocolBridge / BridgedProtocol
//! - IntegrityBridge / EncryptorBridge / MutatorBridge
//!
//! Activation
//! ----------
//! Enabled when -Y / --rpc-sock or NEXSIZ_RPC_SOCK is set. On non-Unix
//! platforms RpcServer::start returns an explicit error; the rest of the
//! fuzzer remains fully usable without the control plane.
//!
//! Design invariants
//! -----------------
//! - Hot path (mutate → repair → encrypt → send) never performs reverse-RPC
//!   except for the optional oracle is_interesting query (bounded timeout).
//! - All live plugin injection is push-style (name / model / dictionary);
//!   workers re-resolve on the next cycle via generation or name comparison.
//! - Zero behaviour change when the RPC socket is not configured.
//!
//! See Also
//! --------
//! - execution/engine.rs  : owns RpcServer and wires the bridges
//! - readme.txt           : operator-facing one-paragraph summary

pub mod protocol;
pub mod json;
pub mod server;
pub mod handler;
pub mod oracle_bridge;
pub mod protocol_bridge;
pub mod integrity_bridge;
pub mod encryptor_bridge;
pub mod mutator_bridge;
pub mod seed_parse;

pub use server::RpcServer;
pub use handler::RpcContext;
pub use oracle_bridge::{BridgedOracle, OracleBridge};
pub use protocol_bridge::{BridgedProtocol, ProtocolBridge};
pub use integrity_bridge::IntegrityBridge;
pub use encryptor_bridge::EncryptorBridge;
pub use mutator_bridge::MutatorBridge;
