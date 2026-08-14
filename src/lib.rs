//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Module  : nexsiz::src::lib
//!
//! Architecture follows the four-layer design:
//!   1. Input Construction Layer   - semantic token sequences + hierarchical mutators
//!   2. State Awareness & Feedback - hybrid black/grey-box state model + adaptive prediction
//!   3. Execution & Efficiency     - intelligent connection reuse + parallel workers
//!   4. Monitoring, Oracle & Analysis - crash/hang detection, minimization, structured logging
//!
//! Plus a trait-based plugin layer for Protocol / Integrity / Oracle / Encryptor
//! and a CoverageProvider layer for true grey-box instrumentation hooks.
//! Plus an out-of-process RPC campaign control surface for Python scripting.
//! Plus NXS existence-script integration (meta writer + non-blocking spawn).
//! Plus a platform abstraction layer for multi-OS support (Windows, Linux, ...).
//! Minimal external dependencies (libc for robust signal handling only).

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

pub mod common;
pub mod input;
pub mod state;
pub mod execution;
pub mod monitor;
pub mod plugin;
pub mod coverage;
pub mod scripting;
pub mod nxs;
pub mod platform;

pub use common::config::Config;
pub use common::error::{NexsizError, Result};
pub use common::types::*;
pub use plugin::PluginRegistry;
pub use coverage::{CoverageProvider, CoverageFeedback, resolve_coverage};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Tool banner (consistent with README)
pub const BANNER: &str = r#"
   _  _______  ______________    
  / |/ / __/ |/_/ __/  _/_  /    
 /    / _/_>  <_\ \_/ /  / /_    
/_/|_/___/_/|_/___/___/ /___/    

        Nexsiz v0.1.0
  Stateful Network Protocol Fuzzer
  Semantic • Adaptive • High-Throughput
  Grey-box Instrumentation Ready
"#;
