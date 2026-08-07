//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Files   : nexsiz/src/coverage/provider.rs
//!
//! NEXSIZ – CoverageProvider trait

use crate::common::types::ExecutionResult;

/// Classic AFL-style map size (64 KiB).
pub const MAP_SIZE: usize = 1 << 16;

/// Feedback collected from one execution.
#[derive(Debug, Clone, Default)]
pub struct CoverageFeedback {
    /// Number of *new* edges discovered in this execution.
    pub new_edges: u32,
    /// Total edges hit in this execution (including previously seen).
    pub hit_edges: u32,
    /// Hash of the current coverage bitmap (for state combining).
    pub map_hash: u64,
    /// Whether any new coverage was observed.
    pub interesting: bool,
}

impl CoverageFeedback {
    pub fn none() -> Self {
        Self::default()
    }
}

/// Trait implemented by every coverage backend.
///
/// Lifecycle per execution:
///   1. `reset()`          – clear ephemeral state before sending input
///   2. (target runs)
///   3. `collect(result)`  – harvest coverage after execution finishes
///
/// Providers that talk to an external agent (Frida, SHM writer, …) implement
/// the same interface; the rest of the engine stays agnostic.
pub trait CoverageProvider: Send + Sync {
    /// Human-readable name ("null", "map", "software", …).
    fn name(&self) -> &str;

    /// Reset per-execution state (bitmap, counters, …).
    fn reset(&self);

    /// Collect coverage after an execution.  May also update the global
    /// seen-edge set inside the provider.
    fn collect(&self, result: &ExecutionResult) -> CoverageFeedback;

    /// Optional: expose the raw current map (for advanced observers).
    fn map_snapshot(&self) -> Option<Vec<u8>> {
        None
    }

    /// Total unique edges ever observed by this provider.
    fn total_edges(&self) -> u64 {
        0
    }
}
