//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Module  : nexsiz::src::coverage::provider
//!
//! Coverage provider abstraction and related types.
//!
//! This module defines the CoverageProvider trait and the CoverageFeedback
//! struct which represent the engine-facing contract for collecting and
//! reporting runtime coverage information produced by target executions.
//!
//! Key responsibilities:
//! - Define a small, stable lifecycle for providers: `reset()` → run target →
//!   `collect(&ExecutionResult)`.
//! - Provide an implementation-agnostic feedback object (`CoverageFeedback`)
//!   describing new/total edges, a compact map hash, and whether the input was
//!   "interesting" (i.e., produced new coverage).
//! - Expose optional hooks for advanced backends: `map_snapshot()` for raw
//!   bitmap inspection and `total_edges()` for provider-local cardinality.
//!
//! Notes and guarantees:
//! - The canonical bitmap size used by map-style providers is MAP_SIZE (64 KiB)
//!   to keep parity with classic AFL-style instrumentation.
//! - Implementers must be Send + Sync; providers are expected to be safe for
//!   concurrent use by the fuzzing engine and should document any internal
//!   synchronization or state mutation semantics.
//! - Default implementations return empty/zero responses (no-op semantics) so
//!   simple or remote-backed providers can opt-in to functionality selectively.
//!
//! Implementation guidance:
//! - Providers that interact with external agents (e.g., frida, shared memory,
//!   or out-of-process collectors) should keep IPC and serialization overhead
//!   minimal in the hot path and perform heavier merging or bookkeeping
//!   asynchronously when possible.
//! - Keep `collect()` idempotent per execution and ensure any global seen-edge
//!   tracking is consistent across threads/processes if used for scheduling.

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
