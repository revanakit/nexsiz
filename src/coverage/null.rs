//!
//! Author : Revana
//! Date   : 12/08/2026
//! Module : nexsiz::src::coverage::null
//!
//! Null Coverage Provider
//! ----------------------
//! A minimal, zero-overhead implementation of the CoverageProvider trait that
//! intentionally provides no runtime coverage or execution feedback. This
//! provider preserves classic black-box fuzzing semantics by always returning
//! an empty CoverageFeedback and performing no instrumentation or state
//! mutation.
//!
//! Intended use cases:
//! - Baseline performance or throughput measurements where any feedback would
//!   bias results.
//! - Targets or environments where instrumentation is unavailable or
//!   impractical (e.g., closed-source binaries, remote services).
//! - Reproducing legacy black-box fuzzing workflows for comparison against
//!   feedback-driven strategies.
//!
//! Behaviour and guarantees:
//! - collect(&ExecutionResult) => CoverageFeedback::none()
//! - reset() is a no-op.
//! - name() returns the static identifier "null".
//! - Stateless and thread-safe: the provider holds no internal state and has
//!   negligible runtime cost.
//!
//! Implementation notes:
//! - Keep this provider selectable at runtime to enable direct comparisons
//!   between feedback-driven and pure black-box fuzzing modes.
//! - Any additional telemetry or logging should be implemented externally; the
//!   provider itself must remain a strict no-op for coverage collection.

use crate::common::types::ExecutionResult;
use crate::coverage::provider::{CoverageFeedback, CoverageProvider};

/// Default provider – zero overhead, preserves classic black-box behaviour.
#[derive(Debug, Default)]
pub struct NullCoverage;

impl CoverageProvider for NullCoverage {
    fn name(&self) -> &str {
        "null"
    }

    fn reset(&self) {}

    fn collect(&self, _result: &ExecutionResult) -> CoverageFeedback {
        CoverageFeedback::none()
    }
}
