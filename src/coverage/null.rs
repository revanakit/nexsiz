//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Files   : nexsiz/src/coverage/null.rs
//!
//! NEXSIZ – Null coverage provider (pure black-box)

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
