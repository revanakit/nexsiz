//! NEXSIZ – Oracle core (interestingness decision)
//! Author  : Revana
//! Date    : 05/08/2026
//!
//! Base oracles used by the plugin layer. Additional differential and
//! sanitizer oracles live in `src/plugin/oracle.rs` and are composed here
//! or selected by name.

use crate::common::types::ExecutionResult;

/// Trait for any component that decides whether an execution is interesting.
pub trait Oracle: Send + Sync {
    fn name(&self) -> &str;
    fn is_interesting(&self, result: &ExecutionResult) -> bool;
}

// ── Primitive oracles ────────────────────────────────────────────────────────

pub struct CrashOracle;
impl Oracle for CrashOracle {
    fn name(&self) -> &str {
        "crash"
    }
    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        result.crash
            || matches!(
                result.outcome,
                crate::common::types::OutcomeClass::Crash
                    | crate::common::types::OutcomeClass::ConnectionReset
            )
    }
}

pub struct HangOracle;
impl Oracle for HangOracle {
    fn name(&self) -> &str {
        "hang"
    }
    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        result.hang || matches!(result.outcome, crate::common::types::OutcomeClass::Hang)
    }
}

pub struct CoverageOracle;
impl Oracle for CoverageOracle {
    fn name(&self) -> &str {
        "coverage"
    }
    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        result.new_coverage || result.new_state || result.coverage_hits > 0
    }
}

/// Flags any non-Ok outcome or explicit error string.
pub struct ErrorOracle;
impl Oracle for ErrorOracle {
    fn name(&self) -> &str {
        "error"
    }
    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        result.error.is_some()
            || matches!(
                result.outcome,
                crate::common::types::OutcomeClass::Error
                    | crate::common::types::OutcomeClass::Crash
                    | crate::common::types::OutcomeClass::ConnectionReset
                    | crate::common::types::OutcomeClass::Hang
            )
    }
}

// ── Composite ────────────────────────────────────────────────────────────────

/// Composite oracle that returns true if any sub-oracle fires.
pub struct CompositeOracle {
    oracles: Vec<Box<dyn Oracle>>,
    name: String,
}

impl CompositeOracle {
    pub fn new(name: impl Into<String>, oracles: Vec<Box<dyn Oracle>>) -> Self {
        Self {
            name: name.into(),
            oracles,
        }
    }

    /// Classic default set used by the original engine.
    pub fn default_set() -> Self {
        Self::new(
            "composite-default",
            vec![
                Box::new(CrashOracle),
                Box::new(HangOracle),
                Box::new(CoverageOracle),
            ],
        )
    }

    /// Evaluate all sub-oracles (any-match).
    pub fn evaluate(&self, result: &ExecutionResult) -> bool {
        self.oracles.iter().any(|o| o.is_interesting(result))
    }

    pub fn oracles(&self) -> &[Box<dyn Oracle>] {
        &self.oracles
    }
}

impl Oracle for CompositeOracle {
    fn name(&self) -> &str {
        &self.name
    }
    fn is_interesting(&self, result: &ExecutionResult) -> bool {
        self.evaluate(result)
    }
}
