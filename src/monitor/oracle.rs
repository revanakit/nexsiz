//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 05/08/2026
//! Module  : nexsiz::src::monitor::oracle
//!
//! NEXSIZ — Oracle core: interestingness decision logic
//!
//! Module responsibilities:
//! - Define the `Oracle` trait used to decide whether an `ExecutionResult`
//!   produced by the execution engine is "interesting" for further analysis,
//!   triage, or corpus minimization.
//! - Provide a set of primitive oracles (Crash, Hang, Coverage, Error) and
//!   a composable `CompositeOracle` to combine multiple criteria.
//!
//! Key guarantees and expectations:
//! - Implementations of `Oracle` must be thread-safe (`Send + Sync`) because
//!   oracles can be evaluated concurrently by the fuzzing/monitoring runtime.
//! - Oracle decisions should be deterministic for a given `ExecutionResult`;
//!   avoid internal mutable state unless externally synchronized.
//! - Keep `is_interesting` evaluations fast and non-blocking — avoid I/O or
//!   expensive computations inside hot paths to prevent runtime stalls.
//!
//! Public API summary:
//! - trait Oracle { fn name(&self) -> &str; fn is_interesting(&self, result: &ExecutionResult) -> bool; }
//! - Primitives: `CrashOracle`, `HangOracle`, `CoverageOracle`, `ErrorOracle`.
//! - `CompositeOracle` supports composition, a `default_set()` matching the
//!   classical crash+hang+coverage policy, and exposes `evaluate()` for callers.
//!
//! Extensibility:
//! - Additional differential and sanitizer-specific oracles live in
//!   `src/plugin/oracle.rs`. Those implementations are intended to be composed
//!   or selected at runtime by name.
//!
//! Implementation notes:
//! - This module relies on fields and the `OutcomeClass` variants from
//!   `crate::common::types::ExecutionResult`. Ensure that those semantics are
//!   preserved when modifying `ExecutionResult` or `OutcomeClass`.
//! - When adding new oracles, prefer pure functions over side effects so the
//!   composition remains predictable and testable.

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
