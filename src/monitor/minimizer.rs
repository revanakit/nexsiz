//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 04/08/2026
//! Module  : nexsiz::src::monitor::minimizer
//!
//! Test Case Minimizer Module
//!
//! Provides delta-debugging capabilities for reducing crashing or interesting test cases
//! to their minimal reproducible form through iterative re-execution and feedback.
//!
//! Purpose
//! This module implements a multi-stage minimization strategy designed to identify the
//! smallest subset of messages and fields within a test case that reproduces the original
//! execution outcome (crash, hang, or error state). Minimization is essential for:
//! - Reducing test case complexity for analysis
//! - Enabling faster reproduction and root-cause identification
//! - Generating concise bug reports with minimal noise
//!
//! Algorithm Overview
//! The minimization process operates in four sequential stages:
//!
//! 1. Message Removal (Tail): Iteratively removes messages from the end until
//!    no further reduction maintains the crash/hang condition.
//!
//! 2. Message Removal (Head): Iteratively removes messages from the beginning,
//!    allowing earlier messages to be pruned while preserving state.
//!
//! 3. Field Data Truncation: For Binary and Payload field types, performs binary
//!    search-like reduction by halving field data size until a minimum threshold (16 bytes)
//!    is reached.
//!
//! 4. Protected Field Removal: Removes non-protected fields from messages in reverse
//!    order, respecting the `protected` flag on individual fields to preserve critical
//!    protocol elements.
//!
//! Performance Considerations
//! - Each candidate mutation triggers a full re-execution callback
//! - Early termination occurs when a mutation no longer reproduces the interesting behavior
//! - Metadata (depth, parent, id) is preserved from the original test case
//!
//! Usage Example
//! 
//! let minimized = minimize(
//!     &original_test_case,
//!     &original_execution_result,
//!     |tc| executor.run(tc), // Re-execution callback
//! )?;

use crate::common::error::Result;
use crate::common::types::*;

/// Attempt to minimize a crashing / interesting test case by repeatedly
/// reducing it and re-executing the candidate.
pub fn minimize<F>(
    original: &TestCase,
    original_result: &ExecutionResult,
    mut reexec: F,
) -> Result<TestCase>
where
    F: FnMut(&TestCase) -> Result<ExecutionResult>,
{
    let want_crash = original_result.crash
        || original_result.outcome == OutcomeClass::Crash
        || original_result.outcome == OutcomeClass::ConnectionReset;
    let want_hang =
        original_result.hang || original_result.outcome == OutcomeClass::Hang;

    let is_interesting = |r: &ExecutionResult| -> bool {
        (want_crash
            && (r.crash
                || r.outcome == OutcomeClass::Crash
                || r.outcome == OutcomeClass::ConnectionReset
                || r.error.is_some()))
            || (want_hang && (r.hang || r.outcome == OutcomeClass::Hang))
    };

    let mut current = original.clone();

    while current.messages.len() > 1 {
        let mut candidate = current.clone();
        candidate.messages.pop();
        match reexec(&candidate) {
            Ok(r) if is_interesting(&r) => current = candidate,
            _ => break,
        }
    }

    while current.messages.len() > 1 {
        let mut candidate = current.clone();
        candidate.messages.remove(0);
        match reexec(&candidate) {
            Ok(r) if is_interesting(&r) => current = candidate,
            _ => break,
        }
    }

    for msg_idx in 0..current.messages.len() {
        let field_count = current.messages[msg_idx].fields.len();
        for field_idx in 0..field_count {
            let ftype = current.messages[msg_idx].fields[field_idx].ftype.clone();
            if ftype != FieldType::Binary && ftype != FieldType::Payload {
                continue;
            }
            loop {
                let len = current.messages[msg_idx].fields[field_idx].data.len();
                if len <= 16 {
                    break;
                }
                let mut candidate = current.clone();
                candidate.messages[msg_idx].fields[field_idx]
                    .data
                    .truncate(len / 2);
                match reexec(&candidate) {
                    Ok(r) if is_interesting(&r) => current = candidate,
                    _ => break,
                }
            }
        }
    }

    for msg_idx in 0..current.messages.len() {
        loop {
            let fields = &current.messages[msg_idx].fields;
            if fields.len() <= 1 {
                break;
            }
            let drop_idx = match fields.iter().rposition(|f| !f.protected) {
                Some(i) => i,
                None => break,
            };
            let mut candidate = current.clone();
            candidate.messages[msg_idx].fields.remove(drop_idx);
            match reexec(&candidate) {
                Ok(r) if is_interesting(&r) => current = candidate,
                _ => break,
            }
        }
    }

    current.depth = original.depth;
    current.parent = original.parent;
    current.id = original.id;
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::types::{Field, FieldType, Message, OutcomeClass, TestCase};
    use std::time::Duration;

    fn make_tc(n_msgs: usize) -> TestCase {
        let mut messages = Vec::new();
        for i in 0..n_msgs {
            let mut m = Message::new(format!("m{}", i));
            m.add_field(Field::new(
                "p",
                FieldType::Binary,
                vec![i as u8; 32],
            ));
            messages.push(m);
        }
        TestCase::new(1, messages)
    }

    fn crash_result() -> ExecutionResult {
        ExecutionResult {
            seed_id: 1,
            success: false,
            responses: vec![],
            response_codes: vec![],
            elapsed: Duration::from_millis(1),
            new_coverage: false,
            new_state: false,
            crash: true,
            hang: false,
            error: Some("reset".into()),
            state_hash: 0xdead,
            outcome: OutcomeClass::Crash,
        }
    }

    #[test]
    fn minimize_with_mock_reexec_keeps_crash() {
        let original = make_tc(3);
        let result = crash_result();
        // Mock: any non-empty test case still "crashes"
        let reexec = |tc: &TestCase| -> Result<ExecutionResult> {
            if tc.messages.is_empty() {
                Ok(ExecutionResult {
                    seed_id: tc.id,
                    success: true,
                    responses: vec![],
                    response_codes: vec![],
                    elapsed: Duration::from_millis(1),
                    new_coverage: false,
                    new_state: false,
                    crash: false,
                    hang: false,
                    error: None,
                    state_hash: 0,
                    outcome: OutcomeClass::Ok,
                })
            } else {
                Ok(crash_result())
            }
        };
        let min = minimize(&original, &result, reexec).unwrap();
        assert!(min.messages.len() <= original.messages.len());
        assert!(!min.messages.is_empty());
    }
}
