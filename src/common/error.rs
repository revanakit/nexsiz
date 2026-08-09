//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 09/08/2026
//! Files   : nexsiz::src::common::error
//!
//! Centralized error type and related helpers used throughout the fuzzer.
//! This module defines `NexsizError`, an exhaustive enum encapsulating both
//! infrastructure errors (e.g. I/O) and domain-specific failure modes
//! (configuration, protocol handling, mutation, execution, state machine,
//! seed validation, timeouts, and connection termination).
//!
//! Key responsibilities:
//! - Provide a single, typed error representation so public APIs return
//!   `Result<T, NexsizError>` (`pub type Result<T> = std::result::Result<T, NexsizError>`).
//! - Preserve underlying causes where applicable (currently `Io(io::Error)`)
//!   so error chaining via `std::error::Error::source()` is available for diagnostics.
//! - Offer clear `Display` messages for logging and human-readable diagnostics,
//!   and a `From<io::Error>` conversion for convenient propagation.
//!
//! Usage guidance:
//! - Map lower-level errors into the most specific `NexsizError` variant to allow
//!   callers to match and recover where appropriate (e.g., treat `Timeout` and
//!   `ConnectionClosed` differently from `Protocol` or `Internal` errors).
//! - When extending this enum, prefer informative String payloads for context
//!   and update `Display`/`source()` implementations to maintain useful diagnostics.
//!
//! Note for contributors: keep variant responsibilities orthogonal (protocol vs state
//! vs execution) to simplify error handling, metrics, and log analysis.

use std::fmt;
use std::io;

/// Unified error type for the entire fuzzer.
#[derive(Debug)]
pub enum NexsizError {
    Io(io::Error),
    Config(String),
    Protocol(String),
    Mutation(String),
    Execution(String),
    State(String),
    Timeout,
    ConnectionClosed,
    InvalidSeed(String),
    Internal(String),
}

impl fmt::Display for NexsizError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NexsizError::Io(e) => write!(f, "I/O error: {}", e),
            NexsizError::Config(msg) => write!(f, "Configuration error: {}", msg),
            NexsizError::Protocol(msg) => write!(f, "Protocol error: {}", msg),
            NexsizError::Mutation(msg) => write!(f, "Mutation error: {}", msg),
            NexsizError::Execution(msg) => write!(f, "Execution error: {}", msg),
            NexsizError::State(msg) => write!(f, "State error: {}", msg),
            NexsizError::Timeout => write!(f, "Operation timed out"),
            NexsizError::ConnectionClosed => write!(f, "Connection closed by peer"),
            NexsizError::InvalidSeed(msg) => write!(f, "Invalid seed: {}", msg),
            NexsizError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for NexsizError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NexsizError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for NexsizError {
    fn from(e: io::Error) -> Self {
        NexsizError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, NexsizError>;
