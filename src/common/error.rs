//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Files   : nexsiz/src/common/error.rs
//!
//! Centralized error handling for Nexsiz.
//! All public APIs return `Result<T>` using this error type.

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
