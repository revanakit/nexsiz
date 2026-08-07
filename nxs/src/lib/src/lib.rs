//! nxs-lib — shared foundation for every NXS (official + custom).
//!
//! Guarantees the CLI / exit-code / meta-JSON contract defined in
//! `nxs/CONTRACT.md`. All official existence scripts depend on this crate.
//!
//! Design goals:
//! - Forward-compatible meta (unknown fields ignored)
//! - Zero-copy friendly where practical
//! - Deterministic exit codes
//! - Minimal surface, maximum reuse

pub mod args;
pub mod exit;
pub mod meta;
pub mod report;

pub use args::Args;
pub use exit::ExitCode;
pub use meta::Meta;
pub use report::Report;
