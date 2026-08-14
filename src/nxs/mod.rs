//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 09/08/2026
//! Module  : nexsiz::src::nxs::mod
//!
//! NXS integration layer — meta JSON writer + non-blocking existence-script spawn
//!
//! Purpose
//! - Integration layer that bridges the fuzzing engine with external NXS (next-stage)
//!   analysis binaries. Coordinates metadata emission, NXS discovery/resolution,
//!   non-blocking process spawn, and asynchronous exit-code observation.
//!
//! Responsibilities
//! - Produce a compact JSON metadata file for each classified engine event (see nxs/CONTRACT.md §3).
//! - Resolve configured NXS specifications (search path + categories) into executable commands.
//! - Enforce configurable rate limits and deduplication to avoid flooding downstream tools.
//! - Spawn resolved NXS processes non-blocking and hand Child handles to a background reaper
//!   that observes exit codes without blocking the fuzzer hot path.
//! - Record secondary findings (exit-code → classification) as reported by the reaper.
//!
//! Activation & configuration
//! - Opt-in via CLI flag `--nxs` or environment variable `NEXSIZ_NXS`.
//! - Controlled by `cfg.nxs.*` settings (enabled, events list, cooldown_secs, max_per_event, max_total).
//! - Uses `cfg.target` and `cfg.output_dir` to render per-event and per-NXS output directories.
//!
//! Behavior & semantics
//! - Called from engine::handle_result after an event is classified:
//!     1) Write {output_dir}/nxs-meta/{event}_{id}.json using meta::write_meta.
//!     2) Resolve the set of NXS specs for the event via resolve::resolve_nxs_list.
//!     3) Rate-check each spec (rate::check_and_record) and skip/stop according to decision.
//!     4) For allowed specs, perform a non-blocking spawn (spawn::spawn_nxs) and submit the Child to
//!        reaper::submit for asynchronous exit-code handling.
//! - Exit code 2 from an NXS child is treated as a secondary finding by the reaper.
//! - Writer omits optional/empty fields to remain forward-compatible with newer schema versions.
//!
//! Error handling & observability
//! - I/O and resolution failures are logged to stderr with contextual messages and do not panic the engine.
//! - Verbose mode (`cfg.verbose`) emits rate-limit, spawn, and reaper handoff diagnostics.
//!
//! Concurrency & safety
//! - This module does not perform inter-process synchronization; callers must avoid concurrent writes
//!   to the same output paths or provide external locking where necessary.
//! - Spawning is non-blocking; the reaper runs independently to avoid impacting fuzzing throughput.
//!
//! Rate limiting & deduplication
//! - Per-event and global caps are applied, plus a per-spec cooldown window to prevent repeated invocations.
//! - When per-event cap is reached the loop breaks; when global cap is reached the function returns early.
//!
//! Testing recommendations
//! - Unit-test outcome mapping (outcome_str) across ExecutionResult permutations.
//! - Integration tests that simulate resolution failures, spawn failures, and verify reaper handoff.
//! - Parse produced JSON with a robust JSON parser in tests to assert valid output and proper escaping.
//!
//! Contract & references
//! - Canonical schema and expectations: nxs/CONTRACT.md (authoritative).
//! - See meta.rs, resolve.rs, spawn.rs, reaper.rs, and rate.rs for implementation details.

pub mod meta;
pub mod rate;
pub mod reaper;
pub mod resolve;
pub mod spawn;

pub use meta::{write_meta, MetaContext};
pub use reaper::secondary_count;
pub use resolve::{list_resolved, resolve_nxs_list, NxsSpec};
pub use spawn::spawn_nxs;

use crate::common::config::Config;
use crate::common::types::ExecutionResult;
use std::time::Duration;

/// Entry point called from `engine::handle_result` after an event is classified.
///
/// - Writes `{output}/nxs-meta/{event}_{id}.json`
/// - Resolves the configured NXS set for the event
/// - Rate-limits / dedups (Phase 4)
/// - Spawns each allowed binary non-blocking with the contract CLI
/// - Hands the Child to the async reaper so exit codes are observed without
///   blocking the fuzzer hot-path. Exit 2 → secondary finding.
pub fn on_event(
    cfg: &Config,
    event: &str,
    result: &ExecutionResult,
    crash_path: Option<&str>,
    minimized_path: Option<&str>,
    model: Option<&str>,
) {
    if !cfg.nxs.enabled {
        return;
    }
    if !cfg.nxs.events.iter().any(|e| e == event) {
        return;
    }

    let id = format!("id:{:06}_hash:{:016x}", result.seed_id, result.state_hash);
    let meta_dir = format!("{}/nxs-meta", cfg.output_dir);
    let meta_path = format!("{}/{}_{}.json", meta_dir, event, id.replace(':', "_"));

    let ctx = MetaContext {
        nexsiz_version: crate::VERSION,
        event,
        target_host: &cfg.target.host.to_string(),
        target_port: cfg.target.port,
        target_protocol: &cfg.target.protocol,
        model: model.unwrap_or("generic"),
        crash_id: &id,
        crash_path: crash_path.unwrap_or(""),
        minimized_path: minimized_path.unwrap_or(""),
        input_len: 0,
        outcome: outcome_str(result),
        error: result.error.as_deref(),
        elapsed_ms: result.elapsed.as_millis() as u64,
        coverage_hits: result.coverage_hits as u64,
        new_state: result.new_state,
        response_codes: &result.response_codes,
        corpus_id: result.seed_id,
        output_dir: &cfg.output_dir,
    };

    if let Err(e) = write_meta(&meta_path, &ctx) {
        eprintln!("[nexsiz/nxs] meta write failed: {}", e);
        return;
    }

    let specs = match resolve_nxs_list(cfg, event) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[nexsiz/nxs] resolve failed: {}", e);
            return;
        }
    };

    if specs.is_empty() {
        return;
    }

    let target_str = format!("{}:{}", cfg.target.host, cfg.target.port);
    // Per-NXS output directory is further specialised by the reaper / caller if needed;
    // base path is shared for the event.
    let out_base = format!("{}/nxs-out/{}_{}", cfg.output_dir, event, id.replace(':', "_"));
    let cooldown = Duration::from_secs(cfg.nxs.cooldown_secs);

    for spec in specs {
        match rate::check_and_record(
            event,
            &id,
            &spec.id,
            cooldown,
            cfg.nxs.max_per_event,
            cfg.nxs.max_total,
        ) {
            rate::RateDecision::Allow => {}
            rate::RateDecision::DenyCooldown => {
                if cfg.verbose {
                    eprintln!(
                        "[nexsiz/nxs] rate-limit cooldown: {} for {}",
                        spec.id, id
                    );
                }
                continue;
            }
            rate::RateDecision::DenyPerEventCap => {
                if cfg.verbose {
                    eprintln!(
                        "[nexsiz/nxs] rate-limit per-event cap: {} ({})",
                        event, cfg.nxs.max_per_event
                    );
                }
                break;
            }
            rate::RateDecision::DenyTotalCap => {
                if cfg.verbose {
                    eprintln!(
                        "[nexsiz/nxs] rate-limit total cap ({})",
                        cfg.nxs.max_total
                    );
                }
                return;
            }
        }

        // Per-NXS artefact directory keeps concurrent runs from colliding.
        let out_dir = format!("{}/{}", out_base, spec.id.replace('/', "_"));

        match spawn_nxs(
            &spec,
            crash_path,
            minimized_path,
            Some(&meta_path),
            &target_str,
            event,
            model,
            Some(&out_dir),
            cfg.verbose,
        ) {
            Ok(child) => {
                // Hand off to async reaper — hot path stays non-blocking.
                reaper::submit(
                    &spec.id,
                    event,
                    &id,
                    Some(&out_dir),
                    &cfg.output_dir,
                    child,
                );
                if cfg.verbose {
                    eprintln!("[nexsiz/nxs] spawned {} for {} (async exit observation)", spec.id, event);
                }
            }
            Err(e) => {
                eprintln!("[nexsiz/nxs] spawn {} failed: {}", spec.id, e);
            }
        }
    }
}

fn outcome_str(r: &ExecutionResult) -> &'static str {
    use crate::common::types::OutcomeClass;
    match r.outcome {
        OutcomeClass::Crash => "crash",
        OutcomeClass::Hang => "hang",
        OutcomeClass::ConnectionReset => "connection_reset",
        OutcomeClass::Error => "error",
        OutcomeClass::Ok => {
            if r.crash {
                "crash"
            } else if r.hang {
                "hang"
            } else if r.new_coverage || r.coverage_hits > 0 {
                "new_coverage"
            } else if r.new_state {
                "new_state"
            } else {
                "interesting"
            }
        }
    }
}
