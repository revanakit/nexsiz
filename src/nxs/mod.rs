//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 09/08/2026
//! Module  : nexsiz::src::nxs::mod
//!
//! NXS integration layer — meta JSON writer + non-blocking existence-script spawn
//! + asynchronous exit-code observation.
//!
//! Opt-in via `--nxs` / `NEXSIZ_NXS`. When disabled the module is never entered and
//! the engine retains zero behavioural change.
//!
//! Contract: nxs/CONTRACT.md
//!
//! Architecture (modular, pure stdlib):
//!   meta    — hand-rolled JSON matching the forward-compatible schema
//!   resolve — categories.toml + search-path priority → executable paths
//!   spawn   — non-blocking `Command::spawn` (returns Child)
//!   reaper  — background thread that observes exit codes & records secondary findings
//!   rate    — per-crash cooldown + per-event / total caps

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
