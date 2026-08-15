//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! AUTHOR     ::     Revana 
//! MODULE     ::     src::execution::libafl_runner
//!
//! Purpose:
//!   Provides LibAFL campaign wiring and a single-core runner for NEXSIZ.
//!   This module constructs observers, feedbacks, state, executor, and
//!   mutational stages, loads seed corpus files, and drives the LibAFL
//!   fuzzing loop (with optional execution/time limits).
//!
//! Primary responsibilities:
//!   - Construct a process-lifetime response StdMapObserver and ensure it is
//!     shared (moved) consistently between feedbacks and the executor so that
//!     MaxMapFeedback resolves the observer by name correctly.
//!   - Initialize StdState (StdRand, in-memory corpus, on-disk crash corpus),
//!     wiring feedbacks and objective correctly to the state.
//!   - Build NexsizNetworkExecutor using build_executor_with_observer so the
//!     same StdMapObserver instance is owned by the executor (LibAFL 0.15
//!     requirement — see compatibility notes).
//!   - Load seed inputs from the configured seed directory into the fuzzer as
//!     BytesInput values, guaranteeing that at least one seed is present.
//!   - Create a protocol-aware NexsizHierarchicalMutator and expose it via a
//!     StdMutationalStage for the mutational pipeline.
//!   - Run the fuzz loop (fuzz_loop / fuzz_loop_for) honoring configuration
//!     options for max executions or max runtime.
//!
//! Key functions:
//!   - run_libafl_campaign(cfg: &Config) -> Result<()>:
//!       Top-level entry that performs directory sanity checks and then
//!       delegates to the single-core runner. Emits a notice when configured
//!       workers > 1 because multi-core LLMP is temporarily disabled.
//!   - run_single_core(cfg: &Config) -> Result<()>:
//!       Implements the full LibAFL single-core setup described above and
//!       executes the fuzzer loop.
//!
//! Important implementation & compatibility notes (LibAFL 0.15):
//!   - Observer tuple shape: libafl uses nested tuples for observers; this
//!     module uses tuple_list!(observer) producing (Obs, ()) as expected.
//!   - StdMapObserver & MaxMapFeedback: MaxMapFeedback records the observer
//!     by name (e.g., "response_map") and later resolves it inside the
//!     executor's observer list. The StdMapObserver instance passed to
//!     MaxMapFeedback::new MUST be the same instance that is moved into the
//!     executor — passing a different/detached observer will result in an
//!     unwrap panic at evaluation time.
//!   - Multi-core LLMP: multi-worker LLMP support is deferred; when cfg
//!     requests workers > 1, the runner currently falls back to single-core
//!     execution and prints an informational notice for reliability.
//!
//! Robustness and error handling:
//!   - OnDiskCorpus creation errors are converted into NexsizError::Config to
//!     provide clearer diagnostics at startup.
//!   - Seed-loading is defensive: only regular files are read and empty files
//!     are ignored. If no seeds are loaded, a default seed ("NEXSIZ\r\n") is
//!     inserted to ensure the fuzz loop can start.
//!
//! Observability & diagnostics:
//!   - The runner uses SimpleMonitor / SimpleEventManager and prints succinct
//!     status lines indicating target host:port, protocol, and corpus size.
//!
//! See also:
//!   - crate::execution::libafl_exec for executor/observer construction and
//!     behavioural response-map folding.
//!   - crate::execution::libafl_mutator for hierarchical/protocol-aware
//!     mutation logic used in the mutational stage.
//!   - crate::common::config and crate::common::error for configuration and
//!     error mapping conventions used here.

use crate::common::config::Config;
use crate::common::error::{NexsizError, Result};
use crate::execution::libafl_exec::{build_executor_with_observer, make_response_observer};
use crate::execution::libafl_mutator::NexsizHierarchicalMutator;
use libafl::corpus::{Corpus, InMemoryCorpus, OnDiskCorpus};
use libafl::events::SimpleEventManager;
use libafl::feedbacks::{CrashFeedback, MaxMapFeedback};
use libafl::fuzzer::{Evaluator, Fuzzer, StdFuzzer};
use libafl::inputs::BytesInput;
use libafl::monitors::SimpleMonitor;
use libafl::schedulers::QueueScheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, StdState};
use libafl_bolts::rands::StdRand;
use libafl_bolts::tuples::tuple_list;
use std::path::PathBuf;

fn protocol_name(cfg: &Config) -> String {
    cfg.protocol_plugin_name()
        .unwrap_or("generic")
        .to_string()
}

pub fn run_libafl_campaign(cfg: &Config) -> Result<()> {
    cfg.ensure_dirs()?;
    if cfg.execution.workers > 1 {
        println!(
            "[nexsiz-libafl] note: multi-core LLMP temporarily disabled; running single-core (workers={})",
            cfg.execution.workers
        );
    }
    run_single_core(cfg)
}

fn run_single_core(cfg: &Config) -> Result<()> {
    let mon = SimpleMonitor::new(|s| {
        println!("[nexsiz-libafl] {}", s);
    });
    let mut mgr = SimpleEventManager::new(mon);

    // 1. Observer first — must outlive feedback construction, then move into executor.
    let edges_observer = make_response_observer();

    // 2. Feedback bound to observer name "response_map".
    let mut feedback = MaxMapFeedback::new(&edges_observer);
    let mut objective = CrashFeedback::new();

    // 3. State initialises feedback metadata from the observer.
    let mut state = StdState::new(
        StdRand::with_seed(cfg.rng_seed.unwrap_or(0xdead_beef)),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from(format!("{}/crashes", cfg.output_dir))).map_err(|e| {
            NexsizError::Config(format!("OnDiskCorpus: {}", e))
        })?,
        &mut feedback,
        &mut objective,
    )
    .map_err(|e| NexsizError::Config(format!("StdState: {}", e)))?;

    // 4. Move the SAME observer into the executor so feedback lookup succeeds.
    let mut executor = build_executor_with_observer(cfg.target.clone(), edges_observer);

    let seed_dir = PathBuf::from(&cfg.seed_dir);

    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Manually load seed files as BytesInput
    if seed_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&seed_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Ok(data) = std::fs::read(&path) {
                    if data.is_empty() {
                        continue;
                    }
                    let input = BytesInput::new(data);
                    let _ = fuzzer.add_input(&mut state, &mut executor, &mut mgr, input);
                }
            }
        }
    }

    // Ensure at least one seed so the loop never starts empty
    if state.corpus().is_empty() {
        let _ = fuzzer.add_input(
            &mut state,
            &mut executor,
            &mut mgr,
            BytesInput::new(b"NEXSIZ\r\n".to_vec()),
        );
    }

    let proto = protocol_name(cfg);
    let hierarchical = NexsizHierarchicalMutator::from_protocol(
        cfg.rng_seed.unwrap_or(0xdead_beef),
        &proto,
    );
    let mut stages = tuple_list!(StdMutationalStage::new(hierarchical));

    println!(
        "[nexsiz-libafl] single-core | target {}:{} | protocol {} | corpus={}",
        cfg.target.host,
        cfg.target.port,
        proto,
        state.corpus().count()
    );

    if let Some(max) = cfg.max_execs {
        let _ = fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, max);
    } else if let Some(rt) = cfg.max_runtime {
        let approx = (rt.as_secs().max(1) * 200) as u64;
        let _ = fuzzer.fuzz_loop_for(&mut stages, &mut executor, &mut state, &mut mgr, approx);
    } else {
        let _ = fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr);
    }

    Ok(())
}
