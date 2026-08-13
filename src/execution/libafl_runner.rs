//! NEXSIZ – LibAFL campaign runner (single-core, 0.15.x)
//! Author  : Revana
//! Date    : 13/08/2026
//!
//! Multi-core LLMP is temporarily deferred until the single-core path is solid.
//! When workers > 1 we still run single-core (with a notice) for reliability.
//!
//! Observer / feedback wiring (LibAFL 0.15):
//!   1. Create StdMapObserver ("response_map")
//!   2. MaxMapFeedback::new(&observer)  — records the name
//!   3. StdState::new(..., &mut feedback, &mut objective)
//!   4. Move the SAME observer into the executor via build_executor_with_observer
//! Feedback then resolves the observer by name inside the executor — no unwrap panic.

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
