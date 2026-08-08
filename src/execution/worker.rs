//! NEXSIZ – Worker threads with rarity-guided energy, encryptor pipeline
//! grey-box coverage, single repair ownership, MutatorBridge dict merge
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Repair ownership (exactly one stage, live-safe):
//!   1. IntegrityBridge active  → bridge.repairer().prepare_for_send()
//!   2. else cfg.repair_integrity → integrity::prepare_for_send(model_name)
//!   3. else none
//! Mutator internal repair is always OFF in production workers.
//!
//! Protocol Phase 3: template_prob / on_interesting field energy.
//! Snapshot/Desocket Phase 2: ProtocolReset + SocketState via ReusePolicy.
//! Snapshot/Desocket Phase 3: restore_epoch orchestration, cost-aware energy,
//!   desocket/restore counters.
//! Snapshot/Desocket Phase 4: resolve_desocket_from_model (JSON SpecDesocket).

use crate::common::config::Config;
use crate::common::types::*;
use crate::common::utils::XorShift64;
use crate::coverage::CoverageProvider;
use crate::execution::connector::{execute_tcp, execute_udp, TcpConnector, UdpConnector};
use crate::execution::desocket::{resolve_desocket_from_model, reset_or_reconnect, ProtocolReset};
use crate::execution::reuse::ReusePolicy;
use crate::input::corpus::SharedCorpus;
use crate::input::integrity;
use crate::input::mutator::Mutator;
use crate::input::model::ProtocolModel;
use crate::plugin::encryptor::{resolve_encryptor_with_key, Encryptor};
use crate::plugin::integrity::IntegrityRepair;
use crate::scripting::encryptor_bridge::EncryptorBridge;
use crate::scripting::integrity_bridge::IntegrityBridge;
use crate::scripting::mutator_bridge::MutatorBridge;
use crate::state::predictor::StatePredictor;
use crate::state::tracker::StateTracker;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub struct SharedStats {
    pub execs: AtomicU64,
    pub crashes: AtomicU64,
    pub hangs: AtomicU64,
    pub new_paths: AtomicU64,
    pub new_states: AtomicU64,
    /// Snapshot restore count (Phase 3).
    pub restores: AtomicU64,
    /// Successful protocol-level desocket resets (Phase 3).
    pub desockets: AtomicU64,
    /// Monotonic epoch bumped by Engine after every successful restore.
    /// Workers observe this to force post-restore reconnect.
    pub restore_epoch: AtomicU64,
}

impl SharedStats {
    pub fn new() -> Self {
        Self {
            execs: AtomicU64::new(0),
            crashes: AtomicU64::new(0),
            hangs: AtomicU64::new(0),
            new_paths: AtomicU64::new(0),
            new_states: AtomicU64::new(0),
            restores: AtomicU64::new(0),
            desockets: AtomicU64::new(0),
            restore_epoch: AtomicU64::new(0),
        }
    }
}

pub fn spawn_workers(
    cfg: &Config,
    corpus: SharedCorpus,
    tracker: Arc<StateTracker>,
    predictor: Arc<StatePredictor>,
    stats: Arc<SharedStats>,
    result_tx: Sender<ExecutionResult>,
    stop: Arc<AtomicBool>,
    model: ProtocolModel,
    coverage: Arc<dyn CoverageProvider>,
    integrity_bridge: Arc<IntegrityBridge>,
    encryptor_bridge: Arc<EncryptorBridge>,
    mutator_bridge: Arc<MutatorBridge>,
) -> Vec<thread::JoinHandle<()>> {
    let mut handles = Vec::new();
    let encryptor_name = cfg.plugins.encryptor.clone();
    let enc_key = cfg.enc_key.clone();

    for worker_id in 0..cfg.execution.workers {
        let corpus = Arc::clone(&corpus);
        let tracker = Arc::clone(&tracker);
        let predictor = Arc::clone(&predictor);
        let stats = Arc::clone(&stats);
        let result_tx = result_tx.clone();
        let stop = Arc::clone(&stop);
        let model = model.clone();
        let coverage = Arc::clone(&coverage);
        let target = cfg.target.clone();
        let mutator_cfg = cfg.mutator.clone();
        let exec_cfg = cfg.execution.clone();
        let enc_name = encryptor_name.clone();
        let key = enc_key.clone();
        let integrity_bridge = Arc::clone(&integrity_bridge);
        let encryptor_bridge = Arc::clone(&encryptor_bridge);
        let mutator_bridge = Arc::clone(&mutator_bridge);
        let rng_seed =
            cfg.rng_seed.unwrap_or(0) ^ (worker_id as u64).wrapping_mul(0x9e3779b97f4a7c15);

        let handle = thread::Builder::new()
            .name(format!("nexsiz-worker-{}", worker_id))
            .spawn(move || {
                worker_main(
                    worker_id,
                    corpus,
                    tracker,
                    predictor,
                    stats,
                    result_tx,
                    stop,
                    model,
                    target,
                    mutator_cfg,
                    exec_cfg,
                    rng_seed,
                    enc_name,
                    key,
                    coverage,
                    integrity_bridge,
                    encryptor_bridge,
                    mutator_bridge,
                );
            })
            .expect("failed to spawn worker");
        handles.push(handle);
    }

    handles
}

fn worker_main(
    _id: usize,
    corpus: SharedCorpus,
    tracker: Arc<StateTracker>,
    predictor: Arc<StatePredictor>,
    stats: Arc<SharedStats>,
    result_tx: Sender<ExecutionResult>,
    stop: Arc<AtomicBool>,
    model: ProtocolModel,
    target: crate::common::config::TargetConfig,
    mutator_cfg: crate::common::config::MutatorConfig,
    exec_cfg: crate::common::config::ExecutionConfig,
    rng_seed: u64,
    encryptor_name: Option<String>,
    enc_key: Option<String>,
    coverage: Arc<dyn CoverageProvider>,
    integrity_bridge: Arc<IntegrityBridge>,
    encryptor_bridge: Arc<EncryptorBridge>,
    mutator_bridge: Arc<MutatorBridge>,
) {
    let mut rng = XorShift64::new(rng_seed);
    let model_name = model.name.clone();
    let cfg_repair = mutator_cfg.repair_integrity;

    // Resolve desocket before moving model into Mutator.
    let desocket: Box<dyn ProtocolReset> = resolve_desocket_from_model(&model);

    let mut mutator = Mutator::new(
        rng_seed ^ 0xdeadbeef,
        model,
        mutator_cfg.max_mutations,
        mutator_cfg.hierarchical_prob,
        mutator_cfg.field_prob,
        mutator_cfg.dict_prob,
        false,
    )
    .with_template_prob(mutator_cfg.template_prob);

    let mut fallback_encryptor: Box<dyn Encryptor> =
        resolve_encryptor_with_key(encryptor_name.as_deref(), enc_key.as_deref());
    let mut cached_bridge_enc_name: Option<String> = None;
    let mut bridge_encryptor: Option<Box<dyn Encryptor>> = None;

    let mut cached_integrity_strategy: Option<String> = None;
    let mut bridge_repairer: Option<Box<dyn IntegrityRepair>> = None;

    let mut last_mutator_gen: u64 = 0;
    /// Phase 3: last observed restore epoch
    let mut local_restore_epoch: u64 = 0;

    let is_udp = target.protocol == "udp";
    let mut tcp_connector = TcpConnector::new(target.socket_addr(), target.timeout);
    let mut udp_connector = UdpConnector::new(target.socket_addr(), target.timeout);
    let mut reuse = ReusePolicy::new(target.max_reuse_messages, exec_cfg.max_reuse_failures);
    let mut prev_state: Option<u64> = None;

    while !stop.load(Ordering::Relaxed) {
        // --- Phase 3: post-restore orchestration ---
        let epoch = stats.restore_epoch.load(Ordering::Relaxed);
        if epoch != local_restore_epoch {
            local_restore_epoch = epoch;
            // Force all workers off any stale connection after process restore
            tcp_connector.close();
            reuse.force_reset();
        }

        let gen = mutator_bridge.generation();
        if gen != last_mutator_gen {
            last_mutator_gen = gen;
            let extra = mutator_bridge.dictionary();
            if !extra.is_empty() {
                mutator.extend_dictionary(&extra);
            }
        }

        let parent = match corpus.schedule(&mut rng) {
            Some(p) => p,
            None => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
        };

        let child_id = corpus.next_id();
        let mut child = mutator.mutate(&parent, child_id);

        apply_integrity(
            &mut child,
            &integrity_bridge,
            &mut cached_integrity_strategy,
            &mut bridge_repairer,
            cfg_repair,
            &model_name,
        );

        if encryptor_bridge.is_active() {
            let name = encryptor_bridge.encryptor_name();
            if name != cached_bridge_enc_name {
                cached_bridge_enc_name = name;
                bridge_encryptor = encryptor_bridge.encryptor();
            }
            if let Some(ref e) = bridge_encryptor {
                e.encrypt(&mut child);
            } else {
                fallback_encryptor.encrypt(&mut child);
            }
        } else {
            fallback_encryptor.encrypt(&mut child);
        }

        coverage.reset();

        // Track whether this iteration paid a desocket or full-reconnect cost
        let mut paid_desocket = false;
        let mut paid_reconnect = false;

        // --- Connection decision (Phase 2/3 desocket-aware) ---
        let do_reuse = if is_udp {
            false
        } else if !exec_cfg.connection_reuse {
            false
        } else if reuse.should_reuse() {
            true
        } else if reuse.needs_desocket() && desocket.is_enabled() {
            match reset_or_reconnect(desocket.as_ref(), &mut tcp_connector) {
                Ok(()) => {
                    if tcp_connector.is_connected() {
                        reuse.on_desocket_ok();
                        paid_desocket = true;
                        stats.desockets.fetch_add(1, Ordering::Relaxed);
                        true
                    } else {
                        reuse.on_desocket_fallback();
                        paid_reconnect = true;
                        false
                    }
                }
                Err(_) => {
                    reuse.on_desocket_fallback();
                    paid_reconnect = true;
                    false
                }
            }
        } else {
            false
        };

        if !is_udp && !do_reuse {
            reuse.on_reconnect();
            paid_reconnect = true;
            let _ = tcp_connector.connect();
        }

        let mut result = if is_udp {
            match execute_udp(&mut udp_connector, &child, 4096) {
                Ok(r) => r,
                Err(e) => {
                    let r = error_result(child.id, e.to_string());
                    let _ = result_tx.send(r);
                    continue;
                }
            }
        } else {
            match execute_tcp(&mut tcp_connector, &child, do_reuse, 4096) {
                Ok(r) => r,
                Err(e) => {
                    let r = error_result(child.id, e.to_string());
                    reuse.update(&r);
                    let _ = result_tx.send(r);
                    continue;
                }
            }
        };

        if !is_udp {
            reuse.update(&result);
        }

        let cov_fb = coverage.collect(&result);
        result.coverage_hits = cov_fb.new_edges;
        result.coverage_map_hash = cov_fb.map_hash;

        let (new_state, new_edge) = tracker.observe(&result, prev_state, Some(&cov_fb));
        result.new_state = new_state;
        result.new_coverage = new_edge || cov_fb.interesting;

        if let Some(prev) = prev_state {
            predictor.observe(prev, result.state_hash);
            let rarity = predictor.rarity(prev, result.state_hash);
            corpus.apply_rarity_boost(parent.id, rarity);
            if result.is_interesting() {
                corpus.apply_rarity_boost(child.id, rarity);
            }
        }
        prev_state = Some(result.state_hash);

        if result.is_interesting() {
            mutator.on_interesting();
        }

        stats.execs.fetch_add(1, Ordering::Relaxed);
        if result.crash {
            stats.crashes.fetch_add(1, Ordering::Relaxed);
        }
        if result.hang {
            stats.hangs.fetch_add(1, Ordering::Relaxed);
        }
        if result.new_coverage {
            stats.new_paths.fetch_add(1, Ordering::Relaxed);
        }
        if result.new_state {
            stats.new_states.fetch_add(1, Ordering::Relaxed);
        }

        if result.is_interesting() {
            let mut interesting_child = child;
            interesting_child.interesting = true;
            interesting_child.last_state = Some(result.state_hash);
            if let Some(prev) = prev_state {
                let rarity = predictor.rarity(prev, result.state_hash);
                interesting_child.energy *= 1.0 + (1.0 - rarity) * 1.5;
            }
            if cov_fb.new_edges > 0 {
                interesting_child.energy *= 1.0 + (cov_fb.new_edges as f64 * 0.15);
            }
            // Phase 3 cost-aware energy: cases that survived after paying
            // desocket/reconnect cost are slightly more valuable to re-explore.
            if paid_desocket {
                interesting_child.energy *= 1.12;
            } else if paid_reconnect {
                interesting_child.energy *= 1.06;
            }
            let _ = corpus.add_if_new(interesting_child);
            corpus.mark_interesting(result.seed_id, Some(result.state_hash));
        }

        let _ = result_tx.send(result);
    }
}

fn apply_integrity(
    child: &mut TestCase,
    integrity_bridge: &IntegrityBridge,
    cached_strategy: &mut Option<String>,
    bridge_repairer: &mut Option<Box<dyn IntegrityRepair>>,
    cfg_repair: bool,
    model_name: &str,
) {
    if integrity_bridge.is_active() {
        let strat = integrity_bridge.strategy();
        if strat != *cached_strategy {
            *cached_strategy = strat.clone();
            *bridge_repairer = integrity_bridge.repairer();
        }
        if let Some(ref r) = bridge_repairer {
            r.prepare_for_send(child);
        }
        return;
    }
    if cached_strategy.is_some() {
        *cached_strategy = None;
        *bridge_repairer = None;
    }
    if cfg_repair {
        integrity::prepare_for_send(child, model_name);
    }
}

fn error_result(seed_id: SeedId, err: String) -> ExecutionResult {
    ExecutionResult {
        seed_id,
        success: false,
        responses: vec![],
        response_codes: vec![],
        elapsed: Duration::from_millis(0),
        new_coverage: false,
        new_state: false,
        crash: false,
        hang: false,
        error: Some(err),
        state_hash: 0,
        outcome: OutcomeClass::Error,
        coverage_hits: 0,
        coverage_map_hash: 0,
    }
}
