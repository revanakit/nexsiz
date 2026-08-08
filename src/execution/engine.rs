//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//! Author  : Revana
//! Date    : 08/08/2026
//!
//! Phase 1 Snapshot integration:
//!   Engine owns SnapshotProvider. When snapshot=true the provider
//!   manages target process lifecycle (prepare → take_snapshot →
//!   restore-on-crash). ProcessMonitor is retained only as a legacy
//!   fallback when snapshot is disabled.

use crate::common::config::Config;
use crate::common::error::Result;
use crate::common::types::*;
use crate::common::utils::format_duration;
use crate::coverage::{resolve_coverage_with_shm, CoverageProvider};
use crate::execution::connector::{execute_tcp, execute_udp, TcpConnector, UdpConnector};
use crate::execution::process_monitor::ProcessMonitor;
use crate::execution::snapshot::{resolve_snapshot, SnapshotProvider};
use crate::execution::worker::{spawn_workers, SharedStats};
use crate::input::corpus::{Corpus, SharedCorpus};
use crate::input::model::load_seeds_from_dir;
use crate::monitor::logger::Logger;
use crate::monitor::minimizer;
use crate::monitor::oracle::Oracle;
use crate::plugin::oracle::resolve_oracle;
use crate::plugin::protocol::resolve_protocol;
use crate::plugin::PluginRegistry;
use crate::scripting::encryptor_bridge::EncryptorBridge;
use crate::scripting::handler::RpcContext;
use crate::scripting::integrity_bridge::IntegrityBridge;
use crate::scripting::mutator_bridge::MutatorBridge;
use crate::scripting::oracle_bridge::{BridgedOracle, OracleBridge};
use crate::scripting::protocol_bridge::ProtocolBridge;
use crate::scripting::server::RpcServer;
use crate::state::predictor::StatePredictor;
use crate::state::tracker::StateTracker;
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub struct Engine {
    cfg: Config,
    corpus: SharedCorpus,
    tracker: Arc<StateTracker>,
    predictor: Arc<StatePredictor>,
    stats: Arc<SharedStats>,
    stop: Arc<AtomicBool>,
    logger: Logger,
    /// Legacy process monitor — only populated when snapshot is disabled.
    process_monitor: Option<ProcessMonitor>,
    /// Snapshot / restore provider (Null when disabled).
    snapshot: Box<dyn SnapshotProvider>,
    oracle: Box<dyn Oracle>,
    plugins_summary: String,
    coverage: Arc<dyn CoverageProvider>,
    _rpc: Option<RpcServer>,
    oracle_bridge: Arc<OracleBridge>,
    protocol_bridge: Arc<ProtocolBridge>,
    integrity_bridge: Arc<IntegrityBridge>,
    encryptor_bridge: Arc<EncryptorBridge>,
    mutator_bridge: Arc<MutatorBridge>,
    /// Cached protocol model name for NXS meta.
    model_name: String,
}

impl Engine {
    pub fn new(cfg: Config) -> Result<Self> {
        cfg.ensure_dirs()?;

        let plugins = PluginRegistry::from_names_with_key(
            cfg.protocol_plugin_name(),
            cfg.plugins.integrity.as_deref(),
            cfg.plugins.oracle.as_deref(),
            cfg.plugins.encryptor.as_deref(),
            cfg.enc_key.as_deref(),
        );

        let plugins_summary = plugins.summary();
        let model_name = plugins.protocol.name().to_string();
        let fallback_oracle = resolve_oracle(cfg.plugins.oracle.as_deref());

        let coverage = Arc::from(resolve_coverage_with_shm(
            cfg.coverage.as_deref(),
            cfg.coverage_shm.as_deref(),
        ));

        let corpus = Arc::new(Corpus::new());
        let tracker = Arc::new(StateTracker::new(
            cfg.state.max_states,
            cfg.state.response_weight,
        ));
        let predictor = Arc::new(StatePredictor::new());
        let stats = Arc::new(SharedStats::new());
        let stop = Arc::new(AtomicBool::new(false));
        let logger = Logger::new(&cfg.output_dir, cfg.verbose)?;
        let oracle_bridge = Arc::new(OracleBridge::new());
        let protocol_bridge = Arc::new(ProtocolBridge::new());
        let integrity_bridge = Arc::new(IntegrityBridge::new());
        let encryptor_bridge = Arc::new(EncryptorBridge::new());
        let mutator_bridge = Arc::new(MutatorBridge::new());

        let oracle: Box<dyn Oracle> = Box::new(BridgedOracle::new(
            Arc::clone(&oracle_bridge),
            fallback_oracle,
        ));

        // Snapshot provider takes ownership of process lifecycle when enabled.
        let mut snapshot = resolve_snapshot(
            cfg.execution.snapshot,
            &cfg.execution.snapshot_backend,
            cfg.target.target_cmd.as_deref(),
            &cfg.output_dir,
        );

        // Legacy ProcessMonitor only when snapshot is off (keeps old behaviour).
        let process_monitor = if !cfg.execution.snapshot {
            if let Some(ref cmd) = cfg.target.target_cmd {
                match ProcessMonitor::spawn(cmd) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        eprintln!("Warning: could not spawn target process: {}", e);
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // Eager prepare + first snapshot when enabled.
        if snapshot.is_enabled() {
            if let Err(e) = snapshot.prepare() {
                eprintln!("[nexsiz] warning: snapshot prepare failed: {}", e);
            } else if let Err(e) = snapshot.take_snapshot() {
                eprintln!("[nexsiz] warning: initial take_snapshot failed: {}", e);
            }
        }

        let rpc_path = cfg
            .rpc_sock
            .clone()
            .or_else(|| std::env::var("NEXSIZ_RPC_SOCK").ok())
            .filter(|s| !s.is_empty());

        let mut rpc_server = None;
        if let Some(ref path) = rpc_path {
            let oracle_name = plugins.oracle.name().to_string();
            let model_name_rpc = plugins.protocol.name().to_string();
            let integrity_name = plugins.integrity.name().to_string();
            let encryptor_name = plugins.encryptor.name().to_string();
            let target_summary = format!(
                "{}:{} ({})",
                cfg.target.host, cfg.target.port, cfg.target.protocol
            );

            let ctx = Arc::new(RpcContext {
                corpus: Arc::clone(&corpus),
                stats: Arc::clone(&stats),
                stop: Arc::clone(&stop),
                tracker: Arc::clone(&tracker),
                coverage: Arc::clone(&coverage),
                plugins: Arc::new(Mutex::new(plugins)),
                seed_dir: cfg.seed_dir.clone(),
                output_dir: cfg.output_dir.clone(),
                started: Instant::now(),
                oracle_name: Arc::new(Mutex::new(oracle_name)),
                model_name: Arc::new(Mutex::new(model_name_rpc)),
                integrity_name: Arc::new(Mutex::new(integrity_name)),
                encryptor_name: Arc::new(Mutex::new(encryptor_name)),
                target_summary,
                workers: cfg.execution.workers,
                oracle_bridge: Arc::clone(&oracle_bridge),
                protocol_bridge: Arc::clone(&protocol_bridge),
                integrity_bridge: Arc::clone(&integrity_bridge),
                encryptor_bridge: Arc::clone(&encryptor_bridge),
                mutator_bridge: Arc::clone(&mutator_bridge),
            });

            match RpcServer::start(path, ctx, Arc::clone(&stop)) {
                Ok(srv) => {
                    eprintln!("[nexsiz] RPC campaign control listening on {}", path);
                    rpc_server = Some(srv);
                }
                Err(e) => {
                    eprintln!("[nexsiz] Warning: RPC server failed to start: {}", e);
                }
            }
        }

        Ok(Self {
            cfg,
            corpus,
            tracker,
            predictor,
            stats,
            stop,
            logger,
            process_monitor,
            snapshot,
            oracle,
            plugins_summary,
            coverage,
            _rpc: rpc_server,
            oracle_bridge,
            protocol_bridge,
            integrity_bridge,
            encryptor_bridge,
            mutator_bridge,
            model_name,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        self.logger.info(&format!("Nexsiz v{} starting", crate::VERSION));
        self.logger.info(&format!(
            "Target: {}:{} ({})",
            self.cfg.target.host, self.cfg.target.port, self.cfg.target.protocol
        ));
        self.logger.info(&format!("Plugins: {}", self.plugins_summary));
        self.logger.info(&format!("Coverage provider: {}", self.coverage.name()));
        self.logger.info(&format!("Oracle: {}", self.oracle.name()));
        if self.cfg.nxs.enabled {
            self.logger.info(&format!(
                "NXS enabled: set={} events={:?} (async exit observation active)",
                self.cfg.nxs.set, self.cfg.nxs.events
            ));
        }

        if self.snapshot.is_enabled() {
            self.logger.info(&format!(
                "Snapshot provider: {} (backend={})",
                self.snapshot.name(),
                self.cfg.execution.snapshot_backend
            ));
            if let Some(dir) = self.snapshot.image_dir() {
                self.logger.info(&format!("Snapshot image dir: {}", dir.display()));
            }
        } else if let Some(ref mon) = self.process_monitor {
            self.logger.info(&format!("Process monitor active: {}", mon.cmd()));
        }

        if let Some(ref path) = self.cfg.rpc_sock {
            self.logger.info(&format!("RPC control socket: {}", path));
        }
        self.logger.info(&format!(
            "Workers: {} | Connection reuse: {} | Adaptive state: {}",
            self.cfg.execution.workers,
            self.cfg.execution.connection_reuse,
            self.cfg.state.adaptive_prediction
        ));

        if self.cfg.rpc_sock.is_some() && !self.protocol_bridge.is_active() {
            self.logger.info("Waiting up to 2s for Python register_protocol…");
            for _ in 0..20 {
                if self.protocol_bridge.is_active() || self.stop.load(Ordering::Relaxed) {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }

        let model = if let Some(m) = self.protocol_bridge.model() {
            self.logger.info(&format!(
                "Protocol model: python:{} (dict entries: {})",
                m.name,
                m.dictionary.len()
            ));
            self.model_name = m.name.clone();
            m
        } else {
            let m = resolve_protocol(self.cfg.protocol_plugin_name()).build_model();
            self.logger.info(&format!("Protocol model: {}", m.name));
            self.model_name = m.name.clone();
            m
        };

        if self.integrity_bridge.is_active() {
            self.logger.info(&format!(
                "Integrity strategy (Python): {}",
                self.integrity_bridge.name()
            ));
        }
        if self.encryptor_bridge.is_active() {
            self.logger.info(&format!(
                "Encryptor (Python): {}",
                self.encryptor_bridge.display_name()
            ));
        }
        if self.mutator_bridge.is_active() {
            self.logger.info(&format!(
                "Mutator extras (Python): {} dict tokens",
                self.mutator_bridge.dictionary_len()
            ));
        }

        let seeds = load_seeds_from_dir(&self.cfg.seed_dir, 1)?;
        let added = self.corpus.add_seeds(seeds);
        self.logger.info(&format!("Loaded {} unique seeds", added));

        if added == 0 {
            self.logger.warn("No seeds loaded – using built-in default");
        }

        let (result_tx, result_rx) = channel::<ExecutionResult>();

        let handles = spawn_workers(
            &self.cfg,
            Arc::clone(&self.corpus),
            Arc::clone(&self.tracker),
            Arc::clone(&self.predictor),
            Arc::clone(&self.stats),
            result_tx,
            Arc::clone(&self.stop),
            model,
            Arc::clone(&self.coverage),
            Arc::clone(&self.integrity_bridge),
            Arc::clone(&self.encryptor_bridge),
            Arc::clone(&self.mutator_bridge),
        );

        let start = Instant::now();
        let mut last_status = Instant::now();
        let status_interval = Duration::from_secs(5);

        install_signal_handlers(Arc::clone(&self.stop));

        loop {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(max) = self.cfg.max_execs {
                if self.stats.execs.load(Ordering::Relaxed) >= max {
                    self.logger.info("Reached max_execs limit");
                    break;
                }
            }
            if let Some(max_rt) = self.cfg.max_runtime {
                if start.elapsed() >= max_rt {
                    self.logger.info("Reached max_runtime limit");
                    break;
                }
            }

            // Snapshot path: detect crash → restore
            if self.snapshot.is_enabled() {
                if self.snapshot.crashed() {
                    self.logger.warn(&format!(
                        "Target process crashed (snapshot={}); restoring…",
                        self.snapshot.name()
                    ));
                    self.stats.crashes.fetch_add(1, Ordering::Relaxed);
                    if let Err(e) = self.snapshot.restore() {
                        self.logger.warn(&format!("Snapshot restore failed: {}", e));
                    } else {
                        self.logger.info("Snapshot restore completed");
                    }
                }
            } else if let Some(ref mon) = self.process_monitor {
                if mon.crashed() {
                    self.logger.warn("Target process exited abnormally (crash indicator)");
                    self.stats.crashes.fetch_add(1, Ordering::Relaxed);
                }
            }

            while let Ok(result) = result_rx.try_recv() {
                self.handle_result(&result);
            }

            if last_status.elapsed() >= status_interval {
                self.print_status(start.elapsed());
                last_status = Instant::now();
            }

            thread::sleep(Duration::from_millis(50));
        }

        self.stop.store(true, Ordering::Relaxed);
        self.logger.info("Shutting down workers…");
        for h in handles {
            let _ = h.join();
        }

        while let Ok(result) = result_rx.try_recv() {
            self.handle_result(&result);
        }

        if self.snapshot.is_enabled() {
            self.snapshot.terminate();
        } else if let Some(ref mon) = self.process_monitor {
            mon.terminate();
        }

        // Give the NXS reaper a short window to finish observing late exits.
        if self.cfg.nxs.enabled {
            thread::sleep(Duration::from_millis(800));
        }

        self.print_final_stats(start.elapsed());
        Ok(())
    }

    fn handle_result(&mut self, result: &ExecutionResult) {
        let oracle_interesting = self.oracle.is_interesting(result);
        let is_crash = result.crash
            || result.outcome == OutcomeClass::Crash
            || result.outcome == OutcomeClass::ConnectionReset;
        let is_hang = result.hang || result.outcome == OutcomeClass::Hang;

        let mut crash_path: Option<String> = None;
        let mut minimized_path: Option<String> = None;

        if is_crash {
            self.logger.crash(result);
            let path = format!(
                "{}/crashes/id:{:06}_hash:{:016x}",
                self.cfg.output_dir, result.seed_id, result.state_hash
            );
            if let Some(tc) = self.corpus.get(result.seed_id) {
                let _ = fs::write(&path, tc.serialize());
                crash_path = Some(path.clone());
                let cfg = self.cfg.clone();
                let reexec = |candidate: &TestCase| -> Result<ExecutionResult> {
                    if cfg.target.protocol == "udp" {
                        let mut conn =
                            UdpConnector::new(cfg.target.socket_addr(), cfg.target.timeout);
                        execute_udp(&mut conn, candidate, 4096)
                    } else {
                        let mut conn =
                            TcpConnector::new(cfg.target.socket_addr(), cfg.target.timeout);
                        execute_tcp(&mut conn, candidate, false, 4096)
                    }
                };
                if let Ok(min) = minimizer::minimize(&tc, result, reexec) {
                    let min_path = format!("{}.min", path);
                    let _ = fs::write(&min_path, min.serialize());
                    minimized_path = Some(min_path);
                }
            }

            // After a crash observed via the network path, attempt restore
            // if the snapshot provider is active (covers cases where the
            // process died but ProcessMonitor/CRIU hasn't noticed yet).
            if self.snapshot.is_enabled() {
                if let Err(e) = self.snapshot.restore() {
                    self.logger.warn(&format!(
                        "Post-crash snapshot restore failed: {}",
                        e
                    ));
                }
            }

            // NXS: meta + non-blocking spawn + async exit observation
            crate::nxs::on_event(
                &self.cfg,
                "crash",
                result,
                crash_path.as_deref(),
                minimized_path.as_deref(),
                Some(&self.model_name),
            );
        } else if is_hang {
            self.logger.hang(result);
            let path = format!("{}/hangs/id:{:06}", self.cfg.output_dir, result.seed_id);
            if let Some(tc) = self.corpus.get(result.seed_id) {
                let _ = fs::write(&path, tc.serialize());
                crash_path = Some(path);
            }

            crate::nxs::on_event(
                &self.cfg,
                "hang",
                result,
                crash_path.as_deref(),
                None,
                Some(&self.model_name),
            );
        } else if oracle_interesting || result.is_interesting() {
            self.logger.interesting(result);

            // interesting / new_coverage / new_state — only if operator opted in via events
            let event = if result.new_coverage || result.coverage_hits > 0 {
                "new_coverage"
            } else if result.new_state {
                "new_state"
            } else {
                "interesting"
            };
            crate::nxs::on_event(
                &self.cfg,
                event,
                result,
                None,
                None,
                Some(&self.model_name),
            );
        }
    }

    fn print_status(&self, elapsed: Duration) {
        let execs = self.stats.execs.load(Ordering::Relaxed);
        let crashes = self.stats.crashes.load(Ordering::Relaxed);
        let hangs = self.stats.hangs.load(Ordering::Relaxed);
        let paths = self.stats.new_paths.load(Ordering::Relaxed);
        let states = self.stats.new_states.load(Ordering::Relaxed);
        let corpus = self.corpus.len();
        let cov_edges = self.coverage.total_edges();
        let eps = if elapsed.as_secs_f64() > 0.0 {
            execs as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };

        let nxs_secondary = if self.cfg.nxs.enabled {
            crate::nxs::secondary_count()
        } else {
            0
        };

        let snap = if self.snapshot.is_enabled() {
            self.snapshot.name()
        } else {
            "-"
        };

        self.logger.status(&format!(
            "[{}] execs: {} ({:.0}/s) | corpus: {} | paths: {} | states: {} | cov_edges: {} | crashes: {} | hangs: {} | nxs_sec: {} | snap: {} | tracker_states: {} | py_oracle: {}/{} | py_proto: {} | py_int: {} | py_enc: {} | py_mut: {}",
            format_duration(elapsed),
            execs,
            eps,
            corpus,
            paths,
            states,
            cov_edges,
            crashes,
            hangs,
            nxs_secondary,
            snap,
            self.tracker.state_count(),
            self.oracle_bridge.hits(),
            self.oracle_bridge.misses(),
            if self.protocol_bridge.is_active() {
                self.protocol_bridge.name()
            } else {
                "-".into()
            },
            if self.integrity_bridge.is_active() {
                self.integrity_bridge.name()
            } else {
                "-".into()
            },
            if self.encryptor_bridge.is_active() {
                self.encryptor_bridge.display_name()
            } else {
                "-".into()
            },
            if self.mutator_bridge.is_active() {
                format!("{}", self.mutator_bridge.dictionary_len())
            } else {
                "-".into()
            }
        ));
    }

    fn print_final_stats(&self, elapsed: Duration) {
        self.logger.info("=== Campaign Summary ===");
        self.print_status(elapsed);
        self.logger.info(&format!("Unique states observed: {}", self.tracker.state_count()));
        self.logger.info(&format!("Transitions recorded: {}", self.tracker.transition_count()));
        self.logger.info(&format!("Predictor observations: {}", self.predictor.observation_count()));
        self.logger.info(&format!(
            "Coverage edges ({}): {}",
            self.coverage.name(),
            self.coverage.total_edges()
        ));
        self.logger.info(&format!(
            "Python oracle hits/misses: {}/{}",
            self.oracle_bridge.hits(),
            self.oracle_bridge.misses()
        ));
        self.logger.info(&format!(
            "Python mutator extra dict: {}",
            if self.mutator_bridge.is_active() {
                format!("{} tokens", self.mutator_bridge.dictionary_len())
            } else {
                "inactive".into()
            }
        ));
        if self.snapshot.is_enabled() {
            self.logger.info(&format!(
                "Snapshot provider: {} (backend={})",
                self.snapshot.name(),
                self.cfg.execution.snapshot_backend
            ));
        }
        if self.cfg.nxs.enabled {
            let sec = crate::nxs::secondary_count();
            self.logger.info(&format!(
                "NXS secondary findings (exit 2): {}  →  {}/nxs-findings/secondary.jsonl",
                sec, self.cfg.output_dir
            ));
        }
        self.logger.info(&format!("Plugins used: {}", self.plugins_summary));
    }
}

fn install_signal_handlers(stop: Arc<AtomicBool>) {
    use std::sync::Once;
    static INIT: Once = Once::new();
    static mut STOP_FLAG: Option<Arc<AtomicBool>> = None;

    INIT.call_once(|| {
        unsafe {
            STOP_FLAG = Some(stop);

            extern "C" fn handler(_: libc::c_int) {
                unsafe {
                    if let Some(ref flag) = STOP_FLAG {
                        flag.store(true, Ordering::Relaxed);
                    }
                }
            }

            libc::signal(libc::SIGINT, handler as usize);
            libc::signal(libc::SIGTERM, handler as usize);
        }
    });
}
