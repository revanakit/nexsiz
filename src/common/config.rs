//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Files   : nexsiz/src/common/config.rs
//!
//! Configuration management for Nexsiz.

use crate::common::error::{NexsizError, Result};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

/// Target connection parameters.
#[derive(Debug, Clone)]
pub struct TargetConfig {
    pub host: IpAddr,
    pub port: u16,
    pub protocol: String, // "tcp" | "udp"
    pub timeout: Duration,
    pub max_reuse_messages: usize,
    /// Optional command to spawn the target as a child process for monitoring.
    pub target_cmd: Option<String>,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            host: IpAddr::from_str("127.0.0.1").unwrap(),
            port: 80,
            protocol: "tcp".to_string(),
            timeout: Duration::from_millis(500),
            max_reuse_messages: 32,
            target_cmd: None,
        }
    }
}

impl TargetConfig {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }
}

/// Mutation engine parameters.
#[derive(Debug, Clone)]
pub struct MutatorConfig {
    pub hierarchical_prob: f64,
    pub field_prob: f64,
    pub dict_prob: f64,
    pub max_mutations: usize,
    pub repair_integrity: bool,
}

impl Default for MutatorConfig {
    fn default() -> Self {
        Self {
            hierarchical_prob: 0.15,
            field_prob: 0.70,
            dict_prob: 0.25,
            max_mutations: 8,
            repair_integrity: true,
        }
    }
}

/// Execution engine parameters.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    pub workers: usize,
    pub queue_size: usize,
    pub connection_reuse: bool,
    pub snapshot: bool,
    pub max_reuse_failures: u32,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            workers: num_cpus_approx(),
            queue_size: 4096,
            connection_reuse: true,
            snapshot: false,
            max_reuse_failures: 3,
        }
    }
}

/// State awareness parameters.
#[derive(Debug, Clone)]
pub struct StateConfig {
    pub response_weight: f64,
    pub adaptive_prediction: bool,
    pub max_states: usize,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            response_weight: 0.6,
            adaptive_prediction: true,
            max_states: 10_000,
        }
    }
}

/// Plugin selection (names resolved by PluginRegistry).
#[derive(Debug, Clone, Default)]
pub struct PluginConfig {
    pub protocol: Option<String>,
    pub integrity: Option<String>,
    pub oracle: Option<String>,
    pub encryptor: Option<String>,
}

/// NXS (existence-script) configuration. Disabled by default → zero overhead.
#[derive(Debug, Clone)]
pub struct NxsConfig {
    /// Master enable (set true when --nxs is supplied).
    pub enabled: bool,
    /// Set expression: "default", "crash", "crash/auto-repro", "default,hang", …
    pub set: String,
    /// Extra colon-separated search directories (prepended to the standard path).
    pub path: Option<String>,
    /// Events that trigger spawn: crash, hang, interesting, new_coverage, new_state.
    pub events: Vec<String>,
    /// Minimum seconds between identical (event, crash_id, nxs_id) spawns.
    pub cooldown_secs: u64,
    /// Max NXS spawns per event type this campaign (0 = unlimited).
    pub max_per_event: u64,
    /// Max total NXS spawns this campaign (0 = unlimited).
    pub max_total: u64,
}

impl Default for NxsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            set: "default".to_string(),
            path: None,
            events: vec!["crash".into(), "hang".into()],
            cooldown_secs: 30,
            max_per_event: 0,
            max_total: 0,
        }
    }
}

/// Top-level configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub target: TargetConfig,
    pub mutator: MutatorConfig,
    pub execution: ExecutionConfig,
    pub state: StateConfig,
    pub plugins: PluginConfig,
    pub protocol_model: Option<String>,
    pub seed_dir: String,
    pub output_dir: String,
    pub max_runtime: Option<Duration>,
    pub max_execs: Option<u64>,
    pub verbose: bool,
    pub rng_seed: Option<u64>,
    pub use_libafl: bool,
    pub coverage: Option<String>,
    pub enc_key: Option<String>,
    /// POSIX SHM id for coverage map (`/nexsiz-cov-<id>`). Also NEXSIZ_SHM_ID.
    pub coverage_shm: Option<String>,
    /// Unix domain socket path for the Python/RPC campaign control surface.
    /// Also NEXSIZ_RPC_SOCK / -Y --rpc.
    pub rpc_sock: Option<String>,
    /// NXS existence-script integration (Phase 2+).
    pub nxs: NxsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: TargetConfig::default(),
            mutator: MutatorConfig::default(),
            execution: ExecutionConfig::default(),
            state: StateConfig::default(),
            plugins: PluginConfig::default(),
            protocol_model: None,
            seed_dir: "seeds".to_string(),
            output_dir: "output".to_string(),
            max_runtime: None,
            max_execs: None,
            verbose: false,
            rng_seed: None,
            use_libafl: false,
            coverage: None,
            enc_key: None,
            coverage_shm: None,
            rpc_sock: None,
            nxs: NxsConfig::default(),
        }
    }
}

impl Config {
    pub fn protocol_plugin_name(&self) -> Option<&str> {
        self.plugins
            .protocol
            .as_deref()
            .or(self.protocol_model.as_deref())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .map_err(|e| NexsizError::Config(format!("Cannot read config: {}", e)))?;

        let mut cfg = Config::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, '=');
            let key = parts.next().unwrap_or("").trim();
            let val = parts.next().unwrap_or("").trim();

            match key {
                "host" => {
                    cfg.target.host = IpAddr::from_str(val)
                        .map_err(|e| NexsizError::Config(format!("Invalid host: {}", e)))?;
                }
                "port" => {
                    cfg.target.port = val
                        .parse()
                        .map_err(|e| NexsizError::Config(format!("Invalid port: {}", e)))?;
                }
                "protocol" => cfg.target.protocol = val.to_lowercase(),
                "model" | "protocol_model" => {
                    let v = val.to_lowercase();
                    cfg.protocol_model = Some(v.clone());
                    cfg.plugins.protocol = Some(v);
                }
                "integrity" | "integrity_plugin" => {
                    cfg.plugins.integrity = Some(val.to_lowercase());
                }
                "oracle" | "oracle_plugin" => {
                    cfg.plugins.oracle = Some(val.to_lowercase());
                }
                "encryptor" | "encryptor_plugin" => {
                    cfg.plugins.encryptor = Some(val.to_lowercase());
                }
                "enc_key" | "encryptor_key" | "key" => {
                    cfg.enc_key = Some(val.to_string());
                }
                "coverage" | "coverage_provider" => {
                    cfg.coverage = Some(val.to_lowercase());
                }
                "coverage_shm" | "shm" | "shm_id" => {
                    cfg.coverage_shm = Some(val.to_string());
                }
                "rpc_sock" | "rpc" | "python_rpc" => {
                    cfg.rpc_sock = Some(val.to_string());
                }
                "target_cmd" => {
                    cfg.target.target_cmd = Some(val.to_string());
                }
                "timeout_ms" => {
                    let ms: u64 = val
                        .parse()
                        .map_err(|e| NexsizError::Config(format!("Invalid timeout: {}", e)))?;
                    cfg.target.timeout = Duration::from_millis(ms);
                }
                "max_reuse_messages" => {
                    cfg.target.max_reuse_messages = val.parse().map_err(|e| {
                        NexsizError::Config(format!("Invalid max_reuse_messages: {}", e))
                    })?;
                }
                "workers" => {
                    cfg.execution.workers = val
                        .parse()
                        .map_err(|e| NexsizError::Config(format!("Invalid workers: {}", e)))?;
                }
                "connection_reuse" => {
                    cfg.execution.connection_reuse = val == "true" || val == "1";
                }
                "seed_dir" => cfg.seed_dir = val.to_string(),
                "output_dir" => cfg.output_dir = val.to_string(),
                "verbose" => cfg.verbose = val == "true" || val == "1",
                "rng_seed" => {
                    cfg.rng_seed = Some(val.parse().map_err(|e| {
                        NexsizError::Config(format!("Invalid rng_seed: {}", e))
                    })?);
                }
                "max_execs" => {
                    cfg.max_execs = Some(val.parse().map_err(|e| {
                        NexsizError::Config(format!("Invalid max_execs: {}", e))
                    })?);
                }
                "use_libafl" | "libafl" => {
                    cfg.use_libafl = val == "true" || val == "1";
                }
                // NXS
                "nxs" | "nxs_set" => {
                    cfg.nxs.enabled = true;
                    cfg.nxs.set = val.to_string();
                }
                "nxs_path" => {
                    cfg.nxs.path = Some(val.to_string());
                }
                "nxs_events" => {
                    cfg.nxs.events = val
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                "nxs_cooldown" | "nxs_cooldown_secs" => {
                    cfg.nxs.cooldown_secs = val.parse().unwrap_or(30);
                }
                "nxs_max_per_event" => {
                    cfg.nxs.max_per_event = val.parse().unwrap_or(0);
                }
                "nxs_max_total" => {
                    cfg.nxs.max_total = val.parse().unwrap_or(0);
                }
                _ => {}
            }
        }

        Ok(cfg)
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.seed_dir)?;
        fs::create_dir_all(&self.output_dir)?;
        fs::create_dir_all(format!("{}/crashes", self.output_dir))?;
        fs::create_dir_all(format!("{}/hangs", self.output_dir))?;
        fs::create_dir_all(format!("{}/queue", self.output_dir))?;
        if self.nxs.enabled {
            fs::create_dir_all(format!("{}/nxs-meta", self.output_dir))?;
            fs::create_dir_all(format!("{}/nxs-out", self.output_dir))?;
            fs::create_dir_all(format!("{}/nxs-findings", self.output_dir))?;
        }
        Ok(())
    }
}

fn num_cpus_approx() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
