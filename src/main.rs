//! NEXSIZ – NEXT-GENERATION STATEFUL NETWORK PROTOCOL FUZZER
//!
//! Author  : Revana
//! Date    : 07/08/2026
//! Files   : nexsiz/src/main.rs
//!
//! Entry point. Parses a minimal CLI (no external clap dependency) and
//! launches the fuzzing engine (native or LibAFL-powered).
//! Short aliases prioritised for operational speed and memorability.

use nexsiz::common::config::Config;
use nexsiz::common::error::{NexsizError, Result};
use nexsiz::execution::engine::Engine;
use nexsiz::{BANNER, VERSION};
use std::env;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;
use std::time::Duration;

fn print_usage() {
    eprintln!(
        r#"Nexsiz v{} – Stateful Network Protocol Fuzzer

USAGE:
    nexsiz [OPTIONS]

OPTIONS (short · long):
    -h, --host <ADDR>         Target host                 (default: 127.0.0.1)
    -p, --port <PORT>         Target port                 (default: 80)
    -P, --proto <PROTO>       Protocol: tcp | udp         (default: tcp)
    -m, --model <NAME>        Protocol model: ftp|smtp|http|generic
    -O, --oracle <NAME>       Oracle: default|strict|crash|hang|coverage|
                              differential|sanitizer|diffsan|expanded
    -i, --int <NAME>          Integrity: default|http|ftp|smtp|binary|null
    -e, --enc <NAME>          Encryptor: null|xor|chacha20|tls-record|chacha20+tls|xor+tls
    -k, --key <KEY>           Encryptor key (hex 0x.. or raw string)
    -C, --cov <NAME>          Coverage: null|map|software (default: null)
    -S, --shm <ID>            Coverage SHM id (/nexsiz-cov-<ID>) for Frida agent
    -Y, --rpc <PATH>          Unix socket for Python/RPC campaign control
    -t, --cmd <CMD>           Spawn target process for crash monitoring
    -w, --workers <N>         Worker threads              (default: #cores)
    -s, --seed <DIR>          Seed directory              (default: seeds)
    -o, --out <DIR>           Output directory            (default: output)
    -c, --config <FILE>       Load key=value config file
    -T, --timeout <MS>        Per-operation timeout ms    (default: 500)
    -x, --execs <N>           Stop after N executions
    -R, --runtime <SECS>      Stop after SECS seconds
    -n, --no-reuse            Disable intelligent connection reuse
    -r, --rng <N>             Deterministic RNG seed
    -L, --libafl              Use LibAFL path (needs --features libafl)
    -v, --verbose             Verbose logging
    -?, --help                Show this help
    -V, --version             Show version

NXS (existence scripts — post-crash/hang deepening):
    --nxs <EXPR>              Enable NXS; EXPR = default|crash|hang|safe|intrusive|
                              external|crash/auto-repro|default,hang|…
    --nxs-path <DIRS>         Extra colon-separated search paths for nxs binaries
    --nxs-cooldown <SECS>     Per (event,crash,nxs) cooldown (default: 30)
    --nxs-max-per-event <N>   Cap spawns per event type (0 = unlimited)
    --nxs-max-total <N>       Cap total NXS spawns this campaign (0 = unlimited)
    --nxs-list                Resolve --nxs set, print found/missing paths, exit
    Env: NEXSIZ_NXS           Same as --nxs
    Env: NEXSIZ_NXS_PATH      Same as --nxs-path
    Events default: crash,hang  (override via config nxs_events=…)

ORACLE NOTES:
    differential / diff   Multi-dimensional behavioural divergence
    sanitizer / san       ASan/UBSan patterns, length anomaly, null-byte, protocol violation
    diffsan               differential + sanitizer + coverage (recommended deep campaigns)
    expanded              diffsan + error oracle (maximum sensitivity)

RPC / PYTHON CONTROL:
    -Y /tmp/nexsiz.sock   Enable campaign control socket
    Env: NEXSIZ_RPC_SOCK  Same as -Y
    Client: python3 python/nexsiz_client.py

EXAMPLES:
    nexsiz -h 127.0.0.1 -p 21 -m ftp -s seeds/ftp -o out/ftp -v
    nexsiz -h 127.0.0.1 -p 21 -m ftp --nxs default -v
    nexsiz --nxs default --nxs-list
    nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs intrusive --nxs-cooldown 60 -v

Key: NEXSIZ_ENC_KEY / NEXSIZ_ENC_NONCE
SHM: NEXSIZ_SHM_ID
RPC: NEXSIZ_RPC_SOCK
NXS: NEXSIZ_NXS / NEXSIZ_NXS_PATH
"#,
        VERSION
    );
}

struct Parsed {
    cfg: Config,
    nxs_list: bool,
}

fn parse_args() -> Result<Parsed> {
    let args: Vec<String> = env::args().collect();
    let mut cfg = Config::default();
    let mut nxs_list = false;
    let mut i = 1;

    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-?" | "--help" => {
                print_usage();
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("nexsiz {}", VERSION);
                process::exit(0);
            }

            "-h" | "--host" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -h/--host".into()));
                }
                cfg.target.host = IpAddr::from_str(&args[i])
                    .map_err(|e| NexsizError::Config(format!("Invalid host: {}", e)))?;
            }
            "-p" | "--port" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -p/--port".into()));
                }
                cfg.target.port = args[i]
                    .parse()
                    .map_err(|e| NexsizError::Config(format!("Invalid port: {}", e)))?;
            }
            "-P" | "--proto" | "--protocol" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -P/--proto".into()));
                }
                cfg.target.protocol = args[i].to_lowercase();
            }

            "-m" | "--model" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -m/--model".into()));
                }
                let v = args[i].to_lowercase();
                cfg.protocol_model = Some(v.clone());
                cfg.plugins.protocol = Some(v);
            }
            "-O" | "--oracle" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -O/--oracle".into()));
                }
                cfg.plugins.oracle = Some(args[i].to_lowercase());
            }
            "-i" | "--int" | "--integrity" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -i/--int".into()));
                }
                cfg.plugins.integrity = Some(args[i].to_lowercase());
            }
            "-e" | "--enc" | "--encryptor" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -e/--enc".into()));
                }
                cfg.plugins.encryptor = Some(args[i].to_lowercase());
            }
            "-k" | "--key" | "--enc-key" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -k/--key".into()));
                }
                cfg.enc_key = Some(args[i].clone());
            }
            "-C" | "--cov" | "--coverage" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -C/--cov".into()));
                }
                cfg.coverage = Some(args[i].to_lowercase());
            }
            "-S" | "--shm" | "--coverage-shm" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -S/--shm".into()));
                }
                cfg.coverage_shm = Some(args[i].clone());
            }
            "-Y" | "--rpc" | "--python-rpc" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -Y/--rpc".into()));
                }
                cfg.rpc_sock = Some(args[i].clone());
            }

            "-t" | "--cmd" | "--target-cmd" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -t/--cmd".into()));
                }
                cfg.target.target_cmd = Some(args[i].clone());
            }
            "-w" | "--workers" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -w/--workers".into()));
                }
                cfg.execution.workers = args[i]
                    .parse()
                    .map_err(|e| NexsizError::Config(format!("Invalid workers: {}", e)))?;
            }
            "-s" | "--seed" | "--seed-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -s/--seed".into()));
                }
                cfg.seed_dir = args[i].clone();
            }
            "-o" | "--out" | "--output-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -o/--out".into()));
                }
                cfg.output_dir = args[i].clone();
            }
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -c/--config".into()));
                }
                cfg = Config::from_file(&args[i])?;
            }
            "-T" | "--timeout" | "--timeout-ms" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -T/--timeout".into()));
                }
                let ms: u64 = args[i]
                    .parse()
                    .map_err(|e| NexsizError::Config(format!("Invalid timeout: {}", e)))?;
                cfg.target.timeout = Duration::from_millis(ms);
            }
            "-x" | "--execs" | "--max-execs" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -x/--execs".into()));
                }
                cfg.max_execs = Some(args[i].parse().map_err(|e| {
                    NexsizError::Config(format!("Invalid max-execs: {}", e))
                })?);
            }
            "-R" | "--runtime" | "--max-runtime" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -R/--runtime".into()));
                }
                let secs: u64 = args[i].parse().map_err(|e| {
                    NexsizError::Config(format!("Invalid max-runtime: {}", e))
                })?;
                cfg.max_runtime = Some(Duration::from_secs(secs));
            }
            "-n" | "--no-reuse" => {
                cfg.execution.connection_reuse = false;
            }
            "-r" | "--rng" | "--rng-seed" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for -r/--rng".into()));
                }
                cfg.rng_seed = Some(args[i].parse().map_err(|e| {
                    NexsizError::Config(format!("Invalid rng-seed: {}", e))
                })?);
            }
            "-L" | "--libafl" => {
                cfg.use_libafl = true;
            }
            "-v" | "--verbose" => {
                cfg.verbose = true;
            }

            // NXS
            "--nxs" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for --nxs".into()));
                }
                cfg.nxs.enabled = true;
                cfg.nxs.set = args[i].clone();
            }
            "--nxs-path" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for --nxs-path".into()));
                }
                cfg.nxs.path = Some(args[i].clone());
            }
            "--nxs-cooldown" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for --nxs-cooldown".into()));
                }
                cfg.nxs.cooldown_secs = args[i].parse().map_err(|e| {
                    NexsizError::Config(format!("Invalid --nxs-cooldown: {}", e))
                })?;
            }
            "--nxs-max-per-event" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config(
                        "missing value for --nxs-max-per-event".into(),
                    ));
                }
                cfg.nxs.max_per_event = args[i].parse().map_err(|e| {
                    NexsizError::Config(format!("Invalid --nxs-max-per-event: {}", e))
                })?;
            }
            "--nxs-max-total" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for --nxs-max-total".into()));
                }
                cfg.nxs.max_total = args[i].parse().map_err(|e| {
                    NexsizError::Config(format!("Invalid --nxs-max-total: {}", e))
                })?;
            }
            "--nxs-list" => {
                nxs_list = true;
                // Ensure a set is active for listing even if --nxs omitted
                if !cfg.nxs.enabled {
                    cfg.nxs.enabled = true;
                }
            }

            other if other.starts_with('-') => {
                return Err(NexsizError::Config(format!("Unknown option: {}", other)));
            }
            _ => {
                return Err(NexsizError::Config(format!("Unexpected argument: {}", arg)));
            }
        }
        i += 1;
    }

    if cfg.rpc_sock.is_none() {
        if let Ok(v) = env::var("NEXSIZ_RPC_SOCK") {
            if !v.is_empty() {
                cfg.rpc_sock = Some(v);
            }
        }
    }

    if !cfg.nxs.enabled {
        if let Ok(v) = env::var("NEXSIZ_NXS") {
            if !v.is_empty() {
                cfg.nxs.enabled = true;
                cfg.nxs.set = v;
            }
        }
    }
    if cfg.nxs.path.is_none() {
        if let Ok(v) = env::var("NEXSIZ_NXS_PATH") {
            if !v.is_empty() {
                cfg.nxs.path = Some(v);
            }
        }
    }

    Ok(Parsed { cfg, nxs_list })
}

fn main() {
    println!("{}", BANNER);

    let parsed = match parse_args() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Use -? or --help for usage information.");
            process::exit(1);
        }
    };

    if parsed.nxs_list {
        match nexsiz::nxs::list_resolved(&parsed.cfg) {
            Ok(rows) => {
                if rows.is_empty() {
                    println!("(no NXS resolved for set '{}')", parsed.cfg.nxs.set);
                } else {
                    println!("NXS set '{}' →", parsed.cfg.nxs.set);
                    for (id, path) in rows {
                        match path {
                            Some(p) => println!("  [found]   {}  →  {}", id, p.display()),
                            None => println!("  [missing] {}", id),
                        }
                    }
                }
                process::exit(0);
            }
            Err(e) => {
                eprintln!("nxs-list error: {}", e);
                process::exit(1);
            }
        }
    }

    let cfg = parsed.cfg;

    if cfg.use_libafl {
        #[cfg(feature = "libafl")]
        {
            if let Err(e) = nexsiz::execution::libafl_runner::run_libafl_campaign(&cfg) {
                eprintln!("LibAFL campaign error: {}", e);
                process::exit(1);
            }
            return;
        }
        #[cfg(not(feature = "libafl"))]
        {
            eprintln!(
                "Error: -L/--libafl was requested but this binary was not built with the `libafl` feature.\n\
                 Rebuild with:  cargo build --release --features libafl"
            );
            process::exit(1);
        }
    }

    let mut engine = match Engine::new(cfg) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to initialize engine: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = engine.run() {
        eprintln!("Campaign error: {}", e);
        process::exit(1);
    }
}
