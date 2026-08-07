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
use nexsiz::input::model::{infer_model_from_bytes, ProtocolModel};
use nexsiz::{BANNER, VERSION};
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
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
    -m, --model <NAME>        Protocol model: ftp|smtp|http|generic|
                              dns|mqtt|smb|binary-lp|binary-lp-le|
                              path/to/model.json
    -O, --oracle <NAME>       Oracle: default|strict|crash|hang|coverage|
                              differential|sanitizer|diffsan|expanded
    -i, --int <NAME>          Integrity: default|http|ftp|smtp|binary|binary-le|null
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

MODEL INFERENCE (offline):
    --infer-model             Infer protocol model from -s seed directory and exit
    --infer-out <PATH>        Write inferred model (JSON if --features json-model,
                              otherwise human-readable summary) to PATH

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
    nexsiz -h 10.0.0.5 -p 53 -m dns -P tcp -v
    nexsiz -h 10.0.0.5 -p 1883 -m mqtt -v
    nexsiz --infer-model -s seeds/ftp -v
    nexsiz --infer-model -s seeds/custom --infer-out models/inferred.json
    nexsiz -h 127.0.0.1 -p 21 -m ftp --nxs default -v
    nexsiz --nxs default --nxs-list

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
    infer_model: bool,
    infer_out: Option<String>,
}

fn parse_args() -> Result<Parsed> {
    let args: Vec<String> = env::args().collect();
    let mut cfg = Config::default();
    let mut nxs_list = false;
    let mut infer_model = false;
    let mut infer_out: Option<String> = None;
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
                // Keep original case for paths; lowercase only pure names
                let v = args[i].clone();
                let lower = v.to_lowercase();
                if lower.ends_with(".json") || v.contains('/') || v.contains('\\') {
                    cfg.protocol_model = Some(v.clone());
                    cfg.plugins.protocol = Some(v);
                } else {
                    cfg.protocol_model = Some(lower.clone());
                    cfg.plugins.protocol = Some(lower);
                }
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

            // Model inference
            "--infer-model" => {
                infer_model = true;
            }
            "--infer-out" => {
                i += 1;
                if i >= args.len() {
                    return Err(NexsizError::Config("missing value for --infer-out".into()));
                }
                infer_out = Some(args[i].clone());
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

    Ok(Parsed {
        cfg,
        nxs_list,
        infer_model,
        infer_out,
    })
}

/// Offline model inference: read all files under seed_dir, run heuristics,
/// print summary, optionally write output.
fn run_infer_model(seed_dir: &str, out_path: Option<&str>, verbose: bool) -> Result<()> {
    let dir = Path::new(seed_dir);
    if !dir.is_dir() {
        return Err(NexsizError::Config(format!(
            "seed directory does not exist: {}",
            seed_dir
        )));
    }

    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for entry in fs::read_dir(dir).map_err(NexsizError::Io)? {
        let entry = entry.map_err(NexsizError::Io)?;
        let path = entry.path();
        if path.is_file() {
            if let Ok(data) = fs::read(&path) {
                if !data.is_empty() {
                    blobs.push(data);
                }
            }
        }
    }

    if blobs.is_empty() {
        return Err(NexsizError::Config(format!(
            "no non-empty seed files in {}",
            seed_dir
        )));
    }

    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let name = dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("inferred");
    let model = infer_model_from_bytes(name, &refs, &[]);

    // Human summary always to stdout
    println!("=== Nexsiz model inference ===");
    println!("source      : {}", seed_dir);
    println!("name        : {}", model.name);
    println!("seeds       : {}", blobs.len());
    println!(
        "delimiter   : {}",
        model
            .delimiter
            .map(|d| format!("{:?}", d as char))
            .unwrap_or_else(|| "none".into())
    );
    println!("length_pref : {}", model.length_prefixed);
    if let Some(w) = model.length_width {
        println!("length_width: {}", w);
    }
    println!("endian      : {:?}", model.endian);
    println!("dictionary  : {} tokens", model.dictionary.len());
    if verbose {
        for (i, tok) in model.dictionary.iter().take(32).enumerate() {
            let printable = String::from_utf8_lossy(tok);
            if printable.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                println!("  [{:02}] \"{}\"", i, printable);
            } else {
                println!("  [{:02}] {:02x?}", i, tok);
            }
        }
        if model.dictionary.len() > 32 {
            println!("  … +{} more", model.dictionary.len() - 32);
        }
    }

    if let Some(path) = out_path {
        write_inferred_model(&model, path)?;
        println!("wrote       : {}", path);
    }

    println!("hint: use -m {} or refine into a formal JSON model", model.name);
    Ok(())
}

fn write_inferred_model(model: &ProtocolModel, path: &str) -> Result<()> {
    #[cfg(feature = "json-model")]
    {
        // Minimal JSON dump without full serde derive on ProtocolModel
        let mut dict_json = String::from("[");
        for (i, t) in model.dictionary.iter().enumerate() {
            if i > 0 {
                dict_json.push(',');
            }
            let esc = t
                .iter()
                .map(|b| {
                    if (0x20..0x7f).contains(b) && *b != b'\\' && *b != b'"' {
                        (*b as char).to_string()
                    } else {
                        format!("\\x{:02x}", b)
                    }
                })
                .collect::<String>();
            dict_json.push('"');
            dict_json.push_str(&esc);
            dict_json.push('"');
        }
        dict_json.push(']');

        let endian = match model.endian {
            nexsiz::input::model::ModelEndian::Big => "be",
            nexsiz::input::model::ModelEndian::Little => "le",
        };
        let delim = model
            .delimiter
            .map(|d| format!("\"\\x{:02x}\"", d))
            .unwrap_or_else(|| "null".into());
        let lw = model
            .length_width
            .map(|w| w.to_string())
            .unwrap_or_else(|| "null".into());

        let body = format!(
            r#"{{
  "name": "{}",
  "length_prefixed": {},
  "length_width": {},
  "endian": "{}",
  "delimiter": {},
  "dictionary": {},
  "messages": []
}}
"#,
            model.name, model.length_prefixed, lw, endian, delim, dict_json
        );
        fs::write(path, body).map_err(NexsizError::Io)?;
        return Ok(());
    }
    #[cfg(not(feature = "json-model"))]
    {
        // Human-readable dump when json-model feature is off
        let mut out = String::new();
        out.push_str(&format!("# inferred model: {}\n", model.name));
        out.push_str(&format!("length_prefixed={}\n", model.length_prefixed));
        if let Some(w) = model.length_width {
            out.push_str(&format!("length_width={}\n", w));
        }
        out.push_str(&format!("endian={:?}\n", model.endian));
        out.push_str(&format!("delimiter={:?}\n", model.delimiter));
        out.push_str("dictionary:\n");
        for t in &model.dictionary {
            out.push_str(&format!("  {:02x?}\n", t));
        }
        fs::write(path, out).map_err(NexsizError::Io)?;
        Ok(())
    }
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

    // Offline inference path — no campaign
    if parsed.infer_model {
        if let Err(e) = run_infer_model(
            &parsed.cfg.seed_dir,
            parsed.infer_out.as_deref(),
            parsed.cfg.verbose,
        ) {
            eprintln!("infer-model error: {}", e);
            process::exit(1);
        }
        process::exit(0);
    }

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
