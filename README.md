# Nexsiz

```
   _  _______  ______________    
  / |/ / __/ |/_/ __/  _/_  /    
 /    / _/_>  <_\ \_/ /  / /_    
/_/|_/___/_/|_/___/___/ /___/    
```

**Stateful Network Protocol Fuzzer**

**Nexsiz** is a high-performance, modular, pure Rust-based network protocol fuzzer designed for deep network protocol testing. It is purpose-built to explore the deepest regions of a protocol's state machine—areas where conventional fuzzers miss structural validity or state context and consequently remain blind.

Design priorities are explicit: precision over volume, structural integrity after mutation, hybrid black/grey-box feedback, and operational resilience under realistic network conditions.

> Offensive tooling must execute correctly, remain maintainable under operational pressure, and preserve the operator’s ability to reason about the exact behaviour the target exhibited.

---

## Design Principles

| Principle | Implementation |
|-----------|----------------|
| Semantic-preserving mutation | Hierarchical field / message / sequence mutators that respect protocol grammar |
| Protocol-aware integrity repair | Automatic restoration of length fields, checksums, framing, and terminators after mutation |
| Hybrid state model | Black-box response observation combined with true grey-box edge coverage |
| Grey-box instrumentation | `CoverageProvider` trait, AFL-style shared-memory edge map, external Frida agent |
| Intelligent connection reuse | Stateful TCP reuse with safety-prefix detection to prevent cross-test contamination |
| Adaptive transition prediction | Lightweight predictor that biases mutation scheduling toward promising state transitions |
| Minimal dependency surface | Default build depends only on `libc`; LibAFL is gated behind an optional feature flag |
| Trait-based extensibility | Protocol, Integrity, Oracle, and Encryptor plugins may be registered without core changes |
| Differential & sanitizer oracles | Multi-dimensional behavioural divergence and memory-safety / protocol-anomaly detection |
| NXS existence scripts | Post-event executable actors with rate-limited, non-blocking spawn and asynchronous exit observation |

---

## NXS — Existence After Discovery

Once the engine surfaces a crash, hang, or other interesting event, optional **NXS** binaries deepen the finding without increasing the size or complexity of the fuzzer core.

| Identifier | Role |
|------------|------|
| `crash/auto-repro` | Deterministic replay (prefers minimised input) |
| `crash/save-notify` | Artefact archival + optional external notification command |
| `crash/differential-probe` | Bounded variant probes against a known-good baseline |
| `hang/timeout-analyzer` | Multi-shot classification of hard hangs |
| `external/notify-webhook` | Compact HTTP POST of event metadata |

```bash
cd nxs && ./build.sh
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs default -v
nexsiz --nxs default --nxs-list
cd nxs && ./tests/e2e.sh
```

Contract, search-path resolution, and rate-limit controls are documented in [`nxs/README.md`](nxs/README.md) and [`nxs/CONTRACT.md`](nxs/CONTRACT.md).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  Monitoring · Oracle · NXS                        │
│  crash / hang detection · differential & sanitizer oracles       │
│  minimizer · structured logging · existence-script spawn         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│                 Execution & Efficiency Layer                     │
│  worker pool · intelligent connection reuse · TCP / UDP          │
│  process monitor · optional LibAFL Executor + LLMP Launcher      │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│             State Awareness + Coverage Feedback                  │
│  hybrid state tracker · adaptive transition predictor            │
│  CoverageProvider (null | map+shm | software)                    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│                      Input Construction                          │
│  semantic field model · hierarchical mutator                     │
│  protocol-aware integrity repair pipeline                        │
│  optional LibAFL Mutator adapter                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Build & Quick Start

```bash
# Default (minimal dependencies)
cargo build --release

# Optional LibAFL path
cargo build --release --features libafl

# Minimal seed corpus
mkdir -p seeds/ftp
echo -e "USER anonymous\r\nPASS guest\r\nPWD\r\nQUIT\r\n" > seeds/ftp/login.txt

# Basic campaign
./target/release/nexsiz \
  -h 127.0.0.1 -p 21 -m ftp \
  -s seeds/ftp -o output/ftp -v -x 50000

# Campaign with NXS deepening
cd nxs && ./build.sh && cd ..
./target/release/nexsiz -h 127.0.0.1 -p 21 -m ftp --nxs default -v
```

---

## Command-Line Interface

```
nexsiz [OPTIONS]
```

### Target

| Flag | Description | Default |
|------|-------------|---------|
| `-h`, `--host <ADDR>` | Target host | `127.0.0.1` |
| `-p`, `--port <PORT>` | Target port | `80` |
| `-P`, `--proto <PROTO>` | Transport protocol: `tcp` \| `udp` | `tcp` |
| `-t`, `--cmd <CMD>` | Spawn target process for local crash monitoring | — |
| `-T`, `--timeout <MS>` | Per-operation timeout (milliseconds) | `500` |

### Protocol & Plugins

| Flag | Description |
|------|-------------|
| `-m`, `--model <NAME>` | Protocol model: `ftp` \| `smtp` \| `http` \| `generic` |
| `-O`, `--oracle <NAME>` | Oracle: `default` \| `strict` \| `crash` \| `hang` \| `coverage` \| `differential` \| `sanitizer` \| `diffsan` \| `expanded` |
| `-i`, `--int <NAME>` | Integrity strategy: `default` \| `http` \| `ftp` \| `smtp` \| `binary` \| `null` |
| `-e`, `--enc <NAME>` | Encryptor: `null` \| `xor` \| `chacha20` \| `tls-record` \| `chacha20+tls` \| `xor+tls` |
| `-k`, `--key <KEY>` | Encryptor key (hex `0x…` or raw string) |

**Oracle notes**

| Name | Behaviour |
|------|-----------|
| `differential` / `diff` | Multi-dimensional behavioural divergence |
| `sanitizer` / `san` | ASan/UBSan patterns, length anomaly, null-byte, protocol violation |
| `diffsan` | differential + sanitizer + coverage (recommended for deep campaigns) |
| `expanded` | diffsan + error oracle (maximum sensitivity) |

### Coverage

| Flag | Description | Default |
|------|-------------|---------|
| `-C`, `--cov <NAME>` | Coverage provider: `null` \| `map` \| `software` | `null` |
| `-S`, `--shm <ID>` | Shared-memory id for Frida agent (`/nexsiz-cov-<ID>`) | — |

Environment: `NEXSIZ_SHM_ID`.

### Campaign Control

| Flag | Description | Default |
|------|-------------|---------|
| `-w`, `--workers <N>` | Worker threads | number of cores |
| `-s`, `--seed <DIR>` | Seed directory | `seeds` |
| `-o`, `--out <DIR>` | Output directory | `output` |
| `-c`, `--config <FILE>` | Load key=value configuration file | — |
| `-Y`, `--rpc <PATH>` | Unix domain socket for Python/RPC campaign control | — |
| `-n`, `--no-reuse` | Disable intelligent connection reuse | reuse enabled |
| `-r`, `--rng <N>` | Deterministic RNG seed | — |
| `-L`, `--libafl` | Use LibAFL execution path (requires `--features libafl`) | native path |

Environment: `NEXSIZ_RPC_SOCK` (same as `-Y`).

### Execution Limits

| Flag | Description |
|------|-------------|
| `-x`, `--execs <N>` | Stop after N executions |
| `-R`, `--runtime <SECS>` | Stop after SECS seconds |

### NXS (Existence Scripts)

| Flag | Description | Default |
|------|-------------|---------|
| `--nxs <EXPR>` | Enable NXS set (`default`, `crash`, `hang`, `safe`, `intrusive`, `external`, or concrete ids) | disabled |
| `--nxs-path <DIRS>` | Extra colon-separated search directories | — |
| `--nxs-cooldown <SECS>` | Cooldown per (event, crash, nxs) tuple | `30` |
| `--nxs-max-per-event <N>` | Cap spawns per event type (`0` = unlimited) | `0` |
| `--nxs-max-total <N>` | Cap total NXS spawns for the campaign (`0` = unlimited) | `0` |
| `--nxs-list` | Resolve selected set, print found/missing paths, then exit | — |

Environment: `NEXSIZ_NXS`, `NEXSIZ_NXS_PATH`.  
Default events: `crash`, `hang` (override via config `nxs_events=…`).

### General

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Verbose logging |
| `-?`, `--help` | Show help |
| `-V`, `--version` | Show version |

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `NEXSIZ_ENC_KEY` / `NEXSIZ_ENC_NONCE` | Encryptor key material |
| `NEXSIZ_SHM_ID` | Coverage shared-memory identifier |
| `NEXSIZ_RPC_SOCK` | RPC control socket path |
| `NEXSIZ_NXS` | Equivalent to `--nxs` |
| `NEXSIZ_NXS_PATH` | Equivalent to `--nxs-path` |

### Examples

```bash
nexsiz -h 127.0.0.1 -p 21 -m ftp -s seeds/ftp -o out/ftp -v
nexsiz -h 127.0.0.1 -p 21 -m ftp --nxs default -v
nexsiz --nxs default --nxs-list
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs intrusive --nxs-cooldown 60 -v
nexsiz -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -Y /tmp/nexsiz.sock -v
```

---

## Output Layout

```
output/
├── crashes/          # Crashing inputs (and .min when minimisation succeeds)
├── hangs/
├── nxs-meta/         # Metadata JSON written prior to each NXS spawn
├── nxs-out/          # Per-event NXS artefact trees (report.json, …)
├── nxs-findings/     # Secondary findings (exit code 2) in JSONL form
└── queue/
```

---

## Status

All core subsystems are implemented and production-ready:

- Trait-based plugin architecture (Protocol / Integrity / Oracle / Encryptor)
- LibAFL executor, hierarchical mutator adapter, and LLMP multi-core path
- True grey-box instrumentation (`CoverageProvider` + shared-memory map + Frida agent)
- Protocol-aware integrity repair for HTTP, FTP, SMTP, and binary formats
- Production-grade encryption-layer plugins
- Differential and sanitizer oracles
- Out-of-process campaign control surface (Python RPC)
- NXS Phases 0–5 (contract, shared library, official binaries, core integration, rate limits, e2e harness, webhook)

---

## License

Apache License 2.0. Intended for operational use by offensive security teams.

---

*Nexsiz — precision over noise · depth over breadth · silence until the edge is found.*

Revana Clarestya
