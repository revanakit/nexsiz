# Nexsiz

```
   _  _______  ______________    
  / |/ / __/ |/_/ __/  _/_  /    
 /    / _/_>  <_\ \_/ /  / /_    
/_/|_/___/_/|_/___/___/ /___/    
```

**Stateful Network Protocol Fuzzer**

Nexsiz is a high-performance, modular, pure-Rust network protocol fuzzer designed for red-team and APT-grade operations. It targets the deep corners of protocol state machines—regions where conventional fuzzers lose structural validity or state context and therefore remain blind.

The system prioritises precision over volume, structural integrity after mutation, hybrid black/grey-box feedback, and operational resilience under real-world network conditions.

> Offensive tooling must function correctly, remain maintainable under pressure, and preserve the operator’s ability to reason about what the target actually executed.

---

## Core Design Goals

- **Semantic-preserving mutation** – hierarchical field / message / sequence mutators that respect protocol structure.
- **Protocol-Aware Integrity Repair** – automatic restoration of length fields, checksums, framing, and terminators after mutation so that test cases remain deep-reaching.
- **Hybrid state model** – combination of black-box response observation and true grey-box edge coverage.
- **True grey-box instrumentation** – clean `CoverageProvider` trait with AFL-style shared-memory edge map and an external Frida agent.
- **Intelligent connection reuse** – stateful TCP connection reuse with safety-prefix detection to avoid contamination across test cases.
- **Adaptive state-transition prediction** – lightweight predictor that influences mutation scheduling.
- **Minimal dependency surface** – default build requires only `libc`; LibAFL is fully optional behind a feature flag.
- **Trait-based extensibility** – Protocol, Integrity, Oracle, and Encryptor plugins can be added without modifying the core engine.
- **Production differential & sanitizer oracles** – multi-dimensional behavioural divergence and memory-safety / protocol-anomaly detection.
- **NXS existence scripts** – post-crash/hang executable actors (auto-repro, differential probe, hang analysis, archive, webhook) with rate-limited non-blocking spawn.

---

## NXS — Existence After Discovery

After the engine surfaces a crash or hang, optional **NXS** binaries deepen the finding without bloating the fuzzer core:

| id | Role |
|----|------|
| `crash/auto-repro` | Deterministic replay (prefer minimised) |
| `crash/save-notify` | Archive artefacts + optional `NXS_NOTIFY_CMD` |
| `crash/differential-probe` | Bounded variant probes vs baseline |
| `hang/timeout-analyzer` | Multi-shot hard-hang classification |
| `external/notify-webhook` | HTTP POST of compact meta JSON |

```bash
cd nxs && ./build.sh
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs default -v
nexsiz --nxs default --nxs-list
cd nxs && ./tests/e2e.sh
```

Full contract, search path, and rate-limit flags: [`nxs/README.md`](nxs/README.md) · [`nxs/CONTRACT.md`](nxs/CONTRACT.md).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Monitoring / Oracle / NXS                     │
│   crash · hang · coverage · differential · sanitizer            │
│   minimizer · structured logging · existence-script spawn       │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│                  Execution & Efficiency Layer                   │
│   worker pool · intelligent connection reuse · TCP / UDP        │
│   process monitor · optional LibAFL Executor + LLMP Launcher    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│              State Awareness + Coverage Feedback                │
│   hybrid state tracker · adaptive transition predictor          │
│   CoverageProvider (null | map+shm | software)                  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────┴─────────────────────────────────┐
│                     Input Construction                          │
│   semantic field model · hierarchical mutator                   │
│   protocol-aware integrity repair pipeline                      │
│   optional LibAFL Mutator adapter                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Build & Quick Start

```bash
cargo build --release
# optional LibAFL path
cargo build --release --features libafl

mkdir -p seeds/ftp
echo -e "USER anonymous\r\nPASS guest\r\nPWD\r\nQUIT\r\n" > seeds/ftp/login.txt

./target/release/nexsiz \
  -h 127.0.0.1 -p 21 -m ftp \
  -s seeds/ftp -o output/ftp -v -x 50000

# with NXS deepening
cd nxs && ./build.sh && cd ..
./target/release/nexsiz -h 127.0.0.1 -p 21 -m ftp --nxs default -v
```

---

## Command-Line Interface (NXS subset)

| Flag | Description |
|------|-------------|
| `--nxs <EXPR>` | Enable NXS (`default`, `crash`, `hang`, `safe`, `intrusive`, `external`, or concrete ids) |
| `--nxs-path <DIRS>` | Extra search paths |
| `--nxs-cooldown <SECS>` | Per (event, crash, nxs) cooldown (default 30) |
| `--nxs-max-per-event <N>` | Cap spawns per event type |
| `--nxs-max-total <N>` | Cap total spawns |
| `--nxs-list` | Resolve set and print found/missing paths, then exit |

Env: `NEXSIZ_NXS`, `NEXSIZ_NXS_PATH`.

See full CLI table in prior documentation sections and `--help`.

---

## Output Layout

```
output/
├── crashes/              # Crashing inputs (+ .min when minimised)
├── hangs/
├── nxs-meta/             # Meta JSON written before each NXS spawn
├── nxs-out/              # Per-event NXS artefact trees (report.json, …)
└── queue/
```

---

## Roadmap

**Completed**

- [x] Trait-based plugin architecture (Protocol / Integrity / Oracle / Encryptor)
- [x] Full LibAFL executor, hierarchical mutator adapter, and LLMP multi-core path
- [x] True grey-box instrumentation (`CoverageProvider` + shared map + Frida agent)
- [x] Protocol-aware integrity repair for HTTP, FTP, SMTP, and binary formats
- [x] Production-ready encryption-layer plugins
- [x] Expanded differential and sanitizer oracles
- [x] Out-of-process campaign-control surface (Python RPC)
- [x] **NXS Phases 0–5** — contract, shared lib, official binaries, core integration, rate limits, e2e harness, webhook

**Planned**

- [ ] Snapshot / desocketing support

---

## License

Apache License 2.0. Intended for operational use by offensive security teams.

---

*Nexsiz – precision over noise · depth over breadth · silence until the edge is found.*

Revana Clarestya
