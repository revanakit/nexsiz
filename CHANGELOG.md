# Changelog — Nexsiz

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for public releases. Internal phase markers are retained for operator clarity.

---

## [Unreleased]

### Added
- Root `Makefile` providing operational targets: `release`, `release-full`, `nxs`,
  `campaign-*`, `infer`, `clean-shm`, `status`, `list-nxs`, `install-nxs`, etc.
- `SECURITY.md`, `CHANGELOG.md`, `OPERATIONS.md`

---

## [0.1.0] — 2026-08

Initial operational baseline. Maturity: experimental / operational.

### Core Engine
- Pure-Rust stateful network protocol fuzzer (default dependency surface: `libc` only).
- Four-layer architecture: Input Construction → State Awareness + Coverage →
  Execution & Efficiency → Monitoring / Oracle / NXS.
- Trait-based plugin system: Protocol, Integrity, Oracle, Encryptor.
- Hierarchical semantic mutator with field-aware constraints.
- Protocol-aware integrity repair (length fields, CRC16/CRC32, XOR, additive,
  one’s-complement, HTTP Content-Length, FTP/SMTP CRLF + DATA terminator,
  binary length-prefix BE/LE).
- Intelligent TCP connection reuse with safety-prefix detection.
- Adaptive transition predictor.
- Worker pool, deterministic RNG seed, execution / runtime limits.

### Protocol Models
- Built-in: `generic`, `ftp`, `smtp`, `http`, `dns`, `mqtt`, `smb`/`cifs`,
  `binary-lp`, `binary-lp-le` (+ grammar-enriched aliases).
- Optional JSON field-tree models (`--features json-model`).
- Offline grammar inference (`--infer-model`).

### Coverage (Grey-box)
- `CoverageProvider` trait.
- Providers: `null` (default, zero overhead), `map` (AFL-style 64 KiB SHM),
  `software`.
- Frida / external SHM agent (`agents/frida/nexsiz_cov.js`).
- CLI: `-C` / `--cov`, `-S` / `--shm`; env `NEXSIZ_SHM_ID`.

### Snapshot / Desocketing (Phases 1–3)
- `SnapshotProvider` trait + backends: `Null`, `ProcessRestart`, `Criu` (feature-gated).
- Protocol-aware desocket (FTP / SMTP / MQTT / HTTP) + `SocketState`.
- `restore_epoch` orchestration — workers force-reconnect after restore.
- Cost-aware energy accounting; restores / desockets statistics.
- Zero behaviour change when snapshot is disabled.

### Encryptor
- Pure ChaCha20 (RFC 8439), TLS record framing, XOR, and combinations
  (`chacha20+tls`, `xor+tls`).
- Key material via `-k` / `--key` or `NEXSIZ_ENC_KEY` / `NEXSIZ_ENC_NONCE`.

### Oracles
- `default`, `strict`, `crash`, `hang`, `coverage`, `differential`,
  `sanitizer`, `diffsan`, `expanded`.

### NXS — Existence Scripts (Phases 0–5 + chain-repro)
- Contract-driven post-event actors (`nxs/CONTRACT.md`).
- Official scripts: `auto-repro`, `save-notify`, `differential-probe`,
  `timeout-analyzer`, `notify-webhook`, `chain-repro`, `state-diff`,
  `coverage-probe`, `auth-bypass`.
- Meta writer, non-blocking spawn, rate limits, cooldown, search-path resolution.
- Categories: `default`, `crash`, `hang`, `safe`, `intrusive`, `external`.
- Secondary findings (exit code 2) recorded in `nxs-findings/`.
- `nxs/build.sh` + e2e harness.

### LibAFL Integration
- Optional path (`--features libafl`, CLI `-L`).
- `serdeany_autoreg` fix on `libafl_bolts` (required for stable startup).

### Operator Surfaces
- Compact dependency-free CLI (short aliases preserved).
- Config file support (`-c`).
- Unix-domain RPC socket + Python client (`python/nexsiz_client.py`).
- Structured output layout: `crashes/`, `hangs/`, `nxs-meta/`, `nxs-out/`,
  `nxs-findings/`, `queue/`.

### Build & Quality
- Release profile: LTO, single codegen unit, `panic = abort`, strip.
- Feature flags: `libafl`, `json-model`, `criu`.
- Apache-2.0 license.

---

## Versioning Notes

- `0.1.x` is the current operational series.
- Breaking changes to the NXS contract will increment the NXS major version
  independently and be documented here.
- Feature-gated components (LibAFL, CRIU, JSON models) remain optional so that
  the default binary stays minimal.
