# Nexsiz CLI Reference

Complete command-line interface for **Nexsiz** — Stateful Network Protocol Fuzzer.

```
nexsiz [OPTIONS]
```

---

## Target

| Flag | Description | Default |
|------|-------------|---------|
| `-h`, `--host <ADDR>` | Target host | `127.0.0.1` |
| `-p`, `--port <PORT>` | Target port | `80` |
| `-P`, `--proto`, `--protocol <PROTO>` | Transport: `tcp` \| `udp` | `tcp` |
| `-t`, `--cmd`, `--target-cmd <CMD>` | Spawn target process for crash monitoring / snapshot | — |
| `-T`, `--timeout`, `--timeout-ms <MS>` | Per-operation timeout (milliseconds) | `500` |

---

## Protocol & Plugins

| Flag | Description |
|------|-------------|
| `-m`, `--model <NAME>` | Protocol model: `ftp` \| `smtp` \| `http` \| `generic` \| `dns` \| `mqtt` \| `smb` \| `binary-lp` \| `binary-lp-le` \| path/to/model.json |
| `-O`, `--oracle <NAME>` | Oracle: `default` \| `strict` \| `crash` \| `hang` \| `coverage` \| `differential` \| `sanitizer` \| `diffsan` \| `expanded` |
| `-i`, `--int`, `--integrity <NAME>` | Integrity: `default` \| `http` \| `ftp` \| `smtp` \| `binary` \| `binary-le` \| `null` |
| `-e`, `--enc`, `--encryptor <NAME>` | Encryptor: `null` \| `xor` \| `chacha20` \| `tls-record` \| `chacha20+tls` \| `xor+tls` |
| `-k`, `--key`, `--enc-key <KEY>` | Encryptor key (hex `0x…` or raw string) |

### Oracle notes

| Name | Behaviour |
|------|-----------|
| `differential` / `diff` | Multi-dimensional behavioural divergence |
| `sanitizer` / `san` | ASan/UBSan patterns, length anomaly, null-byte, protocol violation |
| `diffsan` | differential + sanitizer + coverage (recommended for deep campaigns) |
| `expanded` | diffsan + error oracle (maximum sensitivity) |

---

## Model Inference (offline)

| Flag | Description |
|------|-------------|
| `--infer-model` | Infer protocol model from `-s` seed directory and exit |
| `--infer-out <PATH>` | Write inferred model (JSON with `json-model` feature, else human dump) |

```bash
nexsiz --infer-model -s seeds/ftp -v
nexsiz --infer-model -s seeds/custom --infer-out models/inferred.json
```

---

## Coverage

| Flag | Description | Default |
|------|-------------|---------|
| `-C`, `--cov`, `--coverage <NAME>` | Coverage provider: `null` \| `map` \| `software` | `null` |
| `-S`, `--shm`, `--coverage-shm <ID>` | Shared-memory id for Frida agent (`/nexsiz-cov-<ID>`) | — |

Environment: `NEXSIZ_SHM_ID`.

---

## Campaign Control

| Flag | Description | Default |
|------|-------------|---------|
| `-w`, `--workers <N>` | Worker threads | number of cores |
| `-s`, `--seed`, `--seed-dir <DIR>` | Seed directory | `seeds` |
| `-o`, `--out`, `--output-dir <DIR>` | Output directory | `output` |
| `-c`, `--config <FILE>` | Load key=value configuration file | — |
| `-Y`, `--rpc`, `--python-rpc <PATH>` | Unix domain socket for Python/RPC campaign control | — |
| `-n`, `--no-reuse` | Disable intelligent connection reuse | reuse enabled |
| `-r`, `--rng`, `--rng-seed <N>` | Deterministic RNG seed | — |
| `-L`, `--libafl` | Use LibAFL path (requires `--features libafl`) | native path |

Environment: `NEXSIZ_RPC_SOCK` (same as `-Y`).

---

## Snapshot / Process Management

| Flag | Description | Default |
|------|-------------|---------|
| `-Z`, `--snapshot` | Enable process snapshot / restore | disabled |
| `--snapshot-backend <B>` | Backend: `null` \| `process` \| `criu` | `process` (when `-Z`) |

- `process` — kill + respawn on crash (requires `-t/--cmd`)
- `criu` — CRIU dump/restore (requires `--features criu` and `criu` on `PATH`)
- Snapshot implies local process control; combine with `-t`

```bash
nexsiz -t "./target_daemon" -Z --snapshot-backend process -m ftp -v
nexsiz -t "./target_daemon" -Z --snapshot-backend criu -m ftp -v
```

---

## Execution Limits

| Flag | Description |
|------|-------------|
| `-x`, `--execs`, `--max-execs <N>` | Stop after N executions |
| `-R`, `--runtime`, `--max-runtime <SECS>` | Stop after SECS seconds |

---

## NXS (Existence Scripts)

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

```bash
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs default -v
nexsiz --nxs intrusive --nxs-list
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs intrusive --nxs-cooldown 60 -v
```

---

## General

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Verbose logging |
| `-?`, `--help` | Show help |
| `-V`, `--version` | Show version |

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `NEXSIZ_ENC_KEY` / `NEXSIZ_ENC_NONCE` | Encryptor key material |
| `NEXSIZ_SHM_ID` | Coverage shared-memory identifier |
| `NEXSIZ_RPC_SOCK` | RPC control socket path |
| `NEXSIZ_NXS` | Equivalent to `--nxs` |
| `NEXSIZ_NXS_PATH` | Equivalent to `--nxs-path` |
| `NEXSIZ_NONCE_MODE` | Nonce mode: `fixed` \| `incrementing` \| `random` |

---

## Examples

```bash
# Basic FTP campaign
nexsiz -h 127.0.0.1 -p 21 -m ftp -s seeds/ftp -o out/ftp -v

# DNS / MQTT / SMB
nexsiz -h 10.0.0.5 -p 53  -m dns  -P tcp -v
nexsiz -h 10.0.0.5 -p 1883 -m mqtt -v
nexsiz -h 10.0.0.5 -p 445  -m smb  -v

# Offline model inference
nexsiz --infer-model -s seeds/ftp -v
nexsiz --infer-model -s seeds/custom --infer-out models/inferred.json

# NXS deepening
nexsiz -h 127.0.0.1 -p 21 -m ftp --nxs default -v
nexsiz --nxs default --nxs-list
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs intrusive --nxs-cooldown 60 -v

# Coverage + RPC
nexsiz -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -Y /tmp/nexsiz.sock -v

# Custom JSON model (needs --features json-model)
nexsiz -h 10.0.0.5 -p 1234 -m models/custom-example.json -v

# Local target + process snapshot
nexsiz -t "./target_daemon" -Z --snapshot-backend process -m ftp -v
nexsiz -t "./target_daemon" -Z --snapshot-backend criu -m ftp -v

# LibAFL path (needs --features libafl)
nexsiz -h 127.0.0.1 -p 21 -m ftp -L -v
```

---

## Alias summary (parser accepts all of these)

| Primary | Accepted aliases |
|---------|------------------|
| `--proto` | `--protocol` |
| `--int` | `--integrity` |
| `--enc` | `--encryptor` |
| `--key` | `--enc-key` |
| `--cov` | `--coverage` |
| `--shm` | `--coverage-shm` |
| `--rpc` | `--python-rpc` |
| `--cmd` | `--target-cmd` |
| `--seed` | `--seed-dir` |
| `--out` | `--output-dir` |
| `--timeout` | `--timeout-ms` |
| `--execs` | `--max-execs` |
| `--runtime` | `--max-runtime` |
| `--rng` | `--rng-seed` |

---

*Source of truth: `src/main.rs` (`print_usage` + `parse_args`). Keep this file in sync when flags change.*
