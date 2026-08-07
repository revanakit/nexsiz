# NXS — Nexsiz Existence Scripts

Post-crash / post-event **executable** follow-up tools for Nexsiz.

```
Nexsiz (discovery)  →  crash / hang / interesting  →  NXS (existence & depth)
```

## Official Set (complete)

| id | Binary | Category | Exit 2 when |
|----|--------|----------|-------------|
| `crash/auto-repro` | `nxs-auto-repro` | safe, default | Crash/hang reproducible |
| `crash/save-notify` | `nxs-save-notify` | safe, default | — (exit 0) |
| `crash/differential-probe` | `nxs-differential-probe` | intrusive | Differential anomaly |
| `hang/timeout-analyzer` | `nxs-timeout-analyzer` | hang | Hard hang confirmed |
| `external/notify-webhook` | `nxs-notify-webhook` | external | — (HTTP notify) |

## Build

```bash
cd nxs && ./build.sh
# → nxs/bin/nxs-*
```

## Contract smoke tests

```bash
cd nxs && ./tests/e2e.sh
# optional live target:
NXS_E2E_TARGET=127.0.0.1:21 ./tests/e2e.sh
```

## Auto-spawn

```bash
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs default -v
nexsiz --nxs default --nxs-list          # resolve paths, exit
nexsiz ... --nxs intrusive --nxs-cooldown 60 --nxs-max-per-event 20 -v
nexsiz ... --nxs external -v            # webhook (set NXS_WEBHOOK_URL)
```

### Rate limits

| Flag | Default | Meaning |
|------|---------|---------|
| `--nxs-cooldown` | 30s | Per (event, crash_id, nxs_id) |
| `--nxs-max-per-event` | 0 (∞) | Cap per event type |
| `--nxs-max-total` | 0 (∞) | Cap total spawns |

### Search path

1. Absolute `--nxs` path  
2. `NEXSIZ_NXS_PATH` / `--nxs-path`  
3. `~/.nexsiz/nxs/bin/`  
4. `./nxs/bin/`  
5. Relative to nexsiz binary  

### Async exit-code observation (design requirement)

Spawn is **non-blocking**. A background reaper thread (`nxs-reaper`) keeps the `Child` handles and polls with `try_wait`:

- Every exit code is logged: `[nexsiz/nxs] exit <id> → <code> …`
- **Exit 2** (further vulnerability / exploit-assist) is escalated as a **secondary finding**:
  - Atomic counter visible in status line (`nxs_sec`)
  - Appended to `{output}/nxs-findings/secondary.jsonl`
  - Sidecar `exit_code` written under the NXS `--out` directory when present
- Fuzzer hot-path never waits on NXS; zombies are reaped by the background thread.

### Webhook

```bash
export NXS_WEBHOOK_URL=http://127.0.0.1:9000/hook
nexsiz ... --nxs external -v
# or manual:
./nxs/bin/nxs-notify-webhook --meta output/nxs-meta/….json --url http://…
```

HTTPS is not supported in the pure-stdlib client; terminate TLS at a local proxy or use `NXS_NOTIFY_CMD` with curl from `save-notify`.

## Custom NXS

```bash
cp -r nxs/templates/rust ~/.nexsiz/nxs/src/my-chain
cd ~/.nexsiz/nxs/src/my-chain && cargo build --release
cp target/release/nxs-* ~/.nexsiz/nxs/bin/
```

See [CONTRACT.md](CONTRACT.md).

> Existence after discovery. Execute. Deepen. Exploit-assist.
