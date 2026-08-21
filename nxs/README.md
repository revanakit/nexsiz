**NXS — Nexsiz Existence Scripts**

Post-crash / post-event **executable** follow-up tools for Nexsiz.

```
Nexsiz (discovery)  →  crash / hang / interesting  →  NXS (existence & depth)
```

**Official Set (complete)**

Source of truth for categories and membership is `nxs/categories.toml`. The table below mirrors the current official set:

| id | Binary | Category | Exit 2 when |
|----|--------|----------|-------------|
| `crash/auto-repro` | `nxs-auto-repro` | safe, default | Crash/hang reproducible |
| `crash/save-notify` | `nxs-save-notify` | safe, default | — (exit 0) |
| `crash/differential-probe` | `nxs-differential-probe` | intrusive | Differential anomaly |
| `crash/state-diff` | `nxs-state-diff` | intrusive | Response signature divergence across shots |
| `crash/coverage-probe` | `nxs-coverage-probe` | intrusive | Path diversity / mixed behavioural classes |
| `crash/auth-bypass` | `nxs-auth-bypass` | intrusive | Unauthorized-looking success (FTP/SMTP/HTTP) |
| `crash/auth-escalation` | `nxs-auth-escalation` | intrusive | Elevated privilege / command success after anomaly (FTP/SMTP/HTTP) |
| `crash/chain-repro` | `nxs-chain-repro` | intrusive | Chain escalation (leak, class transition, response divergence) |
| `hang/timeout-analyzer` | `nxs-timeout-analyzer` | hang | Hard hang confirmed |
| `external/notify-webhook` | `nxs-notify-webhook` | external | — (HTTP notify) |

**auth-escalation notes**

- **Distinct from auth-bypass**: bypass tries unauthenticated entry; escalation tries *elevated* commands/paths after an anomaly.
- Primary models: **FTP**, **SMTP**, **HTTP**.
- Phase 2 features: confidence (`high`/`medium`/`low`), per-shot artefacts under `--out/shots/`, rich `report.extra`.
- Example: `nexsiz … --nxs crash/auth-escalation -v` or via `--nxs intrusive`.

**Build**

```text
cd nxs && ./build.sh
# → nxs/bin/nxs-*
```

**Contract smoke tests**

```text
cd nxs && ./tests/e2e.sh
# optional live target:
NXS_E2E_TARGET=127.0.0.1:21 ./tests/e2e.sh
```

**Auto-spawn**

```text
nexsiz -h 10.0.0.5 -p 21 -m ftp --nxs default -v
nexsiz --nxs default --nxs-list          # resolve paths, exit
nexsiz ... --nxs intrusive --nxs-cooldown 60 --nxs-max-per-event 20 -v
nexsiz ... --nxs crash/auth-escalation -v
nexsiz ... --nxs crash/chain-repro -v    # explicit single NXS
nexsiz ... --nxs external -v            # webhook (set NXS_WEBHOOK_URL)
```

**Rate limits**

| Flag | Default | Meaning |
|------|---------|---------|
| `--nxs-cooldown` | 30s | Per (event, crash_id, nxs_id) |
| `--nxs-max-per-event` | 0 (∞) | Cap per event type |
| `--nxs-max-total` | 0 (∞) | Cap total spawns |

**Search path**

1. Absolute `--nxs` path  
2. `NEXSIZ_NXS_PATH` / `--nxs-path`  
3. `~/.nexsiz/nxs/bin/`  
4. `./nxs/bin/`  
5. Relative to nexsiz binary  

**Async exit-code observation (design requirement)**

Spawn is **non-blocking**. A dedicated background reaper thread (`src/nxs/reaper.rs`) retains the `Child` handles and polls them with non-blocking `try_wait`:

- Every observed exit is logged: `[nexsiz/nxs] exit <id> → <code> …`
- **Exit code 2** (further vulnerability / exploit-assist) is escalated as a **secondary finding**:
  - Atomic counter exposed in the live status line (`nxs_sec`)
  - Appended as a JSONL record to `{output}/nxs-findings/secondary.jsonl`
  - When the NXS was given `--out`, a sidecar `exit_code` file is also written under that directory
- The fuzzer hot-path never waits on any NXS process; zombies are reaped exclusively by the background thread.

This design keeps campaign throughput independent of NXS latency while still capturing every secondary indication.

**Webhook**

```text
export NXS_WEBHOOK_URL=http://127.0.0.1:9000/hook
nexsiz ... --nxs external -v
# or manual:
./nxs/bin/nxs-notify-webhook --meta output/nxs-meta/….json --url http://…
```

HTTPS is not supported in the pure-stdlib client; terminate TLS at a local proxy or use `NXS_NOTIFY_CMD` with curl from `save-notify`.

**Custom NXS**

```text
cp -r nxs/templates/rust ~/.nexsiz/nxs/src/my-chain
cd ~/.nexsiz/nxs/src/my-chain && cargo build --release
cp target/release/nxs-* ~/.nexsiz/nxs/bin/
```

Templates also exist for C, Go, and Python. Every custom NXS **must** obey the binding contract in [CONTRACT.md](CONTRACT.md).

> Existence after discovery. Execute. Deepen. Exploit-assist.
