# Nexsiz Frida Coverage Agent

External grey-box instrumentation for Nexsiz.

The agent injects an AFL-style 64 KiB edge map into a platform shared-memory region. Nexsiz’s `SharedMapCoverage` provider (`-C map`) owns the region, clears it before every execution, and harvests the hits afterward. What the target touches in the dark becomes visible to the fuzzer.

## SHM protocol

| Field | Value |
|-------|--------|
| Size | 65536 bytes |
| Cell | `u8` saturating hit count |
| Edge | `(prev >> 1) ^ cur` (AFL classic) |

### Naming by platform

| Platform | Default name | With id |
|----------|--------------|---------|
| **Linux** | `/nexsiz-cov` | `/nexsiz-cov-<id>` |
| **Windows** | `Local\nexsiz-cov` | `Local\nexsiz-cov-<id>` |

Nexsiz creates and attaches the region. The Frida agent opens the **same name** and increments cells. Between executions Nexsiz zeroes the map — no residual noise.

On Windows the object lives in the session-local namespace (`Local\`) so no elevation is required. Frida scripts must open the corresponding named File Mapping (UTF-16 name).

## Quick start (Linux)

```bash
# Terminal A – instrument the target
export NEXSIZ_SHM_ID=demo
# Optional: constrain Stalker to a single module
export NEXSIZ_COV_MODULE=mydaemon
frida -l agents/frida/nexsiz_cov.js -f ./mydaemon --no-pause

# Terminal B – fuzz with live SHM coverage
export NEXSIZ_SHM_ID=demo
./target/release/nexsiz -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -v
```

Or pass the SHM id solely via CLI / config:

```bash
nexsiz -C map --shm demo ...
# config file:
# coverage=map
# coverage_shm=demo
```

## Quick start (Windows)

```powershell
# Terminal A – instrument the target (Frida for Windows)
$env:NEXSIZ_SHM_ID = "demo"
frida -l agents/frida/nexsiz_cov.js -f .\mydaemon.exe

# Terminal B – fuzz
$env:NEXSIZ_SHM_ID = "demo"
.\target\release\nexsiz.exe -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -v
```

> **Note**: The stock `nexsiz_cov.js` currently targets POSIX SHM. A Windows-aware agent variant (opening `Local\nexsiz-cov[-id]` via Frida’s Windows Memory / NativeFunction APIs) is required for full grey-box on Windows. Until that agent lands, `-C map` still works for the in-process synthetic edges; external Frida hits need the Windows agent update.

## Modes

| `NEXSIZ_COV_MODE` | Behaviour |
|------------------|-----------|
| `stalker` (default) | Basic-block edge coverage via Frida Stalker — higher fidelity, measurable overhead |
| `exports` | Interceptor on recv/read/send/parse-like exports — lighter, lower noise |

## Environment variables

| Variable | Meaning |
|----------|---------|
| `NEXSIZ_SHM_ID` | SHM suffix or full name |
| `NEXSIZ_COV_MODULE` | Substring filter for Stalker (module name) |
| `NEXSIZ_COV_MODE` | `stalker` \| `exports` |

## Operational notes

- **Linux**: Frida + POSIX SHM under `/dev/shm/`. Clean residual maps with `rm /dev/shm/nexsiz-cov*` when the campaign ends.
- **Windows**: Named File Mapping in the Local namespace. No automatic cleanup of the named object (same design as Linux).
- Stalker carries real cost; prefer `exports` when throughput matters more than block-level resolution.
- Remote-only targets without a local process cannot use this agent; fall back to `-C software`.
- The agent and the fuzzer must agree on the same `NEXSIZ_SHM_ID`. Mismatch is silent blindness.

---
*Precision over noise. The map only records what the target actually touches.*
