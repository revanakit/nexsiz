# Nexsiz Frida Coverage Agent

External grey-box instrumentation for Nexsiz.

The agent injects an AFL-style 64 KiB edge map into a POSIX shared-memory region. Nexsiz’s `SharedMapCoverage` provider (`-C map`) owns the region, clears it before every execution, and harvests the hits afterward. What the target touches in the dark becomes visible to the fuzzer.

## SHM protocol

| Field | Value |
|-------|--------|
| Name | `/nexsiz-cov` or `/nexsiz-cov-<id>` |
| Size | 65536 bytes |
| Cell | `u8` saturating hit count |
| Edge | `(prev >> 1) ^ cur` (AFL classic) |

Nexsiz creates and attaches the region. The Frida agent opens the same name and increments cells. Between executions Nexsiz zeroes the map — no residual noise.

## Quick start

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

## Modes

| `NEXSIZ_COV_MODE` | Behaviour |
|------------------|-----------|
| `stalker` (default) | Basic-block edge coverage via Frida Stalker — higher fidelity, measurable overhead |
| `exports` | Interceptor on recv/read/send/parse-like exports — lighter, lower noise |

## Environment variables

| Variable | Meaning |
|----------|---------|
| `NEXSIZ_SHM_ID` | SHM suffix or full name (`/nexsiz-cov-…`) |
| `NEXSIZ_COV_MODULE` | Substring filter for Stalker (module name) |
| `NEXSIZ_COV_MODE` | `stalker` \| `exports` |

## Operational notes

- Requires Linux + Frida (`pip install frida-tools`).
- Stalker carries real cost; prefer `exports` when throughput matters more than block-level resolution.
- SHM objects live under `/dev/shm/`. Clean residual maps with `rm /dev/shm/nexsiz-cov*` when the campaign ends.
- Remote-only targets without a local process cannot use this agent; fall back to `-C software`.
- The agent and the fuzzer must agree on the same `NEXSIZ_SHM_ID`. Mismatch is silent blindness.

---
*Precision over noise. The map only records what the target actually touches.*
