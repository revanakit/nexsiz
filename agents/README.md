**Nexsiz Frida Coverage Agent**

External grey-box instrumentation for Nexsiz.

The agent injects an AFL-style 64 KiB edge map into a platform shared-memory region. Nexsiz’s `SharedMapCoverage` provider (`-C map`) owns the region, clears it before every execution, and harvests the hits afterward.

**One script, both platforms** — `nexsiz_cov.js` detects `Process.platform` and opens the correct transport automatically.

**SHM protocol**

| Field | Value |
|-------|--------|
| Size | 65536 bytes |
| Cell | `u8` saturating hit count |
| Edge | `(prev >> 1) ^ cur` (AFL classic) |

**Naming by platform**

| Platform | Default name | With id |
|----------|--------------|---------|
| **Linux** | `/nexsiz-cov` | `/nexsiz-cov-<id>` |
| **Windows** | `Local\nexsiz-cov` | `Local\nexsiz-cov-<id>` |

Nexsiz creates/attaches the region. The Frida agent opens the **same name** and increments cells. Between executions Nexsiz zeroes the map.

**Quick start (Linux)**

```text
export NEXSIZ_SHM_ID=demo
export NEXSIZ_COV_MODULE=mydaemon   # optional
frida -l agents/frida/nexsiz_cov.js -f ./mydaemon --no-pause

export NEXSIZ_SHM_ID=demo
./target/release/nexsiz -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -v
```

**Quick start (Windows)**

```text
$env:NEXSIZ_SHM_ID = "demo"
$env:NEXSIZ_COV_MODULE = "mydaemon"   # optional
frida -l agents/frida/nexsiz_cov.js -f .\mydaemon.exe

$env:NEXSIZ_SHM_ID = "demo"
.\target\release\nexsiz.exe -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -v
```

On success the agent logs:

```
[nexsiz-cov] SHM attached (Windows): Local\nexsiz-cov-demo @ 0x...
[nexsiz-cov] agent ready on windows — Nexsiz can now collect grey-box edges
```

**Modes**

| `NEXSIZ_COV_MODE` | Behaviour |
|------------------|-----------|
| `stalker` (default) | Basic-block edge coverage via Frida Stalker |
| `exports` | Interceptor on recv/read/send/parse-like exports (includes `WSARecv` / `WSASend` on Windows) |

**Environment variables**

| Variable | Meaning |
|----------|---------|
| `NEXSIZ_SHM_ID` | SHM suffix or full name |
| `NEXSIZ_COV_MODULE` | Substring filter for Stalker (module name) |
| `NEXSIZ_COV_MODE` | `stalker` \| `exports` |

**Operational notes**

- **Linux**: POSIX SHM under `/dev/shm/`. Clean with `rm /dev/shm/nexsiz-cov*` when done.
- **Windows**: Named File Mapping in the `Local\` namespace (no elevation required). Object is not destroyed on process exit so both sides can reattach.
- Prefer `exports` when throughput matters more than block-level resolution.
- Remote-only targets without a local process cannot use this agent; fall back to `-C software`.
- The agent and the fuzzer must agree on the same `NEXSIZ_SHM_ID`.

---
*Precision over noise. The map only records what the target actually touches.*
