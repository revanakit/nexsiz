# Nexsiz on Windows — Operator Guide

**Status**: Phase 0–5 complete (core port + Frida agent + CI packaging).

---

## Quick start

```powershell
# Build (MSVC toolchain recommended)
cargo build --release

# Or download from Actions artifacts:
#   nexsiz-windows-x86_64-default  /  nexsiz-windows-x86_64-libafl
#   nexsiz-release-packages-windows  (zip with agent + docs)

# Minimal campaign against a local service
.\target\release\nexsiz.exe -h 127.0.0.1 -p 80 -m generic -s seeds\generic -o out\win -v

# Grey-box map + Frida (same script works on Windows and Linux)
$env:NEXSIZ_SHM_ID = "demo"
frida -l agents\frida\nexsiz_cov.js -f .\mydaemon.exe
# other terminal:
.\target\release\nexsiz.exe -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -v
```

---

## CI artifacts (Phase 5)

| Artifact | Contents |
|----------|----------|
| `nexsiz-windows-x86_64-default` | `nexsiz.exe` (no LibAFL) |
| `nexsiz-windows-x86_64-libafl` | `nexsiz.exe` + LibAFL (`-L`) |
| `nexsiz-windows-x86_64-json-model` | JSON protocol models |
| `nexsiz-windows-x86_64-libafl-json` | LibAFL + JSON |
| `nexsiz-release-packages-windows` | Zip archives with `nexsiz.exe`, Frida agent, `docs/windows.md`, notes |

Linux packages continue to ship prebuilt NXS binaries. Windows packages ship the agent and docs; place your own `nxs-*.exe` under `nxs\bin` or set `NEXSIZ_NXS_PATH`.

---

## Snapshot backends

| Backend | Windows | Notes |
|---------|---------|-------|
| `process` (default with `-Z`) | ✅ | Kill + respawn target via `target_cmd` |
| `criu` | ❌ | **Linux-only** — CRIU uses Linux kernel C/R APIs |
| `null` | ✅ | No snapshot |

On Windows always use `--snapshot-backend process` (or omit; it is the default when `-Z` is set).

---

## Coverage shared memory

| Platform | Default name | With id |
|----------|--------------|---------|
| Linux | `/nexsiz-cov` | `/nexsiz-cov-<id>` |
| Windows | `Local\nexsiz-cov` | `Local\nexsiz-cov-<id>` |

Pass the same id via `--shm <id>` / `NEXSIZ_SHM_ID`.

The Frida agent (`agents/frida/nexsiz_cov.js`) is **cross-platform**: it detects `Process.platform` and opens POSIX SHM on Linux or `OpenFileMappingW` / `MapViewOfFile` on Windows.

---

## NXS search path

| | Unix | Windows |
|---|------|--------|
| Separator | `:` | `;` |
| Example | `/opt/nxs/bin:~/.nexsiz/nxs/bin` | `C:\tools\nxs\bin;%USERPROFILE%\.nexsiz\nxs\bin` |
| Home dir | `$HOME` | `%USERPROFILE%` (fallback if `HOME` unset) |
| Binary suffix | mode bit `+x` | `.exe` / `.cmd` / `.bat` also tried |

```powershell
$env:NEXSIZ_NXS_PATH = "C:\tools\nxs\bin;D:\lab\nxs\bin"
.\nexsiz.exe --nxs default --nxs-list
```

---

## Output layout

```
output\
  nexsiz.log
  crashes\
  hangs\
  queue\
  nxs-meta\      (if --nxs)
  nxs-out\
  nxs-findings\
  snapshot\      (if -Z)
```

---

## Process & crash behaviour

- Target and NXS children use `CREATE_NEW_PROCESS_GROUP` so console Ctrl-C on the fuzzer does not always cascade.
- Crash detection uses non-zero exit codes (`TerminateProcess`).
- No POSIX signals; reaper maps missing codes to exit `1`. Exit `2` = secondary finding.

---

## Known limits (v1)

| Feature | Windows status |
|---------|----------------|
| Grey-box SHM map | ✅ File Mapping |
| Frida external agent | ✅ Cross-platform `nexsiz_cov.js` |
| Process monitor / NXS | ✅ |
| CRIU snapshot | ❌ Linux-only |
| Process snapshot backend | ✅ kill+respawn |
| Python RPC (`-Y` Unix socket) | ⚠️ Prefer Linux; named-pipe transport later |
| `libafl` feature | ✅ Optional (CI builds it) |
| Official NXS prebuilts in Windows zip | ❌ Build locally or supply your own `.exe` |

---

## Smoke checklist

1. `cargo build --release` on `x86_64-pc-windows-msvc` **or** download CI artifact
2. Campaign with `-m generic` or `-m http`
3. Confirm `out\...\crashes` / `nexsiz.log`
4. `-C map --shm demo` → log: `coverage SHM attached: Local\nexsiz-cov-demo`
5. Frida agent → log: `SHM attached (Windows): Local\nexsiz-cov-demo`
6. Optional: `--nxs-list` with Windows `NEXSIZ_NXS_PATH`

---

*Precision over noise · depth over breadth*
