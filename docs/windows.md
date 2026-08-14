# Nexsiz on Windows — Operator Guide

**Status**: Phase 0–4 complete (core port). CI packaging is Phase 5.

---

## Quick start

```powershell
# Build (MSVC toolchain recommended)
cargo build --release

# Minimal HTTP-ish campaign against a local service
.\target\release\nexsiz.exe -h 127.0.0.1 -p 80 -m generic -s seeds\generic -o out\win -v

# With grey-box map coverage (in-process synthetic edges always work;
# external Frida hits require a Windows-aware agent)
.\target\release\nexsiz.exe -h 127.0.0.1 -p 21 -m ftp -C map --shm demo -v
```

---

## Coverage shared memory

| Platform | Default name | With id |
|----------|--------------|---------|
| Linux | `/nexsiz-cov` | `/nexsiz-cov-<id>` |
| Windows | `Local\nexsiz-cov` | `Local\nexsiz-cov-<id>` |

Pass the same id via `--shm <id>` / `NEXSIZ_SHM_ID`. The fuzzer creates a pagefile-backed File Mapping; Frida agents must open the matching `Local\...` name.

> The stock `agents/frida/nexsiz_cov.js` targets POSIX SHM. Until a Windows agent variant is published, `-C map` still provides hybrid synthetic response edges; external Stalker hits need the Windows agent.

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

Created under `-o` / `output_dir` via `Path::join` (Windows-correct separators):

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
- Crash detection uses non-zero exit codes (`Child::kill` → `TerminateProcess`).
- There are no POSIX signals; the reaper maps missing codes to operational exit `1`. Exit `2` remains the secondary-finding contract.

---

## Connection reuse

TCP/UDP connectors use `std::net` only — fully portable. Reuse policy is protocol-code based and identical on Windows.

---

## Known limits (v1)

| Feature | Windows status |
|---------|----------------|
| Grey-box SHM map | ✅ File Mapping |
| Frida external agent | ⚠️ Needs Windows agent script |
| Process monitor / NXS | ✅ |
| CRIU snapshot | ❌ Linux-only (`--features criu`) |
| Process snapshot backend | ✅ kill+respawn |
| Python RPC (`-Y` Unix socket) | ⚠️ Unix domain sockets; prefer Linux or a future named-pipe transport |
| `libafl` feature | Optional; LibAFL itself supports Windows |

---

## Smoke checklist

1. `cargo build --release` on `x86_64-pc-windows-msvc`
2. Campaign against a local TCP service with `-m generic` or `-m http`
3. Confirm `out\...\crashes` / `nexsiz.log` are created
4. Optional: `-C map --shm demo` and verify log line `coverage SHM attached: Local\nexsiz-cov-demo`
5. Optional: `--nxs-list` with a Windows `NEXSIZ_NXS_PATH`

---

*Precision over noise · depth over breadth*
