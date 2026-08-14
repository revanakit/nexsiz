# Windows Port Audit & Progress

**Date**: 2026-08-14  
**Author**: Revana / Grok  
**Status**: Phase 0–5 ✅  
**Operator guide**: [windows.md](windows.md)

---

## Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Audit + skeleton traits | ✅ |
| 1 | Linux SHM behind `SharedMemory` | ✅ |
| 2 | Windows File Mapping | ✅ |
| 3 | Process / crash detection | ✅ |
| 4 | Integration & edge cases | ✅ |
| 5 | CI matrix + packaging | ✅ |

---

## Phase 4 changes

| Issue | Fix |
|-------|-----|
| `ensure_dirs` used `format!("{}/…")` | `PathBuf::join` for crashes/hangs/queue/nxs-* |
| `NEXSIZ_NXS_PATH` split on `:` | `;` on Windows (protects `C:\...`) |
| Home dir only `HOME` | Fallback `USERPROFILE` |
| NXS binary discovery | Also try `.exe` / `.cmd` / `.bat` |
| Path joins in search dirs | `Path::join` throughout resolver |
| Operator docs | `docs/windows.md` |

Connection reuse / TCP / UDP were already portable (`std::net`) — no code change required.

---

## Phase 5 changes

| Item | Detail |
|------|--------|
| `libc` dependency | Moved to `[target.'cfg(unix)'.dependencies]` — MSVC builds no longer pull POSIX crate |
| Workflow | `.github/workflows/build.yml` activated (was `.locked`) |
| Windows jobs | `build-windows-default`, `-libafl`, `-json-model`, `-libafl-json` on `windows-latest` (x86_64-pc-windows-msvc) |
| Packaging | `package-windows` produces `nexsiz-windows-x86_64-*-version-(0.1.0).zip` with `nexsiz.exe` + Frida agent + operator notes |
| Linux packaging | Unchanged; still ships NXS prebuilts |
| NXS on Windows | Not prebuilt in CI (POSIX scripts); operator builds or places `nxs-*.exe` under `nxs\bin` / `NEXSIZ_NXS_PATH` |

Artifacts (Actions):

- `nexsiz-windows-x86_64-default`
- `nexsiz-windows-x86_64-libafl`
- `nexsiz-windows-x86_64-json-model`
- `nexsiz-windows-x86_64-libafl-json`
- `nexsiz-release-packages-windows` (zip archives)

---

## Architecture reminder

```
SharedMapCoverage → platform::current().create_coverage_map()
                      ├── Linux:  POSIX SHM
                      └── Windows: File Mapping (Local\nexsiz-cov*)

NXS / target spawn → CREATE_NEW_PROCESS_GROUP (Windows)
                  → setsid() (Unix)
```

---

## Optional follow-ups (post-Phase 5)

- Windows Frida agent packaging notes (already cross-platform JS)
- Named-pipe RPC transport for `-Y` on Windows
- Prebuilt NXS `.exe` matrix (if operator demand rises)
