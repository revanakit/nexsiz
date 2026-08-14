# Windows Port Audit & Progress

**Date**: 2026-08-14  
**Author**: Revana / Grok  
**Status**: Phase 0–4 ✅  ·  Phase 5 pending  
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
| 5 | CI matrix + packaging | Pending (`build.yml` locked) |

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

## Remaining (Phase 5)

- Unlock / extend `.github/workflows/build.yml` with `windows-latest`
- Release asset: portable zip of `nexsiz.exe`
- Optional: Windows Frida agent script
- Optional: named-pipe RPC transport

---

## Architecture reminder

```
SharedMapCoverage → platform::current().create_coverage_map()
                      ├── Linux:  POSIX SHM
                      └── Windows: File Mapping (Local\nexsiz-cov*)

NXS / target spawn → CREATE_NEW_PROCESS_GROUP (Windows)
                  → setsid() (Unix)
```
