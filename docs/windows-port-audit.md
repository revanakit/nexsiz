# Windows Port Audit & Progress

**Date**: 2026-08-14  
**Author**: Revana / Grok  
**Status**: Phase 0–3 ✅  ·  Phase 4 pending  
**Scope**: Full inventory + platform abstraction for multi-OS support.

---

## Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Audit + skeleton traits | ✅ Complete |
| 1 | Linux SHM behind `SharedMemory` + wire into coverage | ✅ Complete |
| 2 | Windows File Mapping implementation | ✅ Complete |
| 3 | Process / crash detection hardening | ✅ Complete |
| 4 | Integration & edge cases | Pending |
| 5 | CI matrix + packaging | Pending |

---

## 1. Executive Summary

Nexsiz is a pure-Rust stateful network protocol fuzzer. Platform-specific primitives are isolated behind `crate::platform` (coverage) and thin `#[cfg]` gates (process detach).

**Phase 3 result**: Process spawn, monitor, NXS detach, and exit-code observation are parity-ready on Windows.

---

## 2. Shared Memory Naming (Agent Contract)

| Platform | Default name | With id |
|----------|--------------|---------|
| Linux | `/nexsiz-cov` | `/nexsiz-cov-<id>` |
| Windows | `Local\nexsiz-cov` | `Local\nexsiz-cov-<id>` |

---

## 3. Process / Crash Semantics (Phase 3)

| Concern | Linux | Windows |
|---------|-------|---------|
| Target spawn | `std::process::Command` | Same + `CREATE_NEW_PROCESS_GROUP` |
| NXS detach | `setsid()` via `pre_exec` | `CREATE_NEW_PROCESS_GROUP` (0x200) |
| Alive check | `Child::try_wait` | Same |
| Kill | SIGKILL via `Child::kill` | `TerminateProcess` via `Child::kill` |
| Crash indicator | `!status.success()` (exit or signal) | `!status.success()` (exit code only) |
| NXS signal death | Mapped to exit **4** | N/A (no POSIX signals) |
| NXS missing code | exit **1** | exit **1** |
| Secondary finding | exit **2** | exit **2** (unchanged) |

Job Objects were **not** introduced in v1: `CREATE_NEW_PROCESS_GROUP` is sufficient for console-detach parity and keeps the dependency surface zero.

---

## 4. Implementation Locations

| Component | Path |
|-----------|------|
| Traits + SHM | `src/platform/` |
| Process monitor | `src/execution/process_monitor.rs` |
| NXS spawn (detach) | `src/nxs/spawn.rs` |
| NXS reaper | `src/nxs/reaper.rs` |
| Coverage consumer | `src/coverage/map.rs` |

---

## 5. Phase Checklists

### Phase 0–2 ✅
- Abstraction + Linux SHM + Windows File Mapping

### Phase 3 ✅
- [x] NXS Windows process-group detach (`CREATE_NEW_PROCESS_GROUP`)
- [x] Process monitor Windows detach + documented crash semantics
- [x] Reaper Windows exit-code path clarified (no signal branch)
- [x] Portable unit test for process monitor
- [x] Linux behaviour unchanged

### Phase 4 (next)
- [ ] Path / output directory conventions on Windows
- [ ] Connection reuse edge cases
- [ ] End-to-end campaign smoke (HTTP/generic) on Windows
- [ ] Frida Windows agent note follow-up if needed

### Phase 5
- [ ] Unlock / extend `build.yml` with `windows-latest`
- [ ] Release packaging (portable zip)

---

## 6. Next Step

**Phase 4 — Integration & Edge Cases**

Validate full campaign paths on Windows (paths, connection reuse, NXS out dirs) and document any remaining operator notes.
