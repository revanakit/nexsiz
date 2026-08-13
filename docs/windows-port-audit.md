# Windows Port Audit & Progress

**Date**: 2026-08-13  
**Author**: Revana / Grok  
**Status**: Phase 0 ✅  ·  Phase 1 ✅  ·  Phase 2 ✅  ·  Phase 3 pending  
**Scope**: Full inventory + platform abstraction for multi-OS support.

---

## Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Audit + skeleton traits | ✅ Complete |
| 1 | Linux SHM behind `SharedMemory` + wire into coverage | ✅ Complete |
| 2 | Windows File Mapping implementation | ✅ Complete |
| 3 | Process / crash detection hardening | Pending |
| 4 | Integration & edge cases | Pending |
| 5 | CI matrix + packaging | Pending |

---

## 1. Executive Summary

Nexsiz is a pure-Rust stateful network protocol fuzzer. The majority of the codebase is portable. Platform-specific primitives are isolated behind `crate::platform`.

**Phase 2 result**: Windows grey-box coverage path is implemented via named File Mapping (`CreateFileMappingW` / `MapViewOfFile`). No extra crate was added — pure `extern "system"` FFI against `kernel32`.

---

## 2. Shared Memory Naming (Agent Contract)

| Platform | Default name | With id |
|----------|--------------|---------|
| Linux | `/nexsiz-cov` | `/nexsiz-cov-<id>` |
| Windows | `Local\nexsiz-cov` | `Local\nexsiz-cov-<id>` |

- Windows uses the **Local\\** namespace so no elevation is required.
- Frida / external agents must open the same name (UTF-16 on Windows).
- Objects are intentionally **not** destroyed on Drop so agents and subsequent runs can reattach.

---

## 3. Implementation Locations

| Component | Path |
|-----------|------|
| Traits | `src/platform/mod.rs` |
| Linux SHM | `src/platform/linux.rs` (`LinuxSharedMemory`) |
| Windows File Mapping | `src/platform/windows.rs` (`WindowsSharedMemory`) |
| Consumer | `src/coverage/map.rs` (`SharedMapCoverage`) |
| Compatibility wrapper | `src/coverage/shm.rs` (thin adapter) |

---

## 4. Portable Components (No Change Required)

- Semantic field model + hierarchical mutator
- Integrity repair pipeline
- Hybrid state tracker + predictor
- Plugin system
- Coverage provider trait + Null / Software providers
- Scripting / RPC bridges
- Core engine, workers, connection reuse
- NXS resolve / rate limiting / meta writer

---

## 5. Remaining Platform Work

### Phase 3 — Process / Crash Detection
- `std::process` already covers most spawn/wait/kill.
- Unix signal path is already `#[cfg(unix)]`.
- Optional: Job Objects for cleaner process-tree management on Windows.

### Phase 4 — Integration & Edge Cases
- Connection reuse, path handling, NXS detach semantics on Windows.
- End-to-end campaign validation.

### Phase 5 — CI & Packaging
- Unlock / extend `build.yml` with `windows-latest`.
- Portable zip / optional MSI.

---

## 6. Frida Agent Notes

- Linux agent continues to use POSIX SHM names.
- Windows agent must open `Local\nexsiz-cov` (or the id variant) via Windows File Mapping APIs / Frida’s Memory APIs.
- Layout remains AFL-style 64 KiB edge map; only the transport differs.

---

## 7. Risk Summary

| Risk | Severity | Mitigation |
|------|----------|------------|
| SHM semantics differ | Medium | Documented naming + Local\\ namespace |
| Frida agent divergence | Medium | Explicit agent contract above |
| Process group behaviour | Low | Feature-gate advanced detach (Phase 3) |
| Path separators | Low | Use `std::path` |
| Performance difference | Low | Benchmark when CI is unlocked |

---

## 8. Phase Checklists

### Phase 0 ✅
- [x] Inventory + abstraction design + skeleton

### Phase 1 ✅
- [x] Linux `SharedMemory` live
- [x] `SharedMapCoverage` consumes platform layer

### Phase 2 ✅
- [x] Windows `WindowsSharedMemory` via CreateFileMappingW / MapViewOfFile
- [x] Naming convention documented (`Local\nexsiz-cov[-<id>]`)
- [x] Zero extra crate dependency
- [x] Linux path untouched

### Phase 3 (next)
- [ ] Review process monitor + NXS spawn/reaper for Windows edge cases
- [ ] Optional Job Object support
- [ ] Confirm crash/hang detection parity

---

## 9. Next Step

**Phase 3 — Process Management & Crash Detection**

Audit and harden process spawn/monitor and NXS reaper for Windows, keeping Linux behaviour unchanged.
