# Windows Port Audit & Progress

**Date**: 2026-08-13  
**Author**: Revana / Grok  
**Status**: Phase 0 ✅  ·  Phase 1 ✅  ·  Phase 2 pending  
**Scope**: Full inventory + platform abstraction for multi-OS support.

---

## Current Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Audit + skeleton traits | ✅ Complete |
| 1 | Linux SHM behind `SharedMemory` + wire into coverage | ✅ Complete |
| 2 | Windows File Mapping implementation | Pending |
| 3 | Process / crash detection hardening | Pending |
| 4 | Integration & edge cases | Pending |
| 5 | CI matrix + packaging | Pending |

---

## 1. Executive Summary

Nexsiz is currently a **Linux-primary** pure-Rust fuzzer. The majority of the codebase is already portable. Only a small set of modules interact with OS primitives that differ significantly on Windows.

**Key finding**: No full rewrite is required. An abstraction layer + Windows implementations of 4–5 components will suffice.

**Phase 1 result**: Coverage path now goes through `platform::current().create_coverage_map()`. Linux behaviour is unchanged; the path is ready for a Windows implementation.

---

## 2. Inventory of Linux-Specific Code

### 2.1 Coverage / Shared Memory

| Item | Current (Linux) | Windows Equivalent |
|------|-----------------|--------------------|
| Creation / Open | `libc::shm_open` | `CreateFileMappingW` / `OpenFileMappingW` |
| Size | `ftruncate` | size parameter to CreateFileMapping |
| Mapping | `mmap(MAP_SHARED)` | `MapViewOfFile` |
| Unmap | `munmap` + `close` | `UnmapViewOfFile` + `CloseHandle` |
| Naming | `/nexsiz-cov[-<id>]` | `Global\\nexsiz-cov-<id>` or `Local\\...` |
| Cleanup | No automatic unlink | No automatic unlink |

**Location after Phase 1**: `src/platform/linux.rs` (`LinuxSharedMemory`).

### 2.2 Process Monitoring (`src/execution/process_monitor.rs`)

Mostly portable via `std::process`. Unix signal path is already `#[cfg(unix)]`.

### 2.3 NXS Spawn & Reaper

`setsid` and signal handling already gated with `#[cfg(unix)]`. Background reaper is fully portable.

### 2.4 Snapshot / CRIU

Feature-gated, Linux-only. Remains Linux-only for v1.

---

## 3. Portable Components (No Change Required)

- Semantic field model + hierarchical mutator
- Integrity repair pipeline
- Hybrid state tracker + predictor
- Plugin system
- Coverage provider trait + Null / Software providers
- Scripting / RPC bridges
- Core engine, workers, connection reuse
- NXS resolve / rate limiting / meta writer

---

## 4. Abstraction Surface (Live)

```rust
// src/platform/mod.rs
pub trait SharedMemory: Send + Sync { ... }
pub trait PlatformServices: Send + Sync {
    fn create_coverage_map(&self, id: Option<&str>) -> Result<Box<dyn SharedMemory>, PlatformError>;
}
pub fn current() -> &'static dyn PlatformServices;
```

- Linux: full implementation (`LinuxSharedMemory`)
- Windows: stub (returns clear error until Phase 2)
- `SharedMapCoverage` now holds `Option<Box<dyn SharedMemory>>`

---

## 5. Frida Agent Considerations

- Current agent assumes POSIX SHM naming.
- Windows agent will need the equivalent named mapping.
- Frida Windows support is mature.

---

## 6. Build & CI Notes

- `build.yml` is currently locked by the operator until the port is stable.
- Later: add `windows-latest` to the matrix.
- `criu` feature remains Linux-only.

---

## 7. Risk Summary

| Risk | Severity | Mitigation |
|------|----------|------------|
| SHM semantics differ | Medium | Explicit named objects + docs |
| Frida agent divergence | Medium | Dual agent or portable naming |
| Process group behaviour | Low | Feature-gate advanced detach |
| Path separators | Low | Use `std::path` |
| Performance difference | Low | Benchmark in Phase 2 |

---

## 8. Phase Checklists

### Phase 0 ✅
- [x] Inventory
- [x] Mapping to Windows equivalents
- [x] Abstraction surface design
- [x] Skeleton `src/platform/`

### Phase 1 ✅
- [x] Full Linux `SharedMemory` implementation in `platform/linux.rs`
- [x] `SharedMapCoverage` consumes `platform::SharedMemory`
- [x] `coverage/shm.rs` reduced to thin compatibility wrapper
- [x] Zero behavioural change expected on Linux

### Phase 2 (next)
- [ ] Implement Windows File Mapping in `platform/windows.rs`
- [ ] Validate coverage map with Frida on Windows
- [ ] Document naming conventions for agents

---

## 9. Next Step

**Phase 2 — Windows Shared Memory + Coverage**

Implement `WindowsSharedMemory` using `CreateFileMapping` / `MapViewOfFile`, wire it through the existing trait, and keep the Linux path untouched.
