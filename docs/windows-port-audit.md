# Windows Port Audit — Phase 0

**Date**: 2026-08-13  
**Author**: Revana / Grok  
**Status**: Complete  
**Scope**: Full inventory of platform-specific code required for Windows support.

---

## 1. Executive Summary

Nexsiz is currently a **Linux-primary** pure-Rust fuzzer. The majority of the codebase (semantic mutation, integrity repair, state tracking, plugins, NXS logic, scripting) is already portable. Only a small set of modules interact with OS primitives that differ significantly on Windows.

**Key finding**: No full rewrite is required. An abstraction layer + Windows implementations of 4–5 components will suffice.

---

## 2. Inventory of Linux-Specific Code

### 2.1 Coverage / Shared Memory (`src/coverage/shm.rs`)

| Item | Current Implementation | Windows Equivalent |
|------|------------------------|--------------------|
| Creation / Open | `libc::shm_open` + `O_CREAT\|O_EXCL` | `CreateFileMappingW` / `OpenFileMappingW` |
| Size | `ftruncate` | `CreateFileMapping` size parameter |
| Mapping | `mmap(..., MAP_SHARED, PROT_READ\|PROT_WRITE)` | `MapViewOfFile` |
| Unmap | `munmap` + `close` | `UnmapViewOfFile` + `CloseHandle` |
| Naming | `/nexsiz-cov` or `/nexsiz-cov-<id>` | `Global\\nexsiz-cov-<id>` or `Local\\...` |
| Cleanup | Intentionally **no** `shm_unlink` on Drop | No automatic unlink; operator cleans named objects |

**Impact**: High. This is the grey-box coverage path used by the Frida agent.

**Notes**:
- Frida on Windows already supports shared memory / custom agents.
- Prefer named file mapping over pagefile-backed for cross-process visibility with Frida.

### 2.2 Process Monitoring (`src/execution/process_monitor.rs`)

| Item | Current | Windows |
|------|---------|---------|
| Spawn | `std::process::Command` (works) | Same (`Command` is cross-platform) |
| Wait non-blocking | `Child::try_wait` | Same |
| Kill | `Child::kill` | Same |
| Crash detection | Exit status + Unix signal via `ExitStatusExt` | `GetExitCodeProcess` + structured exception if needed |

**Impact**: Low–Medium. `std::process` already abstracts most of this. Only the Unix-specific signal path in the reaper needs attention.

### 2.3 NXS Spawn & Reaper (`src/nxs/spawn.rs`, `src/nxs/reaper.rs`)

| Item | Current | Windows |
|------|---------|---------|
| Detach / new session | `libc::setsid()` via `pre_exec` (Unix only) | `CREATE_NEW_PROCESS_GROUP` or Job Objects |
| Exit code observation | `Child::try_wait` + `status.code()` | Same |
| Signal termination | `#[cfg(unix)]` + `ExitStatusExt::signal()` | Treat as non-zero / map to exit 4 |
| Background reaper | Thread + `mpsc` + `try_wait` every 250 ms | Fully portable |

**Impact**: Low. Already mostly portable; only the `setsid` and signal handling need Windows equivalents.

### 2.4 Snapshot / CRIU (`src/execution/snapshot/`)

- CRIU is Linux-only (feature-gated).
- On Windows this path can remain a no-op or be replaced later by process snapshot APIs if desired.
- **Decision for v1**: Keep `criu` feature Linux-only; Windows uses null / process restart strategy.

### 2.5 Other Occurrences

- `src/nxs/reaper.rs`: explicit `#[cfg(unix)]` for signal handling — already correctly gated.
- `src/nxs/spawn.rs`: `#[cfg(unix)]` for `setsid` — already gated.
- No heavy use of `/proc`, `pidfd_*`, cgroup, or other Linux-only syscalls in the hot path beyond the SHM module.
- Frida agent (`agents/frida/nexsiz_cov.js`) currently assumes POSIX SHM name layout.

---

## 3. Portable Components (No Change Required)

- Semantic field model + hierarchical mutator (`src/input/`)
- Integrity repair pipeline
- Hybrid state tracker + predictor (`src/state/`)
- Plugin system (Protocol / Integrity / Oracle / Encryptor)
- Coverage provider trait + Null / Software / Map providers
- Scripting / RPC bridges
- Core engine, workers, connection reuse (TCP)
- Configuration, logging, minimizer, oracle orchestration
- NXS resolve / rate limiting / meta writer (pure logic)

---

## 4. Recommended Abstraction Surface (Phase 1)

```rust
// src/platform/mod.rs (sketch)

pub trait SharedMemory: Send + Sync {
    fn name(&self) -> &str;
    fn clear(&self);
    fn snapshot(&self) -> Vec<u8>;
    fn get(&self, idx: usize) -> u8;
    fn as_mut_ptr(&self) -> *mut u8; // for advanced use
}

pub trait PlatformServices: Send + Sync {
    fn create_coverage_map(&self, id: Option<&str>) -> Result<Box<dyn SharedMemory>, String>;
    // future: process group / job object helpers if needed
}

pub fn current() -> &'static dyn PlatformServices;
```

- Linux implementation moves existing `ShmMap` behind the trait.
- Windows implementation uses File Mapping APIs.
- Coverage registry resolves the correct provider based on `target_os` or explicit config.

---

## 5. Frida Agent Considerations

- Current agent (`agents/frida/nexsiz_cov.js`) hard-codes POSIX SHM naming.
- Windows agent must open the equivalent named mapping.
- Frida’s Windows support is mature; we only need a Windows-specific variant of the coverage writer or a portable naming scheme.

---

## 6. Build & CI Notes (for later phases)

- Add `x86_64-pc-windows-msvc` (and optionally `x86_64-pc-windows-gnu`) to CI matrix.
- `libc` crate is already present and works on Windows (provides some compatibility).
- Prefer pure `windows` crate or `winapi` only where necessary; keep surface minimal.
- Feature flags: keep `libafl` and `criu` as-is; `criu` remains Linux-only.

---

## 7. Risk Summary

| Risk | Severity | Mitigation |
|------|----------|------------|
| SHM semantics differ (permissions, lifetime) | Medium | Explicit named objects + documentation |
| Frida agent divergence | Medium | Dual agent or portable naming |
| Process group / job object behaviour | Low | Feature-gate advanced detach |
| Path separators / long paths | Low | Use `std::path` consistently |
| Performance of File Mapping vs POSIX SHM | Low | Benchmark in Phase 2 |

---

## 8. Phase 0 Deliverables Checklist

- [x] Full inventory of Linux-specific APIs
- [x] Mapping to Windows equivalents
- [x] Identification of portable vs non-portable modules
- [x] Proposed abstraction surface
- [x] Risk register
- [ ] Skeleton `src/platform/` module (next commit)
- [ ] Update `Cargo.toml` / toolchain notes if needed

---

## 9. Next Step

Proceed to **Phase 1 — Platform Abstraction Layer**:
1. Create `src/platform/` with traits.
2. Move existing Linux SHM behind the trait.
3. Ensure zero regression on Linux.
4. Add Windows stub that returns a clear “not yet implemented” error (or soft null coverage).

This document will be updated as implementation progresses.
