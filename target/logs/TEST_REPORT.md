# Nexsiz Systematic Test Report — Snapshot + Process Target + Coverage SHM
**Date:** 2026-08-12  
**Binary:** artifacts/nexsiz (v0.1.0) executed via /tmp (artifacts fuse is noexec)  
**Target:** crashable_server.py (FTP-like, CRASH/HANG triggers) on 127.0.0.1:2121

## Test Matrix

| # | Scenario | Flags | Result | Key Metrics |
|---|----------|-------|--------|-------------|
| 01 | Baseline process monitor | `-t ...` (no -Z) | PASS | Process monitor active, crashes/hangs detected, restores=0 |
| 02 | Snapshot + process backend | `-t ... -Z --snapshot-backend process` | PASS | Snapshot provider: process; restores: 7; snap: process |
| 03 | Coverage SharedMap | `-C map -t ...` | PASS | SHM `/nexsiz-cov` attached; cov_edges: 15; provider=map+shm |
| 04 | Coverage + explicit SHM id | `-C map -S test42` | PASS | SHM `/nexsiz-cov-test42` (64 KiB); cov_edges: 6 |
| 05 | Combined (snapshot+SHM) | `-t -Z process -C map -S combined1` | PASS | Both providers active; multiple restore cycles; SHM attached |
| 06 | Coverage software | `-C software` | PASS | Coverage provider: software; cov_edges: 22 |

## Observations

1. **Snapshot requires `-t/--cmd`**. Without it: `snapshot=true but no target_cmd; snapshot disabled (null)`.
2. **Process backend** correctly detects network-observed crashes, kills/respawns target, bumps restore_epoch → workers reconnect.
3. **Coverage SHM** is POSIX 64 KiB AFL-style map. Default name `/nexsiz-cov`, with `-S <id>` → `/nexsiz-cov-<id>`. Visible under `/dev/shm/`.
4. **Combined operation** is stable: snapshot restores and coverage map operate concurrently without interference.
5. Software coverage provider also functional (no SHM required).
6. CRIU backend not tested (criu not present in environment).

## Log Locations
All under `artifacts/nexsiz-test/logs/`:
- 01_baseline_nexsiz.log
- 02_snapshot_process.log
- 03_cov_map.log
- 04_cov_shm_id.log
- 05_combined.log
- 06_cov_software.log
- TEST_REPORT.md (this file)

## Command Templates (operational)

```bash
# Snapshot + process target
./nexsiz -h 127.0.0.1 -p 2121 -m ftp -s seeds -o out \
  -t "./target" -Z --snapshot-backend process -v

# Coverage SHM (Frida-ready)
./nexsiz ... -C map -S myid -v
# External agent attaches to /nexsiz-cov-myid (64 KiB)

# Full stack
./nexsiz ... -t "./target" -Z --snapshot-backend process -C map -S run1 -v
```
