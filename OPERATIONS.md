# Operations Guide — Nexsiz

Practical runbook for red-team / APT operators running Nexsiz campaigns.

This document assumes you already understand the high-level design (see `README.md`).
It focuses on **repeatable, safe, high-signal** operational practice.

---

## 1. Quick Start (Recommended Path)

```bash
# 1. Build
make release          # or: make release-full
make nxs              # official existence scripts

# 2. Verify
make status
make list-nxs

# 3. Minimal local campaign
make campaign-ftp

# 4. After campaign
make clean-shm
```

---

## 2. Build Variants

| Goal                         | Command                          |
|------------------------------|----------------------------------|
| Minimal / default            | `make release`                   |
| Full optional features       | `make release-full`              |
| Custom feature set           | `make release FEATURES=libafl,json-model` |
| Debug symbols                | `make debug`                     |
| NXS only                     | `make nxs`                       |

The default binary depends only on `libc`. Optional features never alter
behaviour when the corresponding CLI flags are not used.

---

## 3. Campaign Patterns

### 3.1 Local process under test (snapshot-enabled)

```bash
./target/release/nexsiz \
  -t "./mydaemon --port 2121" \
  -h 127.0.0.1 -p 2121 -m ftp \
  -Z --snapshot-backend process \
  -s sample/seeds/ftp -o output/ftp-local -v
```

- `-Z` enables snapshot.
- `process` backend = kill + respawn (no CRIU required).
- `criu` backend requires `--features criu` and `criu` on `PATH`.

### 3.2 Remote target (no snapshot)

```bash
./target/release/nexsiz \
  -h 10.0.0.5 -p 21 -m ftp \
  -s seeds/ftp -o output/ftp-remote \
  --nxs default -v
```

Prefer `-C software` when the target is remote-only (no local process for Frida).

### 3.3 Deep / intrusive campaign

```bash
make campaign-ftp NXS_SET=intrusive EXTRA_FLAGS='-O diffsan -C software -x 200000'
```

Or explicitly:

```bash
./target/release/nexsiz \
  -h 10.0.0.5 -p 21 -m ftp \
  --nxs intrusive --nxs-cooldown 60 \
  -O diffsan -C software -v
```

### 3.4 Protocol-specific notes

| Model   | Typical port | Notes                                      |
|---------|--------------|--------------------------------------------|
| ftp     | 21           | Strong integrity + auth-bypass NXS         |
| smtp    | 25           | CRLF + DATA terminator repair              |
| http    | 80 / 443     | Content-Length repair; consider TLS proxy  |
| dns     | 53           | Prefer `-P tcp` for length-prefix models   |
| mqtt    | 1883         | Remaining-length integrity                 |
| smb     | 445          | NetBIOS + SMB magic / command dictionary   |
| binary-lp / binary-lp-le | any | Generic length-prefix + optional CRC32 |

---

## 4. Coverage Workflows

### Software coverage (remote-friendly)
```bash
-C software
```

### Shared-memory + Frida agent
```bash
# Terminal 1 – start target under Frida with the agent
# (see agents/frida/README.md)

# Terminal 2
./target/release/nexsiz -h 127.0.0.1 -p ... -C map -S myid -v
# or: NEXSIZ_SHM_ID=myid
```

Always clean residual maps:
```bash
make clean-shm
# or: rm -f /dev/shm/nexsiz-cov*
```

---

## 5. NXS Operational Practice

- Default events: `crash`, `hang`.
- Sets: `default`, `crash`, `hang`, `safe`, `intrusive`, `external`, or concrete ids.
- Rate limits / cooldowns are conservative by design — tune with
  `--nxs-cooldown`, `--nxs-max-per-event`, `--nxs-max-total`.
- Exit code `2` from any NXS is treated as a secondary finding and written to
  `nxs-findings/secondary.jsonl`.
- Meta files live in `nxs-meta/`; per-event artefacts in `nxs-out/`.

Useful commands:
```bash
make list-nxs
make list-nxs NXS_SET=intrusive
./target/release/nexsiz --nxs default --nxs-list
```

Install NXS into the user search path:
```bash
make install-nxs   # → ~/.nexsiz/nxs/bin/
```

---

## 6. Model Inference

```bash
make infer-ftp
make infer SEED=seeds/custom OUT=models/inferred.json
# requires --features json-model for JSON output
```

Treat inferred models as a starting point; refine length/checksum/command
fields before long campaigns.

---

## 7. Output Layout (do not commit)

```
output/
├── crashes/          # crashing inputs (+ .min when minimised)
├── hangs/
├── nxs-meta/         # metadata JSON written before each NXS spawn
├── nxs-out/          # per-event NXS artefact trees
├── nxs-findings/     # secondary findings (JSONL)
└── queue/
```

Add `output/` to `.gitignore` (already present). Treat crash corpora as
sensitive.

---

## 8. House-keeping Checklist

After every campaign (or at the end of a shift):

```bash
make clean-shm
# optionally:
make clean-output
```

Full wipe (build artefacts + output + SHM):
```bash
make clean-all
```

---

## 9. Safety & Isolation

- Run only against systems you are authorised to test.
- Prefer dedicated VMs / containers / network namespaces.
- Non-root execution is strongly recommended.
- When using encryptors, keep real keys out of tracked config files.
- Snapshot / process monitoring implies the fuzzer can kill and restart the
  target process — ensure this is acceptable in the test environment.

See `SECURITY.md` for the formal policy.

---

## 10. Common Overrides (Makefile)

```bash
HOST=10.0.0.5
PORT=2121
MODEL=ftp
SEED=seeds/ftp
OUT=output/ftp-run1
WORKERS=8
TIMEOUT=800
NXS_SET=intrusive
EXTRA_FLAGS='-O diffsan -C software -x 500000'
FEATURES=libafl,json-model
```

Example:
```bash
make campaign-ftp HOST=10.0.0.5 PORT=2121 NXS_SET=intrusive \
  EXTRA_FLAGS='-O diffsan -C software'
```

---

## 11. Troubleshooting Quick Reference

| Symptom                        | Likely cause / action                                      |
|--------------------------------|------------------------------------------------------------|
| `-L` panics at startup         | Rebuild with `--features libafl` (serdeany_autoreg fixed) |
| No NXS found                   | `make nxs` then `make list-nxs`                            |
| Residual SHM maps              | `make clean-shm`                                           |
| Snapshot does nothing          | Need `-Z` **and** `-t/--cmd`                               |
| CRIU backend fails             | Install `criu`, build with `--features criu`               |
| Remote coverage flat           | Use `-C software` instead of `map`                         |
| Connection reuse contamination | Add `-n` / `--no-reuse` for diagnosis                      |

---

*This guide is intentionally concise. For design rationale and full CLI
reference see `README.md`. For NXS contract details see `nxs/CONTRACT.md`.*
