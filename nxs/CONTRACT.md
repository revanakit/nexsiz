# NXS Contract — Nexsiz Existence Scripts

**Version:** 0.1  
**Status:** Binding for all official and custom NXS  
**Parent:** Nexsiz (stateful network protocol fuzzer)

> Breaking changes to this contract will increment the major version number.  
> Additive clarifications and new optional fields remain compatible within the same major version.

NXS are **executable programs** (binary or `chmod +x` script) triggered after an interesting event (crash, hang, interesting, new_coverage, new_state). They are actors, not passive handlers.

---

## 1. Invocation

```
nxs-<name> [GLOBAL OPTIONS] [SCRIPT-SPECIFIC OPTIONS]
```

### Global options (mandatory support)

| Option | Required | Description |
|--------|----------|-------------|
| `--crash <path>` | Yes* | Path to the input that caused the event |
| `--target <host:port>` | Yes* | e.g. `10.0.0.5:21` |
| `--event <type>` | No | `crash` \| `hang` \| `interesting` \| `new_coverage` \| `new_state` (default: `crash`) |
| `--model <name>` | No | Protocol model (`ftp`, `http`, `smtp`, `generic`, …) |
| `--minimized <path>` | No | Path to minimised version of the crash input |
| `--meta <path>` | No | JSON metadata file written by Nexsiz |
| `--out <dir>` | No | Directory for NXS artefacts |
| `--timeout <secs>` | No | Internal timeout |
| `--verbose` / `-v` | No | Human-readable log to stderr |
| `--help` / `-h` | Yes | Usage |
| `--version` | Yes | Version + stable id |

\* At least one of `--crash` or `--meta` must be present. When `--meta` contains `crash.path` and `target`, those fields may be populated from the meta file.

---

## 2. Exit Codes (mandatory)

| Code | Meaning |
|------|---------|
| 0 | Completed normally, no further vulnerability indication |
| 1 | Operational error (missing file, unreachable target, invalid args) |
| 2 | Indication of further vulnerability / successful exploit-assist → **escalate** |
| 3 | Internal timeout |
| 4 | Interrupted / cancelled |
| ≥10 | Script-specific success variants (document in header / nxs.toml) |

---

## 3. Metadata JSON (`--meta`)

Nexsiz writes this file on spawn (or the operator supplies it). NXS **must** ignore unknown fields.

Minimal schema:

```json
{
  "nexsiz_version": "0.1.0",
  "event": "crash",
  "timestamp": 1722912345.123,
  "target": {
    "host": "10.0.0.5",
    "port": 21,
    "protocol": "tcp"
  },
  "model": "ftp",
  "crash": {
    "id": "id_000042",
    "path": "output/crashes/id_000042",
    "minimized_path": "output/crashes/id_000042.min",
    "input_len": 48
  },
  "result": {
    "outcome": "crash",
    "error": "Connection reset by peer",
    "elapsed_ms": 87,
    "coverage_hits": 12,
    "new_state": true,
    "response_codes": [220, 331, 230]
  },
  "worker_id": 3,
  "corpus_id": 42,
  "output_dir": "output"
}
```

---

## 4. Output Artefacts (recommended when `--out` is given)

```
<out>/
├── report.json
├── repro/
├── logs/
└── artifacts/
```

Suggested `report.json` fields (example of a successful secondary finding):

```json
{
  "nxs_id": "crash/auto-repro",
  "nxs_version": "1.0.0",
  "exit_hint": 2,
  "summary": "Repro confirmed; service dies on refined input after 3 deterministic shots",
  "findings": [
    {
      "type": "reproducible_crash",
      "confidence": "high",
      "detail": "Connection reset on refined payload"
    }
  ],
  "artifacts": ["repro/refined.bin", "logs/shot-01.txt"],
  "target": "10.0.0.5:21",
  "crash_id": "id_000042",
  "shots": 3,
  "elapsed_ms": 412
}
```

---

## 5. Stdio

- **stdout** — concise; optional single JSON line at the end (machine-friendly)
- **stderr** — human log, progress, errors (`-v`)
- **stdin** — not required; `--meta -` may read meta from stdin

---

## 6. Identity (`--version` / `nxs.toml`)

| Field | Example |
|-------|---------|
| `id` | `crash/auto-repro` |
| `name` | `auto-repro` |
| `version` | `1.0.0` |
| `categories` | `crash,safe,default` |
| `events` | `crash,hang` |
| `description` | one paragraph |

---

## 7. Checklist (every NXS must)

- [ ] Executable (`chmod +x` / `.exe`)
- [ ] Support `--crash`, `--target`, `--meta`, `--out`, `--help`, `--version`
- [ ] Honour exit-code table above
- [ ] Ignore unknown meta fields
- [ ] Do not block on stdin without reason
- [ ] Possess a stable `id` (category/name)

Recommended:

- [ ] Write `report.json` when `--out` is supplied
- [ ] Human log to stderr with `-v`
- [ ] Internal timeout
- [ ] Short `README.md` / `nxs.toml`

---

## 8. Search Path Priority (Nexsiz side)

1. Absolute path given to `--nxs`
2. `NEXSIZ_NXS_PATH` (colon-separated)
3. `~/.nexsiz/nxs/bin/`
4. `./nxs/bin/` (cwd)
5. Official `nxs/bin/` (relative to install prefix / source tree)

---
