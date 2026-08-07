# Protocol Expansion Track — Complete

**Branch:** `feature/protocol-phase3-v2`  
**Date:** 2026-08-07

## Scope closed

| Feature | Status |
|---------|--------|
| Phase 1 built-ins + JSON models | on main |
| Phase 2 `--infer-model` + field-aware mutation | on main |
| Phase 3 directed scheduling + templates | this PR |
| Field energy feedback | done |
| `template_prob=` config | done |
| Sequence templates | done |

## Field energy feedback

- `mutate()` records touched fields in `last_touched`
- Worker calls `mutator.on_interesting()` when result is interesting
- Energy (cap 64) multiplies base weight: `w * (1 + energy)`

## Config

```
template_prob=0.12
hierarchical_prob=0.15
field_prob=0.70
dict_prob=0.25
max_mutations=8
```

## Sequences

| Model | Sequences |
|-------|-----------|
| `ftp` | `login`, `session` |
| `mqtt` | `connect-publish` |

API: `Mutator::synthesise_sequence("login")`
