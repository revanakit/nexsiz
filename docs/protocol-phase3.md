# Protocol Expansion Track — Complete

**Branch:** `feature/protocol-phase3`  
**Date:** 2026-08-07

## Scope closed

| Feature | Status |
|---------|--------|
| Phase 1 built-ins + JSON models | merged to main |
| Phase 2 `--infer-model` + field-aware mutation | merged to main |
| Phase 3 directed scheduling + templates | this branch |
| Field energy feedback | done |
| `template_prob=` config | done |
| Sequence templates | done |

## Field energy feedback

- Each `mutate()` records touched field names in `last_touched`.
- Worker calls `mutator.on_interesting()` when `ExecutionResult::is_interesting()`.
- Energy (capped at 64) multiplies base field-type weight: `w * (1 + energy)`.
- Biases future mutations toward fields that historically produced coverage / crashes / new states.

## Config

```
template_prob=0.12
hierarchical_prob=0.15
field_prob=0.70
dict_prob=0.25
max_mutations=8
```

## Sequence templates

```rust
SequenceSpec { name: "login", steps: ["user", "pass"] }
```

Built-in examples:

| Model | Sequences |
|-------|-----------|
| `ftp` | `login` (user→pass), `session` (user→pass→pwd→quit) |
| `mqtt` | `connect-publish` |

API: `Mutator::synthesise_sequence("login") -> Vec<Message>`.

`splice_template` prefers sequences (~55%) when present, else single MessageSpec.

## Operational notes

- Models without `messages` / `sequences` → behaviour unchanged from Phase 2.
- Integrity repair remains single-owner in the worker.
- Energy is **per-worker** (local HashMap); not shared across workers by design (simple, lock-free).

## Suggested next tracks (outside this feature)

1. Snapshot / desocketing
2. Shared corpus orchestration
3. Cross-worker energy aggregation (optional)
