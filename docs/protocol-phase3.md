# Protocol Phase 3 — Directed MessageSpec Scheduling

**Branch:** `feature/protocol-phase3`  
**Status:** Implemented  
**Date:** 2026-08-07

## Goals

1. **Directed field selection** — mutation energy concentrates on semantically interesting fields (Command, String, Payload) rather than Length/Checksum.
2. **Template synthesis** — when `ProtocolModel.messages` is non-empty, the mutator can materialise concrete `Message` instances from `MessageSpec` and splice them into the test case.
3. **Zero behaviour change** for models without field trees (`generic`, classic text FTP seeds, etc.).

## Field weight table

| FieldType   | Weight | Notes |
|-------------|--------|-------|
| Command     | 10     | Primary target |
| String      | 9      | |
| Payload     | 8      | |
| Binary      | 6      | |
| Numeric     | 5      | |
| Custom      | 4      | |
| Length      | 1      | Rare; integrity repair owns correctness |
| Checksum    | 0      | Never scheduled for destructive mutation |

Protected and empty fields are always skipped.

## Template path

```
mutate()
  └─ if model.messages non-empty && rng < template_prob (default 0.12)
       └─ splice_template()
            ├─ synthesise_from_spec(MessageSpec)
            │    └─ materialise_field(FieldSpec)  // values → size → dictionary → random
            └─ replace | insert | append into TestCase.messages
```

`Mutator::with_template_prob(p)` / `set_template_prob(p)` for operator tuning.

## API additions

- `Mutator::synthesise_from_spec(&MessageSpec) -> Message`
- `Mutator::with_template_prob(f64) -> Self`
- `Mutator::set_template_prob(f64)`

## Tests

- `synthesise_from_dns_spec` — DNS query template materialises with correct field sizes
- `template_splice_adds_message` — empty parent + template_prob=1 yields ≥1 message
- `weighted_prefers_command_over_checksum` — Checksum never selected

## Operational impact

| Scenario | Effect |
|----------|--------|
| `-m ftp` / text seeds, no MessageSpec | Identical to Phase 2 |
| `-m dns` / `mqtt` / `smb` / JSON models | Directed scheduling + occasional template splice |
| Thin corpus | Templates seed structural diversity without hand-written seeds |

## Next (optional)

- Energy feedback: boost field weights that historically produced new coverage / states
- Config key `template_prob=` for campaign files
- Multi-message sequence templates (login → command → logout)
