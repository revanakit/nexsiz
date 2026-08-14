NEXSIZ :: execution

Campaign runtime and target interaction.

Owns the Engine (orchestrator), worker pool, TCP/UDP connectors,
connection-reuse policy, process monitor, optional LibAFL path,
and the snapshot + desocket subsystems.

This is the hot path: mutate → repair → encrypt → send → observe
→ feedback. All parallelism and restore_epoch orchestration
live here.
