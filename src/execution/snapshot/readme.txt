NEXSIZ :: execution/snapshot

Target process snapshot / restore backends.

SnapshotProvider trait with:
  null     — disabled (default)
  process  — kill + respawn via target_cmd
  criu     — CRIU dump/restore (feature-gated)

Engine takes snapshot at campaign start and restores on crash.
Successful restore bumps restore_epoch so all workers force
reconnect. Zero behaviour change when snapshot is off.
