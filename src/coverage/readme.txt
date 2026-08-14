NEXSIZ :: coverage

Grey-box instrumentation layer.

Defines CoverageProvider trait and concrete backends:
  null      — zero overhead, default
  map       — AFL-style 64 KiB shared edge map
  software  — pure software edge tracking
  shm       — POSIX SHM bridge for external agents (Frida)

Produces CoverageFeedback (new edges, map hash, interesting flag)
consumed by the engine and state tracker. Default remains null
so behaviour is unchanged unless -C is set.
