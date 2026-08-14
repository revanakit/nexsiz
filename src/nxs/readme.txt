NEXSIZ :: nxs

Existence-script integration layer.

After the engine classifies a crash/hang/interesting event,
this module writes contract-compliant meta JSON, resolves
NXS binaries from categories + search paths, applies rate
limits/cooldowns, spawns non-blocking, and hands children
to an async reaper.

Exit code 2 from any NXS is recorded as a secondary finding.
Completely opt-in; zero overhead when disabled.
