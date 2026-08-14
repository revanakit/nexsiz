NEXSIZ :: platform

OS abstraction boundary.

Linux and Windows specific helpers (signals, process control,
path conventions, SHM where applicable). Keeps the rest of
the codebase free of raw cfg(target_os) noise.

Primary production target remains Linux x86_64; Windows path
exists for future completeness.
