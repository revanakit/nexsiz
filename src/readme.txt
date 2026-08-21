NEXSIZ :: src

Core library and binary entry point.

Organises the entire fuzzer into focused crates-local modules:
  common, coverage, execution, input, monitor, nxs, platform,
  plugin, scripting, state.

main.rs owns CLI parsing and campaign bootstrap.
lib.rs re-exports the public surface for embedding / tests.
All operational logic lives in the sub-modules; this root
only wires them together.
