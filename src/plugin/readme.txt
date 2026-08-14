NEXSIZ :: plugin

Trait-based extensibility surface.

Protocol, Integrity, Oracle, and Encryptor plugins plus the
PluginRegistry and composition pipelines (crypto stages,
TLS framing, AEAD).

Selected by name from CLI/config. Default implementations
preserve original behaviour; custom plugins can be registered
without touching the engine core.
