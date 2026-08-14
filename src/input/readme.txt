NEXSIZ :: input

Input construction and mutation pipeline.

Contains protocol models (built-in + JSON), hierarchical
field/message/sequence mutator with energy feedback,
protocol-aware integrity repair (length, checksum, framing),
and the shared corpus scheduler.

Produces structurally valid TestCase instances ready for
the execution layer. Integrity repair runs post-mutation
and pre-encrypt.
