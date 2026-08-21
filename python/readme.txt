NEXSIZ :: python

External control and extension surface.

nexsiz_client.py — pure-stdlib RPC client over Unix domain socket.
Provides Campaign control, structured SeedBuilder, MutatorHooks,
and a live Oracle server that can register back into a running
fuzzer instance.

No third-party Python deps. Intended for operator scripts,
custom oracles, and live dictionary injection during campaigns.
