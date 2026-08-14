NEXSIZ :: scripting

Out-of-process campaign control and Python bridges.

RPC server (Unix socket), bridges for protocol / integrity /
encryptor / mutator / oracle so a Python client can inject
or override behaviour at runtime, plus seed parsing helpers.

Enables live campaign steering without recompilation.
Activated via -Y / NEXSIZ_RPC_SOCK.
