**Current Nexsiz Directory Tree**

```text
nexsiz/
├── .github/
│   ├── FUNDING.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── config.yml
│   │   └── feature_request.md
│   ├── dependabot.yml
│   └── workflows/
│       ├── build.yml
│       └── release.yml
├── .gitignore
├── Cargo.lock
├── Cargo.toml
├── LICENSE
├── Makefile
├── README.md
├── SECURITY.md
├── agents/
│   ├── README.md
│   └── frida/
│       └── nexsiz_cov.js
├── config/
│   └── example.conf
├── models/
│   ├── binary-lp.json
│   ├── custom-example.json
│   ├── dns.json
│   └── mqtt.json
├── nexsiz-author.md
├── nexsiz-command.md
├── nexsiz-mascot.png
├── nxs/
│   ├── CONTRACT.md
│   ├── README.md
│   ├── bin/
│   │   └── .gitkeep
│   ├── build.sh
│   ├── categories.toml
│   ├── scripts/
│   │   └── .gitkeep
│   ├── src/
│   │   ├── auth-bypass/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── auth-escalation/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── auto-repro/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── chain-repro/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── coverage-probe/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── differential-probe/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── lib/
│   │   │   ├── Cargo.toml
│   │   │   └── src/
│   │   │       ├── args.rs
│   │   │       ├── exit.rs
│   │   │       ├── lib.rs
│   │   │       ├── meta.rs
│   │   │       └── report.rs
│   │   ├── notify-webhook/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── save-notify/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   ├── state-diff/
│   │   │   ├── Cargo.toml
│   │   │   ├── nxs.toml
│   │   │   └── src/
│   │   │       └── main.rs
│   │   └── timeout-analyzer/
│   │       ├── Cargo.toml
│   │       ├── nxs.toml
│   │       └── src/
│   │           └── main.rs
│   ├── templates/
│   │   ├── c/
│   │   │   ├── Makefile
│   │   │   ├── main.c
│   │   │   └── nxs.toml
│   │   ├── go/
│   │   │   ├── go.mod
│   │   │   ├── main.go
│   │   │   └── nxs.toml
│   │   ├── python/
│   │   │   ├── nxs.toml
│   │   │   └── run
│   │   └── rust/
│   │       ├── Cargo.toml
│   │       ├── nxs.toml
│   │       └── src/
│   │           └── main.rs
│   └── tests/
│       └── e2e.sh
├── python/
│   └── nexsiz_client.py
├── rust-toolchain.toml
├── sample/
│   ├── readme.txt
│   └── seeds/
│       ├── ftp/
│       │   ├── login.txt
│       │   └── retr.txt
│       ├── generic/
│       │   ├── raw.bin
│       │   └── rew.bin
│       ├── http/
│       │   └── get.txt
│       └── smtp/
│           ├── hello.txt
│           └── helo.txt
└── src/
    ├── common/
    │   ├── config.rs
    │   ├── error.rs
    │   ├── mod.rs
    │   ├── readme.txt
    │   ├── types.rs
    │   └── utils.rs
    ├── coverage/
    │   ├── map.rs
    │   ├── mod.rs
    │   ├── null.rs
    │   ├── provider.rs
    │   ├── readme.txt
    │   ├── registry.rs
    │   ├── shm.rs
    │   └── software.rs
    ├── execution/
    │   ├── connector.rs
    │   ├── desocket/
    │   │   ├── binary.rs
    │   │   ├── builtin.rs
    │   │   ├── mod.rs
    │   │   ├── null.rs
    │   │   ├── readme.txt
    │   │   ├── spec.rs
    │   │   └── state.rs
    │   ├── engine.rs
    │   ├── libafl_exec.rs
    │   ├── libafl_mutator.rs
    │   ├── libafl_runner.rs
    │   ├── mod.rs
    │   ├── process_monitor.rs
    │   ├── readme.txt
    │   ├── reuse.rs
    │   ├── snapshot/
    │   │   ├── criu.rs
    │   │   ├── mod.rs
    │   │   ├── null.rs
    │   │   ├── process.rs
    │   │   └── readme.txt
    │   └── worker.rs
    ├── input/
    │   ├── corpus.rs
    │   ├── integrity.rs
    │   ├── mod.rs
    │   ├── model.rs
    │   ├── mutator.rs
    │   └── readme.txt
    ├── lib.rs
    ├── main.rs
    ├── monitor/
    │   ├── logger.rs
    │   ├── minimizer.rs
    │   ├── mod.rs
    │   ├── oracle.rs
    │   └── readme.txt
    ├── nxs/
    │   ├── meta.rs
    │   ├── mod.rs
    │   ├── rate.rs
    │   ├── readme.txt
    │   ├── reaper.rs
    │   ├── resolve.rs
    │   └── spawn.rs
    ├── platform/
    │   ├── linux.rs
    │   ├── mod.rs
    │   ├── readme.txt
    │   └── windows.rs
    ├── plugin/
    │   ├── crypto.rs
    │   ├── encryptor.rs
    │   ├── integrity.rs
    │   ├── mod.rs
    │   ├── oracle.rs
    │   ├── pipeline.rs
    │   ├── protocol.rs
    │   ├── readme.txt
    │   └── registry.rs
    ├── readme.txt
    ├── scripting/
    │   ├── encryptor_bridge.rs
    │   ├── handler.rs
    │   ├── integrity_bridge.rs
    │   ├── json.rs
    │   ├── mod.rs
    │   ├── mutator_bridge.rs
    │   ├── oracle_bridge.rs
    │   ├── protocol.rs
    │   ├── protocol_bridge.rs
    │   ├── readme.txt
    │   ├── seed_parse.rs
    │   └── server.rs
    └── state/
        ├── mod.rs
        ├── predictor.rs
        ├── readme.txt
        └── tracker.rs
```
