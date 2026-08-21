NXS :: src

Source tree for all official Nexsiz Existence Scripts (NXS).

Each sub-directory is an independent pure-stdlib binary that
obeys nxs/CONTRACT.md. Shared foundation lives in lib/ (nxs-lib).
Built via nxs/build.sh into nxs/bin/.

These actors run post-event (crash, hang, interesting) to deepen
findings without bloating the fuzzer core.
