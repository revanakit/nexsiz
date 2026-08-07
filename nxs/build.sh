#!/usr/bin/env bash
# NXS official build — compiles every crate under nxs/src/ (except lib) into nxs/bin/
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BIN="$ROOT/bin"
SRC="$ROOT/src"

mkdir -p "$BIN"

echo "[nxs] building official existence scripts → $BIN"

for dir in "$SRC"/*/; do
  name="$(basename "$dir")"
  if [[ "$name" == "lib" ]]; then
    continue
  fi
  if [[ ! -f "$dir/Cargo.toml" ]]; then
    echo "[nxs] skip $name (no Cargo.toml)"
    continue
  fi
  echo "[nxs] → $name"
  # Do not use --quiet: CI needs full rustc diagnostics on failure.
  (cd "$dir" && cargo build --release)
  bin_name="nxs-${name}"
  if [[ -x "$dir/target/release/$bin_name" ]]; then
    cp -f "$dir/target/release/$bin_name" "$BIN/"
  elif [[ -x "$dir/target/release/$name" ]]; then
    cp -f "$dir/target/release/$name" "$BIN/$bin_name"
  else
    found=$(find "$dir/target/release" -maxdepth 1 -type f -executable ! -name "*.d" ! -name "*.rlib" | head -1 || true)
    if [[ -n "$found" ]]; then
      cp -f "$found" "$BIN/$bin_name"
    else
      echo "[nxs] WARNING: no binary produced for $name" >&2
    fi
  fi
done

echo "[nxs] done. binaries:"
ls -la "$BIN"
