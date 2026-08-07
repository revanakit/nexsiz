#!/usr/bin/env bash
# NXS Phase 5 — contract smoke / e2e harness
#
# Validates every official binary against the CONTRACT checklist without
# requiring a live fuzz target where possible. Network-touching tests are
# skipped unless NXS_E2E_TARGET is set (host:port).
#
# Usage:
#   cd nxs && ./tests/e2e.sh
#   NXS_E2E_TARGET=127.0.0.1:21 ./tests/e2e.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin"
TMP="$(mktemp -d -t nxs-e2e.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
SKIP=0

ok()   { echo "  PASS  $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP  $*"; SKIP=$((SKIP+1)); }

echo "[nxs-e2e] root=$ROOT"
echo "[nxs-e2e] tmp=$TMP"

# Ensure binaries exist
if [[ ! -d "$BIN" ]] || [[ -z "$(ls -A "$BIN" 2>/dev/null | grep -v gitkeep || true)" ]]; then
  echo "[nxs-e2e] building official binaries…"
  (cd "$ROOT" && ./build.sh)
fi

OFFICIAL=(
  nxs-auto-repro
  nxs-save-notify
  nxs-differential-probe
  nxs-timeout-analyzer
  nxs-notify-webhook
  nxs-state-diff
  nxs-coverage-probe
  nxs-auth-bypass
)

# ---------------------------------------------------------------------------
# 1. Presence + --version + --help
# ---------------------------------------------------------------------------
echo
echo "== identity / help =="
for b in "${OFFICIAL[@]}"; do
  path="$BIN/$b"
  if [[ ! -x "$path" ]]; then
    fail "$b missing or not executable"
    continue
  fi
  if "$path" --version >/dev/null 2>&1; then
    ok "$b --version"
  else
    fail "$b --version"
  fi
  if "$path" --help >/dev/null 2>&1; then
    ok "$b --help"
  else
    fail "$b --help"
  fi
done

# ---------------------------------------------------------------------------
# 2. Synthetic meta + crash fixture
# ---------------------------------------------------------------------------
CRASH_FILE="$TMP/crash.bin"
printf 'USER x\r\nPASS y\r\n' > "$CRASH_FILE"
META_FILE="$TMP/meta.json"
cat > "$META_FILE" <<EOF
{
  "nexsiz_version": "0.1.0",
  "event": "crash",
  "timestamp": 1722912345.0,
  "target": { "host": "127.0.0.1", "port": 9, "protocol": "tcp" },
  "model": "ftp",
  "crash": {
    "id": "id_e2e_001",
    "path": "$CRASH_FILE",
    "minimized_path": null,
    "input_len": 16
  },
  "result": {
    "outcome": "crash",
    "error": "Connection reset by peer",
    "elapsed_ms": 12,
    "coverage_hits": 0,
    "new_state": false,
    "response_codes": []
  },
  "corpus_id": 1,
  "output_dir": "$TMP"
}
EOF

OUT_SAVE="$TMP/out-save"
OUT_HOOK="$TMP/out-hook"

echo
echo "== save-notify (no network) =="
if "$BIN/nxs-save-notify" --meta "$META_FILE" --out "$OUT_SAVE" -v >"$TMP/save.stdout" 2>"$TMP/save.stderr"; then
  if [[ -f "$OUT_SAVE/report.json" ]] && [[ -f "$OUT_SAVE/archive/id_e2e_001/input.bin" ]]; then
    ok "save-notify archive + report.json"
  else
    fail "save-notify missing artefacts"
  fi
else
  fail "save-notify exit $?"
fi

echo
echo "== notify-webhook dry-run (no URL) =="
if "$BIN/nxs-notify-webhook" --meta "$META_FILE" --out "$OUT_HOOK" -v >"$TMP/hook.stdout" 2>"$TMP/hook.stderr"; then
  if [[ -f "$OUT_HOOK/report.json" ]]; then
    ok "notify-webhook dry-run + report"
  else
    fail "notify-webhook missing report"
  fi
else
  fail "notify-webhook dry-run exit $?"
fi

echo
echo "== required-arg rejection =="
# Must exit 1 when neither --crash nor --meta
if "$BIN/nxs-auto-repro" --target 127.0.0.1:9 >/dev/null 2>&1; then
  fail "auto-repro should reject missing --crash/--meta"
else
  ok "auto-repro rejects missing inputs"
fi

# New NXS also reject missing inputs
for b in nxs-state-diff nxs-coverage-probe nxs-auth-bypass; do
  if "$BIN/$b" --target 127.0.0.1:9 >/dev/null 2>&1; then
    fail "$b should reject missing --crash/--meta"
  else
    ok "$b rejects missing inputs"
  fi
done

# ---------------------------------------------------------------------------
# 3. Optional live-target probes
# ---------------------------------------------------------------------------
echo
echo "== live target probes =="
if [[ -z "${NXS_E2E_TARGET:-}" ]]; then
  skip "set NXS_E2E_TARGET=host:port to exercise network NXS"
else
  T="$NXS_E2E_TARGET"
  # auto-repro against discard/closed port often yields unreachable (exit 1) or
  # confirmed (exit 2) — both are contract-legal; only crash (signal) is fail.
  set +e
  "$BIN/nxs-auto-repro" --crash "$CRASH_FILE" --target "$T" --out "$TMP/out-repro" -v \
    >"$TMP/repro.stdout" 2>"$TMP/repro.stderr"
  rc=$?
  set -e
  if [[ $rc -eq 0 || $rc -eq 1 || $rc -eq 2 || $rc -eq 3 ]]; then
    ok "auto-repro live exit=$rc (contract-legal)"
  else
    fail "auto-repro live unexpected exit=$rc"
  fi

  set +e
  "$BIN/nxs-differential-probe" --crash "$CRASH_FILE" --target "$T" --out "$TMP/out-diff" \
    --timeout 6 -v >"$TMP/diff.stdout" 2>"$TMP/diff.stderr"
  rc=$?
  set -e
  if [[ $rc -eq 0 || $rc -eq 1 || $rc -eq 2 || $rc -eq 3 ]]; then
    ok "differential-probe live exit=$rc"
  else
    fail "differential-probe live unexpected exit=$rc"
  fi

  set +e
  "$BIN/nxs-timeout-analyzer" --crash "$CRASH_FILE" --target "$T" --event hang \
    --out "$TMP/out-hang" --timeout 8 -v >"$TMP/hang.stdout" 2>"$TMP/hang.stderr"
  rc=$?
  set -e
  if [[ $rc -eq 0 || $rc -eq 1 || $rc -eq 2 || $rc -eq 3 ]]; then
    ok "timeout-analyzer live exit=$rc"
  else
    fail "timeout-analyzer live unexpected exit=$rc"
  fi

  set +e
  "$BIN/nxs-state-diff" --crash "$CRASH_FILE" --target "$T" --out "$TMP/out-state" \
    --timeout 8 --shots 3 -v >"$TMP/state.stdout" 2>"$TMP/state.stderr"
  rc=$?
  set -e
  if [[ $rc -eq 0 || $rc -eq 1 || $rc -eq 2 || $rc -eq 3 ]]; then
    ok "state-diff live exit=$rc"
  else
    fail "state-diff live unexpected exit=$rc"
  fi

  set +e
  "$BIN/nxs-coverage-probe" --crash "$CRASH_FILE" --target "$T" --out "$TMP/out-cov" \
    --timeout 8 -v >"$TMP/cov.stdout" 2>"$TMP/cov.stderr"
  rc=$?
  set -e
  if [[ $rc -eq 0 || $rc -eq 1 || $rc -eq 2 || $rc -eq 3 ]]; then
    ok "coverage-probe live exit=$rc"
  else
    fail "coverage-probe live unexpected exit=$rc"
  fi

  set +e
  "$BIN/nxs-auth-bypass" --crash "$CRASH_FILE" --target "$T" --model ftp \
    --out "$TMP/out-auth" --timeout 8 -v >"$TMP/auth.stdout" 2>"$TMP/auth.stderr"
  rc=$?
  set -e
  if [[ $rc -eq 0 || $rc -eq 1 || $rc -eq 2 || $rc -eq 3 ]]; then
    ok "auth-bypass live exit=$rc"
  else
    fail "auth-bypass live unexpected exit=$rc"
  fi
fi

# ---------------------------------------------------------------------------
echo
echo "[nxs-e2e] PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
