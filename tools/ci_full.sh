#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# AzOS + Brain — Full cross-repo CI check.
#
# Validates:
#   1. azos: all 5 feature combos build clean
#   2. AzOSRobotBrain: pytest suite passes
#   3. Protocol sync: brain_protocol.rs matches protocol.py
#
# Usage: bash tools/ci_full.sh

set -euo pipefail
# qgrep: grep -q at the end of a pipe, safe under pipefail (see tools/ci_check.sh).
qgrep() { local rc; grep "$@"; rc=$?; cat >/dev/null; return "$rc"; }

OS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BRAIN_DIR="$OS_DIR/../AzOSRobotBrain"
CARGO="${CARGO:-cargo}"

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"
    shift
    printf "  %-30s" "${label}..."
    if "$@" >/dev/null 2>&1; then
        echo "PASS"
        PASS=$((PASS + 1))
    else
        echo "FAIL"
        FAIL=$((FAIL + 1))
    fi
}

# U12-7: `check` above only tests exit status, so the header's claim ("all 5
# feature combos build clean") was never checked for the warning half of
# "clean" — the same gap `tools/ci_check.sh`'s own `build()` was rewritten to
# close (see its comment: an allowlist of five warning spellings let a real
# lint through all three kernel builds while reporting clean). One shape is
# excluded by pattern, not by name: a build script announcing which key it
# embedded (`warning: <pkg>@<version>: ...`, `crates/core/ota`'s), not a lint.
check_build() {
    local label="$1"; shift
    printf "  %-30s" "${label}..."
    local out rc
    out="$("$@" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ] || printf '%s\n' "$out" | qgrep -qE "^error"; then
        echo "FAIL"; FAIL=$((FAIL + 1))
        printf '%s\n' "$out" | grep -E "^error" | sed -n '1,5p' | sed 's/^/      /'
        return
    fi
    if printf '%s\n' "$out" | grep -E "^warning:" \
         | qgrep -qvE "^warning: [A-Za-z0-9_-]+@[0-9]"; then
        echo "FAIL (warnings)"; FAIL=$((FAIL + 1))
        printf '%s\n' "$out" | grep -E "^warning:" \
          | grep -vE "^warning: [A-Za-z0-9_-]+@[0-9]" | sed -n '1,5p' | sed 's/^/      /'
        return
    fi
    echo "PASS"; PASS=$((PASS + 1))
}

echo "========================================="
echo " AzOS + Brain — Full CI"
echo "========================================="
echo ""

# ── 1. AzOS builds ──────────────────────────────────────────────
echo "[1/3] AzOS builds"
cd "$OS_DIR"

check_build "default (QEMU)"    $CARGO build --release
check_build "no-ml"             $CARGO build --release --features no-ml
check_build "no-mmu"            $CARGO build --release --features no-mmu
check_build "vf2"               $CARGO build --release --features vf2
check_build "k1"                $CARGO build --release --features k1
echo ""

# ── 2. AzOS Robot Brain tests ────────────────────────────────────────────
echo "[2/3] AzOS Robot Brain tests"
if [ -d "$BRAIN_DIR" ]; then
    cd "$BRAIN_DIR"
    # Syntax check
    check "syntax (server.py)"   python3 -m py_compile server.py
    check "syntax (protocol.py)" python3 -m py_compile protocol.py

    # Pytest
    #
    # U12-7: a summary line like "3 failed, 10 passed" contains "passed" and
    # used to print PASS. `sed -n '$p'` in place of `tail -1` (no `tail` in
    # this tree's tooling); the pass/fail decision now requires "passed" AND
    # the ABSENCE of an "N failed" clause, not just the substring.
    printf "  %-30s" "pytest..."
    PYTEST_OUT=$(python3 -m pytest tests/ -q --tb=line 2>&1)
    RESULT="$(printf '%s\n' "$PYTEST_OUT" | sed -n '$p')"
    if printf '%s\n' "$RESULT" | qgrep -q "passed" \
       && ! printf '%s\n' "$RESULT" | qgrep -qE '[0-9]+ failed'; then
        echo "PASS ($RESULT)"
        PASS=$((PASS + 1))
    else
        echo "FAIL ($RESULT)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  SKIP — $BRAIN_DIR not found"
    WARN=$((WARN + 1))
fi
echo ""

# ── 3. Protocol sync ───────────────────────────────────────────────
echo "[3/3] Protocol sync"
RUST_PROTO="$OS_DIR/domains/robot/behavior/src/brain_protocol.rs"
PY_PROTO="$BRAIN_DIR/protocol.py"

if [ -f "$RUST_PROTO" ] && [ -f "$PY_PROTO" ]; then
    SYNC_OK=true

    # Check key packet types exist in both.
    #
    # U12-7: `grep -c` into an integer test, not `grep -q` — the exact trap
    # `tools/ci_check.sh` documents (search that file for "grep -c" for the
    # write-up): `grep -c` prints `0` AND exits 1 when nothing matches, so
    # `"$(grep -c ... || echo 0)"` yields the two-line string "0\n0" and
    # `[ "$IN_RUST" -gt 0 ]` dies with "integer expression expected" — a
    # failed `[` is just a false branch, so the check silently never ran for
    # any packet type absent from either file, which is the common case this
    # loop exists to catch. Only existence is needed here, so `grep -q`.
    for PKT in "0x01" "0x02" "0x03" "0x80" "0x81" "0x82" "0x83" "0x84" "0x85" "0x86" "0x88"; do
        if grep -q -- "$PKT" "$RUST_PROTO" 2>/dev/null \
           && ! grep -q -- "$PKT" "$PY_PROTO" 2>/dev/null; then
            echo "  MISSING in Python: packet type $PKT"
            SYNC_OK=false
        fi
    done

    if $SYNC_OK; then
        echo "  Protocol sync:                PASS"
        PASS=$((PASS + 1))
    else
        echo "  Protocol sync:                WARN (missing types in Python)"
        WARN=$((WARN + 1))
    fi
else
    echo "  SKIP — protocol files not found"
    WARN=$((WARN + 1))
fi

echo ""
echo "========================================="
echo " Results: $PASS passed, $FAIL failed, $WARN warnings"
echo "========================================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
