#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# AzOS, with its optional companion client — Full CI check.
#
# Validates:
#   1. azos: the feature combos build clean (needs nothing outside this repo)
#   2. AzOSRobotBrain: pytest suite passes
#   3. Protocol sync: companion_protocol.rs matches protocol.py, and the companion's
#      protocol_consts.py holds the values this .config gives
#      (tools/build/export_kernel_consts.py --check)
#
# Steps 2 and 3 run when the companion repo is found (tools/lib/companion_dir.sh:
# AZOS_COMPANION_DIR, then the siblings of the checkout) and COMPANION is not 0; absent,
# they print one skip line and the run is not red. COMPANION=1 requires the repo.
#
# Usage: bash tools/gate/ci_full.sh

set -euo pipefail
# qgrep: grep -q at the end of a pipe, safe under pipefail (see tools/gate/ci_check.sh).
qgrep() { local rc; grep "$@"; rc=$?; cat >/dev/null; return "$rc"; }

OS_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
. "$OS_DIR/tools/lib/companion_dir.sh"
companion_resolve "$OS_DIR" || exit 1
COMPANION_DIR="$COMPANION_PATH"
CARGO="${CARGO:-cargo}"
# Outputs live under $AZOS_OUT (tools/lib/out_dir.py), never in the checkout.
AZOS_OUT="${AZOS_OUT:-$(python3 "$(dirname "$0")/../lib/out_dir.py")}"; export AZOS_OUT
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AZOS_OUT/target}"

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

# `check` above only tests exit status, so the header's claim ("all 5
# feature combos build clean") was never checked for the warning half of
# "clean" — the same gap `tools/gate/ci_check.sh`'s own `build()` was rewritten to
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
echo " AzOS — Full CI"
echo "========================================="
echo ""

# ── 1. AzOS builds ──────────────────────────────────────────────
echo "[1/3] AzOS builds"
cd "$OS_DIR"

# The .config's own kernel, and three selections on it (tools/build/kconfig_to_cargo.py
# --select: each a copy of the .config the build reads; Kconfig is the only
# source of the kernel's features).
SEL_DIR="$(python3 tools/lib/out_dir.py)/build"
mkdir -p "$SEL_DIR"
sel() { python3 tools/build/kconfig_to_cargo.py --select "$1" --out "$SEL_DIR/ci-full-$1.config" .config; }
check_build "default (QEMU)"    $CARGO build --release -p azos_kernel $(python3 tools/build/kconfig_to_cargo.py .config)
check_build "no-ml"             env KCONFIG_CONFIG="$SEL_DIR/ci-full-no-ml.config" $CARGO build --release -p azos_kernel $(sel no-ml)
check_build "vf2"               env KCONFIG_CONFIG="$SEL_DIR/ci-full-vf2.config" $CARGO build --release -p azos_kernel $(sel vf2)
check_build "k1"                env KCONFIG_CONFIG="$SEL_DIR/ci-full-k1.config" $CARGO build --release -p azos_kernel $(sel k1)
echo ""

# ── 2. AzOS Robot Companion tests ────────────────────────────────────────────
echo "[2/3] AzOS Robot Companion tests"
if [ "$COMPANION_STATE" = required ]; then
    echo "  FAIL — COMPANION=1 but no AzOSRobotBrain at ${COMPANION_PATH:-the sibling of the checkout}"
    FAIL=$((FAIL + 1))
elif [ "$COMPANION_STATE" = found ]; then
    cd "$COMPANION_DIR"
    # Syntax check
    check "syntax (server.py)"   python3 -m py_compile server.py
    check "syntax (protocol.py)" python3 -m py_compile protocol.py

    # Pytest
    #
    # a summary line like "3 failed, 10 passed" contains "passed" and
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
    echo "  SKIP — $(companion_skip_reason)"
fi
echo ""

# ── 3. Protocol sync ───────────────────────────────────────────────
echo "[3/3] Protocol sync"
RUST_PROTO="$OS_DIR/crates/domains/robot/behavior/src/companion_protocol.rs"
PY_PROTO="$COMPANION_DIR/protocol.py"

if [ "$COMPANION_STATE" != found ]; then
    echo "  SKIP — $(companion_skip_reason)"
elif [ -f "$RUST_PROTO" ] && [ -f "$PY_PROTO" ]; then
    SYNC_OK=true

    # Check key packet types exist in both.
    #
    # `grep -c` into an integer test, not `grep -q` — the exact trap
    # `tools/gate/ci_check.sh` documents (search that file for "grep -c" for the
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

# The kernel constants the companion mirrors (TCP caps, OTA size, task ceiling,
# board and limits tier): its protocol_consts.py against this checkout's
# .config. A drift warns, as the packet check above does: the mirror follows
# one chosen .config, and the companion's own pytest asserts what it relies on.
PY_CONSTS="$COMPANION_DIR/protocol_consts.py"
if [ "$COMPANION_STATE" != found ]; then
    echo "  SKIP — $(companion_skip_reason)"
elif [ -f "$OS_DIR/.config" ]; then
    if CONSTS_OUT="$(python3 "$OS_DIR/tools/build/export_kernel_consts.py" --config "$OS_DIR/.config" --out "$PY_CONSTS" --check 2>&1)"; then
        echo "  Kernel constants:             PASS"
        PASS=$((PASS + 1))
    else
        echo "  Kernel constants:             WARN (regenerate: python3 tools/build/export_kernel_consts.py)"
        printf '%s\n' "$CONSTS_OUT" | sed -n 1,8p | sed 's/^/    /'
        WARN=$((WARN + 1))
    fi
else
    echo "  SKIP — no .config"
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
