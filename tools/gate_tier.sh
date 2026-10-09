#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# The gate's short tiers (wave 15). `make ci` is the full gate (N2).
#
#   tools/gate_tier.sh n0   `make check` for riscv64, aarch64 and x86_64, plus
#                           the host suites the diff reaches (`make check0`)
#   tools/gate_tier.sh n1   n0's host suites, then tools/ci_check.sh under
#                           CI_TIER=rows with the per-ISA smoke boots and the
#                           n1 rows the diff maps to (`make check1`)
#
# The diff is the working tree against GATE_BASE (default HEAD); see
# tools/rows_for_diff.py for how paths map to rows and suites.
# GATE_DRY=1 prints what would run and runs nothing.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
tier="${1:-}"
base="${GATE_BASE:-HEAD}"
case "$tier" in n0|n1) ;; *) echo "usage: tools/gate_tier.sh n0|n1"; exit 2 ;; esac
export TOPOLOGY_PUBKEY_PATH="${TOPOLOGY_PUBKEY_PATH:-$PWD/tools/keys/test_pub.bin}"

suites="$(python3 tools/rows_for_diff.py --base "$base" --host)" || exit 2
fail=0
t0=$SECONDS

if [ "${GATE_DRY:-0}" = 1 ]; then
    echo "host suites: ${suites:-none}" | tr '\n' ' '; echo
    [ "$tier" = n1 ] && { echo "rows:"; python3 tools/rows_for_diff.py --base "$base" --rows --explain | sed 's/^/  /'; }
    exit 0
fi

# The gate's own rules: zero warnings for riscv64 and aarch64 but build-script
# notes and the aarch64 build's known noise (A64_KNOWN_NOISE in ci_check.sh);
# the x86_64 skeleton by exit status, as the gate's "x86_64: make check" row.
noise='^warning: [A-Za-z0-9_-]+@[0-9]|prod pubkey|packages contain code that will be rejected by a future version of Rust: core v0\.0\.0'
if [ "$tier" = n0 ]; then
    for arch in riscv64 aarch64 x86_64; do
        printf "  %-26s" "check ${arch}..."
        if out="$(make ARCH="$arch" check 2>&1)" \
           && { [ "$arch" = x86_64 ] || ! printf '%s\n' "$out" | grep -E '^warning:' | grep -qvE "$noise"; }; then
            echo ok
        else
            echo FAIL; fail=1
            printf '%s\n' "$out" | grep -E '^(error|warning)' | sed -n 1,5p | sed 's/^/      /'
        fi
    done
fi

# The boot sequence lint (tools/boot_seq_lint.py), as the gate's row does.
if [ "$tier" = n0 ]; then
    printf "  %-26s" "boot seq lint..."
    if out="$(python3 tools/boot_seq_lint.py --self-test 2>&1)" \
       && out="$(python3 tools/boot_seq_lint.py 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

# `make help` must not name a target the Makefile lacks (tools/check_make_help.sh).
if [ "$tier" = n0 ]; then
    printf "  %-26s" "make help targets..."
    if out="$(bash tools/check_make_help.sh 2>&1)"; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | sed -n 1,5p | sed 's/^/      /'
    fi
fi

for s in $suites; do
    printf "  %-26s" "host ${s#tests/host/}..."
    if out="$(cd "$s" && cargo test --release 2>&1)" \
       && ! printf '%s\n' "$out" | grep -q 'test result: FAILED' \
       && ! printf '%s\n' "$out" | grep -qE '^warning: .*generated'; then
        echo ok
    else
        echo FAIL; fail=1
        printf '%s\n' "$out" | grep -E '^(error|warning)|test result|panicked' | sed -n 1,5p | sed 's/^/      /'
    fi
done

if [ "$tier" = n1 ]; then
    rows="$(python3 tools/rows_for_diff.py --base "$base" --rows)" || exit 2
    CI_TIER=rows CI_ROWS="$rows" bash tools/ci_check.sh || fail=1
fi

echo "gate_tier ${tier}: $((SECONDS - t0)) s, $([ "$fail" = 0 ] && echo green || echo RED)"
exit "$fail"
