#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# The OS needs nothing from the companion repo: the gate's selections run with it
# hidden (AZOS_COMPANION_DIR names a path that does not exist).
#
#   bash tools/gate/nocompanion_check.sh          the resolver, the lint, the companion-free tools, the companion rows' skip
#   bash tools/gate/nocompanion_check.sh --n0     and then tools/gate/gate_tier.sh n0 with the repo hidden (`make check0-nocompanion`)
#
# Canaries: COMPANION=1 with the repo hidden must turn the resolver, ci_full.sh and the
# SBOM red; a planted companion path and an unguarded companion scenario turn the lint red
# (tools/lint/companion_dep_lint.py --self-test).
set -uo pipefail
cd "$(dirname "$0")/../.."
AZOS_OUT="${AZOS_OUT:-$(python3 tools/lib/out_dir.py)}"; export AZOS_OUT
HIDDEN="$AZOS_OUT/no-companion-here"
rm -rf "$HIDDEN"
fail=0
row() { # row <label> <command...>
    local label="$1"; shift
    printf "  %-46s" "${label}..."
    if out="$("$@" 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,6p | sed 's/^/      /'; fi
}
expect_state() { [ "$(env "${@:2}" python3 tools/lib/azos_tools.py companion | cut -d' ' -f1)" = "$1" ]; }

row "resolver: hidden is absent" expect_state absent AZOS_COMPANION_DIR="$HIDDEN"
row "resolver: COMPANION=1 requires it" expect_state required AZOS_COMPANION_DIR="$HIDDEN" COMPANION=1
row "resolver: COMPANION=0 is off" expect_state off AZOS_COMPANION_DIR="$HIDDEN" COMPANION=0
row "companion dependency lint" bash -c 'python3 tools/lint/companion_dep_lint.py --self-test && python3 tools/lint/companion_dep_lint.py'
row "export_kernel_consts self-test" env AZOS_COMPANION_DIR="$HIDDEN" python3 tools/build/export_kernel_consts.py --self-test
row "export_kernel_consts writes nowhere unasked" bash -c '! python3 tools/build/export_kernel_consts.py >/dev/null 2>&1'
row "fake_companion framing self-test" env AZOS_COMPANION_DIR="$HIDDEN" python3 tools/gate/fake_companion.py --selftest
row "link_peer refuses without the repo" bash -c 'AZOS_COMPANION_DIR="$1" python3 tools/gate/link_peer.py --selftest; [ $? = 4 ]' _ "$HIDDEN"
row "sbom has no Python part" bash -c 'AZOS_COMPANION_DIR="$1" bash tools/gate/sbom.sh "$2" >/dev/null && ! grep -q "pkg:pypi" "$2"' _ "$HIDDEN" "$AZOS_OUT/build/nocompanion-sbom.json"
row "canary: COMPANION=1 turns the sbom red" bash -c '! COMPANION=1 AZOS_COMPANION_DIR="$1" bash tools/gate/sbom.sh "$2" >/dev/null 2>&1' _ "$HIDDEN" "$AZOS_OUT/build/nocompanion-sbom.json"
row "canary: COMPANION=1 turns ci_full red" bash -c '! COMPANION=1 AZOS_COMPANION_DIR="$1" CARGO=true bash tools/gate/ci_full.sh >/dev/null 2>&1' _ "$HIDDEN"
row "ci_full skips the companion steps" bash -c 'AZOS_COMPANION_DIR="$1" CARGO=true bash tools/gate/ci_full.sh 2>&1 | grep -c "SKIP — no AzOSRobotBrain" | grep -qx 3' _ "$HIDDEN"

if [ "${1:-}" = --n0 ]; then
    echo "  n0 with the companion repo hidden:"
    AZOS_COMPANION_DIR="$HIDDEN" COMPANION= env -u CARGO_TARGET_DIR bash tools/gate/gate_tier.sh n0 || fail=1
fi
echo "nocompanion_check: $([ "$fail" = 0 ] && echo green || echo RED)"
exit "$fail"
