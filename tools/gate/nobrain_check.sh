#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# The OS needs nothing from the brain repo: the gate's selections run with it
# hidden (AZOS_BRAIN_DIR names a path that does not exist).
#
#   bash tools/gate/nobrain_check.sh          the resolver, the lint, the brain-free tools, the brain rows' skip
#   bash tools/gate/nobrain_check.sh --n0     and then tools/gate/gate_tier.sh n0 with the repo hidden (`make check0-nobrain`)
#
# Canaries: BRAIN=1 with the repo hidden must turn the resolver, ci_full.sh and the
# SBOM red; a planted brain path and an unguarded brain scenario turn the lint red
# (tools/lint/brain_dep_lint.py --self-test).
set -uo pipefail
cd "$(dirname "$0")/../.."
AZOS_OUT="${AZOS_OUT:-$(python3 tools/lib/out_dir.py)}"; export AZOS_OUT
HIDDEN="$AZOS_OUT/no-brain-here"
rm -rf "$HIDDEN"
fail=0
row() { # row <label> <command...>
    local label="$1"; shift
    printf "  %-46s" "${label}..."
    if out="$("$@" 2>&1)"; then echo ok; else echo FAIL; fail=1; printf '%s\n' "$out" | sed -n 1,6p | sed 's/^/      /'; fi
}
expect_state() { [ "$(env "${@:2}" python3 tools/lib/azos_tools.py brain | cut -d' ' -f1)" = "$1" ]; }

row "resolver: hidden is absent" expect_state absent AZOS_BRAIN_DIR="$HIDDEN"
row "resolver: BRAIN=1 requires it" expect_state required AZOS_BRAIN_DIR="$HIDDEN" BRAIN=1
row "resolver: BRAIN=0 is off" expect_state off AZOS_BRAIN_DIR="$HIDDEN" BRAIN=0
row "brain dependency lint" bash -c 'python3 tools/lint/brain_dep_lint.py --self-test && python3 tools/lint/brain_dep_lint.py'
row "export_kernel_consts self-test" env AZOS_BRAIN_DIR="$HIDDEN" python3 tools/build/export_kernel_consts.py --self-test
row "export_kernel_consts writes nowhere unasked" bash -c '! python3 tools/build/export_kernel_consts.py >/dev/null 2>&1'
row "fake_brain framing self-test" env AZOS_BRAIN_DIR="$HIDDEN" python3 tools/gate/fake_brain.py --selftest
row "link_peer refuses without the repo" bash -c 'AZOS_BRAIN_DIR="$1" python3 tools/gate/link_peer.py --selftest; [ $? = 4 ]' _ "$HIDDEN"
row "sbom has no Python part" bash -c 'AZOS_BRAIN_DIR="$1" bash tools/gate/sbom.sh "$2" >/dev/null && ! grep -q "pkg:pypi" "$2"' _ "$HIDDEN" "$AZOS_OUT/build/nobrain-sbom.json"
row "canary: BRAIN=1 turns the sbom red" bash -c '! BRAIN=1 AZOS_BRAIN_DIR="$1" bash tools/gate/sbom.sh "$2" >/dev/null 2>&1' _ "$HIDDEN" "$AZOS_OUT/build/nobrain-sbom.json"
row "canary: BRAIN=1 turns ci_full red" bash -c '! BRAIN=1 AZOS_BRAIN_DIR="$1" CARGO=true bash tools/gate/ci_full.sh >/dev/null 2>&1' _ "$HIDDEN"
row "ci_full skips the brain steps" bash -c 'AZOS_BRAIN_DIR="$1" CARGO=true bash tools/gate/ci_full.sh 2>&1 | grep -c "SKIP — no AzOSRobotBrain" | grep -qx 3' _ "$HIDDEN"

if [ "${1:-}" = --n0 ]; then
    echo "  n0 with the brain repo hidden:"
    AZOS_BRAIN_DIR="$HIDDEN" BRAIN= env -u CARGO_TARGET_DIR bash tools/gate/gate_tier.sh n0 || fail=1
fi
echo "nobrain_check: $([ "$fail" = 0 ] && echo green || echo RED)"
exit "$fail"
