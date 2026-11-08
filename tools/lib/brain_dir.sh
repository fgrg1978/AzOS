# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The brain repo (optional client of the OS), resolved by tools/lib/azos_tools.py.
# Sets BRAIN_STATE (found | absent | required | off) and BRAIN_PATH, and exports
# AZOS_BRAIN_DIR when the repo is found so the Python peers read the same one.
brain_resolve() { # brain_resolve <repo-root>
    local out
    out="$(python3 "$1/tools/lib/azos_tools.py" brain)" || return 1
    BRAIN_STATE="${out%% *}"
    BRAIN_PATH="${out#* }"
    [ "$BRAIN_STATE" = found ] && export AZOS_BRAIN_DIR="$BRAIN_PATH"
    return 0
}
# brain_skip_reason: the one line a run prints when it leaves the brain out.
brain_skip_reason() {
    case "$BRAIN_STATE" in
        off) echo "BRAIN=0" ;;
        *) echo "no AzOSRobotBrain at ${BRAIN_PATH:-the sibling of the checkout}; set AZOS_BRAIN_DIR, or BRAIN=1 to require it" ;;
    esac
}
