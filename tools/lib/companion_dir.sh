# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The companion repo (optional client of the OS), resolved by tools/lib/azos_tools.py.
# Sets COMPANION_STATE (found | absent | required | off) and COMPANION_PATH, and exports
# AZOS_COMPANION_DIR when the repo is found so the Python peers read the same one.
companion_resolve() { # companion_resolve <repo-root>
    local out
    out="$(python3 "$1/tools/lib/azos_tools.py" companion)" || return 1
    COMPANION_STATE="${out%% *}"
    COMPANION_PATH="${out#* }"
    [ "$COMPANION_STATE" = found ] && export AZOS_COMPANION_DIR="$COMPANION_PATH"
    return 0
}
# companion_skip_reason: the one line a run prints when it leaves the companion out.
companion_skip_reason() {
    case "$COMPANION_STATE" in
        off) echo "COMPANION=0" ;;
        *) echo "no AzOSRobotBrain at ${COMPANION_PATH:-the sibling of the checkout}; set AZOS_COMPANION_DIR, or COMPANION=1 to require it" ;;
    esac
}
