#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Fails if `make help` (tools/make_help.txt) names a target the Makefile does
# not define. A target counts as defined when the make database holds a rule
# for it, or a pattern rule that matches it (defconfig-%); a defconfig-<name>
# target must also have config/defconfigs/<name>.config.
#
# Usage: bash tools/check_make_help.sh
set -u
cd "$(dirname "$0")/.." || exit 2

help=tools/make_help.txt
db=$(mktemp "${TMPDIR:-/tmp}/make_db.XXXXXX") || exit 2
trap 'rm -f "$db"' EXIT
make -qp help >"$db" 2>/dev/null

# Section entries only: two spaces, then a target-looking word (continuation
# lines are indented deeper). The
# "Variables" section lists assignments, not targets.
names=$(awk '/^Variables$/ {exit} /^  [A-Za-z0-9_.\/-]+( |$)/ {print $1}' "$help")
[ -n "$names" ] || { echo "[HELP] no targets found in $help"; exit 1; }

# Explicit targets, and pattern rules turned into shell globs.
explicit=$(sed -n 's/^\([A-Za-z0-9_.\/-][A-Za-z0-9_.\/-]*\):.*/\1/p' "$db" | sort -u)
patterns=$(sed -n 's/^\([A-Za-z0-9_.\/-][A-Za-z0-9_.\/-]*%[A-Za-z0-9_.\/-]*\):.*/\1/p' "$db" | sort -u)

bad=0
for t in $names; do
    ok=0
    if printf '%s\n' "$explicit" | grep -qxF -- "$t"; then ok=1; fi
    if [ $ok = 0 ]; then
        for p in $patterns; do
            # shellcheck disable=SC2254
            case "$t" in ${p//%/*}) ok=1; break ;; esac
        done
    fi
    if [ $ok = 1 ]; then
        case "$t" in
            defconfig-*) [ -f "config/defconfigs/${t#defconfig-}.config" ] || ok=0 ;;
        esac
    fi
    if [ $ok = 0 ]; then
        echo "[HELP] 'make help' names '$t', which the Makefile does not define"
        bad=1
    fi
done
[ $bad = 0 ] && echo "[HELP] ok: $(printf '%s\n' "$names" | wc -l | tr -d ' ') targets in $help exist"
exit $bad
