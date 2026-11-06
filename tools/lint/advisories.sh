#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# RustSec advisories for every registry crate a lockfile of the tree resolves
# (kernel, userspace, sdk), offline, against the snapshot in third_party/advisory-db.
#
#   advisories.sh check    materialise the snapshot as a git repo under $AZOS_OUT and
#                          run `cargo deny check advisories` once per lockfile.
#                          Exit 1 on an advisory; exit 0 with a "WARN" line when the
#                          snapshot is missing, older than 45 days, or a lockfile
#                          could not be resolved.
#   advisories.sh update   BY HAND, with a network: fetch the RustSec database and
#                          rewrite the snapshot (tarball + SNAPSHOT with its date).
#   advisories.sh update-from <dir>   the same from a local checkout of the database.
set -u
cd "$(dirname "$0")/../.." || exit 2
snap=third_party/advisory-db
out="${AZOS_OUT:-$HOME/azos-out/default}/advisory-db"
url=https://github.com/RustSec/advisory-db
stale_days=45

field() { sed -n "s/^$1 *= *//p" "$snap/SNAPSHOT"; }

pack() { # <checkout>
    local src="$1" commit date
    commit="$(git -C "$src" rev-parse HEAD)" && date="$(git -C "$src" log -1 --format=%cI)" || return 1
    mkdir -p "$snap"
    tar -C "$src" -cJf "$snap/advisory-db.tar.xz" crates || return 1
    printf 'upstream = %s\ncommit = %s\ndate = %s\n' "$url" "$commit" "$date" >"$snap/SNAPSHOT"
    echo "snapshot: $commit ($date)"
}

case "${1:-check}" in
update)
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/advdb.XXXXXX")" || exit 2
    git clone --depth 1 "$url" "$tmp/db" && pack "$tmp/db"; rc=$?
    rm -rf "$tmp"; exit $rc ;;
update-from)
    [ -d "${2:-}/crates" ] || { echo "usage: advisories.sh update-from <advisory-db checkout>"; exit 2; }
    pack "$2"; exit $? ;;
check) ;;
*) echo "usage: advisories.sh check|update|update-from <dir>"; exit 2 ;;
esac

if [ ! -f "$snap/SNAPSHOT" ] || [ ! -f "$snap/advisory-db.tar.xz" ]; then
    echo "WARN advisory db missing ($snap): advisories NOT checked; run \`make advisories-update\`"
    exit 0
fi
commit="$(field commit)"; date="$(field date)"
age=$(python3 -c 'import sys,datetime as d; print((d.datetime.now(d.timezone.utc)-d.datetime.fromisoformat(sys.argv[1])).days)' "$date")

# cargo-deny reads <db-path>/<name for the url>/ as a git checkout whose HEAD time is the db date.
db="$out/advisory-db-3157b0e258782691"
if [ "$(cat "$out/stamp" 2>/dev/null)" != "$commit" ]; then
    rm -rf "$out"; mkdir -p "$db"
    tar -C "$db" -xJf "$snap/advisory-db.tar.xz" || exit 2
    ( cd "$db" && git init -q && git remote add origin "$url" && git add -A \
      && GIT_AUTHOR_DATE="$date" GIT_COMMITTER_DATE="$date" git -c user.name=snapshot -c user.email=snapshot@invalid \
         -c commit.gpgsign=false commit -q -m "advisory-db $commit" ) || exit 2
    printf '%s' "$commit" >"$out/stamp"
fi
sed "s|^db-path *=.*|db-path = \"$out\"|" deny.toml >"$out/deny.toml"

fail=0; checked=0; skipped=""
for lock in $(git ls-files '*Cargo.lock' | grep -v -e '^third_party/' -e '^tests/'); do
    grep -q '^source = "registry' "$lock" || continue
    d="$(dirname "$lock")"
    if ! cargo metadata --offline --locked --format-version 1 --manifest-path "$d/Cargo.toml" >"$out/md.json" 2>"$out/md.err"; then
        skipped="$skipped $d"; continue
    fi
    checked=$((checked + 1))
    if ! res="$(cargo deny --manifest-path "$d/Cargo.toml" check --config "$out/deny.toml" --metadata-path "$out/md.json" --disable-fetch advisories 2>&1)"; then
        fail=1; echo "FAIL $d"; printf '%s\n' "$res" | grep -A12 -E '^error' | sed -n 1,24p | sed 's/^/      /'
    fi
done
[ -n "$skipped" ] && echo "WARN lockfiles not resolvable offline, advisories NOT checked for:$skipped"
[ "$age" -gt "$stale_days" ] && echo "WARN advisory db is $age days old ($date); run \`make advisories-update\`"
echo "advisories: $checked lockfiles against db $date (${commit%"${commit#????????}"})"
exit $fail
