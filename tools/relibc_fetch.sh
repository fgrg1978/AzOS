#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Fetch relibc at the pinned commit (third_party/RELIBC_PIN): shallow (one
# commit, no history), into a directory OUTSIDE the repository, and verify it.
# `make relibc` builds from a copy of that directory, patched by
# userspace/lib/relibc-azos; nothing in it is run here (no build.rs, no
# Makefile, no submodule script: only `git fetch`, `git checkout` and
# `git submodule update`).
#
# Why not a submodule like the Linux tree: relibc is 4 MB and the repository
# keeps only the pin, the overlay and the patch. A checkout inside the iCloud-
# synced tree would also be a build input that iCloud may duplicate.
#
# Usage: tools/relibc_fetch.sh            # into $RELIBC_SRC, default ~/azos-dl/relibc
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$root/third_party/RELIBC_PIN"
get() { sed -n "s/^$1=//p" "$pin"; }
url="$(get url)"; commit="$(get commit)"
dm_url="$(get dlmalloc_url)"; dm_commit="$(get dlmalloc_commit)"
dir="${RELIBC_SRC:-$HOME/azos-dl/relibc}"

case "$dir/" in
    "$root"/*|*"Mobile Documents"*)
        echo "relibc_fetch: $dir is inside the repository or iCloud Drive; set RELIBC_SRC to a directory outside" >&2
        exit 2 ;;
esac

mkdir -p "$dir"
if [ ! -e "$dir/.git" ]; then
    git -C "$dir" init -q
    git -C "$dir" remote add origin "$url"
fi
if ! git -C "$dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$dir" fetch -q --depth 1 --no-tags origin "$commit"
fi
git -C "$dir" checkout -q -f "$commit"
got="$(git -C "$dir" rev-parse HEAD)"
[ "$got" = "$commit" ] || { echo "relibc_fetch: HEAD is $got, pin is $commit" >&2; exit 1; }

# The submodule commit must be the one the pinned tree records.
rec="$(git -C "$dir" ls-tree HEAD dlmalloc-rs | awk '{print $3}')"
[ "$rec" = "$dm_commit" ] || { echo "relibc_fetch: the tree records dlmalloc-rs $rec, the pin says $dm_commit" >&2; exit 1; }
if [ ! -e "$dir/dlmalloc-rs/.git" ]; then
    git -C "$dir" submodule init dlmalloc-rs >/dev/null
    git -C "$dir" config submodule.dlmalloc-rs.url "$dm_url"
    git -C "$dir" submodule update -q --depth 1 dlmalloc-rs
fi
got="$(git -C "$dir/dlmalloc-rs" rev-parse HEAD)"
[ "$got" = "$dm_commit" ] || { echo "relibc_fetch: dlmalloc-rs HEAD is $got, pin is $dm_commit" >&2; exit 1; }

git -C "$dir" diff --quiet || { echo "relibc_fetch: the checkout differs from the pin" >&2; exit 1; }
echo "relibc_fetch: $dir at ${commit} (relibc), ${dm_commit} (dlmalloc-rs), shallow"
