#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Self-test for tools/lib/volume_stale.sh: a volume snapshotted before an image
# was rebuilt is stale, one made after every image is not.
#
#     bash tools/gate/volume_stale_selftest.sh                          # expect: ok
#     VOLUME_STALE_CANARY=1 bash tools/gate/volume_stale_selftest.sh    # expect: FAIL
#
# The canary swaps in the check the gate had (the volume exists), which calls a
# volume made from the images of an earlier configuration fresh.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tools/lib/volume_stale.sh"
[ -z "${VOLUME_STALE_CANARY:-}" ] || volume_stale() { [ ! -f "$1" ]; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/images"
: >"$WORK/images/compmgr.elf"; : >"$WORK/images/sh.elf"; : >"$WORK/images/notes.txt"
fails=0
expect() { # expect <stale|fresh> <what>
    local got=fresh
    volume_stale "$WORK/disk.pristine" "$WORK/images" && got=stale
    [ "$got" = "$1" ] || { echo "FAIL: $2: reported $got, expected $1"; fails=$((fails + 1)); }
}
touch -t 202610311800 "$WORK/images/compmgr.elf" "$WORK/images/sh.elf"
expect stale "no volume yet"
: >"$WORK/disk.pristine"; touch -t 202610311837 "$WORK/disk.pristine"
expect fresh "volume made after every image"
touch -t 202610311925 "$WORK/images/compmgr.elf"
expect stale "an image rebuilt after the volume was made"
touch -t 202610311926 "$WORK/disk.pristine"
expect fresh "volume remade after the rebuild"
touch -t 202610311930 "$WORK/images/notes.txt"
expect fresh "a file that is not an image changed"
[ "$fails" = 0 ] && echo ok
exit $((fails != 0))
