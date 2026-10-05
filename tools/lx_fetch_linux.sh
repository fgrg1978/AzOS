#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Fetch third_party/linux at the pinned commit (lx/LINUX_PIN): shallow (one
# commit, no history) and sparse (only the directories the lx/ layer will
# build from), RFC-0053 4.5 and stage L0.
#
# Why not `git submodule update --init`: the submodule is marked
# `update = none` in .gitmodules so that a plain clone or `submodule update`
# never pulls the Linux tree (about 300 MB of pack for one shallow commit)
# into a checkout that does not build the layer, and in particular not into
# the iCloud-synced main checkout, whose memory notes record iCloud
# duplicates corrupting fixtures. This script is the one way in.
#
# The sparse set excludes three uapi netfilter header directories: Linux
# ships pairs of headers differing only in case (xt_CONNMARK.h /
# xt_connmark.h), which a case-insensitive macOS volume cannot hold, so a
# full checkout there is permanently "modified" and the gate's
# "submodule == pin" check could never pass. No class RFC-0053 plans needs them.
#
# Stage L1 (Kbuild in a container, tools/lx_kbuild/) adds what configuring
# and preparing a tree needs beyond the source directories: every `Kconfig*`
# file (the top-level Kconfig sources them from all over the tree, and a
# missing one is a hard error), x86's syscall table (the top-level Kbuild's
# missing-syscalls check reads it on every arch) and drivers/Makefile (an
# in-tree single-module target descends through it). +1.7 MB.
#
# Usage: tools/lx_fetch_linux.sh [--force-icloud]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
pin="$root/lx/LINUX_PIN"
url="$(sed -n 's/^url=//p' "$pin")"
commit="$(sed -n 's/^commit=//p' "$pin")"
tag="$(sed -n 's/^tag=//p' "$pin")"
dir="$root/third_party/linux"

case "$root" in
    *"Mobile Documents"*)
        if [ "${1:-}" != "--force-icloud" ]; then
            echo "lx_fetch_linux: $root is inside iCloud Drive; fetch in a worktree outside it" >&2
            echo "                (or pass --force-icloud to do it anyway)" >&2
            exit 2
        fi ;;
esac

mkdir -p "$dir"
if [ ! -e "$dir/.git" ]; then
    git -C "$dir" init -q
    git -C "$dir" remote add origin "$url"
fi
git -C "$dir" config core.sparseCheckout true
git -C "$dir" sparse-checkout init --no-cone
mkdir -p "$(git -C "$dir" rev-parse --absolute-git-dir)/info"
cat > "$(git -C "$dir" rev-parse --absolute-git-dir)/info/sparse-checkout" <<'SPARSE'
/*
!/*/
/include/
!/include/uapi/linux/netfilter/
!/include/uapi/linux/netfilter_ipv4/
!/include/uapi/linux/netfilter_ipv6/
/arch/riscv/
/arch/arm64/
/fs/ext2/
/fs/ext4/
/fs/jbd2/
/kernel/
/lib/
/mm/
/drivers/base/
/scripts/
/LICENSES/
/tools/include/
Kconfig*
/arch/x86/entry/syscalls/
/drivers/Makefile
SPARSE
if ! git -C "$dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
    git -C "$dir" fetch --depth 1 --no-tags origin "$commit"
fi
git -C "$dir" checkout -q -f "$commit"
git -C "$dir" sparse-checkout reapply
got="$(git -C "$dir" rev-parse HEAD)"
[ "$got" = "$commit" ] || { echo "lx_fetch_linux: HEAD is $got, pin is $commit" >&2; exit 1; }
git -C "$dir" diff --quiet || { echo "lx_fetch_linux: the checkout differs from $tag" >&2; exit 1; }
echo "lx_fetch_linux: third_party/linux at $tag ($commit), shallow + sparse"
