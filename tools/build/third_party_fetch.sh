#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Fetch third-party source trees (.gitmodules) at their pins: each one is a
# gitlink under third_party/, checked out at its path, shallow (one commit, no
# history), and verified (HEAD == the gitlink, the tag peels to it, no local
# change). Nothing fetched is run here: only `git fetch`, `git checkout` and,
# for relibc, `git submodule update` of the one submodule its build needs.
#
#   tools/build/third_party_fetch.sh <name>...   busybox limine linux relibc u-boot
#   tools/build/third_party_fetch.sh --all
#   add --force-icloud to fetch into a checkout inside iCloud Drive anyway
#
# Why not `git submodule update --init`: every entry is `update = none`, so a
# plain clone never pulls these trees (Linux alone is about 300 MB of pack for
# one shallow commit) into a checkout that does not build them, and above all
# not into the iCloud-synced main checkout, where iCloud duplicates files
# (build inputs included). This script is the one way in, and it refuses an
# iCloud checkout: fetch in a worktree outside it. Builds read the trees in
# place and never write into them (they copy, or build out of tree).
#
# A tree with a `tag` in .gitmodules is fetched by that tag (git.busybox.net
# serves no commit by id) and the tag must peel to the gitlink; one without
# (relibc, a commit of `master`) is fetched by commit.
#
# Linux is sparse: only the directories the crates/drivers/lx/ layer builds from or reads.
#   * Three uapi netfilter header directories are excluded: Linux ships pairs
#     of headers differing only in case (xt_CONNMARK.h / xt_connmark.h), which
#     a case-insensitive macOS volume cannot hold, so a full checkout there is
#     permanently "modified" and the pin row could never pass.
#   * Kbuild in a container (tools/build/lx_kbuild/) needs every `Kconfig*` file (the
#     top-level Kconfig sources them from all over the tree, and a missing one
#     is a hard error) and drivers/Makefile (an in-tree single-module target
#     descends through it). +1.7 MB.
#   * The x86_64 module build needs all of arch/x86/ (16 MB; its syscall
#     table is read on every arch, by the top-level Kbuild's missing-syscalls
#     check) and objtool's sources (4.4 MB): x86_64 selects OBJTOOL
#     unconditionally (HAVE_STATIC_CALL_INLINE, HAVE_UACCESS_VALIDATION), so
#     `modules_prepare` builds tools/objtool through tools/Makefile, with
#     tools/build, tools/lib, tools/scripts and the tools/arch/ headers of
#     both the host and the target. Without tools/Makefile, `make -s
#     modules_prepare` still succeeds (make finds no rule and the directory
#     tools/objtool exists), and the first module then fails on
#     "objtool: not found".
#   * drivers/net/ethernet/intel/igc and igb (1.4 MB) are the register-level
#     reference the native Intel NIC driver (crates/drivers/net/src/igc.rs) is
#     checked against: its host tests cite igc_regs.h, igc_defines.h, igc_hw.h
#     and igb's e1000_regs.h by name. They are read for facts, not built.
#   * drivers/i2c/busses/i2c-k1.c (24 KB) is the same kind of reference for
#     the native SpacemiT K1 I2C master (crates/drivers/bus/src/i2c_k1.rs).
#   * The ext4 stage adds /fs/Makefile (the same
#     descent for fs/ext4/ext4.ko and fs/jbd2/jbd2.ko) and /fs/mbcache.c
#     (EXT4_FS selects FS_MBCACHE). The rest of fs/ that ext4.ko imports from
#     (buffer.c, inode.c, dcache.c, ...) is checked out file by file, below.
#   * The next slices of the layer (Documentation/design/lx-driver-slices.md)
#     add exact files, 4.0 MiB in all. A sparse set chooses what is checked
#     out, not what is fetched: the depth-1 fetch of the pinned commit brings
#     every blob of it, so widening the set downloads nothing, and a tree
#     fetched earlier only needs this script re-run.
#     - ext4: the files that export what crates/drivers/lx/FS_EXT4_UNRESOLVED lists and are
#       not in a directory of the set already: 25 top-level files of fs/, four
#       of fs/iomap, six of block/, init/main.c (system_state), init/version.c
#       (init_uts_ns), drivers/char/random.c (get_random_*) and, for aarch64,
#       drivers/clocksource/arm_arch_timer.c (arch_timer_read_counter). The
#       slice decides which are compiled and which crates/drivers/lx/emul re-implements.
#     - the URB adapter: the HID core (hid-core, hid-input, hid-quirks,
#       hid-generic and their two local headers), usbhid, the first two quirk
#       leaves (hid-multitouch, hid-playstation), and the USB-core and
#       input-core files whose exports they call, which the adapter
#       re-implements over the native xHCI stack.
#     - the sensor pilot: imx219 (crates/drivers/lx/DEVICE_SOURCES) and the Makefiles that
#       descend to it, v4l2-core and mc (the subdev, control, fwnode and CCI
#       helpers it calls), and the I2C-core, regulator, clock and GPIO files
#       whose exports it calls, which the server provides over its
#       capabilities.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
gm="$root/.gitmodules"
die() { echo "third_party_fetch: $*" >&2; exit 1; }

linux_sparse() {
    cat <<'SPARSE'
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
/drivers/net/ethernet/intel/igc/
/drivers/net/ethernet/intel/igb/
/drivers/i2c/busses/i2c-k1.c
/scripts/
/LICENSES/
/tools/include/
Kconfig*
/arch/x86/
/tools/Makefile
/tools/objtool/
/tools/build/
/tools/lib/
/tools/scripts/
/tools/arch/
/drivers/Makefile
/fs/Makefile
/fs/mbcache.c
/fs/buffer.c
/fs/inode.c
/fs/dcache.c
/fs/libfs.c
/fs/fs_parser.c
/fs/fs-writeback.c
/fs/mnt_idmapping.c
/fs/read_write.c
/fs/seq_file.c
/fs/stat.c
/fs/attr.c
/fs/bad_inode.c
/fs/namespace.c
/fs/open.c
/fs/super.c
/fs/filesystems.c
/fs/ioctl.c
/fs/sync.c
/fs/d_path.c
/fs/file.c
/fs/file_attr.c
/fs/file_table.c
/fs/fserror.c
/fs/namei.c
/fs/splice.c
/fs/iomap/fiemap.c
/fs/iomap/seek.c
/fs/iomap/direct-io.c
/fs/iomap/swapfile.c
/block/bdev.c
/block/blk-core.c
/block/bio.c
/block/blk-lib.c
/block/blk-flush.c
/block/blk-ioc.c
/init/main.c
/init/version.c
/drivers/char/random.c
/drivers/clocksource/arm_arch_timer.c
/drivers/hid/Makefile
/drivers/hid/hid-core.c
/drivers/hid/hid-input.c
/drivers/hid/hid-quirks.c
/drivers/hid/hid-generic.c
/drivers/hid/hid-ids.h
/drivers/hid/hid-haptic.h
/drivers/hid/hid-multitouch.c
/drivers/hid/hid-playstation.c
/drivers/hid/usbhid/
/drivers/usb/core/urb.c
/drivers/usb/core/message.c
/drivers/usb/core/driver.c
/drivers/usb/core/usb.c
/drivers/usb/core/hub.c
/drivers/input/input.c
/drivers/input/input-mt.c
/drivers/input/ff-core.c
/drivers/input/ff-memless.c
/drivers/media/Makefile
/drivers/media/i2c/Makefile
/drivers/media/i2c/imx219.c
/drivers/media/v4l2-core/
/drivers/media/mc/
/drivers/i2c/i2c-core-base.c
/drivers/regulator/core.c
/drivers/regulator/devres.c
/drivers/clk/clk.c
/drivers/gpio/gpiolib.c
/drivers/gpio/gpiolib-devres.c
SPARSE
}

fetch_one() {
    local name="$1" key="submodule.third_party/$1" url tag commit dir got
    url="$(git config -f "$gm" "$key.url")" || die "no third_party/$name in .gitmodules"
    tag="$(git config -f "$gm" "$key.tag" || true)"
    commit="$(git -C "$root" ls-files -s "third_party/$name" | awk '$1 == "160000" { print $2 }')"
    [ -n "$commit" ] || die "third_party/$name is not a gitlink in the index"
    dir="$root/third_party/$name"

    mkdir -p "$dir"
    if [ ! -e "$dir/.git" ]; then
        git -C "$dir" init -q
        git -C "$dir" remote add origin "$url"
    fi
    git -C "$dir" remote set-url origin "$url"
    if [ "$name" = linux ]; then
        git -C "$dir" config core.sparseCheckout true
        git -C "$dir" sparse-checkout init --no-cone
        linux_sparse >"$(git -C "$dir" rev-parse --absolute-git-dir)/info/sparse-checkout"
    fi
    if [ -n "$tag" ]; then
        git -C "$dir" rev-parse -q --verify "refs/tags/$tag" >/dev/null \
            || git -C "$dir" fetch -q --depth 1 --no-tags origin "refs/tags/$tag:refs/tags/$tag"
        got="$(git -C "$dir" rev-parse "refs/tags/$tag^{commit}")"
        [ "$got" = "$commit" ] || die "$name: tag $tag is $got upstream, the gitlink is $commit"
    elif ! git -C "$dir" cat-file -e "$commit^{commit}" 2>/dev/null; then
        git -C "$dir" fetch -q --depth 1 --no-tags origin "$commit"
    fi
    git -C "$dir" checkout -q -f --detach "$commit"
    [ "$name" = linux ] && git -C "$dir" sparse-checkout reapply

    if [ "$name" = relibc ]; then
        # The allocator, at the commit relibc's own tree records, from the URL
        # relibc's own .gitmodules names.
        local rec
        rec="$(git -C "$dir" ls-tree HEAD dlmalloc-rs | awk '{ print $3 }')"
        [ -n "$rec" ] || die "relibc: the pinned tree records no dlmalloc-rs"
        git -C "$dir" submodule update -q --init --depth 1 dlmalloc-rs
        got="$(git -C "$dir/dlmalloc-rs" rev-parse HEAD)"
        [ "$got" = "$rec" ] || die "relibc: dlmalloc-rs HEAD is $got, the tree records $rec"
    fi

    got="$(git -C "$dir" rev-parse HEAD)"
    [ "$got" = "$commit" ] || die "$name: HEAD is $got, the gitlink is $commit"
    [ -z "$(git -C "$dir" status --porcelain --untracked-files=no)" ] \
        || die "$name: the checkout differs from $commit"
    echo "third_party_fetch: third_party/$name at ${tag:+$tag }($commit), shallow$([ "$name" != linux ] || echo ' + sparse')"
}

icloud_ok=0 names=()
for a in "$@"; do
    case "$a" in
        --force-icloud) icloud_ok=1 ;;
        --all) while read -r p; do names+=("${p#third_party/}"); done \
                   < <(git config -f "$gm" --get-regexp '^submodule\..*\.path$' | awk '{ print $2 }') ;;
        -*) die "unknown option $a" ;;
        *) names+=("$a") ;;
    esac
done
[ "${#names[@]}" -gt 0 ] || die "usage: tools/build/third_party_fetch.sh <name>... | --all [--force-icloud]"
case "$root" in
    *"Mobile Documents"*)
        [ "$icloud_ok" = 1 ] || die "$root is inside iCloud Drive; fetch in a worktree outside it (or pass --force-icloud)" ;;
esac
for n in "${names[@]}"; do fetch_one "$n"; done
