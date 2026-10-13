#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Runs INSIDE the lx-kbuild container (tools/lx_kbuild/Containerfile), never
# on the host; tools/lx_kbuild/run.sh starts it with --network=none and
# these mounts: /src = the pinned Linux tree (read-only), /cfg = this
# directory (read-only), /glue = lx/glue (read-only), /out = where the
# results land (read-write).
#
#   kbuild-in.sh <arch> <SYMBOL>=<path/in/tree.ko> ...
#   kbuild-in.sh xz <in> <out>
#   kbuild-in.sh linux <arch> <SYMBOL>=<path/in/tree.ko> ...
#
# `linux` builds the comparison Linux kernel (Image), lxbench.ko and an
# initramfs, from the FULL pinned tree that run.sh streams in with `git
# archive` (extracted to /work/linux, container-local), with the modules'
# configuration plus <arch>.linux.config (the difference is recorded in
# <isa>/config-vs-modules.diff).
#
# <arch> is riscv or arm64. Configures tinyconfig + common.config +
# <arch>.config + each SYMBOL=m in a fresh O= directory inside the
# container, runs modules_prepare, builds lx/glue as an external module
# (lxbase.ko) and each upstream module as an in-tree single target: Linux's
# own sources compiled by Linux's own Kbuild, the tree never written.
set -eu
export LC_ALL=C TZ=UTC
if [ "$1" = xz ]; then
    # The decompression fixture: one xz stream, CRC32 check (the check
    # type Linux's xz_dec verifies), fixed preset, single-threaded.
    xz --format=xz --check=crc32 -6 --threads=1 -c "$2" > "$3"
    exit 0
fi
mode=modules
if [ "$1" = linux ]; then mode=linux; shift; fi
src=/src; [ "$mode" = linux ] && src=/work/linux
arch="$1"; shift
case "$arch" in
    riscv) cross=riscv64-linux-gnu- ;;
    arm64) cross=aarch64-linux-gnu- ;;
    *) echo "kbuild-in: unknown arch $arch" >&2; exit 2 ;;
esac
o="/work/$mode-$arch"   # container-local: the host mount is slow and case-insensitive
# A fixed build identity: the .ko must not depend on who, where or when.
export KBUILD_BUILD_TIMESTAMP='1970-01-01' KBUILD_BUILD_USER=lx KBUILD_BUILD_HOST=azos \
       KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=0
# Unresolved imports are reported, not fatal, here: there is no vmlinux.
# tools/lx_license_lint.py --ko is the real check (imports must be the host
# ABI or exports of modules loaded earlier).
export KBUILD_MODPOST_WARN=1
mk() { make -s -C "$src" O="$o" ARCH="$arch" CROSS_COMPILE="$cross" LOCALVERSION= -j"$(nproc)" "$@"; }
rm -rf "$o"; mkdir -p "$o"
frag="$o/lx.fragment"
cat /cfg/common.config "/cfg/$arch.config" > "$frag"
for m in "$@"; do echo "CONFIG_${m%%=*}=m" >> "$frag"; done
# The comparison kernel is Linux at its best on this ISA: <arch>.linux.config
# turns on what modules cannot have (ISA extensions whose code is patched in
# with `.alternative`, which the AzOS loader refuses) but vmlinux uses.
if [ "$mode" = linux ] && [ -f "/cfg/$arch.linux.config" ]; then
    for sym in $(sed -n 's/^\(CONFIG_[A-Z0-9_]*\)=.*/\1/p' "/cfg/$arch.linux.config"); do
        grep -v -x "# $sym is not set" "$frag" > "$frag.tmp"; mv "$frag.tmp" "$frag"
    done
    cat "/cfg/$arch.linux.config" >> "$frag"
fi
mk tinyconfig >/dev/null
"$src/scripts/kconfig/merge_config.sh" -m -O "$o" "$o/.config" "$frag" >/dev/null
mk olddefconfig >/dev/null
# Every requested line must have survived olddefconfig (a dependency it
# lacks silently drops it, and the build would then prove nothing).
grep -v -E '^#|^$' "$frag" | while read -r want; do
    grep -qxF "$want" "$o/.config" || { echo "kbuild-in: $arch: '$want' did not survive olddefconfig" >&2; exit 1; }
done
grep -E '^# CONFIG_[A-Z0-9_]+ is not set' "$frag" | while read -r _ sym _; do
    if grep -q "^$sym=" "$o/.config"; then echo "kbuild-in: $arch: $sym is still set" >&2; exit 1; fi
done
if [ "$mode" = linux ]; then
    isa=riscv64; [ "$arch" = arm64 ] && isa=aarch64
    # Record exactly how this kernel's config differs from the modules'
    # (only the <arch>.linux.config lines and what they select).
    diff "/mods/$isa/config" "$o/.config" | grep -E '^[<>] ' > "/work/config-$arch.diff" || true
    mk Image
    mk modules_prepare
    rm -rf "/work/bench-$arch"; cp -R /glue/bench "/work/bench-$arch"
    quiet() {
        if ! mk "$@" > "$o/step.log" 2>&1; then cat "$o/step.log" >&2; exit 1; fi
        grep -v -E 'WARNING: modpost: "|modpost: suppressed|vmlinux.o is missing|Module.symvers is missing|Modules may not have|You may get many|KBUILD_MODPOST_WARN=1 to turn|proceed at your own risk' "$o/step.log" || true
    }
    quiet M="/work/bench-$arch" modules
    "${cross}gcc" -static -nostdlib -ffreestanding -fno-pic -no-pie -O2 -Wall -Werror \
        -o "/work/init-$arch" /bench-src/init.c
    gcc -O2 -o /work/gen_init_cpio "$src/usr/gen_init_cpio.c"
    cat > "/work/initramfs-$arch.list" <<LIST
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
file /init /work/init-$arch 0755 0 0
file /xz_dec.ko /mods/$isa/xz_dec.ko 0644 0 0
file /lxbench.ko /work/bench-$arch/lxbench.ko 0644 0 0
file /XZTEST.XZ /mods/XZTEST.XZ 0644 0 0
LIST
    mkdir -p "/out/$isa"
    /work/gen_init_cpio "/work/initramfs-$arch.list" > "/out/$isa/initramfs.cpio"
    cp "$o/arch/$arch/boot/Image" "/out/$isa/Image"
    cp "/work/config-$arch.diff" "/out/$isa/config-vs-modules.diff"
    echo "kbuild-in: linux $arch: Image + initramfs ($(cat "$o/include/config/kernel.release"))"
    exit 0
fi
mk modules_prepare
# The base: lx/glue as an external module, built from a copy because
# Kbuild writes an external module's objects next to its sources.
rm -rf "/work/glue-$arch"; cp -R /glue "/work/glue-$arch"
# modpost's "undefined" and "vmlinux.o is missing" warnings are expected
# (see KBUILD_MODPOST_WARN above) and filtered; a failing make prints all.
quiet() {
    if ! mk "$@" > "$o/step.log" 2>&1; then cat "$o/step.log" >&2; exit 1; fi
    grep -v -E 'WARNING: modpost: "|modpost: suppressed|vmlinux.o is missing|Module.symvers is missing|Modules may not have|You may get many|KBUILD_MODPOST_WARN=1 to turn|proceed at your own risk' "$o/step.log" || true
}
quiet M="/work/glue-$arch" modules
for m in "$@"; do quiet "${m#*=}"; done
mkdir -p "/out/$arch"
cp "/work/glue-$arch/lxbase.ko" "/out/$arch/"
for m in "$@"; do cp "$o/${m#*=}" "/out/$arch/"; done
cp "$o/.config" "/out/$arch/config"
cp "$o/include/config/kernel.release" "/out/$arch/kernel.release"
echo "kbuild-in: $arch: $(cat "$o/include/config/kernel.release")"
