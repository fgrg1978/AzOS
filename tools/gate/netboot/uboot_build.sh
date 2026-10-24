#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Build U-Boot for QEMU riscv64 (qemu-riscv64_smode: the S-mode U-Boot that
# OpenSBI starts) with this tree's
# configuration fragment, and print the path of u-boot.bin.
#
#   tools/gate/netboot/uboot_build.sh [outdir]
#
# The source is the gitlink third_party/u-boot (.gitmodules: its release
# tag), checked out by `tools/build/third_party_fetch.sh u-boot`; this script never
# downloads. U_BOOT_SRC points at a checkout elsewhere (it must be at the
# gitlink). It is built out of tree (`O=`) under <outdir> (default
# $AZOS_OUT/netboot) and never written; the build tree is removed once
# u-boot.bin is installed, so a repeat call with the same pin and fragment
# returns at once.
#
# Needs a riscv64 GCC (riscv64-unknown-elf-gcc), GNU make, and an LLD
# (`ld.lld`): the bare-metal GNU linker cannot make the -pie image U-Boot's
# RISC-V port links. rustc's own LLD (rustup `gcc-ld/ld.lld`) is used, so no
# extra tool is needed beyond the toolchain this tree already pins.
set -euo pipefail

here="$(cd "$(dirname "$0")/../../.." && pwd)"
export AZOS_OUT="${AZOS_OUT:-$(python3 "$here/tools/lib/out_dir.py")}"
out="${1:-$AZOS_OUT/netboot}"
src="${U_BOOT_SRC:-$here/third_party/u-boot}"
commit="$(git -C "$here" ls-files -s third_party/u-boot | awk '$1 == "160000" { print $2 }')"
frag="$here/tools/gate/netboot/uboot-qemu-riscv64.fragment"
bin="$out/u-boot-qemu-riscv64.bin"
stamp="$out/u-boot-qemu-riscv64.stamp"

[ -n "$commit" ] || { echo "uboot_build: third_party/u-boot is not a gitlink" >&2; exit 1; }
[ -e "$src/.git" ] && [ "$(git -C "$src" rev-parse HEAD)" = "$commit" ] && [ -z "$(git -C "$src" status --porcelain --untracked-files=no)" ] \
    || { echo "uboot_build: no clean U-Boot checkout at $commit in $src (tools/build/third_party_fetch.sh u-boot)" >&2; exit 1; }
# The stamp names this script too: a U-Boot an older recipe built is rebuilt.
want_stamp="$commit $(shasum -a 256 "$frag" "$0" | awk '{print $1}' | tr '\n' ' ')"
mkdir -p "$out"
if [ -f "$bin" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$want_stamp" ]; then echo "$bin"; exit 0; fi

command -v riscv64-unknown-elf-gcc >/dev/null || { echo "uboot_build: riscv64-unknown-elf-gcc not found" >&2; exit 1; }
gmake="$(command -v gmake || command -v make)"
lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/gcc-ld/ld.lld"
[ -x "$lld" ] || lld="$(command -v ld.lld || true)"
[ -n "$lld" ] || { echo "uboot_build: no ld.lld (rustup component llvm-tools / rust-lld, or an LLVM install)" >&2; exit 1; }
# The host tools U-Boot builds (mkimage, fdt tools) include <openssl/...>.
ssl=""
for d in /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3 /usr; do
    [ -f "$d/include/openssl/evp.h" ] && { ssl="$d"; break; }
done
hostcflags=""; hostldflags=""
if [ -n "$ssl" ] && [ "$ssl" != /usr ]; then hostcflags="-I$ssl/include"; hostldflags="-L$ssl/lib"; fi

bld="$out/u-boot-build"
rm -rf "$bld"
export CROSS_COMPILE=riscv64-unknown-elf-
# U-Boot's Kconfig honours KCONFIG_CONFIG as this tree's does. Inherited from
# the gate (tools/gate/ci_check.sh exports the primary column's), it made U-Boot
# configure, and rewrite, that file instead of $bld/.config, so the fragment
# appended there was never read: a U-Boot with its own defaults (distro boot,
# the EFI loader) that fetched the image by DHCP and asked for dtb/.
unset KCONFIG_CONFIG
jobs="${CARGO_BUILD_JOBS:-2}"
(
    cd "$src"
    "$gmake" O="$bld" qemu-riscv64_smode_defconfig >&2
    cat "$frag" >>"$bld/.config"
    "$gmake" O="$bld" olddefconfig >&2
    # A symbol the fragment sets that the defconfig expansion dropped would
    # leave a U-Boot that boots something else: say so.
    for sym in FIT_SIGNATURE RSA RSA_VERIFY; do
        grep -q "^CONFIG_$sym=y\$" "$bld/.config" || { echo "uboot_build: CONFIG_$sym was dropped" >&2; exit 1; }
    done
    grep -q '^CONFIG_BOOTCOMMAND="source ${scriptaddr}"$' "$bld/.config" || { echo "uboot_build: CONFIG_BOOTCOMMAND was dropped" >&2; exit 1; }
    "$gmake" O="$bld" -j"$jobs" LD="$lld" HOSTCFLAGS="$hostcflags" HOSTLDFLAGS="$hostldflags" >&2
)
# The binary's default environment is the proof the fragment was built in.
grep -aqF 'bootcmd=source ${scriptaddr}' "$bld/u-boot.bin" \
    || { echo "uboot_build: u-boot.bin does not run the netboot script (bootcmd)" >&2; exit 1; }
cp "$bld/u-boot.bin" "$bin"
printf '%s\n' "$want_stamp" >"$stamp"
rm -rf "$bld"
echo "$bin"
