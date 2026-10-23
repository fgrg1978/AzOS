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
# A module spelled `fs:<SYMBOL>=<path>` belongs to the filesystem set: the same configuration and build as the others, copied to
# /out/<arch>/fs/ instead of /out/<arch>/ (its imports are not yet all
# provided, so tools/lx_license_lint.py gates it by a recorded list, not by
# the K3 rule of the validated set).
#
# `linux` builds the comparison Linux kernel (Image), lxbench.ko and an
# initramfs, from the FULL pinned tree that run.sh streams in with `git
# archive` (extracted to /work/linux, container-local), with the modules'
# configuration plus <arch>.linux.config (the difference is recorded in
# <isa>/config-vs-modules.diff).
#
# <arch> is riscv, arm64 or x86_64 (Linux ARCH names). x86_64, not x86:
# Kconfig then fixes 64BIT=y (under ARCH=x86, tinyconfig answers that prompt
# n and builds i386 unless a fragment says otherwise), and the output
# directory is already the ISA's name. Configures tinyconfig + common.config +
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
    x86_64) cross=x86_64-linux-gnu- ;;
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
for m in "$@"; do m="${m#fs:}"; echo "CONFIG_${m%%=*}=m" >> "$frag"; done
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
# arm64: Linux 7.2 always compiles its atomics, load-acquire and per-CPU base
# reads with run-time alternatives (LSE atomics, LDAPR, and TPIDR_EL1 vs
# TPIDR_EL2 under VHE), so any module that takes a spinlock or touches a
# per-CPU variable carries a `.altinstructions` table, which the loader
# refuses (it has no patcher). The original sequence of each of those is the
# one a CPU without the feature runs (LL/SC, LDAR, TPIDR_EL1), so leaving the
# table out leaves that baseline in place; AzOS runs no VHE kernel. The table
# is dropped only after every entry's capability number, taken from the header
# Kbuild generated from the pinned tree's own list, is one of those three; an
# erratum workaround, or any other capability, fails the build instead of
# being silently left unpatched. An entry with the callback bit set (bit 15 of
# the capability) has no fixed alternative sequence: a callback fills its
# original code in at patch time, and that code may be a placeholder, so
# dropping the table would leave the placeholder in the module. Such an entry
# is refused (reported as `cb:<cap>`), with one exception: the callback
# alt_cb_patch_nops, which is what alternative_has_cap_likely() uses
# (`b l_no` at the site, rewritten to NOPs only when the capability is
# present). Its original is a real branch, the capability-absent path, so
# leaving it is leaving the baseline. The entry's callback is read from the
# relocation of its `alt` field, in .rela.altinstructions. (Whether the
# baseline can RUN in ring 3 is a separate question: `current` and the per-CPU
# base are MRS SP_EL0 and MRS TPIDR_EL1, which are UNDEFINED at EL0. The slice
# has to answer that.)
strip_opt_alts() { # <ko>
    ko="$1"
    "${cross}objdump" -h "$ko" | grep -q ' \.altinstructions ' || return 0
    # Capability numbers come from the header Kbuild generated from the
    # pinned tree's own list (arch/arm64/tools/cpucaps).
    defs="$o/arch/arm64/include/generated/asm/cpucap-defs.h"
    ok="$(sed -n -e 's/^#define ARM64_HAS_LSE_ATOMICS[[:space:]]*//p' -e 's/^#define ARM64_HAS_LDAPR[[:space:]]*//p' -e 's/^#define ARM64_HAS_VIRT_HOST_EXTN[[:space:]]*//p' "$defs" | tr '\n' ' ')"
    [ "$(echo $ok | wc -w)" = 3 ] || { echo "kbuild-in: $defs: HAS_LSE_ATOMICS / HAS_LDAPR / HAS_VIRT_HOST_EXTN not found" >&2; exit 1; }
    "${cross}objcopy" --dump-section .altinstructions=/work/alt.bin "$ko" /work/alt.ko
    # struct alt_instr: s32 orig, s32 alt, u16 cpucap (bit 15: callback, refused), u8 orig_len, u8 alt_len.
    # Entries (index = r_offset / 12) whose alt field relocates against alt_cb_patch_nops.
    nops="$("${cross}objdump" -r -j .altinstructions "$ko" | awk '
        function hex(s,  i, v) { v = 0; s = tolower(s); for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
        $2 ~ /^R_AARCH64_/ && $3 == "alt_cb_patch_nops" && hex($1) % 12 == 4 { printf "%d ", int(hex($1) / 12) }')"
    bad="$(od -An -v -tu2 -w12 /work/alt.bin | awk -v ok="$ok" -v nops="$nops" '
        BEGIN { n = split(ok, a, " "); for (i = 1; i <= n; i++) good[a[i]] = 1
                n = split(nops, a, " "); for (i = 1; i <= n; i++) isnops[a[i]] = 1 }
        { c = $5; cb = (c >= 32768); if (cb) c -= 32768
          if (!(c in good) || (cb && !((NR - 1) in isnops))) print (cb ? "cb:" : "") c }' | sort -u | tr '\n' ' ')"
    if [ -n "$bad" ]; then
        echo "kbuild-in: $ko: .altinstructions carries capabilities ($bad) that are not optimisation-only (allowed: $ok)" >&2
        exit 1
    fi
    "${cross}objcopy" --remove-section .altinstructions "$ko" /work/alt.ko
    if "${cross}objdump" -h /work/alt.ko | grep -q altinstr; then
        echo "kbuild-in: $ko: objcopy left an altinstructions section behind" >&2; exit 1
    fi
    mv /work/alt.ko "$ko"
}
if [ "$arch" = arm64 ]; then
    for m in "$@"; do strip_opt_alts "$o/${m#*=}"; done
fi
mkdir -p "/out/$arch/fs"
cp "/work/glue-$arch/lxbase.ko" "/out/$arch/"
for m in "$@"; do
    case "$m" in
        fs:*) cp "$o/${m#*=}" "/out/$arch/fs/" ;;
        *) cp "$o/${m#*=}" "/out/$arch/" ;;
    esac
done
rmdir "/out/$arch/fs" 2>/dev/null || true
cp "$o/.config" "/out/$arch/config"
cp "$o/include/config/kernel.release" "/out/$arch/kernel.release"
echo "kbuild-in: $arch: $(cat "$o/include/config/kernel.release")"
