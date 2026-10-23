#!/bin/bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Build one QEMU development kernel for virtual KASLR (Kconfig KASLR) and print
# the path of the image to boot:
#
#   tools/kaslr_image.sh <riscv64|aarch64|x86_64> <slid|plain> [outdir]
#
# slid:  the ISA's QEMU defconfig with CONFIG_KASLR_PROBE=y (the position-
#        independent link: kernel/build.rs, with the codegen half from
#        tools/kconfig_to_cargo.py kaslr_rustflags).
# plain: the same with CONFIG_KASLR_NEVER=y, the canary of tools/
#        kaslr_boot_row.sh (a judge that reads "slid" here passes an image
#        that does nothing).
#
# KASLR_EXTRA_FEATURES (comma-separated) adds kernel features to the riscv64
# build (the `display: ramfb on a slid kernel` rows: `ramfb`, and its canary);
# such an image wants its own [outdir].
#
# Each build has its own config and its own cargo target directory under
# <outdir> (default $AZOS_OUT/build/kaslr-<isa>-<mode>), so it never rebuilds
# or overwrites the gate's images. The user images and their digest tables
# (build/image_hashes*.rs) are the Makefile's, made first when missing. The
# recipes are the Makefile's own (`build`, `aarch64`, `x86_64` in mk/kernel.mk)
# with the config and the target directory swapped.
#
# Output: the image path on stdout, diagnostics on stderr. Exit 0 = built. The
# riscv64 and aarch64 images are flat binaries (llvm-objcopy -O binary), the
# x86_64 one the ELF its PVH entry note lives in.

set -eu

isa="${1:-}"; mode="${2:-}"
case "$isa" in riscv64|aarch64|x86_64) ;; *) echo "usage: $0 <riscv64|aarch64|x86_64> <slid|plain> [outdir]" >&2; exit 2 ;; esac
case "$mode" in slid|plain) ;; *) echo "usage: $0 <riscv64|aarch64|x86_64> <slid|plain> [outdir]" >&2; exit 2 ;; esac

here="$(cd "$(dirname "$0")/.." && pwd)"
cd "$here"
export AZOS_OUT="${AZOS_OUT:-$(python3 tools/out_dir.py)}"
out="${3:-$AZOS_OUT/build/kaslr-$isa-$mode}"
mkdir -p "$out"
cfg="$out/$isa.config"
tdir="$out/target"
cargo="${CARGO:-$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}"

case "$isa" in
    riscv64) defcfg=config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config ;;
    aarch64) defcfg=config/defconfigs/robot-sbc-aarch64-dev+qemu+linux+gui.config ;;
    x86_64)  defcfg=config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+gui.config ;;
esac
cp "$defcfg" "$cfg"
if [ "$mode" = slid ]; then echo "CONFIG_KASLR_PROBE=y" >>"$cfg"; else echo "CONFIG_KASLR_NEVER=y" >>"$cfg"; fi
KCONFIG_CONFIG="$cfg" python3 -m olddefconfig >/dev/null
want=$([ "$mode" = slid ] && echo CONFIG_KASLR_PROBE || echo CONFIG_KASLR_NEVER)
if ! grep -qx "$want=y" "$cfg"; then
    echo "kaslr_image: $cfg lost $want=y (is KASLR available on $isa under $defcfg?)" >&2
    exit 1
fi

# The digest tables the kernel include!s, from the Makefile.
case "$isa" in
    riscv64) make "$AZOS_OUT/build/image_hashes.rs" >&2 ;;
    aarch64) make "$AZOS_OUT/build/image_hashes_aarch64.rs" >&2 ;;
    x86_64)  make "$AZOS_OUT/build/image_hashes_x86_64.rs" >&2 ;;
esac

# The dynamic relocations of the ELF, as the boot walk will see them: a slid
# image holds thousands of the ISA's R_*_RELATIVE and nothing else (one
# GLOB_DAT or R_*_64 makes the boot refuse the table under both probe and
# require); a plain one holds none (KASLR n leaves the link as it was).
reloc_lint() { # reloc_lint <elf> <R_*_RELATIVE name>
    local objdump n other rels
    objdump="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objdump"
    [ -f "$1" ] || { echo "kaslr_image: no ELF at $1" >&2; exit 1; }
    # A failing objdump must not read as "no relocations".
    if ! rels="$("$objdump" -R "$1" 2>&1)"; then
        # An image that is not a position-independent link has no dynamic section.
        if [ "$mode" = plain ] && printf '%s' "$rels" | grep -q "not a dynamic object"; then return 0; fi
        echo "kaslr_image: llvm-objdump -R $1 failed: $rels" >&2
        exit 1
    fi
    n="$(printf '%s\n' "$rels" | awk -v t="$2" '$2 == t' | wc -l | tr -d ' ')"
    other="$(printf '%s\n' "$rels" | awk -v t="$2" 'NF >= 3 && $1 ~ /^[0-9a-f]+$/ && $2 != t' | wc -l | tr -d ' ')"
    if [ "$mode" = slid ]; then
        if [ "$other" != 0 ] || [ "$n" -lt 1000 ]; then
            echo "kaslr_image: $1: $n $2 and $other other dynamic relocations (want thousands of the first, none of the second)" >&2
            printf '%s\n' "$rels" | awk -v t="$2" 'NF >= 3 && $1 ~ /^[0-9a-f]+$/ && $2 != t' | sed -n 1,5p >&2
            exit 1
        fi
    elif [ "$n" != 0 ] || [ "$other" != 0 ]; then
        echo "kaslr_image: $1: a KASLR n image holds $((n + other)) dynamic relocations" >&2
        exit 1
    fi
}

case "$isa" in
    riscv64)
        rf="$(python3 tools/kconfig_to_cargo.py --rustflags --toml --skip-base "$cfg")"
        isa_cfg=""; [ -z "$rf" ] || isa_cfg="target.riscv64imac-unknown-none-elf.rustflags=[$rf]"
        # shellcheck disable=SC2046
        KCONFIG_CONFIG="$cfg" CARGO_TARGET_DIR="$tdir" "$cargo" build --release -p azos_kernel --features "qemu${KASLR_EXTRA_FEATURES:+,$KASLR_EXTRA_FEATURES}" \
            ${isa_cfg:+--config "$isa_cfg"} $(python3 tools/kconfig_to_cargo.py --base "$cfg") >&2
        reloc_lint "$tdir/riscv64imac-unknown-none-elf/release/kernel" R_RISCV_RELATIVE
        # A flat binary, as the boards take it (VF2/K1 `kernel.bin`): QEMU puts a
        # raw `-kernel` at the start of RAM past the firmware, where the image is
        # linked, and does not have to accept the ET_DYN file a -pie link makes.
        objcopy="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
        "$objcopy" -O binary "$tdir/riscv64imac-unknown-none-elf/release/kernel" "$out/kernel-riscv64.bin"
        echo "$out/kernel-riscv64.bin"
        ;;
    aarch64)
        # shellcheck disable=SC2046
        env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$cfg" CARGO_TARGET_DIR="$tdir" \
            RUSTFLAGS="-C link-arg=-Tkernel/linker-aarch64.ld $(python3 tools/kconfig_to_cargo.py --rustflags "$cfg")" \
            "$cargo" build --release -p azos_kernel $(python3 tools/kconfig_to_cargo.py "$cfg" | tr -s ' ') >&2
        reloc_lint "$tdir/aarch64-unknown-none-softfloat/release/kernel" R_AARCH64_RELATIVE
        objcopy="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
        "$objcopy" -O binary "$tdir/aarch64-unknown-none-softfloat/release/kernel" "$out/kernel-aarch64.img"
        echo "$out/kernel-aarch64.img"
        ;;
    x86_64)
        # shellcheck disable=SC2046
        env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$cfg" CARGO_TARGET_DIR="$tdir" \
            RUSTFLAGS="-C link-arg=-Tkernel/linker-x86_64.ld -C relocation-model=static --cfg curve25519_dalek_backend=\"serial\" $(python3 tools/kconfig_to_cargo.py --rustflags "$cfg")" \
            "$cargo" build --release -p azos_kernel $(python3 tools/kconfig_to_cargo.py "$cfg" | tr -s ' ') >&2
        reloc_lint "$tdir/x86_64-unknown-none/release/kernel" R_X86_64_RELATIVE
        echo "$tdir/x86_64-unknown-none/release/kernel"
        ;;
esac
