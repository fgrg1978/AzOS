#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Build the QEMU development kernel of one ISA as the file a network boot
# fetches, and print its path:
#
#   tools/gate/netboot/kernel_image.sh <riscv64|x86_64> [outdir]
#
#   riscv64  a flat binary linked at 0x80200000 (the ELF through
#            objcopy -O binary)
#   x86_64   the Limine ELF (the `x86_64-limine` build of mk/qemu.mk), debug
#            info stripped: the ELF is ~60 MB with it and ~7 MB without, and
#            the loader reads every byte over the network
#
# There is no aarch64 image: no network-boot path of this tree runs the arm64
# `Image` (see Documentation/building.md).
#
# The configuration is the ISA's QEMU defconfig as it stands (no rows' extras),
# expanded into <outdir> and built in a cargo target directory of its own there
# (default $AZOS_OUT/build/netboot-<isa>), so it never rebuilds or overwrites
# the gate's images. The digest tables of the user images are the Makefile's,
# made first when missing; the recipes are the Makefile's own (`build`,
# `x86_64` with the `x86_64-limine` variables in mk/kernel.mk, mk/qemu.mk) with
# the configuration and the target directory swapped, as tools/image/kaslr_image.sh
# does for the KASLR rows.
set -euo pipefail

isa="${1:-}"
case "$isa" in riscv64|x86_64) ;; *) echo "usage: $0 <riscv64|x86_64> [outdir]" >&2; exit 2 ;; esac
here="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$here"
export AZOS_OUT="${AZOS_OUT:-$(python3 tools/lib/out_dir.py)}"
out="${2:-$AZOS_OUT/build/netboot-$isa}"
mkdir -p "$out"
cargo="${CARGO:-$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}"
host="$(rustc -vV | sed -n 's/^host: //p')"
objcopy="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-objcopy"

case "$isa" in
    riscv64)
        cfg="$out/riscv64.config"; tdir="$out/target"
        cp config/defconfigs/robot-sbc-riscv64-dev+qemu+linux+gui.config "$cfg"
        KCONFIG_CONFIG="$cfg" python3 -m olddefconfig >/dev/null
        make "$AZOS_OUT/build/image_hashes.rs" >&2
        rf="$(python3 tools/build/kconfig_to_cargo.py --rustflags --toml --skip-base "$cfg")"
        isa_cfg=""; [ -z "$rf" ] || isa_cfg="target.riscv64imac-unknown-none-elf.rustflags=[$rf]"
        # shellcheck disable=SC2046
        KCONFIG_CONFIG="$cfg" CARGO_TARGET_DIR="$tdir" "$cargo" build --release -p azos_kernel \
            ${isa_cfg:+--config "$isa_cfg"} $(python3 tools/build/kconfig_to_cargo.py "$cfg") >&2
        "$objcopy" -O binary "$tdir/riscv64imac-unknown-none-elf/release/kernel" "$out/kernel-riscv64.bin"
        echo "$out/kernel-riscv64.bin"
        ;;
    x86_64)
        cfg="$out/x86_64.config"; tdir="$out/target"
        cp config/defconfigs/robot-sbc-x86_64-dev+qemu+linux+limine.config "$cfg"
        KCONFIG_CONFIG="$cfg" python3 -m olddefconfig >/dev/null
        make "$AZOS_OUT/build/image_hashes_x86_64.rs" >&2
        # shellcheck disable=SC2046
        env -u CARGO_BUILD_RUSTFLAGS KCONFIG_CONFIG="$cfg" CARGO_TARGET_DIR="$tdir" \
            RUSTFLAGS="-C link-arg=-Tarch/x86_64/boot/linker-x86_64-limine.ld -C relocation-model=static --cfg curve25519_dalek_backend=\"serial\" $(python3 tools/build/kconfig_to_cargo.py --rustflags "$cfg")" \
            "$cargo" build --release -p azos_kernel $(python3 tools/build/kconfig_to_cargo.py "$cfg" | tr -s ' ') >&2
        "$objcopy" --strip-debug "$tdir/x86_64-unknown-none/release/kernel" "$out/kernel-x86_64-limine.elf"
        echo "$out/kernel-x86_64-limine.elf"
        ;;
esac
