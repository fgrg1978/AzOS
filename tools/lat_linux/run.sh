#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The Linux counterpart of the AzOS `lat:` rows (wave 13, RT7): the same
# measurement and load as kernel/src/lat_smoke.rs (tools/lat_linux/lat.c),
# as /init of an initramfs, under the same QEMU arguments as the rows
# (-smp 1 -icount shift=0,sleep=off; one virtual ns per guest instruction).
# The disk the reader reads is a copy of the AzOS row's own image.
#
#   tools/lat_linux/run.sh <rv|arm> <linux Image> <disk image> <outdir>
#
# Prints the guest's `[LATLX]` lines. Exit 0 when they came, 1 otherwise.
# `PROG=tail` runs tail.c instead (the periodic-wake tail under ping-pong
# contention, kernel/src/smokes/tail_smoke.rs's counterpart): `[TAIL]` lines.
# Not a gate row: the Linux image is an environment choice, as vsbench's.
set -euo pipefail
isa="${1:?isa}"; image="${2:?linux Image}"; disk="${3:?disk}"; out="${4:?outdir}"
here="$(cd "$(dirname "$0")" && pwd)"
prog="${PROG:-lat}"
cc="${LX_CC:-/opt/homebrew/opt/llvm/bin/clang}"
lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
mkdir -p "$out/root"; out="$(cd "$out" && pwd)"
common=(-ffreestanding -fno-builtin -fno-pic -fno-stack-protector -O2 -Wall -Wextra -Werror)
if [ "$isa" = rv ]; then
    "$cc" --target=riscv64-unknown-linux-gnu -march=rv64imac -mabi=lp64 -mcmodel=medany -mno-relax \
        "${common[@]}" -c "$here/$prog.c" -o "$out/lat.o"
else
    "$cc" --target=aarch64-unknown-linux-gnu -mgeneral-regs-only "${common[@]}" -c "$here/$prog.c" -o "$out/lat.o"
fi
"$lld" -flavor gnu -static -e _start -o "$out/root/init" "$out/lat.o"
chmod +x "$out/root/init"
( cd "$out/root" && find . | cpio -o -H newc ) > "$out/initramfs.cpio" 2>/dev/null
cp "$disk" "$out/disk.img"
log="$out/linux.log"
if [ "$isa" = rv ]; then
    qemu-system-riscv64 -machine virt -nographic -bios default -smp 1 -icount shift=0,sleep=off \
        -kernel "$image" -initrd "$out/initramfs.cpio" -append "rdinit=/init console=ttyS0" \
        -drive file="$out/disk.img",if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0 \
        </dev/null >"$log" 2>&1 &
else
    qemu-system-aarch64 -M virt,gic-version=3 -cpu max,pauth=on -smp 1 -icount shift=0,sleep=off -nographic \
        -kernel "$image" -initrd "$out/initramfs.cpio" -append "rdinit=/init console=ttyAMA0" \
        -drive file="$out/disk.img",if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0 \
        </dev/null >"$log" 2>&1 &
fi
pid=$!
for _ in $(seq 1 1200); do
    grep -aq "^\[\(LATLX\|TAIL\)\] done" "$log" 2>/dev/null && break
    grep -aq "Kernel panic" "$log" 2>/dev/null && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
done
kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
rm -f "$out/disk.img"
tr -d '\r' < "$log" | grep -a "^\[\(LATLX\|TAIL\)\] \(isa\|load\)" || { echo "lat_linux: no result line, log: $log" >&2; exit 1; }
