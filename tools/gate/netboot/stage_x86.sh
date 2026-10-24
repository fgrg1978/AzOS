#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Stage the x86_64 netboot server root: Limine's EFI loader, its configuration
# and the AzOS kernel, the three things a PC fetches over the network when it has
# nothing on a disk (UEFI PXE: the TFTP root; UEFI HTTP Boot: the FAT image
# built from it).
#
#   tools/gate/netboot/stage_x86.sh <kernel.elf> <outdir> [--tamper kernel|config] [--image <esp.img>]
#
#   <outdir>/BOOTX64.EFI      Limine, the configuration's BLAKE2B enrolled
#   <outdir>/limine.conf      one entry, the kernel named with its BLAKE2B
#   <outdir>/boot/kernel.elf  the image (the `make x86_64-limine` ELF)
#
# Verification (Limine's, the loader the firmware runs): `limine enroll-config`
# writes the configuration's BLAKE2B-512 into BOOTX64.EFI, so a limine.conf
# that is not the one staged is refused; the configuration names the kernel
# with its own BLAKE2B (`path: ...#<hash>`), so a kernel that is not the one
# staged is refused. Both checks are made by the loader on the bytes it
# fetched, before it jumps to them. What authenticates BOOTX64.EFI itself is
# the firmware's own Secure Boot, which these QEMU rows do not turn on.
#
# --tamper changes one byte of the kernel (or appends a line to the
# configuration) AFTER the hash is taken: the canary for the check.
# --image also writes a FAT16 image of the root (the RAM disk UEFI HTTP Boot
# loads when its URL names a .img).
#
# Limine comes from LIMINE_DIR (a release's binary branch; default the
# gitlink third_party/limine, tools/build/third_party_fetch.sh limine); its host tool is built from the limine.c that ships with
# it into $AZOS_OUT/netboot/limine/.
set -euo pipefail

kernel="${1:?usage: stage_x86.sh <kernel.elf> <outdir> [--tamper kernel|config] [--image <esp.img>]}"
out="${2:?usage: stage_x86.sh <kernel.elf> <outdir> [--tamper kernel|config] [--image <esp.img>]}"
shift 2
tamper=""; image=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tamper) tamper="${2:?}"; shift 2 ;;
        --image) image="${2:?}"; shift 2 ;;
        *) echo "stage_x86: unknown argument $1" >&2; exit 2 ;;
    esac
done
case "$tamper" in ""|kernel|config) ;; *) echo "stage_x86: --tamper kernel|config" >&2; exit 2 ;; esac

here="$(cd "$(dirname "$0")/../../.." && pwd)"
export AZOS_OUT="${AZOS_OUT:-$(python3 "$here/tools/lib/out_dir.py")}"
limine_dir="${LIMINE_DIR:-$here/third_party/limine}"
[ -f "$limine_dir/BOOTX64.EFI" ] && [ -f "$limine_dir/limine.c" ] \
    || { echo "stage_x86: $limine_dir has no BOOTX64.EFI and limine.c (set LIMINE_DIR to a Limine binary release)" >&2; exit 1; }
[ -f "$kernel" ] || { echo "stage_x86: no kernel at $kernel" >&2; exit 1; }

tool="$AZOS_OUT/netboot/limine/limine"
if [ ! -x "$tool" ] || [ "$limine_dir/limine.c" -nt "$tool" ]; then
    mkdir -p "$(dirname "$tool")"
    # Rows run in parallel: build beside the tool and rename, so none of them
    # ever executes a half-written file.
    cc -O2 -std=c99 -o "$tool.$$" "$limine_dir/limine.c" && mv -f "$tool.$$" "$tool"
fi
b2() { python3 -c 'import hashlib,sys; print(hashlib.blake2b(open(sys.argv[1], "rb").read()).hexdigest())' "$1"; }

rm -rf "$out"; mkdir -p "$out/boot"
out="$(cd "$out" && pwd)"
cp "$kernel" "$out/boot/kernel.elf"
cp "$limine_dir/BOOTX64.EFI" "$out/BOOTX64.EFI"
printf 'timeout: 0\nserial: yes\n\n/AzOS\n    protocol: limine\n    path: boot():/boot/kernel.elf#%s\n' \
    "$(b2 "$out/boot/kernel.elf")" >"$out/limine.conf"
"$tool" enroll-config --quiet "$out/BOOTX64.EFI" "$(b2 "$out/limine.conf")" >/dev/null
case "$tamper" in
    kernel) printf '\377' | dd of="$out/boot/kernel.elf" bs=1 seek=4096 conv=notrunc 2>/dev/null ;;
    config) printf '    comment: tampered\n' >>"$out/limine.conf" ;;
esac

if [ -n "$image" ]; then
    kib=$(( ( $(wc -c <"$out/boot/kernel.elf") + $(wc -c <"$out/BOOTX64.EFI") ) / 1024 + 1024 ))
    kib=$(( (kib + 1023) / 1024 * 1024 ))
    [ "$kib" -ge 8192 ] || kib=8192
    rm -f "$image"
    mkfs.fat -F 16 -C "$image" "$kib" >/dev/null
    mmd -i "$image" ::EFI ::EFI/BOOT ::boot
    mcopy -i "$image" "$out/BOOTX64.EFI" ::EFI/BOOT/BOOTX64.EFI
    mcopy -i "$image" "$out/limine.conf" ::limine.conf
    mcopy -i "$image" "$out/boot/kernel.elf" ::boot/kernel.elf
fi
echo "$out"
