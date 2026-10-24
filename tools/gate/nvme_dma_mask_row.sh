#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Gate row proxy for the per-device DMA limit (hwbus `Device::dma_mask`,
# `azos_dma::alloc_below`, the NVMe driver's queue and staging pages).
#
# QEMU's `virt` PCI host has no `dma-ranges` and its devices address every
# byte, so a default boot never exercises the limit. This boots the kernel on
# a copy of QEMU's own device tree with a `dma-ranges` added to the PCI host
# bridge node, in four variants of one machine (256 MiB of RAM at 0x80000000):
#
#   none   the tree as QEMU wrote it. NVMe is up; there is NO "DMA limit" line
#          (the unlimited path is unchanged).
#   above  dma-ranges [0, 4 GiB): the limit (0xffffffff) is above all of RAM.
#          NVMe is up, and the kernel says "[NVME] DMA limit 0xffffffff".
#   below  dma-ranges [0, 2 GiB): the limit (0x7fffffff) is under the first
#          byte of RAM. The controller can reach no free page: the kernel says
#          "no page at or below 0x7fffffff" and "controller ... not used", and
#          does not fault. If the limit were ignored NVMe would come up.
#   alias  dma-ranges bus 0xc0000000 -> CPU 0, 1 GiB (the Raspberry Pi shape):
#          a mask cannot describe it, so the limit is refused outright (0x0):
#          "no page at or below 0x0", "not used", no fault. If the translation
#          were ignored NVMe would come up and DMA to the wrong memory.
#
# Usage: tools/gate/nvme_dma_mask_row.sh <riscv64|aarch64> <kernel-image> <disk.img>
#   riscv64: the ELF built with `--features qemu,pci,nvme`.
#   aarch64: the flat Image built with `--features pci,nvme` (QEMU hands a DTB
#            pointer only to an Image).
# Needs qemu-system-<isa> and dtc. Exit 0 when every variant behaves.
# Run by the gate: `nvme: dma limit (riscv64)` in tools/gate/ci_check.sh.
set -u
isa="${1:?isa}"; kernel="${2:?kernel image}"; disk="${3:?disk image}"
work="$(mktemp -d "${TMPDIR:-/tmp}/nvme-dma.XXXXXX")"
trap 'rm -rf "$work"' EXIT

case "$isa" in
riscv64)
    qemu=qemu-system-riscv64
    machine="virt,aia=aplic-imsic"
    qargs=(-bios default -smp 1 -m 256M)
    ;;
aarch64)
    qemu=qemu-system-aarch64
    machine="virt,gic-version=3"
    qargs=(-cpu max,pauth=on -smp 2 -m 256M)
    ;;
*) echo "usage: $0 <riscv64|aarch64> <kernel-image> <disk.img>" >&2; exit 2 ;;
esac
nvme=(-drive "file=$disk,if=none,format=raw,id=nv" -device nvme,serial=x,drive=nv)

# QEMU's own tree for this exact machine (the kernel reads the memory and
# interrupt nodes from it, so it must be the one the variants edit).
"$qemu" -M "$machine,dumpdtb=$work/virt.dtb" "${qargs[@]}" -nographic >/dev/null 2>&1 \
    || { echo "dma limit ($isa): QEMU could not dump its device tree"; exit 1; }
dtc -I dtb -O dts "$work/virt.dtb" -o "$work/virt.dts" 2>/dev/null \
    || { echo "dma limit ($isa): dtc could not read the dump"; exit 1; }

# variant <name> <size-hi> <size-lo> [bus-address]: the PCI host bridge gets
# `dma-ranges = <child(3 cells) cpu(2 cells) size(2 cells)>` covering
# [0, size) at CPU 0, the bus address being 0 unless given.
variant() {
    local name="$1" hi="$2" lo="$3" bus="${4:-0x00}"
    awk -v hi="$hi" -v lo="$lo" -v bus="$bus" '
        { print }
        /compatible = "pci-host-ecam-generic";/ && hi != "" {
            printf "\t\tdma-ranges = <0x00 0x00 %s 0x00 0x00 %s %s>;\n", bus, hi, lo
        }' "$work/virt.dts" > "$work/$name.dts"
    dtc -I dts -O dtb "$work/$name.dts" -o "$work/$name.dtb" 2>/dev/null
}

boot() { # boot <name>: the log of a boot with that tree
    local name="$1" log="$work/$1.log" pid i=0
    "$qemu" -M "$machine" "${qargs[@]}" -nographic -dtb "$work/$name.dtb" -kernel "$kernel" "${nvme[@]}" \
        >"$log" 2>&1 &
    pid=$!
    while [ "$i" -lt 240 ]; do
        grep -aqE "NVME\] prp selftest (PASS|FAIL)|NVME\] controller .* not used|\[FATAL\]|EXCEPTION\]" "$log" 2>/dev/null && break
        kill -0 "$pid" 2>/dev/null || break
        i=$((i + 1)); sleep 0.5
    done
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    echo "$log"
}

fail=0
check() { # check <variant> <description> <grep -a pattern> <expect: yes|no>
    local log="$1" what="$2" pat="$3" want="$4" got=no
    grep -aqE "$pat" "$log" && got=yes
    if [ "$got" != "$want" ]; then
        local kept="${TMPDIR:-/tmp}/nvme-dma-$isa-$(basename "$log")"
        cp "$log" "$kept"
        echo "dma limit ($isa): $what: expected $want, log kept: $kept"
        fail=1
    fi
}

variant none "" ""
variant above 0x01 0x00
variant below 0x00 0x80000000
variant alias 0x00 0x40000000 0xc0000000

log="$(boot none)"
check "$log" "no dma-ranges: NVMe up"          "NVME\] controller [0-9a-f:.]+ ns1" yes
check "$log" "no dma-ranges: no limit line"    "NVME\] DMA limit"                  no
check "$log" "no dma-ranges: no fault"         "EXCEPTION\]|\[FATAL\]"             no

log="$(boot above)"
check "$log" "limit above RAM: limit line"     "NVME\] DMA limit 0xffffffff"       yes
check "$log" "limit above RAM: NVMe up"        "NVME\] controller [0-9a-f:.]+ ns1" yes
check "$log" "limit above RAM: no fault"       "EXCEPTION\]|\[FATAL\]"             no

log="$(boot below)"
check "$log" "limit under RAM: limit line"     "NVME\] DMA limit 0x7fffffff"       yes
check "$log" "limit under RAM: refusal"        "NVME\] no page at or below 0x7fffffff" yes
check "$log" "limit under RAM: not used"       "NVME\] controller .* not used"     yes
check "$log" "limit under RAM: NVMe not up"    "NVME\] controller [0-9a-f:.]+ ns1" no
check "$log" "limit under RAM: no fault"       "EXCEPTION\]|\[FATAL\]"             no

log="$(boot alias)"
check "$log" "translated bus: limit line"      "NVME\] DMA limit 0x0"                yes
check "$log" "translated bus: refusal"         "NVME\] no page at or below 0x0"      yes
check "$log" "translated bus: not used"        "NVME\] controller .* not used"       yes
check "$log" "translated bus: NVMe not up"     "NVME\] controller [0-9a-f:.]+ ns1"   no
check "$log" "translated bus: no fault"        "EXCEPTION\]|\[FATAL\]"               no

[ "$fail" -eq 0 ] && echo "dma limit ($isa): ok"
exit "$fail"
