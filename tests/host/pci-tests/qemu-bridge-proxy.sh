#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# QEMU proxy for the hardware QEMU `virt` normally hides: a PCIe root port
# (a PCI-to-PCI bridge) that no firmware numbered, with a virtio-net-pci
# behind it whose BAR4 is a 64-bit prefetchable memory BAR. Real boards put
# devices behind bridges and give them a 64-bit window; this boots the kernel
# on exactly that. NOT run by any gate yet: wire it as a row of
# tools/gate/ci_check.sh in the testing week (`kbuild "qemu,pci"` first), or run
# it by hand:
#
#   ISA=riscv64 KERNEL=<kernel ELF built with --features qemu,pci> \
#       bash tests/host/pci-tests/qemu-bridge-proxy.sh
#   ISA=aarch64 KERNEL=<flat Image: objcopy -O binary of the ELF> \
#       bash tests/host/pci-tests/qemu-bridge-proxy.sh
#
# What it proves (riscv64, PLIC machine, 39-bit Sv39, DTB mem64 window at
# 0x4_0000_0000, bus == CPU):
#   * the host bridge line names both windows from the DTB;
#   * the root port at 00:04.0 got buses 1-1 (the DTB has no bus numbers and
#     QEMU's -kernel boot runs no firmware, so it came out of enumerate_tree's
#     numbering), and a non-prefetchable window at the start of the 32-bit
#     window plus a prefetchable one at the start of the 64-bit window, each
#     1 MiB (the granule), covering the NIC's BAR1 (MSI-X) and BAR4;
#   * the NIC at 01:00.0 enumerates through the bridge and its driver comes
#     up (`mode=poll`: the PLIC machine has no MSI route; `mode=irq` on aarch64).
# aarch64 (4 KiB granule: 39-bit address space): the DTB's 64-bit window sits
# at 512 GiB, one past what the kernel can map, so the report says so and BAR4
# lands in the 32-bit window next to BAR1: one non-prefetchable window, no
# prefetchable one.
#
# Canaries (each must turn the row red; run by hand):
#   * drop `azos_pci::place_behind_bridges` from kernel/src/main.rs: no bridge
#     line, and the NIC's BARs are programmed outside any bridge window, so
#     the driver reads all-ones from them;
#   * drop the bus numbering in `enumerate_tree`: `01:00.0` is never listed.
# A QEMU that rejects `pcie-root-port` flags prints its own error into the log.
set -u
ISA="${ISA:-riscv64}"
KERNEL="${KERNEL:?set KERNEL to the kernel built with the pci selection (CONFIG_DRV_PCI=y)}"
OUT="${AZOS_OUT:-$HOME/azos-out}/pci-bridge-proxy"
mkdir -p "$OUT"
log="$OUT/proxy-$ISA.log"
rm -f "$log"
# Four QEMUs host-wide at most; this one is a single instance.
if [ "$(pgrep -f qemu-system | wc -l)" -ge 4 ]; then
    echo "SKIP: four QEMU instances already run on this host" >&2
    exit 77
fi

# Root port at slot 4 (the NIC is its only child); slot 3 is left free so
# the numbering below is the root port's alone.
RP="-device pcie-root-port,id=rp0,bus=pcie.0,chassis=1,addr=0x4"
NIC="-netdev user,id=net0 -device virtio-net-pci,bus=rp0,netdev=net0,disable-legacy=on"
case "$ISA" in
riscv64)
    qemu=qemu-system-riscv64
    # shellcheck disable=SC2086
    "$qemu" -machine virt -nographic -bios default -kernel "$KERNEL" $RP $NIC >"$log" 2>&1 &
    want_host='[PCI] host bridge: ECAM 0x30000000 (dtb), mem32 0x40000000+0x40000000 (dtb), pref64 0x400000000+0x400000000 (dtb)'
    want_bridge='[PCI] bridge 00:04.0 buses 1-1 mem 0x40000000+0x100000 pref 0x400000000+0x100000'
    ;;
aarch64)
    qemu=qemu-system-aarch64
    # shellcheck disable=SC2086
    "$qemu" -M virt,gic-version=3 -cpu max,pauth=on -nographic -kernel "$KERNEL" $RP $NIC >"$log" 2>&1 &
    want_host='[PCI] host bridge: ECAM 0x4010000000 (dtb), mem32 0x10000000+0x2eff0000 (dtb), pref64 0x0+0x0 (dtb, beyond the kernel'
    want_bridge='[PCI] bridge 00:04.0 buses 1-1 mem 0x10000000+0x100000'
    ;;
*)
    echo "ISA must be riscv64 or aarch64" >&2
    exit 2
    ;;
esac
qpid=$!
i=0
while [ "$i" -lt 60 ]; do
    grep -aq "\[NET\] virtio-net-pci 01:00.0\|not used" "$log" 2>/dev/null && break
    grep -aqE "EXCEPTION\]|panicked|FAILED" "$log" 2>/dev/null && break
    kill -0 "$qpid" 2>/dev/null || break
    i=$((i + 1)); sleep 1
done
kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null

fail() { echo "FAIL: $1 — log kept: $log"; exit 1; }
grep -aqE "EXCEPTION\]|panicked|FAILED" "$log" && fail "fault during bring-up"
grep -aqF "$want_host" "$log" || fail "host bridge line: wanted '$want_host'"
grep -aqF "$want_bridge" "$log" || fail "bridge line: wanted '$want_bridge'"
grep -aqE "\[PCI\] pci 01:00\.0 1af4:1041 " "$log" || fail "the NIC behind the bridge was not enumerated"
grep -aqE "\[NET\] virtio-net-pci 01:00\.0 mode=(poll|irq)" "$log" || fail "the NIC behind the bridge did not come up"
grep -aqF "not used" "$log" && fail "the NIC driver refused the function"
echo "ok: $ISA bridge proxy"
rm -f "$log"
