#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# QEMU proxy for a host bridge that TRANSLATES bus to CPU addresses. QEMU
# `virt` has none (its PCI windows are identity), so this edits the DTB it
# would hand the kernel: the 32-bit `ranges` entry keeps bus address
# 0x40000000 but claims the CPU sees it at 0x60000000. NOT run by any gate
# yet; run it by hand in the testing week:
#
#   KERNEL=<kernel ELF built with --features qemu,pci> \
#       bash tests/host/pci-tests/qemu-translated-window-proxy.sh
#
# riscv64 only (QEMU takes `-dtb` for `-kernel` boots there). What it proves
# is the kernel's side of the translation, not the data path:
#   * the host bridge line reports `mem32 0x40000000+0x40000000 -> cpu
#     0x60000000`: the window is handed out in BUS addresses and not refused
#     (the old line said "unusable ... needs bus == cpu");
#   * the root port at 00:04.0 gets its window at the BUS address
#     (`mem 0x40000000+0x100000`), the value a real translating bridge
#     forwards, not the CPU one.
# What it cannot prove: QEMU decodes the NIC's BARs at the bus address
# (identity), so the CPU access at 0x60000000 reaches nothing and the NIC
# cannot come up. The script therefore does NOT wait for the NIC; the data
# path through a real translation needs a board whose host bridge translates.
#
# Canary (by hand): restore the refusal in `resolve_bar_window` (hand out an
# empty window when `bus != cpu`): the host bridge line loses its `-> cpu`
# part and the bridge line is not printed, so the row goes red.
set -u
KERNEL="${KERNEL:?set KERNEL to the kernel built with the pci selection (CONFIG_DRV_PCI=y)}"
OUT="${AZOS_OUT:-$HOME/azos-out}/pci-translated-proxy"
mkdir -p "$OUT"
log="$OUT/proxy.log"
rm -f "$log" "$OUT/virt.dtb" "$OUT/virt.dts" "$OUT/xlat.dts" "$OUT/xlat.dtb"
if [ "$(pgrep -f qemu-system | wc -l)" -ge 4 ]; then
    echo "SKIP: four QEMU instances already run on this host" >&2
    exit 77
fi
command -v dtc >/dev/null || { echo "SKIP: dtc not installed" >&2; exit 77; }

RP="-device pcie-root-port,id=rp0,bus=pcie.0,chassis=1,addr=0x4"
NIC="-netdev user,id=net0 -device virtio-net-pci,bus=rp0,netdev=net0,disable-legacy=on"
# shellcheck disable=SC2086
qemu-system-riscv64 -machine virt,dumpdtb="$OUT/virt.dtb" $RP $NIC -nographic >/dev/null 2>&1
dtc -I dtb -O dts -o "$OUT/virt.dts" "$OUT/virt.dtb" 2>/dev/null
# <flags busHi busLo cpuHi cpuLo sizeHi sizeLo>: the 0x2000000 (32-bit memory)
# entry, CPU address 0x40000000 -> 0x60000000.
sed 's/\(0x2000000 0x00 0x40000000 0x00\) 0x40000000/\1 0x60000000/' "$OUT/virt.dts" >"$OUT/xlat.dts"
grep -q "0x2000000 0x00 0x40000000 0x00 0x60000000" "$OUT/xlat.dts" || { echo "FAIL: ranges entry not found in the QEMU DTB"; exit 1; }
dtc -I dts -O dtb -o "$OUT/xlat.dtb" "$OUT/xlat.dts" 2>/dev/null

# shellcheck disable=SC2086
qemu-system-riscv64 -machine virt -nographic -bios default -kernel "$KERNEL" -dtb "$OUT/xlat.dtb" $RP $NIC >"$log" 2>&1 &
qpid=$!
i=0
while [ "$i" -lt 30 ]; do
    grep -aq "\[PCI\] bridge 00:04.0" "$log" 2>/dev/null && break
    kill -0 "$qpid" 2>/dev/null || break
    i=$((i + 1)); sleep 1
done
kill "$qpid" 2>/dev/null; wait "$qpid" 2>/dev/null

fail() { echo "FAIL: $1 — log kept: $log"; exit 1; }
grep -aqF '[PCI] host bridge: ECAM 0x30000000 (dtb), mem32 0x40000000+0x40000000 -> cpu 0x60000000 (dtb), pref64 0x400000000+0x400000000 (dtb)' "$log" \
    || fail "host bridge line does not show the translated window"
grep -aqF 'unusable' "$log" && fail "the window is still refused"
grep -aqF '[PCI] bridge 00:04.0 buses 1-1 mem 0x40000000+0x100000 pref 0x400000000+0x100000' "$log" \
    || fail "the root port window is not programmed with the bus address"
echo "ok: translated window proxy"
rm -f "$log"
