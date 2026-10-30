#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Gate row: the desktop preset boots clean on aarch64 QEMU `virt` at EL1.
#
# The preset asks for the hypervisor (Kconfig VIRT_SPLIT, so HV) and so has a
# `VMMD.ELF` row, but this boot has no EL2 to keep and no `[guest.*]` row: the
# kernel installs no monitor and `vm.0` answers NOT_READY. `VMMD.ELF` then has
# nothing to serve, and used to exit with an error, be restarted three times
# and be given up on by the component manager, with every row that imports its
# `vmctl` stopped behind it. The row is left out of the manager's plan
# (`boot::hv::install_hv`) and, were it started, the monitor ends cleanly
# (NOT_READY is a clean exit in `userspace/services/vmmd`).
#
# Judged on one boot of the whole system, built the way a user builds it
# (`make defconfig-...`, `make build`, in a private output directory so the
# gate's own cells are untouched):
#   - `[HV] VMMD.ELF not started: no monitor on this boot` is said once;
#   - the manager never starts, restarts, gives up on or blocks behind VMMD.ELF;
#   - the console program has the console (the boot is not the recovery one);
#   - no `guest did not run` line (the stall credit is not fed by an idle disk);
#   - no panic, no unhandled trap.
# Canaries, by hand (each reverted): `mark_unstartable` left out of
# `install_hv` -> `[compmgr] start VMMD.ELF` and a clean exit; and also the
# NOT_READY test left out of vmmd -> start, restart x3, give-up.
#
# Usage: tools/gate/vmmd_withhold_row.sh <defconfig name> [qemu seconds]
# Needs the gate's environment (PATH, CARGO_NET_OFFLINE) and `AZOS_OUT`; builds
# under $VMMD_WITHHOLD_OUT (default $AZOS_OUT/vmmd-withhold), kept between runs
# so only the first one builds everything. Exit 0 when the boot is clean.
set -u
defc="${1:?defconfig name, e.g. desktop-desktop-aarch64-dev+qemu}"
secs="${2:-90}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${VMMD_WITHHOLD_OUT:-${AZOS_OUT:?AZOS_OUT}/vmmd-withhold}"
log="$out/boot.log"
mkdir -p "$out"
cfg="$out/row.config"
unset CARGO_TARGET_DIR
cd "$root" || exit 1

env AZOS_OUT="$out" KCONFIG_CONFIG="$cfg" make "defconfig-$defc" >"$out/defconfig.log" 2>&1 \
    || { echo "vmmd withhold: make defconfig-$defc failed, log: $out/defconfig.log"; exit 1; }
for want in CONFIG_ARCH_AARCH64=y CONFIG_HV=y CONFIG_USERSPACE_VMMD=y; do
    grep -qx "$want" "$cfg" || { echo "vmmd withhold: $defc does not hold $want: the row would prove nothing"; exit 1; }
done
env AZOS_OUT="$out" KCONFIG_CONFIG="$cfg" make build >"$out/build.log" 2>&1 \
    || { echo "vmmd withhold: make build failed, log: $out/build.log"; exit 1; }
kernel="$out/build/kernel-aarch64.img"
volume="$out/build/disk-aarch64-sh.img"
[ -f "$kernel" ] && [ -f "$volume" ] || { echo "vmmd withhold: make build left no kernel or volume under $out/build"; exit 1; }
cp "$volume" "$out/boot.img"

while [ $(( $(pgrep -x qemu-system-riscv64 | wc -l) + $(pgrep -x qemu-system-aarch64 | wc -l) + $(pgrep -x qemu-system-x86_64 | wc -l) )) -ge 4 ]; do sleep 2; done
# EL1: no `virtualization=on`, as `make qemu` boots.
qemu-system-aarch64 -M virt,gic-version=3 -cpu max,pauth=on -smp 2 -m 1G -nographic \
    -global virtio-mmio.force-legacy=false \
    -drive file="$out/boot.img",if=none,format=raw,id=hd0 -device virtio-blk-device,drive=hd0 \
    -device virtio-rng-device -kernel "$kernel" </dev/null >"$log" 2>&1 &
pid=$!
i=0
while [ "$i" -lt $((secs * 2)) ] && kill -0 "$pid" 2>/dev/null; do
    grep -aqE "!!! KERNEL PANIC !!!|AARCH64-TRAP\] unhandled" "$log" 2>/dev/null && break
    grep -aqE "\[CONSOLE\] user shell tid=[0-9]+ has the console" "$log" 2>/dev/null && [ "$i" -ge 60 ] && break
    i=$((i + 1)); sleep 0.5
done
# Run on after the console is up: a restart or a stall line comes later.
sleep 20
kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
rm -f "$out/boot.img"
tr -d '\r' <"$log" >"$log.t" && mv "$log.t" "$log"

fail=0
need() { # need <description> <fixed string>
    grep -aqF "$2" "$log" || { echo "vmmd withhold: $1: '$2' is not in the log"; fail=1; }
}
forbid() { # forbid <description> <ere>
    if grep -aqE "$2" "$log"; then
        echo "vmmd withhold: $1:"; grep -aE "$2" "$log" | sed -n '1,4p' | sed 's/^/    /'; fail=1
    fi
}
need "the row is left out of the plan" "[HV] VMMD.ELF not started: no monitor on this boot"
forbid "the manager touched VMMD.ELF" "\[compmgr\] (start|restart|exit|stopped|give-up|blocked) VMMD\.ELF"
forbid "a component was given up on or blocked" "\[compmgr\] (give-up|blocked) "
forbid "the monitor was started with nothing to serve" "\[vmmd\] "
forbid "the stall credit was fed by an idle disk" "guest did not run for"
forbid "the kernel panicked or trapped" "!!! KERNEL PANIC !!!|AARCH64-TRAP\] unhandled"
grep -aqE "\[CONSOLE\] user shell tid=[0-9]+ has the console" "$log" \
    || { echo "vmmd withhold: the console program never took the console"; fail=1; }
[ "$fail" -eq 0 ] && { echo "vmmd withhold ($defc): ok"; rm -f "$log"; exit 0; }
echo "vmmd withhold: log kept: $log"
exit 1
