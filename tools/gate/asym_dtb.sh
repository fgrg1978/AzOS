#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# QEMU's own device tree with CPUs that differ: the first half are the small
# ones. On riscv64 the last CPU also lacks Zbb. asym_dtb.sh <rv|arm> <cpus> <out>
set -e
isa="$1" n="$2" out="$3"
if [ "$isa" = rv ]; then
    qemu-system-riscv64 -machine virt,dumpdtb="$out" -nographic -bios default -smp "$n" >/dev/null 2>&1
else
    "$(dirname "$0")/qemu_a64.py" --tcg -M virt,gic-version=3,dumpdtb="$out" -cpu max,pauth=on -smp "$n" -nographic >/dev/null 2>&1
fi
c=0
while [ "$c" -lt "$n" ]; do
    cap=512
    [ "$c" -ge $((n / 2)) ] && cap=1024
    fdtput -t i "$out" "/cpus/cpu@$c" capacity-dmips-mhz "$cap"
    c=$((c + 1))
done
if [ "$isa" = rv ]; then
    last="/cpus/cpu@$((n - 1))"
    fdtput -t s "$out" "$last" riscv,isa "$(fdtget -t s "$out" "$last" riscv,isa | sed 's/_zbb_/_/')"
    set --
    for w in $(fdtget -t s "$out" "$last" riscv,isa-extensions); do
        [ "$w" = zbb ] || set -- "$@" "$w"
    done
    fdtput -t s "$out" "$last" riscv,isa-extensions "$@"
fi
