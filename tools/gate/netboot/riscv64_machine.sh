# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# The riscv64 netboot machine, sourced by stage_riscv64.sh and row.sh: one
# definition, because the device tree the key is added to has to describe the
# machine the row boots, and the two used to be two lists.
#
# RV_LOAD    where the kernel is linked (kernel/linker.ld) and U-Boot loads it
# RV_SCRIPT  U-Boot's ${scriptaddr} (include/configs/qemu-riscv.h): where its
#            boot.scr is read to
RV_LOAD=0x80200000
RV_SCRIPT=0x8c100000
# After `-machine virt`; the dump adds its option to that one.
RV_COMMON=(-m 256M -smp 2 -nographic -no-reboot -bios default)

rv_dumpdtb() { # rv_dumpdtb <out.dtb>: QEMU's device tree for the machine (writes it and exits)
    qemu-system-riscv64 -machine "virt,dumpdtb=$1" "${RV_COMMON[@]}" >/dev/null 2>&1 </dev/null || true
    [ -s "$1" ] || { echo "rv_dumpdtb: QEMU wrote no device tree to $1" >&2; return 1; }
}
