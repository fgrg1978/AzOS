#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#
# Runs INSIDE the lx-kbuild container, started by tools/build/lx_kbuild/run.sh vsbench
# with /work/linux = the pinned Linux tree (git archive of the gitlink) and /out = where
# the image lands. Builds the Linux kernel the Linux column of vsbench boots
# (tools/bench/vsbench_linux.conf): the ISA's defconfig plus the options below, none of
# which may be silently dropped by Kconfig (each one is checked in the result).
#
#   vsbench_linux_in.sh <riscv|arm64|x86_64>
set -eu
arch="$1"
cd /work/linux
o=/work/o
case "$arch" in
riscv)  cross=riscv64-linux-gnu-; target=Image;   name=Image-riscv64;   base="defconfig" ;;
arm64)  cross=aarch64-linux-gnu-; target=Image;   name=Image-aarch64;   base="defconfig" ;;
x86_64) cross=x86_64-linux-gnu-;  target=bzImage; name=bzImage-x86_64; base="x86_64_defconfig kvm_guest.config" ;;
*) echo "vsbench_linux_in: unknown arch $arch" >&2; exit 2 ;;
esac
mk() { make -s ARCH="$arch" CROSS_COMPILE="$cross" O="$o" "$@"; }

# virtio-mmio/pci, virtio-blk/net/rng, vfat, devtmpfs, initramfs and TCP/IP built in (vsbench boots with no modules).
on="VIRTIO VIRTIO_MMIO VIRTIO_PCI VIRTIO_BLK VIRTIO_NET HW_RANDOM HW_RANDOM_VIRTIO BLOCK BLK_DEV NET INET VFAT_FS FAT_FS
    NLS_CODEPAGE_437 NLS_ISO8859_1 DEVTMPFS DEVTMPFS_MOUNT BLK_DEV_INITRD TTY PREEMPT_NONE"
# PREEMPT_NONE and HZ=250; the riscv64 defconfig's debug options off, as arm64 and x86_64 already are.
off="PREEMPT_VOLUNTARY PREEMPT PREEMPT_DYNAMIC HZ_100 HZ_300 HZ_1000"
case "$arch" in
riscv) off="$off DEBUG_PAGEALLOC DEBUG_VM DEBUG_VM_PGFLAGS DEBUG_SPINLOCK DEBUG_MUTEXES DEBUG_LIST DEBUG_ATOMIC_SLEEP" ;;
esac
on="$on HZ_250"

mkdir -p "$o"
mk $base
args=""
for s in $on; do args="$args -e $s"; done
for s in $off; do args="$args -d $s"; done
scripts/config --file "$o/.config" $args
mk olddefconfig
for s in $on; do grep -q "^CONFIG_$s=y" "$o/.config" || { echo "vsbench_linux_in: CONFIG_$s did not stay y for $arch" >&2; exit 1; }; done
for s in $off; do grep -q "^CONFIG_$s=y" "$o/.config" && { echo "vsbench_linux_in: CONFIG_$s stayed y for $arch" >&2; exit 1; }; done
grep -q '^CONFIG_HZ=250' "$o/.config" || { echo "vsbench_linux_in: HZ is not 250 for $arch" >&2; exit 1; }
mk -j"$(nproc)" "$target"
case "$arch" in
x86_64) cp "$o/arch/x86/boot/bzImage" "/out/$name" ;;
*)      cp "$o/arch/$arch/boot/Image" "/out/$name" ;;
esac
cp "$o/.config" "/out/$name.config"
echo "vsbench_linux_in: $name"
