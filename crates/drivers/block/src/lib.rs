// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Block devices: the backend selection (`blkdev`, VirtIO, NVMe, AHCI or
//! SD/eMMC), the drivers (`mmc`: SDHCI, `dwmshc`: DesignWare MSHC, `ahci`, the
//! NVMe one), and the partition table parser.

#![no_std]

// The submit/wait request queue in front of a one-command-at-a-time
// controller (owner rule F1); `mmc` and `dwmshc` are its users.
pub mod dev_queue;

// The block request layer: per-hart submission queues with merge and plug in
// front of a device's hardware queue (`HwQueue`); `blkdev` is its synchronous
// facade for a device bound to it (NVMe today).
pub mod queue;

// SDHCI SD/eMMC driver: the SpacemiT K1's MMC blocks (`spacemit,k1-sdhci`);
// on QEMU only under `mmc-pci`, which binds it to a `sdhci-pci` BAR for the
// MMC flush row.
#[cfg(any(feature = "k1", feature = "mmc-pci"))]
pub mod mmc;

// DesignWare MSHC SD driver: the StarFive JH7110's SDIO blocks
// (`starfive,jh7110-mmc`), bound from the device tree by the hardware bus.
#[cfg(feature = "vf2")]
pub mod dwmshc;

// NVMe over PCIe (Kconfig DRV_NVME): the boot block device in place of
// virtio-blk when a controller was attached before `blkdev::init`.
#[cfg(feature = "nvme")]
pub mod nvme;
#[cfg(feature = "nvme")]
pub mod nvme_route;

// AHCI SATA host (Kconfig DRV_AHCI): a SATA disk as the boot block device
// when no NVMe controller took the role, over PCI (class 01:06:01) and MSI.
#[cfg(feature = "ahci")]
pub mod ahci;

// A USB mass-storage disk as a hardware queue of the request layer (Kconfig
// USB_STORAGE), with a request layer of its own: it is not the boot disk.
#[cfg(feature = "usb-msc")]
pub mod usb_msc;

// Partition table parser, and the table the disk capability is scoped by.
// Pure; `tests/host/fs-tests` pulls it with `#[path]`.
pub mod partition;

// Block device abstraction: routes to NVMe (when attached), VirtIO (QEMU),
// the DesignWare MSHC (VF2) or SDHCI (K1).
pub mod blkdev;

pub mod write_observer;
