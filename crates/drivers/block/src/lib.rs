// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Block devices: the backend selection (`blkdev`, VirtIO or SD/eMMC), the
//! SD/eMMC driver, and the partition table parser.

#![no_std]

// eMMC / SD driver (real hardware; on QEMU only under `mmc-pci`, which binds
// it to a `sdhci-pci` BAR for the MMC flush row).
#[cfg(any(feature = "vf2", feature = "k1", feature = "mmc-pci"))]
pub mod mmc;

// Partition table parser + the table the disk capability is scoped by
// (RFC-0048 P3). Pure; `tests/host/fs-tests` pulls it with `#[path]`.
pub mod partition;

// Block device abstraction: routes to VirtIO (QEMU) or SDHCI (VF2).
pub mod blkdev;

pub mod write_observer;
