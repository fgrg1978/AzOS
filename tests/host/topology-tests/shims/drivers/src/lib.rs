// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for the driver class crates (`azos_drv_*`), reduced to what
//! the topology bridge reads: the hardware bus, the PLIC bound and
//! the partition table, as `mmio_cap.rs`, `irq_bind.rs` and `disk_cap.rs` need
//! them.
//!
//! **WHY this exists.** The real `azos_drv_*` is RV64-only (its `azos_arch`
//! MMIO/CSR chain), so it cannot be built for the host. But
//! `tests/host/topology-tests` compiles the real minters to test the P1
//! topology→cap_store bridge (`crates/core/ipc/src/cap_seed.rs`) end to end --
//! the bridge's job is `CapSpec.target` string → `resource` id → minted cap,
//! and the only way to prove that without reimplementing the minters is to
//! compile the real ones.

/// The board constants — the REAL module, not a stub (constants and `const
/// fn`s, nothing in it needs a device).
#[path = "../../../../../../crates/drivers/base/src/platform.rs"]
pub mod platform;

/// The hardware bus's static instance and its two lookups — the REAL module.
/// `mmio_cap` mints and resolves against it; `mmio_cap_tests` fills it.
#[path = "../../../../../../crates/drivers/bus/src/hwbus.rs"]
pub mod hwbus;

/// PLIC line bound for the host `irq_bind` stand-in (QEMU virt has 96 real
/// sources; the kernel constant is the same order of magnitude).
pub mod plic {
    pub const MAX_IRQS: u32 = 1024;
}

/// The partition table parser and the published table `Cap<Disk>` is scoped
/// by partition (see `partition.rs`) — the REAL module: it names only `core`.
#[path = "../../../../../../crates/drivers/block/src/partition.rs"]
pub mod partition;
