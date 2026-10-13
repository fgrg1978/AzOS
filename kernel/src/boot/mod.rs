// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot-time install steps that `kernel_main` runs in order, one module per
//! subsystem. Everything is re-exported so `kernel_main` calls them by name.

mod early;
// The `[ISA]` boot line and the baseline/`require` refusals.
pub(crate) mod isa;
// SpinWait probe sites: the boot-once rewrite (wave 15, N2b).
pub(crate) mod spin_patch;
pub(crate) use early::early_main;
mod entropy;
pub(crate) use entropy::*;
mod config_auth;
pub(crate) use config_auth::*;
pub(crate) mod entropy_pool;
mod topology;
pub(crate) use topology::*;
#[cfg(feature = "energy")]
mod energy;
#[cfg(feature = "energy")]
pub(crate) use energy::*;
mod sched;
pub(crate) use sched::*;
mod blk_irq;
pub(crate) use blk_irq::*;
#[cfg(feature = "nvme")]
mod nvme;
#[cfg(feature = "nvme")]
pub(crate) use nvme::*;
#[cfg(feature = "virtio-input")]
mod input_irq;
#[cfg(feature = "virtio-input")]
pub(crate) use input_irq::*;
// Kconfig DRV_PS2 (x86_64 only; Kconfig keeps the feature off other ISAs).
#[cfg(feature = "ps2")]
mod ps2_irq;
#[cfg(feature = "ps2")]
pub(crate) use ps2_irq::*;

/// Wake the task parked on console input, as the UART arms do after they
/// queue a byte. Interrupt context. Returns whether a task was woken. Called
/// by the arms of the keyboards that feed the console's RX ring: virtio-input
/// and PS/2.
#[cfg(any(feature = "virtio-input", feature = "ps2"))]
pub(crate) fn console_rx_wake() -> bool {
    let tid = azos_drv_sys::uart::rx_waiter_take();
    tid != 0 && azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)))
}
// The hardware bus: enumeration, the driver registry, binding in stages.
pub(crate) mod hwbus;
mod net;
pub(crate) use net::*;
// DMA domains and IOMMUs (Kconfig "DMA and IOMMU").
mod dma;
pub(crate) use dma::*;
mod seams;
pub(crate) use seams::*;
mod procfs;
pub(crate) use procfs::*;
// Kconfig CHAOS / DECISION_RECORDS_DEV: command line, canaries, ktests.
pub(crate) mod chaos;
mod robot;
pub(crate) use robot::*;
mod ota;
pub(crate) use ota::*;
mod stacks;
pub(crate) use stacks::*;

/// [`azos_mm::vmm::map_mmio_region`], saying a refusal (N12i): the first
/// on the console, with the Kconfig symbol that bounds the record; every
/// one counted by `vmm::mmio_regions_refused`. `false` when refused.
///
/// Callers: early boot's device windows, the PCI ECAM and the boot hooks.
pub(crate) fn map_mmio_region(base: usize, size: usize) -> bool {
    use core::sync::atomic::{AtomicBool, Ordering};
    static SAID: AtomicBool = AtomicBool::new(false);
    match azos_mm::vmm::map_mmio_region(base, size) {
        Ok(()) => true,
        Err(e) => {
            if !SAID.swap(true, Ordering::Relaxed) {
                azos_drv_sys::kerr!("[MM] device window {:#x} (+{:#x}) NOT mapped: {:?}; the record holds \
                    MAX_MMIO_REGIONS = {} windows (make config); later refusals are counted, not printed",
                    base, size, e, azos_limits::MAX_MMIO_REGIONS);
            }
            false
        }
    }
}
mod percpu;
pub(crate) use percpu::*;
#[cfg(feature = "fb-generic")]
pub(crate) mod fb;
// Entered from `boot.S` by symbol (`#[no_mangle]`); nothing in Rust names them.
pub(crate) mod smp;
