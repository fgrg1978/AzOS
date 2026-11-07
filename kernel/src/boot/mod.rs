// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot-time install steps that `kernel_main` runs in order, one module per
//! subsystem. Everything is re-exported so `kernel_main` calls them by name.
//!
//! `kernel_main`'s boot phases are functions here and in `tasks` and `smokes`,
//! each a stretch of its sequence, called in the order the stretches had in
//! its one body. Each is `#[inline(always)]`: the boot still runs in one frame
//! on the boot stack, the frame the boot-stack line (`boot_stack_report`) and
//! the frame row (`stack_frames.py --boot kernel_main`) read.

mod early;
pub(crate) mod caches;
// The `[ISA]` boot line and the baseline/`require` refusals.
pub(crate) mod isa;
// SpinWait probe sites: the boot-once rewrite (wave 15, N2b).
pub(crate) mod spin_patch;
// Signed kernel livepatch (Kconfig LIVEPATCH): the boot re-apply of the topology's rows.
mod livepatch;
pub(crate) use livepatch::install_livepatch;
pub(crate) use early::early_main;
// kernel_main's Phase 6: the bus, entropy, PCI, the block device and the mounts.
mod devices;
pub(crate) use devices::bring_up_devices;
// kernel_main's Phase G2: CONFIG.INI, the OTA slots, the link and operator keys.
mod persist;
pub(crate) use persist::recover_persistent_state;
mod entropy;
pub(crate) use entropy::*;
// Kconfig TPM: the TPM 2.0 as an entropy source, the boot measurements and the OTA floor.
#[cfg(feature = "tpm")]
pub(crate) mod tpm;
// Kconfig DRV_RTC: the real-time clock seeds the wall clock before the network.
#[cfg(feature = "rtc")]
pub(crate) mod rtc;
mod config_auth;
pub(crate) use config_auth::*;
pub(crate) mod entropy_pool;
mod topology;
pub(crate) use topology::*;
#[cfg(feature = "energy")]
mod energy;
#[cfg(feature = "energy")]
pub(crate) mod thermal;
#[cfg(feature = "energy")]
pub(crate) use energy::*;
// Kconfig INSPECT: the introspection tree (kernel state as read-only MemObjs).
// The terminal server's two kernel-owned regions: the input event ring and
// the console screen (Kconfig DRV_VIRTIO_INPUT / DRV_PS2 / USB_HID / FB_CONSOLE).
#[cfg(any(feature = "virtio-input", feature = "ps2", feature = "usb-hid", feature = "fb-console"))]
pub(crate) mod term_regions;
// Kconfig KLOG: the structured kernel log's ring, as a kernel-owned region.
pub(crate) mod klog_region;
#[cfg(feature = "inspect")]
mod inspect;
#[cfg(feature = "inspect")]
mod inspect_metrics;
#[cfg(feature = "inspect")]
mod inspect_tasks;
#[cfg(feature = "inspect")]
mod inspect_views;
#[cfg(feature = "inspect")]
pub(crate) use inspect::install_inspect;
#[cfg(all(feature = "inspect", feature = "lat-trace", feature = "lat-smoke"))]
pub(crate) use inspect::refresh_now as inspect_refresh_now;
#[cfg(all(feature = "inspect", feature = "lat-trace"))]
pub(crate) use inspect::public_str as inspect_public_str;
/// The decimal name of an introspection-tree node numbered `n` (for the
/// latency subtree, outside this module).
#[cfg(all(feature = "inspect", feature = "lat-trace"))]
pub(crate) fn inspect_num(n: u64) -> inspect_metrics::Num {
    inspect_metrics::Num::name("", n)
}
mod sched;
pub(crate) use sched::*;
// kernel_main's Phase 5: the topology and what it declares, then the scheduler.
mod sched_init;
pub(crate) use sched_init::init_scheduler;
// The boot launcher: the component manager and the rows that move between hosts.
mod launch;
pub(crate) use launch::*;
// Storage L11 part B: the page cache's hooks into the file layer.
pub(crate) mod pagecache;
mod blk_irq;
pub(crate) use blk_irq::*;
#[cfg(feature = "nvme")]
mod nvme;
#[cfg(feature = "nvme")]
pub(crate) use nvme::*;
#[cfg(feature = "ahci")]
mod ahci;
#[cfg(feature = "ahci")]
pub(crate) use ahci::*;
// Kconfig USB_HOST: the native USB host (kernel/src/boot/usb.rs).
#[cfg(feature = "usb-host")]
pub(crate) mod usb;
// Kconfig USB_HID: the kernel's side of the USB HID class driver (the sink of its events).
#[cfg(feature = "usb-hid")]
mod usb_hid;
#[cfg(feature = "virtio-input")]
mod input_irq;
#[cfg(feature = "virtio-input")]
pub(crate) use input_irq::*;
// Kconfig DRV_VIRTIO_SND: the virtio-sound device's interrupt wiring.
#[cfg(feature = "virtio-snd")]
pub(crate) mod snd_irq;
// Kconfig DRV_PS2 (x86_64 only; Kconfig keeps the feature off other ISAs).
#[cfg(feature = "ps2")]
mod ps2_irq;
#[cfg(feature = "ps2")]
pub(crate) use ps2_irq::*;

/// Wake the task parked on console input, as the UART arms do after they
/// queue a byte. Interrupt context. Returns whether a task was woken. Called
/// by the arms of the keyboards that feed the console's RX ring: virtio-input
/// and PS/2; and, from task context, by the `usb` task after the HID driver
/// queued input and by the pump task after the USB serial console did.
#[cfg(any(feature = "virtio-input", feature = "ps2", feature = "usb-hid", feature = "usb-cdc-console"))]
pub(crate) fn console_rx_wake() -> bool {
    let tid = azos_drv_sys::uart::rx_waiter_take();
    tid != 0 && azos_sched::scheduler::wake_task_by_tid(
        tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)))
}
// Kconfig MM_SWAP_BACKEND: the swap partition's boot step (claim, key, attach).
pub(crate) mod swap;
// Kconfig HV (VIRT is not none): the topology's guest rows, admitted at boot.
#[cfg(feature = "hv")]
mod hv;
#[cfg(feature = "hv")]
pub(crate) use hv::install_hv;
// The hardware bus: enumeration, binding in stages; the driver records it binds through.
pub(crate) mod hwbus;
pub(crate) mod driver_records;
// Kconfig SOC_FRAMEWORKS: the clock, reset, regulator and power-domain managers
// built from the device tree.
#[cfg(feature = "soc")]
pub(crate) mod soc;
#[cfg(feature = "net")]
mod net;
#[cfg(feature = "net")]
pub(crate) use net::*;
// kernel_main's network bring-up after the NIC probe (`install_net`).
mod network;
pub(crate) use network::start_network;
// kernel_main's Phases D and 16: crash counter, PMP policy, stack canary.
mod security;
pub(crate) use security::report_security;
// The keystore's roots (the TPM's secret, the volume's), read before the first task.
pub(crate) mod keys;
// L15: the topology's `[volume.NAME]` rows, mounted.
// The volume engine, under the one name the apply step uses, so the host suite
// can include that file over its own copy of the engine.
#[cfg(feature = "pkg-boot-apply")]
use azos_fs::azvol as engine;
mod azvol;
pub(crate) use azvol::{fat32_check_report, install_azvol};
// The key of a sealed volume row, derived from the board's seed.
mod azvol_key;
// The boot-time apply of staged packages: the decision (host-tested over the
// real engine) and the kernel's side of it. Called from the topology install.
#[cfg(feature = "pkg-boot-apply")]
mod pkg_apply;
#[cfg(feature = "pkg-boot-apply")]
pub(crate) mod pkg_boot;
#[cfg(all(feature = "pkg-boot-apply", not(feature = "boot-slots")))]
compile_error!("Kconfig PKG_BOOT_APPLY needs BOOT_SLOTS: its trial reads the boot counter, its floor rises at a confirmed boot");
// The PCI host bridge: the configuration space the enumeration reads and, with
// Kconfig PCI_SOC_HOST, the SoC controllers brought up before it.
#[cfg(feature = "pci")]
pub(crate) mod pci;
// DMA domains and IOMMUs (Kconfig "DMA and IOMMU").
pub(crate) mod dma;
pub(crate) use dma::*;
mod seams;
pub(crate) use seams::*;
// Kconfig CHAOS / DECISION_RECORDS_DEV: command line, canaries, ktests.
pub(crate) mod chaos;
#[cfg(feature = "ktest")]
mod asym_ktests;
#[cfg(all(feature = "ktest", feature = "use-robot"))]
mod ext_ktests;
#[cfg(all(feature = "ktest", not(feature = "use-robot")))]
mod effect_ktests;
mod board;
pub(crate) use board::*;
mod robot;
pub(crate) use robot::*;
// Kconfig BOOT_SLOTS: A/B boot trust.
#[cfg(feature = "boot-slots")]
mod ota;
#[cfg(feature = "boot-slots")]
pub(crate) use ota::*;
#[cfg(all(feature = "secure-boot-enforced", not(feature = "boot-slots")))]
compile_error!("Kconfig SECURE_BOOT_ENFORCED verifies the boot slot's image: it needs BOOT_SLOTS");
mod stacks;
pub(crate) use stacks::*;
// The end of hook installation: `.data.ro_after_init` read-only.
mod seal;
pub(crate) use seal::seal_ro_after_init;
#[cfg(feature = "pt-protection")]
pub(crate) use seal::lock_pt_pool;

/// [`azos_mm::vmm::map_mmio_region`], saying a refusal. A full record
/// (N12i): the first on the console, with the Kconfig symbol that bounds it;
/// every one counted by `vmm::mmio_regions_refused`. A page that could not be
/// mapped: every one on the console (the window is unusable, and the device
/// behind it is not driven). `false` when refused.
///
/// Callers: early boot's device windows, the PCI ECAM and the boot hooks.
pub(crate) fn map_mmio_region(base: usize, size: usize) -> bool {
    use core::sync::atomic::{AtomicBool, Ordering};
    static SAID: AtomicBool = AtomicBool::new(false);
    match azos_mm::vmm::map_mmio_region(base, size) {
        Ok(()) => true,
        Err(azos_common::error::KernelError::CapacityFull) => {
            if !SAID.swap(true, Ordering::Relaxed) {
                azos_drv_sys::kerr!("[MM] device window {:#x} (+{:#x}) NOT mapped: the record holds \
                    MAX_MMIO_REGIONS = {} windows (make config); later refusals are counted, not printed",
                    base, size, azos_limits::MAX_MMIO_REGIONS);
            }
            false
        }
        Err(e) => {
            azos_drv_sys::kerr!("[MM] device window {:#x} (+{:#x}) NOT mapped: {:?}", base, size, e);
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
