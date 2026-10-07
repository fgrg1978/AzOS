// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! virtio-pci **modern** transport (VirtIO 1.x over PCI, not MMIO).
//!
//! `mod.rs` next door is the existing virtio-**MMIO** transport (1,683
//! lines, U05-12's `VIRTIO_F_VERSION_1` fix already landed there,
//! 2026-09-26 — this file does NOT touch that fix, it is the PCI-side
//! counterpart of the same negotiation). This module is the RFC-0046
//! stage-1 deliverable: virtio-net/blk over `virtio-pci` instead of
//! `virtio-mmio`, with MSI-X delivery (see "MSI-X delivery" below).
//!
//! # Why only [`msix_selftest`] uses `crate::...`
//!
//! Everything outside [`msix_selftest`] depends only on `azos_pci`
//! (config-space types) and a local [`Mmio`] trait — no drivers-crate
//! internals, no raw `*mut u32`. That is what lets `azos_pci_tests`
//! pull this exact file with `#[path]` and test it against a fake config
//! space + fake BAR memory. [`msix_selftest`] is the kernel-side glue
//! (volatile BAR access, page allocation, the per-controller
//! [`msix_selftest::MsiRoute`]); it is compiled only for `target_os =
//! "none"`, so the host pull never sees it.
//!
//! # MSI-X delivery
//!
//! `setup_queue`/`set_msix_config_vector` program a vector index; the
//! PCI-standard MSI-X table entry that vector names (address + data) is
//! programmed by `azos_pci::program_msix_entry`. On riscv64
//! `virt,aia=aplic-imsic` the address is an IMSIC interrupt file and the
//! data an IMSIC identity (`azos_drv_irqchip::irqchip`); on aarch64 it is the GICv3
//! ITS `GITS_TRANSLATER` and an EventID (`azos_arch_aarch64::its`).
//!
//! Two callers (target builds, both ISAs): [`msix_selftest`], a boot-time
//! self-test that drives one virtio-net-pci TX completion and counts the
//! MSI that reports it — through the IMSIC on riscv64 AIA, through the ITS
//! as an LPI on aarch64 — and `crate::virtio::net::init_pci`, the kernel's
//! NIC over this transport (it reuses [`msix_selftest::map_bars`],
//! [`msix_selftest::KernelBar`] and the [`msix_selftest::MsiRoute`] trait).
//! The block path is virtio-MMIO only.

use azos_pci::{Bdf, Capability, ConfigSpace, CAP_ID_VENDOR};

// ---------------------------------------------------------------------
// Mmio — the seam that makes this module host-testable
// ---------------------------------------------------------------------

/// Byte-addressed access into one PCI BAR's memory window. The kernel
/// implementor wraps a volatile `*mut u8` over the mapped BAR;
/// `azos_pci_tests` implements it over a `Vec<u8>` (well, a fixed
/// array — no allocator needed for a BAR-sized fake).
pub trait Mmio {
    fn read8(&self, offset: usize) -> u8;
    fn write8(&mut self, offset: usize, val: u8);

    fn read16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.read8(offset), self.read8(offset + 1)])
    }
    fn write16(&mut self, offset: usize, val: u16) {
        let b = val.to_le_bytes();
        self.write8(offset, b[0]);
        self.write8(offset + 1, b[1]);
    }
    fn read32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.read8(offset),
            self.read8(offset + 1),
            self.read8(offset + 2),
            self.read8(offset + 3),
        ])
    }
    fn write32(&mut self, offset: usize, val: u32) {
        let b = val.to_le_bytes();
        for (i, byte) in b.iter().enumerate() {
            self.write8(offset + i, *byte);
        }
    }
    fn read64(&self, offset: usize) -> u64 {
        (self.read32(offset) as u64) | ((self.read32(offset + 4) as u64) << 32)
    }
    fn write64(&mut self, offset: usize, val: u64) {
        self.write32(offset, val as u32);
        self.write32(offset + 4, (val >> 32) as u32);
    }
}

// ---------------------------------------------------------------------
// virtio_pci_cap (vendor-specific capability, cfg_type 1..5)
// ---------------------------------------------------------------------

pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
/// Spec-legal cfg_type this driver never looks for (`find_cfg_type` has no
/// caller passing it) — kept for completeness against the virtio 1.x
/// capability list, not dead in the sense of "should be removed".
#[allow(dead_code)]
pub const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioPciCap {
    pub cfg_type: u8,
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
    /// Only meaningful for `VIRTIO_PCI_CAP_NOTIFY_CFG` — the extra field
    /// the spec appends right after the common `virtio_pci_cap` fields
    /// for that one cfg_type.
    pub notify_off_multiplier: Option<u32>,
}

/// Parse one vendor-specific capability (`cap.id == CAP_ID_VENDOR`,
/// already located by `azos_pci::walk_capabilities`) as a
/// `virtio_pci_cap`. Field layout (virtio 1.x spec §4.1.4):
/// `cap_len`@+2, `cfg_type`@+3, `bar`@+4, `offset`@+8 (u32), `length`@+12
/// (u32), and for `NOTIFY_CFG` only, `notify_off_multiplier`@+16 (u32).
pub fn parse_virtio_cap<C: ConfigSpace>(cfg: &C, bdf: Bdf, cap: Capability) -> VirtioPciCap {
    debug_assert_eq!(cap.id, CAP_ID_VENDOR);
    let cap_len = cfg.read8(bdf, cap.offset + 2);
    let cfg_type = cfg.read8(bdf, cap.offset + 3);
    let bar = cfg.read8(bdf, cap.offset + 4);
    let offset = cfg.read32(bdf, cap.offset + 8);
    let length = cfg.read32(bdf, cap.offset + 12);
    let notify_off_multiplier = if cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG && cap_len >= 20 {
        Some(cfg.read32(bdf, cap.offset + 16))
    } else {
        None
    };
    VirtioPciCap { cfg_type, bar, offset, length, notify_off_multiplier }
}

/// Fixed-capacity list of the up-to-5 virtio caps a well-formed device
/// exposes (one per cfg_type; PCI_CFG is optional and this crate does
/// not use it).
pub const MAX_VIRTIO_CAPS: usize = 8;

pub fn find_virtio_caps<C: ConfigSpace>(cfg: &C, bdf: Bdf) -> ([Option<VirtioPciCap>; MAX_VIRTIO_CAPS], usize) {
    let mut out: [Option<VirtioPciCap>; MAX_VIRTIO_CAPS] = [None; MAX_VIRTIO_CAPS];
    let mut n = 0usize;
    let caps = azos_pci::walk_capabilities(cfg, bdf);
    for cap in caps.iter() {
        if cap.id == CAP_ID_VENDOR && n < MAX_VIRTIO_CAPS {
            out[n] = Some(parse_virtio_cap(cfg, bdf, *cap));
            n += 1;
        }
    }
    (out, n)
}

fn find_cfg_type(caps: &[Option<VirtioPciCap>], n: usize, cfg_type: u8) -> Option<VirtioPciCap> {
    caps[..n].iter().flatten().find(|c| c.cfg_type == cfg_type).copied()
}

// ---------------------------------------------------------------------
// Common configuration structure (virtio 1.x spec §4.1.4.3)
// ---------------------------------------------------------------------

mod common_off {
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub const DEVICE_FEATURE: usize = 0x04;
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub const DRIVER_FEATURE: usize = 0x0c;
    pub const MSIX_CONFIG: usize = 0x10;
    pub const NUM_QUEUES: usize = 0x12;
    pub const DEVICE_STATUS: usize = 0x14;
    pub const CONFIG_GENERATION: usize = 0x15;
    pub const QUEUE_SELECT: usize = 0x16;
    pub const QUEUE_SIZE: usize = 0x18;
    pub const QUEUE_MSIX_VECTOR: usize = 0x1a;
    pub const QUEUE_ENABLE: usize = 0x1c;
    pub const QUEUE_NOTIFY_OFF: usize = 0x1e;
    pub const QUEUE_DESC: usize = 0x20;
    pub const QUEUE_DRIVER: usize = 0x28; // aka "avail"
    pub const QUEUE_DEVICE: usize = 0x30; // aka "used"
}

pub const VIRTIO_PCI_NO_VECTOR: u16 = 0xffff;

// Device status bits (shared with the MMIO transport's numbering).
pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_FAILED: u8 = 128;

/// Bit 32 overall (bit 0 of the high feature word) — VIRTIO_F_VERSION_1.
/// MANDATORY for this transport: a device that doesn't offer it is not
/// actually a modern device and this module refuses it rather than limp
/// along on a legacy-shaped negotiation (that is what U05-12 was about
/// on the MMIO side).
const VIRTIO_F_VERSION_1_HI_BIT: u32 = 1 << 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NegotiateError {
    /// Device did not offer `VIRTIO_F_VERSION_1` — refuses to speak
    /// modern virtio-pci to it rather than falling back to legacy
    /// silently.
    NotModern,
    /// Device dropped `FEATURES_OK` after we set it — feature set it
    /// didn't like, or a device that failed for an unrelated reason.
    FeaturesRejected,
}

/// One virtio-pci device, addressed through a single BAR's [`Mmio`].
///
/// Scope note: this assumes every cfg_type this driver needs
/// (common/notify/isr/device) lives in the SAME bar — true of every
/// `virtio-*-pci` device QEMU exposes today (they all pack everything
/// into one memory BAR). A device that split them across BARs would
/// need a `[M; N]` instead; not built here because nothing in scope
/// needs it.
pub struct VirtioPciDevice<M: Mmio> {
    mmio: M,
    common: usize,
    notify: usize,
    notify_off_multiplier: u32,
    isr: usize,
    pub device_cfg: usize,
}

impl<M: Mmio> VirtioPciDevice<M> {
    /// Build from the caps `find_virtio_caps` found. Fails if
    /// COMMON_CFG, NOTIFY_CFG or ISR_CFG is missing (DEVICE_CFG is
    /// allowed to be absent — some device types don't need one) or if
    /// any required cap is not in `expected_bar` (this module doesn't
    /// map more than one BAR).
    pub fn new(mmio: M, caps: &[Option<VirtioPciCap>], n: usize, expected_bar: u8) -> Option<Self> {
        let common = find_cfg_type(caps, n, VIRTIO_PCI_CAP_COMMON_CFG).filter(|c| c.bar == expected_bar)?;
        let notify = find_cfg_type(caps, n, VIRTIO_PCI_CAP_NOTIFY_CFG).filter(|c| c.bar == expected_bar)?;
        let isr = find_cfg_type(caps, n, VIRTIO_PCI_CAP_ISR_CFG).filter(|c| c.bar == expected_bar)?;
        let device_cfg = find_cfg_type(caps, n, VIRTIO_PCI_CAP_DEVICE_CFG).filter(|c| c.bar == expected_bar);

        Some(VirtioPciDevice {
            mmio,
            common: common.offset as usize,
            notify: notify.offset as usize,
            notify_off_multiplier: notify.notify_off_multiplier.unwrap_or(0),
            isr: isr.offset as usize,
            device_cfg: device_cfg.map(|c| c.offset as usize).unwrap_or(0),
        })
    }

    fn c(&self, off: usize) -> usize {
        self.common + off
    }

    /// Negotiate features. `wanted_low` is the caller's requested
    /// feature bits 0..32; VIRTIO_F_VERSION_1 (bit 32) is ALWAYS
    /// requested by this function regardless of `wanted_high` — it is
    /// not optional for this transport — and any other high bits the
    /// caller wants go in `wanted_high`.
    pub fn negotiate_features(&mut self, wanted_low: u32, wanted_high: u32) -> Result<(), NegotiateError> {
        self.mmio.write32(self.c(common_off::DEVICE_FEATURE_SELECT), 0);
        let device_low = self.mmio.read32(self.c(common_off::DEVICE_FEATURE));
        self.mmio.write32(self.c(common_off::DEVICE_FEATURE_SELECT), 1);
        let device_high = self.mmio.read32(self.c(common_off::DEVICE_FEATURE));

        if device_high & VIRTIO_F_VERSION_1_HI_BIT == 0 {
            return Err(NegotiateError::NotModern);
        }

        self.mmio.write32(self.c(common_off::DRIVER_FEATURE_SELECT), 0);
        self.mmio.write32(self.c(common_off::DRIVER_FEATURE), wanted_low & device_low);
        self.mmio.write32(self.c(common_off::DRIVER_FEATURE_SELECT), 1);
        self.mmio.write32(
            self.c(common_off::DRIVER_FEATURE),
            (wanted_high & device_high) | VIRTIO_F_VERSION_1_HI_BIT,
        );

        let status = self.mmio.read8(self.c(common_off::DEVICE_STATUS));
        self.mmio.write8(self.c(common_off::DEVICE_STATUS), status | STATUS_FEATURES_OK);

        let status = self.mmio.read8(self.c(common_off::DEVICE_STATUS));
        if status & STATUS_FEATURES_OK == 0 {
            self.mmio.write8(self.c(common_off::DEVICE_STATUS), STATUS_FAILED);
            return Err(NegotiateError::FeaturesRejected);
        }
        Ok(())
    }

    /// Full reset -> acknowledge -> driver -> negotiate -> driver_ok
    /// sequence (virtio 1.x spec §3.1.1), for a caller with no queues to
    /// set up. A caller with queues uses [`Self::begin`], then
    /// `setup_queue`, then [`Self::set_driver_ok`]: the spec sets up
    /// virtqueues after FEATURES_OK and before DRIVER_OK.
    pub fn init(&mut self, wanted_low: u32, wanted_high: u32) -> Result<(), NegotiateError> {
        self.begin(wanted_low, wanted_high)?;
        self.set_driver_ok();
        Ok(())
    }

    /// Reset -> acknowledge -> driver -> negotiate (ends at FEATURES_OK).
    pub fn begin(&mut self, wanted_low: u32, wanted_high: u32) -> Result<(), NegotiateError> {
        self.reset();
        self.mmio.write8(self.c(common_off::DEVICE_STATUS), STATUS_ACKNOWLEDGE);
        let s = self.mmio.read8(self.c(common_off::DEVICE_STATUS));
        self.mmio.write8(self.c(common_off::DEVICE_STATUS), s | STATUS_DRIVER);
        self.negotiate_features(wanted_low, wanted_high)
    }

    pub fn set_driver_ok(&mut self) {
        let s = self.mmio.read8(self.c(common_off::DEVICE_STATUS));
        self.mmio.write8(self.c(common_off::DEVICE_STATUS), s | STATUS_DRIVER_OK);
    }

    /// Device status 0: the device stops all DMA and forgets its queues.
    pub fn reset(&mut self) {
        self.mmio.write8(self.c(common_off::DEVICE_STATUS), 0);
    }

    /// Select and size one queue, program its three ring addresses
    /// (already-translated [bus addresses][azos_drv_dmac::dma::DmaAddr] — this
    /// function takes raw `u64` so it has no dependency on `crates/drivers/dma`;
    /// the caller does that translation), and enable it.
    ///
    /// `msix_vector` is programmed as given; [`VIRTIO_PCI_NO_VECTOR`]
    /// means no interrupt for this queue. See the module doc on MSI-X.
    ///
    /// `requested` is the ring size the caller actually allocated (e.g.
    /// `VIRTIO_QUEUE_SIZE` = 16, matching `Virtq` in `virtio/mod.rs`).
    /// The device's `queue_size` register defaults to ITS maximum
    /// (QEMU typically offers 256) — **not writing it back would leave
    /// the device believing the queue has 256 slots while the driver's
    /// rings only have `requested`**, and the device is free to index
    /// anywhere in that larger range the moment it's live. This function
    /// clamps to `min(device max, requested)` and programs it before any
    /// address is written, and returns the size actually agreed so the
    /// caller can catch a device that offers fewer than it asked for.
    pub fn setup_queue(&mut self, queue_idx: u16, requested: u16, desc: u64, driver_avail: u64, device_used: u64, msix_vector: u16) -> u16 {
        self.mmio.write16(self.c(common_off::QUEUE_SELECT), queue_idx);
        let max_size = self.mmio.read16(self.c(common_off::QUEUE_SIZE));
        let size = max_size.min(requested);
        self.mmio.write16(self.c(common_off::QUEUE_SIZE), size);

        self.mmio.write64(self.c(common_off::QUEUE_DESC), desc);
        self.mmio.write64(self.c(common_off::QUEUE_DRIVER), driver_avail);
        self.mmio.write64(self.c(common_off::QUEUE_DEVICE), device_used);
        self.mmio.write16(self.c(common_off::QUEUE_MSIX_VECTOR), msix_vector);
        self.mmio.write16(self.c(common_off::QUEUE_ENABLE), 1);

        size
    }

    /// The notify-capability's per-queue offset multiplier applied — the
    /// byte offset (within the BAR) to write `queue_idx` to in order to
    /// kick that queue (virtio 1.x spec §4.1.4.4).
    pub fn queue_notify_offset(&self, queue_notify_off: u16) -> usize {
        self.notify + (queue_notify_off as usize) * (self.notify_off_multiplier as usize)
    }

    pub fn notify_queue(&mut self, queue_idx: u16, queue_notify_off: u16) {
        let off = self.queue_notify_offset(queue_notify_off);
        self.mmio.write16(off, queue_idx);
    }

    /// Read-and-clear the ISR status byte. Bit 0: a queue interrupt is
    /// pending; bit 1: device configuration changed. Only meaningful
    /// without MSI-X: with MSI-X enabled the device does not set it.
    pub fn read_and_clear_isr(&mut self) -> u8 {
        self.mmio.read8(self.isr)
    }

    pub fn queue_notify_off_of(&mut self, queue_idx: u16) -> u16 {
        self.mmio.write16(self.c(common_off::QUEUE_SELECT), queue_idx);
        self.mmio.read16(self.c(common_off::QUEUE_NOTIFY_OFF))
    }

    /// Number of queues the device implements (common cfg `num_queues`,
    /// read-only) — a caller sizes its queue array from this instead of
    /// a per-device-type constant.
    pub fn num_queues(&self) -> u16 {
        self.mmio.read16(self.c(common_off::NUM_QUEUES))
    }

    /// Bumped by the device whenever its config space changes; a driver
    /// re-reads `device_cfg` and compares generations before trusting a
    /// multi-field read as atomic (virtio 1.x spec §2.4.2).
    pub fn config_generation(&self) -> u8 {
        self.mmio.read8(self.c(common_off::CONFIG_GENERATION))
    }

    /// Program the device-wide (non-per-queue) MSI-X vector used for
    /// configuration-change notifications.
    pub fn set_msix_config_vector(&mut self, vector: u16) {
        self.mmio.write16(self.c(common_off::MSIX_CONFIG), vector);
    }

    /// `queue_msix_vector` of `queue_idx` as the device reports it. A
    /// device that could not map the vector reads back
    /// [`VIRTIO_PCI_NO_VECTOR`] (virtio 1.x spec §4.1.5.1.2).
    pub fn queue_msix_vector(&mut self, queue_idx: u16) -> u16 {
        self.mmio.write16(self.c(common_off::QUEUE_SELECT), queue_idx);
        self.mmio.read16(self.c(common_off::QUEUE_MSIX_VECTOR))
    }
}

/// BAR index holding the common configuration structure — the BAR a
/// caller must map and hand to [`VirtioPciDevice::new`].
pub fn common_cfg_bar(caps: &[Option<VirtioPciCap>], n: usize) -> Option<u8> {
    find_cfg_type(caps, n, VIRTIO_PCI_CAP_COMMON_CFG).map(|c| c.bar)
}

/// Test-only pokes/reads into raw common-cfg registers, so
/// `azos_pci_tests` can drive the "device side" of a fake without
/// this module needing a second, device-facing trait it has no other
/// use for. Compiled only under `cfg(test)` — never part of the real
/// driver's API surface.
#[cfg(test)]
impl<M: Mmio> VirtioPciDevice<M> {
    pub fn mmio_poke_device_features(&mut self, select: u32, val: u32) {
        self.mmio.write32(self.c(common_off::DEVICE_FEATURE_SELECT), select);
        self.mmio.write32(self.c(common_off::DEVICE_FEATURE), val);
    }
    pub fn mmio_read_driver_features(&mut self, select: u32) -> u32 {
        self.mmio.write32(self.c(common_off::DRIVER_FEATURE_SELECT), select);
        self.mmio.read32(self.c(common_off::DRIVER_FEATURE))
    }
    pub fn mmio_read_queue_desc(&self) -> u64 {
        self.mmio.read64(self.c(common_off::QUEUE_DESC))
    }
    pub fn mmio_read_queue_driver(&self) -> u64 {
        self.mmio.read64(self.c(common_off::QUEUE_DRIVER))
    }
    pub fn mmio_read_queue_device(&self) -> u64 {
        self.mmio.read64(self.c(common_off::QUEUE_DEVICE))
    }
    pub fn mmio_read_queue_msix_vector(&self) -> u16 {
        self.mmio.read16(self.c(common_off::QUEUE_MSIX_VECTOR))
    }
    pub fn mmio_read_queue_enable(&self) -> u16 {
        self.mmio.read16(self.c(common_off::QUEUE_ENABLE))
    }
    pub fn mmio_poke_isr(&mut self, val: u8) {
        self.mmio.write8(self.isr, val);
    }
    pub fn mmio_read_at(&self, offset: usize) -> u16 {
        self.mmio.read16(offset)
    }
    pub fn mmio_read_status(&self) -> u8 {
        self.mmio.read8(self.c(common_off::DEVICE_STATUS))
    }
    pub fn mmio_poke_num_queues(&mut self, val: u16) {
        self.mmio.write16(self.c(common_off::NUM_QUEUES), val);
    }
    pub fn mmio_poke_config_generation(&mut self, val: u8) {
        self.mmio.write8(self.c(common_off::CONFIG_GENERATION), val);
    }
    pub fn mmio_read_msix_config_vector(&self) -> u16 {
        self.mmio.read16(self.c(common_off::MSIX_CONFIG))
    }
    /// Poke as if the device reported `val` for `queue_idx`'s
    /// notify_off when selected — real hardware ties this to
    /// `QUEUE_SELECT` too, so this fake does the same select-then-write.
    pub fn mmio_poke_queue_notify_off(&mut self, queue_idx: u16, val: u16) {
        self.mmio.write16(self.c(common_off::QUEUE_SELECT), queue_idx);
        self.mmio.write16(self.c(common_off::QUEUE_NOTIFY_OFF), val);
    }
    /// Set what the fake "device" reports as its own max/current queue
    /// size — models the register's reset-time value (the device's
    /// maximum) before any driver write.
    pub fn mmio_poke_queue_size(&mut self, val: u16) {
        self.mmio.write16(self.c(common_off::QUEUE_SIZE), val);
    }
    pub fn mmio_read_queue_size(&self) -> u16 {
        self.mmio.read16(self.c(common_off::QUEUE_SIZE))
    }
}

// ---------------------------------------------------------------------
// Kernel-side MSI-X self-test, both ISAs (RFC-0046 stage 1a)
// ---------------------------------------------------------------------

/// One virtio-net-pci TX completion, delivered as an MSI-X message through
/// an [`MsiRoute`](msix_selftest::MsiRoute) — the boot hart's IMSIC file on
/// riscv64 AIA, an ITS EventID→LPI on aarch64 — and counted there.
///
/// Sequence: assign and map the function's memory BARs, enable Memory
/// Space + Bus Master, program MSI-X vector 0 (config) and 1 (TX queue)
/// with the route's address/data pair for each, set MSI-X
/// Enable, bring the device to DRIVER_OK with TX queue 1 on vector 1,
/// post one frame and notify. The device's used-ring index shows the
/// completion happened; the identity count shows whether its MSI arrived.
/// With MSI-X Enable clear (`azos_pci/msix-enable-canary`) the device
/// signals INTx instead, which no APLIC source is wired for: `used` still
/// moves, the count stays 0.
#[cfg(target_os = "none")]
pub mod msix_selftest {
    use super::*;
    use azos_pci::{BarKind, BarMem, BarWindow, FunctionInfo, BAR_COUNT};

    /// Where a device's MSI-X vectors are delivered — the one part of this
    /// self-test that differs between interrupt controllers. riscv64 AIA:
    /// an IMSIC file address and an interrupt identity per vector
    /// ([`AiaRoute`]). aarch64 GICv3: `GITS_TRANSLATER` and an ITS EventID
    /// per vector, translated to an LPI (the kernel's ITS route, built in
    /// `kernel_main` because the ITS instance and the LPI counters live in
    /// the kernel's aarch64 entry code).
    pub trait MsiRoute {
        /// Make vectors `0..n` deliverable. `false` = no route on this machine.
        fn prepare(&mut self, n: u16) -> bool;
        /// The (address, data) pair to program into MSI-X table entry `vec`.
        fn target(&self, vec: u16) -> (u64, u32);
        /// Deliveries counted so far for vector `vec`.
        fn delivered(&self, vec: u16) -> u64;
        /// The number the kernel's interrupt path sees for vector `vec` —
        /// what `crate::virtio::net::msi_irq` is called with. riscv64 AIA:
        /// the IMSIC identity, which is the MSI data word (the default).
        /// aarch64 ITS: `intid - LPI_INTID_BASE`, which differs from the
        /// EventID the data word carries whenever the route maps EventID N
        /// to an LPI other than `LPI_INTID_BASE + N`.
        fn isr_token(&self, vec: u16) -> u32 {
            self.target(vec).1
        }
    }

    /// riscv64 AIA route: identities allocated on `hart`'s IMSIC file.
    // arch-only: the riscv64 AIA route; x86_64's is ApicMsiRoute below,
    // aarch64's the kernel's ITS route.
    #[cfg(target_arch = "riscv64")]
    pub struct AiaRoute {
        hart: u32,
        first: u32,
    }

    #[cfg(target_arch = "riscv64")]
    impl AiaRoute {
        pub fn new(hart: u32) -> Self {
            AiaRoute { hart, first: 0 }
        }
    }

    #[cfg(target_arch = "riscv64")]
    impl MsiRoute for AiaRoute {
        fn prepare(&mut self, n: u16) -> bool {
            if azos_drv_irqchip::irqchip::msi_target_addr(self.hart).is_none() {
                return false;
            }
            let Some(first) = azos_drv_irqchip::irqchip::alloc_msi_ids(n as u32) else { return false };
            self.first = first;
            for i in 0..n as u32 {
                azos_drv_irqchip::irqchip::enable_irq(self.hart, first + i);
            }
            true
        }
        fn target(&self, vec: u16) -> (u64, u32) {
            (azos_drv_irqchip::irqchip::msi_target_addr(self.hart).unwrap_or(0), self.first + vec as u32)
        }
        fn delivered(&self, vec: u16) -> u64 {
            azos_drv_irqchip::irqchip::delivered(self.first + vec as u32) as u64
        }
    }

    /// x86_64 skeleton (and any further ISA): MSI-X straight to a LAPIC
    /// (address 0xFEE0_0000 | dest APIC ID << 12, data = vector). aarch64's
    /// route is the ITS one the kernel builds; it needs no arm here.
    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    pub struct ApicMsiRoute {
        pub hart: u32,
    }

    #[cfg(all(target_os = "none", not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
    impl MsiRoute for ApicMsiRoute {
        fn prepare(&mut self, _n: u16) -> bool {
            todo!("x86_64: ApicMsiRoute::prepare: allocate n IDT vectors on the destination CPU")
        }
        fn target(&self, _vec: u16) -> (u64, u32) {
            todo!("x86_64: ApicMsiRoute::target: (0xFEE0_0000 | apic_id << 12, vector)")
        }
        fn delivered(&self, _vec: u16) -> u64 {
            todo!("x86_64: ApicMsiRoute::delivered: per-vector delivery count")
        }
    }

    /// Volatile access to a BAR mapped at `base` (identity-mapped MMIO).
    /// Every width is a single access of that width: virtio common-cfg
    /// registers must not be split into byte accesses.
    pub struct KernelBar {
        base: usize,
    }

    impl KernelBar {
        /// `base` must be a BAR mapped by [`map_bars`] (or equivalent).
        pub const fn new(base: usize) -> Self {
            KernelBar { base }
        }
        /// The CPU address of byte `off` of this BAR.
        pub const fn addr(&self, off: usize) -> usize {
            self.base + off
        }
    }

    impl Mmio for KernelBar {
        fn read8(&self, off: usize) -> u8 {
            // SAFETY: `base` is a mapped BAR and `off` lies inside it
            // (offsets come from the device's own virtio caps / MSI-X cap).
            unsafe { core::ptr::read_volatile((self.base + off) as *const u8) }
        }
        fn write8(&mut self, off: usize, val: u8) {
            // SAFETY: as for `read8`.
            unsafe { core::ptr::write_volatile((self.base + off) as *mut u8, val) }
        }
        fn read16(&self, off: usize) -> u16 {
            // SAFETY: as for `read8`; virtio register offsets are aligned.
            unsafe { core::ptr::read_volatile((self.base + off) as *const u16) }
        }
        fn write16(&mut self, off: usize, val: u16) {
            // SAFETY: as for `read16`.
            unsafe { core::ptr::write_volatile((self.base + off) as *mut u16, val) }
        }
        fn read32(&self, off: usize) -> u32 {
            // SAFETY: as for `read16`.
            unsafe { core::ptr::read_volatile((self.base + off) as *const u32) }
        }
        fn write32(&mut self, off: usize, val: u32) {
            // SAFETY: as for `read16`.
            unsafe { core::ptr::write_volatile((self.base + off) as *mut u32, val) }
        }
    }

    impl BarMem for KernelBar {
        fn read32(&self, off: usize) -> u32 {
            Mmio::read32(self, off)
        }
        fn write32(&mut self, off: usize, val: u32) {
            Mmio::write32(self, off, val)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SelftestError {
        NoMsix,
        TooFewVectors,
        BarAssign,
        BarMap,
        NotAia,
        NoIdentities,
        NoVirtioCaps,
        Negotiate(NegotiateError),
        VectorRefused,
        NoMemory,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Report {
        pub msix_enabled: bool,
        pub table_size: u16,
        /// MSI address programmed for vector 1 (TX queue).
        pub target: u64,
        /// MSI data of vector 0 (config) and vector 1 (TX queue): an IMSIC
        /// identity on riscv64, an ITS EventID on aarch64.
        pub ids: [u32; 2],
        /// The route's delivery count for each vector after the wait.
        pub counts: [u32; 2],
        /// TX used-ring index after the wait: 1 = the device completed the frame.
        pub used: u16,
    }

    const TX_QUEUE: u16 = 1;
    const QUEUE_SIZE: u16 = 16;
    /// virtio-net header with VIRTIO_F_VERSION_1 (12 bytes) + a minimum
    /// Ethernet frame (60 bytes, broadcast, EtherType 0x88b5 = local
    /// experimental — nothing on the host side acts on it).
    const FRAME_LEN: usize = 12 + 60;

    /// Assign every memory BAR of `info` from `window`, map it, and turn
    /// on Memory Space decode + Bus Master. Returns the CPU address of each
    /// BAR by index (0 = not a memory BAR). Decode is switched off first:
    /// [`azos_pci::assign_bar`] needs it off, and an earlier user of
    /// the function (the TX self-test, before the NIC driver) leaves it on.
    /// BAR addresses are 0 after reset — nothing ahead of this kernel
    /// assigns them on QEMU `virt`.
    pub fn map_bars<C: ConfigSpace>(
        cfg: &mut C,
        info: &FunctionInfo,
        window: &mut BarWindow,
    ) -> Result<[usize; BAR_COUNT], SelftestError> {
        azos_pci::clear_command_bits(
            cfg, info.bdf, azos_pci::CMD_MEM_SPACE | azos_pci::CMD_BUS_MASTER);
        let mut bar_base = [0usize; BAR_COUNT];
        for bar in info.bars[..info.bar_count].iter().flatten() {
            if bar.kind == BarKind::Io {
                continue;
            }
            let addr = window.alloc(bar.size).ok_or(SelftestError::BarAssign)?;
            azos_pci::assign_bar(cfg, info.bdf, bar, addr).ok_or(SelftestError::BarAssign)?;
            let map_len = (bar.size as usize).max(0x1000);
            azos_mm::vmm::map_mmio_region(addr as usize, map_len)
                .map_err(|_| SelftestError::BarMap)?;
            bar_base[bar.index as usize] = addr as usize;
        }
        // New device mappings must be visible to the next table walk before
        // the first BAR access (aarch64: `map_mmio_region` writes the live
        // TTBR0 table with no barrier — see boot_hooks' GICR note).
        {
            use azos_arch::Mmu;
            azos_arch::ARCH.flush_tlb_all();
        }
        azos_pci::set_command_bits(
            cfg, info.bdf, azos_pci::CMD_MEM_SPACE | azos_pci::CMD_BUS_MASTER);
        Ok(bar_base)
    }

    fn alloc_zeroed_page() -> Result<(usize, u64), SelftestError> {
        let pa = azos_mm::pmm::alloc_page().map_err(|_| SelftestError::NoMemory)?.0;
        Ok((crate::virtio::dma_page_ptr(pa), pa as u64))
    }

    /// Run the self-test on `info` (a virtio-net-pci function), delivering
    /// its MSI-X vectors through `route`.
    pub fn tx_selftest<C: ConfigSpace, R: MsiRoute>(
        cfg: &mut C,
        info: &FunctionInfo,
        window: &mut BarWindow,
        route: &mut R,
    ) -> Result<Report, SelftestError> {
        let msix = info.msix.ok_or(SelftestError::NoMsix)?;
        if msix.table_size < 2 {
            return Err(SelftestError::TooFewVectors);
        }
        if !route.prepare(2) {
            return Err(SelftestError::NotAia);
        }

        let bar_base = map_bars(cfg, info, window)?;
        let table_base = bar_base.get(msix.table_bar as usize).copied().unwrap_or(0);
        if table_base == 0 {
            return Err(SelftestError::BarAssign);
        }

        // Vector 0 (config change) and vector 1 (TX queue), routed by `route`.
        let mut ids = [0u32; 2];
        let mut target = 0u64;
        let mut table = KernelBar { base: table_base };
        for vec in 0..2u16 {
            let (addr, data) = route.target(vec);
            azos_pci::program_msix_entry(&mut table, msix.table_offset, vec, addr, data, false);
            ids[vec as usize] = data;
            target = addr;
        }
        azos_pci::msix_set_enable(cfg, info.bdf, &msix, true);
        let msix_enabled = azos_pci::msix_is_enabled(cfg, info.bdf, &msix);

        // Virtio bring-up through the common-cfg BAR.
        let (caps, n) = find_virtio_caps(cfg, info.bdf);
        let common_bar = common_cfg_bar(&caps, n).ok_or(SelftestError::NoVirtioCaps)?;
        let dev_base = bar_base.get(common_bar as usize).copied().unwrap_or(0);
        if dev_base == 0 {
            return Err(SelftestError::NoVirtioCaps);
        }
        let mut dev = VirtioPciDevice::new(KernelBar { base: dev_base }, &caps, n, common_bar)
            .ok_or(SelftestError::NoVirtioCaps)?;
        dev.begin(0, 0).map_err(SelftestError::Negotiate)?;
        dev.set_msix_config_vector(0);

        let (desc, desc_pa) = alloc_zeroed_page()?;
        let (avail, avail_pa) = alloc_zeroed_page()?;
        let (used, used_pa) = alloc_zeroed_page()?;
        let (buf, buf_pa) = alloc_zeroed_page()?;
        dev.setup_queue(TX_QUEUE, QUEUE_SIZE, desc_pa, avail_pa, used_pa, 1);
        if dev.queue_msix_vector(TX_QUEUE) != 1 {
            dev.reset();
            return Err(SelftestError::VectorRefused);
        }
        let notify_off = dev.queue_notify_off_of(TX_QUEUE);
        dev.set_driver_ok();

        // SAFETY: `desc`/`avail`/`buf` are freshly allocated, zeroed,
        // kernel-mapped pages owned by this function; the device reads them
        // only after the notify below.
        unsafe {
            let frame = buf as *mut u8;
            for i in 0..6 {
                frame.add(12 + i).write_volatile(0xff); // destination: broadcast
            }
            frame.add(12 + 6).write_volatile(0x52);
            frame.add(12 + 7).write_volatile(0x54); // source 52:54:00:...
            frame.add(12 + 12).write_volatile(0x88);
            frame.add(12 + 13).write_volatile(0xb5);
            // Descriptor 0: {addr u64, len u32, flags u16, next u16}.
            (desc as *mut u64).write_volatile(buf_pa);
            ((desc + 8) as *mut u32).write_volatile(FRAME_LEN as u32);
            // Avail ring: flags u16 = 0 (interrupts wanted), idx u16, ring[].
            ((avail + 4) as *mut u16).write_volatile(0);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            ((avail + 2) as *mut u16).write_volatile(1);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        }
        dev.notify_queue(TX_QUEUE, notify_off);

        // Wait for the completion, then give its MSI time to be claimed.
        let hz = azos_drv_sys::timebase::TIMER_FREQ;
        let start = azos_drv_sys::timebase::now();
        let mut done_at = 0u64;
        let used_idx = loop {
            let now = azos_drv_sys::timebase::now();
            // SAFETY: `used` is this function's page; the device writes it.
            let used_idx = unsafe { ((used + 2) as *const u16).read_volatile() };
            if used_idx != 0 && done_at == 0 {
                done_at = now;
            }
            if (route.delivered(1) > 0 && used_idx != 0)
                || (done_at != 0 && now - done_at > hz / 10)
                || now - start > hz
            {
                break used_idx;
            }
            core::hint::spin_loop();
        };

        // Stop the device before its rings go away.
        dev.reset();
        azos_pci::msix_set_enable(cfg, info.bdf, &msix, false);
        for pa in [desc_pa, avail_pa, used_pa, buf_pa] {
            let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr(pa as usize));
        }

        Ok(Report {
            msix_enabled,
            table_size: msix.table_size,
            target,
            ids,
            counts: [route.delivered(0) as u32, route.delivered(1) as u32],
            used: used_idx,
        })
    }
}
