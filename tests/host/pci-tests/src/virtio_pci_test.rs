// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for `crates/drivers/virtio/src/virtio/pci.rs`, pulled in via
//! `#[path]` — the same pattern `azos_drv_tests` uses for other
//! driver modules, and the reason that file has no `use crate::...`
//! (see its module doc).

#[path = "../../../../crates/drivers/virtio/src/virtio/pci.rs"]
mod virtio_pci;

use azos_pci::{Bdf, ConfigSpace, CAP_ID_VENDOR};
use virtio_pci::*;

/// One function's plain 4 KiB config space — no BAR-sizing hardware
/// emulation needed here (this file never calls `decode_bars`), just
/// byte storage.
struct FakeCfg {
    bytes: [u8; 256],
}

impl FakeCfg {
    fn new() -> Self {
        FakeCfg { bytes: [0; 256] }
    }

    fn write_u8(&mut self, off: u16, val: u8) {
        self.bytes[off as usize] = val;
    }
    fn write_u16(&mut self, off: u16, val: u16) {
        self.bytes[off as usize..off as usize + 2].copy_from_slice(&val.to_le_bytes());
    }
    fn write_u32(&mut self, off: u16, val: u32) {
        self.bytes[off as usize..off as usize + 4].copy_from_slice(&val.to_le_bytes());
    }

    /// Lay down a virtio_pci_cap (vendor id 0x09) at `at`, chained to
    /// `next`, for `cfg_type`/`bar`/`offset`/`length`, optionally with
    /// the notify_off_multiplier trailer.
    fn add_virtio_cap(&mut self, at: u16, next: u8, cfg_type: u8, bar: u8, offset: u32, length: u32, notify_mult: Option<u32>) {
        self.write_u8(at, CAP_ID_VENDOR);
        self.write_u8(at + 1, next);
        self.write_u8(at + 2, if notify_mult.is_some() { 20 } else { 16 }); // cap_len
        self.write_u8(at + 3, cfg_type);
        self.write_u8(at + 4, bar);
        self.write_u32(at + 8, offset);
        self.write_u32(at + 12, length);
        if let Some(mult) = notify_mult {
            self.write_u32(at + 16, mult);
        }
    }

    fn set_cap_list(&mut self, first: u8) {
        self.write_u16(0x06, 1 << 4); // status.CAP_LIST
        self.write_u8(0x34, first);
    }
}

impl ConfigSpace for FakeCfg {
    fn read32(&self, _bdf: Bdf, offset: u16) -> u32 {
        let o = offset as usize;
        u32::from_le_bytes(self.bytes[o..o + 4].try_into().unwrap())
    }
    fn write32(&mut self, _bdf: Bdf, offset: u16, val: u32) {
        let o = offset as usize;
        self.bytes[o..o + 4].copy_from_slice(&val.to_le_bytes());
    }
}

/// Backing size for [`FakeMmio`] — must cover the highest offset any
/// fake region below uses (`DEVICE_OFF + its length`).
const BAR_SIZE: usize = 0x4000;

/// A BAR's memory window, backed by a plain byte array — big enough for
/// common cfg + notify + isr + device cfg all packed in, as QEMU's
/// virtio-pci devices do.
///
/// `DEVICE_FEATURE`/`DRIVER_FEATURE` are windowed registers on real
/// hardware — the same address means "word 0" or "word 1" depending on
/// which value was last written to the matching `*_SELECT` register.
/// A dumb flat byte array can't express that (two writes at different
/// `select` values would just overwrite the same bytes), so this fake
/// gives those four common-cfg registers real windowed storage and
/// leaves everything else — notify/isr/device cfg, queue registers — as
/// plain flat memory, which is all they need since none of them are
/// windowed.
struct FakeMmio {
    bytes: [u8; BAR_SIZE],
    device_feature: [u32; 2],
    driver_feature: [u32; 2],
    device_feature_select: usize,
    driver_feature_select: usize,
}

impl FakeMmio {
    fn new() -> Self {
        FakeMmio {
            bytes: [0; BAR_SIZE],
            device_feature: [0, 0],
            driver_feature: [0, 0],
            device_feature_select: 0,
            driver_feature_select: 0,
        }
    }
}

const OFF_DEVICE_FEATURE_SELECT: usize = 0x00;
const OFF_DEVICE_FEATURE: usize = 0x04;
const OFF_DRIVER_FEATURE_SELECT: usize = 0x08;
const OFF_DRIVER_FEATURE: usize = 0x0c;

impl Mmio for FakeMmio {
    fn read8(&self, offset: usize) -> u8 {
        self.bytes[offset]
    }
    fn write8(&mut self, offset: usize, val: u8) {
        self.bytes[offset] = val;
    }

    fn read32(&self, offset: usize) -> u32 {
        match offset {
            OFF_DEVICE_FEATURE_SELECT => self.device_feature_select as u32,
            OFF_DEVICE_FEATURE => self.device_feature[self.device_feature_select],
            OFF_DRIVER_FEATURE_SELECT => self.driver_feature_select as u32,
            OFF_DRIVER_FEATURE => self.driver_feature[self.driver_feature_select],
            _ => u32::from_le_bytes([
                self.bytes[offset],
                self.bytes[offset + 1],
                self.bytes[offset + 2],
                self.bytes[offset + 3],
            ]),
        }
    }

    fn write32(&mut self, offset: usize, val: u32) {
        match offset {
            OFF_DEVICE_FEATURE_SELECT => self.device_feature_select = (val & 1) as usize,
            OFF_DEVICE_FEATURE => self.device_feature[self.device_feature_select] = val,
            OFF_DRIVER_FEATURE_SELECT => self.driver_feature_select = (val & 1) as usize,
            OFF_DRIVER_FEATURE => self.driver_feature[self.driver_feature_select] = val,
            _ => {
                let b = val.to_le_bytes();
                self.bytes[offset..offset + 4].copy_from_slice(&b);
            }
        }
    }
}

const BAR: u8 = 4;
const COMMON_OFF: u32 = 0x0000;
const NOTIFY_OFF: u32 = 0x1000;
const ISR_OFF: u32 = 0x2000;
const DEVICE_OFF: u32 = 0x3000;
const NOTIFY_MULT: u32 = 4;

// Capability chain offsets. NOTIFY_CFG needs 20 bytes (cap_len 20, the
// extra notify_off_multiplier trailer) — every other cap here needs 16.
// The first version of this test packed them 0x10 apart uniformly and
// the notify cap's trailer silently overwrote the next cap's header
// (caught by `find_virtio_caps_locates_all_four_cfg_types` reading back
// garbage — see the RED captured in this crate's report). 4-byte-aligned
// gaps below leave room.
const CAP_COMMON: u16 = 0x40;
const CAP_NOTIFY: u16 = 0x50;
const CAP_ISR: u16 = 0x64; // 0x50 + 20 bytes, not 0x60
const CAP_DEVICE: u16 = 0x74;

fn build_caps() -> FakeCfg {
    let mut cfg = FakeCfg::new();
    cfg.add_virtio_cap(CAP_COMMON, CAP_NOTIFY as u8, VIRTIO_PCI_CAP_COMMON_CFG, BAR, COMMON_OFF, 0x38, None);
    cfg.add_virtio_cap(CAP_NOTIFY, CAP_ISR as u8, VIRTIO_PCI_CAP_NOTIFY_CFG, BAR, NOTIFY_OFF, 0x1000, Some(NOTIFY_MULT));
    cfg.add_virtio_cap(CAP_ISR, CAP_DEVICE as u8, VIRTIO_PCI_CAP_ISR_CFG, BAR, ISR_OFF, 0x1, None);
    cfg.add_virtio_cap(CAP_DEVICE, 0x00, VIRTIO_PCI_CAP_DEVICE_CFG, BAR, DEVICE_OFF, 0x100, None);
    cfg.set_cap_list(CAP_COMMON as u8);
    cfg
}

// -----------------------------------------------------------------------
// Capability discovery
// -----------------------------------------------------------------------

#[test]
fn find_virtio_caps_locates_all_four_cfg_types() {
    let cfg = build_caps();
    let (caps, n) = find_virtio_caps(&cfg, Bdf::new(0, 0, 0));
    assert_eq!(n, 4);
    let common = caps[..n].iter().flatten().find(|c| c.cfg_type == VIRTIO_PCI_CAP_COMMON_CFG).unwrap();
    assert_eq!(common.bar, BAR);
    assert_eq!(common.offset, COMMON_OFF);

    let notify = caps[..n].iter().flatten().find(|c| c.cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG).unwrap();
    assert_eq!(notify.notify_off_multiplier, Some(NOTIFY_MULT));
}

// -----------------------------------------------------------------------
// Feature negotiation — VIRTIO_F_VERSION_1 is mandatory
// -----------------------------------------------------------------------

fn make_device() -> VirtioPciDevice<FakeMmio> {
    let cfg = build_caps();
    let (caps, n) = find_virtio_caps(&cfg, Bdf::new(0, 0, 0));
    VirtioPciDevice::new(FakeMmio::new(), &caps, n, BAR).expect("all required caps present")
}

#[test]
fn negotiate_fails_closed_when_device_does_not_offer_version_1() {
    let mut dev = make_device();
    // Device offers nothing in the high word -> VERSION_1 absent.
    let err = dev.negotiate_features(0, 0).unwrap_err();
    assert_eq!(err, NegotiateError::NotModern);
}

#[test]
fn negotiate_succeeds_and_always_requests_version_1() {
    let mut dev = make_device();
    // Poke the fake "device" side directly: DEVICE_FEATURE at the
    // selected word. Select 1 (high word) then write the value the
    // *device* would present — but our Mmio has no separate device-side
    // state, so model the device's offered features by pre-seeding the
    // same register the common-cfg negotiation reads as "device
    // feature". This mirrors how a real device's read-only bits would
    // appear on `DEVICE_FEATURE` after `DEVICE_FEATURE_SELECT` is set.
    dev.mmio_poke_device_features(0, 0xffff_ffff);
    dev.mmio_poke_device_features(1, 0x1); // VERSION_1 offered

    dev.negotiate_features(0xffff_ffff, 0).expect("device offers VERSION_1, must succeed");
}

#[test]
fn negotiate_masks_driver_features_to_what_device_actually_offers() {
    let mut dev = make_device();
    dev.mmio_poke_device_features(0, 0x0000_00ff); // only low 8 bits offered
    dev.mmio_poke_device_features(1, 0x1);

    dev.negotiate_features(0xffff_ffff, 0).unwrap();
    let driver_low = dev.mmio_read_driver_features(0);
    assert_eq!(driver_low, 0xff, "driver must not claim bits the device never offered");
    // What virtio-net reads back to learn whether EVENT_IDX (bit 29) stuck.
    assert_eq!(dev.driver_features_low(), 0xff);
}

// -----------------------------------------------------------------------
// Queue setup + notify offset math
// -----------------------------------------------------------------------

#[test]
fn setup_queue_programs_addresses_and_no_vector_by_default() {
    let mut dev = make_device();
    dev.mmio_poke_device_features(0, 0xffff_ffff);
    dev.mmio_poke_device_features(1, 0x1);
    dev.negotiate_features(0, 0).unwrap();
    // Device's own maximum, as QEMU typically offers (256) — must NOT
    // survive untouched. A no-op `setup_queue` (the bug this test caught
    // once already: it read QUEUE_SIZE and threw it away instead of
    // clamping+writing it back) would leave this at 256 while the
    // driver's own ring only has 16 slots, and the device would then be
    // free to index up to 256 into 16-slot memory.
    dev.mmio_poke_queue_size(256);

    let agreed = dev.setup_queue(0, 16, 0x1000_0000, 0x1000_1000, 0x1000_2000, VIRTIO_PCI_NO_VECTOR);

    assert_eq!(agreed, 16, "must clamp to what the driver actually requested");
    assert_eq!(dev.mmio_read_queue_size(), 16, "QUEUE_SIZE register must be written back, not left at the device max");
    assert_eq!(dev.mmio_read_queue_desc(), 0x1000_0000);
    assert_eq!(dev.mmio_read_queue_driver(), 0x1000_1000);
    assert_eq!(dev.mmio_read_queue_device(), 0x1000_2000);
    assert_eq!(dev.mmio_read_queue_msix_vector(), VIRTIO_PCI_NO_VECTOR);
    assert_eq!(dev.mmio_read_queue_enable(), 1);
}

#[test]
fn setup_queue_clamps_to_device_max_when_requested_is_larger() {
    let mut dev = make_device();
    dev.mmio_poke_queue_size(8); // device only has 8 slots for this queue
    let agreed = dev.setup_queue(0, 16, 0, 0, 0, VIRTIO_PCI_NO_VECTOR);
    assert_eq!(agreed, 8, "must not ask for more than the device offers");
    assert_eq!(dev.mmio_read_queue_size(), 8);
}

#[test]
fn queue_notify_offset_applies_the_multiplier() {
    let dev = make_device();
    // notify cap at NOTIFY_OFF, multiplier NOTIFY_MULT; queue_notify_off
    // 3 for some queue -> notify base + 3*mult.
    assert_eq!(dev.queue_notify_offset(3), NOTIFY_OFF as usize + 3 * NOTIFY_MULT as usize);
}

#[test]
fn isr_read_reaches_the_isr_bar_offset() {
    let mut dev = make_device();
    dev.mmio_poke_isr(0x3); // queue + config-change bits both pending
    assert_eq!(dev.read_and_clear_isr(), 0x3);
}

#[test]
fn notify_queue_writes_the_queue_index_at_the_computed_offset() {
    let mut dev = make_device();
    dev.notify_queue(5, 2); // queue 5, its notify_off is 2
    assert_eq!(dev.mmio_read_at(dev.queue_notify_offset(2)), 5);
}

#[test]
fn init_runs_the_full_handshake_and_ends_driver_ok() {
    let mut dev = make_device();
    dev.mmio_poke_device_features(0, 0xffff_ffff);
    dev.mmio_poke_device_features(1, 0x1);

    dev.init(0, 0).expect("full handshake must succeed when VERSION_1 is offered");
    assert_eq!(dev.mmio_read_status(), STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
}

#[test]
fn queue_notify_off_of_selects_the_queue_before_reading() {
    let mut dev = make_device();
    dev.mmio_poke_queue_notify_off(2, 9); // queue 2's notify_off register value = 9
    assert_eq!(dev.queue_notify_off_of(2), 9);
}

#[test]
fn device_cfg_offset_is_captured_from_the_device_cfg_capability() {
    let dev = make_device();
    assert_eq!(dev.device_cfg, DEVICE_OFF as usize);
}

#[test]
fn num_queues_and_config_generation_and_msix_config_vector_roundtrip() {
    let mut dev = make_device();
    dev.mmio_poke_num_queues(3);
    dev.mmio_poke_config_generation(7);
    assert_eq!(dev.num_queues(), 3);
    assert_eq!(dev.config_generation(), 7);

    dev.set_msix_config_vector(42);
    assert_eq!(dev.mmio_read_msix_config_vector(), 42);
}

// -----------------------------------------------------------------------
// Queue-before-DRIVER_OK ordering and MSI-X vector read-back (stage 1a)
// -----------------------------------------------------------------------

#[test]
fn begin_stops_at_features_ok_and_set_driver_ok_finishes() {
    let mut dev = make_device();
    dev.mmio_poke_device_features(0, 0xffff_ffff);
    dev.mmio_poke_device_features(1, 0x1);

    dev.begin(0, 0).expect("VERSION_1 offered");
    assert_eq!(dev.mmio_read_status() & STATUS_DRIVER_OK, 0,
        "queues are set up between FEATURES_OK and DRIVER_OK; begin must not set DRIVER_OK");
    assert_ne!(dev.mmio_read_status() & STATUS_FEATURES_OK, 0);
    dev.set_driver_ok();
    assert_ne!(dev.mmio_read_status() & STATUS_DRIVER_OK, 0);
    dev.reset();
    assert_eq!(dev.mmio_read_status(), 0);
}

#[test]
fn queue_msix_vector_reads_back_the_selected_queue() {
    let mut dev = make_device();
    dev.setup_queue(1, 16, 0, 0, 0, 1);
    assert_eq!(dev.queue_msix_vector(1), 1);
}

#[test]
fn common_cfg_bar_names_the_bar_of_the_common_cap() {
    let cfg = build_caps();
    let (caps, n) = find_virtio_caps(&cfg, Bdf::new(0, 0, 0));
    assert_eq!(common_cfg_bar(&caps, n), Some(BAR));
    assert_eq!(common_cfg_bar(&caps, 0), None, "no caps -> no common BAR");
}
