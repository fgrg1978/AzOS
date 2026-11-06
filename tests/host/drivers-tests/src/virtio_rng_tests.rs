// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_virtio_rng` against a model of the virtio-mmio entropy device: the
//! model reads the request queue out of the region the driver laid out, at the
//! bus addresses the driver programmed, writes its bytes where the descriptor
//! says, and raises its interrupt, as QEMU's does (legacy and modern).

use azos_drvkit::fake::FakeMmio;
use azos_drvkit::{Mmio, Width};
use azos_virtio_proto::*;
use azos_virtio_rng::{Error, Layout, Rng, BUF_BYTES, QUEUE_ENTRIES};
use std::cell::Cell;

const PAGE: u64 = 4096;
const REGION: usize = 3 * PAGE as usize;
/// Where the region sits in bus space.
const BUS: u64 = 0x8040_0000;

type Region = FakeMmio<REGION>;

fn peek(m: &Region, off: usize, n: usize) -> u64 {
    (0..n).fold(0, |v, i| v | (m.peek8(off + i) as u64) << (8 * i))
}

fn poke(m: &Region, off: usize, n: usize, v: u64) {
    for i in 0..n {
        m.poke8(off + i, (v >> (8 * i)) as u8);
    }
}

/// The device's registers, and what it does on the doorbell.
struct Dev<'a> {
    version: u32,
    device_id: u32,
    region: &'a Region,
    status: Cell<u32>,
    feat_sel: Cell<u32>,
    dfeat_sel: Cell<u32>,
    drv_feat: Cell<u64>,
    num: Cell<u32>,
    page: Cell<u32>,
    pfn: Cell<u32>,
    desc: Cell<u64>,
    avail: Cell<u64>,
    used: Cell<u64>,
    ready: Cell<u32>,
    isr: Cell<u32>,
    /// Bytes the device claims it wrote: more than asked when set.
    overreport: Cell<u32>,
    last_avail: Cell<u16>,
    /// Buffers it wrote: (offset in the region, length).
    wrote: std::cell::RefCell<Vec<(u64, u32)>>,
}

impl<'a> Dev<'a> {
    fn new(version: u32, region: &'a Region) -> Self {
        Dev {
            version,
            device_id: VIRTIO_DEV_RNG,
            region,
            status: Cell::new(0),
            feat_sel: Cell::new(0),
            dfeat_sel: Cell::new(0),
            drv_feat: Cell::new(0),
            num: Cell::new(0),
            page: Cell::new(0),
            pfn: Cell::new(0),
            desc: Cell::new(0),
            avail: Cell::new(0),
            used: Cell::new(0),
            ready: Cell::new(0),
            isr: Cell::new(0),
            overreport: Cell::new(0),
            last_avail: Cell::new(0),
            wrote: Default::default(),
        }
    }

    /// The bus address `a` as an offset in the region.
    fn at(&self, a: u64) -> usize {
        assert!(a >= BUS && a < BUS + REGION as u64, "the device was sent outside the region: {a:#x}");
        (a - BUS) as usize
    }

    /// The queue's three parts, as the transport the driver used says.
    fn parts(&self) -> (u64, u64, u64) {
        if self.version == 1 {
            let base = self.pfn.get() as u64 * self.page.get() as u64;
            let l = Layout::of(self.num.get() as u16, self.page.get() as u64);
            (base, base + l.avail, base + l.used)
        } else {
            (self.desc.get(), self.avail.get(), self.used.get())
        }
    }

    fn notified(&self) {
        let r = self.region;
        let (desc, avail, used) = self.parts();
        let n = self.num.get() as u16;
        let idx = peek(r, self.at(avail) + VIRTQ_AVAIL_IDX_OFF as usize, 2) as u16;
        while self.last_avail.get() != idx {
            let k = self.last_avail.get();
            let head = peek(r, self.at(avail) + VIRTQ_AVAIL_RING_OFF as usize + 2 * (k % n) as usize, 2) as u64;
            let d = self.at(desc) + (head * VIRTQ_DESC_BYTES) as usize;
            let addr = peek(r, d, 8);
            let len = peek(r, d + VIRTQ_DESC_LEN_OFF as usize, 4) as u32;
            let flags = peek(r, d + VIRTQ_DESC_FLAGS_OFF as usize, 2) as u16;
            assert!(flags & VIRTQ_DESC_F_WRITE != 0, "the buffer is not device-writable");
            let at = self.at(addr);
            for i in 0..len as usize {
                r.poke8(at + i, 0xC0 ^ i as u8);
            }
            self.wrote.borrow_mut().push((at as u64, len));
            let uidx = peek(r, self.at(used) + VIRTQ_USED_IDX_OFF as usize, 2) as u16;
            let e = self.at(used) + VIRTQ_USED_RING_OFF as usize + (uidx % n) as usize * VIRTQ_USED_ELEM_BYTES as usize;
            poke(r, e, 4, head);
            poke(r, e + VIRTQ_USED_ELEM_LEN_OFF as usize, 4, (len + self.overreport.get()) as u64);
            poke(r, self.at(used) + VIRTQ_USED_IDX_OFF as usize, 2, uidx.wrapping_add(1) as u64);
            self.last_avail.set(k.wrapping_add(1));
            self.isr.set(self.isr.get() | VIRTIO_MMIO_INT_VRING);
        }
    }
}

impl Mmio for Dev<'_> {
    fn load(&self, off: usize, _w: Width) -> u64 {
        let offered = feature::VERSION_1 | feature::ACCESS_PLATFORM | (1 << 5);
        (match off as u32 {
            VIRTIO_MMIO_MAGIC => VIRTIO_MAGIC,
            VIRTIO_MMIO_VERSION => self.version,
            VIRTIO_MMIO_DEVICE_ID => self.device_id,
            VIRTIO_MMIO_DEVICE_FEATURES => feature::word(offered, self.feat_sel.get()),
            VIRTIO_MMIO_QUEUE_NUM_MAX => 8,
            VIRTIO_MMIO_STATUS => self.status.get(),
            VIRTIO_MMIO_INTERRUPT_STATUS => self.isr.get(),
            _ => 0,
        }) as u64
    }
    fn store(&self, off: usize, _w: Width, v: u64) {
        let v32 = v as u32;
        let hi = |c: &Cell<u64>| c.set(c.get() & 0xffff_ffff | (v32 as u64) << 32);
        let lo = |c: &Cell<u64>| c.set(c.get() & !0xffff_ffff | v32 as u64);
        match off as u32 {
            VIRTIO_MMIO_STATUS => {
                self.status.set(v32);
                if v32 == 0 {
                    self.ready.set(0);
                    self.last_avail.set(0);
                }
            }
            VIRTIO_MMIO_DEVICE_FEATURES_SEL => self.feat_sel.set(v32),
            VIRTIO_MMIO_DRIVER_FEATURES => {
                self.drv_feat.set(self.drv_feat.get() | (v32 as u64) << (32 * (self.dfeat_sel.get() & 1)));
            }
            VIRTIO_MMIO_DRIVER_FEATURES_SEL => self.dfeat_sel.set(v32),
            VIRTIO_MMIO_QUEUE_NUM => self.num.set(v32),
            VIRTIO_MMIO_GUEST_PAGE_SIZE => self.page.set(v32),
            VIRTIO_MMIO_QUEUE_PFN => self.pfn.set(v32),
            VIRTIO_MMIO_QUEUE_DESC_LOW => lo(&self.desc),
            VIRTIO_MMIO_QUEUE_DESC_HIGH => hi(&self.desc),
            VIRTIO_MMIO_QUEUE_AVAIL_LOW => lo(&self.avail),
            VIRTIO_MMIO_QUEUE_AVAIL_HIGH => hi(&self.avail),
            VIRTIO_MMIO_QUEUE_USED_LOW => lo(&self.used),
            VIRTIO_MMIO_QUEUE_USED_HIGH => hi(&self.used),
            VIRTIO_MMIO_QUEUE_READY => self.ready.set(v32),
            VIRTIO_MMIO_QUEUE_NOTIFY => self.notified(),
            VIRTIO_MMIO_INTERRUPT_ACK => self.isr.set(self.isr.get() & !v32),
            _ => {}
        }
    }
    fn base(&self) -> usize {
        0x1000_1000
    }
}

fn read_once(version: u32) -> (Vec<u8>, Vec<(u64, u32)>) {
    let region = Region::new();
    let dev = Dev::new(version, &region);
    let mut rng = Rng::bring_up(&dev, &region, BUS, REGION as u64, PAGE).expect("bring-up");
    assert_eq!(dev.status.get() & VIRTIO_STATUS_DRIVER_OK, VIRTIO_STATUS_DRIVER_OK, "DRIVER_OK");
    if version == 2 {
        assert_eq!(dev.ready.get(), 1, "the modern queue is ready");
        assert_eq!(dev.drv_feat.get() & feature::VERSION_1, feature::VERSION_1, "VERSION_1 accepted");
        assert_eq!(dev.drv_feat.get() & (1 << 5), 0, "a feature the driver does not know was accepted");
    } else {
        assert_eq!(dev.pfn.get() as u64 * PAGE, BUS, "the legacy queue at the region's page");
    }
    assert_eq!(rng.complete(), None, "nothing in flight");
    rng.request(48).unwrap();
    assert_eq!(rng.request(8), Err(Error::Busy), "one request at a time");
    assert_eq!(rng.ack_interrupt(), VIRTIO_MMIO_INT_VRING, "the used-buffer interrupt");
    assert_eq!(dev.isr.get(), 0, "acknowledged at the device");
    let n = rng.complete().expect("the device used the request");
    let mut out = vec![0u8; n];
    rng.copy_out(&mut out);
    let wrote = dev.wrote.borrow().clone();
    (out, wrote)
}

/// **The device fills the buffer the driver laid out in the region, through
/// the bus address it was given, on either transport.** The bytes come back
/// in order and nothing the device was told points outside the region.
///
/// **Canary.** Program the queue at `bus + PAGE` instead of `bus`: the model
/// finds no request, and `complete` answers `None`.
#[test]
fn the_device_fills_the_request_on_both_transports() {
    for version in [1, 2] {
        let (out, wrote) = read_once(version);
        assert_eq!(out, (0..48).map(|i| 0xC0 ^ i as u8).collect::<Vec<_>>(), "version {version}");
        let l = Layout::of(QUEUE_ENTRIES, PAGE);
        assert_eq!(wrote, vec![(l.buf, 48)], "version {version}: the buffer the layout names");
        assert!(l.bytes <= REGION as u64);
    }
}

/// **The length the device reports is clamped to what was asked.** A device
/// that says it wrote more cannot make the driver read past its request.
///
/// **Canary.** Return the device's length unclamped: 48 + 100 bytes.
#[test]
fn a_device_length_past_the_request_is_clamped() {
    let region = Region::new();
    let dev = Dev::new(2, &region);
    dev.overreport.set(100);
    let mut rng = Rng::bring_up(&dev, &region, BUS, REGION as u64, PAGE).unwrap();
    rng.request(48).unwrap();
    assert_eq!(rng.complete(), Some(48));
    rng.request(BUF_BYTES + 10).unwrap();
    assert_eq!(rng.complete(), Some(BUF_BYTES), "a request is at most one buffer");
}

/// **A device that is not an entropy one, and a region too small, are
/// refused before anything is programmed.**
#[test]
fn the_wrong_device_and_a_short_region_are_refused() {
    let region = Region::new();
    let mut dev = Dev::new(2, &region);
    dev.device_id = VIRTIO_DEV_BLOCK;
    assert!(matches!(Rng::bring_up(&dev, &region, BUS, REGION as u64, PAGE), Err(Error::NotEntropy)));
    let dev = Dev::new(2, &region);
    let short = Layout::of(QUEUE_ENTRIES, PAGE).bytes - 1;
    assert!(matches!(Rng::bring_up(&dev, &region, BUS, short, PAGE), Err(Error::Region)));
    assert_eq!(dev.ready.get(), 0, "a refused region was programmed");
    let dev = Dev::new(1, &region);
    assert!(matches!(Rng::bring_up(&dev, &region, BUS + 8, REGION as u64, PAGE), Err(Error::Region)), "a legacy queue off a page");
}

/// **`stop` resets the device: it uses no request after it.**
#[test]
fn stop_resets_the_device() {
    let region = Region::new();
    let dev = Dev::new(2, &region);
    let rng = Rng::bring_up(&dev, &region, BUS, REGION as u64, PAGE).unwrap();
    assert!(rng.stop());
    assert_eq!(dev.status.get(), 0);
    assert_eq!(dev.ready.get(), 0);
}
