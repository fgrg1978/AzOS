// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtio entropy device (id 4) on the virtio-mmio transport, legacy
//! (version 1) and modern (version 2), written for any host: no syscalls, no
//! statics. The host gives it two `azos_drvkit::Mmio` blocks, the device's
//! registers and the CPU's view of one physically contiguous region of
//! [`Layout::bytes`] bytes that holds the request queue and the buffer the
//! device writes, and the bus address its DMA domain gave that region. The
//! ring-3 host (`userspace/drivers/rng_drv`) maps the registers with
//! `DOMAIN_MMIO_MAP` and the region is a `DEVICE_DMA_MAP` object.
//!
//! One request is in flight at a time: [`Rng::request`] posts the buffer,
//! the device's interrupt (or a poll) is followed by [`Rng::complete`], which
//! answers how many bytes the device wrote, and [`Rng::copy_out`] reads them.
#![no_std]
#![forbid(unsafe_code)]

use azos_drvkit::Mmio;
use azos_virtio_proto::{
    feature, virtq_avail_bytes, virtq_used_bytes, VIRTIO_DEV_RNG, VIRTIO_MAGIC, VIRTIO_MMIO_DEVICE_FEATURES,
    VIRTIO_MMIO_DEVICE_FEATURES_SEL, VIRTIO_MMIO_DEVICE_ID, VIRTIO_MMIO_DRIVER_FEATURES,
    VIRTIO_MMIO_DRIVER_FEATURES_SEL, VIRTIO_MMIO_GUEST_PAGE_SIZE, VIRTIO_MMIO_INTERRUPT_ACK,
    VIRTIO_MMIO_INTERRUPT_STATUS, VIRTIO_MMIO_MAGIC, VIRTIO_MMIO_QUEUE_ALIGN, VIRTIO_MMIO_QUEUE_AVAIL_HIGH,
    VIRTIO_MMIO_QUEUE_AVAIL_LOW, VIRTIO_MMIO_QUEUE_DESC_HIGH, VIRTIO_MMIO_QUEUE_DESC_LOW, VIRTIO_MMIO_QUEUE_NOTIFY,
    VIRTIO_MMIO_QUEUE_NUM, VIRTIO_MMIO_QUEUE_NUM_MAX, VIRTIO_MMIO_QUEUE_PFN, VIRTIO_MMIO_QUEUE_READY,
    VIRTIO_MMIO_QUEUE_SEL, VIRTIO_MMIO_QUEUE_USED_HIGH, VIRTIO_MMIO_QUEUE_USED_LOW, VIRTIO_MMIO_STATUS,
    VIRTIO_MMIO_VERSION, VIRTIO_STATUS_ACK, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_DRIVER_OK,
    VIRTIO_STATUS_FEATURES_OK, VIRTQ_AVAIL_IDX_OFF, VIRTQ_AVAIL_RING_OFF, VIRTQ_DESC_BYTES,
    VIRTQ_DESC_FLAGS_OFF, VIRTQ_DESC_F_WRITE, VIRTQ_DESC_LEN_OFF, VIRTQ_DESC_NEXT_OFF, VIRTQ_USED_ELEM_BYTES,
    VIRTQ_USED_ELEM_LEN_OFF, VIRTQ_USED_IDX_OFF, VIRTQ_USED_RING_OFF,
};

/// Entries the driver asks the request queue for (fewer if the device has
/// fewer): one request is in flight at a time, so two leave room for none
/// to wait on a descriptor.
pub const QUEUE_ENTRIES: u16 = 2;
/// Bytes one request asks for at most.
pub const BUF_BYTES: usize = 64;
/// Polls of the status register a reset is given to read back 0.
const RESET_POLLS: u32 = 1 << 16;

/// Why the device cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No virtio-mmio transport at the window (magic or version).
    NotVirtio,
    /// A virtio device, not an entropy one.
    NotEntropy,
    /// The device did not read back 0 after a reset.
    ResetTimeout,
    /// The device refused the features (no `FEATURES_OK`).
    Features,
    /// Queue 0 does not exist.
    NoQueue,
    /// The region is smaller than [`Layout::bytes`], or not page-aligned in
    /// bus space for a legacy device.
    Region,
    /// A request is in flight already.
    Busy,
}

/// Where the queue's parts sit in the region, for a queue of `n` entries
/// (the legacy transport computes the used ring's place from `n` and the
/// page size, so the driver lays it out the same way).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub n: u16,
    pub avail: u64,
    pub used: u64,
    pub buf: u64,
    /// Bytes the region must have.
    pub bytes: u64,
}

const fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

impl Layout {
    /// The layout of a queue of `n` entries in pages of `page` bytes.
    pub const fn of(n: u16, page: u64) -> Layout {
        let avail = VIRTQ_DESC_BYTES * n as u64;
        let used = align_up(avail + virtq_avail_bytes(n as u64), page);
        let buf = align_up(used + virtq_used_bytes(n as u64), 64);
        Layout { n, avail, used, buf, bytes: buf + BUF_BYTES as u64 }
    }
}

/// The device, brought up, with its request queue in the region.
pub struct Rng<R: Mmio, M: Mmio> {
    regs: R,
    mem: M,
    layout: Layout,
    bus: u64,
    /// The available ring's next index.
    avail_idx: u16,
    /// The used ring's index last consumed.
    used_idx: u16,
    /// Bytes the request in flight asked for.
    asked: Option<u32>,
}

/// Reset the device at `regs` and wait for it to read back 0: no request
/// it held is used after this.
pub fn reset<R: Mmio>(regs: &R) -> bool {
    regs.write32(VIRTIO_MMIO_STATUS as usize, 0);
    (0..RESET_POLLS).any(|_| regs.read32(VIRTIO_MMIO_STATUS as usize) == 0)
}

impl<R: Mmio, M: Mmio> Rng<R, M> {
    /// Bring the entropy device at `regs` up with its request queue in the
    /// region `mem` (the CPU's view, `region` bytes long) whose bus address is
    /// `bus`, in pages of `page` bytes. The region is zeroed first.
    pub fn bring_up(regs: R, mem: M, bus: u64, region: u64, page: u64) -> Result<Self, Error> {
        if regs.read32(VIRTIO_MMIO_MAGIC as usize) != VIRTIO_MAGIC {
            return Err(Error::NotVirtio);
        }
        let version = regs.read32(VIRTIO_MMIO_VERSION as usize);
        if version != 1 && version != 2 {
            return Err(Error::NotVirtio);
        }
        let legacy = version == 1;
        if regs.read32(VIRTIO_MMIO_DEVICE_ID as usize) != VIRTIO_DEV_RNG {
            return Err(Error::NotEntropy);
        }
        if !reset(&regs) {
            return Err(Error::ResetTimeout);
        }
        let status = |s: u32| regs.write32(VIRTIO_MMIO_STATUS as usize, s);
        status(VIRTIO_STATUS_ACK);
        status(VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);
        let mut st = VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER;
        if !legacy {
            // The modern interface, and the device's own addresses where it
            // sits behind an IOMMU; the device needs nothing else.
            let mut offered = 0u64;
            for sel in 0..2u32 {
                regs.write32(VIRTIO_MMIO_DEVICE_FEATURES_SEL as usize, sel);
                offered |= (regs.read32(VIRTIO_MMIO_DEVICE_FEATURES as usize) as u64) << (32 * sel);
            }
            let take = offered & (feature::VERSION_1 | feature::ACCESS_PLATFORM);
            for sel in 0..2u32 {
                regs.write32(VIRTIO_MMIO_DRIVER_FEATURES_SEL as usize, sel);
                regs.write32(VIRTIO_MMIO_DRIVER_FEATURES as usize, feature::word(take, sel));
            }
            st |= VIRTIO_STATUS_FEATURES_OK;
            status(st);
            if regs.read32(VIRTIO_MMIO_STATUS as usize) & VIRTIO_STATUS_FEATURES_OK == 0 {
                return Err(Error::Features);
            }
        } else {
            regs.write32(VIRTIO_MMIO_DRIVER_FEATURES_SEL as usize, 0);
            regs.write32(VIRTIO_MMIO_DRIVER_FEATURES as usize, 0);
        }
        regs.write32(VIRTIO_MMIO_QUEUE_SEL as usize, 0);
        let max = regs.read32(VIRTIO_MMIO_QUEUE_NUM_MAX as usize);
        if max == 0 {
            return Err(Error::NoQueue);
        }
        let n = (max as u16).min(QUEUE_ENTRIES);
        let layout = Layout::of(n, page);
        if layout.bytes > region || (legacy && bus % page != 0) {
            return Err(Error::Region);
        }
        for off in (0..layout.bytes as usize).step_by(4) {
            mem.write32(off, 0);
        }
        regs.write32(VIRTIO_MMIO_QUEUE_NUM as usize, n as u32);
        let split = |v: u64| (v as u32, (v >> 32) as u32);
        if legacy {
            let Ok(pfn) = u32::try_from(bus / page) else { return Err(Error::Region) };
            regs.write32(VIRTIO_MMIO_GUEST_PAGE_SIZE as usize, page as u32);
            regs.write32(VIRTIO_MMIO_QUEUE_ALIGN as usize, page as u32);
            regs.write32(VIRTIO_MMIO_QUEUE_PFN as usize, pfn);
        } else {
            for (lo, hi, at) in [
                (VIRTIO_MMIO_QUEUE_DESC_LOW, VIRTIO_MMIO_QUEUE_DESC_HIGH, bus),
                (VIRTIO_MMIO_QUEUE_AVAIL_LOW, VIRTIO_MMIO_QUEUE_AVAIL_HIGH, bus + layout.avail),
                (VIRTIO_MMIO_QUEUE_USED_LOW, VIRTIO_MMIO_QUEUE_USED_HIGH, bus + layout.used),
            ] {
                let (l, h) = split(at);
                regs.write32(lo as usize, l);
                regs.write32(hi as usize, h);
            }
            regs.write32(VIRTIO_MMIO_QUEUE_READY as usize, 1);
        }
        status(st | VIRTIO_STATUS_DRIVER_OK);
        Ok(Rng { regs, mem, layout, bus, avail_idx: 0, used_idx: 0, asked: None })
    }

    /// The layout the queue was set up with.
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// Ask the device for `len` bytes (at most [`BUF_BYTES`]): one
    /// device-writable descriptor naming the buffer, published, then the
    /// doorbell.
    pub fn request(&mut self, len: usize) -> Result<(), Error> {
        if self.asked.is_some() {
            return Err(Error::Busy);
        }
        let len = len.clamp(1, BUF_BYTES) as u32;
        let d = 0usize;
        self.mem.write64(d, self.bus + self.layout.buf);
        self.mem.write32(d + VIRTQ_DESC_LEN_OFF as usize, len);
        self.mem.write16(d + VIRTQ_DESC_FLAGS_OFF as usize, VIRTQ_DESC_F_WRITE);
        self.mem.write16(d + VIRTQ_DESC_NEXT_OFF as usize, 0);
        let avail = self.layout.avail as usize;
        let slot = (self.avail_idx % self.layout.n) as usize;
        self.mem.write16(avail + VIRTQ_AVAIL_RING_OFF as usize + 2 * slot, 0);
        // The descriptor and the ring entry before the index the device reads.
        azos_dma::order::dma_wmb();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.mem.write16(avail + VIRTQ_AVAIL_IDX_OFF as usize, self.avail_idx);
        // The index before the doorbell.
        azos_dma::order::io_wmb();
        self.regs.write32(VIRTIO_MMIO_QUEUE_NOTIFY as usize, 0);
        self.asked = Some(len);
        Ok(())
    }

    /// The request in flight, if the device has used it: the bytes it wrote,
    /// at most what was asked (the length is the device's word).
    pub fn complete(&mut self) -> Option<usize> {
        let asked = self.asked?;
        let used = self.layout.used as usize;
        if self.mem.read16(used + VIRTQ_USED_IDX_OFF as usize) == self.used_idx {
            return None;
        }
        // The index before the element it publishes.
        azos_dma::order::dma_rmb();
        let slot = (self.used_idx % self.layout.n) as usize;
        let elem = used + VIRTQ_USED_RING_OFF as usize + slot * VIRTQ_USED_ELEM_BYTES as usize;
        let len = self.mem.read32(elem + VIRTQ_USED_ELEM_LEN_OFF as usize);
        self.used_idx = self.used_idx.wrapping_add(1);
        self.asked = None;
        Some(len.min(asked) as usize)
    }

    /// Copy the first `out.len()` bytes the device wrote, and clear them.
    pub fn copy_out(&self, out: &mut [u8]) {
        let buf = self.layout.buf as usize;
        for (i, b) in out.iter_mut().take(BUF_BYTES).enumerate() {
            *b = self.mem.read8(buf + i);
            self.mem.write8(buf + i, 0);
        }
    }

    /// Take the device's interrupt: the cause bits, acknowledged at the
    /// device so its line drops.
    pub fn ack_interrupt(&self) -> u32 {
        let s = self.regs.read32(VIRTIO_MMIO_INTERRUPT_STATUS as usize);
        if s != 0 {
            self.regs.write32(VIRTIO_MMIO_INTERRUPT_ACK as usize, s);
        }
        s
    }

    /// Stop the device: a reset, confirmed. Nothing in the region is read or
    /// written by it after a `true`.
    pub fn stop(&self) -> bool {
        reset(&self.regs)
    }
}
