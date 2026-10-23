// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! What the driver needs from the machine, as three traits.
//!
//! The crate never touches hardware itself. [`Regs`] reaches the controller's
//! register window, [`Memory`] hands out the DMA memory the controller reads
//! and writes (already mapped through the device's DMA domain, under its
//! addressing limit), and [`Clock`] measures and waits. The kernel
//! implements them over the mapped BAR, the page allocator with
//! `azos_dma::alloc_below` and the `DmaDomain`, and the arch timer
//! (kernel/src/boot/usb.rs); the host tests implement them over a register
//! array, a leaked host allocation and a virtual clock, and put a fake
//! controller behind the registers (tests/host/usb-tests).

use core::ptr;

/// The controller's register window. Offsets are bytes from the start of the
/// capability registers; the driver adds the operational, runtime and
/// doorbell bases itself.
pub trait Regs {
    fn read32(&self, off: usize) -> u32;
    fn write32(&self, off: usize, val: u32);

    /// A 64-bit register as two 32-bit accesses, low first. The xHCI
    /// specification allows it for every 64-bit register, and a window that
    /// cannot do a 64-bit access (several SoC buses) then needs no special
    /// case.
    fn read64(&self, off: usize) -> u64 {
        let lo = self.read32(off) as u64;
        lo | (self.read32(off + 4) as u64) << 32
    }
    fn write64(&self, off: usize, val: u64) {
        self.write32(off, val as u32);
        self.write32(off + 4, (val >> 32) as u32);
    }
}

/// Time. The driver waits in small steps, so a virtual clock that advances in
/// [`Clock::delay_us`] is a complete implementation for a test.
pub trait Clock {
    fn now_us(&self) -> u64;
    fn delay_us(&self, us: u32);
}

/// A block of DMA memory: where the CPU reads it, where the device does, how
/// long it is. Copyable; whoever allocated it frees it.
#[derive(Clone, Copy, Debug)]
pub struct DmaBuf {
    cpu: *mut u8,
    bus: u64,
    len: usize,
}

// SAFETY: a `DmaBuf` is an address pair; the memory behind it is accessed
// only by volatile word accesses and by the device, never through a Rust
// reference.
unsafe impl Send for DmaBuf {}

impl DmaBuf {
    /// `cpu` and `bus` name the same `len` bytes.
    ///
    /// # Safety
    /// `cpu` must be mapped, writable memory of `len` bytes for as long as the
    /// value is used.
    pub const unsafe fn new(cpu: *mut u8, bus: u64, len: usize) -> Self {
        DmaBuf { cpu, bus, len }
    }
    pub const EMPTY: DmaBuf = DmaBuf { cpu: ptr::null_mut(), bus: 0, len: 0 };

    pub fn cpu(&self) -> *mut u8 {
        self.cpu
    }
    pub fn bus(&self) -> u64 {
        self.bus
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Bus address of byte `off`.
    pub fn bus_at(&self, off: usize) -> u64 {
        self.bus + off as u64
    }
    /// The `len` bytes at `off`, as a buffer of their own.
    pub fn sub(&self, off: usize, len: usize) -> DmaBuf {
        assert!(off.checked_add(len).is_some_and(|e| e <= self.len), "DmaBuf::sub out of range");
        DmaBuf { cpu: self.cpu.wrapping_add(off), bus: self.bus + off as u64, len }
    }

    pub fn r32(&self, off: usize) -> u32 {
        assert!(off + 4 <= self.len && off % 4 == 0);
        // SAFETY: in range (checked) of memory `new` promised is mapped; the
        // device may write it, hence volatile.
        unsafe { ptr::read_volatile(self.cpu.add(off) as *const u32) }
    }
    pub fn w32(&self, off: usize, v: u32) {
        assert!(off + 4 <= self.len && off % 4 == 0);
        // SAFETY: as for `r32`.
        unsafe { ptr::write_volatile(self.cpu.add(off) as *mut u32, v) }
    }
    pub fn r64(&self, off: usize) -> u64 {
        self.r32(off) as u64 | (self.r32(off + 4) as u64) << 32
    }
    pub fn w64(&self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }
    pub fn zero(&self) {
        let mut o = 0;
        while o < self.len {
            self.w32(o, 0);
            o += 4;
        }
    }
    /// Copy `out.len()` bytes from `off` (bytewise, so any alignment).
    pub fn read_bytes(&self, off: usize, out: &mut [u8]) {
        assert!(off + out.len() <= self.len);
        for (i, b) in out.iter_mut().enumerate() {
            // SAFETY: in range (checked).
            *b = unsafe { ptr::read_volatile(self.cpu.add(off + i)) };
        }
    }
    pub fn write_bytes(&self, off: usize, data: &[u8]) {
        assert!(off + data.len() <= self.len);
        for (i, b) in data.iter().enumerate() {
            // SAFETY: in range (checked).
            unsafe { ptr::write_volatile(self.cpu.add(off + i), *b) };
        }
    }
}

/// DMA memory for the controller.
pub trait Memory {
    /// A zeroed, physically contiguous block of `len` bytes (a multiple of
    /// 4 KiB), aligned to `align`, every byte of it reachable at a bus
    /// address no higher than `mask`, and mapped for the device. Zero as the
    /// device sees it too: a controller that does not snoop the CPU's caches
    /// gets the block written back and dropped first. `None`: none to be had.
    fn alloc_region(&self, len: usize, align: usize, mask: u64) -> Option<DmaBuf>;
    /// Give a block back (unmapped first).
    fn free_region(&self, b: DmaBuf);
    /// Every region the controller will ever be given is mapped: start
    /// enforcing the DMA domain (a translating one now refuses the device any
    /// page that is not mapped). Called once, before the controller runs.
    /// `false`: the domain would not start.
    fn enable(&self) -> bool;
    /// The CPU wrote `[cpu, cpu + len)` and the device is about to read it:
    /// clean the cache lines. A coherent device makes this a no-op.
    fn to_device(&self, cpu: *const u8, len: usize);
    /// The device wrote `[cpu, cpu + len)` and the CPU is about to read it:
    /// drop the stale cache lines. A coherent device makes this a no-op.
    fn from_device(&self, cpu: *const u8, len: usize);
    /// Where the CPU reaches the `len` bytes at bus address `bus` of a buffer
    /// the device was handed (a class driver's), if the platform can say:
    /// what a controller that bounces part of a transfer copies through
    /// (`crate::dwc2`). `None`: it cannot, and such a transfer is refused.
    fn cpu_of(&self, _bus: u64, _len: usize) -> Option<*mut u8> {
        None
    }
}

/// Bytes of one arena page: the xHCI minimum page size, and what every
/// context, ring and table below fits in.
pub const PAGE: usize = 4096;

/// Pages the arena holds: the controller's fixed tables (the device context
/// base array, the command ring, the event ring and its segment table, the
/// shared input context), then per device its device context and endpoint-0
/// ring, and per pipe one transfer ring.
pub const ARENA_PAGES: usize = 8 + 2 * crate::MAX_DEVICES + crate::MAX_PIPES;
const ARENA_WORDS: usize = ARENA_PAGES.div_ceil(64);

/// Page-granular allocation inside the one region the controller owns. One
/// region is one DMA mapping, whatever the hot-plug traffic.
pub struct Arena {
    base: DmaBuf,
    used: [u64; ARENA_WORDS],
}

impl Arena {
    /// The arena over `region` (at least [`ARENA_PAGES`] pages are used; a
    /// longer region wastes the rest).
    pub fn new(region: DmaBuf) -> Option<Arena> {
        if region.len() < ARENA_PAGES * PAGE {
            return None;
        }
        Some(Arena { base: region, used: [0; ARENA_WORDS] })
    }

    /// One zeroed page, zero for the controller too: on a machine whose
    /// controller does not snoop the CPU's caches the zeroes are cleaned out,
    /// or it would read what the page held before (a stale TRB with a valid
    /// cycle bit) and a dirty line evicted later would overwrite what it
    /// wrote. `None` when all are in use.
    pub fn page<M: Memory>(&mut self, m: &M) -> Option<DmaBuf> {
        for p in 0..ARENA_PAGES {
            let (w, b) = (p / 64, p % 64);
            if self.used[w] & (1 << b) == 0 {
                self.used[w] |= 1 << b;
                let page = self.base.sub(p * PAGE, PAGE);
                page.zero();
                #[cfg(not(feature = "canary-arena-clean"))]
                m.to_device(page.cpu(), PAGE);
                #[cfg(feature = "canary-arena-clean")]
                let _ = m;
                return Some(page);
            }
        }
        None
    }

    /// Give a page back. A page that is not in use is ignored (a double free
    /// must not free someone else's).
    pub fn release(&mut self, page: DmaBuf) {
        let off = page.bus().wrapping_sub(self.base.bus()) as usize;
        if off % PAGE != 0 || off / PAGE >= ARENA_PAGES {
            return;
        }
        let p = off / PAGE;
        self.used[p / 64] &= !(1 << (p % 64));
    }

    pub fn free_pages(&self) -> usize {
        ARENA_PAGES - self.used.iter().map(|w| w.count_ones() as usize).sum::<usize>()
    }

    pub fn region(&self) -> DmaBuf {
        self.base
    }
}
