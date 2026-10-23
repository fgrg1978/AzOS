// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO MMIO driver — common structures and queue management.
//!
//! Direct port of kernel/drivers/virtio.c + kernel/include/virtio.h.
//! Supports both legacy (v1) and modern (v2) MMIO transport.

pub mod blk;
pub mod blk_proto;
pub mod gpu;
pub mod gpu_proto;
pub mod input;
pub mod input_cfg;
pub mod net;
#[cfg(feature = "pci")]
pub mod pci;
pub mod rng;
pub mod snd;
pub mod snd_proto;

use core::sync::atomic::{fence, Ordering};

use azos_dma::{Direction, DmaDomain};

// ---- MMIO Register Offsets (from virtio.h) ----

pub const VIRTIO_MMIO_MAGIC:              u32 = 0x000;
pub const VIRTIO_MMIO_VERSION:            u32 = 0x004;
pub const VIRTIO_MMIO_DEVICE_ID:          u32 = 0x008;
pub const VIRTIO_MMIO_VENDOR_ID:          u32 = 0x00c;
pub const VIRTIO_MMIO_DEVICE_FEATURES:    u32 = 0x010;
pub const VIRTIO_MMIO_DEVICE_FEATURES_SEL:u32 = 0x014;
pub const VIRTIO_MMIO_DRIVER_FEATURES:    u32 = 0x020;
pub const VIRTIO_MMIO_DRIVER_FEATURES_SEL:u32 = 0x024;
pub const VIRTIO_MMIO_GUEST_PAGE_SIZE:    u32 = 0x028; // legacy only
pub const VIRTIO_MMIO_QUEUE_SEL:          u32 = 0x030;
pub const VIRTIO_MMIO_QUEUE_NUM_MAX:      u32 = 0x034;
pub const VIRTIO_MMIO_QUEUE_NUM:          u32 = 0x038;
pub const VIRTIO_MMIO_QUEUE_ALIGN:        u32 = 0x03c; // legacy only
pub const VIRTIO_MMIO_QUEUE_PFN:          u32 = 0x040; // legacy only
pub const VIRTIO_MMIO_QUEUE_READY:        u32 = 0x044; // modern only
pub const VIRTIO_MMIO_QUEUE_NOTIFY:       u32 = 0x050;
pub const VIRTIO_MMIO_INTERRUPT_STATUS:   u32 = 0x060;
pub const VIRTIO_MMIO_INTERRUPT_ACK:      u32 = 0x064;
pub const VIRTIO_MMIO_STATUS:             u32 = 0x070;
pub const VIRTIO_MMIO_QUEUE_DESC_LOW:     u32 = 0x080;
pub const VIRTIO_MMIO_QUEUE_DESC_HIGH:    u32 = 0x084;
pub const VIRTIO_MMIO_QUEUE_AVAIL_LOW:    u32 = 0x090;
pub const VIRTIO_MMIO_QUEUE_AVAIL_HIGH:   u32 = 0x094;
pub const VIRTIO_MMIO_QUEUE_USED_LOW:     u32 = 0x0a0;
pub const VIRTIO_MMIO_QUEUE_USED_HIGH:    u32 = 0x0a4;
pub const VIRTIO_MMIO_CONFIG:             u32 = 0x100;

// ---- Constants ----

pub const VIRTIO_MAGIC:      u32 = 0x7472_6976; // "virt"
pub const VIRTIO_DEV_NET:    u32 = 1;
pub const VIRTIO_DEV_BLOCK:  u32 = 2;
pub const VIRTIO_DEV_RNG:    u32 = 4;
pub const VIRTIO_DEV_INPUT:  u32 = 18;
pub const VIRTIO_DEV_GPU:    u32 = 16;
pub const VIRTIO_DEV_SND:    u32 = 25;
pub const VIRTIO_QUEUE_SIZE: usize = 16;

/// Capacity of the ring arrays every [`Virtq`] carries (`avail.ring`,
/// `used.ring`, `desc_used`): the largest queue any driver here asks for —
/// [`VIRTIO_QUEUE_SIZE`] (blk, rng) or the virtio-net rings (Kconfig
/// `NET_VIRTIO_RXQ_SIZE` / `NET_VIRTIO_TXQ_SIZE`). A queue's actual size is
/// `Virtq::num`, and every index is taken modulo it, so a queue smaller than
/// the capacity uses the first `num` entries of each array — which is also
/// where the device looks: the split-ring entry offsets (`4 + 2*i`,
/// `4 + 8*i`) do not depend on the queue size.
pub const VIRTQ_CAPACITY: usize = {
    let mut c = VIRTIO_QUEUE_SIZE;
    if azos_limits::NET_VIRTIO_RXQ_SIZE as usize > c { c = azos_limits::NET_VIRTIO_RXQ_SIZE as usize; }
    if azos_limits::NET_VIRTIO_TXQ_SIZE as usize > c { c = azos_limits::NET_VIRTIO_TXQ_SIZE as usize; }
    c
};
// One page of descriptors (16 B each), and `free_count`/`free_head` are u16.
const _: () = assert!(VIRTQ_CAPACITY <= 256 && VIRTQ_CAPACITY.is_power_of_two());

// ---- MMIO transport window (one definition, three former copies) ----
//
// `blk.rs`, `net.rs` and `rng.rs`'s `device` submodule each hardcoded their
// own `VIRTIO_MMIO_BASE`/stride/count under a different local name. Moved
// here so a second ISA needs one new arm, not three.
//
// This block, not `platform::hw`: on QEMU `virt` (either ISA) the VirtIO
// window is a property of the *machine*, not the board family — VF2/K1 are
// real silicon with no VirtIO devices at all, and `blkdev.rs`/`net`'s own
// per-board routing never calls into this module on those features (see
// `blkdev.rs`'s module doc), so this crate compiles the same literal for
// every RISC-V feature combination, unused and harmless on real hardware —
// exactly the pre-existing behaviour, just no longer copied three times. The
// value only actually changes on the one board family it is board-specific
// for: aarch64 `virt`, where it comes from `platform::hw` (single source —
// see that module's own doc for the DTB fetch that confirmed it) since that
// side has no "same value on real hardware too" excuse to share.
/// First VirtIO-MMIO slot. RISC-V QEMU `virt`: `hw/riscv/virt.c`'s
/// `VIRT_VIRTIO` MemMapEntry.
#[cfg(not(any(all(target_arch = "aarch64", target_os = "none"), all(target_arch = "x86_64", target_os = "none"))))]
pub const VIRTIO_MMIO_BASE: usize = 0x1000_1000;
#[cfg(not(any(all(target_arch = "aarch64", target_os = "none"), all(target_arch = "x86_64", target_os = "none"))))]
pub const VIRTIO_MMIO_STRIDE: usize = 0x1000;
#[cfg(not(any(all(target_arch = "aarch64", target_os = "none"), all(target_arch = "x86_64", target_os = "none"))))]
pub const VIRTIO_MMIO_COUNT: usize = 8;

/// aarch64 QEMU `virt` — see `platform::hw::VIRTIO_MMIO_BASE`'s doc for the
/// DTB fetch this was confirmed against (32 slots, 0x200 stride, base
/// 0x0A00_0000).
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use azos_drv_base::platform::hw::{
    VIRTIO_MMIO_BASE, VIRTIO_MMIO_STRIDE, VIRTIO_MMIO_COUNT,
};

/// x86_64 (QEMU microvm): the window `platform::hw` takes from Kconfig
/// `X86_VIRTIO_MMIO_*`; each transport's GSI is the boot's discovery
/// (`azos_arch::platform_impl::platform().virtio_gsi`).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use azos_drv_base::platform::hw::{
    VIRTIO_MMIO_BASE, VIRTIO_MMIO_STRIDE, VIRTIO_MMIO_COUNT,
};

// Status bits
pub const VIRTIO_STATUS_ACK:          u32 = 1;
pub const VIRTIO_STATUS_DRIVER:       u32 = 2;
pub const VIRTIO_STATUS_DRIVER_OK:    u32 = 4;
pub const VIRTIO_STATUS_FEATURES_OK:  u32 = 8;
pub const VIRTIO_STATUS_FAILED:       u32 = 128;

// Descriptor flags
pub const VIRTQ_DESC_F_NEXT:     u16 = 1;
pub const VIRTQ_DESC_F_WRITE:    u16 = 2;

// ---- VirtIO Ring Structures (repr(C, packed) matches C ABI) ----

#[repr(C, packed)]
pub struct VirtqDesc {
    pub addr:  u64,
    pub len:   u32,
    pub flags: u16,
    pub next:  u16,
}

/// The driver area. `used_event` (VIRTIO_F_EVENT_IDX) sits at
/// `ring[num]`, after the queue's own entries, so it is not a field here:
/// no driver negotiates EVENT_IDX (see [`virtq_device_wants_kick`]).
#[repr(C, packed)]
pub struct VirtqAvail {
    pub flags:      u16,
    pub idx:        u16,
    pub ring:       [u16; VIRTQ_CAPACITY],
}

#[repr(C, packed)]
pub struct VirtqUsedElem {
    pub id:  u32,
    pub len: u32,
}

/// The device area. `avail_event` (VIRTIO_F_EVENT_IDX) sits at
/// `ring[num]`; not a field, for the reason [`VirtqAvail`] gives.
#[repr(C, packed)]
pub struct VirtqUsed {
    pub flags:       u16,
    pub idx:         u16,
    pub ring:        [VirtqUsedElem; VIRTQ_CAPACITY],
}

// ---- VirtQueue state ----

pub struct Virtq {
    pub desc:          *mut VirtqDesc,
    pub avail:         *mut VirtqAvail,
    pub used:          *mut VirtqUsed,
    pub num:           u16,
    pub free_head:     u16,
    pub free_count:    u16,
    pub last_used_idx: u16,
    pub desc_used:     [bool; VIRTQ_CAPACITY],
    /// Used-ring entries consumed whose `id` was out of range. Nonzero means
    /// the device wrote garbage into the used ring — a device fault, not a
    /// driver state. The entry is still consumed (see `virtq_poll_with_len`:
    /// leaving it would wedge the queue on the same entry forever), so this
    /// counter is the ONLY trace the fault leaves; drivers should treat a
    /// nonzero value as reason to distrust the device.
    pub bad_completions: u16,
    /// VIRTIO_F_EVENT_IDX negotiated for this queue's device: kicks follow
    /// the device's `avail_event`, interrupts the driver's `used_event`,
    /// and both flags fields are ignored (virtio 1.x 2.7.7, 2.7.10).
    pub event_idx: bool,
    /// `avail.idx` at the last kick decision ([`virtq_kick_decision`]):
    /// the `old` of the EVENT_IDX test.
    pub kick_idx: u16,
    /// The queue's DMA domain when the device is NOT cache-coherent, else
    /// `None`: every access to a ring then goes through cache maintenance
    /// (`clean` what the device reads, `flush` what it writes).
    nc: Option<&'static dyn DmaDomain>,
    /// The bus addresses the device was given for the descriptor table, the
    /// driver area and the device area (a legacy queue's one block: the
    /// first, the others 0). Kept so a reset device is programmed again over
    /// the same memory ([`virtq_reprogram`], [`virtq_reset_rings`]).
    pub bus: [u64; 3],
}

impl Virtq {
    pub const fn zeroed() -> Self {
        Virtq {
            desc:          core::ptr::null_mut(),
            avail:         core::ptr::null_mut(),
            used:          core::ptr::null_mut(),
            num:           0,
            free_head:     0,
            free_count:    0,
            last_used_idx: 0,
            desc_used:     [false; VIRTQ_CAPACITY],
            bad_completions: 0,
            event_idx:     false,
            kick_idx:      0,
            nc:            None,
            bus:           [0; 3],
        }
    }

    /// Make the CPU's writes to `[p, p + len)` of the driver area (the
    /// descriptor table, the avail ring) visible to a non-coherent device.
    #[inline(always)]
    unsafe fn clean<T>(&self, p: *const T, len: usize) {
        if let Some(d) = self.nc {
            unsafe { azos_dma::cache::sync_for_device(d, p as usize, len, Direction::ToDevice) };
        }
    }

    /// Drop the CPU's cached copy of `[p, p + len)` of the device area (the
    /// used ring) so the next read sees what the device wrote.
    #[inline(always)]
    unsafe fn refresh<T>(&self, p: *const T, len: usize) {
        if let Some(d) = self.nc {
            unsafe { azos_dma::cache::sync_for_cpu(d, p as usize, len, Direction::FromDevice) };
        }
    }
}

// ---- VirtIO Device ----

#[derive(Clone, Copy)]
pub struct VirtioDev {
    pub base:      *mut u32, // MMIO base address
    pub device_id: u32,
    pub version:   u32,
}

impl VirtioDev {
    pub const fn zeroed() -> Self {
        VirtioDev { base: core::ptr::null_mut(), device_id: 0, version: 0 }
    }
}

// ---- MMIO helpers (port of virtio_read32 / virtio_write32 inline functions) ----

#[inline(always)]
pub unsafe fn mmio_read(base: *mut u32, offset: u32) -> u32 {
    core::ptr::read_volatile(base.add((offset / 4) as usize))
}

#[inline(always)]
pub unsafe fn mmio_write(base: *mut u32, offset: u32, val: u32) {
    core::ptr::write_volatile(base.add((offset / 4) as usize), val);
}

// ---- virtio_probe (port of virtio_probe in virtio.c) ----

/// How a device reaches memory: the DMA domain it sits in.
///
/// A device performs DMA with BUS addresses. Without an IOMMU a bus address
/// is the physical address; with one it is whatever the device's domain
/// made reachable. The CPU reaches the same bytes through its own virtual
/// address, and those differ from the physical ones on aarch64 and x86_64.
/// So a buffer is MAPPED through the domain once ([`Dma::map`]) and the
/// device is told the bus address that returns, never `virt_to_phys` of the
/// pointer: the domain may refuse the buffer (outside RAM, out of reach of
/// the device), and a translating domain refuses the device every page that
/// was not mapped. Every buffer here is driver-owned `static` storage or a
/// ring page, so each mapping lives as long as the kernel.
///
/// Behind a domain that is not cache-coherent, the CPU also brackets each
/// transfer with [`Dma::sync_for_device`] / [`Dma::sync_for_cpu`]; behind a
/// coherent one both are a no-op.
#[derive(Clone, Copy)]
pub struct Dma {
    domain: &'static dyn DmaDomain,
}

impl Dma {
    /// The domain of a device nobody installed one for; what a `static`
    /// driver state starts with, replaced at init.
    pub const fn fallback() -> Dma {
        Dma { domain: azos_dma::registry::fallback() }
    }

    /// The platform device (virtio-mmio) whose registers start at `base`:
    /// the default domain, with the cache coherence the firmware declared
    /// for the device.
    pub fn mmio(base: usize) -> Dma {
        Dma { domain: azos_dma::registry::domain_for_mmio(base as u64) }
    }

    /// The PCI function with requester id `rid` (`bus << 8 | dev << 3 | fn`).
    pub fn pci(rid: u32) -> Dma {
        Dma { domain: azos_dma::registry::domain_for(Some(rid)) }
    }

    pub fn coherent(&self) -> bool {
        self.domain.coherent()
    }

    /// The domain, if the CPU has to maintain caches around its transfers
    /// (a [`Virtq`] keeps it for the ring accesses).
    fn non_coherent(&self) -> Option<&'static dyn DmaDomain> {
        if self.domain.coherent() { None } else { Some(self.domain) }
    }

    /// Map `len` bytes at the physical address `pa` for `dir`; the bus
    /// address of the first byte.
    pub fn map_phys(&self, pa: u64, len: usize, dir: Direction) -> Result<u64, ()> {
        self.domain.map(pa, len, dir).map(|b| b.0).map_err(|e| {
            azos_drv_sys::kerr!("[VIRTIO] DMA map of {:#x}+{:#x} refused: {:?}", pa, len, e);
        })
    }

    /// Map `len` bytes at the kernel address `ptr` (physically contiguous:
    /// kernel image storage or one page-allocator block).
    pub fn map<T: ?Sized>(&self, ptr: *const T, len: usize, dir: Direction) -> Result<u64, ()> {
        self.map_phys(azos_mm::addr::virt_to_phys(ptr as *const u8 as usize) as u64, len, dir)
    }

    /// Undo a mapping [`Dma::map_phys`] made: `bus`, `len` as it returned
    /// and was asked. A stream's arena is mapped for the stream's life.
    pub fn unmap(&self, bus: u64, len: usize) {
        let _ = self.domain.unmap(azos_dma::DmaAddr(bus), len);
    }

    /// Start the domain enforcing (a translating domain now refuses the
    /// device every page that is not mapped). After every buffer is mapped,
    /// before the device is started.
    pub fn enable(&self) -> Result<(), ()> {
        self.domain.enable().map_err(|e| {
            azos_drv_sys::kerr!("[VIRTIO] DMA domain would not start: {:?}", e);
        })
    }

    /// Let the device write the interrupt doorbell at `doorbell` (an MSI-X
    /// message address): a translating domain refuses it otherwise.
    pub fn allow_msi(&self, doorbell: u64) -> Result<(), ()> {
        self.domain.allow_msi(doorbell).map_err(|e| {
            azos_drv_sys::kerr!("[VIRTIO] DMA domain refused the interrupt doorbell {:#x}: {:?}", doorbell, e);
        })
    }

    /// Hand `[ptr, ptr + len)` to the device for a transfer of `dir`.
    ///
    /// # Safety
    /// The range must be mapped kernel memory.
    #[inline(always)]
    pub unsafe fn sync_for_device(&self, ptr: *const u8, len: usize, dir: Direction) {
        unsafe { azos_dma::cache::sync_for_device(self.domain, ptr as usize, len, dir) }
    }

    /// Take `[ptr, ptr + len)` back from the device after a transfer of `dir`.
    ///
    /// # Safety
    /// The range must be mapped kernel memory.
    #[inline(always)]
    pub unsafe fn sync_for_cpu(&self, ptr: *const u8, len: usize, dir: Direction) {
        unsafe { azos_dma::cache::sync_for_cpu(self.domain, ptr as usize, len, dir) }
    }
}

/// The pointer the CPU must use for a page the allocator handed back.
///
/// `pmm::alloc_page` returns a PHYSICAL address. Dereferencing it directly
/// only worked while the kernel was identity-mapped.
#[inline]
pub fn dma_page_ptr(pa: usize) -> usize {
    azos_mm::addr::phys_to_virt(pa)
}

/// Check if a VirtIO device exists at the given MMIO address.
/// Returns Ok(device_id) or Err.
pub unsafe fn probe(base_addr: usize, dev: &mut VirtioDev) -> Result<(), ()> {
    let base = base_addr as *mut u32;

    let magic = mmio_read(base, VIRTIO_MMIO_MAGIC);
    if magic != VIRTIO_MAGIC {
        return Err(());
    }

    let version = mmio_read(base, VIRTIO_MMIO_VERSION);
    if version != 1 && version != 2 {
        return Err(());
    }

    let device_id = mmio_read(base, VIRTIO_MMIO_DEVICE_ID);
    if device_id == 0 {
        return Err(());
    }

    dev.base      = base;
    dev.device_id = device_id;
    dev.version   = version;
    Ok(())
}

// ---- virtio_init (port of virtio_init in virtio.c) ----

/// Initialize a VirtIO device (feature negotiation, status handshake).
/// Follows the VirtIO initialization sequence from the spec.
pub unsafe fn init(dev: &mut VirtioDev) -> Result<(), ()> {
    init_with(dev, 0).map(|_| ())
}

/// [`init`], also accepting the optional feature bits of word 0 in
/// `want_low` that the device offers. Returns the bits accepted.
pub unsafe fn init_with(dev: &mut VirtioDev, want_low: u32) -> Result<u32, ()> {
    // Step 1: Reset
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, 0);

    // Legacy: set guest page size
    if dev.version == 1 {
        mmio_write(dev.base, VIRTIO_MMIO_GUEST_PAGE_SIZE, azos_arch::PAGE_SIZE as u32);
    }

    // Step 2: ACK
    let s = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_ACK);

    // Step 3: DRIVER
    let s = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER);

    // Step 4: Feature negotiation — accept no optional features EXCEPT
    // VIRTIO_F_VERSION_1 (bit 32) on a modern (v2) transport.
    //
    // U05-12 fix (2026-09-26): this module's doc claims "Supports both
    // legacy (v1) and modern (v2)", but a v2 transport MUST see
    // VIRTIO_F_VERSION_1 acknowledged before it will grant FEATURES_OK —
    // the VirtIO 1.0+ spec (§6, "Legacy Interface") makes accepting this
    // bit the definition of "not legacy", and a device is free to refuse
    // FEATURES_OK otherwise. That bit lives in the SECOND feature word
    // (bits 32-63), selected via `*_FEATURES_SEL = 1` — this function only
    // ever touched selector 0 (bits 0-31), so no v2 device could ever pass
    // the FEATURES_OK check below; it fell through to `FAILED` every time,
    // invisibly, because QEMU `virt` exposes legacy v1 slots and the gate
    // never exercises a v2 slot.
    mmio_write(dev.base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
    let features = mmio_read(dev.base, VIRTIO_MMIO_DEVICE_FEATURES);
    let accepted = features & want_low;
    mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES, accepted);

    if dev.version != 1 {
        const VIRTIO_F_VERSION_1_BIT0: u32 = 1 << 0; // bit 32 overall, bit 0 of word 1
        mmio_write(dev.base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1);
        let hi_features = mmio_read(dev.base, VIRTIO_MMIO_DEVICE_FEATURES);
        mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1);
        mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES, hi_features & VIRTIO_F_VERSION_1_BIT0);
    }

    // Step 5: FEATURES_OK
    let s = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_FEATURES_OK);

    let status = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
    if status & VIRTIO_STATUS_FEATURES_OK == 0 {
        mmio_write(dev.base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return Err(());
    }

    Ok(accepted)
}

// ---- virtq_init (port of virtq_init in virtio.c) ----

/// Initialize a virtqueue of [`VIRTIO_QUEUE_SIZE`] entries (or fewer, if
/// the device offers fewer). Handles both legacy (v1) and modern (v2).
pub unsafe fn virtq_init(dev: &mut VirtioDev, queue_idx: u32, vq: &mut Virtq, dma: &Dma) -> Result<(), ()> {
    virtq_init_sized(dev, queue_idx, vq, VIRTIO_QUEUE_SIZE, dma)
}

/// [`virtq_init`] for a queue of `want` entries (a power of two, at most
/// [`VIRTQ_CAPACITY`]); the device may grant fewer (`QUEUE_NUM_MAX`).
pub unsafe fn virtq_init_sized(
    dev: &mut VirtioDev,
    queue_idx: u32,
    vq: &mut Virtq,
    want: usize,
    dma: &Dma,
) -> Result<(), ()> {
    use azos_mm::pmm;

    mmio_write(dev.base, VIRTIO_MMIO_QUEUE_SEL, queue_idx);

    let max_size = mmio_read(dev.base, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if max_size == 0 || want == 0 || want > VIRTQ_CAPACITY {
        return Err(());
    }

    // A device maximum below `want` that is not a power of two (legal on
    // the legacy transport only) still yields a power of two here.
    let mut queue_size = want.min(max_size as usize);
    while !queue_size.is_power_of_two() { queue_size &= queue_size - 1; }
    let queue_size = queue_size as u16;
    vq.num = queue_size;
    vq.nc = dma.non_coherent();

    if dev.version == 1 {
        // Legacy mode: contiguous memory block
        // Layout: [desc_table | avail_ring | padding_to_page | used_ring]
        // For 16 entries: total ~4230 bytes = 2 pages; for 256, 3 pages.
        let (desc_size, used_offset, total_size) = legacy_layout(queue_size);
        let page_sz = azos_arch::PAGE_SIZE;
        let pages_needed = (total_size + page_sz - 1) / page_sz;

        // One physically contiguous block: the device is told only the first
        // PFN and finds the used ring at `used_offset` from it. Consecutive
        // `alloc_page()` calls do not guarantee that (the PMM's scan cursor
        // can hand back a page below, or far from, the previous one), so the
        // used ring could land in a frame that belongs to someone else.
        // `alloc_contiguous` returns the block zeroed, and on failure claims
        // nothing, so no page leaks on this error path.
        let first_page = pmm::alloc_contiguous(pages_needed).map_err(|_| ())?.0;
        // `first_page` is PHYSICAL. The CPU writes the rings through its own
        // mapping; the device is told the BUS frame number of the same block
        // below (the domain's answer: the physical one without an IOMMU).
        let queue_mem = dma_page_ptr(first_page) as *mut u8;
        let bus = dma.map_phys(first_page as u64, pages_needed * page_sz, Direction::Bidirectional)?;

        vq.desc  = queue_mem as *mut VirtqDesc;
        vq.avail = queue_mem.add(desc_size) as *mut VirtqAvail;
        vq.used  = queue_mem.add(used_offset) as *mut VirtqUsed;
        vq.bus   = [bus, 0, 0];
    } else {
        // Modern mode: separate pages for desc, avail, used
        let desc_page  = pmm::alloc_page().map_err(|_| ())?.0;
        let avail_page = pmm::alloc_page().map_err(|_| ())?.0;
        let used_page  = pmm::alloc_page().map_err(|_| ())?.0;
        // PAs from the allocator: the CPU needs its own view of them.
        vq.desc  = dma_page_ptr(desc_page)  as *mut VirtqDesc;
        vq.avail = dma_page_ptr(avail_page) as *mut VirtqAvail;
        vq.used  = dma_page_ptr(used_page)  as *mut VirtqUsed;

        // The device's view: the bus address of each ring page.
        let page = azos_arch::PAGE_SIZE;
        vq.bus = [
            dma.map_phys(desc_page  as u64, page, Direction::Bidirectional)?,
            dma.map_phys(avail_page as u64, page, Direction::Bidirectional)?,
            dma.map_phys(used_page  as u64, page, Direction::Bidirectional)?,
        ];
    }
    virtq_reprogram(dev, queue_idx, vq)
}

/// `(descriptor table bytes, offset of the used ring, total bytes)` of a
/// legacy queue of `num` entries: one block, the used ring page-aligned.
fn legacy_layout(num: u16) -> (usize, usize, usize) {
    let desc_size  = 16 * num as usize;
    let avail_size = 6 + 2 * num as usize;
    let page_sz    = azos_arch::PAGE_SIZE;
    let used_offset = ((desc_size + avail_size + page_sz - 1) / page_sz) * page_sz;
    let used_size  = 6 + 8 * num as usize;
    (desc_size, used_offset, used_offset + used_size)
}

/// Make the rings of `vq` empty again over the memory they already have:
/// zeroed, every descriptor free, the cursors at 0. After a device reset
/// (status 0 read back: the device no longer touches them), before the queue
/// is given to the device again.
pub unsafe fn virtq_reset_rings(vq: &mut Virtq, legacy: bool) {
    let page = azos_arch::PAGE_SIZE;
    let (_, used_offset, total) = legacy_layout(vq.num);
    if legacy {
        core::ptr::write_bytes(vq.desc as *mut u8, 0, total);
    } else {
        core::ptr::write_bytes(vq.desc  as *mut u8, 0, page);
        core::ptr::write_bytes(vq.avail as *mut u8, 0, page);
        core::ptr::write_bytes(vq.used  as *mut u8, 0, page);
    }
    init_free_list(vq, vq.num);
    // A non-coherent device reads the zeroed rings from RAM: write them
    // back, then drop the used ring's lines so the device's entries show.
    if legacy {
        vq.clean(vq.desc, total);
        vq.refresh(vq.used, total - used_offset);
    } else {
        vq.clean(vq.desc, page);
        vq.clean(vq.avail, page);
        vq.refresh(vq.used, page);
    }
    vq.kick_idx = 0;
}

/// Give the virtio-mmio device queue `queue_idx` over `vq`'s memory, the
/// rings emptied first ([`virtq_reset_rings`]): bring-up ([`virtq_init_sized`])
/// and the re-programming of a device that was reset after a timeout
/// (`azos_drv_api::recovery`), which must not allocate or map again.
pub unsafe fn virtq_reprogram(dev: &VirtioDev, queue_idx: u32, vq: &mut Virtq) -> Result<(), ()> {
    if vq.desc.is_null() || vq.num == 0 {
        return Err(());
    }
    mmio_write(dev.base, VIRTIO_MMIO_QUEUE_SEL, queue_idx);
    // A reset device that now offers a smaller queue cannot take this one.
    if mmio_read(dev.base, VIRTIO_MMIO_QUEUE_NUM_MAX) < vq.num as u32 {
        return Err(());
    }
    virtq_reset_rings(vq, dev.version == 1);
    mmio_write(dev.base, VIRTIO_MMIO_QUEUE_NUM, vq.num as u32);
    if dev.version == 1 {
        // Tell device: queue num, alignment, PFN
        let page_sz = azos_arch::PAGE_SIZE;
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_ALIGN,  page_sz as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_PFN,   (vq.bus[0] / page_sz as u64) as u32);
    } else {
        let [desc_addr, avail_addr, used_addr] = vq.bus;
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_DESC_LOW,  desc_addr  as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_DESC_HIGH, (desc_addr  >> 32) as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_AVAIL_LOW, avail_addr as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_AVAIL_HIGH,(avail_addr >> 32) as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_USED_LOW,  used_addr  as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_USED_HIGH, (used_addr  >> 32) as u32);

        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_READY, 1);
    }
    Ok(())
}

unsafe fn init_free_list(vq: &mut Virtq, queue_size: u16) {
    vq.free_head     = 0;
    vq.free_count    = queue_size;
    vq.last_used_idx = 0;

    for i in 0..queue_size as usize {
        (*vq.desc.add(i)).next = (i + 1) as u16;
        vq.desc_used[i] = false;
    }
    (*vq.desc.add(queue_size as usize - 1)).next = 0xFFFF;
}

// ---- virtq_alloc_desc ----

pub unsafe fn virtq_alloc_desc(vq: &mut Virtq) -> Option<usize> {
    if vq.free_count == 0 {
        return None;
    }
    let idx = vq.free_head as usize;
    // Defensive: if the free list ever got corrupted (accounting drift, a
    // stray write), `free_head` could be the 0xFFFF terminator or worse while
    // `free_count` still claims descriptors are free. Indexing would then be
    // an OOB write into `desc.add(idx)` and a panic in `desc_used[idx]`
    // (panic == board reset). Fail the allocation instead.
    if idx >= vq.num as usize {
        return None;
    }
    vq.free_head    = (*vq.desc.add(idx)).next;
    vq.free_count  -= 1;
    vq.desc_used[idx] = true;
    Some(idx)
}

// ---- virtq_free_desc ----

pub unsafe fn virtq_free_desc(vq: &mut Virtq, idx: usize) {
    if idx >= vq.num as usize || !vq.desc_used[idx] {
        return;
    }
    let d = vq.desc.add(idx);
    // Scrub the descriptor, don't just relink it. Two reasons:
    //  * A freed descriptor used to keep its old `flags`, so it still looked
    //    like "has next" while `.next` now pointed into the free list. Any
    //    chain walk that reaches an already-freed descriptor (duplicate
    //    completion from a hostile device) would follow the free list to the
    //    0xFFFF terminator and index far outside the table. With flags
    //    cleared, such a walk terminates at the first freed descriptor.
    //  * Zeroing addr/len means a device that (out of spec) re-reads a stale
    //    descriptor sees a zero-length buffer instead of a live address.
    (*d).addr  = 0;
    (*d).len   = 0;
    (*d).flags = 0;
    (*d).next  = vq.free_head;
    vq.free_head             = idx as u16;
    vq.free_count           += 1;
    vq.desc_used[idx]        = false;
}

// ---- virtq_submit (port of virtq_submit in virtio.c) ----

pub unsafe fn virtq_submit(dev: &VirtioDev, queue_idx: u32, desc_head: usize, vq: &mut Virtq) {
    if virtq_publish(vq, desc_head) {
        virtq_notify_mmio(dev, queue_idx);
    }
}

/// The transport-independent half of [`virtq_submit`]: put `desc_head` on
/// the avail ring and publish the new index, ordered so the device sees
/// the ring entry before the index. The doorbell orders both before itself
/// ([`virtq_notify_mmio`], [`virtq_notify_pci`]).
/// Returns `false` (and publishes nothing) for an uninitialised queue.
/// The virtio-pci net path uses this with its own notify register.
#[inline(always)]
pub unsafe fn virtq_publish(vq: &mut Virtq, desc_head: usize) -> bool {
    // An uninitialized queue would be a division by zero (`% vq.num`) and a
    // null deref below — both panic, and panic == board reset. Submitting
    // nothing is the safer failure mode.
    if vq.num == 0 || vq.avail.is_null() {
        return false;
    }
    let avail_idx = ((*vq.avail).idx as usize) % vq.num as usize;
    (*vq.avail).ring[avail_idx] = desc_head as u16;

    // A non-coherent device reads RAM: the descriptors (written by the
    // caller) and the ring entry go out BEFORE the index that announces them,
    // each in its own write-back; one clean over the whole ring could write
    // the index's line first.
    vq.clean(vq.desc, vq.num as usize * core::mem::size_of::<VirtqDesc>());
    vq.clean(core::ptr::addr_of!((*vq.avail).ring[avail_idx]), 2);

    // Memory before memory: the device reads the ring as another hart would
    // (Linux `virtio_wmb` with weak barriers).
    fence(Ordering::Release);

    (*vq.avail).idx = (*vq.avail).idx.wrapping_add(1);
    vq.clean(core::ptr::addr_of!((*vq.avail).idx), 2);
    true
}

/// Allocate the three rings of a split virtqueue for a transport that is
/// told their addresses by the caller (virtio-pci common cfg), one zeroed
/// page each, and thread the descriptor free list for `queue_size`
/// entries (`1..=VIRTQ_CAPACITY`), mapped through `dma`. Returns the rings'
/// BUS addresses `(desc, avail, used)` — the device's view.
///
/// The MMIO transport does the same inside [`virtq_init`], then gives the
/// rings to the device with [`virtq_reprogram`]; this is the allocation half
/// alone. The bus addresses are kept in [`Virtq::bus`] as well.
pub unsafe fn virtq_alloc_rings(vq: &mut Virtq, queue_size: u16, dma: &Dma) -> Result<(u64, u64, u64), ()> {
    use azos_mm::pmm;
    if queue_size == 0 || queue_size as usize > VIRTQ_CAPACITY {
        return Err(());
    }
    let desc_page  = pmm::alloc_page().map_err(|_| ())?.0;
    let avail_page = pmm::alloc_page().map_err(|_| ())?.0;
    let used_page  = pmm::alloc_page().map_err(|_| ())?.0;
    let desc_va  = dma_page_ptr(desc_page);
    let avail_va = dma_page_ptr(avail_page);
    let used_va  = dma_page_ptr(used_page);
    core::ptr::write_bytes(desc_va  as *mut u8, 0, azos_arch::PAGE_SIZE);
    core::ptr::write_bytes(avail_va as *mut u8, 0, azos_arch::PAGE_SIZE);
    core::ptr::write_bytes(used_va  as *mut u8, 0, azos_arch::PAGE_SIZE);
    vq.desc  = desc_va  as *mut VirtqDesc;
    vq.avail = avail_va as *mut VirtqAvail;
    vq.used  = used_va  as *mut VirtqUsed;
    vq.num   = queue_size;
    vq.nc    = dma.non_coherent();
    init_free_list(vq, queue_size);
    let page = azos_arch::PAGE_SIZE;
    vq.clean(vq.desc, page);
    vq.clean(vq.avail, page);
    vq.refresh(vq.used, page);
    vq.bus = [
        dma.map_phys(desc_page as u64, page, Direction::Bidirectional)?,
        dma.map_phys(avail_page as u64, page, Direction::Bidirectional)?,
        dma.map_phys(used_page as u64, page, Direction::Bidirectional)?,
    ];
    Ok((vq.bus[0], vq.bus[1], vq.bus[2]))
}

/// Re-thread the free list for a smaller size than [`virtq_alloc_rings`]
/// was given — for a device that agreed to fewer entries than requested.
pub unsafe fn virtq_resize(vq: &mut Virtq, queue_size: u16) {
    if queue_size == 0 || queue_size as usize > VIRTQ_CAPACITY || vq.desc.is_null() {
        return;
    }
    vq.num = queue_size;
    init_free_list(vq, queue_size);
    vq.clean(vq.desc, azos_arch::PAGE_SIZE);
}

/// `avail.flags` bit 0 (virtio 1.x §2.7.7): the driver does not want an
/// interrupt when the device consumes a buffer. Advisory — the device may
/// still interrupt — so a driver never relies on its absence.
pub const VIRTQ_AVAIL_F_NO_INTERRUPT: u16 = 1;

/// Write `avail.flags`. Only [`VIRTQ_AVAIL_F_NO_INTERRUPT`] is defined.
#[inline(always)]
pub unsafe fn virtq_set_avail_flags(vq: &mut Virtq, flags: u16) {
    if vq.avail.is_null() {
        return;
    }
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*vq.avail).flags), flags);
    vq.clean(core::ptr::addr_of!((*vq.avail).flags), 2);
}

/// `used.flags` bit 0 (virtio 1.x 2.7.10; `VRING_USED_F_NO_NOTIFY` on the
/// legacy transport, same bit, same meaning): the device does not need a
/// doorbell for buffers added now — it is already processing the queue
/// and will look at `avail.idx` again before it stops.
pub const VIRTQ_USED_F_NO_NOTIFY: u16 = 1;

/// After publishing new avail entries: does the device want a doorbell?
/// `false` while it reports [`VIRTQ_USED_F_NO_NOTIFY`]. Advisory in the
/// other direction only — a doorbell the device did not need is harmless —
/// so a stale read can cost a redundant doorbell but never a lost one,
/// PROVIDED the read is ordered after the `avail.idx` store: the device
/// clears the flag and then re-reads `avail.idx` (QEMU's
/// `virtio_queue_set_notification` + re-check), so a driver that sees the
/// flag still set after its index store is visible has published an
/// index the device's re-read will see. Hence the full fence: store ->
/// load ordering, which the Release fence of [`virtq_publish`] does not
/// give (virtio 1.x 2.7.13.3, "a memory barrier before reading flags").
///
/// Not EVENT_IDX: no driver here negotiates it, so `avail_event` is never
/// written by the device and is not read.
#[inline(always)]
pub unsafe fn virtq_device_wants_kick(vq: &Virtq) -> bool {
    if vq.used.is_null() {
        return false;
    }
    fence(Ordering::SeqCst);
    vq.refresh(core::ptr::addr_of!((*vq.used).flags), 2);
    core::ptr::read_volatile(core::ptr::addr_of!((*vq.used).flags)) & VIRTQ_USED_F_NO_NOTIFY == 0
}

/// VIRTIO_F_EVENT_IDX (feature bit 29, word 0): the driver and the device
/// each publish the ring index at which they want to be told next, in place
/// of the NO_INTERRUPT / NO_NOTIFY flags.
pub const VIRTIO_F_EVENT_IDX: u32 = 1 << 29;

/// The EVENT_IDX test (virtio 1.x 2.7.7.2, Linux `vring_need_event`): with
/// the index moving `old -> new`, did it pass `event`? Wrapping u16 maths.
#[inline(always)]
pub const fn vring_need_event(event: u16, new: u16, old: u16) -> bool {
    new.wrapping_sub(event).wrapping_sub(1) < new.wrapping_sub(old)
}

/// `used_event`: the driver area's word after `ring[num]`.
#[inline(always)]
unsafe fn used_event_ptr(vq: &Virtq) -> *mut u16 {
    (vq.avail as *mut u8).add(4 + 2 * vq.num as usize) as *mut u16
}

/// `avail_event`: the device area's word after `ring[num]`.
#[inline(always)]
unsafe fn avail_event_ptr(vq: &Virtq) -> *const u16 {
    (vq.used as *const u8).add(4 + 8 * vq.num as usize) as *const u16
}

/// After publishing new avail entries: ring the doorbell? Without
/// EVENT_IDX, [`virtq_device_wants_kick`]. With it, only if `avail.idx`
/// moved past the device's `avail_event` since the last decision. Same
/// store -> load ordering requirement, same full fence.
#[inline(always)]
pub unsafe fn virtq_kick_decision(vq: &mut Virtq) -> bool {
    if !vq.event_idx || vq.used.is_null() || vq.num == 0 {
        return virtq_device_wants_kick(vq);
    }
    fence(Ordering::SeqCst);
    let new = core::ptr::read_volatile(core::ptr::addr_of!((*vq.avail).idx));
    let old = vq.kick_idx;
    vq.kick_idx = new;
    vq.refresh(avail_event_ptr(vq), 2);
    vring_need_event(core::ptr::read_volatile(avail_event_ptr(vq)), new, old)
}

/// Ask for an interrupt on the next used entry (`on`), or for none. With
/// EVENT_IDX the device ignores `avail.flags`: `used_event` = the next
/// entry we will consume arms it; half the index space ahead disarms it
/// (the device's test cannot pass until 32,768 more completions).
/// Without it, `avail.flags` NO_INTERRUPT. Either way a hint: the caller
/// re-checks the ring after arming.
#[inline(always)]
pub unsafe fn virtq_set_interrupts(vq: &mut Virtq, on: bool) {
    if vq.avail.is_null() {
        return;
    }
    if vq.event_idx && vq.num != 0 {
        let ev = if on { vq.last_used_idx } else { vq.last_used_idx.wrapping_add(0x8000) };
        core::ptr::write_volatile(used_event_ptr(vq), ev);
        vq.clean(used_event_ptr(vq), 2);
    } else {
        virtq_set_avail_flags(vq, if on { 0 } else { VIRTQ_AVAIL_F_NO_INTERRUPT });
    }
}

/// The virtio-mmio doorbell alone: tell the device `queue_idx` has new
/// avail entries. [`virtq_submit`] is publish + this. The ring writes are
/// ordered before the register write (`io_wmb`: a memory write before a
/// device write, which [`virtq_publish`]'s fence does not promise).
#[inline(always)]
pub unsafe fn virtq_notify_mmio(dev: &VirtioDev, queue_idx: u32) {
    azos_dma::order::io_wmb();
    mmio_write(dev.base, VIRTIO_MMIO_QUEUE_NOTIFY, queue_idx);
}

/// The virtio-pci doorbell: the queue index, 16 bits, into the queue's notify
/// register at `notify` (virtio 1.x 4.1.5.2), ordered after the ring writes
/// as [`virtq_notify_mmio`] is.
#[inline(always)]
pub unsafe fn virtq_notify_pci(notify: usize, queue: u16) {
    azos_dma::order::io_wmb();
    core::ptr::write_volatile(notify as *mut u16, queue);
}

/// Has the device written a used entry this driver has not consumed yet?
/// Volatile read of `used.idx` — the same load [`virtq_poll_with_len`]
/// starts with, without consuming anything.
#[inline(always)]
pub unsafe fn virtq_has_used(vq: &Virtq) -> bool {
    if vq.num == 0 || vq.used.is_null() {
        return false;
    }
    vq.refresh(core::ptr::addr_of!((*vq.used).idx), 2);
    core::ptr::read_volatile(core::ptr::addr_of!((*vq.used).idx)) != vq.last_used_idx
}

// ---- virtq_poll (port of virtq_poll in virtio.c) ----

/// Returns Some(desc_head) if a request completed, None if queue is empty.
///
/// NOTE: this drops the `len` field from the used-ring entry — for net RX
/// that means callers don't know the actual received packet length. Prefer
/// `virtq_poll_with_len()` for RX paths where the device writes a variable
/// amount into the descriptor's buffer.
pub unsafe fn virtq_poll(vq: &mut Virtq) -> Option<usize> {
    virtq_poll_with_len(vq).map(|(id, _)| id)
}

/// Like `virtq_poll`, but also returns the device-reported length written
/// into the buffer. Required for RX paths (Ethernet, block reads) where the
/// payload is shorter than the buffer; without it the consumer reads past
/// the real data into stale buffer contents.
///
/// Both `id` and `len` come from the device — a buggy or malicious device
/// can write any value. We bounds-check both before returning so callers
/// can trust them as array indices / slice lengths without further checks.
pub unsafe fn virtq_poll_with_len(vq: &mut Virtq) -> Option<(usize, usize)> {
    // An uninitialized queue would be a null deref and a division by zero
    // (`% vq.num`) — both panic, and panic == board reset. Report "empty".
    if vq.num == 0 || vq.used.is_null() {
        return None;
    }

    // The used ring is written by the device (DMA), so read the index
    // volatile: callers busy-wait on this function, and a plain load of
    // device-written memory is exactly what the optimizer is allowed to
    // treat as loop-invariant.
    vq.refresh(core::ptr::addr_of!((*vq.used).idx), 2);
    let used_idx_now = core::ptr::read_volatile(core::ptr::addr_of!((*vq.used).idx));
    if vq.last_used_idx == used_idx_now {
        return None;
    }

    // fence r,r AFTER observing the new index and BEFORE reading the ring
    // entry (and before the caller reads any DMA'd payload/status). RISC-V
    // may satisfy the later loads early; without this fence the entry — or
    // the buffer contents the caller inspects next — can be stale even
    // though `idx` was seen to advance.
    fence(Ordering::Acquire);

    let used_idx = (vq.last_used_idx as usize) % vq.num as usize;
    let elem = core::ptr::addr_of!((*vq.used).ring[used_idx]);
    vq.refresh(elem, core::mem::size_of::<VirtqUsedElem>());
    let id  = core::ptr::read_volatile(core::ptr::addr_of!((*elem).id))  as usize;
    let len = core::ptr::read_volatile(core::ptr::addr_of!((*elem).len)) as usize;
    vq.last_used_idx = vq.last_used_idx.wrapping_add(1);

    // Defensive bounds: a malicious / malfunctioning device could write
    // an `id` outside the descriptor table. Indexing without this check
    // is OOB read in `vq.desc.add(id)` calls higher up the stack.
    //
    // The entry was already consumed above (`last_used_idx` advanced) — on
    // purpose: NOT consuming it would re-read the same corrupt entry forever
    // and wedge the queue. The cost is that the caller cannot tell this
    // `None` from "ring empty", so the associated buffer/descriptor cannot be
    // recovered (for RX that is a permanently lost buffer). `bad_completions`
    // records the fault so drivers and health checks can see the device is
    // misbehaving instead of the loss being fully silent.
    let qsize = vq.num as usize;
    if id >= qsize {
        vq.bad_completions = vq.bad_completions.saturating_add(1);
        return None;
    }
    // `len` larger than the descriptor's buffer length should also be
    // impossible per virtio spec, but we let the caller cap it against
    // its own buffer size so we don't have to re-derive that here.

    Some((id, len))
}

// ---- virtio_read_config32 / 64 ----

pub unsafe fn read_config32(dev: &VirtioDev, offset: u32) -> u32 {
    mmio_read(dev.base, VIRTIO_MMIO_CONFIG + offset)
}

pub unsafe fn read_config64(dev: &VirtioDev, offset: u32) -> u64 {
    let low  = mmio_read(dev.base, VIRTIO_MMIO_CONFIG + offset) as u64;
    let high = mmio_read(dev.base, VIRTIO_MMIO_CONFIG + offset + 4) as u64;
    (high << 32) | low
}
