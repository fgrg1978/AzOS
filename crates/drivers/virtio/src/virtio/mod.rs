// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO MMIO driver — common structures and queue management.
//!
//! Direct port of kernel/drivers/virtio.c + kernel/include/virtio.h.
//! Supports both legacy (v1) and modern (v2) MMIO transport.

pub mod blk;
pub mod net;
#[cfg(feature = "pci")]
pub mod pci;
pub mod rng;

use core::sync::atomic::{fence, Ordering};

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

/// The address a DEVICE must be given for a buffer the CPU knows by pointer.
///
/// A device performs DMA with PHYSICAL addresses; the CPU reaches the same
/// bytes through whatever virtual address its own page table uses. Those
/// were the same number while the kernel was identity-mapped, and stopped
/// being the same the moment the aarch64 kernel moved into the upper half —
/// handing a device a kernel VA there means it reads or writes whatever
/// physical page that number happens to name. `virt_to_phys` is identity on
/// riscv64, so this changes nothing there.
#[inline]
pub fn dma_addr_of<T: ?Sized>(ptr: *const T) -> u64 {
    azos_mm::addr::virt_to_phys(ptr as *const u8 as usize) as u64
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
    let _features = mmio_read(dev.base, VIRTIO_MMIO_DEVICE_FEATURES);
    mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES, 0);

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

    Ok(())
}

// ---- virtq_init (port of virtq_init in virtio.c) ----

/// Initialize a virtqueue of [`VIRTIO_QUEUE_SIZE`] entries (or fewer, if
/// the device offers fewer). Handles both legacy (v1) and modern (v2).
pub unsafe fn virtq_init(dev: &mut VirtioDev, queue_idx: u32, vq: &mut Virtq) -> Result<(), ()> {
    virtq_init_sized(dev, queue_idx, vq, VIRTIO_QUEUE_SIZE)
}

/// [`virtq_init`] for a queue of `want` entries (a power of two, at most
/// [`VIRTQ_CAPACITY`]); the device may grant fewer (`QUEUE_NUM_MAX`).
pub unsafe fn virtq_init_sized(dev: &mut VirtioDev, queue_idx: u32, vq: &mut Virtq, want: usize) -> Result<(), ()> {
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

    if dev.version == 1 {
        // Legacy mode: contiguous memory block
        // Layout: [desc_table | avail_ring | padding_to_page | used_ring]
        // For 16 entries: total ~4230 bytes = 2 pages; for 256, 3 pages.
        let desc_size  = 16 * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize;
        let page_sz    = azos_arch::PAGE_SIZE;
        let used_offset = ((desc_size + avail_size + page_sz - 1) / page_sz) * page_sz;
        let used_size  = 6 + 8 * queue_size as usize;
        let total_size = used_offset + used_size;
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
        // mapping; the device is told the PHYSICAL frame number below. Those
        // were the same number until the aarch64 kernel moved to the upper
        // half.
        let queue_mem = dma_page_ptr(first_page) as *mut u8;

        vq.desc  = queue_mem as *mut VirtqDesc;
        vq.avail = queue_mem.add(desc_size) as *mut VirtqAvail;
        vq.used  = queue_mem.add(used_offset) as *mut VirtqUsed;

        init_free_list(vq, queue_size);

        // Tell device: queue num, alignment, PFN
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_NUM,   queue_size as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_ALIGN,  page_sz as u32);
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_PFN,   (first_page / page_sz) as u32);
    } else {
        // Modern mode: separate pages for desc, avail, used
        let desc_page  = pmm::alloc_page().map_err(|_| ())?.0;
        let avail_page = pmm::alloc_page().map_err(|_| ())?.0;
        let used_page  = pmm::alloc_page().map_err(|_| ())?.0;
        // PAs from the allocator: the CPU needs its own view of them.
        let desc_va  = dma_page_ptr(desc_page);
        let avail_va = dma_page_ptr(avail_page);
        let used_va  = dma_page_ptr(used_page);

        core::ptr::write_bytes(desc_va  as *mut u8, 0, azos_arch::PAGE_SIZE);
        core::ptr::write_bytes(avail_va as *mut u8, 0, azos_arch::PAGE_SIZE);
        core::ptr::write_bytes(used_va  as *mut u8, 0, azos_arch::PAGE_SIZE);

        vq.desc  = desc_va  as *mut VirtqDesc;
        vq.avail = avail_va as *mut VirtqAvail;
        vq.used  = used_va  as *mut VirtqUsed;

        init_free_list(vq, queue_size);

        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_NUM, queue_size as u32);

        let desc_addr  = desc_page  as u64;   // PHYSICAL: the device's view
        let avail_addr = avail_page as u64;   // PHYSICAL
        let used_addr  = used_page  as u64;   // PHYSICAL

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
        mmio_write(dev.base, VIRTIO_MMIO_QUEUE_NOTIFY, queue_idx);
    }
}

/// The transport-independent half of [`virtq_submit`]: put `desc_head` on
/// the avail ring and publish the new index, ordered so the device sees
/// the ring entry before the index and both before the caller's notify.
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

    fence(Ordering::Release); // fence w,w before updating idx

    (*vq.avail).idx = (*vq.avail).idx.wrapping_add(1);

    fence(Ordering::Release); // fence w,w before notify
    true
}

/// Allocate the three rings of a split virtqueue for a transport that is
/// told their addresses by the caller (virtio-pci common cfg), one zeroed
/// page each, and thread the descriptor free list for `queue_size`
/// entries (`1..=VIRTQ_CAPACITY`). Returns the rings' PHYSICAL
/// addresses `(desc, avail, used)` — the device's view.
///
/// The MMIO transport does the same inside [`virtq_init`], interleaved
/// with its register writes; this is the allocation half alone.
pub unsafe fn virtq_alloc_rings(vq: &mut Virtq, queue_size: u16) -> Result<(u64, u64, u64), ()> {
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
    init_free_list(vq, queue_size);
    Ok((desc_page as u64, avail_page as u64, used_page as u64))
}

/// Re-thread the free list for a smaller size than [`virtq_alloc_rings`]
/// was given — for a device that agreed to fewer entries than requested.
pub unsafe fn virtq_resize(vq: &mut Virtq, queue_size: u16) {
    if queue_size == 0 || queue_size as usize > VIRTQ_CAPACITY || vq.desc.is_null() {
        return;
    }
    vq.num = queue_size;
    init_free_list(vq, queue_size);
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
/// load ordering, which the Release fences of [`virtq_publish`] do not
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
    core::ptr::read_volatile(core::ptr::addr_of!((*vq.used).flags)) & VIRTQ_USED_F_NO_NOTIFY == 0
}

/// The virtio-mmio doorbell alone: tell the device `queue_idx` has new
/// avail entries. [`virtq_submit`] is publish + this.
#[inline(always)]
pub unsafe fn virtq_notify_mmio(dev: &VirtioDev, queue_idx: u32) {
    mmio_write(dev.base, VIRTIO_MMIO_QUEUE_NOTIFY, queue_idx);
}

/// Has the device written a used entry this driver has not consumed yet?
/// Volatile read of `used.idx` — the same load [`virtq_poll_with_len`]
/// starts with, without consuming anything.
#[inline(always)]
pub unsafe fn virtq_has_used(vq: &Virtq) -> bool {
    if vq.num == 0 || vq.used.is_null() {
        return false;
    }
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
