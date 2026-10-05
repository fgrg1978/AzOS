// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO Block Device Driver.
//!
//! Direct port of kernel/drivers/virtio_blk.c + kernel/include/virtio_blk.h.
//! Scans MMIO addresses for a block device, initializes it, and provides
//! sector-level read/write via the VirtIO request protocol.

use super::{
    VirtioDev, Virtq,
    VIRTIO_DEV_BLOCK, VIRTIO_STATUS_DRIVER_OK, VIRTIO_MMIO_STATUS,
    VIRTIO_STATUS_ACK, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_FEATURES_OK,
    VIRTIO_STATUS_FAILED, VIRTIO_MMIO_GUEST_PAGE_SIZE,
    VIRTIO_MMIO_DEVICE_FEATURES, VIRTIO_MMIO_DEVICE_FEATURES_SEL,
    VIRTIO_MMIO_DRIVER_FEATURES, VIRTIO_MMIO_DRIVER_FEATURES_SEL,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use super::{mmio_read, mmio_write, probe, virtq_init,
            virtq_alloc_desc, virtq_free_desc, virtq_submit, virtq_poll,
            read_config64};
use azos_drv_api::block::FlushError;
use azos_drv_sys::kprintln;
use azos_sync::pi_mutex::PiMutex;

// ---- Constants (from virtio_blk.h) ----

// Sourced from `super` (`virtio::mod`'s `VIRTIO_MMIO_*`, ISA-selected there)
// instead of a local literal — was `0x1000_1000` / `0x1000` / `8` here only,
// now the same definition `net.rs`/`rng.rs` use.
use super::VIRTIO_MMIO_BASE;
use super::VIRTIO_MMIO_STRIDE as VIRTIO_MMIO_STEP;
use super::VIRTIO_MMIO_COUNT;

pub const SECTOR_SIZE: usize = 512;

// Request types (virtio 1.2 section 5.2.6)
const BLK_T_IN:    u32 = 0; // read from device
const BLK_T_OUT:   u32 = 1; // write to device
const BLK_T_FLUSH: u32 = 4; // commit the device's volatile write cache

// Status codes
const BLK_S_OK:     u8 = 0;
const BLK_S_UNSUPP: u8 = 2;

// Device feature bits, feature word 0 (virtio 1.2 section 5.2.3).
const VIRTIO_BLK_F_RO:    u32 = 1 << 5;
const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

// ---- Request structures (repr(C, packed) to match device ABI) ----

#[repr(C, packed)]
struct BlkReqHdr {
    req_type: u32,
    reserved: u32,
    sector:   u64,
}

// ---- Global device state ----

struct BlkDev {
    vdev:     VirtioDev,
    vq:       Virtq,
    capacity: u64,   // sectors
    readonly: bool,
    flush:    bool,  // VIRTIO_BLK_F_FLUSH negotiated: T_FLUSH may be sent
    ready:    bool,  // init() completed; queue is usable
    failed:   bool,  // latched dead after a timeout — never cleared
}

static mut BLK_DEV: BlkDev = BlkDev {
    vdev:     VirtioDev::zeroed(),
    vq:       Virtq::zeroed(),
    capacity: 0,
    readonly: false,
    flush:    false,
    ready:    false,
    failed:   false,
};

/// Serializes every path that touches `BLK_DEV`, the virtqueue, or the DMA
/// staging statics below. The driver is a strictly one-request-at-a-time
/// protocol over shared `static mut` state; without this lock two harts
/// calling `read`/`write` concurrently interleave stagings into the single
/// `BLK_DMA_BUF`, corrupt the free-descriptor accounting, and race the
/// header/status statics mid-DMA. (The syscall layer serializes per-CPU
/// only, which is not enough on SMP.)
///
/// Held across the whole multi-chunk transfer, including the bounded
/// busy-wait for completion — the same discipline as the C kernel, just made
/// explicit.
/// **A `PiMutex`, not a `SpinLock`, and that is now a correctness requirement
/// rather than a preference.**
///
/// This lock is held across a whole transfer, including a poll whose deadline
/// is 500 ms. That budget is deliberate -- it exists to bound a DEAD device,
/// not to police a slow one -- but it means the critical section is
/// unbounded in the only sense that matters here.
///
/// As of K-C29 step 2 every `SpinLock` section is non-preemptible on its hart.
/// Under a `SpinLock` this section would therefore have made real-time dispatch
/// latency on whichever hart runs block I/O up to half a second: longer than
/// the watchdog, and five hundred times the 1 kHz control period. The fix for a
/// priority-inversion class would have created a far worse latency bomb than the
/// inversion it removed.
///
/// `PiMutexGuard` deliberately takes no preempt count, so the holder stays
/// preemptible for the whole transfer; a waiter yields rather than spinning, so
/// it does not burn a hart either, and priority inheritance keeps a low-priority
/// holder from being starved by the task waiting on it.
///
/// Safe at boot despite yielding: `init()` is the only caller that runs before
/// the scheduler exists, it is single-threaded and uncontended, and `PiMutex`'s
/// fast path is a plain CAS that never reaches the yielding branch.
static BLK_LOCK: PiMutex<()> = PiMutex::new(());

// ---- DMA staging area ----
//
// The device is NEVER handed a pointer into caller memory. A VirtIO request
// cannot be cancelled or recalled: once the chain is in the avail ring the
// device owns those buffers until it posts a used-ring entry, and if we give
// up waiting (see the timeout path in `blk_rw`) it may still DMA into them
// arbitrarily later. A caller buffer is very often a stack frame that has been
// popped and reused by then, so a late write would silently corrupt unrelated
// state far from the call site.
//
// Every buffer in a request therefore lives in driver-owned `static` storage
// whose lifetime is the lifetime of the kernel. Transfers larger than the
// staging area are split into chunks by the public `read`/`write` wrappers.
//
// Re-verified 2026-09-06 (claims_check audit): every descriptor `.addr` set
// in this file points at a driver-owned static — `BLK_REQ_HDR`, `BLK_DMA_BUF`
// or `BLK_STATUS` — never at a caller-supplied pointer (grep `\.addr` in this
// file: five sites, three in `blk_rw` and two in `blk_flush`, none derived
// from `buf`/`dst`/`src`). The caller's `buf`
// only ever meets `copy_nonoverlapping`, never a descriptor: `write()` stages
// caller bytes into `BLK_DMA_BUF` *before* `blk_rw` submits the chain, and
// `read()` copies `BLK_DMA_BUF` out to the caller *after* `blk_rw` has
// returned (i.e. after the device posted its used-ring entry) — the
// caller's own memory is never in the descriptor, before or during DMA.
// Re-check the grep if a new descriptor-setup site is added anywhere in
// this driver.
const BLK_DMA_SECTORS: usize = 8;
const BLK_DMA_BYTES:   usize = BLK_DMA_SECTORS * SECTOR_SIZE; // 4 KiB

#[repr(C, align(512))]
struct DmaBuf([u8; BLK_DMA_BYTES]);

// Static request buffers (aligned, single-request protocol like the C kernel)
static mut BLK_REQ_HDR: BlkReqHdr = BlkReqHdr { req_type: 0, reserved: 0, sector: 0 };
static mut BLK_STATUS:  u8         = 0xFF;
static mut BLK_DMA_BUF: DmaBuf     = DmaBuf([0u8; BLK_DMA_BYTES]);

// ---- Feature negotiation ----

/// The device-status handshake for this device: reset, ACK, DRIVER, feature
/// negotiation, FEATURES_OK. Same steps and order as `super::init`, which
/// the other virtio drivers use; the only difference is feature word 0.
/// `super::init` acknowledges no word-0 feature, and for this device that
/// matters: without `VIRTIO_BLK_F_FLUSH` the driver may not send
/// `VIRTIO_BLK_T_FLUSH` (virtio 1.2 section 5.2.6.2), so nothing the kernel
/// does could make a write durable on a device with a volatile cache.
///
/// Accepted from word 0: `VIRTIO_BLK_F_FLUSH` (so `flush()` can be issued)
/// and `VIRTIO_BLK_F_RO` (so a read-only medium is refused on the write path
/// instead of failing per request). Word 1: `VIRTIO_F_VERSION_1` on a v2
/// transport, exactly as `super::init` does.
///
/// Observed on QEMU 11.0 (blklogwrites log of a boot): while FLUSH is NOT
/// negotiated QEMU runs its cache writethrough and follows every write with
/// a host flush; once it IS negotiated the cache is writeback and only the
/// driver's `T_FLUSH` requests reach the backing file. So negotiating FLUSH
/// makes every path that does not call `flush()` less durable on QEMU than
/// it was before; the callers that claim durability call it.
///
/// Returns `(offered, accepted)` feature word 0.
unsafe fn negotiate(dev: &mut VirtioDev) -> Result<(u32, u32), ()> {
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, 0);
    if dev.version == 1 {
        mmio_write(dev.base, VIRTIO_MMIO_GUEST_PAGE_SIZE,
                   azos_arch::mmu::PAGE_SIZE as u32);
    }
    let s = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_ACK);
    let s = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER);

    mmio_write(dev.base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
    let offered = mmio_read(dev.base, VIRTIO_MMIO_DEVICE_FEATURES);
    let accepted = offered & (VIRTIO_BLK_F_FLUSH | VIRTIO_BLK_F_RO);
    mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
    mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES, accepted);

    if dev.version != 1 {
        const VIRTIO_F_VERSION_1_BIT0: u32 = 1 << 0; // bit 32 overall
        mmio_write(dev.base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1);
        let hi = mmio_read(dev.base, VIRTIO_MMIO_DEVICE_FEATURES);
        mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1);
        mmio_write(dev.base, VIRTIO_MMIO_DRIVER_FEATURES, hi & VIRTIO_F_VERSION_1_BIT0);
    }

    let s = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
    mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_FEATURES_OK);
    if mmio_read(dev.base, VIRTIO_MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK == 0 {
        mmio_write(dev.base, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_FAILED);
        return Err(());
    }
    Ok((offered, accepted))
}

// ---- virtio_blk_init (port of virtio_blk_init in virtio_blk.c) ----

/// Initialize the VirtIO block device.
/// Scans MMIO slots 0x10001000–0x10008000 for a block device.
pub fn init() -> Result<(), ()> {
    let _guard = BLK_LOCK.lock();

    let dev = unsafe { &mut *(&raw mut BLK_DEV) };

    // After a timeout the driver is latched dead: the device misbehaved once
    // and three descriptors are quarantined. Re-running init() would re-arm
    // that same device (DRIVER_OK) while `failed` still blocks all I/O —
    // an inconsistent half-alive state. Refuse instead.
    if dev.failed {
        azos_drv_sys::kerr!("[VIRTIO-BLK] init refused: driver latched dead after timeout");
        return Err(());
    }
    // Idempotent: a second init would leak the ring pages (the PMM cannot
    // reclaim them) and reset a live device mid-flight.
    if dev.ready {
        return Ok(());
    }

    kprintln!("[VIRTIO-BLK] Scanning for block devices...");

    let mut found = false;

    for i in 0..VIRTIO_MMIO_COUNT {
        let addr = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STEP;
        unsafe {
            if probe(addr, &mut dev.vdev).is_ok() && dev.vdev.device_id == VIRTIO_DEV_BLOCK {
                kprintln!("[VIRTIO-BLK] Found block device at {:#x}", addr);
                found = true;
                break;
            }
        }
    }

    if !found {
        kprintln!("[VIRTIO-BLK] No block device found");
        return Err(());
    }

    unsafe {
        // Initialize device (feature negotiation, status handshake)
        let (offered, accepted) = negotiate(&mut dev.vdev).map_err(|_| {
            azos_drv_sys::kerr!("[VIRTIO-BLK] Failed to initialize VirtIO device");
        })?;

        // Read capacity from device config (offset 0 = uint64 capacity in sectors)
        dev.capacity = read_config64(&dev.vdev, 0);
        dev.readonly = accepted & VIRTIO_BLK_F_RO != 0;
        dev.flush    = accepted & VIRTIO_BLK_F_FLUSH != 0;
        // Two distinct lines so a log tells "the device offered no flush"
        // (nothing the driver can do) from "the driver did not take it".
        if dev.flush {
            kprintln!("[VIRTIO-BLK] flush: negotiated (write cache is volatile until T_FLUSH)");
        } else if offered & VIRTIO_BLK_F_FLUSH == 0 {
            kprintln!("[VIRTIO-BLK] flush: not offered by the device; flush() reports Unsupported");
        }
        if dev.readonly {
            kprintln!("[VIRTIO-BLK] device is read-only (VIRTIO_BLK_F_RO)");
        }

        // `capacity` is device-supplied and untrusted: a bogus value near
        // u64::MAX would overflow the byte conversion, and overflow-checks are
        // on in release (panic == board reset). Saturate instead.
        kprintln!("[VIRTIO-BLK] Disk: {} sectors ({} MB)",
            dev.capacity,
            dev.capacity.saturating_mul(SECTOR_SIZE as u64) / (1024 * 1024));

        // Initialize the request queue (queue 0)
        virtq_init(&mut dev.vdev, 0, &mut dev.vq).map_err(|_| {
            azos_drv_sys::kerr!("[VIRTIO-BLK] Failed to initialize queue");
        })?;

        // Mark device as DRIVER_OK
        let s = mmio_read(dev.vdev.base, VIRTIO_MMIO_STATUS);
        mmio_write(dev.vdev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK);

        dev.ready = true;
    }

    kprintln!("[VIRTIO-BLK] Block device ready");
    Ok(())
}

// ---- virtio_blk_rw (port of virtio_blk_rw in virtio_blk.c) ----

// **A wall-clock budget, not a spin count.**
//
// This used to be `let mut timeout = 1_000_000i32;` decremented once per
// poll. A spin count is not a deadline: how much real time it buys depends
// on core frequency, on how often the timer preempts this hart, and on
// whatever else the emulator or the SoC is doing. The same million
// iterations is a different amount of patience on QEMU, on the VF2 and on
// the K1 — which is exactly the kind of budget that works on the desk and
// fails on the board.
//
// It already failed here: measured **1 boot in 10** aborting with
// "request timeout" while the device was merely slow, and because the
// failure path disables block I/O for the rest of the boot, CONFIG.INI
// then could not be read and the autorun task was never created. The robot
// boots without its program — from a transient.
//
// 500 ms is deliberately generous. A virtio-blk request should complete in
// microseconds here and in low milliseconds on real storage; the budget
// exists to bound a *dead* device, not to police a slow one. Being late is
// survivable, being wrong is not.
const BLK_TIMEOUT_US: u64 = 500_000;

/// Budget for a `T_FLUSH`. A flush writes out the device's whole volatile
/// cache, so its completion time scales with how much is dirty rather than
/// with one request, and on real storage it is the slowest request there
/// is. Timing out latches the driver dead for the rest of the boot (see
/// [`latch_dead`]), so the budget stays a bound on a DEAD device: four times
/// the per-request one.
const BLK_FLUSH_TIMEOUT_US: u64 = 4 * BLK_TIMEOUT_US;

/// Put the chain headed by `head` in the avail ring and wait, bounded by
/// `timeout_us` of wall-clock time, for the device to post that chain's
/// used-ring entry. `Err` carries the reason; the caller must then call
/// [`latch_dead`] and must not free the chain's descriptors.
///
/// Caller must hold `BLK_LOCK`.
#[inline(always)]
unsafe fn submit_and_wait(vdev: &VirtioDev, vq: &mut Virtq, head: usize, timeout_us: u64)
    -> Result<(), &'static str>
{
    virtq_submit(vdev, 0, head, vq);
    let deadline = azos_drv_sys::timebase::now()
        + timeout_us * azos_drv_irqchip::clint::TIMER_FREQ / 1_000_000;
    loop {
        match virtq_poll(vq) {
            // Only the completion for OUR chain counts. The device reports
            // which chain completed via the used-ring `id`; a value other
            // than `head` is a completion we never submitted. Accepting it
            // would report success on a request whose DMA has not happened
            // (and whose buffers the device may still write later), so it is
            // treated exactly like a timeout.
            Some(id) if id == head => return Ok(()),
            Some(_) => return Err("foreign completion id"),
            None => {
                if azos_drv_sys::timebase::now() >= deadline {
                    return Err("request timeout");
                }
            }
        }
    }
}

/// Reset the device and latch the driver dead after a request failed to
/// complete (or a completion arrived that was never submitted).
///
/// The request is still owned by the device. VirtIO has no cancel:
/// the chain stays in the ring and the device may post it — and DMA
/// into the header, the staging buffer and the status byte — at any
/// point in the future. Three properties make that late write inert,
/// and all three are enforced rather than assumed:
///
/// 1. Every buffer in the chain is driver-owned `static` storage
///    (BLK_REQ_HDR / BLK_DMA_BUF / BLK_STATUS), never caller memory.
///    A late DMA cannot reach a popped stack frame.
/// 2. The descriptors are deliberately NOT returned to the free
///    list. Recycling them would let the stale completion land on a
///    live chain, and would leave `last_used_idx` desynchronised so
///    the next request would mistake the stale used-ring entry for
///    its own and report success on an untouched buffer. They stay
///    quarantined for the lifetime of the kernel.
/// 3. The device is reset and the driver latched dead, so nothing
///    ever submits again or reads those statics again.
///
/// Reset first (stops the device touching guest memory per spec),
/// then latch. The cost is that one timeout disables block I/O
/// until reboot: recovering the queue would mean re-running init()
/// and re-allocating the ring pages, which the PMM cannot reclaim,
/// and re-arming a device that has already misbehaved. On a
/// safety-critical target, no disk beats silently wrong disk.
unsafe fn latch_dead(dev: &mut BlkDev, reason: &str) {
    mmio_write(dev.vdev.base, VIRTIO_MMIO_STATUS, 0);
    dev.failed = true;
    dev.ready  = false;
    azos_drv_sys::kerr!("[VIRTIO-BLK] Error: {} - device reset, block I/O disabled", reason);
}

/// Internal read/write of one chunk — submits a 3-descriptor chain
/// (header | data | status). The data descriptor always points at the
/// driver-owned staging buffer `BLK_DMA_BUF`, never at caller memory;
/// `read`/`write` copy in and out around this call.
///
/// `count` must be in `1..=BLK_DMA_SECTORS`; anything else is rejected.
///
/// Caller must hold `BLK_LOCK`.
unsafe fn blk_rw(sector: u64, count: u32, write: bool) -> Result<(), ()> {
    let dev = unsafe { &mut *(&raw mut BLK_DEV) };

    // A previous request timed out: the device was reset and may still have
    // been mid-DMA into the statics above. Submitting anything else would
    // reuse buffers the device might still be writing, so the driver stays
    // dead until reboot. See the timeout path below.
    if dev.failed || !dev.ready { return Err(()); }

    let vq = &mut dev.vq;

    // Queue must be live: a null table would be a null deref below, and
    // `virtq_submit` divides by `vq.num`.
    if vq.desc.is_null() || vq.num == 0 { return Err(()); }

    if count == 0 || count as usize > BLK_DMA_SECTORS { return Err(()); }

    // `sector + count` can overflow with a hostile LBA; overflow-checks are on
    // in release, so a plain add is a panic (== board reset). Check it.
    let end = sector.checked_add(count as u64).ok_or(())?;
    if end > dev.capacity {
        azos_drv_sys::kerr!("[VIRTIO-BLK] Error: sector out of range");
        return Err(());
    }
    if write && dev.readonly {
        azos_drv_sys::kerr!("[VIRTIO-BLK] Error: disk is read-only");
        return Err(());
    }

    // The driver is idle here (strictly one request at a time, BLK_LOCK held
    // by our caller), so the used ring must be empty. An entry now can only
    // be a duplicate or forged completion — a device not following the
    // protocol. Left in the ring, it would make the NEXT request appear
    // complete the instant it was submitted, before any DMA happened, and
    // the caller would consume stale staging-buffer contents as disk data.
    // Same remedy as a timeout: reset, latch dead. (No descriptors are
    // allocated yet, so there is nothing to quarantine.)
    if virtq_poll(vq).is_some() {
        latch_dead(dev, "spurious completion while idle");
        return Err(());
    }

    // Prepare request header
    BLK_REQ_HDR.req_type = if write { BLK_T_OUT } else { BLK_T_IN };
    BLK_REQ_HDR.reserved = 0;
    BLK_REQ_HDR.sector   = sector;
    BLK_STATUS           = 0xFF;

    // Allocate 3 descriptors: [header] → [data] → [status]
    let d_hdr    = virtq_alloc_desc(vq).ok_or(())?;
    let d_data   = virtq_alloc_desc(vq).ok_or_else(|| { virtq_free_desc(vq, d_hdr); })?;
    let d_status = virtq_alloc_desc(vq).ok_or_else(|| {
        virtq_free_desc(vq, d_hdr);
        virtq_free_desc(vq, d_data);
    })?;

    // count <= BLK_DMA_SECTORS was checked above, so this cannot overflow and
    // cannot exceed BLK_DMA_BYTES — the staging buffer is always large enough.
    // Re-verified 2026-09-06 (claims_check audit): "checked above" means
    // line 235 in *this* function (`if count == 0 || count as usize >
    // BLK_DMA_SECTORS { return Err(()); }`), not merely a contract the
    // `read`/`write` wrappers happen to uphold — `blk_rw` re-validates its
    // own `count` argument regardless of caller. BLK_DMA_SECTORS = 8,
    // SECTOR_SIZE = 512, so the product is <= 4096 = BLK_DMA_BYTES; the
    // `checked_mul` is redundant defense, not the only guard.
    let data_len = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;

    // Descriptor 0: request header (device reads)
    let p = vq.desc.add(d_hdr);
    (*p).addr  = super::dma_addr_of(&raw const BLK_REQ_HDR);
    (*p).len   = core::mem::size_of::<BlkReqHdr>() as u32;
    (*p).flags = VIRTQ_DESC_F_NEXT;
    (*p).next  = d_data as u16;

    // Descriptor 1: data buffer — always the driver-owned staging area, so a
    // late DMA after a timeout can only land in memory this driver owns.
    let p = vq.desc.add(d_data);
    (*p).addr  = super::dma_addr_of(&raw const BLK_DMA_BUF);
    (*p).len   = data_len as u32;
    (*p).flags = VIRTQ_DESC_F_NEXT | if !write { VIRTQ_DESC_F_WRITE } else { 0 };
    (*p).next  = d_status as u16;

    // Descriptor 2: status byte (device writes)
    let p = vq.desc.add(d_status);
    (*p).addr  = super::dma_addr_of(&raw const BLK_STATUS);
    (*p).len   = 1;
    (*p).flags = VIRTQ_DESC_F_WRITE;
    (*p).next  = 0;

    // Submit and busy-wait for completion (same as C kernel)
    if let Err(reason) = submit_and_wait(&dev.vdev, vq, d_hdr, BLK_TIMEOUT_US) {
        latch_dead(dev, reason);
        return Err(());
    }

    virtq_free_desc(vq, d_hdr);
    virtq_free_desc(vq, d_data);
    virtq_free_desc(vq, d_status);

    // The status byte was written by the device via DMA; read it volatile so
    // the 0xFF sentinel store above cannot be constant-propagated into this
    // comparison. (Ordering is provided by the acquire fence in `virtq_poll`,
    // which sits between observing the used index and this load.)
    let status = core::ptr::read_volatile(&raw const BLK_STATUS);
    if status != BLK_S_OK {
        azos_drv_sys::kerr!("[VIRTIO-BLK] Error: status {}", status);
        return Err(());
    }

    Ok(())
}

// ---- Public API ----

/// True while the driver may touch the staging buffer and submit requests.
/// False before init() and forever after a timeout, when the device may still
/// own `BLK_DMA_BUF`. Checked before staging, not just before submitting.
///
/// Must be called with `BLK_LOCK` held.
fn usable() -> bool {
    let dev = unsafe { &*(&raw const BLK_DEV) };
    dev.ready && !dev.failed
}

/// Read `count` sectors starting at `sector` into `buf`.
///
/// Transfers via the driver's staging buffer in chunks of at most
/// `BLK_DMA_SECTORS`; `buf` is never exposed to the device. Returns `Err` on a
/// short buffer or a bad count instead of panicking (release builds abort on
/// panic, which on this target is a board reset).
pub fn read(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    // Held for the whole multi-chunk transfer: the staging buffer, the
    // request statics and the virtqueue are all shared mutable state.
    let _guard = BLK_LOCK.lock();
    if !usable() { return Err(()); }
    let total = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
    if total == 0 || buf.len() < total { return Err(()); }

    let mut done: u32 = 0;
    while done < count {
        let chunk = core::cmp::min((count - done) as usize, BLK_DMA_SECTORS);
        let bytes = chunk.checked_mul(SECTOR_SIZE).ok_or(())?;
        let off   = (done as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
        let end   = off.checked_add(bytes).ok_or(())?;
        let lba   = sector.checked_add(done as u64).ok_or(())?;

        unsafe { blk_rw(lba, chunk as u32, false)? };

        // Staging -> caller. `get_mut` rather than an index so a later edit
        // cannot reintroduce a panicking slice.
        let dst = buf.get_mut(off..end).ok_or(())?;
        // SAFETY: the device has posted the used-ring entry (virtq_poll
        // succeeded, which fences Acquire), so it is done with the staging
        // buffer. `bytes <= BLK_DMA_BYTES` and `dst.len() == bytes`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&raw const BLK_DMA_BUF) as *const u8, dst.as_mut_ptr(), bytes);
        }

        done += chunk as u32;
    }
    Ok(())
}

/// Write `count` sectors starting at `sector` from `buf`.
///
/// Chunked like `read`. A failure part-way through a multi-chunk transfer
/// leaves the earlier chunks committed to the disk — same as any multi-sector
/// request that fails mid-flight; callers must not assume atomicity.
pub fn write(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    // Held for the whole multi-chunk transfer — see `read`.
    let _guard = BLK_LOCK.lock();
    if !usable() { return Err(()); }
    let total = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
    if total == 0 || buf.len() < total { return Err(()); }

    let mut done: u32 = 0;
    while done < count {
        let chunk = core::cmp::min((count - done) as usize, BLK_DMA_SECTORS);
        let bytes = chunk.checked_mul(SECTOR_SIZE).ok_or(())?;
        let off   = (done as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
        let end   = off.checked_add(bytes).ok_or(())?;
        let lba   = sector.checked_add(done as u64).ok_or(())?;

        let src = buf.get(off..end).ok_or(())?;
        // SAFETY: no request is in flight (BLK_LOCK serializes callers, the
        // driver is strictly one request at a time and latches dead on
        // timeout), so the device does not own the staging buffer here.
        // `bytes <= BLK_DMA_BYTES`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(), (&raw mut BLK_DMA_BUF) as *mut u8, bytes);
        }

        unsafe { blk_rw(lba, chunk as u32, true)? };

        done += chunk as u32;
    }
    Ok(())
}

/// Commit every write the device has completed to stable storage: one
/// `VIRTIO_BLK_T_FLUSH` request, a two-descriptor chain (header, status),
/// waited for like any other request.
///
/// `Err(Unsupported)` when the device did not offer `VIRTIO_BLK_F_FLUSH`
/// (the request is then never sent: virtio 1.2 section 5.2.6.2 forbids it)
/// or answered `VIRTIO_BLK_S_UNSUPP`. `Err(Io)` before `init()`, after the
/// driver latched dead, on a timeout, or on any other status. Never `Ok`
/// without the device having answered `VIRTIO_BLK_S_OK` to a flush.
pub fn flush() -> Result<(), FlushError> {
    let _guard = BLK_LOCK.lock();
    if !usable() { return Err(FlushError::Io); }
    let dev = unsafe { &mut *(&raw mut BLK_DEV) };
    if !dev.flush { return Err(FlushError::Unsupported); }
    unsafe { blk_flush(dev) }
}

/// Caller must hold `BLK_LOCK`; `dev` must be usable with FLUSH negotiated.
unsafe fn blk_flush(dev: &mut BlkDev) -> Result<(), FlushError> {
    let vq = &mut dev.vq;
    if vq.desc.is_null() || vq.num == 0 { return Err(FlushError::Io); }

    // Idle-ring check, as in `blk_rw`.
    if virtq_poll(vq).is_some() {
        latch_dead(dev, "spurious completion while idle");
        return Err(FlushError::Io);
    }

    // `sector` is reserved for T_FLUSH and must be zero.
    BLK_REQ_HDR.req_type = BLK_T_FLUSH;
    BLK_REQ_HDR.reserved = 0;
    BLK_REQ_HDR.sector   = 0;
    BLK_STATUS           = 0xFF;

    // No data descriptor: a flush carries no payload, and a zero-length
    // buffer in the chain is something a device may reject outright.
    let d_hdr    = virtq_alloc_desc(vq).ok_or(FlushError::Io)?;
    let d_status = virtq_alloc_desc(vq).ok_or_else(|| {
        virtq_free_desc(vq, d_hdr);
        FlushError::Io
    })?;

    let p = vq.desc.add(d_hdr);
    (*p).addr  = super::dma_addr_of(&raw const BLK_REQ_HDR);
    (*p).len   = core::mem::size_of::<BlkReqHdr>() as u32;
    (*p).flags = VIRTQ_DESC_F_NEXT;
    (*p).next  = d_status as u16;

    let p = vq.desc.add(d_status);
    (*p).addr  = super::dma_addr_of(&raw const BLK_STATUS);
    (*p).len   = 1;
    (*p).flags = VIRTQ_DESC_F_WRITE;
    (*p).next  = 0;

    if let Err(reason) = submit_and_wait(&dev.vdev, vq, d_hdr, BLK_FLUSH_TIMEOUT_US) {
        latch_dead(dev, reason);
        return Err(FlushError::Io);
    }

    virtq_free_desc(vq, d_hdr);
    virtq_free_desc(vq, d_status);

    // Volatile for the same reason as in `blk_rw`.
    match core::ptr::read_volatile(&raw const BLK_STATUS) {
        BLK_S_OK => Ok(()),
        BLK_S_UNSUPP => {
            azos_drv_sys::kerr!("[VIRTIO-BLK] Error: flush answered UNSUPP after FLUSH was negotiated");
            Err(FlushError::Unsupported)
        }
        status => {
            azos_drv_sys::kerr!("[VIRTIO-BLK] Error: flush status {}", status);
            Err(FlushError::Io)
        }
    }
}

/// Disk capacity in bytes. Saturates: `capacity` is device-reported.
///
/// Deliberately lock-free: an aligned u64 load is single-copy atomic on
/// RV64, and taking `BLK_LOCK` here would block behind a full transfer's
/// busy-wait just to read a number. Worst case during init is reading 0.
pub fn capacity_bytes() -> u64 {
    unsafe { BLK_DEV.capacity.saturating_mul(SECTOR_SIZE as u64) }
}

/// Disk capacity in sectors. Lock-free — see `capacity_bytes`.
pub fn capacity_sectors() -> u64 {
    unsafe { BLK_DEV.capacity }
}
