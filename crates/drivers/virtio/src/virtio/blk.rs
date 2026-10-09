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
    VIRTIO_MMIO_INTERRUPT_STATUS, VIRTIO_MMIO_INTERRUPT_ACK,
};
use super::{mmio_read, mmio_write, probe, virtq_init,
            virtq_alloc_desc, virtq_free_desc, virtq_submit, virtq_poll,
            read_config64};
use azos_drv_api::block::FlushError;
use azos_drv_sys::kprintln;
use azos_sync::pi_mutex::PiMutex;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

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

/// Serializes every path that touches `BLK_DEV` and the virtqueue: device
/// setup, building and submitting a chain, reaping the used ring, and
/// freeing a completed chain's descriptors. On SMP two harts doing that
/// concurrently would corrupt the free-descriptor accounting and race the
/// ring indices. (The syscall layer serializes per-CPU only.)
///
/// **Not held across the device request** (owner rule F1, wave 15). A request
/// is submitted under it and then waited for WITHOUT it: the waiter polls,
/// taking the lock only for each short reap of the used ring. Each in-flight
/// request owns a staging slot ([`slot_claim`]), so nothing the device is
/// DMAing into is reachable by another request. The lock's sections are a
/// few hundred instructions — no wait on the device — so a contended taker
/// waits for bookkeeping, never for the disk, and its priority inheritance
/// never stretches across I/O.
///
/// Safe at boot despite yielding: `init()` runs before the scheduler exists,
/// single-threaded and uncontended, and `PiMutex`'s fast path is a plain CAS
/// that never reaches the yielding branch.
static BLK_LOCK: PiMutex<()> = PiMutex::new(());

// ---- DMA staging slots ----
//
// The device is NEVER handed a pointer into caller memory. A VirtIO request
// cannot be cancelled or recalled: once the chain is in the avail ring the
// device owns those buffers until it posts a used-ring entry, and if we give
// up waiting (see the timeout path in `wait_done`) it may still DMA into them
// until `latch_dead` resets it. A caller buffer is very often a stack frame
// that has been popped and reused by then, so a late write would silently
// corrupt unrelated state far from the call site.
//
// Every buffer in a request therefore lives in driver-owned `static` storage
// whose lifetime is the lifetime of the kernel: slot `i` is `BLK_REQ_HDR[i]`,
// `BLK_DMA_BUF[i]` and `BLK_STATUS[i]`. Up to `BLK_SLOTS` requests are in
// flight at once, one per slot (Kconfig `VIRTIO_BLK_INFLIGHT`). Transfers
// larger than one slot's staging area are split into chunks by the public
// `read`/`write` wrappers, all on the slot they claimed.
//
// Every descriptor `.addr` set in this file points at a slot's static —
// never at a caller-supplied pointer (grep `\.addr` in this file: five
// sites, three in `blk_rw` and two in `flush`, none derived from
// `buf`/`dst`/`src`). The caller's `buf` only ever meets
// `copy_nonoverlapping`: `write()` stages caller bytes into its slot *before*
// `blk_rw` submits the chain, and `read()` copies its slot out to the caller
// *after* `blk_rw` has returned (i.e. after the device posted the used-ring
// entry). Re-check the grep if a descriptor-setup site is added.
/// Sectors per slot's staging buffer (Kconfig `VIRTIO_BLK_SLOT_KB`; was a
/// fixed 8 = 4 KiB): the largest transfer one request carries.
const BLK_DMA_SECTORS: usize = azos_limits::VIRTIO_BLK_SLOT_KB as usize * 1024 / SECTOR_SIZE;
const BLK_DMA_BYTES:   usize = BLK_DMA_SECTORS * SECTOR_SIZE;
const _: () = assert!(BLK_DMA_SECTORS >= 8);

/// Requests in flight at once (Kconfig `VIRTIO_BLK_INFLIGHT`). A read or
/// write takes 3 descriptors, so the queue bounds it.
const BLK_SLOTS: usize = azos_limits::VIRTIO_BLK_INFLIGHT as usize;
const _: () = assert!(BLK_SLOTS >= 1 && BLK_SLOTS * 3 <= super::VIRTIO_QUEUE_SIZE && BLK_SLOTS <= 32);

#[repr(C, align(512))]
struct DmaBuf([u8; BLK_DMA_BYTES]);

// Static request buffers, one set per slot.
static mut BLK_REQ_HDR: [BlkReqHdr; BLK_SLOTS] =
    [const { BlkReqHdr { req_type: 0, reserved: 0, sector: 0 } }; BLK_SLOTS];
static mut BLK_STATUS:  [u8; BLK_SLOTS] = [0xFF; BLK_SLOTS];
static mut BLK_DMA_BUF: [DmaBuf; BLK_SLOTS] = [const { DmaBuf([0u8; BLK_DMA_BYTES]) }; BLK_SLOTS];

/// Head descriptor of slot `i`'s in-flight chain, `NO_CHAIN` when none.
/// Written under `BLK_LOCK`; read by the reaper under it.
static SLOT_HEAD: [AtomicUsize; BLK_SLOTS] = [const { AtomicUsize::new(NO_CHAIN) }; BLK_SLOTS];
/// Slot `i`'s chain completed (set by whichever task reaped it).
static SLOT_DONE: [AtomicBool; BLK_SLOTS] = [const { AtomicBool::new(false) }; BLK_SLOTS];
const NO_CHAIN: usize = usize::MAX;

/// Slot ownership: bit `i` set while a request owns slot `i`. Claimed with
/// `fetch_or`; a caller that finds every slot taken sleeps (no priority
/// inheritance: the owner is waiting on the device, not on a CPU) until a
/// release bumps `SLOT_GEN`, re-checked under the queue's lock.
static SLOT_BUSY: AtomicU32 = AtomicU32::new(0);
static SLOT_GEN:  AtomicU32 = AtomicU32::new(0);
static SLOT_WQ:   azos_sync::waitqueue::WaitQueue = azos_sync::waitqueue::WaitQueue::new();

/// A claimed staging slot; released on drop.
struct SlotClaim(usize);

/// A free slot right now, or `None` (never sleeps): the extra slots a
/// multi-request write pipelines over.
fn slot_try_claim() -> Option<SlotClaim> {
    let all: u32 = if BLK_SLOTS == 32 { u32::MAX } else { (1u32 << BLK_SLOTS) - 1 };
    loop {
        let free = !SLOT_BUSY.load(Ordering::SeqCst) & all;
        if free == 0 {
            return None;
        }
        let bit = 1u32 << free.trailing_zeros();
        if SLOT_BUSY.fetch_or(bit, Ordering::SeqCst) & bit == 0 {
            return Some(SlotClaim(free.trailing_zeros() as usize));
        }
    }
}

fn slot_claim() -> SlotClaim {
    let all: u32 = if BLK_SLOTS == 32 { u32::MAX } else { (1u32 << BLK_SLOTS) - 1 };
    loop {
        let gen = SLOT_GEN.load(Ordering::SeqCst);
        let free = !SLOT_BUSY.load(Ordering::SeqCst) & all;
        if free != 0 {
            let bit = 1u32 << free.trailing_zeros();
            if SLOT_BUSY.fetch_or(bit, Ordering::SeqCst) & bit == 0 {
                return SlotClaim(free.trailing_zeros() as usize);
            }
            continue;
        }
        SLOT_WQ.wait_if(|| SLOT_GEN.load(Ordering::SeqCst) == gen);
    }
}

impl Drop for SlotClaim {
    fn drop(&mut self) {
        SLOT_BUSY.fetch_and(!(1u32 << self.0), Ordering::SeqCst);
        SLOT_GEN.fetch_add(1, Ordering::SeqCst);
        SLOT_WQ.wake_all();
    }
}

// ---- Completion by interrupt (wave 15) ----
//
// The device raises its virtio-mmio line when it posts a used-ring entry.
// Once the kernel has wired that line (`set_irq_mode`, after the interrupt
// controller routes it), a waiter in task context SLEEPS until the line's
// handler (`irq`) wakes it, instead of spinning on the used ring: no CPU is
// spent waiting, and under `-icount` host disk latency no longer turns into
// guest instructions. The handler only acknowledges the device and wakes the
// waiters by TID (a wake that lands before the waiter blocks is stamped and
// its block returns at once, so none is lost); the waiter reaps the ring
// itself, under `BLK_LOCK`, as before. Bounded: the sleep ends at the
// request's deadline too, and a waiter that cannot block (no scheduler yet,
// interrupts or preemption off: early boot, the panic path) spins as before.

/// The wired line (`u32::MAX` while polled), and the device's MMIO base for
/// the handler's acknowledge.
static IRQ_LINE: AtomicU32 = AtomicU32::new(u32::MAX);
static IRQ_BASE: AtomicUsize = AtomicUsize::new(0);
/// Interrupts taken / waits that slept (diagnostics, `blk_irq_counts`).
static IRQ_TAKEN: AtomicU32 = AtomicU32::new(0);
static IRQ_SLEPT: AtomicU32 = AtomicU32::new(0);
/// The task waiting on slot `i`'s request (0: none, or not sleeping).
static SLOT_WAITER: [AtomicU32; BLK_SLOTS] = [const { AtomicU32::new(0) }; BLK_SLOTS];
/// The kernel's hooks: block the caller until woken or `deadline` (timebase
/// ticks), `false` when it cannot block; wake task `tid`.
static BLOCK_FN: AtomicUsize = AtomicUsize::new(0);
static WAKE_FN: AtomicUsize = AtomicUsize::new(0);

/// The virtio-mmio slot `init` found the device in (`usize::MAX`: none).
static FOUND_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);

fn mmio_base() -> Option<usize> {
    let _guard = BLK_LOCK.lock();
    let dev = unsafe { &*(&raw const BLK_DEV) };
    if dev.ready { Some(dev.vdev.base as usize) } else { None }
}

/// `(slot, physical address)` of the virtio-mmio transport the block device
/// is on, once `init` succeeded: the kernel maps it to its interrupt line.
pub fn mmio_slot() -> Option<(usize, usize)> {
    mmio_base()?;
    let i = FOUND_SLOT.load(Ordering::Acquire);
    if i == usize::MAX { return None; }
    Some((i, VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STEP))
}

/// Take completions by interrupt on `line` from now on. Call BEFORE the
/// interrupt controller enables `line` (its handler must already recognise
/// it: [`irq`]); the device's pending interrupt is acknowledged here.
pub fn set_irq_mode(line: u32, block_until: fn(u64) -> bool, wake: fn(u32)) {
    if cfg!(feature = "blk-poll-canary") { return; }
    let Some(base) = mmio_base() else { return; };
    BLOCK_FN.store(block_until as usize, Ordering::Release);
    WAKE_FN.store(wake as usize, Ordering::Release);
    IRQ_BASE.store(base, Ordering::Release);
    IRQ_LINE.store(line, Ordering::Release);
    // Every completion so far raised the line and nobody acknowledged it:
    // clear it now, so a level line is not asserted the moment the
    // controller enables it, and an edge line can rise again.
    // SAFETY: as in `irq`.
    unsafe {
        let b = base as *mut u32;
        let status = mmio_read(b, VIRTIO_MMIO_INTERRUPT_STATUS);
        mmio_write(b, VIRTIO_MMIO_INTERRUPT_ACK, status);
    }
}

/// `true` once completions come by interrupt.
pub fn irq_mode() -> bool {
    IRQ_LINE.load(Ordering::Acquire) != u32::MAX
}

/// `(interrupts taken, waits that slept)`.
pub fn blk_irq_counts() -> (u32, u32) {
    (IRQ_TAKEN.load(Ordering::Relaxed), IRQ_SLEPT.load(Ordering::Relaxed))
}

/// The interrupt handler's arm for `line` (interrupt context, any CPU):
/// `None` when the line is not this device's; otherwise acknowledge the
/// device and wake every sleeping waiter, `Some(true)` when one was woken.
pub fn irq(line: u32) -> Option<bool> {
    if line != IRQ_LINE.load(Ordering::Acquire) {
        return None;
    }
    let base = IRQ_BASE.load(Ordering::Acquire) as *mut u32;
    // SAFETY: `base` is the device's mapped MMIO window (`set_irq_mode`
    // took it from the initialised device); the two registers are the
    // virtio-mmio interrupt status and acknowledge.
    unsafe {
        let status = mmio_read(base, VIRTIO_MMIO_INTERRUPT_STATUS);
        mmio_write(base, VIRTIO_MMIO_INTERRUPT_ACK, status);
    }
    IRQ_TAKEN.fetch_add(1, Ordering::Relaxed);
    let wake = WAKE_FN.load(Ordering::Acquire);
    if wake == 0 {
        return Some(false);
    }
    // SAFETY: only `set_irq_mode` stores here, and it stores a `fn(u32)`.
    let wake: fn(u32) = unsafe { core::mem::transmute::<usize, fn(u32)>(wake) };
    let mut woke = false;
    for w in SLOT_WAITER.iter() {
        let tid = w.load(Ordering::Acquire);
        if tid != 0 {
            wake(tid);
            woke = true;
        }
    }
    Some(woke)
}

/// Sleep until the line's next interrupt or `deadline`; `false` when the
/// caller cannot sleep (then it spins, as in polled mode).
fn sleep_for_completion(slot: usize, deadline: u64) -> bool {
    if !irq_mode() { return false; }
    let f = BLOCK_FN.load(Ordering::Acquire);
    if f == 0 { return false; }
    let tid = azos_sync::waitqueue::caller_tid();
    if tid == 0 || tid == u32::MAX { return false; }
    SLOT_WAITER[slot].store(tid, Ordering::Release);
    // Re-check after publishing the waiter: a completion posted before the
    // store raised its interrupt before anyone could be woken.
    let done = {
        let _g = BLK_LOCK.lock();
        let dev = unsafe { &mut *(&raw mut BLK_DEV) };
        unsafe { reap(dev) };
        SLOT_DONE[slot].load(Ordering::Acquire) || dev.failed
    };
    let slept = if done {
        true
    } else {
        // SAFETY: only `set_irq_mode` stores here, and it stores a `fn(u64) -> bool`.
        let f: fn(u64) -> bool = unsafe { core::mem::transmute::<usize, fn(u64) -> bool>(f) };
        // One slice at a time, never straight to the deadline: an idle CPU
        // under QEMU `-icount ... sleep=off` jumps its clock to the next
        // timer, and a sleep to the deadline would declare the device dead
        // before the host had answered (Kconfig `VIRTIO_BLK_IRQ_SLICE_US`).
        let slice = azos_limits::VIRTIO_BLK_IRQ_SLICE_US as u64
            * azos_drv_irqchip::clint::TIMER_FREQ / 1_000_000;
        let until = deadline.min(azos_drv_sys::timebase::now().saturating_add(slice.max(1)));
        let s = f(until);
        if s { IRQ_SLEPT.fetch_add(1, Ordering::Relaxed); }
        s
    };
    SLOT_WAITER[slot].store(0, Ordering::Release);
    slept
}

/// `blk-wait-probe` (the `lat-fat` smoke): waits for a completion, and those
/// made with a `PiMutex` held that the request's caller did not hold when it
/// entered the driver — `BLK_LOCK` across the device request, the F1 shape.
#[cfg(feature = "blk-wait-probe")]
static WAITS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "blk-wait-probe")]
static WAITS_LOCKED: AtomicU32 = AtomicU32::new(0);

/// `(waits, waits with a driver PiMutex held)`; the second must be 0.
#[cfg(feature = "blk-wait-probe")]
pub fn wait_probe_counts() -> (u32, u32) {
    (WAITS.load(Ordering::Relaxed), WAITS_LOCKED.load(Ordering::Relaxed))
}

#[inline(always)]
fn caller_pi_held() -> u32 {
    #[cfg(feature = "blk-wait-probe")]
    { azos_sync::pi_mutex::held_by(azos_sync::waitqueue::caller_tid()) }
    #[cfg(not(feature = "blk-wait-probe"))]
    { 0 }
}

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
                   azos_arch::PAGE_SIZE as u32);
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
                FOUND_SLOT.store(i, Ordering::Release);
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

/// Reap every completion the device has posted: mark the slot whose chain
/// it names done. A completion naming no in-flight chain is a device not
/// following the protocol — it would make some later request appear complete
/// before its DMA happened — so the driver latches dead. Caller holds
/// `BLK_LOCK`.
unsafe fn reap(dev: &mut BlkDev) {
    while let Some(id) = virtq_poll(&mut dev.vq) {
        match (0..BLK_SLOTS).find(|&i| {
            SLOT_HEAD[i].load(Ordering::Relaxed) == id && !SLOT_DONE[i].load(Ordering::Relaxed)
        }) {
            Some(i) => SLOT_DONE[i].store(true, Ordering::Release),
            None => {
                latch_dead(dev, "foreign completion id");
                return;
            }
        }
    }
}

/// Put slot `slot`'s chain, headed by `head`, in the avail ring. Caller
/// holds `BLK_LOCK`; the wait ([`wait_done`]) runs without it.
unsafe fn submit(dev: &mut BlkDev, slot: usize, head: usize) {
    SLOT_DONE[slot].store(false, Ordering::Relaxed);
    SLOT_HEAD[slot].store(head, Ordering::Relaxed);
    virtq_submit(&dev.vdev, 0, head, &mut dev.vq);
}

/// Wait, WITHOUT `BLK_LOCK`, for slot `slot`'s chain to complete, bounded by
/// `timeout_us` of wall-clock time. Each poll takes the lock only to reap the
/// used ring (another request's waiter may have reaped ours already).
/// `Err` when the device latched dead meanwhile or the deadline passed (the
/// driver is then latched dead here); the caller must then not free the
/// chain's descriptors.
fn wait_done(slot: usize, timeout_us: u64, pi_base: u32) -> Result<(), ()> {
    let deadline = azos_drv_sys::timebase::now()
        + timeout_us * azos_drv_irqchip::clint::TIMER_FREQ / 1_000_000;
    #[cfg(feature = "blk-wait-probe")]
    WAITS.fetch_add(1, Ordering::Relaxed);
    // Gate canary: the pre-F1 shape, the lock held across the whole wait.
    let _canary = if cfg!(feature = "blk-lock-wait-canary") { Some(BLK_LOCK.lock()) } else { None };
    #[cfg(feature = "blk-wait-probe")]
    if caller_pi_held() > pi_base {
        WAITS_LOCKED.fetch_add(1, Ordering::Relaxed);
    }
    let _ = pi_base;
    loop {
        if SLOT_DONE[slot].load(Ordering::Acquire) {
            return Ok(());
        }
        let can_sleep = _canary.is_none();
        {
            let _g = if _canary.is_some() { None } else { Some(BLK_LOCK.lock()) };
            let dev = unsafe { &mut *(&raw mut BLK_DEV) };
            unsafe { reap(dev) };
            if SLOT_DONE[slot].load(Ordering::Acquire) {
                return Ok(());
            }
            if dev.failed {
                return Err(());
            }
            if azos_drv_sys::timebase::now() >= deadline {
                unsafe { latch_dead(dev, "request timeout") };
                return Err(());
            }
        }
        if !(can_sleep && sleep_for_completion(slot, deadline)) {
            core::hint::spin_loop();
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

/// Internal read/write of one chunk on slot `slot` — a 3-descriptor chain
/// (header | data | status). The data descriptor always points at the slot's
/// driver-owned staging buffer, never at caller memory; `read`/`write` copy
/// in and out around this call. Submitted under `BLK_LOCK`, waited for
/// without it.
///
/// `count` must be in `1..=BLK_DMA_SECTORS`; anything else is rejected.
fn blk_rw(slot: usize, sector: u64, count: u32, write: bool, pi_base: u32) -> Result<(), ()> {
    let chain = blk_submit(slot, sector, count, write)?;
    blk_complete(slot, chain, pi_base)
}

/// The descriptors of one submitted request chain.
#[derive(Clone, Copy)]
struct Chain(usize, usize, usize);

/// First half of [`blk_rw`]: build and submit slot `slot`'s chain under
/// `BLK_LOCK`; nothing is waited for.
fn blk_submit(slot: usize, sector: u64, count: u32, write: bool) -> Result<Chain, ()> {
    let (d_hdr, d_data, d_status) = {
        let _guard = BLK_LOCK.lock();
        let dev = unsafe { &mut *(&raw mut BLK_DEV) };

        // A previous request timed out: the device was reset and the driver
        // stays dead until reboot.
        if dev.failed || !dev.ready { return Err(()); }

        // Queue must be live: a null table would be a null deref below, and
        // `virtq_submit` divides by `vq.num`.
        if dev.vq.desc.is_null() || dev.vq.num == 0 { return Err(()); }

        if count == 0 || count as usize > BLK_DMA_SECTORS { return Err(()); }

        // `sector + count` can overflow with a hostile LBA; overflow-checks are
        // on in release, so a plain add is a panic (== board reset). Check it.
        let end = sector.checked_add(count as u64).ok_or(())?;
        if end > dev.capacity {
            azos_drv_sys::kerr!("[VIRTIO-BLK] Error: sector out of range");
            return Err(());
        }
        if write && dev.readonly {
            azos_drv_sys::kerr!("[VIRTIO-BLK] Error: disk is read-only");
            return Err(());
        }

        // Anything the device posted is reaped first: a completion naming no
        // in-flight chain latches the driver dead here, before this request
        // could be mistaken for complete.
        unsafe { reap(dev) };
        if dev.failed { return Err(()); }

        // SAFETY: this task owns slot `slot` (`SlotClaim`), so its header and
        // status are not in any in-flight chain.
        unsafe {
            BLK_REQ_HDR[slot].req_type = if write { BLK_T_OUT } else { BLK_T_IN };
            BLK_REQ_HDR[slot].reserved = 0;
            BLK_REQ_HDR[slot].sector   = sector;
            BLK_STATUS[slot]           = 0xFF;
        }

        let vq = &mut dev.vq;
        // Allocate 3 descriptors: [header] → [data] → [status]. The queue
        // holds 3 per slot (`BLK_SLOTS` assert), so this does not fail while
        // the driver is alive.
        let d_hdr    = unsafe { virtq_alloc_desc(vq) }.ok_or(())?;
        let d_data   = unsafe { virtq_alloc_desc(vq) }.ok_or_else(|| unsafe { virtq_free_desc(vq, d_hdr); })?;
        let d_status = unsafe { virtq_alloc_desc(vq) }.ok_or_else(|| unsafe {
            virtq_free_desc(vq, d_hdr);
            virtq_free_desc(vq, d_data);
        })?;

        // count <= BLK_DMA_SECTORS was checked above (in this function), so
        // this cannot exceed BLK_DMA_BYTES; `checked_mul` is redundant defence.
        let data_len = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;

        unsafe {
            // Descriptor 0: request header (device reads)
            let p = vq.desc.add(d_hdr);
            (*p).addr  = super::dma_addr_of(&raw const BLK_REQ_HDR[slot]);
            (*p).len   = core::mem::size_of::<BlkReqHdr>() as u32;
            (*p).flags = VIRTQ_DESC_F_NEXT;
            (*p).next  = d_data as u16;

            // Descriptor 1: data — the slot's driver-owned staging area.
            let p = vq.desc.add(d_data);
            (*p).addr  = super::dma_addr_of(&raw const BLK_DMA_BUF[slot]);
            (*p).len   = data_len as u32;
            (*p).flags = VIRTQ_DESC_F_NEXT | if !write { VIRTQ_DESC_F_WRITE } else { 0 };
            (*p).next  = d_status as u16;

            // Descriptor 2: status byte (device writes)
            let p = vq.desc.add(d_status);
            (*p).addr  = super::dma_addr_of(&raw const BLK_STATUS[slot]);
            (*p).len   = 1;
            (*p).flags = VIRTQ_DESC_F_WRITE;
            (*p).next  = 0;

            submit(dev, slot, d_hdr);
        }
        (d_hdr, d_data, d_status)
    };
    Ok(Chain(d_hdr, d_data, d_status))
}

/// Second half of [`blk_rw`]: wait (without `BLK_LOCK`) for slot `slot`'s
/// chain, free its descriptors and read its status.
fn blk_complete(slot: usize, chain: Chain, pi_base: u32) -> Result<(), ()> {
    let Chain(d_hdr, d_data, d_status) = chain;
    // The device request, waited for without BLK_LOCK. On failure the chain's
    // descriptors stay quarantined (`latch_dead`).
    wait_done(slot, BLK_TIMEOUT_US, pi_base)?;

    let _guard = BLK_LOCK.lock();
    let dev = unsafe { &mut *(&raw mut BLK_DEV) };
    SLOT_HEAD[slot].store(NO_CHAIN, Ordering::Relaxed);
    unsafe {
        virtq_free_desc(&mut dev.vq, d_hdr);
        virtq_free_desc(&mut dev.vq, d_data);
        virtq_free_desc(&mut dev.vq, d_status);
    }

    // The status byte was written by the device via DMA; read it volatile so
    // the 0xFF sentinel store above cannot be constant-propagated into this
    // comparison. (Ordering: the acquire fence in `virtq_poll` sits between
    // observing the used index and the reaper's release of `SLOT_DONE`, which
    // `wait_done` acquired.)
    let status = unsafe { core::ptr::read_volatile(&raw const BLK_STATUS[slot]) };
    if status != BLK_S_OK {
        azos_drv_sys::kerr!("[VIRTIO-BLK] Error: status {}", status);
        return Err(());
    }

    Ok(())
}

// ---- Public API ----

/// True while the driver may submit requests. False before init() and forever
/// after a timeout. Checked before staging, not just before submitting.
fn usable() -> bool {
    let _guard = BLK_LOCK.lock();
    let dev = unsafe { &*(&raw const BLK_DEV) };
    dev.ready && !dev.failed
}

/// Read `count` sectors starting at `sector` into `buf`.
///
/// Transfers via a staging slot in chunks of at most `BLK_DMA_SECTORS`; `buf`
/// is never exposed to the device. Returns `Err` on a short buffer or a bad
/// count instead of panicking (release builds abort on panic, which on this
/// target is a board reset).
pub fn read(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    let pi_base = caller_pi_held();
    let total = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
    if total == 0 || buf.len() < total { return Err(()); }
    // Held for the whole multi-chunk transfer: the slot's staging buffer is
    // this request's alone.
    let slot = slot_claim();
    if !usable() { return Err(()); }

    let mut done: u32 = 0;
    while done < count {
        let chunk = core::cmp::min((count - done) as usize, BLK_DMA_SECTORS);
        let bytes = chunk.checked_mul(SECTOR_SIZE).ok_or(())?;
        let off   = (done as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
        let end   = off.checked_add(bytes).ok_or(())?;
        let lba   = sector.checked_add(done as u64).ok_or(())?;

        blk_rw(slot.0, lba, chunk as u32, false, pi_base)?;

        // Staging -> caller. `get_mut` rather than an index so a later edit
        // cannot reintroduce a panicking slice.
        let dst = buf.get_mut(off..end).ok_or(())?;
        // SAFETY: the device has posted this slot's used-ring entry
        // (`wait_done` acquired it), so it is done with the staging buffer,
        // and the slot is this task's. `bytes <= BLK_DMA_BYTES`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&raw const BLK_DMA_BUF[slot.0]) as *const u8, dst.as_mut_ptr(), bytes);
        }

        done += chunk as u32;
    }
    Ok(())
}

/// Write `count` sectors starting at `sector` from `buf`.
///
/// Chunked like `read`, but pipelined (wave 15): the chunks go out on every
/// slot free at entry, up to `VIRTIO_BLK_INFLIGHT` requests in the device at
/// once. A failure part-way through leaves other chunks committed to the
/// disk — same as any multi-sector request that fails mid-flight; callers
/// must not assume atomicity.
pub fn write(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    let pi_base = caller_pi_held();
    let total = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
    if total == 0 || buf.len() < total { return Err(()); }
    let chunks = (count as usize).div_ceil(BLK_DMA_SECTORS);
    // The first slot is waited for; more are taken only if free now, up to
    // one per chunk: a multi-request write (a coalesced write-back run)
    // keeps up to `VIRTIO_BLK_INFLIGHT` requests in the device at once
    // instead of one round trip per chunk. Its chunks carry no order among
    // themselves (one write; `flush` covers only completed requests, and
    // this returns only once every chunk completed).
    let mut slots: [Option<SlotClaim>; BLK_SLOTS] = [const { None }; BLK_SLOTS];
    slots[0] = Some(slot_claim());
    let mut k = 1usize;
    while k < BLK_SLOTS && k < chunks && !cfg!(feature = "blk-serial-write-canary") {
        match slot_try_claim() {
            Some(c) => { slots[k] = Some(c); k += 1; }
            None => break,
        }
    }
    if !usable() { return Err(()); }

    let mut inflight: [Option<Chain>; BLK_SLOTS] = [None; BLK_SLOTS];
    let mut result: Result<(), ()> = Ok(());
    let mut done: u32 = 0;
    let mut i = 0usize;
    while done < count {
        let j = i % k;
        let slot = match &slots[j] { Some(c) => c.0, None => { result = Err(()); break; } };
        // The slot's previous chunk first: its staging buffer is reused.
        if let Some(ch) = inflight[j].take() {
            if blk_complete(slot, ch, pi_base).is_err() { result = Err(()); break; }
        }
        let chunk = core::cmp::min((count - done) as usize, BLK_DMA_SECTORS);
        let bytes = chunk * SECTOR_SIZE;
        let off = done as usize * SECTOR_SIZE;
        let lba = match sector.checked_add(done as u64) { Some(l) => l, None => { result = Err(()); break; } };
        let src = match buf.get(off..off + bytes) { Some(b) => b, None => { result = Err(()); break; } };
        // SAFETY: the slot is this task's and its previous chain (if any)
        // completed just above, so the device does not own its staging
        // buffer. `bytes <= BLK_DMA_BYTES`.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), (&raw mut BLK_DMA_BUF[slot]) as *mut u8, bytes);
        }
        match blk_submit(slot, lba, chunk as u32, true) {
            Ok(ch) => inflight[j] = Some(ch),
            Err(()) => { result = Err(()); break; }
        }
        done += chunk as u32;
        i += 1;
    }
    // Every submitted chunk completes before its slot is released: the
    // device owns the staging buffer until then.
    for j in 0..k {
        if let (Some(ch), Some(c)) = (inflight[j].take(), &slots[j]) {
            if blk_complete(c.0, ch, pi_base).is_err() { result = Err(()); }
        }
    }
    result
}

/// Commit every write the device has completed to stable storage: one
/// `VIRTIO_BLK_T_FLUSH` request, a two-descriptor chain (header, status),
/// submitted and waited for like any other request.
///
/// `Err(Unsupported)` when the device did not offer `VIRTIO_BLK_F_FLUSH`
/// (the request is then never sent: virtio 1.2 section 5.2.6.2 forbids it)
/// or answered `VIRTIO_BLK_S_UNSUPP`. `Err(Io)` before `init()`, after the
/// driver latched dead, on a timeout, or on any other status. Never `Ok`
/// without the device having answered `VIRTIO_BLK_S_OK` to a flush.
///
/// A flush covers the writes that COMPLETED before it was submitted; one
/// still in flight on another slot is not ordered by it (virtio 1.2 section
/// 5.2.6.4) — every caller that claims durability flushes after its own
/// writes returned.
pub fn flush() -> Result<(), FlushError> {
    let pi_base = caller_pi_held();
    let slot = slot_claim();
    let (d_hdr, d_status) = {
        let _guard = BLK_LOCK.lock();
        let dev = unsafe { &mut *(&raw mut BLK_DEV) };
        if !(dev.ready && !dev.failed) { return Err(FlushError::Io); }
        if !dev.flush { return Err(FlushError::Unsupported); }
        if dev.vq.desc.is_null() || dev.vq.num == 0 { return Err(FlushError::Io); }
        unsafe { reap(dev) };
        if dev.failed { return Err(FlushError::Io); }

        // `sector` is reserved for T_FLUSH and must be zero.
        unsafe {
            BLK_REQ_HDR[slot.0].req_type = BLK_T_FLUSH;
            BLK_REQ_HDR[slot.0].reserved = 0;
            BLK_REQ_HDR[slot.0].sector   = 0;
            BLK_STATUS[slot.0]           = 0xFF;
        }

        // No data descriptor: a flush carries no payload, and a zero-length
        // buffer in the chain is something a device may reject outright.
        let vq = &mut dev.vq;
        let d_hdr    = unsafe { virtq_alloc_desc(vq) }.ok_or(FlushError::Io)?;
        let d_status = unsafe { virtq_alloc_desc(vq) }.ok_or_else(|| {
            unsafe { virtq_free_desc(vq, d_hdr) };
            FlushError::Io
        })?;

        unsafe {
            let p = vq.desc.add(d_hdr);
            (*p).addr  = super::dma_addr_of(&raw const BLK_REQ_HDR[slot.0]);
            (*p).len   = core::mem::size_of::<BlkReqHdr>() as u32;
            (*p).flags = VIRTQ_DESC_F_NEXT;
            (*p).next  = d_status as u16;

            let p = vq.desc.add(d_status);
            (*p).addr  = super::dma_addr_of(&raw const BLK_STATUS[slot.0]);
            (*p).len   = 1;
            (*p).flags = VIRTQ_DESC_F_WRITE;
            (*p).next  = 0;

            submit(dev, slot.0, d_hdr);
        }
        (d_hdr, d_status)
    };

    wait_done(slot.0, BLK_FLUSH_TIMEOUT_US, pi_base).map_err(|_| FlushError::Io)?;

    let _guard = BLK_LOCK.lock();
    let dev = unsafe { &mut *(&raw mut BLK_DEV) };
    SLOT_HEAD[slot.0].store(NO_CHAIN, Ordering::Relaxed);
    unsafe {
        virtq_free_desc(&mut dev.vq, d_hdr);
        virtq_free_desc(&mut dev.vq, d_status);
    }

    // Volatile for the same reason as in `blk_rw`.
    match unsafe { core::ptr::read_volatile(&raw const BLK_STATUS[slot.0]) } {
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
