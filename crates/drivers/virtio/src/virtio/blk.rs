// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VirtIO block device, driven by the block request layer.
//!
//! The device is a [`HwQueue`](azos_drv_api::block::HwQueue): the request
//! layer (`azos_drv_block::queue`) claims a slot, starts a command on it,
//! reaps the completions and copies a read's data out; this file puts the
//! command on a virtqueue and reports what the device finished. There is no
//! synchronous read/write path here any more, and no waiting under a driver
//! lock: a command is submitted under its queue's lock, and the layer waits
//! for it in [`HwQueue::wait`] (the completion interrupt) with none held.
//!
//! # Queues
//!
//! With `VIRTIO_BLK_F_MQ` offered and Kconfig `VIRTIO_BLK_QUEUES` above one,
//! the driver sets up `min(num_queues, VIRTIO_BLK_QUEUES, NR_CPUS)` request
//! queues. Slot `t` belongs to queue `t mod queues` (see
//! [`blk_proto::queue_of`](super::blk_proto::queue_of)); [`HwQueue::claim`]
//! hands a task a slot of its CPU's queue first, so two CPUs submit on two
//! rings, each with its own lock and used ring, while a slot of their own is
//! free. A virtio-mmio device has one interrupt line whatever the queue count,
//! so there is one reaper and one waiter, as for NVMe.
//!
//! # Commands
//!
//! * Read, write: header | data | status. The data descriptor always points at
//!   the slot's driver-owned staging buffer, never at a caller's memory: a
//!   request cannot be cancelled once it is in the avail ring, and a late DMA
//!   into a popped stack frame would corrupt unrelated state.
//! * Flush (`VIRTIO_BLK_T_FLUSH`): header | status; a device that did not
//!   offer `VIRTIO_BLK_F_FLUSH` is never sent one (virtio 1.2 section 5.2.6.2)
//!   and the command is reported `Unsupported`.
//! * Discard (`VIRTIO_BLK_T_DISCARD`, Kconfig `BLK_DISCARD` not off): header |
//!   one 16-byte segment | status, up to the device's `max_discard_sectors`.
//! * No FUA: virtio-blk has no per-request bit for it, so the capabilities say
//!   so and the layer refuses a request that asks. `WRITE_ZEROES` is not
//!   negotiated: nothing in the kernel asks for it.
//!
//! A command that does not complete within its budget resets the device and
//! programs it again over the same rings, once per boot; the next one latches
//! the driver dead: see [`timed_out`] and `azos_drv_api::recovery`.
//!
//! Observed on QEMU 11.0 (blklogwrites log of a boot): while FLUSH is NOT
//! negotiated QEMU runs its cache writethrough and follows every write with a
//! host flush; once it IS negotiated the cache is writeback and only the
//! driver's `T_FLUSH` requests reach the backing file. So negotiating FLUSH
//! makes every path that does not flush less durable on QEMU than it was
//! before; the callers that claim durability flush.

use super::blk_proto as proto;
use super::{
    Dma, VirtioDev, Virtq,
    VIRTIO_DEV_BLOCK, VIRTIO_STATUS_DRIVER_OK, VIRTIO_MMIO_STATUS,
    VIRTIO_STATUS_ACK, VIRTIO_STATUS_DRIVER, VIRTIO_STATUS_FEATURES_OK,
    VIRTIO_STATUS_FAILED, VIRTIO_MMIO_GUEST_PAGE_SIZE,
    VIRTIO_MMIO_DEVICE_FEATURES, VIRTIO_MMIO_DEVICE_FEATURES_SEL,
    VIRTIO_MMIO_DRIVER_FEATURES, VIRTIO_MMIO_DRIVER_FEATURES_SEL,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    VIRTIO_MMIO_INTERRUPT_STATUS, VIRTIO_MMIO_INTERRUPT_ACK,
    VIRTIO_QUEUE_SIZE,
};
use super::{mmio_read, mmio_write, probe, virtq_init, virtq_reprogram,
            virtq_alloc_desc, virtq_free_desc, virtq_submit, virtq_poll,
            read_config32, read_config64};
use azos_dma::Direction;
use azos_drv_api::block::{Claim, DeviceWait, HwCaps, HwCmd, HwDone, HwOp, HwQueue, HwStatus, StallClock, HW_TAGS_MAX, STALL_GAP_US};
use azos_drv_api::recovery::{Class, Recovery, Verdict};
use azos_drv_sys::kprintln;
use azos_sync::kmutex::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

// ---- Constants ----

// Sourced from `super` (`virtio::mod`'s `VIRTIO_MMIO_*`, ISA-selected there)
// instead of a local literal: the same definition `net.rs`/`rng.rs` use.
use super::VIRTIO_MMIO_BASE;
use super::VIRTIO_MMIO_STRIDE as VIRTIO_MMIO_STEP;
use super::VIRTIO_MMIO_COUNT;

pub const SECTOR_SIZE: usize = 512;

/// Request queues the driver has room for (Kconfig `VIRTIO_BLK_QUEUES`).
const MAXQ: usize = azos_limits::VIRTIO_BLK_QUEUES as usize;
/// Commands the driver has room for in flight (Kconfig `VIRTIO_BLK_INFLIGHT`);
/// how many are usable is `BlkDev::slots`.
const SLOTS: usize = azos_limits::VIRTIO_BLK_INFLIGHT as usize;
const _: () = assert!(SLOTS >= 1 && SLOTS <= HW_TAGS_MAX && MAXQ >= 1 && MAXQ <= 4);
const _: () = assert!(proto::DESCS_PER_REQUEST * 5 <= VIRTIO_QUEUE_SIZE);

/// Sectors per slot's staging buffer (Kconfig `VIRTIO_BLK_SLOT_KB`): the
/// largest transfer one command carries.
const BLK_DMA_SECTORS: usize = azos_limits::VIRTIO_BLK_SLOT_KB as usize * 1024 / SECTOR_SIZE;
const BLK_DMA_BYTES:   usize = BLK_DMA_SECTORS * SECTOR_SIZE;
const _: () = assert!(BLK_DMA_SECTORS >= 8 && BLK_DMA_BYTES >= proto::DISCARD_SEG_BYTES);

// What a slot runs, for the status mapping and its budget
// (`proto::budget_us`).
use proto::{OP_DATA, OP_DISCARD, OP_FLUSH};

// ---- Request structures (repr(C, packed) to match device ABI) ----

#[repr(C, packed)]
struct BlkReqHdr {
    req_type: u32,
    reserved: u32,
    sector:   u64,
}

// ---- Device state ----

/// What bring-up learned; written once under [`BLK_LOCK`] before `READY` is
/// set and only read after.
struct BlkDev {
    vdev:     VirtioDev,
    /// The DMA domain the device sits in, and the bus address of the first
    /// slot of each static array below (slot `i` is at `base + i * stride`).
    dma:        Dma,
    hdr_bus:    u64,
    status_bus: u64,
    buf_bus:    u64,
    /// Sectors on the medium.
    capacity:  u64,
    readonly:  bool,
    /// `VIRTIO_BLK_F_FLUSH` negotiated: `T_FLUSH` may be sent.
    flush:     bool,
    /// The largest discard in sectors; 0: none.
    discard_max: u32,
    /// Request queues in use, and slots usable (`<= SLOTS`).
    queues:    usize,
    slots:     usize,
    /// Feature word 0 the driver accepted: a reset device must accept the
    /// same again ([`reprogram`]).
    accepted:  u32,
}

static mut BLK_DEV: BlkDev = BlkDev {
    vdev:       VirtioDev::zeroed(),
    dma:        Dma::fallback(),
    hdr_bus:    0,
    status_bus: 0,
    buf_bus:    0,
    capacity:   0,
    readonly:   false,
    flush:      false,
    discard_max: 0,
    queues:     1,
    slots:      1,
    accepted:   0,
};

/// `init_at` completed; the queues are usable.
static READY: AtomicBool = AtomicBool::new(false);
/// Live, being reset after a timeout, or latched dead (resets spent, or a
/// protocol violation): the timeout policy, Kconfig `DEVICE_TIMEOUT_RESETS`.
static RECOVERY: Recovery = Recovery::new(Class::Block, "virtio-blk", azos_limits::DEVICE_TIMEOUT_RESETS as u8);

/// Serialises bring-up and the reads of the device's identity.
static BLK_LOCK: Mutex<()> = Mutex::new(());

/// One lock per request queue: building and submitting a chain, reaping the
/// used ring and freeing a completed chain's descriptors. On SMP two harts
/// doing that on one queue concurrently would corrupt the free-descriptor
/// accounting and race the ring indices. **Never held across the device
/// request** (owner rule F1): a command is submitted under it, and the wait
/// is the request layer's, with none held. The sections are a few hundred
/// instructions with no wait on the device.
static QLOCK: [Mutex<()>; MAXQ] = [const { Mutex::new(()) }; MAXQ];

/// The request queues. Queue `q` is touched only under `QLOCK[q]`.
static mut VQS: [Virtq; MAXQ] = [const { Virtq::zeroed() }; MAXQ];

// ---- DMA staging slots ----
//
// The device is NEVER handed a pointer into caller memory (see the module
// doc). Slot `i` is `BLK_REQ_HDR[i]`, `BLK_DMA_BUF[i]` and `BLK_STATUS[i]`,
// static storage whose lifetime is the lifetime of the kernel.

#[repr(C, align(512))]
struct DmaBuf([u8; BLK_DMA_BYTES]);

/// A header or a status byte alone in its cache line(s): behind a
/// non-coherent device, cleaning or flushing one slot's line must not touch
/// a neighbour's bytes while the device is writing them.
#[repr(C, align(128))]
struct Padded<T>(T);

static mut BLK_REQ_HDR: [Padded<BlkReqHdr>; SLOTS] =
    [const { Padded(BlkReqHdr { req_type: 0, reserved: 0, sector: 0 }) }; SLOTS];
static mut BLK_STATUS:  [Padded<u8>; SLOTS] = [const { Padded(proto::S_PENDING) }; SLOTS];
static mut BLK_DMA_BUF: [DmaBuf; SLOTS] = [const { DmaBuf([0u8; BLK_DMA_BYTES]) }; SLOTS];

const HDR_STRIDE:    u64 = core::mem::size_of::<Padded<BlkReqHdr>>() as u64;
const STATUS_STRIDE: u64 = core::mem::size_of::<Padded<u8>>() as u64;
const BUF_STRIDE:    u64 = core::mem::size_of::<DmaBuf>() as u64;

/// The chain a slot's command is in: its head and descriptors, and what the
/// device will have written. Touched under the slot's queue lock.
#[derive(Clone, Copy)]
struct Chain {
    head:  usize,
    descs: [usize; proto::DESCS_PER_REQUEST],
    n:     usize,
    /// Bytes the device writes into the staging buffer (a read's data).
    read_len: usize,
}

static mut CHAINS: [Chain; SLOTS] =
    [const { Chain { head: usize::MAX, descs: [0; proto::DESCS_PER_REQUEST], n: 0, read_len: 0 } }; SLOTS];

/// Slot ownership: bit `i` set while a command owns slot `i` (from `claim`
/// until `release`).
static SLOT_BUSY: AtomicU32 = AtomicU32::new(0);
/// A command is in the device or finished and not yet released.
static SLOT_INFLIGHT: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
/// The device posted the command's completion (its status byte is in
/// `SLOT_STATUS`).
static SLOT_DONE: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
/// `reap` reported the completion to the layer.
static SLOT_REPORTED: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
static SLOT_STATUS: [AtomicU8; SLOTS] = [const { AtomicU8::new(proto::S_PENDING) }; SLOTS];
static SLOT_OP: [AtomicU8; SLOTS] = [const { AtomicU8::new(OP_DATA) }; SLOTS];
/// Timebase tick at which a command not done is out of its budget.
static SLOT_DEADLINE: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// The stall credit when each slot's command was submitted.
static SLOT_CREDIT: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// The time the guest did not run while commands were in flight: a command's
/// budget is time the device was left to answer, not wall-clock
/// (`StallClock`).
static STALL: StallClock = StallClock::new();

/// Tell [`STALL`] the guest is looking at the device now; says so once per
/// stall. Returns the timebase tick it read.
fn watch() -> u64 {
    let now = azos_drv_sys::timebase::now();
    // Gate canary `blk-stall-canary`: no gap is a stall, the budget is wall-clock.
    let gap = if cfg!(feature = "blk-stall-canary") { u64::MAX } else { STALL_GAP_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000 };
    let credited = STALL.observe(now, gap);
    if credited != 0 {
        azos_drv_sys::kprintln!(
            "[VIRTIO-BLK] guest did not run for {} ms: command budgets extended by that time",
            credited * 1000 / azos_drv_sys::timebase::TIMER_FREQ);
    }
    now
}

/// Take a free slot, those of queue `pref` first. `None`: all taken.
fn slot_take(pref: usize, queues: usize, slots: usize) -> Option<usize> {
    for pass in 0..2 {
        for t in 0..slots {
            if proto::tag_preferred(t, queues, pref) != (pass == 0) {
                continue;
            }
            let bit = 1u32 << t;
            if SLOT_BUSY.fetch_or(bit, Ordering::SeqCst) & bit == 0 {
                return Some(t);
            }
        }
    }
    None
}

fn slot_give(t: usize) {
    SLOT_BUSY.fetch_and(!(1u32 << t), Ordering::SeqCst);
}

// ---- Completion by interrupt (wave 15) ----
//
// The device raises its virtio-mmio line when it posts a used-ring entry.
// Once the kernel has wired that line (`set_irq_mode`, after the interrupt
// controller routes it), the layer's reaper SLEEPS in [`HwQueue::wait`] until
// the line's handler (`irq`) wakes it, instead of spinning on the used rings:
// no CPU is spent waiting, and under `-icount` host disk latency no longer
// turns into guest instructions. The handler only acknowledges the device and
// wakes the waiter by TID (a wake that lands before the waiter blocks is
// stamped and its block returns at once, so none is lost); the waiter reaps
// the rings itself, under the queue locks. Bounded: the layer sleeps one
// slice at a time, and a waiter that cannot block (no scheduler yet,
// interrupts or preemption off: early boot, the panic path) spins.

/// The wired line (`u32::MAX` while polled), and the device's MMIO base for
/// the handler's acknowledge.
static IRQ_LINE: AtomicU32 = AtomicU32::new(u32::MAX);
static IRQ_BASE: AtomicUsize = AtomicUsize::new(0);
/// Interrupts taken / waits that slept (diagnostics, `blk_irq_counts`).
static IRQ_TAKEN: AtomicU32 = AtomicU32::new(0);
static IRQ_SLEPT: AtomicU32 = AtomicU32::new(0);
/// The task asleep in [`HwQueue::wait`] (0: none). The layer lets one task at
/// a time in there.
static WAITER: DeviceWait = DeviceWait::new();
azos_common::ro_hook! {
    /// The kernel's hook: block the caller until woken or `deadline` (timebase
    /// ticks), `false` when it cannot block.
    static BLOCK_FN: fn(u64) -> bool;
}
azos_common::ro_hook! {
    /// The kernel's hook: wake task `tid`.
    static WAKE_FN: fn(u32);
}

/// The virtio-mmio slot `init` found the device in (`usize::MAX`: none).
static FOUND_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);

fn mmio_base() -> Option<usize> {
    let _guard = BLK_LOCK.lock();
    if !READY.load(Ordering::Acquire) { return None; }
    // SAFETY: `READY` is set after bring-up wrote the device; it is only read.
    Some(unsafe { (*(&raw const BLK_DEV)).vdev.base } as usize)
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
    BLOCK_FN.set(block_until);
    WAKE_FN.set(wake);
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

/// Back to polled completions: the interrupt controller refused to enable
/// the line [`set_irq_mode`] named, so no interrupt will come and a wait must
/// poll again instead of sleeping to its deadline.
pub fn irq_mode_off() {
    IRQ_LINE.store(u32::MAX, Ordering::Release);
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
/// device and wake the sleeping waiter, `Some(true)` when there was one.
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
    let Some(wake) = WAKE_FN.get() else {
        return Some(false);
    };
    let tid = WAITER.sleeper();
    if tid != 0 {
        wake(tid);
        return Some(true);
    }
    Some(false)
}

/// Timebase ticks of `ns` nanoseconds.
fn ns_to_ticks(ns: u64) -> u64 {
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    (ns / 1_000_000_000).saturating_mul(f).saturating_add((ns % 1_000_000_000) * f / 1_000_000_000)
}

/// Timebase tick `us` microseconds from now.
fn deadline_after_us(us: u64) -> u64 {
    azos_drv_sys::timebase::now().saturating_add(us * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000)
}

/// `blk-wait-probe` (the `lat-fat` smoke): waits for a completion, and those
/// made with a `Mutex` held that the driver itself took on the way in:
/// `QLOCK` across the device wait, the F1 shape.
#[cfg(feature = "blk-wait-probe")]
static WAITS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "blk-wait-probe")]
static WAITS_LOCKED: AtomicU32 = AtomicU32::new(0);

/// `(waits, waits with a driver Mutex held)`; the second must be 0.
#[cfg(feature = "blk-wait-probe")]
pub fn wait_probe_counts() -> (u32, u32) {
    (WAITS.load(Ordering::Relaxed), WAITS_LOCKED.load(Ordering::Relaxed))
}

#[inline(always)]
fn caller_pi_held() -> u32 {
    #[cfg(feature = "blk-wait-probe")]
    { azos_sync::held::held_by(azos_sync::waitqueue::caller_tid()) }
    #[cfg(not(feature = "blk-wait-probe"))]
    { 0 }
}

// ---- Feature negotiation ----

/// The device-status handshake for this device: reset, ACK, DRIVER, feature
/// negotiation, FEATURES_OK. Same steps and order as `super::init`, which
/// the other virtio drivers use; the difference is feature word 0.
/// `super::init` acknowledges no word-0 feature, and for this device that
/// matters: without `VIRTIO_BLK_F_FLUSH` the driver may not send
/// `VIRTIO_BLK_T_FLUSH` (virtio 1.2 section 5.2.6.2), so nothing the kernel
/// does could make a write durable on a device with a volatile cache.
///
/// Accepted from word 0: `F_FLUSH`, `F_RO` (a read-only medium is refused on
/// the write path instead of failing per request), `F_MQ` when more than one
/// queue may be used, and `F_DISCARD` when discard is compiled in. Word 1:
/// `VIRTIO_F_VERSION_1` on a v2 transport, exactly as `super::init` does.
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
    let mut want = proto::F_FLUSH | proto::F_RO;
    if MAXQ > 1 {
        want |= proto::F_MQ;
    }
    if !azos_limits::BLK_DISCARD_OFF {
        want |= proto::F_DISCARD;
    }
    let accepted = offered & want;
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

// ---- Bring-up ----

/// Bring up the block device whose virtio-mmio transport is at `base`.
///
/// Called by the hardware bus when it binds `virtio-blk` to a device
/// (`kernel/src/boot/hwbus.rs`); the driver serves one device, so a second
/// call is refused while the first is up. `Err` also for a window that is
/// not a block device, a device the driver latched dead, and a device whose
/// handshake fails. The block layer binds it afterwards (`blkdev::init`).
pub fn init_at(base: usize) -> Result<(), ()> {
    let _guard = BLK_LOCK.lock();

    // A driver latched dead keeps its descriptors quarantined. Re-running
    // init would re-arm that same device (DRIVER_OK) while the latch still
    // blocks all I/O -- an inconsistent half-alive state. Refuse instead.
    if RECOVERY.dead() {
        azos_drv_sys::kerr!("[VIRTIO-BLK] init refused: driver latched dead after timeout");
        return Err(());
    }
    // One device: a second init would leak the ring pages (the PMM cannot
    // reclaim them) and reset a live device mid-flight.
    if READY.load(Ordering::Acquire) {
        return Err(());
    }

    // SAFETY: `READY` is clear and `BLK_LOCK` held: nobody else reads the
    // device state, and the queues are not in use.
    let dev = unsafe { &mut *(&raw mut BLK_DEV) };

    kprintln!("[VIRTIO-BLK] Scanning for block devices...");

    let slot = match base.checked_sub(VIRTIO_MMIO_BASE) {
        Some(off) if off % VIRTIO_MMIO_STEP == 0 && off / VIRTIO_MMIO_STEP < VIRTIO_MMIO_COUNT => {
            off / VIRTIO_MMIO_STEP
        }
        _ => {
            kprintln!("[VIRTIO-BLK] No block device found");
            return Err(());
        }
    };
    unsafe {
        if probe(base, &mut dev.vdev).is_ok() && dev.vdev.device_id == VIRTIO_DEV_BLOCK {
            kprintln!("[VIRTIO-BLK] Found block device at {:#x}", base);
            FOUND_SLOT.store(slot, Ordering::Release);
        } else {
            kprintln!("[VIRTIO-BLK] No block device found");
            return Err(());
        }
    }

    unsafe {
        let (offered, accepted) = negotiate(&mut dev.vdev).map_err(|_| {
            azos_drv_sys::kerr!("[VIRTIO-BLK] Failed to initialize VirtIO device");
        })?;

        // Read capacity from device config (offset 0 = uint64 capacity in sectors)
        dev.capacity = read_config64(&dev.vdev, 0);
        dev.accepted = accepted;
        dev.readonly = accepted & proto::F_RO != 0;
        dev.flush    = accepted & proto::F_FLUSH != 0;
        // Two distinct lines so a log tells "the device offered no flush"
        // (nothing the driver can do) from "the driver did not take it".
        if dev.flush {
            kprintln!("[VIRTIO-BLK] flush: negotiated (write cache is volatile until T_FLUSH)");
        } else if offered & proto::F_FLUSH == 0 {
            kprintln!("[VIRTIO-BLK] flush: not offered by the device; a flush reports Unsupported");
        }
        if dev.readonly {
            kprintln!("[VIRTIO-BLK] device is read-only (VIRTIO_BLK_F_RO)");
        }

        let mq = accepted & proto::F_MQ != 0;
        let offered_queues = if mq {
            proto::num_queues_of(read_config32(&dev.vdev, proto::CFG_NUM_QUEUES_WORD))
        } else {
            1
        };
        dev.queues = proto::queues_used(mq, offered_queues, MAXQ, azos_limits::NR_CPUS);
        dev.slots = proto::slots_usable(SLOTS, dev.queues, VIRTIO_QUEUE_SIZE);
        dev.discard_max = if accepted & proto::F_DISCARD != 0 {
            proto::max_discard(
                true,
                read_config32(&dev.vdev, proto::CFG_MAX_DISCARD_SECTORS),
                read_config32(&dev.vdev, proto::CFG_MAX_DISCARD_SEG),
            )
        } else {
            0
        };

        // `capacity` is device-supplied and untrusted: a bogus value near
        // u64::MAX would overflow the byte conversion, and overflow-checks are
        // on in release (panic == board reset). Saturate instead.
        kprintln!("[VIRTIO-BLK] Disk: {} sectors ({} MB), {} of {} queues, {} slots, discard {}",
            dev.capacity,
            dev.capacity.saturating_mul(SECTOR_SIZE as u64) / (1024 * 1024),
            dev.queues, offered_queues, dev.slots,
            if dev.discard_max != 0 { "yes" } else { "no" });

        // The device's DMA domain, and every buffer it will ever touch
        // mapped through it: the request headers (the device reads), the
        // status bytes (it writes) and the staging buffers (both).
        dev.dma = Dma::mmio(base);
        let dma = dev.dma;
        dev.hdr_bus = dma.map(
            (&raw const BLK_REQ_HDR) as *const u8, SLOTS * HDR_STRIDE as usize, Direction::ToDevice)
            .map_err(|_| azos_drv_sys::kerr!("[VIRTIO-BLK] request headers not mappable"))?;
        dev.status_bus = dma.map(
            (&raw const BLK_STATUS) as *const u8, SLOTS * STATUS_STRIDE as usize, Direction::FromDevice)
            .map_err(|_| azos_drv_sys::kerr!("[VIRTIO-BLK] status bytes not mappable"))?;
        dev.buf_bus = dma.map(
            (&raw const BLK_DMA_BUF) as *const u8, SLOTS * BUF_STRIDE as usize, Direction::Bidirectional)
            .map_err(|_| azos_drv_sys::kerr!("[VIRTIO-BLK] staging buffers not mappable"))?;

        // The request queues (queue indices 0..queues).
        for q in 0..dev.queues {
            virtq_init(&mut dev.vdev, q as u32, &mut (*(&raw mut VQS))[q], &dma).map_err(|_| {
                azos_drv_sys::kerr!("[VIRTIO-BLK] Failed to initialize queue {}", q);
            })?;
        }
        dma.enable()?;

        // Mark device as DRIVER_OK
        let s = mmio_read(dev.vdev.base, VIRTIO_MMIO_STATUS);
        mmio_write(dev.vdev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK);
    }

    READY.store(true, Ordering::Release);
    kprintln!("[VIRTIO-BLK] Block device ready");
    Ok(())
}

/// Is the block device the bus bound up? (`BlockDevice::init`: the layer
/// above asks, and a machine with no admitted virtio disk answers no.)
pub fn init() -> Result<(), ()> {
    if READY.load(Ordering::Acquire) { Ok(()) } else { Err(()) }
}

/// True while the driver may submit commands. False before `init_at`, while
/// the device is reset, and forever once it is latched dead.
fn usable() -> bool {
    READY.load(Ordering::Acquire) && RECOVERY.live()
}

// ---- The request queues ----

/// Reset the device and latch the driver dead: the command timed out with
/// the device's resets spent (`latched`: the policy already says dead), or a
/// completion arrived that was never submitted.
///
/// A command may still be owned by the device. VirtIO has no cancel: the
/// chain stays in the ring and the device may post it, and DMA into the
/// header, the staging buffer and the status byte, at any point in the
/// future. Three properties make that late write inert:
///
/// 1. Every buffer in a chain is driver-owned `static` storage, never a
///    caller's memory. A late DMA cannot reach a popped stack frame.
/// 2. The descriptors are deliberately NOT returned to the free list, and
///    the slots are never released (`release` keeps a dead device's slots
///    taken). Recycling them would let the stale completion land on a live
///    chain.
/// 3. The device is reset and the driver latched dead, so nothing ever
///    submits again.
///
/// Reset first (stops the device touching guest memory per spec), then
/// latch. The cost is that block I/O is disabled until reboot: on a
/// safety-critical target, no disk beats silently wrong disk.
fn latch_dead(reason: &str, latched: bool) {
    if !latched && !RECOVERY.latch() {
        return;
    }
    // SAFETY: the transport base was set in bring-up, before `READY`.
    unsafe { mmio_write((*(&raw const BLK_DEV)).vdev.base, VIRTIO_MMIO_STATUS, 0) };
    READY.store(false, Ordering::Release);
    azos_drv_sys::kerr!("[VIRTIO-BLK] Error: {} - device reset, block I/O disabled", reason);
}

/// How long a reset device may take to read back status 0 (virtio 1.2
/// section 2.4.1: the driver waits for it before it touches the queues).
const RESET_WAIT_US: u64 = 100_000;

/// Commands in `late` (a slot bitmap, every one in the device) ran out of
/// their budget at tick `now`. The timeout policy decides: reset the device
/// and program it again over the same rings, or, with the resets spent,
/// latch it dead. The late commands end `Timeout`; a reset ends the others
/// the device held `Reset`. Called by `reap` with no queue lock held.
fn timed_out(late: u32, now: u64) {
    // SAFETY: written once in bring-up.
    let dev = unsafe { &*(&raw const BLK_DEV) };
    let first = late.trailing_zeros() as usize;
    // SAFETY: the slot's command is in the device; its header was written at
    // start and is not written again until the slot is released.
    let sector = unsafe { core::ptr::read_volatile(&raw const BLK_REQ_HDR[first].0.sector) };
    let budget = proto::budget_us(SLOT_OP[first].load(Ordering::Relaxed));
    let waited_ms = budget / 1000 + now.saturating_sub(SLOT_DEADLINE[first].load(Ordering::Relaxed))
        * 1000 / azos_drv_sys::timebase::TIMER_FREQ;
    match RECOVERY.timed_out(sector, waited_ms) {
        Verdict::Reset => {
            azos_drv_sys::kerr!("[VIRTIO-BLK] request timeout at sector {}: resetting the device", sector);
            // SAFETY: the transport base was set in bring-up.
            let base = unsafe { (*(&raw const BLK_DEV)).vdev.base };
            // SAFETY: as above; status 0 resets the device.
            unsafe { mmio_write(base, VIRTIO_MMIO_STATUS, 0) };
            let stopped = wait_us(RESET_WAIT_US, || unsafe { mmio_read(base, VIRTIO_MMIO_STATUS) } == 0);
            let ok = stopped && reprogram(dev, late);
            if !ok {
                // SAFETY: as above.
                unsafe { mmio_write(base, VIRTIO_MMIO_STATUS, 0) };
                READY.store(false, Ordering::Release);
                azos_drv_sys::kerr!("[VIRTIO-BLK] Error: {} - block I/O disabled",
                    if stopped { "the reset device would not program again" } else { "the device did not confirm its reset" });
            } else {
                azos_drv_sys::kprintln!("[VIRTIO-BLK] device reset and programmed again: block I/O resumed");
            }
            RECOVERY.reset_done(ok, sector, waited_ms);
            if !ok {
                mark_late(dev, late);
            }
        }
        Verdict::Latch => {
            latch_dead("request timeout, resets spent", true);
            mark_late(dev, late);
        }
        Verdict::Handled => {}
    }
}

/// The commands in `late` end `Timeout`: their slots stay taken while the
/// driver is dead (`release`).
fn mark_late(dev: &BlkDev, late: u32) {
    for t in 0..dev.slots {
        if late & (1 << t) != 0 {
            SLOT_STATUS[t].store(proto::S_TIMEOUT, Ordering::Relaxed);
            SLOT_DONE[t].store(true, Ordering::Release);
        }
    }
}

/// Spin until `cond` holds or `us` microseconds passed; `cond` is asked once
/// more at the end.
fn wait_us(us: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = deadline_after_us(us);
    while !cond() {
        if azos_drv_sys::timebase::now() >= deadline {
            return cond();
        }
        core::hint::spin_loop();
    }
    true
}

/// The device read back status 0 (it no longer touches the rings or the
/// staging buffers): negotiate again, check it is the same device, give it
/// every request queue over the memory it had, end the commands it held
/// (`late` ones `Timeout`, the others `Reset`), and set DRIVER_OK. Each queue
/// is emptied and its commands ended under its lock, so a `start` either
/// submitted before (and its command is ended here) or finds the device being
/// reset. `false`: the device is not the one that was brought up, or a queue
/// did not program.
fn reprogram(dev: &BlkDev, late: u32) -> bool {
    let mut vdev = dev.vdev;
    // SAFETY: the device is reset and nothing submits to it (the policy says
    // it is being reset; `start` checks that under the queue lock).
    unsafe {
        let Ok((_, accepted)) = negotiate(&mut vdev) else { return false };
        if accepted != dev.accepted || read_config64(&vdev, 0) != dev.capacity {
            azos_drv_sys::kerr!("[VIRTIO-BLK] the reset device offers other features or another size");
            return false;
        }
        for q in 0..dev.queues {
            let _g = QLOCK[q].lock();
            if virtq_reprogram(&vdev, q as u32, &mut (*(&raw mut VQS))[q]).is_err() {
                return false;
            }
            for t in (0..dev.slots).filter(|&t| proto::queue_of(t, dev.queues) == q) {
                if SLOT_INFLIGHT[t].load(Ordering::Acquire) && !SLOT_DONE[t].load(Ordering::Acquire) {
                    let st = if late & (1 << t) != 0 { proto::S_TIMEOUT } else { proto::S_RESET };
                    SLOT_STATUS[t].store(st, Ordering::Relaxed);
                    SLOT_DONE[t].store(true, Ordering::Release);
                }
            }
        }
        let s = mmio_read(vdev.base, VIRTIO_MMIO_STATUS);
        mmio_write(vdev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK);
    }
    true
}

/// Take every completion queue `q` has posted: free the finished chain's
/// descriptors, read its status and mark the slot done. A completion naming no
/// command in flight on this queue is a device not following the protocol (it
/// would make some later command look complete before its DMA happened), so
/// the driver latches dead. Caller holds `QLOCK[q]`.
unsafe fn drain(q: usize) {
    let dev = &*(&raw const BLK_DEV);
    let vq = &mut (*(&raw mut VQS))[q];
    while let Some(id) = virtq_poll(vq) {
        let found = (0..dev.slots).find(|&t| {
            proto::queue_of(t, dev.queues) == q
                && SLOT_INFLIGHT[t].load(Ordering::Relaxed)
                && !SLOT_DONE[t].load(Ordering::Relaxed)
                && (*(&raw const CHAINS))[t].head == id
        });
        let Some(t) = found else {
            latch_dead("foreign completion id", false);
            return;
        };
        let ch = (*(&raw const CHAINS))[t];
        for &d in &ch.descs[..ch.n] {
            virtq_free_desc(vq, d);
        }
        // Behind a non-coherent device, drop the CPU's lines over what the
        // device wrote: the status byte, and the data of a read.
        dev.dma.sync_for_cpu((&raw const BLK_STATUS[t]) as *const u8, 1, Direction::FromDevice);
        if ch.read_len != 0 {
            dev.dma.sync_for_cpu((&raw const BLK_DMA_BUF[t]) as *const u8, ch.read_len, Direction::FromDevice);
        }
        // The status byte was written by the device via DMA; read it volatile
        // so the sentinel store at submit cannot be constant-propagated into
        // the comparison. (Ordering: the acquire fence in `virtq_poll` sits
        // between observing the used index and this read.)
        let st = core::ptr::read_volatile(&raw const BLK_STATUS[t].0);
        SLOT_STATUS[t].store(st, Ordering::Relaxed);
        SLOT_DONE[t].store(true, Ordering::Release);
    }
}

/// The device has answered a discard (`hw_status` says how, once per boot).
static DISCARD_ANSWERED: AtomicBool = AtomicBool::new(false);

/// Map the device's status byte of a finished command to what the layer is
/// told.
fn hw_status(op: u8, st: u8) -> HwStatus {
    let s = proto::status_of(op == OP_DATA, st);
    if s == HwStatus::Io {
        azos_drv_sys::kerr!("[VIRTIO-BLK] Error: status {}", st);
    }
    // The first discard's answer, once: a device that refuses the command
    // switches the file system's discard off without a word otherwise.
    if op == OP_DISCARD && s != HwStatus::Io && !DISCARD_ANSWERED.swap(true, Ordering::Relaxed) {
        if s == HwStatus::Ok {
            azos_drv_sys::kprintln!("[VIRTIO-BLK] discard: the device took the first one");
        } else {
            azos_drv_sys::kwarn!("[VIRTIO-BLK] discard: the device refused the first one (status {})", st);
        }
    }
    s
}

/// The device as the request layer drives it.
pub struct VirtioBlk;

/// The one virtio-blk device, for `queue::bind` (`blkdev::init`).
pub static VIRTIO_BLK: VirtioBlk = VirtioBlk;

impl HwQueue for VirtioBlk {
    fn caps(&self) -> HwCaps {
        // SAFETY: written once in bring-up, before `READY`; the layer asks
        // after `blkdev::init` found the device ready.
        let dev = unsafe { &*(&raw const BLK_DEV) };
        HwCaps {
            sectors: dev.capacity,
            max_sectors: BLK_DMA_SECTORS as u32,
            max_discard_sectors: dev.discard_max,
            fua: false,
        }
    }

    fn cpu(&self) -> usize {
        azos_arch::Cpu::hart_id(&azos_arch::ARCH)
    }

    fn claim(&self) -> Claim {
        if RECOVERY.resetting() {
            return Claim::Busy;
        }
        if !usable() {
            return Claim::Dead;
        }
        // SAFETY: written once in bring-up.
        let dev = unsafe { &*(&raw const BLK_DEV) };
        match slot_take(proto::queue_of(self.cpu(), dev.queues), dev.queues, dev.slots) {
            Some(t) => Claim::Tag(t as u8),
            None => Claim::Busy,
        }
    }

    fn start(&self, tag: u8, cmd: &HwCmd<'_>) -> Result<(), ()> {
        let t = tag as usize;
        // SAFETY: written once in bring-up.
        let dev = unsafe { &*(&raw const BLK_DEV) };
        // No FUA on this device: the layer does not send it (`HwCaps::fua`).
        if t >= dev.slots || !READY.load(Ordering::Acquire) || RECOVERY.dead() || cmd.fua {
            return Err(());
        }
        // The request type, what the slot runs, the header's sector, the data
        // descriptor (bytes, and whether the device writes them) and the
        // budget.
        let (rtype, op, sector, data, budget): (u32, u8, u64, Option<(usize, bool)>, u64) = match cmd.op {
            HwOp::Read | HwOp::Write => {
                let write = cmd.op == HwOp::Write;
                let bytes = cmd.sectors as usize * SECTOR_SIZE;
                let end = cmd.lba.checked_add(cmd.sectors as u64).ok_or(())?;
                if cmd.sectors == 0 || cmd.sectors as usize > BLK_DMA_SECTORS || end > dev.capacity
                    || (write && (dev.readonly || cmd.segs.iter().map(|s| s.len()).sum::<usize>() != bytes))
                {
                    return Err(());
                }
                if write {
                    // SAFETY: the slot is this caller's (`claim`), and its
                    // previous command, if any, completed: the device does not
                    // own the staging buffer. `bytes <= BLK_DMA_BYTES`.
                    let mut off = 0;
                    for s in cmd.segs {
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                s.as_ptr(), ((&raw mut BLK_DMA_BUF[t]) as *mut u8).add(off), s.len());
                        }
                        off += s.len();
                    }
                }
                (if write { proto::T_OUT } else { proto::T_IN }, OP_DATA, cmd.lba,
                 Some((bytes, !write)), proto::budget_us(OP_DATA))
            }
            HwOp::Flush => {
                if !dev.flush {
                    // A device that offered no flush is never sent one
                    // (virtio 1.2 section 5.2.6.2): the command ends at once
                    // as the device's "I have no such command".
                    SLOT_OP[t].store(OP_FLUSH, Ordering::Relaxed);
                    SLOT_STATUS[t].store(proto::S_UNSUPP, Ordering::Relaxed);
                    SLOT_REPORTED[t].store(false, Ordering::Relaxed);
                    SLOT_DONE[t].store(true, Ordering::Relaxed);
                    SLOT_INFLIGHT[t].store(true, Ordering::Release);
                    return Ok(());
                }
                (proto::T_FLUSH, OP_FLUSH, 0, None, proto::budget_us(OP_FLUSH))
            }
            HwOp::Discard => {
                let end = cmd.lba.checked_add(cmd.sectors as u64).ok_or(())?;
                if dev.discard_max == 0 || cmd.sectors == 0 || cmd.sectors > dev.discard_max
                    || end > dev.capacity || dev.readonly
                {
                    return Err(());
                }
                let seg = proto::discard_segment(cmd.lba, cmd.sectors);
                // Gate canary `blk-discard-unmap-canary`: the segment carries
                // `unmap` again, which the device must refuse.
                #[cfg(feature = "blk-discard-unmap-canary")]
                let seg = { let mut s = seg; s[12] = 1; s };
                // SAFETY: as for a write's staging copy; the segment is 16 bytes.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        seg.as_ptr(), (&raw mut BLK_DMA_BUF[t]) as *mut u8, proto::DISCARD_SEG_BYTES);
                }
                // The segment is the data descriptor; the header's sector is
                // unused for a discard.
                (proto::T_DISCARD, OP_DISCARD, 0, Some((proto::DISCARD_SEG_BYTES, false)),
                 proto::budget_us(OP_DISCARD))
            }
        };

        let q = proto::queue_of(t, dev.queues);
        let _g = QLOCK[q].lock();
        // SAFETY: `QLOCK[q]` is held; the slot is this caller's.
        unsafe {
            let vq = &mut (*(&raw mut VQS))[q];
            // A queue that was never set up would be a null deref below, and
            // `virtq_submit` divides by `vq.num`.
            if !READY.load(Ordering::Acquire) || RECOVERY.dead() || vq.desc.is_null() || vq.num == 0 {
                return Err(());
            }
            if RECOVERY.resetting() {
                // Claimed before the reset began: the device is being reset
                // and programmed again, so the command ends at once as one
                // the reset abandoned.
                SLOT_OP[t].store(op, Ordering::Relaxed);
                SLOT_STATUS[t].store(proto::S_RESET, Ordering::Relaxed);
                SLOT_REPORTED[t].store(false, Ordering::Relaxed);
                SLOT_DONE[t].store(true, Ordering::Relaxed);
                SLOT_INFLIGHT[t].store(true, Ordering::Release);
                return Ok(());
            }
            // Anything the device posted is taken first: a completion naming no
            // command in flight latches the driver dead here, before this one
            // could be mistaken for complete.
            drain(q);
            if !RECOVERY.live() {
                return Err(());
            }

            BLK_REQ_HDR[t].0.req_type = rtype;
            BLK_REQ_HDR[t].0.reserved = 0;
            BLK_REQ_HDR[t].0.sector   = sector;
            BLK_STATUS[t].0           = proto::S_PENDING;

            // Descriptors: [header] -> [data]? -> [status]. The queue holds
            // `DESCS_PER_REQUEST` per slot it serves (`slots_usable`), so this
            // does not fail while the driver is alive.
            let mut descs = [0usize; proto::DESCS_PER_REQUEST];
            let n = if data.is_some() { 3 } else { 2 };
            for i in 0..n {
                match virtq_alloc_desc(vq) {
                    Some(d) => descs[i] = d,
                    None => {
                        for &d in &descs[..i] {
                            virtq_free_desc(vq, d);
                        }
                        return Err(());
                    }
                }
            }
            let (d_hdr, d_status) = (descs[0], descs[n - 1]);

            let dma = dev.dma;
            // Behind a non-coherent device the header and the sentinel status
            // go out to RAM, and the staging buffer is handed over: cleaned
            // when the device reads it, flushed for a read (the device writes
            // it, and no stale line may be written back over what it stores).
            dma.sync_for_device((&raw const BLK_REQ_HDR[t]) as *const u8,
                core::mem::size_of::<BlkReqHdr>(), Direction::ToDevice);
            dma.sync_for_device((&raw const BLK_STATUS[t]) as *const u8, 1, Direction::FromDevice);

            // Descriptor 0: request header (device reads)
            let p = vq.desc.add(d_hdr);
            (*p).addr  = dev.hdr_bus + t as u64 * HDR_STRIDE;
            (*p).len   = core::mem::size_of::<BlkReqHdr>() as u32;
            (*p).flags = VIRTQ_DESC_F_NEXT;
            (*p).next  = descs[1] as u16;

            let mut read_len = 0;
            if let Some((len, dev_writes)) = data {
                dma.sync_for_device((&raw const BLK_DMA_BUF[t]) as *const u8, len,
                    if dev_writes { Direction::FromDevice } else { Direction::ToDevice });
                // Descriptor 1: data, the slot's driver-owned staging area.
                let p = vq.desc.add(descs[1]);
                (*p).addr  = dev.buf_bus + t as u64 * BUF_STRIDE;
                (*p).len   = len as u32;
                (*p).flags = VIRTQ_DESC_F_NEXT | if dev_writes { VIRTQ_DESC_F_WRITE } else { 0 };
                (*p).next  = d_status as u16;
                if dev_writes {
                    read_len = len;
                }
            }

            // Last descriptor: status byte (device writes)
            let p = vq.desc.add(d_status);
            (*p).addr  = dev.status_bus + t as u64 * STATUS_STRIDE;
            (*p).len   = 1;
            (*p).flags = VIRTQ_DESC_F_WRITE;
            (*p).next  = 0;

            (*(&raw mut CHAINS))[t] = Chain { head: d_hdr, descs, n, read_len };
            SLOT_OP[t].store(op, Ordering::Relaxed);
            SLOT_STATUS[t].store(proto::S_PENDING, Ordering::Relaxed);
            // The look before the credit is read: the slot's baseline already
            // holds any stall that ended just now.
            watch();
            SLOT_CREDIT[t].store(STALL.credit(), Ordering::Relaxed);
            SLOT_DEADLINE[t].store(deadline_after_us(budget), Ordering::Relaxed);
            SLOT_DONE[t].store(false, Ordering::Relaxed);
            SLOT_REPORTED[t].store(false, Ordering::Relaxed);
            SLOT_INFLIGHT[t].store(true, Ordering::Release);

            virtq_submit(&dev.vdev, q as u32, d_hdr, vq);
        }
        Ok(())
    }

    fn reap(&self, out: &mut [HwDone; HW_TAGS_MAX]) -> usize {
        // SAFETY: written once in bring-up.
        let dev = unsafe { &*(&raw const BLK_DEV) };
        for q in 0..dev.queues {
            let _g = QLOCK[q].lock();
            // SAFETY: `QLOCK[q]` is held.
            unsafe { drain(q) };
        }
        let now = watch();
        // Out of budget first: a reset then ends every command the device
        // held, and the loop below reports them.
        if RECOVERY.live() {
            let late = (0..dev.slots)
                .filter(|&t| {
                    SLOT_INFLIGHT[t].load(Ordering::Acquire)
                        && !SLOT_DONE[t].load(Ordering::Acquire)
                        && STALL.expired(now, SLOT_DEADLINE[t].load(Ordering::Relaxed), SLOT_CREDIT[t].load(Ordering::Relaxed))
                })
                .fold(0u32, |m, t| m | 1 << t);
            if late != 0 {
                timed_out(late, now);
            }
        }
        let dead = RECOVERY.dead();
        let mut n = 0;
        for t in 0..dev.slots {
            if !SLOT_INFLIGHT[t].load(Ordering::Acquire) || SLOT_REPORTED[t].load(Ordering::Relaxed) {
                continue;
            }
            let status = if SLOT_DONE[t].load(Ordering::Acquire) {
                hw_status(SLOT_OP[t].load(Ordering::Relaxed), SLOT_STATUS[t].load(Ordering::Relaxed))
            } else if dead {
                // The device died with this command in it: no data to trust.
                HwStatus::Io
            } else {
                continue;
            };
            SLOT_REPORTED[t].store(true, Ordering::Relaxed);
            out[n] = HwDone { tag: t as u8, status };
            n += 1;
        }
        n
    }

    fn copy_out(&self, tag: u8, off: usize, dst: &mut [u8]) {
        let t = tag as usize;
        if t >= SLOTS || off.checked_add(dst.len()).map_or(true, |e| e > BLK_DMA_BYTES) {
            return;
        }
        // SAFETY: the device posted this slot's completion (`drain`
        // synchronised the buffer for the CPU), so it is done with the staging
        // buffer; the slot is still the caller's until `release`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                ((&raw const BLK_DMA_BUF[t]) as *const u8).add(off), dst.as_mut_ptr(), dst.len());
        }
    }

    fn release(&self, tag: u8) {
        let t = tag as usize;
        if RECOVERY.dead() {
            // The device is dead: a command it could not recall may still be
            // writing to this slot's buffers. The slot stays taken for good.
            // (A reset that brought it back confirmed its stop first: the
            // slots of the commands it ended are free again.)
            return;
        }
        SLOT_INFLIGHT[t].store(false, Ordering::Release);
        slot_give(t);
    }

    fn wait(&self, until_ns: u64) -> bool {
        // Lockdep (N1): the device wait, with nothing spinning held under it.
        azos_sync::lockdep::might_wait_device("virtio-blk wait");
        #[cfg(feature = "blk-wait-probe")]
        WAITS.fetch_add(1, Ordering::Relaxed);
        let base_held = caller_pi_held();
        // Gate canary: the pre-F1 shape, a driver lock held across the whole
        // wait; `blk-wait-probe` must count it.
        let canary = if cfg!(feature = "blk-lock-wait-canary") { Some(QLOCK[0].lock()) } else { None };
        #[cfg(feature = "blk-wait-probe")]
        if caller_pi_held() > base_held {
            WAITS_LOCKED.fetch_add(1, Ordering::Relaxed);
        }
        let _ = base_held;

        if !irq_mode() {
            return false;
        }
        let tid = azos_sync::waitqueue::caller_tid();
        let Some(f) = BLOCK_FN.get().filter(|_| tid != 0 && tid != u32::MAX) else {
            return false;
        };
        // Re-check after listing the waiter: a completion posted before the
        // listing raised its interrupt before anyone could be woken.
        let slept = WAITER.park(
            tid,
            || !RECOVERY.live() || completions_pending(canary.is_some()),
            || {
                let s = f(ns_to_ticks(until_ns));
                if s {
                    IRQ_SLEPT.fetch_add(1, Ordering::Relaxed);
                }
                s
            },
        );
        drop(canary);
        slept
    }
}

/// Has the device finished a command the layer has not been told about? Takes
/// the completions off the used rings to see (`reap` finds them marked).
/// `held`: queue 0's lock is already this task's (the lock-across-wait
/// canary).
fn completions_pending(held: bool) -> bool {
    // SAFETY: written once in bring-up.
    let dev = unsafe { &*(&raw const BLK_DEV) };
    for q in 0..dev.queues {
        if held && q == 0 {
            // SAFETY: the canary holds `QLOCK[0]`.
            unsafe { drain(q) };
        } else {
            let _g = QLOCK[q].lock();
            // SAFETY: `QLOCK[q]` is held.
            unsafe { drain(q) };
        }
    }
    (0..dev.slots).any(|t| {
        SLOT_INFLIGHT[t].load(Ordering::Acquire)
            && SLOT_DONE[t].load(Ordering::Acquire)
            && !SLOT_REPORTED[t].load(Ordering::Relaxed)
    })
}
