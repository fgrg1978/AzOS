// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! NVMe block driver (Kconfig `DRV_NVME`, cargo feature `nvme`).
//!
//! The wire protocol (register layout, doorbell and ring arithmetic, SQE/CQE
//! encoding, PRP lists, Identify decoding) lives in `azos_nvme` and is
//! host-tested; this file owns the device: BAR mapping, the admin and I/O
//! queues in page-allocator memory, the staging slots, the interrupts, and the
//! [`BlockDevice`](azos_drv_api::block::BlockDevice) entry points
//! `blkdev` forwards to when [`active`].
//!
//! # Shape
//!
//! This file is the NVMe driver's half of the block request layer
//! (`queue.rs`): it implements [`HwQueue`](crate::queue::HwQueue) for the
//! controller and binds it at [`attach`]. The layer owns the queueing, the
//! merging and the waiting; this file owns the device.
//!
//! * **Bring-up** ([`attach`]): runs from `kernel_main` after PCI
//!   enumeration and before `blkdev::init`. Maps the BARs, routes the MSI-X
//!   vectors where the machine has a route (0: admin, `q`: I/O queue `q`),
//!   resets the controller, programs the admin queue pair, enables it,
//!   identifies the controller and namespace 1, asks for the I/O queue pairs
//!   and creates the ones the controller grants. The admin queue is used only
//!   here, polled, single-threaded.
//! * **One I/O queue pair per CPU** (Kconfig `NVME_QUEUES`: at most one per
//!   CPU, per command slot, per pair the controller grants and per vector the
//!   machine can route). Command slot `t` is on queue `t mod queues`;
//!   [`HwQueue::claim`] gives a CPU the slots of its own queue first, so two
//!   CPUs submit to two submission queues, each behind its own lock
//!   ([`QLOCK`]) held for bookkeeping only (publish a command, drain the
//!   completion queue) and never across a device wait (owner rule F1). Queue
//!   `q` has MSI-X vector `q`, which a [`QueueRoute`] delivers to the CPU of
//!   the same number where the interrupt controller can (each hart's IMSIC
//!   file, each CPU's local APIC). The interrupt only wakes the one reaper
//!   ([`WAITER`]); whoever reaps drains every queue. A command runs on
//!   another CPU's queue when its own has no free slot: the slot, not the
//!   CPU, names the queue. Queue `q`'s interrupt is raised on CPU `q` only
//!   while that CPU runs (one that never started, or went offline, has none),
//!   so [`HwQueue::claim`] takes slots of queues whose CPU runs before the
//!   others (`nvme_route::slot_rank`); a command on the others still
//!   completes, noticed by the request layer's reap at the end of its slice.
//! * **Staging slots are the command tags.** Each command in flight owns a
//!   slot: `SLOT_PAGES` separate 4 KiB pages of bounce buffer and one PRP-list
//!   page. The device is never handed caller memory (a command cannot be
//!   recalled, and a caller buffer is often a popped stack frame). A write's
//!   segments are copied in at `start`, a read's data out at `copy_out`. The
//!   pages need not be contiguous: that is what the PRP list is for, and a
//!   command of more than two pages exercises it on every use. A slot is
//!   `claim`ed (a bit of [`SLOT_BUSY`]), `start`ed, reported by `reap` and
//!   `release`d; the request layer starts up to `NVME_INFLIGHT` commands
//!   before the first is reaped. The slot is also the command identifier, so
//!   a completion names its slot and, by `t mod queues`, the queue it must
//!   have come from.
//! * **Completion.** By MSI-X where a route exists: the one task the request
//!   layer lets sleep in the device ([`HwQueue::wait`]) is woken by
//!   [`msi_irq`], bounded by a slice. Without a route, or before the scheduler
//!   exists, the layer spins and `reap` polls the completion queues' phase
//!   tags. Whoever reaps does so under the queue's lock.
//! * **A timeout resets the controller once.** A command that misses its
//!   deadline disables the controller (`CC.EN = 0`, which stops its DMA on
//!   every queue), waits for `CSTS.RDY` to drop, and brings it up again over
//!   the same pages: the admin queue, the queue count, every I/O queue pair
//!   (`azos_drv_api::recovery`, Kconfig `DEVICE_TIMEOUT_RESETS`). The late
//!   command ends `Timeout`, the others the controller held `Reset`, and
//!   their slots are reused. The next timeout, a controller that does not
//!   come back, or a completion naming no command in flight on its queue
//!   latches the driver failed until reboot, as `virtio::blk` does: no disk
//!   beats silently wrong disk. `reap` then reports every command still in
//!   the device as failed, without copying anything, and their slots are
//!   never reused.
//! * **FUA, Flush, Dataset Management.** Force Unit Access is a bit of the
//!   Write command, so it is native. A Flush the controller answers
//!   `Invalid Opcode` (no volatile cache) is reported `Unsupported`, which the
//!   layer treats as nothing-to-flush for a `PREFLUSH` and refuses to call
//!   durable for an explicit flush. Discard is a Dataset Management
//!   deallocate of one range, offered only where `ONCS` says the controller
//!   has the command.
//!
//! DMA coherence is assumed (QEMU, and the coherent PCIe hosts this tree
//! targets), as it is for the virtio drivers.

use crate::queue::{Claim, HwCaps, HwCmd, HwDone, HwOp, HwQueue, HwStatus, HW_TAGS_MAX};
use azos_drv_api::block::{DeviceWait, StallClock, STALL_GAP_US};
use azos_drv_api::recovery::{Class, Recovery, Verdict};
use azos_drv_sys::kprintln;
use azos_drv_virtio::virtio::blk_proto::queue_of;
use azos_drv_virtio::virtio::pci::msix_selftest::{map_bars, KernelBar, MsiRoute, SelftestError};
use crate::nvme_route::{self as route_math, qid_of, CpuVectors, MAXQ, VEC_ADMIN};
pub use crate::nvme_route::{PerCpuRoute, QueueRoute};

/// Every single-CPU MSI route (an IMSIC file's identities, a local APIC's
/// vectors) is a CPU's vectors.
impl<R: MsiRoute> CpuVectors for R {
    fn prepare(&mut self, n: u16) -> bool {
        MsiRoute::prepare(self, n)
    }
    fn target(&self, vec: u16) -> (u64, u32) {
        MsiRoute::target(self, vec)
    }
    fn isr_token(&self, vec: u16) -> u32 {
        MsiRoute::isr_token(self, vec)
    }
}
use azos_nvme as proto;
use azos_pci::{BarWindow, ConfigSpace, FunctionInfo};
use azos_sync::kmutex::Mutex;
use core::sync::atomic::{fence, AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

const SECTOR_SIZE: usize = 512;
const PAGE: usize = proto::PAGE_SIZE;

/// Commands in flight at once (Kconfig `NVME_INFLIGHT`).
const SLOTS: usize = azos_limits::NVME_INFLIGHT as usize;
/// Bounce pages per slot (Kconfig `NVME_SLOT_KB`).
const SLOT_PAGES: usize = azos_limits::NVME_SLOT_KB as usize * 1024 / PAGE;
/// Entries of the I/O queues (Kconfig `NVME_QUEUE_DEPTH`).
const IO_DEPTH: u16 = azos_limits::NVME_QUEUE_DEPTH as u16;
const ADMIN_DEPTH: u16 = 8;
const _: () = assert!(SLOTS >= 1 && SLOTS <= HW_TAGS_MAX && SLOTS < IO_DEPTH as usize);
const _: () = assert!(MAXQ >= 1 && MAXQ <= 8);
const _: () = assert!(SLOT_PAGES >= 1 && SLOT_PAGES <= 32);
// One 4 KiB page holds the whole submission queue (64 B entries).
const _: () = assert!(IO_DEPTH as usize * proto::SQE_BYTES <= PAGE);
// A PRP list page holds PAGE / 8 entries; a slot needs SLOT_PAGES - 1.
const _: () = assert!(SLOT_PAGES - 1 <= PAGE / 8);

/// Pages taken from the page allocator at bring-up: admin SQ and CQ, the SQ
/// and CQ of every I/O queue pair, and for every slot its bounce pages and
/// its PRP list.
const MAX_PAGES: usize = 2 + 2 * MAXQ + SLOTS * (SLOT_PAGES + 1);

const NSID: u32 = 1;

/// Budget for one admin command, and for a command on the I/O queue. Both
/// bound a DEAD controller, not a slow one (`virtio::blk` uses 500 ms the
/// same way); a flush writes the whole volatile cache back, so it gets four
/// times as much. The I/O budget is enforced by `reap`: the request layer
/// reaps at least once per slice while anything waits.
const ADMIN_TIMEOUT_US: u64 = 1_000_000;
const IO_TIMEOUT_US: u64 = 500_000;
const FLUSH_TIMEOUT_US: u64 = 4 * IO_TIMEOUT_US;

/// Sectors one Dataset Management range deallocates (a request of the layer is
/// one range). 32 MiB: under the Range Size Limit controllers report where
/// they report one, and a larger discard is several commands in flight.
const DSM_RANGE_MAX_SECTORS: u32 = 65536;

/// Why [`attach`] did not bring the controller up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NvmeError {
    /// Not class 01:08:02, or already attached.
    NotNvme,
    AlreadyUp,
    Bars(SelftestError),
    /// BAR 0 is not a memory BAR.
    NoRegisters,
    /// `CAP` says no NVM command set or no 4 KiB page support.
    Capabilities,
    /// `CSTS.RDY` did not follow `CC.EN` in time, or `CSTS.CFS` came up.
    Timeout,
    NoMemory,
    /// An admin command failed (named) or timed out.
    Admin(&'static str),
    /// Namespace 1 is empty, or not 512-byte blocks without metadata.
    Format,
}

/// One controller: what bring-up decides and nothing after it changes (the
/// queues' moving parts are [`Queue`], behind [`QLOCK`]; whether the driver is
/// up is [`READY`] and [`RECOVERY`]). The admin cursors are used by bring-up
/// and by a reset, each on its own copy.
#[derive(Clone, Copy)]
struct Dev {
    /// CPU address of BAR 0 (the registers).
    bar: usize,
    dstrd: u32,
    capacity: u64,
    vwc: bool,
    /// The controller implements Dataset Management (`ONCS` bit 2).
    discard: bool,
    /// RTD3 Entry Latency from Identify (microseconds, 0 = not reported):
    /// how long [`shutdown`] may wait for `CSTS.SHST`.
    rtd3e_us: u32,
    /// Sectors one command carries: slot size, MDTS, 65536 (NLB is 16 bits).
    max_sectors: u32,
    /// Admin queue memory: CPU address and device (physical) address.
    asq: usize,
    asq_pa: u64,
    acq: usize,
    acq_pa: u64,
    a_tail: u16,
    a_cq: proto::CqCursor,
    a_cid: u16,
    /// I/O queue pairs created (`1..=MAXQ`).
    queues: usize,
    /// MSI-X routed (completions raise the queues' vectors).
    irq: bool,
    /// Queue `q`'s vector lands on CPU `q` (`QueueRoute::per_cpu`), so it is
    /// raised only while that CPU runs.
    per_cpu: bool,
    /// `CAP.TO`: how long `CSTS.RDY` may take to follow `CC.EN`.
    ready_ms: u64,
}

const DEV_ZERO: Dev = Dev {
    bar: 0,
    dstrd: 0,
    capacity: 0,
    vwc: false,
    discard: false,
    rtd3e_us: 0,
    max_sectors: 0,
    asq: 0,
    asq_pa: 0,
    acq: 0,
    acq_pa: 0,
    a_tail: 0,
    a_cq: proto::CqCursor::new(),
    a_cid: 0,
    queues: 1,
    irq: false,
    per_cpu: false,
    ready_ms: 0,
};

static mut DEV: Dev = DEV_ZERO;

/// One I/O queue pair. Its fields change at runtime and are behind the
/// pair's [`QLOCK`].
struct Queue {
    /// CPU and device addresses of the submission and completion queue pages.
    sq: usize,
    cq: usize,
    sq_pa: u64,
    cq_pa: u64,
    /// Next free entry of the submission queue.
    tail: u16,
    /// The controller's submission head, from the last completion.
    sq_head: u16,
    cur: proto::CqCursor,
}

const QUEUE_ZERO: Queue = Queue { sq: 0, cq: 0, sq_pa: 0, cq_pa: 0, tail: 0, sq_head: 0, cur: proto::CqCursor::new() };

static mut QUEUES: [Queue; MAXQ] = [QUEUE_ZERO; MAXQ];

/// Serializes queue `i`'s state: building and publishing an SQE, reaping its
/// completion queue. Never held across the device wait, and never two at once.
static QLOCK: [Mutex<()>; MAXQ] = [const { Mutex::new(()) }; MAXQ];

/// Set once the controller is up; `blkdev` routes here when true.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The controller is enabled and accepts commands (set at the end of
/// bring-up, cleared by a failed bring-up or by [`latch_dead`]).
static READY: AtomicBool = AtomicBool::new(false);
/// Live, being reset after a timeout, or latched dead until reboot (the
/// timeout policy, Kconfig `DEVICE_TIMEOUT_RESETS`; [`latch_dead`]).
static RECOVERY: Recovery = Recovery::new(Class::Block, "nvme", azos_limits::DEVICE_TIMEOUT_RESETS as u8);

// ---- Staging slots ----

static mut ALLOCATED: [usize; MAX_PAGES] = [0; MAX_PAGES];
static mut ALLOCATED_N: usize = 0;
/// Slot `i`'s bounce pages: CPU and device addresses.
static mut SLOT_VA: [[usize; SLOT_PAGES]; SLOTS] = [[0; SLOT_PAGES]; SLOTS];
static mut SLOT_PA: [[u64; SLOT_PAGES]; SLOTS] = [[0; SLOT_PAGES]; SLOTS];
/// Slot `i`'s PRP list page.
static mut LIST_VA: [usize; SLOTS] = [0; SLOTS];
static mut LIST_PA: [u64; SLOTS] = [0; SLOTS];

/// Slot `i` holds a started command (set at start, cleared at release).
static SLOT_INFLIGHT: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
/// Slot `i`'s completion was drained from the completion queue.
static SLOT_DONE: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
/// Slot `i`'s completion (or death) was handed to the request layer.
static SLOT_REPORTED: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
static SLOT_STATUS: [AtomicU16; SLOTS] = [const { AtomicU16::new(0) }; SLOTS];
/// Slot `i`'s first sector (for the timeout record).
static SLOT_LBA: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// What slot `i` runs: [`OP_DATA`], [`OP_FLUSH`] or [`OP_DISCARD`].
static SLOT_OP: [AtomicU8; SLOTS] = [const { AtomicU8::new(0) }; SLOTS];
/// Timebase tick by which slot `i`'s command must have completed.
static SLOT_DEADLINE: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// The stall credit when slot `i`'s command was submitted.
static SLOT_CREDIT: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
/// The time the guest did not run while commands were in flight: a command's
/// budget is time the controller was left to answer, not wall-clock
/// (`StallClock`).
static STALL: StallClock = StallClock::new();

const OP_DATA: u8 = 0;
const OP_FLUSH: u8 = 1;
const OP_DISCARD: u8 = 2;

/// Driver-side marks in [`SLOT_STATUS`], outside the 11 bits a completion's
/// status has: the command's budget ran out, or the controller was reset
/// with it in (another command's budget ran out).
const ST_TIMEOUT: u16 = 0xFFFF;
const ST_RESET: u16 = 0xFFFE;

/// Bit `i` set while a command owns slot `i`; claimed with `fetch_or`.
static SLOT_BUSY: AtomicU32 = AtomicU32::new(0);

/// Take a free slot: those of queue `pref` first, then those of the other
/// queues whose interrupt somebody takes (`served`), then the rest, which only
/// polling completes (`route_math::slot_rank`). Slot `t` is on queue
/// `t mod queues`. `None` when every one is in use.
fn slot_take(pref: usize, queues: usize, served: u32) -> Option<usize> {
    for pass in 0..3 {
        for t in 0..SLOTS {
            if route_math::slot_rank(t, queues, pref, served) != pass {
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

fn slot_give(slot: usize) {
    SLOT_BUSY.fetch_and(!(1u32 << slot), Ordering::SeqCst);
}

// ---- Registers and barriers ----

/// Order the writes to queue memory before the doorbell write that tells
/// the controller to read them. `fence w,o` / `dsb st` order a memory write
/// before a device write, which the portable fences do not promise.
#[inline(always)]
fn io_wmb() {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: a fence has no operands and no effect beyond ordering.
    unsafe {
        core::arch::asm!("fence w, o", options(nostack))
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("dsb st", options(nostack))
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    fence(Ordering::SeqCst);
}

#[inline(always)]
fn rd32(bar: usize, off: usize) -> u32 {
    // SAFETY: `bar` is BAR 0 mapped by `map_bars`; `off` is a register
    // offset of the NVMe register map, inside it.
    unsafe { core::ptr::read_volatile((bar + off) as *const u32) }
}

#[inline(always)]
fn wr32(bar: usize, off: usize, val: u32) {
    // SAFETY: as `rd32`.
    unsafe { core::ptr::write_volatile((bar + off) as *mut u32, val) }
}

/// A 64-bit register as two 32-bit accesses (low dword first), which every
/// controller must accept.
fn rd64(bar: usize, off: usize) -> u64 {
    rd32(bar, off) as u64 | (rd32(bar, off + 4) as u64) << 32
}

fn wr64(bar: usize, off: usize, val: u64) {
    wr32(bar, off, val as u32);
    wr32(bar, off + 4, (val >> 32) as u32);
}

fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

/// Tell [`STALL`] the guest is looking at the controller now; says so once per
/// stall. Returns the timebase tick it read.
fn watch() -> u64 {
    let t = now();
    let credited = STALL.observe(t, STALL_GAP_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000);
    if credited != 0 {
        azos_drv_sys::kprintln!(
            "[NVME] guest did not run for {} ms: command budgets extended by that time",
            credited * 1000 / azos_drv_sys::timebase::TIMER_FREQ);
    }
    t
}

fn deadline_after_us(us: u64) -> u64 {
    now().saturating_add(us.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000)
}

// ---- Queue memory ----

/// The page allocator as [`alloc_below`](azos_dma::alloc_below) takes it.
struct Pmm;

impl azos_dma::PageSource for Pmm {
    fn alloc(&self, len: usize) -> Option<u64> {
        debug_assert_eq!(len, PAGE);
        azos_mm::pmm::alloc_page().ok().map(|p| p.0 as u64)
    }
    fn free(&self, pa: u64, _len: usize) {
        let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr(pa as usize));
    }
}

/// One zeroed page from the page allocator that the controller can reach
/// (`dma_mask`: the highest address its DMA gets to, `u64::MAX` for no
/// limit): `(CPU address, device address)`.
fn alloc_page(dma_mask: u64) -> Result<(usize, u64), NvmeError> {
    let pa = azos_dma::alloc_below(&Pmm, dma_mask, PAGE).map_err(|e| {
        if e == azos_dma::DmaError::NeedsBounce {
            kprintln!("[NVME] no page at or below {:#x}: the controller cannot reach the free memory", dma_mask);
        }
        NvmeError::NoMemory
    })? as usize;
    let va = azos_drv_virtio::virtio::dma_page_ptr(pa);
    // SAFETY: a page the allocator just handed out, mapped in the kernel's
    // direct map; nothing else refers to it.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, PAGE);
        if ALLOCATED_N < MAX_PAGES {
            ALLOCATED[ALLOCATED_N] = pa;
            ALLOCATED_N += 1;
        }
    }
    Ok((va, pa as u64))
}

/// Give back every page `alloc_page` took (a failed bring-up).
fn free_pages() {
    // SAFETY: bring-up is single-threaded and the controller is disabled
    // (or was never enabled) before this runs.
    unsafe {
        for i in 0..ALLOCATED_N {
            let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr(ALLOCATED[i]));
        }
        ALLOCATED_N = 0;
    }
}

// ---- Admin queue (bring-up only, polled) ----

fn sqe_write(sq: usize, index: u16, sqe: &proto::Sqe) {
    let p = (sq + index as usize * proto::SQE_BYTES) as *mut u32;
    for (i, d) in sqe.0.iter().enumerate() {
        // SAFETY: `sq` is a queue page of ours and `index < depth`, so the
        // 64-byte entry lies inside it.
        unsafe { core::ptr::write_volatile(p.add(i), *d) }
    }
}

/// The entry at `index` of a completion queue page. The phase dword is read
/// first and the rest only if it is new, behind an acquire fence: the
/// controller writes the phase tag last.
fn cqe_peek(cq: usize, cur: &proto::CqCursor) -> Option<proto::Cqe> {
    let p = (cq + cur.head as usize * proto::CQE_BYTES) as *const u32;
    // SAFETY: `cq` is a queue page of ours and `head < depth`.
    unsafe {
        let dw3 = core::ptr::read_volatile(p.add(3));
        let e = proto::Cqe { dw3, ..proto::Cqe::default() };
        if !proto::cqe_is_new(&e, cur.phase) {
            return None;
        }
        fence(Ordering::Acquire);
        Some(proto::Cqe {
            dw0: core::ptr::read_volatile(p),
            dw1: core::ptr::read_volatile(p.add(1)),
            dw2: core::ptr::read_volatile(p.add(2)),
            dw3,
        })
    }
}

impl Dev {
    fn sq_doorbell(&self, qid: u16) -> usize {
        self.bar + proto::doorbell_offset(qid, false, self.dstrd)
    }

    fn cq_doorbell(&self, qid: u16) -> usize {
        self.bar + proto::doorbell_offset(qid, true, self.dstrd)
    }

    /// Run one admin command to completion, polling. Bring-up only.
    fn admin(&mut self, mk: impl FnOnce(u16) -> proto::Sqe, what: &'static str) -> Result<proto::Cqe, NvmeError> {
        self.a_cid = self.a_cid.wrapping_add(1);
        let cid = self.a_cid;
        let sqe = mk(cid);
        sqe_write(self.asq, self.a_tail, &sqe);
        self.a_tail = proto::ring_next(self.a_tail, ADMIN_DEPTH);
        io_wmb();
        // SAFETY: the admin SQ tail doorbell of a mapped controller.
        unsafe { core::ptr::write_volatile(self.sq_doorbell(0) as *mut u32, self.a_tail as u32) };
        let deadline = deadline_after_us(ADMIN_TIMEOUT_US);
        loop {
            if let Some(e) = cqe_peek(self.acq, &self.a_cq) {
                self.a_cq.advance(ADMIN_DEPTH);
                // SAFETY: the admin CQ head doorbell.
                unsafe { core::ptr::write_volatile(self.cq_doorbell(0) as *mut u32, self.a_cq.head as u32) };
                if e.cid() != cid {
                    return Err(NvmeError::Admin(what));
                }
                if !e.is_success() {
                    azos_drv_sys::kerr!("[NVME] admin {} failed: status {:#x}", what, e.status());
                    return Err(NvmeError::Admin(what));
                }
                return Ok(e);
            }
            if now() >= deadline || rd32(self.bar, proto::REG_CSTS) & proto::CSTS_CFS != 0 {
                azos_drv_sys::kerr!("[NVME] admin {} timed out", what);
                return Err(NvmeError::Admin(what));
            }
            core::hint::spin_loop();
        }
    }
}

fn wait_ready(bar: usize, want: bool, timeout_ms: u64) -> Result<(), NvmeError> {
    let deadline = deadline_after_us(timeout_ms.max(500) * 1000);
    loop {
        let csts = rd32(bar, proto::REG_CSTS);
        if csts & proto::CSTS_CFS != 0 {
            return Err(NvmeError::Timeout);
        }
        if (csts & proto::CSTS_RDY != 0) == want {
            return Ok(());
        }
        if now() >= deadline {
            return Err(NvmeError::Timeout);
        }
        core::hint::spin_loop();
    }
}

// ---- Bring-up ----

/// Is `info` an NVM Express controller (class 01, subclass 08, prog-if 02)?
pub fn is_nvme_function<C: ConfigSpace>(cfg: &C, info: &FunctionInfo) -> bool {
    cfg.read32(info.bdf, 0x08) >> 8 == 0x01_08_02
}

/// Bring the controller `info` up as the boot block device. Call after PCI
/// enumeration, before `blkdev::init`. `route` delivers the MSI-X vectors
/// (one for the admin queue and one per I/O queue; a route that cannot, or a
/// function without MSI-X, leaves the driver polled). `cpus` is how many CPUs
/// the machine will run: no more I/O queue pairs than that are created.
/// `dma_mask` is the highest physical address the controller's DMA reaches
/// (the hardware bus's record of the device, `u64::MAX` for none): every page
/// the controller is given lies at or below it.
pub fn attach<C: ConfigSpace, R: QueueRoute>(
    cfg: &mut C,
    info: &FunctionInfo,
    window: &mut BarWindow,
    route: &mut R,
    dma_mask: u64,
    cpus: usize,
) -> Result<(), NvmeError> {
    if ACTIVE.load(Ordering::Acquire) {
        return Err(NvmeError::AlreadyUp);
    }
    if !is_nvme_function(cfg, info) {
        return Err(NvmeError::NotNvme);
    }
    let r = attach_inner(cfg, info, window, route, dma_mask, cpus);
    if r.is_err() {
        // SAFETY: bring-up is single-threaded; stop the controller before
        // its queue pages go back to the allocator.
        unsafe {
            if DEV.bar != 0 {
                wr32(DEV.bar, proto::REG_CC, 0);
            }
        }
        READY.store(false, Ordering::Release);
        free_pages();
    }
    r
}

fn attach_inner<C: ConfigSpace, R: QueueRoute>(
    cfg: &mut C,
    info: &FunctionInfo,
    window: &mut BarWindow,
    route: &mut R,
    dma_mask: u64,
    cpus: usize,
) -> Result<(), NvmeError> {
    if dma_mask != u64::MAX {
        kprintln!("[NVME] DMA limit {:#x}: queue and staging pages are taken at or below it", dma_mask);
    }
    let bar_base = map_bars(cfg, info, window).map_err(NvmeError::Bars)?;
    let bar = bar_base[0];
    if bar == 0 {
        return Err(NvmeError::NoRegisters);
    }

    // As many queue pairs as there are CPUs to use them, command slots to
    // keep them busy, and Kconfig allows; the controller and the interrupt
    // controller may say fewer below. `cpus` is what the machine is expected
    // to run: a CPU that never starts leaves its queue to polling only, which
    // `slot_take` uses last.
    let mut queues = route_math::queues_wanted(MAXQ, SLOTS, cpus);

    // MSI-X: vector 0 for the admin queue (polled, so only counted), vector
    // `q` for I/O queue `q`. Programmed before the controller is enabled. A
    // route that carries fewer vectors than queues wanted caps the queues:
    // a queue without a vector would be completed only by polling.
    let msix = info.msix.filter(|m| m.table_size >= 2);
    let routed = match msix {
        Some(m) => {
            let asked = route_math::vectors_wanted(queues, m.table_size);
            (route.prepare(asked) as usize).min(asked as usize)
        }
        None => 0,
    };
    let mut msix_on = false;
    if let (true, Some(m)) = (routed > 0, msix) {
        let table_base = bar_base.get(m.table_bar as usize).copied().unwrap_or(0);
        if table_base == 0 {
            return Err(NvmeError::Bars(SelftestError::BarAssign));
        }
        let mut table = KernelBar::new(table_base);
        for vec in 0..=routed as u16 {
            let (addr, data) = route.target(vec);
            azos_pci::program_msix_entry(&mut table, m.table_offset, vec, addr, data, false);
        }
        azos_pci::msix_set_enable(cfg, info.bdf, &m, true);
        msix_on = azos_pci::msix_is_enabled(cfg, info.bdf, &m);
        TOKEN_ADMIN.store(route.isr_token(VEC_ADMIN), Ordering::Relaxed);
        for q in 0..routed {
            TOKEN_Q[q].store(route.isr_token(qid_of(q)), Ordering::Relaxed);
        }
    }
    let irq = routed > 0 && msix_on;
    queues = route_math::queues_routed(queues, routed, irq);

    let cap = proto::decode_cap(rd64(bar, proto::REG_CAP));
    if !cap.nvm_command_set || cap.mps_min_shift > 12 || cap.mps_max_shift < 12 {
        return Err(NvmeError::Capabilities);
    }
    if (cap.max_queue_entries as usize) < IO_DEPTH as usize || cap.max_queue_entries < ADMIN_DEPTH as u32 {
        return Err(NvmeError::Capabilities);
    }

    // SAFETY: bring-up is single-threaded and runs before any user of `DEV`
    // and `QUEUES`.
    let dev = unsafe { &mut *(&raw mut DEV) };
    *dev = Dev { bar, dstrd: cap.dstrd, irq, per_cpu: route.per_cpu(), ready_ms: cap.ready_timeout_ms, ..DEV_ZERO };
    // SAFETY: as above.
    unsafe { *(&raw mut QUEUES) = [QUEUE_ZERO; MAXQ] };
    READY.store(false, Ordering::Relaxed);

    // Reset: disable and wait for RDY to drop (section 7.6.1).
    wr32(bar, proto::REG_CC, 0);
    wait_ready(bar, false, cap.ready_timeout_ms)?;

    // Memory: the admin pages, then every slot's pages. The I/O queues come
    // after the controller says how many it grants.
    let (asq, asq_pa) = alloc_page(dma_mask)?;
    let (acq, acq_pa) = alloc_page(dma_mask)?;
    dev.asq = asq;
    dev.asq_pa = asq_pa;
    dev.acq = acq;
    dev.acq_pa = acq_pa;
    for s in 0..SLOTS {
        for p in 0..SLOT_PAGES {
            let (va, pa) = alloc_page(dma_mask)?;
            // SAFETY: single-threaded bring-up.
            unsafe {
                SLOT_VA[s][p] = va;
                SLOT_PA[s][p] = pa;
            }
        }
        let (va, pa) = alloc_page(dma_mask)?;
        // SAFETY: as above.
        unsafe {
            LIST_VA[s] = va;
            LIST_PA[s] = pa;
        }
    }

    // Admin queues, then enable (sections 3.1.8 - 3.1.10, 7.6.1).
    wr32(bar, proto::REG_AQA, proto::aqa(ADMIN_DEPTH as u32, ADMIN_DEPTH as u32));
    wr64(bar, proto::REG_ASQ, asq_pa);
    wr64(bar, proto::REG_ACQ, acq_pa);
    io_wmb();
    wr32(bar, proto::REG_CC, proto::cc_enable());
    wait_ready(bar, true, cap.ready_timeout_ms)?;

    // Identify controller, then namespace 1, into slot 0's first page.
    // SAFETY: slot 0's page is not in use yet.
    let (scratch_va, scratch_pa) = unsafe { (SLOT_VA[0][0], SLOT_PA[0][0]) };
    dev.admin(|cid| proto::identify(cid, 0, proto::CNS_CONTROLLER, scratch_pa), "identify controller")?;
    let mut id = [0u8; 4096];
    // SAFETY: `scratch_va` is a whole page the controller just filled.
    unsafe { core::ptr::copy_nonoverlapping(scratch_va as *const u8, id.as_mut_ptr(), PAGE) };
    let ctrl = proto::decode_controller(&id);
    if ctrl.namespaces == 0 {
        return Err(NvmeError::Format);
    }
    dev.admin(|cid| proto::identify(cid, NSID, proto::CNS_NAMESPACE, scratch_pa), "identify namespace")?;
    // SAFETY: as above.
    unsafe { core::ptr::copy_nonoverlapping(scratch_va as *const u8, id.as_mut_ptr(), PAGE) };
    let ns = proto::decode_namespace(&id);
    if ns.blocks == 0 || ns.lba_shift != 9 || ns.metadata_bytes != 0 {
        azos_drv_sys::kerr!("[NVME] namespace 1: {} blocks of 2^{} B + {} B metadata: not driven",
            ns.blocks, ns.lba_shift, ns.metadata_bytes);
        return Err(NvmeError::Format);
    }

    // The I/O queue pairs, as many as the controller grants.
    let e = dev.admin(|cid| proto::set_number_of_queues(cid, queues as u16, queues as u16), "set number of queues")?;
    let (nsq, ncq) = proto::granted_queues(e.dw0);
    queues = route_math::queues_granted(queues, nsq, ncq);
    if queues < 1 {
        return Err(NvmeError::Admin("set number of queues"));
    }
    dev.queues = queues;
    for q in 0..queues {
        let (sq, sq_pa) = alloc_page(dma_mask)?;
        let (cq, cq_pa) = alloc_page(dma_mask)?;
        // SAFETY: single-threaded bring-up.
        unsafe { (*(&raw mut QUEUES))[q] = Queue { sq, cq, sq_pa, cq_pa, ..QUEUE_ZERO } };
        let qid = qid_of(q);
        dev.admin(|cid| proto::create_io_cq(cid, qid, IO_DEPTH, cq_pa, qid, irq), "create io cq")?;
        dev.admin(|cid| proto::create_io_sq(cid, qid, IO_DEPTH, sq_pa, qid), "create io sq")?;
    }

    dev.capacity = ns.blocks;
    dev.vwc = ctrl.volatile_write_cache;
    dev.discard = ctrl.dataset_management;
    dev.rtd3e_us = ctrl.rtd3e_us;
    dev.max_sectors = (SLOT_PAGES * PAGE / SECTOR_SIZE)
        .min(proto::mdts_max_sectors(ctrl.mdts) as usize)
        .min(65536) as u32;
    READY.store(true, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);
    // From here on `blkdev` reads, writes and flushes are requests on this
    // controller.
    crate::queue::bind(&NVME);

    kprintln!("[NVME] controller {} ns{} {} sectors mode={} depth={} queues={} slots={} xfer={} KiB vwc={} discard={}",
        info.bdf, NSID, dev.capacity, if irq { "irq" } else { "poll" }, IO_DEPTH, queues, SLOTS,
        dev.max_sectors as usize * SECTOR_SIZE / 1024, if dev.vwc { "y" } else { "n" },
        if dev.discard { "y" } else { "n" });
    Ok(())
}


// ---- Completion by interrupt ----

/// What the kernel's interrupt path passes to [`msi_irq`] for each vector
/// (`QueueRoute::isr_token`): the admin vector's, and one per I/O queue
/// (`u32::MAX` for a queue that has none).
static TOKEN_ADMIN: AtomicU32 = AtomicU32::new(u32::MAX);
static TOKEN_Q: [AtomicU32; MAXQ] = [const { AtomicU32::new(u32::MAX) }; MAXQ];
static IRQ_TAKEN: AtomicU32 = AtomicU32::new(0);
static IRQ_SLEPT: AtomicU32 = AtomicU32::new(0);
/// The task asleep in [`HwQueue::wait`] (0: none). The request layer lets one
/// task at a time in there; the others sleep on its own wait queue.
static WAITER: DeviceWait = DeviceWait::new();
azos_common::ro_hook! {
    /// The kernel's hook: block the caller until woken or `deadline`
    /// (timebase ticks), `false` when it cannot block.
    static BLOCK_FN: fn(u64) -> bool;
}
azos_common::ro_hook! {
    /// The kernel's hook: wake task `tid`.
    static WAKE_FN: fn(u32);
}

/// Let waiters sleep instead of spin: call once the scheduler exists. A
/// no-op where the controller has no MSI-X route.
pub fn set_irq_hooks(block_until: fn(u64) -> bool, wake: fn(u32)) {
    BLOCK_FN.set(block_until);
    WAKE_FN.set(wake);
}

/// `true` once completions are taken by interrupt and waiters may sleep.
pub fn irq_mode() -> bool {
    // SAFETY: `irq` is written once in bring-up, before `ACTIVE`.
    ACTIVE.load(Ordering::Acquire)
        && unsafe { DEV.irq }
        && BLOCK_FN.is_set()
}

/// `(interrupts taken, waits that slept)`.
pub fn irq_counts() -> (u32, u32) {
    (IRQ_TAKEN.load(Ordering::Relaxed), IRQ_SLEPT.load(Ordering::Relaxed))
}

/// The interrupt handler's arm for an MSI of the kernel's `token` (interrupt
/// context, any CPU): `None` when it is not this controller's; otherwise
/// wake the sleeping waiter, `Some(true)` when there was one. An MSI needs
/// no acknowledge at the device: the waiter that wakes reaps the queues
/// and rings the completion doorbells.
pub fn msi_irq(token: u32) -> Option<bool> {
    let is_io = TOKEN_Q.iter().any(|t| t.load(Ordering::Acquire) == token);
    if !is_io && token != TOKEN_ADMIN.load(Ordering::Acquire) {
        return None;
    }
    if !is_io {
        return Some(false);
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

// ---- The I/O queues ----

/// Drain every completion the controller has posted on I/O queue `qi`: mark
/// the slot whose command it names done, free the submission slots it reports
/// consumed, and ring the completion doorbell once. A completion naming no
/// command in flight on this queue is a controller not following the protocol
/// (it would make some later command look complete before its DMA happened):
/// latch dead. Caller holds [`QLOCK`]`[qi]`.
fn drain(dev: &Dev, qi: usize, q: &mut Queue) {
    let mut any = false;
    while let Some(e) = cqe_peek(q.cq, &q.cur) {
        q.cur.advance(IO_DEPTH);
        any = true;
        q.sq_head = e.sq_head();
        let Some(slot) = route_math::completion_slot(qi, dev.queues, e.sq_id(), e.cid(), SLOTS)
            .filter(|&s| SLOT_INFLIGHT[s].load(Ordering::Relaxed) && !SLOT_DONE[s].load(Ordering::Relaxed))
        else {
            latch_dead(dev, "foreign completion", false);
            return;
        };
        // Kconfig CHAOS `nvme-completion-drop`: the completion is consumed
        // and lost, so the command runs out of its budget and the timeout
        // policy resets the controller. Not while it is being reset.
        if RECOVERY.live() && azos_chaos::fire(azos_chaos::Point::NvmeCompletionDrop) {
            continue;
        }
        SLOT_STATUS[slot].store(e.status(), Ordering::Relaxed);
        SLOT_DONE[slot].store(true, Ordering::Release);
    }
    if any {
        // SAFETY: the CQ head doorbell of queue `qi` of a mapped controller.
        unsafe { core::ptr::write_volatile(dev.cq_doorbell(qid_of(qi)) as *mut u32, q.cur.head as u32) };
    }
}

/// Reset the controller (`CC.EN = 0` stops its DMA, on every queue) and latch
/// the driver dead. The staging pages stay owned by the driver and are never
/// reused: a command still in the controller may DMA into them until the reset
/// lands, and nothing submits again afterwards. Takes no lock, so any queue's
/// holder may call it; the first call does the work. `latched`: the policy
/// already says dead (a timeout with the resets spent).
fn latch_dead(dev: &Dev, reason: &str, latched: bool) {
    if !latched && !RECOVERY.latch() {
        return;
    }
    wr32(dev.bar, proto::REG_CC, 0);
    READY.store(false, Ordering::Release);
    azos_drv_sys::kerr!("[NVME] Error: {} - controller reset, block I/O disabled", reason);
}

/// Commands in `late` (a slot bitmap, every one in the controller) ran out of
/// their budget at tick `t`. The timeout policy decides: reset the controller
/// and bring it up again over the same pages, or, with the resets spent,
/// latch it dead. The late commands end `Timeout`; a reset ends the others
/// the controller held `Reset`. Called by `reap` with no queue lock held.
fn timed_out(dev: &Dev, late: u32, t: u64) {
    let first = late.trailing_zeros() as usize;
    let sector = SLOT_LBA[first].load(Ordering::Relaxed);
    let budget = if SLOT_OP[first].load(Ordering::Relaxed) == OP_FLUSH { FLUSH_TIMEOUT_US } else { IO_TIMEOUT_US };
    let waited_ms = budget / 1000
        + t.saturating_sub(SLOT_DEADLINE[first].load(Ordering::Relaxed)) * 1000 / azos_drv_sys::timebase::TIMER_FREQ;
    match RECOVERY.timed_out(sector, waited_ms) {
        Verdict::Reset => {
            azos_drv_sys::kerr!("[NVME] command timeout at sector {}: resetting the controller", sector);
            // Disable: the controller stops its DMA on every queue once
            // `CSTS.RDY` drops (section 7.6.1).
            wr32(dev.bar, proto::REG_CC, 0);
            let stopped = wait_ready(dev.bar, false, dev.ready_ms).is_ok();
            let ok = stopped && bring_up_again(dev, late).is_ok();
            if ok {
                kprintln!("[NVME] controller reset and brought up again: block I/O resumed");
            } else {
                wr32(dev.bar, proto::REG_CC, 0);
                READY.store(false, Ordering::Release);
                azos_drv_sys::kerr!("[NVME] Error: {} - block I/O disabled",
                    if stopped { "the reset controller did not come back" } else { "the controller did not confirm its reset" });
            }
            RECOVERY.reset_done(ok, sector, waited_ms);
            if !ok {
                mark_late(late);
            }
        }
        Verdict::Latch => {
            latch_dead(dev, "command timeout, resets spent", true);
            mark_late(late);
        }
        Verdict::Handled => {}
    }
}

/// The commands in `late` end `Timeout`: their slots stay taken while the
/// driver is dead (`release`).
fn mark_late(late: u32) {
    for slot in (0..SLOTS).filter(|s| late & (1 << s) != 0) {
        SLOT_STATUS[slot].store(ST_TIMEOUT, Ordering::Relaxed);
        SLOT_DONE[slot].store(true, Ordering::Release);
    }
}

/// The controller is disabled and `CSTS.RDY` is 0 (it no longer touches any
/// queue or staging page): bring it up again over the pages it had, as
/// bring-up did (admin queue, enable, queue count, the I/O queue pairs), and
/// end the commands it held (`late` ones `Timeout`, the others `Reset`). Each
/// I/O queue is emptied and its commands ended under its lock (the admin
/// commands run without it), so a `submit` either published before (and its
/// command is ended here) or finds the controller being reset. Namespace 1 is not identified again: a controller
/// reset does not change it, and the staging pages that bring-up identified
/// into may hold a finished read the layer has not copied out yet.
fn bring_up_again(dev: &Dev, late: u32) -> Result<(), NvmeError> {
    // The admin queue's cursors are this copy's: nothing else issues admin
    // commands after bring-up.
    let mut a = *dev;
    a.a_tail = 0;
    a.a_cq = proto::CqCursor::new();
    // SAFETY: the controller is disabled; the admin pages are the driver's.
    unsafe {
        core::ptr::write_bytes(a.asq as *mut u8, 0, PAGE);
        core::ptr::write_bytes(a.acq as *mut u8, 0, PAGE);
    }
    wr32(a.bar, proto::REG_AQA, proto::aqa(ADMIN_DEPTH as u32, ADMIN_DEPTH as u32));
    wr64(a.bar, proto::REG_ASQ, a.asq_pa);
    wr64(a.bar, proto::REG_ACQ, a.acq_pa);
    io_wmb();
    wr32(a.bar, proto::REG_CC, proto::cc_enable());
    wait_ready(a.bar, true, a.ready_ms)?;
    let queues = dev.queues;
    let e = a.admin(|cid| proto::set_number_of_queues(cid, queues as u16, queues as u16), "set number of queues")?;
    let (nsq, ncq) = proto::granted_queues(e.dw0);
    if route_math::queues_granted(queues, nsq, ncq) < queues {
        return Err(NvmeError::Admin("set number of queues"));
    }
    for qi in 0..queues {
        // Under the lock only to wait out a `submit` that began before the
        // reset, empty the queue and end its commands; the admin commands
        // that create it again run with no lock held (owner rule F1: no
        // queue lock across a device wait). A `submit` meanwhile finds the
        // controller being reset, and a reap's drain finds the zeroed
        // completion queue empty.
        let (cq_pa, sq_pa) = {
            let _g = QLOCK[qi].lock();
            // SAFETY: queue `qi` is under its lock; the controller has no
            // I/O queue yet, so it touches neither page.
            let q = unsafe { &mut (*(&raw mut QUEUES))[qi] };
            // SAFETY: as above.
            unsafe {
                core::ptr::write_bytes(q.sq as *mut u8, 0, PAGE);
                core::ptr::write_bytes(q.cq as *mut u8, 0, PAGE);
            }
            *q = Queue { sq: q.sq, cq: q.cq, sq_pa: q.sq_pa, cq_pa: q.cq_pa, ..QUEUE_ZERO };
            for slot in (qi..SLOTS).step_by(queues) {
                if SLOT_INFLIGHT[slot].load(Ordering::Acquire) && !SLOT_DONE[slot].load(Ordering::Acquire) {
                    SLOT_STATUS[slot].store(if late & (1 << slot) != 0 { ST_TIMEOUT } else { ST_RESET }, Ordering::Relaxed);
                    SLOT_DONE[slot].store(true, Ordering::Release);
                }
            }
            (q.cq_pa, q.sq_pa)
        };
        let (qid, irq) = (qid_of(qi), dev.irq);
        a.admin(|cid| proto::create_io_cq(cid, qid, IO_DEPTH, cq_pa, qid, irq), "create io cq")?;
        a.admin(|cid| proto::create_io_sq(cid, qid, IO_DEPTH, sq_pa, qid), "create io sq")?;
    }
    Ok(())
}

/// Publish `sqe` on I/O queue `qi` and ring its doorbell. Caller holds
/// [`QLOCK`]`[qi]`; `slot` is on that queue.
fn submit(dev: &Dev, qi: usize, q: &mut Queue, slot: usize, sqe: &proto::Sqe) -> Result<(), ()> {
    if RECOVERY.resetting() {
        // Claimed before the reset began: the controller is being brought up
        // again, so the command ends at once as one the reset abandoned.
        SLOT_STATUS[slot].store(ST_RESET, Ordering::Relaxed);
        SLOT_REPORTED[slot].store(false, Ordering::Relaxed);
        SLOT_DONE[slot].store(true, Ordering::Relaxed);
        SLOT_INFLIGHT[slot].store(true, Ordering::Release);
        return Ok(());
    }
    drain(dev, qi, q);
    if !RECOVERY.live() || proto::sq_full(q.sq_head, q.tail, IO_DEPTH) {
        return Err(());
    }
    SLOT_DONE[slot].store(false, Ordering::Relaxed);
    SLOT_REPORTED[slot].store(false, Ordering::Relaxed);
    SLOT_INFLIGHT[slot].store(true, Ordering::Release);
    sqe_write(q.sq, q.tail, sqe);
    q.tail = proto::ring_next(q.tail, IO_DEPTH);
    io_wmb();
    // SAFETY: the SQ tail doorbell of queue `qi` of a mapped controller.
    unsafe { core::ptr::write_volatile(dev.sq_doorbell(qid_of(qi)) as *mut u32, q.tail as u32) };
    Ok(())
}

/// Where the data of a command of `bytes` bytes sits and how the controller
/// finds it: build the PRPs over slot `slot`'s pages.
fn prps_for(slot: usize, bytes: usize) -> Result<(u64, u64), ()> {
    let n = proto::pages_spanned(0, bytes);
    // SAFETY: the slot is this caller's; its pages and list were set at
    // bring-up and are never freed while the driver is up.
    unsafe {
        let list = core::slice::from_raw_parts_mut(LIST_VA[slot] as *mut u64, PAGE / 8);
        let pages = core::slice::from_raw_parts((&raw const SLOT_PA[slot]) as *const u64, n);
        proto::build_prps(pages, 0, bytes, LIST_PA[slot], list).map_err(|_| ())
    }
}

/// Copy `src` into slot `slot`'s bounce pages, from byte `off` of them.
fn stage_in(slot: usize, mut off: usize, src: &[u8]) {
    let mut done = 0;
    while done < src.len() {
        let in_page = PAGE - off % PAGE;
        let n = (src.len() - done).min(in_page);
        // SAFETY: the slot is this caller's, its previous command (if any)
        // completed, and `off + src.len() <= SLOT_PAGES * PAGE` (checked by
        // `start`).
        unsafe {
            let dst = (SLOT_VA[slot][off / PAGE] + off % PAGE) as *mut u8;
            core::ptr::copy_nonoverlapping(src.as_ptr().add(done), dst, n);
        }
        done += n;
        off += n;
    }
}

/// The controller as bring-up left it, read-only from then on (only the
/// queues' moving parts change, behind [`QLOCK`]). Called once the controller
/// was bound, never during bring-up.
fn dev() -> &'static Dev {
    // SAFETY: `DEV` is written by `attach` alone, single-threaded, before
    // `queue::bind` publishes the controller; every caller runs after it.
    unsafe { &*(&raw const DEV) }
}

/// `true` while the driver may submit.
fn usable() -> bool {
    READY.load(Ordering::Acquire) && RECOVERY.live()
}

// ---- Public API ----

/// `true` once a controller is up and `blkdev` routes block I/O here.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Orderly power-off or reboot (`blkdev::shutdown`), after the last flush:
/// stop submitting (`READY` false, so every claim answers `Dead`), ask the
/// controller for a normal shutdown (`CC.SHN` = 01b, section 7.6.2) and poll
/// `CSTS.SHST` until it says complete, at most the controller's RTD3E or
/// `floor_ms`, whichever is longer (`azos_nvme::shutdown_timeout_ms`). A
/// clean shutdown is what keeps the drive's unsafe-shutdown count still and
/// its volatile cache written. `None`: no controller is up (never attached,
/// or latched failed and already disabled); `Some(false)`: the controller
/// did not confirm in time or reported a fatal status. The power-off goes on
/// either way.
pub fn shutdown(floor_ms: u64) -> Option<bool> {
    if !usable() {
        return None;
    }
    READY.store(false, Ordering::Release);
    let (bar, rtd3e_us) = (dev().bar, dev().rtd3e_us);
    wr32(bar, proto::REG_CC, proto::cc_shutdown(rd32(bar, proto::REG_CC)));
    let deadline = deadline_after_us(proto::shutdown_timeout_ms(rtd3e_us, floor_ms).saturating_mul(1000));
    loop {
        let csts = rd32(bar, proto::REG_CSTS);
        if proto::shutdown_complete(csts) {
            return Some(true);
        }
        if csts & proto::CSTS_CFS != 0 || now() >= deadline {
            return Some(false);
        }
        core::hint::spin_loop();
    }
}

/// The controller as the request layer drives it.
struct Nvme;

static NVME: Nvme = Nvme;

/// Map a completion status of a command of kind `op` to what the request
/// layer is told. An Invalid Command Opcode (generic status `0x001`) from a
/// Flush or a Dataset Management is the controller saying it has none.
fn hw_status(op: u8, st: u16) -> HwStatus {
    match st {
        0 => HwStatus::Ok,
        0x001 if op != OP_DATA => HwStatus::Unsupported,
        ST_TIMEOUT => HwStatus::Timeout,
        ST_RESET => HwStatus::Reset,
        _ => {
            azos_drv_sys::kerr!("[NVME] command failed: status type {} code {:#x}",
                proto::status_type(st), proto::status_code(st));
            HwStatus::Io
        }
    }
}

impl HwQueue for Nvme {
    fn caps(&self) -> HwCaps {
        let dev = dev();
        HwCaps {
            sectors: dev.capacity,
            max_sectors: dev.max_sectors.max(1),
            max_discard_sectors: if dev.discard { DSM_RANGE_MAX_SECTORS } else { 0 },
            fua: true,
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
        // SAFETY: written once in bring-up, before `bind`.
        let (queues, irq, per_cpu) = unsafe { (DEV.queues, DEV.irq, DEV.per_cpu) };
        let served = route_math::served_queues(queues, irq, per_cpu, azos_percpu::cpu_online);
        match slot_take(queue_of(self.cpu(), queues), queues, served) {
            Some(s) => Claim::Tag(s as u8),
            None => Claim::Busy,
        }
    }

    fn start(&self, tag: u8, cmd: &HwCmd<'_>) -> Result<(), ()> {
        let slot = tag as usize;
        // SAFETY: `max_sectors` and `queues` are written in bring-up, before `bind`.
        let (max, queues) = unsafe { (DEV.max_sectors, DEV.queues) };
        let (sqe, op, budget) = match cmd.op {
            HwOp::Read | HwOp::Write => {
                let bytes = cmd.sectors as usize * SECTOR_SIZE;
                if cmd.sectors == 0 || cmd.sectors > max || (cmd.op == HwOp::Write && cmd.segs.iter().map(|s| s.len()).sum::<usize>() != bytes) {
                    return Err(());
                }
                let write = cmd.op == HwOp::Write;
                if write {
                    let mut off = 0;
                    for s in cmd.segs {
                        stage_in(slot, off, s);
                        off += s.len();
                    }
                }
                let (prp1, prp2) = prps_for(slot, bytes)?;
                let sqe = proto::read_write(slot as u16, NSID, write, cmd.lba, cmd.sectors, prp1, prp2);
                (if cmd.fua { proto::with_fua(sqe) } else { sqe }, OP_DATA, IO_TIMEOUT_US)
            }
            HwOp::Flush => (proto::flush(slot as u16, NSID), OP_FLUSH, FLUSH_TIMEOUT_US),
            HwOp::Discard => {
                // One range, in the slot's first bounce page.
                stage_in(slot, 0, &proto::dsm_range(cmd.lba, cmd.sectors));
                // SAFETY: bring-up set the slot's pages.
                let pa = unsafe { SLOT_PA[slot][0] };
                (proto::dataset_management_deallocate(slot as u16, NSID, 1, pa), OP_DISCARD, IO_TIMEOUT_US)
            }
        };
        SLOT_OP[slot].store(op, Ordering::Relaxed);
        SLOT_LBA[slot].store(cmd.lba, Ordering::Relaxed);
        // The look before the credit is read: the slot's baseline already
        // holds any stall that ended just now.
        watch();
        SLOT_CREDIT[slot].store(STALL.credit(), Ordering::Relaxed);
        SLOT_DEADLINE[slot].store(deadline_after_us(budget), Ordering::Relaxed);
        // The queue the slot is on, whichever CPU claimed it.
        let qi = queue_of(slot, queues);
        let _g = QLOCK[qi].lock();
        // SAFETY: bring-up wrote `DEV`; queue `qi` is under its lock.
        let (dev, q) = unsafe { (&*(&raw const DEV), &mut (*(&raw mut QUEUES))[qi]) };
        submit(dev, qi, q, slot, &sqe)
    }

    fn reap(&self, out: &mut [HwDone; HW_TAGS_MAX]) -> usize {
        let dev = dev();
        // Every queue's completions first, each under its lock.
        for qi in 0..dev.queues {
            let _g = QLOCK[qi].lock();
            // SAFETY: queue `qi` is under its lock.
            let q = unsafe { &mut (*(&raw mut QUEUES))[qi] };
            drain(dev, qi, q);
        }
        // Out of budget next, with no lock held (a reset waits for the
        // controller): it ends every command the controller held, and the
        // loop below reports them.
        let t = watch();
        if RECOVERY.live() {
            let late = (0..SLOTS)
                .filter(|&s| {
                    SLOT_INFLIGHT[s].load(Ordering::Acquire)
                        && !SLOT_DONE[s].load(Ordering::Acquire)
                        && STALL.expired(t, SLOT_DEADLINE[s].load(Ordering::Relaxed), SLOT_CREDIT[s].load(Ordering::Relaxed))
                })
                .fold(0u32, |m, s| m | 1 << s);
            if late != 0 {
                timed_out(dev, late, t);
            }
        }
        let dead = RECOVERY.dead();
        let mut n = 0;
        for qi in 0..dev.queues {
            // One queue at a time, under its lock: a slot is reported once.
            let _g = QLOCK[qi].lock();
            for slot in (qi..SLOTS).step_by(dev.queues) {
                if !SLOT_INFLIGHT[slot].load(Ordering::Acquire) || SLOT_REPORTED[slot].load(Ordering::Relaxed) {
                    continue;
                }
                let status = if SLOT_DONE[slot].load(Ordering::Acquire) {
                    hw_status(SLOT_OP[slot].load(Ordering::Relaxed), SLOT_STATUS[slot].load(Ordering::Relaxed))
                } else if dead {
                    // The device died with this command in it: no data to trust.
                    HwStatus::Io
                } else {
                    continue;
                };
                SLOT_REPORTED[slot].store(true, Ordering::Relaxed);
                out[n] = HwDone { tag: slot as u8, status };
                n += 1;
            }
        }
        n
    }

    fn copy_out(&self, tag: u8, mut off: usize, dst: &mut [u8]) {
        let slot = tag as usize;
        let mut done = 0;
        while done < dst.len() {
            let n = (dst.len() - done).min(PAGE - off % PAGE);
            // SAFETY: the controller posted this slot's completion, so it is
            // done with the pages; the slot is still the caller's until
            // `release`. `off + dst.len()` is inside the command's data.
            unsafe {
                let src = (SLOT_VA[slot][off / PAGE] + off % PAGE) as *const u8;
                core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(done), n);
            }
            done += n;
            off += n;
        }
    }

    fn release(&self, tag: u8) {
        let slot = tag as usize;
        if RECOVERY.dead() {
            // The controller is dead: a command it could not recall may still
            // be writing to this slot's pages. The slot stays taken for good.
            // (A reset that brought it back confirmed its stop first: the
            // slots of the commands it ended are free again.)
            return;
        }
        SLOT_INFLIGHT[slot].store(false, Ordering::Release);
        slot_give(slot);
    }

    fn wait(&self, until_ns: u64) -> bool {
        if !irq_mode() {
            return false;
        }
        let tid = azos_sync::waitqueue::caller_tid();
        let Some(f) = BLOCK_FN.get().filter(|_| tid != 0 && tid != u32::MAX) else {
            return false;
        };
        // Re-check after listing the waiter: a completion posted before the
        // listing raised its interrupt before anyone could be woken.
        // SAFETY: bring-up wrote `DEV`.
        let queues = unsafe { DEV.queues };
        WAITER.park(
            tid,
            || {
                !RECOVERY.live()
                    || (0..queues).any(|qi| {
                        let _g = QLOCK[qi].lock();
                        // SAFETY: queue `qi` is under its lock.
                        let q = unsafe { &(*(&raw const QUEUES))[qi] };
                        cqe_peek(q.cq, &q.cur).is_some()
                    })
            },
            || {
                let s = f(ns_to_ticks(until_ns));
                if s {
                    IRQ_SLEPT.fetch_add(1, Ordering::Relaxed);
                }
                s
            },
        )
    }
}
