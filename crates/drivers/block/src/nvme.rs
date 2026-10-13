// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! NVMe block driver (Kconfig `DRV_NVME`, cargo feature `nvme`).
//!
//! The wire protocol (register layout, doorbell and ring arithmetic, SQE/CQE
//! encoding, PRP lists, Identify decoding) lives in `azos_nvme` and is
//! host-tested; this file owns the device: BAR mapping, the admin and I/O
//! queues in page-allocator memory, the staging slots, the interrupt, and the
//! [`BlockDevice`](azos_drv_api::block::BlockDevice) entry points
//! `blkdev` forwards to when [`active`].
//!
//! # Shape (follows `virtio::blk`)
//!
//! * **Bring-up** ([`attach`]): runs from `kernel_main` after PCI
//!   enumeration and before `blkdev::init`. Maps the BARs, routes two MSI-X
//!   vectors where the machine has a route (0: admin, 1: I/O), resets the
//!   controller, programs the admin queue pair, enables it, identifies the
//!   controller and namespace 1, asks for one I/O queue pair and creates it.
//!   The admin queue is used only here, polled, single-threaded.
//! * **One I/O queue pair for every CPU.** A queue per CPU needs a vector
//!   per CPU, and the MSI route (the boot hart's IMSIC file, the ITS's one
//!   collection) delivers to the boot CPU only; a second queue would add a
//!   lock-free submit path with nothing to complete it elsewhere. The queue
//!   is shared under [`LOCK`], held for bookkeeping only (a submit, a reap)
//!   and never across the device wait (owner rule F1): a command is
//!   submitted under it and then waited for without it.
//! * **Staging slots.** Each in-flight command owns a slot: `SLOT_PAGES`
//!   separate 4 KiB pages of bounce buffer and one PRP-list page. The
//!   device is never handed caller memory (a command cannot be recalled, and
//!   a caller buffer is often a popped stack frame). A transfer larger than
//!   one slot is split; several chunks go out together on every free slot
//!   (reads and writes alike) before the first wait. The pages need not be
//!   contiguous: that is what the PRP list is for, and a transfer of more
//!   than two pages exercises it on every use.
//! * **Completion.** By MSI-X where a route exists: the waiter sleeps (hooks
//!   from [`set_irq_hooks`]) until [`msi_irq`] wakes it, bounded by a slice
//!   and the command's deadline. Without a route, or before the scheduler
//!   exists, it polls the completion queue's phase tags. Either way it is
//!   the waiter that reaps, under [`LOCK`].
//! * **Dead means dead.** A command that misses its deadline, or a
//!   completion naming no command in flight, resets the controller
//!   (`CC.EN = 0`, which stops its DMA) and latches the driver failed until
//!   reboot, as `virtio::blk` does: no disk beats silently wrong disk.
//!
//! DMA coherence is assumed (QEMU, and the coherent PCIe hosts this tree
//! targets), as it is for the virtio drivers.

use azos_drv_api::block::FlushError;
use azos_drv_sys::kprintln;
use azos_drv_virtio::virtio::pci::msix_selftest::{map_bars, KernelBar, MsiRoute, SelftestError};
use azos_nvme as proto;
use azos_pci::{BarWindow, ConfigSpace, FunctionInfo};
use azos_sync::kmutex::Mutex;
use core::sync::atomic::{fence, AtomicBool, AtomicU16, AtomicU32, AtomicUsize, Ordering};

const SECTOR_SIZE: usize = 512;
const PAGE: usize = proto::PAGE_SIZE;

/// Commands in flight at once (Kconfig `NVME_INFLIGHT`).
const SLOTS: usize = azos_limits::NVME_INFLIGHT as usize;
/// Bounce pages per slot (Kconfig `NVME_SLOT_KB`).
const SLOT_PAGES: usize = azos_limits::NVME_SLOT_KB as usize * 1024 / PAGE;
/// Entries of the I/O queues (Kconfig `NVME_QUEUE_DEPTH`).
const IO_DEPTH: u16 = azos_limits::NVME_QUEUE_DEPTH as u16;
const ADMIN_DEPTH: u16 = 8;
const _: () = assert!(SLOTS >= 1 && SLOTS <= 8 && SLOTS < IO_DEPTH as usize);
const _: () = assert!(SLOT_PAGES >= 1 && SLOT_PAGES <= 32);
// One 4 KiB page holds the whole submission queue (64 B entries).
const _: () = assert!(IO_DEPTH as usize * proto::SQE_BYTES <= PAGE);
// A PRP list page holds PAGE / 8 entries; a slot needs SLOT_PAGES - 1.
const _: () = assert!(SLOT_PAGES - 1 <= PAGE / 8);

/// Pages taken from the page allocator at bring-up: admin SQ and CQ, I/O SQ
/// and CQ, and for every slot its bounce pages and its PRP list.
const MAX_PAGES: usize = 4 + SLOTS * (SLOT_PAGES + 1);

/// Queue id and MSI-X vector of the I/O queue pair (the admin pair is 0).
const IO_QID: u16 = 1;
const VEC_ADMIN: u16 = 0;
const VEC_IO: u16 = 1;

const NSID: u32 = 1;

/// Budget for one admin command, and for a command on the I/O queue. Both
/// bound a DEAD controller, not a slow one (`virtio::blk` uses 500 ms the
/// same way); a flush writes the whole volatile cache back, so it gets four
/// times as much.
const ADMIN_TIMEOUT_US: u64 = 1_000_000;
const IO_TIMEOUT_US: u64 = 500_000;
const FLUSH_TIMEOUT_US: u64 = 4 * IO_TIMEOUT_US;
/// Longest sleep of a waiter between completion checks. A slice, never the
/// deadline: an idle CPU under QEMU `-icount ... sleep=off` jumps its clock
/// to the next timer, and one sleep to the deadline would declare the
/// device dead before the host answered.
const IRQ_SLICE_US: u64 = 1_000;

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

/// One controller, all of it behind [`LOCK`].
struct Dev {
    /// CPU address of BAR 0 (the registers).
    bar: usize,
    dstrd: u32,
    capacity: u64,
    vwc: bool,
    /// Sectors one command carries: slot size, MDTS, 65536 (NLB is 16 bits).
    max_sectors: u32,
    /// Queue memory: CPU address and device (physical) address.
    asq: usize,
    asq_pa: u64,
    acq: usize,
    acq_pa: u64,
    isq: usize,
    isq_pa: u64,
    icq: usize,
    icq_pa: u64,
    a_tail: u16,
    a_cq: proto::CqCursor,
    a_cid: u16,
    i_tail: u16,
    i_sq_head: u16,
    i_cq: proto::CqCursor,
    /// MSI-X routed (completions raise the I/O vector).
    irq: bool,
    ready: bool,
    failed: bool,
}

const DEV_ZERO: Dev = Dev {
    bar: 0,
    dstrd: 0,
    capacity: 0,
    vwc: false,
    max_sectors: 0,
    asq: 0,
    asq_pa: 0,
    acq: 0,
    acq_pa: 0,
    isq: 0,
    isq_pa: 0,
    icq: 0,
    icq_pa: 0,
    a_tail: 0,
    a_cq: proto::CqCursor::new(),
    a_cid: 0,
    i_tail: 0,
    i_sq_head: 0,
    i_cq: proto::CqCursor::new(),
    irq: false,
    ready: false,
    failed: false,
};

static mut DEV: Dev = DEV_ZERO;

/// Serializes the queue state: building and publishing an SQE, reaping the
/// completion queue. Never held across the device wait.
static LOCK: Mutex<()> = Mutex::new(());

/// Set once the controller is up; `blkdev` routes here when true.
static ACTIVE: AtomicBool = AtomicBool::new(false);

// ---- Staging slots ----

static mut ALLOCATED: [usize; MAX_PAGES] = [0; MAX_PAGES];
static mut ALLOCATED_N: usize = 0;
/// Slot `i`'s bounce pages: CPU and device addresses.
static mut SLOT_VA: [[usize; SLOT_PAGES]; SLOTS] = [[0; SLOT_PAGES]; SLOTS];
static mut SLOT_PA: [[u64; SLOT_PAGES]; SLOTS] = [[0; SLOT_PAGES]; SLOTS];
/// Slot `i`'s PRP list page.
static mut LIST_VA: [usize; SLOTS] = [0; SLOTS];
static mut LIST_PA: [u64; SLOTS] = [0; SLOTS];

static SLOT_INFLIGHT: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
static SLOT_DONE: [AtomicBool; SLOTS] = [const { AtomicBool::new(false) }; SLOTS];
static SLOT_STATUS: [AtomicU16; SLOTS] = [const { AtomicU16::new(0) }; SLOTS];

/// Bit `i` set while a command owns slot `i`; claimed with `fetch_or`. A
/// caller that finds every slot taken sleeps until a release bumps `SLOT_GEN`.
static SLOT_BUSY: AtomicU32 = AtomicU32::new(0);
static SLOT_GEN: AtomicU32 = AtomicU32::new(0);
static SLOT_WQ: azos_sync::waitqueue::WaitQueue = azos_sync::waitqueue::WaitQueue::new();

struct SlotClaim(usize);

const ALL_SLOTS: u32 = (1u32 << SLOTS) - 1;

fn slot_try_claim() -> Option<SlotClaim> {
    loop {
        let free = !SLOT_BUSY.load(Ordering::SeqCst) & ALL_SLOTS;
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
    loop {
        let gen = SLOT_GEN.load(Ordering::SeqCst);
        if let Some(c) = slot_try_claim() {
            return c;
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

fn deadline_after_us(us: u64) -> u64 {
    now().saturating_add(us.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000)
}

// ---- Queue memory ----

/// One zeroed page from the page allocator: `(CPU address, device address)`.
fn alloc_page() -> Result<(usize, u64), NvmeError> {
    let pa = azos_mm::pmm::alloc_page().map_err(|_| NvmeError::NoMemory)?.0;
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
/// enumeration, before `blkdev::init`. `route` delivers the two MSI-X
/// vectors (a route that cannot, or a function without MSI-X, leaves the
/// driver polled).
pub fn attach<C: ConfigSpace, R: MsiRoute>(
    cfg: &mut C,
    info: &FunctionInfo,
    window: &mut BarWindow,
    route: &mut R,
) -> Result<(), NvmeError> {
    if ACTIVE.load(Ordering::Acquire) {
        return Err(NvmeError::AlreadyUp);
    }
    if !is_nvme_function(cfg, info) {
        return Err(NvmeError::NotNvme);
    }
    let r = attach_inner(cfg, info, window, route);
    if r.is_err() {
        // SAFETY: bring-up is single-threaded; stop the controller before
        // its queue pages go back to the allocator.
        unsafe {
            if DEV.bar != 0 {
                wr32(DEV.bar, proto::REG_CC, 0);
            }
            DEV.ready = false;
        }
        free_pages();
    }
    r
}

fn attach_inner<C: ConfigSpace, R: MsiRoute>(
    cfg: &mut C,
    info: &FunctionInfo,
    window: &mut BarWindow,
    route: &mut R,
) -> Result<(), NvmeError> {
    let bar_base = map_bars(cfg, info, window).map_err(NvmeError::Bars)?;
    let bar = bar_base[0];
    if bar == 0 {
        return Err(NvmeError::NoRegisters);
    }

    // MSI-X: vector 0 for the admin queue (polled, so only counted), vector
    // 1 for I/O. Programmed before the controller is enabled.
    let msix = info.msix.filter(|m| m.table_size >= 2);
    let irq = msix.is_some() && route.prepare(2);
    let mut msix_on = false;
    if let (true, Some(m)) = (irq, msix) {
        let table_base = bar_base.get(m.table_bar as usize).copied().unwrap_or(0);
        if table_base == 0 {
            return Err(NvmeError::Bars(SelftestError::BarAssign));
        }
        let mut table = KernelBar::new(table_base);
        for vec in 0..2u16 {
            let (addr, data) = route.target(vec);
            azos_pci::program_msix_entry(&mut table, m.table_offset, vec, addr, data, false);
        }
        azos_pci::msix_set_enable(cfg, info.bdf, &m, true);
        msix_on = azos_pci::msix_is_enabled(cfg, info.bdf, &m);
        TOKEN_ADMIN.store(route.isr_token(VEC_ADMIN), Ordering::Relaxed);
        TOKEN_IO.store(route.isr_token(VEC_IO), Ordering::Relaxed);
    }
    let irq = irq && msix_on;

    let cap = proto::decode_cap(rd64(bar, proto::REG_CAP));
    if !cap.nvm_command_set || cap.mps_min_shift > 12 || cap.mps_max_shift < 12 {
        return Err(NvmeError::Capabilities);
    }
    if (cap.max_queue_entries as usize) < IO_DEPTH as usize || cap.max_queue_entries < ADMIN_DEPTH as u32 {
        return Err(NvmeError::Capabilities);
    }

    // SAFETY: bring-up is single-threaded and runs before any user of `DEV`.
    let dev = unsafe { &mut *(&raw mut DEV) };
    *dev = Dev { bar, dstrd: cap.dstrd, irq, ..DEV_ZERO };

    // Reset: disable and wait for RDY to drop (section 7.6.1).
    wr32(bar, proto::REG_CC, 0);
    wait_ready(bar, false, cap.ready_timeout_ms)?;

    // Memory: the four queue pages, then every slot's pages.
    let (asq, asq_pa) = alloc_page()?;
    let (acq, acq_pa) = alloc_page()?;
    let (isq, isq_pa) = alloc_page()?;
    let (icq, icq_pa) = alloc_page()?;
    dev.asq = asq;
    dev.asq_pa = asq_pa;
    dev.acq = acq;
    dev.acq_pa = acq_pa;
    dev.isq = isq;
    dev.isq_pa = isq_pa;
    dev.icq = icq;
    dev.icq_pa = icq_pa;
    for s in 0..SLOTS {
        for p in 0..SLOT_PAGES {
            let (va, pa) = alloc_page()?;
            // SAFETY: single-threaded bring-up.
            unsafe {
                SLOT_VA[s][p] = va;
                SLOT_PA[s][p] = pa;
            }
        }
        let (va, pa) = alloc_page()?;
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

    // One I/O queue pair, and the controller must grant it.
    let e = dev.admin(|cid| proto::set_number_of_queues(cid, 1, 1), "set number of queues")?;
    let (nsq, ncq) = proto::granted_queues(e.dw0);
    if nsq < 1 || ncq < 1 {
        return Err(NvmeError::Admin("set number of queues"));
    }
    dev.admin(|cid| proto::create_io_cq(cid, IO_QID, IO_DEPTH, icq_pa, VEC_IO, irq), "create io cq")?;
    dev.admin(|cid| proto::create_io_sq(cid, IO_QID, IO_DEPTH, isq_pa, IO_QID), "create io sq")?;

    dev.capacity = ns.blocks;
    dev.vwc = ctrl.volatile_write_cache;
    dev.max_sectors = (SLOT_PAGES * PAGE / SECTOR_SIZE)
        .min(proto::mdts_max_sectors(ctrl.mdts) as usize)
        .min(65536) as u32;
    dev.ready = true;
    ACTIVE.store(true, Ordering::Release);

    kprintln!("[NVME] controller {} ns{} {} sectors mode={} depth={} slots={} xfer={} KiB vwc={}",
        info.bdf, NSID, dev.capacity, if irq { "irq" } else { "poll" }, IO_DEPTH, SLOTS,
        dev.max_sectors as usize * SECTOR_SIZE / 1024, if dev.vwc { "y" } else { "n" });
    Ok(())
}


// ---- Completion by interrupt ----

/// What the kernel's interrupt path passes to [`msi_irq`] for each vector
/// (`MsiRoute::isr_token`).
static TOKEN_ADMIN: AtomicU32 = AtomicU32::new(u32::MAX);
static TOKEN_IO: AtomicU32 = AtomicU32::new(u32::MAX);
static IRQ_TAKEN: AtomicU32 = AtomicU32::new(0);
static IRQ_SLEPT: AtomicU32 = AtomicU32::new(0);
/// The task waiting on slot `i`'s command (0: none, or not sleeping).
static SLOT_WAITER: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];
/// The kernel's hooks: block the caller until woken or `deadline`
/// (timebase ticks), `false` when it cannot block; wake task `tid`.
static BLOCK_FN: AtomicUsize = AtomicUsize::new(0);
static WAKE_FN: AtomicUsize = AtomicUsize::new(0);

/// Let waiters sleep instead of spin: call once the scheduler exists. A
/// no-op where the controller has no MSI-X route.
pub fn set_irq_hooks(block_until: fn(u64) -> bool, wake: fn(u32)) {
    BLOCK_FN.store(block_until as usize, Ordering::Release);
    WAKE_FN.store(wake as usize, Ordering::Release);
}

/// `true` once completions are taken by interrupt and waiters may sleep.
pub fn irq_mode() -> bool {
    // SAFETY: `irq` is written once in bring-up, before `ACTIVE`.
    ACTIVE.load(Ordering::Acquire)
        && unsafe { DEV.irq }
        && BLOCK_FN.load(Ordering::Acquire) != 0
}

/// `(interrupts taken, waits that slept)`.
pub fn irq_counts() -> (u32, u32) {
    (IRQ_TAKEN.load(Ordering::Relaxed), IRQ_SLEPT.load(Ordering::Relaxed))
}

/// The interrupt handler's arm for an MSI of the kernel's `token` (interrupt
/// context, any CPU): `None` when it is not this controller's; otherwise
/// wake every sleeping waiter, `Some(true)` when one was woken. An MSI needs
/// no acknowledge at the device: the waiter that wakes reaps the queue and
/// rings the completion doorbell.
pub fn msi_irq(token: u32) -> Option<bool> {
    let is_io = token == TOKEN_IO.load(Ordering::Acquire);
    if !is_io && token != TOKEN_ADMIN.load(Ordering::Acquire) {
        return None;
    }
    if !is_io {
        return Some(false);
    }
    IRQ_TAKEN.fetch_add(1, Ordering::Relaxed);
    let wake = WAKE_FN.load(Ordering::Acquire);
    if wake == 0 {
        return Some(false);
    }
    // SAFETY: only `set_irq_hooks` stores here, and it stores a `fn(u32)`.
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

/// Sleep until the next interrupt or `deadline`; `false` when the caller
/// cannot sleep (then it spins, as when polled).
fn sleep_for_completion(slot: usize, deadline: u64) -> bool {
    if !irq_mode() {
        return false;
    }
    let f = BLOCK_FN.load(Ordering::Acquire);
    let tid = azos_sync::waitqueue::caller_tid();
    if f == 0 || tid == 0 || tid == u32::MAX {
        return false;
    }
    SLOT_WAITER[slot].store(tid, Ordering::Release);
    // Re-check after publishing the waiter: a completion posted before the
    // store raised its interrupt before anyone could be woken.
    let done = {
        let _g = LOCK.lock();
        // SAFETY: under `LOCK`.
        let dev = unsafe { &mut *(&raw mut DEV) };
        reap(dev);
        SLOT_DONE[slot].load(Ordering::Acquire) || dev.failed
    };
    let slept = if done {
        true
    } else {
        // SAFETY: only `set_irq_hooks` stores here, and it stores a `fn(u64) -> bool`.
        let f: fn(u64) -> bool = unsafe { core::mem::transmute::<usize, fn(u64) -> bool>(f) };
        let slice = IRQ_SLICE_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000;
        let until = deadline.min(now().saturating_add(slice.max(1)));
        let s = f(until);
        if s {
            IRQ_SLEPT.fetch_add(1, Ordering::Relaxed);
        }
        s
    };
    SLOT_WAITER[slot].store(0, Ordering::Release);
    slept
}

// ---- The I/O queue ----

/// Reap every completion the controller has posted: mark the slot whose
/// command it names done, free the submission slots it reports consumed, and
/// ring the completion doorbell once. A completion naming no command in
/// flight is a controller not following the protocol (it would make some
/// later command look complete before its DMA happened): latch dead.
/// Caller holds [`LOCK`].
fn reap(dev: &mut Dev) {
    let mut any = false;
    while let Some(e) = cqe_peek(dev.icq, &dev.i_cq) {
        dev.i_cq.advance(IO_DEPTH);
        any = true;
        dev.i_sq_head = e.sq_head();
        let slot = e.cid() as usize;
        if slot >= SLOTS || !SLOT_INFLIGHT[slot].load(Ordering::Relaxed) || SLOT_DONE[slot].load(Ordering::Relaxed) {
            latch_dead(dev, "foreign completion");
            return;
        }
        SLOT_STATUS[slot].store(e.status(), Ordering::Relaxed);
        SLOT_DONE[slot].store(true, Ordering::Release);
    }
    if any {
        // SAFETY: the I/O CQ head doorbell of a mapped controller.
        unsafe { core::ptr::write_volatile(dev.cq_doorbell(IO_QID) as *mut u32, dev.i_cq.head as u32) };
    }
}

/// Reset the controller (`CC.EN = 0` stops its DMA) and latch the driver
/// dead. The staging pages stay owned by the driver and are never reused:
/// a command still in the controller may DMA into them until the reset
/// lands, and nothing submits again afterwards.
fn latch_dead(dev: &mut Dev, reason: &str) {
    wr32(dev.bar, proto::REG_CC, 0);
    dev.failed = true;
    dev.ready = false;
    azos_drv_sys::kerr!("[NVME] Error: {} - controller reset, block I/O disabled", reason);
}

/// Publish `sqe` on the I/O submission queue and ring its doorbell. Caller
/// holds [`LOCK`] and has checked the queue is not full.
fn submit(dev: &mut Dev, slot: usize, sqe: &proto::Sqe) -> Result<(), ()> {
    reap(dev);
    if dev.failed || proto::sq_full(dev.i_sq_head, dev.i_tail, IO_DEPTH) {
        return Err(());
    }
    SLOT_DONE[slot].store(false, Ordering::Relaxed);
    SLOT_INFLIGHT[slot].store(true, Ordering::Relaxed);
    sqe_write(dev.isq, dev.i_tail, sqe);
    dev.i_tail = proto::ring_next(dev.i_tail, IO_DEPTH);
    io_wmb();
    // SAFETY: the I/O SQ tail doorbell of a mapped controller.
    unsafe { core::ptr::write_volatile(dev.sq_doorbell(IO_QID) as *mut u32, dev.i_tail as u32) };
    Ok(())
}

/// Wait, WITHOUT [`LOCK`], for slot `slot`'s command, bounded by
/// `timeout_us` of wall-clock time. `Err` when the controller latched dead
/// meanwhile or the deadline passed (it is then latched dead here).
fn wait_done(slot: usize, timeout_us: u64) -> Result<(), ()> {
    azos_sync::lockdep::might_wait_device("nvme wait");
    let deadline = deadline_after_us(timeout_us);
    loop {
        if SLOT_DONE[slot].load(Ordering::Acquire) {
            return Ok(());
        }
        {
            let _g = LOCK.lock();
            // SAFETY: under `LOCK`.
            let dev = unsafe { &mut *(&raw mut DEV) };
            reap(dev);
            if SLOT_DONE[slot].load(Ordering::Acquire) {
                return Ok(());
            }
            if dev.failed {
                return Err(());
            }
            if now() >= deadline {
                latch_dead(dev, "command timeout");
                return Err(());
            }
        }
        if !sleep_for_completion(slot, deadline) {
            core::hint::spin_loop();
        }
    }
}

/// `true` while the driver may submit.
fn usable() -> bool {
    let _g = LOCK.lock();
    // SAFETY: under `LOCK`.
    let dev = unsafe { &*(&raw const DEV) };
    dev.ready && !dev.failed
}

/// Where the data of a command of `chunk` sectors sits and how the
/// controller finds it: build the PRPs over slot `slot`'s pages.
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

/// Copy `src` into slot `slot`'s bounce pages.
fn stage_in(slot: usize, src: &[u8]) {
    let mut off = 0;
    while off < src.len() {
        let n = (src.len() - off).min(PAGE);
        // SAFETY: the slot is this caller's, its previous command (if any)
        // completed, and `src.len() <= SLOT_PAGES * PAGE`.
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr().add(off), SLOT_VA[slot][off / PAGE] as *mut u8, n);
        }
        off += n;
    }
}

/// Copy slot `slot`'s bounce pages out to `dst`, once its command completed.
fn stage_out(slot: usize, dst: &mut [u8]) {
    let mut off = 0;
    while off < dst.len() {
        let n = (dst.len() - off).min(PAGE);
        // SAFETY: the controller posted this slot's completion, so it is
        // done with the pages; the slot is this caller's.
        unsafe {
            core::ptr::copy_nonoverlapping(SLOT_VA[slot][off / PAGE] as *const u8, dst.as_mut_ptr().add(off), n);
        }
        off += n;
    }
}

/// Submit one read/write chunk of `chunk` sectors from `lba` on `slot`
/// (data already staged for a write).
fn submit_chunk(slot: usize, lba: u64, chunk: u32, write: bool) -> Result<(), ()> {
    let bytes = chunk as usize * SECTOR_SIZE;
    let (prp1, prp2) = prps_for(slot, bytes)?;
    let sqe = proto::read_write(slot as u16, NSID, write, lba, chunk, prp1, prp2);
    let _g = LOCK.lock();
    // SAFETY: under `LOCK`.
    let dev = unsafe { &mut *(&raw mut DEV) };
    submit(dev, slot, &sqe)
}

/// Collect slot `slot`'s completion: wait, then check its status. The slot's
/// command is retired either way.
fn finish_chunk(slot: usize, timeout_us: u64) -> Result<(), ()> {
    let r = wait_done(slot, timeout_us);
    if r.is_err() {
        // The command may still be in the controller; the slot stays
        // INFLIGHT (never reused: the driver is latched dead).
        return Err(());
    }
    SLOT_INFLIGHT[slot].store(false, Ordering::Relaxed);
    let st = SLOT_STATUS[slot].load(Ordering::Relaxed);
    if st != 0 {
        azos_drv_sys::kerr!("[NVME] command failed: status type {} code {:#x}",
            proto::status_type(st), proto::status_code(st));
        return Err(());
    }
    Ok(())
}

/// One transfer of `count` sectors from `sector`, chunked and pipelined over
/// the slots free at entry (the first is waited for). `buf` is read (write)
/// or filled (read); it never meets the controller.
fn transfer(sector: u64, count: u32, buf: *mut u8, write: bool) -> Result<(), ()> {
    // SAFETY: `max_sectors` is written in bring-up, before `ACTIVE`.
    let max = unsafe { DEV.max_sectors }.max(1);
    let chunks = (count as usize).div_ceil(max as usize);
    let mut slots: [Option<SlotClaim>; SLOTS] = [const { None }; SLOTS];
    slots[0] = Some(slot_claim());
    let mut k = 1usize;
    while k < SLOTS && k < chunks {
        match slot_try_claim() {
            Some(c) => {
                slots[k] = Some(c);
                k += 1;
            }
            None => break,
        }
    }
    if !usable() {
        return Err(());
    }
    // Per slot: the sector offset and count of the chunk it carries.
    let mut inflight: [Option<(u32, u32)>; SLOTS] = [None; SLOTS];
    let mut result = Ok(());
    let mut done = 0u32;
    let mut i = 0usize;

    // A finished read chunk is copied out; a finished write needs nothing.
    let retire = |slot: usize, off: u32, n: u32| -> Result<(), ()> {
        finish_chunk(slot, IO_TIMEOUT_US)?;
        if !write {
            // SAFETY: `buf` covers `count * 512` bytes (checked by the
            // callers) and `off + n <= count`.
            let dst = unsafe {
                core::slice::from_raw_parts_mut(buf.add(off as usize * SECTOR_SIZE), n as usize * SECTOR_SIZE)
            };
            stage_out(slot, dst);
        }
        Ok(())
    };

    while done < count {
        let j = i % k;
        let slot = match &slots[j] {
            Some(c) => c.0,
            None => {
                result = Err(());
                break;
            }
        };
        // The slot's previous chunk first: its pages are reused.
        if let Some((off, n)) = inflight[j].take() {
            if retire(slot, off, n).is_err() {
                result = Err(());
                break;
            }
        }
        let n = (count - done).min(max);
        let lba = match sector.checked_add(done as u64) {
            Some(l) => l,
            None => {
                result = Err(());
                break;
            }
        };
        if write {
            // SAFETY: `buf` covers `count * 512` bytes.
            let src = unsafe {
                core::slice::from_raw_parts(buf.add(done as usize * SECTOR_SIZE), n as usize * SECTOR_SIZE)
            };
            stage_in(slot, src);
        }
        if submit_chunk(slot, lba, n, write).is_err() {
            result = Err(());
            break;
        }
        inflight[j] = Some((done, n));
        done += n;
        i += 1;
    }
    // Every submitted chunk completes before its slot is released: the
    // controller owns the staging pages until then.
    for j in 0..k {
        if let (Some((off, n)), Some(c)) = (inflight[j].take(), &slots[j]) {
            if retire(c.0, off, n).is_err() {
                result = Err(());
            }
        }
    }
    result
}

// ---- Public API (what `blkdev` forwards to) ----

/// `true` once a controller is up and `blkdev` routes block I/O here.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// `Ok` when a controller is attached ([`attach`] did the work).
pub fn init() -> Result<(), ()> {
    if active() { Ok(()) } else { Err(()) }
}

/// Disk capacity in 512-byte sectors. Lock-free: written once in bring-up.
pub fn capacity_sectors() -> u64 {
    // SAFETY: an aligned u64 load; `capacity` is written once, before `ACTIVE`.
    unsafe { DEV.capacity }
}

/// Read `count` sectors from `sector` into `buf`.
pub fn read(sector: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    let total = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
    if total == 0 || buf.len() < total {
        return Err(());
    }
    if sector.checked_add(count as u64).ok_or(())? > capacity_sectors() {
        return Err(());
    }
    transfer(sector, count, buf.as_mut_ptr(), false)
}

/// Write `count` sectors from `buf` to `sector`. A failure part-way leaves
/// other chunks committed, as for any multi-sector request.
pub fn write(sector: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    let total = (count as usize).checked_mul(SECTOR_SIZE).ok_or(())?;
    if total == 0 || buf.len() < total {
        return Err(());
    }
    if sector.checked_add(count as u64).ok_or(())? > capacity_sectors() {
        return Err(());
    }
    transfer(sector, count, buf.as_ptr() as *mut u8, true)
}

/// Commit every completed write to stable media: one NVM Flush. `Unsupported`
/// when the controller answers Invalid Opcode; `Io` on a dead driver, a
/// timeout or any other status. Never `Ok` without a successful completion.
pub fn flush() -> Result<(), FlushError> {
    let slot = slot_claim();
    {
        let _g = LOCK.lock();
        // SAFETY: under `LOCK`.
        let dev = unsafe { &mut *(&raw mut DEV) };
        if !(dev.ready && !dev.failed) {
            return Err(FlushError::Io);
        }
        let sqe = proto::flush(slot.0 as u16, NSID);
        submit(dev, slot.0, &sqe).map_err(|_| FlushError::Io)?;
    }
    wait_done(slot.0, FLUSH_TIMEOUT_US).map_err(|_| FlushError::Io)?;
    SLOT_INFLIGHT[slot.0].store(false, Ordering::Relaxed);
    let st = SLOT_STATUS[slot.0].load(Ordering::Relaxed);
    match st {
        0 => Ok(()),
        // Generic command status, Invalid Command Opcode.
        0x001 => Err(FlushError::Unsupported),
        _ => {
            azos_drv_sys::kerr!("[NVME] flush status type {} code {:#x}", proto::status_type(st), proto::status_code(st));
            Err(FlushError::Io)
        }
    }
}
