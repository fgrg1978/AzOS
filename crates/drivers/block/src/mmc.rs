// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// SD/eMMC host driver for the SD Host Controller Interface (SDHCI) v3.0
// register model (SDHCI Specification v3.00, SD Association) with ADMA2 data
// transfers and interrupt completion.
//
// Which hardware speaks this register set:
//   - SpacemiT K1 (`k1`): both MMC blocks, `sdhci0@d4280000` and
//     `emmc@d4281000`, are `compatible = "spacemit,k1-sdhci"` in mainline
//     `k1.dtsi` (checked 2026-10-21 against the Linux v7.2.9 tree).
//   - QEMU's `sdhci-pci`, under `mmc-pci` (the MMC flush and interrupt rows).
// The StarFive JH7110 (VisionFive 2) does NOT: its SDIO blocks are
// `starfive,jh7110-mmc`, a Synopsys DesignWare MSHC with a different register
// file, driven by `dwmshc.rs`. This file used to be the VisionFive 2's driver
// as well, modelling the wrong IP.
//
// K1 has not run on silicon either; everything below is checked against QEMU's
// model and the host register model only.
//
// Boot flow (SD card, SDHC):
//   mmc_init → SW-reset → power-on → clock@400kHz → CMD0 → CMD8 → ACMD41 ×N
//             → CMD2 → CMD3(RCA) → CMD7(select) → ACMD6(4-bit) → clock@25MHz
//
// Data path. `mmc_read`/`mmc_write` move up to `MAX_XFER_BLOCKS` sectors per
// command (CMD17/24, or CMD18/25 with Auto CMD12) through ADMA2: the host
// controller walks a descriptor table in RAM (one 8-byte 32-bit descriptor
// per 4 KiB bounce page, the last one flagged End) and moves the data
// itself, so the CPU copies a request in and out of the bounce pages once
// and never touches the Buffer Data Port. The pages and the table are taken
// below 4 GiB (`azos_dma::alloc_below`: a 32-bit ADMA2 descriptor cannot
// name more) and bracketed with the DMA domain's cache maintenance for a
// controller that is not coherent with the CPU.
//
// Completion. The controller's interrupt status is the only thing a request
// waits on. `harvest` reads INT_STATUS, clears exactly the bits it read and
// ORs them into `EVENTS`; the interrupt handler (`irq`, called from the
// kernel's external-interrupt arm and, with Kconfig IRQ_THREADED, from the
// `irq-thread`) and a polling waiter both call it, so one wait path serves
// both modes. Until the kernel wires the line (`mmc_set_irq_mode`) a waiter
// spins on INT_STATUS; afterwards it sleeps (`IrqHooks::block_until`) and
// the handler wakes it by TID, bounded by the request's deadline and a
// short slice so a lost line costs latency, not a hang.
//
// `mmc_flush` (2026-09-28) is the SD/eMMC durability point: CMD13
// SEND_STATUS until the card is back in `tran` with READY_FOR_DATA, error
// bits checked, and — only if an eMMC cache was ever enabled, which this
// driver never does — CMD6 FLUSH_CACHE. Under `--features mmc-pci` (QEMU
// only) this same file drives QEMU's `sdhci-pci`, an SDHCI-v3 model, through
// a BAR the kernel assigns; that is the one place any of it has run.
//
// The register file is reached through [`Regs`]: the kernel's [`Hw`] is a
// volatile MMIO window, the host test (`tests/host/drivers-tests`) drives
// the very same functions over a model of the controller and the card.

use azos_drv_api::block::FlushError;
use azos_dma::Direction;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use crate::dev_queue::{DevQueue, Turn};

#[cfg(feature = "k1")]
use azos_drv_base::platform::hw::{MMC0_BASE, MMC1_BASE};

// ── SDHCI register offsets ────────────────────────────────────────────────────
const SDHCI_BLOCK_SIZE:    usize = 0x04; // 16-bit: [14:12] boundary, [11:0] size
const SDHCI_BLOCK_COUNT:   usize = 0x06; // 16-bit
const SDHCI_ARGUMENT:      usize = 0x08; // 32-bit
const SDHCI_TRANSFER_MODE: usize = 0x0C; // 16-bit
const SDHCI_COMMAND:       usize = 0x0E; // 16-bit
const SDHCI_RESPONSE0:     usize = 0x10; // 32-bit  response[31:0]
const SDHCI_RESPONSE1:     usize = 0x14; // 32-bit  response[63:32]
const SDHCI_RESPONSE2:     usize = 0x18; // 32-bit  response[95:64]
const SDHCI_RESPONSE3:     usize = 0x1C; // 32-bit  response[127:96]
const SDHCI_PRESENT_STATE: usize = 0x24; // 32-bit  read-only
const SDHCI_HOST_CONTROL:  usize = 0x28; // 8-bit
const SDHCI_POWER_CONTROL: usize = 0x29; // 8-bit
const SDHCI_CLOCK_CONTROL: usize = 0x2C; // 16-bit
const SDHCI_TIMEOUT:       usize = 0x2E; // 8-bit   data timeout counter
const SDHCI_SW_RESET:      usize = 0x2F; // 8-bit
const SDHCI_INT_STATUS:    usize = 0x30; // 32-bit
const SDHCI_INT_ENABLE:    usize = 0x34; // 32-bit  status enable
const SDHCI_SIGNAL_ENABLE: usize = 0x38; // 32-bit  IRQ signal enable
const SDHCI_ADMA_ERROR:    usize = 0x54; // 32-bit  ADMA error status
const SDHCI_ADMA_ADDRESS:  usize = 0x58; // 64-bit  ADMA2 descriptor table address
const SDHCI_CAPABILITIES:  usize = 0x40; // 64-bit; [15:8] = base clock MHz

/// CAPABILITIES bit 19: the host supports ADMA2.
const CAP_ADMA2: u32 = 1 << 19;

// PRESENT_STATE bits
const STATE_CMD_INHIBIT:  u32 = 1 << 0;
const STATE_DAT_INHIBIT:  u32 = 1 << 1;
const STATE_CARD_PRESENT: u32 = 1 << 16;

// INT_STATUS bits
const INT_CMD_COMPLETE:  u32 = 1 << 0;
const INT_TRANSFER_DONE: u32 = 1 << 1;
/// Bits 16..=25 (bit 15, the Error Interrupt summary, follows them and is
/// not tracked): command timeout / CRC / end bit / index, data timeout /
/// CRC / end bit, current limit, Auto CMD12 and ADMA errors.
const INT_ERR_MASK:      u32 = 0x03FF_0000;
const INT_ADMA_ERROR:    u32 = 1 << 25;
/// What a request waits on, and what the controller is asked to report (both
/// the status enable and, in interrupt mode, the signal enable).
const EV_MASK:           u32 = INT_CMD_COMPLETE | INT_TRANSFER_DONE | INT_ERR_MASK;

// SW_RESET bits
const RESET_ALL:  u8 = 1 << 0;
const RESET_CMD:  u8 = 1 << 1;
const RESET_DAT:  u8 = 1 << 2;

// HOST_CONTROL bits
const HC_4BIT_BUS:    u8 = 1 << 1;
/// DMA Select [4:3] = 0b10: ADMA2 with 32-bit descriptors.
const HC_DMA_ADMA2_32: u8 = 0b10 << 3;

// POWER_CONTROL: 3.3 V, power on
const PWR_33V_ON: u8 = 0x0F;

// TRANSFER_MODE bits (16-bit register at 0x0C)
const TM_DMA_EN:     u16 = 1 << 0;
const TM_BLK_CNT_EN: u16 = 1 << 1;
const TM_AUTO_CMD12: u16 = 1 << 2;
const TM_READ:       u16 = 1 << 4; // 1 = card-to-host, 0 = host-to-card
const TM_MULTI:      u16 = 1 << 5;

// ── ADMA2 descriptor (SDHCI v3.00 §1.13.2, 32-bit address form) ──────────────
// 8 bytes, little-endian: attribute (16), length (16), address (32).
const ADMA2_VALID:    u16 = 1 << 0;
const ADMA2_END:      u16 = 1 << 1;
/// Act [5:4] = 0b10: transfer the described data ("tran").
const ADMA2_ACT_TRAN: u16 = 0b10 << 4;
const ADMA2_DESC_BYTES: usize = 8;

// ── Response type flags for send_cmd ─────────────────────────────────────────
// Encode SDHCI Command Register bits [5:0]:
//   [5] Data Present Select
//   [4] Command Index Check Enable
//   [3] Command CRC Check Enable
//   [2] reserved (0)
//   [1:0] Response Type: 00=none, 01=136-bit, 10=48-bit, 11=48-bit+busy
const RESP_NONE: u16 = 0x00; // No response
const RESP_R1:   u16 = 0x1A; // 48-bit, CRC + index check
const RESP_R1B:  u16 = 0x1B; // 48-bit + busy (DAT0), CRC + index check
const RESP_R2:   u16 = 0x09; // 136-bit, CRC check only (no index)
const RESP_R3:   u16 = 0x02; // 48-bit, no CRC, no index (OCR)
const RESP_R6:   u16 = 0x1A; // 48-bit, CRC + index (RCA) — same encoding as R1
const RESP_R7:   u16 = 0x1A; // 48-bit, CRC + index (IF_COND)
const RESP_DATA: u16 = 0x20; // OR into flags when command transfers data

// ── SD command indices ────────────────────────────────────────────────────────
const CMD_GO_IDLE:        u16 = 0;
const CMD_ALL_SEND_CID:   u16 = 2;
const CMD_SEND_RCA:       u16 = 3;
const CMD_SELECT:         u16 = 7;
const CMD_SEND_IF_COND:   u16 = 8;
const CMD_SWITCH:         u16 = 6;  // eMMC SWITCH (CMD6); SD's CMD6 is a different command
const CMD_SEND_STATUS:    u16 = 13;
const CMD_SET_BLOCKLEN:   u16 = 16;
const CMD_READ_SINGLE:    u16 = 17;
const CMD_READ_MULTI:     u16 = 18;
const CMD_WRITE_SINGLE:   u16 = 24;
const CMD_WRITE_MULTI:    u16 = 25;
const CMD_APP_CMD:        u16 = 55;
const ACMD_SD_SEND_OP:    u16 = 41;
const ACMD_SET_BUS_WIDTH: u16 = 6;

// ── R1 card status (SD Physical Layer spec, "Card Status") ───────────────────
/// Error bits: OUT_OF_RANGE(31) ADDRESS_ERROR(30) BLOCK_LEN_ERROR(29)
/// ERASE_SEQ_ERROR(28) ERASE_PARAM(27) WP_VIOLATION(26) LOCK_UNLOCK_FAILED(24)
/// COM_CRC_ERROR(23) ILLEGAL_COMMAND(22) CARD_ECC_FAILED(21) CC_ERROR(20)
/// ERROR(19) CSD_OVERWRITE(16) WP_ERASE_SKIP(15) AKE_SEQ_ERROR(3). Most are
/// clear-on-read: the card reports them ONCE, in the response of the command
/// that saw them or of the next one — which is why `mmc_write` checks its
/// own CMD24/CMD25 response instead of leaving everything to `mmc_flush`'s
/// CMD13.
const R1_ERRORS:         u32 = 0xFDF9_8008;
const R1_READY_FOR_DATA: u32 = 1 << 8;
/// eMMC only: SWITCH_ERROR(7), set when a CMD6 was refused.
const R1_SWITCH_ERROR:   u32 = 1 << 7;
const R1_STATE_SHIFT:    u32 = 9;
const R1_STATE_MASK:     u32 = 0xF;
const STATE_TRAN: u32 = 4;
const STATE_RCV:  u32 = 6;
const STATE_PRG:  u32 = 7;

// ── Timeouts and sizes ───────────────────────────────────────────────────────
// Wall-clock bounds on the timebase (the controller has its own data timeout
// too, `SDHCI_TIMEOUT`); a request that misses one fails instead of hanging.
/// A command's Command Complete: a 48-bit exchange at 400 kHz is ~0.2 ms.
const CMD_TIMEOUT_US: u64 = 100_000;
/// CMD/DAT inhibit to clear before a command is issued.
const INHIBIT_TIMEOUT_US: u64 = 250_000;
/// A data command's Transfer Complete (the whole chunk, Auto CMD12 included).
const XFER_TIMEOUT_US: u64 = 4_000_000;
/// An R1b command's busy release (Transfer Complete without data).
const BUSY_TIMEOUT_US: u64 = 4_000_000;
/// `mmc_flush` waiting for the card to leave `prg`: sized for an SD card's
/// garbage collection after a batch of writes (250 ms per block write per
/// the SD spec), not measured on any board.
const FLUSH_TIMEOUT_US: u64 = 5_000_000;
/// SDHCI Timeout Control: DAT timeout = TMCLK × 2^(13 + 0xE), the maximum.
const DATA_TIMEOUT_MAX: u8 = 0x0E;

const PAGE: usize = 4096;
/// Bounce pages per slot, one ADMA2 descriptor each: the most a single
/// command moves. 16 pages = 64 KiB = 128 sectors (BLOCK_COUNT is 16-bit).
const XFER_PAGES: usize = 16;
const MAX_XFER_BLOCKS: u32 = (XFER_PAGES * PAGE / 512) as u32;
/// The highest address a 32-bit ADMA2 descriptor can name (inclusive).
const DMA_MASK_32: u64 = u32::MAX as u64;

// ── Per-slot runtime state ────────────────────────────────────────────────────
#[derive(Clone, Copy)]
struct SlotState {
    rca:      u32,  // Relative Card Address
    is_sdhc:  bool, // High-Capacity card (block-addressed)
    capacity: u64,  // Usable sectors (512 B each)
    ready:    bool,
    /// An eMMC volatile cache was switched on (EXT_CSD[33] CACHE_CTRL = 1).
    /// Nothing in this driver ever sets it: `mmc_init` runs the SD flow only.
    /// `mmc_flush` issues CMD6 FLUSH_CACHE if and only if this is true.
    cache_on: bool,
}

static mut SLOT_STATE: [SlotState; 2] = [
    SlotState { rca: 0, is_sdhc: false, capacity: 0, ready: false, cache_on: false },
    SlotState { rca: 0, is_sdhc: false, capacity: 0, ready: false, cache_on: false },
];

fn slot_state(idx: usize) -> SlotState {
    // SAFETY: written only by `init_on` (boot, before any request of the slot).
    unsafe { *(&raw const SLOT_STATE[idx]) }
}

/// A write on this slot failed — its CMD24/CMD25 response carried an error
/// bit, or the transfer itself failed — since the last `mmc_flush`.
/// `mmc_flush` reports it (`Err(Io)`) and clears it, so a flush never
/// confirms a batch that lost a write whose error the card has already
/// reported and forgotten.
static WRITE_FAULT: [AtomicBool; 2] = [AtomicBool::new(false), AtomicBool::new(false)];

/// Evidence for the QEMU row: CMD13 responses `mmc_flush` read, and the last
/// status it accepted. A flush that answers `Ok` without asking the card
/// leaves both untouched.
static FLUSH_STATUS_READS: AtomicU32 = AtomicU32::new(0);
static FLUSH_LAST_STATUS:  AtomicU32 = AtomicU32::new(0);

/// `(CMD13 responses read by mmc_flush, last accepted status)` — see
/// `FLUSH_STATUS_READS`.
pub fn mmc_flush_evidence() -> (u32, u32) {
    (FLUSH_STATUS_READS.load(Ordering::Acquire), FLUSH_LAST_STATUS.load(Ordering::Acquire))
}

/// One request queue per slot (owner rule F1, wave 15 MMC). A request
/// (`mmc_read`, `mmc_write`, `mmc_flush`) owns its controller from its turn
/// to its last `INT_TRANSFER_DONE` — two harts interleaving
/// `SDHCI_ARGUMENT`/`SDHCI_COMMAND` writes would each read back the other's
/// data (U05-8) — but holds the queue's `Mutex` only while it writes the
/// registers that start a command ([`Turn::program`]). Every device wait
/// (`wait_inhibit`, `wait_events`, the CMD13 polls) runs in [`Turn::wait`]
/// with no lock held, and a second caller sleeps in the queue until its turn
/// instead of spinning on a mutex held across the transfer. Per slot: MMC0
/// and MMC1 are two independent controllers
/// (`platform::hw::MMC0_BASE`/`MMC1_BASE`). `mmc_init` runs at boot before
/// any request and does not queue.
static MMC_QUEUES: [DevQueue; 2] = [DevQueue::new(), DevQueue::new()];

// ── Register access ──────────────────────────────────────────────────────────
/// A controller's SDHCI register file. [`Hw`] is the MMIO window; the host
/// test implements it over a model of the controller and the card.
pub trait Regs {
    /// The window's address: names the controller to the DMA domain registry
    /// (a platform device may differ from the default in cache coherence).
    fn base(&self) -> usize;
    fn rd8(&self, off: usize) -> u8;
    fn rd16(&self, off: usize) -> u16;
    fn rd32(&self, off: usize) -> u32;
    fn wr8(&self, off: usize, val: u8);
    fn wr16(&self, off: usize, val: u16);
    fn wr32(&self, off: usize, val: u32);
}

/// The controller's mapped register window at this address.
pub struct Hw(pub usize);

impl Regs for Hw {
    fn base(&self) -> usize { self.0 }
    #[inline(always)]
    fn rd8(&self, off: usize) -> u8 {
        // SAFETY: `self.0` is a mapped SDHCI window (`slot_base`) and `off` a register inside it.
        unsafe { core::ptr::read_volatile((self.0 + off) as *const u8) }
    }
    #[inline(always)]
    fn rd16(&self, off: usize) -> u16 {
        // SAFETY: as `rd8`.
        unsafe { core::ptr::read_volatile((self.0 + off) as *const u16) }
    }
    #[inline(always)]
    fn rd32(&self, off: usize) -> u32 {
        // SAFETY: as `rd8`.
        unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
    }
    #[inline(always)]
    fn wr8(&self, off: usize, val: u8) {
        // SAFETY: as `rd8`.
        unsafe { core::ptr::write_volatile((self.0 + off) as *mut u8, val) }
    }
    #[inline(always)]
    fn wr16(&self, off: usize, val: u16) {
        // SAFETY: as `rd8`.
        unsafe { core::ptr::write_volatile((self.0 + off) as *mut u16, val) }
    }
    #[inline(always)]
    fn wr32(&self, off: usize, val: u32) {
        // SAFETY: as `rd8`.
        unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, val) }
    }
}

/// A store to RAM (descriptors, bounce pages) ordered before the MMIO store
/// that tells the controller to read it. `fence w,o` / `dsb st` order a
/// memory write before a device write, which the portable fences do not
/// promise.
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
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// The MMIO read that saw the controller finish ordered before the CPU's
/// reads of what it wrote to RAM.
#[inline(always)]
fn io_rmb() {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: a fence has no operands and no effect beyond ordering.
    unsafe {
        core::arch::asm!("fence i, r", options(nostack))
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: as above.
    unsafe {
        core::arch::asm!("dsb ld", options(nostack))
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
    core::sync::atomic::fence(Ordering::SeqCst);
}

fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

fn deadline_after_us(us: u64) -> u64 {
    now().saturating_add(us.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000)
}

// ── Completion events and the interrupt ──────────────────────────────────────
pub use crate::dev_queue::IrqHooks;

static HOOKS: AtomicPtr<IrqHooks> = AtomicPtr::new(core::ptr::null_mut());

fn hooks() -> Option<&'static IrqHooks> {
    // SAFETY: only `set_irq_mode_on` stores here, and it stores a `&'static IrqHooks`.
    unsafe { HOOKS.load(Ordering::Acquire).as_ref() }
}

/// Status bits harvested and not yet consumed by the request waiting on
/// them, per slot.
static EVENTS: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
/// The interrupt line the slot completes on (`u32::MAX`: polled).
static IRQ_LINE: [AtomicU32; 2] = [AtomicU32::new(u32::MAX), AtomicU32::new(u32::MAX)];
/// The task sleeping for the slot's next event (0: none).
static WAITER: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
/// Interrupts taken / waits that slept (diagnostics, `mmc_irq_counts`).
static IRQ_TAKEN: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static IRQ_SLEPT: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];

fn irq_mode(idx: usize) -> bool {
    IRQ_LINE[idx].load(Ordering::Acquire) != u32::MAX
}

/// Move the controller's pending events into `EVENTS`: read INT_STATUS,
/// write back exactly the bits read (write-1-to-clear: an event raised
/// between the read and the write stays pending), OR them in. Idempotent
/// across two callers racing on the same bits.
fn harvest<R: Regs>(r: &R, idx: usize) -> u32 {
    let st = r.rd32(SDHCI_INT_STATUS) & EV_MASK;
    if st != 0 {
        r.wr32(SDHCI_INT_STATUS, st);
        EVENTS[idx].fetch_or(st, Ordering::AcqRel);
    }
    st
}

/// Forget everything pending, before a command is issued.
fn clear_events<R: Regs>(r: &R, idx: usize) {
    r.wr32(SDHCI_INT_STATUS, 0xFFFF_FFFF);
    EVENTS[idx].store(0, Ordering::Release);
}

/// The interrupt handler's arm for `line` (interrupt context, any CPU):
/// `None` when the line is not a slot's; otherwise harvest the controller's
/// events (which quiets a level line) and wake the sleeping waiter,
/// `Some(true)` when there was one.
pub fn irq(line: u32) -> Option<bool> {
    let idx = (0..2).find(|&i| IRQ_LINE[i].load(Ordering::Acquire) == line)?;
    let base = slot_base(if idx == 0 { MmcSlot::Emmc } else { MmcSlot::Sd });
    Some(irq_on(&Hw(base), idx))
}

/// [`irq`] for slot `idx` over `r`.
pub fn irq_on<R: Regs>(r: &R, idx: usize) -> bool {
    harvest(r, idx);
    IRQ_TAKEN[idx].fetch_add(1, Ordering::Relaxed);
    let tid = WAITER[idx].load(Ordering::Acquire);
    match hooks() {
        Some(h) if tid != 0 => {
            (h.wake)(tid);
            true
        }
        _ => false,
    }
}

/// Sleep until the slot's next interrupt, the `deadline`, or one slice
/// (Kconfig `VIRTIO_BLK_IRQ_SLICE_US`: never straight to the deadline, an
/// idle CPU under QEMU `-icount ... sleep=off` jumps its clock to the next
/// timer and would declare the card dead before the host answered).
/// `false` when the caller cannot sleep (polled mode, no scheduler): it then
/// spins.
fn sleep_for_event<R: Regs>(r: &R, idx: usize, deadline: u64) -> bool {
    if !irq_mode(idx) {
        return false;
    }
    let Some(h) = hooks() else { return false };
    let tid = (h.tid)();
    if tid == 0 || tid == u32::MAX {
        return false;
    }
    WAITER[idx].store(tid, Ordering::Release);
    // An event raised before the waiter was published woke nobody: look
    // again before sleeping.
    harvest(r, idx);
    let slept = if EVENTS[idx].load(Ordering::Acquire) != 0 {
        true
    } else {
        let slice = azos_limits::VIRTIO_BLK_IRQ_SLICE_US as u64
            * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000;
        let until = deadline.min(now().saturating_add(slice.max(1)));
        let s = (h.block_until)(until);
        if s {
            IRQ_SLEPT[idx].fetch_add(1, Ordering::Relaxed);
        }
        s
    };
    WAITER[idx].store(0, Ordering::Release);
    slept
}

/// Wait for the event `want` (one bit of `EV_MASK`) of slot `idx`, up to
/// `timeout_us`. `Err` on any error bit (the lines are reset so the next
/// command starts clean) and on the deadline.
fn wait_events<R: Regs>(r: &R, idx: usize, want: u32, timeout_us: u64) -> Result<(), ()> {
    let deadline = deadline_after_us(timeout_us);
    loop {
        harvest(r, idx);
        let ev = EVENTS[idx].load(Ordering::Acquire);
        if ev & INT_ERR_MASK != 0 {
            let adma = if ev & INT_ADMA_ERROR != 0 { r.rd32(SDHCI_ADMA_ERROR) } else { 0 };
            azos_drv_sys::kerr!("[MMC] slot {}: error interrupt {:#010x} (ADMA error {:#x}) waiting for {:#x}",
                idx, ev & INT_ERR_MASK, adma, want);
            recover(r, idx);
            return Err(());
        }
        if ev & want != 0 {
            EVENTS[idx].fetch_and(!want, Ordering::AcqRel);
            return Ok(());
        }
        if now() >= deadline {
            azos_drv_sys::kerr!("[MMC] slot {}: timeout waiting for {:#x} ({} us)", idx, want, timeout_us);
            recover(r, idx);
            return Err(());
        }
        if !sleep_for_event(r, idx, deadline) {
            core::hint::spin_loop();
        }
    }
}

/// After an error or a timeout: reset the command and data lines (SDHCI
/// §3.7.1: the controller is not usable again until they are), drop what is
/// pending.
fn recover<R: Regs>(r: &R, idx: usize) {
    r.wr8(SDHCI_SW_RESET, RESET_CMD | RESET_DAT);
    for _ in 0..200_000u32 {
        if r.rd8(SDHCI_SW_RESET) & (RESET_CMD | RESET_DAT) == 0 { break; }
    }
    clear_events(r, idx);
}

/// Take the slot's completions by interrupt on `line` from now on, with the
/// kernel's sleep and wake `hooks`. Call BEFORE the interrupt controller
/// enables `line` (the handler, [`irq`], must already recognise it). `false`
/// where it cannot be (slot not initialised, or `mmc-poll-canary`).
pub fn set_irq_mode_on<R: Regs>(r: &R, slot: MmcSlot, line: u32, hooks: &'static IrqHooks) -> bool {
    let idx = slot as usize;
    if cfg!(feature = "mmc-poll-canary") || !slot_state(idx).ready {
        return false;
    }
    HOOKS.store(hooks as *const IrqHooks as *mut IrqHooks, Ordering::Release);
    // Whatever completed so far was polled: drop it, so the line is not
    // asserted the moment the controller enables it.
    clear_events(r, idx);
    IRQ_LINE[idx].store(line, Ordering::Release);
    r.wr32(SDHCI_SIGNAL_ENABLE, EV_MASK);
    true
}

/// Back to polled completions (the line could not be routed).
pub fn irq_off_on<R: Regs>(r: &R, slot: MmcSlot) {
    let idx = slot as usize;
    r.wr32(SDHCI_SIGNAL_ENABLE, 0);
    IRQ_LINE[idx].store(u32::MAX, Ordering::Release);
}

/// `(interrupts taken, waits that slept)` of `slot`.
pub fn mmc_irq_counts(slot: MmcSlot) -> (u32, u32) {
    let i = slot as usize;
    (IRQ_TAKEN[i].load(Ordering::Relaxed), IRQ_SLEPT[i].load(Ordering::Relaxed))
}

// ── DMA memory ───────────────────────────────────────────────────────────────
/// A slot's ADMA2 descriptor table and bounce pages: CPU and bus addresses,
/// allocated once at the first `mmc_init` and kept.
struct DmaMem {
    ready:    AtomicBool,
    table_va: AtomicUsize,
    table_pa: AtomicU64,
    page_va:  [AtomicUsize; XFER_PAGES],
    page_pa:  [AtomicU64; XFER_PAGES],
}

impl DmaMem {
    const fn new() -> Self {
        DmaMem {
            ready: AtomicBool::new(false),
            table_va: AtomicUsize::new(0),
            table_pa: AtomicU64::new(0),
            page_va: [const { AtomicUsize::new(0) }; XFER_PAGES],
            page_pa: [const { AtomicU64::new(0) }; XFER_PAGES],
        }
    }
}

static DMA: [DmaMem; 2] = [DmaMem::new(), DmaMem::new()];

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

/// One zeroed page a 32-bit ADMA2 descriptor can name: `(CPU address, bus address)`.
fn alloc_dma_page() -> Option<(usize, u64)> {
    let pa = azos_dma::alloc_below(&Pmm, DMA_MASK_32, PAGE).ok()?;
    let va = azos_mm::addr::phys_to_virt(pa as usize);
    // SAFETY: a page the allocator just handed out, mapped in the kernel's
    // direct map; nothing else refers to it.
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE) };
    Some((va, pa))
}

/// The slot's table and bounce pages, allocated if they are not yet.
fn dma_prepare(idx: usize) -> bool {
    let d = &DMA[idx];
    if d.ready.load(Ordering::Acquire) {
        return true;
    }
    let Some((tva, tpa)) = alloc_dma_page() else { return false };
    d.table_va.store(tva, Ordering::Relaxed);
    d.table_pa.store(tpa, Ordering::Relaxed);
    for p in 0..XFER_PAGES {
        let Some((va, pa)) = alloc_dma_page() else {
            // Give back what this attempt took.
            for q in 0..p {
                let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr(d.page_pa[q].load(Ordering::Relaxed) as usize));
            }
            let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr(tpa as usize));
            return false;
        };
        d.page_va[p].store(va, Ordering::Relaxed);
        d.page_pa[p].store(pa, Ordering::Relaxed);
    }
    d.ready.store(true, Ordering::Release);
    true
}

/// One ADMA2 descriptor in its 8-byte little-endian form: a valid "tran"
/// descriptor of `len` bytes (1..=65535) at bus address `addr`, flagged End
/// when it is the last of the table.
pub fn adma2_descriptor(addr: u32, len: usize, last: bool) -> [u8; ADMA2_DESC_BYTES] {
    debug_assert!(len >= 1 && len <= 0xFFFF);
    let attr = ADMA2_VALID | ADMA2_ACT_TRAN | if last { ADMA2_END } else { 0 };
    let mut d = [0u8; ADMA2_DESC_BYTES];
    d[0..2].copy_from_slice(&attr.to_le_bytes());
    d[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    d[4..8].copy_from_slice(&addr.to_le_bytes());
    d
}

/// Describe a transfer of `bytes` over the first `pages` bounce pages of
/// slot `idx` in its table: one descriptor per page, the last one End and
/// as long as what is left.
fn write_table(idx: usize, bytes: usize) -> usize {
    let d = &DMA[idx];
    let pages = bytes.div_ceil(PAGE);
    debug_assert!(pages >= 1 && pages <= XFER_PAGES);
    let table = d.table_va.load(Ordering::Relaxed) as *mut u8;
    for p in 0..pages {
        let len = (bytes - p * PAGE).min(PAGE);
        let pa = d.page_pa[p].load(Ordering::Relaxed);
        debug_assert!(pa <= DMA_MASK_32 - (PAGE as u64 - 1));
        let desc = adma2_descriptor(pa as u32, len, p + 1 == pages);
        // SAFETY: the table page is ours and `p < XFER_PAGES`, so the 8-byte
        // entry lies inside it.
        unsafe { core::ptr::copy_nonoverlapping(desc.as_ptr(), table.add(p * ADMA2_DESC_BYTES), ADMA2_DESC_BYTES) };
    }
    pages
}

/// Copy `src` into slot `idx`'s bounce pages (a write, before the command).
fn bounce_in(idx: usize, src: &[u8]) {
    let d = &DMA[idx];
    for (p, chunk) in src.chunks(PAGE).enumerate() {
        let va = d.page_va[p].load(Ordering::Relaxed) as *mut u8;
        // SAFETY: bounce page `p` is ours, `chunk` is at most a page, and
        // the two do not overlap (the page is not caller memory).
        unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), va, chunk.len()) };
    }
}

/// Copy slot `idx`'s bounce pages out to `dst` (a read, after the transfer).
fn bounce_out(idx: usize, dst: &mut [u8]) {
    let d = &DMA[idx];
    for (p, chunk) in dst.chunks_mut(PAGE).enumerate() {
        let va = d.page_va[p].load(Ordering::Relaxed) as *const u8;
        // SAFETY: as `bounce_in`.
        unsafe { core::ptr::copy_nonoverlapping(va, chunk.as_mut_ptr(), chunk.len()) };
    }
}

// ── Clock setup ───────────────────────────────────────────────────────────────
/// Set SDCLK to the highest frequency ≤ `target_hz`.
///
/// Reads the base clock from CAPABILITIES[15:8] (MHz).
/// Uses the SDHCI v3 10-bit divider: SDCLK = base / (2 × N), N = 0 → bypass.
/// Returns `false` if the internal clock never becomes stable.
fn mmc_set_clock<R: Regs>(r: &R, target_hz: u32) -> bool {
    // Preserve timeout byte; disable SD clock first.
    let timeout = r.rd8(SDHCI_TIMEOUT);
    r.wr16(SDHCI_CLOCK_CONTROL, 0);

    // Base clock from capabilities [15:8] in MHz (8-bit field in SDHCI v3).
    let caps     = r.rd32(SDHCI_CAPABILITIES);
    let base_mhz = ((caps >> 8) & 0xFF) as u32;
    let base_hz  = if base_mhz > 0 { base_mhz * 1_000_000 } else { 50_000_000 };

    // Divider N: SDCLK = base / (2N).  N=0 → divide-by-1 on some controllers.
    let n: u32 = if target_hz >= base_hz {
        0
    } else {
        (base_hz + 2 * target_hz - 1) / (2 * target_hz) // ceiling division
    }.min(0x3FF);

    // SDHCI v3 10-bit divider: bits [15:8] = N[7:0], bits [7:6] = N[9:8].
    let n_lo = (n & 0xFF) as u16;
    let n_hi = ((n >> 8) & 0x3) as u16;
    let clkctl: u16 = (n_lo << 8) | (n_hi << 6) | 0x01; // bit 0 = Internal Clock Enable

    r.wr16(SDHCI_CLOCK_CONTROL, clkctl);
    r.wr8(SDHCI_TIMEOUT, timeout);

    // Wait for Internal Clock Stable (bit 1).
    for _ in 0..200_000u32 {
        if r.rd16(SDHCI_CLOCK_CONTROL) & 0x02 != 0 {
            r.wr16(SDHCI_CLOCK_CONTROL, clkctl | 0x04); // bit 2 = SD Clock Enable
            return true;
        }
    }
    false
}

// ── Command engine ────────────────────────────────────────────────────────────
/// A step that writes registers: under the queue's lock when queued.
fn programming<T>(turn: Option<&Turn<'_>>, f: impl FnOnce() -> T) -> T {
    match turn { Some(t) => t.program(f), None => f() }
}

/// A device wait: with no lock held when queued.
fn waiting<T>(turn: Option<&Turn<'_>>, f: impl FnOnce() -> T) -> T {
    match turn { Some(t) => t.wait(f), None => f() }
}

/// Spin until CMD (and optionally DAT) inhibit clears.
fn wait_inhibit<R: Regs>(r: &R, check_dat: bool) -> bool {
    let mask = STATE_CMD_INHIBIT | if check_dat { STATE_DAT_INHIBIT } else { 0 };
    let deadline = deadline_after_us(INHIBIT_TIMEOUT_US);
    loop {
        if r.rd32(SDHCI_PRESENT_STATE) & mask == 0 { return true; }
        if now() >= deadline { return false; }
        core::hint::spin_loop();
    }
}

/// Issue one command without data and return the 4 response registers.
/// `flags` = RESP_xxx constant. An R1b command (DAT0 busy) is complete when
/// the controller reports Transfer Complete, i.e. when the busy ended.
fn send_cmd_on<R: Regs>(r: &R, idx: usize, turn: Option<&Turn<'_>>, cmd: u16, arg: u32, flags: u16) -> Option<[u32; 4]> {
    let busy = flags & 0x3 == 0x3;
    if !waiting(turn, || wait_inhibit(r, busy)) { return None; }

    programming(turn, || {
        clear_events(r, idx);
        r.wr32(SDHCI_ARGUMENT, arg);
        r.wr16(SDHCI_TRANSFER_MODE, 0);
        // [15:8] = command index, [5:0] = flags (Data Present / Index / CRC / RespType)
        r.wr16(SDHCI_COMMAND, ((cmd & 0x3F) << 8) | (flags & 0x3F));
    });

    waiting(turn, || wait_events(r, idx, INT_CMD_COMPLETE, CMD_TIMEOUT_US)).ok()?;
    let resp = [
        r.rd32(SDHCI_RESPONSE0),
        r.rd32(SDHCI_RESPONSE1),
        r.rd32(SDHCI_RESPONSE2),
        r.rd32(SDHCI_RESPONSE3),
    ];
    if busy {
        waiting(turn, || wait_events(r, idx, INT_TRANSFER_DONE, BUSY_TIMEOUT_US)).ok()?;
    }
    Some(resp)
}

/// [`send_cmd_on`] outside a queued request (`mmc_init`).
fn send_cmd<R: Regs>(r: &R, idx: usize, cmd: u16, arg: u32, flags: u16) -> Option<[u32; 4]> {
    send_cmd_on(r, idx, None, cmd, arg, flags)
}

/// One data command of `nblk` sectors (1..=`MAX_XFER_BLOCKS`) at card
/// address `addr` through ADMA2 over the slot's bounce pages; for a write
/// they already hold the data. Returns the command's R1 response. `Err` on
/// any controller error, ADMA error or timeout (the lines are reset).
fn xfer_chunk<R: Regs>(r: &R, idx: usize, turn: &Turn<'_>, write: bool, addr: u32, nblk: u32) -> Result<u32, ()> {
    debug_assert!(nblk >= 1 && nblk <= MAX_XFER_BLOCKS);
    let d = &DMA[idx];
    let bytes = nblk as usize * 512;
    let pages = write_table(idx, bytes);

    // Hand the table and the pages to the device: a non-coherent controller
    // reads RAM behind the CPU's caches (no-op on a coherent one).
    let domain = azos_dma::registry::domain_for_mmio(r.base() as u64);
    let dir = if write { Direction::ToDevice } else { Direction::FromDevice };
    // SAFETY: the table and the pages are ours, mapped kernel memory.
    unsafe {
        azos_dma::cache::sync_for_device(domain, d.table_va.load(Ordering::Relaxed), pages * ADMA2_DESC_BYTES, Direction::ToDevice);
        for p in 0..pages {
            azos_dma::cache::sync_for_device(domain, d.page_va[p].load(Ordering::Relaxed), PAGE, dir);
        }
    }
    io_wmb();

    if !turn.wait(|| wait_inhibit(r, true)) { return Err(()); }

    let (cmd, tm) = match (write, nblk > 1) {
        (false, false) => (CMD_READ_SINGLE, TM_DMA_EN | TM_BLK_CNT_EN | TM_READ),
        (false, true)  => (CMD_READ_MULTI,  TM_DMA_EN | TM_BLK_CNT_EN | TM_READ | TM_MULTI | TM_AUTO_CMD12),
        (true, false)  => (CMD_WRITE_SINGLE, TM_DMA_EN | TM_BLK_CNT_EN),
        (true, true)   => (CMD_WRITE_MULTI,  TM_DMA_EN | TM_BLK_CNT_EN | TM_MULTI | TM_AUTO_CMD12),
    };
    let table_pa = d.table_pa.load(Ordering::Relaxed);
    turn.program(|| {
        clear_events(r, idx);
        r.wr16(SDHCI_BLOCK_SIZE, 512);
        r.wr16(SDHCI_BLOCK_COUNT, nblk as u16);
        r.wr32(SDHCI_ADMA_ADDRESS, table_pa as u32);
        r.wr32(SDHCI_ADMA_ADDRESS + 4, (table_pa >> 32) as u32);
        r.wr32(SDHCI_ARGUMENT, addr);
        // Write TRANSFER_MODE then COMMAND (order matters for some controllers).
        r.wr16(SDHCI_TRANSFER_MODE, tm);
        // R1 response + data present (bit 5)
        r.wr16(SDHCI_COMMAND, (cmd << 8) | (RESP_R1 | RESP_DATA));
    });

    turn.wait(|| wait_events(r, idx, INT_CMD_COMPLETE, CMD_TIMEOUT_US))?;
    // The card's verdict on the command (address, write protect, ...).
    let r1 = r.rd32(SDHCI_RESPONSE0);
    turn.wait(|| wait_events(r, idx, INT_TRANSFER_DONE, XFER_TIMEOUT_US))?;

    io_rmb();
    if !write {
        // SAFETY: as above.
        unsafe {
            for p in 0..pages {
                azos_dma::cache::sync_for_cpu(domain, d.page_va[p].load(Ordering::Relaxed), PAGE, Direction::FromDevice);
            }
        }
    }
    Ok(r1)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// MMC/SD controller slot.
#[derive(Clone, Copy, PartialEq)]
pub enum MmcSlot {
    Emmc = 0, // SDIO0 @ MMC0_BASE — eMMC (onboard)
    Sd   = 1, // SDIO1 @ MMC1_BASE — microSD slot
}

#[cfg(feature = "k1")]
fn slot_base(slot: MmcSlot) -> usize {
    match slot { MmcSlot::Emmc => MMC0_BASE, MmcSlot::Sd => MMC1_BASE }
}

/// `mmc-pci` (QEMU only): the SDHCI register block is BAR 0 of QEMU's
/// `sdhci-pci`, at whatever address the kernel assigned — see
/// [`mmc_bind_pci_bar`]. Both slots name it; 0 = not bound.
#[cfg(not(feature = "k1"))]
static PCI_BAR: AtomicUsize = AtomicUsize::new(0);
/// The PLIC/APLIC source the function's INTx pin is wired to.
#[cfg(not(feature = "k1"))]
static PCI_LINE: AtomicU32 = AtomicU32::new(u32::MAX);

#[cfg(not(feature = "k1"))]
fn slot_base(_slot: MmcSlot) -> usize {
    PCI_BAR.load(Ordering::Acquire)
}

/// Point this driver at a mapped SDHCI BAR (`mmc-pci`, QEMU only) whose INTx
/// arrives on interrupt-controller source `line`.
#[cfg(not(feature = "k1"))]
pub fn mmc_bind_pci_bar(base: usize, line: u32) {
    PCI_LINE.store(line, Ordering::Release);
    PCI_BAR.store(base, Ordering::Release);
}

/// The interrupt-controller source of `slot`'s SDHCI block. K1: the sources
/// of `sdhci0` and `emmc` (`k1.dtsi`: 99, 101), which `MMC0_BASE` /
/// `MMC1_BASE` name.
#[cfg(feature = "k1")]
fn board_irq_line(slot: MmcSlot) -> Option<u32> {
    Some(match slot { MmcSlot::Emmc => 99, MmcSlot::Sd => 101 })
}

#[cfg(not(feature = "k1"))]
fn board_irq_line(_slot: MmcSlot) -> Option<u32> {
    Some(PCI_LINE.load(Ordering::Acquire)).filter(|&l| l != u32::MAX)
}

/// The line `slot` can complete requests on, once its card is initialised:
/// what the kernel routes and hands to [`mmc_set_irq_mode`]. `None`: the
/// slot stays polled.
pub fn mmc_irq_line(slot: MmcSlot) -> Option<u32> {
    if !slot_state(slot as usize).ready { return None; }
    board_irq_line(slot)
}

/// Take `slot`'s completions by interrupt on `line` ([`set_irq_mode_on`]).
pub fn mmc_set_irq_mode(slot: MmcSlot, line: u32, hooks: &'static IrqHooks) -> bool {
    let base = slot_base(slot);
    base != 0 && set_irq_mode_on(&Hw(base), slot, line, hooks)
}

/// Back to polled completions ([`irq_off_on`]).
pub fn mmc_irq_off(slot: MmcSlot) {
    let base = slot_base(slot);
    if base != 0 { irq_off_on(&Hw(base), slot); }
}

/// Initialise an SD card in `slot`.
///
/// Performs the full SD initialisation sequence:
///   SW-reset → power-on → 400 kHz clock → CMD0 → CMD8 → ACMD41×N →
///   CMD2 → CMD3 → CMD7 → CMD16 (SDSC) → ACMD6 (4-bit) → 25 MHz clock.
///
/// Returns `true` on success.  Safe to call multiple times (re-initialises).
pub fn mmc_init(slot: MmcSlot) -> bool {
    let base = slot_base(slot);
    if base == 0 { return false; }
    init_on(&Hw(base), slot)
}

/// [`mmc_init`] over `r`.
pub fn init_on<R: Regs>(r: &R, slot: MmcSlot) -> bool {
    let idx  = slot as usize;

    // ── 1. Software reset (all lines) ─────────────────────────────────────────
    r.wr8(SDHCI_SW_RESET, RESET_ALL);
    for _ in 0..200_000u32 {
        if r.rd8(SDHCI_SW_RESET) & RESET_ALL == 0 { break; }
    }

    // The data path is ADMA2: a host without it cannot run this driver.
    if r.rd32(SDHCI_CAPABILITIES) & CAP_ADMA2 == 0 {
        azos_drv_sys::kerr!("[MMC] slot {}: controller does not advertise ADMA2", idx);
        return false;
    }
    if !dma_prepare(idx) {
        azos_drv_sys::kerr!("[MMC] slot {}: no DMA-reachable memory for the ADMA2 table", idx);
        return false;
    }

    // ── 2. Power on at 3.3 V ──────────────────────────────────────────────────
    r.wr8(SDHCI_POWER_CONTROL, PWR_33V_ON);

    // ── 3. SD clock at 400 kHz (card identification frequency) ───────────────
    if !mmc_set_clock(r, 400_000) {
        azos_drv_sys::kerr!("[MMC] slot {}: clock setup failed", idx);
        return false;
    }

    // ── 4. Event reporting: status bits on, the line only once the kernel ────
    // routes it (`mmc_set_irq_mode`); the reset above dropped both.
    r.wr8(SDHCI_TIMEOUT, DATA_TIMEOUT_MAX);
    r.wr32(SDHCI_INT_ENABLE,    EV_MASK);
    r.wr32(SDHCI_SIGNAL_ENABLE, if irq_mode(idx) { EV_MASK } else { 0 });
    clear_events(r, idx);

    // ── 5. Card presence ──────────────────────────────────────────────────────
    if r.rd32(SDHCI_PRESENT_STATE) & STATE_CARD_PRESENT == 0 {
        azos_drv_sys::kprintln!("[MMC] slot {}: no card present", idx);
        return false;
    }

    // ── 6. CMD0 — GO_IDLE_STATE ───────────────────────────────────────────────
    send_cmd(r, idx, CMD_GO_IDLE, 0, RESP_NONE);
    for _ in 0..10_000u32 { core::hint::spin_loop(); }

    // ── 7. CMD8 — SEND_IF_COND (VHS=1 → 2.7-3.6 V, check pattern=0xAA) ───────
    // A valid echo-back (pattern matches) means the card supports SDHC/SDXC.
    let sdhc_hint = match send_cmd(r, idx, CMD_SEND_IF_COND, 0x0000_01AA, RESP_R7) {
        Some(resp) if resp[0] & 0x1FF == 0x1AA => true,
        _ => false,
    };

    // ── 8. ACMD41 — SD_SEND_OP_COND, repeat until power-up bit set ───────────
    // HCS=1 if sdhc_hint (tells card we support high capacity).
    // Voltage window: 3.0-3.6 V (0xFF8000).
    let acmd41_arg = if sdhc_hint { 0x4000_0000u32 } else { 0 } | 0x00FF_8000;
    let mut ocr = 0u32;
    for _ in 0..1_000u32 {
        send_cmd(r, idx, CMD_APP_CMD, 0, RESP_R1); // CMD55 prefix
        if let Some(resp) = send_cmd(r, idx, ACMD_SD_SEND_OP, acmd41_arg, RESP_R3) {
            ocr = resp[0];
            if ocr >> 31 != 0 { break; } // power-up complete
        }
        for _ in 0..5_000u32 { core::hint::spin_loop(); }
    }
    if ocr >> 31 == 0 {
        azos_drv_sys::kerr!("[MMC] slot {}: ACMD41 timeout (OCR={:#x})", idx, ocr);
        return false;
    }
    let is_sdhc = (ocr >> 30) & 1 != 0; // CCS bit: 1 = SDHC/SDXC block-addressed

    // ── 9. CMD2 — ALL_SEND_CID ────────────────────────────────────────────────
    send_cmd(r, idx, CMD_ALL_SEND_CID, 0, RESP_R2);

    // ── 10. CMD3 — SEND_RELATIVE_ADDR → get RCA ───────────────────────────────
    let rca = match send_cmd(r, idx, CMD_SEND_RCA, 0, RESP_R6) {
        Some(resp) => resp[0] >> 16,
        None => {
            azos_drv_sys::kerr!("[MMC] slot {}: CMD3 (RCA) failed", idx);
            return false;
        }
    };

    // ── 11. CMD7 — SELECT card (tran state); R1b: done when DAT0 is released ─
    if send_cmd(r, idx, CMD_SELECT, rca << 16, RESP_R1B).is_none() {
        azos_drv_sys::kerr!("[MMC] slot {}: CMD7 (select) failed", idx);
        return false;
    }

    // ── 12. CMD16 — SET_BLOCKLEN 512 B (SDSC only; SDHC ignores it) ──────────
    if !is_sdhc {
        send_cmd(r, idx, CMD_SET_BLOCKLEN, 512, RESP_R1);
    }

    // ── 13. ACMD6 — SET_BUS_WIDTH 4-bit; the host's DMA is ADMA2 ─────────────
    send_cmd(r, idx, CMD_APP_CMD, rca << 16, RESP_R1);
    send_cmd(r, idx, ACMD_SET_BUS_WIDTH, 2, RESP_R1); // 2 = 4-bit
    r.wr8(SDHCI_HOST_CONTROL, HC_4BIT_BUS | HC_DMA_ADMA2_32);

    // ── 14. Raise clock to 25 MHz (data transfer frequency) ──────────────────
    mmc_set_clock(r, 25_000_000);

    // Capacity: SDHC cards report in 512-byte blocks.
    // **U05-8: hardcoded, not read from the card.** `0x100_0000` sectors is
    // exactly 8 GiB; any SDHC card that is not exactly that size (larger OR
    // smaller) gets the wrong bound here — `mmc_capacity` and any caller
    // that trusts it (bounds-checking a read/write against "the card's
    // size") is wrong for every other capacity. CMD9 (SEND_CSD) + CSD
    // register parsing is the real fix and was not attempted this pass —
    // not a small addition (CSD version 1.0 vs 2.0 have different capacity
    // encodings), so left as the same honest "future refinement" the
    // previous comment called it, now with the concrete failure mode
    // spelled out instead of just a TODO.
    let capacity: u64 = if is_sdhc { 0x100_0000 } else { 0x40_0000 };

    // ── Store slot state ──────────────────────────────────────────────────────
    // SAFETY: boot-time, before any request of this slot.
    unsafe {
        *(&raw mut SLOT_STATE[idx]) = SlotState { rca, is_sdhc, capacity, ready: true, cache_on: false };
    }
    WRITE_FAULT[idx].store(false, Ordering::Release);

    azos_drv_sys::kprintln!("[MMC] slot {}: {} card ready  RCA={:#06x}  ~{} MiB",
        idx,
        if is_sdhc { "SDHC" } else { "SDSC" },
        rca,
        capacity / 2048);
    true
}

/// Number of 512-byte sectors on the card in `slot`.  Zero if not initialised.
pub fn mmc_capacity(slot: MmcSlot) -> u64 {
    slot_state(slot as usize).capacity
}

/// The card address of sector `lba`: block-addressed on SDHC, byte-addressed
/// on SDSC.
fn card_addr(is_sdhc: bool, lba: u64) -> u32 {
    if is_sdhc { lba as u32 } else { (lba * 512) as u32 }
}

/// Read `count` 512-byte sectors starting at `lba` into `buf` (ADMA2).
pub fn mmc_read(slot: MmcSlot, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    let base = slot_base(slot);
    if base == 0 { return Err(()); }
    read_on(&Hw(base), slot, lba, count, buf)
}

/// [`mmc_read`] over `r`.
pub fn read_on<R: Regs>(r: &R, slot: MmcSlot, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    if buf.len() < count as usize * 512 { return Err(()); }
    let idx  = slot as usize;
    let turn = MMC_QUEUES[idx].submit();
    let st   = slot_state(idx);
    if !st.ready { return Err(()); }

    let mut done = 0u32;
    while done < count {
        let n = (count - done).min(MAX_XFER_BLOCKS);
        xfer_chunk(r, idx, &turn, false, card_addr(st.is_sdhc, lba + done as u64), n)?;
        bounce_out(idx, &mut buf[done as usize * 512..(done + n) as usize * 512]);
        done += n;
    }
    Ok(())
}

/// Write `count` 512-byte sectors starting at `lba` from `buf` (ADMA2).
///
/// Any failure — including an error bit in a CMD24/CMD25 response, which the
/// card reports once and then clears — also latches `WRITE_FAULT`, so the
/// next `mmc_flush` does not confirm durability over it.
pub fn mmc_write(slot: MmcSlot, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    let base = slot_base(slot);
    if base == 0 { return Err(()); }
    write_on(&Hw(base), slot, lba, count, buf)
}

/// [`mmc_write`] over `r`.
pub fn write_on<R: Regs>(r: &R, slot: MmcSlot, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    if buf.len() < count as usize * 512 { return Err(()); }
    let idx  = slot as usize;
    let turn = MMC_QUEUES[idx].submit();
    let res  = write_chunks(r, slot, &turn, lba, count, buf);
    if res.is_err() { WRITE_FAULT[idx].store(true, Ordering::Release); }
    res
}

fn write_chunks<R: Regs>(r: &R, slot: MmcSlot, turn: &Turn<'_>, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    let idx = slot as usize;
    let st  = slot_state(idx);
    if !st.ready { return Err(()); }

    let mut done = 0u32;
    while done < count {
        let n = (count - done).min(MAX_XFER_BLOCKS);
        bounce_in(idx, &buf[done as usize * 512..(done + n) as usize * 512]);
        let r1 = xfer_chunk(r, idx, turn, true, card_addr(st.is_sdhc, lba + done as u64), n)?;
        // The data phase ran to its end (the controller had committed to it;
        // abandoning it mid-way would leave DAT inhibit set for the next
        // command); the card's verdict decides the request.
        if r1 & R1_ERRORS != 0 {
            azos_drv_sys::kerr!("[MMC] slot {}: write lba {} status {:#010x} (error bits {:#010x})",
                idx, lba + done as u64, r1, r1 & R1_ERRORS);
            return Err(());
        }
        done += n;
    }
    Ok(())
}

/// CMD13 SEND_STATUS until the card is in `tran` with READY_FOR_DATA.
///
/// `Ok(status)` only on that confirmed state. `Err` on: a CMD13 the
/// controller did not complete, any R1 error bit, a state other than
/// `tran`/`prg`/`rcv` (the card is not selected, or is somewhere a write
/// cannot leave it), or `FLUSH_TIMEOUT_US` without reaching `tran` + ready.
/// `prg` (programming) and `rcv` are the states a card passes through after
/// a write and are polled through.
fn wait_card_ready<R: Regs>(r: &R, idx: usize, turn: &Turn<'_>, rca: u32, extra_errors: u32) -> Result<u32, FlushError> {
    let deadline = deadline_after_us(FLUSH_TIMEOUT_US);
    loop {
        let Some(resp) = send_cmd_on(r, idx, Some(turn), CMD_SEND_STATUS, rca << 16, RESP_R1) else {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: CMD13 did not complete", idx);
            return Err(FlushError::Io);
        };
        let st = resp[0];
        FLUSH_STATUS_READS.fetch_add(1, Ordering::AcqRel);
        if st & (R1_ERRORS | extra_errors) != 0 {
            azos_drv_sys::kerr!("[MMC] slot {}: flush: card status {:#010x} carries error bits {:#010x}",
                idx, st, st & (R1_ERRORS | extra_errors));
            return Err(FlushError::Io);
        }
        let state = (st >> R1_STATE_SHIFT) & R1_STATE_MASK;
        match state {
            STATE_TRAN if st & R1_READY_FOR_DATA != 0 => return Ok(st),
            STATE_TRAN | STATE_PRG | STATE_RCV => {}
            _ => {
                azos_drv_sys::kprintln!("[MMC] slot {}: flush: card in state {} (status {:#010x}), not tran",
                    idx, state, st);
                return Err(FlushError::Io);
            }
        }
        if now() >= deadline {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: card still busy after {} us (last {:#010x})",
                idx, FLUSH_TIMEOUT_US, st);
            return Err(FlushError::Io);
        }
    }
}

/// Make every write this slot completed durable on the card.
///
/// SD/eMMC semantics: a CMD24 completes when the controller has sent the
/// block and the card released DAT0 busy; the card may still be moving it
/// from its buffer into flash. The card reports it is done by returning to
/// `tran` with READY_FOR_DATA, which is what CMD13 is polled for here. If an
/// eMMC cache were enabled (`SlotState::cache_on`, never set by this
/// driver), the data could still sit in that cache: CMD6 SWITCH
/// FLUSH_CACHE (EXT_CSD[32] = 1), a DAT0 busy wait, and a second CMD13
/// (which also carries SWITCH_ERROR) would follow.
///
/// `Ok` only on a confirmed card status. A slot that is not initialised, a
/// write that failed since the last flush (`WRITE_FAULT`), a CMD13 or CMD6
/// that did not complete, an error bit, or the deadline → `Err(Io)`.
pub fn mmc_flush(slot: MmcSlot) -> Result<(), FlushError> {
    let base = slot_base(slot);
    if base == 0 { return Err(FlushError::Io); }
    flush_on(&Hw(base), slot)
}

/// [`mmc_flush`] over `r`.
pub fn flush_on<R: Regs>(r: &R, slot: MmcSlot) -> Result<(), FlushError> {
    let idx  = slot as usize;
    let turn = MMC_QUEUES[idx].submit();
    let st   = slot_state(idx);
    if !st.ready { return Err(FlushError::Io); }
    if cfg!(feature = "mmc-flush-canary") { return Ok(()); }
    if WRITE_FAULT[idx].swap(false, Ordering::AcqRel) {
        azos_drv_sys::kerr!("[MMC] slot {}: flush: a write failed since the last flush", idx);
        return Err(FlushError::Io);
    }

    let mut status = wait_card_ready(r, idx, &turn, st.rca, 0)?;

    if st.cache_on {
        // SWITCH, access = Write Byte (0b11), index 32 (FLUSH_CACHE), value 1.
        let arg = (0b11u32 << 24) | (32 << 16) | (1 << 8);
        // R1b: `send_cmd_on` returns once the card released DAT0, i.e. the
        // cache is written out.
        let Some(resp) = send_cmd_on(r, idx, Some(&turn), CMD_SWITCH, arg, RESP_R1B) else {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: CMD6 FLUSH_CACHE did not complete", idx);
            return Err(FlushError::Io);
        };
        if resp[0] & (R1_ERRORS | R1_SWITCH_ERROR) != 0 {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: CMD6 status {:#010x}", idx, resp[0]);
            return Err(FlushError::Io);
        }
        status = wait_card_ready(r, idx, &turn, st.rca, R1_SWITCH_ERROR)?;
    }

    FLUSH_LAST_STATUS.store(status, Ordering::Release);
    Ok(())
}
