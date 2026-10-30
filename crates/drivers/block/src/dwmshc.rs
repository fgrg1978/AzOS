// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// SD card driver for the Synopsys DesignWare Mobile Storage Host Controller
// (DW_mshc), the StarFive JH7110's SDIO blocks (`starfive,jh7110-mmc`,
// `jh7110.dtsi`: `mmc0@16010000` is the eMMC, `mmc1@16020000` the microSD
// socket of the VisionFive 2).
//
// SOURCES. Nothing here has run on silicon, and there is no QEMU model of this
// IP. The pinned Linux tree (v7.2.9, sparse) does not carry
// `drivers/mmc/host/dw_mmc*`; the register file was checked against U-Boot
// 2025.07 (the pinned tree, `third_party/u-boot`: `include/dwmmc.h` and
// `drivers/mmc/dw_mmc.c`, which lists `starfive,jh7110-mmc` among its
// matches in `drivers/mmc/snps_dw_mmc.c`), and the board facts (clocks
// `biu`/`ciu`, interrupts 74/75, `cd-gpios` on mmc1, `non-removable` on mmc0)
// against the local `jh7110.dtsi` and `jh7110-starfive-visionfive-2.dtsi`.
// Each constant below says "U-Boot" when that source has it. What U-Boot does
// not have and this file uses anyway is marked "databook": the Synopsys
// DesignWare Cores Mobile Storage Host databook, from memory of its register
// descriptions, NOT re-read here:
//   - CTRL.INT_ENABLE (bit 4), the global interrupt enable;
//   - CMD.SEND_INIT (bit 15), the 80 initialisation clocks before CMD0;
//   - the IDSTS bits other than TI/RI (FBE, DU, CES, NI, AI) and their
//     IDINTEN enables;
//   - the HCON fields other than ADDR_CONFIG (bit 27).
//
// What it does. The controller is driven by its internal DMA controller
// (IDMAC): per request the driver builds a descriptor chain over bounce pages
// (a chained descriptor holds one buffer: DES0 control, DES1 size, DES2 buffer
// address, DES3 next descriptor, the layout the databook calls dual-buffer
// used in chain mode, `CH=1`, as U-Boot does; HCON.ADDR_CONFIG selects the
// 32-bit form or the 64-bit form with its own offsets), points DBADDR at it,
// enables the IDMAC and issues the command. The CPU never touches the FIFO
// data port. The bounce pages and the chain sit below 4 GiB and are bracketed
// with the DMA domain's cache maintenance, because the controller is not
// coherent with the CPU.
//
// Init (`init_on`): controller reset, PWREN, FIFOTH from the power-on RX
// watermark, IDMAC reset, 400 kHz, CMD0 (with the initialisation clocks), CMD8,
// CMD55+ACMD41 until the card is powered up (bounded, one second), CMD2, CMD3,
// CMD9 (the capacity comes from the CSD, not a constant), CMD7, CMD16 on a
// standard-capacity card, CMD55+ACMD6 (4-bit, CTYPE), 25 MHz, then CMD6
// high speed (a 64-byte data read through the same IDMAC path) and 50 MHz when
// the card offers it. No UHS, no tuning, no `starfive,sysreg` sample phase.
//
// Requests: CMD17/CMD24 for one sector, CMD18/CMD25 for more followed by an
// explicit CMD12 (U-Boot's way: no auto-stop). A command is complete when
// RINTSTS says so; a data command also when the IDMAC reports TI/RI. A card
// that is busy after a write is waited out through STATUS.DATA_BUSY, bounded.
//
// Completion. `harvest` reads RINTSTS and IDSTS, clears exactly the bits it
// read (write-1-to-clear: an event raised in between stays pending) and ORs
// them into `EVENTS`. The interrupt handler (`irq`) and a polling waiter both
// call it. Until the kernel wires the line (`set_irq_mode`) a waiter spins on
// RINTSTS; afterwards it sleeps with the device-wait pattern
// (`azos_drv_api::block::DeviceWait`: list the task, fence, look again, only
// then block) for at most one slice at a time and until the request's deadline,
// and the handler wakes it by TID. Every wait is bounded by the request's
// deadline.
//
// The register file is reached through [`Regs`]: the kernel's [`Hw`] is a
// volatile MMIO window, the host test (`tests/host/drivers-tests`) drives the
// very same functions over a register model of the controller and a card.

use crate::dev_queue::{DevQueue, IrqHooks, Turn};
use azos_dma::Direction;
use azos_drv_api::block::{DeviceWait, FlushError};
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ── Registers (U-Boot `include/dwmmc.h`, offsets and bits) ───────────────────
const CTRL: usize = 0x000;
const PWREN: usize = 0x004;
const CLKDIV: usize = 0x008;
const CLKSRC: usize = 0x00C;
const CLKENA: usize = 0x010;
const TMOUT: usize = 0x014;
const CTYPE: usize = 0x018;
const BLKSIZ: usize = 0x01C;
const BYTCNT: usize = 0x020;
const INTMASK: usize = 0x024;
const CMDARG: usize = 0x028;
const CMD: usize = 0x02C;
const RESP0: usize = 0x030;
const RESP1: usize = 0x034;
const RESP2: usize = 0x038;
const RESP3: usize = 0x03C;
const RINTSTS: usize = 0x044;
const STATUS: usize = 0x048;
const FIFOTH: usize = 0x04C;
const HCON: usize = 0x070;
const BMOD: usize = 0x080;
// IDMAC registers, 32-bit descriptor mode (U-Boot `DWMCI_DBADDR` ..).
/// Descriptor base address (the low word in 64-bit mode too).
const DBADDR: usize = 0x088;
const IDSTS32: usize = 0x08C;
const IDINTEN32: usize = 0x090;
// IDMAC registers, 64-bit descriptor mode (U-Boot `DWMCI_DBADDRU` ..).
const DBADDRU64: usize = 0x08C;
const IDSTS64: usize = 0x090;
const IDINTEN64: usize = 0x094;

/// HCON bit 27, ADDR_CONFIG: the IDMAC uses 64-bit descriptors (U-Boot
/// `dwmci_init_dma`).
const HCON_ADDR64: u32 = 1 << 27;

// CTRL (U-Boot).
const CTRL_RESET: u32 = 1 << 0;
const CTRL_FIFO_RESET: u32 = 1 << 1;
const CTRL_DMA_RESET: u32 = 1 << 2;
/// Global interrupt enable (databook).
const CTRL_INT_ENABLE: u32 = 1 << 4;
const CTRL_DMA_EN: u32 = 1 << 5;
const CTRL_IDMAC_EN: u32 = 1 << 25;
const CTRL_RESET_ALL: u32 = CTRL_RESET | CTRL_FIFO_RESET | CTRL_DMA_RESET;

// CMD (U-Boot).
const CMD_RESP_EXP: u32 = 1 << 6;
const CMD_RESP_LEN: u32 = 1 << 7;
const CMD_CHECK_CRC: u32 = 1 << 8;
const CMD_DATA_EXP: u32 = 1 << 9;
const CMD_RW: u32 = 1 << 10;
const CMD_PRV_DAT_WAIT: u32 = 1 << 13;
const CMD_ABORT_STOP: u32 = 1 << 14;
/// Send the initialisation sequence (80 clocks) first (databook).
const CMD_SEND_INIT: u32 = 1 << 15;
const CMD_UPD_CLK: u32 = 1 << 21;
const CMD_USE_HOLD: u32 = 1 << 29;
const CMD_START: u32 = 1 << 31;

// CLKENA (U-Boot).
const CLKENA_ENABLE: u32 = 1 << 0;
const CLKENA_LOW_PWR: u32 = 1 << 16;

// CTYPE (U-Boot).
const CTYPE_4BIT: u32 = 1 << 0;

// STATUS (U-Boot): the card holds DAT0 low.
const STATUS_DATA_BUSY: u32 = 1 << 9;

// BMOD (U-Boot).
const BMOD_SWR: u32 = 1 << 0;
const BMOD_FB: u32 = 1 << 1;
const BMOD_DE: u32 = 1 << 7;

// RINTSTS bits (U-Boot `DWMCI_INTMSK_*`).
const RI_RE: u32 = 1 << 1;
const RI_CDONE: u32 = 1 << 2;
const RI_DTO: u32 = 1 << 3;
const RI_RCRC: u32 = 1 << 6;
const RI_DCRC: u32 = 1 << 7;
const RI_RTO: u32 = 1 << 8;
const RI_DRTO: u32 = 1 << 9;
const RI_HTO: u32 = 1 << 10;
const RI_FRUN: u32 = 1 << 11;
const RI_HLE: u32 = 1 << 12;
const RI_SBE: u32 = 1 << 13;
const RI_EBE: u32 = 1 << 15;
/// The error bits of RINTSTS the driver reacts to.
const RI_ERR: u32 =
    RI_RE | RI_RCRC | RI_DCRC | RI_RTO | RI_DRTO | RI_HTO | RI_FRUN | RI_HLE | RI_SBE | RI_EBE;
/// What the driver tracks of RINTSTS (the FIFO request bits RXDR/TXDR and the
/// card-detect bit belong to a PIO driver).
const RI_MASK: u32 = RI_CDONE | RI_DTO | RI_ERR;

// IDSTS / IDINTEN bits: TI and RI are U-Boot's; the rest is the databook's.
const ID_TI: u32 = 1 << 0;
const ID_RI: u32 = 1 << 1;
const ID_FBE: u32 = 1 << 2;
const ID_DU: u32 = 1 << 4;
const ID_CES: u32 = 1 << 5;
const ID_NI: u32 = 1 << 8;
const ID_AI: u32 = 1 << 9;
const ID_ERR: u32 = ID_FBE | ID_DU | ID_CES;
const ID_MASK: u32 = ID_TI | ID_RI | ID_ERR | ID_NI | ID_AI;

/// The harvested events (`EVENTS`): RINTSTS in the low half, IDSTS in the high half.
const EV_CDONE: u32 = RI_CDONE;
const EV_DTO: u32 = RI_DTO;
const EV_DMA_DONE: u32 = (ID_TI | ID_RI) << 16;
const EV_ERR: u32 = RI_ERR | (ID_ERR << 16);

// IDMAC descriptor control word (U-Boot `DWMCI_IDMAC_*`).
const DES0_OWN: u32 = 1 << 31;
/// Disable interrupt on completion: the descriptor raises no IDSTS TI/RI.
const DES0_DIC: u32 = 1 << 1;
const DES0_CH: u32 = 1 << 4;
const DES0_FS: u32 = 1 << 3;
const DES0_LD: u32 = 1 << 2;
const DESC32_BYTES: usize = 16;
const DESC64_BYTES: usize = 32;

// FIFOTH (U-Boot `MSIZE`, `RX_WMARK`, `TX_WMARK`).
const FIFOTH_RX_SHIFT: u32 = 16;

// ── SD commands (SD Physical Layer spec) ─────────────────────────────────────
const CMD_GO_IDLE: u32 = 0;
const CMD_ALL_SEND_CID: u32 = 2;
const CMD_SEND_RCA: u32 = 3;
const CMD_SWITCH_FUNC: u32 = 6;
const CMD_SELECT: u32 = 7;
const CMD_SEND_IF_COND: u32 = 8;
const CMD_SEND_CSD: u32 = 9;
const CMD_STOP: u32 = 12;
const CMD_SEND_STATUS: u32 = 13;
const CMD_SET_BLOCKLEN: u32 = 16;
const CMD_READ_SINGLE: u32 = 17;
const CMD_READ_MULTI: u32 = 18;
const CMD_WRITE_SINGLE: u32 = 24;
const CMD_WRITE_MULTI: u32 = 25;
const CMD_APP_CMD: u32 = 55;
const ACMD_SET_BUS_WIDTH: u32 = 6;
const ACMD_SD_SEND_OP: u32 = 41;

/// CMD6 argument: mode 0 (check), group 1 function 1 (high speed), the other
/// groups left as they are.
const SWITCH_CHECK_HS: u32 = 0x00FF_FFF1;
/// CMD6 argument: mode 1 (switch), group 1 function 1.
const SWITCH_SET_HS: u32 = 0x80FF_FFF1;
/// The CMD6 status block is 64 bytes.
const SWITCH_STATUS_BYTES: usize = 64;
/// Switch status byte 13, bit 1: group 1 supports function 1 (high speed).
const SWITCH_HS_SUPPORTED: u8 = 0x02;
/// CCC bit 10 of the CSD: the card implements the switch class (CMD6).
const CCC_SWITCH: u32 = 1 << 10;

// R1 card status (SD Physical Layer spec): the error bits, as `mmc.rs` lists
// them, and the state field.
const R1_ERRORS: u32 = 0xFDF9_8008;
const R1_READY_FOR_DATA: u32 = 1 << 8;
const R1_STATE_SHIFT: u32 = 9;
const R1_STATE_MASK: u32 = 0xF;
const STATE_TRAN: u32 = 4;
const STATE_RCV: u32 = 6;
const STATE_PRG: u32 = 7;

// ── Timeouts and sizes ───────────────────────────────────────────────────────
/// A command's Command Done: a 48-bit exchange at 400 kHz is ~0.2 ms.
const CMD_TIMEOUT_US: u64 = 100_000;
/// A data command's data over (the whole chunk).
const XFER_TIMEOUT_US: u64 = 4_000_000;
/// The card holding DAT0 low after a command (a write's programming, an R1b).
const BUSY_TIMEOUT_US: u64 = 4_000_000;
/// ACMD41 until the card is powered up: the spec allows one second.
const POWER_UP_TIMEOUT_US: u64 = 1_000_000;
/// `flush_on` waiting for the card to leave `prg`: sized for an SD card's
/// garbage collection after a batch of writes, not measured on any board.
const FLUSH_TIMEOUT_US: u64 = 5_000_000;
/// The CMD register's START bit to clear (the controller took the command):
/// a handshake of a few CIU clocks.
const START_TIMEOUT_US: u64 = 10_000;
/// A controller reset bit to clear.
const RESET_TIMEOUT_US: u64 = 10_000;
/// TMOUT: data read timeout in the high 24 bits, response timeout in the low
/// 8, both at their maximum (U-Boot).
const TMOUT_MAX: u32 = 0xFFFF_FFFF;

/// The FIFO depths a node may declare (U-Boot `snps_dwmmc_of_to_plat`).
const FIFO_MIN: u32 = 8;
const FIFO_MAX: u32 = 4096;

/// The identification clock, and the two data clocks.
const CLK_IDENT_HZ: u32 = 400_000;
const CLK_DEFAULT_HZ: u32 = 25_000_000;
const CLK_HIGH_SPEED_HZ: u32 = 50_000_000;

const PAGE: usize = 4096;
/// Bounce pages: the most a single command moves. 16 pages = 64 KiB = 128
/// sectors.
const XFER_PAGES: usize = 16;
const MAX_XFER_BLOCKS: u32 = (XFER_PAGES * PAGE / 512) as u32;
/// The highest address a 32-bit IDMAC descriptor can name (inclusive).
const DMA_MASK_32: u64 = u32::MAX as u64;

// ── What went wrong ──────────────────────────────────────────────────────────
/// Why a command or a transfer did not complete.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// The card did not answer (RTO): no card, or not that command's.
    NoResponse,
    /// A CRC error on the response or on the data.
    Crc,
    /// Any other error bit, or the IDMAC's.
    Hardware,
    /// The driver's own deadline passed with no event.
    Deadline,
}

// ── Register access ──────────────────────────────────────────────────────────
/// The controller's register file, all 32-bit. [`Hw`] is the MMIO window; the
/// host test implements it over a model of the controller and the card.
pub trait Regs {
    /// The window's address: names the controller to the DMA domain registry
    /// (JH7110's is not coherent with the CPU).
    fn base(&self) -> usize;
    fn rd32(&self, off: usize) -> u32;
    fn wr32(&self, off: usize, val: u32);
}

/// The controller's mapped register window at this address.
pub struct Hw(pub usize);

impl Regs for Hw {
    fn base(&self) -> usize {
        self.0
    }
    #[inline(always)]
    fn rd32(&self, off: usize) -> u32 {
        // SAFETY: `self.0` is the window the hardware bus mapped for the bound
        // node (`attach`), and `off` a register inside its 64 KiB.
        unsafe { azos_arch_api::mmio::read32(self.0 + off) }
    }
    #[inline(always)]
    fn wr32(&self, off: usize, val: u32) {
        // SAFETY: as `rd32`.
        unsafe { azos_arch_api::mmio::write32(self.0 + off, val) }
    }
}

/// The MMIO read that saw the controller finish ordered before the CPU's reads
/// of what it wrote to RAM.
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

/// Wait `us` microseconds (init only, before any task sleeps).
fn delay_us(us: u64) {
    let until = deadline_after_us(us);
    while now() < until {
        core::hint::spin_loop();
    }
}

// ── The one controller ───────────────────────────────────────────────────────
// The driver serves ONE controller: the microSD socket. The VisionFive 2's
// other block, `mmc0`, is the eMMC (`non-removable` in the board tree) and
// needs the eMMC init (CMD1, EXT_CSD) this driver does not have; the probe arm
// refuses it (`attach` is for a removable SD slot).
static BASE: AtomicUsize = AtomicUsize::new(0);
static LINE: AtomicU32 = AtomicU32::new(u32::MAX);
static CIU_HZ: AtomicU32 = AtomicU32::new(0);
static FIFO_DEPTH: AtomicU32 = AtomicU32::new(0);

/// What the device-tree node of the controller says (the probe arm reads it).
#[derive(Clone, Copy, Debug)]
pub struct Node {
    /// The mapped register window (`reg`).
    pub base: usize,
    /// The interrupt-controller source (`interrupts`), `u32::MAX` when none.
    pub line: u32,
    /// The rate in Hz of the card interface unit clock (`clocks`, name `ciu`):
    /// the clock the card clock is divided from.
    pub ciu_hz: u32,
    /// The FIFO depth in 32-bit words (`fifo-depth`). The power-on watermark
    /// would give it too, but the bootloader has usually rewritten that.
    pub fifo_depth: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttachError {
    /// A controller is attached already: the driver serves one.
    Busy,
    /// The window, the CIU clock rate or the FIFO depth is not usable.
    Invalid,
}

/// Bind the driver to the SD socket's controller. Nothing is touched on the
/// hardware until [`init`].
pub fn attach(node: Node) -> Result<(), AttachError> {
    if node.base == 0 || node.ciu_hz < CLK_IDENT_HZ || !(FIFO_MIN..=FIFO_MAX).contains(&node.fifo_depth) {
        return Err(AttachError::Invalid);
    }
    if BASE.compare_exchange(0, node.base, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return Err(AttachError::Busy);
    }
    LINE.store(node.line, Ordering::Release);
    CIU_HZ.store(node.ciu_hz, Ordering::Release);
    FIFO_DEPTH.store(node.fifo_depth, Ordering::Release);
    Ok(())
}

/// Is a controller attached.
pub fn attached() -> bool {
    BASE.load(Ordering::Acquire) != 0
}

// ── Card state ───────────────────────────────────────────────────────────────
static READY: AtomicBool = AtomicBool::new(false);
static IS_SDHC: AtomicBool = AtomicBool::new(false);
static RCA: AtomicU32 = AtomicU32::new(0);
static CAPACITY: AtomicU64 = AtomicU64::new(0);
/// The card runs in high-speed mode (50 MHz).
static HIGH_SPEED: AtomicBool = AtomicBool::new(false);
/// The IDMAC takes 64-bit descriptors (HCON.ADDR_CONFIG), decided at init.
static DMA64: AtomicBool = AtomicBool::new(false);

/// A write failed — its CMD24/CMD25 response carried an error bit, or the
/// transfer itself failed — since the last [`flush`]. `flush` reports it and
/// clears it, so a flush never confirms a batch that lost a write whose error
/// the card has already reported and forgotten.
static WRITE_FAULT: AtomicBool = AtomicBool::new(false);

/// One request queue for the controller (owner rule F1): a request owns the
/// controller from its turn to its last event, holds the queue's `Mutex` only
/// while it writes the registers that start a command, and every device wait
/// runs with no lock held.
static QUEUE: DevQueue = DevQueue::new();

/// Number of 512-byte sectors on the card. Zero if not initialised.
pub fn capacity() -> u64 {
    CAPACITY.load(Ordering::Acquire)
}

/// The card runs at 50 MHz (high speed).
pub fn high_speed() -> bool {
    HIGH_SPEED.load(Ordering::Acquire)
}

// ── Completion events and the interrupt ──────────────────────────────────────
static HOOKS: AtomicPtr<IrqHooks> = AtomicPtr::new(core::ptr::null_mut());

fn hooks() -> Option<&'static IrqHooks> {
    // SAFETY: only `set_irq_mode_on` stores here, and it stores a `&'static IrqHooks`.
    unsafe { HOOKS.load(Ordering::Acquire).as_ref() }
}

/// Events harvested and not yet consumed by the request waiting on them.
static EVENTS: AtomicU32 = AtomicU32::new(0);
/// The interrupt line the controller completes on (`u32::MAX`: polled).
static IRQ_LINE: AtomicU32 = AtomicU32::new(u32::MAX);
/// The task sleeping for the controller's next event, listed with the fences
/// that make the list-then-look-again handshake sound.
static WAIT: DeviceWait = DeviceWait::new();
/// Interrupts taken / waits that slept (diagnostics, [`irq_counts`]).
static IRQ_TAKEN: AtomicU32 = AtomicU32::new(0);
static IRQ_SLEPT: AtomicU32 = AtomicU32::new(0);

fn irq_mode() -> bool {
    IRQ_LINE.load(Ordering::Acquire) != u32::MAX
}

fn idsts() -> usize {
    if DMA64.load(Ordering::Acquire) { IDSTS64 } else { IDSTS32 }
}

fn idinten() -> usize {
    if DMA64.load(Ordering::Acquire) { IDINTEN64 } else { IDINTEN32 }
}

/// Move the controller's pending events into `EVENTS`: read RINTSTS and IDSTS,
/// write back exactly the bits read (write-1-to-clear), OR them in.
/// Idempotent across two callers racing on the same bits.
fn harvest<R: Regs>(r: &R) -> u32 {
    let ri = r.rd32(RINTSTS) & RI_MASK;
    if ri != 0 {
        r.wr32(RINTSTS, ri);
    }
    let id = r.rd32(idsts()) & ID_MASK;
    if id != 0 {
        r.wr32(idsts(), id);
    }
    let st = ri | (id << 16);
    if st != 0 {
        EVENTS.fetch_or(st, Ordering::AcqRel);
    }
    st
}

/// Forget everything pending, before a command is issued.
fn clear_events<R: Regs>(r: &R) {
    r.wr32(RINTSTS, 0xFFFF_FFFF);
    r.wr32(idsts(), 0xFFFF_FFFF);
    EVENTS.store(0, Ordering::Release);
}

/// The interrupt handler's arm for `line` (interrupt context, any CPU): `None`
/// when the line is not the controller's; otherwise harvest its events (which
/// quiets a level line) and wake the sleeping waiter, `Some(true)` when there
/// was one.
pub fn irq(line: u32) -> Option<bool> {
    let base = BASE.load(Ordering::Acquire);
    if base == 0 || IRQ_LINE.load(Ordering::Acquire) != line {
        return None;
    }
    Some(irq_on(&Hw(base)))
}

/// [`irq`] over `r`.
pub fn irq_on<R: Regs>(r: &R) -> bool {
    harvest(r);
    IRQ_TAKEN.fetch_add(1, Ordering::Relaxed);
    // After the event is visible in `EVENTS`: the fence inside `sleeper` pairs
    // with the one in `park`.
    let tid = WAIT.sleeper();
    match hooks() {
        Some(h) if tid != 0 => {
            (h.wake)(tid);
            true
        }
        _ => false,
    }
}

/// Sleep until the controller's next interrupt, the `deadline`, or one slice
/// (Kconfig `VIRTIO_BLK_IRQ_SLICE_US`: never straight to the deadline, an idle
/// CPU under `-icount ... sleep=off` jumps its clock to the next timer). `ready`
/// is what the sleeper looks at after it is listed. `false` when the caller
/// cannot sleep (polled mode, no scheduler): it then spins.
fn sleep_until<R: Regs>(r: &R, deadline: u64, ready: impl FnOnce(&R) -> bool) -> bool {
    if !irq_mode() {
        return false;
    }
    let Some(h) = hooks() else { return false };
    let tid = (h.tid)();
    if tid == 0 || tid == u32::MAX {
        return false;
    }
    let slice = azos_limits::VIRTIO_BLK_IRQ_SLICE_US as u64 * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000;
    let until = deadline.min(now().saturating_add(slice.max(1)));
    let mut blocked = false;
    // `park` lists the task, fences, asks `ready` (an event raised before the
    // task was listed woke nobody) and blocks only if it is not.
    WAIT.park(tid, || ready(r), || {
        blocked = (h.block_until)(until);
        blocked
    });
    if blocked {
        IRQ_SLEPT.fetch_add(1, Ordering::Relaxed);
    }
    blocked
}

/// Wait for one of the events `want` (bits of `EV_MASK`), up to `timeout_us`.
/// The error events win over `want`. On an error or the deadline the
/// controller is reset so the next command starts clean.
fn wait_events<R: Regs>(r: &R, want: u32, timeout_us: u64) -> Result<(), Fault> {
    let deadline = deadline_after_us(timeout_us);
    loop {
        harvest(r);
        let ev = EVENTS.load(Ordering::Acquire);
        if ev & EV_ERR != 0 {
            // A card that does not answer is an expected outcome of some
            // commands (CMD8 on an SD 1.x card): the caller says if it is not.
            if ev & RI_RTO == 0 {
                azos_drv_sys::kerr!("[SDMMC] error event {:#010x} waiting for {:#x}", ev & EV_ERR, want);
            }
            recover(r);
            return Err(if ev & RI_RTO != 0 {
                Fault::NoResponse
            } else if ev & (RI_RCRC | RI_DCRC) != 0 {
                Fault::Crc
            } else {
                Fault::Hardware
            });
        }
        if ev & want != 0 {
            EVENTS.fetch_and(!want, Ordering::AcqRel);
            return Ok(());
        }
        if now() >= deadline {
            azos_drv_sys::kerr!("[SDMMC] timeout waiting for {:#x} ({} us)", want, timeout_us);
            recover(r);
            return Err(Fault::Deadline);
        }
        let seen = |r: &R| {
            harvest(r);
            EVENTS.load(Ordering::Acquire) & (want | EV_ERR) != 0
        };
        if !sleep_until(r, deadline, seen) {
            core::hint::spin_loop();
        }
    }
}

/// Wait for the card to release DAT0 (STATUS.DATA_BUSY clear), up to
/// `timeout_us`. Nothing raises an interrupt for it: the wait naps one slice at
/// a time when it can sleep, and spins when it cannot.
fn wait_not_busy<R: Regs>(r: &R, timeout_us: u64) -> bool {
    let deadline = deadline_after_us(timeout_us);
    loop {
        if r.rd32(STATUS) & STATUS_DATA_BUSY == 0 {
            return true;
        }
        if now() >= deadline {
            return false;
        }
        if !sleep_until(r, deadline, |_| false) {
            core::hint::spin_loop();
        }
    }
}

/// Spin until the bits in `mask` of register `off` are clear, up to
/// `timeout_us`.
fn wait_clear<R: Regs>(r: &R, off: usize, mask: u32, timeout_us: u64) -> bool {
    let deadline = deadline_after_us(timeout_us);
    loop {
        if r.rd32(off) & mask == 0 {
            return true;
        }
        if now() >= deadline {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// After an error or a timeout: reset the controller, its FIFO and the IDMAC
/// (CTRL, then BMOD.SWR), give the card interface its clock settings back (a
/// reset needs an update-clock command), drop what is pending and restore the
/// interrupt enables.
fn recover<R: Regs>(r: &R) {
    r.wr32(CTRL, r.rd32(CTRL) | CTRL_RESET_ALL);
    wait_clear(r, CTRL, CTRL_RESET_ALL, RESET_TIMEOUT_US);
    r.wr32(BMOD, BMOD_SWR);
    wait_clear(r, BMOD, BMOD_SWR, RESET_TIMEOUT_US);
    update_clock(r);
    clear_events(r);
    enable_irqs(r);
}

/// The interrupt enables of the current mode: nothing when polled.
fn enable_irqs<R: Regs>(r: &R) {
    if irq_mode() {
        r.wr32(INTMASK, RI_MASK);
        r.wr32(idinten(), ID_MASK);
        r.wr32(CTRL, r.rd32(CTRL) | CTRL_INT_ENABLE);
    } else {
        r.wr32(CTRL, r.rd32(CTRL) & !CTRL_INT_ENABLE);
        r.wr32(INTMASK, 0);
        r.wr32(idinten(), 0);
    }
}

/// Take the controller's completions by interrupt on `line` from now on, with
/// the kernel's sleep and wake `hooks`. Call BEFORE the interrupt controller
/// enables `line` (the handler, [`irq`], must already recognise it). `false`
/// where it cannot be (not initialised).
pub fn set_irq_mode_on<R: Regs>(r: &R, line: u32, hooks: &'static IrqHooks) -> bool {
    if !READY.load(Ordering::Acquire) {
        return false;
    }
    HOOKS.store(hooks as *const IrqHooks as *mut IrqHooks, Ordering::Release);
    // Whatever completed so far was polled: drop it, so the line is not
    // asserted the moment the controller enables it.
    clear_events(r);
    IRQ_LINE.store(line, Ordering::Release);
    enable_irqs(r);
    true
}

/// [`set_irq_mode_on`] over the attached controller's window.
pub fn set_irq_mode(line: u32, hooks: &'static IrqHooks) -> bool {
    let base = BASE.load(Ordering::Acquire);
    base != 0 && set_irq_mode_on(&Hw(base), line, hooks)
}

/// Back to polled completions (the line could not be routed).
pub fn irq_off_on<R: Regs>(r: &R) {
    IRQ_LINE.store(u32::MAX, Ordering::Release);
    enable_irqs(r);
}

/// [`irq_off_on`] over the attached controller's window.
pub fn irq_off() {
    let base = BASE.load(Ordering::Acquire);
    if base != 0 {
        irq_off_on(&Hw(base));
    }
}

/// The interrupt-controller source the controller's node names, once the card
/// is initialised: what the kernel routes and hands to [`set_irq_mode`]. `None`
/// when the card is not up or the node carried no interrupt.
pub fn irq_line() -> Option<u32> {
    let line = LINE.load(Ordering::Acquire);
    (READY.load(Ordering::Acquire) && line != u32::MAX && line != 0).then_some(line)
}

/// `(interrupts taken, waits that slept)`.
pub fn irq_counts() -> (u32, u32) {
    (IRQ_TAKEN.load(Ordering::Relaxed), IRQ_SLEPT.load(Ordering::Relaxed))
}

// ── DMA memory ───────────────────────────────────────────────────────────────
/// The IDMAC descriptor chain and bounce pages: CPU and bus addresses,
/// allocated once at the first `init_on` and kept.
struct DmaMem {
    ready: AtomicBool,
    table_va: AtomicUsize,
    table_pa: AtomicU64,
    page_va: [AtomicUsize; XFER_PAGES],
    page_pa: [AtomicU64; XFER_PAGES],
}

static DMA: DmaMem = DmaMem {
    ready: AtomicBool::new(false),
    table_va: AtomicUsize::new(0),
    table_pa: AtomicU64::new(0),
    page_va: [const { AtomicUsize::new(0) }; XFER_PAGES],
    page_pa: [const { AtomicU64::new(0) }; XFER_PAGES],
};

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

/// One zeroed page the IDMAC can name: `(CPU address, bus address)`.
fn alloc_dma_page() -> Option<(usize, u64)> {
    let pa = azos_dma::alloc_below(&Pmm, DMA_MASK_32, PAGE).ok()?;
    let va = azos_mm::addr::phys_to_virt(pa as usize);
    // SAFETY: a page the allocator just handed out, mapped in the kernel's
    // direct map; nothing else refers to it.
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE) };
    Some((va, pa))
}

/// The table and bounce pages, allocated if they are not yet.
fn dma_prepare() -> bool {
    let d = &DMA;
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

/// One IDMAC descriptor, 32-bit form, in its 16-byte little-endian layout
/// (U-Boot `struct dwmci_idmac32`): DES0 control, DES1 buffer size, DES2 buffer
/// address, DES3 next descriptor address.
pub fn idmac_desc32(control: u32, size: u32, buf: u32, next: u32) -> [u8; DESC32_BYTES] {
    let mut d = [0u8; DESC32_BYTES];
    d[0..4].copy_from_slice(&control.to_le_bytes());
    d[4..8].copy_from_slice(&size.to_le_bytes());
    d[8..12].copy_from_slice(&buf.to_le_bytes());
    d[12..16].copy_from_slice(&next.to_le_bytes());
    d
}

/// One IDMAC descriptor, 64-bit form, 32 bytes (U-Boot `struct
/// dwmci_idmac64`): DES0 control, DES1 reserved, DES2 buffer size, DES3
/// reserved, DES4/5 buffer address, DES6/7 next descriptor address.
pub fn idmac_desc64(control: u32, size: u32, buf: u64, next: u64) -> [u8; DESC64_BYTES] {
    let mut d = [0u8; DESC64_BYTES];
    d[0..4].copy_from_slice(&control.to_le_bytes());
    d[8..12].copy_from_slice(&size.to_le_bytes());
    d[16..20].copy_from_slice(&(buf as u32).to_le_bytes());
    d[20..24].copy_from_slice(&((buf >> 32) as u32).to_le_bytes());
    d[24..28].copy_from_slice(&(next as u32).to_le_bytes());
    d[28..32].copy_from_slice(&((next >> 32) as u32).to_le_bytes());
    d
}

/// Describe a transfer of `bytes` over the first pages of the bounce area in
/// the chain: one chained descriptor per page (first FS, last LD, every one
/// OWN|CH, the last one as long as what is left). Only the LD descriptor
/// raises TI/RI (every other one has DIC, as in Linux `dw_mmc`), so that event
/// means the whole chain has been moved. Returns the page count.
fn write_chain(bytes: usize) -> usize {
    let d = &DMA;
    let pages = bytes.div_ceil(PAGE);
    debug_assert!(pages >= 1 && pages <= XFER_PAGES);
    let table_va = d.table_va.load(Ordering::Relaxed);
    let table_pa = d.table_pa.load(Ordering::Relaxed);
    let wide = DMA64.load(Ordering::Acquire);
    let stride = if wide { DESC64_BYTES } else { DESC32_BYTES };
    for p in 0..pages {
        let len = (bytes - p * PAGE).min(PAGE);
        let pa = d.page_pa[p].load(Ordering::Relaxed);
        debug_assert!(pa <= DMA_MASK_32 - (PAGE as u64 - 1));
        let mut control = DES0_OWN | DES0_CH;
        if p == 0 {
            control |= DES0_FS;
        }
        if p + 1 == pages {
            control |= DES0_LD;
        } else {
            control |= DES0_DIC;
        }
        let next = table_pa + ((p + 1) * stride) as u64;
        let at = (table_va + p * stride) as *mut u8;
        if wide {
            let desc = idmac_desc64(control, len as u32, pa, next);
            // SAFETY: the table page is ours and `p < XFER_PAGES`, so the entry lies inside it.
            unsafe { core::ptr::copy_nonoverlapping(desc.as_ptr(), at, DESC64_BYTES) };
        } else {
            let desc = idmac_desc32(control, len as u32, pa as u32, next as u32);
            // SAFETY: as above.
            unsafe { core::ptr::copy_nonoverlapping(desc.as_ptr(), at, DESC32_BYTES) };
        }
    }
    pages
}

/// Copy `src` into the bounce pages (a write, before the command).
fn bounce_in(src: &[u8]) {
    for (p, chunk) in src.chunks(PAGE).enumerate() {
        let va = DMA.page_va[p].load(Ordering::Relaxed) as *mut u8;
        // SAFETY: bounce page `p` is ours, `chunk` is at most a page, and the
        // two do not overlap (the page is not caller memory).
        unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), va, chunk.len()) };
    }
}

/// Copy the bounce pages out to `dst` (a read, after the transfer).
fn bounce_out(dst: &mut [u8]) {
    for (p, chunk) in dst.chunks_mut(PAGE).enumerate() {
        let va = DMA.page_va[p].load(Ordering::Relaxed) as *const u8;
        // SAFETY: as `bounce_in`.
        unsafe { core::ptr::copy_nonoverlapping(va, chunk.as_mut_ptr(), chunk.len()) };
    }
}

// ── Clock ────────────────────────────────────────────────────────────────────
/// CLKDIV for a card clock of at most `target_hz` from a `ciu_hz` clock: the
/// card clock is `ciu / (2 * div)`, `div = 0` is bypass (U-Boot
/// `dwmci_setup_bus`). `None` when the 8-bit divider cannot reach the target.
pub fn clock_divider(ciu_hz: u32, target_hz: u32) -> Option<u32> {
    if target_hz == 0 {
        return None;
    }
    if target_hz >= ciu_hz {
        return Some(0);
    }
    let div = (ciu_hz as u64).div_ceil(2 * target_hz as u64);
    (div <= 0xFF).then_some(div as u32)
}

/// Tell the card interface unit to take the clock registers (an update-clock
/// command, no card command): START with UPD_CLK, then wait for START to clear
/// (U-Boot `dwmci_control_clken`).
fn update_clock<R: Regs>(r: &R) -> bool {
    r.wr32(CMD, CMD_START | CMD_UPD_CLK | CMD_PRV_DAT_WAIT);
    wait_clear(r, CMD, CMD_START, START_TIMEOUT_US)
}

/// Run the card clock at the highest rate not above `target_hz`, with the
/// clock stopped while the divider changes (U-Boot `dwmci_update_div`).
fn set_clock<R: Regs>(r: &R, target_hz: u32) -> bool {
    let Some(div) = clock_divider(CIU_HZ.load(Ordering::Acquire), target_hz) else {
        azos_drv_sys::kerr!("[SDMMC] card clock {} Hz is out of reach of the {} Hz CIU clock",
            target_hz, CIU_HZ.load(Ordering::Acquire));
        return false;
    };
    r.wr32(CLKENA, 0);
    if !update_clock(r) {
        return false;
    }
    r.wr32(CLKDIV, div);
    r.wr32(CLKSRC, 0);
    r.wr32(CLKENA, CLKENA_ENABLE | CLKENA_LOW_PWR);
    update_clock(r)
}

// ── Command engine ───────────────────────────────────────────────────────────
/// The response a command expects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Resp {
    None,
    /// 48-bit with CRC (R1, R6, R7).
    R1,
    /// 136-bit with CRC (CID, CSD).
    R2,
    /// 48-bit without CRC (the OCR).
    R3,
}

impl Resp {
    fn flags(self) -> u32 {
        match self {
            Resp::None => 0,
            Resp::R1 => CMD_RESP_EXP | CMD_CHECK_CRC,
            Resp::R2 => CMD_RESP_EXP | CMD_RESP_LEN | CMD_CHECK_CRC,
            Resp::R3 => CMD_RESP_EXP,
        }
    }
}

/// A step that writes registers: under the queue's lock when queued.
fn programming<T>(turn: Option<&Turn<'_>>, f: impl FnOnce() -> T) -> T {
    match turn {
        Some(t) => t.program(f),
        None => f(),
    }
}

/// A device wait: with no lock held when queued.
fn waiting<T>(turn: Option<&Turn<'_>>, f: impl FnOnce() -> T) -> T {
    match turn {
        Some(t) => t.wait(f),
        None => f(),
    }
}

/// The response registers: the long response comes out RESP3 first, so word 0
/// holds response bits 127:96 and CSD bit N is bit N of the 128-bit value
/// (U-Boot `dwmci_send_cmd_common`, which reads RESP3..RESP0 into
/// `response[0..4]`). A short response is word 0 only.
fn read_response<R: Regs>(r: &R, long: bool) -> [u32; 4] {
    if long {
        [r.rd32(RESP3), r.rd32(RESP2), r.rd32(RESP1), r.rd32(RESP0)]
    } else {
        [r.rd32(RESP0), 0, 0, 0]
    }
}

/// Issue one command without data and return its response. The caller is the
/// owner of the controller (init, or a queued request's `turn`). A command whose
/// response is R1b (CMD7, CMD12) leaves the card holding DAT0 low for a while;
/// the busy is not waited for here but by the start of the next command, which
/// is the only thing that could collide with it.
fn send_cmd_on<R: Regs>(r: &R, turn: Option<&Turn<'_>>, cmd: u32, arg: u32, resp: Resp) -> Result<[u32; 4], Fault> {
    let abort = cmd == CMD_STOP;
    // A previous write's programming, or an R1b's busy: the controller waits on
    // its own for the data state machine (PRV_DAT_WAIT), but DAT0 is the card's.
    if !abort && !waiting(turn, || wait_not_busy(r, BUSY_TIMEOUT_US)) {
        azos_drv_sys::kerr!("[SDMMC] CMD{}: the card stayed busy", cmd);
        return Err(Fault::Deadline);
    }
    let mut flags = cmd | resp.flags() | CMD_START | CMD_USE_HOLD;
    flags |= if abort { CMD_ABORT_STOP } else { CMD_PRV_DAT_WAIT };
    if cmd == CMD_GO_IDLE {
        flags |= CMD_SEND_INIT;
    }
    programming(turn, || {
        clear_events(r);
        r.wr32(CMDARG, arg);
        r.wr32(CMD, flags);
    });
    if !waiting(turn, || wait_clear(r, CMD, CMD_START, START_TIMEOUT_US)) {
        azos_drv_sys::kerr!("[SDMMC] CMD{}: the controller did not take the command", cmd);
        waiting(turn, || recover(r));
        return Err(Fault::Deadline);
    }
    waiting(turn, || wait_events(r, EV_CDONE, CMD_TIMEOUT_US))?;
    Ok(read_response(r, resp == Resp::R2))
}

/// CMD55 then the application command `acmd`.
fn send_acmd_on<R: Regs>(r: &R, turn: Option<&Turn<'_>>, rca: u32, acmd: u32, arg: u32, resp: Resp) -> Result<[u32; 4], Fault> {
    send_cmd_on(r, turn, CMD_APP_CMD, rca << 16, Resp::R1)?;
    send_cmd_on(r, turn, acmd, arg, resp)
}

/// One data command of `bytes` bytes in blocks of `blksz` through the IDMAC
/// over the bounce pages (a write's data is already there). Returns the
/// command's R1. `Err` on any controller error, IDMAC error or timeout (the
/// controller is reset).
fn data_cmd<R: Regs>(r: &R, turn: Option<&Turn<'_>>, cmd: u32, arg: u32, write: bool, bytes: usize, blksz: u32) -> Result<u32, Fault> {
    debug_assert!(bytes >= 1 && bytes <= XFER_PAGES * PAGE);
    let pages = write_chain(bytes);

    // Hand the chain and the pages to the device: a non-coherent controller
    // reads RAM behind the CPU's caches (no-op on a coherent one).
    let domain = azos_dma::registry::domain_for_mmio(r.base() as u64);
    let dir = if write { Direction::ToDevice } else { Direction::FromDevice };
    let stride = if DMA64.load(Ordering::Acquire) { DESC64_BYTES } else { DESC32_BYTES };
    // SAFETY: the chain and the pages are ours, mapped kernel memory.
    unsafe {
        azos_dma::cache::sync_for_device(domain, DMA.table_va.load(Ordering::Relaxed), pages * stride, Direction::ToDevice);
        for p in 0..pages {
            azos_dma::cache::sync_for_device(domain, DMA.page_va[p].load(Ordering::Relaxed), PAGE, dir);
        }
    }
    azos_dma::order::io_wmb();

    if !waiting(turn, || wait_not_busy(r, BUSY_TIMEOUT_US)) {
        azos_drv_sys::kerr!("[SDMMC] CMD{}: the card stayed busy", cmd);
        return Err(Fault::Deadline);
    }
    // The FIFO is empty before a transfer (a reset bit, a few CIU clocks).
    waiting(turn, || {
        r.wr32(CTRL, r.rd32(CTRL) | CTRL_FIFO_RESET);
        wait_clear(r, CTRL, CTRL_FIFO_RESET, RESET_TIMEOUT_US)
    });

    let table_pa = DMA.table_pa.load(Ordering::Relaxed);
    let mut flags = cmd | CMD_START | CMD_USE_HOLD | CMD_PRV_DAT_WAIT | CMD_DATA_EXP | Resp::R1.flags();
    if write {
        flags |= CMD_RW;
    }
    programming(turn, || {
        clear_events(r);
        r.wr32(DBADDR, table_pa as u32);
        if DMA64.load(Ordering::Acquire) {
            r.wr32(DBADDRU64, (table_pa >> 32) as u32);
        }
        r.wr32(CTRL, r.rd32(CTRL) | CTRL_IDMAC_EN | CTRL_DMA_EN);
        r.wr32(BMOD, r.rd32(BMOD) | BMOD_FB | BMOD_DE);
        r.wr32(BLKSIZ, blksz);
        r.wr32(BYTCNT, bytes as u32);
        r.wr32(CMDARG, arg);
        r.wr32(CMD, flags);
    });

    let res = (|| {
        if !waiting(turn, || wait_clear(r, CMD, CMD_START, START_TIMEOUT_US)) {
            azos_drv_sys::kerr!("[SDMMC] CMD{}: the controller did not take the command", cmd);
            waiting(turn, || recover(r));
            return Err(Fault::Deadline);
        }
        waiting(turn, || wait_events(r, EV_CDONE, CMD_TIMEOUT_US))?;
        // The card's verdict on the command (address, write protect, ...).
        let r1 = r.rd32(RESP0);
        waiting(turn, || wait_events(r, EV_DTO, XFER_TIMEOUT_US))?;
        // The IDMAC has also moved the last byte to or from memory.
        waiting(turn, || wait_events(r, EV_DMA_DONE, XFER_TIMEOUT_US))?;
        Ok(r1)
    })();
    // Whether it worked or not, the controller stops walking the chain.
    programming(turn, || r.wr32(CTRL, r.rd32(CTRL) & !CTRL_DMA_EN));
    let r1 = res?;

    io_rmb();
    if !write {
        // SAFETY: as above.
        unsafe {
            for p in 0..pages {
                azos_dma::cache::sync_for_cpu(domain, DMA.page_va[p].load(Ordering::Relaxed), PAGE, Direction::FromDevice);
            }
        }
    }
    Ok(r1)
}

/// One request chunk of `nblk` sectors (1..=`MAX_XFER_BLOCKS`) at card address
/// `addr`: CMD17/24, or CMD18/25 followed by CMD12. Returns the data command's
/// R1.
fn xfer_chunk<R: Regs>(r: &R, turn: &Turn<'_>, write: bool, addr: u32, nblk: u32) -> Result<u32, Fault> {
    debug_assert!(nblk >= 1 && nblk <= MAX_XFER_BLOCKS);
    let multi = nblk > 1;
    let cmd = match (write, multi) {
        (false, false) => CMD_READ_SINGLE,
        (false, true) => CMD_READ_MULTI,
        (true, false) => CMD_WRITE_SINGLE,
        (true, true) => CMD_WRITE_MULTI,
    };
    let res = data_cmd(r, Some(turn), cmd, addr, write, nblk as usize * 512, 512);
    if multi {
        // The card keeps streaming, or keeps waiting for blocks, until CMD12;
        // after a failed transfer too, or it would stay out of `tran`.
        let stop = send_cmd_on(r, Some(turn), CMD_STOP, 0, Resp::R1);
        if res.is_ok() {
            stop?;
        }
    }
    res
}

// ── Card init ────────────────────────────────────────────────────────────────
/// A field of the 128-bit CSD/CID response `v`: bits `hi..=lo`.
fn csd_bits(v: &[u32; 4], hi: u32, lo: u32) -> u32 {
    let w = (v[0] as u128) << 96 | (v[1] as u128) << 64 | (v[2] as u128) << 32 | v[3] as u128;
    ((w >> lo) & ((1u128 << (hi - lo + 1)) - 1)) as u32
}

/// The card's size in 512-byte sectors from its CSD (SD Physical Layer spec,
/// CSD version 1.0 and 2.0). `None` for a structure this driver does not know
/// (SDUC).
pub fn csd_sectors(csd: &[u32; 4]) -> Option<u64> {
    match csd_bits(csd, 127, 126) {
        0 => {
            let read_bl_len = csd_bits(csd, 83, 80);
            let c_size = csd_bits(csd, 73, 62) as u64;
            let mult = csd_bits(csd, 49, 47);
            if read_bl_len < 9 || read_bl_len > 11 {
                return None;
            }
            Some(((c_size + 1) << (mult + 2)) * (1u64 << read_bl_len) / 512)
        }
        1 => Some((csd_bits(csd, 69, 48) as u64 + 1) * 1024),
        _ => None,
    }
}

/// Switch the card to high speed (CMD6 in two steps, the second one only when
/// the first said the function is there) and run the clock at 50 MHz.
/// `false` leaves the card at the default speed.
fn enter_high_speed<R: Regs>(r: &R, csd: &[u32; 4]) -> bool {
    if csd_bits(csd, 95, 84) & CCC_SWITCH == 0 {
        return false;
    }
    let status = |arg: u32| -> Option<[u8; SWITCH_STATUS_BYTES]> {
        let r1 = data_cmd(r, None, CMD_SWITCH_FUNC, arg, false, SWITCH_STATUS_BYTES, SWITCH_STATUS_BYTES as u32).ok()?;
        if r1 & R1_ERRORS != 0 {
            return None;
        }
        let mut s = [0u8; SWITCH_STATUS_BYTES];
        bounce_out(&mut s);
        Some(s)
    };
    // Cache-line maintenance is in `data_cmd`; the status is the first bytes
    // of the first bounce page.
    match status(SWITCH_CHECK_HS) {
        Some(s) if s[13] & SWITCH_HS_SUPPORTED != 0 => {}
        _ => return false,
    }
    // The function selected in group 1 is the low nibble of byte 16.
    match status(SWITCH_SET_HS) {
        Some(s) if s[16] & 0xF == 1 => {}
        _ => return false,
    }
    set_clock(r, CLK_HIGH_SPEED_HZ)
}

/// Initialise the SD card behind the attached controller: the full sequence in
/// the module doc. Safe to call again (it resets the controller first).
/// Returns `true` with the card selected, in 4-bit mode and at its speed.
pub fn init() -> bool {
    let base = BASE.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    init_on(&Hw(base))
}

/// [`init`] over `r`.
pub fn init_on<R: Regs>(r: &R) -> bool {
    READY.store(false, Ordering::Release);
    HIGH_SPEED.store(false, Ordering::Release);
    CAPACITY.store(0, Ordering::Release);
    let ciu = CIU_HZ.load(Ordering::Acquire);
    if ciu < CLK_IDENT_HZ {
        azos_drv_sys::kerr!("[SDMMC] no CIU clock rate: not initialising");
        return false;
    }

    // ── 1. Reset the controller, its FIFO and the IDMAC ─────────────────────
    r.wr32(PWREN, 1);
    r.wr32(CTRL, CTRL_RESET_ALL);
    if !wait_clear(r, CTRL, CTRL_RESET_ALL, RESET_TIMEOUT_US) {
        azos_drv_sys::kerr!("[SDMMC] controller reset did not complete");
        return false;
    }

    // ── 2. FIFO watermarks and the IDMAC ────────────────────────────────────
    // MSIZE 0b010 (burst of 8), RX watermark thr - 1, TX watermark thr, with
    // thr half the FIFO (U-Boot `dwmci_init_fifo`).
    let thr = FIFO_DEPTH.load(Ordering::Acquire) / 2;
    r.wr32(FIFOTH, (0x2 << 28) | ((thr - 1) << FIFOTH_RX_SHIFT) | thr);
    r.wr32(BMOD, BMOD_SWR);
    wait_clear(r, BMOD, BMOD_SWR, RESET_TIMEOUT_US);
    DMA64.store(r.rd32(HCON) & HCON_ADDR64 != 0, Ordering::Release);
    if !dma_prepare() {
        azos_drv_sys::kerr!("[SDMMC] no DMA-reachable memory for the IDMAC chain");
        return false;
    }

    // ── 3. Event reporting: status polled until the kernel routes the line ──
    r.wr32(TMOUT, TMOUT_MAX);
    r.wr32(CTYPE, 0);
    clear_events(r);
    enable_irqs(r);

    // ── 4. Card clock at 400 kHz ────────────────────────────────────────────
    if !set_clock(r, CLK_IDENT_HZ) {
        azos_drv_sys::kerr!("[SDMMC] clock setup failed");
        return false;
    }

    // ── 5. CMD0, CMD8 ───────────────────────────────────────────────────────
    let _ = send_cmd_on(r, None, CMD_GO_IDLE, 0, Resp::None);
    delay_us(1_000);
    // A valid echo of the check pattern means the card is SD 2.0+ (SDHC/SDXC
    // possible). A card that does not answer is SD 1.x or absent.
    let v2 = matches!(send_cmd_on(r, None, CMD_SEND_IF_COND, 0x0000_01AA, Resp::R1), Ok(resp) if resp[0] & 0x1FF == 0x1AA);

    // ── 6. ACMD41 until the card is powered up (HCS if CMD8 answered) ───────
    let acmd41_arg = if v2 { 0x4000_0000u32 } else { 0 } | 0x00FF_8000;
    let deadline = deadline_after_us(POWER_UP_TIMEOUT_US);
    let mut ocr = 0u32;
    loop {
        match send_acmd_on(r, None, 0, ACMD_SD_SEND_OP, acmd41_arg, Resp::R3) {
            Ok(resp) => {
                ocr = resp[0];
                if ocr >> 31 != 0 {
                    break;
                }
            }
            // Nothing answers CMD55: no card, or not an SD card.
            Err(Fault::NoResponse) => {
                azos_drv_sys::kprintln!("[SDMMC] no SD card answers");
                return false;
            }
            Err(_) => {}
        }
        if now() >= deadline {
            azos_drv_sys::kerr!("[SDMMC] ACMD41 timeout (OCR={:#x})", ocr);
            return false;
        }
        delay_us(1_000);
    }
    let is_sdhc = (ocr >> 30) & 1 != 0; // CCS: 1 = SDHC/SDXC, block-addressed

    // ── 7. CMD2, CMD3, CMD9 ─────────────────────────────────────────────────
    if send_cmd_on(r, None, CMD_ALL_SEND_CID, 0, Resp::R2).is_err() {
        azos_drv_sys::kerr!("[SDMMC] CMD2 (CID) failed");
        return false;
    }
    let rca = match send_cmd_on(r, None, CMD_SEND_RCA, 0, Resp::R1) {
        Ok(resp) => resp[0] >> 16,
        Err(_) => {
            azos_drv_sys::kerr!("[SDMMC] CMD3 (RCA) failed");
            return false;
        }
    };
    let csd = match send_cmd_on(r, None, CMD_SEND_CSD, rca << 16, Resp::R2) {
        Ok(csd) => csd,
        Err(_) => {
            azos_drv_sys::kerr!("[SDMMC] CMD9 (CSD) failed");
            return false;
        }
    };
    let Some(capacity) = csd_sectors(&csd) else {
        azos_drv_sys::kerr!("[SDMMC] CSD {:08x}{:08x}{:08x}{:08x}: structure not supported", csd[0], csd[1], csd[2], csd[3]);
        return false;
    };

    // ── 8. CMD7 selects the card (R1b), CMD16 on a standard-capacity card ───
    if send_cmd_on(r, None, CMD_SELECT, rca << 16, Resp::R1).is_err() {
        azos_drv_sys::kerr!("[SDMMC] CMD7 (select) failed");
        return false;
    }
    if !is_sdhc && send_cmd_on(r, None, CMD_SET_BLOCKLEN, 512, Resp::R1).is_err() {
        azos_drv_sys::kerr!("[SDMMC] CMD16 failed");
        return false;
    }

    // ── 9. ACMD6: 4-bit bus, then the controller's CTYPE ────────────────────
    if send_acmd_on(r, None, rca, ACMD_SET_BUS_WIDTH, 2, Resp::R1).is_err() {
        azos_drv_sys::kerr!("[SDMMC] ACMD6 (bus width) failed");
        return false;
    }
    r.wr32(CTYPE, CTYPE_4BIT);

    // ── 10. 25 MHz, then high speed (50 MHz) when the card has it ───────────
    if !set_clock(r, CLK_DEFAULT_HZ) {
        return false;
    }
    let hs = enter_high_speed(r, &csd);
    HIGH_SPEED.store(hs, Ordering::Release);

    RCA.store(rca, Ordering::Release);
    IS_SDHC.store(is_sdhc, Ordering::Release);
    CAPACITY.store(capacity, Ordering::Release);
    WRITE_FAULT.store(false, Ordering::Release);
    READY.store(true, Ordering::Release);
    azos_drv_sys::kprintln!("[SDMMC] {} card ready  RCA={:#06x}  {} MiB  4-bit {}",
        if is_sdhc { "SDHC" } else { "SDSC" }, rca, capacity / 2048,
        if hs { "50 MHz" } else { "25 MHz" });
    true
}

// ── Requests ─────────────────────────────────────────────────────────────────
/// The card address of sector `lba`: block-addressed on SDHC, byte-addressed
/// on SDSC.
fn card_addr(lba: u64) -> u32 {
    if IS_SDHC.load(Ordering::Acquire) { lba as u32 } else { (lba * 512) as u32 }
}

/// Is `count` sectors at `lba` inside the card.
fn in_range(lba: u64, count: u32) -> bool {
    lba.checked_add(count as u64).is_some_and(|end| end <= capacity())
}

/// Read `count` 512-byte sectors starting at `lba` into `buf`.
pub fn read(lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    let base = BASE.load(Ordering::Acquire);
    if base == 0 {
        return Err(());
    }
    read_on(&Hw(base), lba, count, buf)
}

/// [`read`] over `r`.
pub fn read_on<R: Regs>(r: &R, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    if buf.len() < count as usize * 512 {
        return Err(());
    }
    let turn = QUEUE.submit();
    if !READY.load(Ordering::Acquire) || !in_range(lba, count) {
        return Err(());
    }
    let mut done = 0u32;
    while done < count {
        let n = (count - done).min(MAX_XFER_BLOCKS);
        xfer_chunk(r, &turn, false, card_addr(lba + done as u64), n).map_err(|_| ())?;
        bounce_out(&mut buf[done as usize * 512..(done + n) as usize * 512]);
        done += n;
    }
    Ok(())
}

/// Write `count` 512-byte sectors starting at `lba` from `buf`.
///
/// Any failure — including an error bit in a CMD24/CMD25 response, which the
/// card reports once and then clears — also latches `WRITE_FAULT`, so the next
/// [`flush`] does not confirm durability over it.
pub fn write(lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    let base = BASE.load(Ordering::Acquire);
    if base == 0 {
        return Err(());
    }
    write_on(&Hw(base), lba, count, buf)
}

/// [`write`] over `r`.
pub fn write_on<R: Regs>(r: &R, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    if buf.len() < count as usize * 512 {
        return Err(());
    }
    let turn = QUEUE.submit();
    let res = write_chunks(r, &turn, lba, count, buf);
    if res.is_err() {
        WRITE_FAULT.store(true, Ordering::Release);
    }
    res
}

fn write_chunks<R: Regs>(r: &R, turn: &Turn<'_>, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    if !READY.load(Ordering::Acquire) || !in_range(lba, count) {
        return Err(());
    }
    let mut done = 0u32;
    while done < count {
        let n = (count - done).min(MAX_XFER_BLOCKS);
        bounce_in(&buf[done as usize * 512..(done + n) as usize * 512]);
        let r1 = xfer_chunk(r, turn, true, card_addr(lba + done as u64), n).map_err(|_| ())?;
        // The data phase ran to its end; the card's verdict decides the request.
        if r1 & R1_ERRORS != 0 {
            azos_drv_sys::kerr!("[SDMMC] write lba {} status {:#010x} (error bits {:#010x})",
                lba + done as u64, r1, r1 & R1_ERRORS);
            return Err(());
        }
        done += n;
    }
    Ok(())
}

/// CMD13 SEND_STATUS until the card is in `tran` with READY_FOR_DATA. `Err` on:
/// a CMD13 the controller did not complete, any R1 error bit, a state other
/// than `tran`/`prg`/`rcv` (the card is not selected, or is somewhere a write
/// cannot leave it), or `FLUSH_TIMEOUT_US` without reaching `tran` + ready.
fn wait_card_ready<R: Regs>(r: &R, turn: &Turn<'_>, rca: u32) -> Result<u32, FlushError> {
    let deadline = deadline_after_us(FLUSH_TIMEOUT_US);
    loop {
        let Ok(resp) = send_cmd_on(r, Some(turn), CMD_SEND_STATUS, rca << 16, Resp::R1) else {
            azos_drv_sys::kprintln!("[SDMMC] flush: CMD13 did not complete");
            return Err(FlushError::Io);
        };
        let st = resp[0];
        if st & R1_ERRORS != 0 {
            azos_drv_sys::kerr!("[SDMMC] flush: card status {:#010x} carries error bits {:#010x}", st, st & R1_ERRORS);
            return Err(FlushError::Io);
        }
        let state = (st >> R1_STATE_SHIFT) & R1_STATE_MASK;
        match state {
            STATE_TRAN if st & R1_READY_FOR_DATA != 0 => return Ok(st),
            STATE_TRAN | STATE_PRG | STATE_RCV => {}
            _ => {
                azos_drv_sys::kprintln!("[SDMMC] flush: card in state {} (status {:#010x}), not tran", state, st);
                return Err(FlushError::Io);
            }
        }
        if now() >= deadline {
            azos_drv_sys::kprintln!("[SDMMC] flush: card still busy after {} us (last {:#010x})", FLUSH_TIMEOUT_US, st);
            return Err(FlushError::Io);
        }
    }
}

/// Make every write the controller completed durable on the card: a CMD24 is
/// complete when the block is sent and DAT0 is released, but the card may
/// still be moving it into flash. It reports it is done by returning to `tran`
/// with READY_FOR_DATA, which is what CMD13 is polled for. There is no eMMC
/// cache here to flush. `Ok` only on a confirmed card status; a write that
/// failed since the last flush, a CMD13 that did not complete, an error bit,
/// or the deadline answer `Err(Io)`.
pub fn flush() -> Result<(), FlushError> {
    let base = BASE.load(Ordering::Acquire);
    if base == 0 {
        return Err(FlushError::Io);
    }
    flush_on(&Hw(base))
}

/// [`flush`] over `r`.
pub fn flush_on<R: Regs>(r: &R) -> Result<(), FlushError> {
    let turn = QUEUE.submit();
    if !READY.load(Ordering::Acquire) {
        return Err(FlushError::Io);
    }
    if WRITE_FAULT.swap(false, Ordering::AcqRel) {
        azos_drv_sys::kerr!("[SDMMC] flush: a write failed since the last flush");
        return Err(FlushError::Io);
    }
    wait_card_ready(r, &turn, RCA.load(Ordering::Acquire)).map(|_| ())
}
