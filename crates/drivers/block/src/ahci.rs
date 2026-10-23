// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AHCI 1.3 SATA host (Kconfig `DRV_AHCI`, cargo feature `ahci`): one ATA disk
//! as the boot block device, for the PCs whose disk is not NVMe.
//!
//! The file has two halves. The first is the driver: [`Ahci`] over a register
//! window ([`Regs`]), which brings the HBA and one port up and implements
//! [`HwQueue`] for the block request layer (`queue.rs`). It names no PCI
//! type and no kernel static, so `tests/host/drivers-tests` runs the very
//! functions the kernel runs over a model of the HBA and a disk (the way
//! `mmc.rs` is run). The second half (the cargo feature `ahci`) is the
//! kernel's handle on the one controller: the static it lives in, the MSI
//! entry and the scheduler hooks. The PCI work (BAR 5, the MSI message) is
//! the kernel's (`kernel/src/boot/ahci.rs`), which passes this file the
//! mapped ABAR, the DMA limit and the MSI token.
//!
//! # Shape
//!
//! * **Bring-up** ([`Ahci::attach`]): take the HBA from the firmware if it
//!   owns it (BOHC), reset it (`GHC.HR`), and for every implemented port
//!   stop it, power it and wait (bounded) for the link and for the device to
//!   leave BSY. The first port whose signature is ATA is the disk; ATAPI and
//!   port multipliers are left alone. The command list, the received-FIS area
//!   and the command table share one page; the staging pages follow. Then
//!   IDENTIFY DEVICE (polled, bounded) says whether the disk is driveable:
//!   LBA48, 512-byte logical sectors.
//! * **One command at a time.** NCQ is off, and the commands used (READ/WRITE
//!   DMA EXT, FLUSH CACHE EXT) are not queued, so slot 0 is the only slot:
//!   [`HwQueue::claim`] answers `Busy` while it is held, and the request layer
//!   keeps the rest queued. The HBA's other 31 slots are never used.
//! * **Staging.** The device is never handed caller memory (a command cannot
//!   be recalled, and a caller buffer is often a popped stack frame). A
//!   write's segments are copied into the staging pages at `start`, a read's
//!   data out of them at `copy_out`. The command table's PRDT names one entry
//!   per page, so the pages need not be contiguous. Every page comes from the
//!   page allocator below the controller's DMA limit (`azos_dma`): the
//!   caller's mask, narrowed to 4 GiB when `CAP.S64A` says the HBA has no
//!   64-bit addressing.
//! * **Completion.** A command is done when its `PxCI` bit is clear. By MSI
//!   where the machine routes one: [`Ahci::irq`] reads and clears `PxIS`/`IS`,
//!   remembers the bits and wakes the one task the request layer lets sleep
//!   in the device ([`HwQueue::wait`], a [`DeviceWait`]). Without a route, or
//!   before the scheduler exists, the layer spins and `reap` reads the
//!   registers. Legacy INTx is not routed (no PCI driver in this tree has an
//!   INTx pin to interrupt line route yet).
//! * **Errors.** A fatal port interrupt (task file error, host bus or
//!   interface error) fails the command and restarts the port (AHCI 1.3
//!   section 6.2.2.1: stop, clear `PxSERR` and `PxIS`, start), which abandons
//!   the commands the HBA held; the disk stays usable. An aborted FLUSH CACHE
//!   EXT is "this disk has no flush" ([`HwStatus::Unsupported`]), as for NVMe.
//!   A command that misses its budget resets the HBA (`GHC.HR`, which stops
//!   its DMA on every port) and brings the port up again, once per boot
//!   (Kconfig `DEVICE_TIMEOUT_RESETS`, `azos_drv_api::recovery`): the command
//!   ends [`HwStatus::Timeout`] and the disk carries on, if the same disk
//!   answers IDENTIFY again. A second timeout, a reset that does not bring it
//!   back, or a port that will not restart latches the driver dead until
//!   reboot: no disk beats silently wrong disk. The staging pages are then
//!   never reused (a command the HBA could not recall may still be writing
//!   to them).
//! * **Budgets** are time the guest ran ([`StallClock`]): a guest the host
//!   stopped for a second does not find its disk dead.
//! * **No FUA, no discard.** SATA has Force Unit Access only inside NCQ, so
//!   [`HwCaps::fua`] is false and the layer orders writes with a flush.
//!   Nothing in the tree needs TRIM for a SATA disk yet.
//!
//! DMA coherence is assumed (the PCs this driver is for), as for NVMe.

use crate::queue::{Claim, HwCaps, HwCmd, HwDone, HwOp, HwQueue, HwStatus, HW_TAGS_MAX};
use azos_drv_api::block::{DeviceWait, StallClock, STALL_GAP_US};
use azos_drv_api::recovery::{Class, Recovery, Verdict};
use azos_sync::kmutex::Mutex;
use core::sync::atomic::{fence, AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicU8, Ordering};

// ---- Registers (AHCI 1.3.1, section 3) ----

/// HBA registers.
const REG_CAP: usize = 0x00;
const REG_GHC: usize = 0x04;
const REG_IS: usize = 0x08;
const REG_PI: usize = 0x0C;
const REG_CAP2: usize = 0x24;
const REG_BOHC: usize = 0x28;
/// Port `n`'s registers start at `PORT_BASE + n * PORT_STRIDE`.
const PORT_BASE: usize = 0x100;
const PORT_STRIDE: usize = 0x80;

const CAP_SCLO: u32 = 1 << 24;
const CAP_S64A: u32 = 1 << 31;
const CAP2_BOH: u32 = 1 << 0;

const GHC_HR: u32 = 1 << 0;
const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31;

const BOHC_BOS: u32 = 1 << 0;
const BOHC_OOS: u32 = 1 << 1;
const BOHC_BB: u32 = 1 << 4;

/// Port registers, relative to the port's base.
const P_CLB: usize = 0x00;
const P_CLBU: usize = 0x04;
const P_FB: usize = 0x08;
const P_FBU: usize = 0x0C;
const P_IS: usize = 0x10;
const P_IE: usize = 0x14;
const P_CMD: usize = 0x18;
const P_TFD: usize = 0x20;
const P_SIG: usize = 0x24;
const P_SSTS: usize = 0x28;
const P_SERR: usize = 0x30;
const P_CI: usize = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_CLO: u32 = 1 << 3;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const CMD_CPD: u32 = 1 << 20;

/// `PxIS`: a D2H register FIS arrived (the end of every command we send).
const IS_DHRS: u32 = 1 << 0;
const IS_IFS: u32 = 1 << 27;
const IS_HBDS: u32 = 1 << 28;
const IS_HBFS: u32 = 1 << 29;
const IS_TFES: u32 = 1 << 30;
/// The errors that stop the port's command engine (section 6.2.2): the
/// command is failed and the port restarted.
const IS_FATAL: u32 = IS_TFES | IS_HBFS | IS_HBDS | IS_IFS;
/// What the port is allowed to interrupt for.
const IE_MASK: u32 = IS_DHRS | IS_FATAL;

const TFD_ERR: u32 = 1 << 0;
const TFD_DRQ: u32 = 1 << 3;
const TFD_DF: u32 = 1 << 5;
const TFD_BSY: u32 = 1 << 7;
/// The ATA error register sits in `PxTFD` 15:8; bit 2 is ABRT.
const ATA_ERR_ABRT: u32 = 1 << 2;

const SSTS_DET_MASK: u32 = 0xF;
const SSTS_DET_PRESENT: u32 = 3;
const SSTS_DET_DETECTED: u32 = 1;
const SSTS_IPM_ACTIVE: u32 = 1 << 8;
const SSTS_IPM_MASK: u32 = 0xF << 8;

/// `PxSIG` of an ATA device (a disk), and the unset value of a device that
/// has not sent its signature FIS yet.
const SIG_ATA: u32 = 0x0000_0101;
const SIG_UNSET: u32 = 0xFFFF_FFFF;

// ---- ATA ----

const ATA_IDENTIFY: u8 = 0xEC;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_FLUSH_CACHE_EXT: u8 = 0xEA;
/// Device register of a command in LBA mode.
const ATA_DEVICE_LBA: u8 = 0x40;

pub const SECTOR_SIZE: usize = 512;
const PAGE: usize = 4096;

// ---- Memory layout ----

/// Bounce pages one command moves (Kconfig `AHCI_XFER_KB`).
pub const XFER_PAGES: usize = azos_limits::AHCI_XFER_KB as usize * 1024 / PAGE;
/// Sectors one command carries at most.
pub const XFER_SECTORS: usize = XFER_PAGES * PAGE / SECTOR_SIZE;

/// The first page: the command list (slot 0's 32-byte header at the start,
/// 1 KiB aligned), the received-FIS area (256-byte aligned) and the command
/// table (128-byte aligned: the command FIS, then the PRDT from `CT_PRDT`).
const CL_OFF: usize = 0;
const FB_OFF: usize = 0x400;
const CT_OFF: usize = 0x800;
const CT_PRDT: usize = 0x80;
const PRD_BYTES: usize = 16;
const _: () = assert!(XFER_PAGES >= 1 && CT_OFF + CT_PRDT + XFER_PAGES * PRD_BYTES <= PAGE);
const _: () = assert!(XFER_SECTORS <= 65536);

/// What the command in slot 0 is, for how its end is read.
const OP_DATA: u8 = 0;
const OP_FLUSH: u8 = 1;
/// A flush the disk has no command for: complete at the next `reap`, as
/// unsupported, without touching the HBA.
const OP_NO_FLUSH: u8 = 2;

// ---- Pure encodings (the wire, apart from the device) ----

/// The 20-byte H2D register FIS of a command (AHCI 1.3 section 10.3.4,
/// SATA 3 section 10.3.4): the Command bit set, LBA mode, 48-bit LBA and
/// sector count split the way the FIS lays them out. A count of 65536 is 0.
pub fn h2d_fis(command: u8, lba: u64, count: u32) -> [u8; 20] {
    let mut f = [0u8; 20];
    f[0] = 0x27;
    f[1] = 0x80;
    f[2] = command;
    f[4] = lba as u8;
    f[5] = (lba >> 8) as u8;
    f[6] = (lba >> 16) as u8;
    f[7] = ATA_DEVICE_LBA;
    f[8] = (lba >> 24) as u8;
    f[9] = (lba >> 32) as u8;
    f[10] = (lba >> 40) as u8;
    f[12] = count as u8;
    f[13] = (count >> 8) as u8;
    f
}

/// IDENTIFY DEVICE addresses no sector: its FIS carries no LBA, and the
/// device register is 0.
fn identify_fis() -> [u8; 20] {
    let mut f = h2d_fis(ATA_IDENTIFY, 0, 0);
    f[7] = 0;
    f
}

/// Command header (slot 0) as eight dwords: 5 FIS dwords, the write
/// direction bit, `prdtl` PRDT entries, and the table's bus address. PRDBC
/// (dword 1) starts at 0; the HBA counts into it.
pub fn cmd_header(write: bool, prdtl: usize, ctba: u64) -> [u32; 8] {
    [5 | (write as u32) << 6 | (prdtl as u32) << 16, 0, ctba as u32, (ctba >> 32) as u32, 0, 0, 0, 0]
}

/// One PRDT entry: the data base address, a reserved dword, and the byte
/// count minus one (22 bits; the interrupt-on-completion bit stays clear).
pub fn prd_entry(pa: u64, len: usize) -> [u32; 4] {
    [pa as u32, (pa >> 32) as u32, 0, (len as u32 - 1) & 0x3F_FFFF]
}

/// What IDENTIFY DEVICE says that the driver needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ident {
    pub sectors: u64,
    /// The disk has FLUSH CACHE EXT.
    pub flush_ext: bool,
}

/// Why a disk or a controller is not brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AhciError {
    NoMemory,
    /// The firmware kept the HBA (BOHC) past the budget.
    Handoff,
    /// `GHC.HR` did not clear.
    Reset,
    /// No port has an ATA disk behind it that came ready.
    NoDisk,
    /// A port would not stop or start.
    Port(&'static str),
    /// A command of bring-up failed or timed out.
    Identify(&'static str),
    /// The disk is not one this driver drives (named).
    Format(&'static str),
    /// Another controller is already the block device.
    Taken,
}

/// Decode the 256 words of IDENTIFY DEVICE (ACS-3 table 45). 48-bit LBA is
/// required (READ/WRITE DMA EXT), and the logical sector must be 512 bytes.
pub fn decode_identify(w: &[u16; 256]) -> Result<Ident, AhciError> {
    // Word 0 bit 15: not an ATA device (ATAPI answers IDENTIFY PACKET DEVICE).
    if w[0] & 0x8000 != 0 {
        return Err(AhciError::Format("not an ATA disk"));
    }
    // Word 83 is valid when bit 14 is set and bit 15 clear.
    let w83_valid = w[83] & 0xC000 == 0x4000;
    if !(w83_valid && w[83] & (1 << 10) != 0) {
        return Err(AhciError::Format("no 48-bit LBA"));
    }
    // Word 106: logical sector size; valid when bit 14 set and bit 15 clear.
    // Bit 12: the logical sector is longer than 256 words, words 117-118 say
    // by how much (in words).
    if w[106] & 0xC000 == 0x4000 && w[106] & (1 << 12) != 0 {
        let words = w[117] as u32 | (w[118] as u32) << 16;
        if words != 256 {
            return Err(AhciError::Format("logical sector is not 512 bytes"));
        }
    }
    let sectors = w[100] as u64 | (w[101] as u64) << 16 | (w[102] as u64) << 32 | (w[103] as u64) << 48;
    if sectors == 0 {
        return Err(AhciError::Format("empty disk"));
    }
    Ok(Ident { sectors, flush_ext: w[83] & (1 << 13) != 0 })
}

/// The model string (words 27-46: two characters a word, the first in the
/// high byte), trimmed, into `out`; returns its length.
pub fn model_string(w: &[u16; 256], out: &mut [u8; 40]) -> usize {
    for i in 0..20 {
        out[2 * i] = (w[27 + i] >> 8) as u8;
        out[2 * i + 1] = w[27 + i] as u8;
    }
    let mut n = 40;
    while n > 0 && (out[n - 1] == b' ' || out[n - 1] == 0) {
        n -= 1;
    }
    for b in out[..n].iter_mut() {
        if !(0x20..0x7F).contains(b) {
            *b = b'?';
        }
    }
    n
}

// ---- Register access ----

/// An HBA's register file. [`Hw`] is the MMIO window (BAR 5); the host test
/// implements it over a model of the HBA and a disk.
pub trait Regs {
    fn rd32(&self, off: usize) -> u32;
    fn wr32(&self, off: usize, val: u32);
}

/// The HBA's mapped register window at this address.
pub struct Hw(pub usize);

impl Regs for Hw {
    #[inline(always)]
    fn rd32(&self, off: usize) -> u32 {
        // SAFETY: `self.0` is the HBA's ABAR, mapped by the kernel's PCI
        // bring-up, and `off` a register offset inside the 4 KiB-or-larger
        // window.
        unsafe { core::ptr::read_volatile((self.0 + off) as *const u32) }
    }
    #[inline(always)]
    fn wr32(&self, off: usize, val: u32) {
        // SAFETY: as `rd32`.
        unsafe { core::ptr::write_volatile((self.0 + off) as *mut u32, val) }
    }
}

/// One port's registers.
struct Port<'a, R: Regs> {
    r: &'a R,
    base: usize,
}

impl<R: Regs> Port<'_, R> {
    #[inline(always)]
    fn rd(&self, off: usize) -> u32 {
        self.r.rd32(self.base + off)
    }
    #[inline(always)]
    fn wr(&self, off: usize, val: u32) {
        self.r.wr32(self.base + off, val)
    }

    /// Stop the command engine and the FIS receiver (section 10.1.2) and wait
    /// for `CR` and `FR` to drop. `false`: the port did not stop in time.
    fn stop(&self, b: &Budgets) -> bool {
        let cmd = self.rd(P_CMD);
        if cmd & (CMD_ST | CMD_CR | CMD_FRE | CMD_FR) == 0 {
            return true;
        }
        self.wr(P_CMD, cmd & !CMD_ST);
        if !wait_for(b.stop_us, || self.rd(P_CMD) & CMD_CR == 0) {
            return false;
        }
        let cmd = self.rd(P_CMD);
        if cmd & (CMD_FRE | CMD_FR) != 0 {
            self.wr(P_CMD, cmd & !CMD_FRE);
            return wait_for(b.stop_us, || self.rd(P_CMD) & CMD_FR == 0);
        }
        true
    }

    /// Start the FIS receiver, wait for the device to leave BSY and DRQ (a
    /// Command List Override clears them where the HBA has one), then start
    /// the command engine (section 10.3.1).
    fn start(&self, cap: u32, b: &Budgets) -> bool {
        self.wr(P_CMD, self.rd(P_CMD) | CMD_FRE);
        if !wait_for(b.ready_us, || self.rd(P_TFD) & (TFD_BSY | TFD_DRQ) == 0) {
            if cap & CAP_SCLO == 0 {
                return false;
            }
            self.wr(P_CMD, self.rd(P_CMD) | CMD_CLO);
            if !wait_for(b.stop_us, || self.rd(P_CMD) & CMD_CLO == 0)
                || self.rd(P_TFD) & (TFD_BSY | TFD_DRQ) != 0
            {
                return false;
            }
        }
        self.wr(P_CMD, self.rd(P_CMD) | CMD_ST);
        true
    }
}

// ---- Time ----

fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

fn deadline_after_us(us: u64) -> u64 {
    now().saturating_add(us.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000)
}

/// Timebase ticks of `ns` nanoseconds.
fn ns_to_ticks(ns: u64) -> u64 {
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    (ns / 1_000_000_000).saturating_mul(f).saturating_add((ns % 1_000_000_000) * f / 1_000_000_000)
}

/// Poll `cond` until it holds or `us` microseconds passed; `cond` is asked
/// once more at the deadline. Bring-up only: it spins.
fn wait_for(us: u64, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = deadline_after_us(us);
    loop {
        if cond() {
            return true;
        }
        if now() >= deadline {
            return cond();
        }
        core::hint::spin_loop();
    }
}

/// How long the driver waits for each thing. All of them bound a DEAD device
/// or an absent one, not a slow one; the command budgets are measured in time
/// the guest ran ([`StallClock`]).
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    /// The firmware to let go of the HBA (BOHC; 2 s is the spec's allowance).
    pub handoff_us: u64,
    /// `GHC.HR` to clear (the spec says 1 s).
    pub reset_us: u64,
    /// A port to stop (`CR`, `FR`; 500 ms in the spec).
    pub stop_us: u64,
    /// A port that shows a device to bring the link up.
    pub link_us: u64,
    /// A port that shows nothing (`DET` 0) to show something.
    pub absent_us: u64,
    /// A device to leave BSY and send its signature.
    pub ready_us: u64,
    /// IDENTIFY DEVICE.
    pub identify_us: u64,
    /// A read or a write. A spinning disk may retry a bad sector for seconds.
    pub io_us: u64,
    /// A flush writes the whole volatile cache back.
    pub flush_us: u64,
    /// Resets after a command timeout before the driver latches dead
    /// (Kconfig `DEVICE_TIMEOUT_RESETS`).
    pub resets: u8,
}

impl Budgets {
    pub const DEFAULT: Budgets = Budgets {
        handoff_us: 2_000_000,
        reset_us: 1_000_000,
        stop_us: 500_000,
        link_us: 1_000_000,
        absent_us: 100_000,
        ready_us: 5_000_000,
        identify_us: 2_000_000,
        io_us: 5_000_000,
        flush_us: 20_000_000,
        resets: azos_limits::DEVICE_TIMEOUT_RESETS as u8,
    };
}

/// What the kernel gives the driver to sleep and wake with: the caller's
/// TID, "block the caller until a TID wake or `deadline` (timebase ticks)"
/// (`false` where a task cannot block: before the scheduler, with interrupts
/// or preemption off; the waiter then spins), and "wake task `tid`".
pub struct Hooks {
    pub tid: fn() -> u32,
    pub block_until: fn(u64) -> bool,
    pub wake: fn(u32),
}

/// Staging memory comes from the page allocator, below the controller's DMA
/// limit.
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

/// One zeroed page the controller can reach (`mask`: the highest address its
/// DMA gets to): `(CPU address, bus address)`.
fn alloc_page(mask: u64) -> Option<(usize, u64)> {
    let pa = azos_dma::alloc_below(&Pmm, mask, PAGE).ok()?;
    let va = azos_mm::addr::phys_to_virt(pa as usize);
    // SAFETY: a page the allocator just handed out, mapped in the kernel's
    // direct map; nothing else refers to it.
    unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE) };
    Some((va, pa))
}

fn free_page(pa: u64) {
    let _ = azos_mm::pmm::free_page(azos_mm::addr::PhysAddr(pa as usize));
}

#[inline(always)]
fn put32(va: usize, v: u32) {
    // SAFETY: `va` is a dword of a page of ours (command list or table).
    unsafe { core::ptr::write_volatile(va as *mut u32, v) }
}

#[inline(always)]
fn get32(va: usize) -> u32 {
    // SAFETY: as `put32`.
    unsafe { core::ptr::read_volatile(va as *const u32) }
}

// ---- The driver ----

/// One HBA with one ATA disk behind one of its ports.
pub struct Ahci<R: Regs> {
    r: R,
    /// Register offset of the chosen port, and its number.
    pbase: usize,
    port: u8,
    cap: u32,
    b: Budgets,
    sectors: u64,
    flush_ext: bool,
    irq: bool,
    /// The first page: command list, received FIS, command table.
    cl_va: usize,
    cl_pa: u64,
    bounce_va: [usize; XFER_PAGES],
    bounce_pa: [u64; XFER_PAGES],
    /// Serializes publishing a command and reading its outcome; never held
    /// across the device wait.
    lock: Mutex<()>,
    /// Slot 0 is claimed (set by `claim`, cleared by `release`).
    busy: AtomicBool,
    /// Slot 0 holds a started command / its outcome was handed out.
    inflight: AtomicBool,
    reported: AtomicBool,
    op: AtomicU8,
    /// Bytes the HBA must report moved (`PRDBC`) for the command to be whole.
    bytes: AtomicU32,
    /// Timebase tick by which the command must have completed, the stall
    /// credit when it was submitted; when it was started and its first
    /// sector (for the record).
    deadline: AtomicU64,
    credit: AtomicU64,
    started: AtomicU64,
    lba: AtomicU64,
    /// Live, being reset, or latched dead until reboot (the timeout policy).
    recovery: Recovery,
    /// `PxIS` bits read and cleared, not yet looked at by the reaper.
    events: AtomicU32,
    stall: StallClock,
    waiter: DeviceWait,
    hooks: AtomicPtr<Hooks>,
    taken: AtomicU32,
    slept: AtomicU32,
}

impl<R: Regs> Ahci<R> {
    fn port_regs(&self) -> Port<'_, R> {
        Port { r: &self.r, base: self.pbase }
    }

    /// Bring the HBA behind `r` up with the first ATA disk it has. `dma_mask`
    /// is the highest bus address the controller reaches (`u64::MAX`: no
    /// limit); `irq`: its MSI is routed, so interrupts are enabled in the HBA.
    pub fn attach(r: R, dma_mask: u64, irq: bool, b: Budgets) -> Result<Self, AhciError> {
        // The HBA speaks AHCI, not the legacy register set.
        r.wr32(REG_GHC, r.rd32(REG_GHC) | GHC_AE);
        bios_handoff(&r, &b)?;
        r.wr32(REG_GHC, GHC_AE | GHC_HR);
        if !wait_for(b.reset_us, || r.rd32(REG_GHC) & GHC_HR == 0) {
            return Err(AhciError::Reset);
        }
        r.wr32(REG_GHC, GHC_AE);
        let cap = r.rd32(REG_CAP);
        let pi = r.rd32(REG_PI);
        // No 64-bit addressing: every address the HBA is given fits 32 bits.
        let mask = if cap & CAP_S64A != 0 { dma_mask } else { dma_mask.min(0xFFFF_FFFF) };

        // Memory: the page of the command structures, then the staging pages.
        // Taken before the ports are looked at: a device's signature reaches
        // the port only through the received-FIS area, so a port is probed
        // with its command list and FIS area in place and the FIS receiver on.
        let (cl_va, cl_pa) = alloc_page(mask).ok_or(AhciError::NoMemory)?;
        let mut bounce_va = [0usize; XFER_PAGES];
        let mut bounce_pa = [0u64; XFER_PAGES];
        for i in 0..XFER_PAGES {
            match alloc_page(mask) {
                Some((va, pa)) => {
                    bounce_va[i] = va;
                    bounce_pa[i] = pa;
                }
                None => {
                    free_page(cl_pa);
                    for &pa in &bounce_pa[..i] {
                        free_page(pa);
                    }
                    return Err(AhciError::NoMemory);
                }
            }
        }

        // The first port with an ATA disk behind it (one at a time: every
        // probed port leaves its engine stopped, and the winner's structures
        // are the ones in place).
        let mut found = None;
        for n in (0..32u8).filter(|n| pi >> n & 1 != 0) {
            let p = Port { r: &r, base: PORT_BASE + n as usize * PORT_STRIDE };
            if probe_port(&p, cl_pa, &b) {
                found = Some(n);
                break;
            }
        }
        let Some(port) = found else {
            free_page(cl_pa);
            for &pa in &bounce_pa {
                free_page(pa);
            }
            return Err(AhciError::NoDisk);
        };
        let mut me = Ahci {
            r,
            pbase: PORT_BASE + port as usize * PORT_STRIDE,
            port,
            cap,
            b,
            sectors: 0,
            flush_ext: false,
            irq,
            cl_va,
            cl_pa,
            bounce_va,
            bounce_pa,
            lock: Mutex::new(()),
            busy: AtomicBool::new(false),
            inflight: AtomicBool::new(false),
            reported: AtomicBool::new(false),
            op: AtomicU8::new(OP_DATA),
            bytes: AtomicU32::new(0),
            deadline: AtomicU64::new(0),
            credit: AtomicU64::new(0),
            started: AtomicU64::new(0),
            lba: AtomicU64::new(0),
            recovery: Recovery::new(Class::Block, "ahci", b.resets),
            events: AtomicU32::new(0),
            stall: StallClock::new(),
            waiter: DeviceWait::new(),
            hooks: AtomicPtr::new(core::ptr::null_mut()),
            taken: AtomicU32::new(0),
            slept: AtomicU32::new(0),
        };
        match me.start_port() {
            Ok(id) => {
                me.sectors = id.sectors;
                me.flush_ext = id.flush_ext;
                Ok(me)
            }
            Err(e) => {
                me.teardown();
                Err(e)
            }
        }
    }

    /// Start the probed port (its command list and FIS area are in place),
    /// identify the disk, and turn the interrupts on. Bring-up, and the
    /// reset after a timeout.
    fn start_port(&self) -> Result<Ident, AhciError> {
        let p = self.port_regs();
        p.wr(P_SERR, 0xFFFF_FFFF);
        p.wr(P_IS, 0xFFFF_FFFF);
        self.r.wr32(REG_IS, 1 << self.port);
        if !p.start(self.cap, &self.b) {
            return Err(AhciError::Port("start"));
        }

        // IDENTIFY DEVICE: 512 bytes into the first staging page.
        self.exec_polled(&identify_fis(), SECTOR_SIZE, self.b.identify_us)?;
        let mut words = [0u16; 256];
        // SAFETY: the first staging page, which the HBA has finished with
        // (the command completed); 512 bytes of it were written.
        unsafe {
            for (i, w) in words.iter_mut().enumerate() {
                *w = core::ptr::read_volatile((self.bounce_va[0] + 2 * i) as *const u16);
            }
        }
        let id = decode_identify(&words)?;

        let mut model = [0u8; 40];
        let n = model_string(&words, &mut model);
        azos_drv_sys::kprintln!(
            "[AHCI] port {} {}: {} sectors mode={} xfer={} KiB flush={}",
            self.port,
            core::str::from_utf8(&model[..n]).unwrap_or("?"),
            id.sectors,
            if self.irq { "irq" } else { "poll" },
            XFER_SECTORS * SECTOR_SIZE / 1024,
            if id.flush_ext { "y" } else { "n" }
        );

        // Interrupts last: nothing was left pending by the polled commands.
        let p = self.port_regs();
        p.wr(P_IS, 0xFFFF_FFFF);
        self.r.wr32(REG_IS, 1 << self.port);
        if self.irq {
            p.wr(P_IE, IE_MASK);
            self.r.wr32(REG_GHC, GHC_AE | GHC_IE);
        }
        Ok(id)
    }

    /// A failed bring-up: stop the port and the HBA's DMA, give the pages back.
    fn teardown(&mut self) {
        let p = self.port_regs();
        let _ = p.stop(&self.b);
        self.r.wr32(REG_GHC, GHC_AE | GHC_HR);
        let _ = wait_for(self.b.reset_us, || self.r.rd32(REG_GHC) & GHC_HR == 0);
        free_page(self.cl_pa);
        for &pa in &self.bounce_pa {
            free_page(pa);
        }
    }

    /// Run one command of bring-up to completion, polling, bounded. `bytes`
    /// of the first staging page are read by the host.
    fn exec_polled(&self, fis: &[u8; 20], bytes: usize, timeout_us: u64) -> Result<(), AhciError> {
        self.build_command(fis, false, bytes);
        let p = self.port_regs();
        azos_dma::order::io_wmb();
        p.wr(P_CI, 1);
        let deadline = deadline_after_us(timeout_us);
        loop {
            if p.rd(P_IS) & IS_FATAL != 0 {
                return Err(AhciError::Identify("the port reported an error"));
            }
            if p.rd(P_CI) & 1 == 0 {
                fence(Ordering::Acquire);
                if p.rd(P_TFD) & (TFD_ERR | TFD_DF) != 0 {
                    return Err(AhciError::Identify("the disk refused the command"));
                }
                if get32(self.cl_va + CL_OFF + 4) as usize != bytes {
                    return Err(AhciError::Identify("short transfer"));
                }
                return Ok(());
            }
            if now() >= deadline {
                return Err(AhciError::Identify("timed out"));
            }
            core::hint::spin_loop();
        }
    }

    /// Write slot 0's command header and command table: the FIS, and a PRDT
    /// of `bytes` over the staging pages.
    fn build_command(&self, fis: &[u8; 20], write: bool, bytes: usize) {
        let ct = self.cl_va + CT_OFF;
        let ct_pa = self.cl_pa + CT_OFF as u64;
        // The command FIS, 20 bytes as five dwords; the rest of the 64-byte
        // CFIS area and the ATAPI command area are zero.
        for i in 0..(CT_PRDT / 4) {
            let v = if i < 5 { u32::from_le_bytes([fis[4 * i], fis[4 * i + 1], fis[4 * i + 2], fis[4 * i + 3]]) } else { 0 };
            put32(ct + 4 * i, v);
        }
        let n = bytes.div_ceil(PAGE);
        for i in 0..n {
            let len = (bytes - i * PAGE).min(PAGE);
            let e = prd_entry(self.bounce_pa[i], len);
            for (j, d) in e.iter().enumerate() {
                put32(ct + CT_PRDT + i * PRD_BYTES + 4 * j, *d);
            }
        }
        let h = cmd_header(write, n, ct_pa);
        for (j, d) in h.iter().enumerate() {
            put32(self.cl_va + CL_OFF + 4 * j, *d);
        }
        self.bytes.store(bytes as u32, Ordering::Relaxed);
    }

    // ---- Events ----

    /// Read and clear the port's pending interrupt causes (write-1-to-clear:
    /// a cause raised between the read and the write stays pending), and the
    /// HBA's summary bit for the port; remember what was read. Idempotent
    /// across two callers racing on the same bits. Takes no lock.
    fn harvest(&self) -> u32 {
        let p = self.port_regs();
        let is = p.rd(P_IS);
        if is != 0 {
            p.wr(P_IS, is);
            self.r.wr32(REG_IS, 1 << self.port);
            self.events.fetch_or(is, Ordering::AcqRel);
        }
        is
    }

    fn take_events(&self) -> u32 {
        self.harvest();
        self.events.swap(0, Ordering::AcqRel)
    }

    /// The HBA's interrupt (interrupt context, any CPU): record the causes,
    /// which quiets the line, and wake the sleeping waiter; `true` when there
    /// was one.
    pub fn irq(&self) -> bool {
        self.harvest();
        self.taken.fetch_add(1, Ordering::Relaxed);
        let tid = self.waiter.sleeper();
        if tid == 0 {
            return false;
        }
        match self.hooks() {
            Some(h) => {
                (h.wake)(tid);
                true
            }
            None => false,
        }
    }

    fn hooks(&self) -> Option<&'static Hooks> {
        // SAFETY: only `set_hooks` stores here, and it stores a `&'static Hooks`.
        unsafe { self.hooks.load(Ordering::Acquire).as_ref() }
    }

    /// Let waiters sleep instead of spin: call once the scheduler exists. A
    /// no-op for the sleeping where the HBA has no MSI route.
    pub fn set_hooks(&self, hooks: &'static Hooks) {
        self.hooks.store(hooks as *const Hooks as *mut Hooks, Ordering::Release);
    }

    /// Completions are taken by interrupt and waiters may sleep.
    pub fn irq_mode(&self) -> bool {
        self.irq && self.hooks().is_some()
    }

    /// `(interrupts taken, waits that slept)`.
    pub fn irq_counts(&self) -> (u32, u32) {
        (self.taken.load(Ordering::Relaxed), self.slept.load(Ordering::Relaxed))
    }

    pub fn sectors(&self) -> u64 {
        self.sectors
    }

    /// The driver is latched dead.
    pub fn is_dead(&self) -> bool {
        self.recovery.dead()
    }

    /// Resets the timeout policy has done since bring-up.
    pub fn resets(&self) -> u8 {
        self.recovery.resets()
    }

    /// Tell [`StallClock`] the guest is looking at the HBA now; says so once
    /// per stall. Returns the timebase tick it read.
    fn watch(&self) -> u64 {
        let t = now();
        let credited = self.stall.observe(t, STALL_GAP_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000);
        if credited != 0 {
            azos_drv_sys::kprintln!(
                "[AHCI] guest did not run for {} ms: command budgets extended by that time",
                credited * 1000 / azos_drv_sys::timebase::TIMER_FREQ
            );
        }
        t
    }

    // ---- Failure ----

    /// Reset the HBA: stop the port's engines and set `GHC.HR`, which stops
    /// its DMA on every port. `true` once the HBA says the reset is over.
    fn reset_hba(&self) -> bool {
        let p = self.port_regs();
        p.wr(P_CMD, p.rd(P_CMD) & !(CMD_ST | CMD_FRE));
        self.r.wr32(REG_GHC, GHC_AE | GHC_HR);
        wait_for(self.b.reset_us, || self.r.rd32(REG_GHC) & GHC_HR == 0)
    }

    /// Reset the HBA and latch the driver dead. The staging pages stay owned
    /// by the driver and are never reused. `latched`: the caller already
    /// moved the policy to dead (a timeout with the resets spent).
    fn latch_dead(&self, reason: &str, latched: bool) {
        if !latched && !self.recovery.latch() {
            return;
        }
        let _ = self.reset_hba();
        azos_drv_sys::kerr!("[AHCI] Error: {} - controller reset, block I/O disabled", reason);
    }

    /// The command ran out of its budget and the policy handed this caller
    /// the reset: reset the HBA, bring the port up again over the same
    /// memory, and check it is the same disk. The command is over (the reset
    /// stopped the engine): the caller answers `Timeout` for it.
    fn reset_after_timeout(&self) -> bool {
        azos_drv_sys::kerr!("[AHCI] port {}: command timed out: resetting the HBA", self.port);
        if !self.reset_hba() {
            azos_drv_sys::kerr!("[AHCI] the HBA reset did not complete");
            return false;
        }
        self.r.wr32(REG_GHC, GHC_AE);
        if !probe_port(&self.port_regs(), self.cl_pa, &self.b) {
            azos_drv_sys::kerr!("[AHCI] port {}: no disk after the reset", self.port);
            return false;
        }
        match self.start_port() {
            Ok(id) if id.sectors == self.sectors && id.flush_ext == self.flush_ext => {
                self.events.store(0, Ordering::Release);
                azos_drv_sys::kprintln!("[AHCI] port {}: reset done, the disk is back", self.port);
                true
            }
            Ok(id) => {
                azos_drv_sys::kerr!("[AHCI] port {}: a different disk after the reset ({} sectors, was {})",
                    self.port, id.sectors, self.sectors);
                false
            }
            Err(_) => false,
        }
    }

    /// After a fatal port error (AHCI 1.3 section 6.2.2.1): stop the command
    /// engine (which drops the commands the HBA held), clear the error and
    /// interrupt status, and start again. `false`: the port did not come back
    /// (the caller latches the driver dead).
    fn restart_port(&self) -> bool {
        let p = self.port_regs();
        if !p.stop(&self.b) {
            return false;
        }
        p.wr(P_SERR, 0xFFFF_FFFF);
        p.wr(P_IS, 0xFFFF_FFFF);
        self.r.wr32(REG_IS, 1 << self.port);
        self.events.store(0, Ordering::Release);
        p.start(self.cap, &self.b)
    }

    /// The outcome of the command in slot 0, if it has one. Caller holds `lock`.
    fn outcome(&self, op: u8) -> Option<HwStatus> {
        if op == OP_NO_FLUSH {
            return Some(HwStatus::Unsupported);
        }
        let ev = self.take_events();
        let t = self.watch();
        if !self.recovery.live() {
            // The device died with this command in it: no data to trust.
            return Some(HwStatus::Io);
        }
        let p = self.port_regs();
        let ci = p.rd(P_CI);
        let tfd = p.rd(P_TFD);
        if ev & IS_FATAL != 0 {
            let aborted = op == OP_FLUSH && (tfd >> 8) & ATA_ERR_ABRT != 0 && ev & IS_TFES != 0;
            if !aborted {
                azos_drv_sys::kerr!("[AHCI] port {}: error interrupt {:#010x}, task file {:#06x}: command failed, port restarted",
                    self.port, ev & IS_FATAL, tfd & 0xFFFF);
            }
            if !self.restart_port() {
                self.latch_dead("port restart failed", false);
            }
            return Some(if aborted { HwStatus::Unsupported } else { HwStatus::Io });
        }
        if ci & 1 == 0 {
            fence(Ordering::Acquire);
            if tfd & (TFD_ERR | TFD_DF) != 0 {
                azos_drv_sys::kerr!("[AHCI] port {}: command ended with task file {:#06x}", self.port, tfd & 0xFFFF);
                return Some(if op == OP_FLUSH && (tfd >> 8) & ATA_ERR_ABRT != 0 { HwStatus::Unsupported } else { HwStatus::Io });
            }
            let moved = get32(self.cl_va + CL_OFF + 4);
            if moved != self.bytes.load(Ordering::Relaxed) {
                azos_drv_sys::kerr!("[AHCI] port {}: {} of {} bytes moved", self.port, moved, self.bytes.load(Ordering::Relaxed));
                return Some(HwStatus::Io);
            }
            return Some(HwStatus::Ok);
        }
        if self.stall.expired(t, self.deadline.load(Ordering::Relaxed), self.credit.load(Ordering::Relaxed)) {
            return Some(HwStatus::Timeout);
        }
        None
    }

    /// The command in slot 0 ran out of its budget (`waited`: ticks since it
    /// was started): the timeout policy resets the HBA once, then latches it
    /// dead. Runs with `lock` NOT held (the reset spins), after the outcome
    /// was marked reported, so no other reaper looks at the slot meanwhile.
    fn timed_out(&self, waited: u64) {
        let ms = waited.saturating_mul(1000) / azos_drv_sys::timebase::TIMER_FREQ.max(1);
        let lba = self.lba.load(Ordering::Relaxed);
        match self.recovery.timed_out(lba, ms) {
            Verdict::Reset => {
                let ok = self.reset_after_timeout();
                if !ok {
                    // The engine is stopped or the HBA is held in reset; the
                    // pages stay quarantined all the same.
                    let _ = self.reset_hba();
                    azos_drv_sys::kerr!("[AHCI] Error: reset did not bring the disk back - block I/O disabled");
                }
                self.recovery.reset_done(ok, lba, ms);
            }
            Verdict::Latch => self.latch_dead("command timeout, resets spent", true),
            Verdict::Handled => {}
        }
    }
}

/// The firmware may still own the HBA (BIOS/OS Handoff, section 10.6.3):
/// ask for it and wait for the firmware to let go.
fn bios_handoff<R: Regs>(r: &R, b: &Budgets) -> Result<(), AhciError> {
    if r.rd32(REG_CAP2) & CAP2_BOH == 0 || r.rd32(REG_BOHC) & BOHC_BOS == 0 {
        return Ok(());
    }
    r.wr32(REG_BOHC, r.rd32(REG_BOHC) | BOHC_OOS);
    if wait_for(b.handoff_us, || r.rd32(REG_BOHC) & (BOHC_BOS | BOHC_BB) == 0) {
        Ok(())
    } else {
        Err(AhciError::Handoff)
    }
}

/// Is there an ATA disk on this port, ready? Stops the port, points it at the
/// command list and FIS area at `cl_pa` (AHCI 1.3 section 10.1.2: the order
/// is the structures, then the FIS receiver, then the device), powers and
/// spins it up, waits for the link (a port that shows nothing for
/// `absent_us` has nothing) and for the device to leave BSY and send its
/// signature. Leaves the port stopped, with the FIS receiver on when it
/// found a disk.
fn probe_port<R: Regs>(p: &Port<'_, R>, cl_pa: u64, b: &Budgets) -> bool {
    if !p.stop(b) {
        return false;
    }
    let found = probe_stopped_port(p, cl_pa, b);
    if !found {
        // Quiet again: no FIS receiver writing into memory that goes back.
        let _ = p.stop(b);
    }
    found
}

fn probe_stopped_port<R: Regs>(p: &Port<'_, R>, cl_pa: u64, b: &Budgets) -> bool {
    let clb = cl_pa + CL_OFF as u64;
    let fb = cl_pa + FB_OFF as u64;
    p.wr(P_CLB, clb as u32);
    p.wr(P_CLBU, (clb >> 32) as u32);
    p.wr(P_FB, fb as u32);
    p.wr(P_FBU, (fb >> 32) as u32);
    p.wr(P_SERR, 0xFFFF_FFFF);
    let cmd = p.rd(P_CMD);
    // Power on (where a cold presence detect says the slot is powered by us),
    // spin up (staggered spin-up holds the device until this), and receive
    // FISes, so the signature has somewhere to land.
    p.wr(P_CMD, cmd | CMD_SUD | CMD_FRE | if cmd & CMD_CPD != 0 { CMD_POD } else { 0 });
    // Device present, PHY up, interface active.
    let live = || p.rd(P_SSTS) & (SSTS_DET_MASK | SSTS_IPM_MASK) == SSTS_DET_PRESENT | SSTS_IPM_ACTIVE;
    let start = now();
    let absent_ticks = b.absent_us.saturating_mul(azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000;
    // Nothing (or an offline device) for `absent_us` is an empty port; a
    // device detected without a link yet is given the whole `link_us`.
    if !wait_for(b.link_us, || {
        live() || (p.rd(P_SSTS) & SSTS_DET_MASK != SSTS_DET_DETECTED && now().saturating_sub(start) >= absent_ticks)
    }) || !live()
    {
        return false;
    }
    // A device that is still in its power-on reset reads BSY and a signature
    // not yet sent.
    wait_for(b.ready_us, || p.rd(P_TFD) & (TFD_BSY | TFD_DRQ) == 0 && p.rd(P_SIG) != SIG_UNSET)
        && p.rd(P_SIG) == SIG_ATA
}

impl<R: Regs + Sync> HwQueue for Ahci<R> {
    fn caps(&self) -> HwCaps {
        HwCaps {
            sectors: self.sectors,
            max_sectors: XFER_SECTORS as u32,
            // No TRIM, no FUA (SATA has it only inside NCQ): the layer
            // refuses a discard and orders writes with a flush.
            max_discard_sectors: 0,
            fua: false,
        }
    }

    fn cpu(&self) -> usize {
        azos_arch::Cpu::hart_id(&azos_arch::ARCH)
    }

    fn claim(&self) -> Claim {
        if self.recovery.dead() {
            return Claim::Dead;
        }
        if self.recovery.resetting() {
            return Claim::Busy;
        }
        if self.busy.swap(true, Ordering::AcqRel) {
            Claim::Busy
        } else {
            Claim::Tag(0)
        }
    }

    fn start(&self, tag: u8, cmd: &HwCmd<'_>) -> Result<(), ()> {
        if tag != 0 || !self.recovery.live() {
            return Err(());
        }
        let (fis, write, bytes, op, budget) = match cmd.op {
            HwOp::Read | HwOp::Write => {
                let bytes = cmd.sectors as usize * SECTOR_SIZE;
                let write = cmd.op == HwOp::Write;
                if cmd.sectors == 0
                    || cmd.sectors as usize > XFER_SECTORS
                    || cmd.lba.checked_add(cmd.sectors as u64).is_none_or(|end| end > self.sectors)
                    || (write && cmd.segs.iter().map(|s| s.len()).sum::<usize>() != bytes)
                {
                    return Err(());
                }
                if write {
                    let mut off = 0;
                    for s in cmd.segs {
                        self.stage_in(off, s);
                        off += s.len();
                    }
                }
                let c = if write { ATA_WRITE_DMA_EXT } else { ATA_READ_DMA_EXT };
                (h2d_fis(c, cmd.lba, cmd.sectors), write, bytes, OP_DATA, self.b.io_us)
            }
            HwOp::Flush if self.flush_ext => (h2d_fis(ATA_FLUSH_CACHE_EXT, 0, 0), false, 0, OP_FLUSH, self.b.flush_us),
            HwOp::Flush => ([0; 20], false, 0, OP_NO_FLUSH, 0),
            HwOp::Discard => return Err(()),
        };
        if op != OP_NO_FLUSH {
            self.build_command(&fis, write, bytes);
        }
        // The look before the credit is read: the baseline already holds any
        // stall that ended just now.
        self.watch();
        self.credit.store(self.stall.credit(), Ordering::Relaxed);
        self.deadline.store(deadline_after_us(budget), Ordering::Relaxed);
        self.lba.store(cmd.lba, Ordering::Relaxed);
        self.started.store(now(), Ordering::Relaxed);
        let _g = self.lock.lock();
        if !self.recovery.live() {
            return Err(());
        }
        // Whatever the port said before this command is not about it.
        self.harvest();
        self.events.store(0, Ordering::Release);
        self.op.store(op, Ordering::Relaxed);
        self.reported.store(false, Ordering::Relaxed);
        self.inflight.store(true, Ordering::Release);
        if op != OP_NO_FLUSH {
            azos_dma::order::io_wmb();
            self.port_regs().wr(P_CI, 1);
        }
        Ok(())
    }

    fn reap(&self, out: &mut [HwDone; HW_TAGS_MAX]) -> usize {
        if !self.inflight.load(Ordering::Acquire) || self.reported.load(Ordering::Acquire) {
            return 0;
        }
        let g = self.lock.lock();
        if !self.inflight.load(Ordering::Relaxed) || self.reported.load(Ordering::Relaxed) {
            return 0;
        }
        let Some(status) = self.outcome(self.op.load(Ordering::Relaxed)) else {
            return 0;
        };
        self.reported.store(true, Ordering::Release);
        drop(g);
        if status == HwStatus::Timeout {
            // Reset (or latch) before the layer hears of it: the slot it is
            // about to release must not be claimed while the HBA is reset.
            self.timed_out(now().saturating_sub(self.started.load(Ordering::Relaxed)));
        }
        out[0] = HwDone { tag: 0, status };
        1
    }

    fn copy_out(&self, tag: u8, mut off: usize, dst: &mut [u8]) {
        debug_assert_eq!(tag, 0);
        let mut done = 0;
        while done < dst.len() {
            let n = (dst.len() - done).min(PAGE - off % PAGE);
            // SAFETY: the HBA finished the command, so it is done with the
            // pages; the slot is still the caller's until `release`.
            // `off + dst.len()` is inside the command's data.
            unsafe {
                let src = (self.bounce_va[off / PAGE] + off % PAGE) as *const u8;
                core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(done), n);
            }
            done += n;
            off += n;
        }
    }

    fn release(&self, _tag: u8) {
        self.inflight.store(false, Ordering::Release);
        // A dead driver answers `Dead` to every claim, so the slot is not
        // reused (a command the HBA could not recall may still be writing to
        // the staging pages). After a reset that brought the disk back the
        // HBA's engine was stopped, so it writes to none of them.
        self.busy.store(false, Ordering::Release);
    }

    fn wait(&self, until_ns: u64) -> bool {
        if !self.irq {
            return false;
        }
        let Some(h) = self.hooks() else { return false };
        let tid = (h.tid)();
        if tid == 0 || tid == u32::MAX {
            return false;
        }
        // Re-check after listing the waiter: a completion whose interrupt
        // came before the listing woke nobody.
        self.waiter.park(
            tid,
            || {
                let p = self.port_regs();
                !self.recovery.live()
                    || self.events.load(Ordering::Acquire) != 0
                    || p.rd(P_IS) != 0
                    || (self.inflight.load(Ordering::Acquire) && p.rd(P_CI) & 1 == 0)
            },
            || {
                let s = (h.block_until)(ns_to_ticks(until_ns));
                if s {
                    self.slept.fetch_add(1, Ordering::Relaxed);
                }
                s
            },
        )
    }
}

impl<R: Regs> Ahci<R> {
    /// Copy `src` into the staging pages from byte `off`.
    fn stage_in(&self, mut off: usize, src: &[u8]) {
        let mut done = 0;
        while done < src.len() {
            let n = (src.len() - done).min(PAGE - off % PAGE);
            // SAFETY: slot 0 is this caller's, its previous command (if any)
            // completed, and `off + src.len() <= XFER_PAGES * PAGE` (checked
            // by `start`).
            unsafe {
                let dst = (self.bounce_va[off / PAGE] + off % PAGE) as *mut u8;
                core::ptr::copy_nonoverlapping(src.as_ptr().add(done), dst, n);
            }
            done += n;
            off += n;
        }
    }
}

// ---- The kernel's controller ----
//
// Only with the cargo feature `ahci` (the host test pulls this file in
// without it and builds its own `Ahci` over a model).

/// The one controller: written once by [`attach`], read by the interrupt arm.
#[cfg(feature = "ahci")]
static mut CONTROLLER: core::mem::MaybeUninit<Ahci<Hw>> = core::mem::MaybeUninit::uninit();
#[cfg(feature = "ahci")]
static CLAIMED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "ahci")]
static UP: AtomicBool = AtomicBool::new(false);
/// The MSI token the kernel's interrupt path passes to [`msi_irq`] for the
/// controller's vector (`u32::MAX`: none, polled).
#[cfg(feature = "ahci")]
static TOKEN: AtomicU32 = AtomicU32::new(u32::MAX);

/// Bring the HBA at `abar` (the mapped BAR 5) up as the boot block device.
/// Call after PCI enumeration, before `blkdev::init`. `dma_mask` is the
/// highest physical address the controller's DMA reaches (the hardware bus's
/// record of the device, `u64::MAX` for none); `msi_token` the number the
/// interrupt path will pass to [`msi_irq`] for the controller's MSI, `None`
/// where the machine routes none (the controller is polled).
#[cfg(feature = "ahci")]
pub fn attach(abar: usize, dma_mask: u64, msi_token: Option<u32>) -> Result<(), AhciError> {
    if crate::queue::bound().is_some() || CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(AhciError::Taken);
    }
    // Before the HBA can interrupt: the arm that recognises its token.
    TOKEN.store(msi_token.unwrap_or(u32::MAX), Ordering::Release);
    match Ahci::attach(Hw(abar), dma_mask, msi_token.is_some(), Budgets::DEFAULT) {
        Ok(a) => {
            // SAFETY: `CLAIMED` makes this the only write, and `UP` is
            // published after it; every reader checks `UP` first.
            let c: &'static Ahci<Hw> = unsafe { (*(&raw mut CONTROLLER)).write(a) };
            UP.store(true, Ordering::Release);
            // From here `blkdev` reads, writes and flushes are requests on this disk.
            crate::queue::bind(c);
            Ok(())
        }
        Err(e) => {
            TOKEN.store(u32::MAX, Ordering::Release);
            CLAIMED.store(false, Ordering::Release);
            Err(e)
        }
    }
}

#[cfg(feature = "ahci")]
fn controller() -> Option<&'static Ahci<Hw>> {
    if !UP.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: `UP` is set after `CONTROLLER` was written, and it is never written again.
    Some(unsafe { (*(&raw const CONTROLLER)).assume_init_ref() })
}

/// `true` once a disk is up and `blkdev` routes block I/O here.
#[cfg(feature = "ahci")]
pub fn active() -> bool {
    UP.load(Ordering::Acquire)
}

/// Let the waiters sleep: call once the scheduler exists. A no-op without a
/// controller.
#[cfg(feature = "ahci")]
pub fn set_irq_hooks(hooks: &'static Hooks) {
    if let Some(c) = controller() {
        c.set_hooks(hooks);
    }
}

/// `true` once completions are taken by interrupt and waiters may sleep.
#[cfg(feature = "ahci")]
pub fn irq_mode() -> bool {
    controller().is_some_and(|c| c.irq_mode())
}

/// `(interrupts taken, waits that slept)`.
#[cfg(feature = "ahci")]
pub fn irq_counts() -> (u32, u32) {
    controller().map_or((0, 0), |c| c.irq_counts())
}

/// The interrupt handler's arm for an MSI of the kernel's `token` (interrupt
/// context, any CPU): `None` when it is not this controller's; otherwise
/// record the causes and wake the sleeping waiter, `Some(true)` when there
/// was one. An MSI needs no acknowledge at the device beyond what
/// [`Ahci::irq`] does.
#[cfg(feature = "ahci")]
pub fn msi_irq(token: u32) -> Option<bool> {
    if token != TOKEN.load(Ordering::Acquire) {
        return None;
    }
    Some(controller()?.irq())
}
