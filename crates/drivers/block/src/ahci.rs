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
//!   and the internal command (its table and a 512-byte buffer) share one
//!   page. IDENTIFY DEVICE (polled, bounded, through the internal command)
//!   says whether the disk is driveable (LBA48, 512-byte logical sectors)
//!   and how deep it queues; only then are the command slots' tables and
//!   staging pages taken, for as many slots as will be used.
//! * **Command slots.** With native command queuing (the HBA's `CAP.SNCQ`,
//!   IDENTIFY word 76 bit 8) the depth is the smallest of the disk's queue
//!   depth (word 75), the HBA's slots (`CAP.NCS`) and Kconfig
//!   `AHCI_NCQ_DEPTH`; reads and writes are READ/WRITE FPDMA QUEUED, as many
//!   in the device at once as there are slots, each slot with its own
//!   command table and staging pages. Without it (or a depth of 1) slot 0 is
//!   the only one and the commands are READ/WRITE DMA EXT. [`HwQueue::claim`]
//!   answers `Busy` when every slot is held, and the request layer keeps the
//!   rest queued.
//! * **Issue order.** A command is issued in the order it was started. A
//!   command that is not queued (FLUSH CACHE EXT, and every command without
//!   NCQ) may not be issued while queued ones are in the device, nor a queued
//!   one while it is: [`HwQueue::start`] arms it, and it is issued once the
//!   queued commands ahead of it are over; the queued commands started after
//!   it wait for it. Its budget starts when it is issued, not when it was
//!   armed.
//! * **Staging.** The device is never handed caller memory (a command cannot
//!   be recalled, and a caller buffer is often a popped stack frame). A
//!   write's segments are copied into the slot's staging pages at `start`, a
//!   read's data out of them at `copy_out`. The command table's PRDT names
//!   one entry per page, so the pages need not be contiguous. Every page
//!   comes from the page allocator below the controller's DMA limit
//!   (`azos_dma`): the caller's mask, narrowed to 4 GiB when `CAP.S64A` says
//!   the HBA has no 64-bit addressing.
//! * **Completion.** A queued command is done when the disk's Set Device
//!   Bits FIS cleared its `PxSACT` bit, any other when its `PxCI` bit is
//!   clear. By MSI where the machine routes one: [`Ahci::irq`] reads and
//!   clears `PxIS`/`IS`, remembers the bits and wakes the one task the
//!   request layer lets sleep in the device ([`HwQueue::wait`], a
//!   [`DeviceWait`]). Without a route, or before the scheduler exists, the
//!   layer spins and `reap` reads the registers. Legacy INTx is not routed
//!   (no PCI driver in this tree has an INTx pin to interrupt line route
//!   yet).
//! * **Errors.** A fatal port interrupt (task file error, host bus or
//!   interface error) restarts the port (AHCI 1.3 section 6.2.2.1: stop,
//!   clear `PxSERR` and `PxIS`, start), which abandons the commands the HBA
//!   held. A task file error with queued commands in the device is an NCQ
//!   error: the disk answers nothing but READ LOG EXT of the NCQ Command
//!   Error log (page 10h) until that log is read, and the log names the
//!   failed tag. That command fails; the queued commands the error stopped
//!   are issued again from their own slots (their staging still holds a
//!   write's data), once each. Any other error fails the commands it
//!   abandoned, and the disk stays usable. An aborted FLUSH CACHE EXT is
//!   "this disk has no flush" ([`HwStatus::Unsupported`]), as for NVMe.
//! * **Timeouts.** A command that misses its budget (or the NCQ error log's
//!   READ LOG EXT that does) resets the HBA (`GHC.HR`, which stops its DMA
//!   on every port) and brings the port up again, once per boot (Kconfig
//!   `DEVICE_TIMEOUT_RESETS`, `azos_drv_api::recovery`), if the same disk
//!   (the whole IDENTIFY record the driver keeps) answers IDENTIFY again:
//!   the late command ends [`HwStatus::Timeout`], every other command the
//!   device held [`HwStatus::Reset`] (not issued again), and the commands
//!   still waiting to be issued are issued after the reset. A second
//!   timeout, a reset that does not bring the disk back, or a port that will
//!   not restart latches the driver dead until reboot: no disk beats
//!   silently wrong disk. The staging pages are then never reused (a command
//!   the HBA could not recall may still be writing to them).
//! * **Budgets** are time the guest ran ([`StallClock`]): a guest the host
//!   stopped for a second does not find its disk dead.
//! * **FUA.** Where IDENTIFY says the disk has it (word 84 bit 6, the WRITE
//!   DMA FUA EXT bit, as Linux's `ata_id_has_fua`), [`HwCaps::fua`] is set
//!   and a write that asks for it is stable when it completes: the FUA bit
//!   of WRITE FPDMA QUEUED (the Device register's bit 7) with NCQ, WRITE DMA
//!   FUA EXT without. Elsewhere the layer refuses a FUA request and its
//!   callers order their writes with a flush (`blkdev::fua_commit`).
//! * **TRIM.** Where IDENTIFY says the disk has it (word 169 bit 0, on a disk
//!   of ATA8-ACS or later, as Linux's `ata_id_has_trim`), a discard is DATA
//!   SET MANAGEMENT with the TRIM bit: one 512-byte block of up to 64 LBA
//!   range entries ([`TRIM_MAX_SECTORS`] a command), staged in the slot's
//!   first page. It is not queued (SEND FPDMA QUEUED is not used: Linux
//!   keeps a list of disks whose queued TRIM is broken, and it would need
//!   the NCQ Send and Receive log read first), so it waits for the queue to
//!   drain as a flush does. A disk that aborts it has no TRIM after all
//!   ([`HwStatus::Unsupported`]: FAT32 stops asking until the next mount).
//!
//! DMA coherence is assumed (the PCs this driver is for), as for NVMe.

use crate::queue::{Claim, HwCaps, HwCmd, HwDone, HwOp, HwQueue, HwStatus, HW_TAGS_MAX};
use azos_drv_api::block::{DeviceWait, StallClock, STALL_GAP_US, STALL_SAY_EVERY_US};
use azos_drv_api::recovery::{Class, Recovery, Verdict};
use azos_sync::kmutex::Mutex;
#[cfg(feature = "ahci")]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{fence, AtomicPtr, AtomicU32, Ordering};

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

/// `CAP.NCS`: command slots minus one, bits 12:8.
const CAP_NCS_SHIFT: u32 = 8;
const CAP_NCS_MASK: u32 = 0x1F;
const CAP_SCLO: u32 = 1 << 24;
const CAP_SNCQ: u32 = 1 << 30;
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
const P_SACT: usize = 0x34;
const P_CI: usize = 0x38;

const CMD_ST: u32 = 1 << 0;
const CMD_SUD: u32 = 1 << 1;
const CMD_POD: u32 = 1 << 2;
const CMD_CLO: u32 = 1 << 3;
const CMD_FRE: u32 = 1 << 4;
const CMD_FR: u32 = 1 << 14;
const CMD_CR: u32 = 1 << 15;
const CMD_CPD: u32 = 1 << 20;

/// `PxIS`: a D2H register FIS arrived (the end of a non-data or DMA
/// command), a PIO Setup FIS (the data of IDENTIFY and READ LOG EXT), a Set
/// Device Bits FIS (the end of queued commands).
const IS_DHRS: u32 = 1 << 0;
const IS_PSS: u32 = 1 << 1;
const IS_SDBS: u32 = 1 << 3;
const IS_IFS: u32 = 1 << 27;
const IS_HBDS: u32 = 1 << 28;
const IS_HBFS: u32 = 1 << 29;
const IS_TFES: u32 = 1 << 30;
/// The errors that stop the port's command engine (section 6.2.2): the
/// commands are failed or issued again, and the port restarted.
const IS_FATAL: u32 = IS_TFES | IS_HBFS | IS_HBDS | IS_IFS;
/// What the port is allowed to interrupt for.
const IE_MASK: u32 = IS_DHRS | IS_PSS | IS_SDBS | IS_FATAL;

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
const ATA_DATA_SET_MANAGEMENT: u8 = 0x06;
/// DATA SET MANAGEMENT's Features: the TRIM bit.
const DSM_TRIM: u8 = 0x01;
const ATA_READ_DMA_EXT: u8 = 0x25;
const ATA_READ_LOG_EXT: u8 = 0x2F;
const ATA_WRITE_DMA_EXT: u8 = 0x35;
const ATA_WRITE_DMA_FUA_EXT: u8 = 0x3D;
const ATA_READ_FPDMA_QUEUED: u8 = 0x60;
const ATA_WRITE_FPDMA_QUEUED: u8 = 0x61;
const ATA_FLUSH_CACHE_EXT: u8 = 0xEA;
/// Device register of a command in LBA mode, and the FUA bit of WRITE FPDMA
/// QUEUED's.
const ATA_DEVICE_LBA: u8 = 0x40;
const ATA_DEVICE_FUA: u8 = 0x80;
/// The NCQ Command Error log (READ LOG EXT, log address 10h): byte 0 is the
/// NQ bit (7: the error was a non-queued command's) and the failed tag (4:0);
/// bytes 2 and 3 are its status and error.
const LOG_NCQ_ERROR: u8 = 0x10;
const NCQ_LOG_NQ: u8 = 0x80;
const NCQ_LOG_TAG: u8 = 0x1F;

pub const SECTOR_SIZE: usize = 512;
const PAGE: usize = 4096;

/// LBA range entries in one 512-byte DATA SET MANAGEMENT block (8 bytes
/// each: the 48-bit LBA, then a 16-bit sector count), and the sectors one
/// entry and one command cover. The driver sends one block a command, which
/// every disk with TRIM takes.
pub const TRIM_RANGES: usize = SECTOR_SIZE / 8;
pub const TRIM_RANGE_SECTORS: u32 = 0xFFFF;
pub const TRIM_MAX_SECTORS: u32 = TRIM_RANGES as u32 * TRIM_RANGE_SECTORS;

// ---- Memory layout ----

/// Bounce pages one command moves (Kconfig `AHCI_XFER_KB`).
pub const XFER_PAGES: usize = azos_limits::AHCI_XFER_KB as usize * 1024 / PAGE;
/// Sectors one command carries at most.
pub const XFER_SECTORS: usize = XFER_PAGES * PAGE / SECTOR_SIZE;
/// Command slots the driver uses at most (Kconfig `AHCI_NCQ_DEPTH`).
pub const MAX_SLOTS: usize = azos_limits::AHCI_NCQ_DEPTH as usize;

/// The first page: the command list (32 headers of 32 bytes, 1 KiB
/// aligned), the received-FIS area (256-byte aligned), the internal
/// command's table (one PRD; 128-byte aligned) and its 512-byte buffer, then
/// the first slots' command tables. A command table is the command FIS, then
/// the PRDT from `CT_PRDT`.
const CL_OFF: usize = 0;
const HDR_BYTES: usize = 32;
const FB_OFF: usize = 0x400;
const IT_OFF: usize = 0x500;
const IB_OFF: usize = 0x600;
const CT0_OFF: usize = 0x800;
const CT_PRDT: usize = 0x80;
const PRD_BYTES: usize = 16;
/// One slot's command table, and how many fit after `CT0_OFF` in the first
/// page and in each further page.
const CT_BYTES: usize = (CT_PRDT + XFER_PAGES * PRD_BYTES).next_multiple_of(128);
const CT_FIRST: usize = (PAGE - CT0_OFF) / CT_BYTES;
const CT_PER_PAGE: usize = PAGE / CT_BYTES;
/// Pages of command tables beyond the first page, for `MAX_SLOTS` slots.
const CT_PAGES: usize = ct_pages(MAX_SLOTS);
const _: () = assert!(XFER_PAGES >= 1 && CT_FIRST >= 1 && XFER_SECTORS <= 65536);
const _: () = assert!(IT_OFF + CT_PRDT + PRD_BYTES <= IB_OFF && IB_OFF + SECTOR_SIZE <= CT0_OFF);
const _: () = assert!(MAX_SLOTS >= 1 && MAX_SLOTS <= 32 && MAX_SLOTS <= HW_TAGS_MAX);

/// Pages of command tables beyond the first page that `slots` slots need.
const fn ct_pages(slots: usize) -> usize {
    if slots > CT_FIRST {
        (slots - CT_FIRST).div_ceil(CT_PER_PAGE)
    } else {
        0
    }
}

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

/// The H2D FIS of READ or WRITE FPDMA QUEUED: the sector count moves to the
/// Features bytes (FIS bytes 3 and 11; 65536 is 0) and the Count field
/// carries the NCQ tag in its bits 7:3 (byte 12). The tag is the command
/// slot: an AHCI HBA matches the disk's completion bits to slots by it.
/// `fua`: the Device register's bit 7, the write is on the medium when it
/// completes.
pub fn fpdma_fis(write: bool, lba: u64, count: u32, tag: u8, fua: bool) -> [u8; 20] {
    let mut f = h2d_fis(if write { ATA_WRITE_FPDMA_QUEUED } else { ATA_READ_FPDMA_QUEUED }, lba, 0);
    f[3] = count as u8;
    f[7] = ATA_DEVICE_LBA | if fua { ATA_DEVICE_FUA } else { 0 };
    f[11] = (count >> 8) as u8;
    f[12] = (tag & 0x1F) << 3;
    f[13] = 0;
    f
}

/// READ LOG EXT of `sectors` sectors of log `log`, page 0: the log address
/// is LBA 7:0 and the page LBA 15:8.
pub fn read_log_fis(log: u8, sectors: u32) -> [u8; 20] {
    h2d_fis(ATA_READ_LOG_EXT, log as u64, sectors)
}

/// DATA SET MANAGEMENT with the TRIM bit, one 512-byte block of ranges: the
/// TRIM bit in Features (byte 3), the blocks in Count, no LBA.
pub fn dsm_trim_fis() -> [u8; 20] {
    let mut f = h2d_fis(ATA_DATA_SET_MANAGEMENT, 0, 1);
    f[3] = DSM_TRIM;
    f
}

/// The range block that trims `sectors` sectors from `lba`: entries of at
/// most [`TRIM_RANGE_SECTORS`], little-endian, the rest of the block zero
/// (an entry of 0 sectors is ignored). `sectors <= TRIM_MAX_SECTORS`.
pub fn trim_ranges(lba: u64, sectors: u32, out: &mut [u8; SECTOR_SIZE]) {
    out.fill(0);
    let (mut at, mut left) = (lba, sectors);
    for e in out.chunks_exact_mut(8) {
        if left == 0 {
            break;
        }
        let n = left.min(TRIM_RANGE_SECTORS);
        e.copy_from_slice(&((at & 0xFFFF_FFFF_FFFF) | (n as u64) << 48).to_le_bytes());
        at += n as u64;
        left -= n;
    }
}

/// IDENTIFY DEVICE addresses no sector: its FIS carries no LBA, and the
/// device register is 0.
fn identify_fis() -> [u8; 20] {
    let mut f = h2d_fis(ATA_IDENTIFY, 0, 0);
    f[7] = 0;
    f
}

/// Command header as eight dwords: 5 FIS dwords, the write direction bit,
/// `prdtl` PRDT entries, and the table's bus address. PRDBC (dword 1)
/// starts at 0; the HBA counts into it.
pub fn cmd_header(write: bool, prdtl: usize, ctba: u64) -> [u32; 8] {
    [5 | (write as u32) << 6 | (prdtl as u32) << 16, 0, ctba as u32, (ctba >> 32) as u32, 0, 0, 0, 0]
}

/// One PRDT entry: the data base address, a reserved dword, and the byte
/// count minus one (22 bits; the interrupt-on-completion bit stays clear).
pub fn prd_entry(pa: u64, len: usize) -> [u32; 4] {
    [pa as u32, (pa >> 32) as u32, 0, (len as u32 - 1) & 0x3F_FFFF]
}

/// What IDENTIFY DEVICE says that the driver needs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ident {
    pub sectors: u64,
    /// The disk has FLUSH CACHE EXT.
    pub flush_ext: bool,
    /// Native command queuing: the queue depth the disk reports (1-32), 0
    /// for a disk without it.
    pub ncq_depth: u8,
    /// Force Unit Access writes (WRITE DMA FUA EXT, and the FUA bit of WRITE
    /// FPDMA QUEUED).
    pub fua: bool,
    /// DATA SET MANAGEMENT with the TRIM bit.
    pub trim: bool,
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
    // Word 76 (Serial ATA capabilities; 0 and FFFFh: not implemented), bit
    // 8: native command queuing, at the depth word 75 bits 4:0 hold minus one.
    let w76_valid = w[76] != 0 && w[76] != 0xFFFF;
    let ncq_depth = if w76_valid && w[76] & (1 << 8) != 0 { (w[75] & 0x1F) as u8 + 1 } else { 0 };
    // Word 84 (valid as word 83 is) bit 6: WRITE DMA FUA EXT. Linux takes it
    // as the disk's FUA for the FPDMA bit too (`ata_id_has_fua`); so does
    // this driver.
    let fua = w[84] & 0xC000 == 0x4000 && w[84] & (1 << 6) != 0;
    // Word 169 bit 0: TRIM, believed (as by Linux's `ata_id_has_trim`) on a
    // disk whose major version (word 80, its highest bit of 1-14; FFFFh is
    // not reported) is ATA8-ACS (7) or later.
    let major = if w[80] == 0xFFFF { 0 } else { (1..=14).rev().find(|b| w[80] >> b & 1 != 0).unwrap_or(0) };
    let trim = major >= 7 && w[169] & 1 != 0;
    Ok(Ident { sectors, flush_ext: w[83] & (1 << 13) != 0, ncq_depth, fua, trim })
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

/// The queue depth the driver uses: the disk's, the HBA's command slots
/// (`CAP.NCS`) and Kconfig `AHCI_NCQ_DEPTH`, whichever is smallest, when the
/// HBA and the disk both queue (`CAP.SNCQ`, IDENTIFY word 76 bit 8); 1 (one
/// command at a time, not queued) otherwise. A depth of 1 is not worth
/// queuing either.
pub fn queue_depth(cap: u32, id: &Ident) -> usize {
    let hba = ((cap >> CAP_NCS_SHIFT) & CAP_NCS_MASK) as usize + 1;
    if cap & CAP_SNCQ == 0 || id.ncq_depth == 0 {
        return 1;
    }
    (id.ncq_depth as usize).min(hba).min(MAX_SLOTS)
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
/// the guest ran ([`StallClock`]) from the moment the command is issued.
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
    /// IDENTIFY DEVICE, and the READ LOG EXT of an NCQ error.
    pub identify_us: u64,
    /// A read or a write. A spinning disk may retry a bad sector for seconds.
    pub io_us: u64,
    /// A flush writes the whole volatile cache back; a TRIM is given as long.
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

/// The slot numbers of the set bits of `mask`, lowest first.
fn bits(mut mask: u32) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        (mask != 0).then(|| {
            let k = mask.trailing_zeros() as usize;
            mask &= mask - 1;
            k
        })
    })
}

// ---- The driver ----

/// A started command: how it is issued (again) and how its end is read.
#[derive(Clone, Copy)]
struct Cmd {
    /// READ/WRITE FPDMA QUEUED, over when its `PxSACT` bit clears; else a
    /// command alone in the device, over when its `PxCI` bit clears.
    queued: bool,
    write: bool,
    /// FLUSH CACHE EXT or DATA SET MANAGEMENT (the one optional command
    /// that writes): an abort means the disk has no such command
    /// ([`HwStatus::Unsupported`]).
    optional: bool,
    /// A write forced to the medium.
    fua: bool,
    prdtl: u16,
    /// Bytes the HBA must report moved (`PRDBC`) for a command that is not
    /// queued to be whole. The HBA does not count a queued command's bytes
    /// for the driver to check.
    bytes: u32,
    budget_us: u64,
    /// Its first sector (the timeout record's detail).
    lba: u64,
    /// When it was started (wrapping): commands are issued in this order.
    seq: u32,
    /// Issued again after an NCQ error that was another command's: a second
    /// one fails it.
    retried: bool,
}

const NO_CMD: Cmd = Cmd { queued: false, write: false, optional: false, fua: false, prdtl: 0, bytes: 0, budget_us: 0, lba: 0, seq: 0, retried: false };

/// NCQ error recovery under way: the READ LOG EXT is in the device (through
/// the internal command, header 0), and these queued commands wait for its
/// answer.
#[derive(Clone, Copy)]
struct LogRead {
    held: u32,
    deadline: u64,
    credit: u64,
}

/// What [`HwQueue::reap`] must do once it has let go of [`Ahci::st`], after a
/// look at the device found something past its budget.
#[derive(Clone, Copy)]
enum After {
    Nothing,
    /// The policy handed this caller the reset ([`Ahci::reset_and_resume`]).
    Reset { late: u32, lba: u64, waited_ms: u64 },
    /// The resets are spent: the policy says dead, reset the HBA.
    Latch,
}

/// The slots' moving parts, behind [`Ahci::st`]: a bit per slot.
struct Slots {
    cmd: [Cmd; MAX_SLOTS],
    /// Started, waiting to be issued.
    armed: u32,
    /// In the device: queued commands (`PxSACT`), and the one that is not
    /// queued (`PxCI`; at most one bit).
    queued: u32,
    single: u32,
    /// Over, not yet reported by `reap`.
    done: u32,
    status: [HwStatus; MAX_SLOTS],
    /// Timebase tick by which an issued command must be over, and the stall
    /// credit when it was issued.
    deadline: [u64; MAX_SLOTS],
    credit: [u64; MAX_SLOTS],
    next_seq: u32,
    log: Option<LogRead>,
}

impl Slots {
    /// The commands of `mask` are over with `status`: `reap` reports them.
    fn end(&mut self, mask: u32, status: HwStatus) {
        for k in bits(mask) {
            self.status[k] = status;
        }
        self.done |= mask;
        self.armed &= !mask;
    }

    /// Every command the driver holds (issued, armed, held for the NCQ error
    /// log) is over with `status`.
    fn end_all(&mut self, status: HwStatus) {
        let all = self.queued | self.single | self.armed | self.log.map_or(0, |l| l.held);
        self.end(all, status);
        self.queued = 0;
        self.single = 0;
        self.log = None;
    }
}

/// `a` was started before `b` (wrapping order).
fn older(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

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
    /// What IDENTIFY said at bring-up: a reset after a timeout must find
    /// this disk again, all of it.
    ident: Ident,
    fua: bool,
    trim: bool,
    /// Slots in use (1 without NCQ), and whether reads and writes are queued.
    slots: usize,
    ncq: bool,
    irq: bool,
    /// The first page: command list, received FIS, the internal command, the
    /// first command tables.
    cl_va: usize,
    cl_pa: u64,
    /// Further pages of command tables (the first `ct_pages(slots)`).
    ct_page_pa: [u64; CT_PAGES],
    /// Each slot's command table and staging pages.
    ct_va: [usize; MAX_SLOTS],
    ct_pa: [u64; MAX_SLOTS],
    bounce_va: [[usize; XFER_PAGES]; MAX_SLOTS],
    bounce_pa: [[u64; XFER_PAGES]; MAX_SLOTS],
    /// Issuing commands and reading their outcome; never held across the
    /// device wait.
    st: Mutex<Slots>,
    /// Slots claimed (set by `claim`, cleared by `release`).
    claimed: AtomicU32,
    /// Copies of `Slots::queued`, `Slots::single` (bit 0 also while the NCQ
    /// error log is read) and `Slots::done`, for the waiter's look, which
    /// takes no lock.
    in_queued: AtomicU32,
    in_single: AtomicU32,
    ready: AtomicU32,
    /// Live, being reset, or latched dead until reboot (the timeout policy).
    recovery: Recovery,
    /// `PxIS` bits read and cleared, not yet looked at by the reaper.
    events: AtomicU32,
    stall: StallClock,
    waiter: DeviceWait,
    hooks: AtomicPtr<Hooks>,
    taken: AtomicU32,
    slept: AtomicU32,
    /// Most commands in the device at once since bring-up, and the FUA
    /// writes and TRIMs that completed.
    deepest: AtomicU32,
    fua_writes: AtomicU32,
    trims: AtomicU32,
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

        // The page of the command structures, taken before the ports are
        // looked at: a device's signature reaches the port only through the
        // received-FIS area, so a port is probed with its command list and
        // FIS area in place and the FIS receiver on.
        let (cl_va, cl_pa) = alloc_page(mask).ok_or(AhciError::NoMemory)?;

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
            ident: Ident::default(),
            fua: false,
            trim: false,
            slots: 0,
            ncq: false,
            irq,
            cl_va,
            cl_pa,
            ct_page_pa: [0; CT_PAGES],
            ct_va: [0; MAX_SLOTS],
            ct_pa: [0; MAX_SLOTS],
            bounce_va: [[0; XFER_PAGES]; MAX_SLOTS],
            bounce_pa: [[0; XFER_PAGES]; MAX_SLOTS],
            st: Mutex::new(Slots {
                cmd: [NO_CMD; MAX_SLOTS],
                armed: 0,
                queued: 0,
                single: 0,
                done: 0,
                status: [HwStatus::Ok; MAX_SLOTS],
                deadline: [0; MAX_SLOTS],
                credit: [0; MAX_SLOTS],
                next_seq: 0,
                log: None,
            }),
            claimed: AtomicU32::new(0),
            in_queued: AtomicU32::new(0),
            in_single: AtomicU32::new(0),
            ready: AtomicU32::new(0),
            recovery: Recovery::new(Class::Block, "ahci", b.resets),
            events: AtomicU32::new(0),
            stall: StallClock::new(),
            waiter: DeviceWait::new(),
            hooks: AtomicPtr::new(core::ptr::null_mut()),
            taken: AtomicU32::new(0),
            slept: AtomicU32::new(0),
            deepest: AtomicU32::new(0),
            fua_writes: AtomicU32::new(0),
            trims: AtomicU32::new(0),
        };
        let id = match me.start_port() {
            Ok(id) => id,
            Err(e) => {
                me.teardown();
                return Err(e);
            }
        };
        me.sectors = id.sectors;
        me.flush_ext = id.flush_ext;
        me.ident = id;
        me.fua = id.fua;
        me.trim = id.trim;
        let want = queue_depth(cap, &id);
        me.slots = me.alloc_slots(mask, want);
        if me.slots == 0 {
            me.teardown();
            return Err(AhciError::NoMemory);
        }
        me.ncq = me.slots > 1;
        azos_drv_sys::kprintln!(
            "[AHCI] port {}: {} command slot(s){} (disk queue depth {}, HBA {} slots{}, Kconfig {})",
            me.port,
            me.slots,
            if me.ncq { ", native command queuing" } else { "" },
            id.ncq_depth,
            ((cap >> CAP_NCS_SHIFT) & CAP_NCS_MASK) + 1,
            if cap & CAP_SNCQ != 0 { " with NCQ" } else { " without NCQ" },
            MAX_SLOTS
        );
        if me.slots < want {
            azos_drv_sys::kprintln!("[AHCI] port {}: memory for {} of {} slots only", me.port, me.slots, want);
        }
        Ok(me)
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

        // IDENTIFY DEVICE: 512 bytes into the internal buffer.
        self.exec_polled(&identify_fis(), self.b.identify_us)?;
        let mut words = [0u16; 256];
        // SAFETY: the internal buffer, which the HBA has finished with (the
        // command completed); 512 bytes of it were written.
        unsafe {
            for (i, w) in words.iter_mut().enumerate() {
                *w = core::ptr::read_volatile((self.cl_va + IB_OFF + 2 * i) as *const u16);
            }
        }
        let id = decode_identify(&words)?;

        let mut model = [0u8; 40];
        let n = model_string(&words, &mut model);
        azos_drv_sys::kprintln!(
            "[AHCI] port {} {}: {} sectors mode={} xfer={} KiB flush={} ncq={} fua={} trim={} (w75 {:#06x} w76 {:#06x} w84 {:#06x} w169 {:#06x})",
            self.port,
            core::str::from_utf8(&model[..n]).unwrap_or("?"),
            id.sectors,
            if self.irq { "irq" } else { "poll" },
            XFER_SECTORS * SECTOR_SIZE / 1024,
            if id.flush_ext { "y" } else { "n" },
            id.ncq_depth,
            if id.fua { "y" } else { "n" },
            if id.trim { "y" } else { "n" },
            words[75],
            words[76],
            words[84],
            words[169]
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

    /// Take the command tables and staging pages of up to `want` slots;
    /// returns how many slots have theirs. A slot whose pages are not all
    /// there gives back the ones it got.
    fn alloc_slots(&mut self, mask: u64, want: usize) -> usize {
        for k in 0..want.min(MAX_SLOTS) {
            let (ct_va, ct_pa) = if k < CT_FIRST {
                (self.cl_va + CT0_OFF + k * CT_BYTES, self.cl_pa + (CT0_OFF + k * CT_BYTES) as u64)
            } else {
                let (page, at) = ((k - CT_FIRST) / CT_PER_PAGE, (k - CT_FIRST) % CT_PER_PAGE);
                if at == 0 {
                    match alloc_page(mask) {
                        Some((_, pa)) => self.ct_page_pa[page] = pa,
                        None => return k,
                    }
                }
                let pa = self.ct_page_pa[page] + (at * CT_BYTES) as u64;
                (azos_mm::addr::phys_to_virt(pa as usize), pa)
            };
            for i in 0..XFER_PAGES {
                match alloc_page(mask) {
                    Some((va, pa)) => {
                        self.bounce_va[k][i] = va;
                        self.bounce_pa[k][i] = pa;
                    }
                    None => {
                        for &pa in &self.bounce_pa[k][..i] {
                            free_page(pa);
                        }
                        if k >= CT_FIRST && (k - CT_FIRST) % CT_PER_PAGE == 0 {
                            free_page(self.ct_page_pa[(k - CT_FIRST) / CT_PER_PAGE]);
                        }
                        return k;
                    }
                }
            }
            self.ct_va[k] = ct_va;
            self.ct_pa[k] = ct_pa;
        }
        want.min(MAX_SLOTS)
    }

    /// A failed bring-up: stop the port and the HBA's DMA, give the pages back.
    fn teardown(&mut self) {
        let p = self.port_regs();
        let _ = p.stop(&self.b);
        self.r.wr32(REG_GHC, GHC_AE | GHC_HR);
        let _ = wait_for(self.b.reset_us, || self.r.rd32(REG_GHC) & GHC_HR == 0);
        free_page(self.cl_pa);
        for &pa in &self.ct_page_pa[..ct_pages(self.slots)] {
            free_page(pa);
        }
        for slot in &self.bounce_pa[..self.slots] {
            for &pa in slot {
                free_page(pa);
            }
        }
    }

    /// Run one internal command of bring-up to completion, polling, bounded:
    /// 512 bytes into the internal buffer.
    fn exec_polled(&self, fis: &[u8; 20], timeout_us: u64) -> Result<(), AhciError> {
        self.build_internal(fis);
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
                if get32(self.cl_va + CL_OFF + 4) as usize != SECTOR_SIZE {
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

    /// The command FIS, 20 bytes as five dwords, at the start of the table at
    /// `ct`; the rest of the 64-byte CFIS area and the ATAPI command area are
    /// zero.
    fn put_fis(ct: usize, fis: &[u8; 20]) {
        for i in 0..(CT_PRDT / 4) {
            let v = if i < 5 { u32::from_le_bytes([fis[4 * i], fis[4 * i + 1], fis[4 * i + 2], fis[4 * i + 3]]) } else { 0 };
            put32(ct + 4 * i, v);
        }
    }

    fn put_header(&self, slot: usize, h: [u32; 8]) {
        for (j, d) in h.iter().enumerate() {
            put32(self.cl_va + CL_OFF + slot * HDR_BYTES + 4 * j, *d);
        }
    }

    /// The internal command (IDENTIFY, READ LOG EXT): `fis` and one PRD of
    /// the 512-byte internal buffer, in header 0. Only while nothing else is
    /// in the device; slot 0's own header is written again when it is issued.
    fn build_internal(&self, fis: &[u8; 20]) {
        let ct = self.cl_va + IT_OFF;
        Self::put_fis(ct, fis);
        for (j, d) in prd_entry(self.cl_pa + IB_OFF as u64, SECTOR_SIZE).iter().enumerate() {
            put32(ct + CT_PRDT + 4 * j, *d);
        }
        self.put_header(0, cmd_header(false, 1, self.cl_pa + IT_OFF as u64));
    }

    /// Slot `k`'s command table: the FIS, and a PRDT of `bytes` over its
    /// staging pages; returns the PRDT's length. The header is written when
    /// the command is issued.
    fn build_slot(&self, k: usize, fis: &[u8; 20], bytes: usize) -> u16 {
        let ct = self.ct_va[k];
        Self::put_fis(ct, fis);
        let n = bytes.div_ceil(PAGE);
        for i in 0..n {
            let len = (bytes - i * PAGE).min(PAGE);
            for (j, d) in prd_entry(self.bounce_pa[k][i], len).iter().enumerate() {
                put32(ct + CT_PRDT + i * PRD_BYTES + 4 * j, *d);
            }
        }
        n as u16
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

    /// `(command slots in use, most commands in the device at once so far,
    /// FUA writes and TRIMs completed)`.
    pub fn queue_counts(&self) -> (usize, u32, u32, u32) {
        let r = |a: &AtomicU32| a.load(Ordering::Relaxed);
        (self.slots, r(&self.deepest), r(&self.fua_writes), r(&self.trims))
    }

    /// The commands of `mask` completed `Ok`: count what the evidence counts.
    fn count_ok(&self, st: &Slots, mask: u32) {
        for k in bits(mask) {
            let c = &st.cmd[k];
            if c.fua {
                self.fua_writes.fetch_add(1, Ordering::Relaxed);
            }
            if c.optional && c.write {
                self.trims.fetch_add(1, Ordering::Relaxed);
            }
        }
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
    /// per stall, at most once per `STALL_SAY_EVERY_US`. A gap is a stall only
    /// while a command is in the device (or the NCQ error log is being read),
    /// not for one that is armed and not yet issued. Returns the timebase
    /// tick it read.
    fn watch(&self, st: &Slots) -> u64 {
        let t = now();
        let ticks = |us: u64| us * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000;
        let busy = st.queued | st.single != 0 || st.log.is_some();
        if let Some(n) = self.stall.look(t, ticks(STALL_GAP_US), ticks(STALL_SAY_EVERY_US), busy) {
            azos_drv_sys::kprintln!(
                "[AHCI] guest did not run for {} ms: command budgets extended by that time ({} more since the last line)",
                n.ticks * 1000 / azos_drv_sys::timebase::TIMER_FREQ, n.held
            );
        }
        t
    }

    fn publish(&self, st: &Slots) {
        self.in_queued.store(st.queued, Ordering::Release);
        self.in_single.store(st.single | st.log.map_or(0, |_| 1), Ordering::Release);
        self.ready.store(st.done, Ordering::Release);
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

    /// Reset the HBA and latch the driver dead: every later claim answers
    /// `Dead` and nothing more is issued. The staging pages stay owned by the
    /// driver and are never reused. `latched`: the caller already moved the
    /// policy to dead (a timeout with the resets spent); otherwise the first
    /// call does the work.
    fn latch_dead(&self, reason: &str, latched: bool) {
        if !latched && !self.recovery.latch() {
            return;
        }
        let _ = self.reset_hba();
        azos_drv_sys::kerr!("[AHCI] Error: {} - controller reset, block I/O disabled", reason);
    }

    /// A command ran out of its budget and the policy handed this caller the
    /// reset: reset the HBA, bring the port up again over the same memory
    /// (the command list page and the slots' tables and staging pages), and
    /// check it is the same disk: every field of the IDENTIFY record, so a
    /// disk that now queues to another depth (or reports other features) is
    /// not taken for this one. The commands the device held are over (the
    /// reset stopped the engine): the caller ends them.
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
            Ok(id) if id == self.ident => {
                self.events.store(0, Ordering::Release);
                azos_drv_sys::kprintln!("[AHCI] port {}: reset done, the disk is back", self.port);
                true
            }
            Ok(id) => {
                azos_drv_sys::kerr!("[AHCI] port {}: a different disk after the reset ({:?}, was {:?})",
                    self.port, id, self.ident);
                false
            }
            Err(_) => false,
        }
    }

    /// Something ran out of its budget: the commands of `late` (none for the
    /// NCQ error log's read) and `lba`, the first sector of the command the
    /// record names; `waited_ms` how long it was in the device. The policy
    /// decides, under `st` (it takes no lock and does not spin): a reset is
    /// done by [`HwQueue::reap`] once it has let go of `st`, and until then
    /// the device's commands stay where they are (the policy says
    /// "resetting", so nobody looks at them or issues more); with the resets
    /// spent the late commands end `Timeout`, the others `Io`, and `reap`
    /// resets the HBA of the driver now dead.
    fn on_timeout(&self, st: &mut Slots, late: u32, lba: u64, waited_ms: u64) -> After {
        match self.recovery.timed_out(lba, waited_ms) {
            Verdict::Reset => After::Reset { late, lba, waited_ms },
            Verdict::Latch => {
                st.end(late, HwStatus::Timeout);
                st.queued &= !late;
                st.single &= !late;
                st.end_all(HwStatus::Io);
                After::Latch
            }
            Verdict::Handled => After::Nothing,
        }
    }

    /// The reset [`Ahci::on_timeout`] handed this caller, with `st` NOT held
    /// (the reset spins). Then, under `st`: the late commands end `Timeout`
    /// and every other one the device held (queued, alone, or held for the
    /// NCQ error log) `Reset`, not issued again: a write may or may not have
    /// reached the medium, which the caller must hear. The commands still
    /// armed were never in the device; they are issued now. A reset that did
    /// not bring the disk back latches the driver dead, and they all end `Io`.
    fn reset_and_resume(&self, late: u32, lba: u64, waited_ms: u64) {
        let ok = self.reset_after_timeout();
        if !ok {
            // The engine is stopped or the HBA is held in reset; the pages
            // stay quarantined all the same.
            let _ = self.reset_hba();
            azos_drv_sys::kerr!("[AHCI] Error: reset did not bring the disk back - block I/O disabled");
        }
        let mut st = self.st.lock();
        st.end(late, HwStatus::Timeout);
        st.queued &= !late;
        st.single &= !late;
        if ok {
            let held = st.queued | st.single | st.log.map_or(0, |l| l.held);
            st.end(held, HwStatus::Reset);
            st.queued = 0;
            st.single = 0;
            st.log = None;
        } else {
            st.end_all(HwStatus::Io);
        }
        // Back in service (or dead) only once the slots say so: a reaper that
        // sees the policy live finds no command of the old device.
        self.recovery.reset_done(ok, lba, waited_ms);
        self.kick(&mut st);
        self.publish(&st);
    }

    /// `waited_ms` of a command issued with `budget_us` and due at
    /// `deadline`, seen late at `t`.
    fn waited_ms(budget_us: u64, deadline: u64, t: u64) -> u64 {
        budget_us / 1000 + t.saturating_sub(deadline).saturating_mul(1000) / azos_drv_sys::timebase::TIMER_FREQ.max(1)
    }

    /// After a fatal port error (AHCI 1.3 section 6.2.2.1): stop the command
    /// engine (which drops the commands the HBA held and clears `PxSACT` and
    /// `PxCI`), clear the error and interrupt status, and start again.
    /// `false`: the port did not come back (the caller latches the driver
    /// dead).
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

    /// Issue the armed commands in the order they were started, while the
    /// device takes them: queued commands together, one that is not queued
    /// alone (after the queued ones in the device are over; the queued ones
    /// started after it wait for it). Caller holds `st`.
    fn kick(&self, st: &mut Slots) {
        if !self.recovery.live() || st.log.is_some() {
            return;
        }
        while st.armed != 0 {
            let k = bits(st.armed).reduce(|a, b| if older(st.cmd[b].seq, st.cmd[a].seq) { b } else { a }).unwrap_or(0);
            let c = st.cmd[k];
            if st.single != 0 || (!c.queued && st.queued != 0) {
                break;
            }
            if st.queued == 0 {
                // Whatever the port said before this command is not about it.
                self.harvest();
                self.events.store(0, Ordering::Release);
            }
            let bit = 1u32 << k;
            self.put_header(k, cmd_header(c.write, c.prdtl as usize, self.ct_pa[k]));
            // The look before the credit is read: the baseline already holds
            // any stall that ended just now.
            self.watch(st);
            st.credit[k] = self.stall.credit();
            st.deadline[k] = deadline_after_us(c.budget_us);
            st.armed &= !bit;
            let p = self.port_regs();
            azos_dma::order::io_wmb();
            if c.queued {
                // The slot's `PxSACT` bit before its `PxCI` bit (AHCI 1.3
                // section 5.3.1): the HBA takes it as a queued command.
                p.wr(P_SACT, bit);
                st.queued |= bit;
            } else {
                st.single = bit;
            }
            p.wr(P_CI, bit);
            self.deepest.fetch_max((st.queued | st.single).count_ones(), Ordering::Relaxed);
        }
    }

    /// Look at the device: decide the outcome of every command it finished,
    /// recover from an error. Caller holds `st`. Something that ran out of
    /// its budget goes to the timeout policy ([`Ahci::on_timeout`]); the
    /// answer says what the caller does once it has let go of `st`.
    fn outcome(&self, st: &mut Slots) -> After {
        if self.recovery.resetting() {
            // Another reaper is resetting the HBA: the commands in the device
            // are its to end, and the registers are not to be read meanwhile.
            return After::Nothing;
        }
        let ev = self.take_events();
        let t = self.watch(st);
        if self.recovery.dead() {
            // The device died with these commands in it: no data to trust.
            st.end_all(HwStatus::Io);
            return After::Nothing;
        }
        if st.log.is_some() {
            return self.ncq_log_step(st, ev, t);
        }
        if st.queued | st.single == 0 {
            return After::Nothing;
        }
        let p = self.port_regs();
        // A queued command is over when the disk's Set Device Bits FIS
        // cleared its `PxSACT` bit; one that did before an error is good.
        if st.queued != 0 {
            let fin = st.queued & !p.rd(P_SACT);
            if fin != 0 {
                fence(Ordering::Acquire);
                self.count_ok(st, fin);
                st.end(fin, HwStatus::Ok);
                st.queued &= !fin;
            }
        }
        let tfd = p.rd(P_TFD);
        if ev & IS_FATAL != 0 {
            if ev & IS_TFES != 0 && st.queued != 0 && st.single == 0 {
                self.ncq_error(st);
                return After::Nothing;
            }
            let single = st.single;
            let optional = single != 0 && st.cmd[single.trailing_zeros() as usize].optional;
            let aborted = optional && (tfd >> 8) & ATA_ERR_ABRT != 0 && ev & IS_TFES != 0;
            if !aborted {
                azos_drv_sys::kerr!("[AHCI] port {}: error interrupt {:#010x}, task file {:#06x}: {} command(s) failed, port restarted",
                    self.port, ev & IS_FATAL, tfd & 0xFFFF, (st.queued | single).count_ones());
            }
            st.end(st.queued, HwStatus::Io);
            st.end(single, if aborted { HwStatus::Unsupported } else { HwStatus::Io });
            st.queued = 0;
            st.single = 0;
            if !self.restart_port() {
                self.latch_dead("port restart failed", false);
                st.end_all(HwStatus::Io);
            }
            return After::Nothing;
        }
        if st.single != 0 && p.rd(P_CI) & st.single == 0 {
            fence(Ordering::Acquire);
            let k = st.single.trailing_zeros() as usize;
            let c = st.cmd[k];
            let status = if tfd & (TFD_ERR | TFD_DF) != 0 {
                azos_drv_sys::kerr!("[AHCI] port {}: command ended with task file {:#06x}", self.port, tfd & 0xFFFF);
                if c.optional && (tfd >> 8) & ATA_ERR_ABRT != 0 { HwStatus::Unsupported } else { HwStatus::Io }
            } else {
                let moved = get32(self.cl_va + CL_OFF + k * HDR_BYTES + 4);
                if moved != c.bytes {
                    azos_drv_sys::kerr!("[AHCI] port {}: {} of {} bytes moved", self.port, moved, c.bytes);
                    HwStatus::Io
                } else {
                    self.count_ok(st, st.single);
                    HwStatus::Ok
                }
            };
            st.end(st.single, status);
            st.single = 0;
        }
        let late = bits(st.queued | st.single)
            .filter(|&k| self.stall.expired(t, st.deadline[k], st.credit[k]))
            .fold(0u32, |m, k| m | 1 << k);
        if late == 0 {
            return After::Nothing;
        }
        let k = late.trailing_zeros() as usize;
        let waited = Self::waited_ms(st.cmd[k].budget_us, st.deadline[k], t);
        self.on_timeout(st, late, st.cmd[k].lba, waited)
    }

    /// A task file error with queued commands in the device: the disk took
    /// them all off its queue and answers only READ LOG EXT of the NCQ
    /// Command Error log until that is read. Restart the port, and read the
    /// log through the internal command.
    fn ncq_error(&self, st: &mut Slots) {
        let held = st.queued;
        st.queued = 0;
        if !self.restart_port() {
            self.latch_dead("port restart failed", false);
            st.end(held, HwStatus::Io);
            return;
        }
        self.build_internal(&read_log_fis(LOG_NCQ_ERROR, 1));
        self.watch(st);
        st.log = Some(LogRead { held, deadline: deadline_after_us(self.b.identify_us), credit: self.stall.credit() });
        azos_dma::order::io_wmb();
        self.port_regs().wr(P_CI, 1);
    }

    /// The NCQ error log's READ LOG EXT: once it is over, the command the log
    /// names fails and the others it held are armed again (once each); a log
    /// that names none of them, or says the error was not a queued
    /// command's, fails them all, and so does a log read that fails. A log
    /// read past its budget is a device timeout like any other: the policy
    /// resets the HBA (the held commands then end `Reset`) or latches it dead.
    fn ncq_log_step(&self, st: &mut Slots, ev: u32, t: u64) -> After {
        let Some(log) = st.log else { return After::Nothing };
        let p = self.port_regs();
        let ci = p.rd(P_CI);
        let tfd = p.rd(P_TFD);
        let over = ci & 1 == 0;
        if ev & IS_FATAL != 0 || (over && (tfd & (TFD_ERR | TFD_DF) != 0 || get32(self.cl_va + CL_OFF + 4) as usize != SECTOR_SIZE)) {
            st.log = None;
            azos_drv_sys::kerr!("[AHCI] port {}: NCQ error, and its log could not be read (task file {:#06x}): {} command(s) failed",
                self.port, tfd & 0xFFFF, log.held.count_ones());
            st.end(log.held, HwStatus::Io);
            if !self.restart_port() {
                self.latch_dead("port restart failed", false);
                st.end_all(HwStatus::Io);
            }
            return After::Nothing;
        }
        if !over {
            if self.stall.expired(t, log.deadline, log.credit) {
                azos_drv_sys::kerr!("[AHCI] port {}: the NCQ error log was not read in time", self.port);
                let first = log.held.trailing_zeros() as usize;
                let lba = if log.held != 0 { st.cmd[first].lba } else { 0 };
                return self.on_timeout(st, 0, lba, Self::waited_ms(self.b.identify_us, log.deadline, t));
            }
            return After::Nothing;
        }
        fence(Ordering::Acquire);
        st.log = None;
        // The log's first dword: byte 0 (NQ, tag), 2 (status), 3 (error).
        let d0 = get32(self.cl_va + IB_OFF);
        let (b0, status, error) = (d0 as u8, (d0 >> 16) as u8, (d0 >> 24) as u8);
        let tag = (b0 & NCQ_LOG_TAG) as usize;
        let named = b0 & NCQ_LOG_NQ == 0 && log.held >> tag & 1 != 0;
        let culprit = if named { 1u32 << tag } else { log.held };
        st.end(culprit, HwStatus::Io);
        let (mut again, mut lost) = (0u32, 0u32);
        for k in bits(log.held & !culprit) {
            if st.cmd[k].retried {
                lost |= 1 << k;
            } else {
                st.cmd[k].retried = true;
                again |= 1 << k;
            }
        }
        st.end(lost, HwStatus::Io);
        st.armed |= again;
        if named {
            azos_drv_sys::kerr!("[AHCI] port {}: NCQ error on tag {} (status {:#04x}, error {:#04x}): it failed, {} issued again, {} failed twice",
                self.port, tag, status, error, again.count_ones(), lost.count_ones());
        } else {
            azos_drv_sys::kerr!("[AHCI] port {}: NCQ error the log does not name (byte 0 {:#04x}): {} command(s) failed",
                self.port, b0, culprit.count_ones());
        }
        After::Nothing
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
            // 0 without TRIM: the layer refuses a discard.
            max_discard_sectors: if self.trim { TRIM_MAX_SECTORS } else { 0 },
            fua: self.fua,
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
        let all = if self.slots >= 32 { u32::MAX } else { (1u32 << self.slots) - 1 };
        let mut c = self.claimed.load(Ordering::Acquire);
        loop {
            let free = !c & all;
            if free == 0 {
                return Claim::Busy;
            }
            let k = free.trailing_zeros();
            match self.claimed.compare_exchange_weak(c, c | 1 << k, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Claim::Tag(k as u8),
                Err(now) => c = now,
            }
        }
    }

    fn start(&self, tag: u8, cmd: &HwCmd<'_>) -> Result<(), ()> {
        let k = tag as usize;
        if k >= self.slots || self.claimed.load(Ordering::Acquire) >> k & 1 == 0 || !self.recovery.live() {
            return Err(());
        }
        let (fis, write, bytes, optional, budget_us, queued) = match cmd.op {
            HwOp::Read | HwOp::Write => {
                let bytes = cmd.sectors as usize * SECTOR_SIZE;
                let write = cmd.op == HwOp::Write;
                if cmd.sectors == 0
                    || cmd.sectors as usize > XFER_SECTORS
                    || cmd.lba.checked_add(cmd.sectors as u64).is_none_or(|end| end > self.sectors)
                    || (write && cmd.segs.iter().map(|s| s.len()).sum::<usize>() != bytes)
                    || (cmd.fua && !(write && self.fua))
                {
                    return Err(());
                }
                if write {
                    let mut off = 0;
                    for s in cmd.segs {
                        self.stage_in(k, off, s);
                        off += s.len();
                    }
                }
                let fis = if self.ncq {
                    fpdma_fis(write, cmd.lba, cmd.sectors, tag, cmd.fua)
                } else {
                    let c = match (write, cmd.fua) {
                        (false, _) => ATA_READ_DMA_EXT,
                        (true, false) => ATA_WRITE_DMA_EXT,
                        (true, true) => ATA_WRITE_DMA_FUA_EXT,
                    };
                    h2d_fis(c, cmd.lba, cmd.sectors)
                };
                (fis, write, bytes, false, self.b.io_us, self.ncq)
            }
            HwOp::Flush if self.flush_ext => (h2d_fis(ATA_FLUSH_CACHE_EXT, 0, 0), false, 0, true, self.b.flush_us, false),
            HwOp::Flush => {
                // The disk has no flush command: over at once, as unsupported,
                // without touching the HBA.
                let mut st = self.st.lock();
                st.end(1 << k, HwStatus::Unsupported);
                self.publish(&st);
                return Ok(());
            }
            HwOp::Discard if self.trim => {
                if cmd.sectors == 0
                    || cmd.sectors > TRIM_MAX_SECTORS
                    || cmd.lba.checked_add(cmd.sectors as u64).is_none_or(|end| end > self.sectors)
                {
                    return Err(());
                }
                let mut ranges = [0u8; SECTOR_SIZE];
                trim_ranges(cmd.lba, cmd.sectors, &mut ranges);
                self.stage_in(k, 0, &ranges);
                // A TRIM may erase what it deallocates before it answers:
                // the flush's budget.
                (dsm_trim_fis(), true, SECTOR_SIZE, true, self.b.flush_us, false)
            }
            HwOp::Discard => return Err(()),
        };
        let prdtl = self.build_slot(k, &fis, bytes);
        let mut st = self.st.lock();
        if !self.recovery.live() {
            return Err(());
        }
        let seq = st.next_seq;
        st.next_seq = seq.wrapping_add(1);
        st.cmd[k] = Cmd { queued, write, optional, fua: cmd.fua, prdtl, bytes: bytes as u32, budget_us, lba: cmd.lba, seq, retried: false };
        st.armed |= 1 << k;
        self.kick(&mut st);
        self.publish(&st);
        Ok(())
    }

    fn reap(&self, out: &mut [HwDone; HW_TAGS_MAX]) -> usize {
        if self.in_queued.load(Ordering::Acquire) | self.in_single.load(Ordering::Acquire) | self.ready.load(Ordering::Acquire) == 0 {
            return 0;
        }
        let mut st = self.st.lock();
        match self.outcome(&mut st) {
            After::Nothing => {}
            After::Reset { late, lba, waited_ms } => {
                // Reset before the layer hears of any command the device
                // held: the slots it is about to release must not be claimed
                // while the HBA is reset (`claim` answers `Busy` meanwhile).
                self.publish(&st);
                drop(st);
                self.reset_and_resume(late, lba, waited_ms);
                st = self.st.lock();
            }
            After::Latch => {
                // Reset the HBA (which stops its DMA) before the layer hears.
                self.publish(&st);
                drop(st);
                self.latch_dead("command timeout, resets spent", true);
                st = self.st.lock();
            }
        }
        self.kick(&mut st);
        let mut n = 0;
        for k in bits(st.done) {
            out[n] = HwDone { tag: k as u8, status: st.status[k] };
            n += 1;
        }
        st.done = 0;
        self.publish(&st);
        n
    }

    fn copy_out(&self, tag: u8, mut off: usize, dst: &mut [u8]) {
        let k = tag as usize;
        let mut done = 0;
        while done < dst.len() {
            let n = (dst.len() - done).min(PAGE - off % PAGE);
            // SAFETY: the HBA finished the command, so it is done with the
            // slot's pages; the slot is still the caller's until `release`.
            // `off + dst.len()` is inside the command's data.
            unsafe {
                let src = (self.bounce_va[k][off / PAGE] + off % PAGE) as *const u8;
                core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr().add(done), n);
            }
            done += n;
            off += n;
        }
    }

    fn release(&self, tag: u8) {
        // A dead driver answers `Dead` to every claim, so the slot is not
        // reused (a command the HBA could not recall may still be writing to
        // the staging pages). After a reset that brought the disk back the
        // HBA's engine was stopped, so it writes to none of them.
        self.claimed.fetch_and(!(1u32 << tag), Ordering::AcqRel);
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
                let (q, s) = (self.in_queued.load(Ordering::Acquire), self.in_single.load(Ordering::Acquire));
                !self.recovery.live()
                    || self.events.load(Ordering::Acquire) != 0
                    || self.ready.load(Ordering::Acquire) != 0
                    || p.rd(P_IS) != 0
                    || (s != 0 && p.rd(P_CI) & s != s)
                    || (q != 0 && p.rd(P_SACT) & q != q)
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
    /// Copy `src` into slot `k`'s staging pages from byte `off`.
    fn stage_in(&self, k: usize, mut off: usize, src: &[u8]) {
        let mut done = 0;
        while done < src.len() {
            let n = (src.len() - done).min(PAGE - off % PAGE);
            // SAFETY: slot `k` is this caller's and holds no command in the
            // device, and `off + src.len() <= XFER_PAGES * PAGE` (checked by
            // `start`).
            unsafe {
                let dst = (self.bounce_va[k][off / PAGE] + off % PAGE) as *mut u8;
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

/// [`Ahci::queue_counts`]: `(command slots, most commands in the disk at
/// once, FUA writes, TRIMs)`; zeros without a controller.
#[cfg(feature = "ahci")]
pub fn queue_counts() -> (usize, u32, u32, u32) {
    controller().map_or((0, 0, 0, 0), |c| c.queue_counts())
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
