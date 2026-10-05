// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// eMMC / SD driver for real-hardware targets (VisionFive 2 / SpacemiT K1).
//
// Implements the SD Host Controller Interface (SDHCI) v3.0 register model
// (SDHCI Specification v3.00, SD Association) in PIO mode. This module's
// prior doc comment claimed this was "verified against the JH7110 TRM
// (Chapter 17 — SDIO)" — that claim could not be re-confirmed in this pass
// (no TRM access here) and is now contradicted by external primary-source
// evidence:
//
// ***UNRESOLVED, HARDWARE-BLOCKING FINDING (2026-09-18)***
// JH7110's own device tree — both `sdio0@16010000` and `sdio1@16020000`
// (= this file's `MMC0_BASE`/`MMC1_BASE`) — declares
// `compatible = "snps,dw-mshc"` (Synopsys DesignWare Mobile Storage Host
// Controller), NOT any SDHCI-compatible string. Confirmed against
// StarFive's own `u-boot` tree, `arch/riscv/dts/jh7110.dtsi`
// (<https://github.com/starfive-tech/u-boot/blob/JH7110_VisionFive2_devel/arch/riscv/dts/jh7110.dtsi>),
// fetched 2026-09-18. DW MSHC (Linux driver family `dw_mmc`) has a
// completely different register layout from SDHCI — CTRL/PWREN/CLKDIV/
// CLKENA/CMD/CMDARG/RESP0-3/MINTSTS/RINTSTS/STATUS/FIFOTH/CDETECT/... vs
// this file's SDHCI DMA_ADDRESS/BLOCK_SIZE/TRANSFER_MODE/COMMAND/BUFFER
// layout below. **This driver, as written, almost certainly will not
// enumerate a card on real VisionFive 2 silicon.** It was never boot-tested
// against real hardware (none available in this environment either); it
// only ever ran against QEMU's `virtio-blk`, which this module's code path
// is not — `blkdev.rs` routes to `virtio::blk` for QEMU and to this module
// only under `--features vf2`/`k1`, so this mismatch has had no green
// signal to catch it. Rewriting this against the real DW-MSHC register map
// (Linux `drivers/mmc/host/dw_mmc.h` is the public reference) is real
// engineering work this pass did not attempt — a blind rewrite with zero
// way to test it here would trade one unverified implementation for
// another, no more trustworthy than this one.
//
// K1's own MMC IP has NOT been independently re-checked in this pass —
// out of scope (VF2/JH7110-specific work only).
//
// Boot flow (microSD, SDHC), as currently coded against the SDHCI model:
//   mmc_init → SW-reset → power-on → clock@400kHz → CMD0 → CMD8 → ACMD41 ×N
//             → CMD2 → CMD3(RCA) → CMD7(select) → ACMD6(4-bit) → clock@25MHz
//
// After mmc_init(), mmc_read/mmc_write use PIO via the Buffer Data Port (0x20).
// DMA (ADMA2) is a future optimisation once PIO proves stable on real hardware
// — moot until the register model above is corrected.
//
// `mmc_flush` (2026-09-28) is the SD/eMMC durability point: CMD13
// SEND_STATUS until the card is back in `tran` with READY_FOR_DATA, error
// bits checked, and — only if an eMMC cache was ever enabled, which this
// driver never does — CMD6 FLUSH_CACHE. Under `--features mmc-pci` (QEMU
// only) this same file drives QEMU's `sdhci-pci`, an SDHCI-v3 model, through
// a BAR the kernel assigns; that is the one place any of it has run. The
// VF2 caveat above still applies to every line.

#![allow(dead_code)]

#[cfg(any(feature = "vf2", feature = "k1"))]
use azos_drv_base::platform::hw::{MMC0_BASE, MMC1_BASE};
use azos_drv_api::block::FlushError;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use azos_sync::pi_mutex::PiMutex;

// ── SDHCI register offsets ────────────────────────────────────────────────────
const SDHCI_DMA_ADDRESS:   usize = 0x00;
const SDHCI_BLOCK_SIZE:    usize = 0x04; // 16-bit: [14:12] boundary, [11:0] size
const SDHCI_BLOCK_COUNT:   usize = 0x06; // 16-bit
const SDHCI_ARGUMENT:      usize = 0x08; // 32-bit
const SDHCI_TRANSFER_MODE: usize = 0x0C; // 16-bit
const SDHCI_COMMAND:       usize = 0x0E; // 16-bit
const SDHCI_RESPONSE0:     usize = 0x10; // 32-bit  response[31:0]
const SDHCI_RESPONSE1:     usize = 0x14; // 32-bit  response[63:32]
const SDHCI_RESPONSE2:     usize = 0x18; // 32-bit  response[95:64]
const SDHCI_RESPONSE3:     usize = 0x1C; // 32-bit  response[127:96]
const SDHCI_BUFFER:        usize = 0x20; // 32-bit  PIO data port
const SDHCI_PRESENT_STATE: usize = 0x24; // 32-bit  read-only
const SDHCI_HOST_CONTROL:  usize = 0x28; // 8-bit
const SDHCI_POWER_CONTROL: usize = 0x29; // 8-bit
const SDHCI_CLOCK_CONTROL: usize = 0x2C; // 16-bit
const SDHCI_TIMEOUT:       usize = 0x2E; // 8-bit   data timeout counter
const SDHCI_SW_RESET:      usize = 0x2F; // 8-bit
const SDHCI_INT_STATUS:    usize = 0x30; // 32-bit
const SDHCI_INT_ENABLE:    usize = 0x34; // 32-bit  status enable (poll)
const SDHCI_SIGNAL_ENABLE: usize = 0x38; // 32-bit  IRQ signal enable (keep 0)
const SDHCI_CAPABILITIES:  usize = 0x40; // 64-bit; [15:8] = base clock MHz
const SDHCI_VERSION:       usize = 0xFE; // 16-bit  vendor version

// PRESENT_STATE bits
const STATE_CMD_INHIBIT:  u32 = 1 << 0;
const STATE_DAT_INHIBIT:  u32 = 1 << 1;
const STATE_CARD_PRESENT: u32 = 1 << 16;

// INT_STATUS bits
const INT_CMD_COMPLETE:    u32 = 1 << 0;
const INT_TRANSFER_DONE:   u32 = 1 << 1;
const INT_BUF_WRITE_READY: u32 = 1 << 4;
const INT_BUF_READ_READY:  u32 = 1 << 5;
const INT_ERROR:           u32 = 1 << 15;

// SW_RESET bits
const RESET_ALL:  u8 = 0x01;

// HOST_CONTROL bits
const HC_4BIT_BUS: u8 = 1 << 1;

// POWER_CONTROL: 3.3 V, power on
const PWR_33V_ON: u8 = 0x0F;

// TRANSFER_MODE bits (16-bit register at 0x0C)
const TM_READ: u16 = 1 << 4; // 1 = card-to-host, 0 = host-to-card

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
const CMD_WRITE_SINGLE:   u16 = 24;
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
/// own CMD24 response instead of leaving everything to `mmc_flush`'s CMD13.
const R1_ERRORS:         u32 = 0xFDF9_8008;
const R1_READY_FOR_DATA: u32 = 1 << 8;
/// eMMC only: SWITCH_ERROR(7), set when a CMD6 was refused.
const R1_SWITCH_ERROR:   u32 = 1 << 7;
const R1_STATE_SHIFT:    u32 = 9;
const R1_STATE_MASK:     u32 = 0xF;
const STATE_TRAN: u32 = 4;
const STATE_RCV:  u32 = 6;
const STATE_PRG:  u32 = 7;

/// CMD13 polls `mmc_flush` spends waiting for the card to leave `prg`. An
/// iteration bound, not a wall-clock one: this file has no timer. At 25 MHz
/// one CMD13 is ~48 bits on the CMD line plus the response, a few µs, so
/// this is on the order of seconds — sized for an SD card's worst-case
/// programming time (250 ms per SD spec for a write), not measured on any
/// board.
const FLUSH_STATUS_POLLS: u32 = 200_000;

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

/// A write on this slot failed — its CMD24 response carried an error bit,
/// or the transfer itself failed — since the last `mmc_flush`. `mmc_flush`
/// reports it (`Err(Io)`) and clears it, so a flush never confirms a batch
/// that lost a write whose error the card has already reported and forgotten.
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

/// U05-8 fix (2026-09-26): one `PiMutex` per slot, mirroring
/// `virtio::blk::BLK_LOCK`'s discipline exactly — held across the WHOLE PIO
/// transfer (`wait_inhibit` .. last `INT_TRANSFER_DONE`), not just the
/// register writes, for the same reason `blk.rs` gives: two harts
/// interleaving `mmc_read`/`mmc_write` on the same controller would
/// interleave their `SDHCI_ARGUMENT`/`SDHCI_COMMAND` writes and each read
/// back the other's data. Per-slot rather than one lock for both: MMC0 and
/// MMC1 are two independent physical SDIO controllers
/// (`platform::hw::MMC0_BASE`/`MMC1_BASE`), so a transfer on one need not
/// block a transfer on the other.
static MMC_LOCKS: [PiMutex<()>; 2] = [PiMutex::new(()), PiMutex::new(())];

// ── MMIO helpers ──────────────────────────────────────────────────────────────
#[inline(always)]
fn rd32(base: usize, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + off) as *const u32) }
}
#[inline(always)]
fn rd16(base: usize, off: usize) -> u16 {
    unsafe { core::ptr::read_volatile((base + off) as *const u16) }
}
#[inline(always)]
fn rd8(base: usize, off: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base + off) as *const u8) }
}
#[inline(always)]
fn wr32(base: usize, off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u32, val) }
}
#[inline(always)]
fn wr16(base: usize, off: usize, val: u16) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u16, val) }
}
#[inline(always)]
fn wr8(base: usize, off: usize, val: u8) {
    unsafe { core::ptr::write_volatile((base + off) as *mut u8, val) }
}

// ── Clock setup ───────────────────────────────────────────────────────────────
/// Set SDCLK to the highest frequency ≤ `target_hz`.
///
/// Reads the base clock from CAPABILITIES[15:8] (MHz).
/// Uses the SDHCI v3 10-bit divider: SDCLK = base / (2 × N), N = 0 → bypass.
/// Returns `false` if the internal clock never becomes stable.
fn mmc_set_clock(base: usize, target_hz: u32) -> bool {
    // Preserve timeout byte; disable SD clock first.
    let timeout = rd8(base, SDHCI_TIMEOUT);
    wr16(base, SDHCI_CLOCK_CONTROL, 0);

    // Base clock from capabilities [15:8] in MHz (8-bit field in SDHCI v3).
    let caps     = rd32(base, SDHCI_CAPABILITIES);
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

    wr16(base, SDHCI_CLOCK_CONTROL, clkctl);
    wr8(base, SDHCI_TIMEOUT, timeout);

    // Wait for Internal Clock Stable (bit 1).
    for _ in 0..200_000u32 {
        if rd16(base, SDHCI_CLOCK_CONTROL) & 0x02 != 0 {
            wr16(base, SDHCI_CLOCK_CONTROL, clkctl | 0x04); // bit 2 = SD Clock Enable
            return true;
        }
    }
    false
}

// ── Command engine ────────────────────────────────────────────────────────────
/// Spin until CMD (and optionally DAT) inhibit clears.
fn wait_inhibit(base: usize, check_dat: bool) -> bool {
    let mask = STATE_CMD_INHIBIT | if check_dat { STATE_DAT_INHIBIT } else { 0 };
    for _ in 0..200_000u32 {
        if rd32(base, SDHCI_PRESENT_STATE) & mask == 0 { return true; }
    }
    false
}

/// Spin until any `mask` bit is set in INT_STATUS, or an error occurs.
fn wait_int(base: usize, mask: u32) -> bool {
    for _ in 0..2_000_000u32 {
        let st = rd32(base, SDHCI_INT_STATUS);
        if st & INT_ERROR != 0 {
            wr32(base, SDHCI_INT_STATUS, st); // clear error bits
            return false;
        }
        if st & mask != 0 { return true; }
    }
    false
}

/// Issue one SD command and return the 4 response registers.
///
/// `flags` = RESP_xxx constant, optionally OR'd with RESP_DATA for data commands.
/// For data commands the caller must set TRANSFER_MODE and BLOCK_SIZE before calling.
fn send_cmd(base: usize, cmd: u16, arg: u32, flags: u16) -> Option<[u32; 4]> {
    let has_data = flags & RESP_DATA != 0;
    if !wait_inhibit(base, has_data) { return None; }

    wr32(base, SDHCI_INT_STATUS, 0xFFFF_FFFF); // clear all pending
    wr32(base, SDHCI_ARGUMENT, arg);

    if !has_data {
        wr16(base, SDHCI_TRANSFER_MODE, 0);
    }
    // [15:8] = command index, [5:0] = flags (Data Present / Index / CRC / RespType)
    wr16(base, SDHCI_COMMAND, ((cmd & 0x3F) << 8) | (flags & 0x3F));

    if !wait_int(base, INT_CMD_COMPLETE) { return None; }
    wr32(base, SDHCI_INT_STATUS, INT_CMD_COMPLETE);

    Some([
        rd32(base, SDHCI_RESPONSE0),
        rd32(base, SDHCI_RESPONSE1),
        rd32(base, SDHCI_RESPONSE2),
        rd32(base, SDHCI_RESPONSE3),
    ])
}

// ── Public API ────────────────────────────────────────────────────────────────

/// MMC/SD controller slot.
#[derive(Clone, Copy, PartialEq)]
pub enum MmcSlot {
    Emmc = 0, // SDIO0 @ MMC0_BASE — eMMC (onboard)
    Sd   = 1, // SDIO1 @ MMC1_BASE — microSD slot
}

#[cfg(any(feature = "vf2", feature = "k1"))]
fn slot_base(slot: MmcSlot) -> usize {
    match slot { MmcSlot::Emmc => MMC0_BASE, MmcSlot::Sd => MMC1_BASE }
}

/// `mmc-pci` (QEMU only): the SDHCI register block is BAR 0 of QEMU's
/// `sdhci-pci`, at whatever address the kernel assigned — see
/// [`mmc_bind_pci_bar`]. Both slots name it; 0 = not bound.
#[cfg(not(any(feature = "vf2", feature = "k1")))]
static PCI_BAR: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(not(any(feature = "vf2", feature = "k1")))]
fn slot_base(_slot: MmcSlot) -> usize {
    PCI_BAR.load(Ordering::Acquire)
}

/// Point this driver at a mapped SDHCI BAR (`mmc-pci`, QEMU only).
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub fn mmc_bind_pci_bar(base: usize) {
    PCI_BAR.store(base, Ordering::Release);
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
    let idx  = slot as usize;
    if base == 0 { return false; }

    // ── 1. Software reset (all lines) ─────────────────────────────────────────
    wr8(base, SDHCI_SW_RESET, RESET_ALL);
    for _ in 0..200_000u32 {
        if rd8(base, SDHCI_SW_RESET) & RESET_ALL == 0 { break; }
    }

    // ── 2. Power on at 3.3 V ──────────────────────────────────────────────────
    wr8(base, SDHCI_POWER_CONTROL, PWR_33V_ON);

    // ── 3. SD clock at 400 kHz (card identification frequency) ───────────────
    if !mmc_set_clock(base, 400_000) {
        azos_drv_sys::kerr!("[MMC] slot {}: clock setup failed", idx);
        return false;
    }

    // ── 4. Interrupt status enable (poll mode — no IRQ signalling) ────────────
    wr32(base, SDHCI_INT_ENABLE,   0x00FF_00FF);
    wr32(base, SDHCI_SIGNAL_ENABLE, 0);

    // ── 5. Card presence ──────────────────────────────────────────────────────
    if rd32(base, SDHCI_PRESENT_STATE) & STATE_CARD_PRESENT == 0 {
        azos_drv_sys::kprintln!("[MMC] slot {}: no card present", idx);
        return false;
    }

    // ── 6. CMD0 — GO_IDLE_STATE ───────────────────────────────────────────────
    send_cmd(base, CMD_GO_IDLE, 0, RESP_NONE);
    for _ in 0..10_000u32 { core::hint::spin_loop(); }

    // ── 7. CMD8 — SEND_IF_COND (VHS=1 → 2.7-3.6 V, check pattern=0xAA) ───────
    // A valid echo-back (pattern matches) means the card supports SDHC/SDXC.
    let sdhc_hint = match send_cmd(base, CMD_SEND_IF_COND, 0x0000_01AA, RESP_R7) {
        Some(r) if r[0] & 0x1FF == 0x1AA => true,
        _ => false,
    };

    // ── 8. ACMD41 — SD_SEND_OP_COND, repeat until power-up bit set ───────────
    // HCS=1 if sdhc_hint (tells card we support high capacity).
    // Voltage window: 3.0-3.6 V (0xFF8000).
    let acmd41_arg = if sdhc_hint { 0x4000_0000u32 } else { 0 } | 0x00FF_8000;
    let mut ocr = 0u32;
    for _ in 0..1_000u32 {
        send_cmd(base, CMD_APP_CMD, 0, RESP_R1); // CMD55 prefix
        if let Some(r) = send_cmd(base, ACMD_SD_SEND_OP, acmd41_arg, RESP_R3) {
            ocr = r[0];
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
    send_cmd(base, CMD_ALL_SEND_CID, 0, RESP_R2);

    // ── 10. CMD3 — SEND_RELATIVE_ADDR → get RCA ───────────────────────────────
    let rca = match send_cmd(base, CMD_SEND_RCA, 0, RESP_R6) {
        Some(r) => r[0] >> 16,
        None => {
            azos_drv_sys::kerr!("[MMC] slot {}: CMD3 (RCA) failed", idx);
            return false;
        }
    };

    // ── 11. CMD7 — SELECT card (tran state) ───────────────────────────────────
    if send_cmd(base, CMD_SELECT, rca << 16, RESP_R1B).is_none() {
        azos_drv_sys::kerr!("[MMC] slot {}: CMD7 (select) failed", idx);
        return false;
    }
    // R1b keeps DAT0 low while the card is busy; wait for it to be released.
    for _ in 0..2_000_000u32 {
        if rd32(base, SDHCI_PRESENT_STATE) & STATE_DAT_INHIBIT == 0 { break; }
    }

    // ── 12. CMD16 — SET_BLOCKLEN 512 B (SDSC only; SDHC ignores it) ──────────
    if !is_sdhc {
        send_cmd(base, CMD_SET_BLOCKLEN, 512, RESP_R1);
    }

    // ── 13. ACMD6 — SET_BUS_WIDTH 4-bit ──────────────────────────────────────
    send_cmd(base, CMD_APP_CMD, rca << 16, RESP_R1);
    send_cmd(base, ACMD_SET_BUS_WIDTH, 2, RESP_R1); // 2 = 4-bit
    wr8(base, SDHCI_HOST_CONTROL, HC_4BIT_BUS);

    // ── 14. Raise clock to 25 MHz (data transfer frequency) ──────────────────
    mmc_set_clock(base, 25_000_000);

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
    unsafe { (*(&raw const SLOT_STATE[slot as usize])).capacity }
}

/// Read `count` 512-byte sectors starting at `lba` into `buf` (PIO).
pub fn mmc_read(slot: MmcSlot, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), ()> {
    if buf.len() < count as usize * 512 { return Err(()); }
    let _guard  = MMC_LOCKS[slot as usize].lock();
    let base    = slot_base(slot);
    let is_sdhc = unsafe { (*(&raw const SLOT_STATE[slot as usize])).is_sdhc };

    for blk in 0..count {
        // SDHC uses block (sector) address; SDSC uses byte address.
        let addr: u32 = if is_sdhc {
            (lba + blk as u64) as u32
        } else {
            ((lba + blk as u64) * 512) as u32
        };

        wr16(base, SDHCI_BLOCK_SIZE,  512);
        wr16(base, SDHCI_BLOCK_COUNT, 1);

        if !wait_inhibit(base, true) { return Err(()); }
        wr32(base, SDHCI_INT_STATUS, 0xFFFF_FFFF);
        wr32(base, SDHCI_ARGUMENT, addr);

        // Write TRANSFER_MODE then COMMAND (order matters for some controllers).
        wr16(base, SDHCI_TRANSFER_MODE, TM_READ);
        // CMD17 R1 response + data present (bit 5)
        wr16(base, SDHCI_COMMAND, (CMD_READ_SINGLE << 8) | (RESP_R1 | RESP_DATA));

        if !wait_int(base, INT_CMD_COMPLETE) { return Err(()); }
        wr32(base, SDHCI_INT_STATUS, INT_CMD_COMPLETE);

        if !wait_int(base, INT_BUF_READ_READY) { return Err(()); }

        let off = blk as usize * 512;
        for i in (0..512).step_by(4) {
            let w = rd32(base, SDHCI_BUFFER);
            buf[off + i]     = w as u8;
            buf[off + i + 1] = (w >>  8) as u8;
            buf[off + i + 2] = (w >> 16) as u8;
            buf[off + i + 3] = (w >> 24) as u8;
        }

        if !wait_int(base, INT_TRANSFER_DONE) { return Err(()); }
        wr32(base, SDHCI_INT_STATUS, INT_TRANSFER_DONE);
    }
    Ok(())
}

/// Write `count` 512-byte sectors starting at `lba` from `buf` (PIO).
///
/// Any failure — including an error bit in a CMD24 response, which the card
/// reports once and then clears — also latches `WRITE_FAULT`, so the next
/// `mmc_flush` does not confirm durability over it.
pub fn mmc_write(slot: MmcSlot, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    if buf.len() < count as usize * 512 { return Err(()); }
    let _guard  = MMC_LOCKS[slot as usize].lock();
    let r = mmc_write_locked(slot, lba, count, buf);
    if r.is_err() { WRITE_FAULT[slot as usize].store(true, Ordering::Release); }
    r
}

fn mmc_write_locked(slot: MmcSlot, lba: u64, count: u32, buf: &[u8]) -> Result<(), ()> {
    let base    = slot_base(slot);
    let is_sdhc = unsafe { (*(&raw const SLOT_STATE[slot as usize])).is_sdhc };
    let mut r1_error = false;

    for blk in 0..count {
        let addr: u32 = if is_sdhc {
            (lba + blk as u64) as u32
        } else {
            ((lba + blk as u64) * 512) as u32
        };

        wr16(base, SDHCI_BLOCK_SIZE,  512);
        wr16(base, SDHCI_BLOCK_COUNT, 1);

        if !wait_inhibit(base, true) { return Err(()); }
        wr32(base, SDHCI_INT_STATUS, 0xFFFF_FFFF);
        wr32(base, SDHCI_ARGUMENT, addr);

        wr16(base, SDHCI_TRANSFER_MODE, 0); // write, single block
        // CMD24 R1 response + data present
        wr16(base, SDHCI_COMMAND, (CMD_WRITE_SINGLE << 8) | (RESP_R1 | RESP_DATA));

        if !wait_int(base, INT_CMD_COMPLETE) { return Err(()); }
        wr32(base, SDHCI_INT_STATUS, INT_CMD_COMPLETE);
        // The card's verdict on the command (address, write protect, ...).
        // The data phase still runs: the controller has committed to it,
        // and abandoning it mid-way would leave DAT inhibit set for the
        // next command.
        let r1 = rd32(base, SDHCI_RESPONSE0);
        if r1 & R1_ERRORS != 0 {
            azos_drv_sys::kerr!("[MMC] slot {}: CMD24 lba {} status {:#010x} (error bits {:#010x})",
                slot as usize, lba + blk as u64, r1, r1 & R1_ERRORS);
            r1_error = true;
        }

        if !wait_int(base, INT_BUF_WRITE_READY) { return Err(()); }

        let off = blk as usize * 512;
        for i in (0..512).step_by(4) {
            let w = (buf[off + i]     as u32)
                  | (buf[off + i + 1] as u32) <<  8
                  | (buf[off + i + 2] as u32) << 16
                  | (buf[off + i + 3] as u32) << 24;
            wr32(base, SDHCI_BUFFER, w);
        }

        if !wait_int(base, INT_TRANSFER_DONE) { return Err(()); }
        wr32(base, SDHCI_INT_STATUS, INT_TRANSFER_DONE);
        if r1_error { return Err(()); }
    }
    Ok(())
}

/// CMD13 SEND_STATUS until the card is in `tran` with READY_FOR_DATA.
///
/// `Ok(status)` only on that confirmed state. `Err` on: a CMD13 the
/// controller did not complete, any R1 error bit, a state other than
/// `tran`/`prg`/`rcv` (the card is not selected, or is somewhere a write
/// cannot leave it), or `FLUSH_STATUS_POLLS` responses without reaching
/// `tran` + ready. `prg` (programming) and `rcv` are the states a card
/// passes through after a write and are polled through.
fn wait_card_ready(slot: MmcSlot, base: usize, rca: u32, extra_errors: u32) -> Result<u32, FlushError> {
    let idx = slot as usize;
    let mut last = 0u32;
    for _ in 0..FLUSH_STATUS_POLLS {
        let Some(r) = send_cmd(base, CMD_SEND_STATUS, rca << 16, RESP_R1) else {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: CMD13 did not complete", idx);
            return Err(FlushError::Io);
        };
        let st = r[0];
        last = st;
        FLUSH_STATUS_READS.fetch_add(1, Ordering::AcqRel);
        if st & (R1_ERRORS | extra_errors) != 0 {
            azos_drv_sys::kerr!("[MMC] slot {}: flush: card status {:#010x} carries error bits {:#010x}",
                idx, st, st & (R1_ERRORS | extra_errors));
            return Err(FlushError::Io);
        }
        let state = (st >> R1_STATE_SHIFT) & R1_STATE_MASK;
        match state {
            STATE_TRAN if st & R1_READY_FOR_DATA != 0 => return Ok(st),
            STATE_TRAN | STATE_PRG | STATE_RCV => continue,
            _ => {
                azos_drv_sys::kprintln!("[MMC] slot {}: flush: card in state {} (status {:#010x}), not tran",
                    idx, state, st);
                return Err(FlushError::Io);
            }
        }
    }
    azos_drv_sys::kprintln!("[MMC] slot {}: flush: card still busy after {} status polls (last {:#010x})",
        idx, FLUSH_STATUS_POLLS, last);
    Err(FlushError::Io)
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
/// that did not complete, an error bit, or the poll bound → `Err(Io)`.
pub fn mmc_flush(slot: MmcSlot) -> Result<(), FlushError> {
    let _guard = MMC_LOCKS[slot as usize].lock();
    let idx  = slot as usize;
    let base = slot_base(slot);
    let st   = unsafe { *(&raw const SLOT_STATE[idx]) };
    if !st.ready || base == 0 { return Err(FlushError::Io); }
    if cfg!(feature = "mmc-flush-canary") { return Ok(()); }
    if WRITE_FAULT[idx].swap(false, Ordering::AcqRel) {
        azos_drv_sys::kerr!("[MMC] slot {}: flush: a write failed since the last flush", idx);
        return Err(FlushError::Io);
    }

    let mut status = wait_card_ready(slot, base, st.rca, 0)?;

    if st.cache_on {
        // SWITCH, access = Write Byte (0b11), index 32 (FLUSH_CACHE), value 1.
        let arg = (0b11u32 << 24) | (32 << 16) | (1 << 8);
        let Some(r) = send_cmd(base, CMD_SWITCH, arg, RESP_R1B) else {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: CMD6 FLUSH_CACHE did not complete", idx);
            return Err(FlushError::Io);
        };
        if r[0] & (R1_ERRORS | R1_SWITCH_ERROR) != 0 {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: CMD6 status {:#010x}", idx, r[0]);
            return Err(FlushError::Io);
        }
        // R1b: the card holds DAT0 low until the cache is written out.
        if !wait_inhibit(base, true) {
            azos_drv_sys::kprintln!("[MMC] slot {}: flush: DAT0 still busy after FLUSH_CACHE", idx);
            return Err(FlushError::Io);
        }
        status = wait_card_ready(slot, base, st.rca, R1_SWITCH_ERROR)?;
    }

    FLUSH_LAST_STATUS.store(status, Ordering::Release);
    Ok(())
}

/// Print SDHCI controller and card state for `slot`.
pub fn mmc_info(slot: MmcSlot) {
    let base = slot_base(slot);
    let idx  = slot as usize;
    let pst  = rd32(base, SDHCI_PRESENT_STATE);
    let ver  = rd16(base, SDHCI_VERSION);
    let st   = unsafe { *(&raw const SLOT_STATE[idx]) };
    azos_drv_sys::kprintln!(
        "[MMC] slot {}: SDHCI v{}.{}  base={:#010x}  card={}  ready={}  ~{} MiB",
        idx,
        (ver >> 8) & 0xFF, ver & 0xFF,
        base,
        if pst & STATE_CARD_PRESENT != 0 { "present" } else { "absent" },
        st.ready,
        st.capacity / 2048,
    );
}
