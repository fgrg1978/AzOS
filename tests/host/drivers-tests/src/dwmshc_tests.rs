// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `dwmshc.rs` (Synopsys DesignWare MSHC driver: IDMAC chain, command state
//! machine, interrupt completion, SD init) run on the host over a
//! register-level model of the controller and an SD card.
//!
//! The model is written from U-Boot's `dwmmc.h` / `dw_mmc.c` (the register
//! offsets and bits; see the driver's module doc for what is the databook's
//! instead) and the SD Physical Layer spec, not from the driver: its own
//! offsets, its own IDMAC that walks the descriptor chain the driver built out
//! of the "physical" pages the driver gave it, a clock unit that applies
//! CLKDIV/CLKENA only on an update-clock command, and a card that answers the
//! SD command set the driver uses. It refuses what the controller would refuse
//! (a command written while START is still set raises HLE, a response CRC
//! check on the OCR raises RCRC, a data command without the FIFO reset, the
//! IDMAC or the right CTYPE, a chain whose descriptors are not OWN|CH, FS first
//! and LD last, a card clock above 25 MHz on a card that is not in high speed)
//! and records what it saw, so a test asserts on the driver's behaviour, not
//! on its own bookkeeping.
//!
//! Time: a polled waiter makes the model's device progress with every read of
//! RINTSTS (`latency` reads per event); once the driver has switched the
//! controller to interrupt completion (CTRL.INT_ENABLE and INTMASK), reads no
//! longer advance it and the only thing that does is the driver sleeping
//! (`IrqHooks::block_until` -> `step`), after which the model's line is
//! asserted and the "interrupt controller" calls `dwmshc::irq_on`. A driver
//! that polled in interrupt mode would therefore never see its command
//! complete.
//!
//! Canaries (the three buckets): each behaviour has a twin that would go red
//! if the property did not hold. The read test flips a byte in the model's
//! DMA (`corrupt_dma`) and the same comparison must then fail; the capacity
//! test runs two card sizes and the old hardcoded constant fits neither; the
//! timeout and CRC tests run the identical sequence clean first; the HS test
//! runs a card that refuses the switch.

use super::dev_queue::IrqHooks;
use super::dwmshc::{self, AttachError, Node, Regs};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once};

const LINE: u32 = 0x4A;
const CIU_HZ: u32 = 100_000_000;
const FIFO_DEPTH: u32 = 32;

// ---- The model's own register map (U-Boot dwmmc.h) ----
const R_CTRL: usize = 0x000;
const R_PWREN: usize = 0x004;
const R_CLKDIV: usize = 0x008;
const R_CLKENA: usize = 0x010;
const R_TMOUT: usize = 0x014;
const R_CTYPE: usize = 0x018;
const R_BLKSIZ: usize = 0x01C;
const R_BYTCNT: usize = 0x020;
const R_INTMASK: usize = 0x024;
const R_CMDARG: usize = 0x028;
const R_CMD: usize = 0x02C;
const R_RESP0: usize = 0x030;
const R_MINTSTS: usize = 0x040;
const R_RINTSTS: usize = 0x044;
const R_STATUS: usize = 0x048;
const R_FIFOTH: usize = 0x04C;
const R_HCON: usize = 0x070;
const R_BMOD: usize = 0x080;
const R_DBADDR: usize = 0x088;
const R_DBADDRU: usize = 0x08C; // 64-bit mode
const R_IDSTS32: usize = 0x08C;
const R_IDINTEN32: usize = 0x090;
const R_IDSTS64: usize = 0x090;
const R_IDINTEN64: usize = 0x094;

const C_RESET: u32 = 1;
const C_FIFO_RESET: u32 = 2;
const C_DMA_RESET: u32 = 4;
const C_INT_EN: u32 = 1 << 4;
const C_DMA_EN: u32 = 1 << 5;
const C_IDMAC_EN: u32 = 1 << 25;

const CMD_RESP_EXP: u32 = 1 << 6;
const CMD_RESP_LEN: u32 = 1 << 7;
const CMD_CRC: u32 = 1 << 8;
const CMD_DATA: u32 = 1 << 9;
const CMD_WR: u32 = 1 << 10;
const CMD_PRV_WAIT: u32 = 1 << 13;
const CMD_ABORT: u32 = 1 << 14;
const CMD_INIT: u32 = 1 << 15;
const CMD_UPD_CLK: u32 = 1 << 21;
const CMD_START: u32 = 1 << 31;

const I_CDONE: u32 = 1 << 2;
const I_DTO: u32 = 1 << 3;
const I_RCRC: u32 = 1 << 6;
const I_DCRC: u32 = 1 << 7;
const I_RTO: u32 = 1 << 8;
const I_HLE: u32 = 1 << 12;

const ID_TI: u32 = 1;
const ID_RI: u32 = 2;

const D_OWN: u32 = 1 << 31;
const D_DIC: u32 = 1 << 1;
/// A staged IDSTS value carrying this bit (not an IDSTS bit) is the moment the
/// pages after the first have actually been moved.
const ID_LAND: u32 = 1 << 31;
const D_CH: u32 = 1 << 4;
const D_FS: u32 = 1 << 3;
const D_LD: u32 = 1 << 2;

const ST_IDLE: u32 = 0;
const ST_READY: u32 = 1;
const ST_IDENT: u32 = 2;
const ST_STBY: u32 = 3;
const ST_TRAN: u32 = 4;
const ST_PRG: u32 = 7;

const CARD_SECTORS: usize = 16384;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Fault {
    None,
    /// The next command is never answered: RTO (with Command Done).
    NoResponse,
    /// The next command's response fails its CRC check.
    ResponseCrc,
    /// The next data command ends with a data CRC error.
    DataCrc,
    /// The next command is taken and then nothing ever happens.
    Silent,
}

#[derive(Clone, Copy, Debug)]
struct Cfg {
    sdhc: bool,
    sectors: usize,
    /// The card answers CMD8 (SD 2.0+).
    v2: bool,
    /// The IDMAC takes 64-bit descriptors (HCON bit 27).
    dma64: bool,
    /// The card offers the high-speed function.
    hs: bool,
    /// No card in the socket: nothing answers.
    no_card: bool,
}

impl Cfg {
    fn sdhc() -> Cfg {
        Cfg { sdhc: true, sectors: CARD_SECTORS, v2: true, dma64: false, hs: true, no_card: false }
    }
}

#[derive(Clone, Debug)]
struct Cmd {
    idx: u32,
    arg: u32,
    flags: u32,
}

#[derive(Clone, Debug)]
struct Desc {
    control: u32,
    size: u32,
    buf: u64,
    next: u64,
}

/// One page move the IDMAC has not done yet: bounce page, length, card offset, direction.
struct Late {
    mem: usize,
    len: usize,
    card_off: usize,
    read: bool,
}

struct Inner {
    cfg: Cfg,
    regs: [u32; 0x100],
    rint: u32,
    ids: u32,
    stages: VecDeque<(u32, u32)>,
    poll_reads: u32,
    start_left: u32,
    // clock unit
    clk_div_applied: u32,
    clk_ena_applied: bool,
    clock_hist: Vec<u32>,
    // card
    card: Vec<u8>,
    state: u32,
    rca: u32,
    app: bool,
    acmd41_polls: u32,
    prg_left: u32,
    width4: bool,
    card_hs: bool,
    busy_reads: u32,
    // knobs
    latency: u32,
    prg_polls: u32,
    fault: Fault,
    corrupt_dma: bool,
    dma_first: bool,
    /// Copies of the chain's pages after the first, applied when ID_LAND is released.
    late: Vec<Late>,
    /// Canary: the model sees every descriptor as if the driver had left DIC clear.
    strip_dic: bool,
    /// Descriptors of the last chain that raise TI/RI (no DIC).
    irq_descs: usize,
    write_status_error: u32,
    /// ACMD41 never reports power-up.
    never_ready: bool,
    /// Called when a data command starts (the cache test's timeline marker).
    on_data_cmd: Option<fn()>,
    /// A controller reset also clears the interrupt enables (what the databook
    /// does not promise either way).
    reset_clears_irq: bool,
    // evidence
    cmds: Vec<Cmd>,
    descs: Vec<Desc>,
    ctrl_resets: u32,
    fifo_reset_pending: bool,
    bytcnts: Vec<u32>,
    violations: Vec<String>,
}

struct Mock {
    inner: Mutex<Inner>,
    /// The window's address as the driver sees it (names the controller to
    /// the DMA domain registry).
    base: AtomicUsize,
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// The model's own CSD builder (SD spec field positions), 128 bits.
fn csd_for(cfg: &Cfg) -> u128 {
    let ccc: u128 = 0x5B5; // classes 0, 2, 4, 5, 7, 8, 10
    if cfg.sdhc {
        let c_size = (cfg.sectors / 1024 - 1) as u128;
        (1u128 << 126) | (ccc << 84) | (9u128 << 80) | (c_size << 48)
    } else {
        // CSD 1.0 with 512-byte read blocks: capacity = (C_SIZE+1) * 2^(MULT+2) blocks.
        let blocks = cfg.sectors as u128;
        let mult = 7u128; // 2^9
        let c_size = blocks / (1 << (mult + 2)) - 1;
        (ccc << 84) | (9u128 << 80) | (c_size << 62) | (mult << 47)
    }
}

impl Inner {
    fn violation(&mut self, what: impl Into<String>) {
        self.violations.push(what.into());
    }

    fn idsts_off(&self) -> usize {
        if self.cfg.dma64 { R_IDSTS64 } else { R_IDSTS32 }
    }
    fn idinten_off(&self) -> usize {
        if self.cfg.dma64 { R_IDINTEN64 } else { R_IDINTEN32 }
    }

    /// One staged event becomes visible (raw status: whatever the driver
    /// enabled or not).
    fn release_one(&mut self) -> bool {
        self.poll_reads = 0;
        match self.stages.pop_front() {
            Some((r, i)) => {
                self.rint |= r;
                if i & ID_LAND != 0 {
                    self.land();
                }
                self.ids |= i & !ID_LAND;
                true
            }
            None => false,
        }
    }

    /// The IDMAC finishes the pages it was still moving.
    fn land(&mut self) {
        for l in std::mem::take(&mut self.late) {
            let mem = l.mem as *mut u8;
            // SAFETY: `mem` is a bounce page the driver allocated, `len <= 4096`.
            unsafe {
                if l.read {
                    std::ptr::copy_nonoverlapping(self.card[l.card_off..].as_ptr(), mem, l.len);
                } else {
                    std::ptr::copy_nonoverlapping(mem, self.card[l.card_off..].as_mut_ptr(), l.len);
                }
            }
        }
    }

    fn irq_mode(&self) -> bool {
        self.regs[R_CTRL / 4] & C_INT_EN != 0 && self.regs[R_INTMASK / 4] != 0
    }

    fn r1(&self, errors: u32) -> u32 {
        let ready = if self.state == ST_PRG { 0 } else { 1 << 8 };
        (self.state << 9) | ready | errors
    }

    fn respond(&mut self, r: [u32; 4]) {
        // The long response comes out RESP3 first: word 0 of the 128-bit value
        // is RESP3.
        self.regs[R_RESP0 / 4 + 3] = r[0];
        self.regs[R_RESP0 / 4 + 2] = r[1];
        self.regs[R_RESP0 / 4 + 1] = r[2];
        self.regs[R_RESP0 / 4] = r[3];
    }

    fn respond_short(&mut self, v: u32) {
        self.regs[R_RESP0 / 4] = v;
    }

    fn card_clock_hz(&self) -> u32 {
        if self.clk_div_applied == 0 { CIU_HZ } else { CIU_HZ / (2 * self.clk_div_applied) }
    }

    fn write_cmd(&mut self, v: u32) {
        if self.start_left > 0 {
            // START is still set: the controller ignores the write and flags it.
            self.violation("CMD written while START was still set (hardware locked error)");
            self.rint |= I_HLE;
            return;
        }
        self.regs[R_CMD / 4] = v;
        if v & CMD_START == 0 {
            self.violation("CMD written without START");
            return;
        }
        self.start_left = 2;
        if v & CMD_UPD_CLK != 0 {
            self.clk_div_applied = self.regs[R_CLKDIV / 4];
            self.clk_ena_applied = self.regs[R_CLKENA / 4] & 1 != 0;
            if self.clk_ena_applied {
                let hz = self.card_clock_hz();
                if self.clock_hist.last() != Some(&hz) {
                    self.clock_hist.push(hz);
                }
            }
            return;
        }
        self.exec(v);
    }

    fn exec(&mut self, cmdreg: u32) {
        let idx = cmdreg & 0x3F;
        let arg = self.regs[R_CMDARG / 4];
        self.cmds.push(Cmd { idx, arg, flags: cmdreg });

        if self.cfg.no_card {
            self.stages.push_back((I_CDONE | I_RTO, 0));
            return;
        }
        if self.regs[R_PWREN / 4] & 1 == 0 {
            self.violation("command with the card slot unpowered");
        }
        if !self.clk_ena_applied {
            self.violation(format!("CMD{idx} with the card clock off (no update-clock after CLKENA)"));
        }
        if self.card_clock_hz() > 25_000_000 && !self.card_hs {
            self.violation(format!("card clock {} Hz on a card not in high speed", self.card_clock_hz()));
        }
        if idx != 12 && self.busy_reads > 0 {
            self.violation(format!("CMD{idx} issued while the card holds DAT0 low"));
        }
        if self.regs[R_TMOUT / 4] == 0 {
            self.violation("no timeout programmed");
        }
        match self.fault {
            Fault::NoResponse => {
                self.fault = Fault::None;
                self.stages.push_back((I_CDONE | I_RTO, 0));
                return;
            }
            Fault::ResponseCrc => {
                self.fault = Fault::None;
                self.stages.push_back((I_CDONE | I_RCRC, 0));
                return;
            }
            Fault::Silent => {
                self.fault = Fault::None;
                return;
            }
            _ => {}
        }

        let app = std::mem::replace(&mut self.app, false);
        let want_resp = match (app, idx) {
            (_, 0) => 0,
            (_, 2) | (_, 9) => CMD_RESP_EXP | CMD_RESP_LEN | CMD_CRC,
            (true, 41) => CMD_RESP_EXP,
            _ => CMD_RESP_EXP | CMD_CRC,
        };
        let got_resp = cmdreg & (CMD_RESP_EXP | CMD_RESP_LEN | CMD_CRC);
        if got_resp != want_resp {
            if app && idx == 41 && got_resp & CMD_CRC != 0 {
                // The OCR has no CRC: a CRC check on it fails.
                self.stages.push_back((I_CDONE | I_RCRC, 0));
                self.violation("CRC check requested on the R3 response");
                return;
            }
            self.violation(format!("CMD{idx}: response flags {got_resp:#x}, expected {want_resp:#x}"));
        }
        if idx == 0 && cmdreg & CMD_INIT == 0 {
            self.violation("CMD0 without the initialisation clocks");
        }
        if idx == 12 {
            if cmdreg & CMD_ABORT == 0 {
                self.violation("CMD12 without the abort flag");
            }
        } else if cmdreg & CMD_ABORT != 0 {
            self.violation(format!("CMD{idx} with the abort flag"));
        } else if cmdreg & CMD_PRV_WAIT == 0 {
            self.violation(format!("CMD{idx} without wait-previous-data"));
        }

        let mut errors = 0u32;
        let mut dir_read = false;
        let mut data = false;
        let mut start = 0usize;
        let mut nblk = 0usize;
        let mut status_block: Option<[u8; 64]> = None;
        let mut busy = false;

        match (app, idx) {
            (_, 0) => {
                self.state = ST_IDLE;
            }
            (_, 8) => {
                if !self.cfg.v2 {
                    self.stages.push_back((I_CDONE | I_RTO, 0));
                    return;
                }
                self.respond_short(arg & 0x1FF);
            }
            (_, 55) => {
                self.app = true;
                let v = self.r1(1 << 5);
                self.respond_short(v);
            }
            (true, 41) => {
                self.acmd41_polls += 1;
                let up = if !self.never_ready && self.acmd41_polls >= 3 { 1u32 << 31 } else { 0 };
                let hcs = arg & 0x4000_0000 != 0;
                if self.cfg.sdhc && !hcs {
                    self.violation("ACMD41 without HCS on a v2 card (CMD8 answered)");
                }
                self.respond_short(up | 0x00FF_8000 | if self.cfg.sdhc { 1 << 30 } else { 0 });
                if up != 0 {
                    self.state = ST_READY;
                }
            }
            (_, 2) => {
                self.respond([0x0123_4567, 0x89AB_CDEF, 0x1357_9BDF, 0x0246_8ACE]);
                self.state = ST_IDENT;
            }
            (_, 3) => {
                self.rca = 0x1234;
                self.respond_short(self.rca << 16);
                self.state = ST_STBY;
            }
            (_, 9) => {
                if arg >> 16 != self.rca {
                    self.violation("CMD9 not addressed to the RCA");
                }
                let w = csd_for(&self.cfg);
                self.respond([(w >> 96) as u32, (w >> 64) as u32, (w >> 32) as u32, w as u32]);
            }
            (_, 7) => {
                self.state = ST_TRAN;
                let v = self.r1(0);
                self.respond_short(v);
                busy = true;
            }
            (_, 16) => {
                if self.cfg.sdhc {
                    self.violation("CMD16 on an SDHC card");
                }
                let v = self.r1(0);
                self.respond_short(v);
            }
            (true, 6) => {
                self.width4 = arg & 3 == 2;
                let v = self.r1(0);
                self.respond_short(v);
            }
            (false, 6) => {
                // SWITCH_FUNC: a 64-byte status block.
                let mut s = [0u8; 64];
                if arg & 0x8000_0000 == 0 {
                    if self.cfg.hs {
                        s[13] = 0x02;
                    }
                } else if self.cfg.hs && arg & 0xF == 1 {
                    s[16] = 1;
                    self.card_hs = true;
                } else {
                    s[16] = 0xF;
                }
                status_block = Some(s);
                data = true;
                dir_read = true;
                nblk = 0;
                let v = self.r1(0);
                self.respond_short(v);
            }
            (_, 12) => {
                let v = self.r1(0);
                self.respond_short(v);
                busy = true;
                if self.state == ST_PRG {
                    // The stop ends the transfer; programming continues.
                }
            }
            (_, 13) => {
                let v = self.r1(0);
                self.respond_short(v);
                if self.state == ST_PRG {
                    self.prg_left = self.prg_left.saturating_sub(1);
                    if self.prg_left == 0 {
                        self.state = ST_TRAN;
                    }
                }
            }
            (_, 17) | (_, 18) | (_, 24) | (_, 25) => {
                dir_read = idx == 17 || idx == 18;
                let multi = idx == 18 || idx == 25;
                data = true;
                let bytcnt = self.regs[R_BYTCNT / 4] as usize;
                nblk = bytcnt / 512;
                let sector = if self.cfg.sdhc { arg as usize } else { arg as usize / 512 };
                if !self.cfg.sdhc && arg % 512 != 0 {
                    self.violation(format!("SDSC byte address {arg:#x} is not sector aligned"));
                }
                if self.state != ST_TRAN {
                    self.violation(format!("data command in card state {}", self.state));
                }
                if bytcnt % 512 != 0 || nblk == 0 {
                    self.violation(format!("byte count {bytcnt} is not whole sectors"));
                }
                if self.regs[R_BLKSIZ / 4] != 512 {
                    self.violation("block size is not 512");
                }
                if multi != (nblk > 1) {
                    self.violation("multi-block command disagrees with the byte count");
                }
                if sector + nblk > self.cfg.sectors {
                    errors |= 1 << 30; // ADDRESS_ERROR
                } else {
                    start = sector * 512;
                }
                if (cmdreg & CMD_WR != 0) == dir_read {
                    self.violation("write bit disagrees with the command");
                }
                if self.write_status_error != 0 && !dir_read {
                    errors |= self.write_status_error;
                }
                let v = self.r1(errors);
                self.respond_short(v);
            }
            _ => self.violation(format!("unexpected command {idx} (app {app})")),
        }

        if data {
            if cmdreg & CMD_DATA == 0 {
                self.violation("data command without DATA_EXP");
            }
            let ctrl = self.regs[R_CTRL / 4];
            if ctrl & C_IDMAC_EN == 0 || ctrl & C_DMA_EN == 0 {
                self.violation(format!("data command without the IDMAC enabled (CTRL {ctrl:#x})"));
            }
            if self.regs[R_BMOD / 4] & (1 << 7) == 0 {
                self.violation("data command without BMOD.DE");
            }
            if !std::mem::replace(&mut self.fifo_reset_pending, false) {
                self.violation("data command without a FIFO reset before it");
            }
            if (self.regs[R_CTYPE / 4] & 1 != 0) != self.width4 {
                self.violation("CTYPE disagrees with the bus width the card was given");
            }
            self.bytcnts.push(self.regs[R_BYTCNT / 4]);
            if let Some(f) = self.on_data_cmd {
                f();
            }
        } else if cmdreg & CMD_DATA != 0 {
            self.violation(format!("CMD{idx} with DATA_EXP"));
        }

        let mut stages: Vec<(u32, u32)> = vec![(I_CDONE, 0)];
        if data {
            let fault = std::mem::replace(&mut self.fault, Fault::None);
            let bytes = if let Some(_) = status_block { 64 } else { nblk * 512 };
            let ok = errors == 0;
            let walked = self.run_idmac(bytes, dir_read, start, ok, status_block);
            let ids = if dir_read { ID_RI } else { ID_TI };
            match (fault, walked) {
                (Fault::DataCrc, _) | (_, Err(())) => {
                    self.land();
                    stages.push((I_DCRC, 0));
                }
                _ => {
                    // One TI/RI per descriptor without DIC; the last one is the
                    // chain's end and the moment the late pages have landed. A
                    // first one comes before the transfer-over event when the
                    // IDMAC is early, or when several descriptors raise it.
                    let evs = self.irq_descs.max(1);
                    let before = if self.dma_first || evs > 1 { 1 } else { 0 };
                    for k in 0..evs {
                        let v = if k + 1 == evs { ids | ID_LAND } else { ids };
                        if k == before {
                            stages.push((I_DTO, 0));
                        }
                        stages.push((0, v));
                    }
                    if before == evs {
                        stages.push((I_DTO, 0));
                    }
                    if !dir_read && ok && self.prg_polls > 0 {
                        self.state = ST_PRG;
                        self.prg_left = self.prg_polls;
                    }
                    if !dir_read && ok {
                        self.busy_reads = 2;
                    }
                }
            }
        }
        if busy {
            self.busy_reads = self.busy_reads.max(2);
        }
        self.stages.extend(stages);
    }

    /// The IDMAC: walk the chain at DBADDR (the model's own descriptor layout),
    /// moving `bytes` between the pages it names and the card.
    fn run_idmac(&mut self, bytes: usize, dir_read: bool, start: usize, apply: bool, status: Option<[u8; 64]>) -> Result<(), ()> {
        let lo = self.regs[R_DBADDR / 4] as u64;
        let hi = if self.cfg.dma64 { self.regs[R_DBADDRU / 4] as u64 } else { 0 };
        let table = (hi << 32) | lo;
        let stride = if self.cfg.dma64 { 32usize } else { 16 };
        let mut done = 0usize;
        let mut n = 0usize;
        self.irq_descs = 0;
        loop {
            let at = azos_mm::addr::phys_to_virt((table as usize) + n * stride);
            let mut d = [0u8; 32];
            // SAFETY: the table is a page the driver got from the allocator.
            unsafe { std::ptr::copy_nonoverlapping(at as *const u8, d.as_mut_ptr(), stride) };
            let desc = if self.cfg.dma64 {
                Desc {
                    control: le32(&d[0..]),
                    size: le32(&d[8..]),
                    buf: le32(&d[16..]) as u64 | (le32(&d[20..]) as u64) << 32,
                    next: le32(&d[24..]) as u64 | (le32(&d[28..]) as u64) << 32,
                }
            } else {
                Desc { control: le32(&d[0..]), size: le32(&d[4..]), buf: le32(&d[8..]) as u64, next: le32(&d[12..]) as u64 }
            };
            let mut desc = desc;
            if self.strip_dic {
                desc.control &= !D_DIC;
            }
            self.descs.push(desc.clone());
            if desc.control & D_OWN == 0 {
                self.violation("descriptor not owned by the IDMAC");
                return Err(());
            }
            if desc.control & D_CH == 0 {
                self.violation("descriptor without CH: not a chain");
                return Err(());
            }
            if (desc.control & D_FS != 0) != (n == 0) {
                self.violation("FS is not on the first descriptor alone");
                return Err(());
            }
            if desc.next != table + ((n + 1) * stride) as u64 {
                self.violation(format!("descriptor {n} does not chain to the next one ({:#x})", desc.next));
                return Err(());
            }
            if desc.control & D_DIC == 0 {
                self.irq_descs += 1;
                if desc.control & D_LD == 0 {
                    self.violation(format!("descriptor {n} raises TI/RI before the chain is done (no DIC)"));
                }
            }
            let len = desc.size as usize;
            if len == 0 || len > 8191 {
                self.violation(format!("descriptor size {len} does not fit BS1"));
                return Err(());
            }
            let take = len.min(bytes - done);
            if take != len {
                self.violation("descriptors name more than the byte count");
                return Err(());
            }
            let mem = azos_mm::addr::phys_to_virt(desc.buf as usize) as *mut u8;
            if apply && n > 0 && status.is_none() {
                // The pages after the first are still in flight until ID_LAND.
                self.late.push(Late { mem: mem as usize, len, card_off: start + done, read: dir_read });
            } else if apply {
                // SAFETY: `mem` is a bounce page the driver allocated, `len <= 4096`.
                unsafe {
                    if let Some(s) = status {
                        std::ptr::copy_nonoverlapping(s.as_ptr(), mem, len.min(64));
                    } else if dir_read {
                        std::ptr::copy_nonoverlapping(self.card[start + done..].as_ptr(), mem, len);
                        if self.corrupt_dma && done == 0 {
                            *mem ^= 0xFF;
                        }
                    } else {
                        std::ptr::copy_nonoverlapping(mem, self.card[start + done..].as_mut_ptr(), len);
                    }
                }
            }
            // The IDMAC gives the descriptor back.
            let own_cleared = (desc.control & !D_OWN).to_le_bytes();
            // SAFETY: as above, the descriptor is ours to write in the model.
            unsafe { std::ptr::copy_nonoverlapping(own_cleared.as_ptr(), at as *mut u8, 4) };
            done += len;
            n += 1;
            if desc.control & D_LD != 0 {
                if done != bytes {
                    self.violation(format!("chain ended (LD) after {done} of {bytes} bytes"));
                    return Err(());
                }
                return Ok(());
            }
            if done >= bytes {
                self.violation("all data moved but the last descriptor is not LD");
                return Err(());
            }
        }
    }
}

impl Mock {
    fn new(cfg: Cfg) -> Self {
        let mut i = Inner {
            cfg,
            regs: [0; 0x100],
            rint: 0,
            ids: 0,
            stages: VecDeque::new(),
            poll_reads: 0,
            start_left: 0,
            clk_div_applied: 0,
            clk_ena_applied: false,
            clock_hist: Vec::new(),
            card: vec![0; cfg.sectors * 512],
            state: ST_IDLE,
            rca: 0,
            app: false,
            acmd41_polls: 0,
            prg_left: 0,
            width4: false,
            card_hs: false,
            busy_reads: 0,
            latency: 2,
            prg_polls: 0,
            fault: Fault::None,
            corrupt_dma: false,
            dma_first: false,
            late: Vec::new(),
            strip_dic: false,
            irq_descs: 0,
            write_status_error: 0,
            never_ready: false,
            reset_clears_irq: false,
            on_data_cmd: None,
            cmds: Vec::new(),
            descs: Vec::new(),
            ctrl_resets: 0,
            fifo_reset_pending: false,
            bytcnts: Vec::new(),
            violations: Vec::new(),
        };
        // Whatever the bootloader left in FIFOTH: the driver must not trust it.
        i.regs[R_FIFOTH / 4] = (2 << 28) | (7 << 16) | 8;
        Mock { inner: Mutex::new(i), base: AtomicUsize::new(0xD00D_0000) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.inner.lock().unwrap())
    }

    /// Let one pending event happen (the device ran while the driver slept).
    fn step(&self) -> bool {
        self.with(|i| i.release_one())
    }

    /// Is the interrupt line asserted?
    fn irq_asserted(&self) -> bool {
        self.with(|i| {
            let ctrl = i.regs[R_CTRL / 4];
            let ids_en = i.regs[i.idinten_off() / 4];
            ctrl & C_INT_EN != 0 && ((i.rint & i.regs[R_INTMASK / 4]) != 0 || (i.ids & ids_en) != 0)
        })
    }

    fn card_read(&self, byte_off: usize, len: usize) -> Vec<u8> {
        self.with(|i| i.card[byte_off..byte_off + len].to_vec())
    }
}

impl Regs for Mock {
    fn base(&self) -> usize {
        self.base.load(Ordering::SeqCst)
    }

    fn rd32(&self, off: usize) -> u32 {
        self.with(|i| match off {
            R_RINTSTS => {
                if !i.irq_mode() {
                    i.poll_reads += 1;
                    if i.poll_reads >= i.latency {
                        i.release_one();
                    }
                }
                i.rint
            }
            R_MINTSTS => i.rint & i.regs[R_INTMASK / 4],
            R_CMD => {
                if i.start_left > 0 {
                    i.start_left -= 1;
                    if i.start_left == 0 {
                        i.regs[R_CMD / 4] &= !CMD_START;
                    }
                }
                i.regs[R_CMD / 4]
            }
            R_STATUS => {
                if i.busy_reads > 0 {
                    i.busy_reads -= 1;
                    1 << 9
                } else {
                    0
                }
            }
            R_HCON => if i.cfg.dma64 { 1 << 27 } else { 0 },
            o if o == R_IDSTS32 && !i.cfg.dma64 => i.ids,
            o if o == R_IDSTS64 && i.cfg.dma64 => i.ids,
            _ => i.regs[off / 4],
        })
    }

    fn wr32(&self, off: usize, val: u32) {
        self.with(|i| match off {
            R_CTRL => {
                if i.regs[R_CTRL / 4] & C_DMA_EN != 0 && val & C_DMA_EN == 0 && !i.late.is_empty() {
                    let n = i.late.len();
                    i.violation(format!("DMA disabled with {n} page(s) still in flight (the driver stopped at the first TI/RI)"));
                }
                if val & C_FIFO_RESET != 0 {
                    i.fifo_reset_pending = true;
                }
                if val & (C_RESET | C_DMA_RESET) != 0 {
                    i.ctrl_resets += 1;
                    i.stages.clear();
                    i.late.clear();
                    i.rint = 0;
                    i.ids = 0;
                    i.start_left = 0;
                    i.regs[R_CMD / 4] &= !CMD_START;
                    i.busy_reads = 0;
                }
                // The reset bits are self-clearing.
                i.regs[R_CTRL / 4] = val & !(C_RESET | C_FIFO_RESET | C_DMA_RESET);
                if val & (C_RESET | C_DMA_RESET) != 0 && i.reset_clears_irq {
                    i.regs[R_INTMASK / 4] = 0;
                    let off = i.idinten_off();
                    i.regs[off / 4] = 0;
                    i.regs[R_CTRL / 4] &= !C_INT_EN;
                }
            }
            R_BMOD => i.regs[R_BMOD / 4] = val & !1,
            R_RINTSTS => i.rint &= !val,
            R_CMD => i.write_cmd(val),
            o if o == i.idsts_off() => i.ids &= !val,
            _ => i.regs[off / 4] = val,
        })
    }
}

// ---- Harness ----

static CUR: Mutex<Option<Arc<Mock>>> = Mutex::new(None);
static BLOCKS: AtomicU32 = AtomicU32::new(0);
static WAKES: AtomicU32 = AtomicU32::new(0);
static WOKEN_TID: AtomicU32 = AtomicU32::new(0);

const TEST_TID: u32 = 9;

/// While set, the device finishes (and its interrupt is taken) at the moment
/// the driver asks who is sleeping: after its last look at the status, before
/// the waiter is listed, so the handler finds nobody to wake.
static EVENT_IN_THE_WINDOW: AtomicBool = AtomicBool::new(false);

fn t_tid() -> u32 {
    if EVENT_IN_THE_WINDOW.load(Ordering::SeqCst) {
        let m = CUR.lock().unwrap().clone().expect("a model is installed");
        if m.step() && m.irq_asserted() {
            dwmshc::irq_on(&*m);
        }
    }
    TEST_TID
}

/// The driver sleeps: time passes, the device finishes something, and if it
/// raised its line the interrupt handler runs.
fn t_block(_deadline: u64) -> bool {
    BLOCKS.fetch_add(1, Ordering::SeqCst);
    let m = CUR.lock().unwrap().clone().expect("a model is installed");
    if m.step() && m.irq_asserted() {
        dwmshc::irq_on(&*m);
    }
    true
}

fn t_wake(tid: u32) {
    WAKES.fetch_add(1, Ordering::SeqCst);
    WOKEN_TID.store(tid, Ordering::SeqCst);
}

static HOOKS: IrqHooks = IrqHooks { tid: t_tid, block_until: t_block, wake: t_wake };

static SERIAL: Mutex<()> = Mutex::new(());

/// The DMA cache-maintenance hooks are process-wide: the tests that install
/// theirs (this file's and `mmc_tests.rs`'s) take this one.
pub(crate) static CACHE_HOOKS: Mutex<()> = Mutex::new(());
static ATTACH: Once = Once::new();

fn attach_once() {
    ATTACH.call_once(|| {
        dwmshc::attach(Node { base: 0xBEEF_0000, line: LINE, ciu_hz: CIU_HZ, fifo_depth: FIFO_DEPTH }).expect("attach");
    });
}

/// A fresh model with the card initialised through the driver, polled. The
/// driver's state is process-wide, so the tests run one at a time.
fn setup(cfg: Cfg) -> (MutexGuard<'static, ()>, Arc<Mock>) {
    let guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    attach_once();
    azos_mm::pmm::use_low_phys(true);
    let m = Arc::new(Mock::new(cfg));
    *CUR.lock().unwrap() = Some(m.clone());
    dwmshc::irq_off_on(&*m);
    assert!(dwmshc::init_on(&*m), "card initialisation");
    (guard, m)
}

fn pattern(sectors: usize, seed: u8) -> Vec<u8> {
    (0..sectors * 512).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed).wrapping_add((i >> 9) as u8)).collect()
}

fn counts() -> (u32, u32, u32, u32) {
    let (taken, slept) = dwmshc::irq_counts();
    (BLOCKS.load(Ordering::SeqCst), WAKES.load(Ordering::SeqCst), taken, slept)
}

fn clean(m: &Mock) {
    m.with(|i| assert!(i.violations.is_empty(), "the model saw: {:?}", i.violations));
}

fn idx_of(m: &Mock) -> Vec<u32> {
    m.with(|i| i.cmds.iter().map(|c| c.idx).collect())
}

// ---- Pure pieces ----

#[test]
fn idmac_descriptors_are_the_u_boot_layout() {
    // DES0 OWN|CH|FS|LD, DES1 size, DES2 buffer, DES3 next.
    let d = dwmshc::idmac_desc32(0x8000_001C, 4096, 0x4000_2000, 0x4000_1010);
    assert_eq!(d, [0x1C, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x20, 0x00, 0x40, 0x10, 0x10, 0x00, 0x40]);
    // The 64-bit form: DES1 and DES3 reserved, size in DES2, 64-bit buffer in DES4/5, next in DES6/7.
    let d = dwmshc::idmac_desc64(0x8000_0010, 2560, 0x1_4000_3000, 0x1_4000_1020);
    assert_eq!(&d[0..4], &[0x10, 0x00, 0x00, 0x80]);
    assert_eq!(&d[4..8], &[0; 4], "DES1 reserved");
    assert_eq!(&d[8..12], &2560u32.to_le_bytes());
    assert_eq!(&d[12..16], &[0; 4], "DES3 reserved");
    assert_eq!(&d[16..24], &0x1_4000_3000u64.to_le_bytes());
    assert_eq!(&d[24..32], &0x1_4000_1020u64.to_le_bytes());
}

#[test]
fn the_card_clock_divider_takes_the_highest_rate_not_above_the_target() {
    // card clock = ciu / (2 * div), div 0 = bypass.
    assert_eq!(dwmshc::clock_divider(100_000_000, 400_000), Some(125)); // exactly 400 kHz
    assert_eq!(dwmshc::clock_divider(100_000_000, 25_000_000), Some(2)); // 25 MHz
    assert_eq!(dwmshc::clock_divider(100_000_000, 50_000_000), Some(1)); // 50 MHz
    assert_eq!(dwmshc::clock_divider(50_000_000, 50_000_000), Some(0), "bypass");
    assert_eq!(dwmshc::clock_divider(30_000_000, 50_000_000), Some(0), "never above what the ciu has");
    // Rounds up, so the card clock never exceeds the target.
    assert_eq!(dwmshc::clock_divider(100_000_000, 30_000_000), Some(2));
    assert!(100_000_000 / (2 * 2) <= 30_000_000);
    // Out of reach of the 8-bit divider.
    assert_eq!(dwmshc::clock_divider(400_000_000, 400_000), None);
    assert_eq!(dwmshc::clock_divider(100_000_000, 0), None);
}

#[test]
fn the_csd_gives_the_card_size_for_both_structures() {
    let words = |w: u128| [(w >> 96) as u32, (w >> 64) as u32, (w >> 32) as u32, w as u32];
    for sectors in [8192usize, 16384, 1 << 20, 62_333_952] {
        let cfg = Cfg { sectors, ..Cfg::sdhc() };
        assert_eq!(dwmshc::csd_sectors(&words(csd_for(&cfg))), Some(sectors as u64), "CSD 2.0, {sectors} sectors");
    }
    for sectors in [8192usize, 16384, 1 << 17] {
        let cfg = Cfg { sdhc: false, sectors, ..Cfg::sdhc() };
        assert_eq!(dwmshc::csd_sectors(&words(csd_for(&cfg))), Some(sectors as u64), "CSD 1.0, {sectors} sectors");
    }
    // CSD 1.0 with 1 KiB read blocks: 2 sectors per block.
    let w = (10u128 << 80) | (99u128 << 62) | (2u128 << 47); // (99+1) << 4 = 1600 blocks of 1 KiB
    assert_eq!(dwmshc::csd_sectors(&words(w)), Some(3200));
    // A structure the driver does not know (SDUC): refused, not misread.
    assert_eq!(dwmshc::csd_sectors(&words(2u128 << 126)), None);
}

// ---- Attach ----

#[test]
fn attach_serves_one_controller_and_refuses_an_unusable_node() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    attach_once();
    let ok = Node { base: 0x1602_0000, line: 75, ciu_hz: CIU_HZ, fifo_depth: FIFO_DEPTH };
    assert_eq!(dwmshc::attach(ok), Err(AttachError::Busy), "one controller");
    assert_eq!(dwmshc::attach(Node { base: 0, ..ok }), Err(AttachError::Invalid));
    assert_eq!(dwmshc::attach(Node { ciu_hz: 0, ..ok }), Err(AttachError::Invalid), "no clock rate");
    assert_eq!(dwmshc::attach(Node { fifo_depth: 0, ..ok }), Err(AttachError::Invalid));
    assert_eq!(dwmshc::attach(Node { fifo_depth: 1 << 20, ..ok }), Err(AttachError::Invalid));
    assert!(dwmshc::attached());
}

// ---- Init ----

#[test]
fn init_walks_the_sd_sequence_and_ends_in_high_speed() {
    let (_g, m) = setup(Cfg::sdhc());
    assert_eq!(
        idx_of(&m),
        vec![0, 8, 55, 41, 55, 41, 55, 41, 2, 3, 9, 7, 55, 6, 6, 6],
        "CMD0, CMD8, ACMD41 until powered up, CMD2, CMD3, CMD9, CMD7, ACMD6, CMD6 check, CMD6 switch"
    );
    m.with(|i| {
        assert_eq!(i.regs[R_PWREN / 4], 1);
        assert_eq!(i.regs[R_CTYPE / 4], 1, "4-bit bus in the controller too");
        assert!(i.width4, "and in the card");
        assert_eq!(i.regs[R_FIFOTH / 4], (2 << 28) | (15 << 16) | 16, "watermarks from the node's depth, not the bootloader's leftovers");
        assert_eq!(i.clock_hist, vec![400_000, 25_000_000, 50_000_000], "identification, default speed, high speed");
        assert!(i.card_hs);
        assert_eq!(i.regs[R_INTMASK / 4], 0, "polled: nothing armed");
        assert_eq!(i.regs[R_CTRL / 4] & C_INT_EN, 0);
        assert_eq!(i.regs[R_CLKENA / 4], 1 | (1 << 16), "enabled, low-power gating");
    });
    assert!(dwmshc::high_speed());
    assert_eq!(dwmshc::capacity(), CARD_SECTORS as u64);
    clean(&m);
}

#[test]
fn a_card_that_refuses_high_speed_stays_at_25_mhz() {
    // The twin of the test above: the same flow with a card without the function.
    let (_g, m) = setup(Cfg { hs: false, ..Cfg::sdhc() });
    m.with(|i| {
        assert_eq!(i.clock_hist, vec![400_000, 25_000_000], "no 50 MHz");
        assert!(!i.card_hs);
    });
    assert!(!dwmshc::high_speed());
    assert_eq!(idx_of(&m).iter().filter(|&&c| c == 6).count(), 2, "ACMD6 and the one CMD6 check");
    // And it works at 25 MHz.
    let mut b = vec![0u8; 512];
    dwmshc::read_on(&*m, 3, 1, &mut b).unwrap();
    clean(&m);
}

#[test]
fn the_capacity_is_the_cards_not_a_constant() {
    // The driver used to report exactly 8 GiB (0x100_0000 sectors) for every
    // SDHC card: a card of any other size is the canary.
    for sectors in [8192usize, 32768, 1 << 20] {
        let (_g, m) = setup(Cfg { sectors, ..Cfg::sdhc() });
        assert_eq!(dwmshc::capacity(), sectors as u64);
        assert_ne!(dwmshc::capacity(), 0x100_0000);
        // The bound is enforced: one sector past the end never reaches the card.
        let n = m.with(|i| i.cmds.len());
        let mut b = vec![0u8; 512];
        assert!(dwmshc::read_on(&*m, sectors as u64, 1, &mut b).is_err());
        assert!(dwmshc::read_on(&*m, sectors as u64 - 1, 2, &mut vec![0u8; 1024]).is_err());
        assert!(dwmshc::write_on(&*m, u64::MAX, 1, &b).is_err());
        assert_eq!(m.with(|i| i.cmds.len()), n, "refused before the controller was touched");
        dwmshc::read_on(&*m, sectors as u64 - 1, 1, &mut b).expect("the last sector");
        clean(&m);
    }
}

#[test]
fn a_standard_capacity_card_is_byte_addressed_and_gets_a_block_length() {
    let (_g, m) = setup(Cfg { sdhc: false, v2: false, sectors: 8192, hs: false, ..Cfg::sdhc() });
    let ids = idx_of(&m);
    assert!(ids.contains(&16), "CMD16 on an SDSC card: {ids:?}");
    assert_eq!(dwmshc::capacity(), 8192);
    let data = pattern(3, 0x21);
    dwmshc::write_on(&*m, 100, 3, &data).unwrap();
    assert_eq!(m.card_read(100 * 512, 3 * 512), data);
    m.with(|i| {
        let w = i.cmds.iter().rev().find(|c| c.idx == 25).unwrap();
        assert_eq!(w.arg, 100 * 512, "byte address");
    });
    clean(&m);
}

#[test]
fn no_card_ends_init_after_the_first_unanswered_app_command() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    attach_once();
    azos_mm::pmm::use_low_phys(true);
    let m = Arc::new(Mock::new(Cfg { no_card: true, ..Cfg::sdhc() }));
    *CUR.lock().unwrap() = Some(m.clone());
    dwmshc::irq_off_on(&*m);
    let t = std::time::Instant::now();
    assert!(!dwmshc::init_on(&*m));
    assert!(t.elapsed() < std::time::Duration::from_millis(500), "no one-second ACMD41 loop for an empty socket");
    assert_eq!(idx_of(&m), vec![0, 8, 55], "CMD0, CMD8 (no answer is fine), CMD55 (no answer: not an SD card)");
    assert_eq!(dwmshc::capacity(), 0);
    // The controller is left usable: requests are refused, not wedged.
    assert!(dwmshc::read_on(&*m, 0, 1, &mut vec![0u8; 512]).is_err());
}

#[test]
fn an_unpowered_card_is_given_a_second_and_then_refused() {
    // ACMD41 never reports power-up: the loop is bounded by time, not by luck.
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    attach_once();
    azos_mm::pmm::use_low_phys(true);
    let m = Arc::new(Mock::new(Cfg::sdhc()));
    m.with(|i| i.never_ready = true);
    *CUR.lock().unwrap() = Some(m.clone());
    dwmshc::irq_off_on(&*m);
    let t = std::time::Instant::now();
    assert!(!dwmshc::init_on(&*m));
    let e = t.elapsed();
    assert!(e >= std::time::Duration::from_millis(900) && e < std::time::Duration::from_secs(3), "{e:?}");
}

// ---- Reads and writes ----

#[test]
fn a_read_is_one_chained_idmac_transfer_and_stops_the_card_with_cmd12() {
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(37, 0x11);
    // Fill the card behind the driver's back, then read it through the driver.
    m.with(|i| i.card[100 * 512..137 * 512].copy_from_slice(&data));
    m.with(|i| { i.cmds.clear(); i.descs.clear(); i.bytcnts.clear(); });
    let mut back = vec![0u8; 37 * 512];
    dwmshc::read_on(&*m, 100, 37, &mut back).expect("read");
    assert_eq!(back, data, "the data the IDMAC moved is what the card held");

    // 37 sectors: four full pages and a 2560-byte tail, FS first, LD last.
    m.with(|i| {
        assert_eq!(i.descs.len(), 5);
        for (n, d) in i.descs.iter().enumerate() {
            let want = D_OWN | D_CH | if n == 0 { D_FS } else { 0 } | if n == 4 { D_LD } else { D_DIC };
            assert_eq!(d.control, want, "descriptor {n}");
            assert_eq!(d.size as usize, if n == 4 { 2560 } else { 4096 });
            assert_eq!(d.buf % 4096, 0);
            assert!(d.buf < 1 << 32, "below 4 GiB");
        }
        let mut pages: Vec<u64> = i.descs.iter().map(|d| d.buf).collect();
        pages.sort();
        pages.dedup();
        assert_eq!(pages.len(), 5, "five distinct bounce pages");
        assert_eq!(i.bytcnts, vec![37 * 512]);
        let c: Vec<(u32, u32)> = i.cmds.iter().map(|c| (c.idx, c.arg)).collect();
        assert_eq!(c, vec![(18, 100), (12, 0)], "CMD18, then an explicit CMD12");
        assert_eq!(i.cmds[1].flags & CMD_ABORT, CMD_ABORT);
    });
    clean(&m);

    // One sector: CMD17, no CMD12, a one-descriptor chain that is its own FS and LD.
    m.with(|i| { i.cmds.clear(); i.descs.clear(); });
    dwmshc::read_on(&*m, 100, 1, &mut back[..512]).unwrap();
    m.with(|i| {
        assert_eq!(i.cmds.iter().map(|c| c.idx).collect::<Vec<_>>(), vec![17]);
        assert_eq!(i.descs.len(), 1);
        assert_eq!(i.descs[0].control, D_OWN | D_CH | D_FS | D_LD);
    });
    clean(&m);
}

#[test]
fn a_corrupting_dma_is_caught_by_the_same_comparison() {
    // Canary for the test above: the model flips one byte on its way to
    // memory; the comparison that passed there must fail here.
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(8, 0x31);
    m.with(|i| { i.card[..8 * 512].copy_from_slice(&data); i.corrupt_dma = true; });
    let mut back = vec![0u8; 8 * 512];
    dwmshc::read_on(&*m, 0, 8, &mut back).expect("the transfer itself completes");
    assert_ne!(back, data, "the read test would see a corrupting controller");
}

#[test]
fn a_write_reaches_the_card_and_a_flush_waits_for_it_to_leave_programming() {
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(20, 0x42);
    m.with(|i| { i.cmds.clear(); i.prg_polls = 3; });
    dwmshc::write_on(&*m, 40, 20, &data).expect("write");
    assert_eq!(m.card_read(40 * 512, 20 * 512), data, "the card holds what was written");
    assert_eq!(idx_of(&m), vec![25, 12], "CMD25 and an explicit CMD12 (its R1b busy waited out)");
    m.with(|i| assert_eq!(i.state, ST_PRG, "still programming"));

    m.with(|i| i.cmds.clear());
    dwmshc::flush_on(&*m).expect("flush");
    assert_eq!(idx_of(&m), vec![13, 13, 13, 13], "three CMD13 answered in prg, one in tran");
    m.with(|i| assert_eq!(i.state, ST_TRAN));
    clean(&m);
}

#[test]
fn a_request_longer_than_the_chain_is_split_into_commands() {
    let (_g, m) = setup(Cfg::sdhc());
    let n = 300usize; // 128 + 128 + 44
    let data = pattern(n, 0x77);
    m.with(|i| i.cmds.clear());
    dwmshc::write_on(&*m, 1000, n as u32, &data).unwrap();
    m.with(|i| {
        let v: Vec<(u32, u32)> = i.cmds.iter().filter(|c| c.idx == 25).map(|c| (c.idx, c.arg)).collect();
        assert_eq!(v, vec![(25, 1000), (25, 1128), (25, 1256)]);
        assert_eq!(i.cmds.iter().filter(|c| c.idx == 12).count(), 3);
    });
    let mut back = vec![0u8; n * 512];
    dwmshc::read_on(&*m, 1000, n as u32, &mut back).unwrap();
    assert_eq!(back, data);
    clean(&m);
}

#[test]
fn an_idmac_that_finishes_before_the_transfer_over_event_is_waited_for_too() {
    // The TI/RI event may come before or after Data Transfer Over: both orders
    // complete, and neither is skipped.
    let (_g, m) = setup(Cfg::sdhc());
    m.with(|i| i.dma_first = true);
    let data = pattern(4, 0x05);
    dwmshc::write_on(&*m, 8, 4, &data).unwrap();
    let mut back = vec![0u8; 4 * 512];
    dwmshc::read_on(&*m, 8, 4, &mut back).unwrap();
    assert_eq!(back, data);
    clean(&m);
}

#[test]
fn only_the_last_descriptor_raises_the_event_so_the_read_waits_for_every_page() {
    // A chain longer than a page: if the first descriptor raised RI, the
    // driver (which has seen CDONE, DTO and now "DMA done") would copy the
    // pages out while the IDMAC is still filling the later ones.
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(37, 0x31);
    m.with(|i| i.card[100 * 512..137 * 512].copy_from_slice(&data));
    m.with(|i| i.descs.clear());
    let mut back = vec![0u8; 37 * 512];
    dwmshc::read_on(&*m, 100, 37, &mut back).expect("read");
    assert_eq!(back, data, "every page had landed when the driver copied the data out");
    m.with(|i| assert_eq!(i.irq_descs, 1, "one descriptor (LD) raises TI/RI"));
    clean(&m);

    // The same for a write: the card gets every page, even the last.
    let w = pattern(37, 0x52);
    dwmshc::write_on(&*m, 300, 37, &w).expect("write");
    dwmshc::flush_on(&*m).expect("flush");
    m.with(|i| assert_eq!(&i.card[300 * 512..337 * 512], &w[..], "the card has the whole write"));
    clean(&m);
}

#[test]
fn a_chain_whose_first_descriptor_raises_the_event_is_caught() {
    // Canary for the test above: with the model told the driver's chain has no
    // DIC (the descriptors are rewritten before the IDMAC walks them), the
    // first RI satisfies the wait and the driver stops the controller (and
    // would copy the data out) while later pages are still being moved.
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(37, 0x31);
    m.with(|i| i.card[100 * 512..137 * 512].copy_from_slice(&data));
    m.with(|i| i.strip_dic = true);
    let mut back = vec![0u8; 37 * 512];
    let _ = dwmshc::read_on(&*m, 100, 37, &mut back);
    m.with(|i| {
        assert!(i.irq_descs > 1);
        assert!(i.violations.iter().any(|v| v.contains("no DIC")));
        assert!(i.violations.iter().any(|v| v.contains("still in flight")), "the driver finished the transfer too early: {:?}", i.violations);
        i.violations.clear();
    });
    clean(&m);
}

#[test]
fn the_64_bit_idmac_gets_its_own_descriptors_and_registers() {
    let (_g, m) = setup(Cfg { dma64: true, ..Cfg::sdhc() });
    let data = pattern(9, 0x66);
    m.with(|i| i.descs.clear());
    dwmshc::write_on(&*m, 16, 9, &data).unwrap();
    let mut back = vec![0u8; 9 * 512];
    dwmshc::read_on(&*m, 16, 9, &mut back).unwrap();
    assert_eq!(back, data);
    m.with(|i| {
        assert_eq!(i.descs.len(), 2 * 2, "9 sectors = a page and a half: two 64-bit descriptors per transfer");
        assert_eq!(i.descs[0].control & (D_FS | D_OWN | D_CH), D_FS | D_OWN | D_CH);
        assert_eq!(i.descs[0].control & (D_DIC | D_LD), D_DIC, "the first of two: DIC, not LD");
        assert_eq!(i.descs[1].control & (D_DIC | D_LD), D_LD, "the last: LD, raises the event");
    });
    clean(&m);
}

// ---- Faults ----

#[test]
fn a_command_the_card_never_answers_fails_the_request_and_the_controller_recovers() {
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(2, 0x13);
    m.with(|i| i.card[7 * 512..9 * 512].copy_from_slice(&data));
    // The same read, clean: the canary for the failing one.
    let mut b = vec![0u8; 2 * 512];
    dwmshc::read_on(&*m, 7, 2, &mut b).expect("clean read");
    assert_eq!(b, data);

    m.with(|i| { i.fault = Fault::NoResponse; i.ctrl_resets = 0; i.cmds.clear(); });
    let mut b = vec![0u8; 2 * 512];
    assert!(dwmshc::read_on(&*m, 7, 2, &mut b).is_err(), "response timeout");
    m.with(|i| {
        assert!(i.ctrl_resets >= 1, "controller, FIFO and IDMAC reset after the error");
        assert!(i.cmds.iter().any(|c| c.idx == 12), "and the card is told to stop");
        assert_eq!(i.rint, 0, "nothing pending");
        i.violations.clear();
    });
    dwmshc::read_on(&*m, 7, 2, &mut b).expect("usable again");
    assert_eq!(b, data);
    clean(&m);
}

#[test]
fn a_response_crc_error_fails_the_request_and_is_not_an_event_the_next_one_inherits() {
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(1, 0x2E);
    m.with(|i| i.card[512..1024].copy_from_slice(&data));
    m.with(|i| { i.fault = Fault::ResponseCrc; i.ctrl_resets = 0; });
    let mut b = vec![0u8; 512];
    assert!(dwmshc::read_on(&*m, 1, 1, &mut b).is_err());
    m.with(|i| assert!(i.ctrl_resets >= 1));
    dwmshc::read_on(&*m, 1, 1, &mut b).expect("the CRC event did not stay pending");
    assert_eq!(b, data);
    m.with(|i| i.violations.clear());
    clean(&m);
}

#[test]
fn a_data_crc_error_fails_a_multi_block_read_and_the_card_is_stopped_anyway() {
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(6, 0x6B);
    m.with(|i| i.card[..6 * 512].copy_from_slice(&data));
    let mut b = vec![0u8; 6 * 512];
    // Clean twin first.
    dwmshc::read_on(&*m, 0, 6, &mut b).unwrap();
    assert_eq!(b, data);

    m.with(|i| { i.fault = Fault::DataCrc; i.cmds.clear(); i.ctrl_resets = 0; });
    let mut b = vec![0u8; 6 * 512];
    assert!(dwmshc::read_on(&*m, 0, 6, &mut b).is_err(), "data CRC error");
    assert_eq!(idx_of(&m), vec![18, 12], "CMD12 follows the failed CMD18, or the card stays out of tran");
    m.with(|i| {
        assert!(i.ctrl_resets >= 1);
        i.violations.clear();
    });
    // The failed request left no half-copied data visible: the buffer was not touched by a bounce-out.
    assert_ne!(b, data);
    dwmshc::read_on(&*m, 0, 6, &mut b).expect("recovered");
    assert_eq!(b, data);
    clean(&m);
}

#[test]
fn a_write_the_card_reports_an_error_for_fails_and_the_flush_reports_it_once() {
    let (_g, m) = setup(Cfg::sdhc());
    let data = pattern(1, 0x66);
    // Clean twin: the same write and flush succeed.
    dwmshc::write_on(&*m, 5, 1, &data).unwrap();
    dwmshc::flush_on(&*m).expect("clean flush");

    m.with(|i| i.write_status_error = 1 << 26); // WP_VIOLATION in the CMD24 response
    assert!(dwmshc::write_on(&*m, 5, 1, &data).is_err(), "the card's verdict decides the request");
    m.with(|i| i.write_status_error = 0);
    assert!(dwmshc::flush_on(&*m).is_err(), "the fault is reported by the next flush");
    assert!(dwmshc::flush_on(&*m).is_ok(), "and only once");
    clean(&m);
}

#[test]
fn a_command_that_never_completes_gives_up_at_its_deadline() {
    let (_g, m) = setup(Cfg::sdhc());
    m.with(|i| { i.fault = Fault::Silent; i.ctrl_resets = 0; });
    let mut b = vec![0u8; 512];
    let t = std::time::Instant::now();
    assert!(dwmshc::read_on(&*m, 3, 1, &mut b).is_err());
    let e = t.elapsed();
    assert!(e < std::time::Duration::from_secs(2), "the command deadline (100 ms), not the transfer's: {e:?}");
    assert!(e >= std::time::Duration::from_millis(80), "and not before it: {e:?}");
    m.with(|i| {
        assert!(i.ctrl_resets >= 1);
        i.violations.clear();
    });
    dwmshc::read_on(&*m, 3, 1, &mut b).expect("recovered");
}

// ---- Interrupt completion ----

#[test]
fn interrupt_mode_sleeps_instead_of_polling_and_the_handler_wakes_the_waiter() {
    let (_g, m) = setup(Cfg::sdhc());
    let (b0, w0, t0, s0) = counts();
    // Polled first: no sleep.
    let data = pattern(20, 0x31);
    dwmshc::write_on(&*m, 40, 20, &data).unwrap();
    let (b1, _, t1, s1) = counts();
    assert_eq!((b1, t1, s1), (b0, t0, s0), "a polled request never sleeps and takes no interrupt");

    assert!(dwmshc::set_irq_mode_on(&*m, LINE, &HOOKS));
    m.with(|i| {
        assert_eq!(i.regs[R_INTMASK / 4], 0xBFCE, "command done, data over and every error bit");
        assert_ne!(i.regs[R_CTRL / 4] & C_INT_EN, 0, "global enable");
        assert_ne!(i.regs[i.idinten_off() / 4] & (ID_TI | ID_RI), 0, "IDMAC completion armed");
    });
    let mut back = vec![0u8; 20 * 512];
    dwmshc::read_on(&*m, 40, 20, &mut back).expect("a read completes only through the interrupt");
    assert_eq!(back, data);
    let (b2, w2, t2, s2) = counts();
    // Command Done, Data Over, the IDMAC's RI, and the CMD12's Command Done.
    assert!(b2 - b1 >= 3, "the waiter slept for each event ({} blocks)", b2 - b1);
    assert!(t2 - t1 >= 3, "the handler ran for each event");
    assert!(s2 - s1 >= 3, "the sleeps are counted");
    assert!(w2 > w0, "the handler woke the sleeper");
    assert_eq!(WOKEN_TID.load(Ordering::SeqCst), TEST_TID, "by TID");
    clean(&m);

    // And back.
    dwmshc::irq_off_on(&*m);
    m.with(|i| {
        assert_eq!(i.regs[R_INTMASK / 4], 0);
        assert_eq!(i.regs[R_CTRL / 4] & C_INT_EN, 0);
    });
    let (b3, ..) = counts();
    dwmshc::read_on(&*m, 40, 20, &mut back).unwrap();
    assert_eq!(counts().0, b3, "polled again: no sleep");
}

#[test]
fn a_poll_that_the_model_never_advances_would_hang_the_interrupt_test() {
    // Canary for the test above: in interrupt mode a read of RINTSTS does not
    // advance the device, so a driver that only polled would run into its
    // deadline instead of completing. Prove the model really behaves so.
    let (_g, m) = setup(Cfg::sdhc());
    assert!(dwmshc::set_irq_mode_on(&*m, LINE, &HOOKS));
    let (b0, ..) = counts();
    m.with(|i| i.stages.push_back((I_CDONE, 0)));
    for _ in 0..100 {
        let _ = m.rd32(R_RINTSTS);
    }
    assert_eq!(m.with(|i| i.rint & I_CDONE), 0, "polling does not advance an interrupt-mode device");
    assert_eq!(counts().0, b0);
    m.with(|i| i.stages.clear());
    dwmshc::irq_off_on(&*m);
}

#[test]
fn commands_without_data_complete_by_interrupt_too() {
    let (_g, m) = setup(Cfg::sdhc());
    assert!(dwmshc::set_irq_mode_on(&*m, LINE, &HOOKS));
    dwmshc::write_on(&*m, 7, 3, &pattern(3, 0x09)).unwrap();
    m.with(|i| { i.prg_polls = 0; i.cmds.clear(); });
    let (b0, ..) = counts();
    dwmshc::flush_on(&*m).expect("flush");
    assert!(counts().0 > b0, "CMD13 completed by interrupt");
    assert_eq!(idx_of(&m), vec![13]);
    clean(&m);
}

#[test]
fn an_event_raised_while_the_waiter_lists_itself_is_not_slept_through() {
    let (_g, m) = setup(Cfg::sdhc());
    assert!(dwmshc::set_irq_mode_on(&*m, LINE, &HOOKS));
    EVENT_IN_THE_WINDOW.store(true, Ordering::SeqCst);
    let (b0, w0, ..) = counts();
    let r = dwmshc::flush_on(&*m);
    EVENT_IN_THE_WINDOW.store(false, Ordering::SeqCst);
    r.expect("flush");
    let (b1, w1, ..) = counts();
    // The handler ran with nobody listed (no wake), and the waiter, looking
    // once more after it listed itself, found the event instead of sleeping.
    assert_eq!(w1, w0, "nobody was listed when the handler ran");
    assert_eq!(b1, b0, "the waiter slept although its event had already happened");
    clean(&m);
}

#[test]
fn after_an_error_in_interrupt_mode_the_next_request_still_completes_by_interrupt() {
    // A controller reset may take the interrupt enables with it: the recovery
    // gives the mode back, or the next request would run into its deadline.
    let (_g, m) = setup(Cfg::sdhc());
    assert!(dwmshc::set_irq_mode_on(&*m, LINE, &HOOKS));
    m.with(|i| { i.reset_clears_irq = true; i.fault = Fault::NoResponse; });
    let mut b = vec![0u8; 512];
    assert!(dwmshc::read_on(&*m, 3, 1, &mut b).is_err());
    m.with(|i| {
        assert_ne!(i.regs[R_CTRL / 4] & C_INT_EN, 0, "global enable back");
        assert_eq!(i.regs[R_INTMASK / 4], 0xBFCE, "and the mask");
    });
    let data = pattern(1, 0x7A);
    m.with(|i| i.card[3 * 512..4 * 512].copy_from_slice(&data));
    let t = std::time::Instant::now();
    dwmshc::read_on(&*m, 3, 1, &mut b).expect("by interrupt");
    assert_eq!(b, data);
    assert!(t.elapsed() < std::time::Duration::from_millis(80), "not by the 100 ms deadline");
    m.with(|i| { i.reset_clears_irq = false; i.violations.clear(); });
    dwmshc::irq_off_on(&*m);
}

#[test]
fn the_line_is_the_nodes_and_only_once_the_card_is_up() {
    let (_g, _m) = setup(Cfg::sdhc());
    assert_eq!(dwmshc::irq_line(), Some(LINE));
}

#[test]
fn requests_before_init_are_refused() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    attach_once();
    azos_mm::pmm::use_low_phys(true);
    // A controller with no card: init fails and leaves the driver not ready.
    let m = Arc::new(Mock::new(Cfg { no_card: true, ..Cfg::sdhc() }));
    *CUR.lock().unwrap() = Some(m.clone());
    dwmshc::irq_off_on(&*m);
    assert!(!dwmshc::init_on(&*m));
    let n = m.with(|i| i.cmds.len());
    assert!(dwmshc::read_on(&*m, 0, 1, &mut vec![0u8; 512]).is_err());
    assert!(dwmshc::write_on(&*m, 0, 1, &vec![0u8; 512]).is_err());
    assert!(dwmshc::flush_on(&*m).is_err());
    assert_eq!(dwmshc::irq_line(), None);
    assert_eq!(m.with(|i| i.cmds.len()), n, "the controller was not touched");
    assert!(dwmshc::read_on(&*m, 0, 2, &mut vec![0u8; 512]).is_err(), "a buffer shorter than the request");
}

// ---- Cache maintenance for a controller that is not coherent ----

mod noncoherent {
    use super::*;

    static CALLS: Mutex<Vec<(&'static str, usize, usize)>> = Mutex::new(Vec::new());

    unsafe fn clean_fn(va: usize, len: usize) { CALLS.lock().unwrap().push(("clean", va, len)); }
    unsafe fn flush_fn(va: usize, len: usize) { CALLS.lock().unwrap().push(("flush", va, len)); }
    fn cmd_marker() { CALLS.lock().unwrap().push(("cmd", 0, 0)); }

    #[test]
    fn a_non_coherent_controller_gets_cache_maintenance_around_each_transfer() {
        let _h = CACHE_HOOKS.lock().unwrap_or_else(|e| e.into_inner());
        let (_g, m) = setup(Cfg::sdhc());
        // Its own window: only this controller is declared non-coherent.
        m.base.store(0xD00D_1000, Ordering::SeqCst);
        azos_dma::cache::install(clean_fn, flush_fn);
        azos_dma::registry::declare_mmio(0xD00D_1000, 0xD00D_1000, azos_dma::registry::MmioView::coherent(false)).expect("declare once");
        m.with(|i| i.on_data_cmd = Some(cmd_marker));
        CALLS.lock().unwrap().clear();

        let data = pattern(16, 0x3C); // two pages
        dwmshc::write_on(&*m, 0, 16, &data).unwrap();
        let w: Vec<&str> = CALLS.lock().unwrap().drain(..).map(|c| c.0).collect();
        // The chain and the two data pages written back before the device reads them; nothing after.
        assert_eq!(w, vec!["clean", "clean", "clean", "cmd"], "{w:?}");

        let mut back = vec![0u8; 16 * 512];
        dwmshc::read_on(&*m, 0, 16, &mut back).unwrap();
        let r: Vec<&str> = CALLS.lock().unwrap().drain(..).map(|c| c.0).collect();
        // The chain cleaned, the data pages flushed before the device writes them and again after.
        assert_eq!(r, vec!["clean", "flush", "flush", "cmd", "flush", "flush"], "{r:?}");
        assert_eq!(back, data);
        clean(&m);
    }
}
