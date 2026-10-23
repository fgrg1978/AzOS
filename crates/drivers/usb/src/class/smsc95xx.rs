// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The SMSC LAN95xx USB Ethernet function (LAN9500/9500A/9505/9512/9514/
//! 9530/9730: the Raspberry Pi 3 B's on-board Ethernet, behind the LAN9514's
//! own hub) as a NIC (Kconfig `USB_SMSC95XX`).
//!
//! A class driver like the CDC ones ([`super::cdc`]): it serves [`UsbClass`],
//! claims the one vendor-class interface of the function, and moves data only
//! through the pipes the core opened for that claim. The protocol, no lock,
//! no hardware; the kernel half is the same NIC adapter the CDC function has
//! (`crates/drivers/net/src/usb_net.rs`, through [`NetFunction`]). The
//! register layout and the bring-up order follow the LAN9512/9514 datasheet
//! as Linux `drivers/net/usb/smsc95xx.c` drives it; the code is our own.
//!
//! # Registers
//!
//! The chip is reached through two vendor requests to the device: `0xA1`
//! reads and `0xA0` writes one little-endian 32-bit register (`wIndex` its
//! offset). The function has one interface, so a device-recipient vendor
//! request concerns nothing but the claimed function: the core lets the
//! holder of the claim on a device's only interface send it
//! ([`crate::usbcore::Usb::control_allowed`]). The internal PHY (MII address
//! 1) is reached through `MII_ADDR` / `MII_DATA`.
//!
//! # Setup
//!
//! A script of register accesses ([`SCRIPT`]), one control request at a
//! time, each with `CTL_TIMEOUT_US`: read the chip id, lite reset (`HW_CFG.LRST`)
//! and PHY reset (`PM_CTRL.PHY_RST`), each waited for; the MAC address into
//! `ADDRL`/`ADDRH`; bulk-in: NAK when empty, several frames per transfer, a
//! burst cap of one receive buffer; the LEDs, flow control off, all
//! multicast and broadcast passed (the stack filters), no checksum offload;
//! the PHY reset, 10/100 with pause advertised, autonegotiation restarted;
//! then the transmitter and the receiver on. The MAC address is the one the
//! kernel hands in (the device tree's `local-mac-address` of the
//! `usb424,ec00` node, which the Pi firmware fills in from the board's OTP;
//! a locally administered random one when the tree has none): the chips on
//! the Pis have no EEPROM, and an EEPROM is not read.
//!
//! # Data path
//!
//! Receive: `USB_CDC_BUFS` buffers of [`RX_BYTES`] posted to bulk IN at all
//! times. A completed one holds frames back to back, each a status word
//! (frame length in bits 29:16, error summary in bit 15), the frame with its
//! four-byte FCS, and padding to the next 32-bit boundary; a buffer is held
//! until the stack has taken its frames, then posted again, as the CDC driver
//! does. A frame the chip flags, or one under an Ethernet header, is counted
//! and skipped; a status word that runs past the transfer ends the buffer.
//! Transmit: one frame per transfer, after the two command words (`TX_CMD_A`:
//! first and last segment, buffer size; `TX_CMD_B`: frame length). The core
//! queues no zero-length packet, so a transfer that would end on a packet
//! boundary carries one byte of Ethernet padding more, stated in both command
//! words.
//!
//! # Not here
//!
//! Link state (the function is up while it is present, as a CDC one; frames
//! sent before autonegotiation finishes are dropped by the chip), the
//! interrupt endpoint, checksum offload, multicast hash filtering, EEPROM,
//! suspend and wake-on-LAN.

use azos_devif::outcome::{BAD_ARGUMENT, BUSY, OK, UNSUPPORTED};
use azos_devif::Out;
use azos_rings::Push;

use super::cdc::{open_one, Fail, NetStats, SendError, State, BUFS, CTL_TIMEOUT_US, FRAME_MAX, FRAME_MIN, MAX_BAD_RUN};
use super::net::NetFunction;
use crate::class::{Claim, Match, UsbClass, UsbDevice};
use crate::hw::{Clock, DmaBuf, Memory, PAGE};
use crate::usbcore::desc::{Setup, RT_DIR_IN, RT_RECIP_DEVICE, RT_TYPE_VENDOR};
use crate::usbcore::pipe::{Completion, Dir, PipeEnd, PipeRings, Status, Transfer};

/// SMSC's vendor id, and the product ids of the LAN95xx family.
pub const VID_SMSC: u16 = 0x0424;
pub const PIDS: [u16; 8] = [0x9500, 0x9505, 0x9e00, 0x9e01, 0xec00, 0x9530, 0x9730, 0x9e08];

/// Vendor requests (bmRequestType vendor, recipient device).
pub const REQ_WRITE_REGISTER: u8 = 0xa0;
pub const REQ_READ_REGISTER: u8 = 0xa1;

// ---- Registers ----

pub const ID_REV: u16 = 0x00;
pub const INT_STS: u16 = 0x08;
pub const TX_CFG: u16 = 0x10;
pub const HW_CFG: u16 = 0x14;
pub const PM_CTRL: u16 = 0x20;
pub const LED_GPIO_CFG: u16 = 0x24;
pub const AFC_CFG: u16 = 0x2c;
pub const BURST_CAP: u16 = 0x38;
pub const BULK_IN_DLY: u16 = 0x6c;
pub const MAC_CR: u16 = 0x100;
pub const ADDRH: u16 = 0x104;
pub const ADDRL: u16 = 0x108;
pub const MII_ADDR: u16 = 0x114;
pub const MII_DATA: u16 = 0x118;
pub const FLOW: u16 = 0x11c;
pub const VLAN1: u16 = 0x120;
pub const COE_CR: u16 = 0x130;

pub const TX_CFG_ON: u32 = 0x04;
pub const HW_CFG_BCE: u32 = 0x02;
pub const HW_CFG_LRST: u32 = 0x08;
pub const HW_CFG_MEF: u32 = 0x20;
/// Receive data offset (bits 10:9): 0, the frame right after its status word.
pub const HW_CFG_RXDOFF: u32 = 0x600;
/// Bulk-in empty response: NAK.
pub const HW_CFG_BIR: u32 = 0x1000;
pub const PM_CTRL_PHY_RST: u32 = 0x10;
/// The speed, link and duplex LEDs.
pub const LED_GPIO_CFG_LEDS: u32 = 0x0111_0000;
/// Linux's AFC_CFG_DEFAULT: the flow-control thresholds.
pub const AFC_CFG_DEFAULT: u32 = 0x00f8_30a1;
/// Bulk-in delay before a short burst ends (Linux DEFAULT_BULK_IN_DELAY).
pub const BULK_IN_DLY_DEFAULT: u32 = 0x2000;
pub const MAC_CR_RXEN: u32 = 0x04;
pub const MAC_CR_TXEN: u32 = 0x08;
/// Broadcast frames disabled when set.
pub const MAC_CR_BCAST: u32 = 0x800;
pub const MAC_CR_HPFILT: u32 = 0x2000;
pub const MAC_CR_PRMS: u32 = 0x4_0000;
pub const MAC_CR_MCPAS: u32 = 0x8_0000;
pub const MAC_CR_RXALL: u32 = 0x8000_0000;
pub const MII_BUSY: u32 = 0x01;
pub const MII_WRITE: u32 = 0x02;
pub const ETH_P_8021Q: u32 = 0x8100;

/// The internal PHY's MII address.
pub const PHY_ID: u32 = 1;
pub const MII_BMCR: u32 = 0;
pub const MII_ADVERTISE: u32 = 4;
/// PHY interrupt source (read clears) and mask (LAN95xx PHY registers 29, 30).
pub const PHY_INT_SRC: u32 = 29;
pub const PHY_INT_MASK: u32 = 30;
pub const BMCR_RESET: u32 = 0x8000;
pub const BMCR_ANENABLE: u32 = 0x1000;
pub const BMCR_ANRESTART: u32 = 0x0200;
/// 10/100 half and full, CSMA, symmetric and asymmetric pause.
pub const ADVERTISE_ALL_PAUSE: u32 = 0x0de1;
/// Autonegotiation complete and link down.
pub const PHY_INT_MASK_DEFAULT: u32 = 0x50;

pub const TX_CMD_A_FIRST_SEG: u32 = 0x2000;
pub const TX_CMD_A_LAST_SEG: u32 = 0x1000;
pub const RX_STS_ES: u32 = 0x8000;
/// Frame length field of a receive status word (bits 29:16).
pub const RX_STS_FL_SHIFT: u32 = 16;
pub const RX_STS_FL_MASK: u32 = 0x3fff;
/// The FCS each received frame carries.
pub const FCS_LEN: usize = 4;
/// The two transmit command words.
pub const TX_OVERHEAD: usize = 8;

/// Bytes of one receive buffer (also the burst cap): several frames, and a
/// multiple of every bulk packet size (64, 512).
pub const RX_BYTES: usize = 4096;
/// Bytes of one transmit buffer: the command words and the largest frame.
const TX_BYTES: usize = 2048;

const _: () = assert!(RX_BYTES % 512 == 0 && TX_BYTES >= TX_OVERHEAD + FRAME_MAX + 1);

// The region: the control page (the register word of the request on the
// wire), then the receive buffers, then the transmit buffers.
const REG_OFF: usize = 0;
const RX_OFF: usize = PAGE;
const TX_OFF: usize = RX_OFF + BUFS * RX_BYTES;
const REGION_BYTES: usize = (TX_OFF + BUFS * TX_BYTES).next_multiple_of(PAGE);

// Transfer tags.
const TAG_STEP: u32 = 0x200;
const TAG_OUT: u32 = 0x100;
const TAG_CLEAR: u32 = 0x300;

// ---- The setup script ----

/// One register access of the setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Read the register into the accumulator.
    Read(u16),
    /// Write a value.
    Write(u16, u32),
    /// Write the accumulator with `clear` cleared and `set` set.
    Modify(u16, u32, u32),
    /// Read until `mask` reads clear (a reset, a busy MII); a later turn
    /// reads again.
    Until(u16, u32),
    /// The MAC address, low four bytes and high two.
    AddrL,
    AddrH,
    /// The burst cap: one receive buffer, in packets of the bulk-in size.
    BurstCap,
    /// Go back `n` operations when the accumulator has `mask` set (the BMCR
    /// reset bit, read through MII).
    Again(u32, u8),
    /// Keep the chip id the accumulator holds (`ID_REV` bits 31:16).
    Chip,
}

/// `MII_ADDR` for PHY register `reg`, read or write, busy.
const fn mii(reg: u32, write: bool) -> u32 {
    PHY_ID << 11 | reg << 6 | if write { MII_WRITE } else { 0 } | MII_BUSY
}

/// The setup, in order. MII writes are: MII idle, data, address, MII idle.
pub const SCRIPT: &[Op] = &[
    Op::Read(ID_REV),
    Op::Chip,
    Op::Write(HW_CFG, HW_CFG_LRST),
    Op::Until(HW_CFG, HW_CFG_LRST),
    Op::Write(PM_CTRL, PM_CTRL_PHY_RST),
    Op::Until(PM_CTRL, PM_CTRL_PHY_RST),
    Op::AddrL,
    Op::AddrH,
    Op::Read(HW_CFG),
    Op::Modify(HW_CFG, HW_CFG_RXDOFF, HW_CFG_BIR | HW_CFG_MEF | HW_CFG_BCE),
    Op::BurstCap,
    Op::Write(BULK_IN_DLY, BULK_IN_DLY_DEFAULT),
    Op::Write(INT_STS, u32::MAX),
    Op::Write(LED_GPIO_CFG, LED_GPIO_CFG_LEDS),
    Op::Write(FLOW, 0),
    Op::Write(AFC_CFG, AFC_CFG_DEFAULT),
    Op::Write(VLAN1, ETH_P_8021Q),
    Op::Write(COE_CR, 0),
    Op::Read(MAC_CR),
    Op::Modify(MAC_CR, MAC_CR_PRMS | MAC_CR_HPFILT | MAC_CR_BCAST | MAC_CR_RXALL, MAC_CR_MCPAS),
    // PHY: reset, waited for through MII.
    Op::Until(MII_ADDR, MII_BUSY),
    Op::Write(MII_DATA, BMCR_RESET),
    Op::Write(MII_ADDR, mii(MII_BMCR, true)),
    Op::Until(MII_ADDR, MII_BUSY),
    Op::Write(MII_ADDR, mii(MII_BMCR, false)),
    Op::Until(MII_ADDR, MII_BUSY),
    Op::Read(MII_DATA),
    Op::Again(BMCR_RESET, 3),
    // Advertise, clear the PHY's interrupt source, its mask, autonegotiate.
    Op::Write(MII_DATA, ADVERTISE_ALL_PAUSE),
    Op::Write(MII_ADDR, mii(MII_ADVERTISE, true)),
    Op::Until(MII_ADDR, MII_BUSY),
    Op::Write(MII_ADDR, mii(PHY_INT_SRC, false)),
    Op::Until(MII_ADDR, MII_BUSY),
    Op::Write(MII_DATA, PHY_INT_MASK_DEFAULT),
    Op::Write(MII_ADDR, mii(PHY_INT_MASK, true)),
    Op::Until(MII_ADDR, MII_BUSY),
    Op::Write(MII_DATA, BMCR_ANENABLE | BMCR_ANRESTART),
    Op::Write(MII_ADDR, mii(MII_BMCR, true)),
    Op::Until(MII_ADDR, MII_BUSY),
    // Transmitter, then receiver.
    Op::Read(MAC_CR),
    Op::Modify(MAC_CR, 0, MAC_CR_TXEN),
    Op::Write(TX_CFG, TX_CFG_ON),
    Op::Read(MAC_CR),
    Op::Modify(MAC_CR, 0, MAC_CR_RXEN),
];

fn vendor(write: bool, reg: u16) -> Setup {
    Setup {
        request_type: RT_TYPE_VENDOR | RT_RECIP_DEVICE | if write { 0 } else { RT_DIR_IN },
        request: if write { REQ_WRITE_REGISTER } else { REQ_READ_REGISTER },
        value: 0,
        index: reg,
        length: 4,
    }
}

/// The frame whose status word `sts` sits at `at` of a transfer of `len`
/// bytes: (offset of its data, its length without the FCS, whether the chip
/// flagged it, offset of the next status word). `None` when the frame runs
/// past the transfer or is not even an FCS: the transfer ends there. Pure, so
/// the host tests feed it what a hostile device would.
pub fn frame_at(sts: u32, at: usize, len: usize) -> Option<(usize, usize, bool, usize)> {
    let flen = ((sts >> RX_STS_FL_SHIFT) & RX_STS_FL_MASK) as usize;
    let data = at.checked_add(4)?;
    // Canary: the end of the transfer is not looked at.
    let past = data.checked_add(flen)? > len && !cfg!(feature = "canary-smsc-rx-bounds");
    if flen < FCS_LEN || past {
        return None;
    }
    Some((data, flen - FCS_LEN, sts & RX_STS_ES != 0, (data + flen).next_multiple_of(4)))
}

/// The bytes of a transfer that sends `len` bytes of frame: the command words
/// and the frame, one more when that would end on a `mps`-byte packet
/// boundary (the frame then carries a byte of padding).
pub fn tx_len(len: usize, mps: usize) -> usize {
    let n = TX_OVERHEAD + len;
    // Canary: a transfer that ends on a packet boundary is sent as it is.
    if n % mps == 0 && !cfg!(feature = "canary-smsc-zlp") {
        n + 1
    } else {
        n
    }
}

/// The two command words of a transmitted frame of `len` bytes.
pub fn tx_cmd(len: usize) -> [u32; 2] {
    let l = len as u32 & 0x7ff;
    [TX_CMD_A_FIRST_SEG | TX_CMD_A_LAST_SEG | l, l]
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RxSlot {
    Free,
    Posted,
    /// Completed; its frames are not all taken.
    Held { len: u32, next: u32 },
}

/// The LAN95xx function as a NIC.
pub struct Smsc95xx<'q, M: Memory, C: Clock> {
    mem: M,
    clock: C,
    mask: u64,
    rings: &'q [PipeRings],
    state: State,
    claim: Option<Claim>,
    vid_pid: u32,
    gone: bool,
    ctl: Option<PipeEnd<'q>>,
    bin: Option<PipeEnd<'q>>,
    bout: Option<PipeEnd<'q>>,
    ep_in: u8,
    ep_out: u8,
    mps_in: u16,
    mps_out: u16,
    region: Option<DmaBuf>,
    /// The script's position, its accumulator, the deadline of the request
    /// on the wire, and whether one is.
    pc: usize,
    /// The furthest operation reached: the deadline restarts only past it (a
    /// read again, a loop back, keep the deadline of the first try).
    reached: usize,
    acc: u32,
    deadline_us: u64,
    waiting: bool,
    chip: u32,
    mac: [u8; 6],
    mac_hint: [u8; 6],
    rx: [RxSlot; BUFS],
    fifo: [u8; BUFS],
    fifo_head: usize,
    fifo_len: usize,
    tx_busy: [bool; BUFS],
    clear_in: bool,
    clear_out: bool,
    clearing: bool,
    bad_run: u32,
    submitted: bool,
    stats: NetStats,
}

impl<'q, M: Memory, C: Clock> Smsc95xx<'q, M, C> {
    /// A function with no device. `mask` is the controller's DMA mask,
    /// `rings` the pipe rings the core indexes by pipe number, `mac` the
    /// address the kernel gives the function (see the module documentation).
    pub fn new(mem: M, clock: C, mask: u64, rings: &'q [PipeRings], mac: [u8; 6]) -> Self {
        Smsc95xx {
            mem,
            clock,
            mask,
            rings,
            state: State::Idle,
            claim: None,
            vid_pid: 0,
            gone: false,
            ctl: None,
            bin: None,
            bout: None,
            ep_in: 0,
            ep_out: 0,
            mps_in: 0,
            mps_out: 0,
            region: None,
            pc: 0,
            reached: 0,
            acc: 0,
            deadline_us: 0,
            waiting: false,
            chip: 0,
            mac: [0; 6],
            mac_hint: mac,
            rx: [RxSlot::Free; BUFS],
            fifo: [0; BUFS],
            fifo_head: 0,
            fifo_len: 0,
            tx_busy: [false; BUFS],
            clear_in: false,
            clear_out: false,
            clearing: false,
            bad_run: 0,
            submitted: false,
            stats: NetStats::default(),
        }
    }

    /// The rule to register the class driver under: vendor-class interfaces
    /// (the product id is checked at attach).
    pub const fn rule() -> Match {
        Match::interface_class(0xff)
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn stats(&self) -> NetStats {
        self.stats
    }
    /// The chip id setup read (`ID_REV` bits 31:16).
    pub fn chip(&self) -> u32 {
        self.chip
    }
    pub fn vid_pid(&self) -> u32 {
        self.vid_pid
    }

    fn fail(&mut self, f: Fail) {
        self.state = State::Failed(f);
    }

    // ---- Binding ----

    fn open_pipes(&mut self, dev: &mut dyn UsbDevice) -> Result<(), Fail> {
        let n = dev.info(4);
        if n.code != OK {
            return Err(Fail::Pipe);
        }
        let (mut ep_in, mut ep_out) = (None, None);
        for i in 0..n.value as u32 {
            let e = dev.endpoint(i);
            if e.code != OK || (e.value >> 8) & 3 != 2 {
                continue; // the interrupt endpoint is not used
            }
            let (addr, mps) = ((e.value & 0xff) as u8, (e.value >> 16) as u16);
            if addr & 0x80 != 0 {
                ep_in.get_or_insert((addr, mps));
            } else {
                ep_out.get_or_insert((addr, mps));
            }
        }
        let (Some((ep_in, mps_in)), Some((ep_out, mps_out))) = (ep_in, ep_out) else { return Err(Fail::NoEndpoints) };
        if mps_in == 0 || mps_out == 0 {
            return Err(Fail::NoEndpoints);
        }
        let ctl = open_one(dev, self.rings, 0)?;
        let bin = match open_one(dev, self.rings, ep_in) {
            Ok(p) => p,
            Err(f) => {
                let id = ctl.id;
                drop(ctl);
                let _ = dev.pipe_close(id as u32);
                return Err(f);
            }
        };
        let bout = match open_one(dev, self.rings, ep_out) {
            Ok(p) => p,
            Err(f) => {
                for id in [ctl.id, bin.id] {
                    let _ = dev.pipe_close(id as u32);
                }
                return Err(f);
            }
        };
        (self.ctl, self.bin, self.bout) = (Some(ctl), Some(bin), Some(bout));
        (self.ep_in, self.ep_out, self.mps_in, self.mps_out) = (ep_in, ep_out, mps_in, mps_out);
        Ok(())
    }

    /// Open the pipes of the claim and start the setup.
    fn open_claim(&mut self, dev: &mut dyn UsbDevice) {
        if self.state != State::Claimed {
            return;
        }
        if let Err(f) = self.open_pipes(dev) {
            return self.fail(f);
        }
        match self.mem.alloc_region(REGION_BYTES, PAGE, self.mask) {
            Some(r) => self.region = Some(r),
            None => return self.fail(Fail::NoMemory),
        }
        self.mac = self.mac_hint;
        self.state = State::Setup;
        self.pc = 0;
        self.reached = 0;
        self.deadline_us = self.clock.now_us() + CTL_TIMEOUT_US;
        self.run();
    }

    fn ctl(&mut self, tag: u32, s: Setup, buf: u64) -> bool {
        let Some(p) = self.ctl.as_mut() else { return false };
        let t = Transfer { tag, dir: if s.is_in() { Dir::In } else { Dir::Out }, setup: s.to_bytes(), buf, len: s.length as u32 };
        matches!(p.sq.push(t), Push::Pushed)
    }

    /// Queue the register access of the script's current operation, or
    /// finish the script.
    fn run(&mut self) {
        let Some(region) = self.region else { return };
        loop {
            let Some(&op) = SCRIPT.get(self.pc) else {
                self.state = State::Ready;
                self.fill_rx();
                return;
            };
            let write = |s: &mut Self, reg: u16, v: u32| -> bool {
                region.write_bytes(REG_OFF, &v.to_le_bytes());
                s.mem.to_device(region.cpu().wrapping_add(REG_OFF), 4);
                s.ctl(TAG_STEP | s.pc as u32, vendor(true, reg), region.bus_at(REG_OFF))
            };
            let mac = self.mac;
            let queued = match op {
                Op::Read(reg) | Op::Until(reg, _) => self.ctl(TAG_STEP | self.pc as u32, vendor(false, reg), region.bus_at(REG_OFF)),
                Op::Write(reg, v) => write(self, reg, v),
                Op::Modify(reg, clear, set) => write(self, reg, (self.acc & !clear) | set),
                Op::AddrL => write(self, ADDRL, u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]])),
                Op::AddrH => write(self, ADDRH, u16::from_le_bytes([mac[4], mac[5]]) as u32),
                Op::BurstCap => write(self, BURST_CAP, (RX_BYTES / self.mps_in.max(1) as usize) as u32),
                Op::Again(mask, back) => {
                    if self.acc & mask != 0 {
                        if self.clock.now_us() > self.deadline_us {
                            return self.fail(Fail::Timeout);
                        }
                        self.pc -= back as usize;
                    } else {
                        self.pc += 1;
                    }
                    continue;
                }
                Op::Chip => {
                    self.chip = self.acc >> 16;
                    self.pc += 1;
                    continue;
                }
            };
            if !queued {
                return self.fail(Fail::Control(self.pc as u8));
            }
            if self.pc > self.reached {
                self.reached = self.pc;
                self.deadline_us = self.clock.now_us() + CTL_TIMEOUT_US;
            }
            self.waiting = true;
            self.submitted = true;
            return;
        }
    }

    /// The request of the current operation completed.
    fn on_step(&mut self, c: Completion) {
        if c.tag != TAG_STEP | self.pc as u32 {
            return;
        }
        self.waiting = false;
        if c.status != Status::Ok {
            return self.fail(Fail::Control(self.pc as u8));
        }
        let Some(region) = self.region else { return };
        let op = SCRIPT[self.pc];
        if matches!(op, Op::Read(_) | Op::Until(..)) {
            if c.actual < 4 {
                return self.fail(Fail::Control(self.pc as u8));
            }
            self.mem.from_device(region.cpu().wrapping_add(REG_OFF), 4);
            let mut b = [0u8; 4];
            region.read_bytes(REG_OFF, &mut b);
            self.acc = u32::from_le_bytes(b);
        }
        match op {
            Op::Until(_, mask) if self.acc & mask != 0 => {
                if self.clock.now_us() > self.deadline_us {
                    return self.fail(Fail::Timeout);
                }
                // Read again on the next turn: the same operation.
            }
            _ => self.pc += 1,
        }
        self.run();
    }

    fn cleanup(&mut self) {
        for p in [&mut self.ctl, &mut self.bin, &mut self.bout] {
            if let Some(mut e) = p.take() {
                while e.cq.pop().is_some() {}
            }
        }
        if let Some(r) = self.region.take() {
            self.mem.free_region(r);
        }
        self.state = State::Idle;
        self.claim = None;
        self.gone = false;
        self.waiting = false;
        self.rx = [RxSlot::Free; BUFS];
        self.fifo_head = 0;
        self.fifo_len = 0;
        self.tx_busy = [false; BUFS];
        self.clear_in = false;
        self.clear_out = false;
        self.clearing = false;
        self.bad_run = 0;
        self.mac = [0; 6];
    }

    // ---- The turn ----

    fn service_turn(&mut self) {
        if self.gone {
            return self.cleanup();
        }
        match self.state {
            State::Setup => {
                while let Some(c) = self.ctl.as_mut().and_then(|p| p.cq.pop()) {
                    self.on_step(c);
                    if self.state != State::Setup {
                        break;
                    }
                }
                if self.state == State::Setup && self.waiting && self.clock.now_us() > self.deadline_us {
                    self.fail(Fail::Timeout);
                }
            }
            State::Ready => {
                self.reap_rx();
                self.reap_tx();
                while let Some(c) = self.ctl.as_mut().and_then(|p| p.cq.pop()) {
                    if c.tag == TAG_CLEAR {
                        self.clearing = false;
                    }
                }
                self.clear_halts();
                self.fill_rx();
            }
            _ => {}
        }
    }

    /// Clear a halted bulk pipe on the device side, one at a time.
    fn clear_halts(&mut self) {
        if self.clearing {
            return;
        }
        let ep = if self.clear_in {
            self.ep_in
        } else if self.clear_out {
            self.ep_out
        } else {
            return;
        };
        if self.ctl(TAG_CLEAR, Setup::clear_halt(ep), 0) {
            if ep == self.ep_in {
                self.clear_in = false;
            } else {
                self.clear_out = false;
            }
            self.clearing = true;
            self.submitted = true;
        }
    }

    fn bad(&mut self, tx: bool) {
        if tx {
            self.stats.tx_errors += 1;
        } else {
            self.stats.rx_errors += 1;
        }
        self.bad_run += 1;
        if self.bad_run >= MAX_BAD_RUN {
            self.fail(Fail::Transport);
        }
    }

    // ---- Receive ----

    fn fill_rx(&mut self) {
        if self.state != State::Ready || self.clear_in || self.clearing {
            return;
        }
        let (Some(region), Some(p)) = (self.region, self.bin.as_mut()) else { return };
        for i in 0..BUFS {
            if self.rx[i] != RxSlot::Free {
                continue;
            }
            let t = Transfer { tag: i as u32, dir: Dir::In, setup: [0; 8], buf: region.bus_at(RX_OFF + i * RX_BYTES), len: RX_BYTES as u32 };
            if !matches!(p.sq.push(t), Push::Pushed) {
                break;
            }
            self.rx[i] = RxSlot::Posted;
            self.submitted = true;
        }
    }

    fn reap_rx(&mut self) {
        while let Some(c) = self.bin.as_mut().and_then(|p| p.cq.pop()) {
            let i = (c.tag & 0xff) as usize;
            if i >= BUFS || self.rx[i] != RxSlot::Posted {
                continue;
            }
            self.rx[i] = RxSlot::Free;
            match c.status {
                Status::Ok => {
                    self.bad_run = 0;
                    if c.actual > 0 {
                        self.hold(i, (c.actual as usize).min(RX_BYTES));
                    }
                }
                Status::Disconnected => {}
                Status::Stall => self.clear_in = true,
                _ => self.bad(false),
            }
        }
    }

    fn hold(&mut self, i: usize, actual: usize) {
        let Some(region) = self.region else { return };
        self.mem.from_device(region.cpu().wrapping_add(RX_OFF + i * RX_BYTES), actual);
        self.stats.rx_transfers += 1;
        self.rx[i] = RxSlot::Held { len: actual as u32, next: 0 };
        self.fifo[(self.fifo_head + self.fifo_len) % BUFS] = i as u8;
        self.fifo_len += 1;
    }

    /// The next frame of held buffer `i`: (offset in the region, length,
    /// flagged by the chip).
    fn next_frame(&mut self, i: usize) -> Option<(usize, usize, bool)> {
        let region = self.region?;
        let RxSlot::Held { len, next } = self.rx[i] else { return None };
        let base = RX_OFF + i * RX_BYTES;
        let (at, len) = (next as usize, len as usize);
        if at + 4 > len {
            return None;
        }
        let mut head = [0u8; 4];
        region.read_bytes(base + at, &mut head);
        let Some((data, flen, flagged, after)) = frame_at(u32::from_le_bytes(head), at, len) else {
            self.stats.ntb_malformed += 1;
            return None;
        };
        self.rx[i] = RxSlot::Held { len: len as u32, next: after as u32 };
        Some((base + data, flen, flagged))
    }

    fn recv_frame(&mut self, out: &mut [u8]) -> usize {
        if self.state != State::Ready {
            return 0;
        }
        self.reap_rx();
        let Some(region) = self.region else { return 0 };
        while self.fifo_len > 0 {
            let i = self.fifo[self.fifo_head] as usize;
            match self.next_frame(i) {
                Some((off, len, flagged)) => {
                    if flagged {
                        self.stats.rx_errors += 1;
                        continue;
                    }
                    if len < FRAME_MIN || len > out.len() {
                        self.stats.rx_dropped += 1;
                        continue;
                    }
                    region.read_bytes(off, &mut out[..len]);
                    self.stats.rx_frames += 1;
                    return len;
                }
                None => {
                    self.rx[i] = RxSlot::Free;
                    self.fifo_head = (self.fifo_head + 1) % BUFS;
                    self.fifo_len -= 1;
                    self.fill_rx();
                }
            }
        }
        0
    }

    // ---- Transmit ----

    fn reap_tx(&mut self) {
        while let Some(c) = self.bout.as_mut().and_then(|p| p.cq.pop()) {
            let i = (c.tag & 0xff) as usize;
            if c.tag & TAG_OUT == 0 || i >= BUFS || !self.tx_busy[i] {
                continue;
            }
            self.tx_busy[i] = false;
            match c.status {
                Status::Ok => self.bad_run = 0,
                Status::Disconnected => {}
                Status::Stall => {
                    self.clear_out = true;
                    self.stats.tx_errors += 1;
                }
                _ => self.bad(true),
            }
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), SendError> {
        if self.state != State::Ready {
            return Err(SendError::NotReady);
        }
        if frame.len() < FRAME_MIN || frame.len() > FRAME_MAX {
            return Err(SendError::BadLength);
        }
        self.reap_tx();
        let Some(region) = self.region else { return Err(SendError::NotReady) };
        let Some(i) = (0..BUFS).find(|&i| !self.tx_busy[i]) else { return Err(SendError::QueueFull) };
        let n = tx_len(frame.len(), self.mps_out as usize);
        let flen = n - TX_OVERHEAD;
        let off = TX_OFF + i * TX_BYTES;
        let [a, b] = tx_cmd(flen);
        region.write_bytes(off, &a.to_le_bytes());
        region.write_bytes(off + 4, &b.to_le_bytes());
        region.write_bytes(off + TX_OVERHEAD, frame);
        if flen > frame.len() {
            region.write_bytes(off + TX_OVERHEAD + frame.len(), &[0]);
        }
        self.mem.to_device(region.cpu().wrapping_add(off), n);
        let Some(p) = self.bout.as_mut() else { return Err(SendError::NotReady) };
        let t = Transfer { tag: TAG_OUT | i as u32, dir: Dir::Out, setup: [0; 8], buf: region.bus_at(off), len: n as u32 };
        if !matches!(p.sq.push(t), Push::Pushed) {
            return Err(SendError::QueueFull);
        }
        self.tx_busy[i] = true;
        self.stats.tx_transfers += 1;
        self.stats.tx_frames += 1;
        self.submitted = true;
        Ok(())
    }
}

impl<M: Memory, C: Clock> UsbClass for Smsc95xx<'_, M, C> {
    fn attach(&mut self, claim: u32, vid_pid: u32, _triple: u32, _speed_port: u32) -> Out<u32> {
        let c = Claim(claim);
        if c.is_device_scope() {
            return Out::new(BAD_ARGUMENT, 0);
        }
        if (vid_pid >> 16) as u16 != VID_SMSC || !PIDS.contains(&(vid_pid as u16)) {
            return Out::new(UNSUPPORTED, 0);
        }
        if self.gone || self.state != State::Idle {
            return Out::new(BUSY, 0);
        }
        self.claim = Some(c);
        self.vid_pid = vid_pid;
        self.state = State::Claimed;
        Out::new(OK, 0)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        if self.claim == Some(Claim(claim)) {
            // The core killed the pipes; the ring ends go on the next turn.
            self.gone = true;
            self.state = State::Failed(Fail::Gone);
        }
        Out::new(OK, 0)
    }
}

impl<M: Memory, C: Clock> NetFunction for Smsc95xx<'_, M, C> {
    const RULES: &'static [Match] = &[Match::interface_class(0xff)];

    fn session_wanted(&self) -> Option<Claim> {
        if self.state == State::Claimed { self.claim } else { None }
    }
    fn open(&mut self, dev: &mut dyn UsbDevice) {
        self.open_claim(dev)
    }
    fn service(&mut self) {
        self.service_turn()
    }
    fn is_ready(&self) -> bool {
        self.state == State::Ready
    }
    fn rx_pending(&self) -> bool {
        self.fifo_len > 0
    }
    fn take_submitted(&mut self) -> bool {
        core::mem::take(&mut self.submitted)
    }
    fn mac(&self) -> [u8; 6] {
        if self.state == State::Ready { self.mac } else { [0; 6] }
    }
    fn send(&mut self, frame: &[u8]) -> Result<(), SendError> {
        self.send_frame(frame)
    }
    fn recv(&mut self, out: &mut [u8]) -> usize {
        self.recv_frame(out)
    }
    fn tx_begin(&mut self) {}
    fn tx_end(&mut self) {}
}
