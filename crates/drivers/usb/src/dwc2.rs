// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The Synopsys DesignWare USB 2.0 OTG core (`snps,dwc2`, the Raspberry Pi's
//! `brcm,bcm2835-usb`) in host mode, as a controller of the USB core (Kconfig
//! `USB_DWC2`).
//!
//! # What the core sees
//!
//! The USB core was written against xHCI's model: slots that the controller
//! addresses, endpoints with a queue of transfer descriptors each, completion
//! events, a root hub of ports with change bits. A DWC2 has none of that in
//! hardware: one root port (`HPRT0`) and a handful of host channels, each of
//! which runs one transaction sequence to one endpoint of one device address
//! and halts. This driver supplies the model in software, so the core above it
//! is the same core that drives an xHCI ([`crate::usbcore::hc::Hc`]):
//!
//! - the root port's status is `HPRT0` translated to PORTSC bits (connect,
//!   enable, reset, power, speed, the change bits); a disconnect, which the
//!   core reports only in `GINTSTS`, becomes a connect change, and the end of
//!   a port reset (the software times it, 50 ms) a reset change;
//! - a slot is a USB address (the slot number) and the device behind it;
//!   addressing it is a SET_ADDRESS the driver sends to address 0 itself;
//! - an endpoint is a software queue of descriptors; the head descriptor of
//!   each endpoint gets a channel when one is free, and the channel runs its
//!   stages (setup, data, status for a control transfer; the data split by the
//!   channel's transfer-size and packet-count fields otherwise) until the
//!   descriptor is done, then goes back to the pool;
//! - completions are [`HcEvent::Done`] with xHCI's completion codes, the
//!   vocabulary of the core.
//!
//! Buffer DMA mode only (the core's internal DMA engine, `GHWCFG2.OTG_ARCH` =
//! internal DMA, which every DWC2 a supported board has). The driver is
//! polled, as the xHCI one is: the `usb` task calls [`Dwc2::poll`].
//!
//! # Buffers
//!
//! The DMA engine reads and writes whole packets: an IN transfer is programmed
//! as a whole number of max-size packets. A transfer whose length is not one
//! would let a device that sends more than asked write past the buffer, so the
//! last partial packet of an IN descriptor is received into the channel's own
//! bounce page and copied to the buffer, and more than was asked is babble.
//! That needs the CPU's view of the buffer ([`Memory::cpu_of`]): a descriptor
//! whose tail the platform cannot map is refused as [`Error::Bounce`], as is a
//! buffer that is not 4-byte aligned or lies above 4 GiB (the engine's
//! address register is 32 bits).
//!
//! # Not here
//!
//! Split transactions: a full- or low-speed device behind a high-speed hub
//! (behind the Pi 3 B's on-board LAN9514 hub, every external port) needs the
//! hub's transaction translator, which the channels reach with `HCSPLT`. Its
//! address is refused ([`Error::Invalid`]); a high-speed device behind the hub
//! (the LAN9514's own Ethernet function) and any device on the root port work.
//! Isochronous endpoints, high-bandwidth (more than one transaction per
//! microframe) interrupt endpoints, the descriptor DMA mode, the FIQ, an
//! interrupt route (polled like xHCI), OTG (HNP/SRP) and the device mode.

use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use crate::hw::{Clock, DmaBuf, Memory, Regs, PAGE};
use crate::xhci::context::{self, SlotParams};
use crate::xhci::regs as xr;
use crate::xhci::trb::cc;
use crate::xhci::{Done, EpSpec, Error, HcEvent, Owner, PortStatus, Speed, TdKind, TdSpec};
use crate::{MAX_DEVICES, MAX_PIPES};

/// The core's registers (DWC2 databook; Linux `drivers/usb/dwc2/hw.h` names
/// the same fields).
pub mod regs {
    pub const GOTGCTL: usize = 0x000;
    pub const GAHBCFG: usize = 0x008;
    pub const GUSBCFG: usize = 0x00c;
    pub const GRSTCTL: usize = 0x010;
    pub const GINTSTS: usize = 0x014;
    pub const GINTMSK: usize = 0x018;
    pub const GRXFSIZ: usize = 0x024;
    pub const GNPTXFSIZ: usize = 0x028;
    pub const GSNPSID: usize = 0x040;
    pub const GHWCFG2: usize = 0x048;
    pub const GHWCFG3: usize = 0x04c;
    pub const HPTXFSIZ: usize = 0x100;
    pub const HCFG: usize = 0x400;
    pub const HFNUM: usize = 0x408;
    pub const HAINT: usize = 0x414;
    pub const HAINTMSK: usize = 0x418;
    pub const HPRT0: usize = 0x440;
    pub const PCGCCTL: usize = 0xe00;

    /// Host channel `n`'s registers.
    pub const fn hc(n: usize) -> usize {
        0x500 + 0x20 * n
    }
    pub const HCCHAR: usize = 0x00;
    pub const HCSPLT: usize = 0x04;
    pub const HCINT: usize = 0x08;
    pub const HCINTMSK: usize = 0x0c;
    pub const HCTSIZ: usize = 0x10;
    pub const HCDMA: usize = 0x14;

    /// `GSNPSID`: "OT" and the core's major version (2.xx, 3.xx, 4.xx).
    pub const SNPSID_MASK: u32 = 0xffff_f000;
    pub const SNPSID_OT2: u32 = 0x4f54_2000;
    pub const SNPSID_OT3: u32 = 0x4f54_3000;
    pub const SNPSID_OT4: u32 = 0x4f54_4000;

    pub const GAHBCFG_GLBLINTRMSK: u32 = 1 << 0;
    /// Burst length INCR4 (field bits 4:1).
    pub const GAHBCFG_HBSTLEN_INCR4: u32 = 3 << 1;
    pub const GAHBCFG_DMAEN: u32 = 1 << 5;

    pub const GUSBCFG_FORCEHOSTMODE: u32 = 1 << 29;
    pub const GUSBCFG_FORCEDEVMODE: u32 = 1 << 30;

    pub const GRSTCTL_CSFTRST: u32 = 1 << 0;
    pub const GRSTCTL_RXFFLSH: u32 = 1 << 4;
    pub const GRSTCTL_TXFFLSH: u32 = 1 << 5;
    /// TXFNUM = 0x10: every transmit FIFO.
    pub const GRSTCTL_TXFNUM_ALL: u32 = 0x10 << 6;
    pub const GRSTCTL_AHBIDLE: u32 = 1 << 31;

    pub const GINTSTS_CURMOD_HOST: u32 = 1 << 0;
    pub const GINTSTS_PRTINT: u32 = 1 << 24;
    pub const GINTSTS_HCHINT: u32 = 1 << 25;
    pub const GINTSTS_DISCONNINT: u32 = 1 << 29;

    /// `GHWCFG2.OTG_ARCH` (bits 4:3): 2 = internal DMA.
    pub const HWCFG2_ARCH_SHIFT: u32 = 3;
    pub const HWCFG2_ARCH_INTERNAL_DMA: u32 = 2;
    /// `GHWCFG2.NUM_HOST_CHAN` (bits 17:14): channels - 1.
    pub const HWCFG2_NUM_HOST_CHAN_SHIFT: u32 = 14;

    /// `HCFG.FSLSPCLKSEL` (bits 1:0): 0 = the 30/60 MHz PHY clock of a
    /// high-speed (UTMI+ or ULPI) PHY.
    pub const HCFG_FSLSPCLKSEL_MASK: u32 = 3;
    pub const HCFG_FSLSSUPP: u32 = 1 << 2;

    pub const HPRT_CONNSTS: u32 = 1 << 0;
    pub const HPRT_CONNDET: u32 = 1 << 1;
    pub const HPRT_ENA: u32 = 1 << 2;
    pub const HPRT_ENCHNG: u32 = 1 << 3;
    pub const HPRT_OVRCURRACT: u32 = 1 << 4;
    pub const HPRT_OVRCURRCHNG: u32 = 1 << 5;
    pub const HPRT_RST: u32 = 1 << 8;
    pub const HPRT_PWR: u32 = 1 << 12;
    pub const HPRT_SPD_SHIFT: u32 = 17;
    pub const HPRT_SPD_MASK: u32 = 3 << HPRT_SPD_SHIFT;
    pub const HPRT_SPD_HIGH: u32 = 0;
    pub const HPRT_SPD_FULL: u32 = 1;
    pub const HPRT_SPD_LOW: u32 = 2;
    /// The bits a write of 1 clears (or, for ENA, disables the port): never
    /// written back as read.
    pub const HPRT_W1C: u32 = HPRT_CONNDET | HPRT_ENA | HPRT_ENCHNG | HPRT_OVRCURRCHNG;

    pub const HCCHAR_MPS_MASK: u32 = 0x7ff;
    pub const HCCHAR_EPNUM_SHIFT: u32 = 11;
    pub const HCCHAR_EPDIR_IN: u32 = 1 << 15;
    pub const HCCHAR_LSPDDEV: u32 = 1 << 17;
    pub const HCCHAR_EPTYPE_SHIFT: u32 = 18;
    pub const HCCHAR_MC_SHIFT: u32 = 20;
    pub const HCCHAR_DEVADDR_SHIFT: u32 = 22;
    pub const HCCHAR_ODDFRM: u32 = 1 << 29;
    pub const HCCHAR_CHDIS: u32 = 1 << 30;
    pub const HCCHAR_CHENA: u32 = 1 << 31;

    pub const EPTYPE_CONTROL: u32 = 0;
    pub const EPTYPE_ISOC: u32 = 1;
    pub const EPTYPE_BULK: u32 = 2;
    pub const EPTYPE_INTR: u32 = 3;

    pub const HCINT_XFERCOMPL: u32 = 1 << 0;
    pub const HCINT_CHHLTD: u32 = 1 << 1;
    pub const HCINT_AHBERR: u32 = 1 << 2;
    pub const HCINT_STALL: u32 = 1 << 3;
    pub const HCINT_NAK: u32 = 1 << 4;
    pub const HCINT_ACK: u32 = 1 << 5;
    pub const HCINT_NYET: u32 = 1 << 6;
    pub const HCINT_XACTERR: u32 = 1 << 7;
    pub const HCINT_BBLERR: u32 = 1 << 8;
    pub const HCINT_FRMOVRUN: u32 = 1 << 9;
    pub const HCINT_DATATGLERR: u32 = 1 << 10;
    pub const HCINT_ALL: u32 = 0x7ff;

    pub const HCTSIZ_XFERSIZE_MASK: u32 = 0x7_ffff;
    pub const HCTSIZ_PKTCNT_SHIFT: u32 = 19;
    pub const HCTSIZ_PKTCNT_MASK: u32 = 0x3ff;
    pub const HCTSIZ_PID_SHIFT: u32 = 29;
    pub const PID_DATA0: u32 = 0;
    pub const PID_DATA2: u32 = 1;
    pub const PID_DATA1: u32 = 2;
    pub const PID_SETUP: u32 = 3;
}

use regs::*;

/// Smallest register window that holds the channels and `PCGCCTL`.
pub const MIN_WINDOW: u64 = PCGCCTL as u64 + 4;

/// May the host driver take a DWC2 whose `dr_mode` property is `dr_mode` (the
/// raw value, `None` when the node has none)? Anything but `peripheral`. A
/// DWC2 is an OTG core: the binding's default (`otg`, also what a missing
/// property means) is a port that can be either, and the boards that have
/// one wire it as a host (the Raspberry Pis put the LAN9514 hub or a USB-A
/// socket on it). The driver forces host mode (`GUSBCFG.FORCEHOSTMODE`) and
/// never switches roles; a `peripheral` port is the gadget stack's.
pub fn may_host(dr_mode: Option<&[u8]>) -> bool {
    !dr_mode.is_some_and(|v| v == b"peripheral\0" || v == b"peripheral")
}

/// Host channels the driver drives at most (the core has 1 to 16).
pub const MAX_CHANNELS: usize = 16;
/// Endpoints the driver tracks: the control endpoint of every slot first,
/// then one per pipe, the same table the xHCI driver keeps
/// ([`crate::xhci::Xhci::ep0_index`], [`crate::xhci::Xhci::ep_for_pipe`]).
pub const MAX_EPS: usize = MAX_DEVICES + MAX_PIPES;
/// Descriptors queued per endpoint (the xHCI driver's depth).
pub const MAX_TDS: usize = crate::xhci::controller::MAX_TDS;
/// Events held for the core.
const EVENT_QUEUE: usize = 128;
/// Pages of the driver's region the core may take ([`Dwc2::take_page`]).
const CORE_PAGES: usize = 2;
/// Bytes of a channel's slot in the setup page (an 8-byte setup packet,
/// 64-byte apart so no two share a cache line).
const SETUP_SLOT: usize = 64;

/// Root port reset (USB 2.0 7.1.7.5, TDRSTR for a root port).
const PORT_RESET_US: u64 = 50_000;
/// What a reset, a flush, a mode switch or a channel halt gets.
const RESET_TIMEOUT_US: u64 = 100_000;
const MODE_TIMEOUT_US: u64 = 110_000;
const HALT_TIMEOUT_US: u64 = 10_000;
/// SET_ADDRESS gets this long.
const ADDRESS_TIMEOUT_US: u64 = 1_000_000;
/// Transaction errors in a row before a descriptor fails.
const MAX_ERRORS: u8 = 3;
/// A non-periodic transfer the core gave back NAKed is tried again after this.
const NAK_RETRY_US: u64 = 125;
/// FIFO sizes in 32-bit words (receive, non-periodic and periodic transmit):
/// what Linux gives the BCM2835's core, used when the FIFO RAM holds them.
const FIFO_RX: u32 = 774;
const FIFO_NPTX: u32 = 256;
const FIFO_PTX: u32 = 512;

const NO_EP: u16 = u16::MAX;
const NO_CHAN: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Idle,
    Setup,
    Data,
    Status,
    /// A bulk or interrupt descriptor's data.
    Xfer,
}

#[derive(Clone, Copy, Debug)]
struct Td {
    owner: Owner,
    tag: u32,
    kind: TdKind,
    /// The driver's own SET_ADDRESS: its completion is not an event.
    internal: bool,
}

const TD_NONE: Td = Td { owner: Owner::Core, tag: 0, kind: TdKind::Data { buf: 0, len: 0, dir_in: false }, internal: false };

/// One endpoint: its parameters, its queue, the progress of its head.
#[derive(Clone, Copy)]
struct Ep {
    used: bool,
    slot: u8,
    dci: u8,
    /// Endpoint number and direction (bulk and interrupt).
    num: u8,
    dir_in: bool,
    /// `HCCHAR.EPTYPE`.
    ty: u32,
    mps: u16,
    /// Service interval of an interrupt endpoint, us.
    period_us: u64,
    /// The data toggle the next data packet carries (0: DATA0, 1: DATA1).
    toggle: u8,
    halted: bool,
    tds: [Td; MAX_TDS],
    head: u8,
    count: u8,
    stage: Stage,
    /// Data bytes of the head descriptor moved so far.
    done: u32,
    /// The channel running the head descriptor.
    chan: u8,
    /// Not before this time (a periodic endpoint's next interval, a NAK retry).
    due_us: u64,
    errors: u8,
}

impl Ep {
    const FREE: Ep = Ep {
        used: false,
        slot: 0,
        dci: 0,
        num: 0,
        dir_in: false,
        ty: EPTYPE_CONTROL,
        mps: 8,
        period_us: 0,
        toggle: 0,
        halted: false,
        tds: [TD_NONE; MAX_TDS],
        head: 0,
        count: 0,
        stage: Stage::Idle,
        done: 0,
        chan: NO_CHAN,
        due_us: 0,
        errors: 0,
    };
    fn head_td(&self) -> Td {
        self.tds[self.head as usize]
    }
    fn pop(&mut self) -> Td {
        let t = self.tds[self.head as usize];
        self.head = ((self.head as usize + 1) % MAX_TDS) as u8;
        self.count -= 1;
        t
    }
    fn periodic(&self) -> bool {
        self.ty == EPTYPE_INTR
    }
}

/// What a channel is running.
#[derive(Clone, Copy)]
struct Chan {
    ep: u16,
    dir_in: bool,
    /// Bytes and packets programmed.
    len: u32,
    pkts: u32,
    /// Bytes of the descriptor this run is for (an IN run's `len` is whole
    /// packets and may be more).
    want: u32,
    /// An IN run into the bounce page, copied to `dest` when it completes.
    bounce: bool,
    dest: u64,
}

const CHAN_FREE: Chan = Chan { ep: NO_EP, dir_in: false, len: 0, pkts: 0, want: 0, bounce: false, dest: 0 };

#[derive(Clone, Copy)]
struct SlotInfo {
    used: bool,
    /// The USB address the device answers at (0 until SET_ADDRESS).
    addr: u8,
    speed: Speed,
}

const SLOT_FREE: SlotInfo = SlotInfo { used: false, addr: 0, speed: Speed::Full };

pub struct Dwc2<R: Regs, M: Memory, C: Clock> {
    regs: R,
    mem: M,
    clock: C,
    mask: u64,
    nchan: u8,
    /// Most bytes and packets one channel run can be given.
    max_xfer: u32,
    max_pkts: u32,
    /// The driver's DMA region: the setup page, a bounce page per channel,
    /// the core's pages.
    region: DmaBuf,
    core_taken: u8,
    slots: [SlotInfo; MAX_DEVICES],
    eps: [Ep; MAX_EPS],
    chans: [Chan; MAX_CHANNELS],
    events: [Option<HcEvent>; EVENT_QUEUE],
    ev_head: usize,
    ev_count: usize,
    lost_events: u32,
    /// The end of a port reset in flight.
    reset_until: Option<u64>,
    /// Soft change bits: a reset ended, a disconnect was seen.
    reset_changed: bool,
    disconnected: bool,
    /// The change bits last reported as an event.
    reported: u32,
    /// The completion code of the driver's own SET_ADDRESS.
    internal_done: Option<u8>,
    dead: bool,
}

impl<R: Regs, M: Memory, C: Clock> Dwc2<R, M, C> {
    /// Reset the core, put it in host mode and power its port. `dma_mask` is
    /// the highest bus address the device's DMA domain lets it reach (capped
    /// at 4 GiB, the engine's reach).
    pub fn new(regs: R, mem: M, clock: C, dma_mask: u64) -> Result<Self, Error> {
        let mut slot = MaybeUninit::<Self>::uninit();
        Self::init(&mut slot, regs, mem, clock, dma_mask)?;
        // SAFETY: `init` returned `Ok`, so it wrote every field.
        Ok(unsafe { slot.assume_init() })
    }

    /// [`Dwc2::new`] in place: the driver's tables (tens of KB with the
    /// default limits) are written field by field into `slot` and never exist
    /// as a value on the caller's stack. On `Err` the slot must not be assumed
    /// initialized.
    pub fn init<'a>(slot: &'a mut MaybeUninit<Self>, regs: R, mem: M, clock: C, dma_mask: u64) -> Result<&'a mut Self, Error> {
        let id = regs.read32(GSNPSID) & SNPSID_MASK;
        if !matches!(id, SNPSID_OT2 | SNPSID_OT3 | SNPSID_OT4) {
            return Err(Error::BadCaps);
        }
        let hw2 = regs.read32(GHWCFG2);
        if (hw2 >> HWCFG2_ARCH_SHIFT) & 3 != HWCFG2_ARCH_INTERNAL_DMA {
            return Err(Error::BadCaps);
        }
        let nchan = (((hw2 >> HWCFG2_NUM_HOST_CHAN_SHIFT) & 0xf) + 1).min(MAX_CHANNELS as u32) as u8;
        let hw3 = regs.read32(GHWCFG3);
        let max_xfer = (1u32 << ((hw3 & 0xf) + 11)) - 1;
        let max_pkts = (1u32 << (((hw3 >> 4) & 7) + 4)) - 1;
        let fifo_words = hw3 >> 16;
        let mask = dma_mask.min(u32::MAX as u64);
        let pages = 1 + nchan as usize + CORE_PAGES;
        let region = mem.alloc_region(pages * PAGE, PAGE, mask).ok_or(Error::NoMemory)?;
        let p = slot.as_mut_ptr();
        // SAFETY: `p` is valid and aligned for a `Self`; every field is
        // written exactly once through `addr_of_mut!` before `&mut *p` is
        // formed; the tables are filled element by element so that no
        // table-sized temporary is made.
        let d = unsafe {
            addr_of_mut!((*p).regs).write(regs);
            addr_of_mut!((*p).mem).write(mem);
            addr_of_mut!((*p).clock).write(clock);
            addr_of_mut!((*p).mask).write(mask);
            addr_of_mut!((*p).nchan).write(nchan);
            addr_of_mut!((*p).max_xfer).write(max_xfer);
            addr_of_mut!((*p).max_pkts).write(max_pkts);
            addr_of_mut!((*p).region).write(region);
            addr_of_mut!((*p).core_taken).write(0);
            addr_of_mut!((*p).slots).write([SLOT_FREE; MAX_DEVICES]);
            let eps = addr_of_mut!((*p).eps).cast::<Ep>();
            for i in 0..MAX_EPS {
                eps.add(i).write(Ep::FREE);
            }
            addr_of_mut!((*p).chans).write([CHAN_FREE; MAX_CHANNELS]);
            let evs = addr_of_mut!((*p).events).cast::<Option<HcEvent>>();
            for i in 0..EVENT_QUEUE {
                evs.add(i).write(None);
            }
            addr_of_mut!((*p).ev_head).write(0);
            addr_of_mut!((*p).ev_count).write(0);
            addr_of_mut!((*p).lost_events).write(0);
            addr_of_mut!((*p).reset_until).write(None);
            addr_of_mut!((*p).reset_changed).write(false);
            addr_of_mut!((*p).disconnected).write(false);
            addr_of_mut!((*p).reported).write(0);
            addr_of_mut!((*p).internal_done).write(None);
            addr_of_mut!((*p).dead).write(false);
            &mut *p
        };
        if let Err(e) = d.start(fifo_words) {
            d.mem.free_region(d.region);
            return Err(e);
        }
        Ok(d)
    }

    fn rd(&self, off: usize) -> u32 {
        self.regs.read32(off)
    }
    fn wr(&self, off: usize, v: u32) {
        self.regs.write32(off, v)
    }

    /// Wait until `(reg & mask) == want`, at most `us`.
    fn wait(&self, reg: usize, mask: u32, want: u32, us: u64) -> Result<(), Error> {
        let deadline = self.clock.now_us() + us;
        while self.rd(reg) & mask != want {
            if self.clock.now_us() >= deadline {
                return Err(Error::Timeout);
            }
            self.clock.delay_us(10);
        }
        Ok(())
    }

    /// Bring the core up as a host (the order of Linux `dwc2_core_init` and
    /// `dwc2_core_host_init`).
    fn start(&mut self, fifo_words: u32) -> Result<(), Error> {
        self.wr(GAHBCFG, self.rd(GAHBCFG) & !GAHBCFG_GLBLINTRMSK);
        // Core soft reset, with the AHB master idle on both sides of it.
        self.wait(GRSTCTL, GRSTCTL_AHBIDLE, GRSTCTL_AHBIDLE, RESET_TIMEOUT_US)?;
        self.wr(GRSTCTL, self.rd(GRSTCTL) | GRSTCTL_CSFTRST);
        self.wait(GRSTCTL, GRSTCTL_CSFTRST, 0, RESET_TIMEOUT_US)?;
        self.wait(GRSTCTL, GRSTCTL_AHBIDLE, GRSTCTL_AHBIDLE, RESET_TIMEOUT_US)?;
        // Host mode, whatever the ID pin says.
        let u = self.rd(GUSBCFG);
        self.wr(GUSBCFG, (u & !GUSBCFG_FORCEDEVMODE) | GUSBCFG_FORCEHOSTMODE);
        self.wait(GINTSTS, GINTSTS_CURMOD_HOST, GINTSTS_CURMOD_HOST, MODE_TIMEOUT_US)?;
        self.wr(PCGCCTL, 0);
        // A high-speed PHY clocks full and low speed too (FSLSPCLKSEL 30/60 MHz).
        self.wr(HCFG, self.rd(HCFG) & !(HCFG_FSLSPCLKSEL_MASK | HCFG_FSLSSUPP));
        // FIFOs: Linux's BCM2835 sizes when the RAM holds them, else halves.
        let (rx, np, pt) = if fifo_words >= FIFO_RX + FIFO_NPTX + FIFO_PTX {
            (FIFO_RX, FIFO_NPTX, FIFO_PTX)
        } else {
            let rx = fifo_words / 2;
            let np = fifo_words / 4;
            (rx, np, fifo_words - rx - np)
        };
        self.wr(GRXFSIZ, rx);
        self.wr(GNPTXFSIZ, np << 16 | rx);
        self.wr(HPTXFSIZ, pt << 16 | (rx + np));
        self.wr(GRSTCTL, GRSTCTL_TXFFLSH | GRSTCTL_TXFNUM_ALL);
        self.wait(GRSTCTL, GRSTCTL_TXFFLSH, 0, RESET_TIMEOUT_US)?;
        self.wr(GRSTCTL, GRSTCTL_RXFFLSH);
        self.wait(GRSTCTL, GRSTCTL_RXFFLSH, 0, RESET_TIMEOUT_US)?;
        // Every channel halted and quiet.
        for ch in 0..self.nchan as usize {
            self.halt_channel(ch);
            self.wr(hc(ch) + HCINTMSK, 0);
        }
        self.wr(HAINTMSK, 0);
        self.wr(GINTMSK, 0);
        self.wr(GINTSTS, u32::MAX);
        // Port power on.
        let h = self.rd(HPRT0);
        if h & HPRT_PWR == 0 {
            self.wr(HPRT0, hprt_keep(h) | HPRT_PWR);
        }
        self.setup_page().zero();
        self.mem.to_device(self.setup_page().cpu(), PAGE);
        if !self.mem.enable() {
            return Err(Error::Dma);
        }
        self.wr(GAHBCFG, GAHBCFG_DMAEN | GAHBCFG_HBSTLEN_INCR4);
        Ok(())
    }

    fn setup_page(&self) -> DmaBuf {
        self.region.sub(0, PAGE)
    }
    fn bounce_page(&self, ch: usize) -> DmaBuf {
        self.region.sub((1 + ch) * PAGE, PAGE)
    }

    // ---- What the core reads ----

    pub fn ports(&self) -> u8 {
        1
    }
    /// Host channels in use by the driver.
    pub fn channels(&self) -> u8 {
        self.nchan
    }
    pub fn dma_mask(&self) -> u64 {
        self.mask
    }
    pub fn is_dead(&self) -> bool {
        self.dead
    }
    pub fn lost_events(&self) -> u32 {
        self.lost_events
    }
    pub fn clock(&self) -> &C {
        &self.clock
    }
    pub fn mem(&self) -> &M {
        &self.mem
    }
    /// A page of the region for the core's own use (its control buffer, its
    /// hub buffer).
    pub fn take_page(&mut self) -> Option<DmaBuf> {
        if self.core_taken as usize == CORE_PAGES {
            return None;
        }
        let at = (1 + self.nchan as usize + self.core_taken as usize) * PAGE;
        self.core_taken += 1;
        let p = self.region.sub(at, PAGE);
        p.zero();
        Some(p)
    }

    // ---- Events ----

    fn push_event(&mut self, e: HcEvent) {
        if self.ev_count == EVENT_QUEUE {
            self.lost_events += 1;
            return;
        }
        let at = (self.ev_head + self.ev_count) % EVENT_QUEUE;
        self.events[at] = Some(e);
        self.ev_count += 1;
    }

    pub fn next_event(&mut self) -> Option<HcEvent> {
        if self.ev_count == 0 {
            return None;
        }
        let e = self.events[self.ev_head].take();
        self.ev_head = (self.ev_head + 1) % EVENT_QUEUE;
        self.ev_count -= 1;
        e
    }

    // ---- The root port ----

    /// Finish a port reset whose time is up: the reset bit goes, the port
    /// enables, and the reset counts as a change.
    fn port_tick(&mut self) {
        let Some(until) = self.reset_until else { return };
        if self.clock.now_us() < until {
            return;
        }
        let h = self.rd(HPRT0);
        self.wr(HPRT0, hprt_keep(h) & !HPRT_RST);
        self.reset_until = None;
        self.reset_changed = true;
    }

    /// `HPRT0` as the PORTSC bits the core reads.
    pub fn port_status(&mut self, port: u8) -> PortStatus {
        if port != 1 {
            return PortStatus(0);
        }
        self.port_tick();
        let h = self.rd(HPRT0);
        let mut v = 0;
        if h & HPRT_CONNSTS != 0 {
            v |= xr::PORTSC_CCS;
            let psiv = match (h & HPRT_SPD_MASK) >> HPRT_SPD_SHIFT {
                HPRT_SPD_HIGH => Speed::High,
                HPRT_SPD_LOW => Speed::Low,
                _ => Speed::Full,
            }
            .psiv();
            v |= psiv << xr::PORTSC_SPEED_SHIFT;
        }
        if h & HPRT_ENA != 0 {
            v |= xr::PORTSC_PED;
        }
        if h & HPRT_RST != 0 || self.reset_until.is_some() {
            v |= xr::PORTSC_PR;
        }
        if h & HPRT_PWR != 0 {
            v |= xr::PORTSC_PP;
        }
        if h & HPRT_OVRCURRACT != 0 {
            v |= xr::PORTSC_OCA;
        }
        if h & HPRT_CONNDET != 0 || self.disconnected {
            v |= xr::PORTSC_CSC;
        }
        if h & HPRT_ENCHNG != 0 {
            v |= xr::PORTSC_PEC;
        }
        if h & HPRT_OVRCURRCHNG != 0 {
            v |= xr::PORTSC_OCC;
        }
        if self.reset_changed {
            v |= xr::PORTSC_PRC;
        }
        PortStatus(v)
    }

    /// Acknowledge the PORTSC change bits in `changes`.
    pub fn port_ack(&mut self, port: u8, changes: u32) {
        if port != 1 {
            return;
        }
        let mut w1c = 0;
        if changes & xr::PORTSC_CSC != 0 {
            w1c |= HPRT_CONNDET;
            self.disconnected = false;
        }
        if changes & xr::PORTSC_PEC != 0 {
            w1c |= HPRT_ENCHNG;
        }
        if changes & xr::PORTSC_OCC != 0 {
            w1c |= HPRT_OVRCURRCHNG;
        }
        if changes & xr::PORTSC_PRC != 0 {
            self.reset_changed = false;
        }
        if w1c != 0 {
            let h = self.rd(HPRT0);
            self.wr(HPRT0, hprt_keep(h) | w1c);
        }
        self.reported &= !changes;
    }

    /// Start a port reset; it ends [`PORT_RESET_US`] later, on a later look
    /// at the port.
    pub fn port_reset(&mut self, port: u8) {
        if port != 1 {
            return;
        }
        let h = self.rd(HPRT0);
        self.wr(HPRT0, hprt_keep(h) | HPRT_RST);
        self.reset_until = Some(self.clock.now_us() + PORT_RESET_US);
    }

    // ---- Slots ----

    fn slot_ix(&self, slot: u8) -> Result<usize, Error> {
        if slot == 0 || slot as usize > MAX_DEVICES || !self.slots[slot as usize - 1].used {
            return Err(Error::Invalid);
        }
        Ok(slot as usize - 1)
    }

    /// A free slot: the USB address its device will be given.
    pub fn enable_slot(&mut self) -> Result<u8, Error> {
        if self.dead {
            return Err(Error::Dead);
        }
        let i = self.slots.iter().position(|s| !s.used).ok_or(Error::Command(cc::NO_SLOTS))?;
        self.slots[i] = SlotInfo { used: true, addr: 0, speed: Speed::Full };
        Ok(i as u8 + 1)
    }

    /// Give `slot` its control endpoint and address the device: SET_ADDRESS
    /// to address 0, waited for. A full- or low-speed device behind a
    /// high-speed hub would need split transactions: refused (see the module
    /// documentation).
    pub fn address_device(&mut self, slot: u8, params: SlotParams, ep0_mps: u16) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        let speed = Speed::from_psiv(params.speed_psiv).ok_or(Error::Invalid)?;
        // Canary: a device that needs a split is addressed without one.
        let needs_split = speed <= Speed::Full && params.tt_slot != 0 && !cfg!(feature = "canary-dwc2-split");
        if speed.is_super() || needs_split {
            return Err(Error::Invalid);
        }
        self.slots[si].speed = speed;
        self.slots[si].addr = 0;
        let ix = si;
        self.eps[ix] = Ep { used: true, slot, dci: 1, ty: EPTYPE_CONTROL, mps: ep0_mps.max(8), ..Ep::FREE };
        let setup = [0x00, 0x05, slot, 0, 0, 0, 0, 0];
        self.internal_done = None;
        self.push_td(
            ix,
            Td { owner: Owner::Core, tag: 0, kind: TdKind::Control { setup, buf: 0, len: 0, dir_in: false }, internal: true },
        )?;
        let deadline = self.clock.now_us() + ADDRESS_TIMEOUT_US;
        loop {
            self.poll();
            if let Some(code) = self.internal_done.take() {
                if code != cc::SUCCESS {
                    self.recover_ep(ix, false);
                    return Err(Error::Command(code));
                }
                break;
            }
            if self.dead {
                return Err(Error::Dead);
            }
            if self.clock.now_us() >= deadline {
                self.abort_ep(ix, cc::STOPPED);
                return Err(Error::Timeout);
            }
            self.clock.delay_us(50);
        }
        self.slots[si].addr = slot;
        Ok(())
    }

    /// Nothing to tell the hardware: a hub is a device like any other to a
    /// DWC2 (the transaction translator fields matter only to splits).
    pub fn update_slot(&mut self, slot: u8, _params: SlotParams) -> Result<(), Error> {
        self.slot_ix(slot).map(|_| ())
    }

    pub fn set_ep0_mps(&mut self, slot: u8, mps: u16) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        self.eps[si].mps = mps.max(8);
        Ok(())
    }

    /// Add endpoints. Bulk and interrupt only (isochronous is
    /// [`Error::Invalid`]: the module documentation).
    pub fn configure_endpoints(&mut self, slot: u8, specs: &[EpSpec]) -> Result<(), Error> {
        self.slot_ix(slot)?;
        for s in specs {
            let ix = s.ep as usize;
            if !(MAX_DEVICES..MAX_EPS).contains(&ix) || s.dci < 2 {
                return Err(Error::Invalid);
            }
            let (ty, dir_in) = match s.ep_type {
                context::EP_TYPE_BULK_IN => (EPTYPE_BULK, true),
                context::EP_TYPE_BULK_OUT => (EPTYPE_BULK, false),
                context::EP_TYPE_INT_IN => (EPTYPE_INTR, true),
                context::EP_TYPE_INT_OUT => (EPTYPE_INTR, false),
                _ => return Err(Error::Invalid),
            };
            if s.mps == 0 || s.mps > 1024 {
                return Err(Error::Invalid);
            }
            self.eps[ix] = Ep {
                used: true,
                slot,
                dci: s.dci,
                num: s.dci / 2,
                dir_in,
                ty,
                mps: s.mps,
                // xHCI's interval field: 2^interval * 125 us at every speed.
                period_us: if ty == EPTYPE_INTR { 125u64 << s.interval.min(15) } else { 0 },
                ..Ep::FREE
            };
        }
        Ok(())
    }

    /// Drop endpoints by DCI; descriptors still queued complete as stopped.
    pub fn drop_endpoints(&mut self, slot: u8, dcis: u32) -> Result<(), Error> {
        self.slot_ix(slot)?;
        for ix in MAX_DEVICES..MAX_EPS {
            let e = &self.eps[ix];
            if e.used && e.slot == slot && e.dci >= 2 && dcis & (1 << e.dci) != 0 {
                self.abort_ep(ix, cc::STOPPED);
                self.eps[ix] = Ep::FREE;
            }
        }
        Ok(())
    }

    /// Forget a slot: its endpoints stop, what they had queued completes as
    /// stopped, and the address is free again.
    pub fn disable_slot(&mut self, slot: u8) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        for ix in 0..MAX_EPS {
            if self.eps[ix].used && self.eps[ix].slot == slot {
                self.abort_ep(ix, cc::STOPPED);
                self.eps[ix] = Ep::FREE;
            }
        }
        self.slots[si] = SLOT_FREE;
        Ok(())
    }

    // ---- Transfers ----

    pub fn ep_halted(&self, ep: u16) -> bool {
        self.eps.get(ep as usize).is_some_and(|e| e.halted)
    }

    /// Queue one transfer descriptor on endpoint `ep`; it starts as soon as
    /// a channel is free.
    pub fn queue_td(&mut self, ep: u16, spec: TdSpec) -> Result<(), Error> {
        if self.dead {
            return Err(Error::Dead);
        }
        let ix = ep as usize;
        if ix >= MAX_EPS || !self.eps[ix].used {
            return Err(Error::Invalid);
        }
        let (buf, len, dir_in) = match spec.kind {
            TdKind::Control { buf, len, dir_in, .. } => (buf, len as u32, dir_in),
            TdKind::Data { buf, len, dir_in } => (buf, len, dir_in),
            TdKind::Isoch { .. } => return Err(Error::Invalid),
        };
        let control = matches!(spec.kind, TdKind::Control { .. });
        if control != (self.eps[ix].ty == EPTYPE_CONTROL) || (!control && dir_in != self.eps[ix].dir_in) {
            return Err(Error::Invalid);
        }
        if len > 0 {
            if buf.checked_add(len as u64 - 1).is_none_or(|e| e > self.mask) {
                return Err(Error::Bounce);
            }
            if buf & 3 != 0 {
                return Err(Error::Bounce);
            }
            // The partial last packet of an IN goes through the bounce page.
            let tail = len % self.eps[ix].mps as u32;
            if dir_in && tail != 0 && self.mem.cpu_of(buf + (len - tail) as u64, tail as usize).is_none() {
                return Err(Error::Bounce);
            }
        }
        self.push_td(ix, Td { owner: spec.owner, tag: spec.tag, kind: spec.kind, internal: false })
    }

    fn push_td(&mut self, ix: usize, t: Td) -> Result<(), Error> {
        let e = &mut self.eps[ix];
        if e.halted || e.count as usize == MAX_TDS {
            return Err(Error::Busy);
        }
        let at = (e.head as usize + e.count as usize) % MAX_TDS;
        e.tds[at] = t;
        e.count += 1;
        self.schedule();
        Ok(())
    }

    /// Bring every halted endpoint back: what was queued behind the failure
    /// completes as stopped and the toggle starts again at DATA0 (the
    /// device's does too when the class driver clears the halt). Returns how
    /// many were recovered.
    pub fn recover_halted(&mut self) -> usize {
        let mut n = 0;
        for ix in 0..MAX_EPS {
            if self.eps[ix].used && self.eps[ix].halted && !self.dead {
                self.recover_ep(ix, true);
                n += 1;
            }
        }
        n
    }

    fn recover_ep(&mut self, ix: usize, events: bool) {
        let (slot, dci) = (self.eps[ix].slot, self.eps[ix].dci);
        while self.eps[ix].count > 0 {
            let t = self.eps[ix].pop();
            if events && !t.internal {
                self.push_event(HcEvent::Done(Done { owner: t.owner, tag: t.tag, code: cc::STOPPED, actual: 0, slot, dci }));
            }
        }
        let e = &mut self.eps[ix];
        e.halted = false;
        e.toggle = 0;
        e.stage = Stage::Idle;
        e.done = 0;
        e.errors = 0;
    }

    /// Stop endpoint `ix`: its channel is halted and freed, every descriptor
    /// it holds completes with `code`.
    fn abort_ep(&mut self, ix: usize, code: u8) {
        let ch = self.eps[ix].chan;
        if ch != NO_CHAN {
            self.halt_channel(ch as usize);
            self.chans[ch as usize] = CHAN_FREE;
            self.eps[ix].chan = NO_CHAN;
        }
        let (slot, dci) = (self.eps[ix].slot, self.eps[ix].dci);
        while self.eps[ix].count > 0 {
            let t = self.eps[ix].pop();
            if t.internal {
                self.internal_done = Some(code);
            } else {
                self.push_event(HcEvent::Done(Done { owner: t.owner, tag: t.tag, code, actual: 0, slot, dci }));
            }
        }
        let e = &mut self.eps[ix];
        e.stage = Stage::Idle;
        e.done = 0;
    }

    /// Halt channel `ch` if it runs, and clear its interrupts.
    fn halt_channel(&self, ch: usize) {
        let c = self.rd(hc(ch) + HCCHAR);
        if c & HCCHAR_CHENA != 0 {
            self.wr(hc(ch) + HCCHAR, (c & !HCCHAR_EPDIR_IN) | HCCHAR_CHENA | HCCHAR_CHDIS);
            let _ = self.wait(hc(ch) + HCCHAR, HCCHAR_CHENA, 0, HALT_TIMEOUT_US);
        }
        self.wr(hc(ch) + HCINT, HCINT_ALL);
    }

    /// One turn: the port, the channels that halted, then a channel for every
    /// endpoint whose head descriptor waits.
    pub fn poll(&mut self) {
        if self.dead {
            return;
        }
        let g = self.rd(GINTSTS);
        if g & GINTSTS_DISCONNINT != 0 {
            self.wr(GINTSTS, GINTSTS_DISCONNINT);
            self.disconnected = true;
        }
        if g & GINTSTS_CURMOD_HOST == 0 {
            // The core left host mode (an ID-pin flip on an OTG port): nothing
            // the driver started can finish.
            self.dead = true;
            return;
        }
        let changes = self.port_status(1).changes();
        if changes & !self.reported != 0 {
            self.push_event(HcEvent::PortChange(1));
        }
        self.reported = changes;
        for ch in 0..self.nchan as usize {
            if self.chans[ch].ep == NO_EP {
                continue;
            }
            let int = self.rd(hc(ch) + HCINT);
            if int & HCINT_CHHLTD != 0 {
                self.wr(hc(ch) + HCINT, int);
                self.channel_halted(ch, int);
            }
        }
        self.schedule();
    }

    /// Give a channel to every endpoint whose head descriptor waits and is
    /// due, while channels are free.
    fn schedule(&mut self) {
        if self.dead {
            return;
        }
        let now = self.clock.now_us();
        for ix in 0..MAX_EPS {
            let e = &self.eps[ix];
            if !e.used || e.halted || e.count == 0 || e.chan != NO_CHAN || e.due_us > now {
                continue;
            }
            let Some(ch) = (0..self.nchan as usize).find(|&c| self.chans[c].ep == NO_EP) else { return };
            self.chans[ch].ep = ix as u16;
            self.eps[ix].chan = ch as u8;
            if self.eps[ix].stage == Stage::Idle {
                let t = self.eps[ix].head_td();
                self.eps[ix].stage = if matches!(t.kind, TdKind::Control { .. }) { Stage::Setup } else { Stage::Xfer };
                self.eps[ix].done = 0;
            }
            self.run(ix, ch);
        }
    }

    /// Program channel `ch` for the next run of endpoint `ix`'s head
    /// descriptor and enable it.
    fn run(&mut self, ix: usize, ch: usize) {
        let e = self.eps[ix];
        let t = e.head_td();
        let mps = e.mps.max(1) as u32;
        let (dir_in, pid, bus, len, ty) = match (e.stage, t.kind) {
            (Stage::Setup, TdKind::Control { setup, .. }) => {
                let s = self.setup_page().sub(ch * SETUP_SLOT, SETUP_SLOT);
                s.write_bytes(0, &setup);
                self.mem.to_device(s.cpu(), 8);
                (false, PID_SETUP, s.bus(), 8, EPTYPE_CONTROL)
            }
            (Stage::Data, TdKind::Control { buf, len, dir_in, .. }) => {
                let pid = if e.done == 0 { PID_DATA1 } else { toggle_pid(e.toggle) };
                (dir_in, pid, buf + e.done as u64, len as u32 - e.done, EPTYPE_CONTROL)
            }
            (Stage::Status, TdKind::Control { len, dir_in, .. }) => {
                // The other way from the data stage (IN when there is none).
                let s = self.setup_page().sub(ch * SETUP_SLOT, SETUP_SLOT);
                (len == 0 || !dir_in, PID_DATA1, s.bus(), 0, EPTYPE_CONTROL)
            }
            (_, TdKind::Data { buf, len, dir_in }) => (dir_in, toggle_pid(e.toggle), buf + e.done as u64, len - e.done, e.ty),
            _ => {
                // A descriptor on a stage it has no business in: finish it as
                // a TRB error, xHCI's code for a malformed descriptor.
                self.finish(ix, cc::TRB_ERROR, 0);
                return;
            }
        };
        // Whole packets direct; the partial last one of an IN to the bounce page.
        let chunk_max = (self.max_xfer / mps * mps).min(self.max_pkts * mps).max(mps);
        let (prog, pkts, bounce) = if dir_in && len > 0 {
            let whole = len / mps * mps;
            if whole > 0 {
                let p = whole.min(chunk_max);
                (p, p / mps, false)
            } else {
                // Canary: the tail is received in place, as a whole packet.
                (mps, 1, !cfg!(feature = "canary-dwc2-no-bounce"))
            }
        } else if len == 0 {
            (0, 1, false)
        } else {
            let p = len.min(chunk_max);
            (p, p.div_ceil(mps), false)
        };
        let want = if bounce { len } else { prog.min(len) };
        let dma = if bounce { self.bounce_page(ch).bus() } else { bus };
        self.chans[ch] = Chan { ep: ix as u16, dir_in, len: prog, pkts, want, bounce, dest: bus };
        let s = self.slots[e.slot as usize - 1];
        let mut hcchar = (mps & HCCHAR_MPS_MASK)
            | (e.num as u32) << HCCHAR_EPNUM_SHIFT
            | ty << HCCHAR_EPTYPE_SHIFT
            | 1 << HCCHAR_MC_SHIFT
            | (s.addr as u32) << HCCHAR_DEVADDR_SHIFT;
        if dir_in {
            hcchar |= HCCHAR_EPDIR_IN;
        }
        if s.speed == Speed::Low {
            hcchar |= HCCHAR_LSPDDEV;
        }
        // A periodic transaction goes out in the (micro)frame whose parity
        // ODDFRM names: the next one.
        if ty == EPTYPE_INTR && self.rd(HFNUM) & 1 == 0 {
            hcchar |= HCCHAR_ODDFRM;
        }
        let base = hc(ch);
        self.wr(base + HCINT, HCINT_ALL);
        self.wr(base + HCINTMSK, HCINT_CHHLTD);
        self.wr(base + HCSPLT, 0);
        self.wr(base + HCTSIZ, prog | pkts << HCTSIZ_PKTCNT_SHIFT | pid << HCTSIZ_PID_SHIFT);
        self.wr(base + HCDMA, dma as u32);
        self.wr(base + HCCHAR, hcchar);
        self.wr(base + HCCHAR, hcchar | HCCHAR_CHENA);
    }

    /// Channel `ch` halted with interrupt bits `int`.
    fn channel_halted(&mut self, ch: usize, int: u32) {
        let c = self.chans[ch];
        let ix = c.ep as usize;
        self.chans[ch] = CHAN_FREE;
        if ix >= MAX_EPS {
            return;
        }
        self.eps[ix].chan = NO_CHAN;
        if !self.eps[ix].used || self.eps[ix].count == 0 {
            return;
        }
        let tsiz = self.rd(hc(ch) + HCTSIZ);
        let mps = self.eps[ix].mps.max(1) as u32;
        let moved = if c.dir_in {
            c.len.saturating_sub(tsiz & HCTSIZ_XFERSIZE_MASK)
        } else {
            let left = (tsiz >> HCTSIZ_PKTCNT_SHIFT) & HCTSIZ_PKTCNT_MASK;
            if int & HCINT_XFERCOMPL != 0 { c.len } else { (c.pkts.saturating_sub(left) * mps).min(c.len) }
        };
        // The toggle the endpoint is at now: what the core left in the PID.
        // Canary: the toggle is never read back (every packet DATA0).
        if self.eps[ix].stage != Stage::Setup && !cfg!(feature = "canary-dwc2-toggle") {
            self.eps[ix].toggle = if (tsiz >> HCTSIZ_PID_SHIFT) & 3 == PID_DATA0 { 0 } else { 1 };
        }
        let now = self.clock.now_us();
        if int & HCINT_XFERCOMPL != 0 {
            self.eps[ix].errors = 0;
            let mut got = moved.min(c.want);
            if c.bounce {
                if moved > c.want {
                    self.finish(ix, cc::BABBLE, 0);
                    self.eps[ix].halted = true;
                    return;
                }
                // At most one packet (`moved <= want < mps <= 1024`).
                let n = moved as usize;
                let b = self.bounce_page(ch);
                self.mem.from_device(b.cpu(), n);
                let mut tmp = [0u8; 1024];
                b.read_bytes(0, &mut tmp[..n]);
                match self.mem.cpu_of(c.dest, n) {
                    Some(dst) => {
                        // SAFETY: `cpu_of` names `n` writable bytes at `dst`,
                        // the buffer the descriptor was queued with.
                        unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), dst, n) };
                        // Written by the CPU for a reader that drops its stale
                        // lines first: clean them to memory.
                        self.mem.to_device(dst, n);
                    }
                    None => got = 0,
                }
            }
            let short = c.dir_in && moved < c.len;
            self.advance(ix, ch, got, short, now);
            return;
        }
        if int & HCINT_STALL != 0 {
            self.finish(ix, cc::STALL, 0);
            self.eps[ix].halted = true;
            return;
        }
        if int & HCINT_BBLERR != 0 {
            self.finish(ix, cc::BABBLE, 0);
            self.eps[ix].halted = true;
            return;
        }
        if int & HCINT_AHBERR != 0 {
            self.finish(ix, cc::DATA_BUFFER_ERROR, 0);
            self.eps[ix].halted = true;
            return;
        }
        // What was moved before the run stopped counts (an OUT's acknowledged
        // packets, an IN's received bytes).
        if !c.bounce && matches!(self.eps[ix].stage, Stage::Data | Stage::Xfer) {
            self.eps[ix].done += moved.min(c.want);
        }
        if int & (HCINT_XACTERR | HCINT_DATATGLERR | HCINT_FRMOVRUN) != 0 {
            self.eps[ix].errors += 1;
            if self.eps[ix].errors >= MAX_ERRORS {
                self.finish(ix, cc::USB_TRANSACTION_ERROR, 0);
                self.eps[ix].halted = true;
                return;
            }
            self.eps[ix].due_us = now + self.eps[ix].period_us.max(NAK_RETRY_US);
            return;
        }
        // A NAK (or a halt the driver asked for): nothing to report, try again
        // at the endpoint's next interval.
        self.eps[ix].due_us = now + if self.eps[ix].periodic() { self.eps[ix].period_us } else { NAK_RETRY_US };
    }

    /// A run completed: move the head descriptor on, and run its next stage
    /// on the same channel or finish it.
    fn advance(&mut self, ix: usize, ch: usize, got: u32, short: bool, now: u64) {
        let t = self.eps[ix].head_td();
        match (self.eps[ix].stage, t.kind) {
            (Stage::Setup, TdKind::Control { len, .. }) => {
                self.eps[ix].stage = if len > 0 { Stage::Data } else { Stage::Status };
            }
            (Stage::Data, TdKind::Control { len, .. }) => {
                self.eps[ix].done += got;
                if short || self.eps[ix].done >= len as u32 {
                    self.eps[ix].stage = Stage::Status;
                }
            }
            (Stage::Status, TdKind::Control { .. }) => {
                let actual = self.eps[ix].done;
                self.finish(ix, cc::SUCCESS, actual);
                return;
            }
            (Stage::Xfer, TdKind::Data { len, .. }) => {
                self.eps[ix].done += got;
                let done = self.eps[ix].done;
                if short || done >= len {
                    self.finish(ix, if done < len { cc::SHORT_PACKET } else { cc::SUCCESS }, done);
                    if self.eps[ix].periodic() {
                        self.eps[ix].due_us = now + self.eps[ix].period_us;
                    }
                    return;
                }
            }
            _ => {
                self.finish(ix, cc::TRB_ERROR, 0);
                return;
            }
        }
        // The next stage (or chunk) right away, on the same channel.
        self.chans[ch].ep = ix as u16;
        self.eps[ix].chan = ch as u8;
        self.run(ix, ch);
    }

    /// The head descriptor of `ix` is over: report it and free its channel.
    fn finish(&mut self, ix: usize, code: u8, actual: u32) {
        let ch = self.eps[ix].chan;
        if ch != NO_CHAN {
            self.chans[ch as usize] = CHAN_FREE;
            self.eps[ix].chan = NO_CHAN;
        }
        let (slot, dci) = (self.eps[ix].slot, self.eps[ix].dci);
        let t = self.eps[ix].pop();
        let e = &mut self.eps[ix];
        e.stage = Stage::Idle;
        e.done = 0;
        e.errors = 0;
        if t.internal {
            self.internal_done = Some(code);
        } else {
            self.push_event(HcEvent::Done(Done { owner: t.owner, tag: t.tag, code, actual, slot, dci }));
        }
    }
}

/// `HPRT0` as read, made safe to write back: the write-1-to-clear bits (and
/// the enable bit, which a 1 clears) dropped.
fn hprt_keep(h: u32) -> u32 {
    // Canary: written back as read, which disables the port.
    if cfg!(feature = "canary-dwc2-hprt-w1c") {
        h
    } else {
        h & !HPRT_W1C
    }
}

/// The PID of a data packet with toggle `t`.
fn toggle_pid(t: u8) -> u32 {
    if t == 0 {
        PID_DATA0
    } else {
        PID_DATA1
    }
}
