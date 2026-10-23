// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The xHCI controller: bring-up, the command ring, the event ring of
//! interrupter 0, slots and their contexts, endpoints and transfer
//! descriptors, ports.
//!
//! # Shape
//!
//! [`Xhci::new`] resets the controller and starts it (device context base
//! array, scratchpad buffers, command ring, event ring, run). From then on
//! the driver is polled: [`Xhci::poll`] drains the event ring, answers command
//! completions to whoever waits for them, and turns the rest into
//! [`HcEvent`]s the USB core takes with [`Xhci::next_event`]. The same
//! function is what an MSI-X handler would call; the controller is polled
//! when the machine has no route.
//!
//! Commands are synchronous ([`Xhci::command`] rings the doorbell and drains
//! events until the completion carrying its TRB's address arrives, or a
//! deadline passes: a dead controller is an error, not a hang). Transfers are
//! asynchronous: [`Xhci::queue_td`] writes the TRBs of one transfer
//! descriptor and rings the endpoint's doorbell, and the completion comes
//! back as [`HcEvent::Done`] with the owner and tag it was queued with.
//!
//! # Memory
//!
//! Every page the controller reads or writes comes out of one [`Arena`]
//! (one DMA mapping), and lies under the controller's addressing limit: the
//! caller's DMA mask, narrowed to 32 bits when HCCPARAMS1.AC64 is clear. A
//! transfer buffer the class driver hands in is checked against the same
//! limit ([`Error::Bounce`]): the controller is never given an address it
//! cannot reach.
//!
//! # Endpoints and their errors
//!
//! An endpoint is a transfer ring page and a short FIFO of the descriptors in
//! flight ([`Ep`]). A transfer that fails halts the endpoint on the
//! controller; [`Xhci::recover_halted`] resets it (Reset Endpoint), completes
//! what was queued behind the failure as stopped, and moves the dequeue
//! pointer to the enqueue pointer, so the ring is usable again. The device
//! side of a stall (CLEAR_FEATURE ENDPOINT_HALT) is the class driver's.
//!
//! # A controller that stops answering
//!
//! A command its deadline passes on is the device timeout policy's
//! (`azos_drv_api::recovery`, Kconfig `DEVICE_TIMEOUT_RESETS`, the
//! `usb-host-fault` decision record): with a reset left, the controller is
//! halted, reset (HCRST, then Controller Not Ready clears) and programmed
//! again over the memory it had (`Xhci::reset`), and every device it held
//! is gone: the controller refuses commands and transfers
//! ([`Error::Reset`]) until the USB core has removed each of them, their
//! transfers ending `Disconnected` and their class drivers told, and taken
//! the reset ([`Xhci::ack_reset`]); the core then enumerates the ports
//! again. With the resets spent, or when the reset does not bring the same
//! controller back, it is halted and latched dead until reboot, its memory
//! never reused. A host system error or a host controller error the
//! controller reports (USBSTS.HSE, USBSTS.HCE: xHCI 1.2 section 4.10.2.6 and
//! 4.24.1 ask for a reset) goes through the same policy (owner decision
//! 2026-10-23): one reset, shared with the timeouts, and the next fault of
//! any of the three causes latches. The record names the cause
//! ([`Fault`]).

use super::context::{self, EpParams, Layout, SlotParams};
use super::regs::{self, Caps, Speed};
use super::ring::{EventRing, ProducerRing, RING_TRBS};
use super::trb::{self, cc, ty, Trb, TRB_BYTES};
use crate::hw::{Arena, Clock, DmaBuf, Memory, Regs, PAGE};
use crate::{MAX_DEVICES, MAX_PIPES};
use azos_drv_api::recovery::{Class, Recovery, Verdict};

/// Endpoints the controller tracks: the control endpoint of every device slot
/// first, then one per open pipe.
pub const MAX_EPS: usize = MAX_DEVICES + MAX_PIPES;
/// Transfer descriptors in flight per endpoint.
pub const MAX_TDS: usize = if crate::PIPE_DEPTH > 8 { crate::PIPE_DEPTH } else { 8 };
/// Events held between the event ring and the core.
const EVENT_QUEUE: usize = 128;

/// Time the controller gets to answer a command.
const CMD_TIMEOUT_US: u64 = 1_000_000;
/// Time a halt or a reset gets.
const RESET_TIMEOUT_US: u64 = 1_000_000;
const HALT_TIMEOUT_US: u64 = 200_000;
/// Time the firmware gets to release the controller.
const HANDOFF_TIMEOUT_US: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The controller did not answer in time (a command, a reset, a halt).
    Timeout,
    /// No DMA memory (the arena or the region allocator).
    NoMemory,
    /// The capability registers make no sense (not an xHCI window).
    BadCaps,
    /// The controller reported a host system error or died.
    Dead,
    /// A command completed with this code.
    Command(u8),
    /// Not a slot or endpoint the controller has.
    Invalid,
    /// The ring or the descriptor FIFO has no room; retry after a completion.
    Busy,
    /// The buffer lies above what the controller can address.
    Bounce,
    /// The DMA domain of the device would not start.
    Dma,
    /// The controller was reset after a command timed out: the devices it
    /// held are gone, and nothing is accepted until the core has removed
    /// them ([`Xhci::ack_reset`]).
    Reset,
}

/// Why the controller is reset or latched, in the `usb-host-fault` record:
/// the high byte of its first field ([`Fault::detail`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Fault {
    /// A command went unanswered for its budget.
    Timeout = 1,
    /// USBSTS.HSE: the controller hit a host system error (its DMA failed).
    HostSystemError = 2,
    /// USBSTS.HCE: the controller found an internal error.
    HostControllerError = 3,
}

impl Fault {
    /// The record's first field: the cause, then the type of the command
    /// that went unanswered (0 for an error the controller reported).
    pub const fn detail(self, trb_type: u8) -> u64 {
        (self as u64) << 8 | trb_type as u64
    }
}

/// Who a transfer descriptor belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// The USB core's own control requests.
    Core,
    /// A class driver's pipe `n`.
    Pipe(u8),
    /// The status-change endpoint of the hub in slot `n`.
    Hub(u8),
}

/// What a descriptor does.
#[derive(Clone, Copy, Debug)]
pub enum TdKind {
    /// Setup, optional data, status. `buf` is a bus address; `len` the data
    /// stage's length (0: none).
    Control { setup: [u8; 8], buf: u64, len: u16, dir_in: bool },
    /// Bulk or interrupt: normal TRBs over `buf`.
    Data { buf: u64, len: u32, dir_in: bool },
    /// One service interval of an isochronous IN endpoint: `len` bytes at
    /// most (the endpoint's bytes per interval), split as the endpoint's
    /// bursts require.
    Isoch { buf: u64, len: u32 },
}

#[derive(Clone, Copy, Debug)]
pub struct TdSpec {
    pub owner: Owner,
    pub tag: u32,
    pub kind: TdKind,
}

/// A transfer descriptor finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Done {
    pub owner: Owner,
    pub tag: u32,
    /// The completion code of the event that finished it (`cc::*`).
    pub code: u8,
    /// Bytes transferred.
    pub actual: u32,
    pub slot: u8,
    pub dci: u8,
}

impl Done {
    pub fn ok(&self) -> bool {
        self.code == cc::SUCCESS || self.code == cc::SHORT_PACKET
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HcEvent {
    /// Port `n` (1-based) changed state.
    PortChange(u8),
    Done(Done),
    /// The controller reported a host controller event (an error).
    HostError(u8),
}

#[derive(Clone, Copy, Debug)]
struct Td {
    owner: Owner,
    tag: u32,
    first_idx: u16,
    /// Ring positions from the first TRB to the last, Link TRBs included.
    span: u16,
    last_bus: u64,
    len: u32,
    control: bool,
    /// A short packet seen on the data stage of a control transfer: the
    /// bytes moved, kept until the status stage reports.
    short: Option<u32>,
}

const TD_NONE: Td = Td {
    owner: Owner::Core,
    tag: 0,
    first_idx: 0,
    span: 0,
    last_bus: 0,
    len: 0,
    control: false,
    short: None,
};

/// One endpoint: its ring and the descriptors in flight.
pub struct Ep {
    ring: Option<ProducerRing>,
    slot: u8,
    dci: u8,
    mps: u16,
    /// Max burst size field of the endpoint context (packets per burst - 1).
    burst: u8,
    /// An isochronous endpoint: its descriptors never halt it.
    isoch: bool,
    tds: [Td; MAX_TDS],
    head: u8,
    count: u8,
    /// Ring positions in use by descriptors in flight.
    inflight: u16,
    halted: bool,
}

impl Ep {
    const fn new() -> Ep {
        Ep { ring: None, slot: 0, dci: 0, mps: 0, burst: 0, isoch: false, tds: [TD_NONE; MAX_TDS], head: 0, count: 0, inflight: 0, halted: false }
    }
    fn td(&self, k: usize) -> &Td {
        &self.tds[(self.head as usize + k) % MAX_TDS]
    }
    fn pop(&mut self) -> Td {
        let t = self.tds[self.head as usize];
        self.head = ((self.head as usize + 1) % MAX_TDS) as u8;
        self.count -= 1;
        self.inflight = self.inflight.saturating_sub(t.span);
        t
    }
}

/// A port's status register, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortStatus(pub u32);

impl PortStatus {
    pub fn connected(&self) -> bool {
        self.0 & regs::PORTSC_CCS != 0
    }
    pub fn enabled(&self) -> bool {
        self.0 & regs::PORTSC_PED != 0
    }
    pub fn resetting(&self) -> bool {
        self.0 & regs::PORTSC_PR != 0
    }
    pub fn powered(&self) -> bool {
        self.0 & regs::PORTSC_PP != 0
    }
    pub fn changes(&self) -> u32 {
        self.0 & regs::PORTSC_CHANGES
    }
    pub fn link_state(&self) -> u32 {
        (self.0 & regs::PORTSC_PLS_MASK) >> regs::PORTSC_PLS_SHIFT
    }
    pub fn speed(&self) -> Option<Speed> {
        Speed::from_psiv((self.0 & regs::PORTSC_SPEED_MASK) >> regs::PORTSC_SPEED_SHIFT)
    }
}

/// An endpoint to add with Configure Endpoint.
#[derive(Clone, Copy, Debug)]
pub struct EpSpec {
    pub dci: u8,
    pub ep_type: u8,
    pub mps: u16,
    pub burst: u8,
    pub mult: u8,
    pub interval: u8,
    pub max_esit: u32,
    /// The endpoint slot in the controller's table (see [`Xhci::ep_for_pipe`]).
    pub ep: u16,
}

pub struct Xhci<R: Regs, M: Memory, C: Clock> {
    regs: R,
    mem: M,
    clock: C,
    caps: Caps,
    op: usize,
    rt: usize,
    db: usize,
    layout: Layout,
    mask: u64,
    irq: bool,
    arena: Arena,
    dcbaa: DmaBuf,
    /// The event ring segment table (one segment), for a reset to program
    /// again.
    erst: DmaBuf,
    scratch_array: Option<DmaBuf>,
    scratch_bufs: Option<DmaBuf>,
    cmd: ProducerRing,
    evt: EventRing,
    input: DmaBuf,
    slots_en: u8,
    dev_ctx: [DmaBuf; MAX_DEVICES],
    slot_params: [SlotParams; MAX_DEVICES],
    /// DCIs configured on a slot (bit n for DCI n).
    configured: [u32; MAX_DEVICES],
    /// Endpoint table index for (slot, dci); `NO_EP` for none.
    route: [[u16; 32]; MAX_DEVICES],
    eps: [Ep; MAX_EPS],
    cmd_done: Option<Trb>,
    events: [Option<HcEvent>; EVENT_QUEUE],
    ev_head: usize,
    ev_count: usize,
    lost_events: u32,
    /// Live, being reset, or latched dead (the device timeout policy).
    recovery: Recovery,
    /// Reset after a timeout, and the core has not removed the devices the
    /// controller forgot yet ([`Xhci::ack_reset`]).
    reset_pending: bool,
}

const NO_EP: u16 = u16::MAX;

impl<R: Regs, M: Memory, C: Clock> Xhci<R, M, C> {
    /// Reset and start the controller whose registers `regs` reaches.
    /// `dma_mask` is the highest bus address the device's DMA domain lets it
    /// reach; `irq` programs interrupter 0 to interrupt (the caller routes
    /// the interrupt), otherwise the driver is polled.
    pub fn new(regs: R, mem: M, clock: C, dma_mask: u64, irq: bool) -> Result<Self, Error> {
        let mut slot = core::mem::MaybeUninit::<Self>::uninit();
        Self::init(&mut slot, regs, mem, clock, dma_mask, irq)?;
        // SAFETY: `init` returned `Ok`, so it wrote every field.
        Ok(unsafe { slot.assume_init() })
    }

    /// [`Xhci::new`] in place: the controller (19 KB with the default limits,
    /// more with `USB_MAX_DEVICES`) is built in `slot` field by field and
    /// never exists as a value on the caller's stack. On `Err` the slot must not be
    /// assumed initialized (the fields are written before the controller starts;
    /// none of them has a `Drop`, `start`'s failure frees its DMA region by hand).
    pub fn init<'a>(
        slot: &'a mut core::mem::MaybeUninit<Self>,
        regs: R,
        mem: M,
        clock: C,
        dma_mask: u64,
        irq: bool,
    ) -> Result<&'a mut Self, Error> {
        let caps = Caps::decode(
            regs.read32(regs::CAPLENGTH),
            regs.read32(regs::HCSPARAMS1),
            regs.read32(regs::HCSPARAMS2),
            regs.read32(regs::HCCPARAMS1),
            regs.read32(regs::DBOFF),
            regs.read32(regs::RTSOFF),
        );
        if caps.caplength < 0x20 || caps.max_slots == 0 || caps.max_ports == 0 || caps.max_intrs == 0 {
            return Err(Error::BadCaps);
        }
        let op = caps.op_base();

        // A controller the firmware drives (a BIOS keyboard through SMIs) is
        // taken over first.
        bios_handoff(&regs, &clock, &caps)?;

        // Stop, then reset: a controller the firmware left running is halted
        // first (a reset of a running controller is undefined).
        let cmd = regs.read32(op + regs::USBCMD);
        if cmd & regs::CMD_RS != 0 {
            regs.write32(op + regs::USBCMD, cmd & !regs::CMD_RS);
        }
        wait_reg(&regs, &clock, op + regs::USBSTS, regs::STS_HCH, regs::STS_HCH, HALT_TIMEOUT_US)?;
        wait_reg(&regs, &clock, op + regs::USBSTS, regs::STS_CNR, 0, RESET_TIMEOUT_US)?;
        regs.write32(op + regs::USBCMD, regs::CMD_HCRST);
        wait_reg(&regs, &clock, op + regs::USBCMD, regs::CMD_HCRST, 0, RESET_TIMEOUT_US)?;
        wait_reg(&regs, &clock, op + regs::USBSTS, regs::STS_CNR, 0, RESET_TIMEOUT_US)?;

        // The controller reaches 64 bits only if it says so.
        #[cfg(feature = "canary-ac64")]
        let mask = dma_mask;
        #[cfg(not(feature = "canary-ac64"))]
        let mask = if caps.ac64 { dma_mask } else { dma_mask.min(0xffff_ffff) };

        // The controller's page size: the lowest bit set of PAGESIZE, bit n
        // for 2^(n + 12) bytes.
        let ps = regs.read32(op + regs::PAGESIZE) & 0xffff;
        if ps == 0 {
            return Err(Error::BadCaps);
        }
        let hc_page = 1usize << (12 + ps.trailing_zeros());

        let region = mem.alloc_region(crate::hw::ARENA_PAGES * PAGE, PAGE, mask).ok_or(Error::NoMemory)?;
        let Some(mut arena) = Arena::new(region) else {
            mem.free_region(region);
            return Err(Error::NoMemory);
        };
        let (Some(dcbaa), Some(cmd_page), Some(evt_page), Some(erst), Some(input)) =
            (arena.page(), arena.page(), arena.page(), arena.page(), arena.page())
        else {
            mem.free_region(region);
            return Err(Error::NoMemory);
        };
        let cmd_ring = ProducerRing::new(cmd_page);
        let evt = EventRing::new(evt_page);
        let layout = Layout { size: caps.ctx_size() };
        let p = slot.as_mut_ptr();
        // SAFETY: `p` is valid and aligned for a `Self`; each field is written
        // exactly once, through `addr_of_mut!`, before `&mut *p` is formed. The
        // big tables are filled element by element so that no table-sized
        // temporary is made on the stack.
        let x = unsafe {
            use core::ptr::addr_of_mut;
            addr_of_mut!((*p).regs).write(regs);
            addr_of_mut!((*p).mem).write(mem);
            addr_of_mut!((*p).clock).write(clock);
            addr_of_mut!((*p).caps).write(caps);
            addr_of_mut!((*p).op).write(op);
            addr_of_mut!((*p).rt).write(caps.rtsoff);
            addr_of_mut!((*p).db).write(caps.dboff);
            addr_of_mut!((*p).layout).write(layout);
            addr_of_mut!((*p).mask).write(mask);
            addr_of_mut!((*p).irq).write(irq);
            addr_of_mut!((*p).arena).write(arena);
            addr_of_mut!((*p).dcbaa).write(dcbaa);
            addr_of_mut!((*p).erst).write(erst);
            addr_of_mut!((*p).scratch_array).write(None);
            addr_of_mut!((*p).scratch_bufs).write(None);
            addr_of_mut!((*p).cmd).write(cmd_ring);
            addr_of_mut!((*p).evt).write(evt);
            addr_of_mut!((*p).input).write(input);
            addr_of_mut!((*p).slots_en).write(caps.max_slots.min(MAX_DEVICES as u32) as u8);
            let dev_ctx = addr_of_mut!((*p).dev_ctx).cast::<DmaBuf>();
            let slot_params = addr_of_mut!((*p).slot_params).cast::<SlotParams>();
            let configured = addr_of_mut!((*p).configured).cast::<u32>();
            let route = addr_of_mut!((*p).route).cast::<[u16; 32]>();
            for i in 0..MAX_DEVICES {
                dev_ctx.add(i).write(DmaBuf::EMPTY);
                slot_params.add(i).write(SlotParams::default());
                configured.add(i).write(0);
                route.add(i).write([NO_EP; 32]);
            }
            let eps = addr_of_mut!((*p).eps).cast::<Ep>();
            for i in 0..MAX_EPS {
                eps.add(i).write(const { Ep::new() });
            }
            addr_of_mut!((*p).cmd_done).write(None);
            let events = addr_of_mut!((*p).events).cast::<Option<HcEvent>>();
            for i in 0..EVENT_QUEUE {
                events.add(i).write(None);
            }
            addr_of_mut!((*p).ev_head).write(0);
            addr_of_mut!((*p).ev_count).write(0);
            addr_of_mut!((*p).lost_events).write(0);
            addr_of_mut!((*p).recovery)
                .write(Recovery::new(Class::Usb, "xhci", azos_limits::DEVICE_TIMEOUT_RESETS as u8));
            addr_of_mut!((*p).reset_pending).write(false);
            &mut *p
        };
        match x.start(hc_page) {
            Ok(()) => Ok(x),
            Err(e) => {
                x.free_dma();
                Err(e)
            }
        }
    }

    /// Everything after the memory exists: scratchpads, the registers, run.
    fn start(&mut self, hc_page: usize) -> Result<(), Error> {
        let caps = self.caps;
        // Scratchpad buffers: an array of bus addresses, each a page of the
        // controller's page size, owned by the controller for good (a reset
        // gives it the same ones again).
        if caps.scratchpads > 0 {
            let n = caps.scratchpads as usize;
            let arr_len = (n * 8).next_multiple_of(PAGE);
            let arr = self.mem.alloc_region(arr_len, 64, self.mask).ok_or(Error::NoMemory)?;
            self.scratch_array = Some(arr);
            let bufs = self.mem.alloc_region(n * hc_page, hc_page, self.mask).ok_or(Error::NoMemory)?;
            self.scratch_bufs = Some(bufs);
            for i in 0..n {
                arr.w64(i * 8, bufs.bus_at(i * hc_page));
            }
            self.mem.to_device(arr.cpu(), arr_len);
            self.dcbaa.w64(0, arr.bus());
        }
        if !self.mem.enable() {
            return Err(Error::Dma);
        }
        self.program()
    }

    /// Give a halted, reset controller the memory it has and run it: the
    /// device context base array, the command ring, the event ring of
    /// interrupter 0, Run/Stop, a command round trip, port power. Bring-up
    /// and a reset both.
    fn program(&mut self) -> Result<(), Error> {
        let (op, rt, caps) = (self.op, self.rt, self.caps);
        self.mem.to_device(self.dcbaa.cpu(), PAGE);
        // The event ring segment table: one segment.
        self.erst.w64(0, self.evt.base());
        self.erst.w32(8, RING_TRBS as u32);
        self.mem.to_device(self.erst.cpu(), 16);

        // The tables above are read once the registers below name them.
        azos_dma::order::io_wmb();
        let r = &self.regs;
        r.write32(op + regs::CONFIG, self.slots_en as u32);
        r.write64(op + regs::DCBAAP, self.dcbaa.bus());
        r.write64(op + regs::CRCR, self.cmd.base() | regs::CRCR_RCS);
        // Interrupter 0: segment table size, then the dequeue pointer, then
        // the base (writing the base is what arms the ring).
        let ir0 = rt + regs::ir(0);
        r.write32(ir0 + regs::ERSTSZ, 1);
        r.write64(ir0 + regs::ERDP, self.evt.base());
        r.write64(ir0 + regs::ERSTBA, self.erst.bus());
        r.write32(ir0 + regs::IMAN, regs::IMAN_IP | if self.irq { regs::IMAN_IE } else { 0 });
        r.write32(op + regs::USBCMD, regs::CMD_RS | regs::CMD_HSEE | if self.irq { regs::CMD_INTE } else { 0 });
        wait_reg(&self.regs, &self.clock, op + regs::USBSTS, regs::STS_HCH, 0, HALT_TIMEOUT_US)?;

        // A command round trip proves the rings work before anyone relies on them.
        self.command(Trb::noop_cmd())?;
        // Ports a controller leaves unpowered are powered here; the core
        // waits the power-good time itself.
        if caps.ppc {
            for p in 1..=self.ports() {
                if self.port_status(p).0 & regs::PORTSC_PP == 0 {
                    self.port_write(p, regs::PORTSC_PP);
                }
            }
        }
        Ok(())
    }

    /// Give the DMA regions back (a start that failed).
    fn free_dma(&mut self) {
        self.regs.write32(self.op + regs::USBCMD, 0);
        if let Some(b) = self.scratch_bufs.take() {
            self.mem.free_region(b);
        }
        if let Some(a) = self.scratch_array.take() {
            self.mem.free_region(a);
        }
        self.mem.free_region(self.arena.region());
    }

    // ---- Accessors ----

    pub fn caps(&self) -> &Caps {
        &self.caps
    }
    pub fn ports(&self) -> u8 {
        self.caps.max_ports.min(255) as u8
    }
    /// Slots the driver enabled (the controller's MaxSlots, capped by the
    /// device table).
    pub fn max_slots(&self) -> u8 {
        self.slots_en
    }
    /// The highest bus address the controller can reach.
    pub fn dma_mask(&self) -> u64 {
        self.mask
    }
    pub fn irq_mode(&self) -> bool {
        self.irq
    }
    /// Latched dead until reboot: a timeout with the resets spent, a reset
    /// that did not bring the controller back, or an error it reported.
    pub fn is_dead(&self) -> bool {
        self.recovery.dead()
    }
    /// Was the controller reset, with the devices it held still in the
    /// core's tables? The core removes every one of them, then calls
    /// [`Xhci::ack_reset`]; until then commands and transfers are refused
    /// ([`Error::Reset`]), so nothing is sent for a slot the controller
    /// forgot.
    pub fn reset_pending(&self) -> bool {
        self.reset_pending
    }
    /// The core has removed the devices of the reset controller: it takes
    /// commands and transfers again.
    pub fn ack_reset(&mut self) {
        self.reset_pending = false;
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
    pub fn free_pages(&self) -> usize {
        self.arena.free_pages()
    }
    /// A page of the arena for the core's own use (its control buffer).
    pub fn take_page(&mut self) -> Option<DmaBuf> {
        self.arena.page()
    }

    /// Ring doorbell `target`: `io_wmb` orders the TRBs (and their cache
    /// maintenance) before the register write that makes the controller read
    /// them.
    fn doorbell(&self, target: usize, value: u32) {
        azos_dma::order::io_wmb();
        self.regs.write32(self.db + 4 * target, value);
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

    /// The next event for the core.
    pub fn next_event(&mut self) -> Option<HcEvent> {
        if self.ev_count == 0 {
            return None;
        }
        let e = self.events[self.ev_head].take();
        self.ev_head = (self.ev_head + 1) % EVENT_QUEUE;
        self.ev_count -= 1;
        e
    }

    /// Drain the event ring. Stops early when the core's queue is nearly full
    /// (the rest waits in the ring, which is what the ring is for).
    pub fn poll(&mut self) {
        let mut any = false;
        while self.ev_count + 8 < EVENT_QUEUE {
            let Some(t) = self.evt.pop(&self.mem) else { break };
            any = true;
            self.handle_event(t);
        }
        // Acknowledge: the dequeue pointer, with Event Handler Busy cleared,
        // and the interrupt pending flags.
        let ir0 = self.rt + regs::ir(0);
        if any || self.regs.read32(self.op + regs::USBSTS) & regs::STS_EINT != 0 {
            self.regs.write64(ir0 + regs::ERDP, self.evt.erdp());
            self.regs.write32(self.op + regs::USBSTS, regs::STS_EINT);
            self.regs.write32(ir0 + regs::IMAN, regs::IMAN_IP | if self.irq { regs::IMAN_IE } else { 0 });
        }
        // A host system error or a host controller error: the device fault
        // policy, as a timeout (module documentation).
        let sts = self.regs.read32(self.op + regs::USBSTS);
        if sts & (regs::STS_HSE | regs::STS_HCE) != 0 {
            // Canary: the controller latches at once, as before the decision.
            if cfg!(feature = "canary-xhci-hse-latches") {
                self.recovery.latch();
                return;
            }
            let cause = if sts & regs::STS_HCE != 0 { Fault::HostControllerError } else { Fault::HostSystemError };
            self.fault(cause, 0, 0);
        }
    }

    fn handle_event(&mut self, t: Trb) {
        match t.trb_type() {
            ty::COMMAND_COMPLETION => self.cmd_done = Some(t),
            ty::PORT_STATUS_CHANGE => self.push_event(HcEvent::PortChange(t.port_id())),
            ty::TRANSFER_EVENT => self.transfer_event(t),
            ty::HOST_CONTROLLER_EVENT => {
                self.push_event(HcEvent::HostError(t.code()));
            }
            _ => {}
        }
    }

    // ---- Commands ----

    /// Issue a command and wait for its completion event. A completion code
    /// other than success is [`Error::Command`]; the event is returned so the
    /// caller can read the slot id of an Enable Slot.
    pub fn command(&mut self, t: Trb) -> Result<Trb, Error> {
        if self.recovery.dead() {
            return Err(Error::Dead);
        }
        if self.reset_pending {
            return Err(Error::Reset);
        }
        self.cmd_done = None;
        let ty = t.trb_type();
        let at = self.cmd.push(&self.mem, t);
        // Kconfig CHAOS `xhci-command-drop`: the doorbell is not rung, so the
        // controller never answers and the command runs out of its budget.
        // Not while a reset is in progress.
        if !(self.recovery.live() && azos_chaos::fire(azos_chaos::Point::XhciCommandDrop)) {
            self.doorbell(0, 0);
        }
        let deadline = self.clock.now_us() + CMD_TIMEOUT_US;
        loop {
            self.poll();
            if let Some(done) = self.cmd_done.take() {
                if done.param & !0xf == at {
                    return if done.code() == cc::SUCCESS { Ok(done) } else { Err(Error::Command(done.code())) };
                }
                // A completion of an earlier, abandoned command: ignore.
            }
            if self.recovery.dead() {
                return Err(Error::Dead);
            }
            // An error the controller reported reset it under this command.
            if self.reset_pending {
                return Err(Error::Reset);
            }
            if self.clock.now_us() >= deadline {
                // The controller did not answer: stop the command ring so a
                // late completion cannot be taken for the next command's,
                // then let the timeout policy decide.
                self.regs.write64(self.op + regs::CRCR, regs::CRCR_CA);
                self.fault(Fault::Timeout, ty, CMD_TIMEOUT_US / 1000);
                return Err(Error::Timeout);
            }
            self.clock.delay_us(50);
        }
    }

    /// The controller faulted (`cause`; a timeout of a command of type `ty`
    /// after `waited_ms`): reset it, or, with the resets spent, latch it dead
    /// (module documentation). A fault while the controller is being reset
    /// (the reset's own round trip timing out) fails the reset.
    fn fault(&mut self, cause: Fault, ty: u8, waited_ms: u64) {
        let detail = cause.detail(ty);
        // Canary: the first timeout latches the controller, as before the policy.
        if cfg!(feature = "canary-xhci-no-reset") {
            self.recovery.latch();
            self.halt();
            return;
        }
        match self.recovery.timed_out(detail, waited_ms) {
            Verdict::Reset => {
                let ok = self.reset().is_ok();
                if !ok {
                    self.halt();
                }
                self.recovery.reset_done(ok, detail, waited_ms);
            }
            Verdict::Latch => self.halt(),
            Verdict::Handled => {}
        }
    }

    /// Halt the controller (Run/Stop cleared, so it walks no ring again), and
    /// reset it: HCRST, then Controller Not Ready clears. It must be the same
    /// controller (its capability registers unchanged). Then it is programmed
    /// again over the same memory: the slot entries of the device context
    /// base array cleared (the scratchpad array kept), the command and event
    /// rings emptied at their start, interrupter 0, Run/Stop, a command round
    /// trip. The slots, endpoints and descriptors the driver had are left as
    /// they were: the core removes every device ([`Xhci::reset_pending`]),
    /// which ends their transfers and gives their pages back.
    fn reset(&mut self) -> Result<(), Error> {
        let op = self.op;
        self.halt();
        wait_reg(&self.regs, &self.clock, op + regs::USBSTS, regs::STS_HCH, regs::STS_HCH, HALT_TIMEOUT_US)?;
        self.regs.write32(op + regs::USBCMD, regs::CMD_HCRST);
        wait_reg(&self.regs, &self.clock, op + regs::USBCMD, regs::CMD_HCRST, 0, RESET_TIMEOUT_US)?;
        wait_reg(&self.regs, &self.clock, op + regs::USBSTS, regs::STS_CNR, 0, RESET_TIMEOUT_US)?;
        let r = &self.regs;
        let caps = Caps::decode(
            r.read32(regs::CAPLENGTH),
            r.read32(regs::HCSPARAMS1),
            r.read32(regs::HCSPARAMS2),
            r.read32(regs::HCCPARAMS1),
            r.read32(regs::DBOFF),
            r.read32(regs::RTSOFF),
        );
        if caps != self.caps {
            return Err(Error::BadCaps);
        }
        for slot in 1..=self.slots_en as usize {
            self.dcbaa.w64(8 * slot, 0);
        }
        self.cmd.reset(&self.mem);
        // Canary: the event ring keeps the cursor of before the reset, where
        // the controller starts writing at its first entry.
        if !cfg!(feature = "canary-xhci-reset-event-ring") {
            self.evt.reset(&self.mem);
        }
        self.cmd_done = None;
        self.program()?;
        self.reset_pending = true;
        Ok(())
    }

    /// Clear Run/Stop (and the interrupt enable): the controller stops
    /// walking its rings. A latched controller is left so, its memory never
    /// reused: one whose halt was not confirmed may still write to it.
    fn halt(&self) {
        let c = self.regs.read32(self.op + regs::USBCMD);
        self.regs.write32(self.op + regs::USBCMD, c & !(regs::CMD_RS | regs::CMD_INTE));
    }

    // ---- Ports ----

    fn port_reg(&self, port: u8) -> usize {
        self.op + regs::PORT_BASE + (port as usize - 1) * regs::PORT_STRIDE + regs::PORTSC
    }

    pub fn port_status(&self, port: u8) -> PortStatus {
        PortStatus(self.regs.read32(self.port_reg(port)))
    }

    /// Write `bits` to PORTSC with the register's other bits carried back
    /// neutrally: the RW1C bits are never written as read (that would
    /// disable the port or acknowledge a change nobody saw).
    pub fn port_write(&self, port: u8, bits: u32) {
        let v = self.regs.read32(self.port_reg(port));
        self.regs.write32(self.port_reg(port), (v & regs::PORTSC_NEUTRAL) | bits);
    }

    /// Acknowledge the change bits in `changes`.
    pub fn port_ack(&self, port: u8, changes: u32) {
        self.port_write(port, changes & regs::PORTSC_CHANGES);
    }

    /// Start a port reset.
    pub fn port_reset(&self, port: u8) {
        self.port_write(port, regs::PORTSC_PR);
    }

    // ---- Slots ----

    pub fn enable_slot(&mut self) -> Result<u8, Error> {
        let done = self.command(Trb::enable_slot())?;
        let s = done.slot();
        if s == 0 || s > self.slots_en {
            return Err(Error::Invalid);
        }
        Ok(s)
    }

    fn slot_ix(&self, slot: u8) -> Result<usize, Error> {
        if slot == 0 || slot > self.slots_en {
            return Err(Error::Invalid);
        }
        Ok(slot as usize - 1)
    }

    fn ep_ix(&self, ep: u16) -> Result<usize, Error> {
        if (ep as usize) < MAX_EPS { Ok(ep as usize) } else { Err(Error::Invalid) }
    }

    /// The endpoint-table index of the control endpoint of `slot`.
    pub fn ep0_index(slot: u8) -> u16 {
        slot as u16 - 1
    }

    /// The endpoint-table index for pipe `n`.
    pub fn ep_for_pipe(n: u8) -> u16 {
        (MAX_DEVICES + n as usize) as u16
    }

    /// Give `slot` its device context and control endpoint, and address the
    /// device (Address Device without BSR). `params` describes the slot (route
    /// string, speed, root port, transaction translator); `ep0_mps` is the
    /// control endpoint's max packet size.
    pub fn address_device(&mut self, slot: u8, params: SlotParams, ep0_mps: u16) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        let dev = self.arena.page().ok_or(Error::NoMemory)?;
        let ring_page = match self.arena.page() {
            Some(p) => p,
            None => {
                self.arena.release(dev);
                return Err(Error::NoMemory);
            }
        };
        let ring = ProducerRing::new(ring_page);
        let (deq, dcs) = ring.enqueue_ptr();
        self.dcbaa.w64(8 * slot as usize, dev.bus());
        self.mem.to_device(self.dcbaa.cpu().wrapping_add(8 * slot as usize), 8);
        self.mem.to_device(dev.cpu(), PAGE);

        let mut p = params;
        p.entries = 1;
        self.slot_params[si] = p;
        self.configured[si] = 1 << 1;
        self.fill_input(
            si,
            0,
            1 | 1 << 1,
            &[(
                1,
                EpParams {
                    ep_type: context::EP_TYPE_CONTROL,
                    mps: ep0_mps,
                    burst: 0,
                    mult: 0,
                    interval: 0,
                    max_esit: 0,
                    avg_trb_len: 8,
                    deq,
                    dcs,
                },
            )],
        );
        let ep = &mut self.eps[Self::ep0_index(slot) as usize];
        *ep = Ep::new();
        ep.ring = Some(ring);
        ep.slot = slot;
        ep.dci = 1;
        ep.mps = ep0_mps;
        self.route[si][1] = Self::ep0_index(slot);
        self.dev_ctx[si] = dev;

        match self.command(Trb::address_device(slot, self.input.bus(), false)) {
            Ok(_) => Ok(()),
            Err(e) => {
                self.release_slot_memory(slot);
                Err(e)
            }
        }
    }

    /// Write the shared input context: control flags, the slot context from
    /// the slot's parameters, and the endpoint contexts in `eps` (DCI, params).
    fn fill_input(&mut self, si: usize, drop: u32, add: u32, eps: &[(u8, EpParams)]) {
        let l = self.layout;
        let buf = self.input;
        for o in (0..l.input_bytes()).step_by(4) {
            buf.w32(o, 0);
        }
        context::write_input_control(&buf, &l, drop, add);
        let mut sp = self.slot_params[si];
        let top = (31 - self.configured[si].leading_zeros()) as u8;
        sp.entries = top.max(1);
        context::write_slot(&buf, l.input_slot(), &l, &sp);
        for (dci, p) in eps {
            context::write_ep(&buf, l.input_ep(*dci), &l, p);
        }
        self.mem.to_device(buf.cpu(), l.input_bytes());
    }

    /// Update the slot context of `slot` (a hub's port count and TT flags)
    /// with an Evaluate Context.
    pub fn update_slot(&mut self, slot: u8, params: SlotParams) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        self.slot_params[si] = params;
        self.fill_input(si, 0, 1, &[]);
        self.command(Trb::evaluate_context(slot, self.input.bus())).map(|_| ())
    }

    /// Change endpoint 0's max packet size (Evaluate Context).
    pub fn set_ep0_mps(&mut self, slot: u8, mps: u16) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        let l = self.layout;
        // The input slot context must be valid; endpoint 0 carries the new size.
        self.fill_input(si, 0, 1 << 1, &[]);
        let out = self.dev_ctx[si];
        self.mem.from_device(out.cpu(), l.device_bytes());
        // Copy the controller's endpoint-0 context, then change the size.
        for o in (0..l.size).step_by(4) {
            self.input.w32(l.input_ep(1) + o, out.r32(l.dev_ep(1) + o));
        }
        context::set_ep_mps(&self.input, l.input_ep(1), mps);
        self.mem.to_device(self.input.cpu(), l.input_bytes());
        self.command(Trb::evaluate_context(slot, self.input.bus()))?;
        self.eps[Self::ep0_index(slot) as usize].mps = mps;
        Ok(())
    }

    /// Add endpoints to a configured slot (Configure Endpoint). Each gets a
    /// transfer ring.
    pub fn configure_endpoints(&mut self, slot: u8, specs: &[EpSpec]) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        let mut params = [(0u8, EpParams::default()); 8];
        if specs.is_empty() || specs.len() > params.len() {
            return Err(Error::Invalid);
        }
        let mut add = 1u32;
        let mut pages = [DmaBuf::EMPTY; 8];
        for (i, s) in specs.iter().enumerate() {
            let page = match self.arena.page() {
                Some(p) => p,
                None => {
                    for p in &pages[..i] {
                        self.arena.release(*p);
                    }
                    return Err(Error::NoMemory);
                }
            };
            pages[i] = page;
            let ring = ProducerRing::new(page);
            let (deq, dcs) = ring.enqueue_ptr();
            params[i] = (
                s.dci,
                EpParams {
                    ep_type: s.ep_type,
                    mps: s.mps,
                    burst: s.burst,
                    mult: s.mult,
                    interval: s.interval,
                    max_esit: s.max_esit,
                    avg_trb_len: if s.max_esit != 0 { s.max_esit.min(0xffff) as u16 } else { 1024 },
                    deq,
                    dcs,
                },
            );
            add |= 1 << s.dci;
        }
        let was = self.configured[si];
        self.configured[si] |= add & !1;
        self.fill_input(si, 0, add, &params[..specs.len()]);
        match self.command(Trb::configure_endpoint(slot, self.input.bus(), false)) {
            Ok(_) => {}
            Err(e) => {
                self.configured[si] = was;
                for p in &pages[..specs.len()] {
                    self.arena.release(*p);
                }
                return Err(e);
            }
        }
        for (i, s) in specs.iter().enumerate() {
            let ix = s.ep as usize;
            let ep = &mut self.eps[ix];
            *ep = Ep::new();
            ep.ring = Some(ProducerRing::new(pages[i]));
            ep.slot = slot;
            ep.dci = s.dci;
            ep.mps = s.mps;
            ep.burst = s.burst;
            ep.isoch = matches!(s.ep_type, context::EP_TYPE_ISOCH_IN | context::EP_TYPE_ISOCH_OUT);
            self.route[si][s.dci as usize] = s.ep;
        }
        Ok(())
    }

    /// Drop endpoints (Configure Endpoint with drop flags) and free their
    /// rings. Descriptors still in flight complete as stopped.
    pub fn drop_endpoints(&mut self, slot: u8, dcis: u32) -> Result<(), Error> {
        let si = self.slot_ix(slot)?;
        let dcis = dcis & !0b11; // endpoint 0 and the slot are never dropped
        for dci in 2..32u8 {
            if dcis & 1 << dci != 0 {
                self.abort_endpoint(si, dci, cc::STOPPED);
            }
        }
        self.configured[si] &= !dcis;
        // The input context is rebuilt with the drop flags; the slot's entry
        // count is recomputed from what stays.
        self.fill_input(si, dcis, 1, &[]);
        let r = self.command(Trb::configure_endpoint(slot, self.input.bus(), false));
        for dci in 2..32u8 {
            if dcis & 1 << dci != 0 {
                self.free_endpoint(si, dci);
            }
        }
        r.map(|_| ())
    }

    fn abort_endpoint(&mut self, si: usize, dci: u8, code: u8) {
        let ix = self.route[si][dci as usize];
        if ix == NO_EP {
            return;
        }
        let ix = ix as usize;
        let (slot, dci) = (self.eps[ix].slot, self.eps[ix].dci);
        while self.eps[ix].count > 0 {
            let t = self.eps[ix].pop();
            self.push_event(HcEvent::Done(Done { owner: t.owner, tag: t.tag, code, actual: 0, slot, dci }));
        }
    }

    fn free_endpoint(&mut self, si: usize, dci: u8) {
        let ix = self.route[si][dci as usize];
        if ix == NO_EP {
            return;
        }
        self.route[si][dci as usize] = NO_EP;
        if let Some(r) = self.eps[ix as usize].ring.take() {
            self.arena.release(r.buf());
        }
        self.eps[ix as usize] = Ep::new();
    }

    fn release_slot_memory(&mut self, slot: u8) {
        let si = slot as usize - 1;
        for dci in 1..32u8 {
            self.abort_endpoint(si, dci, cc::STOPPED);
            self.free_endpoint(si, dci);
        }
        if self.dev_ctx[si].len() != 0 {
            self.arena.release(self.dev_ctx[si]);
            self.dev_ctx[si] = DmaBuf::EMPTY;
        }
        self.dcbaa.w64(8 * slot as usize, 0);
        self.mem.to_device(self.dcbaa.cpu().wrapping_add(8 * slot as usize), 8);
        self.configured[si] = 0;
    }

    /// Disable a slot (the device is gone, or its enumeration failed): the
    /// controller forgets it, every descriptor in flight completes as
    /// stopped, and its memory is freed.
    pub fn disable_slot(&mut self, slot: u8) -> Result<(), Error> {
        self.slot_ix(slot)?;
        let r = self.command(Trb::disable_slot(slot)).map(|_| ());
        self.release_slot_memory(slot);
        r
    }

    // ---- Transfers ----

    /// Is the endpoint at table index `ep` halted, waiting for
    /// [`Xhci::recover_halted`]?
    pub fn ep_halted(&self, ep: u16) -> bool {
        self.eps.get(ep as usize).is_some_and(|e| e.halted)
    }

    /// Descriptors in flight on `ep`.
    pub fn ep_inflight(&self, ep: u16) -> usize {
        self.eps.get(ep as usize).map_or(0, |e| e.count as usize)
    }

    /// Room for another descriptor on `ep`.
    pub fn ep_has_room(&self, ep: u16) -> bool {
        self.eps.get(ep as usize).is_some_and(|e| (e.count as usize) < MAX_TDS && !e.halted)
    }

    /// Queue one transfer descriptor on endpoint `ep` and ring its doorbell.
    pub fn queue_td(&mut self, ep: u16, spec: TdSpec) -> Result<(), Error> {
        if self.recovery.dead() {
            return Err(Error::Dead);
        }
        if self.reset_pending {
            return Err(Error::Reset);
        }
        let ix = self.ep_ix(ep)?;
        let mask = self.mask;
        let (buf, len) = match spec.kind {
            TdKind::Control { buf, len, .. } => (buf, len as u32),
            TdKind::Data { buf, len, .. } | TdKind::Isoch { buf, len } => (buf, len),
        };
        if len > 0 && buf.checked_add(len as u64 - 1).is_none_or(|e| e > mask) {
            return Err(Error::Bounce);
        }
        let (slot, dci, mps, burst) = {
            let e = &self.eps[ix];
            if e.ring.is_none() {
                return Err(Error::Invalid);
            }
            if e.halted || e.count as usize == MAX_TDS {
                return Err(Error::Busy);
            }
            (e.slot, e.dci, e.mps.max(1) as u32, e.burst as u32)
        };

        // Build the TRBs: at most a setup, a data stage split at 64 KiB
        // boundaries, a status. 64 KiB per TRB and 31 TRBs fill a 2 MiB
        // transfer; a longer one is the class driver's to split.
        let mut trbs = [Trb::default(); 40];
        let mut n = 0;
        let control = matches!(spec.kind, TdKind::Control { .. });
        match spec.kind {
            TdKind::Control { setup, buf, len, dir_in } => {
                trbs[n] = Trb::setup(setup, len, dir_in);
                n += 1;
                if len > 0 {
                    n = split_data(&mut trbs, n, ty::DATA, buf, len as u32, mps, dir_in, false)?;
                }
                // The status stage runs the other way from the data.
                trbs[n] = Trb::status_stage(len == 0 || !dir_in);
                n += 1;
            }
            TdKind::Data { buf, len, dir_in } => {
                n = split_data(&mut trbs, n, ty::NORMAL, buf, len, mps, dir_in, true)?;
            }
            TdKind::Isoch { buf, len } => {
                if len == 0 || !self.eps[ix].isoch {
                    return Err(Error::Invalid);
                }
                // Packets of the TD, in bursts of `burst + 1`: the burst count
                // and the packets of the last burst, both minus one.
                let packets = len.div_ceil(mps);
                let per_burst = burst + 1;
                let tbc = packets.div_ceil(per_burst) - 1;
                let tlbpc = if packets % per_burst == 0 { per_burst - 1 } else { packets % per_burst - 1 };
                // Canary: the packets of the last burst are not counted.
                let tlbpc = if cfg!(feature = "canary-isoch-burst") { 0 } else { tlbpc };
                if tbc > 3 {
                    return Err(Error::Invalid);
                }
                n = split_data(&mut trbs, n, ty::ISOCH, buf, len, mps, true, true)?;
                trbs[0].control |= trb::C_SIA | tbc << 7 | tlbpc << 16;
            }
        }
        let e = &mut self.eps[ix];
        let ring = e.ring.as_mut().expect("checked above");
        // Room: the TRBs, a Link TRB if the TD wraps, and a margin.
        if e.inflight as usize + n + 2 >= RING_TRBS - 4 || n > ProducerRing::MAX_TD {
            return Err(Error::Busy);
        }
        let (first_bus, last_bus) = ring.push_td(&self.mem, &trbs[..n]);
        let first_idx = ring.index_of(first_bus).unwrap_or(0);
        let last_idx = ring.index_of(last_bus).unwrap_or(0);
        let span = ((last_idx + RING_TRBS - first_idx) % RING_TRBS + 1) as u16;
        let slot_td = (e.head as usize + e.count as usize) % MAX_TDS;
        e.tds[slot_td] = Td {
            owner: spec.owner,
            tag: spec.tag,
            first_idx: first_idx as u16,
            span,
            last_bus,
            len,
            control,
            short: None,
        };
        e.count += 1;
        e.inflight += span;
        self.doorbell(slot as usize, dci as u32);
        Ok(())
    }

    fn transfer_event(&mut self, ev: Trb) {
        let (slot, dci) = (ev.slot(), ev.endpoint());
        if slot == 0 || slot > self.slots_en {
            return;
        }
        let si = slot as usize - 1;
        let ix = self.route[si][dci as usize & 31];
        if ix == NO_EP {
            return;
        }
        let ix = ix as usize;
        let code = ev.code();
        let ptr = ev.param & !0xf;
        // The descriptor the event names: usually the oldest in flight.
        let mut k = 0;
        let count = self.eps[ix].count as usize;
        if count == 0 {
            return;
        }
        if let Some(ring) = self.eps[ix].ring.as_ref() {
            if let Some(idx) = ring.index_of(ptr) {
                for j in 0..count {
                    let t = self.eps[ix].td(j);
                    if (idx + RING_TRBS - t.first_idx as usize) % RING_TRBS < t.span as usize {
                        k = j;
                        break;
                    }
                }
            }
        }
        // Descriptors before it were skipped by the controller (it moved past
        // them after an error): they are over.
        for _ in 0..k {
            let t = self.eps[ix].pop();
            self.push_event(HcEvent::Done(Done {
                owner: t.owner,
                tag: t.tag,
                code: cc::STOPPED,
                actual: 0,
                slot,
                dci,
            }));
        }
        let td = *self.eps[ix].td(0);
        // Bytes moved up to and including the TRB the event is for.
        let moved = |s: &Self| -> u32 {
            let Some(ring) = s.eps[ix].ring.as_ref() else { return 0 };
            let idx = ring.index_of(ptr).unwrap_or(td.first_idx as usize);
            let mut sum = 0u32;
            let mut i = td.first_idx as usize;
            loop {
                let o = i * TRB_BYTES;
                let t = Trb { param: 0, status: ring.buf().r32(o + 8), control: ring.buf().r32(o + 12) };
                if matches!(t.trb_type(), ty::NORMAL | ty::DATA | ty::ISOCH) {
                    let l = t.status & 0x1_ffff;
                    if i == idx {
                        return sum + l.saturating_sub(ev.residue());
                    }
                    sum += l;
                }
                if i == idx {
                    return sum;
                }
                i = (i + 1) % RING_TRBS;
                if i == td.first_idx as usize {
                    return sum;
                }
            }
        };
        let is_last = ptr == td.last_bus;
        match code {
            cc::SUCCESS | cc::SHORT_PACKET => {
                if td.control && !is_last {
                    // A short data stage: the status stage reports next.
                    if code == cc::SHORT_PACKET {
                        let m = moved(self);
                        let head = self.eps[ix].head as usize;
                        self.eps[ix].tds[head].short = Some(m);
                    }
                    return;
                }
                // An isochronous descriptor that moved less than it asked for
                // may report Success with the rest as residue.
                let actual = if (code == cc::SHORT_PACKET || self.eps[ix].isoch) && !td.control {
                    moved(self)
                } else {
                    td.short.unwrap_or(td.len)
                };
                let t = self.eps[ix].pop();
                self.push_event(HcEvent::Done(Done { owner: t.owner, tag: t.tag, code, actual, slot, dci }));
            }
            _ => {
                let t = self.eps[ix].pop();
                self.push_event(HcEvent::Done(Done { owner: t.owner, tag: t.tag, code, actual: 0, slot, dci }));
                // A bus error on an isochronous endpoint loses that interval's
                // data and nothing else: the endpoint keeps running.
                let keeps_running = self.eps[ix].isoch && !cfg!(feature = "canary-isoch-halt");
                if !keeps_running && !matches!(code, cc::STOPPED | cc::STOPPED_LENGTH_INVALID) {
                    self.eps[ix].halted = true;
                }
            }
        }
    }

    /// Bring every halted endpoint back: Reset Endpoint, the descriptors
    /// queued behind the failure complete as stopped, and the dequeue pointer
    /// moves to the enqueue pointer. Returns how many were recovered.
    pub fn recover_halted(&mut self) -> usize {
        let mut n = 0;
        for ix in 0..MAX_EPS {
            if !self.eps[ix].halted || self.recovery.dead() || self.reset_pending {
                continue;
            }
            let (slot, dci) = (self.eps[ix].slot, self.eps[ix].dci);
            // A reset of an endpoint that is not halted fails with a context
            // state error, which only means there was nothing to reset.
            let _ = self.command(Trb::reset_endpoint(slot, dci));
            while self.eps[ix].count > 0 {
                let t = self.eps[ix].pop();
                self.push_event(HcEvent::Done(Done {
                    owner: t.owner,
                    tag: t.tag,
                    code: cc::STOPPED,
                    actual: 0,
                    slot,
                    dci,
                }));
            }
            if let Some(ring) = self.eps[ix].ring.as_ref() {
                let (deq, dcs) = ring.enqueue_ptr();
                let _ = self.command(Trb::set_tr_dequeue(slot, dci, deq, dcs));
            }
            self.eps[ix].inflight = 0;
            self.eps[ix].halted = false;
            n += 1;
        }
        n
    }

    /// The device context of `slot`, as the controller last wrote it
    /// (diagnostics and tests): slot state and USB address.
    pub fn slot_state(&self, slot: u8) -> Option<(u8, u8)> {
        let si = self.slot_ix(slot).ok()?;
        let d = self.dev_ctx[si];
        if d.len() == 0 {
            return None;
        }
        self.mem.from_device(d.cpu(), self.layout.device_bytes());
        Some(context::slot_state(&d, self.layout.dev_slot()))
    }

    /// The endpoint state of `dci` on `slot` as the controller last wrote it.
    pub fn endpoint_state(&self, slot: u8, dci: u8) -> Option<u8> {
        let si = self.slot_ix(slot).ok()?;
        let d = self.dev_ctx[si];
        if d.len() == 0 || dci > 31 {
            return None;
        }
        self.mem.from_device(d.cpu(), self.layout.device_bytes());
        Some(context::ep_state(&d, self.layout.dev_ep(dci)))
    }
}

/// Fill `trbs[n..]` with the TRBs that carry `len` bytes at `buf`: no TRB
/// crosses a 64 KiB boundary or carries more than 64 KiB, every TRB but the
/// last is chained, the last interrupts on completion, IN TRBs interrupt on
/// short packet. `first_ty` is the type of the first TRB (a control data
/// stage is a Data TRB, the rest of its chain Normal). Returns the new count.
#[allow(clippy::too_many_arguments)]
fn split_data(
    trbs: &mut [Trb],
    mut n: usize,
    first_ty: u8,
    buf: u64,
    len: u32,
    mps: u32,
    dir_in: bool,
    ioc_on_last: bool,
) -> Result<usize, Error> {
    let mut off = 0u32;
    let mut first = true;
    while off < len {
        let at = buf + off as u64;
        #[cfg(not(feature = "canary-64k"))]
        let to_boundary = (0x1_0000 - (at & 0xffff)) as u32;
        #[cfg(feature = "canary-64k")]
        let to_boundary = u32::MAX;
        let chunk = (len - off).min(to_boundary).min(0x1_0000);
        let remaining_after = len - off - chunk;
        let td_size = remaining_after.div_ceil(mps);
        let last = remaining_after == 0;
        if n >= trbs.len() - 1 {
            return Err(Error::Invalid);
        }
        let mut flags = 0;
        if !last {
            flags |= trb::C_CH;
        } else if ioc_on_last {
            flags |= trb::C_IOC;
        }
        if dir_in {
            flags |= trb::C_ISP;
            if first && first_ty == ty::DATA {
                flags |= trb::C_DIR_IN;
            }
        }
        trbs[n] = Trb::data(if first { first_ty } else { ty::NORMAL }, at, chunk, td_size, flags);
        n += 1;
        off += chunk;
        first = false;
    }
    Ok(n)
}

/// USB Legacy Support (extended capability 1): ask the firmware to release the
/// controller (set the OS-owned semaphore, wait for the BIOS-owned one to
/// clear), then turn its SMIs off. Without this a PC's BIOS keeps emulating a
/// keyboard through the controller and resets what the OS set up.
fn bios_handoff<R: Regs, C: Clock>(regs: &R, clock: &C, caps: &Caps) -> Result<(), Error> {
    let mut off = caps.xecp;
    // A damaged list is not followed forever.
    for _ in 0..64 {
        if off == 0 {
            return Ok(());
        }
        let v = regs.read32(off);
        if v & 0xff == regs::XCAP_LEGACY {
            if v & regs::LEGSUP_BIOS_OWNED != 0 {
                regs.write32(off, v | regs::LEGSUP_OS_OWNED);
                // A firmware that never lets go is overridden after a second,
                // as every OS does: the controller is reset below anyway.
                let _ = wait_reg(regs, clock, off, regs::LEGSUP_BIOS_OWNED, 0, HANDOFF_TIMEOUT_US);
            }
            let c = regs.read32(off + 4);
            regs.write32(off + 4, (c & !regs::LEGCTL_SMI_ENABLES) | regs::LEGCTL_SMI_STATUS);
        }
        let next = ((v >> 8) & 0xff) as usize;
        if next == 0 {
            return Ok(());
        }
        off += next * 4;
    }
    Ok(())
}

/// Wait until `regs[reg] & mask == want`.
fn wait_reg<R: Regs, C: Clock>(regs: &R, clock: &C, reg: usize, mask: u32, want: u32, timeout_us: u64) -> Result<(), Error> {
    let deadline = clock.now_us() + timeout_us;
    loop {
        if regs.read32(reg) & mask == want {
            return Ok(());
        }
        if clock.now_us() >= deadline {
            return Err(Error::Timeout);
        }
        clock.delay_us(100);
    }
}
