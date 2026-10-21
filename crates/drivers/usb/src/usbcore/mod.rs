// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The USB core: the device table, enumeration, hubs, pipes, claims.
//!
//! [`Usb`] owns a controller ([`crate::xhci::Xhci`]) and everything above it.
//! It is driven by one call, [`Usb::service`], made from a kernel task (or from
//! an interrupt handler's deferred half): it drains the controller's events,
//! enumerates what appeared on a port, removes what left, offers new devices
//! to the class drivers in the [`Registry`] it is lent, and moves the
//! transfers class drivers queued on their pipes to the controller and their
//! completions back. Enumeration blocks the caller for the length of the
//! reset and the control transfers (milliseconds; the clock is the
//! controller's), which is what a dedicated task is for.
//!
//! # Devices
//!
//! A device is a controller slot. Its handle everywhere above the hardware is
//! the slot number plus a generation (the [`Claim`]), never a pointer. A hub's
//! children are slots too, linked through the hub's port table; removing a
//! hub removes everything below it first, children before parents.
//!
//! # Authority
//!
//! A class driver holds a [`Claim`] on one interface. Everything it can do to
//! the device goes through the claim: the endpoints it may open are those of
//! its interface ([`Usb::open_pipe`]), the control requests it may send are
//! those that address its interface or its interface's endpoints, plus the
//! reads every driver may make ([`Usb::control_allowed`]). Class and vendor
//! requests to the device or to a hub port, SET_CONFIGURATION, SET_ADDRESS and
//! the rest of the device-wide standard requests are the core's.

pub mod desc;
mod enumerate;
mod hub;
pub mod pipe;

use azos_devif::outcome::{BAD_ARGUMENT, BUSY, DENIED, FAULT, NO_RESOURCE, OK, UNSUPPORTED};
use azos_devif::Out;
use azos_rings::Producer;

use crate::class::{Claim, Registry, UsbDevice, WHOLE_DEVICE};
use crate::event::{EventKind, UsbEvent, EVENT_DEPTH};
use crate::hw::{Clock, DmaBuf, Memory, Regs, PAGE};
use crate::xhci::trb::cc;
use crate::xhci::{self, Done, EpSpec, HcEvent, Owner, Speed, TdKind, TdSpec, Xhci};
use crate::{MAX_DEVICES, MAX_PIPES, PIPE_DEPTH};
use desc::{
    Bos, ConfigDesc, DescError, DeviceDesc, HubDesc, Setup, MAX_IFACES, RT_RECIP_ENDPOINT, RT_RECIP_INTERFACE,
    XFER_BULK, XFER_INTERRUPT, XFER_ISOCH,
};
use pipe::{Completion, CoreEnd, Dir, PipeRings, Status, Transfer};

/// Hub tiers below the root: the route string holds five nibbles.
pub const MAX_TIERS: usize = 5;
/// Ports of a hub the core drives (a route string nibble is 4 bits).
pub const MAX_HUB_PORTS: usize = 15;

/// What a control transfer of the core waits at most.
const CONTROL_TIMEOUT_US: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbError {
    Hc(xhci::Error),
    /// The control transfer completed with this code.
    Transfer(u8),
    Stall,
    Desc(DescError),
    /// No such device, or it is gone.
    NoDevice,
    /// A hub is more than [`MAX_TIERS`] below the root.
    TooDeep,
    /// The device has no configuration, or none the core can use.
    NoConfig,
    /// The port did not reset or did not stay connected.
    Port,
    Timeout,
}

impl From<xhci::Error> for UsbError {
    fn from(e: xhci::Error) -> UsbError {
        UsbError::Hc(e)
    }
}

impl From<DescError> for UsbError {
    fn from(e: DescError) -> UsbError {
        UsbError::Desc(e)
    }
}

/// Text from a string descriptor, ASCII, fixed capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Text {
    bytes: [u8; 24],
    len: u8,
}

impl Text {
    pub const EMPTY: Text = Text { bytes: [0; 24], len: 0 };
    pub(crate) fn from_ascii(b: &[u8]) -> Text {
        let mut t = Text::EMPTY;
        let n = b.len().min(t.bytes.len());
        t.bytes[..n].copy_from_slice(&b[..n]);
        t.len = n as u8;
        t
    }
    pub fn as_str(&self) -> &str {
        // Only printable ASCII ever goes in (`desc::string_ascii`).
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }
}

/// A hub's state.
#[derive(Clone, Copy, Debug)]
pub struct Hub {
    pub ports: u8,
    pub desc: HubDesc,
    /// The pipe-table slot of its status-change endpoint.
    pub pipe: u8,
    /// Slot of the device on each port (0: none).
    pub children: [u8; MAX_HUB_PORTS],
    /// Status-change bitmap not yet handled (bit 0: the hub, bit n: port n).
    pub changed: u32,
    /// A transfer is queued on the status-change endpoint.
    pub armed: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Device {
    pub slot: u8,
    pub generation: u16,
    pub speed: Speed,
    pub root_port: u8,
    /// The hub this device hangs below (0: the root), and its port number.
    pub parent: u8,
    pub port: u8,
    /// Hubs between the device and the root (0: on a root port).
    pub tier: u8,
    pub route: u32,
    pub tt_slot: u8,
    pub tt_port: u8,
    pub desc: DeviceDesc,
    pub config: ConfigDesc,
    pub bos: Option<Bos>,
    pub product: Text,
    pub manufacturer: Text,
    pub hub: Option<Hub>,
    /// Registry id + 1 of the driver that holds interface `i`; 0: none.
    pub(crate) owner: [u8; MAX_IFACES],
    /// Registry ids + 1 of the watchers attached to the device.
    pub(crate) watchers: [u8; 4],
}

impl Device {
    /// `vendor << 16 | product`.
    pub fn vid_pid(&self) -> u32 {
        (self.desc.vendor as u32) << 16 | self.desc.product as u32
    }
    /// The device descriptor's class triple as `c << 16 | s << 8 | p`.
    pub fn triple(&self) -> u32 {
        (self.desc.class as u32) << 16 | (self.desc.subclass as u32) << 8 | self.desc.protocol as u32
    }
    pub fn is_hub(&self) -> bool {
        self.hub.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipeKind {
    Free,
    /// A hub's status-change endpoint: the core's own.
    Hub,
    Class,
}

struct Pipe<'q> {
    kind: PipeKind,
    slot: u8,
    dci: u8,
    ep_addr: u8,
    claim: Claim,
    end: Option<CoreEnd<'q>>,
    /// A transfer taken from the ring that the controller had no room for.
    held: Option<Transfer>,
    inflight: u8,
    dead: bool,
    /// An isochronous IN endpoint: each transfer is one service interval.
    isoch: bool,
}

impl<'q> Pipe<'q> {
    const FREE: Pipe<'q> = Pipe {
        kind: PipeKind::Free,
        slot: 0,
        dci: 0,
        ep_addr: 0,
        claim: Claim(0),
        end: None,
        held: None,
        inflight: 0,
        dead: false,
        isoch: false,
    };
}

/// Counters, for the listing and the tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub enumerated: u32,
    pub failed: u32,
    pub detached: u32,
    /// Hot-plug events dropped because nobody drained the queue.
    pub events_lost: u32,
    /// Completions that did not fit a pipe's ring (a driver exceeding the
    /// depth).
    pub completions_lost: u32,
}

const NO_EVENT: Option<UsbEvent> = None;

pub struct Usb<'q, R: Regs, M: Memory, C: Clock> {
    pub(crate) hc: Xhci<R, M, C>,
    pub(crate) devices: [Option<Device>; MAX_DEVICES],
    generations: [u16; MAX_DEVICES],
    pipes: [Pipe<'q>; MAX_PIPES],
    rings: &'q [PipeRings; MAX_PIPES],
    events: Producer<'q, UsbEvent, EVENT_DEPTH>,
    held_events: [Option<UsbEvent>; 8],
    /// Root ports (bit n-1 for port n) with a change to look at.
    root_pending: [u64; 4],
    /// Root ports with a connection nobody has enumerated yet: set by a
    /// connect change (or at start for a port already connected), cleared by
    /// the attempt. The change events a port reset raises must not start
    /// another one.
    root_connect: [u64; 4],
    /// Slot of the device on each root port.
    root_dev: [u8; 255],
    ctl: DmaBuf,
    hubbuf: DmaBuf,
    seq: u32,
    pub(crate) stats: Stats,
}

/// Bytes of `ctl` the core uses for the data stage of its control transfers.
pub(crate) const CTL_BYTES: usize = 2048;

impl<'q, R: Regs, M: Memory, C: Clock> Usb<'q, R, M, C> {
    /// A core over a started controller. `rings` are the pipes' ring pairs
    /// (static in the kernel); `events` is the producer end of the hot-plug
    /// queue. Every port with something connected is looked at on the first
    /// [`Usb::service`].
    pub fn new(
        hc: Xhci<R, M, C>,
        rings: &'q [PipeRings; MAX_PIPES],
        events: Producer<'q, UsbEvent, EVENT_DEPTH>,
    ) -> Result<Self, UsbError> {
        let mut slot = core::mem::MaybeUninit::<Self>::uninit();
        Self::init(&mut slot, hc, rings, events)?;
        // SAFETY: `init` returned `Ok`, so it wrote every field.
        Ok(unsafe { slot.assume_init() })
    }

    /// [`Usb::new`] in place: the core is built in `slot`, field by field,
    /// and never exists as a value on the caller's stack. It is 37 KB with
    /// the default limits (the controller 19 KB, the device table 15 KB) and
    /// grows with `USB_MAX_DEVICES`; a kernel that boxes it builds it in the
    /// box (`Box::new_uninit`), where `new` would put two or three copies of
    /// it in the frame of the function that starts the controller.
    pub fn init<'a>(
        slot: &'a mut core::mem::MaybeUninit<Self>,
        hc: Xhci<R, M, C>,
        rings: &'q [PipeRings; MAX_PIPES],
        events: Producer<'q, UsbEvent, EVENT_DEPTH>,
    ) -> Result<&'a mut Self, UsbError> {
        // SAFETY: a valid, aligned slot for the one field.
        unsafe { core::ptr::addr_of_mut!((*slot.as_mut_ptr()).hc).write(hc) };
        Self::init_rest(slot, rings, events)
    }

    /// [`Usb::init`] for a controller that does not exist yet: it is started
    /// in place too ([`Xhci::init`]), so neither the controller nor the core
    /// is ever a value on the caller's stack (together 37 KB with the default
    /// limits).
    #[allow(clippy::too_many_arguments)]
    pub fn init_controller<'a>(
        slot: &'a mut core::mem::MaybeUninit<Self>,
        regs: R,
        mem: M,
        clock: C,
        dma_mask: u64,
        irq: bool,
        rings: &'q [PipeRings; MAX_PIPES],
        events: Producer<'q, UsbEvent, EVENT_DEPTH>,
    ) -> Result<&'a mut Self, UsbError> {
        // SAFETY: `hc` is the first thing `init_rest` assumes written; this
        // is the same place, as a `MaybeUninit` (same layout as the value).
        let hc_slot = unsafe {
            &mut *core::ptr::addr_of_mut!((*slot.as_mut_ptr()).hc).cast::<core::mem::MaybeUninit<Xhci<R, M, C>>>()
        };
        Xhci::init(hc_slot, regs, mem, clock, dma_mask, irq)?;
        Self::init_rest(slot, rings, events)
    }

    /// Everything after `hc` is in `slot`.
    fn init_rest<'a>(
        slot: &'a mut core::mem::MaybeUninit<Self>,
        rings: &'q [PipeRings; MAX_PIPES],
        events: Producer<'q, UsbEvent, EVENT_DEPTH>,
    ) -> Result<&'a mut Self, UsbError> {
        let p = slot.as_mut_ptr();
        // SAFETY: `hc` is initialized (the callers' contract), `p` is valid
        // and aligned for a `Self`; every other field is written exactly once,
        // through `addr_of_mut!` (no reference to a field before it is
        // written), before `&mut *p` is formed. The tables are filled
        // element by element so that no table-sized temporary is made.
        let u = unsafe {
            let ctl = (*core::ptr::addr_of_mut!((*p).hc)).take_page().ok_or(xhci::Error::NoMemory)?;
            let hubbuf = (*core::ptr::addr_of_mut!((*p).hc)).take_page().ok_or(xhci::Error::NoMemory)?;
            let devices = core::ptr::addr_of_mut!((*p).devices).cast::<Option<Device>>();
            for i in 0..MAX_DEVICES {
                devices.add(i).write(None);
            }
            core::ptr::addr_of_mut!((*p).generations).write([0; MAX_DEVICES]);
            let pipes = core::ptr::addr_of_mut!((*p).pipes).cast::<Pipe<'q>>();
            for i in 0..MAX_PIPES {
                pipes.add(i).write(Pipe::FREE);
            }
            core::ptr::addr_of_mut!((*p).rings).write(rings);
            core::ptr::addr_of_mut!((*p).events).write(events);
            core::ptr::addr_of_mut!((*p).held_events).write([NO_EVENT; 8]);
            core::ptr::addr_of_mut!((*p).root_pending).write([0; 4]);
            core::ptr::addr_of_mut!((*p).root_connect).write([0; 4]);
            core::ptr::addr_of_mut!((*p).root_dev).write([0; 255]);
            core::ptr::addr_of_mut!((*p).ctl).write(ctl);
            core::ptr::addr_of_mut!((*p).hubbuf).write(hubbuf);
            core::ptr::addr_of_mut!((*p).seq).write(0);
            core::ptr::addr_of_mut!((*p).stats).write(Stats::default());
            &mut *p
        };
        for p in 1..=u.hc.ports() {
            if u.hc.port_status(p).connected() {
                u.mark_root(p);
                u.mark_connect(p, true);
            }
        }
        // Power-good: a port the controller powered just now needs its
        // device to come up before the first look.
        if u.hc.caps().ppc {
            u.hc.clock().delay_us(100_000);
        }
        Ok(u)
    }

    pub fn controller(&self) -> &Xhci<R, M, C> {
        &self.hc
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn device(&self, slot: u8) -> Option<&Device> {
        self.devices.get((slot as usize).wrapping_sub(1))?.as_ref()
    }
    /// The devices in the table, in slot order.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.iter().flatten()
    }

    pub(crate) fn mark_root(&mut self, port: u8) {
        if port >= 1 {
            let i = port as usize - 1;
            self.root_pending[i / 64] |= 1 << (i % 64);
        }
    }

    /// Set (or clear) the "connection to enumerate" flag of a root port;
    /// whether it was set.
    pub(crate) fn mark_connect(&mut self, port: u8, on: bool) -> bool {
        let i = port as usize - 1;
        let was = self.root_connect[i / 64] & 1 << (i % 64) != 0;
        if on {
            self.root_connect[i / 64] |= 1 << (i % 64);
        } else {
            self.root_connect[i / 64] &= !(1 << (i % 64));
        }
        was
    }

    pub(crate) fn emit(&mut self, kind: EventKind, d: &Device) {
        let ev = UsbEvent { kind, slot: d.slot, root_port: d.root_port, vid_pid: d.vid_pid(), class: d.triple() };
        // Older events first.
        self.flush_events();
        if self.held_events.iter().any(|e| e.is_some()) || !matches!(self.events.push(ev), azos_rings::Push::Pushed) {
            match self.held_events.iter_mut().find(|e| e.is_none()) {
                Some(h) => *h = Some(ev),
                None => self.stats.events_lost += 1,
            }
        }
    }

    fn flush_events(&mut self) {
        for i in 0..self.held_events.len() {
            if let Some(ev) = self.held_events[i] {
                if matches!(self.events.push(ev), azos_rings::Push::Pushed) {
                    self.held_events[i] = None;
                } else {
                    return;
                }
            }
        }
    }

    /// One turn of the core. See the module documentation.
    pub fn service(&mut self, reg: &mut Registry<'_>) {
        self.hc.poll();
        self.drain();
        self.root_ports(reg);
        self.hub_ports(reg);
        self.pump();
        // What the controller finished while the submissions went in.
        self.hc.poll();
        self.drain();
        if self.hc.recover_halted() > 0 {
            self.drain();
        }
        self.flush_events();
    }

    /// Hand the controller's events to whoever they belong to.
    fn drain(&mut self) {
        while let Some(ev) = self.hc.next_event() {
            let _ = self.handle(ev);
        }
    }

    /// One controller event. A completion of the core's own control transfer
    /// is returned to the caller that waits for it.
    pub(crate) fn handle(&mut self, ev: HcEvent) -> Option<Done> {
        match ev {
            HcEvent::PortChange(p) => {
                self.mark_root(p);
                None
            }
            HcEvent::Done(d) => match d.owner {
                Owner::Core => Some(d),
                Owner::Pipe(id) => {
                    self.pipe_done(id, d);
                    None
                }
                Owner::Hub(slot) => {
                    self.hub_status_done(slot, d);
                    None
                }
            },
            HcEvent::HostError(_) => None,
        }
    }

    fn root_ports(&mut self, reg: &mut Registry<'_>) {
        for w in 0..4 {
            while self.root_pending[w] != 0 {
                let b = self.root_pending[w].trailing_zeros() as usize;
                self.root_pending[w] &= !(1 << b);
                let port = (w * 64 + b + 1) as u8;
                if port <= self.hc.ports() {
                    self.root_port_event(reg, port);
                }
            }
        }
    }

    // ---- Control transfers of the core ----

    /// A control transfer on a device's endpoint 0, waited for. The data
    /// stage uses the core's control buffer: `data_out` is sent for an OUT
    /// request, an IN request reads up to `setup.length` bytes into
    /// `data_in`. Returns the bytes transferred.
    pub(crate) fn control(
        &mut self,
        slot: u8,
        setup: Setup,
        data_out: &[u8],
        data_in: &mut [u8],
    ) -> Result<usize, UsbError> {
        let len = setup.length as usize;
        if len > CTL_BYTES {
            return Err(UsbError::Desc(DescError::Truncated));
        }
        let dir_in = setup.is_in();
        if !dir_in && len > 0 {
            self.ctl.write_bytes(0, &data_out[..len.min(data_out.len())]);
            self.hc.mem().to_device(self.ctl.cpu(), len);
        }
        self.seq = self.seq.wrapping_add(1);
        let tag = self.seq;
        self.hc.queue_td(
            Xhci::<R, M, C>::ep0_index(slot),
            TdSpec {
                owner: Owner::Core,
                tag,
                kind: TdKind::Control { setup: setup.to_bytes(), buf: self.ctl.bus(), len: len as u16, dir_in },
            },
        )?;
        let deadline = self.hc.clock().now_us() + CONTROL_TIMEOUT_US;
        let done = loop {
            self.hc.poll();
            let mut found = None;
            while let Some(ev) = self.hc.next_event() {
                if let Some(d) = self.handle(ev) {
                    if d.tag == tag {
                        found = Some(d);
                    }
                }
            }
            if let Some(d) = found {
                break d;
            }
            if self.hc.is_dead() {
                return Err(UsbError::Hc(xhci::Error::Dead));
            }
            if self.hc.clock().now_us() >= deadline {
                return Err(UsbError::Timeout);
            }
            self.hc.clock().delay_us(100);
        };
        match done.code {
            cc::SUCCESS | cc::SHORT_PACKET => {
                let n = (done.actual as usize).min(len);
                if dir_in && n > 0 {
                    self.hc.mem().from_device(self.ctl.cpu(), n);
                    let n = n.min(data_in.len());
                    self.ctl.read_bytes(0, &mut data_in[..n]);
                    return Ok(n);
                }
                Ok(n)
            }
            cc::STALL => {
                self.recover();
                Err(UsbError::Stall)
            }
            c => {
                self.recover();
                Err(UsbError::Transfer(c))
            }
        }
    }

    /// Bring halted endpoints back and deliver the completions that makes.
    pub(crate) fn recover(&mut self) {
        self.hc.recover_halted();
        self.drain();
    }

    // ---- Pipes: the class drivers' side ----

    fn claim_device(&self, claim: Claim) -> Option<&Device> {
        let d = self.device(claim.slot())?;
        (d.generation == claim.generation()).then_some(d)
    }

    /// Does `claim` hold endpoint `ep` (an address)? The control endpoint is
    /// everyone's.
    fn claim_has_endpoint(d: &Device, claim: Claim, ep: u8) -> Option<desc::EndpointDesc> {
        if claim.is_device_scope() {
            return None;
        }
        let iface = d.config.interfaces().iter().find(|i| i.number == claim.iface())?;
        iface.endpoints().iter().find(|e| e.address == ep).copied()
    }

    /// May a holder of `claim` send this control request? See the module
    /// documentation.
    pub fn control_allowed(&self, claim: Claim, setup: &Setup) -> bool {
        let Some(d) = self.claim_device(claim) else { return false };
        let recip = setup.recipient();
        if setup.kind() == 0 {
            // Standard requests: the reads every driver may make, and what
            // concerns the claimed interface.
            return match recip {
                0 => setup.is_in() && matches!(setup.request, desc::REQ_GET_DESCRIPTOR | desc::REQ_GET_STATUS),
                RT_RECIP_INTERFACE => !claim.is_device_scope() && (setup.index & 0xff) as u8 == claim.iface(),
                RT_RECIP_ENDPOINT => Self::claim_has_endpoint(d, claim, (setup.index & 0xff) as u8).is_some(),
                _ => false,
            };
        }
        // Class and vendor requests: the interface and its endpoints only. A
        // request to the device or to a hub port is the core's.
        match recip {
            RT_RECIP_INTERFACE => !claim.is_device_scope() && (setup.index & 0xff) as u8 == claim.iface(),
            RT_RECIP_ENDPOINT => Self::claim_has_endpoint(d, claim, (setup.index & 0xff) as u8).is_some(),
            _ => false,
        }
    }

    /// Open a pipe for `claim` on endpoint `ep` (an address; 0: the control
    /// endpoint) of the interface's own endpoint table. The class driver then
    /// takes its ends of the pipe's rings ([`pipe::PipeEnd::take`] on the same
    /// index of the ring array).
    pub fn open_pipe(&mut self, claim: Claim, ep: u8) -> Result<u8, OpenError> {
        self.open_pipe_alt(claim, ep, 0)
    }

    /// As [`Usb::open_pipe`] for endpoint `ep` of alternate setting `alt` of
    /// the claimed interface (0: the interface's own table, see
    /// [`desc::InterfaceDesc::alt_setting`]). The endpoint's parameters are
    /// the setting's: a camera's streaming interface has a setting per
    /// bandwidth and the driver opens the one it selected with SET_INTERFACE.
    /// Isochronous endpoints open for IN only; a transfer on one is a single
    /// service interval (the endpoint's bytes per interval at most).
    pub fn open_pipe_alt(&mut self, claim: Claim, ep: u8, alt: u8) -> Result<u8, OpenError> {
        let Some(d) = self.claim_device(claim).copied() else { return Err(OpenError::NoDevice) };
        if claim.is_device_scope() {
            return Err(OpenError::Denied);
        }
        if !self.owns(&d, claim) {
            return Err(OpenError::Denied);
        }
        // A pipe slot whose rings the last holder left empty.
        let id = (0..MAX_PIPES)
            .find(|&i| {
                self.pipes[i].kind == PipeKind::Free && self.rings[i].sq.is_empty() && self.rings[i].cq.is_empty()
            })
            .ok_or(OpenError::Busy)? as u8;
        let mut isoch = false;
        let dci = if ep == 0 {
            1u8
        } else {
            let Some(e) = d.config.endpoint(claim.iface(), alt, ep) else { return Err(OpenError::Denied) };
            isoch = e.transfer_type() == XFER_ISOCH;
            if !matches!(e.transfer_type(), XFER_BULK | XFER_INTERRUPT | XFER_ISOCH) || (isoch && !e.is_in()) {
                return Err(OpenError::Unsupported);
            }
            if self.pipes.iter().any(|p| p.kind != PipeKind::Free && p.slot == claim.slot() && p.ep_addr == ep) {
                return Err(OpenError::Busy);
            }
            let dci = xhci::context::dci(ep);
            let spec = Self::ep_spec(d.speed, &e, dci, id);
            self.hc.configure_endpoints(claim.slot(), &[spec]).map_err(|_| OpenError::Fault)?;
            dci
        };
        let Some(end) = CoreEnd::take(&self.rings[id as usize]) else {
            if ep != 0 {
                let _ = self.hc.drop_endpoints(claim.slot(), 1 << dci);
            }
            return Err(OpenError::Busy);
        };
        self.pipes[id as usize] = Pipe {
            kind: PipeKind::Class,
            slot: claim.slot(),
            dci,
            ep_addr: ep,
            claim,
            end: Some(end),
            held: None,
            inflight: 0,
            dead: false,
            isoch,
        };
        Ok(id)
    }

    /// The endpoint context to configure for endpoint `e` of a device at
    /// `speed`, on pipe `id`.
    fn ep_spec(speed: Speed, e: &desc::EndpointDesc, dci: u8, id: u8) -> EpSpec {
        use xhci::context as cx;
        let ty = e.transfer_type();
        // Bytes the endpoint moves per service interval (xHCI 1.2 section
        // 6.2.3.8): the SuperSpeed companion's, else the packet size times
        // the transactions per microframe of a high-bandwidth endpoint.
        let bpi = if e.has_companion && e.bytes_per_interval != 0 {
            e.bytes_per_interval as u32
        } else {
            e.mps as u32 * (e.mult as u32 + 1)
        };
        let (ep_type, burst, mult, interval, max_esit) = match (ty, e.is_in()) {
            (XFER_BULK, true) => (cx::EP_TYPE_BULK_IN, e.burst, 0, 0, 0),
            (XFER_BULK, false) => (cx::EP_TYPE_BULK_OUT, e.burst, 0, 0, 0),
            (XFER_ISOCH, _) => (
                cx::EP_TYPE_ISOCH_IN,
                // A high-bandwidth endpoint's extra transactions are bursts.
                if e.has_companion { e.burst } else { e.mult },
                if e.has_companion { e.ss_attrs & 3 } else { 0 },
                cx::interval_field_isoch(speed, e.interval),
                bpi,
            ),
            (_, true) => (cx::EP_TYPE_INT_IN, e.burst, 0, cx::interval_field(speed, e.interval), bpi),
            (_, false) => (cx::EP_TYPE_INT_OUT, e.burst, 0, cx::interval_field(speed, e.interval), bpi),
        };
        EpSpec { dci, ep_type, mps: e.mps, burst, mult, interval, max_esit, ep: Xhci::<R, M, C>::ep_for_pipe(id) }
    }

    fn owns(&self, d: &Device, claim: Claim) -> bool {
        d.config
            .interfaces()
            .iter()
            .position(|i| i.number == claim.iface())
            .is_some_and(|ix| d.owner[ix] != 0)
    }

    /// Close a pipe `claim` opened. Transfers queued on it are dropped.
    pub fn close_pipe(&mut self, claim: Claim, id: u8) -> Result<(), OpenError> {
        let ix = id as usize;
        if ix >= MAX_PIPES || self.pipes[ix].kind != PipeKind::Class || self.pipes[ix].claim != claim {
            return Err(OpenError::NoDevice);
        }
        self.release_pipe(ix);
        Ok(())
    }

    /// Free pipe `ix`: drop its queued transfers, its endpoint, its ring ends.
    pub(crate) fn release_pipe(&mut self, ix: usize) {
        let (slot, dci, dead, is_ctl) = {
            let p = &self.pipes[ix];
            (p.slot, p.dci, p.dead, p.dci == 1)
        };
        if let Some(end) = self.pipes[ix].end.as_mut() {
            while end.sq.pop().is_some() {}
        }
        if !dead && !is_ctl && self.device(slot).is_some() {
            let _ = self.hc.drop_endpoints(slot, 1 << dci);
            self.drain();
        }
        self.pipes[ix] = Pipe::FREE;
    }

    fn pipe_done(&mut self, id: u8, d: Done) {
        let Some(p) = self.pipes.get_mut(id as usize) else { return };
        if p.kind != PipeKind::Class {
            return;
        }
        p.inflight = p.inflight.saturating_sub(1);
        let status = match d.code {
            cc::SUCCESS | cc::SHORT_PACKET => Status::Ok,
            _ if p.dead => Status::Disconnected,
            cc::STALL => Status::Stall,
            cc::BABBLE => Status::Babble,
            cc::USB_TRANSACTION_ERROR => Status::Transaction,
            c => Status::Other(c),
        };
        if let Some(end) = p.end.as_mut() {
            let c = Completion { tag: d.tag, status, actual: d.actual };
            if !matches!(end.cq.push(c), azos_rings::Push::Pushed) {
                self.stats.completions_lost += 1;
            }
        }
    }

    /// Move class drivers' submissions to the controller.
    fn pump(&mut self) {
        for ix in 0..MAX_PIPES {
            if self.pipes[ix].kind != PipeKind::Class || self.pipes[ix].dead || self.pipes[ix].end.is_none() {
                continue;
            }
            loop {
                if self.pipes[ix].held.is_none() {
                    let p = &mut self.pipes[ix];
                    let end = p.end.as_mut().expect("checked");
                    // Room for the completion of everything outstanding.
                    if end.rings.cq.len() + p.inflight as usize + 1 > PIPE_DEPTH {
                        break;
                    }
                    match end.sq.pop() {
                        Some(t) => p.held = Some(t),
                        None => break,
                    }
                }
                let t = self.pipes[ix].held.expect("just taken");
                match self.submit(ix, t) {
                    Ok(()) => {
                        self.pipes[ix].held = None;
                        self.pipes[ix].inflight += 1;
                    }
                    Err(SubmitError::Busy) => break,
                    Err(SubmitError::Refused(status)) => {
                        self.pipes[ix].held = None;
                        if let Some(end) = self.pipes[ix].end.as_mut() {
                            let c = Completion { tag: t.tag, status, actual: 0 };
                            if !matches!(end.cq.push(c), azos_rings::Push::Pushed) {
                                self.stats.completions_lost += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    fn submit(&mut self, ix: usize, t: Transfer) -> Result<(), SubmitError> {
        let (slot, claim, ep_addr) = {
            let p = &self.pipes[ix];
            (p.slot, p.claim, p.ep_addr)
        };
        let kind = if ep_addr == 0 {
            let setup = Setup::from_bytes(t.setup);
            if !self.control_allowed(claim, &setup) {
                return Err(SubmitError::Refused(Status::Denied));
            }
            if t.len < setup.length as u32 {
                return Err(SubmitError::Refused(Status::Invalid));
            }
            TdKind::Control { setup: t.setup, buf: t.buf, len: setup.length, dir_in: setup.is_in() }
        } else {
            let want_in = ep_addr & 0x80 != 0;
            if (t.dir == Dir::In) != want_in {
                return Err(SubmitError::Refused(Status::Invalid));
            }
            if self.pipes[ix].isoch {
                TdKind::Isoch { buf: t.buf, len: t.len }
            } else {
                TdKind::Data { buf: t.buf, len: t.len, dir_in: want_in }
            }
        };
        let epi = if ep_addr == 0 { Xhci::<R, M, C>::ep0_index(slot) } else { Xhci::<R, M, C>::ep_for_pipe(ix as u8) };
        match self.hc.queue_td(epi, TdSpec { owner: Owner::Pipe(ix as u8), tag: t.tag, kind }) {
            Ok(()) => Ok(()),
            Err(xhci::Error::Busy) => Err(SubmitError::Busy),
            Err(xhci::Error::Bounce) => Err(SubmitError::Refused(Status::Bounce)),
            Err(_) => Err(SubmitError::Refused(Status::Invalid)),
        }
    }

    /// Mark every pipe of `slot` dead: the device is going.
    pub(crate) fn kill_pipes(&mut self, slot: u8) {
        for p in self.pipes.iter_mut() {
            if p.kind != PipeKind::Free && p.slot == slot {
                p.dead = true;
            }
        }
    }

    /// Free what is left of the pipes of `slot`.
    pub(crate) fn reap_pipes(&mut self, slot: u8) {
        for ix in 0..MAX_PIPES {
            if self.pipes[ix].kind != PipeKind::Free && self.pipes[ix].slot == slot {
                self.release_pipe(ix);
            }
        }
    }

    pub(crate) fn alloc_pipe_slot(&mut self) -> Option<u8> {
        (0..MAX_PIPES).find(|&i| self.pipes[i].kind == PipeKind::Free).map(|i| i as u8)
    }

    pub(crate) fn set_hub_pipe(&mut self, ix: u8, slot: u8, dci: u8) {
        self.pipes[ix as usize] = Pipe { kind: PipeKind::Hub, slot, dci, ..Pipe::FREE };
    }

    pub fn pipe_in_use(&self, id: u8) -> bool {
        self.pipes.get(id as usize).is_some_and(|p| p.kind == PipeKind::Class)
    }

    /// The session a class driver's endpoint badge selects: the
    /// [`UsbDevice`] implementation for `claim`.
    pub fn session(&mut self, claim: Claim) -> Session<'_, 'q, R, M, C> {
        Session { usb: self, claim }
    }

    pub(crate) fn hub_buf(&self) -> DmaBuf {
        self.hubbuf
    }
    pub(crate) fn next_generation(&mut self, slot: u8) -> u16 {
        let g = &mut self.generations[slot as usize - 1];
        *g = g.wrapping_add(1);
        *g
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The claim names no live device, or the pipe is not the claim's.
    NoDevice,
    /// The endpoint is not the claimed interface's, or the claim is a
    /// device-scope one, or the interface is not held by a driver.
    Denied,
    /// The endpoint is open already, or no pipe is free.
    Busy,
    /// An isochronous OUT endpoint, or a transfer type that is none of bulk,
    /// interrupt and isochronous.
    Unsupported,
    /// The controller refused the endpoint.
    Fault,
}

enum SubmitError {
    Busy,
    Refused(Status),
}

/// The [`UsbDevice`] a class driver's endpoint reaches: one claim's view of
/// the core.
pub struct Session<'a, 'q, R: Regs, M: Memory, C: Clock> {
    usb: &'a mut Usb<'q, R, M, C>,
    claim: Claim,
}

impl<R: Regs, M: Memory, C: Clock> UsbDevice for Session<'_, '_, R, M, C> {
    fn info(&self, what: u32) -> Out<u64> {
        let Some(d) = self.usb.claim_device(self.claim) else { return Out::new(NO_RESOURCE, 0) };
        let iface = d.config.interfaces().iter().find(|i| i.number == self.claim.iface());
        let v = match what {
            0 => d.vid_pid() as u64,
            1 => match iface {
                Some(i) => (i.class as u64) << 16 | (i.subclass as u64) << 8 | i.protocol as u64,
                None => d.triple() as u64,
            },
            2 => d.speed.psiv() as u64,
            3 => (d.desc.bcd_usb as u64) << 16 | d.desc.bcd_device as u64,
            4 => match iface {
                Some(i) => i.num_endpoints as u64,
                None => return Out::new(DENIED, 0),
            },
            5 => match iface {
                Some(i) => i.number as u64,
                None => WHOLE_DEVICE as u64,
            },
            6 => match iface {
                Some(i) => i.alt_setting as u64,
                None => return Out::new(DENIED, 0),
            },
            _ => return Out::new(BAD_ARGUMENT, 0),
        };
        Out::ok(v)
    }

    fn endpoint(&self, index: u32) -> Out<u64> {
        let Some(d) = self.usb.claim_device(self.claim) else { return Out::new(NO_RESOURCE, 0) };
        let Some(i) = d.config.interfaces().iter().find(|i| i.number == self.claim.iface()) else {
            return Out::new(DENIED, 0);
        };
        match i.endpoints().get(index as usize) {
            Some(e) => Out::ok(
                e.address as u64
                    | (e.attrs as u64) << 8
                    | (e.mps as u64) << 16
                    | (e.interval as u64) << 32
                    | (e.burst as u64) << 40,
            ),
            None => Out::new(BAD_ARGUMENT, 0),
        }
    }

    fn pipe_open(&mut self, ep: u32) -> Out<u32> {
        if ep > 0xffff {
            return Out::new(BAD_ARGUMENT, 0);
        }
        match self.usb.open_pipe_alt(self.claim, ep as u8, (ep >> 8) as u8) {
            Ok(id) => Out::ok(id as u32),
            Err(OpenError::NoDevice) => Out::new(NO_RESOURCE, 0),
            Err(OpenError::Denied) => Out::new(DENIED, 0),
            Err(OpenError::Busy) => Out::new(BUSY, 0),
            Err(OpenError::Unsupported) => Out::new(UNSUPPORTED, 0),
            Err(OpenError::Fault) => Out::new(FAULT, 0),
        }
    }

    fn pipe_close(&mut self, pipe: u32) -> Out<u32> {
        if pipe >= MAX_PIPES as u32 {
            return Out::new(BAD_ARGUMENT, 0);
        }
        match self.usb.close_pipe(self.claim, pipe as u8) {
            Ok(()) => Out::new(OK, 0),
            Err(_) => Out::new(NO_RESOURCE, 0),
        }
    }
}

const _: () = assert!(CTL_BYTES <= PAGE);
const _: () = assert!(MAX_TIERS * 4 <= 20);
