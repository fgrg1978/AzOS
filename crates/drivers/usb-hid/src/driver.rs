// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The class driver: from a claimed HID interface to a stream of evdev events.
//!
//! [`HidClass`] is both halves of a class driver. As a [`UsbClass`] it is what
//! the USB core calls: `attach` records the claim of an interface of class 3
//! and `detach` lets it go. It does nothing more there, because the core holds
//! itself mutably while it calls (a driver cannot open a pipe from `attach`).
//! The work is [`HidClass::poll`], which the owner calls after every
//! `Usb::service`, with the core: for each claimed interface it
//!
//! 1. **authorizes** the device ([`crate::authorize`]) and records the decision;
//! 2. opens the control pipe and reads the interface's **report descriptor**
//!    (`GET_DESCRIPTOR(Report)`, the length of the answer is the length of the
//!    descriptor), which [`Layout::parse`] turns into controls. If the device
//!    does not answer, or the answer is not a descriptor, and the interface is
//!    a boot keyboard or mouse, the driver asks the device for the **boot
//!    protocol** (`SET_PROTOCOL(0)`) and reads its reports with the layout of
//!    appendix B ([`crate::boot`]);
//! 3. sends `SET_IDLE(0)`: a keyboard sends a report when something changes
//!    and not on a timer;
//! 4. closes the control pipe, opens the interrupt IN endpoint's and keeps
//!    [`IN_DEPTH`] transfers queued on it, decoding every completed one into
//!    events for the [`Sink`] and queueing the buffer again.
//!
//! Everything it touches in the device it reaches through its claim, as an
//! `UsbDevice` (`Usb::session`): the same calls a ring-3 placement makes over
//! an endpoint. Data moves through the pipes' rings, in one DMA page per
//! interface that the driver allocates from the controller's memory, so the
//! interrupt endpoint costs no call per report. A USB keyboard repeats nothing
//! in hardware: the driver repeats the last key held ([`Repeat`]).

use azos_devif::outcome::{NO_RESOURCE, OK, UNSUPPORTED};
use azos_devif::Out;
use azos_input_wire::event::EV_KEY;
use azos_rings::Push;
use azos_usb::class::{Claim, Match, UsbClass, UsbDevice};
use azos_usb::hw::{Clock, DmaBuf, Memory, Regs, PAGE};
use azos_usb::usbcore::desc::{Setup, RT_RECIP_INTERFACE, RT_TYPE_CLASS};
use azos_usb::usbcore::pipe::{Dir, PipeEnd, PipeRings, Status, Transfer};
use azos_usb::usbcore::Usb;
use azos_usb::{MAX_PIPES, PIPE_DEPTH};

use crate::authorize::{conflicting_class, decide, record, Facts, Policy, Reason};
use crate::boot;
use crate::decode::{Decoder, Repeat};
use crate::report::Layout;

/// Interfaces the driver serves at once (Kconfig `USB_HID_MAX_IFACES`).
pub const MAX_BINDS: usize = azos_limits::USB_HID_MAX_IFACES as usize;
/// Interrupt transfers kept queued per interface.
pub const IN_DEPTH: usize = if PIPE_DEPTH < 4 { PIPE_DEPTH } else { 4 };
/// Bytes of the interface's DMA page that the control transfers use (a report
/// descriptor larger than this is not read).
pub const DESC_MAX: usize = 2048;
/// Bytes of one interrupt transfer's buffer: the largest packet served.
pub const SLICE: usize = 256;
/// How long one control transfer may take (USB 2.0, 9.2.6.4: 5 s for the data stage).
const STAGE_TIMEOUT_MS: u64 = 5_000;
/// Failed interrupt transfers in a row after which the interface is given up.
const MAX_ERRORS: u8 = 16;

const _: () = assert!(DESC_MAX + IN_DEPTH * SLICE <= PAGE);
const _: () = assert!(MAX_BINDS >= 1 && IN_DEPTH >= 1);

/// HID class requests (HID 1.11, 7.2).
const REQ_SET_IDLE: u8 = 0x0a;
const REQ_SET_PROTOCOL: u8 = 0x0b;
/// The report descriptor's descriptor type.
const DT_REPORT: u16 = 0x22;
/// `GET_DESCRIPTOR` to an interface.
const RT_GET_INTERFACE: u8 = 0x81;

/// Where input events go. `dev` is the interface's index in the driver's
/// table, stable from `attach` to `gone`.
pub trait Sink {
    /// One event: `(type, code, value)` as every input producer emits it.
    fn event(&mut self, dev: u8, ty: u16, code: u16, value: u32);
    /// The interface is gone: whatever the sink keeps for `dev` (modifier
    /// state) is stale. Every key and button still down was released by an
    /// event before this call.
    fn gone(&mut self, dev: u8);
}

/// Where an interface is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Free,
    /// Claimed, not looked at yet.
    New,
    /// The report descriptor was asked for.
    Descriptor,
    /// `SET_PROTOCOL(boot)` was sent.
    Protocol,
    /// `SET_IDLE` was sent.
    Idle,
    /// Reports are flowing.
    Running,
    /// The policy refused the device.
    Refused,
    /// The interface has nothing a keyboard or a mouse reports (a vendor
    /// collection, a gamepad): left alone.
    Ignored,
    /// The device did not answer as a HID device must, or a transfer failed
    /// for good.
    Failed,
    /// The core let the claim go; the buffer and the keys are owed.
    Gone,
}

struct Bind<'q> {
    state: State,
    claim: Claim,
    vid_pid: u32,
    triple: u32,
    layout: Layout,
    dec: Decoder,
    rep: Repeat,
    buf: Option<DmaBuf>,
    ctl: Option<PipeEnd<'q>>,
    intr: Option<PipeEnd<'q>>,
    in_len: u16,
    errors: u8,
    since_ms: u64,
    /// The pipe died with the device: no more transfers.
    dead: bool,
}

impl<'q> Bind<'q> {
    const fn free() -> Bind<'q> {
        Bind {
            state: State::Free,
            claim: Claim(0),
            vid_pid: 0,
            triple: 0,
            layout: Layout::EMPTY,
            dec: Decoder::new(),
            rep: Repeat::new(),
            buf: None,
            ctl: None,
            intr: None,
            in_len: 0,
            errors: 0,
            since_ms: 0,
            dead: false,
        }
    }

    fn new(claim: Claim, vid_pid: u32, triple: u32) -> Bind<'q> {
        Bind { state: State::New, claim, vid_pid, triple, ..Bind::free() }
    }

    fn subclass(&self) -> u8 {
        (self.triple >> 8) as u8
    }
    fn protocol(&self) -> u8 {
        self.triple as u8
    }
}

/// Close `end` the way a pipe's owner must: its completions are drained before
/// the rings can be taken again.
fn drop_end(end: &mut Option<PipeEnd<'_>>) {
    if let Some(e) = end.as_mut() {
        while e.cq.pop().is_some() {}
    }
    *end = None;
}

/// The class driver of every HID interface the policy admits.
pub struct HidClass<'q> {
    rings: &'q [PipeRings; MAX_PIPES],
    policy: Policy,
    binds: [Bind<'q>; MAX_BINDS],
    /// The report descriptor being parsed (one at a time).
    scratch: [u8; DESC_MAX],
    /// Reports decoded since boot, for the owner to show.
    pub reports: u64,
}

impl<'q> HidClass<'q> {
    /// `const`: the kernel keeps the driver in a static (it is about 15 KiB, too much to build on a stack).
    pub const fn new(rings: &'q [PipeRings; MAX_PIPES], policy: Policy) -> HidClass<'q> {
        HidClass { rings, policy, binds: [const { Bind::free() }; MAX_BINDS], scratch: [0; DESC_MAX], reports: 0 }
    }

    /// The rule to register the driver under: every interface of class 3.
    pub const fn rule() -> Match {
        Match::interface_class(CLASS_HID)
    }

    /// The state of interface slot `ix`.
    pub fn state(&self, ix: usize) -> State {
        self.binds[ix].state
    }

    /// Interfaces whose reports are flowing.
    pub fn running(&self) -> usize {
        self.binds.iter().filter(|b| b.state == State::Running).count()
    }

    /// One turn, after `usb.service`: advance every interface, decode what its
    /// endpoint delivered, repeat the key held. `now_ms` is a monotonic clock.
    pub fn poll<R: Regs, M: Memory, C: Clock>(&mut self, usb: &mut Usb<'q, R, M, C>, now_ms: u64, sink: &mut dyn Sink) {
        for ix in 0..MAX_BINDS {
            self.step(ix, usb, now_ms, sink);
        }
    }

    fn step<R: Regs, M: Memory, C: Clock>(&mut self, ix: usize, usb: &mut Usb<'q, R, M, C>, now_ms: u64, sink: &mut dyn Sink) {
        let HidClass { rings, policy, binds, scratch, reports } = self;
        let b = &mut binds[ix];
        let dev = ix as u8;
        match b.state {
            State::Free | State::Refused | State::Ignored => {}
            // Failed in a helper that could not close what it had (a submission the
            // ring refused): the pipes and the page go back now.
            State::Failed => {
                if b.ctl.is_some() || b.intr.is_some() || b.buf.is_some() {
                    abandon(usb, b, State::Failed);
                }
            }
            State::New => {
                let Some(d) = usb.device(b.claim.slot()).filter(|d| d.generation == b.claim.generation()) else {
                    b.state = State::Gone;
                    return;
                };
                let facts = Facts {
                    root_port: d.root_port,
                    vid_pid: b.vid_pid,
                    triple: b.triple,
                    tier: d.tier,
                    composite_conflict: d.config.interfaces().iter().any(|i| conflicting_class(i.class)),
                };
                let reason = decide(policy, &facts);
                record(&facts, reason);
                if reason != Reason::Authorized {
                    b.state = State::Refused;
                    return;
                }
                let hc = usb.controller();
                let Some(buf) = hc.mem().alloc_region(PAGE, PAGE, hc.dma_mask()) else {
                    b.state = State::Failed;
                    return;
                };
                // The zeroes the CPU wrote must not be written back over what the device stores.
                hc.mem().to_device(buf.cpu(), PAGE);
                b.buf = Some(buf);
                let Some(end) = open_pipe(usb, rings, b.claim, 0) else {
                    b.state = State::Failed;
                    return;
                };
                b.ctl = Some(end);
                let setup = Setup {
                    request_type: RT_GET_INTERFACE,
                    request: azos_usb::usbcore::desc::REQ_GET_DESCRIPTOR,
                    value: DT_REPORT << 8,
                    index: b.claim.iface() as u16,
                    length: DESC_MAX as u16,
                };
                submit_control(b, setup);
                b.state = State::Descriptor;
                b.since_ms = now_ms;
            }
            State::Descriptor => {
                let Some(c) = b.ctl.as_mut().and_then(|e| e.cq.pop()) else {
                    timeout(usb, b, now_ms);
                    return;
                };
                let parsed = match (c.status, b.buf) {
                    (Status::Ok, Some(buf)) => {
                        let n = (c.actual as usize).min(DESC_MAX);
                        usb.controller().mem().from_device(buf.cpu(), n);
                        buf.read_bytes(0, &mut scratch[..n]);
                        Layout::parse(&scratch[..n]).ok()
                    }
                    _ => None,
                };
                match parsed {
                    Some(l) if l.is_useful() => {
                        b.layout = l;
                        send_idle(b, now_ms);
                    }
                    Some(_) => ignore(usb, b),
                    None if b.subclass() == boot::SUBCLASS_BOOT => match boot::layout(b.protocol()) {
                        Some(l) => {
                            b.layout = l;
                            let setup = hid_request(REQ_SET_PROTOCOL, 0, b.claim.iface());
                            submit_control(b, setup);
                            b.state = State::Protocol;
                            b.since_ms = now_ms;
                        }
                        None => ignore(usb, b),
                    },
                    None => fail(usb, b),
                }
            }
            State::Protocol => {
                let Some(_) = b.ctl.as_mut().and_then(|e| e.cq.pop()) else {
                    timeout(usb, b, now_ms);
                    return;
                };
                // A device that stalls SET_PROTOCOL still sends its boot report.
                send_idle(b, now_ms);
            }
            State::Idle => {
                let Some(_) = b.ctl.as_mut().and_then(|e| e.cq.pop()) else {
                    timeout(usb, b, now_ms);
                    return;
                };
                // SET_IDLE is optional (a device may stall it).
                start_reports(usb, rings, b, now_ms);
            }
            State::Running => {
                let Some(buf) = b.buf else { return };
                let Bind { intr, layout, dec, rep, errors, dead, in_len, state, .. } = b;
                let Some(end) = intr.as_mut() else { return };
                let mut data = [0u8; SLICE];
                while let Some(c) = end.cq.pop() {
                    match c.status {
                        Status::Ok => {
                            *errors = 0;
                            let n = (c.actual as usize).min(SLICE);
                            let off = DESC_MAX + (c.tag as usize % IN_DEPTH) * SLICE;
                            usb.controller().mem().from_device(buf.cpu().wrapping_add(off), n);
                            buf.read_bytes(off, &mut data[..n]);
                            *reports += 1;
                            dec.report(layout, &data[..n], |ty, code, value| {
                                rep.observe(ty, code, value, now_ms, azos_limits::USB_HID_REPEAT_DELAY_MS as u64);
                                sink.event(dev, ty, code, value);
                            });
                        }
                        Status::Disconnected => *dead = true,
                        _ => *errors = errors.saturating_add(1),
                    }
                    if *dead {
                        continue;
                    }
                    if *errors >= MAX_ERRORS {
                        *state = State::Failed;
                        break;
                    }
                    let t = Transfer {
                        tag: c.tag,
                        dir: Dir::In,
                        setup: [0; 8],
                        buf: buf.bus_at(DESC_MAX + (c.tag as usize % IN_DEPTH) * SLICE),
                        len: *in_len as u32,
                    };
                    if !matches!(end.sq.push(t), Push::Pushed) {
                        *errors = errors.saturating_add(1);
                    }
                }
                if b.state == State::Failed {
                    release(b, dev, sink);
                    abandon(usb, b, State::Failed);
                    return;
                }
                if let Some(code) = b.rep.due(now_ms, azos_limits::USB_HID_REPEAT_PERIOD_MS as u64) {
                    sink.event(dev, EV_KEY, code, 2);
                }
            }
            State::Gone => {
                release(b, dev, sink);
                if let Some(buf) = b.buf.take() {
                    usb.controller().mem().free_region(buf);
                }
                *b = Bind::free();
            }
        }
    }
}

/// HID's interface class.
pub const CLASS_HID: u8 = 3;

/// Every key and button down is released, the repeat stops, the sink forgets.
fn release(b: &mut Bind<'_>, dev: u8, sink: &mut dyn Sink) {
    let Bind { dec, rep, .. } = b;
    dec.release_all(|ty, code, value| sink.event(dev, ty, code, value));
    rep.clear();
    sink.gone(dev);
}

fn timeout<R: Regs, M: Memory, C: Clock>(usb: &mut Usb<'_, R, M, C>, b: &mut Bind<'_>, now_ms: u64) {
    if now_ms.saturating_sub(b.since_ms) > STAGE_TIMEOUT_MS {
        abandon(usb, b, State::Failed);
    }
}

fn hid_request(request: u8, value: u16, iface: u8) -> Setup {
    Setup { request_type: RT_TYPE_CLASS | RT_RECIP_INTERFACE, request, value, index: iface as u16, length: 0 }
}

fn submit_control(b: &mut Bind<'_>, setup: Setup) {
    let (Some(end), Some(buf)) = (b.ctl.as_mut(), b.buf) else { return };
    let t = Transfer {
        tag: 0,
        dir: if setup.is_in() { Dir::In } else { Dir::Out },
        setup: setup.to_bytes(),
        buf: buf.bus_at(0),
        len: setup.length as u32,
    };
    if !matches!(end.sq.push(t), Push::Pushed) {
        b.state = State::Failed;
    }
}

fn send_idle(b: &mut Bind<'_>, now_ms: u64) {
    let setup = hid_request(REQ_SET_IDLE, 0, b.claim.iface());
    submit_control(b, setup);
    b.state = if b.state == State::Failed { State::Failed } else { State::Idle };
    b.since_ms = now_ms;
}

/// Open pipe `ep` of `claim` and take its ends.
fn open_pipe<'q, R: Regs, M: Memory, C: Clock>(
    usb: &mut Usb<'q, R, M, C>,
    rings: &'q [PipeRings; MAX_PIPES],
    claim: Claim,
    ep: u8,
) -> Option<PipeEnd<'q>> {
    let out = usb.session(claim).pipe_open(ep as u32);
    if out.code != OK {
        return None;
    }
    let id = out.value as u8;
    match PipeEnd::take(rings.get(id as usize)?, id) {
        Some(e) => Some(e),
        None => {
            let _ = usb.session(claim).pipe_close(id as u32);
            None
        }
    }
}

fn close_pipe<R: Regs, M: Memory, C: Clock>(usb: &mut Usb<'_, R, M, C>, claim: Claim, end: &mut Option<PipeEnd<'_>>) {
    if let Some(e) = end.as_ref() {
        let _ = usb.session(claim).pipe_close(e.id as u32);
    }
    drop_end(end);
}

/// Give back what the interface holds in the core and in memory (its pipes, its
/// DMA page) and leave it in `state`: it will do nothing more until the device goes.
fn abandon<R: Regs, M: Memory, C: Clock>(usb: &mut Usb<'_, R, M, C>, b: &mut Bind<'_>, state: State) {
    close_pipe(usb, b.claim, &mut b.ctl);
    close_pipe(usb, b.claim, &mut b.intr);
    if let Some(buf) = b.buf.take() {
        usb.controller().mem().free_region(buf);
    }
    b.state = state;
}

fn ignore<R: Regs, M: Memory, C: Clock>(usb: &mut Usb<'_, R, M, C>, b: &mut Bind<'_>) {
    abandon(usb, b, State::Ignored);
}

fn fail<R: Regs, M: Memory, C: Clock>(usb: &mut Usb<'_, R, M, C>, b: &mut Bind<'_>) {
    abandon(usb, b, State::Failed);
}

/// The control pipe is done: open the interrupt IN endpoint and queue the first reports.
fn start_reports<'q, R: Regs, M: Memory, C: Clock>(
    usb: &mut Usb<'q, R, M, C>,
    rings: &'q [PipeRings; MAX_PIPES],
    b: &mut Bind<'q>,
    _now_ms: u64,
) {
    close_pipe(usb, b.claim, &mut b.ctl);
    let Some(buf) = b.buf else { return fail(usb, b) };
    let Some((addr, mps)) = interrupt_in(&mut usb.session(b.claim)) else { return fail(usb, b) };
    // Bits 11 and 12 of a high speed endpoint's max packet size count extra
    // transactions per microframe; an interrupt endpoint of a keyboard has none.
    let packet = (mps & 0x7ff) as usize;
    if packet == 0 || packet > SLICE {
        return fail(usb, b);
    }
    let Some(mut end) = open_pipe(usb, rings, b.claim, addr) else { return fail(usb, b) };
    b.in_len = packet as u16;
    for k in 0..IN_DEPTH {
        let t = Transfer { tag: k as u32, dir: Dir::In, setup: [0; 8], buf: buf.bus_at(DESC_MAX + k * SLICE), len: packet as u32 };
        if !matches!(end.sq.push(t), Push::Pushed) {
            break;
        }
    }
    b.intr = Some(end);
    b.state = State::Running;
}

/// The address and max packet size of the interface's first interrupt IN endpoint.
fn interrupt_in(s: &mut impl UsbDevice) -> Option<(u8, u16)> {
    let n = s.info(4);
    if n.code != OK {
        return None;
    }
    for i in 0..n.value as u32 {
        let e = s.endpoint(i);
        if e.code != OK {
            continue;
        }
        let (addr, attrs, mps) = (e.value as u8, (e.value >> 8) as u8, (e.value >> 16) as u16);
        if attrs & 3 == 3 && addr & 0x80 != 0 {
            return Some((addr, mps));
        }
    }
    None
}

impl UsbClass for HidClass<'_> {
    fn attach(&mut self, claim: u32, vid_pid: u32, triple: u32, _speed_port: u32) -> Out<u32> {
        let c = Claim(claim);
        if c.is_device_scope() {
            return Out::new(UNSUPPORTED, 0);
        }
        let Some(b) = self.binds.iter_mut().find(|b| b.state == State::Free) else {
            return Out::new(NO_RESOURCE, 0);
        };
        *b = Bind::new(c, vid_pid, triple);
        Out::new(OK, 0)
    }

    fn detach(&mut self, claim: u32) -> Out<u32> {
        let c = Claim(claim);
        if let Some(b) = self.binds.iter_mut().find(|b| b.state != State::Free && b.state != State::Gone && b.claim == c) {
            // The core freed the device's pipes before it said so; the rings'
            // ends go back so a later pipe can take them.
            drop_end(&mut b.ctl);
            drop_end(&mut b.intr);
            b.state = State::Gone;
        }
        Out::new(OK, 0)
    }
}
