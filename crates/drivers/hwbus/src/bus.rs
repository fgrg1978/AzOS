// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The bus: a fixed table of device objects and the operations on it.
//!
//! A device has a [`Handle`], the value a `Device` capability carries as its
//! resource: its slot index. Devices are enumerated once, at boot, and never
//! leave, so a handle names the same device for the life of the kernel.
//!
//! # Life of a device
//!
//! ```text
//!   add ──► Detected ──► bind ──► Probing ──► Bound ──► unbind ──► Unbound ──► rebind ──► Bound
//!                          │            │                                  ▲
//!                          │            └──► ProbeFailed ──────────────────┤
//!                          └──► NotAdmitted / Unmatched                    │ (a row)
//! ```
//!
//! `Probing` is the instant a native driver is being asked: the bind that has
//! the device takes the bus lock for the state change before and after, and
//! asks the driver with it released ([`Access`]).
//!
//! The bus owns no driver. Probing and removing go through [`Drivers`], which
//! the kernel implements over the drivers it links; everything that happened
//! goes to a [`Sink`], which prints the `[HWBUS]` lines and records the
//! decisions. Both are traits so the host tests run the same code against
//! recorders.

use crate::device::{Device, Name};
use crate::pattern::Pattern;
use crate::policy::{decide, Choice, Policy, Row, Verdict};
use crate::tables::{LinuxEntry, NativeEntry};

/// Slots of the bus (Kconfig `HWBUS_MAX_DEVICES`).
pub const MAX_DEVICES: usize = azos_limits::HWBUS_MAX_DEVICES;

const _: () = assert!(MAX_DEVICES >= 4 && MAX_DEVICES <= 0xffff, "HWBUS_MAX_DEVICES out of range");

/// A device's name for capabilities: its slot index.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Handle(pub u32);

impl Handle {
    const fn new(index: usize) -> Self {
        Handle(index as u32)
    }
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Where a device is in its life.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Free,
    /// Found, not yet decided.
    Detected,
    /// A native driver is being asked (its probe runs with the bus lock
    /// released); no other bind starts on the device and ring 3 gets no
    /// window of it.
    Probing,
    /// A driver (native) or class server (Linux) owns it.
    Bound,
    /// The native driver's probe refused it.
    ProbeFailed,
    /// Was bound; no longer.
    Unbound,
    /// Detected; the policy or a row did not admit it.
    NotAdmitted,
    /// Detected; nothing names it.
    Unmatched,
}

/// Who owns a bound device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Binding {
    None,
    Native(Name),
    Linux { class: Name },
}

/// One slot.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    pub dev: Device,
    pub state: State,
    pub binding: Binding,
    /// Tasks hold a mapping of this device's register window
    /// ([`Bus::claim_user_window`]). Mappings are not tracked per task and
    /// outlive any rule change, so a device with one is never given to a
    /// kernel driver.
    user_maps: u32,
}

/// Why a native probe said no.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeError {
    /// No driver of that name is linked into this image.
    NoSuchDriver,
    /// The driver serves one device and has it already, or a task holds a
    /// mapping of the device's registers.
    Busy,
    /// The driver tried and the hardware refused.
    Failed,
    /// The device's clocks, resets, power domains or pin state could not be
    /// given ([`Drivers::resources`]); the driver was not asked.
    Resources,
}

/// The drivers a kernel links.
pub trait Drivers {
    /// Give the device `dev` (handle `h`) what its device-tree node asks the
    /// SoC for, before `driver` is asked to bind it: its power domains, clocks,
    /// resets and `default` pin state. Called for a native binding only
    /// (a Linux class server or a ring-3 program asks for its resources
    /// through its device interface), and only once the bus has decided to
    /// call [`probe`](Self::probe). `Err` ends the bind without calling it.
    /// The default asks for nothing.
    fn resources(&mut self, _driver: &str, _h: Handle, _dev: &Device) -> Result<(), ProbeError> {
        Ok(())
    }
    /// Give back what [`resources`](Self::resources) gave: after a `probe`
    /// that failed, and after a [`remove`](Self::remove) that succeeded.
    fn release(&mut self, _driver: &str, _h: Handle, _dev: &Device) {}
    /// Bind `driver` to the device `dev` (handle `h`).
    fn probe(&mut self, driver: &str, h: Handle, dev: &Device) -> Result<(), ProbeError>;
    /// Release it. Called for a native binding only, with the driver the
    /// device was bound to. `Err(Busy)`: the driver cannot let go of this
    /// device (a disk with a mounted volume, a controller with its queues
    /// set up); the binding stays.
    fn remove(&mut self, driver: &str, h: Handle, dev: &Device) -> Result<(), ProbeError>;
}

/// What the bus did, in order.
#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    Added { h: Handle, dev: &'a Device },
    Bound { h: Handle, dev: &'a Device, choice: Choice<'a> },
    ProbeFailed { h: Handle, dev: &'a Device, driver: &'a str, err: ProbeError },
    /// Detected, a driver would have taken it, and it was not admitted.
    NotAdmitted { h: Handle, dev: &'a Device, natural: Option<Choice<'a>>, by_row: bool },
    Unmatched { h: Handle, dev: &'a Device },
    Unbound { h: Handle, dev: &'a Device, was: Binding },
    /// A request to release the device was refused by its driver: it stays bound.
    UnbindRefused { h: Handle, dev: &'a Device, driver: &'a str },
}

pub trait Sink {
    fn event(&mut self, ev: &Event<'_>);
}

/// The tables and policy a pass runs under.
#[derive(Clone, Copy)]
pub struct Rules<'a> {
    pub native: &'a [NativeEntry],
    pub linux: &'a [LinuxEntry],
    pub rows: &'a [Row<'a>],
    pub policy: Policy,
}

/// Why [`Bus::unbind`] did not release a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UnbindError {
    /// The handle is stale, or the device has no binding to release.
    NotBound,
    /// The driver cannot let go of it ([`Drivers::remove`]).
    Refused,
}

/// Why [`Bus::add`] refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AddError {
    Full,
}

pub struct Bus {
    slots: [Slot; MAX_DEVICES],
    /// Devices refused because every slot was taken.
    refused: u32,
}

const FREE: Slot = Slot {
    dev: Device::EMPTY,
    state: State::Free,
    binding: Binding::None,
    user_maps: 0,
};

impl Bus {
    pub const fn new() -> Self {
        Bus { slots: [FREE; MAX_DEVICES], refused: 0 }
    }

    pub fn refused(&self) -> u32 {
        self.refused
    }

    /// Record a device in the first free slot. [`Access::add`] is the call
    /// that also reports it.
    pub fn insert(&mut self, dev: Device) -> Result<Handle, AddError> {
        let Some(i) = self.slots.iter().position(|s| s.state == State::Free) else {
            self.refused = self.refused.saturating_add(1);
            return Err(AddError::Full);
        };
        let s = &mut self.slots[i];
        s.dev = dev;
        s.state = State::Detected;
        s.binding = Binding::None;
        s.user_maps = 0;
        Ok(Handle::new(i))
    }

    /// The live slot `h` names, `None` for a free slot or a handle past the table.
    pub fn get(&self, h: Handle) -> Option<&Slot> {
        let s = self.slots.get(h.index())?;
        (s.state != State::Free).then_some(s)
    }

    /// Every live slot, in slot order.
    pub fn iter(&self) -> impl Iterator<Item = (Handle, &Slot)> {
        self.slots.iter().enumerate().filter(|(_, s)| s.state != State::Free)
            .map(|(i, s)| (Handle::new(i), s))
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// The `nth` live device `pattern` names, in slot order.
    pub fn find(&self, pattern: &Pattern<'_>, nth: usize) -> Option<Handle> {
        self.iter().filter(|(_, s)| s.dev.matches(pattern)).nth(nth).map(|(h, _)| h)
    }

    /// The register window ring 3 may map for `h`: the device exists, has a
    /// window, and its life has settled with no kernel driver in it. Refused:
    /// `Detected` (the stage that binds it has not run: a kernel driver may
    /// still take it), `Probing` (a driver is being asked right now),
    /// `ProbeFailed` (a driver may have programmed queues and
    /// DMA addresses before it failed: ring 3 must not write the registers it
    /// left) and `Bound` to a native driver (a kernel-driven device's
    /// registers are the kernel's).
    pub fn user_window(&self, h: Handle) -> Option<(u64, u64)> {
        let s = self.get(h)?;
        let settled = match s.state {
            State::Bound => matches!(s.binding, Binding::Linux { .. }),
            State::Unbound | State::NotAdmitted | State::Unmatched => true,
            State::Free | State::Detected | State::Probing | State::ProbeFailed => false,
        };
        if !settled || s.dev.size == 0 {
            return None;
        }
        Some((s.dev.base, s.dev.size))
    }

    /// [`user_window`](Self::user_window), and book a mapping of it: from now
    /// on no native driver is bound to the device (a bind refuses with
    /// [`ProbeError::Busy`]). A task's mapping cannot be taken back, so the
    /// bus keeps the kernel off the window instead. [`unclaim_user_window`]
    /// (Self::unclaim_user_window) gives the booking back when the mapping
    /// was not made.
    pub fn claim_user_window(&mut self, h: Handle) -> Option<(u64, u64)> {
        let window = self.user_window(h)?;
        let s = self.slot_mut(h)?;
        s.user_maps = s.user_maps.saturating_add(1);
        Some(window)
    }

    /// Give back one booking of [`claim_user_window`](Self::claim_user_window)
    /// whose mapping failed.
    pub fn unclaim_user_window(&mut self, h: Handle) {
        if let Some(s) = self.slot_mut(h) {
            s.user_maps = s.user_maps.saturating_sub(1);
        }
    }

    fn slot_mut(&mut self, h: Handle) -> Option<&mut Slot> {
        let s = self.slots.get_mut(h.index())?;
        (s.state != State::Free).then_some(s)
    }

    /// Is a Linux class server wanted: some device a Linux entry of `class`
    /// matched was admitted. The launcher of that class's server asks this;
    /// a class none of whose ids matched starts nothing.
    pub fn linux_class_wanted(&self, class: &str) -> bool {
        self.iter().any(|(_, s)| {
            s.state == State::Bound && matches!(s.binding, Binding::Linux { class: c } if c.as_str() == class)
        })
    }

    fn settle(&mut self, h: Handle, state: State) {
        if let Some(s) = self.slot_mut(h) {
            s.state = state;
            s.binding = Binding::None;
        }
    }

    /// First step of a bind, under the lock: act on the verdict for `h`. A
    /// verdict with no driver to ask is settled here; a native driver is
    /// not asked here: the slot goes to `Probing` (no other bind starts on
    /// it, ring 3 gets no window of it) and the caller asks the driver with
    /// the lock released ([`Plan::Probe`]).
    fn plan_verdict<'a>(&mut self, h: Handle, verdict: Verdict<'a>) -> Plan<'a> {
        let Some(slot) = self.get(h) else { return Plan::Skip };
        if slot.state == State::Probing {
            return Plan::Skip;
        }
        let dev = slot.dev;
        match verdict {
            Verdict::Bind(choice) => self.plan_choice(h, choice),
            Verdict::NotAdmitted { natural, by_row } => {
                self.settle(h, State::NotAdmitted);
                Plan::Done(Outcome::NotAdmitted { dev, natural, by_row })
            }
            Verdict::Unmatched => {
                self.settle(h, State::Unmatched);
                Plan::Done(Outcome::Unmatched { dev })
            }
        }
    }

    /// [`plan_verdict`](Self::plan_verdict) for a verdict that binds `choice`.
    fn plan_choice<'a>(&mut self, h: Handle, choice: Choice<'a>) -> Plan<'a> {
        let Some(slot) = self.get(h) else { return Plan::Skip };
        if slot.state == State::Probing {
            return Plan::Skip;
        }
        let dev = slot.dev;
        let mapped = slot.user_maps != 0;
        match choice {
            // A task holds a mapping of the window: the driver is not asked.
            Choice::Native(name) if mapped => {
                self.settle(h, State::ProbeFailed);
                Plan::Done(Outcome::ProbeFailed { dev, driver: name, err: ProbeError::Busy })
            }
            Choice::Native(name) => {
                self.settle(h, State::Probing);
                Plan::Probe { dev, name }
            }
            Choice::Linux { class, .. } => {
                if let Some(s) = self.slot_mut(h) {
                    s.state = State::Bound;
                    s.binding = Binding::Linux { class: Name::new(class) };
                }
                Plan::Done(Outcome::Bound { dev, choice })
            }
        }
    }

    /// Last step of a native bind, under the lock again: the driver's answer.
    fn finish_probe<'a>(&mut self, h: Handle, name: &'a str, answer: Result<(), ProbeError>) -> Option<Outcome<'a>> {
        let dev = self.get(h)?.dev;
        Some(match answer {
            Ok(()) => {
                if let Some(s) = self.slot_mut(h) {
                    s.state = State::Bound;
                    s.binding = Binding::Native(Name::new(name));
                }
                Outcome::Bound { dev, choice: Choice::Native(name) }
            }
            Err(err) => {
                self.settle(h, State::ProbeFailed);
                Outcome::ProbeFailed { dev, driver: name, err }
            }
        })
    }
}

/// What a bind did, to be reported once the lock is released.
enum Outcome<'a> {
    Bound { dev: Device, choice: Choice<'a> },
    ProbeFailed { dev: Device, driver: &'a str, err: ProbeError },
    NotAdmitted { dev: Device, natural: Option<Choice<'a>>, by_row: bool },
    Unmatched { dev: Device },
}

impl Outcome<'_> {
    fn emit(&self, h: Handle, sink: &mut dyn Sink) {
        match self {
            Outcome::Bound { dev, choice } => sink.event(&Event::Bound { h, dev, choice: *choice }),
            Outcome::ProbeFailed { dev, driver, err } => {
                sink.event(&Event::ProbeFailed { h, dev, driver, err: *err })
            }
            Outcome::NotAdmitted { dev, natural, by_row } => {
                sink.event(&Event::NotAdmitted { h, dev, natural: *natural, by_row: *by_row })
            }
            Outcome::Unmatched { dev } => sink.event(&Event::Unmatched { h, dev }),
        }
    }
}

/// What one locked step of a bind left to do.
enum Plan<'a> {
    /// Nothing: no such device, or another bind has it in hand.
    Skip,
    /// Decided under the lock; only the report is left.
    Done(Outcome<'a>),
    /// Ask native driver `name` about `dev`, lock released, then
    /// [`Bus::finish_probe`].
    Probe { dev: Device, name: &'a str },
}

/// Carry out a [`Plan`]: the driver calls and the report, with no lock held.
fn run_plan<A: Access + ?Sized>(
    bus: &mut A,
    h: Handle,
    plan: Plan<'_>,
    drivers: &mut dyn Drivers,
    sink: &mut dyn Sink,
) {
    match plan {
        Plan::Skip => {}
        Plan::Done(outcome) => outcome.emit(h, sink),
        Plan::Probe { dev, name } => {
            let answer = drivers.resources(name, h, &dev).and_then(|()| {
                drivers.probe(name, h, &dev).inspect_err(|_| drivers.release(name, h, &dev))
            });
            if let Some(outcome) = bus.with(|b| b.finish_probe(h, name, answer)) {
                outcome.emit(h, sink);
            }
        }
    }
}

/// What [`Access::reconcile`] does with one device.
enum Act<'a> {
    Keep,
    /// One native driver for another.
    Rebind(&'a str),
    /// Unbind, then decide again.
    Replace,
}

/// A way to reach a [`Bus`] that may take its lock in short steps.
///
/// The operations that call drivers and print ([`bind`](Self::bind),
/// [`bind_where`](Self::bind_where), [`unbind`](Self::unbind),
/// [`rebind`](Self::rebind), [`reconcile`](Self::reconcile)) are written
/// over `with` rather than over a `&mut Bus`, so that each takes the lock
/// only for the state change of one device: collect under the lock, act
/// after. A driver's probe and a `[HWBUS]` line run with the lock released.
/// In the kernel the lock is a spinlock with a hold bound
/// (`LOCK_MAX_HOLD_US`) and the bus is walked at boot, device by device;
/// holding it across the whole walk, a probe or a printed line was the
/// longest hold of the boot.
///
/// One caller at a time runs these operations on a bus (the boot stages, then
/// the topology install): a device a bind has in hand is `Probing`, which
/// keeps ring 3 and a second bind off it, but two concurrent unbinds of one
/// device are not arbitrated.
///
/// A plain [`Bus`] is an `Access` (the host tests); the kernel's is
/// `azos_drv_bus::hwbus::Locked`.
pub trait Access {
    /// Run `f` on the bus, under its lock.
    fn with<R>(&mut self, f: impl FnOnce(&mut Bus) -> R) -> R;

    /// Record a device in the first free slot, and report it.
    fn add(&mut self, dev: Device, sink: &mut dyn Sink) -> Result<Handle, AddError> {
        let h = self.with(|b| b.insert(dev))?;
        sink.event(&Event::Added { h, dev: &dev });
        Ok(h)
    }

    /// Decide and apply for one device.
    fn bind(&mut self, h: Handle, rules: &Rules<'_>, drivers: &mut dyn Drivers, sink: &mut dyn Sink) {
        let plan = self.with(|b| {
            let Some(slot) = b.get(h) else { return Plan::Skip };
            let verdict = decide(&slot.dev, rules.native, rules.linux, rules.rows, rules.policy);
            b.plan_verdict(h, verdict)
        });
        run_plan(self, h, plan, drivers, sink);
    }

    /// Decide and apply for every device still `Detected`, in slot order.
    fn bind_all(&mut self, rules: &Rules<'_>, drivers: &mut dyn Drivers, sink: &mut dyn Sink) {
        self.bind_where(rules, drivers, sink, &|_, _| true);
    }

    /// As [`bind_all`](Self::bind_all), for the `Detected` devices whose
    /// verdict `accept` takes; the rest stay `Detected` for a later pass. The
    /// boot binds in stages (the entropy device before the PCI bring-up, the
    /// disk before the filesystem, the NIC after it) because the drivers
    /// depend on each other's order: each stage names the drivers it wants.
    /// `accept` runs under the lock: it must be cheap and take no lock.
    fn bind_where(
        &mut self,
        rules: &Rules<'_>,
        drivers: &mut dyn Drivers,
        sink: &mut dyn Sink,
        accept: &dyn Fn(&Device, &Verdict<'_>) -> bool,
    ) {
        for i in 0..MAX_DEVICES {
            let h = Handle::new(i);
            let plan = self.with(|b| {
                let s = &b.slots[i];
                if s.state != State::Detected {
                    return Plan::Skip;
                }
                let verdict = decide(&s.dev, rules.native, rules.linux, rules.rows, rules.policy);
                if !accept(&s.dev, &verdict) {
                    return Plan::Skip;
                }
                b.plan_verdict(h, verdict)
            });
            run_plan(self, h, plan, drivers, sink);
        }
    }

    /// Run the decision again for every live device under `rules` (a signed
    /// topology arrived after the built-in one bound the first devices) and
    /// bring each to what it says: a device bound to a driver the new rules do
    /// not choose is unbound and rebound, one they do not admit is unbound
    /// and left `NotAdmitted`, one they now admit is bound. A device whose
    /// verdict is what it already is stays untouched: its driver is not
    /// disturbed.
    fn reconcile(&mut self, rules: &Rules<'_>, drivers: &mut dyn Drivers, sink: &mut dyn Sink) {
        for i in 0..MAX_DEVICES {
            let h = Handle::new(i);
            let act = self.with(|b| {
                let s = b.slots[i];
                // A device still `Detected` waits for the stage that binds it,
                // which decides under the rules then in force; one `Probing`
                // is in a bind's hands.
                if matches!(s.state, State::Free | State::Detected | State::Probing) {
                    return Act::Keep;
                }
                let verdict = decide(&s.dev, rules.native, rules.linux, rules.rows, rules.policy);
                let same = match (verdict, s.state, s.binding) {
                    (Verdict::Bind(Choice::Native(n)), State::Bound, Binding::Native(b)) => b.as_str() == n,
                    (Verdict::Bind(Choice::Linux { class, .. }), State::Bound, Binding::Linux { class: b }) => {
                        b.as_str() == class
                    }
                    (Verdict::NotAdmitted { .. }, State::NotAdmitted, _) => true,
                    (Verdict::Unmatched, State::Unmatched, _) => true,
                    // A probe that failed is not tried again for a verdict that
                    // still says bind: the same driver would fail the same way.
                    (Verdict::Bind(_), State::ProbeFailed, _) => true,
                    _ => false,
                };
                if same {
                    return Act::Keep;
                }
                // One native driver for another: a rebind. A driver that will not
                // let go keeps its device and the new rules wait for the next boot.
                match (verdict, s.state, s.binding) {
                    (Verdict::Bind(Choice::Native(n)), State::Bound, Binding::Native(_)) => Act::Rebind(n),
                    _ => Act::Replace,
                }
            });
            match act {
                Act::Keep => {}
                Act::Rebind(n) => {
                    self.rebind(h, n, drivers, sink);
                }
                Act::Replace => {
                    if self.unbind(h, drivers, sink) != Err(UnbindError::Refused) {
                        self.bind(h, rules, drivers, sink);
                    }
                }
            }
        }
    }

    /// Release a bound device. A native driver's `remove` runs first and may
    /// refuse. The device stays on the bus, `Unbound`.
    fn unbind(&mut self, h: Handle, drivers: &mut dyn Drivers, sink: &mut dyn Sink) -> Result<(), UnbindError> {
        let held = self.with(|b| {
            let s = b.get(h)?;
            (s.state == State::Bound).then_some((s.dev, s.binding))
        });
        let Some((dev, binding)) = held else { return Err(UnbindError::NotBound) };
        match binding {
            Binding::None => return Err(UnbindError::NotBound),
            Binding::Native(n) => {
                if drivers.remove(n.as_str(), h, &dev).is_err() {
                    sink.event(&Event::UnbindRefused { h, dev: &dev, driver: n.as_str() });
                    return Err(UnbindError::Refused);
                }
                drivers.release(n.as_str(), h, &dev);
            }
            // The class server is the launcher's: dropping the binding is
            // what tells it the device is gone.
            Binding::Linux { .. } => {}
        }
        self.with(|b| b.settle(h, State::Unbound));
        sink.event(&Event::Unbound { h, dev: &dev, was: binding });
        Ok(())
    }

    /// Unbind `h` if bound, then bind it to the native driver `driver`.
    /// `false` when the old driver would not let go, or the new one refused.
    fn rebind(&mut self, h: Handle, driver: &str, drivers: &mut dyn Drivers, sink: &mut dyn Sink) -> bool {
        if self.with(|b| b.get(h).is_none()) {
            return false;
        }
        if self.unbind(h, drivers, sink) == Err(UnbindError::Refused) {
            return false;
        }
        let plan = self.with(|b| b.plan_choice(h, Choice::Native(driver)));
        run_plan(self, h, plan, drivers, sink);
        self.with(|b| matches!(b.get(h), Some(s) if s.state == State::Bound))
    }
}

impl Access for Bus {
    fn with<R>(&mut self, f: impl FnOnce(&mut Bus) -> R) -> R {
        f(self)
    }
}
