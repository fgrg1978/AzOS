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
//!   add ──► Detected ──► bind ──► Bound ──► unbind ──► Unbound ──► rebind ──► Bound
//!                          │                                  ▲
//!                          ├──► NotAdmitted / Unmatched       │ (a row)
//!                          └──► ProbeFailed ──────────────────┘
//! ```
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
}

/// The drivers a kernel links.
pub trait Drivers {
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

    /// Record a device in the first free slot.
    pub fn add(&mut self, dev: Device, sink: &mut dyn Sink) -> Result<Handle, AddError> {
        let Some(i) = self.slots.iter().position(|s| s.state == State::Free) else {
            self.refused = self.refused.saturating_add(1);
            return Err(AddError::Full);
        };
        let s = &mut self.slots[i];
        s.dev = dev;
        s.state = State::Detected;
        s.binding = Binding::None;
        s.user_maps = 0;
        let h = Handle::new(i);
        sink.event(&Event::Added { h, dev: &self.slots[i].dev });
        Ok(h)
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
    /// still take it), `ProbeFailed` (a driver may have programmed queues and
    /// DMA addresses before it failed: ring 3 must not write the registers it
    /// left) and `Bound` to a native driver (a kernel-driven device's
    /// registers are the kernel's).
    pub fn user_window(&self, h: Handle) -> Option<(u64, u64)> {
        let s = self.get(h)?;
        let settled = match s.state {
            State::Bound => matches!(s.binding, Binding::Linux { .. }),
            State::Unbound | State::NotAdmitted | State::Unmatched => true,
            State::Free | State::Detected | State::ProbeFailed => false,
        };
        if !settled || s.dev.size == 0 {
            return None;
        }
        Some((s.dev.base, s.dev.size))
    }

    /// [`user_window`](Self::user_window), and book a mapping of it: from now
    /// on no native driver is bound to the device (`apply` refuses with
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

    /// Decide and apply for one device.
    pub fn bind(&mut self, h: Handle, rules: &Rules<'_>, drivers: &mut dyn Drivers, sink: &mut dyn Sink) {
        let Some(slot) = self.get(h) else { return };
        let dev = slot.dev;
        match decide(&dev, rules.native, rules.linux, rules.rows, rules.policy) {
            Verdict::Bind(choice) => self.apply(h, choice, drivers, sink),
            Verdict::NotAdmitted { natural, by_row } => {
                self.settle(h, State::NotAdmitted);
                sink.event(&Event::NotAdmitted { h, dev: &dev, natural, by_row });
            }
            Verdict::Unmatched => {
                self.settle(h, State::Unmatched);
                sink.event(&Event::Unmatched { h, dev: &dev });
            }
        }
    }

    /// Decide and apply for every device still `Detected`, in slot order.
    pub fn bind_all(&mut self, rules: &Rules<'_>, drivers: &mut dyn Drivers, sink: &mut dyn Sink) {
        self.bind_where(rules, drivers, sink, &|_, _| true);
    }

    /// As [`bind_all`](Self::bind_all), for the `Detected` devices whose
    /// verdict `accept` takes; the rest stay `Detected` for a later pass. The
    /// boot binds in stages (the entropy device before the PCI bring-up, the
    /// disk before the filesystem, the NIC after it) because the drivers
    /// depend on each other's order: each stage names the drivers it wants.
    pub fn bind_where(
        &mut self,
        rules: &Rules<'_>,
        drivers: &mut dyn Drivers,
        sink: &mut dyn Sink,
        accept: &dyn Fn(&Device, &Verdict<'_>) -> bool,
    ) {
        for i in 0..MAX_DEVICES {
            let s = &self.slots[i];
            if s.state != State::Detected {
                continue;
            }
            let verdict = decide(&s.dev, rules.native, rules.linux, rules.rows, rules.policy);
            if accept(&s.dev, &verdict) {
                self.bind(Handle::new(i), rules, drivers, sink);
            }
        }
    }

    /// Run the decision again for every live device under `rules` (a signed
    /// topology arrived after the built-in one bound the first devices) and
    /// bring each to what it says: a device bound to a driver the new rules do
    /// not choose is unbound and rebound, one they do not admit is unbound
    /// and left `NotAdmitted`, one they now admit is bound. A device whose
    /// verdict is what it already is stays untouched: its driver is not
    /// disturbed.
    pub fn reconcile(&mut self, rules: &Rules<'_>, drivers: &mut dyn Drivers, sink: &mut dyn Sink) {
        for i in 0..MAX_DEVICES {
            let s = self.slots[i];
            // A device still `Detected` waits for the stage that binds it,
            // which decides under the rules then in force.
            if s.state == State::Free || s.state == State::Detected {
                continue;
            }
            let h = Handle::new(i);
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
                continue;
            }
            // One native driver for another: a rebind. A driver that will not
            // let go keeps its device and the new rules wait for the next boot.
            if let (Verdict::Bind(Choice::Native(n)), State::Bound, Binding::Native(_)) = (verdict, s.state, s.binding) {
                self.rebind(h, n, drivers, sink);
                continue;
            }
            if self.unbind(h, drivers, sink) == Err(UnbindError::Refused) {
                continue;
            }
            self.bind(h, rules, drivers, sink);
        }
    }

    /// Release a bound device. A native driver's `remove` runs first and may
    /// refuse. The device stays on the bus, `Unbound`.
    pub fn unbind(&mut self, h: Handle, drivers: &mut dyn Drivers, sink: &mut dyn Sink) -> Result<(), UnbindError> {
        let Some(s) = self.get(h) else { return Err(UnbindError::NotBound) };
        let (dev, binding, state) = (s.dev, s.binding, s.state);
        if state != State::Bound {
            return Err(UnbindError::NotBound);
        }
        match binding {
            Binding::None => return Err(UnbindError::NotBound),
            Binding::Native(n) => {
                if drivers.remove(n.as_str(), h, &dev).is_err() {
                    sink.event(&Event::UnbindRefused { h, dev: &dev, driver: n.as_str() });
                    return Err(UnbindError::Refused);
                }
            }
            // The class server is the launcher's: dropping the binding is
            // what tells it the device is gone.
            Binding::Linux { .. } => {}
        }
        self.settle(h, State::Unbound);
        sink.event(&Event::Unbound { h, dev: &dev, was: binding });
        Ok(())
    }

    /// Unbind `h` if bound, then bind it to the native driver `driver`.
    /// `false` when the old driver would not let go, or the new one refused.
    pub fn rebind(&mut self, h: Handle, driver: &str, drivers: &mut dyn Drivers, sink: &mut dyn Sink) -> bool {
        if self.get(h).is_none() {
            return false;
        }
        if self.unbind(h, drivers, sink) == Err(UnbindError::Refused) {
            return false;
        }
        self.apply(h, Choice::Native(driver), drivers, sink);
        matches!(self.get(h), Some(s) if s.state == State::Bound)
    }

    fn apply(&mut self, h: Handle, choice: Choice<'_>, drivers: &mut dyn Drivers, sink: &mut dyn Sink) {
        let Some(slot) = self.get(h) else { return };
        let dev = slot.dev;
        let mapped = slot.user_maps != 0;
        match choice {
            // A task holds a mapping of the window: the driver is not asked.
            Choice::Native(name) if mapped => {
                self.settle(h, State::ProbeFailed);
                sink.event(&Event::ProbeFailed { h, dev: &dev, driver: name, err: ProbeError::Busy });
            }
            Choice::Native(name) => match drivers.probe(name, h, &dev) {
                Ok(()) => {
                    if let Some(s) = self.slot_mut(h) {
                        s.state = State::Bound;
                        s.binding = Binding::Native(Name::new(name));
                    }
                    sink.event(&Event::Bound { h, dev: &dev, choice });
                }
                Err(err) => {
                    self.settle(h, State::ProbeFailed);
                    sink.event(&Event::ProbeFailed { h, dev: &dev, driver: name, err });
                }
            },
            Choice::Linux { class, .. } => {
                if let Some(s) = self.slot_mut(h) {
                    s.state = State::Bound;
                    s.binding = Binding::Linux { class: Name::new(class) };
                }
                sink.event(&Event::Bound { h, dev: &dev, choice });
            }
        }
    }

    fn settle(&mut self, h: Handle, state: State) {
        if let Some(s) = self.slot_mut(h) {
            s.state = state;
            s.binding = Binding::None;
        }
    }
}
