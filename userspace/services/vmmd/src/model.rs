// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! One VM's device model: the windows, the devices behind them, and the
//! loop step that turns a [`Trap`] into a [`Completion`] and the interrupt
//! lines it raised.
//!
//! # Layout
//!
//! The guest's backends are the topology row's `devices` list, and a device
//! of that list is a virtio-mmio window of [`WINDOW`] bytes at
//! `MMIO_BASE + index * WINDOW`, interrupt line `irq_line(index)`. The kind
//! behind an index is what the row names: `Vm::config` hands vmmd the kinds
//! as a word, 4 bits a backend ([`kinds_of`]), so a row lists its backends in
//! any order. A backend vmmd has no model for (`virtio-rng`, `gpio`, ...) gets
//! no window and reads as an empty bus; so does one vmmd could not set up (a
//! disk with no file).
//!
//! The bases are the platform's own virtio-mmio region (RISC-V `virt`, ARM
//! `virt`) or, on x86 where no machine model fixes one, a hole below 4 GiB;
//! lines are as the guest's interrupt controller numbers them.

use crate::blk::{Blk, BlockStore};
use crate::console::{Console, Term};
use crate::dtb;
use crate::guest::GuestMem;
use crate::loader;
use crate::mmio::{Transport, WINDOW};
use crate::net::{Link, Net};
use crate::trap::{cpl, Completion, Rings, Trap};

/// The kind of backend at a device index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Console,
    Blk,
    Net,
}

/// Devices a row may list (Kconfig `TOPOLOGY_GUEST_DEVICES` at most).
pub const MAX_DEVICES: usize = 16;

/// The codes of `Vm::config`'s backends word (`azos_hv::backend::Backend`,
/// which the host tests check these against): 4 bits a backend.
pub const CODE_BLK: u8 = 1;
pub const CODE_NET: u8 = 2;
pub const CODE_CONSOLE: u8 = 3;

/// The kind a backend code names, if vmmd has a model for it.
pub const fn kind_of_code(code: u8) -> Option<Kind> {
    match code {
        CODE_BLK => Some(Kind::Blk),
        CODE_NET => Some(Kind::Net),
        CODE_CONSOLE => Some(Kind::Console),
        _ => None,
    }
}

/// The kinds of the first `count` devices of a row, from `Vm::config`'s
/// backends word; `None` where vmmd has no model.
pub fn kinds_of(word: u64, count: usize) -> [Option<Kind>; MAX_DEVICES] {
    let mut k = [None; MAX_DEVICES];
    for (i, slot) in k.iter_mut().enumerate().take(count.min(MAX_DEVICES)) {
        *slot = kind_of_code(((word >> (i * 4)) & 0xF) as u8);
    }
    k
}

/// The machine this monitor presents is the platform table of its own ISA
/// (`dtb::platform`): the device tree, the PVH command line and these windows
/// read the same numbers.
const PLATFORM: dtb::Platform = dtb::platform(loader::HOST);
/// The first device's window.
pub const MMIO_BASE: u64 = PLATFORM.mmio_base;

/// Where device `index`'s window starts.
pub const fn window_base(index: usize) -> u64 {
    dtb::device_base(&PLATFORM, index)
}

/// The interrupt line of device `index`.
pub const fn irq_line(index: usize) -> u32 {
    dtb::device_line(&PLATFORM, index)
}

/// A trap served: its answer and the devices whose interrupt line went up
/// while it was served (bit `i` for device index `i`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reaction {
    pub completion: Completion,
    pub raised: u16,
}

/// One pass of the loop: the devices whose line went up (bit `i` for device
/// index `i`) and the vCPUs that were answered (bit `k` for vCPU `k`, the
/// first 64), whom the loop owes a `kick`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Served {
    pub raised: u16,
    pub answered: u64,
}

/// The VM's devices.
pub struct Machine<S: BlockStore, L: Link, T: Term> {
    /// The kind at each device index of the row.
    kinds: [Option<Kind>; MAX_DEVICES],
    pub console: Option<Transport<Console<T>>>,
    pub blk: Option<Transport<Blk<S>>>,
    pub net: Option<Transport<Net<L>>>,
}

/// Run `$body` with `$t` the transport behind device `$i`, if there is one.
macro_rules! on_device {
    ($self:ident, $i:expr, |$t:ident| $body:expr) => {
        match $self.kinds[$i] {
            Some(Kind::Console) => $self.console.as_mut().map(|$t| $body),
            Some(Kind::Blk) => $self.blk.as_mut().map(|$t| $body),
            Some(Kind::Net) => $self.net.as_mut().map(|$t| $body),
            None => None,
        }
    };
}

impl<S: BlockStore, L: Link, T: Term> Machine<S, L, T> {
    /// A machine whose row lists the backends `kinds` names ([`kinds_of`]).
    pub fn new(
        kinds: [Option<Kind>; MAX_DEVICES],
        console: Option<Console<T>>,
        blk: Option<Blk<S>>,
        net: Option<Net<L>>,
    ) -> Self {
        Machine {
            kinds,
            console: console.map(Transport::new),
            blk: blk.map(Transport::new),
            net: net.map(Transport::new),
        }
    }

    /// The loop's clock, once a pass (see [`Term::tick`]).
    pub fn tick(&mut self, now_ns: u64) {
        if let Some(c) = self.console.as_mut() {
            c.dev.term.tick(now_ns);
        }
    }

    /// Is a device holding work it could not finish in one pass? The loop then
    /// comes back at once instead of sleeping.
    pub fn busy(&self) -> bool {
        self.console.as_ref().is_some_and(|t| t.busy())
            || self.blk.as_ref().is_some_and(|t| t.busy())
            || self.net.as_ref().is_some_and(|t| t.busy())
    }

    /// Windows to register with the VM: `(base, len, device index)`, for the
    /// devices of the row vmmd has a model for.
    pub fn windows(&self) -> impl Iterator<Item = (u64, u64, usize)> + '_ {
        (0..MAX_DEVICES).filter(|&i| self.kinds[i].is_some()).map(|i| (window_base(i), WINDOW, i))
    }

    fn locate(&self, gpa: u64) -> Option<(usize, u64)> {
        let rel = gpa.checked_sub(MMIO_BASE)?;
        let i = (rel / WINDOW) as usize;
        (i < MAX_DEVICES && self.kinds[i].is_some()).then_some((i, rel % WINDOW))
    }

    fn level(&mut self, i: usize) -> bool {
        on_device!(self, i, |t| t.irq_level()).unwrap_or(false)
    }

    /// Serve one trap against guest memory `mem`.
    pub fn trap(&mut self, t: &Trap, mem: &mut dyn GuestMem) -> Reaction {
        let done = |status, data| Reaction { completion: Completion { seq: t.seq, status, data }, raised: 0 };
        if !matches!(t.len, 1 | 2 | 4 | 8) {
            return done(cpl::BAD_ACCESS, 0);
        }
        let Some((i, off)) = self.locate(t.gpa) else { return done(cpl::NO_DEVICE, 0) };
        let before = self.level(i);
        let (write, len, val) = (t.write, t.len as usize, t.data);
        let Some(data) = on_device!(self, i, |d| d.access(off, write, len, val, mem)) else {
            return done(cpl::NO_DEVICE, 0);
        };
        let raised = (!before && self.level(i)) as u16 * (1 << i);
        Reaction { completion: Completion { seq: t.seq, status: cpl::OK, data }, raised }
    }

    /// Host-side events (frames, console input): run every device's receive
    /// side. The devices whose line went up.
    pub fn poll(&mut self, mem: &mut dyn GuestMem) -> u16 {
        let mut raised = 0u16;
        for i in 0..MAX_DEVICES {
            if self.kinds[i].is_none() {
                continue;
            }
            let before = self.level(i);
            let _ = on_device!(self, i, |d| d.poll(mem));
            raised |= (!before && self.level(i)) as u16 * (1 << i);
        }
        raised
    }

    /// One pass of the loop: the host side of every device, then every trap
    /// the monitor has posted, each answered on the completion ring. The
    /// devices whose line went up, and the vCPUs that were answered.
    ///
    /// A full completion ring is the monitor not draining it: the answer is
    /// dropped with its vCPU, not retried (the vCPU is not counted as
    /// answered).
    pub fn serve(&mut self, rings: &mut Rings, mem: &mut dyn GuestMem) -> Served {
        let mut out = Served { raised: self.poll(mem), answered: 0 };
        while let Some(t) = rings.pop_trap() {
            let r = self.trap(&t, mem);
            out.raised |= r.raised;
            if rings.push_completion(&r.completion) && t.vcpu < 64 {
                out.answered |= 1 << t.vcpu;
            }
        }
        out
    }
}
