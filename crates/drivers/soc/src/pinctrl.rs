// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pin-control framework: a consumer selects a named pin state
//! (`pinctrl-names` / `pinctrl-N`), each state is a list of configuration
//! nodes, and the manager applies them through the pad controller that is
//! the nearest registered ancestor of the configuration node.
//!
//! A configuration node is either a group itself or the parent of groups
//! (one level). A group carries `pinmux`, a list of words in the pad
//! controller's own encoding (it decodes them: which pad, which function),
//! and optionally one of `bias-disable`, `bias-pull-up`, `bias-pull-down`,
//! `bias-bus-hold`, and any of `drive-strength` (mA), `input-enable` /
//! `input-disable` and `input-schmitt-enable` / `input-schmitt-disable`,
//! which apply to every pad the group's words name. A
//! state is not transactional: a failure stops the walk and leaves the pads
//! already programmed as they are.

use crate::consumer::{self, Sel};
use crate::effect::{self, issue, Class, Effect, EffectSink, Op};
use crate::fdt::{cell, strings, Fdt, NodeId};
use crate::{Bus, Error, Result};

pub const MAX_PROVIDERS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Bias {
    Disable = 0,
    PullUp = 1,
    PullDown = 2,
    BusHold = 3,
}

/// A pad property beyond the mux and the bias (the generic pinctrl
/// properties of the same names).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Conf {
    /// `drive-strength`, in mA.
    DriveStrength(u32),
    /// `input-enable` (`true`) or `input-disable`: the pad's receiver.
    InputEnable(bool),
    /// `input-schmitt-enable` (`true`) or `input-schmitt-disable`.
    Schmitt(bool),
}

impl Conf {
    /// The effect's `value`: the property in the low byte, its argument above.
    pub fn wire(self) -> u64 {
        match self {
            Conf::DriveStrength(ma) => 1 | (ma as u64) << 8,
            Conf::InputEnable(on) => 2 | (on as u64) << 8,
            Conf::Schmitt(on) => 3 | (on as u64) << 8,
        }
    }
}

/// One pad controller.
pub trait PinctrlOps {
    /// The pad a `pinmux` word names.
    fn pin_of(&self, word: u32) -> u32;
    /// Route the pad and function the word names.
    fn set_mux(&mut self, bus: &mut dyn Bus, word: u32) -> Result<()>;
    fn set_bias(&mut self, bus: &mut dyn Bus, pin: u32, bias: Bias) -> Result<()>;
    /// Set one pad property. A controller without it says `Unsupported`.
    fn set_conf(&mut self, _bus: &mut dyn Bus, _pin: u32, _conf: Conf) -> Result<()> {
        Err(Error::Unsupported)
    }
}

struct Slot<'p> {
    node: NodeId,
    ops: &'p mut dyn PinctrlOps,
}

pub struct Pinctrl<'p> {
    slots: [Option<Slot<'p>>; MAX_PROVIDERS],
}

impl<'p> Default for Pinctrl<'p> {
    fn default() -> Self {
        Self::new()
    }
}

fn bias_of(fdt: &Fdt<'_>, n: NodeId) -> Option<Bias> {
    [
        ("bias-disable", Bias::Disable),
        ("bias-pull-up", Bias::PullUp),
        ("bias-pull-down", Bias::PullDown),
        ("bias-bus-hold", Bias::BusHold),
    ]
    .into_iter()
    .find(|(p, _)| fdt.has_prop(n, p))
    .map(|(_, b)| b)
}

/// The pad properties `g` carries, at most one of each.
fn confs_of(fdt: &Fdt<'_>, g: NodeId) -> Result<[Option<Conf>; 3]> {
    let flag = |on: &str, off: &str| {
        if fdt.has_prop(g, on) {
            Some(true)
        } else if fdt.has_prop(g, off) {
            Some(false)
        } else {
            None
        }
    };
    let drive = match fdt.prop(g, "drive-strength") {
        Some(w) => Some(Conf::DriveStrength(cell(w, 0).ok_or(Error::BadSpec)?)),
        None => None,
    };
    Ok([
        drive,
        flag("input-enable", "input-disable").map(Conf::InputEnable),
        flag("input-schmitt-enable", "input-schmitt-disable").map(Conf::Schmitt),
    ])
}

impl<'p> Pinctrl<'p> {
    pub const fn new() -> Self {
        Pinctrl { slots: [const { None }; MAX_PROVIDERS] }
    }

    /// Register the pad controller that is `node`; returns its index.
    pub fn add(&mut self, node: NodeId, ops: &'p mut dyn PinctrlOps) -> Result<u8> {
        let i = self.slots.iter().position(|s| s.is_none()).ok_or(Error::Full)?;
        self.slots[i] = Some(Slot { node, ops });
        Ok(i as u8)
    }

    /// The registered pad controller `cfg` sits under.
    fn controller(&self, fdt: &Fdt<'_>, cfg: NodeId) -> Result<usize> {
        let anc = fdt.ancestors(cfg).ok_or(Error::NotFound)?;
        anc.as_slice()
            .iter()
            .rev()
            .find_map(|a| self.slots.iter().position(|s| s.as_ref().is_some_and(|s| s.node == *a)))
            .ok_or(Error::NoProvider)
    }

    fn apply_group(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, fdt: &Fdt<'_>, prov: usize, g: NodeId) -> Result<()> {
        let words = match fdt.prop(g, "pinmux") {
            Some(w) => w,
            None => return Ok(()),
        };
        let bias = bias_of(fdt, g);
        let confs = confs_of(fdt, g)?;
        for i in 0..words.len() / 4 {
            let word = cell(words, i).ok_or(Error::BadSpec)?;
            let ops = &mut *self.slots[prov].as_mut().ok_or(Error::NoProvider)?.ops;
            let e = Effect { kind: effect::KIND_PINCTRL, op: Op::SetMux, class: Class::Reversible, provider: prov as u8, id: word, value: 0 };
            issue(fx, e, || ops.set_mux(bus, word))?;
            if let Some(b) = bias {
                let pin = ops.pin_of(word);
                let e = Effect { kind: effect::KIND_PINCTRL, op: Op::SetBias, class: Class::Reversible, provider: prov as u8, id: pin, value: b as u64 };
                issue(fx, e, || ops.set_bias(bus, pin, b))?;
            }
            for c in confs.into_iter().flatten() {
                let pin = ops.pin_of(word);
                let e = Effect { kind: effect::KIND_PINCTRL, op: Op::SetConf, class: Class::Reversible, provider: prov as u8, id: pin, value: c.wire() };
                issue(fx, e, || ops.set_conf(bus, pin, c))?;
            }
        }
        Ok(())
    }

    /// Apply the pin state `sel` of `consumer` (`Sel::Name("default")` for
    /// the state a driver sets before it touches its device).
    pub fn select(&mut self, bus: &mut dyn Bus, fx: &mut dyn EffectSink, fdt: &Fdt<'_>, consumer: NodeId, sel: Sel<'_>) -> Result<()> {
        let index = match sel {
            Sel::Index(i) => i,
            Sel::Name(n) => {
                let names = fdt.prop(consumer, "pinctrl-names").ok_or(Error::NotFound)?;
                strings(names).position(|s| s == n).ok_or(Error::NotFound)?
            }
        };
        // "pinctrl-" + decimal index
        let mut buf = [0u8; 20];
        buf[..8].copy_from_slice(b"pinctrl-");
        let mut digits = [0u8; 10];
        let mut v = index;
        let mut nd = 0;
        loop {
            digits[nd] = b'0' + (v % 10) as u8;
            nd += 1;
            v /= 10;
            if v == 0 || nd == digits.len() {
                break;
            }
        }
        for k in 0..nd {
            buf[8 + k] = digits[nd - 1 - k];
        }
        let prop = core::str::from_utf8(&buf[..8 + nd]).map_err(|_| Error::BadSpec)?;
        if !fdt.has_prop(consumer, prop) {
            return Err(Error::NotFound);
        }
        for cfg in consumer::phandles(fdt, consumer, prop) {
            let cfg = cfg?;
            let prov = self.controller(fdt, cfg)?;
            if fdt.has_prop(cfg, "pinmux") {
                self.apply_group(bus, fx, fdt, prov, cfg)?;
            } else {
                for g in fdt.children(cfg) {
                    self.apply_group(bus, fx, fdt, prov, g)?;
                }
            }
        }
        Ok(())
    }
}
