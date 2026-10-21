// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The pin-control framework: state selection by `pinctrl-names`, groups,
//! bias, the controller found among the configuration node's ancestors.
use crate::support::*;
use azos_soc::consumer::Sel;
use azos_soc::effect::{Class, Effect, Op, KIND_PINCTRL};
use azos_soc::fdt::Fdt;
use azos_soc::pinctrl::{Bias, Pinctrl, PinctrlOps};
use azos_soc::{Bus, Error, Result};

/// Word layout of this mock pad controller: `xxPPFF..` is pad `PP`
/// (bits 15:8), function `FF` (bits 7:0). Mux registers at 0x2000 + 4 * pad,
/// bias registers at 0x3000 + 4 * pad.
struct Pads {
    fail_mux_after: Option<usize>,
    muxes: usize,
}

impl PinctrlOps for Pads {
    fn pin_of(&self, word: u32) -> u32 {
        (word >> 8) & 0xff
    }
    fn set_mux(&mut self, bus: &mut dyn Bus, word: u32) -> Result<()> {
        if self.fail_mux_after.is_some_and(|n| self.muxes >= n) {
            return Err(Error::Hardware);
        }
        self.muxes += 1;
        bus.write32(0x2000 + 4 * self.pin_of(word) as u64, word & 0xff);
        Ok(())
    }
    fn set_bias(&mut self, bus: &mut dyn Bus, pin: u32, bias: Bias) -> Result<()> {
        bus.write32(0x3000 + 4 * pin as u64, bias as u32);
        Ok(())
    }
}

fn mux(word: u32) -> Ev {
    Ev::E(Effect { kind: KIND_PINCTRL, op: Op::SetMux, class: Class::Reversible, provider: 0, id: word, value: 0 })
}
fn bias(pin: u32, b: Bias) -> Ev {
    Ev::E(Effect { kind: KIND_PINCTRL, op: Op::SetBias, class: Class::Reversible, provider: 0, id: pin, value: b as u64 })
}

macro_rules! rig {
    ($blob:ident, $fdt:ident, $log:ident, $bus:ident, $fx:ident, $pc:ident, $u:ident, $pads:ident) => {
        let $blob = board();
        let $fdt = Fdt::parse(&$blob).unwrap();
        let $log = Log::new();
        let mut $bus = TraceBus::new(&$log);
        let mut $fx = Sink::new(&$log);
        let mut $pads = Pads { fail_mux_after: None, muxes: 0 };
        let mut $pc = Pinctrl::new();
        let $u = uart(&$fdt);
    };
}

macro_rules! register {
    ($pc:ident, $fdt:ident, $pads:ident) => {
        $pc.add($fdt.by_phandle(PINS).unwrap(), &mut $pads).unwrap();
    };
}

#[test]
fn the_default_state_programs_each_group_mux_then_bias_in_tree_order() {
    rig!(blob, fdt, log, bus, fx, pc, u, pads);
    register!(pc, fdt, pads);
    pc.select(&mut bus, &mut fx, &fdt, u, Sel::Name("default")).unwrap();
    assert_eq!(
        log.all(),
        [
            // tx-pins: pad 3, function 4, bias-disable
            mux(0x0102_0304),
            Ev::W(0x2000 + 4 * 3, 0x04),
            bias(3, Bias::Disable),
            Ev::W(0x3000 + 4 * 3, 0),
            // rx-pins: pads 0x0c and 0x0e, bias-pull-up
            mux(0x0a0b_0c0d),
            Ev::W(0x2000 + 4 * 0x0c, 0x0d),
            bias(0x0c, Bias::PullUp),
            Ev::W(0x3000 + 4 * 0x0c, 1),
            mux(0x0a0b_0e0f),
            Ev::W(0x2000 + 4 * 0x0e, 0x0f),
            bias(0x0e, Bias::PullUp),
            Ev::W(0x3000 + 4 * 0x0e, 1),
        ]
    );
}

#[test]
fn a_configuration_node_may_be_a_group_itself_and_an_empty_state_is_fine() {
    rig!(blob, fdt, log, bus, fx, pc, u, pads);
    register!(pc, fdt, pads);
    // "flat" -> flat-0: pinmux on the node, no bias property: only the mux.
    pc.select(&mut bus, &mut fx, &fdt, u, Sel::Name("flat")).unwrap();
    assert_eq!(log.all(), [mux(0x0000_0501), Ev::W(0x2000 + 4 * 5, 0x01)]);
    log.clear();
    // "sleep" -> pinctrl-1 = <>: nothing to do.
    pc.select(&mut bus, &mut fx, &fdt, u, Sel::Name("sleep")).unwrap();
    assert!(log.all().is_empty());
    // Selecting by index is the same state.
    pc.select(&mut bus, &mut fx, &fdt, u, Sel::Index(2)).unwrap();
    assert_eq!(log.writes(), [(0x2000 + 4 * 5, 0x01)]);
}

#[test]
fn a_state_that_is_not_there_is_not_found() {
    rig!(blob, fdt, log, bus, fx, pc, u, pads);
    register!(pc, fdt, pads);
    assert_eq!(pc.select(&mut bus, &mut fx, &fdt, u, Sel::Name("idle")), Err(Error::NotFound));
    // Index 7 has no pinctrl-7 property.
    assert_eq!(pc.select(&mut bus, &mut fx, &fdt, u, Sel::Index(7)), Err(Error::NotFound));
    assert!(log.all().is_empty());
}

#[test]
fn without_a_registered_pad_controller_nothing_is_programmed() {
    rig!(blob, fdt, log, bus, fx, pc, u, pads);
    let _ = &mut pads;
    assert_eq!(pc.select(&mut bus, &mut fx, &fdt, u, Sel::Name("default")), Err(Error::NoProvider));
    assert!(log.all().is_empty());
}

#[test]
fn a_failure_stops_the_walk_where_it_happened() {
    rig!(blob, fdt, log, bus, fx, pc, u, pads);
    pads.fail_mux_after = Some(1); // the second mux fails
    register!(pc, fdt, pads);
    assert_eq!(pc.select(&mut bus, &mut fx, &fdt, u, Sel::Name("default")), Err(Error::Hardware));
    // tx group done (mux + bias); rx group's first mux was recorded and failed.
    assert_eq!(log.writes(), [(0x2000 + 4 * 3, 4), (0x3000 + 4 * 3, 0)]);
    assert_eq!(log.effects().len(), 3);
}

#[test]
fn a_refused_mux_writes_nothing() {
    rig!(blob, fdt, log, bus, _fx, pc, u, pads);
    register!(pc, fdt, pads);
    let mut fx = Sink::new(&log).refusing(|e| e.op == Op::SetMux);
    assert_eq!(pc.select(&mut bus, &mut fx, &fdt, u, Sel::Name("default")), Err(Error::Refused(77)));
    assert!(log.writes().is_empty());
}
