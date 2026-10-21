// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `gpio_k1.rs` (the SpacemiT K1 GPIO controller) run on the host over a
//! register-level model of the part.
//!
//! The model is written from Linux v7.2.9 `drivers/gpio/gpio-spacemit-k1.c`
//! and its generic-chip setup, not from the driver: its own copy of the
//! offsets (`k1_gpio_data.bank_offsets`, `spacemit_gpio_k1_offsets`) and the
//! behaviour of the registers the Linux driver relies on:
//!
//! - `GPLR` reads the PIN level: an output pin shows its latch, an input pin
//!   shows what the outside drives;
//! - `GPDR` is read-write, one bit per pin, 1 = output;
//! - `GPSR`/`GPCR` are WRITE-ONLY set/clear registers (the driver passes `set`
//!   with `GPIO_GENERIC_UNREADABLE_REG_SET`): a write of bit `b` sets or clears
//!   latch bit `b` and no other, and a READ of them is a bug the model refuses
//!   (it panics), because on the part it returns nothing useful.
//!
//! Any offset the model does not know panics too, so a driver that wanders to
//! the interrupt registers (which this driver must not touch) fails loudly.
//! Every access is logged, so a test asserts on the sequence, not only the
//! result.
//!
//! What it does NOT know, and the board must confirm (listed in the front's
//! report): that `GPLR` of an output pin follows the latch on this silicon;
//! the reset state of `GPDR` per pin (the driver relies on firmware's state,
//! it writes nothing at attach).

use super::gpio_k1::*;
use std::cell::RefCell;
use std::rc::Rc;

// The model's own copy of the reference's offsets.
const M_BANK: [usize; 4] = [0x00, 0x04, 0x08, 0x100];
const M_GPLR: usize = 0x00;
const M_GPDR: usize = 0x0c;
const M_GPSR: usize = 0x18;
const M_GPCR: usize = 0x24;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Access {
    Read(usize),
    Write(usize, u32),
}

#[derive(Default)]
struct Part {
    /// A controller whose clock is off: writes go nowhere, reads give 0.
    gated: bool,
    /// Output latch per bank (what GPSR/GPCR drive).
    latch: [u32; 4],
    /// Direction per bank (GPDR).
    dir: [u32; 4],
    /// What the outside world drives on each pin, per bank.
    external: [u32; 4],
    log: Vec<Access>,
}

impl Part {
    fn decode(off: usize) -> (usize, usize) {
        for (bank, base) in M_BANK.iter().enumerate() {
            for reg in [M_GPLR, M_GPDR, M_GPSR, M_GPCR] {
                if off == base + reg {
                    return (bank, reg);
                }
            }
        }
        panic!("access to offset {off:#x}: not a register this driver may touch")
    }
}

#[derive(Clone)]
struct Model(Rc<RefCell<Part>>);

impl Model {
    fn new() -> Self {
        Model(Rc::new(RefCell::new(Part::default())))
    }
    fn log(&self) -> Vec<Access> {
        self.0.borrow().log.clone()
    }
    fn clear_log(&self) {
        self.0.borrow_mut().log.clear();
    }
}

impl K1GpioBus for Model {
    fn read32(&mut self, off: usize) -> u32 {
        let mut p = self.0.borrow_mut();
        p.log.push(Access::Read(off));
        let (bank, reg) = Part::decode(off);
        if p.gated {
            return 0;
        }
        match reg {
            M_GPLR => (p.latch[bank] & p.dir[bank]) | (p.external[bank] & !p.dir[bank]),
            M_GPDR => p.dir[bank],
            _ => panic!("read of the write-only register at {off:#x}"),
        }
    }
    fn write32(&mut self, off: usize, v: u32) {
        let mut p = self.0.borrow_mut();
        p.log.push(Access::Write(off, v));
        let (bank, reg) = Part::decode(off);
        if p.gated {
            return;
        }
        match reg {
            M_GPDR => p.dir[bank] = v,
            M_GPSR => p.latch[bank] |= v,
            M_GPCR => p.latch[bank] &= !v,
            _ => panic!("write to the read-only register at {off:#x}"),
        }
    }
}

fn pins() -> [u32; 9] {
    // Both ends of every bank, and the first pin the kernel does not expose.
    [0, 13, 31, 32, 63, 64, 96, 97, 127]
}

#[test]
fn a_level_write_is_one_store_to_the_right_set_or_clear_register() {
    for pin in pins() {
        let m = Model::new();
        let mut g = K1Gpio::new(m.clone());
        let bank = (pin / 32) as usize;
        let bit = 1u32 << (pin % 32);

        assert!(g.set_level(pin, true));
        assert_eq!(m.log(), vec![Access::Write(M_BANK[bank] + M_GPSR, bit)], "pin {pin} high");
        m.clear_log();
        assert!(g.set_level(pin, false));
        assert_eq!(m.log(), vec![Access::Write(M_BANK[bank] + M_GPCR, bit)], "pin {pin} low");
    }
}

#[test]
fn a_level_write_changes_that_pin_and_no_neighbour() {
    let m = Model::new();
    let mut g = K1Gpio::new(m.clone());
    // Bank 0 all high, then pin 5 low: the other 31 stay high.
    for pin in 0..32 {
        assert!(g.set_level(pin, true));
    }
    assert!(g.set_level(5, false));
    assert_eq!(m.0.borrow().latch[0], !(1u32 << 5));
    // And the other banks were not touched by bank 0's traffic.
    assert_eq!(m.0.borrow().latch[1..], [0, 0, 0]);
    // The driver never read the write-only registers: the model would have
    // panicked, and the log has no read at all on this path.
    assert!(m.log().iter().all(|a| matches!(a, Access::Write(..))));
}

#[test]
fn the_level_of_an_output_is_its_latch_and_of_an_input_is_the_outside() {
    let m = Model::new();
    let mut g = K1Gpio::new(m.clone());
    {
        let mut p = m.0.borrow_mut();
        p.external[1] = 1 << 3; // pin 35 driven high from outside
    }
    assert_eq!(g.level(35), Some(true), "an input shows the outside");
    assert_eq!(g.level(34), Some(false));

    assert!(g.set_output(35, true));
    assert!(g.set_level(35, false));
    assert_eq!(g.level(35), Some(false), "an output shows its latch, not the outside");
    assert!(g.set_level(35, true));
    assert_eq!(g.level(35), Some(true));
}

#[test]
fn a_direction_change_keeps_the_other_pins_of_the_word() {
    let m = Model::new();
    let mut g = K1Gpio::new(m.clone());
    m.0.borrow_mut().dir[2] = 0b1010_0000; // firmware drove pins 69, 71 as outputs
    assert!(g.set_output(64, true));
    assert_eq!(m.0.borrow().dir[2], 0b1010_0001);
    assert!(g.set_output(69, false));
    assert_eq!(m.0.borrow().dir[2], 0b1000_0001);
    assert_eq!(g.is_output(64), Some(true));
    assert_eq!(g.is_output(69), Some(false));
    assert_eq!(g.is_output(71), Some(true));
    // Bank 3 sits at 0x100: the word of pin 96 is not bank 0's.
    m.clear_log();
    assert!(g.set_output(96, true));
    assert_eq!(m.log(), vec![Access::Read(0x100 + M_GPDR), Access::Write(0x100 + M_GPDR, 1), Access::Read(0x100 + M_GPDR)]);
}

#[test]
fn toggle_flips_the_pin_it_names_only() {
    let m = Model::new();
    let mut g = K1Gpio::new(m.clone());
    assert!(g.set_output(40, true));
    assert!(g.set_output(41, true));
    assert!(g.set_level(41, true));
    assert!(g.toggle(40));
    assert_eq!((g.level(40), g.level(41)), (Some(true), Some(true)), "40 went high, 41 untouched");
    assert!(g.toggle(40));
    assert_eq!((g.level(40), g.level(41)), (Some(false), Some(true)));
}

#[test]
fn a_pin_the_controller_does_not_have_touches_nothing() {
    let m = Model::new();
    let mut g = K1Gpio::new(m.clone());
    assert_eq!(g.level(128), None);
    assert_eq!(g.is_output(128), None);
    assert!(!g.set_level(128, true));
    assert!(!g.set_output(1000, true));
    assert!(!g.toggle(u32::MAX));
    assert_eq!(m.log(), vec![], "no register was accessed");
}

#[test]
fn nothing_is_written_when_the_driver_is_created() {
    let m = Model::new();
    m.0.borrow_mut().dir = [0xdead_beef, 0, 0x1234, 1];
    let _g = K1Gpio::new(m.clone());
    assert_eq!(m.log(), vec![]);
    assert_eq!(m.0.borrow().dir, [0xdead_beef, 0, 0x1234, 1], "the firmware's pins are left as they are");
}

#[test]
fn a_direction_that_did_not_stick_is_reported() {
    // The APBC gate of the controller is the platform's and unmodelled: if the
    // firmware left it off, a write goes nowhere. The read-back tells.
    let m = Model::new();
    m.0.borrow_mut().gated = true;
    let mut g = K1Gpio::new(m.clone());
    assert!(!g.set_output(7, true), "an output that did not take is not success");
    // Asking for an input on a gated controller reads 0 = input: that one is
    // indistinguishable from success, and harmless (an input drives nothing).
    assert!(g.set_output(7, false));
}
