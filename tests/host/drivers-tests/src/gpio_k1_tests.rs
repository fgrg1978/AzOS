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
//! - the edge registers, from the same driver's irq_chip: `GRER`/`GFER` hold
//!   one rising / falling detect-enable bit per pin, set by a write of 1 to
//!   `GSRER`/`GSFER` and cleared by one to `GCRER`/`GCFER` (write-only, a 0
//!   bit changes nothing); an enabled edge latches the pin's `GEDR` bit
//!   whatever the mask; a 1 written to `GEDR` clears that bit; the shared line
//!   is up while any `GEDR` bit is also set in `GAPMASK` (1 = unmasked).
//!
//! Any offset the model does not know panics too, so a driver that wanders
//! off the registers above fails loudly. Every access is logged, so a test
//! asserts on the sequence, not only the result.
//!
//! What it does NOT know, and the board must confirm (listed in the front's
//! report): that `GPLR` of an output pin follows the latch on this silicon;
//! the reset state of `GPDR` per pin (the driver relies on firmware's state,
//! it writes nothing at attach); the edge registers' offsets and their
//! set/clear and write-one-to-clear behaviour (Linux v7.2.9, not a local
//! copy: no K1 reference manual was available) [verify on silicon].

use super::gpio_k1::*;
use std::cell::RefCell;
use std::rc::Rc;

// The model's own copy of the reference's offsets.
const M_BANK: [usize; 4] = [0x00, 0x04, 0x08, 0x100];
const M_GPLR: usize = 0x00;
const M_GPDR: usize = 0x0c;
const M_GPSR: usize = 0x18;
const M_GPCR: usize = 0x24;
const M_GRER: usize = 0x30;
const M_GFER: usize = 0x3c;
const M_GEDR: usize = 0x48;
const M_GSRER: usize = 0x6c;
const M_GCRER: usize = 0x78;
const M_GSFER: usize = 0x84;
const M_GCFER: usize = 0x90;
const M_GAPMASK: usize = 0x9c;
const M_REGS: [usize; 12] = [M_GPLR, M_GPDR, M_GPSR, M_GPCR, M_GRER, M_GFER, M_GEDR, M_GSRER, M_GCRER, M_GSFER, M_GCFER, M_GAPMASK];

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
    /// Rising / falling detect enables, latched edges, interrupt mask.
    rer: [u32; 4],
    fer: [u32; 4],
    edr: [u32; 4],
    apmask: [u32; 4],
    log: Vec<Access>,
}

impl Part {
    fn decode(off: usize) -> (usize, usize) {
        for (bank, base) in M_BANK.iter().enumerate() {
            for reg in M_REGS {
                if off == base + reg {
                    return (bank, reg);
                }
            }
        }
        panic!("access to offset {off:#x}: not a register this driver may touch")
    }

    /// The outside drives `pin` to `high`: an enabled edge latches `GEDR`.
    fn drive(&mut self, pin: u32, high: bool) {
        let (b, bit) = ((pin / 32) as usize, 1u32 << (pin % 32));
        let was = self.external[b] & bit != 0;
        if was == high {
            return;
        }
        if high { self.external[b] |= bit } else { self.external[b] &= !bit }
        let enabled = if high { self.rer[b] } else { self.fer[b] };
        if enabled & bit != 0 {
            self.edr[b] |= bit;
        }
    }

    /// The controller's shared interrupt line.
    fn line(&self) -> bool {
        (0..4).any(|b| self.edr[b] & self.apmask[b] != 0)
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
            M_GRER => p.rer[bank],
            M_GFER => p.fer[bank],
            M_GEDR => p.edr[bank],
            M_GAPMASK => p.apmask[bank],
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
            M_GRER => p.rer[bank] = v,
            M_GFER => p.fer[bank] = v,
            M_GEDR => p.edr[bank] &= !v,
            M_GSRER => p.rer[bank] |= v,
            M_GCRER => p.rer[bank] &= !v,
            M_GSFER => p.fer[bank] |= v,
            M_GCFER => p.fer[bank] &= !v,
            M_GAPMASK => p.apmask[bank] = v,
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

#[test]
fn edge_init_masks_every_bank_disables_detection_and_clears_what_the_firmware_left() {
    let m = Model::new();
    {
        let mut p = m.0.borrow_mut();
        p.rer = [!0; 4];
        p.fer = [1, 2, 3, 4];
        p.edr = [0x10, 0, 0, 0x8000_0000];
        p.apmask = [!0; 4];
    }
    let mut g = K1Gpio::new(m.clone());
    g.edge_irq_init();
    let p = m.0.borrow();
    assert_eq!((p.rer, p.fer, p.edr, p.apmask), ([0; 4], [0; 4], [0; 4], [0; 4]));
    // Only the edge registers: no level or direction write.
    assert!(p.log.iter().all(|a| match a {
        Access::Write(off, _) => [M_GEDR, M_GCRER, M_GCFER, M_GAPMASK].contains(&Part::decode(*off).1),
        Access::Read(_) => false,
    }));
}

#[test]
fn both_edges_of_the_armed_pin_raise_the_line_and_take_acks_and_masks() {
    for pin in [0u32, 30, 33, 63, 96] {
        let m = Model::new();
        let mut g = K1Gpio::new(m.clone());
        g.edge_irq_init();
        m.0.borrow_mut().drive(pin, true); // released, pulled up, before arming
        assert!(g.set_both_edges(pin, true));
        assert!(g.set_unmasked(pin, true));
        assert!(!m.0.borrow().line(), "pin {pin}: arming is not an edge");
        m.0.borrow_mut().drive(pin, false); // pressed
        assert!(m.0.borrow().line(), "pin {pin}: a falling edge raises the line");
        assert!(g.take(pin));
        assert!(!m.0.borrow().line(), "pin {pin}: acknowledged and masked");
        m.0.borrow_mut().drive(pin, true); // released while the caller samples
        assert!(!m.0.borrow().line());
        assert!(!g.take(pin), "pin {pin}: a masked pin's edge is left for its unmask");
        assert!(g.set_unmasked(pin, true));
        assert!(m.0.borrow().line(), "pin {pin}: the edge while masked is taken on the unmask");
        assert!(g.take(pin));
        assert!(!g.take(pin), "pin {pin}: one edge, one take");
    }
}

#[test]
fn take_does_not_claim_a_neighbours_edge_and_arming_keeps_the_neighbours_mask() {
    let m = Model::new();
    let mut g = K1Gpio::new(m.clone());
    g.edge_irq_init();
    m.0.borrow_mut().apmask[0] = 1 << 4;
    assert!(g.set_both_edges(5, true));
    assert!(g.set_unmasked(5, true));
    assert_eq!(m.0.borrow().apmask[0], (1 << 4) | (1 << 5));
    m.0.borrow_mut().rer[0] |= 1 << 6;
    m.0.borrow_mut().drive(6, true);
    assert!(!g.take(5));
    assert!(g.ack(5));
    assert_eq!(m.0.borrow().edr[0], 1 << 6, "pin 6's edge is not pin 5's to clear");
}

#[test]
fn edge_calls_on_a_pin_the_controller_does_not_have_touch_nothing() {
    let m = Model::new();
    let mut g = K1Gpio::new(m.clone());
    assert!(!g.set_both_edges(128, true));
    assert!(!g.set_unmasked(128, true));
    assert!(!g.take(128));
    assert!(!g.ack(128));
    assert_eq!(m.log(), vec![]);
}
