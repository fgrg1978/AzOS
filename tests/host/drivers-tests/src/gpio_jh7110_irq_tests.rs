// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `gpio_jh7110_irq.rs` (the JH7110 sys pin controller's GPIO interrupt
//! registers) run on the host over a register-level model of the block.
//!
//! The model's offsets are its own copy of U-Boot v2025.07
//! `pinctrl-jh7110-sys.c`; the behaviour is Linux
//! `pinctrl-starfive-jh7110.c`'s reading of the block:
//!
//! - an edge on a pin configured for it (`IS`, `IBE`/`IEV`) latches the pin's
//!   raw status whatever its mask;
//! - `MIS` = raw status AND `IE`;
//! - a 1 -> 0 -> 1 pulse of the pin's `IC` bit clears its raw status;
//! - the block raises its line while `EN` = 1 and any `MIS` bit is set.
//!
//! Any other offset panics, so a driver that wanders into the pin
//! multiplexer's arrays from this file fails loudly.
//!
//! Not known, and the board must confirm: that `IC` clears on that pulse
//! (Linux does it; the TRM text was not available); the reset value of `IS`.

use super::gpio_jh7110_irq::*;
use std::cell::RefCell;
use std::rc::Rc;

const M_EN: usize = 0x0dc;
const M_IS: usize = 0x0e0;
const M_IC: usize = 0x0e8;
const M_IBE: usize = 0x0f0;
const M_IEV: usize = 0x0f8;
const M_IE: usize = 0x100;
const M_RIS: usize = 0x108;
const M_MIS: usize = 0x110;

#[derive(Default)]
struct Block {
    en: u32,
    is: [u32; 2],
    ic: [u32; 2],
    ibe: [u32; 2],
    iev: [u32; 2],
    ie: [u32; 2],
    ris: [u32; 2],
    level: [u32; 2],
    writes: usize,
}

impl Block {
    fn reg(&mut self, off: usize) -> (&mut [u32; 2], usize) {
        let (base, arr): (usize, &mut [u32; 2]) = match off & !4 {
            M_IS => (M_IS, &mut self.is),
            M_IC => (M_IC, &mut self.ic),
            M_IBE => (M_IBE, &mut self.ibe),
            M_IEV => (M_IEV, &mut self.iev),
            M_IE => (M_IE, &mut self.ie),
            M_RIS => (M_RIS, &mut self.ris),
            _ => panic!("offset {off:#x} is not a GPIO interrupt register"),
        };
        (arr, (off - base) / 4)
    }

    fn mis(&self, w: usize) -> u32 {
        self.ris[w] & self.ie[w]
    }

    /// The pad driven to `high` from outside.
    fn drive(&mut self, pin: u32, high: bool) {
        let (w, bit) = ((pin / 32) as usize, 1u32 << (pin % 32));
        let was = self.level[w] & bit != 0;
        if was == high {
            return;
        }
        if high { self.level[w] |= bit } else { self.level[w] &= !bit }
        let edge = self.is[w] & bit != 0;
        let both = self.ibe[w] & bit != 0;
        let rising = self.iev[w] & bit != 0;
        if edge && (both || rising == high) {
            self.ris[w] |= bit;
        }
    }

    fn line(&self) -> bool {
        self.en & 1 != 0 && (self.mis(0) | self.mis(1)) != 0
    }
}

#[derive(Clone)]
struct Bus(Rc<RefCell<Block>>);

impl Jh7110Bus for Bus {
    fn read32(&mut self, off: usize) -> u32 {
        let mut b = self.0.borrow_mut();
        match off {
            M_EN => b.en,
            M_MIS | 0x114 => b.mis((off - M_MIS) / 4),
            _ => {
                let (arr, w) = b.reg(off);
                arr[w]
            }
        }
    }
    fn write32(&mut self, off: usize, v: u32) {
        let mut b = self.0.borrow_mut();
        b.writes += 1;
        match off {
            M_EN => b.en = v,
            M_MIS | 0x114 | M_RIS | 0x10c => panic!("write to a status register {off:#x}"),
            _ if off & !4 == M_IC => {
                let w = (off - M_IC) / 4;
                // A bit going 0 -> 1 clears that pin's raw status.
                let rising = !b.ic[w] & v;
                b.ris[w] &= !rising;
                b.ic[w] = v;
            }
            _ => {
                let (arr, w) = b.reg(off);
                arr[w] = v;
            }
        }
    }
}

fn part() -> (Rc<RefCell<Block>>, Jh7110Irq<Bus>) {
    let b = Rc::new(RefCell::new(Block::default()));
    (b.clone(), Jh7110Irq::new(Bus(b)))
}

#[test]
fn init_masks_everything_clears_what_the_firmware_left_and_enables_the_block() {
    let (b, mut c) = part();
    {
        let mut m = b.borrow_mut();
        m.ie = [0xffff_ffff, 0xffff_ffff];
        m.ris = [0x8000_0001, 0x10];
    }
    c.init();
    let m = b.borrow();
    assert_eq!(m.ie, [0, 0]);
    assert_eq!(m.ris, [0, 0], "a firmware-latched edge must not fire on the first unmask");
    assert_eq!(m.en, 1);
}

#[test]
fn an_edge_on_the_armed_pin_raises_the_line_and_take_acks_and_masks() {
    let (b, mut c) = part();
    c.init();
    for pin in [30u32, 33, 63] {
        assert!(c.set_both_edges(pin));
        assert!(c.set_unmasked(pin, true));
        b.borrow_mut().drive(pin, true);
        assert!(b.borrow().line(), "pin {pin}: a rising edge raises the line");
        assert!(c.take(pin));
        assert!(!b.borrow().line(), "pin {pin}: acked and masked");
        b.borrow_mut().drive(pin, false);
        assert!(!b.borrow().line(), "pin {pin}: masked while the caller samples");
        assert!(!c.take(pin), "pin {pin}: a masked pin's edge is left for its unmask");
        assert!(c.set_unmasked(pin, true));
        assert!(b.borrow().line(), "pin {pin}: the falling edge while masked is taken on the unmask");
        assert!(c.take(pin));
    }
}

#[test]
fn take_ignores_another_pins_edge() {
    let (b, mut c) = part();
    c.init();
    c.set_both_edges(30);
    c.set_unmasked(30, true);
    c.set_both_edges(31);
    b.borrow_mut().drive(31, true);
    assert!(!c.take(30));
    assert!(!b.borrow().line(), "pin 31 is not unmasked");
}

#[test]
fn arming_one_pin_leaves_its_word_neighbours_alone() {
    let (b, mut c) = part();
    {
        let mut m = b.borrow_mut();
        m.is = [0x0000_0005, 0];
        m.ibe = [0x0000_0004, 0];
    }
    c.set_both_edges(30);
    c.set_unmasked(30, true);
    let m = b.borrow();
    assert_eq!(m.is[0], 0x4000_0005);
    assert_eq!(m.ibe[0], 0x4000_0004);
    assert_eq!(m.ie[0], 0x4000_0000);
}

#[test]
fn a_pin_the_block_does_not_have_is_refused_without_a_write() {
    let (b, mut c) = part();
    assert!(!c.set_both_edges(64));
    assert!(!c.set_unmasked(64, true));
    assert!(!c.take(64));
    assert_eq!(b.borrow().writes, 0);
    assert_eq!(irq_word_and_bit(32), Some((4, 1)));
    assert_eq!(irq_word_and_bit(31), Some((0, 1 << 31)));
}
