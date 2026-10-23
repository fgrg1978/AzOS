// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `azos_pcspk` against a model of the PC's speaker: PIT channel 2's mode and
//! counter, and port 0x61 with the bits a write must keep.

use std::cell::RefCell;
use std::rc::Rc;

use azos_buzzer::{Driver, Pwm, DUTY_PCT};
use azos_pcspk::{divisor, PcSpeaker, Ports, PIT_HZ, PORT_CH2, PORT_GATE, PORT_MODE};

/// Port 0x61 as firmware leaves it: the NMI enables (bits 2, 3) and the
/// refresh toggle (bit 4) set, which no write may lose.
const GATE_RESET: u8 = 0b0001_1100;

#[derive(Default)]
struct Pit {
    mode: Vec<u8>,
    counter: Vec<u8>,
    gate: u8,
    /// `OUT2` levels the next reads of 0x61 return while the gate is on,
    /// then low forever.
    out2: Vec<bool>,
    /// Every port touched: the driver must touch only its three.
    ports: Vec<u16>,
    /// Every value written to port 0x61.
    writes_to_gate: Vec<u8>,
}

/// The model, shared between the driver (its ports) and the test.
#[derive(Clone)]
struct Bus(Rc<RefCell<Pit>>);

impl Ports for Bus {
    fn inb(&mut self, port: u16) -> u8 {
        self.0.borrow_mut().inb(port)
    }
    fn outb(&mut self, port: u16, v: u8) {
        self.0.borrow_mut().outb(port, v)
    }
}

impl Pit {
    fn inb(&mut self, port: u16) -> u8 {
        self.ports.push(port);
        assert_eq!(port, PORT_GATE, "the driver reads only port 0x61");
        // The counter runs only while its gate (bit 0) is set.
        let out = self.gate & 1 != 0 && !self.out2.is_empty() && self.out2.remove(0);
        self.gate | if out { 0x20 } else { 0 }
    }
    fn outb(&mut self, port: u16, v: u8) {
        self.ports.push(port);
        match port {
            PORT_MODE => self.mode.push(v),
            PORT_CH2 => self.counter.push(v),
            PORT_GATE => {
                self.writes_to_gate.push(v);
                self.gate = v & !0x20;
            }
            _ => panic!("write to port {port:#x}"),
        }
    }
}

fn bus(out2: Vec<bool>) -> Bus {
    Bus(Rc::new(RefCell::new(Pit { gate: GATE_RESET, out2, ..Pit::default() })))
}

#[test]
fn divisor_is_the_rounded_period() {
    // 1 kHz: 1193.182 counts.
    assert_eq!(divisor(1_000_000), Some(1193));
    // A4, 440 Hz.
    assert_eq!(divisor(1_000_000_000 / 440), Some((PIT_HZ as f64 / 440.0).round() as u16));
    // 20 kHz (the buzzer's ceiling) and 20 Hz both fit.
    assert_eq!(divisor(50_000), Some(60));
    assert!(divisor(50_000_000).is_some());
    // Past the counter: below 18.2 Hz, or above 596 kHz.
    for p in [0, 1, 1_000, 60_000_000, u32::MAX] {
        assert_eq!(divisor(p), None, "{p} ns");
    }
}

/// A tone: channel 2 in mode 3 with the divisor lobyte first, then both
/// gate bits on; off clears exactly those two. The other bits of 0x61 stay.
#[test]
fn a_tone_programs_channel_two_and_gates_it() {
    let b = bus(vec![]);
    let mut s = PcSpeaker::new(b.clone());
    assert!(s.set_period_ns(1_000_000));
    assert!(s.set_duty_pct(DUTY_PCT));
    assert!(s.enable());
    {
        let p = b.0.borrow();
        assert_eq!(p.mode, [0xB6], "channel 2, lo/hi, mode 3, binary");
        assert_eq!(p.counter, [(1193 & 0xFF) as u8, (1193 >> 8) as u8]);
        assert_eq!(p.gate, GATE_RESET | 0b11);
    }
    assert!(s.disable());
    let p = b.0.borrow();
    assert_eq!(p.gate, GATE_RESET, "off: gate and data cleared, the rest kept");
    assert!(p.ports.iter().all(|&p| [PORT_CH2, PORT_MODE, PORT_GATE].contains(&p)));
}

/// Mode 3 is a square wave: only the buzzer's 50% is honoured.
#[test]
fn only_fifty_percent_duty() {
    let mut s = PcSpeaker::new(bus(vec![]));
    assert!(!s.set_duty_pct(25));
    assert!(!s.set_duty_pct(100));
    assert!(!s.set_period_ns(1), "a period no divisor gives");
}

/// The self-check: silent (the speaker bit stays clear), true only once
/// `OUT2` was seen high and low, and the gate is off afterwards.
///
/// **Canary.** Make `counter_runs` return after the first read: the
/// floating-bus case (always high) passes and this test fails.
#[test]
fn the_counter_check_needs_both_levels() {
    let b = bus(vec![true, true, false]);
    let mut s = PcSpeaker::new(b.clone());
    assert!(s.counter_runs(1_000_000, 16));
    assert_eq!(b.0.borrow().gate, GATE_RESET, "gate off after the check");
    let b = bus(vec![true; 64]);
    let mut s = PcSpeaker::new(b.clone());
    assert!(!s.counter_runs(1_000_000, 16), "a level that never changes (a floating bus)");
    // The speaker bit was never set: the check makes no sound.
    assert!(b.0.borrow().writes_to_gate.iter().all(|&v| v & 0b10 == 0));
}

/// The buzzer chip logic over the speaker: a beep is a programmed tone, then
/// silence when its time is up.
#[test]
fn the_buzzer_plays_on_the_speaker() {
    use azos_devif::Buzzer;
    let b = bus(vec![]);
    let mut d = Driver::new(PcSpeaker::new(b.clone()));
    assert!(d.tone(1000, 50).is_ok());
    assert_eq!(b.0.borrow().gate & 0b11, 0b11, "sounding");
    d.elapse(50);
    assert_eq!(b.0.borrow().gate & 0b11, 0, "silent when the step ends");
}
