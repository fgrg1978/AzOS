// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PC speaker: every PC's buzzer, as the buzzer chip logic's [`Pwm`]
//! channel (`crates/drivers/buzzer`).
//!
//! The tone is the 8254 PIT's channel 2 in mode 3 (a square wave, 50% duty,
//! at 1.193182 MHz / divisor), and port 0x61 gates it: bit 0 (`GATE2`) runs
//! the counter, bit 1 (`SPKR`) connects its output to the speaker. Bit 5
//! reads the counter's output (`OUT2`), which is how [`PcSpeaker::counter_runs`]
//! proves the channel ticks without a sound (gate on, speaker off). Linux's
//! `pcspkr` driver and its `pit_*` helpers drive the same three ports.
//!
//! Pure over [`Ports`] (the two port accessors), so a host test drives it
//! against a scripted 8254; the ring-3 host (`userspace/drivers/buzz_drv`)
//! hands it the ports its topology row grants (`ioport.66.2`, PIT channel 2
//! and the mode register; `ioport.97.1`, port 0x61).
//!
//! Port 0x61 also holds the NMI enables for parity and channel errors (bits
//! 2 and 3) and the refresh toggle (bit 4): every write here keeps the bits
//! it read except the two it means to change. The mode register (0x43) is
//! shared with channels 0 and 1: every mode word written here names channel 2.

#![no_std]

use azos_buzzer::{Pwm, DUTY_PCT};

/// The two port accessors the chip logic needs.
pub trait Ports {
    fn inb(&mut self, port: u16) -> u8;
    fn outb(&mut self, port: u16, v: u8);
}

/// PIT channel 2's counter (lobyte, then hibyte).
pub const PORT_CH2: u16 = 0x42;
/// The PIT's mode register.
pub const PORT_MODE: u16 = 0x43;
/// The PC's system control port B: the speaker gate and data bits.
pub const PORT_GATE: u16 = 0x61;
/// The first port and the count of each range the driver needs.
pub const RANGE_PIT: (u16, u16) = (PORT_CH2, 2);
pub const RANGE_GATE: (u16, u16) = (PORT_GATE, 1);

/// The PIT's input clock, Hz (14.31818 MHz / 12).
pub const PIT_HZ: u64 = 1_193_182;

/// Mode word: channel 2, lobyte then hibyte, mode 3 (square wave), binary.
const MODE_CH2_SQUARE: u8 = 0b10_11_011_0;
/// Port 0x61 bits.
const GATE2: u8 = 1 << 0;
const SPKR: u8 = 1 << 1;
const OUT2: u8 = 1 << 5;

/// The divisor for a period of `period_ns`, rounded to the nearest; `None`
/// when no divisor gives it (mode 3 counts 2..=65536, written 0 for 65536:
/// this driver keeps to 2..=65535, 18.2 Hz to 596 kHz).
pub fn divisor(period_ns: u32) -> Option<u16> {
    let d = (period_ns as u64 * PIT_HZ + 500_000_000) / 1_000_000_000;
    (2..=u16::MAX as u64).contains(&d).then_some(d as u16)
}

/// The speaker over `P`.
pub struct PcSpeaker<P: Ports> {
    ports: P,
}

impl<P: Ports> PcSpeaker<P> {
    pub const fn new(ports: P) -> Self {
        PcSpeaker { ports }
    }

    fn program(&mut self, d: u16) {
        self.ports.outb(PORT_MODE, MODE_CH2_SQUARE);
        self.ports.outb(PORT_CH2, d as u8);
        self.ports.outb(PORT_CH2, (d >> 8) as u8);
    }

    /// Port 0x61 with `set` bits set and `clear` bits cleared, the rest as read.
    fn gate(&mut self, set: u8, clear: u8) {
        let v = self.ports.inb(PORT_GATE);
        self.ports.outb(PORT_GATE, (v & !clear) | set);
    }

    /// Does channel 2 tick? Programs `period_ns` with the counter gated on
    /// and the speaker off (no sound), and reads `OUT2` up to `reads` times:
    /// true once it was seen at both levels. Leaves the gate off. A machine
    /// with no PIT channel 2 behind port 0x61 (a floating bus reads 0xFF, a
    /// level that never changes) answers false.
    pub fn counter_runs(&mut self, period_ns: u32, reads: u32) -> bool {
        let Some(d) = divisor(period_ns) else { return false };
        self.gate(0, GATE2 | SPKR);
        self.program(d);
        self.gate(GATE2, SPKR);
        let (mut high, mut low) = (false, false);
        for _ in 0..reads {
            if self.ports.inb(PORT_GATE) & OUT2 != 0 {
                high = true;
            } else {
                low = true;
            }
            if high && low {
                break;
            }
        }
        self.gate(0, GATE2 | SPKR);
        high && low
    }
}

impl<P: Ports> Pwm for PcSpeaker<P> {
    fn set_period_ns(&mut self, period_ns: u32) -> bool {
        match divisor(period_ns) {
            Some(d) => {
                self.program(d);
                true
            }
            None => false,
        }
    }
    /// Mode 3 is a square wave: the buzzer's 50% is the only duty it has.
    fn set_duty_pct(&mut self, pct: u32) -> bool {
        pct == DUTY_PCT
    }
    fn enable(&mut self) -> bool {
        self.gate(GATE2 | SPKR, 0);
        true
    }
    fn disable(&mut self) -> bool {
        self.gate(0, GATE2 | SPKR);
        true
    }
}
