// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Piezo buzzer, one source for both placements (RFC-0052 section 6.1,
//! wave 12 DRVPLACE).
//!
//! [`Player`] is the chip logic over a [`Pwm`] channel: a tone, a beep or a
//! pattern is a list of [`Step`]s played against the host's clock, and every
//! request is answered once its first step has started, never after the
//! sound. [`serve`] answers one `buzzer_op` request. A host supplies the
//! channel, the clock and the loop: ring 3 (`userspace/drivers/buzz_drv`, a
//! `DriverRequest` per request through the kernel's proxy, the channel
//! through `Cap<Pwm>`) or the kernel (`crates/drivers/actuator`, feature
//! `buzzer-kernel`, a direct call; the channel through the kernel's PWM
//! driver). Kconfig `DRV_BUZZER_PLACEMENT` picks the host per board.
//!
//! No syscalls, no statics: the same bytes are compiled into both hosts, and
//! each carries [`SOURCE_MARKER`] to prove it (`tools/chip_source_check.py`).

#![no_std]

use azos_abi::drv_kind::buzzer_op;

include!(concat!(env!("OUT_DIR"), "/chip_source.rs"));

/// The PWM channel the buzzer is wired to (the topology grants `pwm.5` to
/// the ring-3 host).
pub const BUZZER_PWM_CHANNEL: u32 = 5;
/// Duty cycle of every tone.
pub const DUTY_PCT: u32 = 50;
/// Longest tone accepted, as `SYS_BUZZER_TONE` clamps.
pub const MAX_TONE_MS: u32 = 10_000;
/// Highest frequency accepted, as `SYS_BUZZER_TONE` clamps.
pub const MAX_FREQ_HZ: u16 = 20_000;

/// Acknowledgment tone, Hz.
pub const TONE_OK: u16 = 1000;
/// Alert tone, Hz.
pub const TONE_ALERT: u16 = 2000;
/// C4, E4, G4, C5, Hz (the start-up arpeggio).
pub const TONE_C4: u16 = 262;
pub const TONE_E4: u16 = 330;
pub const TONE_G4: u16 = 392;
pub const TONE_C5: u16 = 523;

/// The one PWM channel the chip logic drives. `true` when the controller
/// accepted the write.
pub trait Pwm {
    fn set_period_ns(&mut self, period_ns: u32) -> bool;
    fn set_duty_pct(&mut self, pct: u32) -> bool;
    fn enable(&mut self) -> bool;
    fn disable(&mut self) -> bool;
}

/// One step of a sound: a frequency (0 = silence) held for `ms`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Step {
    pub freq: u16,
    pub ms: u32,
}

/// Steps one sound may have.
pub const MAX_STEPS: usize = 8;
/// A step held until it is replaced.
pub const FOREVER: u32 = u32::MAX;

/// What is playing: the steps, the current one and what is left of it.
#[derive(Clone, Copy)]
pub struct Player {
    steps: [Step; MAX_STEPS],
    len: usize,
    idx: usize,
    remaining_ms: u32,
}

impl Player {
    /// Nothing playing.
    pub const fn new() -> Self {
        Player { steps: [Step { freq: 0, ms: 0 }; MAX_STEPS], len: 0, idx: 0, remaining_ms: 0 }
    }

    /// Is nothing playing?
    pub fn silent(&self) -> bool {
        self.idx >= self.len
    }

    /// Replace whatever is playing with `steps` and start the first one.
    /// `true` when the controller accepted every write of that first step.
    pub fn play(&mut self, pwm: &mut impl Pwm, steps: &[Step]) -> bool {
        let n = steps.len().min(MAX_STEPS);
        self.steps[..n].copy_from_slice(&steps[..n]);
        self.len = n;
        self.idx = 0;
        self.start_step(pwm)
    }

    /// Stop whatever is playing and silence the channel.
    pub fn stop(&mut self, pwm: &mut impl Pwm) -> bool {
        self.len = 0;
        self.idx = 0;
        pwm.disable()
    }

    fn start_step(&mut self, pwm: &mut impl Pwm) -> bool {
        if self.silent() {
            return self.stop(pwm);
        }
        let s = self.steps[self.idx];
        self.remaining_ms = s.ms;
        if s.freq == 0 {
            return pwm.disable();
        }
        let period_ns = 1_000_000_000u32 / s.freq as u32;
        pwm.set_period_ns(period_ns) && pwm.set_duty_pct(DUTY_PCT) && pwm.enable()
    }

    /// `ms` have passed: advance through every step they cover (a wake-up
    /// late by more than one step skips it rather than delaying the rest).
    pub fn elapse(&mut self, pwm: &mut impl Pwm, mut ms: u32) {
        loop {
            if self.silent() || self.remaining_ms == FOREVER {
                return;
            }
            if ms < self.remaining_ms {
                self.remaining_ms -= ms;
                return;
            }
            ms -= self.remaining_ms;
            self.idx += 1;
            self.start_step(pwm);
        }
    }

    /// How long the host may wait before the next [`Player::elapse`]: until
    /// the current step is due, or 0 (wait for a request) when nothing is
    /// timed.
    pub fn park_ms(&self) -> u32 {
        if self.silent() || self.remaining_ms == FOREVER {
            0
        } else {
            self.remaining_ms.max(1)
        }
    }
}

impl Default for Player {
    fn default() -> Self {
        Self::new()
    }
}

fn arg_u16(input: &[u8], at: usize) -> u16 {
    match input.get(at..at + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}

fn arg_u32(input: &[u8], at: usize) -> u32 {
    match input.get(at..at + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

/// Answer `buzzer_op` request `op` (`input` = its argument bytes): replace
/// what `p` plays and start it on `pwm`. `Some(true)` when the controller
/// accepted the writes, `Some(false)` when it refused one, `None` for an op
/// this driver does not know (nothing changes).
pub fn serve(p: &mut Player, pwm: &mut impl Pwm, op: u32, input: &[u8]) -> Option<bool> {
    Some(match op {
        buzzer_op::TONE => {
            let freq = arg_u16(input, 0).min(MAX_FREQ_HZ);
            let ms = arg_u32(input, 2).min(MAX_TONE_MS);
            if freq == 0 || ms == 0 { p.stop(pwm) } else { p.play(pwm, &[Step { freq, ms }]) }
        }
        buzzer_op::ON => {
            let freq = arg_u16(input, 0).min(MAX_FREQ_HZ);
            if freq == 0 { p.stop(pwm) } else { p.play(pwm, &[Step { freq, ms: FOREVER }]) }
        }
        buzzer_op::OFF => p.stop(pwm),
        buzzer_op::BEEP => p.play(pwm, &[Step { freq: TONE_OK, ms: 100 }]),
        buzzer_op::ALERT => p.play(pwm, &[
            Step { freq: TONE_ALERT, ms: 80 }, Step { freq: 0, ms: 60 },
            Step { freq: TONE_ALERT, ms: 80 }, Step { freq: 0, ms: 60 },
            Step { freq: TONE_ALERT, ms: 80 },
        ]),
        buzzer_op::STARTUP => p.play(pwm, &[
            Step { freq: TONE_C4, ms: 120 }, Step { freq: 0, ms: 40 },
            Step { freq: TONE_E4, ms: 120 }, Step { freq: 0, ms: 40 },
            Step { freq: TONE_G4, ms: 120 }, Step { freq: 0, ms: 40 },
            Step { freq: TONE_C5, ms: 120 },
        ]),
        _ => return None,
    })
}
