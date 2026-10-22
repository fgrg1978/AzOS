// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Piezo buzzer, one source for both placements (wave 12
//! DRVPLACE).
//!
//! [`Player`] is the chip logic over a [`Pwm`] channel: a tone, a beep or a
//! pattern is a list of [`Step`]s played against the host's clock, and every
//! request is answered once its first step has started, never after the
//! sound. [`Driver`] is the `Buzzer` interface (`azos_devif::buzzer`) over a
//! player and a channel. A host supplies the channel, the clock and the
//! loop: ring 3 (`userspace/drivers/buzz_drv`, which serves the interface on
//! its endpoint, the channel through the `pwm` endpoint) or the kernel
//! (`crates/drivers/actuator`, a direct call; the channel through the
//! kernel's PWM driver). The topology row's placement (`place = ...`, and
//! Kconfig `DRV_BUZZER_PLACEMENT` for the built-in one) picks the host, and a
//! `stateless` row can move between them while the system runs.
//!
//! No syscalls, no statics: the same bytes are compiled into both hosts, and
//! each carries [`SOURCE_MARKER`] to prove it (`tools/chip_source_check.py`).

#![no_std]
#![forbid(unsafe_code)]

use azos_devif::{outcome, Buzzer, Out};

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

/// The buzzer as an implementation of the `Buzzer` interface: a [`Player`]
/// over a [`Pwm`] channel. Both hosts serve the interface with this one value
/// (the kernel's direct-call placement holds it behind its lock, the ring-3
/// program's endpoint loop dispatches into it), so a request does the same on
/// either. `Out::ok` when the controller accepted every write of the first
/// step, `FAULT` when it refused one.
pub struct Driver<P: Pwm> {
    pub player: Player,
    pub pwm: P,
}

impl<P: Pwm> Driver<P> {
    /// Silent, as a host leaves the channel before it serves.
    pub fn new(mut pwm: P) -> Self {
        let mut player = Player::new();
        player.stop(&mut pwm);
        Driver { player, pwm }
    }

    fn done(ok: bool) -> Out<()> {
        if ok { Out::ok(()) } else { Out::err(outcome::FAULT) }
    }

    fn start(&mut self, steps: &[Step]) -> Out<()> {
        Self::done(self.player.play(&mut self.pwm, steps))
    }

    /// Stop the sound: the channel off and nothing left to play.
    fn silence(&mut self) -> Out<()> {
        Self::done(self.player.stop(&mut self.pwm))
    }

    /// `ms` have passed: play the steps they cover.
    pub fn elapse(&mut self, ms: u32) {
        self.player.elapse(&mut self.pwm, ms);
    }
}

impl<P: Pwm> Buzzer for Driver<P> {
    fn tone(&mut self, freq_hz: u32, ms: u32) -> Out<()> {
        let freq = freq_hz.min(MAX_FREQ_HZ as u32) as u16;
        let ms = ms.min(MAX_TONE_MS);
        if freq == 0 || ms == 0 { self.silence() } else { self.start(&[Step { freq, ms }]) }
    }
    fn on(&mut self, freq_hz: u32) -> Out<()> {
        let freq = freq_hz.min(MAX_FREQ_HZ as u32) as u16;
        if freq == 0 { self.silence() } else { self.start(&[Step { freq, ms: FOREVER }]) }
    }
    fn off(&mut self) -> Out<()> {
        self.silence()
    }
    fn beep(&mut self) -> Out<()> {
        self.start(&[Step { freq: TONE_OK, ms: 100 }])
    }
    fn alert(&mut self) -> Out<()> {
        self.start(&[
            Step { freq: TONE_ALERT, ms: 80 }, Step { freq: 0, ms: 60 },
            Step { freq: TONE_ALERT, ms: 80 }, Step { freq: 0, ms: 60 },
            Step { freq: TONE_ALERT, ms: 80 },
        ])
    }
    fn startup(&mut self) -> Out<()> {
        self.start(&[
            Step { freq: TONE_C4, ms: 120 }, Step { freq: 0, ms: 40 },
            Step { freq: TONE_E4, ms: 120 }, Step { freq: 0, ms: 40 },
            Step { freq: TONE_G4, ms: 120 }, Step { freq: 0, ms: 40 },
            Step { freq: TONE_C5, ms: 120 },
        ])
    }
}
