// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clock discipline: a phase-locked loop and a frequency-locked loop that
//! steer the wall clock (`REAL`, and `TAI` with it) toward a reference.
//!
//! **What it disciplines.** Not the counter: the monotonic clock never
//! moves, so every deadline built on it stays true. The wall clock is the
//! monotonic one plus an offset (`azos_abi::time::ClockOffsets`, published in
//! the vDSO page). The discipline decides how that offset changes, and the
//! kernel (`azos_syscall::clock`) writes the changes it asks for into the page.
//!
//! **What a reference tells it.** A measurement is `offset`: the reference
//! minus our wall clock at the same instant, in nanoseconds (positive: we are
//! behind), and `delay`: the round trip of the exchange that produced it. SNTP
//! gives one per reply (`azos_net::ntp::Exchange`), PTP one per sync/delay
//! pair; both reach this code through the same call.
//!
//! **Slew, don't step.**
//!
//! * The *phase loop* takes the offset of each accepted sample as the amount
//!   still to remove and removes it exponentially (time constant
//!   `PLL_GAIN * tc`), never faster than [`Params::max_slew_ppb`], so the
//!   wall clock only ever runs a little fast or slow. At 500 ppm it cannot go
//!   backwards.
//! * The *frequency loop* estimates the rate error the sample interval shows:
//!   the offset left over once the phase we were still slewing is subtracted,
//!   divided by the interval. A fraction of it joins the standing frequency
//!   correction (`freq_ppb`), clamped to [`Params::max_freq_ppb`]. It is the
//!   FLL of RFC 5905 §A.5.5.6 in effect, kept alone because the phase loop
//!   already smooths the phase: summing the two loops' gains is what makes a
//!   PLL ring when the sample interval nears its time constant.
//! * A **step** happens only (1) for the first sample ever (the boot: the
//!   clock has never been set), or (2) when `step_ns` is exceeded by
//!   [`Params::confirm`] consecutive samples that agree with each other (a
//!   lone wild sample, or one spoofed packet, moves nothing). A step beyond
//!   [`Params::panic_ns`] after the clock was set is **refused**: a clock that
//!   was right does not become wrong by a thousand seconds. Both are reported
//!   to the caller, which records them (`Rule::ClockStep`).
//!
//! **Which samples count.** A sample whose delay exceeds
//! [`Params::max_delay_ns`], or twice the smallest delay of the last
//! [`DELAYS`] samples (plus [`DELAY_SLACK_NS`]), is queued behind a busy link
//! and its offset is off by half the excess: it is [`Verdict::Filtered`].
//!
//! No hardware and no global state in this file: the caller passes the time
//! (nanoseconds on the monotonic clock) and applies what [`Discipline::tick`]
//! returns, so the arithmetic is host-tested (`tests/host/drivers-tests`,
//! `discipline.rs`). Products are checked: 64-bit while they fit (a tick does it
//! from the timer interrupt), 128-bit when they do not; the kernel builds with
//! overflow checks, and a wrapped product here would step the clock.

const NS: i64 = 1_000_000_000;

/// The phase loop's time constant is this many times [`Params::tc_ns`].
pub const PLL_GAIN: u64 = 4;

/// Delays remembered for the queueing filter.
pub const DELAYS: usize = 8;

/// A delay this far above twice the smallest recent one is still accepted
/// (a quiet link's jitter), nanoseconds.
pub const DELAY_SLACK_NS: u64 = 1_000_000;

/// Samples taken while the frequency is still being acquired, at the larger
/// gain ([`FREQ_SHIFT_ACQUIRE`]).
pub const ACQUIRE_SAMPLES: u32 = 8;

/// The frequency loop's gain while acquiring: one in 2^2 of the rate error
/// the interval shows.
pub const FREQ_SHIFT_ACQUIRE: u32 = 2;

/// ... and once locked: one in 2^3. Noise on the offset reaches the frequency
/// scaled by this gain, so it is smaller than the acquisition one.
pub const FREQ_SHIFT_TRACK: u32 = 3;

/// No frequency update from an interval shorter than this: the noise on an
/// offset divided by a short interval is a large rate.
pub const MIN_FREQ_INTERVAL_NS: u64 = 4_000_000_000;

/// Sub-ppb bits kept in the standing frequency correction, so a small update
/// is not lost to truncation.
const FREQ_FRAC_BITS: u32 = 16;

/// The measurement sources a sample may name. A label only: it is reported by
/// `status` and recorded with a step, the arithmetic is the same.
pub mod source {
    /// The kernel's SNTP client.
    pub const NTP: u32 = 1;
    /// The PTP daemon.
    pub const PTP: u32 = 2;
    /// Largest valid source number.
    pub const MAX: u32 = PTP;
}

/// The loop's constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// An offset larger than this cannot be slewed in reasonable time: it is
    /// stepped (after confirmation). Nanoseconds.
    pub step_ns: i64,
    /// After the clock was set, an offset larger than this is refused.
    pub panic_ns: i64,
    /// Largest standing frequency correction, ppb either way.
    pub max_freq_ppb: i64,
    /// Largest rate the phase loop adds to the frequency correction, ppb.
    pub max_slew_ppb: i64,
    /// Time constant of the loops, nanoseconds; the phase is removed with
    /// [`PLL_GAIN`] times it.
    pub tc_ns: u64,
    /// A delay above this is never trusted, nanoseconds.
    pub max_delay_ns: u64,
    /// Consecutive agreeing samples beyond `step_ns` that make a step.
    pub confirm: u8,
}

impl Params {
    /// ntpd's step threshold (128 ms) and panic threshold (1000 s), Linux's
    /// 500 ppm limits on frequency and slew, a 16 s time constant (a phase
    /// removed in about a minute), a 1 s delay ceiling, two samples to confirm.
    pub const DEFAULT: Params = Params {
        step_ns: 128_000_000,
        panic_ns: 1_000_000_000_000,
        max_freq_ppb: 500_000,
        max_slew_ppb: 500_000,
        tc_ns: 16_000_000_000,
        max_delay_ns: 1_000_000_000,
        confirm: 2,
    };
}

/// Whether the clock has ever been set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// No reference has set it: `REAL` reads like `MONO`.
    Unset = 0,
    /// Set by a reference and kept by the loops since.
    Synced = 1,
}

/// What [`Discipline::sample`] did with a measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Taken: the offset will be slewed out and the frequency updated.
    Slewed,
    /// The clock must jump by `delta_ns`; `limit_ns` is the threshold that
    /// was crossed (0 for the boot step, which has none). The caller applies
    /// it and records it.
    Stepped { delta_ns: i64, limit_ns: i64 },
    /// Not used: a delay out of range, or the first of a step to confirm.
    Filtered,
    /// A step beyond `limit_ns`, which the clock refuses to make. The caller
    /// records the refusal.
    Refused { delta_ns: i64, limit_ns: i64 },
}

/// The discipline's state, as `status` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub state: State,
    /// The source of the latest sample taken (a [`source`] number; 0 none).
    pub source: u32,
    /// The standing frequency correction, ppb (positive: the clock was slow).
    pub freq_ppb: i64,
    /// The phase not yet slewed out, nanoseconds.
    pub phase_ns: i64,
    /// Steps made since boot.
    pub steps: u32,
    /// Samples filtered or refused since boot.
    pub rejected: u32,
}

/// The loop.
#[derive(Clone, Copy, Debug)]
pub struct Discipline {
    p: Params,
    state: State,
    /// Standing frequency correction, ppb << FREQ_FRAC_BITS.
    freq_q: i64,
    /// Phase still to slew out, ns (positive: the clock must advance).
    phase_ns: i64,
    /// Remainder of `phase * dt / tau`, in ns^2 (|rem| < tau).
    phase_rem: i64,
    /// Remainder of `freq * dt / 1e9`, in ppb * ns.
    freq_rem: i64,
    /// Monotonic ns of the previous `tick` / the previous taken sample.
    last_tick_ns: u64,
    last_sample_ns: u64,
    delays: [u64; DELAYS],
    delays_n: usize,
    delays_at: usize,
    /// The offset a step is waiting to be confirmed on, and how many samples
    /// agreed with it so far.
    pending_ns: i64,
    pending_n: u8,
    slews: u32,
    source: u32,
    steps: u32,
    rejected: u32,
}

impl Discipline {
    pub const fn new(p: Params) -> Discipline {
        Discipline {
            p,
            state: State::Unset,
            freq_q: 0,
            phase_ns: 0,
            phase_rem: 0,
            freq_rem: 0,
            last_tick_ns: 0,
            last_sample_ns: 0,
            delays: [0; DELAYS],
            delays_n: 0,
            delays_at: 0,
            pending_ns: 0,
            pending_n: 0,
            slews: 0,
            source: 0,
            steps: 0,
            rejected: 0,
        }
    }

    pub fn params(&self) -> &Params {
        &self.p
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// True when [`tick`](Self::tick) has something to apply: the clock is
    /// set and a frequency correction or a phase is standing. A caller that
    /// ticks from an interrupt can skip the lock while this is false.
    pub fn active(&self) -> bool {
        self.state == State::Synced && (self.freq_ppb() != 0 || self.phase_ns != 0 || self.freq_rem != 0)
    }

    pub fn freq_ppb(&self) -> i64 {
        self.freq_q >> FREQ_FRAC_BITS
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.state,
            source: self.source,
            freq_ppb: self.freq_ppb(),
            phase_ns: self.phase_ns,
            steps: self.steps,
            rejected: self.rejected,
        }
    }

    /// Smallest delay among the remembered ones and `delay`.
    fn min_delay(&self, delay: u64) -> u64 {
        self.delays[..self.delays_n].iter().copied().fold(delay, u64::min)
    }

    fn remember_delay(&mut self, delay: u64) {
        self.delays[self.delays_at] = delay;
        self.delays_at = (self.delays_at + 1) % DELAYS;
        if self.delays_n < DELAYS {
            self.delays_n += 1;
        }
    }

    /// Take a measurement at monotonic time `now_ns`: `offset_ns` is the
    /// reference minus our wall clock (positive: we are behind), `delay_ns`
    /// the exchange's round trip. `now_ns` must come after the latest
    /// [`tick`](Self::tick); the caller ticks first, so `phase` is current.
    pub fn sample(&mut self, now_ns: u64, offset_ns: i64, delay_ns: u64, source: u32) -> Verdict {
        let min = self.min_delay(delay_ns);
        // Remembered whether or not it passes: a link whose delay rose for
        // good stops being filtered once the old delays age out.
        self.remember_delay(delay_ns);
        if delay_ns > self.p.max_delay_ns || delay_ns > min.saturating_mul(2).saturating_add(DELAY_SLACK_NS) {
            self.rejected = self.rejected.saturating_add(1);
            return Verdict::Filtered;
        }
        self.source = source;

        if self.state == State::Unset {
            return self.step(now_ns, offset_ns, 0);
        }

        let mag = offset_ns.unsigned_abs();
        if mag > self.p.step_ns as u64 {
            if mag > self.p.panic_ns as u64 {
                self.pending_n = 0;
                self.rejected = self.rejected.saturating_add(1);
                return Verdict::Refused { delta_ns: offset_ns, limit_ns: self.p.panic_ns };
            }
            let agrees = self.pending_n > 0 && offset_ns.abs_diff(self.pending_ns) <= self.p.step_ns as u64;
            if agrees {
                self.pending_n = self.pending_n.saturating_add(1);
            } else {
                self.pending_ns = offset_ns;
                self.pending_n = 1;
            }
            if self.pending_n >= self.p.confirm {
                return self.step(now_ns, offset_ns, self.p.step_ns);
            }
            self.rejected = self.rejected.saturating_add(1);
            return Verdict::Filtered;
        }
        self.pending_n = 0;
        self.slew_in(now_ns, offset_ns);
        Verdict::Slewed
    }

    /// The clock jumps by `delta`: nothing is left to slew, the loops start
    /// over from now (the frequency correction, which the jump says nothing
    /// about, is kept).
    fn step(&mut self, now_ns: u64, delta_ns: i64, limit_ns: i64) -> Verdict {
        self.state = State::Synced;
        self.phase_ns = 0;
        self.phase_rem = 0;
        self.freq_rem = 0;
        self.last_tick_ns = now_ns;
        self.last_sample_ns = now_ns;
        self.pending_n = 0;
        self.slews = 0;
        self.steps = self.steps.saturating_add(1);
        Verdict::Stepped { delta_ns, limit_ns }
    }

    fn slew_in(&mut self, now_ns: u64, offset_ns: i64) {
        let dt = now_ns.saturating_sub(self.last_sample_ns);
        if dt >= MIN_FREQ_INTERVAL_NS {
            // The offset we expected to still see is the phase left to slew;
            // anything beyond it accrued at the rate error we are correcting.
            let extra = offset_ns as i128 - self.phase_ns as i128;
            let rate_ppb = extra * NS as i128 / dt as i128;
            let shift = if self.slews < ACQUIRE_SAMPLES { FREQ_SHIFT_ACQUIRE } else { FREQ_SHIFT_TRACK };
            let max_q = (self.p.max_freq_ppb as i128) << FREQ_FRAC_BITS;
            let q = (self.freq_q as i128 + ((rate_ppb << FREQ_FRAC_BITS) >> shift)).clamp(-max_q, max_q);
            self.freq_q = q as i64;
        }
        self.phase_ns = offset_ns;
        self.phase_rem = 0;
        self.last_sample_ns = now_ns;
        self.slews = self.slews.saturating_add(1);
    }

    /// Advance to monotonic time `now_ns`: the nanoseconds the wall clock must
    /// gain (negative: lose) since the previous call, from the standing
    /// frequency correction and the phase being slewed out. The caller adds
    /// it to the published offsets. 0 while the clock is unset.
    pub fn tick(&mut self, now_ns: u64) -> i64 {
        if self.state != State::Synced {
            return 0;
        }
        let dt = now_ns.saturating_sub(self.last_tick_ns).min(i64::MAX as u64) as i64;
        if dt == 0 {
            return 0;
        }
        self.last_tick_ns = now_ns;

        let (mut total, rem) = muldiv(self.freq_ppb(), dt, self.freq_rem, NS);
        self.freq_rem = rem;

        if self.phase_ns != 0 {
            let tau = PLL_GAIN.saturating_mul(self.p.tc_ns).clamp(1, i64::MAX as u64) as i64;
            let (want, rem) = muldiv(self.phase_ns, dt, self.phase_rem, tau);
            let (cap, _) = muldiv(self.p.max_slew_ppb, dt, 0, NS);
            let cap = cap.min(self.phase_ns.saturating_abs());
            let slew = want.clamp(-cap, cap);
            // The remainder only carries while the cap is not what limits.
            self.phase_rem = if want == slew { rem } else { 0 };
            self.phase_ns -= slew;
            total = total.saturating_add(slew);
        } else {
            self.phase_rem = 0;
        }
        total
    }
}

/// `(a * b + rem) / div` and its remainder, for `div > 0`: in 64 bits while
/// the product fits (every tick of a disciplined clock does this twice, from
/// the timer interrupt), in 128 when it does not. The quotient saturates.
fn muldiv(a: i64, b: i64, rem: i64, div: i64) -> (i64, i64) {
    if let Some(p) = a.checked_mul(b).and_then(|p| p.checked_add(rem)) {
        return (p / div, p % div);
    }
    let p = a as i128 * b as i128 + rem as i128;
    ((p / div as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64, (p % div as i128) as i64)
}
