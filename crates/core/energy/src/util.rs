// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `UtilTracker` (RFC-0051 §4.1): how busy a task or a CPU has been lately.
//!
//! A signal is a [`UtilState`] per tracked entity; the tracker is the rule
//! that ages it. Time is the timebase's raw ticks (`timebase::now()`), never
//! microseconds: the window and the period are converted to ticks once, when
//! the tracker is built, so an update divides at most once per window or
//! period boundary it crosses, never on the fast path inside one.
//!
//! The result is on [`SCALE`]: 1024 is "running all the time", 0 "never".
//!
//! # The two variants
//!
//! * **Window** (default, owner question 2 of RFC-0051 §9): busy time is
//!   counted per fixed window; the last [`HISTORY`] closed windows are kept
//!   and the signal is `max(most recent, mean)`, the WALT demand policy. A
//!   step to fully busy shows after one window; a task that stops reads zero
//!   [`HISTORY`] windows later. Nothing decays continuously, so every bound
//!   is exact.
//! * **PELT-like**: per period, `avg = avg·y + input·(1 − y)` with
//!   `y^32 = 1/2` (a half-life of 32 periods), in Q32 fixed point. A gap of
//!   `n` whole periods at constant input is one closed-form step,
//!   `avg·yⁿ + input·(1 − yⁿ)`, with `yⁿ` from a 32-entry table and a shift
//!   per 32 periods. Sub-period time is collected and enters as the input of
//!   the period it belongs to.
//!
//! # Bounds
//!
//! Every update is O(1) whatever the gap since the last one: the window
//! variant pushes at most [`HISTORY`] windows, the PELT one does one table
//! lookup. A clock that reads earlier than the last update (a reading taken on
//! another hart a moment before) changes nothing. Nothing can overflow: busy
//! time is at most one window or period, multiplied by at most `SCALE << 10`.

/// Utilisation scale: one CPU running all the time.
pub const SCALE: u32 = 1024;

/// Closed windows the window variant keeps.
pub const HISTORY: usize = 4;

/// PELT half-life, in periods (`y^HALF_LIFE = 1/2`).
pub const HALF_LIFE: u64 = 32;

/// Extra fraction bits the PELT average carries below [`SCALE`].
const PELT_FRAC: u32 = 10;
/// [`SCALE`] in the PELT average's fixed point.
const PELT_FULL: u64 = (SCALE as u64) << PELT_FRAC;
/// `2^32`: one, in the Q32 of [`Y_INV`].
const Q32_ONE: u64 = 1 << 32;

/// `round(y^n · 2^32)` for `n` in `0..32`, `y = 2^(-1/32)`. Entry 0 is never
/// used (zero periods is no step at all); it is `2^32 - 1` only so that the
/// table fits `u32`. The host suite checks every entry against `f64`.
pub const Y_INV: [u32; 32] = [
    4294967295, 4202935003, 4112874773, 4024744348, 3938502376, 3854108391, 3771522796, 3690706840,
    3611622603, 3534232978, 3458501653, 3384393094, 3311872529, 3240905930, 3171459999, 3103502151,
    3037000500, 2971923842, 2908241642, 2845924021, 2784941738, 2725266179, 2666869345, 2609723834,
    2553802834, 2499080105, 2445529972, 2393127307, 2341847524, 2291666561, 2242560872, 2194507417,
];

/// `y^n` in Q32 for any `n >= 1`: the table for `n mod 32`, halved once per
/// 32 periods. Zero past 32·32 periods, where it is below one part in 2^32.
#[inline]
pub fn y_pow(n: u64) -> u64 {
    if n == 0 {
        return Q32_ONE;
    }
    let halvings = n / HALF_LIFE;
    if halvings >= 32 {
        return 0;
    }
    let base = if n % HALF_LIFE == 0 { Q32_ONE } else { Y_INV[(n % HALF_LIFE) as usize] as u64 };
    base >> halvings
}

/// Which rule ages the signals, with its time constant in ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UtilTracker {
    /// Busy time per window of this many ticks; `max(recent, mean)` of the
    /// last [`HISTORY`] closed windows.
    Window {
        /// Window length, ticks. At least 1.
        window: u64,
    },
    /// Geometric decay, one step per period of this many ticks, half-life
    /// [`HALF_LIFE`] periods.
    Pelt {
        /// Period length, ticks. At least 1.
        period: u64,
    },
}

/// One entity's signal. Both variants use the same fields: `hist` is the
/// window variant's history, `avg` the PELT average; the other is unused.
///
/// The all-zero value ([`UtilState::ZERO`]) is a valid signal: idle since
/// tick 0. A slot nobody updated yet therefore reads 0 and needs no
/// initialisation pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtilState {
    /// Tick of the last update.
    last: u64,
    /// Start of the window/period `last` falls in.
    start: u64,
    /// Busy ticks of that window/period up to `last`.
    busy: u64,
    /// Window variant: closed windows on `SCALE`, newest first.
    hist: [u16; HISTORY],
    /// PELT variant: the average, `SCALE << PELT_FRAC` = always running.
    avg: u32,
    /// Whether the entity has been running since `last`.
    running: bool,
}

impl UtilState {
    /// Idle since tick 0.
    pub const ZERO: Self =
        Self { last: 0, start: 0, busy: 0, hist: [0; HISTORY], avg: 0, running: false };

    /// Whether the entity is accounted as running since the last update.
    #[inline]
    pub fn running(&self) -> bool {
        self.running
    }

    /// Tick of the last update.
    #[inline]
    pub fn last(&self) -> u64 {
        self.last
    }
}

impl UtilTracker {
    /// The window variant, `window` ticks long (0 is taken as 1).
    pub const fn window(window: u64) -> Self {
        Self::Window { window: if window == 0 { 1 } else { window } }
    }

    /// The PELT-like variant, `period` ticks per step (0 is taken as 1).
    pub const fn pelt(period: u64) -> Self {
        Self::Pelt { period: if period == 0 { 1 } else { period } }
    }

    /// Ticks per window or period.
    #[inline]
    pub const fn step(&self) -> u64 {
        match *self {
            Self::Window { window } => window,
            Self::Pelt { period } => period,
        }
    }

    /// A signal that starts at `now`, idle, aligned to the step grid so that
    /// every entity's windows close at the same instants.
    pub fn new_state(&self, now: u64) -> UtilState {
        let start = now - now % self.step();
        UtilState { last: now, start, ..UtilState::ZERO }
    }

    /// Account the time since the last update in the state the entity was
    /// in, then record that it is `running` from `now` on. The enqueue,
    /// dispatch and switch-out points call this.
    #[inline]
    pub fn set_running(&self, st: &mut UtilState, now: u64, running: bool) {
        self.update(st, now);
        st.running = running;
    }

    /// Account the time since the last update in the state the entity was
    /// in. The tick calls this for what is running.
    pub fn update(&self, st: &mut UtilState, now: u64) {
        if now <= st.last {
            return;
        }
        let step = self.step();
        let end = st.start.saturating_add(step);
        if now < end {
            if st.running {
                st.busy += now - st.last;
            }
            st.last = now;
            return;
        }
        // Close the window/period `last` is in.
        if st.running {
            st.busy += end - st.last;
        }
        let closed = st.busy.min(step);
        // Whole steps between its end and `now`, at the current state.
        let full = (now - end) / step;
        match *self {
            Self::Window { window } => {
                push(&mut st.hist, (closed * SCALE as u64 / window) as u16);
                let fill = if st.running { SCALE as u16 } else { 0 };
                for _ in 0..full.min(HISTORY as u64) {
                    push(&mut st.hist, fill);
                }
            }
            Self::Pelt { period } => {
                let input = closed * PELT_FULL / period;
                let mut avg = mix(st.avg as u64, input, Y_INV[1] as u64);
                if full > 0 {
                    let fill = if st.running { PELT_FULL } else { 0 };
                    avg = mix(avg, fill, y_pow(full));
                }
                st.avg = avg.min(PELT_FULL) as u32;
            }
        }
        st.start = end + full * step;
        st.busy = if st.running { now - st.start } else { 0 };
        st.last = now;
    }

    /// The signal as of its last update, on [`SCALE`].
    pub fn util(&self, st: &UtilState) -> u32 {
        match *self {
            Self::Window { .. } => {
                let recent = st.hist[0] as u32;
                let mean = st.hist.iter().map(|&h| h as u32).sum::<u32>() / HISTORY as u32;
                recent.max(mean).min(SCALE)
            }
            Self::Pelt { .. } => {
                (((st.avg as u64 + (1 << (PELT_FRAC - 1))) >> PELT_FRAC) as u32).min(SCALE)
            }
        }
    }

    /// The signal as it would read after an update at `now`, without
    /// changing it: what a reader on another CPU (placement at wake-up)
    /// sees for an entity whose own CPU has not updated it lately.
    pub fn util_at(&self, st: &UtilState, now: u64) -> u32 {
        let mut copy = *st;
        self.update(&mut copy, now);
        self.util(&copy)
    }
}

/// Newest first; the oldest falls off.
#[inline]
fn push(hist: &mut [u16; HISTORY], v: u16) {
    let mut i = HISTORY - 1;
    while i > 0 {
        hist[i] = hist[i - 1];
        i -= 1;
    }
    hist[0] = v;
}

/// `avg·y + input·(1 − y)`, `y` in Q32, rounded to nearest. Both operands are
/// at most `SCALE << PELT_FRAC` (2^20), so each product fits in 52 bits.
#[inline]
fn mix(avg: u64, input: u64, y: u64) -> u64 {
    (avg * y + input * (Q32_ONE - y) + (1 << 31)) >> 32
}
