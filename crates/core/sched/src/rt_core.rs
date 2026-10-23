// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The arithmetic of the real-time band budget and of EDF + CBS, with no
//! scheduler state in it (wave 11 SCHED-RT).
//!
//! `scheduler.rs` cannot be compiled for the host (static task pool, CSRs,
//! assembly context switch), so everything that decides *when* a budget runs
//! out, *what* a release does to a reservation and *whether* a reservation
//! fits a hart lives here, and `tests/host/sched-policy-tests` pulls this file
//! in with `#[path]`. The kernel side (`rt.rs`) only stores these values per
//! hart / per task and calls them at the dispatch, tick and switch points.
//!
//! Units are the monotonic counter's ticks (`timebase::now()`), never
//! scheduler ticks: the old EDF path converted microseconds with the timer
//! frequency and then compared against a counter that moved once per
//! scheduler tick. Every sum saturates: an overflow here would
//! be a panic inside the timer interrupt under `overflow-checks`.

/// One CPU is this many parts per million (the scale the cross-level rule
/// and the topology's boot check share).
pub use azos_abi::rt_levels::PPM;

// ───────────────────────────── band budget ─────────────────────────────────

/// Per-hart RT-band server (the role Linux 6.12's `fair_server` plays, seen
/// from the other side): in each window of `window` ticks the band (priorities
/// below `RT_PRIORITY_THRESHOLD`) may run at most `cap` ticks while a non-band
/// task is ready on the hart. Work-conserving: with nothing else ready the
/// band keeps the hart, and the overshoot is simply charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Band {
    /// Start of the current window.
    pub win_start: u64,
    /// Band run time charged in the current window.
    pub used: u64,
    /// Dispatch stamp of the band task running now; 0 = no band task runs.
    pub since: u64,
    /// `used` reached the cap in this window: while a non-band task is ready,
    /// the band is not eligible until the window ends.
    pub exhausted: bool,
}

impl Band {
    /// A hart whose band has not run yet. The first charge opens a window.
    pub const NEW: Self = Self { win_start: 0, used: 0, since: 0, exhausted: false };

    /// Start a new window at `now` if the current one has ended. Returns
    /// whether it did.
    #[inline]
    pub fn roll(&mut self, now: u64, window: u64) -> bool {
        if now.saturating_sub(self.win_start) >= window {
            self.win_start = now;
            self.used = 0;
            self.exhausted = false;
            true
        } else {
            false
        }
    }

    /// Charge the running band task up to `now` (and keep it running).
    #[inline]
    pub fn charge(&mut self, now: u64, window: u64, cap: u64) {
        if self.since != 0 {
            let ran = now.saturating_sub(self.since);
            // A window that ended while the task ran starts afresh: the time
            // is charged to the window it is observed in, never to one that
            // is already over (that would throttle the band for a window in
            // which it did not run).
            self.roll(now, window);
            self.used = self.used.saturating_add(ran);
            self.since = now.max(1);
        } else {
            self.roll(now, window);
        }
        if self.used >= cap {
            self.exhausted = true;
        }
    }

    /// A band task starts running at `now`.
    #[inline]
    pub fn start(&mut self, now: u64) {
        self.since = now.max(1);
    }

    /// The running band task stops at `now`: charge it.
    #[inline]
    pub fn stop(&mut self, now: u64, window: u64, cap: u64) {
        self.charge(now, window, cap);
        self.since = 0;
    }

    /// The instant the running band would reach the cap, if it keeps running.
    #[inline]
    pub fn exhaust_at(&self, now: u64, cap: u64) -> u64 {
        now.saturating_add(cap.saturating_sub(self.used))
    }

    /// The instant the current window ends.
    #[inline]
    pub fn window_end(&self, window: u64) -> u64 {
        self.win_start.saturating_add(window)
    }
}

/// Is a ready task of priority `prio` skipped by the pick while the band is
/// throttled (`skip_band`)? Band tasks are, except the kernel safety loops
/// exempt from the cap (owner decision, wave 11): those are never throttled.
#[inline]
pub const fn band_throttled(prio: u32, threshold: u32, exempt: bool, skip_band: bool) -> bool {
    skip_band && prio < threshold && !exempt
}

/// Is a running task of priority `prio` charged to the band budget? Band
/// tasks are; an exempt safety loop is not (it is outside the cap).
#[inline]
pub const fn band_charged(prio: u32, threshold: u32, exempt: bool) -> bool {
    prio < threshold && !exempt
}

/// `window × pct / 100`, the band's run time per window. `pct >= 100` is "no
/// cap": the budget can never be exhausted.
#[inline]
pub const fn band_cap_ticks(window: u64, pct: u32) -> u64 {
    if pct >= 100 {
        u64::MAX
    } else {
        ((window as u128) * (pct as u128) / 100) as u64
    }
}

// ───────────────────────────── EDF + CBS ───────────────────────────────────

/// One constant-bandwidth-server reservation, carried by its task.
///
/// `q == 0` is "no reservation": the task is ordered FIFO in its priority
/// level as before. Otherwise the task is ordered by `deadline` among the
/// reservation tasks of its level, ahead of the level's FIFO tasks, and its
/// run time is charged against `budget`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cbs {
    /// Runtime per period (ticks).
    pub q: u64,
    /// Period (ticks).
    pub t: u64,
    /// Relative deadline (ticks), `<= t`.
    pub d: u64,
    /// Hard CBS: on exhaustion the task is throttled until its deadline
    /// (Linux `SCHED_DEADLINE`). Soft CBS: the deadline is postponed by one
    /// period and the budget refilled, and the task keeps competing.
    pub hard: bool,
    /// Budget left in the current server period.
    pub budget: u64,
    /// Absolute deadline of the current server period.
    pub deadline: u64,
    /// Hard CBS ran out: not eligible until `deadline`.
    pub throttled: bool,
    /// The task blocked since it last ran: the CBS release rule is applied
    /// at its next pick, with the clock of that pick.
    pub release_due: bool,
    /// Times the budget ran out while the task was running.
    pub overruns: u32,
    /// The hart the reservation was admitted on.
    pub cpu: u8,
    /// Density booked in the hart's ledger, parts per million.
    pub density_ppm: u32,
    /// Booked against the hart's band cap too.
    pub band: bool,
    /// The priority level (ready-queue bucket) admission booked it at: the
    /// cross-level check ([`levels_check`]) reads it.
    pub level: u32,
}

impl Cbs {
    /// No reservation.
    pub const NONE: Self = Self {
        q: 0, t: 0, d: 0, hard: false, budget: 0, deadline: 0,
        throttled: false, release_due: false, overruns: 0, cpu: 0, density_ppm: 0,
        band: false, level: 0,
    };

    /// A reservation that has not been released yet (its first pick releases it).
    pub const fn new(q: u64, t: u64, d: u64, hard: bool, cpu: u8, density_ppm: u32) -> Self {
        Self {
            q, t, d, hard, budget: 0, deadline: 0,
            throttled: false, release_due: true, overruns: 0, cpu, density_ppm,
            band: false, level: 0,
        }
    }

    /// Whether the task holds a reservation.
    #[inline]
    pub const fn active(&self) -> bool {
        self.q != 0
    }

    /// The CBS release rule (Abeni & Buttazzo), applied when the task becomes
    /// runnable again at `now`: keep the current `(budget, deadline)` only if
    /// the deadline is still ahead and the budget left fits the reserved
    /// density up to it (`budget / (deadline - now) <= q / d`); otherwise
    /// start a new server period: `deadline = now + d`, full budget. Returns
    /// whether a new period was started.
    ///
    /// The rate is the density `q / d` that admission books, not the
    /// bandwidth `q / t`: a new period's deadline is `now + d`, so with
    /// `q / t` a server whose `d < t` that sleeps briefly with budget left
    /// took a full budget and a deadline `d` away at every wake, and ran
    /// above its density at the head of the hart's EDF order (wave 15: a
    /// 50 % server that computes 400 us and sleeps 20 us made a 40 %
    /// neighbour miss every job). With `q / d` the work it gets between a
    /// release and the deadline it holds never exceeds its density times
    /// that span, the bound the density admission relies on. Linux's
    /// `dl_entity_overflow` compares against `dl_deadline` likewise.
    #[inline]
    pub fn release(&mut self, now: u64) -> bool {
        self.release_at_rate(now, self.d)
    }

    /// [`Cbs::release`] with the rate `q / span`: `span = d` is the rule;
    /// `span = t` is the old bandwidth test, kept for the kernel's
    /// `rt-wake-rate-canary` and the host test that shows what it lets
    /// through.
    #[inline]
    pub fn release_at_rate(&mut self, now: u64, span: u64) -> bool {
        self.release_due = false;
        if self.throttled {
            // Still owes the rest of its period: replenishment decides.
            return false;
        }
        let fresh = self.deadline <= now
            || (self.budget as u128) * (span as u128)
                > ((self.deadline - now) as u128) * (self.q as u128);
        if fresh {
            self.deadline = now.saturating_add(self.d);
            self.budget = self.q;
        }
        fresh
    }

    /// Charge `ran` ticks of run time. Returns whether the budget is now 0.
    #[inline]
    pub fn charge(&mut self, ran: u64) -> bool {
        self.budget = self.budget.saturating_sub(ran);
        self.budget == 0
    }

    /// The budget ran out while the task was running at `now`: count the
    /// overrun, then throttle (hard) or postpone (soft).
    #[inline]
    pub fn exhaust(&mut self, now: u64) {
        self.overruns = self.overruns.saturating_add(1);
        if self.hard {
            self.throttled = true;
            // A deadline already in the past (charged late) replenishes at
            // the next pick rather than never.
            if self.deadline < now {
                self.deadline = now;
            }
        } else {
            self.deadline = self.deadline.saturating_add(self.t);
            self.budget = self.q;
        }
    }

    /// A throttled reservation whose deadline has come: refill the budget and
    /// move to the next server period (`deadline += t`, or `now + d` if that is
    /// already past). Returns whether it was replenished.
    #[inline]
    pub fn replenish_if_due(&mut self, now: u64) -> bool {
        if !self.throttled || now < self.deadline {
            return false;
        }
        self.throttled = false;
        self.deadline = self.deadline.saturating_add(self.t);
        if self.deadline <= now {
            self.deadline = now.saturating_add(self.d);
        }
        self.budget = self.q;
        true
    }

    /// Eligible to be picked: a reservation that is not throttled.
    #[inline]
    pub const fn eligible(&self) -> bool {
        !self.throttled
    }
}

/// EDF order inside one priority level: `true` when `(prio_a, deadline_a)`
/// must run before `(prio_b, deadline_b)`. Lower priority number first, then
/// the earlier absolute deadline; ties keep the incumbent (`false`).
#[inline]
pub const fn edf_before(prio_a: u32, deadline_a: u64, prio_b: u32, deadline_b: u64) -> bool {
    prio_a < prio_b || (prio_a == prio_b && deadline_a < deadline_b)
}

/// The rank a reservation at priority `level` competes with in the RT pick
/// and tick. `classes` (the dispatch order; false only under the
/// `sched-dl-in-level` canary): 0, so it runs before every RT band level
/// (the precedence DL > RT, owner decision 10-10), and [`edf_before`] on two
/// ranks orders reservations by absolute deadline alone. Otherwise its level,
/// so a reservation runs first only inside its own level. Ordering only: band
/// accounting keeps the real level.
#[inline(always)]
pub const fn dl_rank(classes: bool, level: u32) -> u32 {
    if classes { 0 } else { level }
}

/// While the band is skipped, may the exempt band loop at `level` run before
/// the best eligible reservation (`best_rank`, `None`: there is none)?
/// `classes` false (the canary): when its level is at least as urgent.
/// Otherwise always, since the exempt loops are the stop class, above DL
/// (owner decision 10-10).
#[inline(always)]
pub const fn exempt_first(classes: bool, level: u32, best_rank: Option<u32>) -> bool {
    match best_rank {
        None => true,
        Some(r) => classes || level <= r,
    }
}

/// What the stop-class step of the RT pick decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopPick {
    /// No exempt loop is involved: the DL / RT / fair pick follows.
    Pass,
    /// The running exempt loop keeps the CPU.
    Keep,
    /// Dispatch the queued exempt loop, past any running task.
    Take,
}

/// The stop-class step: the exempt band loops (the safety loops
/// `exempt_from_band_cap` marks: actuation, e-stop, watchdog) are the stop
/// class and run above DL and the rest of the band.
/// `running`: the level of the running task if it is an exempt loop;
/// `queued`: the most urgent level with a queued exempt loop. Between two
/// exempt loops the more urgent level wins and a tie keeps the running one.
#[inline(always)]
pub const fn stop_pick(running: Option<u32>, queued: Option<u32>) -> StopPick {
    match (running, queued) {
        (Some(r), Some(q)) => if q < r { StopPick::Take } else { StopPick::Keep },
        (Some(_), None) => StopPick::Keep,
        (None, Some(_)) => StopPick::Take,
        (None, None) => StopPick::Pass,
    }
}

/// The RT tick: does a queued exempt loop preempt the running task
/// (`cur_exempt`: it is one itself)?
#[inline(always)]
pub const fn stop_preempts(cur_exempt: bool, queued_exempt: bool) -> bool {
    !cur_exempt && queued_exempt
}

// ───────────────────────────── admission ───────────────────────────────────

/// Why a reservation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `q`, `t` zero, `q > d` or `d > t`.
    Malformed,
    /// No hart the reservation may run on has room for its density.
    NoRoom,
    /// Room on a hart, but not inside that hart's band cap (a band task's
    /// reservations must leave the non-band share the band budget guarantees).
    BandCap,
    /// The task already holds a reservation, or the per-hart set is full.
    Busy,
    /// The hart has room for the density, but its reservations sit at
    /// different priority levels and a level could miss a deadline
    /// ([`levels_check`]). Only while the dispatch runs a level above first
    /// whatever its deadlines ([`LevelOrder::Fixed`], the `sched-dl-in-level`
    /// canary); under EDF across levels, the default, never.
    Levels,
    /// The deadline class is compiled out (`SCHED_CLASS_DL=n`).
    ClassOff,
    /// The task's Domain is held by its `rt_time` envelope row: the
    /// reservation asks for more of a hart than the row lets one take. The
    /// effect gate wrote the refusal (`Rule::EnvelopeRtTime`) and its receipt.
    Envelope,
}

impl Refusal {
    /// The errno a syscall-facing caller returns: `EINVAL` for a malformed
    /// reservation, `EBUSY` for one that does not fit (Linux `sched_setattr`
    /// answers an over-subscribed `SCHED_DEADLINE` with `EBUSY` too).
    pub const fn errno(self) -> i32 {
        match self {
            Refusal::Malformed => 22,
            Refusal::NoRoom | Refusal::BandCap | Refusal::Busy | Refusal::Levels => 16,
            // EACCES: the Domain's row, not the machine, says no.
            Refusal::Envelope => 13,
            // ENOSYS: this build has no deadline class, the answer
            // `SYS_SCHEDCTL` gives for a class compiled out.
            Refusal::ClassOff => 38,
        }
    }
    /// The reason as a number, for the refusal's decision record
    /// ([`refusal_numbers`]); 0 is no reason.
    pub const fn code(self) -> u8 {
        match self {
            Refusal::Malformed => 1,
            Refusal::NoRoom => 2,
            Refusal::BandCap => 3,
            Refusal::Busy => 4,
            Refusal::Levels => 5,
            Refusal::ClassOff => 6,
            Refusal::Envelope => 7,
        }
    }
    /// For the refusal line.
    pub const fn name(self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::NoRoom => "no-room",
            Refusal::BandCap => "band-cap",
            Refusal::Busy => "busy",
            Refusal::Levels => "levels",
            Refusal::ClassOff => "class-off",
            Refusal::Envelope => "envelope",
        }
    }
}

/// `ceil(q * PPM / min(d, t))`: the reservation's density. Same rounding side
/// as the topology's boot check (never under-stated).
#[inline]
pub fn density_ppm(q: u64, t: u64, d: u64) -> Result<u32, Refusal> {
    if q == 0 || t == 0 {
        return Err(Refusal::Malformed);
    }
    let d = if d == 0 { t } else { d };
    if d > t || q > d {
        return Err(Refusal::Malformed);
    }
    let v = ((q as u128) * (PPM as u128)).div_ceil(d as u128);
    Ok(v.min(PPM as u128) as u32)
}

/// What one hart has admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct HartLoad {
    /// Summed density of every reservation on the hart.
    pub total_ppm: u32,
    /// Summed density of the reservations of band tasks.
    pub band_ppm: u32,
}

/// Can a reservation of `density` (a band task's when `band`) be added to
/// `load`, with the band limited to `band_limit_ppm`?
#[inline]
pub fn fits(load: HartLoad, density: u32, band: bool, band_limit_ppm: u32) -> Result<(), Refusal> {
    if (load.total_ppm as u64) + (density as u64) > PPM {
        return Err(Refusal::NoRoom);
    }
    if band && (load.band_ppm as u64) + (density as u64) > band_limit_ppm as u64 {
        return Err(Refusal::BandCap);
    }
    Ok(())
}

/// The largest density [`fits`] still accepts on `load` (a band task's when
/// `band`): the room under 100 % and, for a band task, under
/// `band_limit_ppm`.
#[inline]
pub fn headroom(load: HartLoad, band: bool, band_limit_ppm: u32) -> u32 {
    let mut room = PPM.saturating_sub(load.total_ppm as u64);
    if band {
        room = room.min((band_limit_ppm as u64).saturating_sub(load.band_ppm as u64));
    }
    room as u32
}

/// `ppm` of a window of `window_us`, in microseconds, rounded down: a budget
/// that long over that window has a density ([`density_ppm`]) of at most
/// `ppm`. Saturated to `u32::MAX`.
#[inline]
pub fn ppm_of_us(ppm: u32, window_us: u64) -> u64 {
    ((ppm as u128 * window_us as u128) / PPM as u128).min(u32::MAX as u128) as u64
}

/// What a reservation asked for, as its refusal's record names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ask {
    pub runtime_us: u64,
    pub period_us: u64,
    /// Relative deadline; 0 = the period.
    pub deadline_us: u64,
    /// A band task's: the band cap applies.
    pub band: bool,
}

/// The three numbers of a run-time refusal's decision record
/// (`Rule::DeadlineAdmission`, subject = the task's tid):
///
/// 0. the budget asked, `runtime_us`;
/// 1. the period asked, `period_us`;
/// 2. the budget the best hart in `mask` could still give inside the
///    deadline window (`deadline_us`, the period when 0), in its low 32 bits
///    (saturated), and the reason ([`Refusal::code`]) in bits 32..39.
///
/// "Could still give" is the same test [`fits`] applies ([`headroom`]), the
/// larger of the harts in `mask` (none: 0), turned into microseconds of the
/// window ([`ppm_of_us`]). Rounded down, so a refusal for density always
/// shows `runtime_us > available`.
pub fn refusal_numbers(why: Refusal, ask: Ask, loads: &[HartLoad], mask: u32, band_limit_ppm: u32) -> [u64; 3] {
    let mut best_ppm = 0u32;
    for (h, l) in loads.iter().enumerate().take(32) {
        if mask & (1u32 << h) == 0 {
            continue;
        }
        best_ppm = best_ppm.max(headroom(*l, ask.band, band_limit_ppm));
    }
    let window = if ask.deadline_us == 0 { ask.period_us } else { ask.deadline_us.min(ask.period_us) };
    [ask.runtime_us, ask.period_us, ppm_of_us(best_ppm, window) | (why.code() as u64) << 32]
}

/// First hart in `mask` (bit n = hart n, among `loads`) that fits. Returns the
/// hart, or the refusal of the last hart tried (`NoRoom` beats nothing tried).
pub fn first_fit(loads: &[HartLoad], mask: u32, density: u32, band: bool, band_limit_ppm: u32)
    -> Result<usize, Refusal>
{
    first_fit_by(loads, mask, density, band, band_limit_ppm, |_| true)
}

/// [`first_fit`] with one more test per hart, `levels_ok(hart)` (the
/// cross-level check, [`levels_check`]): a hart whose density fits but whose
/// levels do not is skipped, and refuses with [`Refusal::Levels`].
pub fn first_fit_by(loads: &[HartLoad], mask: u32, density: u32, band: bool, band_limit_ppm: u32,
    levels_ok: impl Fn(usize) -> bool) -> Result<usize, Refusal>
{
    let mut why = Refusal::NoRoom;
    for (h, l) in loads.iter().enumerate().take(32) {
        if mask & (1u32 << h) == 0 {
            continue;
        }
        match fits(*l, density, band, band_limit_ppm) {
            Ok(()) if levels_ok(h) => return Ok(h),
            Ok(()) => why = Refusal::Levels,
            Err(e) => {
                if e == Refusal::BandCap && why != Refusal::Levels {
                    why = e;
                }
            }
        }
    }
    Err(why)
}

/// The cross-level check ([`levels_check`]), what it reads ([`Booked`]) and
/// the dispatch order that decides whether it binds ([`LevelOrder`]): one
/// copy in `azos_abi::rt_levels`, which the topology's boot admission
/// applies too, so a set admitted at boot is admitted here.
pub use azos_abi::rt_levels::{levels_check, Booked, LevelOrder};

/// Proxy execution (the wait graph's stage 2, seL4 MCS passive servers):
/// the task that runs a reservation whose holder is blocked in a call.
///
/// From `holder`, follow the chain of calls (`server_of(t)`: the server `t`
/// is blocked calling, `None` when `t` waits on anything else) for at most
/// `depth` hops, to the first task that is not blocked (`blocked(t)`). That
/// task is the proxy, unless it holds a reservation of its own
/// (`reserved(t)`): an active server runs on its own scheduling context and
/// is ordered by its own deadline. `None` when the holder is not blocked,
/// the chain leaves the calls or comes back to the holder, or is longer than
/// `depth`. Canary `rt-proxy-canary`: never a proxy (stage 1: the server runs
/// on its own priority, boosted).
pub fn proxy_chain(
    holder: usize,
    depth: usize,
    blocked: impl Fn(usize) -> bool,
    server_of: impl Fn(usize) -> Option<usize>,
    reserved: impl Fn(usize) -> bool,
) -> Option<usize> {
    if cfg!(feature = "rt-proxy-canary") || !blocked(holder) {
        return None;
    }
    let mut t = holder;
    for _ in 0..depth {
        let s = server_of(t)?;
        if s == holder {
            return None;
        }
        if !blocked(s) {
            return if reserved(s) { None } else { Some(s) };
        }
        t = s;
    }
    None
}

/// Microseconds to counter ticks at `freq` Hz, rounded up (a reservation is
/// never shorter than declared). Saturating.
#[inline]
pub fn us_to_ticks(us: u64, freq: u64) -> u64 {
    ((us as u128) * (freq as u128)).div_ceil(1_000_000).min(u64::MAX as u128) as u64
}
