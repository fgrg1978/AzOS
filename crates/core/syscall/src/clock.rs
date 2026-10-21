// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's clock discipline and the `Clock` interface it hosts.
//!
//! One [`Discipline`] steers the wall clock (`REAL`, and `TAI` with it); this
//! file is where its decisions reach the vDSO page and the decision recorder.
//! Two feeders, one path ([`feed`]):
//!
//! * the SNTP client in the kernel ([`ntp_exchange`], installed as
//!   `azos_net::ntp`'s exchange sink at boot), and
//! * any task that holds the `clock` endpoint with `WRITE` ([`Server::sample`]):
//!   the PTP daemon.
//!
//! **Slewing needs a clock.** A slew is a rate, and the page holds an offset,
//! so [`tick`] moves the offset a little at a time: called from the timer
//! interrupt on every hart (`vdso_notify::vdso_task_tick`), it returns at once
//! unless the discipline has something standing ([`ACTIVE`]) and a period has
//! passed ([`PERIOD_NS`]), and it never waits for the lock (a hart that finds
//! it taken skips; the next tick applies what accrued, the discipline measures
//! from its own last tick).
//!
//! **Steps are decisions.** A step moves every deadline's wall-clock reading
//! at once, so it is recorded (`Rule::ClockStep`: the clock, the delta, the
//! threshold it crossed; `Admit` when made, `Refuse` when the clock would not).
//! The boot step (the first sample, from a clock nobody set) is recorded too.
//! The records are written after the discipline's lock is released: a
//! `Refuse` goes to the durable sink.
//!
//! **The real-time clock is where the wall clock starts, and where a
//! reference leaves it.** At boot [`seed_wall`] sets the wall clock from the
//! board's RTC (`kernel/src/boot/rtc.rs`, installed with [`install_rtc`]) so
//! the records written before any network carry a date: a step, recorded like
//! the others. The discipline is NOT told: it stays `Unset`, so the first
//! reference still steps without confirming (an RTC is minutes or years off,
//! and a clock that "was set" would refuse a step over the panic threshold;
//! `status` says `STATE_SEEDED`). When a reference steps the wall clock, the
//! RTC is set from it ([`persist_wall`]), so the next boot starts from a
//! time a reference gave.

use azos_abi::cap::CapPerms;
use azos_abi::time::ClockId;
use azos_decision::{Rule, Verdict as Decision};
use azos_devif::clock::{FILTERED, SLEWED, STATE_SEEDED, STATE_SYNCED, STATE_UNSET, STEPPED};
use azos_devif::{outcome, ClockStatus, Out};
use azos_drv_sys::clockdisc::{self, Discipline, Params, State, Verdict};
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::khost::Caller;

/// The loops' constants. The topology's `[clock]` row is the place for the
/// per-node values (the `Rule::ClockStep` record names it as the source of the
/// limit); until it carries them every node runs the defaults.
static DISC: SpinLock<Discipline> = SpinLock::new(Discipline::new(Params::DEFAULT));

/// The discipline has something for [`tick`] to apply. A relaxed flag read on
/// every hart's timer interrupt is all an undisciplined clock costs.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// The earliest monotonic time the next [`tick`] applies (ns).
static NEXT_NS: AtomicU64 = AtomicU64::new(0);

/// The wall clock was seeded from the RTC ([`seed_wall`]).
static SEEDED: AtomicBool = AtomicBool::new(false);

/// What a real-time clock's host can fail with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtcFault {
    /// The chip says its time is lost.
    Lost,
    /// The bus failed.
    Bus,
    /// The chip cannot hold the time.
    Range,
    /// The effect gate refused the record of the set.
    Refused,
}

/// The board's real-time clock, as the kernel hosts it
/// (`kernel/src/boot/rtc.rs`): the chip behind a lock, and the write-ahead
/// record of a set. The syscall layer is core and links no driver, so the
/// kernel, the composition root, installs it.
pub trait RtcHost: Sync {
    /// The chip's time, UTC seconds since 1970-01-01.
    fn read(&self) -> Result<u64, RtcFault>;
    /// Set the chip. `tid` is the task the effect is charged to (0: the
    /// kernel). The effect record is written before the chip is.
    fn set(&self, unix_secs: u64, tid: u32) -> Result<(), RtcFault>;
}

static RTC: SpinLock<Option<&'static dyn RtcHost>> = SpinLock::new(None);

/// Install the board's RTC (boot, once).
pub fn install_rtc(host: &'static dyn RtcHost) {
    *RTC.lock_irqsave() = Some(host);
}

fn rtc() -> Option<&'static dyn RtcHost> {
    *RTC.lock_irqsave()
}

/// Slew period: 125 Hz is faster than the 100 Hz scheduler tick, so every
/// tick that finds the discipline active applies; a slower tick (a tickless
/// idle) applies the whole interval at once.
pub const PERIOD_NS: u64 = 8_000_000;

/// Back to a clock nobody set. Test-only, as `entropy.rs::__entropy_clear_for_tests`.
#[cfg(test)]
pub fn __clock_reset_for_tests() {
    *DISC.lock_irqsave() = Discipline::new(Params::DEFAULT);
    ACTIVE.store(false, Ordering::Relaxed);
    NEXT_NS.store(0, Ordering::Relaxed);
    SEEDED.store(false, Ordering::Relaxed);
    *RTC.lock_irqsave() = None;
}

/// Monotonic nanoseconds, the clock the discipline and the SNTP exchange share.
fn mono_ns() -> u64 {
    azos_abi::time::ticks_to_ns(azos_drv_sys::timebase::now(), azos_drv_sys::timebase::TIMER_FREQ)
}

/// The `[clock]` row's TAI-UTC table, `(utc_secs, tai_offset)` oldest first.
fn leaps() -> impl Iterator<Item = (u64, u16)> {
    azos_topology::get().map_or(&[][..], |t| t.clock().leaps()).iter().map(|l| (l.utc_secs, l.tai_offset))
}

/// Apply the standing correction accrued up to the monotonic time `now`. The
/// caller holds the discipline.
fn advance(d: &mut Discipline, now: u64) {
    azos_mm::vdso::vdso_slew_wall(d.tick(now));
}

/// Move the wall clock one slice. From the timer interrupt, on every hart.
pub fn tick() {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    let now = mono_ns();
    if now < NEXT_NS.load(Ordering::Relaxed) {
        return;
    }
    let Some(mut d) = DISC.try_lock_irqsave() else { return };
    NEXT_NS.store(now.saturating_add(PERIOD_NS), Ordering::Relaxed);
    advance(&mut d, now);
    ACTIVE.store(d.active(), Ordering::Relaxed);
}

/// Take a measurement. `measure` gets the real offset (wall minus monotonic,
/// ns) the page publishes **after** the standing correction was applied up to
/// now, so an offset computed from it is against the clock the discipline
/// steers; it returns `(offset_ns, delay_ns)`.
fn feed(measure: impl FnOnce(u64) -> (i64, u64), source: u32) -> Verdict {
    let now = mono_ns();
    let verdict = {
        let mut d = DISC.lock_irqsave();
        advance(&mut d, now);
        let (offset, delay) = measure(azos_mm::vdso::clock_offsets().real);
        let v = d.sample(now, offset, delay, source);
        match v {
            // The page follows the discipline under its lock: a tick cannot
            // slew between the verdict and the step.
            Verdict::Stepped { delta_ns, .. } => azos_mm::vdso::vdso_step_wall(now, delta_ns, leaps()),
            // A taken sample also re-derives TAI against the leap table.
            Verdict::Slewed => azos_mm::vdso::vdso_step_wall(now, 0, leaps()),
            Verdict::Filtered | Verdict::Refused { .. } => {}
        }
        ACTIVE.store(d.active(), Ordering::Relaxed);
        v
    };
    record(&verdict);
    if matches!(verdict, Verdict::Stepped { .. }) {
        persist_wall();
    }
    verdict
}

/// Set the wall clock to `unix_secs` from the real-time clock, once at boot,
/// before any reference. Only a clock nothing has set is seeded (`false`
/// otherwise: a reference already did better). The discipline is not told
/// (see the module doc); the step is recorded like any other
/// (`Rule::ClockStep`, `Admit`, limit 0: it has none).
pub fn seed_wall(unix_secs: u64) -> bool {
    let Some(target) = unix_secs.checked_mul(1_000_000_000).and_then(|ns| i64::try_from(ns).ok()) else {
        return false;
    };
    let now = mono_ns();
    let delta = {
        let d = DISC.lock_irqsave();
        if d.state() != State::Unset || SEEDED.load(Ordering::Relaxed) {
            return false;
        }
        let wall = now.saturating_add(azos_mm::vdso::clock_offsets().real);
        let delta = target.saturating_sub(i64::try_from(wall).unwrap_or(i64::MAX));
        azos_mm::vdso::vdso_step_wall(now, delta, leaps());
        SEEDED.store(true, Ordering::Relaxed);
        delta
    };
    record(&Verdict::Stepped { delta_ns: delta, limit_ns: 0 });
    true
}

/// Write the wall clock into the real-time clock, so the next boot starts
/// from it. After a step a reference made; a failure is a line, not an error:
/// the wall clock is right, only its backup is not.
fn persist_wall() {
    let Some(host) = rtc() else { return };
    let wall = mono_ns().saturating_add(azos_mm::vdso::clock_offsets().real);
    if let Err(e) = host.set(wall / 1_000_000_000, 0) {
        azos_drv_sys::kwarn!("[RTC] the wall clock was not written back: {:?}", e);
    }
}

/// The `Rule::ClockStep` record of a step made or refused; none for anything
/// else.
fn record(v: &Verdict) {
    let (dec, delta, limit) = match *v {
        Verdict::Stepped { delta_ns, limit_ns } => (Decision::Admit, delta_ns, limit_ns),
        Verdict::Refused { delta_ns, limit_ns } => (Decision::Refuse, delta_ns, limit_ns),
        Verdict::Slewed | Verdict::Filtered => return,
    };
    let clock = ClockId::REAL.raw();
    azos_decision::record(Rule::ClockStep, dec, clock, [clock as u64, delta.unsigned_abs(), limit as u64]);
}

/// A completed SNTP exchange (`azos_net::ntp::set_exchange_sink`).
pub fn ntp_exchange(ex: &azos_net::ntp::Exchange) {
    feed(|real| ex.measure(real), clockdisc::source::NTP);
}

/// How the discipline stands.
pub fn status() -> ClockStatus {
    let s = DISC.lock_irqsave().snapshot();
    ClockStatus {
        state: match s.state {
            State::Unset if SEEDED.load(Ordering::Relaxed) => STATE_SEEDED,
            State::Unset => STATE_UNSET,
            State::Synced => STATE_SYNCED,
        },
        source: s.source,
        freq_ppb: s.freq_ppb,
        phase_ns: s.phase_ns,
        steps: s.steps,
        rejected: s.rejected,
    }
}

/// The answer for a chip that did not give or take the time.
fn rtc_outcome(e: RtcFault) -> u32 {
    match e {
        RtcFault::Lost => outcome::NOT_READY,
        RtcFault::Bus => outcome::FAULT,
        RtcFault::Range => outcome::BAD_ARGUMENT,
        RtcFault::Refused => outcome::REFUSED,
    }
}

/// The `Clock` interface served for one caller.
pub struct Server(pub Caller);

impl azos_devif::Clock for Server {
    /// In order: the right (`WRITE`: the call moves time, and containment
    /// refuses it); the source; then the discipline decides.
    fn sample(&mut self, offset_ns: i64, delay_ns: u64, source: u32) -> Out<u32> {
        if let Err(refused) = self.0.gate::<u32>(CapPerms::WRITE) {
            return refused;
        }
        if source == 0 || source > clockdisc::source::MAX {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        match feed(|_| (offset_ns, delay_ns), source) {
            Verdict::Slewed => Out::ok(SLEWED),
            Verdict::Stepped { .. } => Out::ok(STEPPED),
            Verdict::Filtered => Out::ok(FILTERED),
            Verdict::Refused { .. } => Out::err(outcome::REFUSED),
        }
    }

    fn status(&self) -> Out<ClockStatus> {
        if let Err(refused) = self.0.gate::<ClockStatus>(CapPerms::READ) {
            return refused;
        }
        Out::ok(status())
    }

    /// In order: the right (`READ`), the chip, then its answer.
    fn rtc_read(&self) -> Out<u64> {
        if let Err(refused) = self.0.gate::<u64>(CapPerms::READ) {
            return refused;
        }
        let Some(host) = rtc() else { return Out::err(outcome::NO_RESOURCE) };
        match host.read() {
            Ok(secs) => Out::ok(secs),
            Err(e) => Out::err(rtc_outcome(e)),
        }
    }

    /// In order: the right (`WRITE`: the RTC is what the next boot believes,
    /// and containment refuses it), the chip; the host writes the effect
    /// record before the chip.
    fn rtc_set(&mut self, unix_secs: u64) -> Out<()> {
        if let Err(refused) = self.0.gate::<()>(CapPerms::WRITE) {
            return refused;
        }
        let Some(host) = rtc() else { return Out::err(outcome::NO_RESOURCE) };
        match host.set(unix_secs, self.0.tid) {
            Ok(()) => Out::ok(()),
            Err(e) => Out::err(rtc_outcome(e)),
        }
    }
}
