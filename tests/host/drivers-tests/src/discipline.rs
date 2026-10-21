// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The clock discipline (`crates/drivers/sys/src/clockdisc.rs`) against a model
//! clock: a counter that runs fast or slow by a fixed rate, a reference that
//! is noisy, and a loop that ticks every 10 ms as the timer interrupt does.
//!
//! The model keeps the true time `T` and the disciplined clock `D`; the
//! discipline sees only what the kernel gives it: the monotonic counter
//! (`L = T + T*drift`) and measurements `theta = T - D + noise` with a delay.
//! What `tick` returns is added to `D`, as `vdso_slew_wall` adds it to the page.
//!
//! Wired by `mod discipline;` in `lib.rs`.

#[allow(dead_code)]
#[path = "../../../../crates/drivers/sys/src/clockdisc.rs"]
mod clockdisc;

use clockdisc::{Discipline, Params, State, Verdict, source};

const MS: i64 = 1_000_000;
const SEC: i64 = 1_000_000_000;
/// The timer interrupt's period in the model.
const TICK_NS: i64 = 10 * MS;

/// A deterministic noise source: an LCG, summed over four draws so the
/// distribution has the bell shape (and the bounded tail) of a real jitter.
struct Noise(u64);

impl Noise {
    fn uniform(&mut self) -> i64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((self.0 >> 33) as i64 % 2001) - 1000 // -1000..=1000
    }
    /// About `+-amp`, peak, with sigma near `amp / 3.4`.
    fn bell(&mut self, amp: i64) -> i64 {
        (self.uniform() + self.uniform() + self.uniform() + self.uniform()) * amp / 4000
    }
}

/// The world: true time, a counter with a rate error, and the clock being steered.
struct Sim {
    d: Discipline,
    /// True nanoseconds since the start.
    t: i64,
    /// Rate error of the counter, ppb (positive: it runs fast).
    drift_ppb: i64,
    /// The counter at `t = 0` minus the true time (the monotonic clock is
    /// not the wall clock; only the wall clock's error matters, so this is
    /// the initial wall-clock error).
    err0: i64,
    /// Everything the discipline has added to the wall clock.
    corr: i64,
    noise: Noise,
    /// Noise on a measurement, +- ns, and the link's delay.
    jitter: i64,
    base_delay: u64,
    /// Samples taken, by verdict.
    stepped: u32,
}

impl Sim {
    fn new(drift_ppb: i64, err0: i64) -> Sim {
        Sim {
            d: Discipline::new(Params::DEFAULT),
            t: SEC, // never 0: 0 is the "no time yet" value of the monotonic reads
            drift_ppb,
            err0,
            corr: 0,
            noise: Noise(0x5eed),
            jitter: 50_000,
            base_delay: 200_000,
            stepped: 0,
        }
    }

    /// The counter the discipline reads.
    fn counter(&self) -> u64 {
        (self.t + (self.t as i128 * self.drift_ppb as i128 / SEC as i128) as i64) as u64
    }

    /// The wall clock's error: disciplined minus true, ns.
    fn error(&self) -> i64 {
        self.err0 + (self.t as i128 * self.drift_ppb as i128 / SEC as i128) as i64 + self.corr
    }

    /// Run `ns` of true time in timer ticks.
    fn run(&mut self, ns: i64) {
        let end = self.t + ns;
        while self.t < end {
            let before = self.error();
            self.t += TICK_NS;
            // The counter also moved: that is the drift part of `error`.
            let add = self.d.tick(self.counter());
            self.corr += add;
            // A wall clock that is slewed never runs backwards.
            let moved = self.error() - before;
            assert!(moved + TICK_NS > 0, "the wall clock stepped back by {} ns inside a tick", -(moved + TICK_NS));
        }
    }

    /// One measurement with the model's noise, taken now.
    fn measure(&mut self, delay_extra: u64) -> Verdict {
        let theta = -self.error() + self.noise.bell(self.jitter);
        let delay = self.base_delay + (self.noise.bell(50_000).unsigned_abs()) + delay_extra;
        self.offer(theta, delay)
    }

    fn offer(&mut self, theta: i64, delay: u64) -> Verdict {
        let v = self.d.sample(self.counter(), theta, delay, source::NTP);
        if let Verdict::Stepped { delta_ns, .. } = v {
            self.corr += delta_ns;
            self.stepped += 1;
        }
        v
    }

    /// `n` samples, one every `every_s` seconds of true time.
    fn poll(&mut self, n: u32, every_s: i64) {
        for _ in 0..n {
            self.run(every_s * SEC);
            self.measure(0);
        }
    }
}

/// **Slew converges on a model with noise.** The counter runs 50 ppm fast and
/// the wall clock starts 40 ms off (under the 128 ms step threshold); the
/// reference is polled every 64 s with +-50 us of noise. After an hour the
/// clock is within 150 us of true time (three sigma of the noise), the standing
/// correction has found the counter's rate (-50 ppm within 1.5 ppm), and the
/// clock was never stepped past the boot step: it only ever slewed (`run`
/// asserts it never went backwards).
/// **Canary:** with the frequency loop's update removed the clock still follows
/// the phase but the correction stays 0 and the second assert fails;
/// with the slew removed the error never leaves 40 ms.
#[test]
fn slew_converges_on_a_noisy_model() {
    let mut s = Sim::new(50_000, 40 * MS);
    // The boot step: the first sample from an unset clock.
    assert!(matches!(s.measure(0), Verdict::Stepped { limit_ns: 0, .. }), "boot step");
    assert_eq!(s.stepped, 1);
    // The step corrected the 40 ms (to within the noise); now an error of
    // 40 ms is put back by hand, as a clock that drifted off while unpolled.
    s.corr -= 40 * MS;
    s.poll(56, 64); // about an hour
    let err = s.error();
    let snap = s.d.snapshot();
    assert!(err.abs() < 150_000, "error {err} ns after an hour");
    assert!((snap.freq_ppb + 50_000).abs() < 1_500, "frequency correction {} ppb, counter is +50000", snap.freq_ppb);
    assert_eq!(s.stepped, 1, "slewed after the boot step, never stepped again");
    assert_eq!(snap.state, State::Synced);
    assert_eq!(snap.steps, 1);
}

/// The rate error found is the rate error that is there, in the other
/// direction too, and for a counter off by a few hundred ppm.
#[test]
fn slew_finds_a_slow_counter() {
    let mut s = Sim::new(-300_000, 0);
    s.measure(0);
    s.poll(60, 64);
    assert!(s.error().abs() < 150_000, "error {} ns", s.error());
    assert!((s.d.freq_ppb() - 300_000).abs() < 3_000, "correction {} ppb", s.d.freq_ppb());
}

/// **The first sample is the boot step, whatever its size and sign.** From an
/// unset clock a sample of 1.7e18 ns (the Unix time against a clock that reads
/// the uptime) and one of `i64::MIN` both step; nothing in the arithmetic
/// takes the absolute value of the offset in a type that cannot hold it.
#[test]
fn the_first_sample_steps_at_boot() {
    for off in [1_780_000_000_000_000_000i64, -5, 0, i64::MIN, i64::MAX] {
        let mut d = Discipline::new(Params::DEFAULT);
        assert_eq!(d.state(), State::Unset);
        assert_eq!(d.tick(SEC as u64), 0, "an unset clock has nothing to slew");
        assert_eq!(d.sample(SEC as u64, off, 100_000, source::PTP), Verdict::Stepped { delta_ns: off, limit_ns: 0 }, "offset {off}");
        assert_eq!(d.state(), State::Synced);
        assert_eq!(d.snapshot().steps, 1);
        assert_eq!(d.snapshot().source, source::PTP);
    }
}

/// **An offset under the threshold is slewed, not stepped**, and the phase to
/// remove is exactly the offset.
#[test]
fn a_small_offset_is_slewed_out() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    assert_eq!(d.sample(2 * SEC as u64, 100 * MS, 100_000, source::NTP), Verdict::Slewed);
    assert_eq!(d.snapshot().phase_ns, 100 * MS);
    assert_eq!(d.snapshot().steps, 1, "only the boot step");
    // Exactly at the threshold is still a slew: the step is for "more than".
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    assert_eq!(d.sample(2 * SEC as u64, Params::DEFAULT.step_ns, 100_000, source::NTP), Verdict::Slewed);
}

/// **A phase is removed at no more than the slew limit**, and all of it is
/// removed in the end. 100 ms at 500 ppm takes 200 s; the exponential tail
/// (time constant 4 * 16 s) would take far longer to *start* that fast, so the
/// first seconds run at the cap.
#[test]
fn the_slew_rate_is_capped_and_the_phase_goes_to_zero() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    d.sample(SEC as u64, 100 * MS, 100_000, source::NTP);
    let mut now = SEC as u64;
    let mut applied = 0i64;
    let mut last = 0i64;
    for second in 1..=3600u64 {
        for _ in 0..100 {
            now += TICK_NS as u64;
            let a = d.tick(now);
            assert!(a >= 0 && a <= 5_000, "a 10 ms slice moved the clock {a} ns (cap: 500 ppm = 5000 ns)");
            applied += a;
        }
        if second == 1 {
            assert!(applied <= 500_000, "{applied} ns in the first second, cap 500000");
            assert!(applied >= 490_000, "{applied} ns in the first second, the cap is the rate while far off");
        }
        last = applied;
    }
    assert!((100 * MS - last).abs() <= 2, "{last} of 100000000 applied after an hour");
    assert_eq!(d.snapshot().phase_ns, 100 * MS - last);
    assert!(!d.active() || d.snapshot().phase_ns != 0, "settled");
}

/// **A negative phase is removed by running slow, never by going back**: the
/// per-slice change is at least -5000 ns on a 10 ms slice.
#[test]
fn a_negative_phase_slows_the_clock() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    d.sample(SEC as u64, -100 * MS, 100_000, source::NTP);
    let mut now = SEC as u64;
    for _ in 0..1000 {
        now += TICK_NS as u64;
        let a = d.tick(now);
        assert!((-5_000..=0).contains(&a), "slice {a}");
        assert!(a + TICK_NS > 0, "wall clock must still advance");
    }
}

/// **A step over the threshold is recorded** (the verdict carries the delta
/// and the limit it crossed, which the kernel writes as `Rule::ClockStep`),
/// and it takes two agreeing samples: a lone wild sample moves nothing.
/// **Canary:** `confirm = 1` makes the first row a step.
#[test]
fn a_step_over_the_threshold_is_confirmed_and_reported() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    let t = |n: i64| (SEC + n * 64 * SEC) as u64;
    assert_eq!(d.sample(t(1), 500 * MS, 100_000, source::NTP), Verdict::Filtered, "the first of a step");
    assert_eq!(d.snapshot().phase_ns, 0, "nothing was taken from it");
    assert_eq!(
        d.sample(t(2), 505 * MS, 100_000, source::NTP),
        Verdict::Stepped { delta_ns: 505 * MS, limit_ns: 128 * MS },
        "the second agrees: stepped by that sample's offset, over the 128 ms threshold"
    );
    assert_eq!(d.snapshot().steps, 2);
    assert_eq!(d.snapshot().phase_ns, 0, "a step leaves no phase");
    // Negative side too.
    assert_eq!(d.sample(t(3), -400 * MS, 100_000, source::NTP), Verdict::Filtered);
    assert_eq!(d.sample(t(4), -400 * MS, 100_000, source::NTP), Verdict::Stepped { delta_ns: -400 * MS, limit_ns: 128 * MS });
}

/// Two wild samples that disagree are two loners, and an in-range sample in
/// between breaks a run: only consecutive agreeing ones step.
#[test]
fn samples_that_disagree_or_are_interrupted_do_not_step() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    let t = |n: i64| (SEC + n * 64 * SEC) as u64;
    assert_eq!(d.sample(t(1), 500 * MS, 100_000, source::NTP), Verdict::Filtered);
    assert_eq!(d.sample(t(2), -500 * MS, 100_000, source::NTP), Verdict::Filtered, "the other way");
    assert_eq!(d.sample(t(3), 500 * MS, 100_000, source::NTP), Verdict::Filtered, "the run restarted");
    assert_eq!(d.sample(t(4), 1 * MS, 100_000, source::NTP), Verdict::Slewed, "back in range");
    assert_eq!(d.sample(t(5), 500 * MS, 100_000, source::NTP), Verdict::Filtered, "a run broken by an in-range sample starts over");
    assert_eq!(d.snapshot().steps, 1, "only the boot step");
    assert_eq!(d.snapshot().rejected, 4);
}

/// **A clock that was set does not jump by more than the panic threshold.**
/// 2000 s is refused, every time, however often it is repeated, and the
/// refusal reports the limit (the record's `limit_ns`). `i64::MIN` is refused
/// without overflowing.
#[test]
fn a_huge_step_after_boot_is_refused() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    for i in 1..5i64 {
        let at = (SEC + i * 64 * SEC) as u64;
        assert_eq!(
            d.sample(at, 2_000 * SEC, 100_000, source::NTP),
            Verdict::Refused { delta_ns: 2_000 * SEC, limit_ns: 1_000 * SEC },
            "attempt {i}"
        );
    }
    let at = (SEC + 10 * 64 * SEC) as u64;
    assert_eq!(
        d.sample(at, i64::MIN, 100_000, source::NTP),
        Verdict::Refused { delta_ns: i64::MIN, limit_ns: 1_000 * SEC }
    );
    assert_eq!(d.snapshot().steps, 1, "only the boot step");
    assert_eq!(d.snapshot().phase_ns, 0);
    assert_eq!(d.snapshot().rejected, 5);
}

/// **A sample that queued behind traffic is not believed.** Once a quiet delay
/// is known, a sample 40 ms late with a wild offset is filtered and moves
/// nothing; a delay above the ceiling is filtered from the first; and a link
/// that is slower for good is accepted again once the old delays age out.
/// **Canary:** removing the filter makes the wild offset the phase.
#[test]
fn a_delayed_sample_is_filtered() {
    let mut d = Discipline::new(Params::DEFAULT);
    assert_eq!(d.sample(SEC as u64, 0, 2 * SEC as u64, source::NTP), Verdict::Filtered, "above the delay ceiling, even the first");
    assert_eq!(d.state(), State::Unset, "and it set nothing");
    d.sample(2 * SEC as u64, 0, 200_000, source::NTP);
    let t = |n: i64| (2 * SEC + n * 64 * SEC) as u64;
    assert_eq!(d.sample(t(1), 10 * MS, 40 * MS as u64, source::NTP), Verdict::Filtered);
    assert_eq!(d.snapshot().phase_ns, 0);
    assert_eq!(d.sample(t(2), 30_000, 450_000, source::NTP), Verdict::Slewed, "within 2 * min + 1 ms");
    assert_eq!(d.snapshot().phase_ns, 30_000);
    // The link is now 40 ms for good: filtered until the quiet delays aged out of the 8.
    let mut accepted_at = None;
    for i in 3..30 {
        if d.sample(t(i), 1_000, 40 * MS as u64, source::NTP) == Verdict::Slewed {
            accepted_at = Some(i);
            break;
        }
    }
    let at = accepted_at.expect("a slower link is accepted in the end");
    assert!((10..=12).contains(&at), "accepted at sample {at}");
}

/// **Delay noise in a model does not move the clock.** The reference is polled
/// every 64 s; one poll in four rides a congested link (80 ms late, its offset
/// 40 ms wrong, as asymmetric queueing makes it). With the filter the clock
/// stays within 150 us.
#[test]
fn queueing_asymmetry_does_not_reach_the_clock() {
    let mut s = Sim::new(20_000, 0);
    s.measure(0);
    for i in 0..60 {
        s.run(64 * SEC);
        if i % 4 == 3 {
            let theta = -s.error() + 40 * MS;
            s.offer(theta, 80 * MS as u64 + 200_000);
        } else {
            s.measure(0);
        }
        if i > 30 {
            assert!(s.error().abs() < 150_000, "poll {i}: error {}", s.error());
        }
    }
}

/// The standing correction stays within +-500 ppm however long a persistent
/// offset is shown (a reference that is wrong, or a clock that slews less than
/// the offset grows).
#[test]
fn the_frequency_correction_is_clamped() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    let mut at = SEC as u64;
    for _ in 0..200 {
        at += 64 * SEC as u64;
        d.tick(at);
        d.sample(at, 120 * MS, 100_000, source::NTP);
        assert!(d.freq_ppb().abs() <= 500_000, "freq {}", d.freq_ppb());
    }
    assert_eq!(d.freq_ppb(), 500_000, "and it does reach the clamp");
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    let mut at = SEC as u64;
    for _ in 0..200 {
        at += 64 * SEC as u64;
        d.tick(at);
        d.sample(at, -120 * MS, 100_000, source::NTP);
    }
    assert_eq!(d.freq_ppb(), -500_000);
}

/// **Two samples a millisecond apart teach the frequency nothing**: the noise
/// over so short an interval would be a large rate.
#[test]
fn a_short_interval_does_not_move_the_frequency() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    d.sample(SEC as u64 + 1_000_000, 100 * MS, 100_000, source::NTP);
    assert_eq!(d.freq_ppb(), 0);
}

/// `active` says when a tick has something to do, so the interrupt can skip
/// the lock: never on an unset clock, yes with a phase, no once it is gone.
#[test]
fn active_follows_what_is_standing() {
    let mut d = Discipline::new(Params::DEFAULT);
    assert!(!d.active());
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    assert!(!d.active(), "a step leaves nothing to slew");
    d.sample(2 * SEC as u64, 5 * MS, 100_000, source::NTP);
    assert!(d.active());
}

/// **A tick after a gap of years does not overflow**: the products leave 64
/// bits, the arithmetic goes to 128 (the suite builds with overflow checks,
/// like the kernel), and the answer is the capped slew, not a wrapped number.
#[test]
fn a_very_long_gap_between_ticks_does_not_overflow() {
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    d.sample(SEC as u64, 100 * MS, 100_000, source::NTP);
    let a = d.tick(u64::MAX);
    assert_eq!(a, 100 * MS, "the whole phase is removed in a gap that long (the cap exceeds it)");
    assert_eq!(d.snapshot().phase_ns, 0);
    // The frequency part saturates instead of wrapping.
    let mut d = Discipline::new(Params::DEFAULT);
    d.sample(SEC as u64, 0, 100_000, source::NTP);
    let mut at = SEC as u64;
    for _ in 0..40 {
        at += 64 * SEC as u64;
        d.tick(at);
        d.sample(at, 120 * MS, 100_000, source::NTP);
    }
    assert_eq!(d.freq_ppb(), 500_000);
    assert!(d.tick(u64::MAX) > 0);
}
