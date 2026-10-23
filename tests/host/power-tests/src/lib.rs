// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for the power policy.
//!
//! * `table` — the built-in profile per preset, pinned, and the boot values
//!   the performance preset restores (checked against the kernel's own).
//! * `decisions` — the policy server's decision table
//!   (`userspace/services/power/src/policy.rs`, pulled in by path so the code
//!   under test is the code `POWER.ELF` is built from), run against a kernel
//!   whose limits are the real ones (`azos_energy::policy`).
//! * `wire` — the `PowerPolicy` interface through the generated client stub
//!   and the dispatcher, and the verdict encoding.
//!
//! The server never sees the kernel's floors except by being refused, which is
//! the point: the tests make the kernel refuse and check what the server does
//! about it.

#[allow(dead_code)]
#[path = "../../../../userspace/services/power/src/policy.rs"]
pub mod policy;

#[cfg(test)]
mod runtime_pm;

// The battery model, the degrade rows, the level shares and the budget,
// against the kernel's real limits.
#[cfg(test)]
mod power_ring3;

// System suspend: sequence, gates, boot offset, records.
#[cfg(test)]
mod suspend;

/// A kernel with the real limits behind the `PowerPolicy` trait.
#[cfg(test)]
mod kern {
    use azos_energy::model::{IdleState, Opp, PerfDomain};
    use azos_energy::{EnergyModel, ModelSource, Policy, Refusal};
    use azos_power::*;

    use azos_energy::Governor;

    pub struct Kern {
        pub model: EnergyModel,
        pub policy: Policy,
        /// Real-time density admitted on every hart, ppm.
        pub admitted_ppm: u32,
        /// Answer every governor call with this errno instead (a call that
        /// fails outright: no capability).
        pub fail_governor: Option<u32>,
        pub calls: u32,
    }

    pub fn opp(f: u32, c: u16, p: u32) -> Opp {
        Opp { freq_khz: f, capacity: c, power_mw: p }
    }

    /// One domain per entry of `wcet_ref_khz`: four OPPs (250 MHz .. 2 GHz),
    /// three idle states.
    pub fn machine(wcet_ref_khz: &[u32]) -> EnergyModel {
        let mut m = EnergyModel::from_source(ModelSource::Topology);
        for (i, &w) in wcet_ref_khz.iter().enumerate() {
            let mut d = PerfDomain::new(1 << i);
            for o in [opp(250_000, 128, 20), opp(500_000, 256, 60), opp(1_000_000, 512, 200), opp(2_000_000, 1024, 900)] {
                d.push_opp(o).unwrap();
            }
            d.push_idle(IdleState::new(b"wfi", 1, 1, 8)).unwrap();
            d.push_idle(IdleState::new(b"retention", 120, 500, 2)).unwrap();
            d.push_idle(IdleState::new(b"off", 900, 4_000, 0)).unwrap();
            d.wcet_ref_khz = w;
            m.push_domain(d).unwrap();
        }
        m
    }

    impl Kern {
        pub fn new(model: EnergyModel) -> Self {
            Kern { model, policy: Policy::new(Governor::Fixed), admitted_ppm: 0, fail_governor: None, calls: 0 }
        }
        fn code(&mut self, r: Result<(), Refusal>) -> u32 {
            self.calls += 1;
            r.map_or_else(|e| e.code(), |()| 0)
        }
    }

    impl PowerPolicy for Kern {
        fn set_governor(&mut self, gov: u32) -> u32 {
            if let Some(e) = self.fail_governor {
                self.calls += 1;
                return VERDICT_FAILED | e;
            }
            let r = self.policy.set_governor(&self.model, gov);
            self.code(r)
        }
        fn set_opp_range(&mut self, domain: u32, min: u32, max: u32) -> u32 {
            let r = self.policy.set_opp_range(&self.model, domain, min, max, self.admitted_ppm);
            self.code(r)
        }
        fn set_headroom(&mut self, pct: u32) -> u32 {
            let r = self.policy.set_headroom(pct);
            self.code(r)
        }
        fn set_rate_limit(&mut self, us: u32) -> u32 {
            let r = self.policy.set_rate_limit(us);
            self.code(r)
        }
        fn set_idle_depth(&mut self, depth: u32) -> u32 {
            let r = self.policy.set_idle_depth(&self.model, depth);
            self.code(r)
        }
        fn set_power_cap(&mut self, domain: u32, mw: u32) -> u32 {
            let r = self.policy.set_power_cap(&self.model, domain, mw, self.admitted_ppm);
            self.code(r)
        }
        fn set_parked(&mut self, mask: u32) -> u32 {
            let r = self.policy.set_parked(&self.model, mask, &[self.admitted_ppm; 32]);
            self.code(r)
        }
        fn set_qos_domains(&mut self, class: u32, domains: u32) -> u32 {
            let r = self.policy.set_qos_domains(&self.model, class, domains);
            self.code(r)
        }
        fn report_battery(&mut self, soc_pct: u32, level: u32) -> u32 {
            let r = self.policy.report_battery(soc_pct, level).map(|_| ());
            self.code(r)
        }
        fn state(&self, sel: u32) -> u64 {
            match sel as u64 {
                POLICY_STATE_MODE => 1,
                POLICY_STATE_GOVERNOR => match self.policy.governor() {
                    Governor::Fixed => 0,
                    Governor::Schedutil => 1,
                    Governor::DeadlineFloor => 2,
                },
                POLICY_STATE_DOMAINS => self.model.domains().len() as u64,
                POLICY_STATE_HEADROOM => self.policy.headroom_pct() as u64,
                POLICY_STATE_RATE_LIMIT => self.policy.rate_limit_us() as u64,
                POLICY_STATE_IDLE_DEPTH => self.policy.idle_depth() as u64,
                s if s >= POLICY_STATE_DOMAIN_BASE => {
                    let di = (s - POLICY_STATE_DOMAIN_BASE) as usize;
                    let Some(d) = self.model.domains().get(di) else { return WORD_ERR };
                    let (lo, hi) = self.policy.opp_range(di);
                    d.opps().len() as u64
                        | 255 << 8
                        | (lo as u64) << 16
                        | (hi as u64) << 24
                        | (azos_energy::governor::safety_floor_opp(d) as u64) << 32
                        | (d.idle_states().len() as u64) << 40
                }
                _ => WORD_ERR,
            }
        }
        fn stats(&self, sel: u32) -> u64 {
            match sel as u64 {
                POLICY_STATS_APPLIED => self.policy.applied() as u64,
                POLICY_STATS_REFUSED => self.policy.refused() as u64,
                _ => WORD_ERR,
            }
        }
    }
}

#[cfg(test)]
mod table {
    use crate::policy::*;
    use azos_energy::governor::{HEADROOM_PCT, RATE_LIMIT_US};
    use azos_power::*;

    /// The performance preset restores what the kernel booted with; if the
    /// kernel's defaults move, this fails before a profile lies.
    #[test]
    fn performance_is_the_kernels_boot_policy() {
        let p = profile(Preset::Performance);
        assert_eq!(p.governor as u64, POLICY_GOV_FIXED);
        assert_eq!(p.headroom_pct, HEADROOM_PCT);
        assert_eq!(p.rate_limit_us as u64, RATE_LIMIT_US);
        assert_eq!((DEFAULT_HEADROOM_PCT, DEFAULT_RATE_LIMIT_US as u64), (HEADROOM_PCT, RATE_LIMIT_US));
        assert_eq!((p.cap_pct, p.idle_depth), (100, POLICY_IDLE_UNLIMITED));
    }

    #[test]
    fn the_presets_differ_where_they_should() {
        let (b, e) = (profile(Preset::Balanced), profile(Preset::Endurance));
        assert_eq!(b.governor as u64, POLICY_GOV_DEADLINE_FLOOR);
        assert_eq!(e.governor as u64, POLICY_GOV_DEADLINE_FLOOR);
        assert_eq!(b.cap_pct, 100);
        assert!(e.cap_pct < b.cap_pct && e.headroom_pct < b.headroom_pct && e.rate_limit_us > b.rate_limit_us);
        // Every request is inside the kernel's hard ranges: the table alone
        // never provokes a refusal.
        for p in [Preset::Performance, Preset::Balanced, Preset::Endurance] {
            let r = profile(p);
            assert!((POLICY_HEADROOM_MIN_PCT..=POLICY_HEADROOM_MAX_PCT).contains(&r.headroom_pct), "{p:?}");
            assert!((POLICY_RATE_LIMIT_MIN_US..=POLICY_RATE_LIMIT_MAX_US).contains(&r.rate_limit_us), "{p:?}");
            assert!((1..=100).contains(&r.cap_pct));
        }
    }

    #[test]
    fn names_and_modes_map_to_presets() {
        for (n, p) in [("performance", Preset::Performance), ("balanced", Preset::Balanced), ("endurance", Preset::Endurance)] {
            assert_eq!(Preset::from_name(n.as_bytes()), Some(p));
            assert_eq!(p.name(), n);
        }
        assert_eq!(Preset::from_name(b"turbo"), None);
        assert_eq!(Preset::from_mode(0), Some(Preset::Performance));
        assert_eq!(Preset::from_mode(2), Some(Preset::Endurance));
        assert_eq!(Preset::from_mode(3), None);
    }

    #[test]
    fn a_cap_rounds_up_and_never_leaves_the_table() {
        assert_eq!(cap_index(4, 100), 3);
        assert_eq!(cap_index(4, 60), 2);
        assert_eq!(cap_index(4, 1), 1, "rounded up: 1% of three steps is one step, not zero");
        assert_eq!(cap_index(1, 50), 0);
        assert_eq!(cap_index(0, 50), 0);
        for n in 1..=16 {
            for pct in 1..=100 {
                assert!(cap_index(n, pct) < n);
            }
        }
    }
}

#[cfg(test)]
mod decisions {
    use crate::kern::{machine, Kern};
    use crate::policy::*;
    use azos_power::*;

    fn run(k: &mut Kern, p: Preset) -> (Outcome, Vec<Decision>) {
        let mut log = Vec::new();
        let o = apply(k, &profile(p), &mut |d| log.push(*d));
        (o, log)
    }

    fn range(domain: u32, min: u32, max: u32) -> Step {
        Step::OppRange { domain, min, max }
    }

    /// A clean machine: every call applied, in the order the table says, and
    /// the kernel ends up in the profile's state.
    #[test]
    fn balanced_on_a_clean_machine_applies_every_call_in_order() {
        let mut k = Kern::new(machine(&[1_000_000, 1_000_000]));
        let (o, log) = run(&mut k, Preset::Balanced);
        assert_eq!(o, Outcome { applied: 6, ..Outcome::default() });
        let steps: Vec<Step> = log.iter().map(|d| d.step).collect();
        assert_eq!(steps, [
            Step::Governor(POLICY_GOV_DEADLINE_FLOOR as u32),
            Step::Headroom(25),
            Step::RateLimit(4_000),
            Step::IdleDepth(POLICY_IDLE_UNLIMITED),
            range(0, 0, 3),
            range(1, 0, 3),
        ]);
        assert!(log.iter().all(|d| d.verdict == Verdict::Applied && !d.retry));
        assert_eq!(k.state(POLICY_STATE_GOVERNOR as u32), POLICY_GOV_DEADLINE_FLOOR);
    }

    /// Endurance caps a domain below its WCET reference clock: the kernel
    /// refuses (I6), the server raises the cap to the floor and the second
    /// call is applied; a domain whose cap is legal is left alone.
    #[test]
    fn a_cap_below_the_safety_floor_is_answered_with_the_floor() {
        // Domain 0 may be capped at OPP 2 (reference 1 GHz); domain 1's
        // reference is the top OPP, so OPP 2 is below its floor.
        let mut k = Kern::new(machine(&[1_000_000, 2_000_000]));
        let (o, log) = run(&mut k, Preset::Endurance);
        assert_eq!((o.refused, o.fallbacks, o.applied, o.failed), (1, 1, 6, false));
        let r: Vec<&Decision> = log.iter().filter(|d| matches!(d.step, Step::OppRange { .. })).collect();
        assert_eq!(r.len(), 3);
        assert_eq!((r[0].step, r[0].verdict, r[0].retry), (range(0, 0, 2), Verdict::Applied, false));
        assert_eq!((r[1].step, r[1].verdict), (range(1, 0, 2), Verdict::Refused(POLICY_REFUSED_SAFETY_FLOOR)));
        assert_eq!((r[2].step, r[2].verdict, r[2].retry), (range(1, 0, 3), Verdict::Applied, true));
        assert_eq!(k.policy.opp_range(0), (0, 2));
        assert_eq!(k.policy.opp_range(1), (0, 3), "the cap sits at the safety floor, not below it");
        assert_eq!(k.policy.refused(), 1, "the kernel recorded the refusal");
    }

    /// Admitted real-time reservations lift the floor (I1): the server asks
    /// for no cap when the kernel says the cap breaks a deadline.
    #[test]
    fn a_cap_below_the_deadline_floor_is_answered_with_no_cap() {
        let mut k = Kern::new(machine(&[250_000]));
        k.admitted_ppm = 600_000;
        let (o, log) = run(&mut k, Preset::Endurance);
        assert_eq!((o.refused, o.fallbacks, o.failed), (1, 1, false));
        let last = log.last().unwrap();
        assert_eq!((last.step, last.verdict, last.retry), (range(0, 0, 3), Verdict::Applied, true));
        assert_eq!(k.policy.opp_range(0), (0, 3));
        assert_eq!(k.policy.refused_by(POLICY_REFUSED_DEADLINE_FLOOR as usize), 1);
    }

    /// No energy model: nothing to govern, and the server asks for nothing.
    #[test]
    fn a_machine_with_no_model_is_not_asked() {
        let mut k = Kern::new(azos_energy::EnergyModel::NONE);
        let (o, log) = run(&mut k, Preset::Endurance);
        assert!(o.no_model && !o.failed);
        assert_eq!((k.calls, log.len(), o.applied), (0, 0, 0));
    }

    /// A call that fails outright (no capability) stops the run: the other
    /// setters would fail the same way.
    #[test]
    fn a_failed_call_stops_the_run() {
        let mut k = Kern::new(machine(&[1_000_000]));
        k.fail_governor = Some(1);
        let (o, log) = run(&mut k, Preset::Balanced);
        assert!(o.failed);
        assert_eq!((log.len(), k.calls), (1, 1));
        assert_eq!(log[0].verdict, Verdict::Failed(1));
    }

    /// One level of fallback, no more: a kernel that refuses everything sees
    /// each setter at most twice.
    #[test]
    fn a_refused_fallback_is_not_retried() {
        struct Never(u32);
        impl PowerPolicy for Never {
            fn set_governor(&mut self, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_GOVERNOR }
            fn set_opp_range(&mut self, _: u32, _: u32, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_SAFETY_FLOOR }
            fn set_headroom(&mut self, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_HEADROOM }
            fn set_rate_limit(&mut self, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_RATE_LIMIT }
            fn set_idle_depth(&mut self, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_IDLE_DEPTH }
            fn set_power_cap(&mut self, _: u32, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_RANGE }
            fn set_parked(&mut self, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_PARK }
            fn set_qos_domains(&mut self, _: u32, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_QOS }
            fn report_battery(&mut self, _: u32, _: u32) -> u32 { self.0 += 1; POLICY_REFUSED_BATTERY }
            fn state(&self, sel: u32) -> u64 {
                match sel as u64 {
                    POLICY_STATE_DOMAINS => 1,
                    s if s >= POLICY_STATE_DOMAIN_BASE => 4 | 3 << 32,
                    _ => 0,
                }
            }
            fn stats(&self, _: u32) -> u64 { 0 }
        }
        let mut n = Never(0);
        let mut seen = 0;
        let o = apply(&mut n, &profile(Preset::Endurance), &mut |_| seen += 1);
        assert_eq!(o.applied, 0);
        assert_eq!(n.0, seen);
        assert!(n.0 <= 2 * 5, "{} calls for five setters", n.0);
        assert!(o.fallbacks >= 1 && o.fallbacks <= 5);
    }

    /// The table, row by row.
    #[test]
    fn the_fallback_table() {
        let info = Some(DomainInfo { n_opps: 4, cur: 255, min: 0, max: 255, safety: 3, n_idle: 3 });
        let r = |s, why, i| fallback(s, why, i);
        assert_eq!(r(range(0, 0, 1), POLICY_REFUSED_SAFETY_FLOOR, info), Some(range(0, 0, 3)));
        assert_eq!(r(range(0, 2, 2), POLICY_REFUSED_SAFETY_FLOOR, info), Some(range(0, 2, 3)), "min kept");
        assert_eq!(r(range(0, 3, 3), POLICY_REFUSED_SAFETY_FLOOR, info), None, "already at the floor");
        assert_eq!(r(range(0, 0, 1), POLICY_REFUSED_DEADLINE_FLOOR, info), Some(range(0, 0, 3)));
        assert_eq!(r(range(0, 0, 1), POLICY_REFUSED_SAFETY_FLOOR, None), None, "no domain word, no guess");
        assert_eq!(r(range(0, 0, 9), POLICY_REFUSED_RANGE, info), None);
        assert_eq!(r(range(7, 0, 1), POLICY_REFUSED_DOMAIN, info), None);
        assert_eq!(r(Step::Governor(2), POLICY_REFUSED_NO_MODEL, None), None);
        assert_eq!(r(Step::Governor(1), POLICY_REFUSED_GOVERNOR, None), Some(Step::Governor(0)));
        assert_eq!(r(Step::Governor(0), POLICY_REFUSED_GOVERNOR, None), None, "Fixed is the floor");
        assert_eq!(r(Step::Headroom(5), POLICY_REFUSED_HEADROOM, None), Some(Step::Headroom(25)));
        assert_eq!(r(Step::RateLimit(1), POLICY_REFUSED_RATE_LIMIT, None), Some(Step::RateLimit(4_000)));
        assert_eq!(r(Step::IdleDepth(9), POLICY_REFUSED_IDLE_DEPTH, None), Some(Step::IdleDepth(POLICY_IDLE_UNLIMITED)));
    }

    /// The serve loop re-applies when another client moves the policy, and
    /// only then: applying twice leaves the same signature even when a
    /// fallback was needed.
    #[test]
    fn the_signature_moves_only_when_someone_else_does() {
        let mut k = Kern::new(machine(&[1_000_000, 2_000_000]));
        run(&mut k, Preset::Endurance);
        let sig = signature(&k);
        run(&mut k, Preset::Endurance);
        assert_eq!(signature(&k), sig, "a second apply, fallback included, is a fixed point");
        assert_eq!(k.set_headroom(60), 0);
        assert_ne!(signature(&k), sig);
        run(&mut k, Preset::Endurance);
        assert_eq!(signature(&k), sig, "re-applied");
    }

    #[test]
    fn domain_words_unpack() {
        let w = 4 | 7 << 8 | 1 << 16 | 255 << 24 | 3 << 32 | 3 << 40;
        assert_eq!(DomainInfo::of(w), DomainInfo { n_opps: 4, cur: 7, min: 1, max: 255, safety: 3, n_idle: 3 });
    }
}

#[cfg(test)]
mod wire {
    use crate::kern::{machine, Kern};
    use azos_devif::{outcome, IdlError, MsgDesc, Out, Power, PowerCall, PowerClient, PowerIdl, Transport};
    use azos_power::*;
    use std::cell::RefCell;

    /// The kernel's `Power` interface over the model of its limits: the policy
    /// ops are the model's, the rest of the interface is not modelled.
    struct Host(Kern);

    /// A verdict as the interface answers it.
    fn out(v: u32) -> Out<u32> {
        match Verdict::of(v) {
            Verdict::Applied => Out::ok(0),
            Verdict::Refused(why) => Out::new(outcome::REFUSED, why),
            Verdict::Failed(code) => Out::err(code),
        }
    }

    fn word(w: u64) -> Out<u64> {
        if w == WORD_ERR { Out::err(outcome::BAD_ARGUMENT) } else { Out::ok(w) }
    }

    impl Power for Host {
        fn shutdown(&mut self) -> Out<()> { Out::err(outcome::UNSUPPORTED) }
        fn reboot(&mut self) -> Out<()> { Out::err(outcome::UNSUPPORTED) }
        fn suspend(&mut self) -> Out<u32> { Out::err(outcome::UNSUPPORTED) }
        fn sched_hz(&self) -> Out<u64> { Out::err(outcome::UNSUPPORTED) }
        fn set_sched_hz(&mut self, _hz: u64) -> Out<()> { Out::err(outcome::UNSUPPORTED) }
        fn set_governor(&mut self, gov: u32) -> Out<u32> { out(self.0.set_governor(gov)) }
        fn set_opp_range(&mut self, domain: u32, min: u32, max: u32) -> Out<u32> {
            out(self.0.set_opp_range(domain, min, max))
        }
        fn set_headroom(&mut self, pct: u32) -> Out<u32> { out(self.0.set_headroom(pct)) }
        fn set_rate_limit(&mut self, us: u32) -> Out<u32> { out(self.0.set_rate_limit(us)) }
        fn set_idle_depth(&mut self, depth: u32) -> Out<u32> { out(self.0.set_idle_depth(depth)) }
        fn set_power_cap(&mut self, domain: u32, mw: u32) -> Out<u32> { out(self.0.set_power_cap(domain, mw)) }
        fn set_parked(&mut self, mask: u32) -> Out<u32> { out(self.0.set_parked(mask)) }
        fn set_qos_domains(&mut self, class: u32, domains: u32) -> Out<u32> {
            out(self.0.set_qos_domains(class, domains))
        }
        fn report_battery(&mut self, soc_pct: u32, level: u32) -> Out<u32> {
            out(self.0.report_battery(soc_pct, level))
        }
        fn state(&self, sel: u32) -> Out<u64> { word(self.0.state(sel)) }
        fn stats(&self, sel: u32) -> Out<u64> { word(self.0.stats(sel)) }
        fn cpu_online(&mut self, _cpu: u32, _on: u32) -> Out<u32> { Out::err(outcome::UNSUPPORTED) }
        fn sync(&mut self) -> Out<u32> { Out::err(outcome::UNSUPPORTED) }
    }

    /// The request goes through the wire form to the server's dispatcher.
    struct Loop<'a>(&'a RefCell<Host>);

    impl Transport for Loop<'_> {
        fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
            let req = *msg;
            let _ = PowerIdl::dispatch(&mut *self.0.borrow_mut(), &req, msg);
            Ok(())
        }
    }

    #[test]
    fn every_setter_and_reader_round_trips_through_the_wire() {
        let k = RefCell::new(Host(Kern::new(machine(&[1_000_000]))));
        let mut c = PowerClient::new(Loop(&k));
        assert_eq!(c.set_governor(POLICY_GOV_DEADLINE_FLOOR as u32), Ok(Out::ok(0)));
        assert_eq!(c.set_headroom(40), Ok(Out::ok(0)));
        assert_eq!(c.set_rate_limit(8_000), Ok(Out::ok(0)));
        assert_eq!(c.set_idle_depth(1), Ok(Out::ok(0)));
        assert_eq!(c.set_opp_range(0, 1, 3), Ok(Out::ok(0)));
        assert_eq!(c.state(POLICY_STATE_HEADROOM as u32), Ok(Out::ok(40)));
        assert_eq!(c.state(POLICY_STATE_RATE_LIMIT as u32), Ok(Out::ok(8_000)));
        assert_eq!(c.state(POLICY_STATE_IDLE_DEPTH as u32), Ok(Out::ok(1)));
        assert_eq!(
            c.state((POLICY_STATE_DOMAIN_BASE + 0) as u32).map(|o| (o.value >> 16) & 0xFFFF),
            Ok(1 | 3 << 8)
        );
        // A refusal travels as an outcome and its reason, not as a transport error.
        assert_eq!(c.set_headroom(1), Ok(Out::new(outcome::REFUSED, POLICY_REFUSED_HEADROOM)));
        assert_eq!(c.set_opp_range(0, 0, 1), Ok(Out::new(outcome::REFUSED, POLICY_REFUSED_SAFETY_FLOOR)));
        assert_eq!(c.stats(POLICY_STATS_REFUSED as u32), Ok(Out::ok(2)));
        assert_eq!(c.state(0x7FFF), Ok(Out::err(outcome::BAD_ARGUMENT)), "an unknown selector is refused");
        // The interface's other ops reach the model, which has none of them.
        assert_eq!(c.suspend(), Ok(Out::err(outcome::UNSUPPORTED)));
    }

    #[test]
    fn the_op_table_marks_the_readers_idempotent_only() {
        let ops = PowerIdl::OPS;
        assert_eq!(ops.len(), 18);
        for o in ops {
            // `sync` changes nothing a second ask would undo: the second
            // writes back what the first did not, if anything.
            let reader = o.name == "state" || o.name == "stats" || o.name == "sched_hz" || o.name == "sync";
            assert_eq!(o.idempotent(), reader, "{}", o.name);
        }
    }

    #[test]
    fn a_foreign_message_is_refused() {
        let mut k = Host(Kern::new(machine(&[1_000_000])));
        let mut m = MsgDesc { version: azos_idl::MSG_VERSION, n_words: 1, ..MsgDesc::default() };
        m.words[0] = azos_idl::header(0x1234_5678, 1, 1);
        let mut rep = MsgDesc::default();
        assert_eq!(PowerIdl::dispatch(&mut k, &m, &mut rep), Err(IdlError::BadInterface));
    }

    #[test]
    fn verdicts_encode_and_decode() {
        assert_eq!(verdict_of(outcome::OK, 0), 0);
        assert_eq!(verdict_of(outcome::REFUSED, 5), 5);
        assert_eq!(verdict_of(outcome::UNSUPPORTED, 0), VERDICT_FAILED | outcome::UNSUPPORTED);
        assert_eq!(word_of(outcome::DENIED, 7), WORD_ERR);
        assert_eq!(word_of(outcome::OK, 1 << 40), 1 << 40);
        assert_eq!(Verdict::of(0), Verdict::Applied);
        assert_eq!(Verdict::of(POLICY_REFUSED_RANGE), Verdict::Refused(POLICY_REFUSED_RANGE));
        assert_eq!(Verdict::of(VERDICT_FAILED | outcome::BAD_ARGUMENT), Verdict::Failed(outcome::BAD_ARGUMENT));
        for code in 1..POLICY_REFUSED_COUNT as u32 {
            assert_ne!(refusal_name(code), "unknown", "{code}");
        }
    }
}
