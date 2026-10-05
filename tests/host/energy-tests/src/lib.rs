// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for RFC-0051 stages E0–E4.
//!
//! * `util` — both `UtilTracker` variants against synthetic traces: steps,
//!   duty cycles, the PELT half-life, gaps of any length, a clock that goes
//!   backwards, and a long random trace checked against its bounds and against
//!   the same trace replayed in coarser steps.
//! * `model` — `EnergyModel::validate`, one test per fault, and `resolve`'s
//!   source order.
//! * `seams` — invariant I4: with no model, and in `performance` mode with
//!   one, every seam answers today's behaviour, and the idle governor never
//!   asks for its inputs.
//! * `governor` — E3: schedutil, and invariants I1 (deadline floor) and I6
//!   (WCET floor) over every utilisation, admitted load and current OPP.
//! * `idle` — E4: the TEO-like choice and invariant I3 (exit latency within
//!   the real-time slack) over a grid of inputs and random histories.
//! * `parse` — the `SCHED.TOML` energy sections, through the parser a signed
//!   file takes.
//! * `dt` — `azos_dtb::dtb_energy` + `azos_energy::dt::from_dt` on
//!   dtc-built fixtures and on the QEMU DTBs.
//!
//! Time in these tests is in "ticks"; the trackers never see microseconds.

#[cfg(test)]
mod util {
    use azos_energy::util::{y_pow, UtilState, UtilTracker, HALF_LIFE, HISTORY, SCALE, Y_INV};

    const W: u64 = 10_000; // window, ticks
    const P: u64 = 1_024; // PELT period, ticks

    fn both() -> [UtilTracker; 2] {
        [UtilTracker::window(W), UtilTracker::pelt(P)]
    }

    /// Run `st` through `[(duration, running)]` from `t`, updating at every
    /// state change only. Returns the end time.
    fn run(tr: &UtilTracker, st: &mut UtilState, mut t: u64, trace: &[(u64, bool)]) -> u64 {
        for &(d, r) in trace {
            tr.set_running(st, t, r);
            t += d;
        }
        tr.update(st, t);
        t
    }

    #[test]
    fn decay_table_matches_f64() {
        for n in 1..32u64 {
            let want = (0.5f64.powf(n as f64 / 32.0) * 4294967296.0).round();
            assert_eq!(Y_INV[n as usize] as f64, want, "y^{n}");
        }
        assert_eq!(y_pow(0), 1 << 32);
        assert_eq!(y_pow(HALF_LIFE), 1 << 31, "y^32 = 1/2");
        assert_eq!(y_pow(64), 1 << 30);
        assert_eq!(y_pow(33), Y_INV[1] as u64 >> 1);
        assert_eq!(y_pow(32 * 32), 0);
        assert_eq!(y_pow(u64::MAX), 0);
    }

    #[test]
    fn zero_state_reads_idle() {
        for tr in both() {
            let st = UtilState::ZERO;
            assert_eq!(tr.util(&st), 0);
            assert_eq!(tr.util_at(&st, 123_456_789), 0);
        }
    }

    #[test]
    fn new_state_is_aligned_to_the_grid() {
        let tr = UtilTracker::window(W);
        let mut st = tr.new_state(3 * W + 17);
        tr.set_running(&mut st, 3 * W + 17, true);
        tr.update(&mut st, 4 * W);
        // The first window was entered 17 ticks late: 9983 of 10000 busy.
        assert_eq!(tr.util(&st), (9_983 * SCALE as u64 / W) as u32);
    }

    #[test]
    fn window_step_to_busy_shows_after_one_window() {
        let tr = UtilTracker::window(W);
        let mut st = tr.new_state(0);
        tr.set_running(&mut st, 0, true);
        tr.update(&mut st, W - 1);
        assert_eq!(tr.util(&st), 0, "nothing closed yet");
        tr.update(&mut st, W);
        assert_eq!(tr.util(&st), SCALE);
        tr.update(&mut st, 50 * W);
        assert_eq!(tr.util(&st), SCALE);
    }

    #[test]
    fn window_stop_reads_max_of_recent_and_mean_then_zero() {
        let tr = UtilTracker::window(W);
        let mut st = tr.new_state(0);
        let t = run(&tr, &mut st, 0, &[(10 * W, true)]);
        tr.set_running(&mut st, t, false);
        // Closed windows after k idle ones: k zeros, then 1024s.
        let expect = [SCALE, 768, 512, 256, 0, 0];
        for (k, &e) in expect.iter().enumerate() {
            assert_eq!(tr.util_at(&st, t + k as u64 * W), e, "after {k} idle windows");
        }
        assert_eq!(HISTORY, 4);
    }

    #[test]
    fn window_quarter_duty_is_exact() {
        let tr = UtilTracker::window(W);
        let mut st = tr.new_state(0);
        let mut t = 0;
        for _ in 0..20 {
            t = run(&tr, &mut st, t, &[(W / 4, true), (3 * W / 4, false)]);
        }
        assert_eq!(tr.util(&st), SCALE / 4);
    }

    #[test]
    fn fine_grained_half_duty_reads_half() {
        for tr in both() {
            let mut st = tr.new_state(0);
            let mut t = 0;
            for _ in 0..2_000 {
                t = run(&tr, &mut st, t, &[(250, true), (250, false)]);
            }
            let u = tr.util(&st) as i64;
            assert!((u - 512).abs() <= 8, "{tr:?}: {u}");
        }
    }

    #[test]
    fn pelt_half_life_is_32_periods() {
        let tr = UtilTracker::pelt(P);
        let mut st = tr.new_state(0);
        tr.set_running(&mut st, 0, true);
        tr.update(&mut st, 31 * P);
        let u31 = tr.util(&st);
        tr.update(&mut st, 32 * P);
        let u32_ = tr.util(&st);
        assert!(u31 < 512 && u32_ >= 511 && u32_ <= 513, "31: {u31}, 32: {u32_}");
        tr.update(&mut st, 64 * P);
        let u64_ = tr.util(&st) as i64;
        assert!((u64_ - 768).abs() <= 1, "two half-lives: {u64_}");
        tr.update(&mut st, 2_000 * P);
        assert_eq!(tr.util(&st), SCALE, "converges to full");
        // And back down: one half-life of idle halves it.
        tr.set_running(&mut st, 2_000 * P, false);
        tr.update(&mut st, 2_032 * P);
        let d = tr.util(&st) as i64;
        assert!((d - 512).abs() <= 1, "decay: {d}");
    }

    #[test]
    fn pelt_is_monotone_on_a_step() {
        let tr = UtilTracker::pelt(P);
        let mut st = tr.new_state(0);
        tr.set_running(&mut st, 0, true);
        let mut prev = 0;
        for k in 1..500 {
            tr.update(&mut st, k * P / 3);
            let u = tr.util(&st);
            assert!(u >= prev, "at {k}: {u} < {prev}");
            prev = u;
        }
    }

    #[test]
    fn any_gap_is_bounded_and_exact() {
        for tr in both() {
            for &gap in &[0u64, 1, W, 1 << 20, 1 << 40, u64::MAX / 4] {
                let mut busy = tr.new_state(0);
                tr.set_running(&mut busy, 0, true);
                tr.update(&mut busy, gap);
                let mut idle = tr.new_state(0);
                tr.update(&mut idle, gap);
                assert_eq!(tr.util(&idle), 0, "{tr:?} gap {gap}");
                if gap >= 2_000 * P.max(W) {
                    assert_eq!(tr.util(&busy), SCALE, "{tr:?} gap {gap}");
                }
                assert!(tr.util(&busy) <= SCALE);
            }
        }
    }

    #[test]
    fn a_clock_that_goes_back_changes_nothing() {
        for tr in both() {
            let mut st = tr.new_state(0);
            let t = run(&tr, &mut st, 0, &[(5 * W, true)]);
            let before = st;
            tr.update(&mut st, t - 1);
            tr.set_running(&mut st, t - 7, true);
            assert_eq!(st, before, "{tr:?}");
            tr.update(&mut st, t);
            assert_eq!(st, before, "same instant: {tr:?}");
        }
    }

    #[test]
    fn util_at_does_not_mutate_and_agrees_with_update() {
        for tr in both() {
            let mut st = tr.new_state(0);
            let t = run(&tr, &mut st, 0, &[(3 * W, true), (W / 2, false)]);
            let frozen = st;
            let later = t + 7 * W / 3;
            let peek = tr.util_at(&st, later);
            assert_eq!(st, frozen);
            tr.update(&mut st, later);
            assert_eq!(peek, tr.util(&st), "{tr:?}");
        }
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    /// A long random trace: every reading within bounds, and the same trace
    /// with extra updates in the middle of each constant interval (the tick)
    /// reads the same (exactly for the window; within 2 for PELT, whose
    /// per-period rounding differs from one closed-form step).
    #[test]
    fn random_trace_bounded_and_split_invariant() {
        for tr in both() {
            let mut rng = Lcg(0x5eed);
            let (mut a, mut b) = (tr.new_state(0), tr.new_state(0));
            let mut t = 0u64;
            let mut worst = 0i64;
            for _ in 0..20_000 {
                let d = 1 + rng.next() % (3 * W);
                let r = rng.next() % 3 != 0;
                tr.set_running(&mut a, t, r);
                tr.set_running(&mut b, t, r);
                // b also gets tick updates inside the interval.
                let mut s = t;
                while s + 997 < t + d {
                    s += 997;
                    tr.update(&mut b, s);
                }
                t += d;
                tr.update(&mut a, t);
                tr.update(&mut b, t);
                let (ua, ub) = (tr.util(&a), tr.util(&b));
                assert!(ua <= SCALE && ub <= SCALE);
                worst = worst.max((ua as i64 - ub as i64).abs());
            }
            match tr {
                UtilTracker::Window { .. } => assert_eq!(worst, 0, "window"),
                UtilTracker::Pelt { .. } => assert!(worst <= 2, "pelt: {worst}"),
            }
        }
    }
}

#[cfg(test)]
mod model {
    use azos_energy::model::{IdleState, Opp, PerfDomain};
    use azos_energy::{resolve, EnergyModel, ModelFault, ModelSource};

    pub(crate) fn opp(f: u32, c: u16, p: u32) -> Opp {
        Opp { freq_khz: f, capacity: c, power_mw: p }
    }

    /// Two CPUs: little CPU 0, big CPU 1.
    pub(crate) fn valid() -> EnergyModel {
        let mut m = EnergyModel::from_source(ModelSource::Topology);
        let mut little = PerfDomain::new(0b01);
        for o in [opp(400_000, 160, 30), opp(800_000, 320, 90), opp(1_200_000, 480, 190)] {
            little.push_opp(o).unwrap();
        }
        little.push_idle(IdleState::new(b"wfi", 1, 1, 8)).unwrap();
        little.push_idle(IdleState::new(b"retention", 120, 500, 2)).unwrap();
        let mut big = PerfDomain::new(0b10);
        for o in [opp(500_000, 256, 120), opp(1_000_000, 512, 300), opp(2_000_000, 1024, 1100)] {
            big.push_opp(o).unwrap();
        }
        big.push_idle(IdleState::new(b"wfi", 1, 1, 0)).unwrap();
        m.push_domain(little).unwrap();
        m.push_domain(big).unwrap();
        m
    }

    /// `valid()` with domain `d` rebuilt by `f`.
    fn with_domain(d: usize, f: impl FnOnce(&mut PerfDomain)) -> EnergyModel {
        let v = valid();
        let mut m = EnergyModel::from_source(ModelSource::Topology);
        let mut f = Some(f);
        for (i, dom) in v.domains().iter().enumerate() {
            let mut dom = *dom;
            if i == d {
                (f.take().unwrap())(&mut dom);
            }
            m.push_domain(dom).unwrap();
        }
        m
    }

    fn rebuilt(cpus: u32, opps: &[Opp], idle: &[IdleState]) -> PerfDomain {
        let mut d = PerfDomain::new(cpus);
        for o in opps {
            d.push_opp(*o).unwrap();
        }
        for s in idle {
            d.push_idle(*s).unwrap();
        }
        d
    }

    #[test]
    fn a_consistent_model_is_accepted() {
        assert_eq!(valid().validate(2), Ok(()));
        assert_eq!(valid().opp_count(), 6);
        assert_eq!(valid().domain_of(1).unwrap().cpus, 0b10);
    }

    #[test]
    fn every_fault_is_found() {
        let little_opps = valid().domains()[0].opps().to_vec();
        let little_idle = valid().domains()[0].idle_states().to_vec();
        let cases: Vec<(EnergyModel, usize, ModelFault)> = vec![
            (EnergyModel::from_source(ModelSource::Topology), 2, ModelFault::NoDomains),
            (with_domain(0, |d| d.cpus = 0), 2, ModelFault::EmptyCpuMask { domain: 0 }),
            (valid(), 1, ModelFault::CpuAbsent { domain: 1, cpu: 1 }),
            (with_domain(1, |d| d.cpus = 0b11), 2, ModelFault::CpuInTwoDomains { domain: 1, cpu: 0 }),
            (valid(), 3, ModelFault::CpuUncovered { cpu: 2 }),
            (with_domain(0, |d| *d = rebuilt(1, &[], &[])), 2, ModelFault::NoOpps { domain: 0 }),
            (with_domain(0, |d| *d = rebuilt(1, &[opp(0, 10, 1)], &[])), 2, ModelFault::ZeroFrequency { domain: 0, opp: 0 }),
            (with_domain(0, |d| *d = rebuilt(1, &[opp(10, 0, 1)], &[])), 2, ModelFault::CapacityOutOfRange { domain: 0, opp: 0 }),
            (with_domain(0, |d| *d = rebuilt(1, &[opp(10, 1025, 1)], &[])), 2, ModelFault::CapacityOutOfRange { domain: 0, opp: 0 }),
            (with_domain(0, |d| *d = rebuilt(1, &[opp(10, 10, 0)], &[])), 2, ModelFault::ZeroPower { domain: 0, opp: 0 }),
            (with_domain(0, |d| *d = rebuilt(1, &[opp(10, 10, 1), opp(10, 20, 2)], &[])), 2, ModelFault::FrequencyNotIncreasing { domain: 0, opp: 1 }),
            (with_domain(0, |d| *d = rebuilt(1, &[opp(10, 20, 1), opp(20, 10, 2)], &[])), 2, ModelFault::CapacityDecreasing { domain: 0, opp: 1 }),
            (with_domain(0, |d| *d = rebuilt(1, &[opp(10, 10, 5), opp(20, 20, 5)], &[])), 2, ModelFault::PowerNotIncreasing { domain: 0, opp: 1 }),
            (with_domain(1, |d| *d = rebuilt(2, &[opp(10, 1000, 5)], &[])), 2, ModelFault::NoFullCapacity),
            (with_domain(0, |d| *d = rebuilt(1, &little_opps, &[IdleState::new(b"", 1, 1, 0)])), 2, ModelFault::IdleNameEmpty { domain: 0, state: 0 }),
            (with_domain(0, |d| *d = rebuilt(1, &little_opps, &[IdleState::new(b"a", 10, 5, 0)])), 2, ModelFault::ResidencyBelowLatency { domain: 0, state: 0 }),
            (with_domain(0, |d| *d = rebuilt(1, &little_opps, &[little_idle[1], little_idle[0]])), 2, ModelFault::ExitLatencyDecreasing { domain: 0, state: 1 }),
            (with_domain(0, |d| *d = rebuilt(1, &little_opps, &[IdleState::new(b"a", 1, 1, 5), IdleState::new(b"b", 2, 2, 6)])), 2, ModelFault::IdlePowerIncreasing { domain: 0, state: 1 }),
        ];
        for (i, (m, cpus, want)) in cases.iter().enumerate() {
            assert_eq!(m.validate(*cpus), Err(*want), "case {i}");
        }
        // Unknown idle power (0) is not compared.
        let m = with_domain(0, |d| *d = rebuilt(1, &little_opps, &[IdleState::new(b"a", 1, 1, 0), IdleState::new(b"b", 2, 2, 6)]));
        assert_eq!(m.validate(2), Ok(()));
    }

    #[test]
    fn pools_are_bounded() {
        let mut d = PerfDomain::new(1);
        for i in 0..azos_energy::model::MAX_OPPS as u32 {
            d.push_opp(opp(i + 1, 1, i + 1)).unwrap();
        }
        assert!(d.push_opp(opp(99, 1, 99)).is_err());
        let mut m = EnergyModel::from_source(ModelSource::Topology);
        for _ in 0..azos_energy::model::MAX_DOMAINS {
            m.push_domain(PerfDomain::new(1)).unwrap();
        }
        assert!(m.push_domain(PerfDomain::new(1)).is_err());
    }

    #[test]
    fn resolution_order() {
        let none = EnergyModel::NONE;
        let bad = with_domain(0, |d| d.cpus = 0);
        let mut dtb = valid();
        dtb.source = ModelSource::Dtb;
        // Topology valid wins over a DTB model.
        let (m, r) = resolve(&valid(), Some(Ok(dtb)), 2);
        assert_eq!((m.source, r.source, r.topology_fault, r.dtb_fault), (ModelSource::Topology, ModelSource::Topology, None, None));
        // Topology invalid: none, and the DTB is NOT consulted.
        let (m, r) = resolve(&bad, Some(Ok(dtb)), 2);
        assert_eq!(m, EnergyModel::NONE);
        assert_eq!((r.source, r.topology_fault, r.dtb_fault), (ModelSource::None, Some(ModelFault::EmptyCpuMask { domain: 0 }), None));
        // No topology model: the DTB's.
        let (m, r) = resolve(&none, Some(Ok(dtb)), 2);
        assert_eq!((m.source, r.source), (ModelSource::Dtb, ModelSource::Dtb));
        assert_eq!(m.domains(), dtb.domains());
        // No topology model, DTB invalid / unbuildable: none.
        let (m, r) = resolve(&none, Some(Ok(bad)), 2);
        assert_eq!((m, r.dtb_fault), (EnergyModel::NONE, Some(ModelFault::EmptyCpuMask { domain: 0 })));
        let (m, r) = resolve(&none, Some(Err(ModelFault::DtPartialTables)), 2);
        assert_eq!((m, r.dtb_fault), (EnergyModel::NONE, Some(ModelFault::DtPartialTables)));
        // Neither.
        let (m, r) = resolve(&none, None, 2);
        assert_eq!((m, r.source, r.topology_fault, r.dtb_fault), (EnergyModel::NONE, ModelSource::None, None, None));
    }
}

#[cfg(test)]
mod seams {
    use azos_energy::seams::{GOVERNOR, IDLE_GOVERNOR, PLACEMENT};
    use azos_energy::{EnergyMode, EnergyModel, Governor, IdleChoice, IdleGovernor, Placement, Seams};

    const MODES: [EnergyMode; 3] = [EnergyMode::Performance, EnergyMode::Balanced, EnergyMode::Endurance];

    /// I4: no model → today's behaviour, whatever the mode.
    #[test]
    fn no_model_is_today_in_every_mode() {
        for mode in MODES {
            assert_eq!(Seams::select(&EnergyModel::NONE, mode), Seams::TODAY, "{mode:?}");
        }
        assert_eq!(
            Seams::TODAY,
            Seams { placement: Placement::Legacy, governor: Governor::Fixed, idle: IdleGovernor::WfiOnly }
        );
        assert_eq!((PLACEMENT, GOVERNOR, IDLE_GOVERNOR), (Placement::Legacy, Governor::Fixed, IdleGovernor::WfiOnly));
    }

    /// `performance` with a model is today's seams; `balanced` and
    /// `endurance` opt in to the E3/E4 governors (and only they do).
    #[test]
    fn only_a_non_performance_mode_with_a_model_opts_in() {
        let m = crate::model::valid();
        assert_eq!(Seams::select(&m, EnergyMode::Performance), Seams::TODAY);
        let opted = Seams { placement: Placement::Legacy, governor: Governor::DeadlineFloor, idle: IdleGovernor::Teo };
        assert_eq!(Seams::select(&m, EnergyMode::Balanced), opted);
        assert_eq!(Seams::select(&m, EnergyMode::Endurance), opted);
        for d in m.domains() {
            for util in [0, 1, 512, 1024, 4096] {
                assert_eq!(Governor::Fixed.target_opp(d, util, 0, 500_000), None);
            }
        }
    }

    /// `WfiOnly` answers `wfi` without computing its inputs: the kernel's idle
    /// loops pass the CPU-id read and the timer query lazily, and the default
    /// image's code is the bare `wfi` only because neither is called.
    #[test]
    fn wfi_only_never_asks_for_its_inputs() {
        let c = IdleGovernor::WfiOnly.select_state(
            || -> usize { panic!("cpu id asked for") },
            || -> Option<u64> { panic!("next timer asked for") },
        );
        assert_eq!(c, IdleChoice::Wfi);
    }

    #[test]
    fn mode_spelling_round_trips() {
        for mode in MODES {
            assert_eq!(EnergyMode::from_str(mode.as_str().as_bytes()), Some(mode));
        }
        assert_eq!(EnergyMode::from_str(b"turbo"), None);
        assert_eq!(EnergyMode::from_str(b"Performance"), None);
    }
}

#[cfg(test)]
mod parse {
    use azos_energy::{EnergyMode, EnergySpec, ModelSource};
    use azos_topology::parser::{parse_energy, parse_sched};
    use azos_topology::{ParseError, Topology};

    const FAKE: &[u8] = br#"
[energy]
mode = "balanced"   # a comment

[energy.domain.little]
cpus = 1
opps = [
  { freq_khz = 400000, capacity = 160, power_mw = 30 },   # slowest
  # a comment line inside the array

  { freq_khz = 800000, capacity = 320, power_mw = 90 }, { freq_khz = 1200000, capacity = 480, power_mw = 190 },
]
idle = [ { name = "wfi", exit_latency_us = 1, target_residency_us = 1, power_mw = 8 },
  { name = "retention", exit_latency_us = 120, target_residency_us = 500, power_mw = 2 } ]

[energy.domain.big]
cpus = 2
opps = [ { freq_khz = 500000, capacity = 256, power_mw = 120 }, { freq_khz = 1000000, capacity = 512, power_mw = 300 }, { freq_khz = 2000000, capacity = 1024, power_mw = 1100 } ]
idle = [ { name = "wfi", exit_latency_us = 1, target_residency_us = 1 } ]
"#;

    #[test]
    fn wcet_ref_khz_is_read_per_domain() {
        let text = "[energy]\nmode = \"balanced\"\n[energy.domain.a]\ncpus = 1\nwcet_ref_khz = 600000\nopps = [ { freq_khz = 400000, capacity = 1024, power_mw = 3 } ]\n";
        let spec = parse_energy(text.as_bytes()).expect("parses");
        assert_eq!(spec.model.domains()[0].wcet_ref_khz, 600_000);
        assert_eq!(crate::model::valid().domains()[0].wcet_ref_khz, 0);
    }

    #[test]
    fn the_energy_sections_parse_to_the_declared_model() {
        let spec = parse_energy(FAKE).expect("parses");
        assert_eq!(spec.mode, EnergyMode::Balanced);
        let mut want = crate::model::valid();
        want.source = ModelSource::Topology;
        assert_eq!(spec.model, want);
        assert_eq!(spec.model.validate(2), Ok(()));
        assert_eq!(spec.model.domains()[0].idle_states()[1].name(), b"retention");
    }

    #[test]
    fn no_energy_section_is_performance_and_no_model() {
        assert_eq!(parse_energy(b"[sched]\npartition_window_us = 1000\n"), Ok(EnergySpec::DEFAULT));
        assert_eq!(parse_energy(b""), Ok(EnergySpec::DEFAULT));
        assert_eq!(parse_energy(b"[energy]\n").unwrap(), EnergySpec::DEFAULT);
    }

    /// `parse_sched` reads the classes AND the energy sections of one file.
    #[test]
    fn parse_sched_carries_the_energy_spec() {
        let mut text = b"[class.rt]\npolicy = \"fifo\"\npriority_range = [0, 7]\ncpu_budget_min_pct = 10\ncpu_budget_max_pct = 50\n\n[sched]\npartition_window_us = 5000\n".to_vec();
        text.extend_from_slice(FAKE);
        let text: &'static [u8] = Box::leak(text.into_boxed_slice());
        let mut topo: Box<Topology<'static>> = Box::new(Topology::empty());
        parse_sched(text, &mut topo).expect("parses");
        assert_eq!(topo.classes_len(), 1);
        assert_eq!(topo.sched_config().partition_window_us, 5000);
        assert_eq!(topo.energy().mode, EnergyMode::Balanced);
        assert_eq!(topo.energy().model.domains().len(), 2);
    }

    fn err(text: &str) -> ParseError {
        parse_energy(text.as_bytes()).expect_err(text)
    }

    #[test]
    fn malformed_sections_are_refused() {
        let d = "[energy.domain.a]\n";
        assert_eq!(err("[energy]\nmode = \"turbo\"\n"), ParseError::UnknownEnumValue);
        assert_eq!(err("[energy]\nspeed = 3\n"), ParseError::UnknownField);
        assert_eq!(err(&format!("{d}cores = 1\n")), ParseError::UnknownField);
        assert_eq!(err(&format!("{d}cpus = 4294967296\n")), ParseError::BadValue);
        assert_eq!(err(&format!("{d}opps = [ {{ freq_khz = 1, capacity = 1 }} ]\n")), ParseError::MissingField);
        assert_eq!(err(&format!("{d}opps = [ {{ freq_khz = 1, capacity = 1, power_mw = 1, volts = 1 }} ]\n")), ParseError::UnknownField);
        assert_eq!(err(&format!("{d}opps = [ {{ freq_khz = 1, capacity = 1, power_mw = 1, power_mw = 2 }} ]\n")), ParseError::BadValue);
        assert_eq!(err(&format!("{d}opps = [ {{ freq_khz = 1, capacity = 65536, power_mw = 1 }} ]\n")), ParseError::BadValue);
        assert_eq!(err(&format!("{d}opps = [ {{ freq_khz = \"fast\", capacity = 1, power_mw = 1 }} ]\n")), ParseError::TypeMismatch);
        assert_eq!(err(&format!("{d}idle = [ {{ exit_latency_us = 1, target_residency_us = 1 }} ]\n")), ParseError::MissingField);
        assert_eq!(err(&format!("{d}idle = [ {{ name = 3, exit_latency_us = 1, target_residency_us = 1 }} ]\n")), ParseError::TypeMismatch);
        assert_eq!(err(&format!("{d}opps = 3\n")), ParseError::BadValue);
        assert_eq!(err(&format!("{d}opps = [ {{ freq_khz = 1, capacity = 1, power_mw = 1 }} ] x\n")), ParseError::BadValue);
    }

    /// A `[` whose `]` never comes is refused, never a hang (the EOF guard).
    #[test]
    fn an_unterminated_array_is_refused() {
        for text in [
            "[energy.domain.a]\nopps = [\n",
            "[energy.domain.a]\nopps = [ { freq_khz = 1, capacity = 1, power_mw = 1 },",
            "[energy.domain.a]\nopps = [\n  { freq_khz = 1, capacity = 1, power_mw = 1 },\n\n# eof\n",
        ] {
            assert_eq!(err(text), ParseError::UnterminatedArray, "{text:?}");
        }
    }

    #[test]
    fn pools_overflow_is_refused() {
        let mut t = String::from("[energy.domain.a]\nopps = [\n");
        for i in 1..=17 {
            t += &format!("{{ freq_khz = {i}, capacity = 1, power_mw = {i} }},\n");
        }
        t += "]\n";
        assert_eq!(err(&t), ParseError::TooManyEnergyEntries);
        let five = (0..5).map(|i| format!("[energy.domain.d{i}]\ncpus = 1\n")).collect::<String>();
        assert_eq!(err(&five), ParseError::TooManyEnergyEntries);
    }
}

#[cfg(test)]
mod dt {
    use azos_dtb::dtb_energy;
    use azos_energy::dt::from_dt;
    use azos_energy::model::Opp;
    use azos_energy::{EnergyModel, ModelFault, ModelSource};

    fn fixture(name: &str) -> Vec<u8> {
        let p = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let mut v = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
        // `dtb_energy` reads big-endian words unaligned-safely, but give it
        // an aligned copy anyway, as firmware does.
        v.extend_from_slice(&[0; 8]);
        v
    }

    fn model_of(name: &str) -> Option<Result<EnergyModel, ModelFault>> {
        let blob = fixture(name);
        let dt = unsafe { dtb_energy(blob.as_ptr()) }.expect("readable blob");
        from_dt(&dt)
    }

    #[test]
    fn raw_tables_of_the_two_cluster_fixture() {
        let blob = fixture("energy-2cluster.dtb");
        let dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        assert_eq!((dt.cpus().len(), dt.tables().len(), dt.idle_states().len(), dt.truncated), (4, 2, 2, false));
        // The disabled OPP is not read; the order is the document's.
        let hz: Vec<u64> = dt.tables()[0].opps[..dt.tables()[0].n_opps as usize].iter().map(|o| o.hz).collect();
        assert_eq!(hz, [1_000_000_000, 500_000_000]);
        assert!(dt.tables().iter().all(|t| t.shared));
        // Two-cell opp-microwatt is summed.
        assert_eq!(dt.tables()[1].opps[1].microwatt, 1_800_000);
        assert_eq!(dt.cpus()[0].n_idle, 2);
        assert_eq!(dt.cpus()[2].capacity_dmips_mhz, 1024);
        assert_eq!(&dt.idle_states()[0].name[..dt.idle_states()[0].name_len as usize], b"retention");
        assert_eq!((dt.idle_states()[1].exit_latency_us, dt.idle_states()[1].min_residency_us), (500, 3000));
    }

    #[test]
    fn two_cluster_fixture_gives_a_valid_model() {
        let m = model_of("energy-2cluster.dtb").expect("has tables").expect("builds");
        assert_eq!(m.source, ModelSource::Dtb);
        assert_eq!(m.validate(4), Ok(()));
        let d = m.domains();
        assert_eq!(d.len(), 2);
        assert_eq!((d[0].cpus, d[1].cpus), (0b0011, 0b1100));
        // little: dmips 512 x 1000 MHz against big 1024 x 2000 MHz: 256 at top.
        assert_eq!(d[0].opps(), &[Opp { freq_khz: 500_000, capacity: 128, power_mw: 100 }, Opp { freq_khz: 1_000_000, capacity: 256, power_mw: 400 }]);
        assert_eq!(d[1].opps(), &[Opp { freq_khz: 1_000_000, capacity: 512, power_mw: 600 }, Opp { freq_khz: 2_000_000, capacity: 1024, power_mw: 1800 }]);
        let idle: Vec<(&[u8], u32, u32, u32)> =
            d[0].idle_states().iter().map(|s| (s.name(), s.exit_latency_us, s.target_residency_us, s.power_mw)).collect();
        assert_eq!(idle, [(&b"retention"[..], 40, 100, 0), (&b"state1"[..], 500, 3000, 0)]);
        assert_eq!(d[1].idle_states().len(), 1);
    }

    #[test]
    fn a_private_table_is_a_domain_per_cpu() {
        let m = model_of("energy-private.dtb").unwrap().unwrap();
        let masks: Vec<u32> = m.domains().iter().map(|d| d.cpus).collect();
        assert_eq!(masks, [1, 2, 4, 8]);
        assert_eq!(m.validate(4), Ok(()));
    }

    /// No `opp-microwatt`: power 0, refused by validation (no power is
    /// derived from anything else).
    #[test]
    fn no_power_in_the_dtb_is_refused() {
        let m = model_of("energy-nopower.dtb").unwrap().unwrap();
        assert_eq!(m.validate(4), Err(ModelFault::ZeroPower { domain: 0, opp: 0 }));
    }

    /// The QEMU machines carry no OPP table: the DTB source is "nothing",
    /// and the CPU nodes are still all found.
    #[test]
    fn qemu_dtbs_carry_no_model() {
        for (f, cpus) in [("qemu-riscv64-virt.dtb", 4), ("qemu-riscv64-virt-aia.dtb", 4), ("qemu-aarch64-virt.dtb", 2)] {
            let blob = std::fs::read(format!("{}/../dtb-tests/fixtures/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
            let dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
            assert_eq!((dt.cpus().len(), dt.tables().len(), dt.idle_states().len()), (cpus, 0, 0), "{f}");
            assert!(from_dt(&dt).is_none(), "{f}");
        }
    }

    #[test]
    fn partial_and_dangling_tables_are_refused() {
        let blob = fixture("energy-2cluster.dtb");
        let mut dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let mut partial = dt;
        partial.cpus[3].opp_table = 0;
        assert_eq!(from_dt(&partial), Some(Err(ModelFault::DtPartialTables)));
        dt.cpus[1].opp_table = 0xdead;
        assert_eq!(from_dt(&dt), Some(Err(ModelFault::DtUnknownPhandle)));
    }

    #[test]
    fn garbage_is_not_a_blob() {
        let junk = [0u8; 64];
        assert!(unsafe { dtb_energy(junk.as_ptr()) }.is_none());
        assert!(unsafe { dtb_energy(core::ptr::null()) }.is_none());
    }
}

/// Deterministic xorshift for the property tests.
#[cfg(test)]
pub(crate) struct Rng(u64);
#[cfg(test)]
impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[cfg(test)]
mod governor {
    use azos_energy::governor::{
        deadline_floor_opp, due, safety_floor_opp, schedutil_opp, Why, DEADLINE_MARGIN_PCT, PPM,
    };
    use azos_energy::model::{IdleState, PerfDomain};
    use azos_energy::{Governor, SCALE};

    use crate::model::opp;

    /// Four OPPs, 250 MHz .. 2 GHz, capacity 128 .. 1024.
    fn dom(wcet_ref_khz: u32) -> PerfDomain {
        let mut d = PerfDomain::new(0b11);
        for o in [opp(250_000, 128, 20), opp(500_000, 256, 60), opp(1_000_000, 512, 200), opp(2_000_000, 1024, 900)] {
            d.push_opp(o).unwrap();
        }
        d.push_idle(IdleState::new(b"wfi", 1, 1, 0)).unwrap();
        d.wcet_ref_khz = wcet_ref_khz;
        d
    }

    #[test]
    fn schedutil_follows_utilisation_with_headroom() {
        let d = dom(1);
        // Idle at any OPP → the slowest.
        for cur in 0..4 {
            assert_eq!(schedutil_opp(&d, 0, cur), 0);
        }
        // Saturated: one step up per evaluation, then stays at the top.
        let mut cur = 0;
        for want in [1, 2, 3, 3] {
            cur = schedutil_opp(&d, SCALE, cur);
            assert_eq!(cur, want);
        }
        // At the top (1024), 50 % busy = 512 of demand, ×1.25 = 640 → top.
        assert_eq!(schedutil_opp(&d, SCALE / 2, 3), 3);
        // 40 % busy at the top: 410 ×1.25 = 512 → OPP 2 exactly.
        assert_eq!(schedutil_opp(&d, 400, 3), 2);
        // 20 % at the top: 205 ×1.25 = 256 → OPP 1.
        assert_eq!(schedutil_opp(&d, 200, 3), 1);
    }

    #[test]
    fn deadline_floor_covers_admitted_density_with_margin() {
        let d = dom(1);
        assert_eq!(deadline_floor_opp(&d, 0), 0);
        // 10 % of 1024 = 103 ×1.2 = 123 → OPP 0 (128).
        assert_eq!(deadline_floor_opp(&d, 100_000), 0);
        // 20 %: 205 ×1.2 = 246 → OPP 1 (256).
        assert_eq!(deadline_floor_opp(&d, 200_000), 1);
        // 50 %: 615 → top.
        assert_eq!(deadline_floor_opp(&d, 500_000), 3);
        assert_eq!(deadline_floor_opp(&d, PPM as u32), 3);
    }

    #[test]
    fn safety_floor_is_the_first_opp_at_the_wcet_reference() {
        assert_eq!(safety_floor_opp(&dom(0)), 3, "undeclared: the top");
        assert_eq!(safety_floor_opp(&dom(1)), 0);
        assert_eq!(safety_floor_opp(&dom(375_000)), 1, "first OPP at or above it");
        assert_eq!(safety_floor_opp(&dom(500_000)), 1);
        assert_eq!(safety_floor_opp(&dom(3_000_000)), 3, "above every OPP: the top");
    }

    /// I1 and I6 over every utilisation step, admitted load step, current
    /// OPP and WCET reference: `DeadlineFloor`'s capacity covers the admitted
    /// density with its margin, and neither governor goes below the WCET
    /// floor. The decision's reason names the floor that set it.
    #[test]
    fn i1_and_i6_hold_everywhere() {
        let mut n = 0u32;
        for wref in [0, 1, 250_000, 375_000, 600_000, 1_000_000, 2_000_000, 9_000_000] {
            let d = dom(wref);
            // The WCET floor computed here, not by the code under test.
            let sf = d.opps().iter().position(|o| wref != 0 && o.freq_khz >= wref).unwrap_or(3);
            assert!(d.opps()[sf].freq_khz >= wref.min(2_000_000));
            for cur in 0..4 {
                for util in (0..=SCALE + 64).step_by(16) {
                    for ppm in (0..=PPM as u32).step_by(12_500) {
                        let df = Governor::DeadlineFloor.target_opp(&d, util, cur, ppm).unwrap();
                        let cap = d.opps()[df.opp].capacity as u64;
                        let need = ppm as u64 * d.max_capacity() as u64 * (100 + DEADLINE_MARGIN_PCT);
                        assert!(
                            cap * PPM * 100 >= need || df.opp == 3,
                            "I1: wref={wref} cur={cur} util={util} ppm={ppm} → {df:?}"
                        );
                        assert!(df.opp >= sf, "I6 DeadlineFloor: {df:?}");
                        assert!(df.opp >= schedutil_opp(&d, util, cur));
                        let su = Governor::Schedutil.target_opp(&d, util, cur, ppm).unwrap();
                        assert!(su.opp >= sf, "I6 Schedutil: {su:?}");
                        assert_eq!(su.deadline, 0);
                        let w = match df.why {
                            Why::SafetyFloor => df.safety,
                            Why::DeadlineFloor => df.deadline,
                            Why::Schedutil => df.schedutil,
                        };
                        assert_eq!(w, df.opp);
                        assert_eq!(df.opp, df.schedutil.max(df.deadline).max(df.safety));
                        n += 1;
                    }
                }
            }
        }
        assert!(n > 100_000);
    }

    /// The rate limit: due on the first call, then once per interval.
    #[test]
    fn rate_limit() {
        let f = 10_000_000; // 10 MHz counter: 4 ms = 40_000 ticks
        assert!(due(0, 5, f));
        assert!(!due(1_000, 40_999, f));
        assert!(due(1_000, 41_000, f));
        assert!(!due(50_000, 10, f), "a clock behind `last` is not due");
    }
}

#[cfg(test)]
mod idle {
    use azos_energy::idle::{bin_of, reflect, select, timer_candidate, Limit, TeoCpu, STEP};
    use azos_energy::model::{IdleState, MAX_IDLE_STATES};

    use crate::Rng;

    /// wfi, retention (exit 50, residency 200), power-off (exit 400, residency 2000).
    fn states() -> [IdleState; 3] {
        [
            IdleState::new(b"wfi", 1, 1, 0),
            IdleState::new(b"retention", 50, 200, 0),
            IdleState::new(b"off", 400, 2000, 0),
        ]
    }

    #[test]
    fn the_timer_bound_picks_the_deepest_state_that_pays_off() {
        let s = states();
        let h = TeoCpu::NEW;
        assert_eq!(select(&s, 0, u64::MAX, &h), (0, Limit::Timer));
        assert_eq!(select(&s, 199, u64::MAX, &h), (0, Limit::Timer));
        assert_eq!(select(&s, 200, u64::MAX, &h), (1, Limit::Timer));
        assert_eq!(select(&s, 1999, u64::MAX, &h), (1, Limit::Timer));
        assert_eq!(select(&s, 100_000, u64::MAX, &h), (2, Limit::Timer));
        assert_eq!(select(&s[..1], 100_000, u64::MAX, &h), (0, Limit::Timer));
        assert_eq!(select(&[], 100_000, 0, &h), (0, Limit::Timer));
    }

    #[test]
    fn rt_slack_caps_the_exit_latency() {
        let s = states();
        let h = TeoCpu::NEW;
        assert_eq!(select(&s, 100_000, 399, &h), (1, Limit::RtSlack));
        assert_eq!(select(&s, 100_000, 400, &h), (2, Limit::Timer));
        assert_eq!(select(&s, 100_000, 49, &h), (0, Limit::RtSlack));
        assert_eq!(select(&s, 100_000, 0, &h), (0, Limit::RtSlack));
    }

    #[test]
    fn early_wakes_make_it_shallower_and_timer_wakes_restore_it() {
        let s = states();
        let mut h = TeoCpu::NEW;
        // A CPU woken every ~100 us although its timer says 100 ms.
        for _ in 0..32 {
            assert!(reflect(&s, &mut h, 100, 100_000));
        }
        assert_eq!(select(&s, 100_000, u64::MAX, &h), (0, Limit::History));
        // The interrupt source goes quiet: it sleeps to its timer again.
        for _ in 0..32 {
            assert!(!reflect(&s, &mut h, 100_000, 100_000));
        }
        assert_eq!(select(&s, 100_000, u64::MAX, &h), (2, Limit::Timer));
        // Early wakes into the retention bin keep retention, not power-off.
        let mut h = TeoCpu::NEW;
        for _ in 0..32 {
            reflect(&s, &mut h, 500, 100_000);
        }
        assert_eq!(select(&s, 100_000, u64::MAX, &h), (1, Limit::History));
    }

    #[test]
    fn counters_stay_bounded() {
        let s = states();
        let mut h = TeoCpu::NEW;
        for i in 0..10_000u64 {
            reflect(&s, &mut h, i % 3000, 2500);
        }
        for i in 0..MAX_IDLE_STATES {
            assert!(h.hits[i] < 8 * STEP + 8 && h.intercepts[i] < 8 * STEP + 8, "{h:?}");
        }
        assert_eq!(bin_of(&s, 0), 0);
        assert_eq!(bin_of(&s, 200), 1);
        assert_eq!(bin_of(&s, 1_000_000), 2);
    }

    /// I3 over a grid of bounds and slacks and random histories: the state
    /// chosen (past 0) never has an exit latency above the slack, never a
    /// residency above the timer bound, and is never deeper than the
    /// history-free candidate.
    #[test]
    fn i3_holds_for_any_history() {
        let s = states();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut n = 0u32;
        for _ in 0..200 {
            let mut h = TeoCpu::NEW;
            for _ in 0..(rng.next() % 64) {
                let bound = rng.next() % 20_000;
                reflect(&s, &mut h, rng.next() % (bound + 1), bound);
            }
            for sleep in [0u64, 1, 49, 50, 199, 200, 399, 400, 1999, 2000, 50_000, u64::MAX] {
                for slack in [0u64, 1, 49, 50, 51, 399, 400, 401, 10_000, u64::MAX] {
                    let (c, lim) = select(&s, sleep, slack, &h);
                    if c > 0 {
                        assert!(s[c].exit_latency_us as u64 <= slack, "I3: {c} {sleep} {slack} {h:?}");
                        assert!(s[c].target_residency_us as u64 <= sleep);
                    }
                    let (base, _) = timer_candidate(&s, sleep, slack);
                    assert!(c <= base);
                    if c < base {
                        assert_eq!(lim, Limit::History);
                    }
                    n += 1;
                }
            }
        }
        assert!(n > 20_000);
    }
}
