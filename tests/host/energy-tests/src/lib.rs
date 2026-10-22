// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests for energy-aware scheduling, stages E0–E4.
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

/// The CPU map of a boot that started on the first CPU node: logical CPU n is
/// the node whose `reg` is n (the fixtures number their CPUs from 0).
#[cfg(test)]
fn by_reg(reg: u64) -> Option<usize> {
    Some(reg as usize)
}

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
        let (m, r) = resolve(&valid(), Some(Ok(dtb)), None, None, 2);
        assert_eq!((m.source, r.source, r.topology_fault, r.dtb_fault), (ModelSource::Topology, ModelSource::Topology, None, None));
        // Topology invalid: none, and the DTB is NOT consulted.
        let (m, r) = resolve(&bad, Some(Ok(dtb)), None, None, 2);
        assert_eq!(m, EnergyModel::NONE);
        assert_eq!((r.source, r.topology_fault, r.dtb_fault), (ModelSource::None, Some(ModelFault::EmptyCpuMask { domain: 0 }), None));
        // No topology model: the DTB's.
        let (m, r) = resolve(&none, Some(Ok(dtb)), None, None, 2);
        assert_eq!((m.source, r.source), (ModelSource::Dtb, ModelSource::Dtb));
        assert_eq!(m.domains(), dtb.domains());
        // No topology model, DTB invalid / unbuildable: none.
        let (m, r) = resolve(&none, Some(Ok(bad)), None, None, 2);
        assert_eq!((m, r.dtb_fault), (EnergyModel::NONE, Some(ModelFault::EmptyCpuMask { domain: 0 })));
        let (m, r) = resolve(&none, Some(Err(ModelFault::DtPartialTables)), None, None, 2);
        assert_eq!((m, r.dtb_fault), (EnergyModel::NONE, Some(ModelFault::DtPartialTables)));
        // Neither.
        let (m, r) = resolve(&none, None, None, None, 2);
        assert_eq!((m, r.source, r.topology_fault, r.dtb_fault), (EnergyModel::NONE, ModelSource::None, None, None));
    }
}

#[cfg(test)]
mod seams {
    use azos_energy::governor::HEADROOM_PCT;
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
                assert_eq!(Governor::Fixed.target_opp(d, util, 0, 500_000, HEADROOM_PCT), None);
            }
        }
    }

    #[test]
    fn idle_choice_depth_is_the_state_index() {
        assert_eq!(IdleChoice::Wfi.depth(), 0);
        assert_eq!(IdleChoice::Deep(1).depth(), 1);
        assert_eq!(IdleChoice::Deep(3).depth(), 3);
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
        from_dt(&dt, &crate::by_reg)
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
        // State 0 is the implicit `wfi`; listed states follow, each exit
        // latency is entry + exit (20+40, 250+500).
        assert_eq!(
            idle,
            [(&b"wfi"[..], 1, 1, 0), (&b"retention"[..], 60, 100, 0), (&b"state2"[..], 750, 3000, 0)]
        );
        assert_eq!(d[1].idle_states().len(), 2);
    }

    /// The masks name LOGICAL CPUs (audit K2-M4). A boot that started on the
    /// third CPU node (reg 2, a big core) makes it logical 0 and numbers the
    /// rest in document order after it (`azos_percpu::CpuMap`): reg 0 -> 1,
    /// reg 1 -> 2, reg 3 -> 3. The little domain is then CPUs 1-2, the big
    /// one 0 and 3, and each domain's idle states are found by `reg`.
    ///
    /// **Canary.** Build the masks from the node's place in the document
    /// (`1 << i`, the old `dt::build`): red on the masks.
    #[test]
    fn domain_masks_follow_the_logical_cpu_map_not_the_document_order() {
        let blob = fixture("energy-2cluster.dtb");
        let dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let booted_on_2 = |reg: u64| match reg { 2 => Some(0), 0 => Some(1), 1 => Some(2), 3 => Some(3), _ => None };
        let m = from_dt(&dt, &booted_on_2).unwrap().unwrap();
        let d = m.domains();
        assert_eq!((d[0].cpus, d[1].cpus), (0b0110, 0b1001));
        assert_eq!(m.validate(4), Ok(()));
        let first = |mask| azos_energy::dt::domain_first_cpu(&dt, mask, &booted_on_2).map(|c| c.reg);
        assert_eq!((first(d[0].cpus), first(d[1].cpus)), (Some(0), Some(2)));
        // A node no CPU of this boot answers to is in no domain.
        let three = |reg: u64| (reg < 3).then_some(reg as usize);
        let m = from_dt(&dt, &three).unwrap().unwrap();
        assert_eq!((m.domains()[0].cpus, m.domains()[1].cpus), (0b0011, 0b0100));
    }

    /// A disabled CPU node (the JH7110's S7 monitor core, hart 0) is no CPU
    /// of the boot: `dtb_energy` drops it, as `dtb_cpu_regs` does, so it
    /// neither shifts the others nor makes the tables partial.
    ///
    /// **Canary.** Keep disabled CPU nodes in `dtb_energy`: three CPUs become
    /// four and the model is refused as `DtPartialTables`.
    #[test]
    fn a_disabled_cpu_node_is_not_a_cpu_of_the_model() {
        let blob = fixture("energy-disabled.dtb");
        let dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let regs: Vec<u64> = dt.cpus().iter().map(|c| c.reg).collect();
        assert_eq!(regs, [1, 2, 3, 4]);
        // Harts 1..4 are logical 0..3 (booted on hart 1).
        let m = from_dt(&dt, &|reg: u64| reg.checked_sub(1).map(|l| l as usize)).unwrap().unwrap();
        assert_eq!((m.domains()[0].cpus, m.domains()[1].cpus), (0b0011, 0b1100));
    }

    /// The deep-idle inputs the arch idle seam is fed from: each state's
    /// `arm,psci-suspend-param` (one cell; a word that is not one cell is not a
    /// parameter) and `local-timer-stop`.
    #[test]
    fn suspend_params_and_timer_stop_are_read_per_idle_state() {
        let blob = fixture("energy-suspend.dtb");
        let dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let got: Vec<(Option<u32>, bool)> =
            dt.idle_states().iter().map(|s| (s.suspend_param, s.local_timer_stop)).collect();
        assert_eq!(got, [(Some(0), false), (Some(0x0001_0001), true), (None, false), (None, false)]);
        // Four listed states plus the implicit wfi are one more than a domain
        // holds (MAX_IDLE_STATES): such a DTB gets no model, so the arch seam is
        // never given its states.
        assert_eq!(from_dt(&dt, &crate::by_reg).unwrap().unwrap_err(), ModelFault::TooManyIdleStates { domain: 0 });
        // The other fixtures have none.
        let blob = fixture("energy-2cluster.dtb");
        let dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        assert!(dt.idle_states().iter().all(|s| s.suspend_param.is_none() && !s.local_timer_stop));
    }

    /// Entry latency counts toward the exit latency TEO checks against the
    /// real-time slack (I3), and a residency below the exit latency is raised
    /// to it. Canary: drop `entry_latency_us` from `dt::build` and the first
    /// assertion fails.
    #[test]
    fn dt_idle_state_latencies_are_entry_plus_exit() {
        let m = model_of("energy-2cluster.dtb").unwrap().unwrap();
        let s = m.domains()[0].idle_states();
        assert_eq!(s[1].exit_latency_us, 20 + 40);
        assert_eq!(s[2].exit_latency_us, 250 + 500);
        assert!(s.iter().all(|s| s.target_residency_us >= s.exit_latency_us));
        assert_eq!(m.validate(4), Ok(()));
    }

    /// TEO over the table the DTB gave: the deepest listed state whose
    /// residency fits the next timer, and none past the real-time slack.
    #[test]
    fn teo_picks_the_deepest_dt_state_that_fits_the_timer() {
        use azos_energy::idle::{select, Limit, TeoCpu};
        let m = model_of("energy-2cluster.dtb").unwrap().unwrap();
        let s = m.domains()[0].idle_states();
        let h = TeoCpu::NEW;
        // Residencies 1 / 100 / 3000 us.
        assert_eq!(select(s, 50, u64::MAX, &h), (0, Limit::Timer));
        assert_eq!(select(s, 99, u64::MAX, &h), (0, Limit::Timer));
        assert_eq!(select(s, 100, u64::MAX, &h), (1, Limit::Timer));
        assert_eq!(select(s, 2_999, u64::MAX, &h), (1, Limit::Timer));
        assert_eq!(select(s, 3_000, u64::MAX, &h), (2, Limit::Timer));
        assert_eq!(select(s, 1_000_000, u64::MAX, &h), (2, Limit::Timer));
        // Slack: 750 us of exit latency does not fit 749, 60 does.
        assert_eq!(select(s, 1_000_000, 749, &h), (1, Limit::RtSlack));
        assert_eq!(select(s, 1_000_000, 750, &h), (2, Limit::Timer));
        assert_eq!(select(s, 1_000_000, 59, &h), (0, Limit::RtSlack));
        // The single-state domain (big): wfi + retention.
        let big = m.domains()[1].idle_states();
        assert_eq!(select(big, 1_000_000, u64::MAX, &h), (1, Limit::Timer));
    }

    /// The implicit `wfi` takes a table slot: a DTB listing as many states as
    /// the table holds is refused whole, not silently cut short.
    #[test]
    fn the_implicit_wfi_takes_a_table_slot() {
        use azos_energy::model::MAX_IDLE_STATES;
        assert_eq!(MAX_IDLE_STATES, 4, "the fixture lists four states");
        assert_eq!(
            model_of("energy-fullidle.dtb").unwrap().unwrap_err(),
            ModelFault::TooManyIdleStates { domain: 0 }
        );
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
            assert!(from_dt(&dt, &crate::by_reg).is_none(), "{f}");
        }
    }

    #[test]
    fn partial_and_dangling_tables_are_refused() {
        let blob = fixture("energy-2cluster.dtb");
        let mut dt = unsafe { dtb_energy(blob.as_ptr()) }.unwrap();
        let mut partial = dt;
        partial.cpus[3].opp_table = 0;
        assert_eq!(from_dt(&partial, &crate::by_reg), Some(Err(ModelFault::DtPartialTables)));
        dt.cpus[1].opp_table = 0xdead;
        assert_eq!(from_dt(&dt, &crate::by_reg), Some(Err(ModelFault::DtUnknownPhandle)));
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
        deadline_floor_opp, due, safety_floor_opp, schedutil_opp, Why, DEADLINE_MARGIN_PCT, HEADROOM_PCT,
        PPM, RATE_LIMIT_US,
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
            assert_eq!(schedutil_opp(&d, 0, cur, HEADROOM_PCT), 0);
        }
        // Saturated: one step up per evaluation, then stays at the top.
        let mut cur = 0;
        for want in [1, 2, 3, 3] {
            cur = schedutil_opp(&d, SCALE, cur, HEADROOM_PCT);
            assert_eq!(cur, want);
        }
        // At the top (1024), 50 % busy = 512 of demand, ×1.25 = 640 → top.
        assert_eq!(schedutil_opp(&d, SCALE / 2, 3, HEADROOM_PCT), 3);
        // 40 % busy at the top: 410 ×1.25 = 512 → OPP 2 exactly.
        assert_eq!(schedutil_opp(&d, 400, 3, HEADROOM_PCT), 2);
        // 20 % at the top: 205 ×1.25 = 256 → OPP 1.
        assert_eq!(schedutil_opp(&d, 200, 3, HEADROOM_PCT), 1);
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
                        let df = Governor::DeadlineFloor.target_opp(&d, util, cur, ppm, HEADROOM_PCT).unwrap();
                        let cap = d.opps()[df.opp].capacity as u64;
                        let need = ppm as u64 * d.max_capacity() as u64 * (100 + DEADLINE_MARGIN_PCT);
                        assert!(
                            cap * PPM * 100 >= need || df.opp == 3,
                            "I1: wref={wref} cur={cur} util={util} ppm={ppm} → {df:?}"
                        );
                        assert!(df.opp >= sf, "I6 DeadlineFloor: {df:?}");
                        assert!(df.opp >= schedutil_opp(&d, util, cur, HEADROOM_PCT));
                        let su = Governor::Schedutil.target_opp(&d, util, cur, ppm, HEADROOM_PCT).unwrap();
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
        assert!(due(0, 5, f, RATE_LIMIT_US));
        assert!(!due(1_000, 40_999, f, RATE_LIMIT_US));
        assert!(due(1_000, 41_000, f, RATE_LIMIT_US));
        assert!(!due(50_000, 10, f, RATE_LIMIT_US), "a clock behind `last` is not due");
    }
}

#[cfg(test)]
mod idle {
    use azos_energy::idle::{allowed, bin_of, holds_real_time, reflect, select, timer_candidate, Limit, TeoCpu, STEP};
    use azos_energy::model::{IdleState, PerfDomain, MAX_IDLE_STATES};

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

    /// wfi, retention, power-down (loses the context), deeper power-down.
    fn states_with_powerdown() -> PerfDomain {
        let mut d = PerfDomain::new(0b1);
        d.push_idle(IdleState::new(b"wfi", 1, 1, 0)).unwrap();
        d.push_idle(IdleState::new(b"retention", 50, 200, 0)).unwrap();
        d.push_idle(IdleState::new(b"cpu-off", 400, 2000, 0)).unwrap();
        d.push_idle(IdleState::new(b"cluster-off", 900, 6000, 0)).unwrap();
        d
    }

    #[test]
    fn the_context_loss_mark_names_depths_not_indices() {
        let mut d = states_with_powerdown();
        assert!(d.idle_states().iter().all(|s| !s.loses_context), "nothing is marked until the boot says");
        // Bit d-1 is depth d: bits 1 and 2 are the two power-down states.
        d.mark_context_loss(0b110);
        let lost: Vec<bool> = d.idle_states().iter().map(|s| s.loses_context).collect();
        assert_eq!(lost, [false, false, true, true]);
        // Bits past the table are ignored; depth 0 (wfi) cannot be marked.
        let mut e = states_with_powerdown();
        e.mark_context_loss(0b1111_1000);
        assert!(e.idle_states().iter().all(|s| !s.loses_context));
        // The model marks one domain and ignores one that is not there.
        let mut m = azos_energy::EnergyModel::from_source(azos_energy::ModelSource::Dtb);
        m.push_domain(states_with_powerdown()).unwrap();
        m.mark_context_loss(0, 0b010);
        m.mark_context_loss(5, 0b111);
        let lost: Vec<bool> = m.domains()[0].idle_states().iter().map(|s| s.loses_context).collect();
        assert_eq!(lost, [false, false, true, false]);
    }

    /// A CPU with real-time state is never put into a state that loses its
    /// context, even with no reservation deadline to bound it (slack MAX, the
    /// case the slack alone cannot see) and a timer far away. `allowed` is
    /// what the idle task cuts the list with.
    #[test]
    fn a_real_time_cpu_never_picks_a_state_that_loses_context() {
        let mut d = states_with_powerdown();
        d.mark_context_loss(0b110);
        let s = d.idle_states();
        let h = TeoCpu::NEW;
        // Any CPU: the deepest state the timer allows.
        assert_eq!(select(allowed(s, false), 1_000_000, u64::MAX, &h), (3, Limit::Timer));
        // A real-time CPU: retention, the state before the first power-down.
        let rt = allowed(s, true);
        assert_eq!(rt.len(), 2);
        for sleep in [0u64, 199, 200, 2_000, 6_000, 1_000_000, u64::MAX] {
            for slack in [0u64, 50, 400, 900, u64::MAX] {
                let (c, _) = select(rt, sleep, slack, &h);
                assert!(!s[c].loses_context, "picked {c} for sleep {sleep} slack {slack}");
            }
        }
        assert_eq!(select(rt, 1_000_000, u64::MAX, &h), (1, Limit::Timer));
        // No power-down state listed: nothing is cut for anyone.
        let plain = states();
        assert_eq!(allowed(&plain, true).len(), 3);
        // A power-down state at depth 1 cuts everything but wfi.
        let mut e = states_with_powerdown();
        e.mark_context_loss(0b001);
        assert_eq!(allowed(e.idle_states(), true).len(), 1);
    }

    /// A band task bound to the CPU makes it a real-time CPU while it sleeps:
    /// nothing runs, nothing is queued, no reservation is admitted, and its
    /// timer wake still lands here.
    #[test]
    fn a_sleeping_bound_band_task_makes_the_cpu_real_time() {
        let mut d = states_with_powerdown();
        d.mark_context_loss(0b110);
        let s = d.idle_states();
        // Idle CPU, nothing real-time: the deepest state the timer allows.
        let rt = holds_real_time(false, 0, false);
        assert!(!rt);
        assert_eq!(select(allowed(s, rt), 1_000_000, u64::MAX, &TeoCpu::NEW).0, 3);
        // The same CPU with a sleeping band task pinned to it.
        let rt = holds_real_time(false, 1, false);
        assert!(rt);
        let (c, _) = select(allowed(s, rt), 1_000_000, u64::MAX, &TeoCpu::NEW);
        assert!(!s[c].loses_context);
        // Each of the other sources alone is enough.
        assert!(holds_real_time(true, 0, false));
        assert!(holds_real_time(false, 0, true));
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

/// The run-time policy (owner plan, Energy section 8): setters limit-checked
/// against hard floors, every refusal recorded, the floors re-applied at each
/// evaluation. Time-free: the policy is atomics and the arithmetic of
/// `governor`.
#[cfg(test)]
mod policy {
    use azos_abi::power::*;
    use azos_energy::governor::{self, HEADROOM_PCT, RATE_LIMIT_US};
    use azos_energy::model::{IdleState, PerfDomain};
    use azos_energy::policy::{LOG_LEN, NONE_U8};
    use azos_energy::{EnergyModel, Governor, ModelSource, Policy, Refusal, SCALE};

    use crate::model::opp;

    /// One domain: four OPPs (capacity 128 .. 1024), WCET reference 1 GHz
    /// (so the safety floor is OPP 2), three idle states.
    fn machine() -> EnergyModel {
        machine_with(1_000_000)
    }

    /// The same machine with another WCET reference clock (kHz).
    fn machine_with(wcet_ref_khz: u32) -> EnergyModel {
        let mut d = PerfDomain::new(0b11);
        for o in [opp(250_000, 128, 20), opp(500_000, 256, 60), opp(1_000_000, 512, 200), opp(2_000_000, 1024, 900)] {
            d.push_opp(o).unwrap();
        }
        d.push_idle(IdleState::new(b"wfi", 1, 1, 8)).unwrap();
        d.push_idle(IdleState::new(b"retention", 120, 500, 2)).unwrap();
        d.push_idle(IdleState::new(b"off", 900, 4_000, 0)).unwrap();
        d.wcet_ref_khz = wcet_ref_khz;
        let mut m = EnergyModel::from_source(ModelSource::Topology);
        m.push_domain(d).unwrap();
        m
    }

    fn fresh() -> Policy {
        Policy::new(Governor::DeadlineFloor)
    }

    #[test]
    fn boot_state_is_todays_values() {
        let p = Policy::new(Governor::Fixed);
        assert_eq!(p.governor(), Governor::Fixed);
        assert_eq!(p.headroom_pct(), HEADROOM_PCT);
        assert_eq!(p.rate_limit_us() as u64, RATE_LIMIT_US);
        assert_eq!(p.idle_depth(), NONE_U8);
        assert_eq!(p.opp_range(0), (0, NONE_U8));
        assert_eq!((p.applied(), p.refused()), (0, 0));
    }

    #[test]
    fn legal_settings_apply_and_are_counted() {
        let (m, p) = (machine(), fresh());
        assert_eq!(p.set_governor(&m, POLICY_GOV_FIXED as u32), Ok(()));
        assert_eq!(p.governor(), Governor::Fixed);
        assert_eq!(p.set_governor(&m, POLICY_GOV_DEADLINE_FLOOR as u32), Ok(()));
        assert_eq!(p.governor(), Governor::DeadlineFloor);
        assert_eq!(p.set_opp_range(&m, 0, 1, 3, 0), Ok(()));
        assert_eq!(p.opp_range(0), (1, 3));
        assert_eq!(p.set_headroom(40), Ok(()));
        assert_eq!(p.headroom_pct(), 40);
        assert_eq!(p.set_rate_limit(20_000), Ok(()));
        assert_eq!(p.rate_limit_us(), 20_000);
        assert_eq!(p.set_idle_depth(&m, 1), Ok(()));
        assert_eq!(p.idle_depth(), 1);
        assert_eq!(p.set_idle_depth(&m, POLICY_IDLE_UNLIMITED), Ok(()));
        assert_eq!(p.idle_depth(), NONE_U8);
        assert_eq!((p.applied(), p.refused()), (7, 0));
    }

    /// Bare schedutil cannot honour I1 and a machine with no model has
    /// nothing to govern: both refused, nothing changes.
    #[test]
    fn governor_choice_is_limited() {
        let (m, p) = (machine(), fresh());
        assert_eq!(p.set_governor(&m, 1), Err(Refusal::Governor));
        assert_eq!(p.set_governor(&m, 7), Err(Refusal::Governor));
        assert_eq!(p.governor(), Governor::DeadlineFloor);
        assert_eq!(p.set_governor(&EnergyModel::NONE, POLICY_GOV_FIXED as u32), Err(Refusal::NoModel));
        assert_eq!(p.set_opp_range(&EnergyModel::NONE, 0, 0, 1, 0), Err(Refusal::NoModel));
        assert_eq!(p.set_idle_depth(&EnergyModel::NONE, 0), Err(Refusal::NoModel));
        assert_eq!(p.refused(), 5);
    }

    #[test]
    fn malformed_ranges_are_refused() {
        let (m, p) = (machine(), fresh());
        assert_eq!(p.set_opp_range(&m, 1, 0, 3, 0), Err(Refusal::Domain));
        assert_eq!(p.set_opp_range(&m, 0, 3, 2, 0), Err(Refusal::Range), "min > max");
        assert_eq!(p.set_opp_range(&m, 0, 0, 4, 0), Err(Refusal::Range), "past the table");
        assert_eq!(p.opp_range(0), (0, NONE_U8), "a refusal changes nothing");
    }

    /// I6: a cap below the WCET reference OPP would throttle the safety path.
    #[test]
    fn opp_cap_respects_the_safety_floor() {
        let (m, p) = (machine(), fresh());
        assert_eq!(governor::safety_floor_opp(&m.domains()[0]), 2);
        assert_eq!(p.set_opp_range(&m, 0, 0, 1, 0), Err(Refusal::SafetyFloor));
        assert_eq!(p.opp_range(0), (0, NONE_U8));
        assert_eq!(p.set_opp_range(&m, 0, 0, 2, 0), Ok(()), "the floor itself is allowed");
    }

    /// I1: a cap below what the admitted reservations need is refused; the
    /// same cap is legal with none admitted.
    #[test]
    fn opp_cap_respects_the_deadline_floor() {
        let m = machine_with(250_000); // safety floor 0: only I1 binds
        let p = fresh();
        let ppm = 600_000; // 60 % of the top capacity, +20 %: needs OPP 3
        assert_eq!(governor::deadline_floor_opp(&m.domains()[0], ppm), 3);
        assert_eq!(p.set_opp_range(&m, 0, 0, 2, ppm), Err(Refusal::DeadlineFloor));
        assert_eq!(p.set_opp_range(&m, 0, 0, 2, 0), Ok(()));
        assert_eq!(p.set_opp_range(&m, 0, 0, 3, ppm), Ok(()));
    }

    #[test]
    fn headroom_rate_and_idle_depth_have_hard_limits() {
        let (m, p) = (machine(), fresh());
        for bad in [0, POLICY_HEADROOM_MIN_PCT - 1, POLICY_HEADROOM_MAX_PCT + 1, u32::MAX] {
            assert_eq!(p.set_headroom(bad), Err(Refusal::Headroom), "{bad}");
        }
        for ok in [POLICY_HEADROOM_MIN_PCT, POLICY_HEADROOM_MAX_PCT] {
            assert_eq!(p.set_headroom(ok), Ok(()));
        }
        for bad in [0, POLICY_RATE_LIMIT_MIN_US - 1, POLICY_RATE_LIMIT_MAX_US + 1] {
            assert_eq!(p.set_rate_limit(bad), Err(Refusal::RateLimit), "{bad}");
        }
        for ok in [POLICY_RATE_LIMIT_MIN_US, POLICY_RATE_LIMIT_MAX_US] {
            assert_eq!(p.set_rate_limit(ok), Ok(()));
        }
        assert_eq!(p.set_idle_depth(&m, 3), Err(Refusal::IdleDepth), "three states: depth 0..=2");
        assert_eq!(p.set_idle_depth(&m, 2), Ok(()));
    }

    /// A refusal is recorded: counters, per-reason counter and a record with
    /// the setter, the reason and the argument; the ring keeps the newest.
    #[test]
    fn a_refusal_is_recorded() {
        let (m, p) = (machine(), fresh());
        assert_eq!(p.refusal(0), 0);
        assert_eq!(p.set_headroom(5), Err(Refusal::Headroom));
        assert_eq!(p.refused(), 1);
        assert_eq!(p.refused_by(POLICY_REFUSED_HEADROOM as usize), 1);
        let r = p.refusal(0);
        assert_eq!(r >> 56, POWER_OP_POLICY_HEADROOM, "the setter");
        assert_eq!((r >> 48) & 0xFF, POLICY_REFUSED_HEADROOM as u64, "the reason");
        assert_eq!(r & 0xFFFF_FFFF, 5, "the argument");
        assert_eq!(p.set_opp_range(&m, 0, 0, 1, 0), Err(Refusal::SafetyFloor));
        let r = p.refusal(0);
        assert_eq!((r >> 56, (r >> 48) & 0xFF), (POWER_OP_POLICY_OPP_RANGE, POLICY_REFUSED_SAFETY_FLOOR as u64));
        assert_eq!(r & 0xFFFF_FFFF, 1 << 16, "the wire argument: domain 0, min 0, max 1");
        assert_eq!(p.refusal(1) >> 56, POWER_OP_POLICY_HEADROOM, "the older one is still there");
        // Wrap: more refusals than the ring holds; the newest LOG_LEN survive.
        for i in 0..(2 * LOG_LEN as u32) {
            let _ = p.set_rate_limit(i);
        }
        assert_eq!(p.refusal(0) & 0xFFFF_FFFF, 2 * LOG_LEN as u64 - 1);
        assert_eq!(p.refusal(LOG_LEN - 1) & 0xFFFF_FFFF, LOG_LEN as u64);
        assert_eq!(p.refusal(LOG_LEN), 0);
        // An application is not a refusal.
        let before = p.refused();
        assert_eq!(p.set_headroom(30), Ok(()));
        assert_eq!(p.refused(), before);
        assert_eq!(p.applied(), 1);
    }

    #[test]
    fn refusal_codes_are_distinct_and_in_range() {
        use Refusal::*;
        let all = [NoModel, Governor, Domain, Range, SafetyFloor, DeadlineFloor, Headroom, RateLimit, IdleDepth];
        for (i, a) in all.iter().enumerate() {
            assert!(a.code() >= 1 && (a.code() as usize) < POLICY_REFUSED_COUNT);
            for b in &all[i + 1..] {
                assert_ne!(a.code(), b.code());
            }
        }
    }

    /// The user's range bounds the governor's request, but the deadline and
    /// safety floors win again whatever the range says, including a cap that
    /// was legal when set and is not any more (reservations admitted since).
    #[test]
    fn clamp_never_lowers_a_floor() {
        let mm = machine_with(250_000); // safety floor 0, so I1 and the cap interact
        for (lo, hi) in [(0u32, 3u32), (0, 2), (1, 2), (2, 2), (3, 3)] {
            let p = fresh();
            assert_eq!(p.set_opp_range(&mm, 0, lo, hi, 0), Ok(()));
            for util in [0, 200, 500, 800, SCALE] {
                for cur in 0..4 {
                    for ppm in [0, 100_000, 400_000, 600_000, 900_000] {
                        let dd = &mm.domains()[0];
                        let dec = Governor::DeadlineFloor.target_opp(dd, util, cur, ppm, HEADROOM_PCT).unwrap();
                        let out = p.clamp(0, dec);
                        let at = format!("{lo}..={hi} util {util} cur {cur} ppm {ppm}");
                        assert!(out.opp >= dec.safety, "I6: {at}");
                        assert!(out.opp >= dec.deadline, "I1: {at}");
                        assert!(out.opp >= lo as usize, "the range's floor: {at}");
                        assert!(out.opp <= (hi as usize).max(dec.safety).max(dec.deadline), "the cap: {at}");
                    }
                }
            }
        }
    }

    /// The floors overriding the cap are counted (and a cap that is honoured
    /// is not).
    #[test]
    fn a_cap_the_floors_override_is_counted() {
        let m = machine_with(250_000);
        let p = fresh();
        assert_eq!(p.set_opp_range(&m, 0, 0, 1, 0), Ok(()));
        let d = &m.domains()[0];
        // Idle domain, no reservation: the cap is honoured.
        let dec = Governor::DeadlineFloor.target_opp(d, 0, 0, 0, HEADROOM_PCT).unwrap();
        assert_eq!(p.clamp(0, dec).opp, 0);
        assert_eq!(p.floor_wins(), 0);
        // 60 % admitted since: the deadline floor (OPP 3) beats the cap (1).
        let dec = Governor::DeadlineFloor.target_opp(d, 0, 0, 600_000, HEADROOM_PCT).unwrap();
        assert_eq!(p.clamp(0, dec).opp, 3);
        assert_eq!(p.floor_wins(), 1);
    }

    /// The headroom and the rate limit are read by the governor: more
    /// headroom never lowers the OPP, and a longer interval defers the next
    /// evaluation.
    #[test]
    fn headroom_and_rate_limit_reach_the_governor() {
        let m = machine();
        let d = &m.domains()[0];
        let mut moved = false;
        for util in 0..=SCALE {
            let lo = governor::schedutil_opp(d, util, 3, POLICY_HEADROOM_MIN_PCT);
            let def = governor::schedutil_opp(d, util, 3, HEADROOM_PCT);
            let hi = governor::schedutil_opp(d, util, 3, POLICY_HEADROOM_MAX_PCT);
            assert!(lo <= def && def <= hi, "util {util}");
            moved |= lo < hi;
        }
        assert!(moved, "the headroom must be able to change the answer");
        let f = 10_000_000;
        assert!(governor::due(1_000, 41_000, f, 4_000));
        assert!(!governor::due(1_000, 41_000, f, 20_000));
    }
}

#[cfg(test)]
mod idle_x86;
#[cfg(test)]
mod eas;

// The x86_64 CPUID decode, included from the arch crate (`#[path]`, as
// `tests/host/arch-tests` does): `hybrid.rs` names `crate::cpu::features`.
#[cfg(test)]
#[path = "../../../../crates/core/arch-x86_64/src/cpu/features.rs"]
pub mod x86_features;
#[cfg(test)]
#[path = "../../../../crates/core/arch-x86_64/src/ext/hybrid.rs"]
pub mod x86_hybrid;
#[cfg(test)]
mod cpu {
    pub use super::x86_features as features;
}
#[cfg(test)]
mod ext {
    pub use super::x86_hybrid as hybrid;
}
#[cfg(test)]
mod cpuid;
#[cfg(test)]
mod firmware;
