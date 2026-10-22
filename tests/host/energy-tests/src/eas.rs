// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Energy-aware wake placement (`EnergyModel::eas_pick`) on a
//! big.LITTLE model. Four little CPUs (0-3, capacity up to 400) and four big
//! ones (4-7, up to 1024); the big cluster costs more at every capacity both
//! can give. Utilisation is capacity invariant (1024 = a big CPU flat out).
//!
//! Canaries (by hand, in `EnergyModel::eas_pick` / `eas_overutilised`):
//! * pick the highest cost instead of the lowest (`delta < b` -> `delta > b`):
//!   `a_small_task_goes_to_the_little_cluster`, `a_big_task_goes_to_the_big_cluster`
//!   and the brute-force comparison fail;
//! * `eas_pick` skips the overutilised test: `a_full_cpu_hands_placement_back`
//!   fails;
//! * drop the `d.cpus & candidates` mask: `only_candidates_are_chosen` fails;
//! * drop the stay margin (`> stay / EAS_STAY_DIV` -> `> 0`):
//!   `the_stay_margin_is_a_sixteenth_of_the_cost_where_the_task_was` fails;
//! * skip the fit test of the roomiest CPU: `a_big_task_goes_to_the_big_cluster`,
//!   `a_task_that_fits_nowhere_is_overutilised` and the brute-force comparison fail.

use azos_energy::model::{invariant_util, EasChoice, EAS_FIT_PCT};
use azos_energy::{EnergyModel, ModelSource, Opp, PerfDomain};

const LITTLE: u32 = 0x0f;
const BIG: u32 = 0xf0;
const ALL: u32 = 0xff;

fn opp(f: u32, c: u16, p: u32) -> Opp {
    Opp { freq_khz: f, capacity: c, power_mw: p }
}

fn big_little() -> EnergyModel {
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    let mut little = PerfDomain::new(LITTLE);
    for o in [opp(500_000, 100, 40), opp(1_000_000, 200, 100), opp(1_500_000, 300, 200), opp(1_800_000, 400, 350)] {
        little.push_opp(o).unwrap();
    }
    let mut big = PerfDomain::new(BIG);
    for o in [opp(800_000, 400, 700), opp(1_400_000, 700, 1300), opp(2_000_000, 1024, 2500)] {
        big.push_opp(o).unwrap();
    }
    m.push_domain(little).unwrap();
    m.push_domain(big).unwrap();
    assert_eq!(m.validate(8), Ok(()));
    m
}

fn symmetric() -> EnergyModel {
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    for cpus in [0x3, 0xc] {
        let mut d = PerfDomain::new(cpus);
        d.push_opp(opp(1_000_000, 512, 100)).unwrap();
        d.push_opp(opp(2_000_000, 1024, 400)).unwrap();
        m.push_domain(d).unwrap();
    }
    m
}

fn idle() -> [u32; 8] {
    [0; 8]
}

fn is_little(c: usize) -> bool {
    LITTLE >> c & 1 != 0
}

#[test]
fn only_a_machine_with_two_capacities_is_asymmetric() {
    assert!(big_little().is_asymmetric());
    assert!(!symmetric().is_asymmetric());
    assert!(!EnergyModel::NONE.is_asymmetric());
    // One domain is one capacity, however many OPPs.
    let mut one = EnergyModel::from_source(ModelSource::Topology);
    let mut d = PerfDomain::new(0xf);
    d.push_opp(opp(1, 1024, 10)).unwrap();
    one.push_domain(d).unwrap();
    assert!(!one.is_asymmetric());
}

#[test]
fn a_small_task_goes_to_the_little_cluster() {
    let m = big_little();
    // It last ran on a big CPU; the whole machine is idle.
    for prev in 0..8 {
        match m.eas_pick(&idle(), 50, prev, ALL) {
            EasChoice::Cpu(c) => assert!(is_little(c), "prev {prev}: a task of 50 went to CPU {c}"),
            EasChoice::Overutilised => panic!("an idle machine is not overutilised"),
        }
    }
}

#[test]
fn a_big_task_goes_to_the_big_cluster() {
    let m = big_little();
    // 500 is over 80% of 400, the top of a little CPU, and under 80% of 1024.
    for prev in 0..8 {
        match m.eas_pick(&idle(), 500, prev, ALL) {
            EasChoice::Cpu(c) => assert!(!is_little(c), "prev {prev}: a task of 500 went to CPU {c}"),
            EasChoice::Overutilised => panic!("500 fits a big CPU"),
        }
    }
}

#[test]
fn a_loaded_little_cluster_costs_more_than_waking_a_big_cpu_at_its_lowest_clock() {
    let m = big_little();
    // Every little CPU at 200 runs the cluster at 300 (200 + 25%): 200 mW.
    // Adding 100 to one lifts it to the 400 OPP, 350 mW for the whole
    // cluster. A big CPU at its lowest OPP (400, 700 mW) holds 100 for less.
    let mut u = idle();
    u[..4].fill(200);
    assert_eq!(m.eas_pick(&u, 100, 0, ALL), EasChoice::Cpu(4));
    // The same task with a little CPU free of load: the little cluster.
    u[3] = 0;
    assert_eq!(m.eas_pick(&u, 100, 0, ALL), EasChoice::Cpu(3));
}

#[test]
fn a_full_cpu_hands_placement_back() {
    let m = big_little();
    let fits_little = 400 * EAS_FIT_PCT / 100; // 320 does not fit, 319 does
    let mut u = idle();
    u[1] = fits_little as u32 - 1;
    assert_ne!(m.eas_pick(&u, 10, 0, ALL), EasChoice::Overutilised);
    u[1] = fits_little as u32;
    assert!(m.eas_overutilised(&u, ALL));
    assert_eq!(m.eas_pick(&u, 10, 0, ALL), EasChoice::Overutilised);
    // A full big CPU does the same.
    let mut u = idle();
    u[6] = 900;
    assert_eq!(m.eas_pick(&u, 10, 0, ALL), EasChoice::Overutilised);
    // The full CPU is out of the candidates: nothing to judge.
    assert_ne!(m.eas_pick(&u, 10, 0, ALL & !(1 << 6)), EasChoice::Overutilised);
}

#[test]
fn a_task_that_fits_nowhere_is_overutilised() {
    let m = big_little();
    // 80% of 1024 is 819.2: 820 fits no CPU.
    assert_eq!(m.eas_pick(&idle(), 820, 5, ALL), EasChoice::Overutilised);
    assert_eq!(m.eas_pick(&idle(), 819, 5, ALL), EasChoice::Cpu(5));
    // Candidates that are all too small for it.
    assert_eq!(m.eas_pick(&idle(), 500, 0, LITTLE), EasChoice::Overutilised);
    // No candidate at all.
    assert_eq!(m.eas_pick(&idle(), 1, 0, 0), EasChoice::Overutilised);
}

#[test]
fn only_candidates_are_chosen() {
    let m = big_little();
    for mask in [0x01u32, 0x02, 0x06, 0x30, 0xc1, 0xfe, 0x7f] {
        for task in [0u32, 20, 90, 250, 400, 700] {
            for prev in 0..8 {
                if let EasChoice::Cpu(c) = m.eas_pick(&idle(), task, prev, mask) {
                    assert!(mask >> c & 1 != 0, "mask {mask:#x} task {task} prev {prev}: chose CPU {c}");
                }
            }
        }
    }
    // A candidate set of one CPU that fits gives that CPU.
    assert_eq!(m.eas_pick(&idle(), 30, 7, 0x04), EasChoice::Cpu(2));
}

#[test]
fn a_saving_under_a_sixteenth_keeps_the_task_where_it_was() {
    let m = big_little();
    // A zero-utilisation task costs nothing anywhere: it stays.
    for prev in 0..8 {
        assert_eq!(m.eas_pick(&idle(), 0, prev, ALL), EasChoice::Cpu(prev));
    }
    // Two equal little CPUs, one a little busier but at the same OPP: the
    // task stays on the busier one it last ran on while the saving is small.
    let mut u = idle();
    u[0] = 60;
    u[1] = 55;
    // 60+10 and 55+10 both need the 100-capacity OPP... 70*1.25 = 88: yes.
    assert_eq!(m.eas_pick(&u, 10, 0, LITTLE), EasChoice::Cpu(0));
    // The idler CPU is chosen when the saving is real: 75 + 10 asks the
    // cluster for the 200 OPP (100 mW), 75 alone and 10 on the idler CPU
    // stay on the 100 one (40 mW).
    let mut u = idle();
    u[0] = 75;
    assert_eq!(m.eas_pick(&u, 10, 0, LITTLE), EasChoice::Cpu(1));
}

/// CPU 0 alone in a domain with a 512-capacity OPP at 1000 mW; CPU 1 in a
/// domain with the same capacity at `big_mw` and a 1024 one above it.
fn two_cpus(big_mw: u32) -> EnergyModel {
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    let mut a = PerfDomain::new(0x1);
    a.push_opp(opp(1_000_000, 512, 1000)).unwrap();
    let mut b = PerfDomain::new(0x2);
    b.push_opp(opp(1_000_000, 512, big_mw)).unwrap();
    b.push_opp(opp(2_000_000, 1024, 3000)).unwrap();
    m.push_domain(a).unwrap();
    m.push_domain(b).unwrap();
    assert_eq!(m.validate(2), Ok(()));
    m
}

#[test]
fn the_stay_margin_is_a_sixteenth_of_the_cost_where_the_task_was() {
    // CPU 1 costs 3% more than CPU 0 for the same task: not worth a move.
    assert_eq!(two_cpus(1030).eas_pick(&[0, 0], 100, 1, 0b11), EasChoice::Cpu(1));
    // 5% more (under 6.25): still not.
    assert_eq!(two_cpus(1050).eas_pick(&[0, 0], 100, 1, 0b11), EasChoice::Cpu(1));
    // 8% more: it moves.
    assert_eq!(two_cpus(1080).eas_pick(&[0, 0], 100, 1, 0b11), EasChoice::Cpu(0));
    // The other way round, the cheaper CPU is where it was: it stays at any price.
    assert_eq!(two_cpus(1080).eas_pick(&[0, 0], 100, 0, 0b11), EasChoice::Cpu(0));
    // And with the CPU it last ran on out of the candidates the cheapest wins
    // whatever the margin.
    assert_eq!(two_cpus(1030).eas_pick(&[0, 0], 100, 1, 0b01), EasChoice::Cpu(0));
}

/// Independent model of the cost the doc of `eas_pick` states.
fn cost(d: &PerfDomain, util: &[u32], at: Option<(usize, u32)>) -> u64 {
    let (mut max, mut sum) = (0u64, 0u64);
    for c in 0..8 {
        if d.cpus >> c & 1 == 0 {
            continue;
        }
        let u = util[c] as u64 + at.filter(|&(a, _)| a == c).map_or(0, |(_, t)| t as u64);
        max = max.max(u);
        sum += u;
    }
    let need = (max * 125).div_ceil(100);
    let o = d.opps().iter().find(|o| o.capacity as u64 >= need).unwrap_or_else(|| d.opps().last().unwrap());
    o.power_mw as u64 * sum * 1024 / o.capacity as u64
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

#[test]
fn the_pick_is_within_the_stay_margin_of_the_cheapest_cpu_that_fits() {
    let m = big_little();
    let mut r = Lcg(7);
    let (mut picked, mut handed_back) = (0, 0);
    for _ in 0..20_000 {
        let mut u = [0u32; 8];
        for x in u.iter_mut() {
            *x = if r.next(3) == 0 { r.next(300) as u32 } else { r.next(60) as u32 };
        }
        let task = r.next(400) as u32;
        let prev = r.next(8) as usize;
        let mask = (r.next(255) + 1) as u32;
        let got = m.eas_pick(&u, task, prev, mask);
        let judged_full = m.eas_overutilised(&u, mask);
        // The cheapest CPU the task fits, by brute force over every candidate.
        let mut best: Option<u64> = None;
        let mut delta_of = [None; 8];
        for c in 0..8 {
            let d = m.domain_of(c).unwrap();
            let fits = (u[c] as u64 + task as u64) * 100 < d.max_capacity() as u64 * EAS_FIT_PCT;
            if mask >> c & 1 == 0 || !fits {
                continue;
            }
            let dl = cost(d, &u, Some((c, task))) - cost(d, &u, None);
            delta_of[c] = Some(dl);
            best = Some(best.map_or(dl, |b| b.min(dl)));
        }
        match got {
            EasChoice::Overutilised => {
                handed_back += 1;
                assert!(judged_full || best.is_none(), "handed back with room: {u:?} task {task} mask {mask:#x}");
            }
            EasChoice::Cpu(c) => {
                picked += 1;
                assert!(!judged_full, "a full CPU in the candidates and still a pick");
                let dl = delta_of[c].unwrap_or_else(|| panic!("chose CPU {c}, which does not fit: {u:?} {task} {mask:#x}"));
                let b = best.unwrap();
                // Either the cheapest, or the CPU it last ran on within a sixteenth.
                assert!(dl == b || (c == prev && (dl - b) * 16 <= dl), "chose {c} at {dl}, cheapest {b}: {u:?} task {task} prev {prev} mask {mask:#x}");
            }
        }
    }
    assert!(picked > 2_000 && handed_back > 200, "the trace must exercise both answers: {picked} / {handed_back}");
}

#[test]
fn utilisation_is_scaled_by_the_capacity_it_ran_at() {
    // Fully busy at a quarter of the machine's capacity is a quarter.
    assert_eq!(invariant_util(1024, 256), 256);
    assert_eq!(invariant_util(512, 1024), 512);
    assert_eq!(invariant_util(0, 1024), 0);
    // A task busy half the time on a little CPU at 400 is 200: it fits a
    // little CPU (200 < 320) that a half-busy big CPU's 512 would not.
    let m = big_little();
    assert!(m.eas_pick(&idle(), invariant_util(512, 400), 4, ALL) != EasChoice::Overutilised);
    assert!(matches!(m.eas_pick(&idle(), invariant_util(512, 400), 4, ALL), EasChoice::Cpu(c) if is_little(c)));
}

/// The path from the firmware: a DTB with `capacity-dmips-mhz` and
/// `operating-points-v2` becomes the model (little CPUs 0-1 topping out at
/// 256, big CPUs 2-3 at 1024), and placement reads it.
#[test]
fn a_device_tree_model_places_small_tasks_little_and_big_tasks_big() {
    let p = format!("{}/fixtures/energy-2cluster.dtb", env!("CARGO_MANIFEST_DIR"));
    let mut blob = std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"));
    blob.extend_from_slice(&[0; 8]);
    let dt = unsafe { azos_dtb::dtb_energy(blob.as_ptr()) }.expect("readable blob");
    let m = azos_energy::dt::from_dt(&dt, &crate::by_reg).unwrap().unwrap();
    assert!(m.is_asymmetric());
    let idle = [0u32; 4];
    // 30 is a fraction of what a little CPU can do at its top OPP (256 * 80% = 204).
    assert!(matches!(m.eas_pick(&idle, 30, 3, 0xf), EasChoice::Cpu(c) if c < 2));
    // 300 is not.
    assert!(matches!(m.eas_pick(&idle, 300, 0, 0xf), EasChoice::Cpu(c) if c >= 2));
    // A little CPU at 205 is full, and the machine is overutilised.
    assert_eq!(m.eas_pick(&[205, 0, 0, 0], 30, 3, 0xf), EasChoice::Overutilised);
    // One below it is not; with a little CPU that busy the big cluster is cheaper.
    assert_eq!(m.eas_pick(&[204, 0, 0, 0], 30, 3, 0xf), EasChoice::Cpu(3));
}
