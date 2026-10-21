// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The x86_64 actuator and meter (`azos_thermal::x86`) against a fake CPU: the
//! MSR layouts word for word, the level an OPP asks for, the order the control
//! is switched on in, a CPU that gives the OS no control, a request the CPU
//! does not keep, RAPL across its wrap, and the runtime driving all of it
//! through the sensor's board object (`x86_sensor::X86Board`): heat caps the
//! clock, the floors hold, a CPU with no control raises the level instead.
//!
//! Canaries (by hand, each must turn the named test red): drop the `+ den - 1`
//! in `level_for` -> `the_level_rounds_up_so_a_request_is_never_below_its_opp`;
//! write the request before the enable in `bring_up` ->
//! `the_control_is_switched_on_before_its_capabilities_are_read`; skip the
//! read-back in `request` -> `a_request_the_cpu_does_not_keep_is_refused`;
//! let `is_remote_msr` accept every MSR ->
//! `only_the_actuators_registers_may_be_touched_from_another_cpu`; return the
//! slowest OPP from `boot_khz` -> `the_boot_state_is_the_range_the_firmware_left_open`.

use azos_energy::model::{EnergyModel, ModelSource, Opp, PerfDomain, MAX_DOMAINS};
use azos_energy::opp::{ActuateError, OppActuator};
use azos_energy::thermal::{LEVEL_CAUTIOUS, LEVEL_SLOW};
use azos_thermal::runtime::{Inputs, Runtime};
use azos_thermal::x86::*;
use azos_thermal::x86_sensor::{package_zone, Kind, MsrBus, RootComplex, X86Board, X86Sensor};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};

/// Two domains: CPUs 0-1 over 800..3200 MHz (4 OPPs), CPU 2 over one OPP.
fn model(wcet_ref_khz: u32) -> EnergyModel {
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    let mut a = PerfDomain::new(0b011);
    a.wcet_ref_khz = wcet_ref_khz;
    for (f, c, p) in [(800_000, 256, 500), (1_600_000, 512, 1500), (2_400_000, 768, 3000), (3_200_000, 1024, 6000)] {
        a.push_opp(Opp { freq_khz: f, capacity: c, power_mw: p }).unwrap();
    }
    m.push_domain(a).unwrap();
    let mut b = PerfDomain::new(0b100);
    b.push_opp(Opp { freq_khz: 2_000_000, capacity: 600, power_mw: 1800 }).unwrap();
    m.push_domain(b).unwrap();
    m
}

fn opp(m: &EnergyModel, dom: usize, i: usize) -> Opp {
    m.domains()[dom].opps()[i]
}

/// HWP capabilities: highest, guaranteed, most efficient, lowest.
fn hwp_caps(highest: u8, guaranteed: u8, efficient: u8, lowest: u8) -> u64 {
    highest as u64 | (guaranteed as u64) << 8 | (efficient as u64) << 16 | (lowest as u64) << 24
}

/// CPPC CAP1: lowest, lowest non-linear, nominal, highest.
fn cppc_caps(lowest: u8, nonlinear: u8, nominal: u8, highest: u8) -> u64 {
    lowest as u64 | (nonlinear as u64) << 8 | (nominal as u64) << 16 | (highest as u64) << 24
}

#[derive(Default)]
struct Cpu {
    regs: HashMap<(usize, u32), u64>,
    /// Every access, in order: `(cpu, msr, Some(value written) | None for a read)`.
    log: Vec<(usize, u32, Option<u64>)>,
    online: u32,
    this: usize,
    /// CPUs that never answer a remote access.
    mute: HashSet<usize>,
    /// The request register ignores writes (package control, a lock).
    request_locked: bool,
    /// The enable bit does not stick.
    enable_stuck: bool,
}

impl Cpu {
    fn new(online: u32) -> Self {
        Self { online, ..Self::default() }
    }
    fn set(&mut self, cpu: usize, msr: u32, v: u64) {
        self.regs.insert((cpu, msr), v);
    }
    fn get(&self, cpu: usize, msr: u32) -> u64 {
        self.regs.get(&(cpu, msr)).copied().unwrap_or(0)
    }
    fn writes(&self, msr: u32) -> Vec<(usize, u64)> {
        self.log.iter().filter(|e| e.1 == msr && e.2.is_some()).map(|e| (e.0, e.2.unwrap())).collect()
    }
}

struct Fake<'a>(&'a mut Cpu);

impl Platform for Fake<'_> {
    fn this_cpu(&self) -> usize {
        self.0.this
    }
    fn cpu_online(&self, cpu: usize) -> bool {
        self.0.online & 1 << cpu != 0
    }
    fn rdmsr(&mut self, cpu: usize, msr: u32) -> Option<u64> {
        if cpu != self.0.this {
            assert!(is_remote_msr(msr), "a remote read of {msr:#x}");
            if self.0.mute.contains(&cpu) {
                return None;
            }
        }
        self.0.log.push((cpu, msr, None));
        Some(self.0.get(cpu, msr))
    }
    fn wrmsr(&mut self, cpu: usize, msr: u32, v: u64) -> bool {
        if cpu != self.0.this {
            assert!(is_remote_msr(msr), "a remote write of {msr:#x}");
            if self.0.mute.contains(&cpu) {
                return false;
            }
        }
        self.0.log.push((cpu, msr, Some(v)));
        if (msr == IA32_HWP_REQUEST || msr == MSR_AMD_CPPC_REQ) && self.0.request_locked {
            return true;
        }
        if (msr == IA32_PM_ENABLE || msr == MSR_AMD_CPPC_ENABLE) && self.0.enable_stuck {
            return true;
        }
        self.0.set(cpu, msr, v);
        true
    }
}

fn hw(perf: Perf) -> Hw {
    Hw { perf, meter: Meter::Intel }
}

/// An Intel part with HWP: CPU 0-1 lowest 8 .. highest 40, CPU 2 4 .. 20, HWP
/// not yet enabled, the firmware's energy preference 0x80.
fn intel(online: u32) -> Cpu {
    let mut c = Cpu::new(online);
    for cpu in [0, 1] {
        c.set(cpu, IA32_HWP_CAPABILITIES, hwp_caps(40, 30, 12, 8));
        c.set(cpu, IA32_HWP_REQUEST, 0x80 << 24 | 40 << 8 | 8);
    }
    c.set(2, IA32_HWP_CAPABILITIES, hwp_caps(20, 16, 8, 4));
    c.set(2, IA32_HWP_REQUEST, 0x80 << 24 | 20 << 8 | 4);
    c
}

fn amd(online: u32) -> Cpu {
    let mut c = Cpu::new(online);
    for cpu in 0..3 {
        c.set(cpu, MSR_AMD_CPPC_CAP1, cppc_caps(10, 40, 100, 200));
        c.set(cpu, MSR_AMD_CPPC_REQ, 0x70 << 24 | 10 << 8 | 200);
    }
    c
}

fn min_max_hwp(v: u64) -> (u8, u8) {
    (v as u8, (v >> 8) as u8)
}

fn min_max_cppc(v: u64) -> (u8, u8) {
    ((v >> 8) as u8, v as u8)
}

// ── The arithmetic ───────────────────────────────────────────────────────────

#[test]
fn the_capability_registers_decode_field_by_field() {
    // Intel: highest 7:0, lowest 31:24 (guaranteed and efficient are neither).
    assert_eq!(PerfRange::from_hwp(hwp_caps(40, 30, 12, 8)), Some(PerfRange { lowest: 8, highest: 40 }));
    // AMD: lowest 7:0, highest 31:24.
    assert_eq!(PerfRange::from_cppc(cppc_caps(10, 40, 100, 200)), Some(PerfRange { lowest: 10, highest: 200 }));
    // A register of zeros is the firmware keeping the control; so is a range
    // turned over.
    assert_eq!(PerfRange::from_hwp(0), None);
    assert_eq!(PerfRange::from_cppc(0), None);
    assert_eq!(PerfRange::from_hwp(hwp_caps(8, 8, 8, 40)), None);
    assert_eq!(PerfRange::from_cppc(cppc_caps(0, 0, 0, 200)), None, "a lowest of 0 is not a level");
    assert_eq!(PerfRange::from_hwp(hwp_caps(0, 0, 0, 5)), None);
}

#[test]
fn a_level_lies_on_the_range_and_is_monotonic_in_the_frequency() {
    let r = PerfRange { lowest: 8, highest: 40 };
    let (slow, fast) = (800_000, 3_200_000);
    assert_eq!(r.level_for(slow, slow, fast), 8);
    assert_eq!(r.level_for(fast, slow, fast), 40);
    // Outside the OPP span is clamped to the range, never past it.
    assert_eq!(r.level_for(1, slow, fast), 8);
    assert_eq!(r.level_for(u32::MAX, slow, fast), 40);
    let mut prev = 0;
    for khz in (slow..=fast).step_by(25_000) {
        let l = r.level_for(khz, slow, fast);
        assert!((8..=40).contains(&l));
        assert!(l >= prev, "{khz} kHz gave {l} after {prev}");
        prev = l;
    }
    // A domain with one OPP has nothing to interpolate: its level is the top.
    assert_eq!(r.level_for(2_000_000, 2_000_000, 2_000_000), 40);
}

#[test]
fn the_level_rounds_up_so_a_request_is_never_below_its_opp() {
    // 1 kHz above the slowest of a 1000 kHz span over 10 levels: 0.01 of a
    // level, which a rounding down would lose and the deadline floor would pay.
    let r = PerfRange { lowest: 10, highest: 20 };
    assert_eq!(r.level_for(1_001, 1_000, 2_000), 11);
    assert_eq!(r.level_for(1_100, 1_000, 2_000), 11);
    assert_eq!(r.level_for(1_101, 1_000, 2_000), 12);
}

#[test]
fn the_request_words_keep_the_preference_and_clear_package_control() {
    // HWP: min 7:0, max 15:8, desired 23:16 (zeroed), EPP 31:24 and the
    // activity window kept, package control (42) cleared.
    let cur = 0x80u64 << 24 | 0x33 << 16 | 40 << 8 | 8 | 1 << 42 | 0x155 << 32;
    let w = hwp_request(cur, 12, 24);
    assert_eq!(w & 0xFFFF_FFFF, 0x80 << 24 | 24 << 8 | 12);
    assert_eq!(w >> 32, 0x155);
    // CPPC: max 7:0, min 15:8, desired 23:16, EPP 31:24.
    let cur = 0x70u64 << 24 | 0x44 << 16 | 10 << 8 | 200;
    assert_eq!(cppc_request(cur, 20, 150), 0x70 << 24 | 20 << 8 | 150);
}

#[test]
fn rapl_counts_microjoules_across_the_wrap() {
    // ESU 14: 1/16384 J = 61.035 uJ per count.
    let unit = 14 << 8 | 3;
    assert!(Rapl::new(0, 0).is_none(), "an energy unit of 0 is not a unit");
    let mut r = Rapl::new(unit, 1000).unwrap();
    // 16384 counts is exactly one joule; over 1000 ms that is 1000 mW.
    let e = r.sample(1000 + 16_384, 1000);
    assert_eq!((e.total_uj, e.power_mw), (1_000_000, 1000));
    // The counter wraps at 2^32: 10 counts before the end, 22 after it.
    let mut r = Rapl::new(unit, u32::MAX - 9).unwrap();
    let e = r.sample(22, 100);
    assert_eq!(e.total_uj, 32 * 1_000_000 / 16_384, "32 counts");
    let e2 = r.sample(22 + 16_384, 500);
    assert_eq!(e2.total_uj, (32 + 16_384) * 1_000_000 / 16_384);
    assert_eq!(e2.power_mw, 2000, "one joule in half a second");
    // A zero interval has no power.
    assert_eq!(r.sample(22 + 16_384 + 5, 0).power_mw, 0);
}

#[test]
fn only_the_actuators_registers_may_be_touched_from_another_cpu() {
    for m in [IA32_PM_ENABLE, IA32_HWP_CAPABILITIES, IA32_HWP_REQUEST, MSR_AMD_CPPC_CAP1, MSR_AMD_CPPC_ENABLE, MSR_AMD_CPPC_REQ] {
        assert!(is_remote_msr(m), "{m:#x}");
    }
    // The package sensor (0x1B1, 0x19C), the meter, and a few that would do harm.
    for m in [0x1B1, 0x19C, MSR_PKG_ENERGY_STATUS, MSR_AMD_PKG_ENERGY_STATUS, 0x1B0, 0xC000_0080, 0x3A, 0x10] {
        assert!(!is_remote_msr(m), "{m:#x}");
    }
}

// ── The actuator ─────────────────────────────────────────────────────────────

#[test]
fn the_slowest_opp_pins_each_cpu_at_its_own_lowest_level_and_the_fastest_releases_the_range() {
    let m = model(0);
    let mut cpu = intel(0b111);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    {
        let mut b = st.actuator(Fake(&mut cpu));
        b.set_opp(0, &opp(&m, 0, 0)).unwrap();
    }
    for c in [0, 1] {
        assert_eq!(min_max_hwp(cpu.get(c, IA32_HWP_REQUEST)), (8, 8), "cpu {c}");
        assert_eq!(cpu.get(c, IA32_HWP_REQUEST) >> 24 & 0xFF, 0x80, "the firmware's preference is kept");
    }
    assert_eq!(min_max_hwp(cpu.get(2, IA32_HWP_REQUEST)), (4, 20), "cpu 2 belongs to the other domain: untouched");
    {
        let mut b = st.actuator(Fake(&mut cpu));
        b.set_opp(0, &opp(&m, 0, 3)).unwrap();
    }
    for c in [0, 1] {
        assert_eq!(min_max_hwp(cpu.get(c, IA32_HWP_REQUEST)), (8, 40), "released to the part's range");
    }
}

#[test]
fn a_domain_of_other_cores_gets_levels_on_its_own_scale() {
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    // CPU 2 is an efficiency core: levels 4..20.
    let mut d = PerfDomain::new(0b100);
    for (f, c, p) in [(1_000_000, 100, 100), (2_000_000, 200, 400)] {
        d.push_opp(Opp { freq_khz: f, capacity: c, power_mw: p }).unwrap();
    }
    m.push_domain(d).unwrap();
    let mut cpu = intel(0b111);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    let mut b = st.actuator(Fake(&mut cpu));
    b.set_opp(0, &opp(&m, 0, 0)).unwrap();
    assert_eq!(min_max_hwp(cpu.get(2, IA32_HWP_REQUEST)), (4, 4));
}

#[test]
fn the_levels_between_are_proportional_and_inside_the_range() {
    let m = model(0);
    let mut cpu = intel(0b011);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    let mut seen = vec![];
    for i in 0..4 {
        let mut b = st.actuator(Fake(&mut cpu));
        b.set_opp(0, &opp(&m, 0, i)).unwrap();
        let (lo, hi) = min_max_hwp(cpu.get(0, IA32_HWP_REQUEST));
        assert!((8..=40).contains(&lo) && (8..=40).contains(&hi));
        seen.push((lo, hi));
    }
    // 800/1600/2400/3200 MHz over 8..40: 8, 8+ceil(32/3)=19, 8+ceil(64/3)=30, then the release.
    assert_eq!(seen, vec![(8, 8), (19, 19), (30, 30), (8, 40)]);
}

#[test]
fn the_control_is_switched_on_before_its_capabilities_are_read() {
    let m = model(0);
    let mut cpu = intel(0b001);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 1)).unwrap();
    let pos = |msr: u32, write: bool| cpu.log.iter().position(|e| e.0 == 0 && e.1 == msr && e.2.is_some() == write).unwrap();
    assert!(pos(IA32_PM_ENABLE, true) < pos(IA32_HWP_CAPABILITIES, false), "HWP_CAPABILITIES is not valid before PM_ENABLE");
    assert!(pos(IA32_HWP_CAPABILITIES, false) < pos(IA32_HWP_REQUEST, true));
    assert_eq!(cpu.get(0, IA32_PM_ENABLE) & 1, 1);
    // Switched on once: the next request does not touch the enable again.
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 2)).unwrap();
    assert_eq!(cpu.writes(IA32_PM_ENABLE).len(), 1);
    assert_eq!(cpu.log.iter().filter(|e| e.1 == IA32_HWP_CAPABILITIES).count(), 1, "the range is read once");
}

#[test]
fn an_enable_already_on_is_left_alone() {
    let m = model(0);
    let mut cpu = intel(0b001);
    cpu.set(0, IA32_PM_ENABLE, 1);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 1)).unwrap();
    assert!(cpu.writes(IA32_PM_ENABLE).is_empty(), "HWP's enable is one-way: no need to write it again");
}

#[test]
fn amd_cppc_is_enabled_then_requested_with_max_in_the_low_byte() {
    let m = model(0);
    let mut cpu = amd(0b011);
    let mut st = X86Pstate::new(Hw { perf: Perf::Cppc, meter: Meter::Amd }, &m);
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0)).unwrap();
    for c in [0, 1] {
        assert_eq!(cpu.get(c, MSR_AMD_CPPC_ENABLE) & 1, 1);
        assert_eq!(min_max_cppc(cpu.get(c, MSR_AMD_CPPC_REQ)), (10, 10));
        assert_eq!(cpu.get(c, MSR_AMD_CPPC_REQ) >> 24, 0x70, "the preference is kept");
    }
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 3)).unwrap();
    assert_eq!(min_max_cppc(cpu.get(0, MSR_AMD_CPPC_REQ)), (10, 200));
}

#[test]
fn a_cpu_that_gives_the_os_no_control_is_refused_and_never_written_to() {
    let m = model(0);
    // HWP_CAPABILITIES reads zero: the firmware kept the control.
    let mut cpu = intel(0b001);
    cpu.set(0, IA32_HWP_CAPABILITIES, 0);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    let r = st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0));
    assert_eq!(r, Err(ActuateError::Refused));
    assert!(cpu.writes(IA32_HWP_REQUEST).is_empty());
    // Not asked again.
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 1)).unwrap_err();
    assert_eq!(cpu.log.iter().filter(|e| e.1 == IA32_HWP_CAPABILITIES).count(), 1);
    // The enable does not stick.
    let mut cpu = intel(0b001);
    cpu.enable_stuck = true;
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    let r = st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0));
    assert_eq!(r, Err(ActuateError::Refused));
    assert!(cpu.writes(IA32_HWP_REQUEST).is_empty());
}

#[test]
fn a_request_the_cpu_does_not_keep_is_refused() {
    let m = model(0);
    let mut cpu = intel(0b001);
    cpu.request_locked = true;
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    let r = st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0));
    assert_eq!(r, Err(ActuateError::Refused), "package control or a lock: the clock did not move");
    assert_eq!(st.refused, 1);
}

#[test]
fn a_cpu_that_does_not_answer_fails_the_domain_but_is_not_condemned() {
    let m = model(0);
    let mut cpu = intel(0b011);
    cpu.this = 0;
    cpu.mute.insert(1);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    let r = st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0));
    assert!(matches!(r, Err(ActuateError::Fault(_))), "{r:?}");
    assert_eq!(min_max_hwp(cpu.get(0, IA32_HWP_REQUEST)), (8, 8), "the CPU that answered took it");
    // It answers next time.
    cpu.mute.clear();
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0)).unwrap();
    assert_eq!(min_max_hwp(cpu.get(1, IA32_HWP_REQUEST)), (8, 8));
}

#[test]
fn an_offline_cpu_is_skipped_and_a_domain_with_none_online_is_refused() {
    let m = model(0);
    let mut cpu = intel(0b001);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0)).unwrap();
    assert!(cpu.log.iter().all(|e| e.0 != 1), "CPU 1 is offline: no IPI to it");
    let mut cpu = intel(0b100);
    let mut st = X86Pstate::new(hw(Perf::Hwp), &m);
    let r = st.actuator(Fake(&mut cpu)).set_opp(0, &opp(&m, 0, 0));
    assert_eq!(r, Err(ActuateError::Refused));
}

#[test]
fn a_cpu_with_no_level_request_is_the_no_actuator_case() {
    let m = model(0);
    let mut cpu = Cpu::new(0b111);
    let mut st = X86Pstate::new(hw(Perf::None), &m);
    let mut b = st.actuator(Fake(&mut cpu));
    assert_eq!(b.set_opp(0, &opp(&m, 0, 0)), Err(ActuateError::Unsupported));
    assert_eq!(b.set_opp(MAX_DOMAINS - 1, &opp(&m, 0, 0)), Err(ActuateError::Unsupported), "a domain the model lacks");
    assert!(cpu.log.is_empty(), "nothing was touched");
}

// ── The sensor ───────────────────────────────────────────────────────────────

// ── The meter ────────────────────────────────────────────────────────────────

#[test]
fn the_meter_is_found_on_the_first_sample_and_accumulates_after() {
    let m = model(0);
    let mut cpu = Cpu::new(1);
    cpu.set(0, MSR_RAPL_POWER_UNIT, 14 << 8 | 3);
    cpu.set(0, MSR_PKG_ENERGY_STATUS, u32::MAX as u64 - 99);
    let mut st = X86Pstate::new(hw(Perf::None), &m);
    let first = st.energy(&mut Fake(&mut cpu), 0).unwrap();
    assert_eq!(first, Energy::default(), "the first sample only sets the origin");
    // 16384 counts (1 J) and a wrap, a second later.
    cpu.set(0, MSR_PKG_ENERGY_STATUS, 16_284);
    let e = st.energy(&mut Fake(&mut cpu), 1000).unwrap();
    assert_eq!(e.total_uj, 1_000_000);
    assert_eq!(e.power_mw, 1000);
    assert_eq!(st.last_energy(), e);
}

#[test]
fn the_amd_meter_reads_its_own_registers() {
    let m = model(0);
    let mut cpu = Cpu::new(1);
    cpu.set(0, MSR_AMD_RAPL_POWER_UNIT, 16 << 8 | 3);
    cpu.set(0, MSR_AMD_PKG_ENERGY_STATUS, 0);
    let mut st = X86Pstate::new(Hw { perf: Perf::Cppc, meter: Meter::Amd }, &m);
    st.energy(&mut Fake(&mut cpu), 0).unwrap();
    cpu.set(0, MSR_AMD_PKG_ENERGY_STATUS, 65_536 * 3);
    let e = st.energy(&mut Fake(&mut cpu), 1000).unwrap();
    assert_eq!((e.total_uj, e.power_mw), (3_000_000, 3000), "ESU 16: 65536 counts per joule");
}

#[test]
fn no_meter_or_an_unreadable_one_is_looked_for_once() {
    let m = model(0);
    let mut cpu = Cpu::new(1);
    let mut st = X86Pstate::new(Hw { meter: Meter::None, ..hw(Perf::None) }, &m);
    assert_eq!(st.energy(&mut Fake(&mut cpu), 0), None);
    assert!(cpu.log.is_empty());
    // A unit register of zero is not RAPL.
    let mut st = X86Pstate::new(hw(Perf::None), &m);
    st.energy(&mut Fake(&mut cpu), 0);
    let n = cpu.log.len();
    assert_eq!(st.energy(&mut Fake(&mut cpu), 1000), None);
    assert_eq!(st.energy(&mut Fake(&mut cpu), 2000), None);
    assert_eq!(cpu.log.len(), n, "not asked again");
}

// ── The boot state ───────────────────────────────────────────────────────────

#[test]
fn the_boot_state_is_the_range_the_firmware_left_open() {
    let m = model(0);
    // A level request leaves the part's whole range to the hardware: the
    // fastest OPP of each domain is what a cap is lifted back to.
    assert_eq!(boot_khz(hw(Perf::Hwp), &m, 0), Some(3_200_000));
    assert_eq!(boot_khz(hw(Perf::Cppc), &m, 1), Some(2_000_000));
    assert_eq!(boot_khz(hw(Perf::Hwp), &m, 2), None, "a domain the model lacks");
    // No level request, no clock the framework knows.
    assert_eq!(boot_khz(hw(Perf::None), &m, 0), None);
}

// ── The runtime over the board ───────────────────────────────────────────────

/// The package sensor's MSR: the status word the test sets, read as
/// `IA32_PACKAGE_THERM_STATUS` (the only MSR the sensor may read).
struct Status<'a>(&'a Cell<u64>);

impl MsrBus for Status<'_> {
    fn rdmsr(&mut self, msr: u32) -> u64 {
        assert_eq!(msr, 0x1b1, "the package sensor reads the package register");
        self.0.get()
    }
}

struct NoRoot;

impl RootComplex for NoRoot {
    fn vendor_id(&self) -> u16 {
        0xffff
    }
    fn smn_read(&mut self, _addr: u32) -> u32 {
        panic!("an Intel package has no SMN");
    }
}

/// The limit of the Intel sensors below.
const TJMAX_MDEG: i32 = 100_000;

/// A readout of `c` degrees Celsius.
fn heat(status: &Cell<u64>, c: i32) {
    status.set(1 << 31 | ((TJMAX_MDEG / 1000 - c) as u64) << 16);
}

/// The runtime over the sensor's board object paired with this module's
/// actuator, the zone Kconfig would build (passive 75, hot 85, critical 100).
struct Rig {
    rt: Runtime,
    st: X86Pstate,
    cpu: Cpu,
    status: Cell<u64>,
    m: EnergyModel,
}

fn rig(m: EnergyModel, cpu: Cpu, perf: Perf) -> Rig {
    let dt = package_zone(&m, 75, 85, 100, 1000).unwrap();
    let h = hw(perf);
    let (rt, report) = Runtime::from_dt(&dt, &m, |d| boot_khz(h, &m, d));
    assert_eq!((report.zones, report.zones_dropped, report.coolers_dropped), (1, 0, 0));
    let st = X86Pstate::new(h, &m);
    Rig { rt, st, cpu, status: Cell::new(0), m }
}

impl Rig {
    fn run(&mut self, inp: &Inputs, from: u64, ticks: u64) {
        for k in from..from + ticks {
            let mut hw = X86Board {
                sensor: X86Sensor::new(Kind::Intel { package: true, tjmax_mdeg: TJMAX_MDEG }, Status(&self.status), NoRoot),
                actuator: self.st.actuator(Fake(&mut self.cpu)),
            };
            self.rt.tick(&mut hw, &self.m, k * 1000, inp);
        }
    }
}

#[test]
fn heat_caps_the_clock_through_hwp_and_never_below_the_realtime_floor() {
    // wcet_ref 2.4 GHz: the safety floor is the 2.4 GHz OPP (index 2), level 30 of 8..40.
    let mut r = rig(model(2_400_000), intel(0b011), Perf::Hwp);
    heat(&r.status, 90);
    r.run(&Inputs::IDLE, 0, 8);
    for c in [0, 1] {
        assert_eq!(min_max_hwp(r.cpu.get(c, IA32_HWP_REQUEST)), (30, 30), "cpu {c}: the floor held the cap");
    }
    assert_eq!(r.rt.dvfs.current(0), Some(2));
    assert_eq!(min_max_hwp(r.cpu.get(2, IA32_HWP_REQUEST)), (4, 20), "the one-OPP domain is not capped");
    // The heat goes: the cap is released one step per read, and the range
    // comes back.
    heat(&r.status, 50);
    r.run(&Inputs::IDLE, 8, 12);
    for c in [0, 1] {
        assert_eq!(min_max_hwp(r.cpu.get(c, IA32_HWP_REQUEST)), (8, 40), "cpu {c}");
    }
    assert_eq!(r.rt.dvfs.current(0), Some(3));
    assert_eq!(r.rt.last().level, 0);
}

#[test]
fn a_cpu_with_no_control_raises_the_level_instead_of_running_hot_unannounced() {
    // The WCET reference at the slowest OPP: the cap may go all the way down.
    let mut r = rig(model(800_000), Cpu::new(0b111), Perf::None);
    heat(&r.status, 97);
    r.run(&Inputs::IDLE, 0, 3);
    assert!(r.rt.last().level >= LEVEL_SLOW, "level {}", r.rt.last().level);
    assert!(r.cpu.log.is_empty(), "nothing was written or read on the CPU");
    // Cool: nothing was ever moved, and nothing is.
    heat(&r.status, 40);
    r.run(&Inputs::IDLE, 3, 8);
    assert_eq!(r.rt.last().level, 0);
    assert!(r.cpu.log.is_empty());
    let _ = LEVEL_CAUTIOUS;
}

#[test]
fn a_cpu_that_keeps_no_request_raises_the_level_when_it_is_hot() {
    // The firmware kept the control: HWP capabilities read zero on every CPU.
    let mut c = intel(0b011);
    for cpu in 0..3 {
        c.set(cpu, IA32_HWP_CAPABILITIES, 0);
    }
    let mut r = rig(model(800_000), c, Perf::Hwp);
    heat(&r.status, 90);
    r.run(&Inputs::IDLE, 0, 4);
    assert!(r.rt.last().level >= LEVEL_SLOW, "level {}", r.rt.last().level);
    assert!(r.cpu.writes(IA32_HWP_REQUEST).is_empty(), "never written to");
    assert!(r.st.refused > 0 && r.st.applied == 0, "refused {} applied {}", r.st.refused, r.st.applied);
}

#[test]
fn a_cool_machine_with_no_governor_is_not_touched() {
    let mut r = rig(model(0), intel(0b011), Perf::Hwp);
    heat(&r.status, 40);
    r.run(&Inputs::IDLE, 0, 5);
    assert!(r.cpu.writes(IA32_HWP_REQUEST).is_empty() && r.cpu.writes(IA32_PM_ENABLE).is_empty(), "invariant I4");
    assert!(r.cpu.log.is_empty(), "not even a read");
}

#[test]
fn the_governors_opp_reaches_the_cpu() {
    // The WCET reference at the slowest OPP: the safety floor is that OPP, so
    // the governor's request for it stands.
    let mut r = rig(model(800_000), intel(0b011), Perf::Hwp);
    heat(&r.status, 40);
    let mut inp = Inputs::IDLE;
    inp.want[0] = Some(0);
    r.run(&inp, 0, 2);
    for c in [0, 1] {
        assert_eq!(min_max_hwp(r.cpu.get(c, IA32_HWP_REQUEST)), (8, 8), "cpu {c}");
    }
    assert_eq!(r.rt.dvfs.current(0), Some(0));
}
