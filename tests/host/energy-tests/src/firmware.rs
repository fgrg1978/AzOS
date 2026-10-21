// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The firmware energy source (Raspberry Pi: the ARM clock range the VideoCore
//! reports): the table `EnergyModel::from_clock_range` makes from a minimum, a
//! maximum and a step, and where the table ranks among the sources (`resolve`).
//! The mailbox half, from a fake VideoCore to this table, is
//! `tests/host/thermal-tests` (`rpi`).
//!
//! Canary (`firmware-model-canary`): the builder accepts a degenerate range and
//! ends the table on the step grid instead of at the firmware's maximum. Exactly
//! these four turn red: `a_range_that_cannot_make_a_table_is_refused`,
//! `the_last_opp_is_the_firmwares_maximum_even_off_the_step_grid`,
//! `a_wide_range_takes_a_wider_step_and_keeps_both_ends` and
//! `power_is_a_declared_placeholder_that_is_nonzero_and_strictly_increasing`
//! (its low range ends off the grid).

use azos_energy::model::{CAPACITY_SCALE, FIRMWARE_PLACEHOLDER_MAX_POWER_MW, MAX_OPPS};
use azos_energy::{resolve, EnergyModel, ModelFault, ModelSource};

const STEP: u32 = 100_000;

fn freqs(m: &EnergyModel) -> Vec<u32> {
    m.domains()[0].opps().iter().map(|o| o.freq_khz).collect()
}

#[test]
fn the_pi5_range_makes_ten_opps_from_the_minimum_to_the_maximum_and_validates() {
    let m = EnergyModel::from_clock_range(0b1111, 1_500_000, 2_400_000, STEP).unwrap();
    assert_eq!(m.source, ModelSource::Firmware);
    assert_eq!(m.domains().len(), 1);
    assert_eq!(m.domains()[0].cpus, 0b1111);
    assert_eq!(freqs(&m), (15..=24).map(|h| h * 100_000).collect::<Vec<_>>());
    assert_eq!(m.validate(4), Ok(()));
    // Capacity is linear in the clock and exactly the scale at the top.
    let caps: Vec<u16> = m.domains()[0].opps().iter().map(|o| o.capacity).collect();
    assert_eq!(caps[0], (1_500_000u64 * 1024 / 2_400_000) as u16);
    assert_eq!(*caps.last().unwrap(), CAPACITY_SCALE);
}

#[test]
fn the_last_opp_is_the_firmwares_maximum_even_off_the_step_grid() {
    // 1.5 GHz to 2.45 GHz: the grid passes the maximum between two steps.
    let m = EnergyModel::from_clock_range(0b11, 1_500_000, 2_450_000, STEP).unwrap();
    let f = freqs(&m);
    assert_eq!(*f.last().unwrap(), 2_450_000, "the table ends at what the firmware accepts, not past it");
    assert_eq!(f[f.len() - 2], 2_400_000);
    assert_eq!(m.domains()[0].max_capacity(), CAPACITY_SCALE);
    assert_eq!(m.validate(2), Ok(()));
    // A maximum below the first step is the table's only other point.
    let near = EnergyModel::from_clock_range(0b1, 1_500_000, 1_550_000, STEP).unwrap();
    assert_eq!(freqs(&near), [1_500_000, 1_550_000]);
}

#[test]
fn a_range_that_cannot_make_a_table_is_refused() {
    let bad = |cpus, min, max, step| EnergyModel::from_clock_range(cpus, min, max, step).unwrap_err();
    let want = ModelFault::ClockRangeDegenerate;
    assert_eq!(bad(0b1, 0, 2_400_000, STEP), want, "a zero minimum");
    assert_eq!(bad(0b1, 2_400_000, 2_400_000, STEP), want, "a minimum that is not below the maximum");
    assert_eq!(bad(0b1, 2_500_000, 2_400_000, STEP), want, "a minimum above the maximum");
    assert_eq!(bad(0b1, 1_500_000, 2_400_000, 0), want, "a zero step");
    assert_eq!(bad(0, 1_500_000, 2_400_000, STEP), want, "no CPU");
}

#[test]
fn power_is_a_declared_placeholder_that_is_nonzero_and_strictly_increasing() {
    let m = EnergyModel::from_clock_range(0b1111, 1_500_000, 2_400_000, STEP).unwrap();
    let p: Vec<u32> = m.domains()[0].opps().iter().map(|o| o.power_mw).collect();
    assert_eq!(*p.last().unwrap(), FIRMWARE_PLACEHOLDER_MAX_POWER_MW);
    assert!(p[0] > 0 && p.windows(2).all(|w| w[0] < w[1]), "{p:?}");
    // A range so low that the cubic rounds several OPPs to the same figure
    // still gives a model that validates.
    let low = EnergyModel::from_clock_range(0b1, 1, 1_000, 1).unwrap();
    let p: Vec<u32> = low.domains()[0].opps().iter().map(|o| o.power_mw).collect();
    assert!(p.windows(2).all(|w| w[0] < w[1]), "{p:?}");
    assert_eq!(low.validate(1), Ok(()));
}

#[test]
fn a_wide_range_takes_a_wider_step_and_keeps_both_ends() {
    let m = EnergyModel::from_clock_range(0b1, 100_000, 3_000_000, STEP).unwrap();
    let f = freqs(&m);
    assert!(f.len() <= MAX_OPPS, "{} OPPs", f.len());
    assert_eq!((f[0], *f.last().unwrap()), (100_000, 3_000_000));
    assert_eq!(f[1] - f[0], 200_000, "the smallest whole multiple of the step that fits");
    assert_eq!(m.validate(1), Ok(()));
}

#[test]
fn the_firmware_model_ranks_after_the_topology_the_dtb_and_cpuid() {
    let fw = || Some(Ok(EnergyModel::from_clock_range(0b11, 1_500_000, 2_400_000, STEP).unwrap()));
    // Nothing before it: the firmware's.
    let (m, r) = resolve(&EnergyModel::NONE, None, None, fw(), 2);
    assert_eq!((m.source, r.source, r.firmware_fault), (ModelSource::Firmware, ModelSource::Firmware, None));
    assert_eq!(m.opp_count(), 10);
    // The signed topology's measured figures win, and the firmware's table is left unused.
    let (m, r) = resolve(&crate::model::valid(), None, None, fw(), 2);
    assert_eq!((m.source, r.source), (ModelSource::Topology, ModelSource::Topology));
    // So does a DTB table.
    let mut dtb = crate::model::valid();
    dtb.source = ModelSource::Dtb;
    let (m, r) = resolve(&EnergyModel::NONE, Some(Ok(dtb)), None, fw(), 2);
    assert_eq!((m.source, r.source), (ModelSource::Dtb, ModelSource::Dtb));
    // A DTB table that was refused is not replaced by the firmware's.
    let (m, r) = resolve(&EnergyModel::NONE, Some(Err(ModelFault::DtPartialTables)), None, fw(), 2);
    assert_eq!((m, r.source, r.dtb_fault, r.firmware_fault), (EnergyModel::NONE, ModelSource::None, Some(ModelFault::DtPartialTables), None));
}

#[test]
fn a_firmware_model_that_could_not_be_built_is_a_fault_of_its_own() {
    let (m, r) = resolve(&EnergyModel::NONE, None, None, Some(Err(ModelFault::ClockRangeDegenerate)), 4);
    assert_eq!(m, EnergyModel::NONE);
    assert_eq!((r.source, r.firmware_fault, r.cpuid_fault), (ModelSource::None, Some(ModelFault::ClockRangeDegenerate), None));
    // And no firmware at all is no model, no fault.
    let (m, r) = resolve(&EnergyModel::NONE, None, None, None, 4);
    assert_eq!((m, r.firmware_fault), (EnergyModel::NONE, None));
}
