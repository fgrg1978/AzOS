// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The governor's apply assertion (`azos_energy::opp`): the board's apply step
//! judges what the actuator did with the governor's choice
//! (`check_applied`), the record is left once per run of lost choices
//! (`apply_record`), and a choice no apply step answers by the deadline is
//! overdue (`apply_overdue`), the check the kernel's governor makes from the
//! tick (`azos_sched::energy::gov_maybe`).
//!
//! Canaries (cargo features of this suite):
//!
//! * `apply-canary`: `check_applied` takes every answer, a refusal included,
//!   as applied: `a_refused_choice_is_not_applied`,
//!   `a_clock_that_keeps_refusing_leaves_one_record` and
//!   `a_board_with_no_actuator_is_not_a_failure` fail;
//! * `apply-overdue-canary`: `apply_overdue` never fires:
//!   `a_choice_nobody_answers_is_overdue_after_the_deadline` and
//!   `a_dead_apply_step_is_caught_through_dvfs` fail.

use azos_energy::opp::{
    apply_overdue, apply_record, check_applied, ActuateError, Applied, ApplyRecord, Dvfs, GovApply, OppActuator,
    APPLY_OVERDUE,
};
use azos_energy::{EnergyModel, ModelSource, Opp, PerfDomain};

fn model() -> EnergyModel {
    let mut m = EnergyModel::from_source(ModelSource::Topology);
    let mut d = PerfDomain::new(0x3);
    for (f, c, p) in [(500_000, 256, 60), (1_000_000, 512, 150), (1_500_000, 768, 300), (2_000_000, 1024, 600)] {
        d.push_opp(Opp { freq_khz: f, capacity: c, power_mw: p }).unwrap();
    }
    m.push_domain(d).unwrap();
    m
}

/// A clock that answers with `answer` and remembers what it was asked.
struct Clock {
    answer: Result<(), ActuateError>,
    asked: Vec<u32>,
}

impl OppActuator for Clock {
    fn set_opp(&mut self, _domain: usize, opp: &Opp) -> Result<(), ActuateError> {
        self.asked.push(opp.freq_khz);
        self.answer
    }
}

/// One apply step: the governor chose `want`, the heat or a floor made it
/// `target`; the answer judged.
fn apply(dvfs: &mut Dvfs, clock: &mut Clock, m: &EnergyModel, want: usize, target: usize) -> GovApply {
    let r = dvfs.set(clock, m, 0, target);
    check_applied(want, target, r)
}

#[test]
fn a_choice_the_clock_took_is_applied() {
    let m = model();
    let (mut dvfs, mut clock) = (Dvfs::new(), Clock { answer: Ok(()), asked: vec![] });
    assert_eq!(apply(&mut dvfs, &mut clock, &m, 2, 2), GovApply::Applied);
    assert_eq!(clock.asked, [1_500_000]);
    assert_eq!(dvfs.current(0), Some(2));
    // Asked again, nothing is sent and the choice is still applied.
    assert_eq!(apply(&mut dvfs, &mut clock, &m, 2, 2), GovApply::Applied);
    assert_eq!(clock.asked.len(), 1);
}

#[test]
fn the_heat_cap_and_a_floor_are_reached_not_lost() {
    let m = model();
    let (mut dvfs, mut clock) = (Dvfs::new(), Clock { answer: Ok(()), asked: vec![] });
    let capped = apply(&mut dvfs, &mut clock, &m, 3, 1);
    assert_eq!(capped, GovApply::Capped);
    assert!(capped.reached());
    let raised = apply(&mut dvfs, &mut clock, &m, 0, 2);
    assert_eq!(raised, GovApply::Raised);
    assert!(raised.reached());
}

#[test]
fn a_refused_choice_is_not_applied() {
    let m = model();
    for err in [ActuateError::Refused, ActuateError::Fault(-5)] {
        let (mut dvfs, mut clock) = (Dvfs::new(), Clock { answer: Err(err), asked: vec![] });
        let a = apply(&mut dvfs, &mut clock, &m, 2, 2);
        assert_eq!(a, GovApply::Unapplied(err), "{err:?}");
        assert!(!a.reached());
        assert_eq!(dvfs.current(0), None, "a refusal leaves the domain where it was");
    }
    // An index the model does not have is refused before any actuator call.
    let (mut dvfs, mut clock) = (Dvfs::new(), Clock { answer: Ok(()), asked: vec![] });
    assert_eq!(apply(&mut dvfs, &mut clock, &m, 9, 9), GovApply::Unapplied(ActuateError::Refused));
    assert!(clock.asked.is_empty());
}

#[test]
fn a_board_with_no_actuator_is_not_a_failure() {
    let m = model();
    let (mut dvfs, mut clock) = (Dvfs::new(), Clock { answer: Err(ActuateError::Unsupported), asked: vec![] });
    let a = apply(&mut dvfs, &mut clock, &m, 2, 2);
    assert_eq!(a, GovApply::NoActuator);
    assert!(!a.reached());
    // Never a record: there is nothing a clock could have done.
    assert_eq!(apply_record(false, a), ApplyRecord::None);
    assert_eq!(apply_record(true, a), ApplyRecord::None);
}

#[test]
fn a_clock_that_keeps_refusing_leaves_one_record() {
    let m = model();
    let (mut dvfs, mut clock) = (Dvfs::new(), Clock { answer: Err(ActuateError::Refused), asked: vec![] });
    let mut lost = false;
    let mut records = vec![];
    for want in [1, 2, 3, 2, 1] {
        let a = apply(&mut dvfs, &mut clock, &m, want, want);
        match apply_record(lost, a) {
            ApplyRecord::Lost => {
                lost = true;
                records.push(ApplyRecord::Lost);
            }
            ApplyRecord::Back => {
                lost = false;
                records.push(ApplyRecord::Back);
            }
            ApplyRecord::None => {}
        }
    }
    assert_eq!(records, [ApplyRecord::Lost], "one record for a run of refusals, not one per evaluation");
    // The clock takes requests again: one recovery record.
    clock.answer = Ok(());
    let a = apply(&mut dvfs, &mut clock, &m, 2, 2);
    assert_eq!(apply_record(lost, a), ApplyRecord::Back);
}

#[test]
fn a_choice_nobody_answers_is_overdue_after_the_deadline() {
    // Ticks: decided at 1_000, deadline 250.
    assert!(!apply_overdue(3, 2, 1_000, 1_100, 250), "within the deadline");
    assert!(!apply_overdue(3, 2, 1_000, 1_250, 250), "at the deadline");
    assert!(apply_overdue(3, 2, 1_000, 1_251, 250), "past it");
    // An answered choice is never overdue, whatever the answer was.
    assert!(!apply_overdue(3, 3, 1_000, 99_999, 250));
}

/// The kernel's sequence with a dead apply step: the governor's choice moves,
/// no step answers, and the assertion fires; once a step answers it is quiet.
#[test]
fn a_dead_apply_step_is_caught_through_dvfs() {
    let m = model();
    let (mut dvfs, mut clock) = (Dvfs::new(), Clock { answer: Ok(()), asked: vec![] });
    let (deadline, mut acked, choice, since) = (250u64, u8::MAX, 2u8, 10u64);
    assert!(apply_overdue(choice, acked, since, since + deadline + 1, deadline), "no step answered: overdue");
    // A step runs and answers.
    let a = apply(&mut dvfs, &mut clock, &m, choice as usize, choice as usize);
    assert!(a.reached());
    acked = choice;
    assert!(!apply_overdue(choice, acked, since, since + 10 * deadline, deadline));
}

#[test]
fn the_record_codes_are_distinct() {
    let all = [
        GovApply::Applied,
        GovApply::Capped,
        GovApply::Raised,
        GovApply::NoActuator,
        GovApply::Unapplied(ActuateError::Refused),
        GovApply::Unapplied(ActuateError::Fault(1)),
    ];
    let mut codes: Vec<u32> = all.iter().map(|a| a.code()).collect();
    codes.push(APPLY_OVERDUE);
    let n = codes.len();
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), n, "every outcome reads as itself in a record");
    // The changed answer of a `Dvfs::set` that sent nothing is still applied.
    assert_eq!(check_applied(1, 1, Ok(Applied::Unchanged)), GovApply::Applied);
}
