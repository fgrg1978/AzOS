// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The user principal in the built-in (shipped) topology.
//!
//! `apply_principal` gives a task the principal its row's CLASS declares. Until
//! the `session` class existed no shipped class declared anything but `system`,
//! so no task ever ran as a user and no one could mint a declassification
//! warrant. These tests read the topology every board and QEMU image is built
//! from (`default_minimal`, which `topo_emit` writes out as SCHED.TOM and
//! CAPS.TOM):
//!
//! * the interactive shell row sits in the one class whose principal is `user`;
//! * that class is the only shipped class that declares a principal other than
//!   `system`, and the shell is its only row (a service in it would be labelled
//!   as the human);
//! * the shell's declared priority is inside the class's range, so
//!   `resolve` applies it (and with it `apply_principal`) unchanged;
//! * the class survives the emit -> parse round trip with its principal, so a
//!   signed SCHED.TOM carries it.
//!
//! **Canaries.** Move `SH.ELF` back to `best_effort` in `builder.rs`: the first
//! test is red. Set the `session` class's principal to `System`: the first and
//! the third are red. Drop the `principal` line from `emit_sched`: the third is
//! red.

#[allow(dead_code)]
#[path = "../../../../crates/core/sched/src/class.rs"]
mod class;

use azos_topology::builder::{default_minimal, TASK_SH_IMAGE};
use azos_topology::emit::emit_sched;
use azos_topology::{parse_sched, MaybeStr, PrincipalKind, RowSched, Topology};

/// The class of an interactive shell session.
const SESSION: &[u8] = b"session";

fn class_of(t: &Topology<'_>, row: &[u8]) -> Vec<u8> {
    t.tasks().iter().find(|r| r.name.as_bytes() == row).expect("the row exists").class_name.as_bytes().to_vec()
}

#[test]
fn the_shell_row_is_in_the_class_that_declares_the_user_principal() {
    let t = default_minimal();
    assert_eq!(class_of(&t, TASK_SH_IMAGE), SESSION);
    let class = t.find_class(&MaybeStr::from_bytes(SESSION)).expect("the shipped topology declares `session`");
    assert_eq!(class.principal, PrincipalKind::User);
    assert!(t.admission_check().is_ok(), "the topology with the new class is still admitted");
}

#[test]
fn only_the_session_class_is_a_user_and_only_the_shell_is_in_it() {
    let t = default_minimal();
    let non_system: Vec<&[u8]> =
        t.classes().iter().filter(|c| c.principal != PrincipalKind::System).map(|c| c.name.as_bytes()).collect();
    assert_eq!(non_system, [SESSION], "a shipped class other than `session` declares a principal");
    let rows: Vec<&[u8]> =
        t.tasks().iter().filter(|r| r.class_name.as_bytes() == SESSION).map(|r| r.name.as_bytes()).collect();
    assert_eq!(rows, [TASK_SH_IMAGE], "a row other than the shell would act as the human");
}

#[test]
fn the_shell_keeps_its_priority_inside_the_session_class() {
    let t = default_minimal();
    match t.row_sched(TASK_SH_IMAGE) {
        RowSched::Apply { class_name, declared, priority } => {
            assert_eq!(class_name.as_bytes(), SESSION);
            assert_eq!(priority, declared, "the class range clamped the shell's priority");
        }
        _ => panic!("the shell row does not resolve to a class"),
    }
    // The budgets still sum to the whole machine: `session` reserves nothing.
    let total: u32 = t.classes().iter().map(|c| c.cpu_budget_min_pct as u32).sum();
    assert_eq!(total, 100);
}

#[test]
fn the_session_class_survives_the_signed_file() {
    let t = default_minimal();
    let mut sched = String::new();
    emit_sched(&t, &mut sched).expect("emit SCHED.TOM");
    assert!(sched.contains("[class.session]"), "{sched}");
    assert!(sched.contains("principal = \"user\""), "{sched}");
    let mut back = Box::new(Topology::empty());
    parse_sched(sched.as_bytes(), &mut back).expect("the emitted SCHED.TOM parses");
    let c = back.find_class(&MaybeStr::from_bytes(SESSION)).expect("class read back");
    assert_eq!(c.principal, PrincipalKind::User);
    assert_eq!(back.classes().len(), t.classes().len());
    for (a, b) in t.classes().iter().zip(back.classes()) {
        assert_eq!(a.principal, b.principal, "{:?}", a.name.as_bytes());
    }
}

/// The shell's shipped row is scheduled and reported as the interactive class
/// at the latency QoS tier, not `best_effort` (owner decision 16-10). This
/// reads the class the kernel resolves the row to (`SchedClass::from_name` on
/// the row's class, as `topo_sched::resolve` does). **Canary**: map `session`
/// to `BestEffort` in `class.rs`.
#[test]
fn the_shell_row_resolves_to_the_interactive_class() {
    use class::SchedClass;
    let t = default_minimal();
    let RowSched::Apply { class_name, .. } = t.row_sched(TASK_SH_IMAGE) else { panic!("no shell row") };
    let c = SchedClass::from_name(class_name.as_bytes()).expect("the kernel schedules the shell's class");
    assert_eq!(c, SchedClass::Interactive);
    assert_eq!(c.name(), "interactive");
    assert_eq!(c.qos_hint(), azos_abi::syscall_nr::QOS_LATENCY);
    // And it is the only shipped row that does: every other row is still
    // scheduled as the class it declares.
    for r in t.tasks().iter().filter(|r| r.name.as_bytes() != TASK_SH_IMAGE) {
        let RowSched::Apply { class_name, .. } = t.row_sched(r.name.as_bytes()) else { continue };
        assert_ne!(SchedClass::from_name(class_name.as_bytes()), Some(SchedClass::Interactive),
            "{:?}", r.name.as_str());
    }
}
