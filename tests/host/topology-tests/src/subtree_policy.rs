// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! SUBTREE-POLICY, the shipped row. The built-in topology binds the shell's
//! jobs with a `[policy.shjobs]` row: a `subtree` row on `SH.ELF`, so every
//! program the shell starts (a Domain beneath the shell's) is refused endpoint
//! and port creation whatever its own row grants. The kernel's side (the
//! gate, `families::install_policy`) is tested in
//! `tests/host/syscall-tests/src/subtree_policy.rs` and
//! `tests/host/sched-wake-tests/src/subtree_policy.rs`; this file pins what
//! the topology says and that what it says survives the file a board signs.
//!
//! **Canary.** Delete the `push_policy` in `builder::default_minimal_topology`:
//! the first test reads no row and the emitted file holds no `[policy.`.

use azos_topology::emit::{emit_caps, emit_sched, first_difference};
use azos_topology::{default_minimal, parse_caps, parse_sched, Binding, PolicyScope, Topology};

/// **The default topology limits the shell's subtree: no endpoints, no ports,
/// no MemObj ceiling, on a row that exists and is admitted.**
#[test]
fn the_default_topology_limits_the_shells_jobs() {
    let t = default_minimal();
    assert_eq!(t.admission_check(), Ok(()), "a `domain` that names no task row is refused at admission");
    let rows: Vec<_> = t.policies().iter().filter(|p| p.domain.as_bytes() == b"SH.ELF").collect();
    assert_eq!(rows.len(), 1, "one `subtree` row for the shell");
    let p = rows[0];
    assert_eq!(p.name.as_str(), "shjobs");
    assert_eq!(p.scope, PolicyScope::Subtree, "a `self` row would leave its jobs unbound");
    assert!(!p.create_endpoints && !p.create_ports, "endpoints and ports are what a job must not create");
    assert_eq!(p.memobj_max_pages, 0, "no ceiling: PKG.ELF sizes a MemObj by the package");
}

/// **The row survives the file a board signs**: emitted, parsed back and
/// compared field by field, the topology carries it unchanged.
///
/// **Canary.** Drop the policy loop in `emit::emit_caps`: the file has no row
/// and the comparison reports the policy count.
#[test]
fn the_shell_row_survives_emit_and_parse() {
    let t = default_minimal();
    let mut sched = String::new();
    emit_sched(&t, &mut sched).expect("SCHED.TOM");
    let mut caps = String::new();
    emit_caps(&t, &Binding::default(), &mut caps).expect("CAPS.TOM");
    assert!(
        caps.contains("[policy.shjobs]\ndomain = \"SH.ELF\"\nscope = \"subtree\"\ncreate_endpoints = false\ncreate_ports = false\n"),
        "{caps}"
    );
    let mut back = Box::new(Topology::empty());
    parse_sched(sched.as_bytes(), &mut back).expect("SCHED.TOM parses back");
    parse_caps(caps.as_bytes(), &mut back).expect("CAPS.TOM parses back");
    assert_eq!(back.admission_check(), Ok(()));
    assert_eq!(first_difference(&t, &back), None);
}
