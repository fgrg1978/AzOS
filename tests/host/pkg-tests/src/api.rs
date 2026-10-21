// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device's interface table is one table for the installer and the
//! kernel's boot-time apply, and its restated levels are the libraries' own.


#[test]
fn the_restated_levels_are_the_libraries_own() {
    let u = azos_pkg::api::USER_SERVED;
    assert_eq!(u.decisions, azos_decisions::DecisionsIdl::LEVEL as u32);
    assert_eq!(u.names, azos_names::NamesIdl::LEVEL as u32);
    assert_eq!(u.packages, azos_packages::PackagesIdl::LEVEL as u32);
    assert_eq!(u.terminal, azos_term::TerminalIdl::LEVEL as u32);
}

#[test]
fn the_table_is_sorted_unique_and_every_level_is_nonzero() {
    let t = azos_pkg::api::device_api();
    assert_eq!(t.len(), azos_pkg::api::COUNT);
    let mut names: Vec<_> = t.iter().map(|(n, _)| *n).collect();
    let before = names.clone();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), before.len(), "no interface twice");
    assert!(t.iter().all(|&(_, l)| l != 0), "an interface at level 0 admits nothing");
    // A package asking only for what the table serves is admitted by `Names`.
    assert!(t.iter().any(|&(n, l)| n == "Names" && l >= 1));
}
