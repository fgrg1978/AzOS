// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The daemon's topology row and the view it reads its domain from.

use crate::link;
use azos_abi::cap::{CapKind, CapPerms};
use azos_topology::default_minimal;

/// **The row is the whole of the daemon's authority**: `WRITE` on the kernel's
/// `clock` endpoint (`Clock::sample` moves time; no `READ`, so it claims no
/// service, and no `transfer`: it lends the right to nobody) and the
/// kernel's view of the `[clock]` row (`inspect.clock`). The row exists,
/// and starts, only with Kconfig `PTPD`, and then the built-in topology also
/// declares the `[clock]` row naming the domain the daemon serves.
///
/// **Canary.** Give the row `READ` on `clock`: the permission assertion goes
/// red (it would claim to be the clock service, not a caller of it). With
/// `PTPD` off the test checks only that no row and no clock row exist.
#[test]
fn the_daemon_row_writes_clock_and_reads_the_root() {
    let t = default_minimal();
    assert_eq!(t.admission_check(), Ok(()));
    let row = t.tasks().iter().find(|r| r.name.as_bytes() == azos_topology::builder::TASK_PTPD_IMAGE);
    assert_eq!(row.is_some(), azos_topology::builder::PTPD_ROW, "a row exactly when Kconfig PTPD");
    let Some(row) = row else {
        assert_eq!(t.clock().ptp_domain, None, "no daemon, no PTP domain declared");
        return;
    };
    let caps = t.caps_of(row);
    assert_eq!(caps.len(), 2);
    assert_eq!((caps[0].kind, caps[0].perms, caps[0].transfer), (CapKind::Endpoint, CapPerms::WRITE, false));
    assert_eq!(caps[0].target.as_bytes(), b"clock");
    assert_eq!((caps[1].kind, caps[1].perms), (CapKind::Node, CapPerms::READ), "the read-only root");
    assert!(row.start, "the kernel starts it with the row");
    assert_eq!(t.clock().ptp_domain, Some(azos_limits::PTPD_DOMAIN as u8), "the domain it serves is the [clock] row's");
}

/// The target the row names is an interface the kernel hosts: a typo in
/// `RESOURCE_CLOCK` would make the row refuse to seed, not fail a build.
#[test]
fn the_clock_endpoint_the_row_names_is_a_kernel_interface() {
    let (iface, badge) = azos_devif::parse_target("clock").expect("clock names an interface");
    assert_eq!((iface.id, badge), (azos_devif::CLOCK_ID, 0));
}

/// The kernel's view carries the row's domain as a number
/// (`kernel/src/boot/inspect_views.rs`); every domain the row may declare
/// reads back.
#[test]
fn every_declarable_domain_reads_back_from_the_view() {
    for d in 0..=azos_topology::PTP_DOMAIN_MAX {
        assert_eq!(link::domain_of(Some(d as u64)), Some(d));
    }
}
