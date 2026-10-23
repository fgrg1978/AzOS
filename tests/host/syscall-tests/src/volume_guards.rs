// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Volume` interface --
// `crates/core/syscall/src/volume_host.rs::Server`: the authority in front of
// the check hook (the endpoint's `WRITE`), the volume its badge names, and
// what it answers. The check itself is `azos_fs`'s (`tests/host/fs-tests`).
//
// Included inside `mod handlers { .. }` like `memctl_guards.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::volume::{badge, FLAG_COMPLETE, VOLUMES};
use azos_devif::{outcome, Out, Volume, VolumeReport};
use crate::khost::Caller;

const TID: u32 = 0x7e45_0020;

fn server(badge: u32, rights: CapPerms) -> crate::volume_host::Server {
    crate::volume_host::Server(Caller { tid: TID, badge, rights })
}

/// What the hook was asked last.
static ASKED: std::sync::Mutex<Option<(u32, bool)>> = std::sync::Mutex::new(None);

/// Volume 0 holds one problem; any other is not mounted.
fn hook(n: u32, scrub: bool) -> Result<VolumeReport, u32> {
    *ASKED.lock().unwrap() = Some((n, scrub));
    if n == 0 {
        Ok(VolumeReport { problems: 1, leaked: 3, flags: FLAG_COMPLETE, ..VolumeReport::default() })
    } else {
        Err(outcome::NO_RESOURCE)
    }
}

/// No `WRITE`, no check (and the hook is not asked); a badge that names no
/// volume is `NO_RESOURCE`; a kernel with no check answers `UNSUPPORTED`;
/// then the hook's report or outcome, for the volume the badge names.
///
/// **Canary.** Drop the `gate` in `Server::check`: red on the `DENIED` line.
#[test]
fn the_check_needs_write_and_checks_the_volume_its_badge_names() {
    let _g = serial();
    *ASKED.lock().unwrap() = None;
    for rights in [CapPerms::READ, CapPerms::EXEC, CapPerms::NONE] {
        assert_eq!(server(badge(0), rights).check(false), Out::err(outcome::DENIED), "{rights:?}");
    }
    assert!(ASKED.lock().unwrap().is_none(), "a refused call reaches nothing");
    for b in [0, badge(VOLUMES)] {
        assert_eq!(server(b, CapPerms::WRITE).check(false), Out::err(outcome::NO_RESOURCE), "badge {b}");
    }
    // Only this test installs the check, after this line.
    assert_eq!(server(badge(0), CapPerms::WRITE).check(false), Out::err(outcome::UNSUPPORTED));
    crate::volume_host::set_check_hook(hook);
    let r = server(badge(0), CapPerms::WRITE).check(true);
    assert_eq!((r.code, r.value.problems, r.value.leaked), (outcome::OK, 1, 3));
    assert_eq!(*ASKED.lock().unwrap(), Some((0, true)));
    assert_eq!(server(badge(3), CapPerms::RW).check(false), Out::err(outcome::NO_RESOURCE));
    assert_eq!(*ASKED.lock().unwrap(), Some((3, false)), "the row on partition 3");
}
