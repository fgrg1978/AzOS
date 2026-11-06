// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The launch check of an exec (`exec_grant.rs`), the one `SYS_SPAWN_EX` and the
// Linux `execve` share: what a task's launch grants admit, and the one
// `exec-grant` record every answer leaves. The spawn and execve call sites are
// not compiled here; what they ask is `decide`.

use super::harness::serial;
use crate::exec_grant::{decide, grant_for, record, Basis, Site, SKIP_CHECK};
use azos_abi::cap::CapPerms;
use azos_decision::{Rule, Verdict};
use azos_sched::seccomp::{package_profile, register_package_images, PackageImage};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Once;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7400_0001);

/// A task bound to pool slot `slot`: callers alive together need slots of their own.
fn caller_in(slot: usize) -> u32 {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, slot);
    azos_ipc::cap_store::reset(tid);
    tid
}

fn caller() -> u32 {
    caller_in(49)
}

fn pkg_target(id: &[u8; 32]) -> String {
    format!("pkg.{}", id.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

const PKG_A: [u8; 32] = [0xA1; 32];
const PKG_B: [u8; 32] = [0xB2; 32];
const PKG_LOW: [u8; 32] = [0xC3; 32];
const MEMBER: [u8; 32] = [0x11; 32];
const LOW: [u8; 32] = [0x77; 32];
const STRANGER: [u8; 32] = [0x22; 32];

/// The applied package table is bound once per process: `PKG_A` carries
/// `MEMBER.ELF`.
fn applied() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let table: &'static [PackageImage] = Box::leak(
            vec![
                PackageImage { digest: MEMBER, package: PKG_A, below_floor: false, profile: package_profile("MEMBER.ELF", &[]) },
                PackageImage { digest: LOW, package: PKG_LOW, below_floor: true, profile: package_profile("LOWPKG.ELF", &[]) },
            ]
            .into_boxed_slice(),
        );
        assert!(register_package_images(table));
    });
}

/// The records of `rule` since `since`, as (verdict, subject, n).
fn records(since: u64) -> Vec<(u8, u32, [u64; 3])> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.seq > since && r.rule == Rule::ExecGrant as u8 {
            v.push((r.verdict, r.subject, r.n));
        }
    });
    v
}

fn prefix(d: &[u8; 32]) -> u64 {
    u64::from_be_bytes(d[..8].try_into().unwrap())
}

/// **A grant on the image admits it, and any other image is refused**; each
/// answer is one record naming the task, the digest, the basis and the site.
///
/// **Canary.** Make `grant_for` answer `Some(Basis::Image)` always (or arm
/// `SKIP_CHECK`): the refusal assertions go red.
#[test]
fn an_image_grant_admits_that_image_only() {
    let _g = serial();
    let tid = caller();
    let img = "XGRANT01.ELF";
    azos_ipc::launch_cap::launch_grant_cap(tid, img, CapPerms::EXEC).unwrap();
    let digest = [0x33; 32];

    let since = azos_decision::total();
    assert_eq!(decide(tid, Site::SpawnEx, img, &digest), Ok(Basis::Image));
    assert_eq!(records(since), vec![(Verdict::Admit as u8, tid, [prefix(&digest), Basis::Image as u64, Site::SpawnEx as u64])]);

    // An image another task holds a grant on is not this task's.
    azos_ipc::launch_cap::launch_resource(b"XGRANT02.ELF").unwrap();
    let since = azos_decision::total();
    assert!(decide(tid, Site::Execve, "XGRANT02.ELF", &digest).is_err());
    assert!(decide(tid, Site::Execve, "XNOGRANT.ELF", &digest).is_err(), "an image no grant names");
    assert_eq!(
        records(since),
        vec![(Verdict::Refuse as u8, tid, [prefix(&digest), Basis::NoGrant as u64, Site::Execve as u64]); 2]
    );
}

/// **The grant is on the bytes' image, not on the name the caller typed**: the
/// check takes the image the digest resolved to. A task holding no grant is
/// refused whatever the path was.
#[test]
fn a_task_with_no_grant_is_refused() {
    let _g = serial();
    let tid = caller();
    azos_ipc::launch_cap::launch_resource(b"XGRANT03.ELF").unwrap();
    assert_eq!(grant_for(tid, "XGRANT03.ELF", &[0x44; 32]), None);
}

/// **A package grant admits the images the package carries, and no others**:
/// an image of another package, bytes no package carries, and a task holding a
/// grant on another package are refused.
///
/// **Canary.** Resolve `package_of_digest` to `None`, or skip the `filter`
/// over `holds` in `grant_for`: the admission or a refusal goes red.
#[test]
fn a_package_grant_admits_the_packages_images_only() {
    let _g = serial();
    applied();
    let holder = caller_in(49);
    azos_ipc::launch_cap::launch_grant_cap(holder, &pkg_target(&PKG_A), CapPerms::EXEC).unwrap();
    let other = caller_in(50);
    azos_ipc::launch_cap::launch_grant_cap(other, &pkg_target(&PKG_B), CapPerms::EXEC).unwrap();
    let none = caller_in(45);

    let since = azos_decision::total();
    assert_eq!(decide(holder, Site::Execve, "MEMBER.ELF", &MEMBER), Ok(Basis::Package));
    assert_eq!(records(since), vec![(Verdict::Admit as u8, holder, [prefix(&MEMBER), Basis::Package as u64, Site::Execve as u64])]);

    assert!(decide(holder, Site::Execve, "MEMBER.ELF", &STRANGER).is_err(), "bytes no package carries");
    assert!(decide(other, Site::Execve, "MEMBER.ELF", &MEMBER).is_err(), "a grant on another package");
    assert!(decide(none, Site::Execve, "MEMBER.ELF", &MEMBER).is_err(), "no grant at all");
}

/// **An image grant and a package grant are independent**: the image's own
/// grant admits it as an image even where its package is not granted.
#[test]
fn an_image_grant_wins_over_an_ungranted_package() {
    let _g = serial();
    applied();
    let tid = caller();
    azos_ipc::launch_cap::launch_grant_cap(tid, "MEMBER.ELF", CapPerms::EXEC).unwrap();
    assert_eq!(grant_for(tid, "MEMBER.ELF", &MEMBER), Some(Basis::Image));
}

/// **The refusals the callers write themselves** (bytes bound to no image,
/// a native row) are records of the same rule, with their own basis.
#[test]
fn a_caller_records_its_own_refusals() {
    let _g = serial();
    let tid = caller();
    let since = azos_decision::total();
    record(tid, Site::Execve, Basis::Unbound, &[0x55; 32]);
    record(tid, Site::Execve, Basis::NotLinuxRow, &[0x56; 32]);
    record(tid, Site::Execve, Basis::OwnRow, &[0x57; 32]);
    let r = records(since);
    assert_eq!(r.iter().map(|x| (x.0, x.2[1])).collect::<Vec<_>>(), vec![
        (Verdict::Refuse as u8, Basis::Unbound as u64),
        (Verdict::Refuse as u8, Basis::NotLinuxRow as u64),
        (Verdict::Admit as u8, Basis::OwnRow as u64),
    ]);
}

/// **The canary switch finds a grant on every image** (what the runtime
/// canary `exec-grant-skip` arms); with it off the check is what the tests
/// above say. The last assertion is the half that discriminates.
#[test]
fn the_skip_switch_is_the_only_way_past_the_check() {
    let _g = serial();
    let tid = caller();
    azos_ipc::launch_cap::launch_resource(b"XGRANT04.ELF").unwrap();
    assert_eq!(grant_for(tid, "XGRANT04.ELF", &[0x66; 32]), None);
    SKIP_CHECK.store(true, Ordering::Relaxed);
    let skipped = grant_for(tid, "XGRANT04.ELF", &[0x66; 32]);
    SKIP_CHECK.store(false, Ordering::Relaxed);
    assert_eq!(skipped, Some(Basis::Image));
    assert_eq!(grant_for(tid, "XGRANT04.ELF", &[0x66; 32]), None);
}

/// **A program of a package below its security floor is refused whatever the
/// caller holds**: a grant on the image and a grant on the package both admit
/// every other program, and this one is refused with the basis that says why,
/// at both sites. The grant check itself is untouched (`grant_for` still finds
/// the grant): the floor is policy, written as its own record.
///
/// **Canary.** Remove the `package_below_floor` test from `decide`: the
/// refusal assertions go red.
#[test]
fn a_package_below_its_security_floor_is_refused_whatever_the_grants() {
    let _g = serial();
    applied();
    let tid = caller();
    azos_ipc::launch_cap::launch_grant_cap(tid, &pkg_target(&PKG_LOW), CapPerms::EXEC).unwrap();
    azos_ipc::launch_cap::launch_grant_cap(tid, "LOWPKG.ELF", CapPerms::EXEC).unwrap();
    assert_eq!(grant_for(tid, "LOWPKG.ELF", &LOW), Some(Basis::Image), "the caller holds the grants");

    for site in [Site::SpawnEx, Site::Execve] {
        let since = azos_decision::total();
        assert!(decide(tid, site, "LOWPKG.ELF", &LOW).is_err(), "{site:?}");
        assert_eq!(
            records(since),
            vec![(Verdict::Refuse as u8, tid, [prefix(&LOW), Basis::BelowSecFloor as u64, site as u64])],
            "one record, naming the floor"
        );
    }
    assert!(!Basis::BelowSecFloor.admitted());

    // The same caller launches a package program that is not below its floor.
    azos_ipc::launch_cap::launch_grant_cap(tid, &pkg_target(&PKG_A), CapPerms::EXEC).unwrap();
    assert_eq!(decide(tid, Site::SpawnEx, "MEMBER.ELF", &MEMBER), Ok(Basis::Package));
}
