// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `refresh`, `outdated` and `upgrade` through the installer's own library over
//! an in-memory volume: the report, the refusals, and the version that replaces
//! the staged one.

use super::service::{Fake, MemVol, Rig, SOURCE_ROWS};
use super::*;
use azos_decision::{Rule, Verdict};
use azos_packages::{id_words, name_words, standing, step, step_name, step_of, status, FetchErr, Packages};
use azos_pkg::index::Version;

fn other() -> SigningKey {
    SigningKey::from_bytes(&[0xC3; 32])
}

fn device_with_two_signers() -> Device0 {
    Device0::with_signers(&format!("{}{}", signer_text("acme", &author(), CEILING), signer_text("other", &other(), CEILING)))
}

fn pkg(version: &str) -> Vec<u8> {
    let mut s = Spec::acme();
    s.version = version.into();
    build(&s, &author())
}

fn v(s: &str) -> u64 {
    Version::parse(s).unwrap().packed()
}

const NAME: &str = "acme-vision";
/// All three version words mean something.
const ALL: u64 = standing::HAS_INSTALLED | standing::HAS_OFFERED | standing::HAS_FLOOR;

/// A device with `installed` staged and the source configured.
fn rig_with(installed: &str) -> Rig {
    let mut r = Rig::new(MemVol::device(&device_with_two_signers(), &owner()));
    r.vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), SOURCE_ROWS.to_vec());
    let (cap, len) = r.put(1, &pkg(installed));
    assert_eq!(r.service().install(cap, len)[0], 0);
    r
}

/// The repository serving `offered` (and its index, signed by `signer`).
fn repo(serial: u32, offered: &[u8], floor: Option<&str>, signer: &SigningKey) -> Fake {
    let body = index_body(serial, &[Offer::of(offered, "ACMEV.PKG", floor)]);
    Fake::repository(&[("INDEX.AZX", build_index(&body, signer)), ("ACMEV.PKG", offered.to_vec())])
}

fn row_facts(r: &mut Rig, i: u32) -> [u64; 4] {
    r.service().outdated(i, 1)
}

fn journal_tail(r: &Rig, n: usize) -> Vec<(u8, u8, [u64; 3])> {
    let j = r.vol.borrow().journal();
    j[j.len() - n..].iter().map(|p| (p.rule, p.verdict, p.n)).collect()
}

#[test]
fn refresh_reports_what_is_behind_and_what_is_below_its_floor() {
    let mut r = rig_with("1.0.0");
    assert_eq!(r.service().outdated(0, 1)[0], status(step::NO_REPORT, 0), "no report before a refresh");

    let offered = pkg("1.3.0");
    let mut svc = r.service_with(repo(7, &offered, Some("1.2.0"), &author()));
    let reply = svc.refresh();
    assert_eq!(svc.remote.asked, ["INDEX.AZX"], "the index is the file beside the package the source names");
    drop(svc);
    assert_eq!(reply, [0, 7, 1, 1]);

    assert_eq!(r.service().outdated(0, 0), name_words(NAME.as_bytes()).unwrap());
    let facts = row_facts(&mut r, 0);
    let want = standing::BEHIND | standing::FLOOR_BELOW | standing::BELOW | ALL;
    assert_eq!(facts, [status(step::ROW, want), v("1.0.0"), v("1.3.0"), v("1.2.0")]);
    assert_eq!(r.service().outdated(1, 1), [0; 4], "all zero past the last row");
    assert_eq!(r.service().outdated(0, 2)[0], status(step::BAD_ARG, 1));

    // The verified index is kept for the boot-time apply, and the acceptance is a decision.
    let stored = r.vol.borrow().files[&slot_path(&author())[..]].clone();
    let body = index_body(7, &[Offer::of(&offered, "ACMEV.PKG", Some("1.2.0"))]);
    assert_eq!(stored, build_index(&body, &author()));
    assert_eq!(journal_tail(&r, 1), vec![(Rule::PackageIndex as u8, Verdict::Admit as u8, [1, 7, 0])]);
}

#[test]
fn a_current_package_and_a_package_the_index_does_not_list_are_not_behind() {
    let mut r = rig_with("1.3.0");
    let offered = pkg("1.3.0");
    r.service_with(repo(1, &offered, None, &author())).refresh();
    assert_eq!(row_facts(&mut r, 0)[0], status(step::ROW, standing::CURRENT | standing::HAS_INSTALLED | standing::HAS_OFFERED));
    // The same index for a package it does not list.
    let mut s = Spec::acme();
    s.name = "elsewhere".into();
    let body = index_body(2, &[Offer::of(&build(&s, &author()), "X.PKG", None)]);
    let fake = Fake::repository(&[("INDEX.AZX", build_index(&body, &author()))]);
    r.service_with(fake).refresh();
    assert_eq!(row_facts(&mut r, 0)[0], status(step::ROW, standing::NOT_LISTED | standing::HAS_INSTALLED));
}

/// **Canary** `pkg-verify-skip-canary`, `pkg-signer-canary`: the forged index is accepted.
#[test]
fn a_refused_index_changes_nothing_and_is_a_decision() {
    let mut r = rig_with("1.0.0");
    let offered = pkg("1.3.0");
    assert_eq!(r.service_with(repo(7, &offered, Some("1.2.0"), &author())).refresh()[0], 0);
    let kept = r.vol.borrow().files[&slot_path(&author())[..]].clone();

    let body = index_body(9, &[Offer::of(&offered, "ACMEV.PKG", Some("99.0"))]);
    let mut tampered = build_index(&body, &author());
    let at = tampered.len() - 3;
    tampered[at] ^= 1;
    let stale_body = index_body(6, &[Offer::of(&offered, "ACMEV.PKG", None)]);
    let cases: [(&str, Vec<u8>, usize, u64); 3] = [
        ("tampered", tampered, 22, 7),
        ("wrong signer", build_index(&body, &stranger()), 22, 6),
        ("older serial", build_index(&stale_body, &author()), 22, 16),
    ];
    for (what, bytes, step_no, detail) in cases {
        let reply = r.service_with(Fake::repository(&[("INDEX.AZX", bytes)])).refresh();
        assert_eq!(step_of(reply[0]), step_no, "{what}: {}", step_name(reply[0]));
        assert_eq!(reply[0] & 0xFF_FFFF, detail, "{what}");
        assert_eq!(r.vol.borrow().files[&slot_path(&author())[..]], kept, "{what}: the stored index is untouched");
        assert_eq!(r.service().outdated(0, 1)[0], status(step::NO_REPORT, 0), "{what}: no report from a refused index");
        assert_eq!(journal_tail(&r, 1)[0].1, Verdict::Refuse as u8, "{what}");
    }
}

#[test]
fn an_index_that_does_not_arrive_is_a_fetch_status_that_records_nothing() {
    let mut r = rig_with("1.0.0");
    let before = r.vol.borrow().journal().len();
    let mut fake = Fake::repository(&[]);
    fake.siblings.insert("INDEX.AZX".into(), Err(FetchErr::Connect));
    assert_eq!(r.service_with(fake).refresh(), [status(step::FETCH, FetchErr::Connect.code()), 0, 0, 0]);
    assert_eq!(r.service_with(Fake::repository(&[])).refresh(), [status(step::FETCH, FetchErr::Status.code()), 0, 0, 0]);
    r.vol.borrow_mut().files.remove(&b"/fat/PKG/SOURCE.CFG"[..]);
    assert_eq!(r.service_with(Fake::repository(&[])).refresh(), [status(step::FETCH, FetchErr::NoSource.code()), 0, 0, 0]);
    assert_eq!(r.vol.borrow().journal().len(), before);
    assert!(r.vol.borrow().files.get(&slot_path(&author())[..]).is_none());
}

#[test]
fn upgrade_installs_the_newer_version_in_place_of_the_staged_one() {
    let mut r = rig_with("1.0.0");
    let (old, offered) = (pkg("1.0.0"), pkg("1.3.0"));
    let (old_id, new_id) = (azos_pkg::Package::parse(&old).unwrap().id(), azos_pkg::Package::parse(&offered).unwrap().id());
    r.service_with(repo(7, &offered, Some("1.2.0"), &author())).refresh();

    let mut svc = r.service_with(repo(7, &offered, Some("1.2.0"), &author()));
    let reply = svc.upgrade(name_words(NAME.as_bytes()).unwrap());
    assert_eq!(svc.remote.asked, ["ACMEV.PKG"], "the package the index names");
    drop(svc);
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    assert_eq!(reply[1], azos_pkg::receipt::id_prefix(&new_id));

    // The new version is staged beside the old one, and the pair is recorded in
    // the same transaction: the boot leaves the old one out while the new is on
    // trial, drops it on confirmation, applies it again on a rollback.
    let staged = r.vol.borrow().staged();
    assert_eq!(staged.len(), 2, "{staged:?}");
    let files: Vec<Vec<u8>> = staged.iter().map(|p| r.vol.borrow().files[p.as_bytes()].clone()).collect();
    assert!(files.contains(&old) && files.contains(&offered), "both versions are staged");
    let sup = r.vol.borrow().files[&b"/fat/PKG/SUPERSEDE.REQ"[..]].clone();
    assert_eq!(sup, [old_id, new_id].concat());
    // The receipt: the new version admitted; the old one is taken away by the boot, with its own record.
    let j = r.vol.borrow().journal();
    let last = j.last().unwrap();
    let id8 = azos_pkg::receipt::id_prefix;
    assert_eq!((last.verdict, last.image_hash_prefix), (Verdict::Admit as u8, id8(&new_id)));
    assert!(j.iter().all(|p| p.verdict != Verdict::Deny as u8), "nothing is removed by the installer");
    // And the report knows: nothing left to do.
    assert_eq!(row_facts(&mut r, 0), [status(step::ROW, standing::CURRENT | standing::FLOOR_MET | ALL), v("1.3.0"), v("1.3.0"), v("1.2.0")]);
    let again = r.service_with(repo(7, &offered, Some("1.2.0"), &author())).upgrade(name_words(NAME.as_bytes()).unwrap());
    assert_eq!((step_of(again[0]), again[0] & 0xFF_FFFF), (23, 12), "the upgrade is not confirmed yet: {}", step_name(again[0]));
}

/// **Canary** `pkg-floor-canary` (the floor row); the others are refusals the
/// installer makes whatever the canaries skip.
#[test]
fn an_upgrade_that_the_index_does_not_allow_is_refused_and_leaves_the_staged_package() {
    // (what, the offered package, floor, signer of the index, step detail)
    let swapped = {
        let mut s = Spec::acme();
        s.version = "1.3.0".into();
        s.images = vec![("ACME.ELF".into(), vec![9; 40])];
        build(&s, &author())
    };
    let mut other_signer = Spec::acme();
    other_signer.version = "1.3.0".into();
    let by_other = build(&other_signer, &other());
    let cases: Vec<(&str, Vec<u8>, Option<&str>, Vec<u8>, u64)> = vec![
        // The file served is not the build the index pins.
        ("another build than pinned", pkg("1.3.0"), None, swapped, 7),
        // The file is pinned, verifies, and is another author's.
        ("another signer", by_other.clone(), None, by_other, 9),
    ];
    for (what, listed, floor, served, detail) in cases {
        let mut r = rig_with("1.0.0");
        let before = r.vol.borrow().staged();
        let body = index_body(7, &[Offer::of(&listed, "ACMEV.PKG", floor)]);
        let fake = || Fake::repository(&[("INDEX.AZX", build_index(&body, &author())), ("ACMEV.PKG", served.clone())]);
        assert_eq!(r.service_with(fake()).refresh()[0], 0, "{what}");
        let reply = r.service_with(fake()).upgrade(name_words(NAME.as_bytes()).unwrap());
        assert_eq!((step_of(reply[0]), reply[0] & 0xFF_FFFF), (23, detail), "{what}: {}", step_name(reply[0]));
        assert_eq!(r.vol.borrow().staged(), before, "{what}");
        let last = journal_tail(&r, 1)[0];
        assert_eq!((last.0, last.1), (Rule::PackageInstall as u8, Verdict::Refuse as u8), "{what}");
    }
}

/// An index offering something older than what is staged (or the same) installs nothing.
///
/// Canary (manual): let `upgrade_entry` accept `Availability::Ahead`.
#[test]
fn an_older_offer_is_not_an_upgrade() {
    let mut r = rig_with("2.0.0");
    let offered = pkg("1.5.0");
    r.service_with(repo(7, &offered, None, &author())).refresh();
    assert_eq!(row_facts(&mut r, 0)[0], status(step::ROW, standing::AHEAD | standing::HAS_INSTALLED | standing::HAS_OFFERED));
    let mut svc = r.service_with(repo(7, &offered, None, &author()));
    let reply = svc.upgrade(name_words(NAME.as_bytes()).unwrap());
    assert!(svc.remote.asked.is_empty(), "nothing is fetched for it");
    drop(svc);
    assert_eq!((step_of(reply[0]), reply[0] & 0xFF_FFFF), (23, 5), "{}", step_name(reply[0]));
    assert_eq!(r.vol.borrow().staged().len(), 1);
}

#[test]
fn upgrade_without_a_report_or_for_a_package_that_is_not_staged_is_refused() {
    let mut r = rig_with("1.0.0");
    assert_eq!(r.service().upgrade(name_words(NAME.as_bytes()).unwrap())[0], status(step::NO_REPORT, 0));
    let offered = pkg("1.3.0");
    r.service_with(repo(7, &offered, None, &author())).refresh();
    let reply = r.service().upgrade(name_words(b"nothing-here").unwrap());
    assert_eq!((step_of(reply[0]), reply[0] & 0xFF_FFFF), (23, 1), "{}", step_name(reply[0]));
    // The package goes away between the report and the upgrade.
    let id = azos_pkg::Package::parse(&pkg("1.0.0")).unwrap().id();
    assert_eq!(r.service().remove(id_words(&id))[0], 0);
    let reply = r.service_with(repo(7, &offered, None, &author())).upgrade(name_words(NAME.as_bytes()).unwrap());
    assert_eq!((step_of(reply[0]), reply[0] & 0xFF_FFFF), (23, 1), "{}", step_name(reply[0]));
    assert!(r.vol.borrow().staged().is_empty(), "nothing was installed in its place");
}

#[test]
fn an_upgrade_the_journal_cannot_record_is_undone() {
    let mut r = rig_with("1.0.0");
    let (old, offered) = (pkg("1.0.0"), pkg("1.3.0"));
    r.service_with(repo(7, &offered, None, &author())).refresh();
    let before = r.vol.borrow().staged();
    r.vol.borrow_mut().fail_append = true;
    let reply = r.service_with(repo(7, &offered, None, &author())).upgrade(name_words(NAME.as_bytes()).unwrap());
    assert_eq!(step_of(reply[0]), step::IO as usize);
    assert_eq!(r.vol.borrow().staged(), before);
    assert_eq!(r.vol.borrow().files[before[0].as_bytes()], old, "the package that was staged is still the one staged");
}

/// One slot and one serial per signer: another signer's index neither replaces
/// this signer's floors nor uses up its serial.
///
/// **Canary (manual):** make `slot_path` in the service ignore the key id; the
/// first assertion after the second refresh goes red.
#[test]
fn each_signer_keeps_its_own_index_and_its_own_serial() {
    let mut r = rig_with("1.0.0");
    let offered = pkg("1.3.0");
    assert_eq!(r.service_with(repo(7, &offered, Some("1.2.0"), &author())).refresh()[..2], [0, 7]);
    let a_slot = r.vol.borrow().files[&slot_path(&author())[..]].clone();

    // Another signer publishes the highest serial there is, for a package of its own.
    let mut s = Spec::acme();
    s.name = "other-pkg".into();
    s.version = "1.0.0".into();
    let theirs = build(&s, &other());
    let body = index_body(u32::MAX, &[Offer::of(&theirs, "OTHER.PKG", None)]);
    let fake = Fake::repository(&[("INDEX.AZX", build_index(&body, &other()))]);
    assert_eq!(r.service_with(fake).refresh()[..2], [0, u32::MAX as u64]);
    assert_eq!(r.vol.borrow().files[&slot_path(&author())[..]], a_slot, "the first signer's slot is untouched");
    assert!(r.vol.borrow().files.contains_key(&slot_path(&other())[..]), "the second has its own");
    assert_ne!(slot_path(&author()), slot_path(&other()));

    // The first signer's next index is not stale because of the second's serial.
    assert_eq!(r.service_with(repo(8, &offered, Some("1.2.0"), &author())).refresh()[..2], [0, 8]);
    // And a lower one from the first signer still is.
    let reply = r.service_with(repo(5, &offered, Some("1.2.0"), &author())).refresh();
    assert_eq!((step_of(reply[0]), reply[0] & 0xFF_FFFF), (22, 16), "{}", step_name(reply[0]));
}

/// The same serial is the same index: a body that differs at a serial the signer
/// already published is refused; the same body again is not.
#[test]
fn an_index_that_differs_at_the_same_serial_is_refused() {
    let mut r = rig_with("1.0.0");
    let offered = pkg("1.3.0");
    assert_eq!(r.service_with(repo(7, &offered, Some("1.2.0"), &author())).refresh()[0], 0);
    assert_eq!(r.service_with(repo(7, &offered, Some("1.2.0"), &author())).refresh()[0], 0, "the same index again");
    let kept = r.vol.borrow().files[&slot_path(&author())[..]].clone();
    let reply = r.service_with(repo(7, &offered, Some("1.1.0"), &author())).refresh();
    assert_eq!((step_of(reply[0]), reply[0] & 0xFF_FFFF), (22, 17), "{}", step_name(reply[0]));
    assert_eq!(r.vol.borrow().files[&slot_path(&author())[..]], kept);
}

/// The stored index is read whole whatever its size (up to the Kconfig bound),
/// so the stale check is never skipped for a large one.
#[test]
fn a_full_size_index_is_stored_and_still_guards_the_serial() {
    let mut r = rig_with("1.0.0");
    let offers = |serial: u32| {
        let o: Vec<Offer> = (0..azos_pkg::index::MAX_ENTRIES)
            .map(|i| Offer { name: format!("p{i:04}-{}", "x".repeat(20)), version: "1.0.0".into(), sec_floor: Some("0.9.0".into()), id: [i as u8; 32], file: "F".repeat(30) })
            .collect();
        Fake::repository(&[("INDEX.AZX", build_index(&index_body(serial, &o), &author()))])
    };
    assert_eq!(r.service_with(offers(9)).refresh()[..2], [0, 9]);
    let before = r.vol.borrow().files[&slot_path(&author())[..]].clone();
    assert!(before.len() > 8000, "a large index: {}", before.len());
    let reply = r.service_with(offers(8)).refresh();
    assert_eq!((step_of(reply[0]), reply[0] & 0xFF_FFFF), (22, 16), "{}", step_name(reply[0]));
    // A write that fails puts the old one back, it does not remove it.
    r.vol.borrow_mut().fail_append = true;
    let reply = r.service_with(offers(10)).refresh();
    assert_eq!(step_of(reply[0]), step::IO as usize);
    assert_eq!(r.vol.borrow().files[&slot_path(&author())[..]], before, "restored, not removed");
}
