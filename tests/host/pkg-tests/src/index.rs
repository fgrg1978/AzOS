// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The repository index (`crates/core/pkg/src/index.rs`): its verification, the
//! standing of installed packages against it, and what an upgrade may install.

use super::*;
use azos_pkg::index::{
    assess, MarkTable, Mark, check_upgrade, upgrade_entry, Availability, Floor, IndexWhy, Installed, UpgradeWhy, Version, VersionError,
};
use azos_pkg::{index, Meta, Package};

fn dev() -> Device0 {
    Device0::with_signers(&signer_text("acme", &author(), CEILING))
}

fn two_signers() -> Device0 {
    let other = SigningKey::from_bytes(&[0xC3; 32]);
    Device0::with_signers(&format!("{}{}", signer_text("acme", &author(), CEILING), signer_text("other", &other, CEILING)))
}

fn pkg_at(version: &str) -> Vec<u8> {
    let mut s = Spec::acme();
    s.version = version.into();
    build(&s, &author())
}

fn id_of(bytes: &[u8]) -> [u8; 32] {
    Package::parse(bytes).unwrap().id()
}

fn installed<'a>(version: &'a str, signer_index: usize) -> Installed<'a> {
    Installed { name: "acme-vision", version, signer_index, id: [0x11; 32] }
}

/// An index offering `offered` with `floor`, signed by the author.
fn index_for(offered: &str, floor: Option<&str>) -> (Vec<u8>, Vec<u8>) {
    let pkg = pkg_at(offered);
    let body = index_body(7, &[Offer::of(&pkg, "ACMEVIS1.PKG", floor)]);
    (build_index(&body, &author()), pkg)
}

#[test]
fn a_good_index_verifies_and_lists_its_entries() {
    let d = dev();
    let topo = d.topology();
    let a = pkg_at("1.3.0");
    let mut s = Spec::acme();
    s.name = "zeta".into();
    s.version = "9.0".into();
    let z = build(&s, &author());
    let body = index_body(42, &[Offer::of(&z, "ZETA.PKG", None), Offer::of(&a, "ACMEVIS1.PKG", Some("1.2.0"))]);
    let bytes = build_index(&body, &author());
    let ix = index::verify(&bytes, &topo).expect("verifies");
    assert_eq!((ix.serial, ix.entries, ix.signer_index), (42, 2, 0));
    let e = ix.find("acme-vision").unwrap();
    assert_eq!((e.version, e.sec_floor, e.file, e.id), (Version([1, 3, 0, 0]), Some(Version([1, 2, 0, 0])), "ACMEVIS1.PKG", id_of(&a)));
    assert_eq!(ix.get(1).unwrap().name, "zeta");
    assert!(ix.get(2).is_none() && ix.find("nope").is_none());
}

/// **Canary** `pkg-verify-skip-canary`: the tampered index verifies.
#[test]
fn a_tampered_index_is_refused() {
    let d = dev();
    let topo = d.topology();
    let (good, _) = index_for("1.3.0", Some("1.2.0"));
    // A bit of the body, after signing: the floor moved.
    let mut bytes = good.clone();
    let at = bytes.len() - 20;
    bytes[at] ^= 0x01;
    assert_eq!(index::verify(&bytes, &topo).unwrap_err(), IndexWhy::Signature);
    // A bit of the signature.
    let mut bytes = good.clone();
    bytes[index::HEADER_LEN + 32 + 3] ^= 0x01;
    assert_eq!(index::verify(&bytes, &topo).unwrap_err(), IndexWhy::Signature);
    // A package's signature over its message is not an index signature.
    let body = index_body(1, &[]);
    let s = Spec::acme();
    let sig = author().sign(&azos_pkg::message(1, body.as_bytes(), s.rows.as_bytes())).to_bytes();
    let replay = assemble_index(1, author().verifying_key().as_bytes(), &sig, body.as_bytes());
    assert_eq!(index::verify(&replay, &topo).unwrap_err(), IndexWhy::Signature);
}

/// **Canary** `pkg-signer-canary`: the stranger's index verifies.
#[test]
fn an_index_signed_by_a_key_the_device_does_not_admit_is_refused() {
    let d = dev();
    let topo = d.topology();
    let pkg = pkg_at("1.3.0");
    let body = index_body(7, &[Offer::of(&pkg, "ACMEVIS1.PKG", None)]);
    assert_eq!(index::verify(&build_index(&body, &stranger()), &topo).unwrap_err(), IndexWhy::UnknownSigner);
    let zero = assemble_index(1, &[0; 32], &[0; 64], body.as_bytes());
    assert_eq!(index::verify(&zero, &topo).unwrap_err(), IndexWhy::UnknownSigner);
    assert_eq!(index::verify(&assemble_index(0, &[], &[], body.as_bytes()), &topo).unwrap_err(), IndexWhy::Algorithm);
}

#[test]
fn a_file_that_is_not_an_index_is_refused_before_anything_is_read() {
    let d = dev();
    let topo = d.topology();
    let (good, _) = index_for("1.3.0", None);
    assert_eq!(index::verify(&good[..10], &topo).unwrap_err(), IndexWhy::Short);
    assert_eq!(index::verify(&good[..good.len() - 1], &topo).unwrap_err(), IndexWhy::Short);
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(index::verify(&longer, &topo).unwrap_err(), IndexWhy::Length);
    assert_eq!(index::verify(&build(&Spec::acme(), &author()), &topo).unwrap_err(), IndexWhy::Magic);
    let mut other_format = good.clone();
    other_format[4] = 9;
    assert_eq!(index::verify(&other_format, &topo).unwrap_err(), IndexWhy::Format);
}

/// The body is checked to the byte, after a signature that verifies.
#[test]
fn a_malformed_body_is_refused_even_when_signed() {
    let d = dev();
    let topo = d.topology();
    let id = hex(&[0xAB; 32]);
    let ok = format!("format = 1\nserial = 1\n[pkg.a]\nversion = \"1.0\"\nid = \"{id}\"\nfile = \"A.PKG\"\n");
    assert!(index::verify(&build_index(&ok, &author()), &topo).is_ok());
    let cases: Vec<(&str, String, IndexWhy)> = vec![
        ("format not first", ok.replacen("format = 1\n", "serial = 1\n", 1), IndexWhy::BodyFormat),
        ("another body format", ok.replacen("format = 1", "format = 2", 1), IndexWhy::BodyFormat),
        ("no serial", ok.replacen("serial = 1\n", "", 1), IndexWhy::Missing),
        ("unknown key", ok.replacen("file =", "path =", 1), IndexWhy::Unknown),
        ("repeated key", ok.replacen("file =", "version = \"1.1\"\nfile =", 1), IndexWhy::Repeated),
        ("no id", ok.replacen(&format!("id = \"{id}\"\n"), "", 1), IndexWhy::Missing),
        ("an unordered version", ok.replacen("\"1.0\"", "\"1.0-rc1\"", 1), IndexWhy::Value),
        ("a floor that is not a version", format!("{ok}sec_floor = \"x\"\n"), IndexWhy::Value),
        ("a short id", ok.replacen(&id, "abcd", 1), IndexWhy::Value),
        ("a path as file", ok.replacen("A.PKG", "../A.PKG", 1), IndexWhy::Value),
        ("the parent directory as file", ok.replacen("A.PKG", "..", 1), IndexWhy::Value),
        ("the current directory as file", ok.replacen("A.PKG", ".", 1), IndexWhy::Value),
        ("a floor above the offered version", ok.replacen("file =", "sec_floor = \"1.1\"\nfile =", 1), IndexWhy::Value),
        ("a foreign section", format!("{ok}[other.x]\n"), IndexWhy::Unknown),
        ("names out of order", format!("{ok}[pkg.a]\nversion = \"1\"\nid = \"{id}\"\nfile = \"B.PKG\"\n"), IndexWhy::Repeated),
        ("a section before the header", format!("[pkg.a]\n{ok}"), IndexWhy::Missing),
    ];
    for (what, body, why) in cases {
        assert_eq!(index::verify(&build_index(&body, &author()), &topo).unwrap_err(), why, "{what}");
    }
    let raw = b"format = 1\nserial = 1\n\xff";
    let sig = author().sign(&index::message(1, raw)).to_bytes();
    let bytes = assemble_index(1, author().verifying_key().as_bytes(), &sig, raw);
    assert_eq!(index::verify(&bytes, &topo).unwrap_err(), IndexWhy::Text);
    // More entries than the Kconfig bound.
    let many: String = (0..=index::MAX_ENTRIES)
        .map(|i| format!("[pkg.p{i:04}]\nversion = \"1\"\nid = \"{id}\"\nfile = \"F.PKG\"\n"))
        .fold("format = 1\nserial = 1\n".to_string(), |a, e| a + &e);
    assert_eq!(index::verify(&build_index(&many, &author()), &topo).unwrap_err(), IndexWhy::TooMany);
}

#[test]
fn an_older_serial_is_stale_and_the_same_index_is_not_a_different_one() {
    let d = dev();
    let topo = d.topology();
    let (bytes, _) = index_for("1.3.0", None);
    let ix = index::verify(&bytes, &topo).unwrap();
    let m = ix.mark();
    assert_eq!(ix.check_against(None), Ok(()));
    assert_eq!(ix.check_against(Some(m)), Ok(()));
    assert_eq!(ix.check_against(Some(Mark { serial: 8, ..m })), Err(IndexWhy::Stale));
    assert_eq!(ix.check_against(Some(Mark { digest: m.digest ^ 1, ..m })), Err(IndexWhy::Diverged), "another body at the same serial");
    assert_eq!(ix.check_against(Some(Mark { serial: 6, digest: m.digest ^ 1 })), Ok(()), "a newer one may differ");
}

#[test]
fn the_mark_table_goes_on_the_medium_and_only_up() {
    let mut t = MarkTable::new();
    assert!(t.raise(1, Mark { serial: 5, digest: 9 }));
    assert!(!t.raise(1, Mark { serial: 5, digest: 10 }), "the same serial changes nothing");
    assert!(!t.raise(1, Mark { serial: 4, digest: 9 }), "never down");
    assert!(t.raise(1, Mark { serial: 6, digest: 10 }));
    for k in 2..=azos_pkg::index::MARKS_MAX as u32 {
        assert!(t.raise(k, Mark { serial: k, digest: 0 }));
    }
    assert!(!t.raise(99, Mark { serial: 1, digest: 0 }), "a full table takes no more");
    let bytes = t.encode();
    assert_eq!(MarkTable::decode(&bytes), Some(t));
    assert_eq!(MarkTable::decode(&[0u8; 512]), None, "a blank sector holds no marks");
    for at in [0, 4, 5, 7, 20, azos_pkg::index::MARKS_LEN - 1] {
        let mut b = bytes;
        b[at] ^= 1;
        assert_eq!(MarkTable::decode(&b), None, "byte {at}");
    }
}

/// What a signer's floors are when the device remembers its index: the newest
/// one it has seen, or unknown, and unknown is not met. **Canary**
/// `pkg-mark-canary`: a replayed or deleted index passes as the first one.
#[test]
fn a_replayed_deleted_or_diverging_index_leaves_the_floors_unknown() {
    use azos_pkg::index::{judge, Floors};
    let d = two_signers();
    let topo = d.topology();
    let make = |serial: u32, floor: &str| {
        let pkg = pkg_at("1.3.0");
        build_index(&index_body(serial, &[Offer::of(&pkg, "A.PKG", Some(floor))]), &author())
    };
    let (v7, v6, v7b, v8) = (make(7, "1.2.0"), make(6, "1.0.0"), make(7, "1.0.0"), make(8, "1.2.0"));
    let mark = |b: &[u8]| index::verify(b, &topo).unwrap().mark();
    let known = |f: &Floors<'_, '_>| matches!(f, Floors::Known(_));

    // First sight: the floors are the index's, and the mark is recorded.
    let (f, raise) = judge(Some(&v7), &topo, 0, None);
    assert!(known(&f) && raise == Some(mark(&v7)));
    // The same index again, or a newer one.
    let (f, raise) = judge(Some(&v7), &topo, 0, Some(mark(&v7)));
    assert!(known(&f) && raise.is_none());
    let (f, raise) = judge(Some(&v8), &topo, 0, Some(mark(&v7)));
    assert!(known(&f) && raise == Some(mark(&v8)));
    // An older signed index put back, another body at the same serial, no file at all.
    for (what, bytes) in [("older", Some(&v6[..])), ("diverging", Some(&v7b[..])), ("deleted", None)] {
        let (f, raise) = judge(bytes, &topo, 0, Some(mark(&v7)));
        assert!(matches!(f, Floors::Unknown) && raise.is_none(), "{what}");
    }
    // A file that does not verify is no file; with no mark there is nothing to be unknown.
    let mut forged = v7.clone();
    let at = forged.len() - 3;
    forged[at] ^= 1;
    assert!(matches!(judge(Some(&forged), &topo, 0, Some(mark(&v7))).0, Floors::Unknown));
    assert!(matches!(judge(Some(&forged), &topo, 0, None).0, Floors::None));
    assert!(matches!(judge(None, &topo, 0, None).0, Floors::None));
    // An index of one signer is no floor source for the other.
    assert!(matches!(judge(Some(&v7), &topo, 1, None).0, Floors::None));
}

#[test]
fn versions_have_one_order() {
    let v = |s: &str| Version::parse(s).unwrap();
    assert_eq!(v("1.2"), v("1.2.0"));
    assert!(v("1.10.0") > v("1.9.9"));
    assert!(v("2") > v("1.65535.65535.65535"));
    assert!(v("1.0.0.1") > v("1.0.0"));
    assert_eq!(Version::from_packed(v("3.14.15.9").packed()), v("3.14.15.9"));
    assert!(v("1.2.3").packed() < v("1.2.4").packed());
    for bad in ["", "1.", ".1", "01", "1.2.3.4.5", "1.0-rc1", "1+b", "65536", "1..2", "a"] {
        assert!(matches!(Version::parse(bad), Err(VersionError::Component | VersionError::TooMany)), "{bad}");
    }
    assert_eq!(format!("{} {}", v("1.2"), v("1.2.3.4")), "1.2.0 1.2.3.4");
}

/// **Canary** `pkg-floor-canary` for the floor rows: a package below the floor
/// is reported as meeting it.
#[test]
fn installed_packages_are_judged_against_the_index() {
    let d = two_signers();
    let topo = d.topology();
    let (bytes, _) = index_for("1.3.0", Some("1.2.0"));
    let ix = index::verify(&bytes, &topo).unwrap();
    let a = |v: &str, s: usize| assess(&installed(v, s), &ix);

    let behind = a("1.2.0", 0);
    assert_eq!((behind.availability, behind.floor), (Availability::Behind(Version([1, 3, 0, 0])), Floor::Met(Version([1, 2, 0, 0]))));
    assert!(!behind.below_floor());
    let old = a("1.1.9", 0);
    assert_eq!((old.availability, old.floor), (Availability::Behind(Version([1, 3, 0, 0])), Floor::Below(Version([1, 2, 0, 0]))));
    assert!(old.below_floor());
    assert_eq!(a("1.3", 0).availability, Availability::Current);
    assert_eq!(a("1.4", 0).availability, Availability::Ahead(Version([1, 3, 0, 0])));
    // A package from another signer: the index has no say about it, floor included.
    let foreign = a("1.1.9", 1);
    assert_eq!((foreign.availability, foreign.floor, foreign.entry), (Availability::OtherSigner, Floor::NoFloor, None));
    assert!(!foreign.below_floor());
    // An unknown package.
    let mut unknown = installed("1.0", 0);
    unknown.name = "other-pkg";
    assert_eq!(assess(&unknown, &ix).availability, Availability::NotListed);
    // A version with no order cannot be shown to meet a floor: it is below it.
    let rc = a("1.0-rc1", 0);
    assert_eq!((rc.availability, rc.floor), (Availability::Unordered, Floor::Unordered(Version([1, 2, 0, 0]))));
    assert!(rc.below_floor());
    // No floor, no problem.
    let (bytes, _) = index_for("1.3.0", None);
    let ix = index::verify(&bytes, &topo).unwrap();
    let none = assess(&installed("0.0.1", 0), &ix);
    assert_eq!((none.floor, none.below_floor()), (Floor::NoFloor, false));
}

fn meta_of(bytes: &[u8]) -> (Meta<'_>, [u8; 32]) {
    let p = Package::parse(bytes).unwrap();
    (Meta::parse(p.meta).unwrap(), p.id())
}

/// The refusals of an upgrade, in the order they are checked.
///
/// **Canary** `pkg-downgrade-canary` (the downgrade row) and `pkg-floor-canary`
/// (the floor row).
#[test]
fn an_upgrade_is_refused_for_a_downgrade_a_floor_a_stranger_or_a_swapped_file() {
    let d = two_signers();
    let topo = d.topology();
    let cur = installed("1.5.0", 0);
    let try_with = |offered: &str, floor: Option<&str>, file_version: &str, inst: &Installed<'_>, signer: usize| {
        let (ibytes, _) = index_for(offered, floor);
        let ix = index::verify(&ibytes, &topo).unwrap();
        let entry = ix.find("acme-vision").unwrap();
        let file = pkg_at(file_version);
        let (m, id) = meta_of(&file);
        check_upgrade(inst, &entry, &m, &id, signer)
    };

    assert_eq!(try_with("1.6.0", Some("1.4.0"), "1.6.0", &cur, 0), Ok(()));
    assert_eq!(try_with("1.4.0", None, "1.4.0", &cur, 0), Err(UpgradeWhy::Downgrade), "below the installed version");
    assert_eq!(try_with("1.5.0", None, "1.5.0", &cur, 0), Err(UpgradeWhy::NotNewer), "the same version");
    // An index cannot say it (the parser refuses a floor above the offer), but the check does not rely on that.
    let entry = azos_pkg::index::Entry { name: "acme-vision", version: Version([1, 6, 0, 0]), sec_floor: Some(Version([1, 7, 0, 0])), id: id_of(&pkg_at("1.6.0")), file: "A.PKG" };
    let p6 = pkg_at("1.6.0");
    let (m6, id6) = meta_of(&p6);
    assert_eq!(check_upgrade(&cur, &entry, &m6, &id6, 0), Err(UpgradeWhy::BelowFloor), "the offer is below its own floor");
    assert_eq!(try_with("1.6.0", None, "1.6.0", &cur, 1), Err(UpgradeWhy::SignerChanged));
    assert_eq!(try_with("1.6.0", None, "1.6.1", &cur, 0), Err(UpgradeWhy::IdMismatch), "another build than the one pinned");
    assert_eq!(try_with("1.6.0", None, "1.6.0", &installed("1.0-rc1", 0), 0), Err(UpgradeWhy::Unordered));

    // A file with the right id and the wrong name cannot exist; the check still names it.
    let (ibytes, _) = index_for("1.6.0", None);
    let ix = index::verify(&ibytes, &topo).unwrap();
    let entry = ix.find("acme-vision").unwrap();
    let mut s = Spec::acme();
    s.name = "other-pkg".into();
    s.version = "1.6.0".into();
    let wrong = build(&s, &author());
    let (m, id) = meta_of(&wrong);
    assert_eq!(check_upgrade(&cur, &entry, &m, &id, 0), Err(UpgradeWhy::NameMismatch));
}

#[test]
fn only_a_newer_listed_version_under_the_same_signer_is_an_upgrade() {
    let d = two_signers();
    let topo = d.topology();
    let (bytes, _) = index_for("1.6.0", None);
    let ix = index::verify(&bytes, &topo).unwrap();
    assert_eq!(upgrade_entry(&assess(&installed("1.5", 0), &ix)).unwrap().version, Version([1, 6, 0, 0]));
    assert_eq!(upgrade_entry(&assess(&installed("1.6", 0), &ix)), Err(UpgradeWhy::NotNewer));
    assert_eq!(upgrade_entry(&assess(&installed("1.7", 0), &ix)), Err(UpgradeWhy::NotNewer));
    assert_eq!(upgrade_entry(&assess(&installed("1.5", 1), &ix)), Err(UpgradeWhy::OtherSigner));
    assert_eq!(upgrade_entry(&assess(&installed("x", 0), &ix)), Err(UpgradeWhy::Unordered));
    let mut gone = installed("1.5", 0);
    gone.name = "other-pkg";
    assert_eq!(upgrade_entry(&assess(&gone, &ix)), Err(UpgradeWhy::NotListed));
}
