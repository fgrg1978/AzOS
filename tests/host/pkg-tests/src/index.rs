// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The repository index (`crates/core/pkg/src/index.rs`): its verification, the
//! standing of installed packages against it, and what an upgrade may install.

use super::*;
use azos_pkg::index::{
    assess, Mark, MarkTable, SignerKey, check_upgrade, upgrade_entry, Availability, Floor, IndexWhy, Installed, UpgradeWhy, Version, VersionError,
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
fn the_mark_table_stores_a_signers_floors_up_to_its_quota() {
    use azos_pkg::index::{name_hash, MarkErr, Taken, SECTOR_ENTRIES};
    let (a, b): (SignerKey, SignerKey) = ([1; 16], [2; 16]);
    let v = |s: &str| Version::parse(s).unwrap();
    let mut t = MarkTable::new(2, 6);
    let floors = [(name_hash(&a, "x"), v("1.2")), (name_hash(&a, "y"), v("3"))];
    t.accept(&a, Mark { serial: 5, digest: 9 }, &floors).unwrap();
    t.accept(&b, Mark { serial: 1, digest: 1 }, &[(name_hash(&b, "x"), v("9"))]).unwrap();
    assert_eq!(t.mark(&a), Some(Mark { serial: 5, digest: 9 }));
    assert_eq!(t.floor_of(&a, name_hash(&a, "x")), Some(v("1.2")));
    assert_eq!(t.floor_of(&b, name_hash(&a, "x")), None, "a floor is a signer's own");
    // A newer index of `a` replaces a's floors and leaves b's.
    t.accept(&a, Mark { serial: 6, digest: 10 }, &[(name_hash(&a, "y"), v("4"))]).unwrap();
    assert_eq!((t.floor_of(&a, name_hash(&a, "x")), t.floor_of(&a, name_hash(&a, "y"))), (None, Some(v("4"))));
    assert_eq!(t.floor_of(&b, name_hash(&b, "x")), Some(v("9")));

    // One signer cannot take another's room: past its quota its mark is still raised
    // and the floors offered first are kept, the rest counted; signers past the
    // capacity are refused (Full), none evicted.
    let seven: Vec<(u64, Version)> = (0..7u64).map(|i| (i, v("1"))).collect();
    assert_eq!(t.accept(&b, Mark { serial: 2, digest: 2 }, &seven), Ok(Taken { left_out: 1 }));
    assert_eq!(t.mark(&b), Some(Mark { serial: 2, digest: 2 }), "the mark is raised");
    assert_eq!((0..7u64).map(|i| t.floor_of(&b, i).is_some()).collect::<Vec<_>>(), [true, true, true, true, true, true, false]);
    assert_eq!(t.floor_of(&a, name_hash(&a, "y")), Some(v("4")), "and a's stand");
    let before = t;
    let mut full = MarkTable::new(1, 20);
    let many: Vec<(u64, Version)> = (0..SECTOR_ENTRIES as u64).map(|i| (i, v("1"))).collect();
    assert_eq!(full.accept(&a, Mark { serial: 1, digest: 0 }, &many), Err(MarkErr::Full));
    assert_eq!(t, before);
}

/// An index listing `names` at 9.0, each with its floor.
fn listing(serial: u32, names: &[(&str, Option<&str>)]) -> Vec<u8> {
    let offers: Vec<Offer> = names
        .iter()
        .enumerate()
        .map(|(i, (n, f))| Offer {
            name: (*n).into(),
            version: "9.0".into(),
            sec_floor: f.map(Into::into),
            id: [i as u8 + 1; 32],
            file: format!("P{i}.PKG"),
        })
        .collect();
    build_index(&index_body(serial, &offers), &author())
}

/// The floors the device remembers of an index: the ones of the packages staged
/// under its signer and the ones it remembers already, the remembered first, with
/// the index's values; a name the index does not floor is not kept, remembered or not.
///
/// **Canary** `pkg-floor-forget-canary`: the remembered package that is not staged
/// loses its floor.
#[test]
fn a_remembered_floor_stays_while_an_index_floors_it() {
    use azos_pkg::index::{floors_to_remember, mark_key, name_hash};
    let d = dev();
    let topo = d.topology();
    let key = mark_key(&topo.signers()[0].key_id);
    let h = |n: &str| name_hash(&key, n);
    let v = |s: &str| Version::parse(s).unwrap();
    let bytes = listing(7, &[("pa", Some("1.0")), ("pb", Some("2.0")), ("pc", Some("3.0")), ("pd", None)]);
    let ix = index::verify(&bytes, &topo).unwrap();
    let staged = |x: u64| x == h("pa") || x == h("pd");
    let remembered = |x: u64| x == h("pc") || x == h("pd") || x == h("gone");
    let got: Vec<(u64, Version)> = floors_to_remember(&ix, &key, &staged, &remembered).collect();
    assert_eq!(got, vec![(h("pc"), v("3.0")), (h("pa"), v("1.0"))], "pc kept although not staged, and first");
    // Nothing staged: the remembered floors are all there is, never none.
    let none = |_: u64| false;
    assert_eq!(floors_to_remember(&ix, &key, &none, &remembered).collect::<Vec<_>>(), vec![(h("pc"), v("3.0"))]);
}

/// What a signer's floors are when the device remembers its index: the newest
/// one it has seen, or unknown, and unknown is not met. **Canary**
/// `pkg-mark-canary`: a replayed or deleted index passes as the first one.
#[test]
fn a_replayed_deleted_or_diverging_index_leaves_the_remembered_floors() {
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
        assert!(matches!(f, Floors::Remembered) && raise.is_none(), "{what}");
    }
    // A file that does not verify is no file; with no mark there is nothing to be unknown.
    let mut forged = v7.clone();
    let at = forged.len() - 3;
    forged[at] ^= 1;
    assert!(matches!(judge(Some(&forged), &topo, 0, Some(mark(&v7))).0, Floors::Remembered));
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

/// The slot file name and the topology's "same slot" rule are one rule: two key
/// ids share a slot name exactly when the topology refuses them as signers.
#[test]
fn the_topology_refuses_exactly_the_key_ids_that_share_a_slot() {
    let base = [0x5Au8; 32];
    for (i, differ) in [(0usize, true), (1, true), (2, true), (3, true), (4, false), (31, false)] {
        for bit in 0..8u8 {
            let mut other = base;
            other[i] ^= 1 << bit;
            let same_slot = azos_pkg::index::slot_name(&base) == azos_pkg::index::slot_name(&other);
            assert_eq!(azos_topology::types::same_index_slot(&base, &other), same_slot, "byte {i} bit {bit}");
            if i == 3 && bit < 4 {
                assert!(same_slot, "the low nibble of byte 3 is not in the name");
            } else if differ {
                assert!(!same_slot, "byte {i} bit {bit}");
            } else {
                assert!(same_slot || i > 3, "byte {i} is past the name");
            }
        }
    }
}

// ── the marks on the medium: two banks ───────────────────────────────────────

mod banks {
    use super::*;
    use azos_pkg::index::{name_hash, MarkStore, Marks};

    const A: SignerKey = [0xA1; 16];
    const B: SignerKey = [0xB2; 16];

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    fn floors(who: &SignerKey, names: &[(&str, &str)]) -> Vec<(u64, Version)> {
        names.iter().map(|(n, f)| (name_hash(who, n), v(f))).collect()
    }

    fn load(t: &RamTail) -> MarkStore<&RamTail> {
        MarkStore::load(t, 2, 5)
    }

    /// What the store knows of a signer: its serial and its floors for `names`.
    fn view(s: &MarkStore<&RamTail>, who: &SignerKey, names: &[&str]) -> (Option<u32>, Vec<Option<Version>>) {
        (s.mark(who).map(|m| m.serial), names.iter().map(|n| s.floor(who, n)).collect())
    }

    /// A tail that holds A at serial 6 (floors p, q) and B at serial 3 (floor r), in
    /// the order A, B, A: both banks hold a copy, the newest in bank 0.
    fn populated() -> RamTail {
        let t = RamTail::new(4);
        let s = load(&t);
        s.accept(&A, Mark { serial: 5, digest: 5 }, &floors(&A, &[("p", "1.0"), ("q", "2.0")])).unwrap();
        s.accept(&B, Mark { serial: 3, digest: 3 }, &floors(&B, &[("r", "7.0")])).unwrap();
        s.accept(&A, Mark { serial: 6, digest: 6 }, &floors(&A, &[("p", "1.5"), ("q", "2.0")])).unwrap();
        t
    }

    /// The same marks with the newest copy in bank 1: a write of the same table writes
    /// nothing, so A's floor q moves twice and comes back in a third write.
    fn populated_newest_in_bank_1() -> RamTail {
        let t = populated();
        let s = load(&t);
        for q in ["2.1", "2.2", "2.0"] {
            s.accept(&A, Mark { serial: 6, digest: 6 }, &floors(&A, &[("p", "1.5"), ("q", q)])).unwrap();
        }
        let mut gens = t.sectors.borrow().iter().map(|s| u32::from_le_bytes([s[5], s[6], s[7], s[8]])).collect::<Vec<_>>();
        gens.dedup();
        assert_eq!(gens, [5, 6], "bank 1 holds the newest copy");
        t
    }

    #[test]
    fn what_is_written_is_what_is_read_back_and_the_banks_alternate() {
        let t = RamTail::new(4);
        let s = load(&t);
        assert!(!s.lost() && s.mark(&A).is_none(), "a medium nothing was written on remembers nothing, and lost nothing");
        s.accept(&A, Mark { serial: 5, digest: 5 }, &floors(&A, &[("p", "1.0")])).unwrap();
        assert!(t.sectors.borrow()[0] != [0u8; 512] && t.sectors.borrow()[2] == [0u8; 512], "the first copy is in bank 0");
        s.accept(&B, Mark { serial: 3, digest: 3 }, &[]).unwrap();
        assert!(t.sectors.borrow()[2] != [0u8; 512], "the next one in bank 1, bank 0 untouched");
        let again = load(&t);
        assert_eq!(view(&again, &A, &["p"]), (Some(5), vec![Some(v("1.0"))]));
        assert_eq!(again.mark(&B).map(|m| m.serial), Some(3));
        // The same thing again writes nothing.
        let before = t.sectors.borrow().clone();
        s.accept(&B, Mark { serial: 3, digest: 3 }, &[]).unwrap();
        assert_eq!(*t.sectors.borrow(), before);
    }

    #[test]
    fn a_bank_that_fails_is_ignored_never_read_as_zeros() {
        // Torn, unreadable and altered banks: the other bank stands, with what it holds.
        for damage in 0..3 {
            let t = populated();
            match damage {
                0 => t.sectors.borrow_mut()[1][200] ^= 1, // the newest bank, second sector
                1 => t.unreadable.borrow_mut().push(0),
                _ => t.sectors.borrow_mut()[0] = [0u8; 512], // zeroed, but the other bank is not
            }
            let s = load(&t);
            assert!(!s.lost(), "damage {damage}: one bank is whole");
            assert_eq!(s.condition().ignored, Some(0), "damage {damage}: and the other is said to be ignored");
            assert_eq!(s.condition().unreadable, damage == 1);
            // Bank 1 holds the copy before the last write: A at serial 5, B at 3.
            assert_eq!(s.mark(&A).map(|m| m.serial), Some(5), "damage {damage}");
            assert_eq!(s.mark(&B).map(|m| m.serial), Some(3), "damage {damage}");
        }
        // Both banks damaged: lost, not empty; the next accept writes it again.
        let t = populated();
        t.sectors.borrow_mut()[0][9] ^= 1;
        t.sectors.borrow_mut()[3][9] ^= 1;
        let s = load(&t);
        assert!(s.lost() && s.mark(&A).is_none() && s.mark(&B).is_none());
        s.accept(&A, Mark { serial: 6, digest: 6 }, &[]).unwrap();
        assert!(!s.lost());
        let again = load(&t);
        assert!(!again.lost() && again.mark(&A).map(|m| m.serial) == Some(6));
        // A sector of garbage on a medium that has been written is not pristine.
        let t = RamTail::new(4);
        t.sectors.borrow_mut()[3] = [0x55; 512];
        assert!(load(&t).lost());
    }

    /// **No cut and no torn sector of a write loses a mark or a floor** that was there:
    /// every signer's mark is at or above what it was, and a signer's floors are the old
    /// ones or the new ones, whole. The write goes to the bank that does not hold the
    /// newest copy, whichever of the two that is, and leaves that one as it was. Two
    /// writes: B raised to a newer serial, and B at the same serial keeping its
    /// remembered floor beside a new one (what a boot that stages a package writes).
    ///
    /// **Canary** `pkg-bank-canary`: the write goes over the newest bank and the cut
    /// leaves the older copy (a lower serial) as the winner.
    #[test]
    fn no_cut_or_torn_sector_of_a_write_loses_a_mark_or_a_floor() {
        let old_b = (Some(3), vec![Some(v("7.0")), None]);
        let writes = [
            (Mark { serial: 4, digest: 4 }, floors(&B, &[("r", "8.0")]), (Some(4), vec![Some(v("8.0")), None])),
            (Mark { serial: 3, digest: 3 }, floors(&B, &[("r", "7.0"), ("s", "1.0")]), (Some(3), vec![Some(v("7.0")), Some(v("1.0"))])),
        ];
        let mut cases = 0;
        for (newest, medium) in [(0usize, populated as fn() -> RamTail), (1, populated_newest_in_bank_1)] {
            for (mark, new_floors, new_b) in &writes {
                for tear in [None, Some(1), Some(37), Some(100), Some(300), Some(500), Some(511)] {
                    for budget in 0..=2usize {
                        let t = medium();
                        let s = load(&t);
                        let before = view(&s, &A, &["p", "q"]);
                        let kept: Vec<[u8; 512]> = t.sectors.borrow()[newest * 2..newest * 2 + 2].to_vec();
                        t.budget.set(Some(budget));
                        t.tear.set(tear);
                        let r = s.accept(&B, *mark, new_floors);
                        assert_eq!(r.is_ok(), budget >= 2, "budget {budget}");
                        t.budget.set(None);
                        let what = format!("newest in bank {newest}, B to {mark:?}, budget {budget} tear {tear:?}");
                        assert_eq!(t.sectors.borrow()[newest * 2..newest * 2 + 2], kept[..], "{what}: the newest bank is not written");
                        if r.is_err() {
                            assert_eq!(view(&s, &B, &["r", "s"]), old_b, "a failed write changes nothing in memory");
                        }
                        let after = load(&t);
                        assert!(!after.lost(), "{what}: the bank that was not written stands");
                        assert_eq!(view(&after, &A, &["p", "q"]), before, "{what}: A is as it was");
                        let b = view(&after, &B, &["r", "s"]);
                        assert!(b == old_b || b == *new_b, "{what}: B is whole old or whole new, got {b:?}");
                        // And the next write goes through.
                        after.accept(&B, *mark, new_floors).unwrap();
                        assert_eq!(view(&load(&t), &B, &["r", "s"]), *new_b);
                        cases += 1;
                    }
                }
            }
        }
        assert_eq!(cases, 84);
    }

    /// **A sector that does not read is not damage.** Sectors 0 and 2 (one of each
    /// bank) do not read: no bank reads whole and the boot judges by nothing, but it
    /// writes nothing either, so the next boot that reads them has every mark. One
    /// unreadable sector of the newest bank leaves the older copy to judge by, and
    /// nothing is written over the newest one.
    ///
    /// Canary (by hand): `accept` writing past an unreadable sector turns this red (the
    /// rebuilt bank 0 replaces the newer marks).
    #[test]
    fn a_boot_that_cannot_read_a_sector_writes_nothing() {
        use azos_pkg::index::MarkErr;
        for unread in [vec![0usize, 2], vec![0], vec![1]] {
            let t = populated();
            let before = t.sectors.borrow().clone();
            *t.unreadable.borrow_mut() = unread.clone();
            let s = load(&t);
            let c = s.condition();
            assert!(c.unreadable, "{unread:?}");
            assert_eq!(c.lost, unread.len() == 2, "{unread:?}: lost only when no bank reads");
            assert_eq!(s.accept(&A, Mark { serial: 7, digest: 7 }, &floors(&A, &[("p", "1.0")])), Err(MarkErr::Unreadable));
            assert_eq!(s.accept(&B, Mark { serial: 4, digest: 4 }, &[]), Err(MarkErr::Unreadable));
            assert_eq!(*t.sectors.borrow(), before, "{unread:?}: nothing written");
            t.unreadable.borrow_mut().clear();
            let again = load(&t);
            assert_eq!(again.condition(), Default::default());
            assert_eq!(view(&again, &A, &["p", "q"]), (Some(6), vec![Some(v("1.5")), Some(v("2.0"))]), "{unread:?}");
            assert_eq!(again.mark(&B).map(|m| m.serial), Some(3));
        }
    }

    /// A bank that was written and does not read whole is said to be ignored, and a
    /// blank one is not.
    #[test]
    fn an_ignored_bank_is_said_to_be() {
        let t = populated();
        t.sectors.borrow_mut()[3][40] ^= 1;
        let c = load(&t).condition();
        assert_eq!((c.ignored, c.unreadable, c.lost), (Some(1), false, false));
        let t = RamTail::new(4);
        load(&t).accept(&A, Mark { serial: 1, digest: 1 }, &[]).unwrap();
        assert_eq!(load(&t).condition(), Default::default(), "bank 1 is still blank");
    }

    /// **A rebuild after a loss starts above every generation on the medium** and fills
    /// the bank with fewer valid sectors: a stale bank that reads again later does not
    /// undo it. A cut of the rebuild leaves the medium lost, never a lower generation
    /// that wins.
    #[test]
    fn a_rebuild_after_a_loss_outranks_every_bank_that_reads_again() {
        // populated(): bank 0 holds generation 3, bank 1 generation 2.
        for (spoiled, spare) in [(vec![1usize, 2], 0usize), (vec![1, 2, 3], 1)] {
            for cut in [None, Some((0usize, None)), Some((1, Some(200)))] {
                let t = populated();
                let good = t.sectors.borrow().clone();
                for &i in &spoiled {
                    t.sectors.borrow_mut()[i][100] ^= 1;
                }
                let s = load(&t);
                assert!(s.lost(), "{spoiled:?}");
                if let Some((budget, tear)) = cut {
                    t.budget.set(Some(budget));
                    t.tear.set(tear);
                    assert!(s.accept(&A, Mark { serial: 2, digest: 2 }, &[]).is_err());
                    t.budget.set(None);
                    assert!(load(&t).lost(), "{spoiled:?} {cut:?}: a cut rebuild is no bank");
                    continue;
                }
                s.accept(&A, Mark { serial: 2, digest: 2 }, &[]).unwrap();
                let gens: Vec<u32> = t.sectors.borrow()[spare * 2..spare * 2 + 2].iter().map(|x| u32::from_le_bytes([x[5], x[6], x[7], x[8]])).collect();
                assert_eq!(gens, [4, 4], "{spoiled:?}: generation 4 into bank {spare}");
                // The spoiled sectors of the other bank read again.
                let other = 1 - spare;
                t.sectors.borrow_mut()[other * 2..other * 2 + 2].copy_from_slice(&good[other * 2..other * 2 + 2]);
                let again = load(&t);
                assert_eq!(view(&again, &A, &["p"]), (Some(2), vec![None]), "{spoiled:?}: the rebuild stands");
                assert!(again.mark(&B).is_none());
            }
        }
    }

    /// **Provisioning writes an empty bank the kernel reads whole**
    /// (`tools/sign/device_provision.py`, also `--clear-index-marks`): byte for byte
    /// what the store encodes for no entries at generation 1, and the next write goes
    /// to the other bank above it.
    #[test]
    fn the_provisioning_tool_writes_an_empty_bank_the_kernel_reads() {
        use azos_pkg::index::MarkTable;
        let tools = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/sign");
        for sectors in [1usize, 2] {
            let script = format!("import sys; sys.path.insert(0, sys.argv[1]); import device_provision as d; sys.stdout.write(d.marks_bank({sectors}).hex())");
            let out = std::process::Command::new("python3").arg("-c").arg(script).arg(&tools).output().expect("python3");
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
            let hex = String::from_utf8(out.stdout).unwrap();
            let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
            let want = MarkTable::new(sectors, 5).encode_bank(1);
            assert_eq!(bytes, want[..sectors].concat(), "{sectors} sector(s) a bank");
            let t = RamTail::new(2 * sectors);
            t.provisioned.set(true);
            for (i, sec) in bytes.chunks(512).enumerate() {
                t.sectors.borrow_mut()[i].copy_from_slice(sec);
            }
            let s = MarkStore::load(&t, sectors, 5);
            assert_eq!((s.condition(), s.mark(&A)), (Default::default(), None));
            s.accept(&A, Mark { serial: 1, digest: 1 }, &[]).unwrap();
            assert_eq!(t.sectors.borrow()[sectors][5], 2, "generation 2, in bank 1");
            assert_eq!(MarkStore::load(&t, sectors, 5).mark(&A).map(|m| m.serial), Some(1));
        }
    }

    /// **A provisioned medium whose marks read all zero was erased**, and that is a
    /// loss on record (event 2, first number 1), not a fresh device; only a medium
    /// with no device record is fresh.
    ///
    /// Canary (by hand): ignoring `provisioned` reads the erased medium as fresh.
    #[test]
    fn an_erased_medium_of_a_provisioned_device_is_lost_not_new() {
        let t = RamTail::new(4);
        assert_eq!(load(&t).condition(), Default::default(), "never provisioned: fresh");
        t.provisioned.set(true);
        let c = load(&t).condition();
        assert!(c.lost && c.erased, "{c:?}");
        let t = populated();
        t.provisioned.set(true);
        *t.sectors.borrow_mut() = vec![[0u8; 512]; 4];
        let s = load(&t);
        assert!(s.lost() && s.condition().erased && s.mark(&A).is_none());
        s.accept(&A, Mark { serial: 6, digest: 6 }, &[]).unwrap();
        assert_eq!(load(&t).condition(), Default::default(), "written again");
    }

    /// The first write of all, cut: nothing was there to lose. Nothing landed, and the
    /// medium is still blank; or something landed, and it is not a whole bank and not
    /// zeros, so it reads as lost. Either way the next accept writes it.
    #[test]
    fn a_cut_of_the_very_first_write_leaves_a_blank_or_lost_medium_and_is_rewritten() {
        for (budget, tear, lost) in [(0, None, false), (0, Some(100), true), (1, None, true), (1, Some(300), true)] {
            let t = RamTail::new(4);
            let s = load(&t);
            t.budget.set(Some(budget));
            t.tear.set(tear);
            assert!(s.accept(&A, Mark { serial: 1, digest: 1 }, &[]).is_err());
            t.budget.set(None);
            let after = load(&t);
            assert_eq!((after.lost(), after.mark(&A).is_none()), (lost, true), "budget {budget} tear {tear:?}");
            after.accept(&A, Mark { serial: 1, digest: 1 }, &[]).unwrap();
            assert_eq!(load(&t).mark(&A).map(|m| m.serial), Some(1));
        }
    }

    /// A third-party signer cannot push another's floors out: it holds to its quota (its
    /// mark raised, its floors past the quota left out), and when the table is full it is
    /// the newcomer that is refused.
    #[test]
    fn a_signer_cannot_evict_another_signers_floors() {
        use azos_pkg::index::{MarkErr, Taken};
        let t = populated();
        let s = load(&t);
        let c: SignerKey = [0xC3; 16];
        let many: Vec<(u64, Version)> = (0..20u64).map(|i| (i, v("1"))).collect();
        assert_eq!(s.accept(&c, Mark { serial: u32::MAX, digest: 0 }, &many), Ok(Taken { left_out: 15 }));
        let d: SignerKey = [0xD4; 16];
        let e: SignerKey = [0xE5; 16];
        let f: SignerKey = [0xF6; 16];
        // 26 entries: A 3, B 2, C 6, D 6, E 6 -- the sixth signer is the one that is refused.
        s.accept(&d, Mark { serial: 1, digest: 0 }, &many[..5]).unwrap();
        s.accept(&e, Mark { serial: 1, digest: 0 }, &many[..5]).unwrap();
        assert_eq!(s.accept(&f, Mark { serial: 1, digest: 0 }, &many[..5]), Err(MarkErr::Full));
        // Nobody who was there lost anything.
        let after = load(&t);
        assert_eq!(view(&after, &A, &["p", "q"]), (Some(6), vec![Some(v("1.5")), Some(v("2.0"))]));
        assert_eq!(view(&after, &B, &["r"]), (Some(3), vec![Some(v("7.0"))]));
        assert_eq!(after.mark(&c).map(|m| m.serial), Some(u32::MAX));
    }
}
