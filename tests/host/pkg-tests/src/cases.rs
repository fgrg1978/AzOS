// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Verification and admission: what is installed and what is refused.

use super::*;
use azos_decision::{Rule, Verdict};
use azos_pkg::{receipt, Package};
use azos_topology::AdmissionError;

fn dev() -> Device0 {
    Device0::with_signers(&signer_text("acme", &author(), CEILING))
}

fn grant(target: &str) -> String {
    format!("{{ kind = \"endpoint\", target = \"{target}\", perm = \"rw\" }}")
}

/// A package whose row is `grants` instead of the fixture's.
fn with_grants(grants: &str) -> Vec<u8> {
    let mut s = Spec::acme();
    s.rows = row("ACME.ELF", "best_effort", 20, grants);
    build(&s, &author())
}

#[test]
fn a_package_signed_by_an_admitted_author_installs() {
    let d = dev();
    let bytes = build(&Spec::acme(), &author());
    let mut topo = d.topology();
    let before = topo.tasks().len();
    let v = verify(&bytes, &topo).expect("verifies");
    assert_eq!(v.meta.name, "acme-vision");
    assert_eq!(v.signer.name.as_bytes(), b"acme");
    assert_eq!(v.image(0).unwrap().len(), 300);
    let a = admit(&v, v.pkg.rows, &mut topo, &device()).expect("admitted");
    assert_eq!((a.first_row, a.rows), (before, 1));
    assert_eq!(topo.tasks().len(), before + 1);
    assert_eq!(topo.tasks()[before].name.as_bytes(), b"ACME.ELF");
    assert!(topo.admission_check().is_ok());
}

/// **Canary** `pkg-verify-skip-canary`: the forged package installs.
#[test]
fn a_forged_signature_is_refused() {
    let d = dev();
    let mut bytes = build(&Spec::acme(), &author());
    // One bit of the signature (it follows the 32-byte key).
    bytes[HEADER_LEN + 32 + 5] ^= 0x01;
    assert_eq!(install(&bytes, &d), Err(Refusal::Signature));
    // And one bit of the metadata after signing.
    let mut bytes = build(&Spec::acme(), &author());
    let at = HEADER_LEN + 32 + 64 + 8;
    bytes[at] ^= 0x01;
    assert_eq!(install(&bytes, &d), Err(Refusal::Signature));
}

/// **Canary** `pkg-verify-skip-canary` (the zero signature) and
/// `pkg-signer-canary` (the all-zero key is not a signer).
#[test]
fn an_unsigned_package_is_refused() {
    let d = dev();
    let s = Spec::acme();
    let (meta, rows) = (s.meta(), s.rows.clone());
    let images: Vec<u8> = s.images.iter().flat_map(|(_, x)| x.clone()).collect();
    // No algorithm, no key, no signature.
    let none = assemble(0, &[], &[], meta.as_bytes(), rows.as_bytes(), &images);
    assert_eq!(install(&none, &d), Err(Refusal::Algorithm(0)));
    // The right shapes, all zero.
    let zero = assemble(1, &[0; 32], &[0; 64], meta.as_bytes(), rows.as_bytes(), &images);
    assert_eq!(install(&zero, &d), Err(Refusal::UnknownSigner));
    // The admitted key with a zero signature.
    let zero = assemble(1, author().verifying_key().as_bytes(), &[0; 64], meta.as_bytes(), rows.as_bytes(), &images);
    assert_eq!(install(&zero, &d), Err(Refusal::Signature));
}

/// A well-formed, validly signed package by a key the device does not admit.
///
/// **Canary** `pkg-signer-canary`: it installs.
#[test]
fn a_package_signed_by_another_author_is_refused() {
    let d = dev();
    let bytes = build(&Spec::acme(), &stranger());
    // It verifies on its own terms: the signature is good.
    let p = Package::parse(&bytes).unwrap();
    assert!(p.alg().unwrap().verify(p.key, &p.message(), p.sig));
    assert_eq!(install(&bytes, &d), Err(Refusal::UnknownSigner));
    // A device with no signer at all admits nobody.
    let none = Device0::with_signers("");
    assert_eq!(install(&build(&Spec::acme(), &author()), &none), Err(Refusal::UnknownSigner));
}

/// Signed with the author's key, but the algorithm id swapped after: the id is
/// in the signed message, and ids other than the device's
/// (Ed25519) are refused, ML-DSA-65 and SLH-DSA with
/// the key and signature sizes their own formats allow included.
#[test]
fn an_algorithm_id_this_build_does_not_verify_is_refused() {
    let d = dev();
    let bytes = build(&Spec::acme(), &author());
    for alg in [2u16, 3, 0x100, 0xFFFF] {
        let mut b = bytes.clone();
        b[6..8].copy_from_slice(&alg.to_le_bytes());
        assert_eq!(install(&b, &d), Err(Refusal::Algorithm(alg)), "alg {alg}");
    }
    // Ed25519 keys and signatures have one length each.
    let s = Spec::acme();
    let (meta, rows) = (s.meta(), s.rows.clone());
    let images: Vec<u8> = s.images.iter().flat_map(|(_, x)| x.clone()).collect();
    let long = assemble(1, &[7; 33], &[7; 64], meta.as_bytes(), rows.as_bytes(), &images);
    assert_eq!(install(&long, &d), Err(Refusal::Algorithm(1)));
    let long = assemble(1, &[7; 32], &[7; 96], meta.as_bytes(), rows.as_bytes(), &images);
    assert_eq!(install(&long, &d), Err(Refusal::Algorithm(1)));
    // The sizes a post-quantum algorithm has fit the container; the device
    // does not take the algorithm.
    let ml = assemble(2, &[7; 1952], &[7; 3309], meta.as_bytes(), rows.as_bytes(), &images);
    assert_eq!(install(&ml, &d), Err(Refusal::Algorithm(2)));
    let slh = assemble(3, &[7; 32], &[7; 7856], meta.as_bytes(), rows.as_bytes(), &images);
    assert_eq!(install(&slh, &d), Err(Refusal::Algorithm(3)));
}

/// An image that is not the one the signed metadata names.
///
/// **Canary** `pkg-image-canary`.
#[test]
fn an_image_that_is_not_the_signed_one_is_refused() {
    let d = dev();
    let mut bytes = build(&Spec::acme(), &author());
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    assert_eq!(install(&bytes, &d), Err(Refusal::Images(0)));
    // Swapping two images changes both hashes.
    let mut s = Spec::acme();
    s.images.push(("OTHER.ELF".into(), vec![9; 40]));
    s.rows.push_str(&row("OTHER.ELF", "best_effort", 20, &grant("endpoint.acme")));
    let mut bytes = build(&s, &author());
    let n = bytes.len();
    bytes[n - 40..].fill(8);
    assert_eq!(install(&bytes, &d), Err(Refusal::Images(1)));
}

/// **Canary** `neverallow-canary` (the rules find nothing): the refusal is the
/// rules', not the ceiling's, because this signer may hold any endpoint.
#[test]
fn a_manifest_that_breaks_a_neverallow_rule_is_refused() {
    let wide = Device0::with_signers(&signer_text("acme", &author(), "mem_pages_max = 64\nwarrants = [\"endpoint:\"]\n"));
    // A ring-3 row that is not an actuation row holds a PWM channel or a pin
    // with write access (and, in a build with the drivetrain, a motor, which
    // the parser itself refuses in a build without).
    match install(&with_grants(&grant("pwm.6")), &wide) {
        Err(Refusal::Admission(AdmissionError::Neverallow(n))) => {
            assert_eq!(n.rule().id, "actuation-outside-actuation-row");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        install(&with_grants(&grant("gpio.21")), &wide),
        Err(Refusal::Admission(AdmissionError::Neverallow(_)))
    ));
    let motor = install(&with_grants(&grant("motor.0")), &wide);
    if cfg!(feature = "profile-actuation") {
        // The drivetrain already has its writer: the parser's one-writer rule
        // answers before the neverallow rules are asked.
        assert!(
            matches!(motor, Err(Refusal::Rows(azos_topology::ParseError::MotorWriteConflict)))
                || matches!(motor, Err(Refusal::Admission(AdmissionError::Neverallow(_)))),
            "{motor:?}"
        );
    } else {
        assert!(matches!(motor, Err(Refusal::Rows(_))), "{motor:?}");
    }
    // Read-only is not actuation.
    assert!(install(&with_grants("{ kind = \"endpoint\", target = \"pwm.6\", perm = \"r\" }"), &wide).is_ok());
}

/// A signer's ceiling is a kind and a prefix: outside it the package is
/// refused before the topology's rules are asked.
///
/// **Canary**: make `Topology::signer_covers` return true (topology-tests).
#[test]
fn a_row_outside_the_signers_ceiling_is_refused() {
    let d = dev();
    let b = with_grants(&format!("{}, {}", grant("endpoint.acme"), grant("endpoint.names")));
    assert_eq!(install(&b, &d), Err(Refusal::OutsideWarrants { row: 0, grant: 1 }));
    // Another kind with a matching prefix.
    let b = with_grants("{ kind = \"node\", target = \"/fat\", perm = \"rw\" }");
    assert_eq!(install(&b, &d), Err(Refusal::OutsideWarrants { row: 0, grant: 0 }));
    // Inside it.
    assert!(install(&with_grants("{ kind = \"memobj\", target = \"stream.cam\", perm = \"r\" }"), &d).is_ok());
}

/// An import is authority by name: the name server lends a held endpoint
/// (`term`) to any row that lists it, so a row that imports a name its signer
/// has no `endpoint:` warrant for is refused, grants or none.
///
/// **Canary** `pkg-import-canary`: the package installs.
#[test]
fn a_row_that_imports_a_name_outside_the_signers_ceiling_is_refused() {
    let imports = |names: &str| {
        let mut s = Spec::acme();
        // `imports` is a format-5 key and the rows text may say its own
        // format before its first section, so the key is reachable.
        s.rows = format!("format = 6\n[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 32\nimports = [{names}]\ncaps = []\n");
        build(&s, &author())
    };
    // The fixture's ceiling holds `endpoint:endpoint.acme` and no `term`.
    let d = dev();
    assert_eq!(install(&imports("\"term\""), &d), Err(Refusal::OutsideImports { row: 0, import: 0 }));
    // A memobj or node warrant is not the right to ask for an endpoint.
    let other = Device0::with_signers(&signer_text("acme", &author(), "mem_pages_max = 64\nwarrants = [\"memobj:term\", \"node:term\"]\n"));
    assert_eq!(install(&imports("\"term\""), &other), Err(Refusal::OutsideImports { row: 0, import: 0 }));
    // With the warrant the same package is admitted: the refusal is the
    // ceiling's, not the shape of the row.
    let wide = Device0::with_signers(&signer_text("acme", &author(), "mem_pages_max = 64\nwarrants = [\"endpoint:te\"]\n"));
    assert!(install(&imports("\"term\""), &wide).is_ok());
}

#[test]
fn real_time_and_frames_are_the_signers_to_allow() {
    let d = dev();
    let mut s = Spec::acme();
    s.rows = format!(
        "[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\nperiod_us = 10000\nruntime_us = 1000\ncaps = []\n");
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::RealTime(0)));
    s.rows = "[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 65\ncaps = []\n".into();
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::Frames(0)));
    s.rows = "[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 64\ncaps = []\n".into();
    assert!(install(&build(&s, &author()), &d).is_ok());
    // The ceiling is the row's whole budget: instances multiply it.
    s.rows = "[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 32\ninstances = 3\ncaps = []\n".into();
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::Frames(0)), "3 x 32 > 64");
    s.rows = "[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 32\ninstances = 2\ncaps = []\n".into();
    assert!(install(&build(&s, &author()), &d).is_ok(), "2 x 32 = 64");
    // Memory pinned for the task's life, a huge region and a ring poller are
    // real-time features: the owner gives them with `rt = true`, or not.
    for extra in ["mem = \"locked\"\n", "sqpoll_idle_ms = 10\n"] {
        s.rows = format!("[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\nmem_pages = 32\n{extra}caps = []\n");
        assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::RealTime(0)), "{extra}");
    }
    // No `mem_pages` is the ring-3 default, which a small board's is not more
    // than 64 frames.
    s.rows = "[task.ACME.ELF]\nclass = \"best_effort\"\npriority = 20\ncaps = []\n".into();
    if azos_topology::RING3_DEFAULT_PAGES > 64 {
        assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::Frames(0)));
    } else {
        assert!(install(&build(&s, &author()), &d).is_ok());
    }
}

#[test]
fn a_package_runs_only_where_its_manifest_says() {
    let d = dev();
    let mut s = Spec::acme();
    s.hardware = vec!["server"];
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::Hardware));
    let mut s = Spec::acme();
    s.abi = azos_abi::ABI_VERSION + 1;
    assert_eq!(
        install(&build(&s, &author()), &d),
        Err(Refusal::Abi { wanted: azos_abi::ABI_VERSION + 1, have: azos_abi::ABI_VERSION })
    );
}

/// **Canary** `pkg-epoch-canary`: a package signed against an epoch the
/// device has already moved past is admitted.
#[test]
fn a_package_below_the_epoch_floor_is_refused() {
    let d = dev();
    let mut s = Spec::acme();
    s.sec_epoch = 4;
    let bytes = build(&s, &author());
    let mut topo = d.topology();
    let v = verify(&bytes, &topo).expect("verifies");
    let high = Device { epoch_floor: 5, ..device() };
    assert_eq!(admit(&v, v.pkg.rows, &mut topo, &high), Err(Refusal::Epoch { have: 4, floor: 5 }));
    assert_eq!(topo.tasks().len(), d.topology().tasks().len(), "the refusal leaves the topology as it was");
    // At the floor and above it, the same package is admitted.
    for floor in [0, 3, 4] {
        let mut topo = d.topology();
        let v = verify(&bytes, &topo).expect("verifies");
        assert!(admit(&v, v.pkg.rows, &mut topo, &Device { epoch_floor: floor, ..device() }).is_ok(), "floor {floor}");
    }
}

#[test]
fn interface_levels_are_checked_against_the_device() {
    let d = dev();
    let mut s = Spec::acme();
    s.api = vec![("Names", 1), ("Decisions", 2)];
    assert!(install(&build(&s, &author()), &d).is_ok());
    s.api = vec![("Names", 1), ("Decisions", 3)];
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::Api(1)), "newer than served");
    s.api = vec![("Teleport", 1)];
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::Api(0)), "not served");
}

/// The rows are `[task.NAME]` sections and nothing else: no policy, no
/// operator key, no pipelines, no classes, no signers of their own.
#[test]
fn a_package_cannot_carry_policy() {
    let d = dev();
    let key = "0f".repeat(32);
    for extra in [
        "[operator]\npubkey = \"00\"\n".to_string(),
        format!("[signer.evil]\nkey_id = \"{key}\"\nmem_pages_max = 1\n"),
        "[pipeline.x]\ndma_kb = 4\n".to_string(),
        "[class.rt]\n".to_string(),
        "  [sched]\n".to_string(),
    ] {
        let mut s = Spec::acme();
        s.rows = format!("format = 6\n{}\n{extra}", s.rows);
        assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::ForeignSection), "{extra}");
    }
}

#[test]
fn rows_and_images_correspond_one_to_one() {
    let d = dev();
    let mut s = Spec::acme();
    s.rows = row("OTHER.ELF", "best_effort", 20, &grant("endpoint.acme"));
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::RowsImages), "row without its image");
    let mut s = Spec::acme();
    s.images.push(("SPARE.ELF".into(), vec![1; 10]));
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::RowsImages), "image without a row");
    let mut s = Spec::acme();
    s.rows = String::new();
    assert_eq!(install(&build(&s, &author()), &d), Err(Refusal::RowsImages), "no row at all");
}

/// A package cannot replace a row of the device, nor install twice.
#[test]
fn a_package_cannot_replace_a_row() {
    let d = dev();
    let mut s = Spec::acme();
    let base_row = d.topology().tasks()[0].name.as_str().to_string();
    assert!(base_row.ends_with(".ELF") || !base_row.is_empty());
    s.images[0].0 = format!("{base_row}");
    s.rows = row(&base_row, "best_effort", 20, &grant("endpoint.acme"));
    let r = install(&build(&s, &author()), &d);
    // A name that is not a `.ELF` image fails the metadata; one that is, the
    // topology's duplicate rule.
    assert!(matches!(r, Err(Refusal::Meta(_)) | Err(Refusal::Admission(AdmissionError::DuplicateTask))), "{r:?}");
    // Twice: the second install sees the first one's row.
    let mut topo = d.topology();
    let bytes = build(&Spec::acme(), &author());
    let v = verify(&bytes, &topo).unwrap();
    admit(&v, v.pkg.rows, &mut topo, &device()).unwrap();
    let again = verify(&bytes, &topo).unwrap();
    assert!(matches!(
        admit(&again, again.pkg.rows, &mut topo, &device()),
        Err(Refusal::Admission(AdmissionError::DuplicateTask)) | Err(Refusal::Rows(_))
    ));
}

#[test]
fn the_receipt_records_the_decision_with_the_package_id() {
    let d = dev();
    let bytes = build(&Spec::acme(), &author());
    let mut topo = d.topology();
    let v = verify(&bytes, &topo).unwrap();
    let a = admit(&v, v.pkg.rows, &mut topo, &device()).unwrap();
    let p = receipt::admitted(&v, &a, 77);
    assert_eq!((p.rule, p.verdict, p.subject), (Rule::PackageInstall as u8, Verdict::Admit as u8, 1));
    assert_eq!(p.n, [1, 1, 0], "one image, the first signer, no refusal");
    assert_eq!(p.image_hash_prefix, u64::from_be_bytes(v.id[..8].try_into().unwrap()));
    assert_eq!((p.topology_row_id as usize, p.clock_ns), (a.first_row + 1, 77));
    // The id names the signed content: another version, another id.
    let mut s = Spec::acme();
    s.version = "1.2.1".into();
    let other = build(&s, &author());
    assert_ne!(Package::parse(&other).unwrap().id(), v.id);
    // And the same content from another author is another package.
    let theirs = build(&Spec::acme(), &stranger());
    assert_ne!(Package::parse(&theirs).unwrap().id(), v.id);
    // The record survives its wire form.
    let back = azos_decision::ProvenanceRecord::from_bytes(&p.to_bytes()).unwrap();
    assert_eq!(back, p);
    let r = receipt::refused(&v.id, 0, &Refusal::UnknownSigner, 5);
    assert_eq!((r.verdict, r.n[2] >> 24), (Verdict::Refuse as u8, 3));
    // Every step has its own code.
    let codes = [
        Refusal::UnknownSigner, Refusal::Signature, Refusal::Hardware, Refusal::ForeignSection, Refusal::RowsImages,
        Refusal::Images(0), Refusal::Api(0), Refusal::RealTime(0), Refusal::Frames(0),
    ];
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] {
            assert_ne!(a.code() >> 24, b.code() >> 24, "{a:?} {b:?}");
        }
    }
}

/// The whole chain: the signers are in a CAPS.TOM the owner signed, so the
/// package verifies against what `load_signed` installed, and a CAPS.TOM that
/// adds a signer without the owner's signature is not loaded.
#[test]
fn the_signer_table_is_the_signed_topologys() {
    use azos_topology::signed::{load_signed, DeviceContext, SignedFiles};
    let d = dev();
    let sig = dsig(&owner(), d.caps.as_bytes());
    let ctx = DeviceContext { device_id: None, floor: 0, bind_device: false, enforce_floor: false };
    let mut topo = Box::new(Topology::empty());
    let files = SignedFiles { caps: d.caps.as_bytes(), caps_sig: &sig, sched: d.sched.as_bytes() };
    load_signed(&mut topo, &files, owner().verifying_key().as_bytes(), &ctx).expect("owner-signed topology loads");
    let bytes = build(&Spec::acme(), &author());
    let v = verify(&bytes, &topo).expect("verifies against the loaded topology");
    admit(&v, v.pkg.rows, &mut topo, &device()).expect("admitted");

    // The author tries to add itself: a CAPS.TOM with an extra signer, signed
    // by the author, not by the owner.
    let evil = Device0::with_signers(&signer_text("evil", &stranger(), CEILING));
    let forged = dsig(&stranger(), evil.caps.as_bytes());
    let mut topo = Box::new(Topology::empty());
    let files = SignedFiles { caps: evil.caps.as_bytes(), caps_sig: &forged, sched: evil.sched.as_bytes() };
    assert!(load_signed(&mut topo, &files, owner().verifying_key().as_bytes(), &ctx).is_err());
}

/// A package refused after its rows were parsed in leaves the topology as it
/// found it, so the next package is judged against the device and not against
/// the debris of the last.
///
/// **Canary**: drop the `rollback` in `admit`: the counts below change.
#[test]
fn a_refused_package_leaves_the_topology_as_it_was() {
    let d = dev();
    let mut topo = d.topology();
    let (rows, caps) = (topo.tasks_len(), topo.caps_pool_len());
    // Parses, then fails the signer's ceiling.
    let b = with_grants(&grant("endpoint.names"));
    let v = verify(&b, &topo).unwrap();
    assert!(matches!(admit(&v, v.pkg.rows, &mut topo, &device()), Err(Refusal::OutsideWarrants { .. })));
    assert_eq!((topo.tasks_len(), topo.caps_pool_len()), (rows, caps));
    // And one that fails the topology's own admission after the merge.
    let wide = Device0::with_signers(&signer_text("acme", &author(), "mem_pages_max = 64\nwarrants = [\"endpoint:\"]\n"));
    let mut topo = wide.topology();
    let (rows, caps) = (topo.tasks_len(), topo.caps_pool_len());
    let b = with_grants(&grant("pwm.6"));
    let v = verify(&b, &topo).unwrap();
    assert!(matches!(admit(&v, v.pkg.rows, &mut topo, &device()), Err(Refusal::Admission(_))));
    assert_eq!((topo.tasks_len(), topo.caps_pool_len()), (rows, caps));
    // The same topology then takes a good package.
    let b = build(&Spec::acme(), &author());
    let v = verify(&b, &topo).unwrap();
    assert!(admit(&v, v.pkg.rows, &mut topo, &device()).is_ok());
    assert_eq!(topo.tasks_len(), rows + 1);
}

/// What the installer reads of a staged package: the head is enough to verify
/// the signature and the metadata and to admit the rows; the images are not.
#[test]
fn the_head_of_a_package_is_enough_to_admit_it() {
    use azos_pkg::verify_head;
    let d = dev();
    let bytes = build(&Spec::acme(), &author());
    let head_len = bytes.len() - 300;
    let mut topo = d.topology();
    let pkg = Package::parse_head(&bytes[..head_len]).expect("head");
    assert_eq!((pkg.images.len(), pkg.images_len), (0, 300));
    let v = verify_head(pkg, &topo).expect("the head verifies");
    assert!(admit(&v, v.pkg.rows, &mut topo, &device()).is_ok());
    // A partial image region parses as a head and is not a whole package.
    assert!(Package::parse_head(&bytes[..head_len + 10]).is_ok());
    assert!(Package::parse(&bytes[..head_len + 10]).is_err());
    assert!(Package::parse_head(&bytes[..head_len - 1]).is_err());
    // verify() still wants the whole file.
    assert!(verify(&bytes[..head_len + 10], &d.topology()).is_err());
}
