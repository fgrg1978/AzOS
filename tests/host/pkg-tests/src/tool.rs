// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `pkg`'s command line and output (`userspace/lib/packages/src/cli.rs`),
//! driven through the generated client stub and a loopback, with the installer
//! over an in-memory volume beyond it.

use super::service::{Fake, MemVol, NoRemote, Shared, SOURCE_ROWS};
use super::*;
use azos_idl::{Cap, MsgDesc, Transport};
use azos_packages::cli::{self, Cmd, Fail, Opener};
use azos_packages::{FetchErr, PackagesClient, PackagesIdl, PkgMem, Remote, Service, Work};
use azos_topology::Topology;
use std::cell::RefCell;

struct Loop<'a, 'w, R: Remote>(&'a RefCell<Service<'w, Shared<'a>, R>>);

impl<R: Remote> Transport for Loop<'_, '_, R> {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        let req = *msg;
        let mut rep = MsgDesc::default();
        PackagesIdl::dispatch(&mut *self.0.borrow_mut(), &req, &mut rep)?;
        *msg = rep;
        Ok(())
    }
}

/// "Files" the tool can open: a path names bytes, opening one makes an object
/// the volume's capability table holds until the installer reads it.
struct Files<'a> {
    vol: &'a RefCell<MemVol>,
    named: Vec<(&'static [u8], Vec<u8>)>,
    next: u32,
}

impl Opener for Files<'_> {
    fn open(&mut self, path: &[u8]) -> Option<(Cap<PkgMem>, u32)> {
        let (_, bytes) = self.named.iter().find(|(p, _)| *p == path)?;
        self.next += 1;
        self.vol.borrow_mut().caps.insert(self.next, bytes.clone());
        Some((Cap::from_raw(self.next), bytes.len() as u32))
    }
}

fn args<'a>(a: &[&'a str]) -> Vec<&'a [u8]> {
    a.iter().map(|s| s.as_bytes()).collect()
}

fn run<'a, R: Remote>(a: &[&'a str], files: &mut Files<'_>, c: &mut PackagesClient<Loop<'_, '_, R>>) -> (Result<i32, Fail>, String) {
    let argv = args(a);
    let cmd = cli::parse(&argv).expect("parses");
    let mut out = String::new();
    let r = cli::run(&cmd, c, files, &mut out);
    (r, out)
}

#[test]
fn the_command_line_is_read_exactly() {
    fn parsed(a: &[&str]) -> Result<(), &'static str> {
        cli::parse(&args(a)).map(|_| ())
    }
    assert_eq!(cli::parse(&args(&["admit", "/fat/A.PKG"])), Ok(Cmd::Admit(b"/fat/A.PKG")));
    assert_eq!(cli::parse(&args(&["install", "x"])), Ok(Cmd::Install(b"x")));
    assert_eq!(cli::parse(&args(&["list"])), Ok(Cmd::List));
    assert_eq!(cli::parse(&args(&["fetch"])), Ok(Cmd::Fetch));
    let ab = "ab".repeat(32);
    assert!(matches!(cli::parse(&args(&["remove", &ab])), Ok(Cmd::Remove(id)) if id[0] == 0xab));
    let zz = "zz".repeat(32);
    for bad in [&[][..], &["install"], &["list", "x"], &["fetch", "x"], &["remove", "abc"], &["remove", &zz], &["format"], &["admit", "a", "b"]] {
        assert!(parsed(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_tool_installs_lists_and_removes_through_the_installer() {
    let d = Device0::with_signers(&signer_text("acme", &author(), CEILING));
    let vol = RefCell::new(MemVol::device(&d, &owner()));
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let svc = RefCell::new(Service::new(Shared(&vol), NoRemote, &mut work, &mut topo, *owner().verifying_key().as_bytes(), device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let good = build(&Spec::acme(), &author());
    let id = azos_pkg::Package::parse(&good).unwrap().id();
    let mut files = Files {
        vol: &vol,
        named: vec![(b"/fat/ACME.AZP", good), (b"/fat/EVIL.AZP", build(&Spec::acme(), &stranger()))],
        next: 0,
    };

    let (r, out) = run(&["admit", "/fat/ACME.AZP"], &mut files, &mut c);
    assert_eq!(r, Ok(0));
    assert!(out.starts_with("would install: package ") && out.contains("1 row(s)"), "{out}");
    assert!(vol.borrow().staged().is_empty());

    let (r, out) = run(&["install", "/fat/ACME.AZP"], &mut files, &mut c);
    assert_eq!(r, Ok(0), "{out}");
    assert!(out.starts_with("installed: package "), "{out}");

    let (r, out) = run(&["list"], &mut files, &mut c);
    assert_eq!(r, Ok(0));
    let want: String = id.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(out, format!("{want}\n"));

    // A refusal is named by its step.
    let (r, out) = run(&["install", "/fat/EVIL.AZP"], &mut files, &mut c);
    assert_eq!(r, Ok(1));
    assert!(out.starts_with("refused: signer (status 0x3000000, package "), "{out}");
    let (r, out) = run(&["install", "/fat/ACME.AZP"], &mut files, &mut c);
    assert_eq!((r, out.starts_with("refused: already staged")), (Ok(1), true), "{out}");

    // A file that is not there is the tool's failure, not the installer's.
    let argv = args(&["install", "/fat/NOPE.AZP"]);
    let mut out = String::new();
    assert_eq!(cli::run(&cli::parse(&argv).unwrap(), &mut c, &mut files, &mut out), Err(Fail::Open));

    let (r, out) = run(&["remove", &want], &mut files, &mut c);
    assert_eq!((r, out.starts_with("removed: package ")), (Ok(0), true), "{out}");
    let (r, out) = run(&["remove", &want], &mut files, &mut c);
    assert_eq!((r, out.starts_with("refused: not staged")), (Ok(1), true), "{out}");
    let (r, out) = run(&["list"], &mut files, &mut c);
    assert_eq!((r, out.as_str()), (Ok(0), ""));
}

/// The step names a status prints match the steps `azos_pkg` numbers.
#[test]
fn every_refusal_prints_the_name_of_its_step() {
    use azos_pkg::{Refusal, MetaError};
    use azos_pkg::container::ParseError;
    let cases = [
        (Refusal::Container(ParseError::Short), "container"),
        (Refusal::Algorithm(9), "algorithm"),
        (Refusal::UnknownSigner, "signer"),
        (Refusal::Signature, "signature"),
        (Refusal::Meta(MetaError::Syntax), "metadata"),
        (Refusal::Images(0), "images"),
        (Refusal::Hardware, "hardware"),
        (Refusal::Abi { wanted: 1, have: 2 }, "abi"),
        (Refusal::Api(0), "interface level"),
        (Refusal::ForeignSection, "foreign section"),
        (Refusal::Rows(azos_topology::ParseError::BadValue), "rows"),
        (Refusal::RowsImages, "rows and images"),
        (Refusal::OutsideWarrants { row: 0, grant: 0 }, "warrants"),
        (Refusal::OutsideImports { row: 0, import: 0 }, "imports"),
        (Refusal::RealTime(0), "real time"),
        (Refusal::Frames(0), "frames"),
        (Refusal::Admission(azos_topology::AdmissionError::DuplicateTask), "admission"),
        (Refusal::Epoch { have: 1, floor: 2 }, "epoch floor"),
        (Refusal::Boot(azos_pkg::apply::BootWhy::Admission), "boot admission"),
        (Refusal::Boot(azos_pkg::apply::BootWhy::Unconfirmed), "unconfirmed trial"),
        (Refusal::Boot(azos_pkg::apply::BootWhy::Volume), "volume"),
        (Refusal::Index(azos_pkg::index::IndexWhy::Signature), "index signature"),
        (Refusal::Index(azos_pkg::index::IndexWhy::Stale), "index older than the stored one"),
        (Refusal::Upgrade(azos_pkg::index::UpgradeWhy::Downgrade), "older than the installed version"),
        (Refusal::Upgrade(azos_pkg::index::UpgradeWhy::BelowFloor), "below the security floor"),
        (Refusal::FloorQuota(5), "floor quota"),
    ];
    for (r, name) in cases {
        assert_eq!(azos_packages::step_name(r.code()), name, "{r:?}");
    }
    assert_eq!(azos_packages::step_name(0), "ok");
}

/// `pkg fetch` asks the installer to get the package from its source, and prints
/// what the installer answered: the package, or the step that said no.
#[test]
fn the_tool_fetches_through_the_installer() {
    let d = Device0::with_signers(&signer_text("acme", &author(), CEILING));
    let vol = RefCell::new(MemVol::device(&d, &owner()));
    vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), SOURCE_ROWS.to_vec());
    let mut files = Files { vol: &vol, named: Vec::new(), next: 0 };
    let good = build(&Spec::acme(), &author());
    let id = azos_pkg::Package::parse(&good).unwrap().id();
    let want: String = id.iter().map(|b| format!("{b:02x}")).collect();

    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let key = *owner().verifying_key().as_bytes();

    // The source cannot be reached: the step is named, nothing is staged.
    {
        let svc = RefCell::new(Service::new(Shared(&vol), Fake::new(Err(FetchErr::Tls)), &mut work, &mut topo, key, device()));
        let mut c = PackagesClient::new(Loop(&svc));
        let (r, out) = run(&["fetch"], &mut files, &mut c);
        assert_eq!((r, out.starts_with("refused: tls (status 0x27000004, package ")), (Ok(1), true), "{out}");
    }
    assert!(vol.borrow().staged().is_empty());

    // The source delivers: installed as `install` does, and listed.
    let svc = RefCell::new(Service::new(Shared(&vol), Fake::new(Ok(good)), &mut work, &mut topo, key, device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let (r, out) = run(&["fetch"], &mut files, &mut c);
    assert_eq!((r, out.starts_with("installed: package ")), (Ok(0), true), "{out}");
    let (r, out) = run(&["list"], &mut files, &mut c);
    assert_eq!((r, out), (Ok(0), format!("{want}\n")));
}

#[test]
fn the_outdated_and_upgrade_commands_are_read_exactly() {
    use azos_packages::cli::Upgrade;
    assert_eq!(cli::parse(&args(&["outdated"])), Ok(Cmd::Outdated));
    assert_eq!(cli::parse(&args(&["upgrade"])), Ok(Cmd::Upgrade(Upgrade::All)));
    assert_eq!(cli::parse(&args(&["upgrade", "--all"])), Ok(Cmd::Upgrade(Upgrade::All)));
    assert_eq!(cli::parse(&args(&["upgrade", "acme-vision"])), Ok(Cmd::Upgrade(Upgrade::Name(b"acme-vision"))));
    let long = "x".repeat(33);
    for bad in [&["outdated", "x"][..], &["upgrade", "a", "b"], &["upgrade", &long]] {
        assert!(cli::parse(&args(bad)).is_err(), "{bad:?}");
    }
}

/// `pkg outdated` and `pkg upgrade` through the installer: the report, the
/// upgrade of what is behind, and what a refusal prints.
#[test]
fn the_tool_reports_what_is_outdated_and_upgrades_it() {
    let d = Device0::with_signers(&signer_text("acme", &author(), CEILING));
    let vol = RefCell::new(MemVol::device(&d, &owner()));
    vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), SOURCE_ROWS.to_vec());
    let at = |name: &str, version: &str| {
        let mut s = Spec::acme();
        s.name = name.into();
        s.version = version.into();
        let image = format!("{}.ELF", name.to_uppercase().replace('-', "_").chars().take(8).collect::<String>());
        s.images = vec![(image.clone(), vec![1; 50])];
        s.rows = row(&image, "best_effort", 20, "{ kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" }");
        build(&s, &author())
    };
    let (acme_old, acme_new, zeta) = (at("acme-vision", "1.0.0"), at("acme-vision", "1.3.0"), at("zeta", "2.0"));
    let body = index_body(5, &[Offer::of(&acme_new, "ACMEV130.PKG", Some("1.2.0")), Offer::of(&zeta, "ZETA.PKG", None)]);
    let remote = Fake::repository(&[("INDEX.AZX", build_index(&body, &author())), ("ACMEV130.PKG", acme_new.clone()), ("ZETA.PKG", zeta.clone())]);

    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let key = *owner().verifying_key().as_bytes();
    let svc = RefCell::new(Service::new(Shared(&vol), remote, &mut work, &mut topo, key, device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let mut files = Files { vol: &vol, named: vec![(b"/a", acme_old.clone()), (b"/z", zeta)], next: 0 };
    for f in ["/a", "/z"] {
        assert_eq!(run(&["install", f], &mut files, &mut c).0, Ok(0));
    }

    let (r, out) = run(&["outdated"], &mut files, &mut c);
    assert_eq!(r, Ok(0), "{out}");
    let line = |name: &str| out.lines().find(|l| l.starts_with(name)).unwrap_or_else(|| panic!("{name} in {out}")).split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(line("acme-vision"), "acme-vision 1.0.0 1.3.0 behind; below security floor 1.2.0");
    assert_eq!(line("zeta"), "zeta 2.0.0 2.0.0 up to date");
    assert!(out.ends_with("1 behind, 1 below their security floor\n"), "{out}");

    // A package that is current is not an upgrade; the refusal names its reason.
    let (r, out) = run(&["upgrade", "zeta"], &mut files, &mut c);
    assert_eq!((r, out.starts_with("refused zeta: nothing newer on offer (status 0x17000005)")), (Ok(1), true), "{out}");
    let (r, out) = run(&["upgrade", "nothing-here"], &mut files, &mut c);
    assert_eq!((r, out.contains("not installed")), (Ok(1), true), "{out}");

    let (r, out) = run(&["upgrade", "--all"], &mut files, &mut c);
    assert_eq!(r, Ok(0), "{out}");
    assert!(out.starts_with("upgraded acme-vision 1.0.0 -> 1.3.0 (package "), "{out}");
    assert_eq!(vol.borrow().staged().len(), 3, "the old version stays staged beside the new one until the boot confirms it");
    let (r, out) = run(&["outdated"], &mut files, &mut c);
    assert_eq!(r, Ok(0));
    assert!(out.ends_with("0 behind, 0 below their security floor\n"), "{out}");
    let (r, out) = run(&["upgrade"], &mut files, &mut c);
    assert_eq!((r, out.as_str()), (Ok(0), "nothing to upgrade\n"));
}

#[test]
fn the_tool_prints_why_an_index_was_refused() {
    let d = Device0::with_signers(&signer_text("acme", &author(), CEILING));
    let vol = RefCell::new(MemVol::device(&d, &owner()));
    vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), SOURCE_ROWS.to_vec());
    let body = index_body(5, &[]);
    let forged = build_index(&body, &stranger());
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let key = *owner().verifying_key().as_bytes();
    let svc = RefCell::new(Service::new(Shared(&vol), Fake::repository(&[("INDEX.AZX", forged)]), &mut work, &mut topo, key, device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let mut files = Files { vol: &vol, named: Vec::new(), next: 0 };
    for cmd in [&["outdated"][..], &["upgrade", "--all"]] {
        let (r, out) = run(cmd, &mut files, &mut c);
        assert_eq!((r, out.starts_with("refused: index signer (status 0x16000006)")), (Ok(1), true), "{cmd:?}: {out}");
    }
}

/// The client prints versions from the wire form; the library prints them from the type.
#[test]
fn the_client_and_the_library_print_a_version_alike() {
    for s in ["0.0.1", "1.2", "1.2.3.4", "65535.0.0", "10.20.30"] {
        let v = azos_pkg::index::Version::parse(s).unwrap();
        let mut a = String::new();
        azos_packages::write_version(&mut a, v.packed()).unwrap();
        assert_eq!(a, v.to_string(), "{s}");
    }
}

/// A version of 0 is a version: a package at 0.0.0 with a floor of 0 prints them, and `-` stays for "none".
#[test]
fn version_zero_is_printed_and_absence_is_a_dash() {
    let d = Device0::with_signers(&signer_text("acme", &author(), CEILING));
    let vol = RefCell::new(MemVol::device(&d, &owner()));
    vol.borrow_mut().files.insert(b"/fat/PKG/SOURCE.CFG".to_vec(), SOURCE_ROWS.to_vec());
    let mut s = Spec::acme();
    s.version = "0.0.0".into();
    let zero = build(&s, &author());
    s.version = "1.0.0".into();
    let body = index_body(1, &[Offer::of(&build(&s, &author()), "A.PKG", Some("0"))]);
    let remote = Fake::repository(&[("INDEX.AZX", build_index(&body, &author()))]);
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let key = *owner().verifying_key().as_bytes();
    let svc = RefCell::new(Service::new(Shared(&vol), remote, &mut work, &mut topo, key, device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let mut files = Files { vol: &vol, named: vec![(b"/z", zero)], next: 0 };
    assert_eq!(run(&["install", "/z"], &mut files, &mut c).0, Ok(0));
    let (r, out) = run(&["outdated"], &mut files, &mut c);
    assert_eq!(r, Ok(0), "{out}");
    let line = out.lines().find(|l| l.starts_with("acme-vision")).unwrap().split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(line, "acme-vision 0.0.0 1.0.0 behind");
}
