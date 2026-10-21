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
