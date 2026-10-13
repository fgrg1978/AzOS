// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The installer (`userspace/lib/packages`) over an in-memory volume: the same
//! code `pkgd` runs, with the volume's failures under the test's control.

use super::*;
use azos_decision::{ProvenanceRecord, Rule, Verdict, PROVENANCE_SIZE};
use azos_idl::{Cap, MsgDesc, Transport};
use azos_packages::{
    id_words, step, step_name, status, Packages, PackagesClient, PackagesIdl, PkgMem, Read, Service, VolErr, Volume,
    Work,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Default)]
pub struct MemVol {
    pub files: BTreeMap<Vec<u8>, Vec<u8>>,
    pub dirs: BTreeSet<Vec<u8>>,
    pub caps: HashMap<u32, Vec<u8>>,
    pub fail_append: bool,
    pub fail_write: bool,
    pub clock: u64,
}

impl MemVol {
    /// A volume holding a device's signed topology (CAPS.TOM, CAPS.SIG,
    /// SCHED.TOM), signed by `signer`.
    pub fn device(d: &Device0, signer: &SigningKey) -> Self {
        let mut v = MemVol { clock: 1000, ..Default::default() };
        // The build provisions the staging directory with the volume.
        v.dirs.insert(b"/fat/PKG".to_vec());
        v.files.insert(b"/fat/CAPS.TOM".to_vec(), d.caps.clone().into_bytes());
        v.files.insert(b"/fat/CAPS.SIG".to_vec(), signer.sign(d.caps.as_bytes()).to_bytes().to_vec());
        v.files.insert(b"/fat/SCHED.TOM".to_vec(), d.sched.clone().into_bytes());
        v
    }

    pub fn staged(&self) -> Vec<String> {
        self.files
            .keys()
            .filter(|k| k.starts_with(b"/fat/PKG/") && k.ends_with(b".PKG"))
            .map(|k| String::from_utf8_lossy(k).into_owned())
            .collect()
    }

    pub fn journal(&self) -> Vec<ProvenanceRecord> {
        let j = self.files.get(&b"/fat/PKG/JOURNAL.BIN"[..]).cloned().unwrap_or_default();
        assert_eq!(j.len() % PROVENANCE_SIZE, 0);
        j.chunks(PROVENANCE_SIZE).map(|c| ProvenanceRecord::from_bytes(c).unwrap()).collect()
    }
}

fn fill(src: &[u8], buf: &mut [u8]) -> Read {
    let n = src.len().min(buf.len());
    buf[..n].copy_from_slice(&src[..n]);
    Read { n, more: src.len() > buf.len() }
}

/// The volume the service is given: a handle on the test's own, so the test
/// can look at what the service did.
pub struct Shared<'a>(pub &'a RefCell<MemVol>);

impl Volume for Shared<'_> {
    fn read_file(&mut self, path: &[u8], buf: &mut [u8]) -> Result<Read, VolErr> {
        self.0.borrow().files.get(path).map(|f| fill(f, buf)).ok_or(VolErr::Missing)
    }
    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr> {
        // The object is the installer's after the call: reading releases it.
        let obj = self.0.borrow_mut().caps.remove(&cap.raw()).ok_or(VolErr::Io)?;
        if len > buf.len() {
            return Err(VolErr::TooLarge);
        }
        if obj.len() < len {
            return Err(VolErr::Io);
        }
        buf[..len].copy_from_slice(&obj[..len]);
        Ok(len)
    }
    fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        let mut v = self.0.borrow_mut();
        if v.fail_write {
            return Err(VolErr::Io);
        }
        v.files.insert(path.to_vec(), data.to_vec());
        Ok(())
    }
    fn append(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr> {
        let mut v = self.0.borrow_mut();
        if v.fail_append {
            return Err(VolErr::Io);
        }
        v.files.entry(path.to_vec()).or_default().extend_from_slice(data);
        Ok(())
    }
    fn remove(&mut self, path: &[u8]) -> Result<(), VolErr> {
        self.0.borrow_mut().files.remove(path).map(|_| ()).ok_or(VolErr::Missing)
    }
    fn entry(&mut self, dir: &[u8], index: usize, name: &mut [u8; 64]) -> Option<usize> {
        let v = self.0.borrow();
        let prefix = [dir, b"/"].concat();
        let e = v.files.keys().filter_map(|k| k.strip_prefix(&prefix[..])).filter(|r| !r.contains(&b'/')).nth(index)?;
        name[..e.len()].copy_from_slice(e);
        Some(e.len())
    }
    fn dir_exists(&mut self, dir: &[u8]) -> bool {
        self.0.borrow().dirs.contains(dir)
    }
    fn now_ns(&mut self) -> u64 {
        let mut v = self.0.borrow_mut();
        v.clock += 1;
        v.clock
    }
}

/// The installer, with a topology key it trusts and this fixture's device.
pub struct Rig {
    pub vol: RefCell<MemVol>,
    work: Box<Work>,
    topo: Box<Topology<'static>>,
}

impl Rig {
    pub fn new(vol: MemVol) -> Self {
        Rig { vol: RefCell::new(vol), work: Box::new(Work::new()), topo: Box::new(Topology::empty()) }
    }

    pub fn service(&mut self) -> Service<'_, Shared<'_>> {
        Service::new(Shared(&self.vol), &mut self.work, &mut self.topo, *owner().verifying_key().as_bytes(), device())
    }

    /// A memory object holding `bytes`, as the capability and the length.
    pub fn put(&self, handle: u32, bytes: &[u8]) -> (Cap<PkgMem>, u32) {
        self.vol.borrow_mut().caps.insert(handle, bytes.to_vec());
        (Cap::from_raw(handle), bytes.len() as u32)
    }
}

fn dev() -> Device0 {
    Device0::with_signers(&signer_text("acme", &author(), CEILING))
}

fn rig() -> Rig {
    Rig::new(MemVol::device(&dev(), &owner()))
}

fn spec(name: &str) -> Spec {
    let mut s = Spec::acme();
    s.images = vec![(name.into(), (0..64u8).collect())];
    s.rows = row(name, "best_effort", 20, "{ kind = \"endpoint\", target = \"endpoint.acme\", perm = \"rw\" }");
    s
}

#[test]
fn install_stages_the_package_and_journals_the_decision() {
    let mut r = rig();
    let bytes = build(&Spec::acme(), &author());
    let (cap, len) = r.put(7, &bytes);
    let reply = r.service().install(cap, len);
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    assert_eq!(reply[2], 1, "one row");
    let staged = r.vol.borrow().staged();
    assert_eq!(staged.len(), 1);
    assert!(staged[0].starts_with("/fat/PKG/") && staged[0].ends_with(".PKG"));
    assert_eq!(r.vol.borrow().files[staged[0].as_bytes()], bytes, "the whole signed package is what is staged");
    assert!(r.vol.borrow().caps.is_empty(), "the capability is the installer's, and is closed");
    let j = r.vol.borrow().journal();
    assert_eq!(j.len(), 1);
    assert_eq!((j[0].rule, j[0].verdict), (Rule::PackageInstall as u8, Verdict::Admit as u8));
    assert_eq!(j[0].image_hash_prefix, reply[1]);
    assert!(j[0].clock_ns > 1000);
    // It is listed, by id.
    let id = azos_pkg::Package::parse(&bytes).unwrap().id();
    assert_eq!(r.service().installed(0), id_words(&id));
    assert_eq!(r.service().installed(1), [0; 4]);
}

/// A staged file is named by four bytes of the package id, so another package
/// can have the same name. It must be staged under another one, and the
/// package already there left as it was.
///
/// The collision is made by hand (a 32-bit prefix is not ground in a test): the
/// victim's file is put where the newcomer's first name is.
#[test]
fn a_package_whose_name_is_taken_by_another_package_is_staged_elsewhere() {
    let mut r = rig();
    let victim = build(&spec("VICTIM.ELF"), &author());
    let attacker = build(&spec("ATTACK.ELF"), &author());
    let aid = azos_pkg::Package::parse(&attacker).unwrap().id();
    assert_ne!(azos_pkg::Package::parse(&victim).unwrap().id(), aid);
    let hex: String = aid[..4].iter().map(|b| format!("{b:02X}")).collect();
    let taken = format!("/fat/PKG/{hex}.PKG").into_bytes();
    r.vol.borrow_mut().files.insert(taken.clone(), victim.clone());

    let (cap, len) = r.put(1, &attacker);
    let reply = r.service().install(cap, len);
    assert_eq!(reply[0], 0, "{}", step_name(reply[0]));
    let v = r.vol.borrow();
    assert_eq!(v.files[&taken], victim, "the package that was there is untouched");
    let staged = v.staged();
    assert_eq!(staged.len(), 2, "{staged:?}");
    let other = staged.iter().find(|p| p.as_bytes() != &taken[..]).unwrap();
    assert_eq!(v.files[other.as_bytes()], attacker);
    // Its name is the next four bytes of its id.
    let next: String = aid[4..8].iter().map(|b| format!("{b:02X}")).collect();
    assert_eq!(*other, format!("/fat/PKG/{next}.PKG"));
    drop(v);
    // A second request for the same package is a duplicate, whichever name it
    // is under, and the journal holds the one install.
    let (cap, len) = r.put(2, &attacker);
    assert_eq!(azos_packages::step_of(r.service().install(cap, len)[0]), step::ALREADY_STAGED as usize);
    assert_eq!(r.vol.borrow().journal().len(), 1);
    // A failed journal removes the file the install wrote and no other.
    let mut s = spec("THIRD.ELF");
    s.version = "3.0".into();
    let third = build(&s, &author());
    let tid = azos_pkg::Package::parse(&third).unwrap().id();
    let thex: String = tid[..4].iter().map(|b| format!("{b:02X}")).collect();
    let tpath = format!("/fat/PKG/{thex}.PKG").into_bytes();
    r.vol.borrow_mut().files.insert(tpath.clone(), victim.clone());
    r.vol.borrow_mut().fail_append = true;
    let (cap, len) = r.put(3, &third);
    assert_eq!(azos_packages::step_of(r.service().install(cap, len)[0]), step::IO as usize);
    assert_eq!(r.vol.borrow().files[&tpath], victim, "the victim of a failed install is still there");
}

/// A dry run changes nothing and records nothing.
#[test]
fn admit_changes_nothing() {
    let mut r = rig();
    let before = r.vol.borrow().files.clone();
    let (cap, len) = r.put(1, &build(&Spec::acme(), &author()));
    assert_eq!(r.service().admit(cap, len)[0], 0);
    assert_eq!(r.vol.borrow().files, before);
    // And it refuses what install would, without a record.
    let (cap, len) = r.put(2, &build(&Spec::acme(), &stranger()));
    assert_eq!(azos_packages::step_of(r.service().admit(cap, len)[0]), 3);
    assert_eq!(r.vol.borrow().files, before);
}

/// The three refusals the plan names, through the whole service: each is a
/// refusal, a journal record, and no staged file.
///
/// **Canary** `pkg-verify-skip-canary`, `pkg-signer-canary` (crate features of
/// the suite) and `neverallow-canary`.
#[test]
fn unsigned_wrong_signer_and_neverallow_manifests_are_refused_and_recorded() {
    let mut r = Rig::new(MemVol::device(
        &Device0::with_signers(&signer_text("acme", &author(), "mem_pages_max = 64\nwarrants = [\"endpoint:\"]\n")),
        &owner(),
    ));
    let s = Spec::acme();
    let images: Vec<u8> = s.images.iter().flat_map(|(_, d)| d.clone()).collect();
    let unsigned = assemble(0, &[], &[], s.meta().as_bytes(), s.rows.as_bytes(), &images);
    let wrong = build(&s, &stranger());
    let mut bad = Spec::acme();
    bad.rows = row("ACME.ELF", "best_effort", 20, "{ kind = \"endpoint\", target = \"pwm.6\", perm = \"rw\" }");
    let violating = build(&bad, &author());
    let mut forged = build(&s, &author());
    forged[azos_pkg::container::HEADER_LEN + 32 + 9] ^= 0x10;
    let cases = [
        ("unsigned", unsigned, 2usize),
        ("wrong signer", wrong, 3),
        ("neverallow", violating, 16),
        ("forged signature", forged, 4),
    ];
    for (i, (what, bytes, step_no)) in cases.iter().enumerate() {
        let (cap, len) = r.put(10 + i as u32, bytes);
        let reply = r.service().install(cap, len);
        assert_eq!(azos_packages::step_of(reply[0]), *step_no, "{what}: {}", step_name(reply[0]));
        assert!(r.vol.borrow().staged().is_empty(), "{what} was staged");
    }
    let j = r.vol.borrow().journal();
    assert_eq!(j.len(), 4, "every refusal is a decision");
    assert!(j.iter().all(|p| p.rule == Rule::PackageInstall as u8 && p.verdict == Verdict::Refuse as u8));
    assert_eq!(j[2].n[1], 1, "the neverallow package was the first signer's");
    assert_eq!(j[1].n[1], 0, "the stranger matched no signer");
}

/// Two packages that cannot both be in the topology: the second is judged
/// against the first, which is staged, and not against the device as it was.
#[test]
fn a_package_is_admitted_against_the_packages_already_staged() {
    let mut r = rig();
    let a = build(&Spec::acme(), &author());
    let mut s = Spec::acme();
    s.version = "2.0".into();
    let b = build(&s, &author());
    let (cap, len) = r.put(1, &b);
    assert_eq!(r.service().admit(cap, len)[0], 0, "alone, the second is fine");
    let (cap, len) = r.put(2, &a);
    assert_eq!(r.service().install(cap, len)[0], 0);
    let (cap, len) = r.put(3, &b);
    let reply = r.service().install(cap, len);
    // The first one's row is in the topology, so the second one's parses into
    // a name the topology already has.
    assert_eq!(azos_packages::step_of(reply[0]), 11, "{}", step_name(reply[0]));
    assert_eq!(r.vol.borrow().staged().len(), 1);
    // Removing the first makes room for the second.
    let id = azos_pkg::Package::parse(&a).unwrap().id();
    assert_eq!(r.service().remove(id_words(&id))[0], 0);
    let (cap, len) = r.put(4, &b);
    assert_eq!(r.service().install(cap, len)[0], 0);
    let j = r.vol.borrow().journal();
    let verdicts: Vec<u8> = j.iter().map(|p| p.verdict).collect();
    assert_eq!(verdicts, [Verdict::Admit as u8, Verdict::Refuse as u8, Verdict::Deny as u8, Verdict::Admit as u8]);
}

#[test]
fn installing_twice_and_removing_what_is_not_staged_are_refused() {
    let mut r = rig();
    let bytes = build(&Spec::acme(), &author());
    let (cap, len) = r.put(1, &bytes);
    assert_eq!(r.service().install(cap, len)[0], 0);
    let (cap, len) = r.put(2, &bytes);
    assert_eq!(r.service().install(cap, len)[0], status(step::ALREADY_STAGED, 0));
    assert_eq!(r.service().remove([1, 2, 3, 4])[0], status(step::NOT_STAGED, 0));
    assert_eq!(r.vol.borrow().staged().len(), 1);
}

#[test]
fn only_so_many_packages_are_staged() {
    let mut r = rig();
    let max = azos_limits::PKG_MAX_STAGED as usize;
    for i in 0..max {
        let (cap, len) = r.put(i as u32, &build(&spec(&format!("P{i:02}.ELF")), &author()));
        let reply = r.service().install(cap, len);
        assert_eq!(reply[0], 0, "package {i}: {}", step_name(reply[0]));
    }
    let (cap, len) = r.put(99, &build(&spec("LAST.ELF"), &author()));
    assert_eq!(r.service().install(cap, len)[0], status(step::NO_ROOM, 0));
    assert_eq!(r.vol.borrow().staged().len(), max);
}

#[test]
fn a_device_without_a_signed_topology_admits_nothing() {
    let none = step::NO_TOPOLOGY;
    let bytes = build(&Spec::acme(), &author());
    // No files at all.
    let mut r = Rig::new(MemVol::default());
    let (cap, len) = r.put(1, &bytes);
    assert_eq!(azos_packages::step_of(r.service().install(cap, len)[0]) as u64, none);
    // A topology signed by somebody else.
    let mut r = Rig::new(MemVol::device(&dev(), &stranger()));
    let (cap, len) = r.put(1, &bytes);
    let reply = r.service().install(cap, len);
    assert_eq!(azos_packages::step_of(reply[0]) as u64, none);
    assert_eq!(reply[0] & 0xFF_FFFF, 3, "the signature step of the topology loader");
    // A topology with a byte changed after it was signed.
    let mut v = MemVol::device(&dev(), &owner());
    v.files.get_mut(&b"/fat/CAPS.TOM"[..]).unwrap().push(b'\n');
    let mut r = Rig::new(v);
    let (cap, len) = r.put(1, &bytes);
    assert_eq!(azos_packages::step_of(r.service().install(cap, len)[0]) as u64, none);
    // A topology with no signers: nobody is admitted.
    let mut r = Rig::new(MemVol::device(&Device0::with_signers(""), &owner()));
    let (cap, len) = r.put(1, &bytes);
    assert_eq!(azos_packages::step_of(r.service().install(cap, len)[0]), 3);
}

#[test]
fn a_volume_that_fails_leaves_no_install_behind() {
    let bytes = build(&Spec::acme(), &author());
    let mut r = rig();
    r.vol.borrow_mut().fail_append = true;
    let (cap, len) = r.put(1, &bytes);
    let reply = r.service().install(cap, len);
    assert_eq!(reply[0], status(step::IO, azos_packages::io::JOURNAL));
    assert!(r.vol.borrow().staged().is_empty(), "an install that cannot be recorded is undone");
    let mut r = rig();
    r.vol.borrow_mut().fail_write = true;
    let (cap, len) = r.put(1, &bytes);
    assert_eq!(r.service().install(cap, len)[0], status(step::IO, azos_packages::io::WRITE_PACKAGE));
    assert!(r.vol.borrow().journal().is_empty());
    // A capability that cannot be read.
    let mut r = rig();
    assert_eq!(r.service().install(Cap::from_raw(5), 10)[0], status(step::IO, azos_packages::io::READ_PACKAGE));
}

/// The installer cannot make its own directory (a tree grant does not cover
/// its own root): a volume without `/fat/PKG` is an error it names.
#[test]
fn a_volume_without_the_staging_directory_is_an_error_not_an_install() {
    let mut v = MemVol::device(&dev(), &owner());
    v.dirs.clear();
    let mut r = Rig::new(v);
    let (cap, len) = r.put(1, &build(&Spec::acme(), &author()));
    assert_eq!(r.service().install(cap, len)[0], status(step::IO, azos_packages::io::NO_STAGE_DIR));
    assert!(r.vol.borrow().staged().is_empty() && r.vol.borrow().journal().is_empty());
}

#[test]
fn a_package_larger_than_the_buffer_is_refused_unread() {
    let mut r = rig();
    let big = vec![0u8; azos_limits::PKG_MAX_KB as usize * 1024 + 1];
    let (cap, len) = r.put(1, &big);
    assert!(len as usize > azos_limits::PKG_MAX_KB as usize * 1024);
    let reply = r.service().install(cap, len);
    assert_eq!(azos_packages::step_of(reply[0]), 1, "container");
    assert!(r.vol.borrow().staged().is_empty());
}

/// Junk in `/fat/PKG` is not a staged package: wrong names are skipped, and
/// a right name with no package in it is skipped too.
#[test]
fn files_that_are_not_staged_packages_are_ignored() {
    let mut r = rig();
    {
        let mut v = r.vol.borrow_mut();
        v.files.insert(b"/fat/PKG/README.TXT".to_vec(), b"hello".to_vec());
        v.files.insert(b"/fat/PKG/DEADBEEF.PKG".to_vec(), b"not a package".to_vec());
        v.files.insert(b"/fat/PKG/deadbeef.pkg".to_vec(), b"x".to_vec());
    }
    assert_eq!(r.service().installed(0), [0; 4]);
    let (cap, len) = r.put(1, &build(&Spec::acme(), &author()));
    assert_eq!(r.service().install(cap, len)[0], 0);
    assert_eq!(r.service().installed(1), [0; 4]);
}

/// The same thing through the generated client stub and dispatcher: the
/// package crosses as a capability, the answer as four words.
struct Loop<'a, 'w>(&'a RefCell<Service<'w, Shared<'a>>>);

impl Transport for Loop<'_, '_> {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        let req = *msg;
        let mut rep = MsgDesc::default();
        PackagesIdl::dispatch(&mut *self.0.borrow_mut(), &req, &mut rep)?;
        *msg = rep;
        Ok(())
    }
}

#[test]
fn the_interface_carries_the_package_as_a_capability() {
    let vol = RefCell::new(MemVol::device(&dev(), &owner()));
    let mut work = Box::new(Work::new());
    let mut topo = Box::new(Topology::empty());
    let bytes = build(&Spec::acme(), &author());
    vol.borrow_mut().caps.insert(42, bytes.clone());
    let len = bytes.len() as u32;
    let svc = RefCell::new(Service::new(Shared(&vol), &mut work, &mut topo, *owner().verifying_key().as_bytes(), device()));
    let mut c = PackagesClient::new(Loop(&svc));
    let reply = azos_packages::PackagesCall::install(&mut c, Cap::from_raw(42), len).expect("served");
    assert_eq!(reply[0], 0);
    assert_eq!(vol.borrow().staged().len(), 1);
    let listed = azos_packages::PackagesCall::installed(&mut c, 0).unwrap();
    assert_eq!(listed, id_words(&azos_pkg::Package::parse(&bytes).unwrap().id()));
    // `install` is never retried; `installed` may be.
    assert!(!PackagesIdl::OPS[1].retry_safe() && PackagesIdl::OPS[1].once_only());
    assert!(PackagesIdl::OPS[3].idempotent());
}

/// The installer's frame budget in the built-in topology covers what the
/// program holds: its buffers, the topology it merges into, and (a generous
/// bound for) its image, stack and page tables.
///
/// **Canary**: drop the staged-rows arena term from `PKGD_MEM_PAGES`'s formula
/// and the first bound goes red.
#[test]
fn the_installers_row_budgets_its_working_set() {
    // A small board has neither row (the budget below is then not spent).
    if !azos_topology::builder::PKGD_ROW {
        let topo = azos_topology::default_minimal();
        assert!(topo.find_task(&azos_topology::MaybeStr::from_bytes(b"PKGD.ELF")).is_none());
        assert!(topo.find_task(&azos_topology::MaybeStr::from_bytes(b"PKG.ELF")).is_none());
        return;
    }
    let working_set = std::mem::size_of::<Work>() + std::mem::size_of::<Topology<'static>>();
    let budget = azos_topology::builder::PKGD_MEM_PAGES as usize * 4096;
    assert!(budget >= working_set + 192 * 1024, "{budget} bytes budgeted, {working_set} held");
    // And not by a wide margin: the budget is a ceiling every board's memory
    // admission adds up.
    assert!(budget <= working_set + 512 * 1024, "{budget} bytes budgeted, {working_set} held");
    // The row is the one the tool and the installer agree on.
    let topo = azos_topology::default_minimal();
    let row = topo.find_task(&azos_topology::MaybeStr::from_bytes(b"PKGD.ELF")).expect("the installer's row");
    assert_eq!(row.mem_pages, azos_topology::builder::PKGD_MEM_PAGES);
    let caps = topo.caps_of(row);
    assert_eq!(caps.len(), 2, "the endpoint and the staging tree, nothing else");
    assert!(caps.iter().any(|c| c.target.as_bytes() == b"endpoint.packages" && c.perms.contains(azos_abi::cap::CapPerms::READ)));
    assert!(caps.iter().any(|c| c.target.as_bytes() == b"/fat/PKG" && c.kind == azos_abi::cap::CapKind::Node));
    let tool = topo.find_task(&azos_topology::MaybeStr::from_bytes(b"PKG.ELF")).expect("the tool's row");
    let tool_caps = topo.caps_of(tool);
    assert_eq!(tool_caps.len(), 1, "the call right and nothing else");
    assert!(tool_caps[0].perms.contains(azos_abi::cap::CapPerms::WRITE) && !tool_caps[0].perms.contains(azos_abi::cap::CapPerms::READ));
    // The built-in topology is judged by the same rules: it is admitted.
    assert_eq!(topo.admission_check(), Ok(()));
}

/// The length a client states is the installer's to distrust: more than the
/// object holds is an error, less than the package is a package that is cut
/// short, and the installer reads no further than the length.
#[test]
fn the_length_a_client_states_is_checked() {
    let bytes = build(&Spec::acme(), &author());
    let mut r = rig();
    let (cap, len) = r.put(1, &bytes);
    assert_eq!(r.service().install(cap, len + 10)[0], status(step::IO, azos_packages::io::READ_PACKAGE));
    let (cap, len) = r.put(2, &bytes);
    let reply = r.service().install(cap, len - 1);
    assert_eq!(azos_packages::step_of(reply[0]), 1, "container: {}", step_name(reply[0]));
    let (cap, _) = r.put(3, &bytes);
    assert_eq!(azos_packages::step_of(r.service().install(cap, 0)[0]), 1);
    assert!(r.vol.borrow().staged().is_empty());
    assert!(r.vol.borrow().caps.is_empty(), "every object was released");
    // Trailing bytes in the object past `len` are not read.
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0xAA; 100]);
    let (cap, _) = r.put(4, &padded);
    assert_eq!(r.service().install(cap, bytes.len() as u32)[0], 0);
}
