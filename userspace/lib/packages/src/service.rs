// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The installer's pure half: the [`Packages`](crate::Packages) service over a
//! volume it does not own.
//!
//! Everything the installer does to the world goes through [`Volume`], so the
//! host suite runs it over a map of files and `pkgd` runs it over libsys. The
//! rest is `azos_pkg` and `azos_topology`: the signed topology is read off the
//! volume and verified against the topology key like the kernel does at boot
//! (`signed::fill_signed`, with no device or counter policy: a ring-3 program
//! cannot know the device record, so the installer checks neither the device id
//! nor the counter floor or the security epoch floor; the kernel's boot-time apply
//! checks them, with the rest again), the packages
//! already staged are merged into it, and the candidate is judged against the
//! result.
//!
//! # Memory
//!
//! One [`Work`] holds every buffer, and a [`Topology`] beside it; the program
//! places both in statics (the buffers are all zero, so they are `.bss`; the
//! topology is not, a `MaybeStr` of nothing is a dangling pointer, so it is
//! `.data`, and its size is the Kconfig tables'). A request reloads the topology
//! from the volume (its text is borrowed from the buffers, so each request
//! clears the topology before the buffers are overwritten: [`parts`]).

use azos_crypto::sig::KEY_LEN;
use azos_decision::{ProvenanceRecord, Rule, Verdict};
use azos_idl::Cap;
use azos_pkg::apply::{supersede_iter, supersede_push, SUPERSEDE_REC};
use azos_pkg::container::{ParseError, HEADER_LEN, KEY_LEN_MAX, SIG_LEN_MAX};
use azos_pkg::index::{assess, check_upgrade, upgrade_entry, Availability, Entry, Floor, IndexWhy, Installed, UpgradeWhy, Version};
use azos_pkg::{admit, receipt, verify, verify_head, Device, Package, Refusal};
use azos_topology::signed::{fill_signed, DeviceContext, SignedFiles};
use azos_topology::{Topology, CAPS_SIG_PATH, CAPS_TOML_PATH, SCHED_TOML_PATH};

use crate::pure::{BootMeta, DeltaSource, SetBase, DELTA_MAGIC};
use crate::update::{self, Source, Store};
use crate::{id_words, io, standing, status, step, words_id, words_name, Packages, PkgMem};

/// Where packages are staged.
pub const STAGE_DIR: &[u8] = b"/fat/PKG";
/// The install journal: `ProvenanceRecord` wire records, appended.
pub const JOURNAL: &[u8] = b"/fat/PKG/JOURNAL.BIN";
/// The rows of the package source [`Service::fetch`] reads: `key=value` lines
/// naming the server, where to connect, what to GET and the keys it is pinned
/// to (`azos_tls::rows`). Absent, there is no source.
pub const SOURCE: &[u8] = b"/fat/PKG/SOURCE.CFG";

/// Where the index of the signer whose key id is `key_id` is kept: the last one
/// the installer verified and accepted from that signer, one slot per signer
/// (`azos_pkg::index::slot_name`). The kernel's boot-time apply reads the
/// security floors from the slots (and verifies each again).
fn slot_path(key_id: &[u8; 32]) -> [u8; 21] {
    let mut p = *b"/fat/PKG/I0000000.AZX";
    p[9..].copy_from_slice(&azos_pkg::index::slot_name(key_id));
    p
}
/// The upgrades in flight (`azos_pkg::apply::SUPERSEDE`).
const SUPERSEDE_PATH: &[u8] = b"/fat/PKG/SUPERSEDE.REQ";
/// Bytes of the buffer the file is read into: a record per staged package, and one more.
const SUPERSEDE_BUF: usize = (azos_limits::PKG_MAX_STAGED as usize + 1) * SUPERSEDE_REC;
// The staged-scan buffer is the largest thing the installer reads at a time.
const _: () = assert!(SUPERSEDE_BUF <= HEAD_BUF);

/// The index's file name beside the package the source rows name.
pub const INDEX_FILE: &str = "INDEX.AZX";

// A fetched index is read into the package buffer, a stored one into a buffer of
// its own: an index that does not fit either would be silently ignored.
const _: () = assert!(azos_pkg::index::FILE_MAX <= PKG_BUF, "PKG_MAX_KB is smaller than the largest index (PKG_INDEX_MAX_ENTRIES)");

const META_MAX: usize = azos_limits::PKG_META_MAX_KB as usize * 1024;
/// Packages staged at once (Kconfig `PKG_MAX_STAGED`).
pub const MAX_STAGED: usize = azos_limits::PKG_MAX_STAGED as usize;
/// The copy buffer of a whole-system update (a FAT volume writes faster in
/// big pieces).
pub const UPDATE_IO: usize = 16 * 1024;
/// The package buffer (Kconfig `PKG_MAX_KB`).
pub const PKG_BUF: usize = azos_limits::PKG_MAX_KB as usize * 1024;
/// What the installer reads of a staged package: everything but the images.
pub const HEAD_BUF: usize = HEADER_LEN + KEY_LEN_MAX + SIG_LEN_MAX + 2 * META_MAX;
const CAPS_BUF: usize = azos_limits::TOPOLOGY_CAPS_MAX_KB as usize * 1024;
const SCHED_BUF: usize = azos_limits::TOPOLOGY_SCHED_MAX_KB as usize * 1024;
/// Directory entries one scan reads before it stops.
const SCAN_MAX: usize = 4 * MAX_STAGED + 8;

/// Why the volume refused an access.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VolErr {
    /// No such file.
    Missing,
    /// Anything else.
    Io,
    /// More bytes than the buffer holds.
    TooLarge,
}

/// A read: how many bytes, and whether the file has more than the buffer held.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Read {
    /// Bytes read.
    pub n: usize,
    /// The buffer was filled and the file goes on.
    pub more: bool,
}

/// What the installer needs of the machine. The file operations a whole-system
/// update shares with the package stager are [`Store`]'s (streams, `remove`,
/// directory listing); the rest are the installer's own.
pub trait Volume: Store {
    /// The update bundle, as the stager reads it.
    type Bundle: Source;
    /// The file at `path`, from its start, into `buf`.
    fn read_file(&mut self, path: &[u8], buf: &mut [u8]) -> Result<Read, VolErr>;
    /// The first `len` bytes of the memory object `cap` names, copied into
    /// `buf` (the client keeps its own mapping, so what is read must be copied
    /// before it is checked), and release the capability whatever happens: the
    /// installer owns what a client gave it. `Err(TooLarge)` when `len` does
    /// not fit `buf`, `Err(Io)` when the object holds fewer than `len` bytes.
    /// The bytes read.
    fn read_package(&mut self, cap: Cap<PkgMem>, len: usize, buf: &mut [u8]) -> Result<usize, VolErr>;
    /// The memory object `cap` names, as a [`Source`] of its first `len` bytes:
    /// mapped in place and read piece by piece (a kernel does not fit a
    /// buffer). The capability is the installer's: the object is released when
    /// the bundle is dropped, and at once if it cannot be opened. `Err(Io)`
    /// when the object holds fewer than `len` bytes.
    fn open_bundle(&mut self, cap: Cap<PkgMem>, len: usize) -> Result<Self::Bundle, VolErr>;
    /// The volume as a [`Store`] of its own, so that the running slot's set can
    /// be read (the base of a delta update) while the stager writes the
    /// inactive one through `self`.
    type Reader: Store;
    /// A new reader of the volume.
    fn reader(&mut self) -> Self::Reader;
    /// The boot slots as the OTA endpoint reports them: the active one and the
    /// last confirmed one. `None` when they cannot be read (the installer's row
    /// grants no OTA endpoint), in which case an update has nowhere to go.
    fn boot_slots(&mut self) -> Option<(u8, u8)>;
    /// Create or replace the file at `path` with `data`.
    fn write_file(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr>;
    /// Append `data` to the file at `path`, creating it.
    fn append(&mut self, path: &[u8], data: &[u8]) -> Result<(), VolErr>;
    /// Does directory `dir` exist? The installer never creates one: its
    /// authority is a tree *inside* `/fat/PKG`, which cannot make `/fat/PKG`
    /// itself, so the volume is provisioned with it (the build's `mmd`).
    fn dir_exists(&mut self, dir: &[u8]) -> bool;
    /// The clock, in nanoseconds, for the journal.
    fn now_ns(&mut self) -> u64;
}

/// Why a package could not be fetched, which is `Remote::get`'s answer when
/// the package never arrived. The detail of a [`step::FETCH`] status is
/// [`FetchErr::code`] (named by [`crate::FETCH_REASONS`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FetchErr {
    /// The volume has no source rows ([`SOURCE`]).
    NoSource,
    /// The rows are not a source.
    Rows,
    /// The server could not be reached.
    Connect,
    /// The handshake was refused: the key is not pinned, the certificate is
    /// outside its validity, the clock was never set, or the TLS stream broke.
    Tls,
    /// The server answered with something other than the package.
    Status,
    /// The package is larger than the buffer (`PKG_MAX_KB`).
    TooLarge,
    /// The transfer broke or ended early.
    Io,
}

impl FetchErr {
    /// The detail of the status word: 1 for [`FetchErr::NoSource`] and so on,
    /// in the order of [`crate::FETCH_REASONS`]. `TooLarge` never reaches a
    /// status: it is the same refusal as a client's package that does not fit.
    pub const fn code(self) -> u64 {
        match self {
            Self::NoSource => 1,
            Self::Rows => 2,
            Self::Connect => 3,
            Self::Tls => 4,
            Self::Status => 5,
            Self::Io | Self::TooLarge => 6,
        }
    }
}

/// Where a package comes from when the installer goes to get it. The transport
/// is a program's (TLS needs the std port, `azos_tls::remote::HttpsRemote`);
/// the installer only decides what to do with the bytes, and what it decides
/// does not depend on how they came: a package is installed because its own
/// signature verifies against the device's signers, never because of the
/// connection it arrived over.
pub trait Remote {
    /// The package the source `rows` describe, into `buf`: how many bytes.
    /// `Err(TooLarge)` when it does not fit.
    fn get(&mut self, rows: &[u8], buf: &mut [u8]) -> Result<usize, FetchErr>;
    /// The file `name` beside the one the source `rows` describe (same server,
    /// same directory: the repository index, or the package an index names),
    /// into `buf`. `name` is a single path segment, never a path
    /// ([`sibling_name_ok`]); a name that is not one is `Err(Rows)`.
    fn get_sibling(&mut self, rows: &[u8], name: &str, buf: &mut [u8]) -> Result<usize, FetchErr>;
}

/// May `name` be asked of a source as a file beside the one its rows name
/// ([`Remote::get_sibling`])? One path segment, never `.` or `..`: every
/// [`Remote`] checks it, whatever the index said.
pub fn sibling_name_ok(name: &str) -> bool {
    azos_pkg::index::file_name_ok(name.as_bytes())
}

/// An offer of the index for an installed package: the entry's fields, owned.
#[derive(Clone, Copy)]
struct Offer {
    version: Version,
    sec_floor: Option<Version>,
    id: [u8; 32],
    file: [u8; 32],
    file_len: u8,
}

impl Offer {
    fn of(e: &Entry<'_>) -> Self {
        let mut file = [0u8; 32];
        file[..e.file.len()].copy_from_slice(e.file.as_bytes());
        Self { version: e.version, sec_floor: e.sec_floor, id: e.id, file, file_len: e.file.len() as u8 }
    }

    fn file(&self) -> &str {
        core::str::from_utf8(&self.file[..self.file_len as usize]).unwrap_or("")
    }

    fn entry<'a>(&'a self, name: &'a str) -> Entry<'a> {
        Entry { name, version: self.version, sec_floor: self.sec_floor, id: self.id, file: self.file() }
    }
}

/// One staged package in the report `refresh` makes.
#[derive(Clone, Copy)]
struct Row {
    name: [u8; 32],
    name_len: u8,
    version: [u8; 24],
    version_len: u8,
    signer: usize,
    id: [u8; 32],
    availability: Availability,
    floor: Floor,
    offer: Option<Offer>,
    /// `Some(why)` when an upgrade of it is refused before anything is fetched.
    blocked: Option<UpgradeWhy>,
}

impl Row {
    const EMPTY: Row = Row {
        name: [0; 32],
        name_len: 0,
        version: [0; 24],
        version_len: 0,
        signer: 0,
        id: [0; 32],
        availability: Availability::NotListed,
        floor: Floor::NoFloor,
        offer: None,
        blocked: None,
    };

    fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("")
    }

    fn version(&self) -> &str {
        core::str::from_utf8(&self.version[..self.version_len as usize]).unwrap_or("")
    }

    fn set_version(&mut self, v: Version) {
        use core::fmt::Write;
        struct Buf<'a>(&'a mut [u8], usize);
        impl Write for Buf<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.1 + s.len();
                self.0.get_mut(self.1..end).ok_or(core::fmt::Error)?.copy_from_slice(s.as_bytes());
                self.1 = end;
                Ok(())
            }
        }
        let mut w = Buf(&mut self.version, 0);
        // A version prints in at most 23 bytes.
        let _ = write!(w, "{v}");
        self.version_len = w.1 as u8;
    }

    fn installed(&self) -> Installed<'_> {
        Installed { name: self.name(), version: self.version(), signer_index: self.signer, id: self.id }
    }

    fn standing(&self) -> u64 {
        let a = match self.availability {
            Availability::NotListed => standing::NOT_LISTED,
            Availability::OtherSigner => standing::OTHER_SIGNER,
            Availability::Current => standing::CURRENT,
            Availability::Behind(_) => standing::BEHIND,
            Availability::Ahead(_) => standing::AHEAD,
            Availability::Unordered => standing::UNORDERED,
        };
        let (f, below) = match self.floor {
            Floor::NoFloor => (standing::NO_FLOOR, 0),
            Floor::Met(_) => (standing::FLOOR_MET, 0),
            Floor::Below(_) => (standing::FLOOR_BELOW, standing::BELOW),
            Floor::Unordered(_) => (standing::FLOOR_UNORDERED, standing::BELOW),
        };
        let has = |b: bool, bit: u64| if b { bit } else { 0 };
        a | f
            | below
            | has(Version::parse(self.version()).is_ok(), standing::HAS_INSTALLED)
            | has(self.offer.is_some(), standing::HAS_OFFERED)
            | has(self.offer.is_some_and(|o| o.sec_floor.is_some()), standing::HAS_FLOOR)
    }
}

/// Where every staged package stands against the index `refresh` last accepted.
struct Report {
    valid: bool,
    n: usize,
    rows: [Row; MAX_STAGED],
}

impl Report {
    const fn new() -> Self {
        Self { valid: false, n: 0, rows: [Row::EMPTY; MAX_STAGED] }
    }

    fn find(&self, name: &[u8]) -> Option<usize> {
        self.rows[..self.n].iter().position(|r| r.name[..r.name_len as usize] == *name)
    }
}

/// Where the bytes of a request are.
enum Input {
    /// In the client's memory object, to be copied out (`Volume::read_package`).
    Object(Cap<PkgMem>, usize),
    /// Already in the package buffer: the first `n` bytes.
    Loaded(usize),
}

/// Every buffer of the installer. Large, all zero: place it in a static.
pub struct Work {
    pkg: [u8; PKG_BUF],
    head: [u8; HEAD_BUF],
    caps: [u8; CAPS_BUF],
    sig: [u8; azos_topology::SIDECAR_MAX],
    sched: [u8; SCHED_BUF],
    arena: [u8; MAX_STAGED * META_MAX],
    kept: [u8; azos_pkg::index::FILE_MAX],
    supersede: [u8; SUPERSEDE_BUF],
    upd: update::Work,
    io: [u8; UPDATE_IO],
    /// The running slot's manifest, for the base of a delta update.
    base_mb: [u8; update::MANIFEST_MAX],
    base_msg: [u8; update::MSG_MAX],
    report: Report,
}

struct Parts<'r> {
    pkg: &'r mut [u8],
    head: &'r mut [u8],
    caps: &'r mut [u8],
    sig: &'r mut [u8],
    sched: &'r mut [u8],
    arena: &'r mut [u8],
    kept: &'r mut [u8],
    supersede: &'r mut [u8],
    topo: &'r mut Topology<'r>,
    report: &'r mut Report,
}

impl Work {
    /// Empty buffers.
    pub const fn new() -> Self {
        Self {
            pkg: [0; PKG_BUF],
            head: [0; HEAD_BUF],
            caps: [0; CAPS_BUF],
            sig: [0; azos_topology::SIDECAR_MAX],
            sched: [0; SCHED_BUF],
            arena: [0; MAX_STAGED * META_MAX],
            kept: [0; azos_pkg::index::FILE_MAX],
            supersede: [0; SUPERSEDE_BUF],
            upd: update::Work::new(),
            io: [0; UPDATE_IO],
            base_mb: [0; update::MANIFEST_MAX],
            base_msg: [0; update::MSG_MAX],
            report: Report::new(),
        }
    }
}

/// The buffers, and the topology emptied: it is about to borrow from them.
fn parts<'r>(w: &'r mut Work, topo: &'r mut Topology<'static>) -> Parts<'r> {
    topo.clear();
    // SAFETY: `topo` holds `MaybeStr`s that point into `caps`, `sched` and
    // `arena`, and nothing else; the service is the only path to either, its
    // `&mut` keeps them from being reached twice, and the topology was emptied
    // above before any buffer is handed out to be overwritten. The lifetime it
    // is handed out with is the request's, so safe code cannot keep a
    // reference into it past the next `parts()`.
    let topo = unsafe { core::mem::transmute::<&mut Topology<'static>, &mut Topology<'_>>(topo) };
    Parts {
        pkg: &mut w.pkg,
        head: &mut w.head,
        caps: &mut w.caps,
        sig: &mut w.sig,
        sched: &mut w.sched,
        arena: &mut w.arena,
        kept: &mut w.kept,
        supersede: &mut w.supersede,
        topo,
        report: &mut w.report,
    }
}

impl Default for Work {
    fn default() -> Self {
        Self::new()
    }
}

/// The installer: a volume, the source it fetches from, its buffers, the
/// topology key and the device.
pub struct Service<'w, V: Volume, R: Remote> {
    /// The volume.
    pub vol: V,
    /// Where `fetch` gets a package from.
    pub remote: R,
    work: &'w mut Work,
    topo: &'w mut Topology<'static>,
    key: [u8; KEY_LEN],
    dev: Device<'w>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Admit,
    Install,
}

impl<'w, V: Volume, R: Remote> Service<'w, V, R> {
    /// An installer over `vol`, fetching from `remote`, with its buffers and
    /// its topology. `key` is the topology key the signed CAPS.TOM
    /// is verified with (`azos_topology::TRUSTED_PUBKEY` in `pkgd`), `dev`
    /// what packages are admitted against.
    pub fn new(vol: V, remote: R, work: &'w mut Work, topo: &'w mut Topology<'static>, key: [u8; KEY_LEN], dev: Device<'w>) -> Self {
        Self { vol, remote, work, topo, key, dev }
    }

    fn request(&mut self, cap: Cap<PkgMem>, len: u32, mode: Mode) -> [u64; 4] {
        let now = self.vol.now_ns();
        let Self { vol, work, topo, key, dev, .. } = self;
        install_or_admit(vol, parts(work, topo), key, dev, Input::Object(cap, len as usize), mode, now, None)
    }
}

impl<V: Volume, R: Remote> Packages for Service<'_, V, R> {
    fn admit(&mut self, pkg: Cap<PkgMem>, len: u32) -> [u64; 4] {
        self.request(pkg, len, Mode::Admit)
    }

    fn install(&mut self, pkg: Cap<PkgMem>, len: u32) -> [u64; 4] {
        self.request(pkg, len, Mode::Install)
    }

    fn remove(&mut self, id: [u64; 4]) -> [u64; 4] {
        let now = self.vol.now_ns();
        let want = words_id(&id);
        let head = &mut self.work.head[..];
        let mut i = 0;
        while let Some((path, pk)) = staged_at(&mut self.vol, head, &mut i) {
            if pk.id() != want {
                continue;
            }
            if self.vol.remove(&path.bytes()).is_err() {
                return [status(step::IO, io::REMOVE), receipt::id_prefix(&want), 0, 0];
            }
            let rows = azos_pkg::Meta::parse(pk.meta).map_or(0, |m| m.images().len() as u32);
            let mut rec = ProvenanceRecord::new(Rule::PackageInstall as u8, Verdict::Deny as u8, rows, [rows as u64, 0, 0]);
            rec.image_hash_prefix = receipt::id_prefix(&want);
            rec.clock_ns = now;
            // A removal that cannot be recorded is still a removal; say so.
            if self.vol.append(JOURNAL, &rec.to_bytes()).is_err() {
                return [status(step::IO, io::JOURNAL), receipt::id_prefix(&want), rows as u64, 0];
            }
            return [0, receipt::id_prefix(&want), rows as u64, 0];
        }
        [status(step::NOT_STAGED, 0), receipt::id_prefix(&want), 0, 0]
    }

    /// Fetch the package from the source the rows in [`SOURCE`] describe and
    /// install it, exactly as `install` does a package a client handed over:
    /// the same verification, admission, staging and journal. A fetch that
    /// fails is a [`step::FETCH`] status and records nothing; one that
    /// delivers a package the device refuses is that refusal, journalled.
    fn fetch(&mut self) -> [u64; 4] {
        let now = self.vol.now_ns();
        let failed = |e: FetchErr| [status(step::FETCH, e.code()), 0, 0, 0];
        let Self { vol, remote, work, topo, key, dev } = self;
        // The rows go in the staging scan's buffer, which nothing uses before
        // the install begins.
        let rows = match vol.read_file(SOURCE, &mut work.head) {
            Ok(Read { n, more: false }) => &work.head[..n],
            Ok(_) => return failed(FetchErr::Rows),
            Err(VolErr::Missing) => return failed(FetchErr::NoSource),
            Err(_) => return failed(FetchErr::Io),
        };
        let n = match remote.get(rows, &mut work.pkg) {
            Ok(n) if n <= PKG_BUF => n,
            Ok(_) => return failed(FetchErr::Io),
            Err(FetchErr::TooLarge) => return refuse(vol, Mode::Install, &[0u8; 32], 0, Refusal::Container(ParseError::Length), now),
            Err(e) => return failed(e),
        };
        install_or_admit(vol, parts(work, topo), key, dev, Input::Loaded(n), Mode::Install, now, None)
    }

    fn refresh(&mut self) -> [u64; 4] {
        let now = self.vol.now_ns();
        let failed = |e: FetchErr| [status(step::FETCH, e.code()), 0, 0, 0];
        let Self { vol, remote, work, topo, key, .. } = self;
        work.report.valid = false;
        let rows = match vol.read_file(SOURCE, &mut work.head) {
            Ok(Read { n, more: false }) => &work.head[..n],
            Ok(_) => return failed(FetchErr::Rows),
            Err(VolErr::Missing) => return failed(FetchErr::NoSource),
            Err(_) => return failed(FetchErr::Io),
        };
        let n = match remote.get_sibling(rows, INDEX_FILE, &mut work.pkg) {
            Ok(n) if n <= PKG_BUF => n,
            Ok(_) => return failed(FetchErr::Io),
            Err(FetchErr::TooLarge) => return refuse_index(vol, IndexWhy::Length, 0, now),
            Err(e) => return failed(e),
        };
        refresh_index(vol, parts(work, topo), key, n, now)
    }

    fn outdated(&mut self, index: u32, part: u32) -> [u64; 4] {
        let r = &self.work.report;
        if !r.valid {
            return [status(step::NO_REPORT, 0), 0, 0, 0];
        }
        let Some(row) = r.rows[..r.n].get(index as usize) else { return [0; 4] };
        let v = |x: Option<Version>| x.map_or(0, Version::packed);
        match part {
            0 => crate::name_words(row.name().as_bytes()).unwrap_or([0; 4]),
            1 => [
                status(step::ROW, row.standing()),
                Version::parse(row.version()).ok().map_or(0, Version::packed),
                v(row.offer.map(|o| o.version)),
                v(row.offer.and_then(|o| o.sec_floor)),
            ],
            _ => [status(step::BAD_ARG, 1), 0, 0, 0],
        }
    }

    fn upgrade(&mut self, name: [u64; 4]) -> [u64; 4] {
        let now = self.vol.now_ns();
        let failed = |e: FetchErr| [status(step::FETCH, e.code()), 0, 0, 0];
        let Self { vol, remote, work, topo, key, dev } = self;
        if !work.report.valid {
            return [status(step::NO_REPORT, 0), 0, 0, 0];
        }
        let (nb, nl) = words_name(&name);
        let Some(at) = work.report.find(&nb[..nl]) else {
            return refuse(vol, Mode::Install, &[0u8; 32], 0, Refusal::Upgrade(UpgradeWhy::NotInstalled), now);
        };
        let row = work.report.rows[at];
        if let Some(why) = row.blocked {
            return refuse(vol, Mode::Install, &row.id, row.signer as u64 + 1, Refusal::Upgrade(why), now);
        }
        let Some(offer) = row.offer else {
            return refuse(vol, Mode::Install, &row.id, row.signer as u64 + 1, Refusal::Upgrade(UpgradeWhy::NotListed), now);
        };
        let rows = match vol.read_file(SOURCE, &mut work.head) {
            Ok(Read { n, more: false }) => &work.head[..n],
            Ok(_) => return failed(FetchErr::Rows),
            Err(VolErr::Missing) => return failed(FetchErr::NoSource),
            Err(_) => return failed(FetchErr::Io),
        };
        let n = match remote.get_sibling(rows, offer.file(), &mut work.pkg) {
            Ok(n) if n <= PKG_BUF => n,
            Ok(_) => return failed(FetchErr::Io),
            Err(FetchErr::TooLarge) => {
                return refuse(vol, Mode::Install, &offer.id, row.signer as u64 + 1, Refusal::Container(ParseError::Length), now)
            }
            Err(e) => return failed(e),
        };
        let replace = Replace { id: row.id, installed: row.installed(), entry: offer.entry(row.name()) };
        let reply = install_or_admit(vol, parts(work, topo), key, dev, Input::Loaded(n), Mode::Install, now, Some(&replace));
        if reply[0] == 0 {
            let r = &mut work.report.rows[at];
            r.set_version(offer.version);
            r.id = offer.id;
            r.availability = Availability::Current;
            r.floor = offer.sec_floor.map_or(Floor::NoFloor, Floor::Met);
            r.blocked = Some(UpgradeWhy::Pending);
        }
        reply
    }

    fn update(&mut self, bundle: Cap<PkgMem>, len: u32) -> [u64; 4] {
        let now = self.vol.now_ns();
        let Self { vol, work, key, .. } = self;
        let src = match vol.open_bundle(bundle, len as usize) {
            Ok(s) => s,
            Err(_) => return [status(step::IO, io::READ_PACKAGE), 0, 0, 0],
        };
        let Work { upd, io, base_mb, base_msg, .. } = &mut **work;
        stage_update(vol, StageBufs { upd, io, base_mb, base_msg }, key, src, now)
    }

    /// `update` for a bundle fetched from the source the rows in [`SOURCE`]
    /// describe: the bytes land in the package buffer and are staged from there.
    fn fetch_update(&mut self) -> [u64; 4] {
        let now = self.vol.now_ns();
        let failed = |e: FetchErr| [status(step::FETCH, e.code()), 0, 0, 0];
        let Self { vol, remote, work, key, .. } = self;
        let Work { pkg, head, upd, io, base_mb, base_msg, .. } = &mut **work;
        let rows = match vol.read_file(SOURCE, &mut head[..]) {
            Ok(Read { n, more: false }) => &head[..n],
            Ok(_) => return failed(FetchErr::Rows),
            Err(VolErr::Missing) => return failed(FetchErr::NoSource),
            Err(_) => return failed(FetchErr::Io),
        };
        let n = match remote.get(rows, &mut pkg[..]) {
            Ok(n) if n <= PKG_BUF => n,
            Ok(_) => return failed(FetchErr::Io),
            Err(FetchErr::TooLarge) => {
                // A bundle that does not fit is a bundle shorter than it says.
                let code = update::Refusal::Length.code();
                let _ = vol.append(JOURNAL, &update_refused(0, code, now).to_bytes());
                return [code, 0, 0, 0];
            }
            Err(e) => return failed(e),
        };
        stage_update(vol, StageBufs { upd, io, base_mb, base_msg }, key, Loaded(&pkg[..n]), now)
    }

    fn installed(&mut self, index: u32) -> [u64; 4] {
        let head = &mut self.work.head[..];
        let (mut i, mut n) = (0, 0u32);
        while let Some((_, pk)) = staged_at(&mut self.vol, head, &mut i) {
            if n == index {
                return id_words(&pk.id());
            }
            n += 1;
        }
        [0; 4]
    }
}

/// `/fat/PKG/XXXXXXXX.PKG`: the staged file of a package. The 8.3 name holds
/// four bytes of the package id in upper-case hex, so two packages can share
/// one: [`StagePath::of_id`] takes `try_` windows of the id in turn (bytes
/// `4*try_..4*try_+4`) and the installer stages at the first one that is free
/// or already this package's, never over another package's file.
#[derive(Clone, Copy)]
struct StagePath {
    b: [u8; 21],
}

/// Names one id can have (the 32 bytes of an id, four to a name).
const STAGE_NAMES: usize = 8;

impl StagePath {
    fn of_id(id: &[u8; 32], try_: usize) -> Self {
        let mut b = *b"/fat/PKG/00000000.PKG";
        for (i, byte) in id[4 * try_..4 * try_ + 4].iter().enumerate() {
            b[9 + 2 * i] = b"0123456789ABCDEF"[(byte >> 4) as usize];
            b[10 + 2 * i] = b"0123456789ABCDEF"[(byte & 15) as usize];
        }
        Self { b }
    }

    fn of_name(name: &[u8]) -> Self {
        let mut b = *b"/fat/PKG/00000000.PKG";
        b[9..].copy_from_slice(name);
        Self { b }
    }

    fn bytes(&self) -> [u8; 21] {
        self.b
    }
}

/// Where `id` is staged: the first of its names that holds no package or
/// holds this one. A file there that is not a package parses to nothing and is
/// free (the installer owns the directory and nothing reads it). `Err(true)`
/// when `id` is staged at that name already, `Err(false)` when every name is
/// another package's.
fn stage_path<V: Volume>(vol: &mut V, head: &mut [u8], id: &[u8; 32]) -> Result<StagePath, bool> {
    for t in 0..STAGE_NAMES {
        let path = StagePath::of_id(id, t);
        match vol.read_file(&path.bytes(), head) {
            Err(VolErr::Missing) => return Ok(path),
            // A name that cannot be read is not known to be free.
            Err(_) => {}
            Ok(r) => match Package::parse_head(&head[..r.n]) {
                Err(_) => return Ok(path),
                Ok(p) if p.id() == *id => return Err(true),
                Ok(_) => {}
            },
        }
    }
    Err(false)
}

/// Is a directory entry the name a staged package has?
fn staged_name(n: &[u8]) -> bool {
    n.len() == 12 && n[8..] == *b".PKG" && n[..8].iter().all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c))
}

/// The next staged package at or after directory index `*i`: its path and its
/// head (read into `head`, parsed, NOT verified: the caller decides what that
/// is worth). `*i` is left after the entry.
fn staged_at<'h, V: Volume>(vol: &mut V, head: &'h mut [u8], i: &mut usize) -> Option<(StagePath, Package<'h>)> {
    let mut name = [0u8; 64];
    // The borrow of `head` that the returned package keeps is made once, at
    // the end, from the bytes the successful read left there.
    let (path, n) = loop {
        if *i >= SCAN_MAX {
            return None;
        }
        let len = vol.entry(STAGE_DIR, *i, &mut name)?;
        *i += 1;
        if !staged_name(&name[..len]) {
            continue;
        }
        let path = StagePath::of_name(&name[..len]);
        let Ok(r) = vol.read_file(&path.bytes(), head) else { continue };
        if Package::parse_head(&head[..r.n]).is_ok() {
            break (path, r.n);
        }
    };
    let pk = Package::parse_head(&head[..n]).ok()?;
    Some((path, pk))
}

fn pkg_status(r: &Refusal) -> u64 {
    r.code()
}

/// The reply of a refused package, journalled when it was an install.
fn refuse<V: Volume>(vol: &mut V, mode: Mode, id: &[u8; 32], signer: u64, r: Refusal, now: u64) -> [u64; 4] {
    if mode == Mode::Install {
        let rec = receipt::refused(id, signer, &r, now);
        // The refusal is the answer whether or not it could be written down.
        let _ = vol.append(JOURNAL, &rec.to_bytes());
    }
    [pkg_status(&r), receipt::id_prefix(id), 0, signer]
}

/// The reply of an index refused, journalled.
fn refuse_index<V: Volume>(vol: &mut V, why: IndexWhy, signer: u64, now: u64) -> [u64; 4] {
    refuse(vol, Mode::Install, &[0u8; 32], signer, Refusal::Index(why), now)
}

/// The device's signed topology, read off the volume and verified like the
/// kernel does at boot. `Err` is the reply that says it could not be.
fn load_topology<'r, V: Volume>(
    vol: &mut V,
    caps_buf: &'r mut [u8],
    sig_buf: &'r mut [u8],
    sched_buf: &'r mut [u8],
    topo: &mut Topology<'r>,
    key: &[u8; KEY_LEN],
) -> Result<(), [u64; 4]> {
    let no_topology = |detail: u64| [status(step::NO_TOPOLOGY, detail), 0, 0, 0];
    let Ok(Read { n: nc, more: false }) = vol.read_file(CAPS_TOML_PATH, caps_buf) else { return Err(no_topology(0)) };
    let Ok(Read { n: ns, more: false }) = vol.read_file(CAPS_SIG_PATH, sig_buf) else { return Err(no_topology(0)) };
    let Ok(Read { n: nh, more: false }) = vol.read_file(SCHED_TOML_PATH, sched_buf) else { return Err(no_topology(0)) };
    let (caps, _) = caps_buf.split_at_mut(nc);
    let (sched, _) = sched_buf.split_at_mut(nh);
    let files = SignedFiles { caps, caps_sig: &sig_buf[..ns], sched };
    // The device id and the counter floor are the device record's, which a ring-3
    // program cannot read: neither is checked here (see the module docs).
    let ctx = DeviceContext { device_id: None, floor: 0, bind_device: false, enforce_floor: false };
    fill_signed(topo, &files, key, &ctx).map(|_| ()).map_err(|r| no_topology(r.code() as u64 >> 28))
}

/// Verify the index in the first `n` bytes of the package buffer, keep it on
/// the volume and work out where every staged package stands against it.
fn refresh_index<V: Volume>(vol: &mut V, p: Parts<'_>, key: &[u8; KEY_LEN], n: usize, now: u64) -> [u64; 4] {
    let Parts { pkg, head, caps, sig, sched, kept, supersede, topo, report, .. } = p;
    if let Err(r) = load_topology(vol, caps, sig, sched, topo, key) {
        return r;
    }
    let bytes = &pkg[..n];
    let ix = match azos_pkg::index::verify(bytes, topo) {
        Ok(ix) => ix,
        Err(why) => return refuse_index(vol, why, 0, now),
    };
    let signer = ix.signer_index as u64 + 1;

    // The slot of this signer: the index it published before, if it still
    // verifies. Its serial never goes backwards and its body never changes at
    // the same serial; it is also what a failed write puts back. Another
    // signer's slot is not touched.
    let slot = slot_path(&ix.key_id());
    let stored_len = match vol.read_file(&slot, kept) {
        Ok(Read { n, more: false }) => Some(n),
        Err(VolErr::Missing) => None,
        // A slot that is there and cannot be read whole cannot be put back.
        _ => return [status(step::IO, io::INDEX_SLOT), 0, 0, 0],
    };
    let stored = stored_len.and_then(|n| azos_pkg::index::verify(&kept[..n], topo).ok());
    if stored.is_some_and(|s| s.key_id() != ix.key_id()) {
        return refuse_index(vol, IndexWhy::SlotTaken, signer, now);
    }
    if let Err(why) = ix.check_against(stored.map(|s| s.mark())) {
        return refuse_index(vol, why, signer, now);
    }

    // An old version whose upgrade is on trial is not a package of the device
    // for now; the new one is not upgraded again until the trial is confirmed.
    let sup_len = match read_supersede(vol, supersede) {
        Ok(n) => n,
        Err(()) => return [status(step::IO, io::SUPERSEDE), 0, 0, 0],
    };
    report.n = 0;
    let mut i = 0;
    while report.n < MAX_STAGED {
        let Some((_, pk)) = staged_at(vol, head, &mut i) else { break };
        if supersede_iter(&supersede[..sup_len]).any(|(old, _)| old == pk.id()) {
            continue;
        }
        let Ok(v) = verify_head(pk, topo) else { continue };
        let a = assess(&Installed { name: v.meta.name, version: v.meta.version, signer_index: v.signer_index, id: v.id }, &ix);
        let mut row = Row::EMPTY;
        row.name[..v.meta.name.len()].copy_from_slice(v.meta.name.as_bytes());
        row.name_len = v.meta.name.len() as u8;
        row.version[..v.meta.version.len()].copy_from_slice(v.meta.version.as_bytes());
        row.version_len = v.meta.version.len() as u8;
        row.signer = v.signer_index;
        row.id = v.id;
        row.availability = a.availability;
        row.floor = a.floor;
        row.offer = a.entry.as_ref().map(Offer::of);
        row.blocked = if supersede_iter(&supersede[..sup_len]).any(|(_, new)| new == v.id) {
            Some(UpgradeWhy::Pending)
        } else {
            upgrade_entry(&a).err()
        };
        report.rows[report.n] = row;
        report.n += 1;
    }

    if !vol.dir_exists(STAGE_DIR) {
        return [status(step::IO, io::NO_STAGE_DIR), 0, 0, 0];
    }
    // The old index goes back if the new one cannot be written down.
    let undo = |vol: &mut V| match stored_len {
        Some(n) => {
            let _ = vol.write_file(&slot, &kept[..n]);
        }
        None => {
            let _ = vol.remove(&slot);
        }
    };
    if vol.write_file(&slot, bytes).is_err() {
        undo(vol);
        return [status(step::IO, io::WRITE_PACKAGE), 0, 0, 0];
    }
    if vol.append(JOURNAL, &receipt::index_accepted(&ix, now).to_bytes()).is_err() {
        undo(vol);
        return [status(step::IO, io::JOURNAL), 0, 0, 0];
    }
    report.valid = true;
    [0, ix.serial as u64, report.n as u64, ix.entries as u64]
}

/// The supersede file into `buf`: how many bytes (0 when there is none).
fn read_supersede<V: Volume>(vol: &mut V, buf: &mut [u8]) -> Result<usize, ()> {
    match vol.read_file(SUPERSEDE_PATH, buf) {
        Ok(Read { n, more: false }) => Ok(n - n % SUPERSEDE_REC),
        Err(VolErr::Missing) => Ok(0),
        _ => Err(()),
    }
}

/// What an upgrade replaces: the staged package, as the report knew it, and
/// the index's entry for the version that replaces it.
struct Replace<'a> {
    id: [u8; 32],
    installed: Installed<'a>,
    entry: Entry<'a>,
}

#[allow(clippy::too_many_arguments)]
fn install_or_admit<'r, V: Volume>(
    vol: &mut V,
    p: Parts<'r>,
    key: &[u8; KEY_LEN],
    dev: &Device<'_>,
    input: Input,
    mode: Mode,
    now: u64,
    replace: Option<&Replace<'_>>,
) -> [u64; 4] {
    let Parts { pkg: pkg_buf, head, caps: caps_buf, sig: sig_buf, sched: sched_buf, arena, supersede, topo, .. } = p;
    let none = [0u8; 32];

    // 1. The package, whole, copied out of the client's object. One larger
    // than the buffer is not read.
    let n = match input {
        Input::Loaded(n) => n,
        Input::Object(cap, len) => match vol.read_package(cap, len, pkg_buf) {
            Ok(n) => n,
            Err(VolErr::TooLarge) => return refuse(vol, mode, &none, 0, Refusal::Container(ParseError::Length), now),
            Err(_) => return [status(step::IO, io::READ_PACKAGE), 0, 0, 0],
        },
    };
    let (pkg_bytes, _) = pkg_buf.split_at_mut(n);
    let pkg_bytes: &'r [u8] = pkg_bytes;
    let id = Package::parse(pkg_bytes).map_or(none, |p| p.id());

    // 2. The device's signed topology, verified like the kernel does.
    if let Err(r) = load_topology(vol, caps_buf, sig_buf, sched_buf, topo, key) {
        return r;
    }

    // 3. What is staged already, merged in first: a package is admitted against
    // the device as it will be, not as it is.
    let sup_len = match read_supersede(vol, supersede) {
        Ok(n) => n,
        Err(()) => return [status(step::IO, io::SUPERSEDE), 0, 0, 0],
    };
    let mut ids = [[0u8; 32]; MAX_STAGED];
    let mut staged = 0usize;
    let mut arena: &'r mut [u8] = arena;
    let mut i = 0;
    let mut old_path: Option<StagePath> = None;
    while let Some((path, pk)) = staged_at(vol, head, &mut i) {
        if staged == MAX_STAGED {
            break;
        }
        // The package an upgrade replaces is no part of the device it is judged
        // against: its rows would collide with its successor's, and its slot is
        // the successor's.
        if replace.is_some_and(|r| r.id == pk.id()) {
            old_path = Some(path);
            continue;
        }
        // A staged package that no longer verifies (its signer was dropped)
        // takes its slot but adds no rows.
        ids[staged] = pk.id();
        staged += 1;
        // An old version whose upgrade is on trial is left out of the device,
        // as the boot leaves it out.
        if supersede_iter(&supersede[..sup_len]).any(|(old, _)| old == pk.id()) {
            continue;
        }
        let Ok(v) = verify_head(pk, topo) else { continue };
        let (slot, rest) = core::mem::take(&mut arena).split_at_mut(META_MAX);
        arena = rest;
        let (rows, _) = slot.split_at_mut(pk.rows.len());
        rows.copy_from_slice(pk.rows);
        let rows: &'r [u8] = rows;
        let _ = admit(&v, rows, topo, dev);
    }
    let full = staged == MAX_STAGED;
    if ids[..staged].contains(&id) {
        return [status(step::ALREADY_STAGED, 0), receipt::id_prefix(&id), 0, 0];
    }
    if mode == Mode::Install && full {
        return [status(step::NO_ROOM, 0), receipt::id_prefix(&id), 0, 0];
    }

    // 4. The candidate. A refusal names the signer when the key was one.
    let signer_of_key = Package::parse(pkg_bytes)
        .ok()
        .and_then(|p| topo.signers().iter().position(|s| s.key_id == p.key_id()))
        .map_or(0, |i| i as u64 + 1);
    let v = match verify(pkg_bytes, topo) {
        Ok(v) => v,
        Err(r) => return refuse(vol, mode, &id, signer_of_key, r, now),
    };
    let signer = v.signer_index as u64 + 1;
    if let Some(r) = replace {
        let why = if old_path.is_none() {
            Some(UpgradeWhy::NotInstalled)
        } else {
            check_upgrade(&r.installed, &r.entry, &v.meta, &v.id, v.signer_index).err()
        };
        if let Some(why) = why {
            return refuse(vol, mode, &id, signer, Refusal::Upgrade(why), now);
        }
    }
    let a = match admit(&v, v.pkg.rows, topo, dev) {
        Ok(a) => a,
        Err(r) => return refuse(vol, mode, &id, signer, r, now),
    };
    if mode == Mode::Admit {
        return [0, receipt::id_prefix(&id), a.rows as u64, a.first_row as u64];
    }

    // 5. Stage it, and write the decision down. An install the journal cannot
    // record is undone.
    if !vol.dir_exists(STAGE_DIR) {
        return [status(step::IO, io::NO_STAGE_DIR), receipt::id_prefix(&id), 0, 0];
    }
    let path = match stage_path(vol, head, &id) {
        Ok(p) => p,
        Err(true) => return [status(step::ALREADY_STAGED, 0), receipt::id_prefix(&id), 0, 0],
        Err(false) => return [status(step::NO_ROOM, 0), receipt::id_prefix(&id), 0, 0],
    };
    if vol.write_file(&path.bytes(), pkg_bytes).is_err() {
        let _ = vol.remove(&path.bytes());
        return [status(step::IO, io::WRITE_PACKAGE), receipt::id_prefix(&id), 0, 0];
    }
    // An upgrade stays beside the version it replaces until the new one is
    // confirmed: the pair goes in the same transaction as the new file and its
    // journal record, and the boot-time apply leaves the old version out while
    // the new one is on trial, removes it on confirmation, and applies it again
    // when the trial is rolled back.
    if let (Some(r), Some(_)) = (replace, old_path) {
        let Some(len) = supersede_push(supersede, sup_len, &r.id, &id) else {
            let _ = vol.remove(&path.bytes());
            return [status(step::NO_ROOM, 0), receipt::id_prefix(&id), 0, 0];
        };
        if vol.write_file(SUPERSEDE_PATH, &supersede[..len]).is_err() {
            let _ = vol.remove(&path.bytes());
            return [status(step::IO, io::SUPERSEDE), receipt::id_prefix(&id), 0, 0];
        }
    }
    if vol.append(JOURNAL, &receipt::admitted(&v, &a, now).to_bytes()).is_err() {
        // The pair, if one was written, names a package that is not there: the
        // boot drops it.
        let _ = vol.remove(&path.bytes());
        return [status(step::IO, io::JOURNAL), receipt::id_prefix(&id), 0, 0];
    }
    if cfg!(feature = "pkg-supersede-canary") {
        // What the installer did before the pair existed: the old version goes now.
        if let Some(old) = old_path {
            let _ = vol.remove(&old.bytes());
        }
    }
    [0, receipt::id_prefix(&id), a.rows as u64, a.first_row as u64]
}

// ── The whole-system update ─────────────────────────────────────────────────

/// The decision record of an update staged. It is a `PackageInstall` record
/// (`azos_decision::Rule`) whose numbers read: the parts of the set, no signer
/// (an update is signed by the device's own trust anchor, not by a package
/// author), and the manifest's epoch in the bits above the slot it was staged
/// into plus one. `image_hash_prefix` is the manifest's id. A package install
/// has a signer and a zero third number, so the two are told apart by them.
fn update_admitted(v: &update::Verified, now: u64) -> ProvenanceRecord {
    let mut p = ProvenanceRecord::new(
        Rule::PackageInstall as u8,
        Verdict::Admit as u8,
        u32::from(v.parts),
        [u64::from(v.parts), 0, u64::from(v.sec_epoch) << 8 | (u64::from(v.slot) + 1)],
    );
    p.image_hash_prefix = v.id;
    p.clock_ns = now;
    p
}

/// The record of an update refused: the third number is the refusal's status
/// (`update::Refusal::code`, or the delta's), whose steps (38 and 48..) no
/// package refusal uses.
fn update_refused(id: u64, code: u64, now: u64) -> ProvenanceRecord {
    let mut p = ProvenanceRecord::new(Rule::PackageInstall as u8, Verdict::Refuse as u8, 0, [0, 0, code]);
    p.image_hash_prefix = id;
    p.clock_ns = now;
    p
}

/// A bundle already in memory: the package buffer after a fetch.
struct Loaded<'a>(&'a [u8]);

impl Source for Loaded<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read(&mut self, off: u64, buf: &mut [u8]) -> Result<usize, update::IoErr> {
        let off = usize::try_from(off).map_err(|_| update::IoErr::Io)?;
        let from = self.0.get(off..).ok_or(update::IoErr::Io)?;
        let n = from.len().min(buf.len());
        buf[..n].copy_from_slice(&from[..n]);
        Ok(n)
    }
}

/// The buffers staging an update works in: the manifest and its parts, the
/// copy buffer, and the running slot's manifest for the base of a delta.
struct StageBufs<'w> {
    upd: &'w mut update::Work,
    io: &'w mut [u8; UPDATE_IO],
    base_mb: &'w mut [u8; update::MANIFEST_MAX],
    base_msg: &'w mut [u8; update::MSG_MAX],
}

/// An update that was not staged: its status word, and whether the stager had
/// verified a manifest by then (the id it names is only the refused one's if so).
struct Refused {
    code: u64,
    manifest_seen: bool,
}

/// The start of a bundle is a delta's magic: the bundle is a patch against the
/// running slot's set, not a whole update (whose first word is the manifest's).
fn is_delta<R: Source>(src: &mut R) -> bool {
    let mut m = [0u8; 4];
    src.len() >= 4 && matches!(src.read(0, &mut m), Ok(4)) && m == DELTA_MAGIC
}

/// Stage the update `patch` makes against the set the running slot was staged
/// from. The patch is checked against that base before the inactive slot is
/// written; the bundle it makes goes through the stager like one that came
/// whole, so the signed manifest and every part's hash decide, not the patch.
fn stage_delta<V: Volume, S: Source>(
    vol: &mut V,
    patch: S,
    active: u8,
    key: &[u8; KEY_LEN],
    dev: &update::Device,
    w: StageBufs<'_>,
) -> Result<update::Verified, Refused> {
    let StageBufs { upd, io: buf, base_mb, base_msg } = w;
    let refused = |code| Refused { code, manifest_seen: false };
    let base = SetBase::open(vol.reader(), active, key, base_mb, base_msg).map_err(|r| refused(r.code()))?;
    // The largest result is what a request's length word can name; the stager
    // checks the kernel's size against the device and the parts against the
    // signed manifest.
    let mut src = DeltaSource::open(base, patch, u32::MAX, buf).map_err(|e| refused(status(step::DELTA, e.code())))?;
    update::stage(vol, &mut src, dev, key, upd, buf).map_err(|r| Refused { code: r.code(), manifest_seen: true })
}

/// Stage the update in `src` (a whole one, or a delta against the running
/// slot's set) into the inactive slot and write the decision down. The decision
/// that cannot be written undoes the stage.
fn stage_update<V: Volume, S: Source>(
    vol: &mut V,
    work: StageBufs<'_>,
    key: &[u8; KEY_LEN],
    mut src: S,
    now: u64,
) -> [u64; 4] {
    let Some((active, last_good)) = vol.boot_slots() else { return [status(step::NO_BOOT_RECORD, 0), 0, 0, 0] };

    // What this side knows of the boot record is the slots. The floors, the
    // platform and whether a switch is on trial beyond what the slots say are
    // the kernel's to hold: the switch checks them against the record itself.
    let mut meta = BootMeta::default();
    meta.active_slot = active;
    meta.last_good = last_good;
    let dev = update::Device {
        platform: None,
        meta,
        max_kernel_size: azos_limits::OTA_MAX_IMAGE_SIZE_BYTES.min(u32::MAX as usize) as u32,
    };

    let staged = if is_delta(&mut src) {
        stage_delta(vol, src, active, key, &dev, StageBufs { upd: &mut *work.upd, io: &mut *work.io, base_mb: &mut *work.base_mb, base_msg: &mut *work.base_msg })
    } else {
        update::stage(vol, &mut src, &dev, key, &mut *work.upd, &mut *work.io).map_err(|r| Refused { code: r.code(), manifest_seen: true })
    };
    match staged {
        Ok(v) => {
            if vol.append(JOURNAL, &update_admitted(&v, now).to_bytes()).is_err() {
                // An update that cannot be recorded is withdrawn.
                let _ = update::unstage(vol, v.slot);
                return [status(step::IO, io::JOURNAL), v.id, 0, 0];
            }
            [0, v.id, u64::from(v.sec_epoch), u64::from(v.slot)]
        }
        Err(r) => {
            let id = if r.manifest_seen { work.upd.last_id() } else { 0 };
            // The refusal is the answer whether or not it could be written down.
            let _ = vol.append(JOURNAL, &update_refused(id, r.code, now).to_bytes());
            [r.code, id, 0, 0]
        }
    }
}
