// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Packages` object: installing a signed application package as a request
//! to a service, not as a command that writes where it likes.
//!
//! `userspace/services/pkgd` serves it on `endpoint.packages`. A client holds
//! the call right on that endpoint (its topology row says so) and hands the
//! package as a **memory object** ([`Cap<PkgMem>`]) with the number of bytes it
//! holds: the installer reads what it is given and nothing else of the client's.
//! A path is not authority, and the interface has none; a file capability would
//! not do either, because a `Cap<File>` names a descriptor of the task that
//! opened it, not of whoever it is moved to.
//!
//! The installer copies the bytes out of the object before it looks at them: the
//! client keeps its mapping, and what is verified must be what is staged.
//!
//! * [`Packages::admit`]: would the device take this package now? It verifies
//!   the package against the signers of the signed topology, merges its rows
//!   into the topology AND the packages already staged, and judges the result
//!   with the same admission a signed CAPS.TOM gets (`azos_pkg`). Nothing is
//!   changed, nothing is recorded.
//! * [`Packages::install`]: `admit`, and if the answer is yes, stage the
//!   package (one file under `/fat/PKG`) and append the decision, with the
//!   package's id as provenance, to the journal. A refusal is journalled too.
//! * [`Packages::remove`]: unstage a package by id, and record it.
//! * [`Packages::installed`]: the id of the n-th staged package.
//! * [`Packages::update`]: stage a whole-system update (one signed manifest over
//!   a kernel, the userspace images, the topology and the configuration) into
//!   the inactive boot slot, and record the decision. Staging is all it does:
//!   the switch changes the boot record, which the installer holds no authority
//!   over, and the system confirms or rolls back as one slot. See
//!   `crates/core/ota/src/update.rs`.
//!   The bundle may be a **delta** (`tools/image/ota_delta.py`; it starts with
//!   `AZDL`): a patch against the set the running slot was staged from. The
//!   installer reads that set as the base, checks the patch against it before
//!   writing a byte, and stages the bundle it makes exactly as a whole one;
//!   the signed manifest and the part hashes still decide.
//!
//! * [`Packages::fetch`]: get the package from the pinned HTTPS source the rows
//!   in `/fat/PKG/SOURCE.CFG` describe, and install it as `install` does. The
//!   connection (`azos_tls`, behind `service::Remote`) decides nothing about the
//!   package; its signature does. A package that does not arrive is a
//!   `step::FETCH` status.
//! * [`Packages::fetch_update`]: the same for a whole-system update: the bundle
//!   (or delta) the source delivers is staged into the inactive slot as
//!   `update` stages one a client handed over. It arrives whole, in the package
//!   buffer (Kconfig `PKG_MAX_KB`); the signed manifest and the part hashes
//!   decide, as for any bundle.
//!
//! **Staging is not installing.** Nothing applies a staged package yet: its
//! rows join no topology and none of its images runs. The kernel's boot-time
//! application is not built. The staged file is the installer's own record (the
//! next request is judged against it) and the journal is the decision. The
//! application, when it is built, must repeat the verification and the
//! admission against the topology it boots, with the device id and counter
//! floor: the volume is a file system, and whoever can write it can write
//! `/fat/PKG`.
//!
//! # Replies
//!
//! Four words. Word 0 is the status: 0, or a code whose bits 24.. are the step
//! that said no. Steps 1..17 are `azos_pkg::Refusal::code`'s (the package or
//! its fit with this device); 32.. are the installer's own ([`step`]).
//! For `admit` and `install` word 1 is the package id's first eight bytes as a
//! big-endian number (0 when the file was not a package), word 2 the rows it
//! adds, word 3 the first row's index (admitted) or the signer's index plus
//! one (refused; 0 when none matched). `installed` answers a package id as
//! four big-endian words, all zero past the last.
#![no_std]

pub use azos_idl::{Cap, IdlError, MsgDesc, Transport};
use azos_idl::azos_interface;

pub mod cli;
#[cfg(feature = "service")]
pub mod service;

#[cfg(feature = "service")]
pub use service::{FetchErr, Read, Remote, Service, VolErr, Volume, Work};

// The whole-system update lives in the OTA crate, which links the drivers and so
// cannot be linked here; its two pure files are included by path, as the host
// suite includes them. `update` reaches `pure` as `crate::pure`.
#[cfg(feature = "service")]
#[doc(hidden)]
#[path = "../../../../crates/core/ota/src/pure.rs"]
pub mod pure;
/// The signed manifest of a whole-system update, its stager and its switch.
#[cfg(feature = "service")]
#[path = "../../../../crates/core/ota/src/update.rs"]
pub mod update;

/// The interface id (ASCII "PKGS").
pub const PACKAGES_ID: u32 = 0x504B_4753;
/// The endpoint a topology row declares for this object.
pub const ENDPOINT: &str = "endpoint.packages";

/// What a package capability names: a memory object (`CapKind::MemObj`) holding
/// the package's bytes, at least `len` of them, from its start.
pub struct PkgMem;

/// The Packages interface.
#[azos_interface(id = 0x504B_4753, level = 1)]
pub trait Packages {
    /// Would the device take the package in the first `len` bytes of `pkg`
    /// now? Changes nothing.
    fn admit(&mut self, pkg: Cap<PkgMem>, len: u32) -> [u64; 4];
    /// Admit the package in the first `len` bytes of `pkg` and stage it,
    /// journalling the decision. Never retried by a transport. If the
    /// installer fails the device keeps the packages it has.
    #[once_only]
    #[on_failure(degrade)]
    fn install(&mut self, pkg: Cap<PkgMem>, len: u32) -> [u64; 4];
    /// Unstage the package whose id is `id` (four big-endian words),
    /// journalling it. Never retried by a transport. If the installer fails
    /// the device keeps the packages it has.
    #[once_only]
    #[on_failure(degrade)]
    fn remove(&mut self, id: [u64; 4]) -> [u64; 4];
    /// The id of the `index`-th staged package file, as four big-endian words;
    /// all zero past the last. Read from the file's head and not verified: the
    /// installer lists what is on the volume, the boot decides what applies.
    #[idempotent]
    fn installed(&mut self, index: u32) -> [u64; 4];
    /// Stage the whole-system update in the first `len` bytes of `bundle` into
    /// the inactive boot slot: a signed manifest and, behind it, the kernel, the
    /// userspace images, the topology and the configuration it covers. Nothing
    /// switches: the running system is not touched, and the switch is the
    /// boot record's, made by whoever holds that authority. Journals the
    /// decision. Never retried by a transport. If the installer fails the
    /// device keeps the system it has.
    ///
    /// Reply: the status, the manifest's id (the first eight bytes of its
    /// signature), its `sec_epoch`, and the slot it was staged into.
    #[once_only]
    #[on_failure(degrade)]
    fn update(&mut self, bundle: Cap<PkgMem>, len: u32) -> [u64; 4];
    /// Get the package from the source the rows in `/fat/PKG/SOURCE.CFG`
    /// describe (a pinned HTTPS server: the installer dials it, no client
    /// hands bytes over) and admit and stage it exactly as `install` does a
    /// package a client handed over: the same verification, admission, staging
    /// and journal, and the same reply. A package that does not arrive is a
    /// `step::FETCH` status and records nothing. Never retried by a transport.
    /// If the installer fails the device keeps the packages it has.
    #[once_only]
    #[on_failure(degrade)]
    fn fetch(&mut self) -> [u64; 4];
    /// `update` for a bundle the installer fetches itself: the source the rows
    /// in `/fat/PKG/SOURCE.CFG` describe delivers the bundle (or a delta
    /// against the running slot's set), which is staged into the inactive boot
    /// slot exactly as `update` stages one a client handed over, and the same
    /// reply. The bundle arrives whole, so it is at most the package buffer
    /// (Kconfig `PKG_MAX_KB`). The way it came decides nothing: the signed
    /// manifest and the hash of every part do. A bundle that does not arrive
    /// is a `step::FETCH` status and records nothing; one that is refused is
    /// journalled. Never retried by a transport. If the installer fails the
    /// device keeps the system it has.
    #[once_only]
    #[on_failure(degrade)]
    fn fetch_update(&mut self) -> [u64; 4];
}

/// Installer steps (bits 24.. of a status), after the 16 of `azos_pkg`.
pub mod step {
    /// The device has no signed topology to admit against (detail: the
    /// `SignedRefusal::code` step, or 0 when a file is missing).
    pub const NO_TOPOLOGY: u64 = 32;
    /// The package is already staged.
    pub const ALREADY_STAGED: u64 = 33;
    /// `PKG_MAX_STAGED` packages are staged.
    pub const NO_ROOM: u64 = 34;
    /// The volume failed (detail: which access, [`super::io`]).
    pub const IO: u64 = 35;
    /// No staged package has that id.
    pub const NOT_STAGED: u64 = 36;
    /// The installer cannot tell which slot is the inactive one (the OTA
    /// endpoint is not among its grants): an update has nowhere to go. The
    /// refusals of the update itself are steps 48.. (`update::Refusal::code`).
    pub const NO_BOOT_RECORD: u64 = 37;
    /// The update is a delta that cannot be applied (detail: the
    /// `DeltaError::code`; [`super::DELTA_REASONS`] names it). A running slot
    /// whose set cannot be the base is the update's own `not staged` or
    /// `signature` refusal, steps 48...
    pub const DELTA: u64 = 38;
    /// The package could not be fetched from the source (detail: the
    /// `FetchErr::code`; [`super::FETCH_REASONS`] names it). Nothing is
    /// recorded: no package arrived.
    pub const FETCH: u64 = 39;
}

/// Which access failed, the detail of a [`step::IO`] status.
pub mod io {
    /// Reading the package's memory object.
    pub const READ_PACKAGE: u64 = 1;
    /// `/fat/PKG` is not on the volume (the build provisions it).
    pub const NO_STAGE_DIR: u64 = 2;
    /// Writing the staged file.
    pub const WRITE_PACKAGE: u64 = 3;
    /// Appending to the journal.
    pub const JOURNAL: u64 = 4;
    /// Removing the staged file.
    pub const REMOVE: u64 = 5;
}

/// A status word from a step and its detail.
pub const fn status(step: u64, detail: u64) -> u64 {
    step << 24 | detail & 0xFF_FFFF
}

/// The step of a status word.
pub const fn step_of(status: u64) -> usize {
    (status >> 24) as usize
}

/// The step number of the first refusal of an update (`update::STEP_FIRST`;
/// the host suite holds the two together).
pub const UPDATE_STEP_FIRST: usize = 48;

/// The names of the update's refusal steps (`update::Refusal::code`), in order
/// from [`UPDATE_STEP_FIRST`]. Here and not in `update`, because the client of
/// this interface links none of the update's code and still prints them.
pub const UPDATE_STEPS: [&str; 19] = [
    "update truncated", "update format", "update signature", "update reserved field", "update part",
    "update shape", "update platform", "update trial pending", "update epoch floor", "update firmware floor",
    "update slot", "update length", "update kernel too large", "update volume", "update part hash",
    "update not staged", "update extra file", "update kernel signature", "update held by envelope",
];

/// Why a delta was refused, by `DeltaError::code` minus one.
pub const DELTA_REASONS: [&str; 8] = [
    "delta truncated", "delta format", "delta result too large", "delta base length", "delta base hash",
    "delta op", "delta result hash", "delta io",
];

/// Why a package was not fetched, by `FetchErr::code` minus one.
pub const FETCH_REASONS: [&str; 6] = ["no source rows", "source rows", "connect", "tls", "http status", "transfer"];

/// The names of the steps of a status word, by step number: 1..17 are
/// `azos_pkg::Refusal::code`'s, 32.. the installer's [`step`]s. Empty where no
/// step has the number.
pub fn step_name(status: u64) -> &'static str {
    const PACKAGE: [&str; 18] = [
        "ok", "container", "algorithm", "signer", "signature", "metadata", "images", "hardware", "abi",
        "interface level", "foreign section", "rows", "rows and images", "warrants", "real time", "frames",
        "admission", "imports",
    ];
    match step_of(status) {
        n if n < PACKAGE.len() => PACKAGE[n],
        32 => "no signed topology",
        33 => "already staged",
        34 => "no room",
        35 => "volume",
        36 => "not staged",
        37 => "no boot record",
        39 => FETCH_REASONS.get(((status & 0xFF_FFFF) as usize).wrapping_sub(1)).copied().unwrap_or("fetch"),
        38 => DELTA_REASONS.get(((status & 0xFF_FFFF) as usize).wrapping_sub(1)).copied().unwrap_or("delta"),
        n if (UPDATE_STEP_FIRST..UPDATE_STEP_FIRST + UPDATE_STEPS.len()).contains(&n) => {
            UPDATE_STEPS[n - UPDATE_STEP_FIRST]
        }
        _ => "?",
    }
}

/// A package id as the four big-endian words `remove` and `installed` carry.
pub fn id_words(id: &[u8; 32]) -> [u64; 4] {
    let mut w = [0u64; 4];
    for (i, c) in id.chunks_exact(8).enumerate() {
        w[i] = u64::from_be_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    }
    w
}

/// The id four words stand for.
pub fn words_id(w: &[u64; 4]) -> [u8; 32] {
    let mut id = [0u8; 32];
    for (i, x) in w.iter().enumerate() {
        id[i * 8..i * 8 + 8].copy_from_slice(&x.to_be_bytes());
    }
    id
}
