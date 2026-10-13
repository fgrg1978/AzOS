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
pub use service::{Read, Service, VolErr, Volume, Work};

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
    /// journalling the decision. Never retried by a transport.
    #[once_only]
    fn install(&mut self, pkg: Cap<PkgMem>, len: u32) -> [u64; 4];
    /// Unstage the package whose id is `id` (four big-endian words),
    /// journalling it. Never retried by a transport.
    #[once_only]
    fn remove(&mut self, id: [u64; 4]) -> [u64; 4];
    /// The id of the `index`-th staged package file, as four big-endian words;
    /// all zero past the last. Read from the file's head and not verified: the
    /// installer lists what is on the volume, the boot decides what applies.
    #[idempotent]
    fn installed(&mut self, index: u32) -> [u64; 4];
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
