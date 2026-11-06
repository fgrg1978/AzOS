// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The launch check of every exec a process makes, and its decision record.
//!
//! `SYS_SPAWN_EX` and the Linux `execve` both resolve the bytes they are about
//! to load to an image (`azos_sched::seccomp::image_for_digest`) and ask here
//! whether the caller holds `EXEC` on a launch grant (`ty::LAUNCH`) for that
//! image, or for the signed package that carries it. The path the caller typed
//! is never consulted. Every answer, admitted or refused, is one
//! [`Rule::ExecGrant`] record: the digest prefix, the [`Basis`] that decided
//! and the [`Site`]. A program of a package below its security floor
//! (`azos_sched::seccomp::package_below_floor`, set by the boot-time apply when
//! Kconfig `PKG_SEC_FLOOR_ENFORCE` is on) is refused before any grant is looked
//! at: [`Basis::BelowSecFloor`].

use core::sync::atomic::{AtomicBool, Ordering};

use azos_abi::cap::{ty, CapPerms};
use azos_decision::{Rule, Verdict};

/// Where the exec was asked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Site {
    /// `SYS_SPAWN_EX`.
    SpawnEx = 0,
    /// The Linux `execve`.
    Execve = 1,
}

/// What decided; the second number of the record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Basis {
    /// Admitted: the caller holds a launch grant on the image.
    Image = 1,
    /// Admitted: the caller holds a launch grant on the package that carries it.
    Package = 2,
    /// Admitted: an `execve` into the image of the caller's own row.
    OwnRow = 3,
    /// Refused: no launch grant on the image or on its package.
    NoGrant = 4,
    /// Refused: the bytes are bound to no image.
    Unbound = 5,
    /// Refused: an `execve` into a native row.
    NotLinuxRow = 6,
    /// Refused: the image has no topology row.
    NoRow = 7,
    /// Refused: the image belongs to a package installed below the security
    /// floor the signed repository index names for it, whatever grant the
    /// caller holds. `pkg upgrade` is the way out.
    BelowSecFloor = 8,
}

impl Basis {
    /// Did the exec go ahead?
    pub const fn admitted(self) -> bool {
        (self as u8) < Basis::NoGrant as u8
    }
}

/// Runtime canary `exec-grant-skip` (set by the kernel at boot): the check
/// finds a grant on every image.
pub static SKIP_CHECK: AtomicBool = AtomicBool::new(false);

fn holds(tid: u32, resource: u32) -> bool {
    azos_ipc::cap_store::with_table(tid, |t| t.holds_kind_resource_uncontained(ty::LAUNCH, resource, CapPerms::EXEC))
        .unwrap_or(false)
}

/// The grant task `tid` holds that covers `image`, whose bytes hash to
/// `digest`.
pub fn grant_for(tid: u32, image: &str, digest: &[u8; 32]) -> Option<Basis> {
    if SKIP_CHECK.load(Ordering::Relaxed) {
        return Some(Basis::Image);
    }
    if azos_ipc::launch_cap::launch_resource_of(image.as_bytes()).is_some_and(|r| holds(tid, r)) {
        return Some(Basis::Image);
    }
    azos_sched::seccomp::package_of_digest(digest)
        .and_then(|id| azos_ipc::launch_cap::package_resource_of(&id))
        .filter(|&r| holds(tid, r))
        .map(|_| Basis::Package)
}

/// Write the record of one exec by task `tid`; its id (0 when nothing kept it).
pub fn record(tid: u32, site: Site, basis: Basis, digest: &[u8; 32]) -> u64 {
    let verdict = if basis.admitted() { Verdict::Admit } else { Verdict::Refuse };
    let prefix = u64::from_be_bytes([digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7]]);
    azos_decision::record_keyed(
        Rule::ExecGrant,
        verdict,
        tid,
        crate::handlers::durable_bucket(tid),
        [prefix, basis as u64, site as u64],
    )
}

/// An exec that was refused: the id of its record (0 when nothing kept it) and
/// the basis that decided, so the caller can say why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Refused {
    /// The record's id.
    pub receipt: u64,
    /// What decided.
    pub basis: Basis,
}

impl Refused {
    /// What the caller prints after "REFUSED:".
    pub const fn why(&self) -> &'static str {
        match self.basis {
            Basis::BelowSecFloor => "its package is below its security floor (pkg upgrade)",
            _ => "no launch grant",
        }
    }
}

/// The floor check alone: `Err` (and its record) for a program of a package
/// below its security floor, whatever the caller holds. Compiled out of a
/// build whose Kconfig `PKG_SEC_FLOOR_ENFORCE` is n: nothing is marked there.
pub fn floor_check(tid: u32, site: Site, digest: &[u8; 32]) -> Result<(), Refused> {
    #[cfg(feature = "pkg-sec-floor")]
    if !cfg!(feature = "exec-floor-canary") && azos_sched::seccomp::package_below_floor(digest) {
        return Err(Refused { receipt: record(tid, site, Basis::BelowSecFloor, digest), basis: Basis::BelowSecFloor });
    }
    let _ = (tid, site, digest);
    Ok(())
}

/// The check and the record: `Ok` with the basis that admits `tid`'s exec of
/// `image`, `Err` with the refusal.
pub fn decide(tid: u32, site: Site, image: &str, digest: &[u8; 32]) -> Result<Basis, Refused> {
    floor_check(tid, site, digest)?;
    match grant_for(tid, image, digest) {
        Some(basis) => {
            record(tid, site, basis, digest);
            Ok(basis)
        }
        None => Err(Refused { receipt: record(tid, site, Basis::NoGrant, digest), basis: Basis::NoGrant }),
    }
}
