// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The anti-rollback floor's hardware backend (Kconfig `OTA_FLOOR_TPM_NV`).
//!
//! The epoch floor (`BootMeta::min_sec_epoch`) lives in BOOTMETA on the FAT
//! volume, which anything that can write the volume can roll back. A backend
//! is a second home for the same number that the volume cannot reach: a TPM NV
//! index today (`kernel/src/boot/tpm.rs`). This module is the whole policy,
//! and all of it is pure (no I/O of its own, so `tests/host/ota-tests`
//! includes the file):
//!
//! * **Read side.** The floor in force is the higher of BOOTMETA's and the
//!   backend's ([`lift`]). The backend's value is read once, when it is
//!   installed, and kept here, so the read side costs nothing at run time and
//!   never waits on the hardware; replacing or deleting BOOTMETA can lower
//!   the floor only down to the backend's.
//! * **Write side.** The floor is raised at one point only, the boot
//!   confirmation ([`commit`], from `ota_mark_boot_good`), exactly where
//!   `ota_mark_boot_good_pure` raises BOOTMETA's. The backend is asked to
//!   raise only when the value is above the one it holds; a raise that fails
//!   is counted and tried again at the next confirmation, and BOOTMETA's
//!   floor holds meanwhile.
//! * **Only upward**, twice: [`commit`] never asks for a value at or below the
//!   known one, and the backend itself reads before it writes
//!   (`azos_tpm::tpm::Tpm::floor_raise`).
//!
//! What it does not do: a backend that never installed (no TPM, a TPM that
//! failed to provision) leaves BOOTMETA alone to hold the floor, and the boot
//! says so. The volume never sets the hardware value: [`commit`] is given the
//! confirmed slot's own epoch (`pure::ota_confirmed_epoch`), not BOOTMETA's
//! `min_sec_epoch`, so a forged floor on the volume cannot be ratcheted into
//! the TPM, where nothing short of clearing it could undo it.

use core::sync::atomic::{AtomicU32, Ordering};

/// A second home for the floor.
pub struct Backend {
    /// Raise the stored floor to `to` if that is higher than what it holds;
    /// the floor in force afterwards, `None` when the hardware failed.
    pub raise: fn(to: u32) -> Option<u32>,
}

azos_common::ro_hook! {
    static BACKEND: &'static Backend;
}
/// The floor the backend is known to hold.
static KNOWN: AtomicU32 = AtomicU32::new(0);
/// Raises the backend refused or could not do.
static RAISE_FAILURES: AtomicU32 = AtomicU32::new(0);

/// The password of the floor's NV index (`index` is the index's number). The
/// index is an ordinary one and nothing else guards it, so it is as safe as
/// this value is secret, and this one is a derivation of public inputs: it
/// keeps out software that does not know the scheme, not an attacker who has
/// read this file. A policy bound to PCRs, which the driver's empty-policy
/// definition does not carry, is the next step.
#[must_use]
pub fn nv_auth(index: u32) -> [u8; 32] {
    const TAG: &[u8; 17] = b"azos/ota-floor/v1";
    let mut m = [0u8; 21];
    m[..17].copy_from_slice(TAG);
    m[17..].copy_from_slice(&index.to_be_bytes());
    azos_crypto::sha256::sha256(&m)
}

/// Install `backend`, which holds `current` right now (the caller read it, so
/// a backend that cannot be read is never installed). Boot, once.
pub fn install(backend: &'static Backend, current: u32) {
    KNOWN.store(current, Ordering::Release);
    BACKEND.set(backend);
}

/// Is a backend installed?
#[must_use]
pub fn active() -> bool {
    BACKEND.is_set()
}

// REQ-014
/// The floor in force: BOOTMETA's `stored`, or the backend's if that is higher.
#[must_use]
pub fn lift(stored: u32) -> u32 {
    if active() { stored.max(KNOWN.load(Ordering::Acquire)) } else { stored }
}

// REQ-014
/// Raise the backend to `floor`, the epoch of the slot just confirmed
/// (`pure::ota_confirmed_epoch`; never the volume's `min_sec_epoch`). Nothing
/// is asked of the hardware at or below the known floor.
pub fn commit(floor: u32) {
    let Some(b) = BACKEND.get().filter(|_| floor > KNOWN.load(Ordering::Acquire)) else {
        return;
    };
    match (b.raise)(floor) {
        Some(now) => {
            KNOWN.fetch_max(now, Ordering::AcqRel);
        }
        None => {
            RAISE_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Raises that failed since boot.
#[must_use]
pub fn raise_failures() -> u32 {
    RAISE_FAILURES.load(Ordering::Relaxed)
}
