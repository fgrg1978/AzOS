// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The keystore's roots at boot (`azos_syscall::keys`, the `keys` interface).
//!
//! A key opened with a deriving backend is derived from that backend's root.
//! The board seed of BOOTMETA's reserved sector needs nothing here (the
//! interface reads it through the link-key seam the first time it is asked
//! for, and this step asks, so that the first ring-3 caller does not wait on the
//! medium); the other two roots are secrets the boot reads before the first
//! task runs:
//!
//! * `tpm_nv`: a 32-byte NV index of the TPM (`boot/tpm.rs`, Kconfig
//!   `KEYSTORE_TPM_NV`);
//! * `volume`: a 32-byte file on a mounted volume (Kconfig
//!   `KEYSTORE_VOLUME_ROOT_PATH`), best on an `aead = true` row.
//!
//! A backend whose root is not there answers `NOT_READY` to the call that asks
//! for it; the line this step prints says which have one.

use azos_crypto::keystore::Backend;
use azos_syscall::keys::{has_root, install_volume_root, VolumeRoot};

use crate::kprintln;

/// After the mounts (the volume root is a file) and the entropy step (a first
/// boot draws both secrets from the pool).
pub(crate) fn install_keystore_roots() {
    #[cfg(feature = "tpm")]
    super::tpm::install_keystore_root();
    match install_volume_root() {
        VolumeRoot::Off | VolumeRoot::Read => {}
        VolumeRoot::Created => kprintln!("[KEYS] {}: made, the volume backend has its root", azos_limits::KEYSTORE_VOLUME_ROOT_PATH),
        VolumeRoot::Failed => azos_drv_sys::kwarn!(
            "[KEYS] {} cannot be read or made (no file system, a file that is not 32 bytes, or an \
             unseeded entropy pool): the volume backend has no root", azos_limits::KEYSTORE_VOLUME_ROOT_PATH),
    }
    let yn = |b: Backend| if has_root(b) { "yes" } else { "no" };
    kprintln!("[KEYS] roots: boot {}, tpm_nv {}, volume {}; {} handles, {} per owner",
              yn(Backend::Boot), yn(Backend::TpmNv), yn(Backend::Volume),
              azos_limits::KEYSTORE_KEYS, azos_limits::KEYSTORE_KEYS_PER_OWNER);
}
