// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure policy: whether ephemeral-key derivation must refuse for lack of
//! entropy (owner decision, 2026-09-26, V1.2 — U09-8 / security finding #26).
//!
//! No dependencies on `azos_drv_*`/`azos_sync`/`azos_crypto` —
//! kept dependency-free, same reason `crates/core/ota/src/pure.rs` is, so
//! `tests/host/behavior-tests/` can `#[path]`-include this file directly and
//! exercise the exact decision `derive_ephemeral_priv`
//! (`domains/robot/behavior/src/encrypt_link.rs`) makes, on the host, with no
//! hardware shims involved.

/// `true` iff ephemeral-key derivation must refuse rather than derive a key
/// from PSK + boot-relative timing alone.
///
/// `seeded` — `azos_crypto::entropy::seeded()` at the moment of
/// derivation. `enforced` — `azos_encrypt_link::link_encrypt_enforced()`,
/// the existing compile-time production gate (`link-encrypt-enforced`
/// cargo feature; `vf2`/`k1` builds already carry it).
///
/// On a build that does NOT enforce (dev/QEMU today, no prod key rolled
/// out), an unseeded derivation still proceeds — degraded, not refused —
/// matching the accepted dev-mode risk documented on
/// `derive_ephemeral_priv` itself.
#[must_use]
pub const fn refuse_unseeded(seeded: bool, enforced: bool) -> bool {
    enforced && !seeded
}

