// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Volume` interface the kernel hosts: the check of a mounted volume, run
//! by hand (`azos_devif::volume` has the contract).
//!
//! User: the toolbox's `fsck` (`userspace/services/toolbox`), whose row holds
//! the boot volume's endpoint (`volume.0`) with `WRITE`. The badge names the
//! volume. The check itself is the filesystem's (`azos_fs`), which this crate
//! does not name: the kernel installs [`set_check_hook`] at boot, as
//! `link_key.rs` and `entropy.rs` do for what sits above them. Without the
//! hook (a build with no filesystem) every check answers `UNSUPPORTED`.

use azos_abi::cap::CapPerms;
use azos_devif::volume::{Report, VOLUMES};
use azos_devif::{outcome, Out};

use crate::khost::Caller;

azos_common::ro_hook! {
    /// Check volume `n` (`azos_devif::volume`: 0 the boot volume, `p` the
    /// row on partition `p`; `scrub`: read the data against its checksums
    /// too): the report, or the outcome code to answer.
    static CHECK_HOOK: fn(u32, bool) -> Result<Report, u32>;
}

/// Install the check. Called once at boot.
pub fn set_check_hook(f: fn(u32, bool) -> Result<Report, u32>) {
    CHECK_HOOK.set(f);
}

/// The `Volume` interface served for one caller.
pub struct Server(pub Caller);

impl azos_devif::Volume for Server {
    /// The endpoint's `WRITE` (one capability-denial record on refusal), the
    /// volume its badge names, then the hook.
    fn check(&mut self, scrub: bool) -> Out<Report> {
        if let Err(e) = self.0.gate::<Report>(CapPerms::WRITE) {
            return e;
        }
        let Some(n) = self.0.badge.checked_sub(1).filter(|&n| n < VOLUMES) else {
            return Out::err(outcome::NO_RESOURCE);
        };
        let Some(check) = CHECK_HOOK.get() else { return Out::err(outcome::UNSUPPORTED) };
        match check(n, scrub) {
            Ok(r) => Out::ok(r),
            Err(code) => Out::err(code),
        }
    }
}
