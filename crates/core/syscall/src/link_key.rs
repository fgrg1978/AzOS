// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `LinkKey` interface the kernel hosts: the ring-3 door onto the brain-link
//! PSK (U06-9, owner decision 2026-09-26; an endpoint op since D6 part A).
//!
//! ## The gap this closes
//!
//! The kernel stopped reading the brain-link PSK from `/fat/LINK.KEY` on
//! 2026-09-26 (`kernel/src/msc_gadget.rs`'s `RESERVED_SECTOR_LINK_KEY`): the
//! key now lives in a reserved tail sector that `Fat32BlockDevice` never
//! reports as present, so a USB host on the MSC port cannot address it.
//! `brain_client` reads it through [`Server`], on the kernel-hosted `linkkey`
//! endpoint: refused unless the caller holds an endpoint capability with
//! `READ` that the signed topology granted it.
//!
//! ## Why a hook and not a direct call
//!
//! `crates/core/syscall` cannot depend on `kernel` -- same TCB reason `FileOps`
//! (`file_ops.rs`) and `ESTOP_HANDLER` (`handlers.rs`) are hooks rather than
//! calls: reading the reserved sector means calling
//! `azos_drv_block::blkdev::read`/`msc_gadget::reserved_region_read`,
//! and `msc_gadget` lives in `kernel/src`, above this crate in the
//! dependency graph. The kernel installs the hook at boot (`kernel/src/main.rs`
//! around the `[SECCHAN] link key loaded` log line).
//!
//! ## Capability shape
//!
//! One brain-link key per board, so the endpoint carries no resource. `READ`
//! is the only right [`Server::read`] checks; there is no write path -- the key
//! is provisioned at image-build time (`Makefile`'s `disk-braincli-linkkey.img`
//! recipe), never by a running task.

use azos_abi::cap::CapPerms;
use azos_devif::linkkey::KEY_WORDS;
use azos_devif::{outcome, Out};
use azos_sync::SpinLock;

use crate::khost::Caller;

/// Length of the brain-link PSK. Mirrors
/// `azos_behavior::auth_envelope::KEY_BYTES` (32) and
/// `msc_gadget`'s reserved-sector format, restated here because this crate
/// cannot depend on `azos_behavior` (this crate is core; `behavior` sits
/// above it — same TCB boundary the hook below exists for) and the kernel
/// has no crate at all that both sides could import it from.
pub const LINK_KEY_BYTES: usize = 32;

/// Where the reserved-sector read is carried out, installed by the kernel at
/// boot.
///
/// Same seam and the same reason as [`crate::handlers::ESTOP_HANDLER`]:
/// the actual I/O (`msc_gadget::reserved_region_read`) lives in `kernel/src`,
/// above this crate in the dependency graph.
///
/// **`None` fails CLOSED, not silently.** The hook returns `bool`, not just
/// filling the buffer, precisely so a missing hook and a genuinely-absent or
/// all-zero key answer through the SAME code path in
/// [`Server::read`] as they do at kernel boot
/// (`main.rs`'s `key_buf.iter().any(|b| *b != 0)` check) — a caller cannot
/// distinguish "no hook installed" from "no key provisioned on this image"
/// and must not be able to: both mean "the wire will be plaintext, act
/// accordingly", which is exactly what `brain_client`'s FATAL-and-refuse-to-run
/// already does on any `false` here.
static LINK_KEY_READ_HOOK: SpinLock<Option<fn(&mut [u8; LINK_KEY_BYTES]) -> bool>> =
    SpinLock::new(None);

/// Install the reserved-sector key reader. Called once at boot.
pub fn set_link_key_read_hook(f: fn(&mut [u8; LINK_KEY_BYTES]) -> bool) {
    *LINK_KEY_READ_HOOK.lock() = Some(f);
}

/// Swap the installed reader for `f`, returning the previous one (ktest
/// installs a probe reader and puts the boot's back).
pub fn replace_link_key_read_hook(
    f: Option<fn(&mut [u8; LINK_KEY_BYTES]) -> bool>,
) -> Option<fn(&mut [u8; LINK_KEY_BYTES]) -> bool> {
    core::mem::replace(&mut *LINK_KEY_READ_HOOK.lock(), f)
}

/// Run the installed reader on `key`; `false` when none is installed.
///
/// The hook is copied out and the SpinLock released BEFORE it runs: the
/// reader is a block-layer read of the reserved sector, which waits for the
/// device. `match *LINK_KEY_READ_HOOK.lock() { Some(f) => f(..) }` kept the
/// guard (a temporary of the scrutinee) alive through the arm, so the read
/// ran under the SpinLock (ktest `link_key_hook_runs_unlocked`).
pub fn read_key_via_hook(key: &mut [u8; LINK_KEY_BYTES]) -> bool {
    let hook = *LINK_KEY_READ_HOOK.lock();
    match hook {
        Some(f) => f(key),
        None => false,
    }
}

/// Put the seam back to "nothing installed". Test-only, same reason
/// `file_ops.rs::__file_ops_clear_for_tests` exists: a host test that
/// installs a stand-in hook must not leave it behind for a test that asserts
/// the uninstalled half.
#[cfg(test)]
pub fn __link_key_read_hook_clear_for_tests() {
    *LINK_KEY_READ_HOOK.lock() = None;
}

/// The `LinkKey` interface served for one caller.
pub struct Server(pub Caller);

impl azos_devif::LinkKey for Server {
    /// In order: the right (`READ`, checked FIRST, one capability-denial
    /// record on refusal, so a caller without it learns nothing about the
    /// sector); then the key itself -- a missing hook or an absent/all-zero
    /// key (see the hook's own doc) answers `NOT_READY`, the same "no
    /// plaintext fallback" outcome `link_key_init`'s FATAL-and-refuse-to-run
    /// already gives the caller; otherwise the 32 bytes as four words.
    fn read(&mut self) -> Out<[u64; KEY_WORDS]> {
        if !self.0.allows(CapPerms::READ) {
            self.0.deny(CapPerms::READ);
            return Out::err(outcome::DENIED);
        }
        let mut key = [0u8; LINK_KEY_BYTES];
        let got = read_key_via_hook(&mut key);
        if !got {
            return Out::err(outcome::NOT_READY);
        }
        let mut out = [0u64; KEY_WORDS];
        for (o, c) in out.iter_mut().zip(key.chunks_exact(8)) {
            *o = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
        }
        // The key was on this stack: not left behind.
        for b in key.iter_mut() {
            // SAFETY: `b` is a valid, aligned `&mut u8`.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        Out::ok(out)
    }
}

// Host tests live in `tests/host/syscall-tests/src/link_key_guards.rs`, not here.
//
// This module cannot carry its own `#[cfg(test)] mod tests` the way a leaf
// crate does: `crates/core/syscall` is `no_std` and depends on `azos_sched`
// (RV64 context-switch asm, CSRs, PLIC), which does not build for a host
// target at all (see `tests/host/syscall-tests/src/lib.rs`'s module doc — that
// crate exists precisely because `cargo test -p azos_syscall` is not a
// thing). `crate::handlers`/`crate::motor_cmd` follow the same rule: neither
// carries its own test module either. `link_key.rs` is pulled into
// `azos_syscall_tests` with `#[path]`, at that crate's root, the same
// way `motor_cmd.rs` is (see this file's own module doc, "Why a hook and
// not a direct call" — the reason it names `crate::handlers::{E_CONTAINED,
// note_typed_denial}`, both `pub(crate)`, applies unchanged to why it must
// sit at that crate's root rather than nested inside `mod handlers { .. }`).
