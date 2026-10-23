// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `LinkKey` interface the kernel hosts: the ring-3 door onto the brain-link
//! PSK (U06-9, owner decision 2026-09-26; an endpoint op since D6 part A).
//!
//! ## The gap this closes
//!
//! The kernel stopped reading the brain-link PSK from `/fat/LINK.KEY` on
//! 2026-09-26 (`kernel/src/reserved_tail.rs`'s `LINK_KEY`): the key now
//! lives, as a validated record, in a reserved tail sector past the
//! filesystem that a USB mass-storage export never reports as present.
//! `brain_client` reads it through [`Server`], on the kernel-hosted `linkkey`
//! endpoint: refused unless the caller holds an endpoint capability with
//! `READ` that the signed topology granted it.
//!
//! ## Why a hook and not a direct call
//!
//! `crates/core/syscall` cannot depend on `kernel` -- same TCB reason `FileOps`
//! (`file_ops.rs`) and `ESTOP_HANDLER` (`handlers.rs`) are hooks rather than
//! calls: reading the reserved sector means calling
//! `azos_drv_block::blkdev::read`/`reserved_tail::read`,
//! and `reserved_tail` lives in `kernel/src`, above this crate in the
//! dependency graph. The kernel installs the hook at boot (`kernel/src/main.rs`
//! around the `[SECCHAN] link key loaded` log line).
//!
//! ## Capability shape
//!
//! One brain-link key per board, so the endpoint carries no resource. All three
//! ops need `READ`; what tells the holders apart is the capability's `OP_MASK`
//! (`azos_ipc::cap::caveat::OP_MASK`, the IDL ops the holder may call, held by
//! `khost::admit` before this server runs). `brain_client` holds `READ`
//! unmasked, so it calls [`Server::read`], the raw key, which is also the device
//! seed of the DICE derivation. `RPCSRV.ELF` and `MCPD.ELF` hold
//! `READ` masked to [`azos_devif::linkkey::NODE_KEY_OPS`]: they can call
//! [`Server::node_key`], the key of the caller's own image, from which the seed
//! cannot be recovered, and no other op. A network-facing task that is
//! compromised can therefore ask for its own identity and never read the seed
//! that every node key derives from. `node_key` is `READ` and not `WRITE`, so
//! containment does not stop it.
//! There is no write path -- the key is provisioned at image-build time
//! (`Makefile`'s `disk-braincli-linkkey.img` recipe), never by a running task.
//!
//! ## The node identity (DICE-ID)
//!
//! The same sector is the device seed of the node's DICE identity
//! ([`azos_crypto::dice`]). [`Server::node_key`] derives, in the kernel, the
//! Noise static key of the **caller's own Domain**: `HKDF(seed, measurement of
//! the caller's image)`. The seed reaches ring 3 only through `read`, which no
//! masked holder can call, and a task running another image gets another key, so the `noise_pk` a topology pins is the key
//! of one image on one board. A Domain with no recorded measurement (not started
//! by the measuring loader) has no identity and is answered `NOT_READY`.

use azos_abi::cap::CapPerms;
use azos_devif::linkkey::KEY_WORDS;
use azos_devif::{outcome, Out};
use azos_sync::SpinLock;

use crate::khost::Caller;

/// Length of the brain-link PSK. Mirrors
/// `azos_behavior::encrypt_link::PSK_BYTES` (32) and
/// the reserved-sector record's key, restated here because this crate
/// cannot depend on `azos_behavior` (this crate is core; `behavior` sits
/// above it — same TCB boundary the hook below exists for) and the kernel
/// has no crate at all that both sides could import it from.
pub const LINK_KEY_BYTES: usize = 32;

/// Where the reserved-sector read is carried out, installed by the kernel at
/// boot.
///
/// Same seam and the same reason as [`crate::handlers::ESTOP_HANDLER`]:
/// the actual I/O (`reserved_tail::read`) lives in `kernel/src`,
/// above this crate in the dependency graph.
///
/// **`None` fails CLOSED, not silently.** The hook returns `bool`, not just
/// filling the buffer, precisely so a missing hook and an absent or malformed
/// key record answer through the SAME code path in
/// [`Server::read`] as they do at kernel boot (`main.rs`'s `link_key_read`,
/// the one reader both use) — a caller cannot
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
        let out = words(&key);
        // The key was on this stack: not left behind.
        wipe(&mut key);
        Out::ok(out)
    }

    /// In order: the right (`READ`; which ops a holder may call is the
    /// capability's `OP_MASK`, see the module doc; a refusal is recorded and
    /// nothing is read); the caller's
    /// Domain measurement (a task with no Domain, or a Domain the loader did
    /// not measure, is `NOT_READY`); the seed (a missing hook or an absent
    /// key is `NOT_READY`); then the derived key as four words. The seed and
    /// the derivation's intermediates are wiped before the reply.
    fn node_key(&mut self) -> Out<[u64; KEY_WORDS]> {
        if !self.0.allows(CapPerms::READ) {
            self.0.deny(CapPerms::READ);
            return Out::err(outcome::DENIED);
        }
        let Some(measurement) = caller_measurement(self.0.tid) else {
            return Out::err(outcome::NOT_READY);
        };
        let mut seed = [0u8; LINK_KEY_BYTES];
        if !read_key_via_hook(&mut seed) {
            return Out::err(outcome::NOT_READY);
        }
        let derived = azos_crypto::dice::node_static_key(&seed, &measurement);
        wipe(&mut seed);
        let Some(mut sk) = derived else {
            return Out::err(outcome::NOT_READY);
        };
        let out = words(&sk);
        wipe(&mut sk);
        Out::ok(out)
    }

    /// In order: the right (`READ`, as for [`Server::read`]); then the key the
    /// signed topology's `[peer.brain]` row pins (`Topology::brain_noise_pk`).
    /// No topology, no such row, or a row without a key is `NO_RESOURCE`:
    /// nothing is pinned and the link runs `Noise_XX`. A public key, so there
    /// is nothing to wipe.
    fn brain_pk(&mut self) -> Out<[u64; KEY_WORDS]> {
        if !self.0.allows(CapPerms::READ) {
            self.0.deny(CapPerms::READ);
            return Out::err(outcome::DENIED);
        }
        match azos_topology::get().and_then(|t| t.brain_noise_pk()) {
            Some(pk) => Out::ok(words(&pk)),
            None => Out::err(outcome::NO_RESOURCE),
        }
    }
}

/// The measurement of the Domain task `tid` runs in; `None` for a task with
/// none and for a Domain whose measurement was never recorded (all zeros).
fn caller_measurement(tid: u32) -> Option<[u8; LINK_KEY_BYTES]> {
    let key = azos_sched::idx_for_tid(tid).map(azos_sched::task_domain)?;
    azos_sched::domain::measurement(key).filter(|m| m.iter().any(|&b| b != 0))
}

/// `key` as four little-endian words.
fn words(key: &[u8; LINK_KEY_BYTES]) -> [u64; KEY_WORDS] {
    let mut out = [0u64; KEY_WORDS];
    for (o, c) in out.iter_mut().zip(key.chunks_exact(8)) {
        *o = u64::from_le_bytes(c.try_into().unwrap_or([0; 8]));
    }
    out
}

/// Zero key material so the stack does not keep it.
fn wipe(key: &mut [u8; LINK_KEY_BYTES]) {
    for b in key.iter_mut() {
        // SAFETY: `b` is a valid, aligned `&mut u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
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
