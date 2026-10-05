// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_ENTROPY_READ_TYPED` — ring-3 read of the kernel entropy pool (wave 9,
//! owner decision P9).
//!
//! ## What it is for
//!
//! A general typed entropy call for ring 3. Its first caller is
//! `userspace/services/brain_client`, which needs fresh randomness for the X25519
//! ephemeral key of each RFC-0019 handshake and for the record nonce
//! prefixes; before this call ring 3 had no source of randomness at all.
//!
//! ## The refusal rule
//!
//! The kernel's own link handshake already refuses on an unseeded pool
//! (`azos_behavior::encrypt_link::refuse_unseeded(seeded, enforced)`,
//! owner decision 2026-09-26 V1.2). That rule refuses only on a
//! `link-encrypt-enforced` build because the handshake has a degraded
//! fallback (PSK + two boot-relative counters) it may use on a dev build.
//! This call has no fallback: the pool's `fill` writes nothing while
//! unseeded, and handing out counter-derived bytes under the name
//! "entropy" is exactly what V1.2 refused. So this is the same rule with
//! `enforced` pinned `true`: unseeded ⇒ refuse, on every build.
//!
//! The answer is `-ENODEV`, not `-EAGAIN`. Nothing seeds the pool after boot
//! in this tree (`install_entropy` in `kernel/src/boot/entropy.rs` is the only
//! credited mix), so a caller told to retry would retry forever.
//!
//! The first refusal of a boot is recorded through the recorder hook — the
//! kernel installs one that prints `[ENTROPY] REFUSED: ring-3 read` and
//! writes the same `SAFETY_ENTROPY_UNSEEDED_REFUSED` record the handshake
//! writes, durably. Every later refusal only counts: a ring-3 loop asking an
//! unseeded pool must not be a synchronous disk write per call (the ring-3
//! e-stop's latch in `domains/robot/safety-core/src/actuation.rs` exists for the
//! same reason).
//!
//! ## Why hooks and not a direct call
//!
//! Same seam as `link_key.rs`: the pool (`azos_crypto::entropy`, reached
//! through `azos_behavior::encrypt_link::pool_fill` for its critical
//! section) and the durable logger both sit above this crate. A missing
//! fill hook fails CLOSED — it answers exactly like an unseeded pool.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use azos_abi::cap::{CapHandle, CapKind, CapPerms};
use azos_abi::error::Errno;
pub use azos_abi::syscall_nr::ENTROPY_READ_MAX;
use azos_ipc::cap::{targets::Entropy, Cap, CapError};
use azos_sync::SpinLock;

/// Fills its argument from the kernel pool; `false`, nothing written, while
/// the pool is unseeded.
static ENTROPY_FILL_HOOK: SpinLock<Option<fn(&mut [u8]) -> bool>> = SpinLock::new(None);

/// Records the first unseeded refusal of a boot; called with the caller's
/// TID.
static ENTROPY_REFUSED_RECORDER: SpinLock<Option<fn(u32)>> = SpinLock::new(None);

/// Set once the first refusal of this boot has gone to the recorder.
static REFUSAL_RECORDED: AtomicBool = AtomicBool::new(false);

/// Unseeded refusals this boot, recorded or not.
static REFUSALS: AtomicU32 = AtomicU32::new(0);

/// Install the pool reader and the refusal recorder. Called once at boot,
/// from `install_entropy`, after the pool has been (or failed to be) seeded.
pub fn set_entropy_hooks(fill: fn(&mut [u8]) -> bool, refused: fn(u32)) {
    *ENTROPY_FILL_HOOK.lock() = Some(fill);
    *ENTROPY_REFUSED_RECORDER.lock() = Some(refused);
}

/// Fill `buf` from the kernel pool for the kernel's own use (RFC-0047: a
/// Linux image's `AT_RANDOM`). `false`, nothing written, while the pool is
/// unseeded or no reader is installed. No capability: nothing reaches ring 3
/// but bytes the kernel chose to place in a new task's stack.
// `tests/host/syscall-tests` compiles this file without `linux.rs`.
#[cfg_attr(not(target_os = "none"), allow(dead_code))]
pub(crate) fn fill_kernel(buf: &mut [u8]) -> bool {
    let hook = *ENTROPY_FILL_HOOK.lock();
    hook.is_some_and(|f| f(buf))
}

/// Unseeded refusals this boot (the recorded first one included).
pub fn entropy_refusals() -> u32 {
    REFUSALS.load(Ordering::Relaxed)
}

/// Back to "nothing installed, nothing refused". Test-only, same reason as
/// `link_key.rs::__link_key_read_hook_clear_for_tests`.
#[cfg(test)]
pub fn __entropy_clear_for_tests() {
    *ENTROPY_FILL_HOOK.lock() = None;
    *ENTROPY_REFUSED_RECORDER.lock() = None;
    REFUSAL_RECORDED.store(false, Ordering::Relaxed);
    REFUSALS.store(0, Ordering::Relaxed);
}

/// The errno for a refused `Cap<Entropy>`, recorded through the same choke
/// point every typed handler uses (see `link_key.rs`).
fn errno_for_entropy_cap_err(e: CapError) -> i64 {
    crate::handlers::note_typed_denial(CapKind::Entropy, e);
    match e {
        CapError::Stale => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => crate::handlers::E_CONTAINED,
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// Count an unseeded refusal; the first one of the boot goes to the recorder.
fn note_unseeded_refusal(tid: u32) {
    REFUSALS.fetch_add(1, Ordering::Relaxed);
    if REFUSAL_RECORDED.swap(true, Ordering::AcqRel) {
        return;
    }
    let rec = *ENTROPY_REFUSED_RECORDER.lock();
    if let Some(f) = rec {
        f(tid);
    }
}

/// Overwrite `buf` with zeros in a way the optimiser may not drop.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned `&mut u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// `SYS_ENTROPY_READ_TYPED` — `a0 = cap` (`Cap<Entropy>`), `a1 = out_ptr`,
/// `a2 = out_len`. Requires `READ`.
///
/// In order: the capability (checked FIRST, one `SAFETY_CAP_DENIED_TYPED`
/// record on refusal, so a caller without it learns nothing about the
/// pool); `out_ptr == 0`, `out_len == 0` or `out_len > ENTROPY_READ_MAX`
/// answers `-EINVAL` and the pool is not touched; an unseeded pool (or no
/// fill hook) answers `-ENODEV` with nothing written; otherwise `out_len`
/// pool bytes are copied out and `out_len` is returned (`-EFAULT` if the copy
/// fails — the bytes drawn are wiped, never reused).
pub fn sys_entropy_read_typed(cap_raw: u64, out_ptr: u64, out_len: u64) -> i64 {
    let cap: Cap<Entropy> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    if let Err(e) = azos_ipc::cap_store::get(tid, cap, CapPerms::READ) {
        return errno_for_entropy_cap_err(e);
    }

    if out_ptr == 0 || out_len == 0 || out_len > ENTROPY_READ_MAX as u64 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let len = out_len as usize;

    let mut buf = [0u8; ENTROPY_READ_MAX];
    let fill = *ENTROPY_FILL_HOOK.lock();
    let got = match fill {
        Some(f) => f(&mut buf[..len]),
        None => false,
    };
    if !got {
        // `Pool::fill` may have written a prefix before refusing (a call
        // that spans the reseed interval); none of it leaves the kernel.
        wipe(&mut buf);
        note_unseeded_refusal(tid);
        return Errno::ENODEV.to_syscall_ret();
    }

    let ret = if azos_sched::current_user_pt() != 0 {
        if azos_sched::copy_to_user(out_ptr as usize, buf.as_ptr(), len) {
            len as i64
        } else {
            Errno::EFAULT.to_syscall_ret()
        }
    } else {
        // Kernel caller (host tests call this directly with a kernel-space
        // pointer, the same convention `link_key.rs` documents).
        let out = unsafe { core::slice::from_raw_parts_mut(out_ptr as *mut u8, len) };
        out.copy_from_slice(&buf[..len]);
        len as i64
    };
    wipe(&mut buf);
    ret
}

// Host tests live in `tests/host/syscall-tests/src/entropy_guards.rs`, for the
// reason `link_key.rs` gives at its foot: this crate does not build for a
// host target.
