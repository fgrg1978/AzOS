// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_LINK_KEY_READ_TYPED` — U06-9 for `brain_client` (owner decision,
//! 2026-09-26).
//!
//! ## The gap this closes
//!
//! The kernel stopped reading the brain-link PSK from `/fat/LINK.KEY` on
//! 2026-09-26 (`kernel/src/msc_gadget.rs`'s `RESERVED_SECTOR_LINK_KEY`): the
//! key now lives in a reserved tail sector that `Fat32BlockDevice` never
//! reports as present, so a USB host on the MSC port cannot address it.
//! `userspace/services/brain_client/src/main.rs`'s `link_key_init` (line ~800 in the
//! tree this was written against) never got the matching fix — it still
//! opens `/fat/LINK.KEY` through `Cap<File>`, i.e. it reads the SAME bytes
//! back off the exported FAT volume the reserved sector exists to take them
//! off of. This syscall is the ring-3 door onto the reserved sector: it
//! copies the 32 raw bytes into a user buffer, refused unless the caller
//! holds a capability the signed topology granted it.
//!
//! ## Why this is its own file rather than another function in `handlers.rs`
//!
//! Same reason `crates/core/syscall/src/motor_cmd.rs` (`SYS_MOTOR_MOVE_TYPED`,
//! 584) is its own file: `dispatch.rs`/`handlers.rs` are owned by another
//! front this wave, so this front is granted exactly one new syscall number
//! and one new file for its handler, wiring into `dispatch.rs` delivered as
//! a unified diff (`F3-dispatch.diff`) instead of edited in place.
//!
//! ## Why a hook and not a direct call
//!
//! `crates/core/syscall` cannot depend on `kernel` — same TCB reason `FileOps`
//! (`file_ops.rs`) and `ESTOP_HANDLER` (`handlers.rs`) are hooks rather than
//! calls: reading the reserved sector means calling
//! `azos_drv_block::blkdev::read`/`msc_gadget::reserved_region_read`,
//! and `msc_gadget` lives in `kernel/src`, above this crate in the
//! dependency graph. The kernel installs the hook at boot, next to
//! `set_estop_handler` and the operator-release-authority load, both of
//! which sit beside the `msc_gadget::reserved_region_read` call this hook
//! wraps (see `kernel/src/main.rs` around the `[SECCHAN] link key loaded`
//! log line — `F3-main.diff`).
//!
//! ## Capability shape
//!
//! `Cap<LinkKey>` (`CapKind::LinkKey`, `crates/core/abi/src/cap.rs` +
//! `crates/core/ipc/src/cap.rs::targets::LinkKey` — `F3-ipc-cap.diff`) is a
//! singleton capability, like `Buzzer`: there is exactly one brain-link key
//! per board, so the resource value the slot carries is always `0` and no
//! target string other than the bare kind name should ever mint one. `READ`
//! is the only permission this call checks; there is no write path — the key
//! is provisioned at image-build time (`Makefile`'s `disk-braincli-linkkey.img`
//! recipe, `F3-Makefile.diff`), never by a running task.

use azos_abi::cap::{CapHandle, CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_ipc::cap::{targets::LinkKey, Cap, CapError};
use azos_sync::SpinLock;

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
/// [`sys_link_key_read_typed`] as they do at kernel boot
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

/// The errno for a `CapError` refused against `CapKind::LinkKey`, recording
/// through the same choke point every other typed handler in this crate
/// uses.
///
/// `crate::handlers::note_typed_denial` is `pub(crate)` (unlike
/// `errno_for_cap_err`, which is a plain private function `handlers.rs`
/// keeps to itself — see `motor_cmd.rs`'s module doc for the same split),
/// so this reaches the SAME recorder every other typed call's denial goes
/// through, under the SAME `SAFETY_CAP_DENIED_TYPED` accounting, without
/// reimplementing it.
fn errno_for_link_key_cap_err(e: CapError) -> i64 {
    crate::handlers::note_typed_denial(CapKind::LinkKey, e);
    match e {
        CapError::Stale => Errno::ECAPSTALE.to_syscall_ret(),
        CapError::WrongKind => Errno::ECAPKIND.to_syscall_ret(),
        CapError::MissingPerms => Errno::ECAPPERMS.to_syscall_ret(),
        CapError::Contained => crate::handlers::E_CONTAINED,
        CapError::NoSpace => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `SYS_LINK_KEY_READ_TYPED` — `a0 = cap` (`Cap<LinkKey>`), `a1 = out_ptr`,
/// `a2 = out_len`. Requires `READ`.
///
/// In order: a refused capability answers `-ECAPSTALE` / `-ECAPKIND` /
/// `-ECAPPERMS` and writes one `SAFETY_CAP_DENIED_TYPED` record (checked
/// FIRST, so a caller without the capability learns nothing about the
/// buffer-length gate below it either); `out_len < LINK_KEY_BYTES` answers
/// `-EINVAL` with no record and the reserved sector is never touched; a
/// missing hook or an absent/all-zero key (see the hook's own doc) answers
/// `-EAUTH` — the same "no plaintext fallback" outcome
/// `link_key_init`'s FATAL-and-refuse-to-run already gives the caller today,
/// just from inside the syscall instead of from a short FAT read; otherwise
/// the 32 bytes are copied to `out_ptr` and this returns `LINK_KEY_BYTES`.
pub fn sys_link_key_read_typed(cap_raw: u64, out_ptr: u64, out_len: u64) -> i64 {
    let cap: Cap<LinkKey> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    if let Err(e) = azos_ipc::cap_store::get(tid, cap, CapPerms::READ) {
        return errno_for_link_key_cap_err(e);
    }

    if out_ptr == 0 || (out_len as usize) < LINK_KEY_BYTES {
        return Errno::EINVAL.to_syscall_ret();
    }

    let mut key = [0u8; LINK_KEY_BYTES];
    let got = read_key_via_hook(&mut key);
    if !got {
        return Errno::EAUTH.to_syscall_ret();
    }

    if azos_sched::current_user_pt() != 0 {
        if azos_sched::copy_to_user(out_ptr as usize, key.as_ptr(), LINK_KEY_BYTES) {
            LINK_KEY_BYTES as i64
        } else {
            Errno::EFAULT.to_syscall_ret()
        }
    } else {
        // Kernel caller (host tests call this directly with a kernel-space
        // pointer, the same convention `sensor_write_to_user` documents).
        let out = unsafe { core::slice::from_raw_parts_mut(out_ptr as *mut u8, LINK_KEY_BYTES) };
        out.copy_from_slice(&key);
        LINK_KEY_BYTES as i64
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
