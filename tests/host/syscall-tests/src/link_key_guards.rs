// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `SYS_LINK_KEY_READ_TYPED` (591, U06-9) —
// `crates/core/syscall/src/link_key.rs::sys_link_key_read_typed`.
//
// The handler lives at THIS crate's root (`crate::link_key`, pulled in with
// `#[path]` by `lib.rs`, the same way `crate::motor_cmd` is — see
// `link_key.rs`'s own module doc for why: it names
// `crate::handlers::{E_CONTAINED, note_typed_denial}`, both `pub(crate)`,
// so it has to sit where `mod handlers` is a sibling rather than a parent).
// This file is therefore included inside `mod handlers { .. }` in `lib.rs`
// like every other guard file in this crate, and reaches the handler under
// test through the full path `crate::link_key::...` — the same reason
// `unit6_contain.rs` writes `crate::motor_cmd::sys_motor_move_typed` instead
// of a bare name.
//
// Four outcomes, matching the brief: (a) allowed with the capability reads
// the key; (b) refused with no capability at all; (c) refused with a
// forged handle (a real grant of a DIFFERENT kind, reinterpreted); (d)
// refused with a buffer one byte short of `LINK_KEY_BYTES`, proved not to
// have reached the hook at all.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_ipc::cap::targets::{Buzzer, LinkKey};
use azos_ipc::cap::Cap;
use std::sync::atomic::{AtomicU32, Ordering};

/// The cap-store pool slot every caller in this file is bound to. `MAX_TASKS`
/// is 64 (0..=63 valid, `crates/core/ipc/src/cap_store.rs`'s own doc) — 64 itself
/// is OUT OF RANGE and `slot_for` refuses it, which is not a hypothetical:
/// this file first shipped with `SLOT = 64` and every grant in it silently
/// returned `None`. 22 and 51-63 are taken by other files in this crate; 45
/// is not.
const SLOT: usize = 45;

/// TIDs no other file in this crate uses.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e00_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// The known-good key `ok_hook` hands back.
const TEST_KEY: [u8; crate::link_key::LINK_KEY_BYTES] = [0x42; crate::link_key::LINK_KEY_BYTES];

fn ok_hook(out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    *out = TEST_KEY;
    true
}

/// Wired into the buffer-too-small test: if this ever ran, it would answer
/// `-EAUTH` (a different, wrong code from `-EINVAL`), so its presence is
/// what proves the short-buffer check runs BEFORE the hook, not just that
/// `rc` happens to be `-EINVAL`.
fn absent_hook(_out: &mut [u8; crate::link_key::LINK_KEY_BYTES]) -> bool {
    false
}

/// Bind `tid` as a kernel-context caller with an empty capability table.
/// Kernel context (`user_pt == 0`, which `serial()`'s reset already leaves
/// it at) is deliberate, not incidental: the handler's own doc says a
/// kernel caller is expected to pass a kernel-space pointer directly
/// (`sensor_write_to_user`'s convention), which is exactly what a plain
/// stack buffer in this test is — no page table needed.
///
/// Two task tables: `cap_store` resolves TIDs through `ipc_task_pool`, the
/// handler asks this crate's `shims/sched`. See `hw_cap_guards.rs`'s
/// `as_user` for the same split.
fn as_kernel_caller(tid: u32) {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
}

fn grant_link_key(tid: u32, perms: CapPerms) -> Cap<LinkKey> {
    azos_ipc::cap_store::grant::<LinkKey>(tid, perms, 0)
        .expect("grant must succeed against a fresh test task")
}

fn call(cap_raw: u64, buf: &mut [u8]) -> i64 {
    crate::link_key::sys_link_key_read_typed(cap_raw, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// (a) Pass: a holder of `Cap<LinkKey>` READ with a big-enough buffer and a
/// working hook gets the exact 32 bytes back.
///
/// **Canary.** Swap `TEST_KEY` for a different array in `ok_hook`: the
/// second assertion fails. Return `false` from `ok_hook`: the first
/// assertion reads `-EAUTH` instead of 32.
#[test]
fn allowed_with_cap_reads_the_key() {
    let _g = serial();
    let tid = fresh_tid();
    as_kernel_caller(tid);
    crate::link_key::set_link_key_read_hook(ok_hook);
    let cap = grant_link_key(tid, CapPerms::READ);

    let mut buf = [0u8; crate::link_key::LINK_KEY_BYTES];
    let rc = call(cap.raw().as_raw() as u64, &mut buf);

    assert_eq!(rc, crate::link_key::LINK_KEY_BYTES as i64, "must report the byte count on success");
    assert_eq!(buf, TEST_KEY, "must copy exactly the hook's bytes, no truncation/reorder");
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (b) Refused: no capability at all (the null handle) never reaches the
/// hook. Anchored on `-ECAPSTALE`, which only the refusal path produces — a
/// hook that ran anyway would instead answer `LINK_KEY_BYTES` or `-EAUTH`,
/// neither of which is this value.
///
/// **Canary.** Skip the cap check in `sys_link_key_read_typed`: this reads
/// `LINK_KEY_BYTES` instead.
#[test]
fn refused_without_cap() {
    let _g = serial();
    let tid = fresh_tid();
    as_kernel_caller(tid);
    crate::link_key::set_link_key_read_hook(ok_hook);

    let mut buf = [0u8; crate::link_key::LINK_KEY_BYTES];
    let rc = call(azos_abi::cap::CAP_NULL.as_raw() as u64, &mut buf);

    assert_eq!(rc, Errno::ECAPSTALE.to_syscall_ret(), "the null handle must resolve as stale, not silently pass");
    assert_eq!(buf, [0u8; crate::link_key::LINK_KEY_BYTES], "the buffer must be untouched when the cap check refuses first");
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (c) Refused: a forged handle — the bit pattern of a capability the task
/// genuinely holds, but of a DIFFERENT kind (`Buzzer`), reinterpreted as
/// `Cap<LinkKey>`. `cap_store::get`'s kind check must catch this: a slot
/// that decodes with `CapKind::LinkKey`'s tag but was never granted as one
/// is exactly the confusion `Cap<T>`'s forgery resistance exists to close
/// (module doc, `crates/core/ipc/src/cap.rs`).
///
/// **Canary.** Drop the kind check from `cap_store::get_uncontained`: this
/// reads `LINK_KEY_BYTES` instead of `-ECAPKIND`.
#[test]
fn refused_with_forged_handle() {
    let _g = serial();
    let tid = fresh_tid();
    as_kernel_caller(tid);
    crate::link_key::set_link_key_read_hook(ok_hook);
    // A real grant of a DIFFERENT kind, so the generation/slot are live —
    // the forgery is purely in the kind tag, not in a stale/garbage handle
    // (that is `refused_without_cap`'s job).
    let other: Cap<Buzzer> = azos_ipc::cap_store::grant(tid, CapPerms::READ, 0)
        .expect("grant of a different kind must succeed");

    let mut buf = [0u8; crate::link_key::LINK_KEY_BYTES];
    let rc = call(other.raw().as_raw() as u64, &mut buf);

    assert_eq!(rc, Errno::ECAPKIND.to_syscall_ret(), "a handle of a different kind must be refused as a kind mismatch, not accepted");
    assert_eq!(buf, [0u8; crate::link_key::LINK_KEY_BYTES]);
    crate::link_key::__link_key_read_hook_clear_for_tests();
}

/// (d) Refused: a genuinely-held `Cap<LinkKey>` READ, but a buffer one byte
/// shorter than `LINK_KEY_BYTES`. Must answer `-EINVAL` and must NOT call
/// the hook at all — proved by wiring `absent_hook` (which would make a
/// call that reached it answer `-EAUTH`, a different, wrong code) rather
/// than merely asserting on `rc`.
///
/// **Canary.** Drop the length check: this reads `-EAUTH` (from
/// `absent_hook`) instead of `-EINVAL`.
#[test]
fn buffer_too_small_refused() {
    let _g = serial();
    let tid = fresh_tid();
    as_kernel_caller(tid);
    crate::link_key::set_link_key_read_hook(absent_hook);
    let cap = grant_link_key(tid, CapPerms::READ);

    let mut buf = [0u8; crate::link_key::LINK_KEY_BYTES - 1];
    let rc = call(cap.raw().as_raw() as u64, &mut buf);

    assert_eq!(rc, Errno::EINVAL.to_syscall_ret(), "a short buffer must be refused before the hook ever runs");
    crate::link_key::__link_key_read_hook_clear_for_tests();
}
