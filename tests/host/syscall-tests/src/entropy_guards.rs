// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `SYS_ENTROPY_READ_TYPED` (596, wave 9 P9) —
// `crates/core/syscall/src/entropy.rs::sys_entropy_read_typed`.
//
// Included inside `mod handlers { .. }` like `link_key_guards.rs`, and reaches
// the handler through `crate::entropy::...` for the same reason that file
// gives.
//
// Every test counts the fill hook's calls, so "refused before the pool was
// touched" is asserted, not inferred from the return code.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_ipc::cap::targets::{Entropy, LinkKey};
use azos_ipc::cap::Cap;
use std::sync::atomic::{AtomicU32, Ordering};

/// Cap-store pool slot for this file; no other file in this crate binds 44.
const SLOT: usize = 44;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e40_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

static FILLS: AtomicU32 = AtomicU32::new(0);
static RECORDED: AtomicU32 = AtomicU32::new(0);
static RECORDED_TID: AtomicU32 = AtomicU32::new(0);

/// A seeded pool: byte `i` is `0xA0 ^ i`.
fn seeded_fill(out: &mut [u8]) -> bool {
    FILLS.fetch_add(1, Ordering::SeqCst);
    for (i, b) in out.iter_mut().enumerate() {
        *b = 0xA0 ^ (i as u8);
    }
    true
}

/// An unseeded pool: writes nothing, refuses.
fn unseeded_fill(_out: &mut [u8]) -> bool {
    FILLS.fetch_add(1, Ordering::SeqCst);
    false
}

/// A fill that wrote a prefix and then refused (`Pool::fill` across the
/// reseed interval). Nothing it wrote may reach the caller.
fn partial_fill(out: &mut [u8]) -> bool {
    FILLS.fetch_add(1, Ordering::SeqCst);
    for b in out.iter_mut() {
        *b = 0x5A;
    }
    false
}

fn recorder(tid: u32) {
    RECORDED.fetch_add(1, Ordering::SeqCst);
    RECORDED_TID.store(tid, Ordering::SeqCst);
}

fn setup(fill: Option<fn(&mut [u8]) -> bool>) -> u32 {
    crate::entropy::__entropy_clear_for_tests();
    FILLS.store(0, Ordering::SeqCst);
    RECORDED.store(0, Ordering::SeqCst);
    RECORDED_TID.store(0, Ordering::SeqCst);
    if let Some(f) = fill {
        crate::entropy::set_entropy_hooks(f, recorder);
    }
    let tid = fresh_tid();
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn grant(tid: u32, perms: CapPerms) -> u64 {
    let c: Cap<Entropy> = azos_ipc::cap_store::grant(tid, perms, 0)
        .expect("grant must succeed against a fresh test task");
    c.raw().as_raw() as u64
}

fn call(cap: u64, buf: &mut [u8]) -> i64 {
    crate::entropy::sys_entropy_read_typed(cap, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// A holder of `Cap<Entropy>` READ on a seeded pool gets exactly the bytes
/// the pool produced, and the count.
///
/// **Canary.** Copy `buf[..len]` after the wipe instead of before it: the
/// byte assertion reads zeros.
#[test]
fn seeded_pool_fills_the_buffer() {
    let _g = serial();
    let tid = setup(Some(seeded_fill));
    let cap = grant(tid, CapPerms::READ);

    let mut buf = [0u8; 32];
    assert_eq!(call(cap, &mut buf), 32);
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(*b, 0xA0 ^ (i as u8), "byte {i} is not the pool's");
    }
    assert_eq!(FILLS.load(Ordering::SeqCst), 1);
    assert_eq!(RECORDED.load(Ordering::SeqCst), 0, "a successful read records nothing");
    crate::entropy::__entropy_clear_for_tests();
}

/// The bound is inclusive at `ENTROPY_READ_MAX` and refuses one past it and
/// zero, without touching the pool.
///
/// **Canary.** Change the bound to `>=`: the 256-byte read answers `-EINVAL`.
#[test]
fn length_bound_is_checked_before_the_pool() {
    let _g = serial();
    let tid = setup(Some(seeded_fill));
    let cap = grant(tid, CapPerms::READ);

    let mut max = [0u8; crate::entropy::ENTROPY_READ_MAX];
    assert_eq!(call(cap, &mut max), crate::entropy::ENTROPY_READ_MAX as i64);
    assert_eq!(FILLS.load(Ordering::SeqCst), 1);

    let mut over = [0u8; crate::entropy::ENTROPY_READ_MAX + 1];
    assert_eq!(call(cap, &mut over), Errno::EINVAL.to_syscall_ret());
    let mut empty = [0u8; 0];
    assert_eq!(call(cap, &mut empty), Errno::EINVAL.to_syscall_ret());
    assert_eq!(crate::entropy::sys_entropy_read_typed(cap, 0, 16), Errno::EINVAL.to_syscall_ret(),
        "a null pointer is refused");
    assert_eq!(FILLS.load(Ordering::SeqCst), 1, "no refused length may reach the pool");
    assert!(over.iter().all(|b| *b == 0));
    crate::entropy::__entropy_clear_for_tests();
}

/// No capability, a capability of another kind, and one without READ are
/// refused by the capability check, before the pool.
///
/// **Canary.** Skip the `cap_store::get` call: the null handle reads 16.
#[test]
fn capability_is_checked_first() {
    let _g = serial();
    let tid = setup(Some(seeded_fill));
    let mut buf = [0u8; 16];

    assert_eq!(call(azos_abi::cap::CAP_NULL.as_raw() as u64, &mut buf),
               Errno::ECAPSTALE.to_syscall_ret());

    let other: Cap<LinkKey> = azos_ipc::cap_store::grant(tid, CapPerms::READ, 0)
        .expect("grant of a different kind must succeed");
    assert_eq!(call(other.raw().as_raw() as u64, &mut buf), Errno::ECAPKIND.to_syscall_ret());

    let wo = grant(tid, CapPerms::WRITE);
    assert_eq!(call(wo, &mut buf), Errno::ECAPPERMS.to_syscall_ret());

    assert_eq!(FILLS.load(Ordering::SeqCst), 0, "a refused capability must not reach the pool");
    assert!(buf.iter().all(|b| *b == 0));
    crate::entropy::__entropy_clear_for_tests();
}

/// An unseeded pool answers `-ENODEV`, writes nothing, and the FIRST refusal
/// of the boot — only the first — goes to the recorder, with the caller's
/// TID. Every refusal is counted.
///
/// **Canary.** Drop the `REFUSAL_RECORDED` swap: `RECORDED` reads 3.
/// Answer `-EAGAIN` instead: the first assertion fails.
#[test]
fn unseeded_pool_refuses_and_records_once() {
    let _g = serial();
    let tid = setup(Some(unseeded_fill));
    let cap = grant(tid, CapPerms::READ);

    let mut buf = [0u8; 32];
    for _ in 0..3 {
        assert_eq!(call(cap, &mut buf), Errno::ENODEV.to_syscall_ret());
    }
    assert!(buf.iter().all(|b| *b == 0), "a refusal writes nothing");
    assert_eq!(RECORDED.load(Ordering::SeqCst), 1, "one record per boot, not one per call");
    assert_eq!(RECORDED_TID.load(Ordering::SeqCst), tid, "the record names the caller");
    assert_eq!(crate::entropy::entropy_refusals(), 3, "every refusal is counted");
    crate::entropy::__entropy_clear_for_tests();
}

/// A fill that wrote a prefix and then refused leaks none of it.
///
/// **Canary.** Copy `buf` out before the `got` check: the caller sees 0x5A.
#[test]
fn a_partial_fill_leaks_nothing() {
    let _g = serial();
    let tid = setup(Some(partial_fill));
    let cap = grant(tid, CapPerms::READ);

    let mut buf = [0u8; 64];
    assert_eq!(call(cap, &mut buf), Errno::ENODEV.to_syscall_ret());
    assert!(buf.iter().all(|b| *b == 0));
    crate::entropy::__entropy_clear_for_tests();
}

/// No fill hook installed fails CLOSED, as an unseeded pool.
///
/// **Canary.** Answer `len` when the hook is `None`: this reads 16.
#[test]
fn no_hook_fails_closed() {
    let _g = serial();
    let tid = setup(None);
    let cap = grant(tid, CapPerms::READ);

    let mut buf = [0u8; 16];
    assert_eq!(call(cap, &mut buf), Errno::ENODEV.to_syscall_ret());
    assert!(buf.iter().all(|b| *b == 0));
    assert_eq!(crate::entropy::entropy_refusals(), 1);
    crate::entropy::__entropy_clear_for_tests();
}
