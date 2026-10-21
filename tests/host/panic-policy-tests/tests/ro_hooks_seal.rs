// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The seal (`azos_common::hook::seal`): after it, every set is refused and
//! `Hook::set` panics naming the hook. One test, one process: sealing is
//! global, and this file's other tests would turn into refusals.

use azos_common::hook::{is_sealed, seal, Hook, SetError};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn boot_fn() -> u32 { 1 }
fn late_fn() -> u32 { 2 }

#[test]
fn a_hook_set_after_the_seal_panics_with_its_name() {
    let before: Hook<fn() -> u32> = Hook::new("BEFORE_SEAL");
    let never: Hook<fn() -> u32> = Hook::new("NEVER_SET");
    before.set(boot_fn);
    assert!(!is_sealed());

    seal();
    assert!(is_sealed());

    // The installed function still answers.
    assert_eq!(before.get().unwrap()(), 1);

    // Every route in is shut: a new hook, an installed hook with a new
    // function, and an installed hook with the SAME function.
    assert_eq!(never.try_set(late_fn), Err(SetError::Sealed));
    assert_eq!(before.try_set(late_fn), Err(SetError::Sealed));
    assert_eq!(before.try_set(boot_fn), Err(SetError::Sealed));
    assert!(never.get().is_none());
    assert_eq!(before.get().unwrap()(), 1, "the sealed value must not move");

    // `set` is the boot's call: it panics, and the message names the hook.
    let err = catch_unwind(AssertUnwindSafe(|| never.set(late_fn))).expect_err("set after the seal must panic");
    let msg = err.downcast_ref::<String>().cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    assert!(msg.contains("NEVER_SET") && msg.contains("seal"), "panic record was: {msg}");
    assert!(never.get().is_none());
}
