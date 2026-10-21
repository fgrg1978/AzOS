// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The native futex calls' edge (`vdso_notify::sys_futex_wait` / `_wake`):
// which key a word gets and what is refused before the table is asked. The
// table (`futex_table.rs`) is proved by its own tests; the cross-address-space
// meeting of a shm word is proved in ring 3 (IPCTEST phase R), because it
// needs two page tables and a real region mapped in both.
//
// The caller is a kernel task (`user_pt == 0`): the shim's `copy_from_user`
// then reads the host address itself, so a host `AtomicU32` is a readable
// "user word". An unreadable word needs a page table this crate does not
// build; ring 3 covers it (`R/futex wake (unmapped) [EFAULT]`).

use super::harness::serial;
use azos_sched::futex::{shim_set_wake_answer, shim_take_calls, Call, Key};
use core::sync::atomic::AtomicU32;

const TID: u32 = 0x6B00_0001;

fn caller() {
    azos_sched::set_current_task_tid(TID);
    azos_sched::set_current_proc_tid(0);
    azos_sched::set_current_user_pt(0);
    shim_take_calls();
}

/// A word the shim can read, 4-aligned (an `AtomicU32` is).
fn word(v: u32) -> &'static AtomicU32 {
    Box::leak(Box::new(AtomicU32::new(v)))
}

#[test]
fn a_misaligned_word_is_einval_before_the_table_is_asked() {
    let _g = serial();
    caller();
    let w = word(1);
    let a = w as *const AtomicU32 as u64;
    assert_eq!(crate::vdso_notify::sys_futex_wait(a + 1, 1, 0), -22);
    assert_eq!(crate::vdso_notify::sys_futex_wake(a + 2, 1), -22);
    assert!(shim_take_calls().is_empty(), "a misaligned word reached the futex table");
}

/// A word in no shm region the caller maps is keyed by the PROCESS: the
/// threads of one process meet on it, nobody else does.
#[test]
fn a_word_outside_every_region_is_keyed_by_the_process() {
    let _g = serial();
    caller();
    azos_sched::set_current_proc_tid(0x6B00_00FF);
    let w = word(5);
    let a = w as *const AtomicU32 as u64;
    shim_set_wake_answer(3);
    assert_eq!(crate::vdso_notify::sys_futex_wake(a, 2), 3, "the wake answers how many the table woke");
    assert_eq!(crate::vdso_notify::sys_futex_wait(a, 5, 0), 0);
    let key = Key::Private { domain: 0x6B00_00FF, addr: a };
    assert_eq!(
        shim_take_calls(),
        vec![
            Call { is_wait: false, key, arg: 2, deadline: None },
            Call { is_wait: true, key, arg: 5, deadline: None },
        ]
    );
    shim_set_wake_answer(0);
}

/// `expected` is the word's value as the sleeper last saw it; one that differs
/// is `-EAGAIN` and nothing blocks. A timeout of 0 is no timeout; any other is
/// a deadline in the future.
#[test]
fn a_wait_on_a_word_that_differs_is_eagain_and_a_timeout_makes_a_deadline() {
    let _g = serial();
    caller();
    let w = word(9);
    let a = w as *const AtomicU32 as u64;
    assert_eq!(crate::vdso_notify::sys_futex_wait(a, 8, 0), -11);
    assert_eq!(crate::vdso_notify::sys_futex_wait(a, 9, 1_000_000), 0);
    let calls = shim_take_calls();
    assert_eq!(calls[0].deadline, None, "timeout 0 is no deadline");
    assert!(calls[1].deadline.is_some(), "a timeout made no deadline");
}

/// The wide `expected` of a 64-bit caller is the word's 32 bits, as Linux's
/// `val` is.
#[test]
fn expected_is_the_low_32_bits() {
    let _g = serial();
    caller();
    let w = word(7);
    let a = w as *const AtomicU32 as u64;
    assert_eq!(crate::vdso_notify::sys_futex_wait(a, (1u64 << 32) | 7, 0), 0);
    assert_eq!(shim_take_calls()[0].arg, 7);
}

/// The point of the whole surface: a word of a shm region is keyed by (region,
/// offset), not by an address and not by the process, so two tasks that map
/// the region at DIFFERENT addresses meet on one key. A wait also reads the
/// word through the kernel's view of the page (the region's, not the user's).
#[test]
fn a_word_of_a_mapped_region_has_the_same_key_for_every_mapper() {
    use azos_ipc::memobj::{
        memobj_acquire_ref, memobj_create_ref, memobj_note_mapping_ref, memobj_release_all, MapAccess, MemPerms,
    };
    const OTHER: u32 = 0x6B00_0002;
    const VA_A: usize = 0x4000_0000;
    const VA_B: usize = 0x5000_0000;
    let _g = serial();
    caller();
    let r = memobj_create_ref(TID, 1, MemPerms::ReadWrite).expect("create a region");
    assert!(memobj_acquire_ref(OTHER, r).is_ok(), "the second task takes a reference");
    assert_eq!(memobj_note_mapping_ref(TID, r, 0x1000, VA_A, 1, MapAccess::RW), Ok(true));
    assert_eq!(memobj_note_mapping_ref(OTHER, r, 0x1000, VA_B, 1, MapAccess::RW), Ok(true));
    let key = Key::Shared { obj: r, offset: 8 };

    azos_sched::set_current_task_tid(TID);
    azos_sched::set_current_proc_tid(0);
    assert_eq!(crate::vdso_notify::sys_futex_wake((VA_A + 8) as u64, 1), 0);
    azos_sched::set_current_task_tid(OTHER);
    // The kernel reads the (zeroed) word through the region: 0 holds, 1 differs.
    assert_eq!(crate::vdso_notify::sys_futex_wait((VA_B + 8) as u64, 0, 0), 0);
    assert_eq!(crate::vdso_notify::sys_futex_wait((VA_B + 8) as u64, 1, 0), -11);
    // A mapped word is never private: no key names the process or an address.
    assert_eq!(
        shim_take_calls(),
        vec![
            Call { is_wait: false, key, arg: 1, deadline: None },
            Call { is_wait: true, key, arg: 0, deadline: None },
            Call { is_wait: true, key, arg: 1, deadline: None },
        ],
        "the two mappers, at different addresses, did not meet on one key"
    );
    memobj_release_all(TID);
    memobj_release_all(OTHER);
}
