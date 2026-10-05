// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The lease grant (`sys_ipc_lease_grant`, once 111; reached since 2026-09-28
// through the typed `SYS_IPC_LEASE_GRANT_TYPED`, 603, tested at the end of
// this file), `_ACCEPT` (112), `_RETURN` (113) and `_FREE` (114). Their bodies were written inside `dispatch.rs`'s match, which this
// crate cannot compile, until wave 7 moved them into `sys_ipc_lease_*` in
// `handlers.rs`. What is tested here is what those bodies add on top of the
// real `crates/core/ipc/src/lease.rs` (pulled whole into `shims/ipc`): whose
// identity each call passes, the privilege it derives, how each argument is
// narrowed, which reason the accept blocks on, and the code each refusal
// returns. The table's own rules are proved in `tests/host/ipc-lease-tests`.
//
// `LEASES` is a 16-entry process-global table with no reset, so every test
// frees what it allocated before it returns.

use super::harness::serial;

const LESSOR: u32 = 0x6A00_0001;
const LESSEE: u32 = 0x6A00_0002;
const STRANGER: u32 = 0x6A00_0003;
const SHM_ID: u64 = 3;

/// The caller for the next call: `tid`, kernel (`user_pt == 0`) or ring 3.
fn caller(tid: u32, ring3: bool) {
    azos_sched::set_current_task_tid(tid);
    azos_sched::set_current_user_pt(if ring3 { 0xBAD0_0000 } else { 0 });
}

/// A lease from LESSOR to LESSEE granted by a kernel lessor (no `Cap<Shm>`
/// check), with the grant's wake drained.
fn kernel_grant() -> u64 {
    caller(LESSOR, false);
    let id = sys_ipc_lease_grant(SHM_ID, LESSEE as u64, 0);
    assert!(id >= 0, "kernel grant refused: {id}");
    ipc_sched_shim::shim_take_lease_accept_wakes();
    id as u64
}

/// Free `id` as a kernel caller, whatever state it is in.
fn kernel_free(id: u64) {
    caller(LESSOR, false);
    assert_eq!(sys_ipc_lease_free(id), 0);
}

#[test]
fn grant_from_ring3_without_a_shm_capability_is_minus_one() {
    let _g = serial();
    caller(LESSOR, true);
    // The caller holds no `Cap<Shm>` at all: `lease_grant_as` answers
    // `NotOwner`, which the arm reports as -1 (not -EPERM, not -EQUOTA).
    assert_eq!(sys_ipc_lease_grant(SHM_ID, LESSEE as u64, 0), -1);
    assert!(ipc_sched_shim::shim_take_lease_accept_wakes().is_empty(), "a refused grant woke a lessee");
}

#[test]
fn grant_names_the_caller_as_lessor_and_wakes_the_pair() {
    let _g = serial();
    ipc_sched_shim::shim_take_lease_accept_wakes();
    caller(LESSOR, false);
    let id = sys_ipc_lease_grant(SHM_ID, LESSEE as u64, 0);
    assert!(id >= 0);
    // The lessor is the scheduler's current TID, not an argument.
    assert_eq!(ipc_sched_shim::shim_take_lease_accept_wakes(), vec![(LESSEE, LESSOR)]);
    kernel_free(id as u64);
}

/// `a1` is narrowed with `as u32`, as the arm always did: the high half is
/// dropped, never refused. Pinned so the move could not tidy it into the
/// `try_from` the accept uses.
#[test]
fn grant_narrows_the_lessee_to_its_low_32_bits() {
    let _g = serial();
    caller(LESSOR, false);
    let id = sys_ipc_lease_grant(SHM_ID, (1u64 << 32) | LESSEE as u64, 0);
    assert!(id >= 0);
    assert_eq!(ipc_sched_shim::shim_take_lease_accept_wakes(), vec![(LESSEE, LESSOR)]);
    caller(LESSEE, true);
    azos_sched::shim_take_blocks();
    assert_eq!(sys_ipc_lease_accept(LESSOR as u64), id, "the lease went to another lessee");
    kernel_free(id as u64);
}

#[test]
fn round_trip_accept_return_free_and_who_may_do_each() {
    let _g = serial();
    let id = kernel_grant();

    // Accept by the lessee, naming the lessor: pending already, so no block.
    caller(LESSEE, true);
    azos_sched::shim_take_blocks();
    assert_eq!(sys_ipc_lease_accept(LESSOR as u64), id as i64);
    assert!(azos_sched::shim_take_blocks().is_empty(), "blocked on a lease that was pending");

    // Return: only the lessee (IPC-6). A stranger gets -1 and wakes nobody.
    ipc_sched_shim::shim_take_wq_wakes();
    caller(STRANGER, true);
    assert_eq!(sys_ipc_lease_return(id), -1);
    assert!(ipc_sched_shim::shim_take_wq_wakes().is_empty(), "a refused return woke the lessor");
    caller(LESSEE, true);
    assert_eq!(sys_ipc_lease_return(id), 0);
    assert_eq!(ipc_sched_shim::shim_take_wq_wakes(), vec![LESSOR]);

    // Free: only the lessor. The lessee is refused.
    caller(LESSEE, true);
    assert_eq!(sys_ipc_lease_free(id), -1);
    caller(LESSOR, true);
    assert_eq!(sys_ipc_lease_free(id), 0);
    // Gone: a second free is refused.
    assert_eq!(sys_ipc_lease_free(id), -1);
}

/// A kernel caller is `privileged`: return and free bypass the owner check.
#[test]
fn a_kernel_caller_returns_and_frees_a_lease_it_is_not_party_to() {
    let _g = serial();
    let id = kernel_grant();
    caller(LESSEE, true);
    assert_eq!(sys_ipc_lease_accept(LESSOR as u64), id as i64);
    caller(STRANGER, false);
    assert_eq!(sys_ipc_lease_return(id), 0);
    assert_eq!(sys_ipc_lease_free(id), 0);
}

/// `a0` wider than a TID is refused with -1 BEFORE the wait: no registration,
/// no block. A truncating narrowing would name lessor 5 and block eight times.
#[test]
fn accept_refuses_a_wide_lessor_without_blocking() {
    let _g = serial();
    caller(LESSEE, true);
    azos_sched::shim_take_blocks();
    // Bit 32 is the retired accept-and-map flag (-EINVAL, below); bit 33 is
    // still a wide TID.
    assert_eq!(sys_ipc_lease_accept((1u64 << 33) | 5), -1);
    assert!(azos_sched::shim_take_blocks().is_empty(), "a wide lessor was truncated and waited on");
}

/// Wave 11 (LEASE3): accept-and-map is its own number (613) and refuses
/// BEFORE the wait — a wide lessor (`-EINVAL`) and a kernel caller (`-EINVAL`,
/// no address space to map into). The unwritable-out-pointer refusal
/// (`-EFAULT`) walks the caller's page table, which this crate's ring-3 caller
/// does not have (`0xBAD0_0000` is a marker, not a table); ring 3 covers it
/// (IPCTEST phase W maps for real).
#[test]
fn accept_map_refuses_before_the_wait() {
    let _g = serial();
    caller(LESSEE, true);
    azos_sched::shim_take_blocks();
    assert_eq!(sys_ipc_lease_accept_map((1u64 << 33) | 5, 0x1000), -22);
    assert_eq!(sys_ipc_lease_accept_map((1u64 << 32) | LESSOR as u64, 0x1000), -22);
    caller(LESSEE, false);
    assert_eq!(sys_ipc_lease_accept_map(LESSOR as u64, 0x1000), -22,
        "a kernel caller has nothing to map into");
    assert!(azos_sched::shim_take_blocks().is_empty(), "a refused accept-and-map waited");
}

/// Wave 11 (LEASE3): the multiplexed accept-and-map encoding of one
/// integration round (`a0` bit 32 on 112) is refused with `-EINVAL` before
/// the wait, whatever the low half names — never taken as a plain accept.
#[test]
fn the_retired_accept_map_bit_is_einval_without_blocking() {
    use azos_abi::syscall_nr::LEASE_ACCEPT_RETIRED_MAP_BIT;
    let _g = serial();
    caller(LESSEE, true);
    azos_sched::shim_take_blocks();
    assert_eq!(sys_ipc_lease_accept(LEASE_ACCEPT_RETIRED_MAP_BIT | LESSOR as u64), -22);
    assert!(azos_sched::shim_take_blocks().is_empty(), "the retired encoding waited");
}

/// Nothing pending: the arm blocks on `LeaseAccept(lessee, lessor)` — the
/// caller's own TID first — for the table's eight turns, then answers -1.
#[test]
fn accept_with_nothing_pending_blocks_on_the_pair_then_answers_minus_one() {
    let _g = serial();
    caller(LESSEE, true);
    azos_sched::shim_take_blocks();
    assert_eq!(sys_ipc_lease_accept(LESSOR as u64), -1);
    let want = vec![
        azos_sched::WaitReason::LeaseAccept(LESSEE, LESSOR);
        azos_ipc::lease::LEASE_ACCEPT_TURNS as usize
    ];
    assert_eq!(azos_sched::shim_take_blocks(), want);
}

#[test]
fn return_and_free_of_an_out_of_range_id_are_minus_one() {
    let _g = serial();
    caller(LESSEE, false);
    assert_eq!(sys_ipc_lease_return(u64::MAX), -1);
    assert_eq!(sys_ipc_lease_free(azos_ipc::lease::MAX_LEASES as u64), -1);
}

/// Wave 11 (LEASE3): the robust ops left `SYS_NOTIFY_WAIT`'s `a1[32..]` for
/// `SYS_NOTIFY_ROBUST` (612). A wait with anything in the high half is
/// `-EINVAL` before the word is resolved (`0x1000` is mapped by nobody here,
/// so a resolve would answer `-EFAULT`), and an unknown robust op is
/// `-EINVAL` the same way.
#[test]
fn the_retired_robust_encoding_and_an_unknown_op_are_einval() {
    use crate::vdso_notify::{sys_notify_robust, sys_notify_wait};
    let _g = serial();
    caller(LESSEE, true);
    assert_eq!(sys_notify_wait(0x1000, 1u64 << 32, 0), -22, "robust add in 592's high half");
    assert_eq!(sys_notify_wait(0x1000, 2u64 << 32, 0), -22, "robust del in 592's high half");
    assert_eq!(sys_notify_robust(0x1000, 0), -22);
    assert_eq!(sys_notify_robust(0x1000, 3), -22);
    // A known op reaches the resolve: nobody maps 0x1000.
    assert_eq!(sys_notify_robust(0x1000, azos_abi::syscall_nr::NOTIFY_ROBUST_ADD), -14);
}
