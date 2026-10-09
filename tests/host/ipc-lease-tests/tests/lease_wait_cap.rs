// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_IPC_LEASE_WAIT`'s body, `lease_wait_return_as`, and the `Cap<Lease>`
//! lifecycle (wave 9).
//!
//! The syscall arm resolves a `Cap<Lease>` (minted by `SYS_IPC_LEASE_GRANT_TYPED`
//! for a ring-3 lessor) to a lease id and calls `lease_wait_return_as` with the
//! caller named. What this suite pins:
//!
//!  * the lessor check is repeated against the table: a stranger is refused
//!    and donates nothing — the whole reason the wait is gated;
//!  * a lease that is already back answers at once, `Returned` vs `Expired`
//!    told apart, and a free slot is `NoLease` (the host shim panics on a
//!    block, so each of these proves "no block" too);
//!  * `lease_free` revokes the lessor's `Cap<Lease>` for that id and only it.
//!
//! The blocking half (donation for the span of the wait) needs the scheduler:
//! it is the `lease-pi3-smoke` QEMU row.
//!
//! A lessor being killed stops waiting at once (`Killed`, plan item 7).
//!
//! **Canaries (run by hand, wave-9 PROXY2 report):** drop the `NotLessor`
//! check in `lease_wait_return_as` → the stranger test fails (a boost to the
//! lessee is recorded, then the shim panics in the block); drop the revoke in
//! `lease_free` → the revocation test fails (the old handle still resolves).

use azos_ipc_lease_tests::cap::{targets::Lease, CapPerms};
use azos_ipc_lease_tests::cap_store;
use azos_ipc_lease_tests::lease::{
    lease_accept, lease_free, lease_grant, lease_return, lease_tick, lease_wait_return_as,
    LeaseWaitEnd, MAX_LEASES,
};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

const LESSOR: u32 = 21;
const STRANGER: u32 = 22;
const LESSEE: u32 = 23;

fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for i in 0..MAX_LEASES {
        lease_free(i, 0, true);
    }
    for tid in [LESSOR, STRANGER, LESSEE] {
        cap_store::reset(tid);
    }
    azos_sched::shim_reset();
    g
}

/// A kernel-granted lease (no region check) from `LESSOR` to `LESSEE`.
fn grant(expire: u64) -> usize {
    lease_grant(0, LESSOR, LESSEE, expire).expect("a free lease slot")
}

#[test]
fn a_stranger_cannot_wait_on_a_lease_and_donates_nothing() {
    let _g = serial();
    azos_sched::shim_set_priority(STRANGER, 4);
    azos_sched::shim_set_priority(LESSEE, 24);
    let id = grant(0);
    assert_eq!(lease_wait_return_as(id, STRANGER, false), LeaseWaitEnd::NotLessor);
    assert!(azos_sched::shim_boosts().is_empty(), "a stranger's wait boosted the lessee");
}

#[test]
fn a_lease_already_back_answers_at_once() {
    let _g = serial();
    let id = grant(0);
    assert_eq!(lease_accept(LESSEE, LESSOR).map(|(l, _)| l), Some(id));
    assert!(lease_return(id, LESSEE, false).is_some());
    assert_eq!(lease_wait_return_as(id, LESSOR, false), LeaseWaitEnd::Returned);
}

#[test]
fn an_expired_lease_answers_expired() {
    let _g = serial();
    let id = grant(5);
    let mut woken = [u32::MAX; MAX_LEASES];
    let _ = lease_tick(u64::MAX / 2, &mut woken);
    assert_eq!(lease_wait_return_as(id, LESSOR, false), LeaseWaitEnd::Expired);
}

/// A lessor being killed stops waiting (plan item 7): a forced stop wakes it
/// out of the wait, and on a lease that never expires and that nobody returns
/// it would otherwise block again for good, and with it the `exit_group` or
/// exec waiting for it to end. It answers `Killed` without blocking (the
/// shim panics on a block), returns the donation it made, and leaves the
/// lease as it was for its exit hook. Canary `kill-reblock-canary`: the loop
/// blocks again and the shim panics.
#[test]
fn a_killed_lessor_stops_waiting_on_a_lease_nobody_returns() {
    let _g = serial();
    azos_sched::shim_set_priority(LESSOR, 4);
    azos_sched::shim_set_priority(LESSEE, 24);
    let id = grant(0);
    azos_sched::shim_set_killed(true);
    assert_eq!(lease_wait_return_as(id, LESSOR, false), LeaseWaitEnd::Killed);
    assert_eq!(azos_sched::shim_boosts().len(), azos_sched::shim_restores().len(),
               "the killed lessor kept its donation to the lessee");
    azos_sched::shim_set_killed(false);
    assert_eq!(lease_accept(LESSEE, LESSOR).map(|(l, _)| l), Some(id),
               "the killed wait changed the lease");
}

#[test]
fn a_free_slot_and_an_out_of_range_id_are_no_lease() {
    let _g = serial();
    let id = grant(0);
    assert!(lease_free(id, LESSOR, false));
    assert_eq!(lease_wait_return_as(id, LESSOR, false), LeaseWaitEnd::NoLease);
    assert_eq!(lease_wait_return_as(MAX_LEASES, LESSOR, false), LeaseWaitEnd::NoLease);
}

#[test]
fn freeing_a_lease_revokes_its_capability_and_only_it() {
    let _g = serial();
    let a = grant(0);
    let b = grant(0);
    let cap_a = cap_store::grant::<Lease>(LESSOR, CapPerms::READ, a as u32).expect("room");
    let cap_b = cap_store::grant::<Lease>(LESSOR, CapPerms::READ, b as u32).expect("room");
    assert_eq!(cap_store::get(LESSOR, cap_a, CapPerms::READ), Ok(a as u32));
    assert!(lease_free(a, LESSOR, false));
    assert!(cap_store::get(LESSOR, cap_a, CapPerms::READ).is_err(),
            "the freed lease's capability still resolves");
    assert_eq!(cap_store::get(LESSOR, cap_b, CapPerms::READ), Ok(b as u32),
               "another lease's capability was revoked too");
}
