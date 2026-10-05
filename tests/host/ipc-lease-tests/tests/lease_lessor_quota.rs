// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A ring-3 lessor may occupy at most `MAX_LEASES_PER_LESSOR` lease entries.
//!
//! `LEASES` is one table for the whole machine. A task that owns a single
//! region could grant it `MAX_LEASES` times and leave every other lessor
//! without a slot. Owner decision 2026-09-14: half the table per lessor TID,
//! counted as occupancy (every non-`Free` entry naming the lessor: `Pending`,
//! `Active`, `Returned`, `Expired`), refused with `-EQUOTA` (the multicast
//! precedent), kernel grants exempt.
//!
//! **A binary of its own**, for the reason `lease_grant_authority.rs` gives:
//! a ring-3 grant needs a real region, and regions take pages from
//! `shims/mm`, whose counts the library's io_ring suite asserts on.

use azos_abi::error::Errno;
use azos_ipc_lease_tests::lease::{
    lease_accept, lease_free, lease_grant_as, lease_is_returned, lease_return, lease_tick,
    LeaseGrantError, MAX_LEASES, MAX_LEASES_PER_LESSOR,
};
use azos_ipc_lease_tests::cap::{objref, CapPerms};
use azos_ipc_lease_tests::cap_store;
use azos_ipc_lease_tests::shm::{shm_create_cap, shm_owner, shm_release, ShmPerms};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::thread;

static SERIAL: Mutex<()> = Mutex::new(());

const A: u32 = 31;
const B: u32 = 32;
const LESSEE: u32 = 33;

/// Take the suite lock, empty the lease table and reset the scheduler shim.
fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    clear_table();
    cap_store::reset(A);
    cap_store::reset(B);
    azos_sched::shim_reset();
    g
}

/// `lease_free` with the kernel bypass is the one public way to clear a slot.
fn clear_table() {
    for i in 0..MAX_LEASES {
        lease_free(i, 0, true);
    }
}

/// A one-page region owned by `owner`, released on drop.
struct Region {
    owner: u32,
    id: u32,
}

impl Region {
    fn new(owner: u32) -> Self {
        // Created with its `Cap<Shm>`: a ring-3 grant needs one.
        let cap = shm_create_cap(owner, 1, ShmPerms::ReadWrite).expect("a one-page region");
        let r = cap_store::get(owner, cap, CapPerms::READ).expect("the creator holds its capability");
        let id = objref::SHM.idx(r);
        assert_eq!(shm_owner(id), Some(owner));
        Region { owner, id }
    }

    /// A ring-3 grant of this region by its owner to `LESSEE`.
    fn grant(&self) -> Result<usize, LeaseGrantError> {
        lease_grant_as(self.id as usize, self.owner, LESSEE, 0, false)
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let _ = shm_release(self.owner, self.id);
    }
}

#[test]
fn the_quota_is_half_the_table_and_leaves_room_for_another_lessor() {
    assert_eq!(MAX_LEASES_PER_LESSOR, MAX_LEASES / 2);
    assert!(MAX_LEASES_PER_LESSOR >= 1);
    assert!(MAX_LEASES_PER_LESSOR < MAX_LEASES);
}

/// Canary: `>=` → `>` on the quota bound (the ninth is granted); or count
/// only `Active` (every lease here is `Pending`, so the count reads 0).
#[test]
fn a_lessor_past_its_quota_is_refused_and_another_lessor_is_not() {
    let _g = serial();
    let ra = Region::new(A);
    let rb = Region::new(B);

    for i in 0..MAX_LEASES_PER_LESSOR {
        ra.grant().unwrap_or_else(|e| panic!("grant {i}, below the quota, refused: {e:?}"));
    }
    assert_eq!(
        ra.grant(),
        Err(LeaseGrantError::Quota),
        "a lessor was granted one lease past its quota"
    );
    // A refusal writes nothing and wakes nobody: one wake per granted lease.
    assert_eq!(azos_sched::shim_lease_accept_wakes().len(), MAX_LEASES_PER_LESSOR);

    // The refusal is A's quota, not a full table: B still gets a lease.
    let from_b = rb.grant().expect("another lessor was refused while A sat at its quota");
    assert_eq!(lease_accept(LESSEE, B).map(|(id, _)| id), Some(from_b));
    // And B's lease did not change A's count.
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota));

    // Exactly the quota's worth of A's leases exist.
    let mut from_a = 0;
    while lease_accept(LESSEE, A).is_some() {
        from_a += 1;
    }
    assert_eq!(from_a, MAX_LEASES_PER_LESSOR);
}

/// Canary: `lease_free` answers `true` for the lessor without clearing the
/// entry (it stays `Pending`, so the quota never comes back).
#[test]
fn freeing_a_lease_gives_its_quota_back() {
    let _g = serial();
    let ra = Region::new(A);
    let ids: Vec<usize> = (0..MAX_LEASES_PER_LESSOR).map(|_| ra.grant().unwrap()).collect();
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota));

    // A refused free gives nothing back.
    assert!(!lease_free(ids[3], B, false));
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota));

    assert!(lease_free(ids[3], A, false));
    ra.grant().expect("a freed lease did not give its quota back");
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota), "one free bought two grants");
}

/// Canary: count only `Pending` (the second refusal, all `Active`, is then
/// granted). The all-`Pending` half is the test above.
#[test]
fn pending_and_active_leases_both_count() {
    let _g = serial();
    let ra = Region::new(A);
    // Every other grant accepted: a mix of `Active` and `Pending`.
    for i in 0..MAX_LEASES_PER_LESSOR {
        ra.grant().unwrap();
        if i % 2 == 0 {
            lease_accept(LESSEE, A).expect("a pending lease");
        }
    }
    assert_eq!(
        ra.grant(),
        Err(LeaseGrantError::Quota),
        "a mix of Pending and Active leases escaped the quota"
    );

    // All of them `Active`.
    while lease_accept(LESSEE, A).is_some() {}
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota), "Active leases escaped the quota");
}

/// Occupancy, not in flight: a `Returned` entry still holds its slot, so it
/// stays charged to its lessor until the lessor frees it.
///
/// Canary: count only `Pending | Active` (the in-flight predicate). The grant
/// right after the return is then accepted.
#[test]
fn a_returned_lease_stays_charged_until_its_lessor_frees_it() {
    let _g = serial();
    let ra = Region::new(A);
    let ids: Vec<usize> = (0..MAX_LEASES_PER_LESSOR).map(|_| ra.grant().unwrap()).collect();
    while lease_accept(LESSEE, A).is_some() {}
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota));

    assert_eq!(lease_return(ids[0], LESSEE, false), Some(A));
    assert_eq!(
        ra.grant(),
        Err(LeaseGrantError::Quota),
        "a Returned lease stopped counting against its lessor"
    );

    // What gives the slot back is the lessor's free, not the return.
    assert!(lease_free(ids[0], A, false));
    ra.grant().expect("freeing a Returned lease did not give its quota back");
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota), "one free bought two grants");
}

/// `Expired` is charged as `Returned` is: the timer ISR's expiry leaves the
/// entry allocated for the lessor to free.
///
/// Canary: the in-flight predicate. The grant after the tick is then accepted.
#[test]
fn an_expired_lease_stays_charged_until_its_lessor_frees_it() {
    const DEADLINE: u64 = 10;
    let _g = serial();
    let ra = Region::new(A);
    let ids: Vec<usize> = (0..MAX_LEASES_PER_LESSOR)
        .map(|i| {
            lease_grant_as(ra.id as usize, A, LESSEE, DEADLINE, false)
                .unwrap_or_else(|e| panic!("grant {i}, below the quota, refused: {e:?}"))
        })
        .collect();

    let mut expired = [0u32; MAX_LEASES];
    assert_eq!(lease_tick(DEADLINE, &mut expired), MAX_LEASES_PER_LESSOR);
    assert!(ids.iter().all(|&id| lease_is_returned(id)), "the tick did not expire every lease");

    assert_eq!(
        ra.grant(),
        Err(LeaseGrantError::Quota),
        "Expired leases stopped counting against their lessor"
    );
    assert!(lease_free(ids[5], A, false));
    ra.grant().expect("freeing an Expired lease did not give its quota back");
    assert_eq!(ra.grant(), Err(LeaseGrantError::Quota), "one free bought two grants");
}

/// The cycle occupancy closes. One task leases its own region to itself,
/// accepts, returns, and grants again. Counted in flight, every round left an
/// uncharged `Returned` entry behind and the task filled the whole table, so
/// every other lessor got `NoSlot`. Counted as occupancy, the grant that would
/// occupy a ninth entry is refused with `-EQUOTA`, and another lessor still
/// gets a slot.
///
/// Canary: restore the in-flight predicate (`Pending | Active`). All
/// `MAX_LEASES` rounds are then granted, and B is refused with `NoSlot`.
#[test]
fn a_grant_accept_return_cycle_cannot_fill_the_table() {
    let _g = serial();
    let ra = Region::new(A);

    let mut rounds = 0;
    let mut refusal = None;
    for _ in 0..MAX_LEASES {
        match lease_grant_as(ra.id as usize, A, A, 0, false) {
            Ok(id) => {
                assert_eq!(lease_accept(A, A).map(|(l, _)| l), Some(id));
                assert_eq!(lease_return(id, A, false), Some(A));
                rounds += 1;
            }
            Err(e) => {
                refusal = Some(e);
                break;
            }
        }
    }
    assert_eq!(
        (rounds, refusal),
        (MAX_LEASES_PER_LESSOR, Some(LeaseGrantError::Quota)),
        "a grant/accept/return cycle occupied {rounds} entries against a quota of \
         {MAX_LEASES_PER_LESSOR}, then answered {refusal:?}"
    );
    assert_eq!(
        refusal.map(LeaseGrantError::syscall_ret),
        Some(Errno::EQUOTA.to_syscall_ret()),
        "the refusal did not surface as -EQUOTA"
    );

    // The table still has room, for someone else.
    let rb = Region::new(B);
    let from_b = rb.grant().expect("another lessor was refused after A's cycle");
    assert_eq!(lease_accept(LESSEE, B).map(|(id, _)| id), Some(from_b));
}

/// Kernel grants are exempt, and a kernel grant never answers `Quota`: past
/// the table it is `NoSlot`. The entries a kernel grant stamps with a lessor's
/// TID are still occupied by that lessor, so they count against its own
/// ring-3 grants.
///
/// Canary: drop `!privileged &&` from the quota test (the tenth kernel grant
/// is refused with `Quota`).
#[test]
fn a_kernel_grant_is_exempt_but_counts_against_the_lessor_it_names() {
    let _g = serial();
    for i in 0..MAX_LEASES {
        lease_grant_as(0, A, LESSEE, 0, true)
            .unwrap_or_else(|e| panic!("kernel grant {i} refused: {e:?}"));
    }
    assert_eq!(lease_grant_as(0, A, LESSEE, 0, true), Err(LeaseGrantError::NoSlot));

    // Half the table back; A still holds the other half in flight.
    for i in 0..MAX_LEASES - MAX_LEASES_PER_LESSOR {
        assert!(lease_free(i, A, false));
    }
    let ra = Region::new(A);
    assert_eq!(
        ra.grant(),
        Err(LeaseGrantError::Quota),
        "kernel grants stamped with A were not charged to A's ring-3 grants"
    );
    // A ring-3 lessor with nothing in flight is unaffected.
    Region::new(B).grant().expect("an unrelated lessor was refused");
}

/// The count and the allocation share one `LEASES` hold. Split them and two
/// grants from one lessor can read the same count below the quota and both
/// allocate.
///
/// Statistical canary: take the count under one `lock_irqsave`, drop it, and
/// allocate under a second one.
#[test]
fn concurrent_grants_by_one_lessor_never_pass_the_quota() {
    const THREADS: usize = 8;
    const EACH: usize = 4; // 32 attempts: over the quota, and over the table
    const ROUNDS: usize = 200;
    let _g = serial();
    let ra = Region::new(A);
    let shm = ra.id as usize;

    for round in 0..ROUNDS {
        clear_table();
        let start = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    (0..EACH)
                        .filter(|_| lease_grant_as(shm, A, LESSEE, 0, false).is_ok())
                        .count()
                })
            })
            .collect();
        let won: usize = workers.into_iter().map(|w| w.join().unwrap()).sum();
        assert_eq!(
            won, MAX_LEASES_PER_LESSOR,
            "round {round}: {won} grants succeeded against a quota of {MAX_LEASES_PER_LESSOR}"
        );
    }
}
