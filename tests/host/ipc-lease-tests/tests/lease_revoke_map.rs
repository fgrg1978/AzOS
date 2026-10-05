// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Leases that bite (wave 11, LEASE2): a lessee's accept-and-map mapping is
//! the lease's, and every way a lease ends removes it.
//!
//! The syscall layer's `SYS_IPC_LEASE_ACCEPT_MAP` (613) is driven here
//! by its steps: `lease_map_target`, a region reference booked under
//! `lease_holder_tid(id)`, `lease_note_map`. The page-table edit is the
//! boot-registered `UnmapHook`; here it records its calls, which is what the
//! assertions read. Each way a lease ends — return, expiry (at the lessor's
//! wake), the lessor's free, the lessor's exit, the lessee's exit, exec —
//! must call it exactly when the lessee's address space outlives the lease,
//! and must give the region reference back (never from the interrupt).
//!
//! **A binary of its own**, as `lease_grant_authority.rs`: real regions take
//! pages from `shims/mm`, which the library binary's io_ring suite counts.
//!
//! **Canary (by hand).** Delete `table.revoke_map(lease_id);` in
//! `lease_return`: `a_return_removes_the_mapping_before_the_lessor_wakes`
//! fails on the hook-call assertion (no PTE removal recorded) and on the
//! reference count (the booked reference is never given back).

use azos_ipc_lease_tests::cap::{CapKind, CapPerms};
use azos_ipc_lease_tests::cap_store;
use azos_ipc_lease_tests::lease::{
    lease_map_info, lease_revoked_rows, lease_accept, lease_exec, lease_free,
    lease_grant_as, lease_holder_tid, lease_map_target, lease_note_map, lease_release_all,
    lease_return, lease_revoked_fault, lease_revoked_faults, lease_take_revoked, lease_tick,
    set_unmap_hook, LeaseMap, Revoked, MAX_LEASES,
    lease_reap_expired, lease_grant_sealed_as, lease_seal_info, set_seal_hook, SealMap,
    lease_sealed_fault, lease_seal_faults,
};
use azos_ipc_lease_tests::shm::{
    shm_acquire_ref, shm_create_cap, shm_info, shm_ref, shm_release, ShmPerms,
};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());
static UNMAPS: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());
static SEALS: Mutex<Vec<(usize, usize, usize, bool)>> = Mutex::new(Vec::new());

fn record_seal(root: usize, va: usize, pages: usize, write: bool) -> usize {
    SEALS.lock().unwrap_or_else(|e| e.into_inner()).push((root, va, pages, write));
    pages
}

fn seals() -> Vec<(usize, usize, usize, bool)> {
    std::mem::take(&mut *SEALS.lock().unwrap_or_else(|e| e.into_inner()))
}

fn record_unmap(root: usize, va: usize, pages: usize) {
    UNMAPS.lock().unwrap_or_else(|e| e.into_inner()).push((root, va, pages));
}

fn unmaps() -> Vec<(usize, usize, usize)> {
    std::mem::take(&mut *UNMAPS.lock().unwrap_or_else(|e| e.into_inner()))
}

const OWNER: u32 = 21;
const LESSEE: u32 = 22;
const ROOT: usize = 0x8123_4000;
const VA: usize = 0x4000_0000;
const PAGE: usize = 4096;

/// No PTE recorded and no reference booked (the address fields may remain).
fn gone(m: LeaseMap) -> bool {
    m.root == 0 && !m.ref_held
}

fn revoked_rows() -> Vec<Revoked> {
    let mut out = [Revoked { tid: 0, lease: 0, va: 0, pages: 0 }; MAX_LEASES];
    let n = lease_revoked_rows(&mut out);
    out[..n].to_vec()
}

fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for i in 0..MAX_LEASES {
        lease_free(i, 0, true);
    }
    // A lessee exit drops any revoked rows a previous test left.
    lease_release_all(LESSEE);
    for tid in [OWNER, LESSEE] {
        cap_store::reset(tid);
    }
    azos_sched::shim_reset();
    set_unmap_hook(record_unmap);
    set_seal_hook(record_seal);
    unmaps();
    seals();
    g
}

/// A one-page region `OWNER` created, so it holds a `Cap<Shm>` with the
/// region's own rights; released (its creation reference) on drop.
struct Region {
    id: u32,
}

impl Region {
    fn new(perms: ShmPerms) -> Self {
        let cap = shm_create_cap(OWNER, 1, perms).expect("a one-page region");
        let r = cap_store::get(OWNER, cap, CapPerms::READ).expect("the creator holds it");
        Region { id: azos_ipc_lease_tests::cap::objref::SHM.idx(r) }
    }
    fn refs(&self) -> u32 {
        shm_info(self.id).map(|i| i.1).unwrap_or(0)
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let _ = shm_release(OWNER, self.id);
    }
}

/// Grant `region` to `LESSEE`, accept it, and map it the way the syscall
/// does. Returns the lease id.
fn grant_accept_map(region: &Region, expire: u64) -> usize {
    let id = lease_grant_as(region.id as usize, OWNER, LESSEE, expire, false).expect("grant");
    assert_eq!(lease_accept(LESSEE, OWNER), Some((id, region.id as usize)));
    let (r, _writable) = lease_map_target(id, LESSEE).expect("an Active lease of the lessee");
    shm_acquire_ref(lease_holder_tid(id), r).expect("the region is live");
    assert!(lease_note_map(id, LESSEE, r, ROOT, VA, 1));
    id
}

#[test]
fn a_return_removes_the_mapping_before_the_lessor_wakes() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 0);
    assert_eq!(region.refs(), 2, "the creator's reference and the lease mapping's");

    assert_eq!(lease_return(id, LESSEE, false), Some(OWNER));
    assert_eq!(unmaps(), vec![(ROOT, VA, 1)], "the lessee's PTEs were removed, once");
    assert!(gone(lease_map_info(id)), "no mapping, no booked reference");
    assert_eq!(region.refs(), 1, "the mapping's reference was given back");
    assert_eq!(
        revoked_rows(),
        vec![Revoked { tid: LESSEE, lease: id as u32, va: VA, pages: 1 }],
        "the window is remembered for the lessee"
    );
    // A second return is refused and removes nothing more.
    assert_eq!(lease_return(id, LESSEE, false), None);
    assert!(unmaps().is_empty());
}

#[test]
fn a_touch_of_a_revoked_window_is_attributed_and_counted() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 0);
    // Not revoked yet: a fault there is not a lease's.
    let before = lease_revoked_faults();
    assert_eq!(lease_revoked_fault(LESSEE, VA), None);
    lease_return(id, LESSEE, false).unwrap();
    assert_eq!(lease_revoked_fault(LESSEE, VA + PAGE - 4), Some(id));
    assert_eq!(lease_revoked_fault(LESSEE, VA + PAGE), None, "past the window");
    assert_eq!(lease_revoked_fault(OWNER, VA), None, "another task's address");
    assert_eq!(lease_revoked_faults(), before + 1);
    // The lessee reaps the window (its next accept-and-map does).
    let mut out = [(0usize, 0usize); 4];
    assert_eq!(lease_take_revoked(LESSEE, &mut out), 1);
    assert_eq!(out[0], (VA, 1));
    assert_eq!(lease_revoked_fault(LESSEE, VA), None, "reaped windows are no longer attributed");
}

#[test]
fn a_lessor_free_revokes_a_live_lessees_mapping() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 0);
    assert!(lease_free(id, OWNER, false));
    assert_eq!(unmaps(), vec![(ROOT, VA, 1)]);
    assert_eq!(region.refs(), 1);
    assert_eq!(revoked_rows().len(), 1);
}

/// The timer interrupt only marks the expiry (no page-table walk there: the
/// kernel-table guard takes a plain lock). The lessor's wake removes the
/// mapping and gives the reference back; a lessor that frees without waiting
/// does the same at its free.
#[test]
fn an_expiry_is_revoked_at_the_lessors_wake_not_in_the_tick() {
    use azos_ipc_lease_tests::lease::{lease_wait_return_as, LeaseWaitEnd};
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 100);
    let mut expired = [0u32; MAX_LEASES];
    assert_eq!(lease_tick(99, &mut expired), 0);
    assert_eq!(lease_tick(100, &mut expired), 1);
    assert_eq!(expired[0], OWNER);
    assert!(unmaps().is_empty(), "no page-table edit in the tick");
    assert_eq!(region.refs(), 2);
    assert_eq!(lease_wait_return_as(id, OWNER, false), LeaseWaitEnd::Expired);
    assert_eq!(unmaps(), vec![(ROOT, VA, 1)], "removed at the lessor's wake");
    assert_eq!(region.refs(), 1);
    assert!(lease_free(id, OWNER, false));
    assert!(unmaps().is_empty(), "nothing left to remove");

    let id = grant_accept_map(&region, 200);
    assert_eq!(lease_tick(200, &mut expired), 1);
    assert!(lease_free(id, OWNER, false));
    assert_eq!(unmaps(), vec![(ROOT, VA, 1)], "a free without a wait removes it");
    assert_eq!(region.refs(), 1);
}

#[test]
fn a_lessors_exit_revokes_and_frees() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 0);
    lease_release_all(OWNER);
    assert_eq!(unmaps(), vec![(ROOT, VA, 1)], "the live lessee loses its mapping");
    assert_eq!(region.refs(), 1);
    assert!(gone(lease_map_info(id)));
    assert!(!lease_free(id, OWNER, true), "the entry was freed by the exit");
}

/// A dying lessee's PTEs are removed before its reference is given back (the
/// exit hook need not run on the hart the task last ran on), and its windows
/// are dropped with it.
#[test]
fn a_lessees_exit_removes_its_mapping_then_gives_the_reference_back() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let first = grant_accept_map(&region, 0);
    lease_return(first, LESSEE, false).unwrap();
    unmaps();
    let id = grant_accept_map(&region, 0);
    assert_eq!(region.refs(), 2);
    lease_release_all(LESSEE);
    assert_eq!(unmaps(), vec![(ROOT, VA, 1)], "removed before the reference goes");
    assert_eq!(region.refs(), 1);
    assert!(gone(lease_map_info(id)));
    assert!(revoked_rows().is_empty(), "its windows died with it");
}

#[test]
fn an_exec_drops_the_mapping_and_keeps_the_lease() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 0);
    lease_exec(LESSEE);
    assert!(unmaps().is_empty(), "the old root is freed by the exec hand-off");
    assert_eq!(region.refs(), 1);
    assert!(gone(lease_map_info(id)));
    assert_eq!(lease_return(id, LESSEE, false), Some(OWNER), "the lease is still the lessee's");
    assert!(unmaps().is_empty(), "nothing to remove at the return");
}

/// The mapping is writable only if the lessor could write: a lessor holding
/// the region with `READ` alone hands out a read-only mapping.
#[test]
fn a_lease_never_hands_out_more_than_its_lessor_had() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 0);
    assert_eq!(lease_map_target(id, LESSEE), None, "already mapped");
    lease_return(id, LESSEE, false).unwrap();

    const READER: u32 = 23;
    cap_store::reset(READER);
    let r = shm_ref(region.id).unwrap();
    assert!(cap_store::with_table(READER, |t| t.grant_raw(CapKind::Shm, CapPerms::READ, r))
        .flatten()
        .is_some());
    let id = lease_grant_as(region.id as usize, READER, LESSEE, 0, false).expect("READ leases");
    assert_eq!(lease_map_target(id, LESSEE), None, "Pending: not accepted yet");
    lease_accept(LESSEE, READER).unwrap();
    assert_eq!(lease_map_target(id, OWNER), None, "not the lessee");
    assert_eq!(lease_map_target(id, LESSEE), Some((r, false)), "read-only for a READ lessor");
    lease_free(id, READER, false);
    cap_store::reset(READER);

    let id = lease_grant_as(region.id as usize, OWNER, LESSEE, 0, false).unwrap();
    lease_accept(LESSEE, OWNER).unwrap();
    assert_eq!(lease_map_target(id, LESSEE), Some((r, true)), "writable for a READ|WRITE lessor");
}

/// A mapping noted after the lease ended is refused, so the caller undoes it.
#[test]
fn a_map_noted_after_the_lease_ended_is_refused() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = lease_grant_as(region.id as usize, OWNER, LESSEE, 0, false).unwrap();
    lease_accept(LESSEE, OWNER).unwrap();
    let (r, _) = lease_map_target(id, LESSEE).unwrap();
    lease_free(id, OWNER, false);
    assert!(!lease_note_map(id, LESSEE, r, ROOT, VA, 1), "the lease is gone");
    // Reissued at the same id to the same lessee over another region: still
    // not the lease this mapping was made for.
    let other = Region::new(ShmPerms::ReadWrite);
    let again = lease_grant_as(other.id as usize, OWNER, LESSEE, 0, false).unwrap();
    assert_eq!(again, id, "the freed slot is reissued");
    lease_accept(LESSEE, OWNER).unwrap();
    assert!(!lease_note_map(id, LESSEE, r, ROOT, VA, 1), "a mapping of the old region");
    assert!(unmaps().is_empty());
}

// ── Wave 11 (LEASE3): expiry without the lessor, and the producer seal ──────

/// An expired lease is revoked by the lease worker's reap, with its lessor
/// idle: the tick only marks it, `lease_reap_expired` removes the lessee's
/// mapping, records the window and gives the booked reference back. A second
/// reap finds nothing, and the lessor's later wait or free removes nothing
/// more.
///
/// **Canary (by hand).** Empty `lease_reap_expired`'s loop: the reap
/// returns 0 and no PTE removal is recorded.
#[test]
fn an_expiry_is_revoked_by_the_reap_with_the_lessor_idle() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let id = grant_accept_map(&region, 100);
    let mut expired = [0u32; MAX_LEASES];
    assert_eq!(lease_tick(100, &mut expired), 1);
    assert!(unmaps().is_empty(), "no page-table edit in the tick");
    assert_eq!(lease_reap_expired(), 1);
    assert_eq!(unmaps(), vec![(ROOT, VA, 1)], "removed by the reap");
    assert!(gone(lease_map_info(id)));
    assert_eq!(region.refs(), 1, "the booked reference was given back");
    assert_eq!(revoked_rows().iter().filter(|r| r.tid == LESSEE).count(), 1);
    assert_eq!(lease_reap_expired(), 0, "nothing left");
    assert!(lease_free(id, OWNER, false));
    assert!(unmaps().is_empty(), "the free found nothing to remove");
}

/// A sealed grant takes the lessor's write in the hold that allocates the
/// entry, and every end gives it back exactly once: the return, the reap of
/// an expiry, the lessor's free, the lessee's exit. The lessor's own exit
/// and exec only forget it (no PTE edit on a dying address space). A write
/// fault inside the sealed range is attributed and counted.
///
/// **Canary (by hand).** Drop `table.unseal(id)` from `lease_reap_expired`:
/// the expiry case records no give-back.
#[test]
fn a_seal_is_given_back_once_by_every_end_and_forgotten_by_the_lessors_exit() {
    let _g = serial();
    let region = Region::new(ShmPerms::ReadWrite);
    let lessor_map = SealMap { root: 0x8777_0000, va: 0x5000_0000, pages: 1 };
    let grant = |expire: u64| -> usize {
        lease_grant_sealed_as(region.id as usize, OWNER, LESSEE, expire, false, Some(lessor_map))
            .expect("sealed grant")
    };
    let take = (lessor_map.root, lessor_map.va, 1usize, false);
    let give = (lessor_map.root, lessor_map.va, 1usize, true);

    // Return.
    let id = grant(0);
    assert_eq!(seals(), vec![take]);
    assert_eq!(lease_seal_info(id), (true, lessor_map));
    let f0 = lease_seal_faults();
    assert_eq!(lease_sealed_fault(OWNER, lessor_map.va + 8), Some(id));
    assert_eq!(lease_sealed_fault(LESSEE, lessor_map.va + 8), None, "only the lessor's writes");
    assert_eq!(lease_seal_faults(), f0 + 1);
    assert!(lease_accept(LESSEE, OWNER).is_some());
    lease_return(id, LESSEE, false).unwrap();
    assert_eq!(seals(), vec![give]);
    assert!(lease_free(id, OWNER, false));
    assert!(seals().is_empty(), "given back once");

    // Expiry, reaped.
    let id = grant(50);
    seals();
    let mut expired = [0u32; MAX_LEASES];
    assert_eq!(lease_tick(50, &mut expired), 1);
    assert!(seals().is_empty(), "no page-table edit in the tick");
    assert_eq!(lease_reap_expired(), 1);
    assert_eq!(seals(), vec![give]);
    assert!(lease_free(id, OWNER, false));

    // The lessor's free.
    let id = grant(0);
    seals();
    assert!(lease_free(id, OWNER, false));
    assert_eq!(seals(), vec![give]);

    // The lessee's exit.
    let _id = grant(0);
    seals();
    lease_release_all(LESSEE);
    assert_eq!(seals(), vec![give]);
    lease_release_all(OWNER);
    assert!(seals().is_empty());

    // The lessor's exit: forgotten, no edit.
    let _id = grant(0);
    seals();
    lease_release_all(OWNER);
    assert!(seals().is_empty(), "a dying lessor's page table is not edited");

    // The lessor's exec: forgotten, no edit, the lease stays.
    let id = grant(0);
    seals();
    lease_exec(OWNER);
    assert_eq!(lease_seal_info(id), (true, SealMap::NONE));
    assert!(lease_free(id, OWNER, false));
    assert!(seals().is_empty());
}
