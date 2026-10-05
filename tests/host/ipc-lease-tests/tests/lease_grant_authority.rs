// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A ring-3 lessor may lease only a shared-memory region it holds a live
//! `Cap<Shm>` for.
//!
//! `SYS_IPC_LEASE_GRANT` (111, retired 2026-09-28 for the typed 603) handed a
//! raw `a0` to `lease_grant_as` as the region id and the caller as the lessor. Until 2026-09-14 nothing checked the region,
//! so a task could advertise a lease over another task's buffer, wake the
//! named lessee with it, and spend a slot of the lease table. The check was
//! then the owner stamp `SYS_IPC_MAP` uses; since RFC-0040 gap 1 stage 2 it is
//! the lessor's own capability table: a `Cap<Shm>` with `READ` whose stored
//! reference is the region's live `(index, generation)`. The kernel bypass is
//! unchanged.
//!
//! **A binary of its own.** These tests create real regions, whose pages come
//! from `shims/mm`'s pool. The io_ring suite in the library's test binary
//! resets that pool and asserts on its page counts, so a region allocated
//! beside it would make either suite's verdict depend on thread timing.

use azos_ipc_lease_tests::cap::{objref, CapKind, CapPerms};
use azos_ipc_lease_tests::cap_store;
use azos_ipc_lease_tests::lease::{
    lease_accept, lease_free, lease_grant, lease_grant_as, LeaseGrantError, MAX_LEASES,
};
use azos_ipc_lease_tests::shm::{
    shm_create, shm_create_cap, shm_owner, shm_ref, shm_release, ShmPerms, MAX_SHM_REGIONS,
};
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());

const OWNER: u32 = 11;
const STRANGER: u32 = 12;
const LESSEE: u32 = 13;

const REFUSED: Result<usize, LeaseGrantError> = Err(LeaseGrantError::NotOwner);

/// Take the suite lock, empty the lease table (`lease_free` with the kernel
/// bypass is the one public way to clear a slot) and the three capability
/// tables.
fn serial() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for i in 0..MAX_LEASES {
        lease_free(i, 0, true);
    }
    for tid in [OWNER, STRANGER, LESSEE] {
        cap_store::reset(tid);
    }
    azos_sched::shim_reset();
    g
}

/// A one-page region created by `tid` through `shm_create_cap`, so its creator
/// holds a `Cap<Shm>`; released on drop so a failing test leaves no region and
/// no page behind.
struct Region {
    tid: u32,
    id: u32,
}

impl Region {
    fn new(tid: u32, perms: ShmPerms) -> Self {
        let cap = shm_create_cap(tid, 1, perms).expect("a one-page region");
        let r = cap_store::get(tid, cap, CapPerms::READ).expect("the creator holds its capability");
        let id = objref::SHM.idx(r);
        assert_eq!(shm_owner(id), Some(tid));
        Region { tid, id }
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let _ = shm_release(self.tid, self.id);
    }
}

/// A region id with no region behind it.
fn free_region_id() -> u32 {
    (0..MAX_SHM_REGIONS as u32)
        .find(|&i| shm_owner(i).is_none())
        .expect("a free region id")
}

/// Grant `tid` a capability of `kind` with `perms` storing `r`.
fn hold(tid: u32, kind: CapKind, perms: CapPerms, r: u32) {
    assert!(cap_store::with_table(tid, |t| t.grant_raw(kind, perms, r)).flatten().is_some());
}

#[test]
fn a_ring3_lessor_holding_no_capability_for_the_region_is_refused() {
    let _g = serial();
    let r = Region::new(OWNER, ShmPerms::ReadWrite);

    assert_eq!(
        lease_grant_as(r.id as usize, STRANGER, LESSEE, 0, false),
        REFUSED,
        "a task holding no capability for the region leased it"
    );
    // Refused means nothing happened: no pending lease for the lessee.
    assert!(lease_accept(LESSEE, STRANGER).is_none(), "a refused grant left a pending lease");

    // Positive control on the same region: the holder may lease it, and the
    // lessee receives exactly that lease naming exactly that region.
    let id = lease_grant_as(r.id as usize, OWNER, LESSEE, 0, false)
        .expect("the holder was refused a lease over its own region");
    assert_eq!(lease_accept(LESSEE, OWNER), Some((id, r.id as usize)));
}

#[test]
fn a_region_id_that_names_no_live_region_of_the_lessor_is_refused() {
    let _g = serial();
    let r = Region::new(OWNER, ShmPerms::ReadWrite);

    // The high bits must not be dropped on the way to the `u32` region id.
    let aliased = (1usize << 32) | r.id as usize;
    assert_eq!(
        lease_grant_as(aliased, OWNER, LESSEE, 0, false),
        REFUSED,
        "an id above u32::MAX was truncated onto the holder's live region"
    );
    // Past the table, and a slot with no region.
    assert_eq!(lease_grant_as(MAX_SHM_REGIONS, OWNER, LESSEE, 0, false), REFUSED);
    assert_eq!(lease_grant_as(usize::MAX, OWNER, LESSEE, 0, false), REFUSED);
    assert_eq!(lease_grant_as(free_region_id() as usize, OWNER, LESSEE, 0, false), REFUSED);

    // A region released by its last holder is no region, although its creator
    // still holds the capability that named it.
    let id = r.id;
    drop(r);
    assert_eq!(shm_owner(id), None);
    assert_eq!(lease_grant_as(id as usize, OWNER, LESSEE, 0, false), REFUSED);
    assert!(lease_accept(LESSEE, OWNER).is_none(), "a refused grant left a pending lease");
}

/// **The generation is part of the authority.** A capability to a released
/// region does not lease the region reissued at its index; the new creator's
/// does.
///
/// **Canary.** Compare the index halves in `holds_packed_ref`: the stale
/// capability leases the new region.
#[test]
fn a_capability_to_a_released_region_does_not_lease_its_successor() {
    let _g = serial();
    let old = Region::new(OWNER, ShmPerms::ReadWrite);
    let idx = old.id;
    drop(old);

    let new = Region::new(STRANGER, ShmPerms::ReadWrite);
    assert_eq!(new.id, idx, "precondition: the released index was reissued");

    assert_eq!(
        lease_grant_as(idx as usize, OWNER, LESSEE, 0, false),
        REFUSED,
        "a capability to the released region leased its successor"
    );
    lease_grant_as(idx as usize, STRANGER, LESSEE, 0, false).expect("the new region's holder was refused");
}

/// **What counts is a `Cap<Shm>` with `READ` storing the live reference**, in
/// the lessor's own table: a read-only region is leasable by its creator, a
/// capability of another kind storing the same value is not, a WRITE-only one
/// is not, and the same reference held with READ by a task that did not create
/// the region is.
///
/// **Canaries.** Drop `s.kind == kind` from `holds_packed_ref`: the Port line
/// leases. Ask `CapPerms::NONE`: the WRITE-only line does. Restore the owner
/// stamp: the last line is refused.
#[test]
fn the_authority_is_a_read_capability_of_the_shm_kind() {
    let _g = serial();
    let r = Region::new(OWNER, ShmPerms::ReadOnly);
    lease_grant_as(r.id as usize, OWNER, LESSEE, 0, false).expect("a READ capability did not lease its region");

    let live = shm_ref(r.id).expect("a live region");
    hold(STRANGER, CapKind::Port, CapPerms::RW, live);
    assert_eq!(
        lease_grant_as(r.id as usize, STRANGER, LESSEE, 0, false),
        REFUSED,
        "a Port capability storing the region's reference leased it"
    );
    hold(STRANGER, CapKind::Shm, CapPerms::WRITE, live);
    assert_eq!(
        lease_grant_as(r.id as usize, STRANGER, LESSEE, 0, false),
        REFUSED,
        "a WRITE-only Shm capability leased the region"
    );
    hold(STRANGER, CapKind::Shm, CapPerms::READ, live);
    lease_grant_as(r.id as usize, STRANGER, LESSEE, 0, false)
        .expect("the capability, not the creator's TID, is the authority");
}

/// A region created without a capability (the untyped `shm_create`) cannot be
/// leased from ring 3, by its creator either; a kernel caller still can.
#[test]
fn a_region_created_without_a_capability_is_not_leasable_from_ring3() {
    let _g = serial();
    let id = shm_create(OWNER, 1, ShmPerms::ReadWrite).expect("a one-page region");
    assert_eq!(shm_owner(id), Some(OWNER));

    assert_eq!(lease_grant_as(id as usize, OWNER, LESSEE, 0, false), REFUSED);
    lease_grant_as(id as usize, OWNER, LESSEE, 0, true).expect("a kernel caller was refused");
    let _ = shm_release(OWNER, id);
}

#[test]
fn a_kernel_caller_keeps_the_bypass() {
    let _g = serial();
    // The bypass `SYS_IPC_MAP` gives a kernel task: no region, no capability.
    let free = free_region_id();
    let id = lease_grant_as(free as usize, STRANGER, LESSEE, 0, true)
        .expect("a kernel caller was refused");
    assert_eq!(lease_accept(LESSEE, STRANGER), Some((id, free as usize)));
}

/// `lease_grant`, the form the kernel lease bench calls, is checked too: it
/// takes the privilege from the scheduler, so a ring-3 context gets the check.
#[test]
fn the_four_argument_form_takes_the_privilege_from_the_scheduler() {
    let _g = serial();
    let r = Region::new(OWNER, ShmPerms::ReadWrite);

    azos_sched::shim_set_current(STRANGER, 0x1000);
    assert_eq!(
        lease_grant(r.id as usize, STRANGER, LESSEE, 0),
        None,
        "a ring-3 stranger leased the region through lease_grant"
    );

    azos_sched::shim_set_current(OWNER, 0x1000);
    let id = lease_grant(r.id as usize, OWNER, LESSEE, 0).expect("a ring-3 holder was refused");
    assert_eq!(lease_accept(LESSEE, OWNER).map(|(l, _)| l), Some(id));

    azos_sched::shim_set_current(STRANGER, 0);
    assert!(
        lease_grant(r.id as usize, STRANGER, LESSEE, 0).is_some(),
        "a kernel caller lost the bypass through lease_grant"
    );
}
