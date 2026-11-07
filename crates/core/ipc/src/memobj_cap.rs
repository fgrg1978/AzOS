// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The capability face of the shared-memory objects: the typed `Cap<Shm>` entries over the
//! object table in `azos_mm::memobj`, and the [`Host`] it calls up into (scheduler, capability
//! store).

use crate::cap::objref;
use crate::cap::{CapError, CapType};
use crate::memobj_core::*;

struct Up;

impl Host for Up {
    fn domain_of(&self, tid: u32) -> Option<u32> {
        azos_sched::idx_for_tid(tid).map(azos_sched::task_domain)
    }
    fn charge(&self, key: u32, pages: u32) -> bool {
        azos_sched::mm_charge_domain(key, pages)
    }
    fn discharge(&self, key: u32, pages: u32) {
        azos_sched::mm_discharge_domain(key, pages)
    }
    fn meta_charge(&self, key: u32, bytes: u64) -> bool {
        crate::cap_store::kmem_charge(key, crate::cap_store::KMEM_MEMOBJ_META, bytes)
    }
    fn meta_discharge(&self, key: u32, bytes: u64) {
        crate::cap_store::kmem_discharge(key, crate::cap_store::KMEM_MEMOBJ_META, bytes)
    }
    fn task_charge(&self, pages: u32) -> bool {
        azos_sched::mm_charge(pages)
    }
    fn task_discharge(&self, pages: u32) {
        azos_sched::mm_discharge(pages)
    }
    fn proc_tid(&self, tid: u32) -> u32 {
        azos_sched::group::proc_tid(tid)
    }
    fn wake_shared(&self, obj: u32, offset: u32) {
        let _ = azos_sched::futex::wake_key(azos_sched::futex::Key::Shared { obj, offset }, u32::MAX);
        crate::port::port_ring_doorbell(obj, offset);
    }
    fn sweep_slot(&self, slot: u32) {
        objref::sweep_index(crate::cap::ty::SHM, slot);
    }
    fn pins_memory(&self, tid: u32) -> bool {
        azos_sched::task_pins_memory(tid)
    }
}

static UP: Up = Up;
static HOST_BOX: HostBox = HostBox(&UP);

/// Hand the object table its scheduler and capability store. Boot, before the first object.
pub fn install_host() {
    set_host(&HOST_BOX);
}

/// Resolve `cap` in `table` for a map: `READ` and `MAP` are required (reading a
/// region through the kernel is not a window in ring 3: `MAP` is the right to
/// have one); `WRITE` decides the writable bit of a read-write object. A refusal other than the missing
/// `WRITE` (a stale or revoked capability, containment) is the map's.
pub fn memobj_resolve_map(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
    op: u16,
) -> Result<MapGrant, MemObjError> {
    let r = table.get_op(cap, crate::cap::CapPerms::READ.union(crate::cap::CapPerms::MAP), op)?;
    let desc = memobj_describe_ref(r)?;
    // A purged object has no frame to map: say so, not "not reachable".
    if desc.purge == PurgeState::Purged {
        return Err(MemObjError::Purged);
    }
    let writable = if desc.perms == MemPerms::ReadWrite {
        match table.get_op(cap, crate::cap::CapPerms::WRITE, op) {
            Ok(_) => true,
            // Canary `memobj-share-no-narrow-canary`: an attenuated capability
            // maps as writable as the object is.
            Err(CapError::MissingPerms) => cfg!(feature = "memobj-share-no-narrow-canary"),
            Err(e) => return Err(MemObjError::Cap(e)),
        }
    } else {
        false
    };
    Ok(MapGrant { r, desc, writable })
}

/// The object half of a capability MOVE: [`crate::cap_store::MoveHook`] for `Cap<Shm>`.
pub fn memobj_moved(kind: CapType, resource: u32, from_tid: u32, to_tid: u32) {
    if kind == crate::cap::ty::SHM {
        memobj_moved_shm(resource, from_tid, to_tid);
    }
}

/// Derive `CapPerms` for a freshly-minted Shm cap from the region's own access
/// mode, for the task that made the region: ReadOnly → READ; ReadWrite → RW;
/// both with `MAP` (its creator maps it), `DUP` (it may share it) and
/// `TRANSFER` (it may hand it over). Callers that want a more restricted grant
/// (e.g. duplicating read-only into a child) derive with fewer rights.
fn cap_perms_for(perms: MemPerms) -> crate::cap::CapPerms {
    use crate::cap::CapPerms;
    let access = match perms {
        MemPerms::ReadOnly => CapPerms::READ,
        MemPerms::ReadWrite => CapPerms::RW,
    };
    access.union(CapPerms::MAP).union(CapPerms::DELEGATE)
}

/// Typed `memobj_create`: allocates a region with `page_count` pages and
/// mints a `Cap<Shm>` into `tid`'s cap-table.
///
/// On cap-table exhaustion the region is released so the caller never
/// observes a partial state.
pub fn memobj_create_cap(
    tid: u32,
    page_count: usize,
    spec: &MemSpec,
) -> Result<crate::cap::Cap<crate::cap::targets::Shm>, MemObjError> {
    let r = memobj_create_spec(tid, page_count, spec)?;
    // A POSIX pipe starts with one reader and one writer, the creator's
    // (`azos_bytepipe::BytePipe::init`): its record holds both. Meaningless
    // for a region that is no pipe (nothing reads it then).
    pipe_creator_ends(tid, r);
    let perms = spec.perms;
    // The capability stores the packed `(index, generation)`. `MAP` and
    // `DELEGATE` (owner decision 2026-09-26, O3.4): the creator maps its own
    // region and may share or gift it.
    match objref::grant_packed::<crate::cap::targets::Shm>(tid, cap_perms_for(perms), r) {
        Some(cap) => Ok(cap),
        None => {
            // Roll back the region so we don't leak it on cap-table
            // exhaustion. `memobj_create` booked one reference against `tid`, so a
            // single release will free all pages and clear the slot. The
            // region has never been mapped at this point, so the "no live
            // mapping" refusal cannot fire.
            let _ = memobj_release_ref(tid, r);
            Err(MemObjError::Full)
        }
    }
}

/// Typed clone: a COW snapshot of the object `src` names in `tid`'s table
/// (requires `READ`), owned by `tid` and charged to its Domain, with its own
/// `Cap<Shm>` of access mode `perms`. `page_count` is 0 or the source's page
/// count (`BadArg` otherwise).
pub fn memobj_clone_cap(
    tid: u32,
    src: crate::cap::Cap<crate::cap::targets::Shm>,
    perms: MemPerms,
    page_count: usize,
) -> Result<crate::cap::Cap<crate::cap::targets::Shm>, MemObjError> {
    let r = crate::cap_store::get(tid, src, crate::cap::CapPerms::READ)?;
    if page_count != 0 && page_count != memobj_describe_ref(r)?.page_count {
        return Err(MemObjError::BadArg);
    }
    let nr = memobj_clone(tid, r, tid, perms)?;
    match objref::grant_packed::<crate::cap::targets::Shm>(tid, cap_perms_for(perms), nr) {
        Some(cap) => Ok(cap),
        None => {
            let _ = memobj_release_ref(tid, nr);
            Err(MemObjError::Full)
        }
    }
}

/// Typed acquire: validates the cap (requires `READ`) and bumps
/// `tid`'s reference on the region. Returns `(page_count, perms)`.
///
/// `tid` must be the task the cap table belongs to — the reference is
/// booked against it, and only it can give the reference back.
///
/// The capability's generation is compared with the region's inside the
/// table lock the acquire takes: a capability to a freed or
/// reused region answers `Stale`.
pub fn memobj_acquire_cap(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
    op: u16,
) -> Result<(usize, MemPerms), MemObjError> {
    let r = table.get_op(cap, crate::cap::CapPerms::READ, op)?;
    memobj_acquire_ref(tid, r)
}

/// Typed release: validates the cap (requires `READ`, since release is
/// paired with acquire and any holder may give back its own references),
/// gives back **every** reference `tid` holds on the region except a pinned
/// one ([`memobj_release_holder_ref`]), **and deletes the cap's slot** (a share
/// made from it stays with its holder: delete is not revoke). Refused
/// (`Closed`) while `tid` still has a mapping recorded; the slot is deleted on
/// every answer.
///
/// The capability is `tid`'s only name for those references, so they go
/// with it: releasing one and revoking the name left the rest booked to `tid`
/// until its exit.
///
/// **WHY the cap is revoked here (W3-F5):** shm ids are handed out
/// first-free-slot, and `CapTable::get` only validates the cap-table slot's
/// own generation — which a region teardown does not touch. Leaving the cap
/// live after the reference is given up means that once the region is freed
/// and id `n` is reissued to a different task, the stale cap still
/// dereferences to `n` and drives somebody else's region: a textbook
/// confused deputy. The previous doc explicitly told callers to revoke
/// separately; nothing did.
///
/// The untyped `SYS_IPC_UNSHARE` it paired with was retired with the move to
/// generation-stamped handles;
/// `SYS_MO_UNMAP` removes the caller's mapping before it calls this.
pub fn memobj_release_cap(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
) -> Result<(), MemObjError> {
    memobj_release_cap_op(tid, table, cap, azos_abi::invoke::op(azos_abi::cap::CapKind::MemObj, azos_abi::invoke::CLASS_CTL, 0))
}

/// [`memobj_release_cap`] for a release that is an op of the caller's:
/// `op` discharges an `OP_MASK` caveat of the capability (`SYS_MO_UNMAP`
/// passes the class-only op of `CTL`, the class that "ends an object").
pub fn memobj_release_cap_op(
    tid: u32,
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Shm>,
    op: u16,
) -> Result<(), MemObjError> {
    let r = table.get_op(cap, crate::cap::CapPerms::READ, op)?;
    let released = memobj_release_holder_ref(tid, r);
    table.delete(cap);
    released
}
