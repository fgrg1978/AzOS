// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `MemCtl` interface -- `crates/core/syscall/src/memctl.rs::Server`: the
// authority in front of `memobj_set_volatile_ref` (the endpoint's `WRITE`, the
// handle, the object's owner) and what it answers. The purge itself is
// `crates/core/ipc/src/memobj.rs`'s tests (`tests/host/ipc-tests`).
//
// Included inside `mod handlers { .. }` like `net_guards.rs`.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::memctl::VolatileMem;
use azos_devif::{outcome, Cap as WireCap, MemCtl, Out};
use azos_ipc::cap::{targets::Shm, Cap};
use azos_ipc::memobj::{
    memobj_acquire_ref, memobj_create_cap, memobj_describe_ref, memobj_purge_volatile, MemPerms, MemSpec, PurgeState,
    ATTR_VOLATILE,
};
use crate::khost::Caller;

const OWNER: u32 = 0x7e45_0010;
const SHARER: u32 = 0x7e45_0011;
const SLOT_OWNER: usize = 50;
const SLOT_SHARER: usize = 51;

/// Gives back every object the test made, panic or not: the region table is
/// shared by the whole suite, and other rows read its first slot.
struct Tidy;

impl Drop for Tidy {
    fn drop(&mut self) {
        azos_ipc::memobj::memobj_release_all(OWNER);
        azos_ipc::memobj::memobj_release_all(SHARER);
    }
}

fn setup() -> Tidy {
    for (tid, slot) in [(OWNER, SLOT_OWNER), (SHARER, SLOT_SHARER)] {
        ipc_task_pool::shim_bind(tid, slot);
        azos_ipc::cap_store::reset(tid);
    }
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(OWNER);
    Tidy
}

fn server(tid: u32, rights: CapPerms) -> crate::memctl::Server {
    crate::memctl::Server(Caller { tid, badge: 0, rights })
}

/// A volatile (or plain) object of OWNER's: its capability and packed reference.
fn object(volatile: bool) -> (Cap<Shm>, u32) {
    let spec = MemSpec::anon(MemPerms::ReadWrite).with_attrs(if volatile { ATTR_VOLATILE } else { 0 });
    let cap = memobj_create_cap(OWNER, 1, &spec).expect("create");
    let r = azos_ipc::cap_store::get(OWNER, cap, CapPerms::READ).expect("resolves");
    (cap, r)
}

fn wire(cap: Cap<Shm>) -> WireCap<VolatileMem> {
    WireCap::from_raw(cap.raw().0)
}

fn nobody_is_locked(_key: u32) -> bool {
    false
}

/// Both ops need `WRITE` on the endpoint; the refusal comes before the handle is
/// looked at, and the object is untouched.
/// **Canary:** skip the gate in `set`: the read-only caller changes the object.
#[test]
fn both_ops_need_write_on_the_endpoint() {
    let _g = serial();
    let _t = setup();
    let (cap, r) = object(true);
    for rights in [CapPerms::NONE, CapPerms::READ, CapPerms::EXEC] {
        assert_eq!(server(OWNER, rights).set_volatile(wire(cap)), Out::err(outcome::DENIED), "set_volatile {rights:?}");
        assert_eq!(server(OWNER, rights).set_nonvolatile(wire(cap)), Out::err(outcome::DENIED), "set_nonvolatile {rights:?}");
    }
    assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Held);
}

/// The owner toggles a volatile object and is told it is whole; a purge is
/// then reported by both ops, and the state does not change back.
/// **Canary:** answer `false` for a purged object: the last two lines go red.
#[test]
fn the_owner_toggles_and_is_told_when_the_object_was_purged() {
    let _g = serial();
    let _t = setup();
    let (cap, r) = object(true);
    let s = &mut server(OWNER, CapPerms::WRITE);
    assert_eq!(s.set_volatile(wire(cap)), Out::ok(false));
    assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Volatile);
    assert_eq!(s.set_nonvolatile(wire(cap)), Out::ok(false));
    assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Held);

    assert_eq!(s.set_volatile(wire(cap)), Out::ok(false));
    assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 1);
    assert_eq!(s.set_nonvolatile(wire(cap)), Out::ok(true), "purged while volatile");
    assert_eq!(s.set_volatile(wire(cap)), Out::ok(true));
    assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Purged);
}

/// What is not a volatile object of the caller's is refused, and says why:
/// an object made without the attribute and a handle that names nothing are
/// `BAD_ARGUMENT`; a task that only shares the object is `DENIED`, and the
/// object is not made droppable under its owner.
/// **Canary:** drop the owner test in `memobj_set_volatile_ref`: the sharer's
/// call is served.
#[test]
fn only_the_owner_of_a_volatile_object_may_toggle_it() {
    let _g = serial();
    let _t = setup();
    let (plain, _) = object(false);
    let (cap, r) = object(true);
    let owner = &mut server(OWNER, CapPerms::WRITE);
    assert_eq!(owner.set_volatile(wire(plain)), Out::err(outcome::BAD_ARGUMENT), "created without the attribute");
    assert_eq!(owner.set_volatile(WireCap::from_raw(0x7777)), Out::err(outcome::BAD_ARGUMENT), "no such handle");

    // The sharer holds a reference and a capability of its own.
    let theirs = azos_ipc::cap::objref::grant_packed::<Shm>(SHARER, CapPerms::RW, r).expect("mint");
    memobj_acquire_ref(SHARER, r).expect("share");
    let sharer = &mut server(SHARER, CapPerms::WRITE);
    assert_eq!(sharer.set_volatile(wire(theirs)), Out::err(outcome::DENIED));
    assert_eq!(memobj_describe_ref(r).unwrap().purge, PurgeState::Held, "droppable under its owner");
    assert_eq!(owner.set_volatile(wire(cap)), Out::ok(false));
}

/// **The map of a purged object says so.** `SYS_MO_MAP` on the capability of an
/// object reclaim took answers `-EPURGED`, not the bare refusals a map without
/// frames used to fall into; an object still whole is not refused for it.
/// **Canary:** drop the `Purged` arm of `errno_for_memobj_err`: this fails to
/// compile; map it to `EBADF`: the assertion is red.
#[test]
fn the_map_of_a_purged_object_answers_epurged() {
    use azos_abi::error::Errno;
    let _g = serial();
    let _t = setup();
    let (cap, _) = object(true);
    let s = &mut server(OWNER, CapPerms::WRITE);
    assert_eq!(s.set_volatile(wire(cap)), Out::ok(false));
    assert_eq!(memobj_purge_volatile(8, nobody_is_locked), 1);
    assert_eq!(crate::ipc_handlers::sys_shm_map_typed(u64::from(cap.raw().0), 0), Errno::EPURGED.to_syscall_ret());
}
