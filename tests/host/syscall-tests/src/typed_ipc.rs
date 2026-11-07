// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Stage 3 of the move to typed calls: the calls that replace the untyped
// shared-memory and port calls. 574 maps a region, 575 binds a source to a
// port, `PORT_SRC_IRQ` binds an IRQ to one, 577 waits on a port; 535
// unmaps before it releases. Each is driven through the pulled handler as a
// ring-3 caller with its own capability table and a real page table.
//
// The capability and port layers read their caller through
// `shims/ipc_sched`, which forwards to the `shims/sched` registers set below:
// the handlers and those layers see one caller, as in the kernel. The
// wait's block is `shims/sched`'s recording `task_block`, whose hook stands for
// what other tasks do while the caller sleeps.

use super::harness::serial;
use crate::ipc_handlers::*;
use azos_abi::cap::{CapHandle, CapKind, CapPerms, ty, CapType};
use azos_abi::error::Errno;
use azos_abi::syscall_nr::{
    PORT_BIND_F_REMOVE, PORT_SRC_CALLS, PORT_SRC_DOORBELL, PORT_SRC_ENDPOINT, PORT_SRC_PRESSURE, PORT_SRC_RING, PORT_SRC_TIMER,
};
use azos_arch_api::PagePerms;
use azos_ipc::cap::objref::PORT;
use azos_ipc::cap::targets::{Endpoint, Irq, Port, Shm};
use azos_ipc::cap::{Cap, CapTarget};
use azos_ipc::port::PortEvent;
use azos_sched::WaitReason;
use std::sync::atomic::{AtomicU32, Ordering};

/// Task-pool slots nothing else in the crate binds.
const SLOT_A: usize = 62;
const SLOT_B: usize = 63;
/// A page mapped user-RW in every caller's page table.
const BUF: usize = 0x0074_0000;
/// A non-null address no test here maps.
const UNMAPPED: u64 = 0x0078_0000;
/// An IRQ number no other test here binds.
const IRQ: u32 = 9;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7730_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

fn errno(e: Errno) -> i64 {
    e.to_syscall_ret()
}

/// Puts back every process static a test here can change, panic or not:
/// containment, the block hook, and every port, region, IRQ binding
/// and capability the callers left.
struct Scene {
    tids: Vec<u32>,
}

impl Scene {
    fn new(tids: &[u32]) -> Scene {
        let _ = azos_sched::shim_take_blocks();
        azos_sched::shim_set_block_hook(None);
        Scene { tids: tids.to_vec() }
    }
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_sched::shim_after_shm_map(Box::new(|| {}));
        azos_sched::shim_at_mm_lock(Box::new(|| {}));
        azos_ipc::cap::degraded_set(false);
        azos_sched::shim_set_block_hook(None);
        let _ = azos_sched::shim_take_blocks();
        azos_sched::set_current_user_pt(0);
        azos_sched::set_current_task_tid(0);
        azos_sched::set_current_proc_tid(0);
        for &t in &self.tids {
            azos_ipc::irq_bind::irq_unbind_all(t);
            azos_ipc::port::port_release_all(t);
            azos_ipc::memobj::memobj_release_all(t);
            azos_ipc::cap_store::reset(t);
        }
    }
}

/// `tid` as a ring-3 caller at `slot`: an empty capability table and a fresh
/// page table with `BUF` mapped user-RW. Returns the page-table root.
fn ring3(tid: u32, slot: usize) -> usize {
    ipc_task_pool::shim_bind(tid, slot);
    azos_ipc::cap_store::reset(tid);
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, BUF, phys, PagePerms::USER_RW).expect("map");
    become_task(tid, pt);
    // A mapping goes at the break, as a native task's does.
    azos_sched::shim_set_brk(0x10_0000);
    pt
}

fn become_task(tid: u32, pt: usize) {
    azos_sched::set_current_user_pt(pt);
    azos_sched::set_current_task_tid(tid);
}

fn handle(ret: i64) -> u64 {
    assert!(ret > 0, "expected a capability handle, got {ret}");
    ret as u64
}

fn kind_of(h: u64) -> Option<CapType> {
    CapType::from_raw(CapHandle::from_raw(h as u32).kind())
}

/// The packed reference `tid`'s capability `h` stores.
fn resource_of<T: CapTarget>(tid: u32, h: u64) -> u32 {
    azos_ipc::cap_store::get(tid, Cap::<T>::from_raw(CapHandle::from_raw(h as u32)), CapPerms::NONE)
        .expect("a live capability")
}

/// Grant `tid` a `Cap<T>` on `resource` straight into its table.
fn held<T: CapTarget>(tid: u32, perms: CapPerms, resource: u32) -> u64 {
    azos_ipc::cap_store::grant::<T>(tid, perms, resource)
        .expect("cap table full")
        .raw()
        .as_raw() as u64
}

fn put(at: usize, bytes: &[u8]) {
    assert!(azos_sched::copy_to_user(at, bytes.as_ptr(), bytes.len()), "put at {at:#x}");
}

fn take16(at: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    assert!(azos_sched::copy_from_user(b.as_mut_ptr(), at, 16), "take at {at:#x}");
    b
}

/// The key of the 16-byte event at `BUF`.
fn key_at_buf() -> u64 {
    u64::from_le_bytes(take16(BUF)[..8].try_into().unwrap())
}

fn event(key: u64) -> PortEvent {
    PortEvent { key, source_type: 3, source_id: 5, code: 0, cpu: 0 }
}

// ═════════════════════════════════════════════════════════════════════════
// 574 and 535
// ═════════════════════════════════════════════════════════════════════════

/// **574 maps a region with the region's own access mode and mints nothing;
/// 535 removes the mapping before it drops the reference.** Before the move the
/// release did not unmap: a task that had mapped the region was refused with
/// `-EBADF` and lost its capability anyway.
///
/// **Canaries.** Skip the unmap in `sys_shm_release_typed`: the release reads
/// `-EBADF`. Map every region writable: the read-only region's page resolves
/// for a write.
#[test]
fn a_typed_map_follows_the_region_and_the_release_unmaps_first() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);

    let rw = handle(sys_shm_create_typed(1, 1));
    let before = azos_ipc::cap_store::occupied(a);
    let va = sys_shm_map_typed(rw, 0);
    assert!(va > 0, "map returned {va}");
    let va = va as usize;
    assert_eq!(azos_ipc::cap_store::occupied(a), before, "the map minted nothing");
    assert!(azos_mm::vmm::translate_user(pt, va, true).is_some(), "a writable region maps writable");
    put(va, b"shared");
    assert_eq!(sys_shm_map_typed(rw, 0), errno(Errno::EBUSY), "one mapping per task and region");

    assert_eq!(sys_shm_release_typed(rw), 0, "the release of a mapped region");
    assert!(azos_mm::vmm::translate_user(pt, va, false).is_none(), "the release unmapped it");
    assert_eq!(sys_shm_map_typed(rw, 0), errno(Errno::ECAPSTALE), "the release revoked the capability");

    let ro = handle(sys_shm_create_typed(1, 0));
    let va = sys_shm_map_typed(ro, 0);
    assert!(va > 0, "map returned {va}");
    let va = va as usize;
    assert!(azos_mm::vmm::translate_user(pt, va, false).is_some(), "a read-only region maps");
    assert!(azos_mm::vmm::translate_user(pt, va, true).is_none(), "read-only");
    assert_eq!(sys_shm_release_typed(ro), 0);
    assert!(azos_mm::vmm::translate_user(pt, va, false).is_none());
}

/// **535 unmaps a region in batches: one TLB shootdown per
/// `UNMAP_GATHER_PAGES` pages, not one per page, and no frame of the region is
/// freed by the unmap** (the region owns them until its last reference goes).
/// A 64-page region cost 64 shootdowns before.
///
/// **Canary.** Restore a per-page `vmm::unmap` loop in `pager::unmap_shared`:
/// the release costs 64 shootdowns, not 1; `unmap-stack-batch-canary`: 2. Free
/// what the unmap clears: the unmap frees the region's frames and the free-page
/// count moves.
#[test]
fn a_release_unmaps_a_region_with_one_shootdown_per_batch() {
    use azos_arch::{SHOOTDOWNS_ON_WATCHED_ROOT, SHOOTDOWN_WATCH_ROOT};
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);

    let pages = azos_ipc::memobj::MAX_MEMOBJ_PAGES;
    let h = handle(sys_shm_create_typed(pages as u64, 1));
    let va = sys_shm_map_typed(h, 0);
    assert!(va > 0, "map returned {va}");
    let va = va as usize;
    let span = pages * azos_arch::mmu::PAGE_SIZE;
    assert!(azos_mm::vmm::translate_user(pt, va + span - 1, false).is_some(), "the last page maps");

    // A second holder keeps the region alive across the release, so a frame
    // the unmap wrongly freed would show in the free count.
    let region_frames_before = azos_mm::pmm::free_pages();
    SHOOTDOWNS_ON_WATCHED_ROOT.store(0, Ordering::SeqCst);
    SHOOTDOWN_WATCH_ROOT.store(pt, Ordering::SeqCst);
    let (unmapped, batches) = {
        // The unmap alone: what 535 runs before it drops the references.
        let mapping = azos_ipc::cap_store::with_table(a, |table| {
            let cap: Cap<Shm> = Cap::from_raw(CapHandle::from_raw(h as u32));
            let r = table.get(cap, CapPerms::READ).ok()?;
            azos_ipc::memobj::memobj_take_mapping_ref(a, r).ok().flatten()
        })
        .flatten()
        .expect("the mapping is recorded");
        let space = azos_sched::shim_space(pt);
        azos_mm::pager::release_range(space, mapping.0, mapping.0 + span).expect("the record goes");
        (mapping.1, SHOOTDOWNS_ON_WATCHED_ROOT.load(Ordering::SeqCst))
    };
    SHOOTDOWN_WATCH_ROOT.store(0, Ordering::SeqCst);
    assert_eq!(unmapped, pages);
    assert!(pages > azos_mm::vmm::UNMAP_BATCH_PAGES, "a region that gathers");
    let per_batch = azos_mm::vmm::UNMAP_GATHER_PAGES;
    assert_eq!(batches, pages.div_ceil(per_batch), "shootdowns for a {pages}-page unmap");
    assert_eq!(azos_mm::pmm::free_pages(), region_frames_before, "the unmap freed a region frame");
    for p in 0..pages {
        let at = va + p * azos_arch::mmu::PAGE_SIZE;
        assert!(azos_mm::vmm::translate_user(pt, at, false).is_none(), "page {p} still maps");
    }
    assert_eq!(sys_shm_release_typed(h), 0, "the release after the unmap");
}

/// **A released mapping gives its record and its address back.** The record
/// of every cycle goes with the release (the space holds a few records), and
/// the range is vacant again: more cycles than the space has records, of the
/// largest region.
///
/// **Canary.** `shm-release-record-kept-canary`: the release leaves the record
/// and its leaves, and the space runs out of records.
#[test]
fn a_released_mapping_gives_its_record_and_its_address_back() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let space = azos_sched::shim_space(pt);

    let pages = azos_ipc::memobj::MAX_MEMOBJ_PAGES;
    let span = pages * azos_arch::mmu::PAGE_SIZE;
    for cycle in 0..2 * azos_mm::pager::MAPPINGS_PER_SPACE + 2 {
        let h = handle(sys_shm_create_typed(pages as u64, 1));
        let va = sys_shm_map_typed(h, 0);
        assert!(va > 0, "cycle {cycle}: map returned {va}");
        let va = va as usize;
        assert_eq!(azos_mm::pager::shim_mappings(space), 1, "cycle {cycle}: the mapping is a record");
        assert_eq!(sys_shm_release_typed(h), 0, "cycle {cycle}: release");
        assert_eq!(azos_mm::pager::shim_mappings(space), 0, "cycle {cycle}: the release kept the record");
        assert!(azos_mm::vmm::user_range_vacant(pt, va, va + span), "cycle {cycle}: the range is not vacant");
    }
}

/// **574 needs `READ`; a writable region maps writable only for a capability
/// that holds `WRITE` too (a READ-only one maps it read-only), and that is the
/// only case containment refuses; a kernel caller is refused; a capability to
/// a released region does not map the region created next at its index.**
///
/// **Canaries.** `memobj-share-no-narrow-canary` (ipc crate): the attenuated
/// capability maps as writable as the object: the "not writable" check goes
/// red. Resolve the `WRITE` with `get_uncontained`: the contained writable map
/// succeeds.
#[test]
fn a_typed_map_asks_write_only_for_a_writable_region() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let pt_b = ring3(b, SLOT_B);
    become_task(a, pt_a);
    let rw = handle(sys_shm_create_typed(1, 1));
    let ro = handle(sys_shm_create_typed(1, 0));
    let chan = held::<Irq>(a, CapPerms::RW, IRQ);
    let r_rw = resource_of::<Shm>(a, rw);
    let r_ro = resource_of::<Shm>(a, ro);

    let rw_read = held::<Shm>(b, CapPerms::READ.union(CapPerms::MAP), r_rw);
    let rw_write = held::<Shm>(b, CapPerms::WRITE.union(CapPerms::MAP), r_rw);
    let rw_full = held::<Shm>(b, CapPerms::RW.union(CapPerms::MAP), r_rw);
    let ro_read = held::<Shm>(b, CapPerms::READ.union(CapPerms::MAP), r_ro);

    become_task(b, pt_b);
    assert_eq!(sys_shm_map_typed(0, 0), errno(Errno::ECAPSTALE), "a forged handle");
    // The map is bounded by the capability: READ alone (a SHARE attenuated to
    // READ) maps a writable region read-only; WRITE alone maps nothing.
    let va = sys_shm_map_typed(rw_read, 0);
    assert!(va > 0, "a READ capability maps a writable region read-only: {va}");
    assert!(azos_mm::vmm::translate_user(pt_b, va as usize, false).is_some(), "mapped");
    assert!(
        azos_mm::vmm::translate_user(pt_b, va as usize, true).is_none(),
        "the mapping of a READ-only capability is not writable"
    );
    assert_eq!(sys_shm_release_typed(rw_read), 0);
    assert_eq!(sys_shm_map_typed(rw_write, 0), errno(Errno::ECAPPERMS), "and READ");
    become_task(a, pt_a);
    assert_eq!(sys_shm_map_typed(chan, 0), errno(Errno::ECAPKIND), "a handle of another kind");
    become_task(b, pt_b);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_shm_map_typed(rw_full, 0), errno(Errno::EAGAIN), "a writable mapping is contained");
    let va = sys_shm_map_typed(ro_read, 0);
    assert!(va > 0, "a read-only mapping is not contained: {va}");
    azos_ipc::cap::degraded_set(false);
    let va = sys_shm_map_typed(rw_full, 0);
    assert!(va > 0, "map returned {va}");

    azos_sched::set_current_user_pt(0);
    assert_eq!(sys_shm_map_typed(ro_read, 0), errno(Errno::EINVAL), "a kernel caller has no user address space");
    become_task(b, pt_b);
    assert_eq!(sys_shm_release_typed(ro_read), 0);
    assert_eq!(sys_shm_release_typed(rw_full), 0);

    become_task(a, pt_a);
    assert_eq!(sys_shm_release_typed(rw), 0, "the creator's release frees the region");
    let rw2 = handle(sys_shm_create_typed(1, 1));
    assert_eq!(
        azos_ipc::cap::objref::SHM.idx(resource_of::<Shm>(a, rw2)),
        azos_ipc::cap::objref::SHM.idx(r_rw),
        "precondition: the index was reused"
    );
    become_task(b, pt_b);
    assert_eq!(sys_shm_map_typed(rw_read, 0), errno(Errno::ECAPSTALE), "a capability to the released region");
}

/// References the region at `idx` holds in all, or `None` once it is freed.
fn shm_refs(idx: u32) -> Option<u32> {
    azos_ipc::memobj::memobj_info(idx).map(|(_, refs, _)| refs)
}

/// **535 gives back every reference the releasing task holds on the region —
/// the creation reference, 574's and 534's — so a create/map/release loop never
/// runs out.** The capability is the task's only name for those references and
/// the release revokes it: a reference left behind stays booked to the task,
/// unnameable, until the task exits. Each loop runs past `MAX_MEMOBJS`. The
/// per-task share (`MAX_MEMOBJS_PER_TASK`, 8) counts the regions a task
/// still has booked, so a release that leaves one reference behind turns the
/// ninth create into `-ENOMEM`; the reference count read after each release
/// shows it on the first round.
///
/// **Canary.** Give back one reference in `memobj_release_cap`
/// (`memobj_release_ref`): the first round reads `Some(1)` after its release.
#[test]
fn a_typed_release_gives_back_every_reference_the_task_holds() {
    use azos_ipc::cap::objref::SHM;
    use azos_ipc::memobj::MAX_MEMOBJS;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let occupied = azos_ipc::cap_store::occupied(a);
    let rounds = MAX_MEMOBJS + 2;

    for i in 0..rounds {
        let h = sys_shm_create_typed(1, 1);
        assert!(h > 0, "create, map, release: round {i}'s create answered {h}");
        let h = h as u64;
        let idx = SHM.idx(resource_of::<Shm>(a, h));
        let va = sys_shm_map_typed(h, 0);
        assert!(va > 0, "round {i}: the map answered {va}");
        assert_eq!(shm_refs(idx), Some(2), "round {i}: the creation reference and the map's");
        assert_eq!(sys_shm_release_typed(h), 0, "round {i}: the release");
        assert_eq!(shm_refs(idx), None, "round {i}: the release gave back both and freed the region");
        assert!(azos_mm::vmm::translate_user(pt, va as usize, false).is_none(), "round {i}: unmapped");
    }
    for i in 0..rounds {
        let h = sys_shm_create_typed(1, 0);
        assert!(h > 0, "create, acquire, release: round {i}'s create answered {h}");
        let h = h as u64;
        let idx = SHM.idx(resource_of::<Shm>(a, h));
        // 8: `SHM_ACQUIRE_OUT_BYTES`, written to `BUF`.
        assert_eq!(sys_shm_acquire_typed(h, BUF as u64), 8, "round {i}: the acquire");
        assert_eq!(sys_shm_release_typed(h), 0, "round {i}: the release");
        assert_eq!(shm_refs(idx), None, "round {i}: the acquire's reference went too");
    }
    for i in 0..rounds {
        let h = sys_shm_create_typed(1, 1);
        assert!(h > 0, "create, release: round {i}'s create answered {h}");
        assert_eq!(sys_shm_release_typed(h as u64), 0, "round {i}: the release");
    }
    assert_eq!(azos_ipc::cap_store::occupied(a), occupied, "every release revoked its capability");
}

/// **One task's release leaves another task's references, capability and
/// mapping live; the region goes with the last holder's release.** A's release
/// gives back A's references only: B's mapping still resolves and still holds
/// B's bytes, B's capability still resolves (574 answers `-EBUSY`: resolved, and
/// already mapped), and the region keeps its generation. B's release frees it.
/// B's capability is granted here the way `held` grants one: in production
/// `Cap<Shm>` is minted only to the creator.
///
/// **Canary.** Free the region at the first holder's release (give back the
/// region's whole count in `release_holder_locked`): the count after A's
/// release reads `None`.
#[test]
fn another_tasks_references_keep_the_region_live_through_a_release() {
    use azos_ipc::cap::objref::SHM;
    use azos_ipc::memobj::memobj_ref;
    use azos_mm::vmm::translate_user;
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_b = ring3(b, SLOT_B);
    let pt_a = ring3(a, SLOT_A);

    let h_a = handle(sys_shm_create_typed(1, 1));
    let r = resource_of::<Shm>(a, h_a);
    let idx = SHM.idx(r);
    let va_a = sys_shm_map_typed(h_a, 0);
    assert!(va_a > 0, "A's map returned {va_a}");
    let h_b = held::<Shm>(b, CapPerms::RW.union(CapPerms::MAP), r);

    become_task(b, pt_b);
    let va_b = sys_shm_map_typed(h_b, 0);
    assert!(va_b > 0, "B's map returned {va_b}");
    let va_b = va_b as usize;
    put(va_b, b"held by B");
    assert_eq!(shm_refs(idx), Some(3), "A's two references and B's map");

    become_task(a, pt_a);
    assert_eq!(sys_shm_release_typed(h_a), 0, "the creator's release");
    assert!(translate_user(pt_a, va_a as usize, false).is_none(), "A's mapping is gone");
    assert_eq!(shm_refs(idx), Some(1), "B's reference is all that is left");
    assert_eq!(memobj_ref(idx), Some(r), "the region kept its generation");

    become_task(b, pt_b);
    assert!(translate_user(pt_b, va_b, true).is_some(), "B's mapping survived A's release");
    let mut got = [0u8; 9];
    assert!(azos_sched::copy_from_user(got.as_mut_ptr(), va_b, got.len()));
    assert_eq!(&got, b"held by B");
    assert_eq!(sys_shm_map_typed(h_b, 0), errno(Errno::EBUSY), "B's capability still resolves");
    assert_eq!(sys_shm_release_typed(h_b), 0, "the last holder's release");
    assert!(translate_user(pt_b, va_b, false).is_none());
    assert_eq!(shm_refs(idx), None, "the region went with the last reference");
    assert_eq!(memobj_ref(idx), None);
    assert_eq!(sys_shm_map_typed(h_b, 0), errno(Errno::ECAPSTALE), "B's release revoked B's capability");
}

/// **A space that ends takes its mapping of a shared object back, and the
/// object's frames stay with its other mapper.** Two tasks map one object; the
/// first ends as a task's space does (its records, then its tables). The
/// second still reads what the first wrote, and the end freed the first's
/// tables and nothing of the object: the space's sweep frees every user leaf
/// it finds, so the leaves of the shared mapping go first (`pager::unmap_shared`).
///
/// **Canary.** `mm-rmap-missing-canary`: the end leaves the leaves, and the
/// sweep frees the object's frames under the second mapper.
#[test]
fn a_space_that_ends_leaves_a_shared_object_to_its_other_mapper() {
    use azos_mm::vmm::translate_user;
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_b = ring3(b, SLOT_B);
    let pt_a = ring3(a, SLOT_A);
    let pages = 16;

    let h_a = handle(sys_shm_create_typed(pages as u64, 1));
    let r = resource_of::<Shm>(a, h_a);
    let va_a = sys_shm_map_typed(h_a, 0);
    assert!(va_a > 0, "A's map returned {va_a}");
    put(va_a as usize, b"written by A");
    let h_b = held::<Shm>(b, CapPerms::RW.union(CapPerms::MAP), r);
    become_task(b, pt_b);
    let va_b = sys_shm_map_typed(h_b, 0);
    assert!(va_b > 0, "B's map returned {va_b}");
    let va_b = va_b as usize;

    let in_use = azos_mm::shim_pages_in_use();
    azos_sched::set_current_user_pt(0);
    azos_sched::shim_end_space(pt_a);
    let released = in_use - azos_mm::shim_pages_in_use();
    assert!(released < pages, "the end of A's space freed {released} pages: the object's frames among them");
    azos_sched::set_current_user_pt(pt_b);
    assert!(translate_user(pt_b, va_b, true).is_some(), "B's mapping survived A's end");
    let mut got = [0u8; 12];
    assert!(azos_sched::copy_from_user(got.as_mut_ptr(), va_b, got.len()));
    assert_eq!(&got, b"written by A", "B reads the frame A wrote");
}

/// **A shared object's mapping is placed in the mmap area and leaves the break
/// where it was, and it cannot be made executable.** The flip to RX
/// (`DOMAIN_MODULE_MAP_X`, `vmm::set_user_range_exec`) refuses any range a
/// shared mapping touches: the object's frames carry no count, and only the
/// space's record says that another writer reaches them. The range lies where
/// the module window would (the mmap area reaches it), as an attacker with a
/// token would place it.
///
/// **Canaries.** `exec-shared-record-canary`: the flip asks nothing and
/// succeeds. `mmap-break-only-canary` is not this row's.
#[test]
fn a_shared_mapping_is_placed_in_the_mmap_area_and_never_made_executable() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let brk = azos_sched::update_user_brk(0);
    let h = handle(sys_shm_create_typed(2, 1));
    let va = sys_shm_map_typed(h, 0);
    assert!(va > 0, "map returned {va}");
    let va = va as usize;
    let (floor, ceiling) = azos_sched::user_mmap_area();
    assert!(va >= floor && va + 2 * azos_arch::mmu::PAGE_SIZE <= ceiling, "placed in the mmap area");
    assert_eq!(azos_sched::update_user_brk(0), brk, "the break did not move");
    let end = va + 2 * azos_arch::mmu::PAGE_SIZE;
    assert!(azos_mm::vmm::set_user_range_exec(pt, va, end).is_err(), "a shared object's frames were made executable");
    assert!(azos_mm::vmm::translate_user(pt, va, true).is_some(), "and the refusal left the mapping writable");
}

/// **A 574 that fails part-way leaves nothing behind.** The pages already
/// mapped go with the mapping's record, shot down, so the reference 574 took is
/// given back with them, and the region can be mapped again.
///
/// **Canary.** `shm-partial-map-kept-canary` keeps the pages and pins the
/// reference, as a map did when nothing named a partial mapping: the page
/// stays mapped and the record stays.
#[test]
fn a_map_that_fails_part_way_leaves_nothing_behind() {
    use azos_ipc::cap::objref::SHM;
    use azos_mm::vmm::translate_user;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let space = azos_sched::shim_space(pt);

    let h = handle(sys_shm_create_typed(2, 1));
    let idx = SHM.idx(resource_of::<Shm>(a, h));
    let next = azos_sched::user_mmap_area().1 - 2 * azos_arch::mmu::PAGE_SIZE;
    azos_sched::process::shim_fail_shm_map_after(Some(1));
    assert_eq!(sys_shm_map_typed(h, 0), errno(Errno::ENOMEM), "the second page could not be mapped");
    azos_sched::process::shim_fail_shm_map_after(None);
    assert!(translate_user(pt, next, false).is_none(), "the first page went with the map");
    assert_eq!(azos_mm::pager::shim_mappings(space), 0, "and the record");
    assert_eq!(shm_refs(idx), Some(1), "the failed map's reference went back");

    let va = sys_shm_map_typed(h, 0);
    assert!(va > 0, "the region maps again: {va}");
    assert_eq!(sys_shm_release_typed(h), 0);
    assert_eq!(shm_refs(idx), None, "and goes with its last reference");
}

// ═════════════════════════════════════════════════════════════════════════
// 575
// ═════════════════════════════════════════════════════════════════════════

/// An op through the entry, in the register form.
fn irq_invoke(line: u64, op: u16, w0: u64, w1: u64, w2: u64) -> i64 {
    let mut out = crate::dispatch::SyscallOut::new();
    crate::invoke::sys_invoke(line, azos_abi::invoke::INVOKE_REGS | op as u64, w0, w1, w2, 0, &mut out)
}

/// `PORT_BIND` of the line `line` (`PORT_SRC_IRQ`) on `port`.
fn irq_bind_op(line: u64, port: u64, key: u64, cpu: u64) -> i64 {
    let mut out = crate::dispatch::SyscallOut::new();
    let opw = azos_abi::invoke::INVOKE_REGS | azos_abi::invoke::PORT_BIND as u64;
    crate::invoke::sys_invoke(port, opw, azos_abi::syscall_nr::PORT_SRC_IRQ, line, key, cpu, &mut out)
}

/// `PORT_BIND_F_REMOVE` of the line `line` on `port`.
fn irq_unbind_op(line: u64, port: u64) -> i64 {
    let mut out = crate::dispatch::SyscallOut::new();
    let opw = azos_abi::invoke::INVOKE_REGS | azos_abi::invoke::PORT_BIND as u64;
    let ty = azos_abi::syscall_nr::PORT_SRC_IRQ | azos_abi::syscall_nr::PORT_BIND_F_REMOVE;
    crate::invoke::sys_invoke(port, opw, ty, line, 0, 0, &mut out)
}

fn irq_ack_op(line: u64) -> i64 {
    irq_invoke(line, azos_abi::invoke::DEVICE_IRQ_ACK, 0, 0, 0)
}

/// **`PORT_SRC_IRQ` binds the IRQ to the port its capability names, and the
/// binding delivers to no other port, the one created next at that index
/// included.**
///
/// **Canary.** Bind with the port's index (`PORT.idx(r)`) instead of its
/// reference: `irq_bind_port` refuses the bare index and the bind reads
/// `-ECAPSTALE`.
#[test]
fn an_irq_bind_delivers_to_the_port_its_capability_names() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);

    assert_eq!(irq_bind_op(irq, port, 0xAB, azos_abi::invoke::DEVICE_IRQ_CPU_ANY), 0, "the CPU the caller binds from");
    azos_ipc::irq_bind::irq_dispatch(IRQ);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16);
    let e = take16(BUF);
    assert_eq!(u64::from_le_bytes(e[..8].try_into().unwrap()), 0xAB, "the key");
    assert_eq!(e[8], azos_abi::syscall_nr::PORT_EVENT_IRQ, "an IRQ event");
    assert_eq!(u32::from_le_bytes(e[12..16].try_into().unwrap()), IRQ, "the IRQ number");
    assert_eq!(irq_ack_op(irq), 0, "the ACK unmasks");

    let r = resource_of::<Port>(a, port);
    assert_eq!(sys_port_destroy_typed(port), 0);
    let port2 = handle(sys_port_create_typed());
    assert_eq!(PORT.idx(resource_of::<Port>(a, port2)), PORT.idx(r), "precondition: the index was reused");
    azos_ipc::irq_bind::irq_dispatch(IRQ);
    assert_eq!(
        sys_port_poll_typed(port2, BUF as u64),
        errno(Errno::EAGAIN),
        "the port created next at the index received the old binding's event"
    );
}

/// **An IRQ event reaches ring 3 with the CPU its line is routed to in byte 9**
/// (and 0 in the code); the other events carry 0 there.
///
/// **Canary.** Leave `buf[PORT_EVENT_CPU_OFFSET]` unwritten in
/// `copy_port_event_out`: byte 9 reads 0 for a line routed to CPU 1.
#[test]
fn an_irq_event_carries_its_cpu_on_the_wire() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);
    // With `IRQ_THREADED` the explicit CPU is the one the reservation runs on.
    ipc_sched_shim::rt::set_reservation_cpu(1);
    let cpu = irq_bind_op(irq, port, 0xAB, 1);
    ipc_sched_shim::rt::set_reservation_cpu(0);
    assert_eq!(cpu, 1, "the line is routed to CPU 1");
    azos_ipc::irq_bind::irq_dispatch(IRQ);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16);
    let e = take16(BUF);
    assert_eq!(e[azos_abi::syscall_nr::PORT_EVENT_CPU_OFFSET], 1, "byte 9 is the CPU");
    assert_eq!(u16::from_le_bytes([e[10], e[11]]), 0, "and the code stays 0");
    assert_eq!(irq_ack_op(irq), 0);
    // An event that is not an interrupt's carries no CPU.
    azos_ipc::port::port_queue_event_ref(resource_of::<Port>(a, port), event(0x77)).unwrap();
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16);
    assert_eq!(take16(BUF)[azos_abi::syscall_nr::PORT_EVENT_CPU_OFFSET], 0);
}

/// **`PORT_SRC_IRQ` refuses in its documented order.** The op first, then
/// the port's capability (`WRITE`; a bind adds a source, so containment
/// refuses it), then the line's (its right: `READ`), then the CPU; a line
/// another task binds is `-EBUSY`. The ACK of a line nobody binds is
/// `-ENOENT`, and containment leaves an ACK live. The remove takes the
/// caller's binding and only it.
///
/// **Canaries.** Resolve the port with `get_uncontained`: the contained bind
/// reads the CPU. Ask `NONE` of the line: the one without `READ` binds. Take
/// the CPU as given: the bind to CPU 9 of 4 reads 9.
#[test]
fn an_irq_bind_refuses_in_its_documented_order() {
    use azos_abi::invoke::{op, CLASS_DRIVER, DEVICE_IRQ_CPU_ANY};
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    let ro_port = held::<Port>(a, CapPerms::READ, r);
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);
    let wo_irq = held::<Irq>(a, CapPerms::WRITE, IRQ);
    let forged_irq = CapHandle::pack(ty::IRQ, 1, 77).as_raw() as u64;
    let forged_port = CapHandle::pack(ty::PORT, 1, 78).as_raw() as u64;
    let any = DEVICE_IRQ_CPU_ANY;

    assert_eq!(irq_invoke(irq, op(CapKind::Device, CLASS_DRIVER, 99), 0, 0, 0), errno(Errno::EINVAL), "an unknown op");
    assert_eq!(irq_ack_op(forged_irq), errno(Errno::ECAPSTALE), "a forged line, ACK");
    assert_eq!(irq_bind_op(forged_irq, port, 1, any), errno(Errno::ECAPSTALE), "a forged line, bind");
    assert_eq!(irq_bind_op(wo_irq, port, 1, any), errno(Errno::ECAPPERMS), "a line without READ");
    assert_eq!(irq_ack_op(wo_irq), errno(Errno::ECAPPERMS), "a line without READ, ACK");
    assert_eq!(irq_bind_op(irq, forged_port, 1, any), errno(Errno::ECAPSTALE), "a forged port");
    assert_eq!(irq_bind_op(irq, port | 1 << 32, 1, any), errno(Errno::EINVAL), "a port handle past 32 bits");
    assert_eq!(irq_bind_op(irq | 1 << 32, port, 1, any), errno(Errno::EINVAL), "a line handle past 32 bits");
    assert_eq!(irq_bind_op(irq, ro_port, 1, any), errno(Errno::ECAPPERMS), "a READ-only port");
    assert_eq!(irq_bind_op(irq, irq, 1, any), errno(Errno::EINVAL), "a line as the port");
    assert_eq!(irq_bind_op(port, port, 1, any), errno(Errno::ECAPKIND), "a port as the line");
    assert_eq!(irq_bind_op(irq, port, 1, 9), errno(Errno::EINVAL), "a CPU that is not online");
    assert_eq!(irq_bind_op(irq, port, 1, u64::MAX - 1), errno(Errno::EINVAL));
    assert_eq!(irq_ack_op(irq), errno(Errno::ENOENT), "nobody binds the line yet");
    assert_eq!(azos_ipc::irq_bind::irq_bindings_of(IRQ), 0, "a refused bind stored a binding");

    azos_ipc::cap::degraded_set(true);
    assert_eq!(irq_bind_op(irq, port, 1, any), errno(Errno::EAGAIN), "a bind is contained");
    azos_ipc::cap::degraded_set(false);
    // With `IRQ_THREADED` the explicit CPU is the one the reservation runs on.
    ipc_sched_shim::rt::set_reservation_cpu(2);
    assert_eq!(irq_bind_op(irq, port, 1, 2), 2, "an explicit CPU is the one it goes to");
    ipc_sched_shim::rt::set_reservation_cpu(0);

    // A second task holding the line cannot take it from the first.
    ring3(b, SLOT_B);
    let port_b = handle(sys_port_create_typed());
    let irq_b = held::<Irq>(b, CapPerms::READ, IRQ);
    assert_eq!(irq_bind_op(irq_b, port_b, 2, any), errno(Errno::EBUSY), "a line another task binds");
    assert_eq!(irq_unbind_op(irq_b, port_b), errno(Errno::ENOENT), "a remove takes only the caller's binding");
    assert_eq!(azos_ipc::irq_bind::irq_bindings_of(IRQ), 1);
    become_task(a, pt_a);
    azos_ipc::cap::degraded_set(true);
    assert_eq!(irq_ack_op(irq), 0, "an ACK is not contained");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(irq_unbind_op(irq, port), 0, "the remove");
    assert_eq!(azos_ipc::irq_bind::irq_bindings_of(IRQ), 0, "the line is bound no more");
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16, "the remove told the port");
    let e = take16(BUF);
    assert_eq!(e[8], azos_abi::syscall_nr::PORT_EVENT_SOURCE_GONE, "a source-gone event");
    assert_eq!(u16::from_le_bytes([e[10], e[11]]), azos_abi::error::Errno::EREVOKED as u16);
    assert_eq!(u32::from_le_bytes(e[12..16].try_into().unwrap()), IRQ, "naming the line");
    assert_eq!(irq_ack_op(irq), errno(Errno::ENOENT), "and its ACK finds no binding");
}

/// **A message-signalled slot (`MSI_LINE | k`) binds through the same op and
/// answers the message its device writes.** The register form returns the
/// address, the data and the vector in `a1..a3`; the slot's vector is
/// delivered by `irq_msi_dispatch`, as the interrupt handlers do, and arrives
/// on the port with the slot as its source id; the ACK of an MSI is 0 and
/// touches no controller. A platform without MSI answers `-ENODEV`.
///
/// **Canary.** Leave `nrep` at 0 in `port_bind_irq`: the replies read back as the
/// words the call passed in.
#[test]
fn an_msi_slot_binds_and_answers_its_message() {
    use azos_ipc::irq_bind::{irq_msi_dispatch, set_msi_ops, MsiOps, MSI_LINE};
    fn alloc() -> Option<u32> { Some(77) }
    fn free(_: u32) {}
    fn enable(_: u32, _: u32) -> bool { true }
    fn message(id: u32, cpu: u32) -> Option<(u64, u32)> { Some((0xFEE0_0000 + cpu as u64 * 0x1000, id)) }
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let slot = held::<Irq>(a, CapPerms::READ, MSI_LINE | 5);

    // No MSI on this platform yet.
    assert_eq!(irq_bind_op(slot, port, 0x51, azos_abi::invoke::DEVICE_IRQ_CPU_ANY), errno(Errno::ENODEV));

    set_msi_ops(MsiOps { supported: || true, alloc, free, enable, message });
    ipc_sched_shim::rt::set_reservation_cpu(2);
    let mut out = crate::dispatch::SyscallOut::new();
    let rc = crate::invoke::sys_invoke(
        port,
        azos_abi::invoke::INVOKE_REGS | azos_abi::invoke::PORT_BIND as u64,
        azos_abi::syscall_nr::PORT_SRC_IRQ, slot, 0x51, 2, &mut out,
    );
    ipc_sched_shim::rt::set_reservation_cpu(0);
    assert_eq!(rc, 2, "the CPU asked for");
    assert!(out.written);
    assert_eq!(&out.regs[..3], &[0xFEE0_2000, 77, 77], "address, data, vector");

    assert!(irq_msi_dispatch(77));
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16);
    let e = take16(BUF);
    assert_eq!(u64::from_le_bytes(e[..8].try_into().unwrap()), 0x51, "the key");
    assert_eq!(u32::from_le_bytes(e[12..16].try_into().unwrap()), MSI_LINE | 5, "the slot");
    assert_eq!(irq_ack_op(slot), 0);
    azos_ipc::irq_bind::irq_unbind_all(a);
    assert!(!irq_msi_dispatch(77), "the vector is still held after the unbind");
    set_msi_ops(MsiOps { supported: || false, alloc: || None, free, enable, message });
}

/// **575 refuses in its documented order.** The port capability first, then
/// the source type, then the source's capability; containment refuses a bind.
///
/// **Canaries.** Resolve the port with `get_uncontained`: the contained bind
/// reads 0. Resolve a ring source as an IRQ capability: the
/// IRQ handle as a ring source reads `-ECAPKIND`.
#[test]
fn a_typed_bind_refuses_in_its_documented_order() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    let ro_port = held::<Port>(a, CapPerms::READ, r);
    // A handle of the wrong kind for every source.
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);

    assert_eq!(sys_port_bind_typed(0, PORT_SRC_ENDPOINT, irq, 1, 0), errno(Errno::ECAPSTALE), "a forged port handle first");
    assert_eq!(sys_port_bind_typed(ro_port, PORT_SRC_RING, irq, 1, 0), errno(Errno::ECAPPERMS), "a READ-only port");
    assert_eq!(sys_port_bind_typed(irq, PORT_SRC_RING, irq, 1, 0), errno(Errno::ECAPKIND), "an IRQ handle as the port");
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_DOORBELL + 1, irq, 1, 0), errno(Errno::EINVAL), "an unknown source type");
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_RING, irq, 1, 4), errno(Errno::EINVAL), "an offset is a doorbell's");
    assert_eq!(sys_port_bind_typed(port, u64::MAX, irq, 1, 0), errno(Errno::EINVAL));
    // Wave 11 (PORTWAIT): a ring and an endpoint take their own capability, a
    // timer none (its source is a deadline). Type 0 was the channel: no source;
    // type 2 was the IRQ line, which binds from its own side.
    assert_eq!(sys_port_bind_typed(port, 0, irq, 1, 0), errno(Errno::EINVAL), "source type 0");
    let mut typed_sources = vec![PORT_SRC_RING, PORT_SRC_ENDPOINT, PORT_SRC_CALLS];
    if azos_limits::FUTEX_SHARED {
        typed_sources.push(PORT_SRC_DOORBELL);
    }
    for typed in typed_sources {
        assert_eq!(sys_port_bind_typed(port, typed, 0, 1, 0), errno(Errno::ECAPSTALE), "source type {typed}, forged");
        assert_eq!(sys_port_bind_typed(port, typed, irq, 1, 0), errno(Errno::ECAPKIND), "source type {typed}, an IRQ handle");
    }
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, u64::MAX, 1, 0), 0, "a timer needs no capability");
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER | 0x200, 0, 1, 0), errno(Errno::EINVAL), "an unknown flag");

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, u64::MAX, 1, 0), errno(Errno::EAGAIN), "a bind is contained");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, u64::MAX, 1, 0), 0);
}

/// **A pressure source names the caller's own Domain and binds its port.** The
/// source word is `DOMAIN_SELF` and nothing else; the Domain keeps the port's
/// reference and the key, a second bind replaces the first, and the remove form
/// takes it away only when the port and the key are the bound ones.
///
/// **Canary.** Store the binding without the key (0): the key row reads 0.
#[test]
fn a_pressure_bind_stores_the_port_on_the_callers_domain() {
    use azos_sched::domain;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let key = domain::create().unwrap();
    azos_sched::shim_bind_domain(a, key);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);
    let me = u64::from(azos_abi::invoke::DOMAIN_SELF.as_raw());

    if !azos_limits::MM_RECLAIM_COMPRESS {
        assert_eq!(sys_port_bind_typed(port, PORT_SRC_PRESSURE, me, 7, 0), errno(Errno::EINVAL), "no reclaim, no watermarks, no source");
        domain::leave(key);
        return;
    }
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_PRESSURE, 0, 7, 0), errno(Errno::EINVAL), "only the Domain itself");
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_PRESSURE, u64::from(irq), 7, 0), errno(Errno::EINVAL), "not a capability");
    assert_eq!(domain::pressure_port(key), None);

    assert_eq!(sys_port_bind_typed(port, PORT_SRC_PRESSURE, me, 7, 0), 0);
    let bound = domain::pressure_port(key).expect("bound");
    assert_eq!((bound.port, bound.key), (r, 7));
    assert_eq!(bound.epoch, azos_ipc::port::port_live_epoch(r).unwrap());

    assert_eq!(sys_port_bind_typed(port, PORT_SRC_PRESSURE, me, 8, 0), 0, "a second bind replaces the first");
    assert_eq!(domain::pressure_port(key).unwrap().key, 8);

    let remove = PORT_SRC_PRESSURE | PORT_BIND_F_REMOVE;
    assert_eq!(sys_port_bind_typed(port, remove, 0, 7, 0), errno(Errno::ENOENT), "the old key is no longer bound");
    assert!(domain::pressure_port(key).is_some());
    assert_eq!(sys_port_bind_typed(port, remove, 0, 8, 0), 0);
    assert_eq!(domain::pressure_port(key), None);
    assert_eq!(sys_port_bind_typed(port, remove, 0, 8, 0), errno(Errno::ENOENT));

    // A binding names a Port: the reclaim task's clear takes away the one it
    // found stale and no other.
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_PRESSURE, me, 9, 0), 0);
    let found = domain::pressure_port(key).unwrap();
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_PRESSURE, me, 10, 0), 0);
    assert!(!domain::clear_pressure_port(key, |now| *now == found), "rebound since: not cleared");
    let now = domain::pressure_port(key).unwrap();
    assert!(domain::clear_pressure_port(key, |b| *b == now));
    domain::leave(key);
}

// ═════════════════════════════════════════════════════════════════════════
// 577
// ═════════════════════════════════════════════════════════════════════════

/// **577 returns an event queued before it blocks without blocking, and one
/// queued while it blocks after one block on `WaitReason::Port` with the
/// port's packed reference.**
///
/// **Canary.** Block on the port's index (`PORT.idx(r)`) in
/// `sys_port_wait`: the recorded reason reads the index.
#[test]
fn a_typed_wait_returns_an_event_queued_before_or_while_it_blocks() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);

    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x11)), Ok(()));
    assert_eq!(sys_port_wait(port, BUF as u64, u64::MAX), 16);
    assert_eq!(key_at_buf(), 0x11);
    assert!(azos_sched::shim_take_blocks().is_empty(), "a queued event needs no block");

    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        let _ = azos_ipc::port::port_queue_event_ref(r, event(0x22));
    })));
    assert_eq!(sys_port_wait(port, BUF as u64, u64::MAX), 16);
    assert_eq!(key_at_buf(), 0x22);
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Port(r)]);
    assert_ne!(r, PORT.idx(r), "precondition: the reference is not the bare index");
}

/// **The port wait ends at once when the port is destroyed while it waits.**
///
/// **Canary.** Wait on a gone port as on an empty one in `port_wait_until_ref`
/// (block and go round on any refusal but `Full`): the destroyed port's wait
/// blocks again, and the block count reads 2.
#[test]
fn a_typed_wait_ends_on_a_destroy() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);

    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        let _ = azos_ipc::port::port_destroy_ref(r);
    })));
    assert_eq!(sys_port_wait(port, BUF as u64, u64::MAX), errno(Errno::ECAPSTALE));
    assert_eq!(azos_sched::shim_take_blocks().len(), 1, "a destroyed port is not waited on again");
    azos_sched::shim_set_block_hook(None);
}

/// **577 checks its capability and then its out pointer before it dequeues
/// anything; containment leaves it live; a kernel caller copies directly.**
///
/// **Canary.** Check the out pointer after the wait: the unwritable wait
/// consumes the event and the poll reads `-EAGAIN`.
#[test]
fn a_typed_wait_checks_capability_and_out_pointer_before_it_dequeues() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    let wo_port = held::<Port>(a, CapPerms::WRITE, r);
    let chan = held::<Irq>(a, CapPerms::RW, IRQ);

    assert_eq!(sys_port_wait(port, 0, u64::MAX), errno(Errno::EINVAL), "a null out pointer");
    assert_eq!(sys_port_wait(0, BUF as u64, u64::MAX), errno(Errno::ECAPSTALE), "a forged handle");
    assert_eq!(sys_port_wait(chan, BUF as u64, u64::MAX), errno(Errno::ECAPKIND), "a handle of another kind");
    assert_eq!(sys_port_wait(wo_port, BUF as u64, u64::MAX), errno(Errno::ECAPPERMS), "no READ");
    assert!(azos_sched::shim_take_blocks().is_empty(), "no refusal blocked");

    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x33)), Ok(()));
    assert_eq!(sys_port_wait(port, UNMAPPED, u64::MAX), errno(Errno::EFAULT));
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16, "the refused wait left the event queued");
    assert_eq!(key_at_buf(), 0x33);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x44)), Ok(()));
    assert_eq!(sys_port_wait(port, BUF as u64, u64::MAX), 16, "a wait while contained");
    assert_eq!(key_at_buf(), 0x44);
    azos_ipc::cap::degraded_set(false);

    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x55)), Ok(()));
    azos_sched::set_current_user_pt(0);
    let mut out = [0u8; 16];
    assert_eq!(sys_port_wait(port, out.as_mut_ptr() as u64, u64::MAX), 16, "a kernel caller");
    assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 0x55);
    become_task(a, pt);
}

/// The protect hook the kernel registers (`kernel/src/boot/sched.rs`), over the
/// real `vmm` this crate runs on the host.
fn host_protect(root: usize, va: usize, pages: usize, write: bool) -> usize {
    let end = va + pages * azos_arch::mmu::PAGE_SIZE;
    azos_mm::vmm::set_user_range_write(root, va, end, write)
}

// ═════════════════════════════════════════════════════════════════════════
// 575 sources and 604 (wave 11, PORTWAIT)
// ═════════════════════════════════════════════════════════════════════════

/// The 16-byte event at `BUF`: `(key, source type, source id)`.
fn event_at_buf() -> (u64, u8, u32) {
    let e = take16(BUF);
    (
        u64::from_le_bytes(e[..8].try_into().unwrap()),
        e[8],
        u32::from_le_bytes(e[12..16].try_into().unwrap()),
    )
}

/// Ticks of the 10 MHz host counter at `ns`, rounded up: the `Timer` reason a
/// wait until `ns` blocks on.
fn ticks(ns: u64) -> u64 {
    azos_abi::time::ns_to_ticks_ceil(ns, azos_drv_sys::timebase::TIMER_FREQ)
}

/// **604 with a passed deadline polls; with a future one and nothing bound it
/// blocks once on `Timer` until that deadline and answers 0; an armed timer
/// earlier than the deadline ends the block at the timer and is the event
/// (type 4); with no deadline and no timer it blocks on `Port` and an event
/// sent meanwhile is returned; a refused block answers `-EBUSY`.**
///
/// **Canaries.** Block on `WaitReason::Port` whatever `until` says
/// (`port_block_reason`): the deadline wait records `Port`. Treat the
/// timed-out wait as `-EAGAIN`: the 0 answer reads -11.
#[test]
fn the_deadline_wait_blocks_until_the_earlier_of_its_deadline_and_a_timer() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    azos_drv_irqchip::clint::set_time(ticks(1_000_000));
    azos_sched::shim_arm_block_outcome(azos_sched::BlockOutcome::Returned);
    // The block stands for the sleep: the clock moves to the instant blocked on.
    let to_deadline = || -> azos_sched::BlockHook {
        Box::new(|reason| match reason {
            WaitReason::Timer(t) => azos_drv_irqchip::clint::set_time(t),
            other => panic!("a wait with a deadline blocked on {other:?}, which no timer ends"),
        })
    };

    assert_eq!(sys_port_wait(port, BUF as u64, 0), 0, "a passed deadline polls");
    assert!(azos_sched::shim_take_blocks().is_empty(), "without blocking");

    azos_sched::shim_set_block_hook(Some(to_deadline()));
    assert_eq!(sys_port_wait(port, BUF as u64, 3_000_000), 0, "timed out");
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Timer(ticks(3_000_000))]);

    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, 4_000_000, 0x7, 0), 0, "a timer at 4 ms");
    assert_eq!(sys_port_wait(port, BUF as u64, 9_000_000), 16);
    assert_eq!(event_at_buf(), (0x7, 4, 0));
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Timer(ticks(4_000_000))], "woke at the timer");

    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        let _ = azos_ipc::port::port_queue_event_ref(r, event(0x99));
    })));
    assert_eq!(sys_port_wait(port, BUF as u64, u64::MAX), 16);
    assert_eq!(key_at_buf(), 0x99);
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Port(r)], "no deadline: Port");

    azos_sched::shim_set_block_hook(None);
    azos_sched::shim_arm_block_outcome(azos_sched::BlockOutcome::Refused);
    assert_eq!(sys_port_wait(port, BUF as u64, u64::MAX), errno(Errno::EBUSY));
    assert_eq!(azos_sched::shim_take_blocks().len(), 1, "one refused block, no spin");
    azos_sched::shim_disarm_block_outcome();
}

/// **577 never sleeps past an armed timer source: it blocks on `Timer` until
/// the timer and returns its event.**
///
/// **Canary.** Ignore `until` in `port_wait_ref_at` (always block on
/// `Port`): the recorded reason is `Port` and the wait reads `-EAGAIN`.
#[test]
fn a_typed_wait_wakes_for_an_armed_timer() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    azos_drv_irqchip::clint::set_time(ticks(1_000_000));
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, 2_000_000, 0x42, 0), 0);
    azos_sched::shim_set_block_hook(Some(Box::new(|reason| match reason {
        WaitReason::Timer(t) => azos_drv_irqchip::clint::set_time(t),
        other => panic!("577 with an armed timer blocked on {other:?}, which no timer ends"),
    })));
    assert_eq!(sys_port_wait(port, BUF as u64, u64::MAX), 16);
    assert_eq!(event_at_buf(), (0x42, 4, 0));
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Timer(ticks(2_000_000))]);
}

// ═════════════════════════════════════════════════════════════════════════
// 575 source 4: endpoint notices, and gone sources (wave 15 N5b)
// ═════════════════════════════════════════════════════════════════════════

/// The event code at `BUF` (bytes 10..12).
fn code_at_buf() -> u16 {
    let e = take16(BUF);
    let c = azos_abi::syscall_nr::PORT_EVENT_CODE_OFFSET;
    u16::from_le_bytes([e[c], e[c + 1]])
}

/// **575 binds an endpoint's notices for its serving task only (`-EPERM` for
/// a holder of `READ` that does not serve it); revoking the last send
/// capability (`WRITE` without `READ`) anywhere posts one no-senders event
/// (type 5, code `ENOSENDERS`, the server's handle); destroying the endpoint
/// posts one source-gone event (type 6, code `EREVOKED`) and frees the
/// slot.**
///
/// **Canaries.** Count every `WRITE` capability (drop the `!READ` in
/// `cap::senders::counted`): the server's own `RW` keeps the count at 1 and
/// the no-senders poll reads `-EAGAIN`. Return before marking in
/// `port_source_gone`: the gone polls read `-EAGAIN`.
#[test]
fn an_endpoint_bound_to_a_port_reports_no_senders_and_its_destruction() {
    use azos_ipc::cap::targets::Endpoint;
    let _g = serial();
    azos_ipc::cap::senders::set_hooks(azos_ipc::endpoint::sender_delta, azos_ipc::endpoint::flush_notices);
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_b = ring3(b, SLOT_B);
    let pt_a = ring3(a, SLOT_A);
    let ep = handle(sys_endpoint_create_typed());
    let r = resource_of::<Endpoint>(a, ep);
    assert_eq!(azos_ipc::endpoint::senders_of(r), Some(0), "the server's RW is not a sender");
    let send = azos_ipc::cap_store::grant::<Endpoint>(b, CapPerms::WRITE, r).expect("client cap");
    let b_read = held::<Endpoint>(b, CapPerms::READ, r);
    assert_eq!(azos_ipc::endpoint::senders_of(r), Some(1));

    let port = handle(sys_port_create_typed());
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_ENDPOINT, ep, 0xE1, 0), 0);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), errno(Errno::EAGAIN), "one sender left: nothing");

    // A holder of READ that does not serve the endpoint may not bind it.
    become_task(b, pt_b);
    let port_b = handle(sys_port_create_typed());
    assert_eq!(sys_port_bind_typed(port_b, PORT_SRC_ENDPOINT, b_read, 1, 0), errno(Errno::EPERM));

    azos_ipc::cap_store::revoke(b, send);
    become_task(a, pt_a);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16, "the last sender went");
    assert_eq!(event_at_buf(), (0xE1, 5, ep as u32));
    assert_eq!(code_at_buf(), Errno::ENOSENDERS as u16);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), errno(Errno::EAGAIN), "once");

    assert_eq!(azos_ipc::endpoint::destroy_ref_as(r, a), Ok(()));
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16, "the endpoint went");
    assert_eq!(event_at_buf(), (0xE1, 6, ep as u32));
    assert_eq!(code_at_buf(), Errno::EREVOKED as u16);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), errno(Errno::EAGAIN), "a gone source reports once");

}

// ── D4/L6: MemObj through the frozen syscalls ───────────────────────────────

/// **The creation word of 533 has fields, and the reserved ones are refused.**
/// The values 0 and 1 keep their meaning; ring 3 creates Anon and Contig (Phys
/// and Paged are not its to ask for); a Contig object takes neither the
/// swappable nor the volatile attribute and is never cloned; swappable,
/// volatile and NO_KERNEL_MAP are accepted on an Anon one; the clone bit and
/// the source capability go together.
#[test]
fn the_creation_word_has_fields_and_refuses_the_reserved_ones() {
    use azos_abi::syscall_nr::*;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let _pt = ring3(a, SLOT_A);
    let einval = errno(Errno::EINVAL);
    for ok in [
        0u64,
        1,
        1 | (SHM_ATTR_SWAPPABLE << SHM_CREATE_ATTR_SHIFT),
        1 | (SHM_ATTR_NO_KERNEL_MAP << SHM_CREATE_ATTR_SHIFT),
        1 | (SHM_ATTR_VOLATILE << SHM_CREATE_ATTR_SHIFT),
        1 | (SHM_KIND_CONTIG << SHM_CREATE_KIND_SHIFT),
        1 | (SHM_KIND_CONTIG << SHM_CREATE_KIND_SHIFT) | (SHM_ATTR_NO_KERNEL_MAP << SHM_CREATE_ATTR_SHIFT),
    ] {
        let h = handle(sys_shm_create_typed(1, ok));
        assert_eq!(sys_shm_release_typed(h), 0, "word {ok:#x}");
    }
    for bad in [
        2u64,
        1 | (1 << SHM_CREATE_KIND_SHIFT),
        1 | (SHM_KIND_CONTIG << SHM_CREATE_KIND_SHIFT) | (SHM_ATTR_SWAPPABLE << SHM_CREATE_ATTR_SHIFT),
        1 | (SHM_KIND_CONTIG << SHM_CREATE_KIND_SHIFT) | (SHM_ATTR_VOLATILE << SHM_CREATE_ATTR_SHIFT),
        1 | (SHM_KIND_CONTIG << SHM_CREATE_KIND_SHIFT) | SHM_CREATE_CLONE | (1u64 << SHM_CREATE_SRC_SHIFT),
        1 | (3 << SHM_CREATE_KIND_SHIFT),
        1 | (8 << SHM_CREATE_ATTR_SHIFT),
        1 | (5u64 << SHM_CREATE_SRC_SHIFT),
        1 | SHM_CREATE_CLONE,
        1 | (1 << 30),
    ] {
        assert_eq!(sys_shm_create_typed(1, bad), einval, "word {bad:#x}");
    }
    // Nothing was left behind by the refusals.
    assert_eq!(azos_ipc::memobj::memobj_info(0), None);
}

/// **Clone through 533.** The snapshot shares frames until a write mapping
/// breaks them; a clone of a capability the caller does not hold is refused; the
/// size is the source's.
#[test]
fn a_clone_through_533_shares_frames_until_it_is_mapped_for_write() {
    use azos_abi::syscall_nr::*;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let _pt = ring3(a, SLOT_A);
    let src = handle(sys_shm_create_typed(2, 1));
    let rs = resource_of::<Shm>(a, src);
    let p0 = azos_ipc::memobj::memobj_page_phys_ref(rs, 0).unwrap().unwrap();
    unsafe { *(p0 as *mut u8) = 0x42 };

    let word = 1 | SHM_CREATE_CLONE | (src << SHM_CREATE_SRC_SHIFT);
    assert_eq!(sys_shm_create_typed(3, word), errno(Errno::EINVAL), "a size that is not the source's");
    assert_eq!(sys_shm_create_typed(0, 1 | SHM_CREATE_CLONE | (0x7fff_ffffu64 << SHM_CREATE_SRC_SHIFT)),
        errno(Errno::ECAPSTALE), "a source nobody holds");
    let clone = handle(sys_shm_create_typed(0, word));
    let rc = resource_of::<Shm>(a, clone);
    assert_ne!(rc, rs);
    assert_eq!(azos_ipc::memobj::memobj_page_phys_ref(rc, 0), Ok(Some(p0)), "frames are shared");
    // A write mapping gives the clone frames of its own first.
    let va = sys_shm_map_typed(clone, 0);
    assert!(va > 0, "map: {va}");
    let c0 = azos_ipc::memobj::memobj_page_phys_ref(rc, 0).unwrap().unwrap();
    assert_ne!(c0, p0, "the write mapping broke the share");
    assert_eq!(unsafe { *(c0 as *const u8) }, 0x42, "with the bytes it had");
    assert_eq!(azos_ipc::memobj::memobj_describe_ref(rc).unwrap().cow_shared, 0);
    assert_eq!(sys_shm_release_typed(clone), 0);
    assert_eq!(sys_shm_release_typed(src), 0);
}

/// **The protect form of 574 is the object's protect.** A writable mapping can
/// drop to read-only (the real PTE) and come back; a mapping a READ-only share
/// made cannot be raised; a task with no mapping, unknown bits and a protect
/// without the protect flag are refused; a clone's shared frames refuse a write
/// protect.
///
/// **Canary** `memobj-protect-max-canary`: the share's mapping is raised.
#[test]
fn the_protect_form_of_574_stays_within_what_the_map_was_allowed() {
    use azos_abi::syscall_nr::{SHM_MAP_OP_PROTECT, SHM_MAP_PROT_WRITE};
    use azos_mm::vmm::user_write_would_be_permitted as writable;
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let pt_b = ring3(b, SLOT_B);
    azos_ipc::memobj::set_protect_hook(host_protect);
    let page = azos_arch::PAGE_SIZE;
    let ro_op = SHM_MAP_OP_PROTECT;
    let rw_op = SHM_MAP_OP_PROTECT | SHM_MAP_PROT_WRITE;

    become_task(a, pt_a);
    let cap = handle(sys_shm_create_typed(2, 1));
    assert_eq!(sys_shm_map_typed(cap, ro_op), errno(Errno::EBADF), "no mapping yet");
    let va = sys_shm_map_typed(cap, 0);
    assert!(va > 0, "map: {va}");
    let uva = va as usize;
    assert!(writable(pt_a, uva), "precondition");
    assert_eq!(sys_shm_map_typed(cap, ro_op), 0);
    assert!(!writable(pt_a, uva) && !writable(pt_a, uva + page), "the PTEs dropped to read-only");
    assert_eq!(sys_shm_map_typed(cap, rw_op), 0);
    assert!(writable(pt_a, uva) && writable(pt_a, uva + page), "and came back");
    assert_eq!(sys_shm_map_typed(cap, 1), errno(Errno::EINVAL), "a write bit without the protect flag");
    assert_eq!(sys_shm_map_typed(cap, ro_op | (1 << 20)), errno(Errno::EINVAL), "an unknown bit");

    // B maps through a READ-only share: read-only, and a protect cannot raise it.
    let r = resource_of::<Shm>(a, cap);
    let ro = held::<Shm>(b, CapPerms::READ.union(CapPerms::MAP), r);
    become_task(b, pt_b);
    let bva = sys_shm_map_typed(ro, 0);
    assert!(bva > 0, "map: {bva}");
    assert!(!writable(pt_b, bva as usize), "the share maps read-only");
    assert_eq!(sys_shm_map_typed(ro, rw_op), errno(Errno::ECAPPERMS), "protect raised past the map's rights");
    assert!(!writable(pt_b, bva as usize), "and the PTE did not change");
    assert_eq!(sys_shm_release_typed(ro), 0);

    // A clone's shared frames: a write protect is refused while they are shared,
    // and allowed again once the other sharer has gone.
    become_task(a, pt_a);
    assert_eq!(sys_shm_map_typed(cap, ro_op), 0);
    let clone = handle(sys_shm_create_typed(0, 1 | azos_abi::syscall_nr::SHM_CREATE_CLONE
        | (cap << azos_abi::syscall_nr::SHM_CREATE_SRC_SHIFT)));
    assert_eq!(sys_shm_map_typed(cap, rw_op), errno(Errno::EBUSY), "the frames are shared with the clone");
    assert_eq!(sys_shm_release_typed(clone), 0);
    assert_eq!(sys_shm_map_typed(cap, rw_op), 0, "the clone is gone: the frames are the object's again");
    assert!(writable(pt_a, uva));
    assert_eq!(sys_shm_release_typed(cap), 0);
}

/// A fork child's real leaves ([`azos_mm::cow::ForkLeaves`]), with what another
/// hart does while the copy is made.
struct RacedLeaves {
    leaves: azos_mm::cow::ForkLeaves,
    during_copy: Option<Box<dyn FnOnce()>>,
}

impl azos_ipc::memobj::ChildLeaves for RacedLeaves {
    fn copy(&mut self) -> bool {
        let copied = self.leaves.copy();
        if let Some(f) = self.during_copy.take() {
            f();
        }
        copied
    }
    fn leaf(&self, va: usize) -> Option<(usize, bool)> {
        self.leaves.leaf(va)
    }
    fn set_write(&mut self, write: bool) {
        self.leaves.set_write(write)
    }
    fn remove(&mut self) {
        self.leaves.remove()
    }
}

/// **A fork child's inherited mapping: its record and its leaves agree, with
/// the parent's access at the booking.** The child's leaves are the parent's,
/// copied before the booking; the parent's mapping turns read-only meanwhile
/// and a clone is taken. The clone copies, and the child is booked read-only
/// with read-only leaves. The other way, leaves copied read-only and the
/// parent writable again by the booking: the child's leaves become writable
/// with its record.
///
/// **Canary** `memobj-inherit-unmarked-canary`: the clone shares the frame
/// under the child's writable leaf.
#[test]
fn a_fork_childs_inherited_record_and_leaves_agree_with_the_parent_at_the_booking() {
    use azos_ipc::memobj::{self as mo, ChildLeaves, MapAccess, MemPerms};
    use azos_mm::vmm::user_write_would_be_permitted as writable;
    use std::sync::Arc;
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let pt_b = ring3(b, SLOT_B);
    mo::set_protect_hook(host_protect);
    become_task(a, pt_a);
    let cap = handle(sys_shm_create_typed(1, 1));
    let va = sys_shm_map_typed(cap, 0);
    assert!(va > 0, "map: {va}");
    let (uva, r) = (va as usize, resource_of::<Shm>(a, cap));
    assert!(mo::memobj_acquire_ref(b, r).is_ok());

    let shared = Arc::new(AtomicU32::new(u32::MAX));
    let seen = shared.clone();
    let mut leaves = RacedLeaves {
        leaves: azos_mm::cow::ForkLeaves { parent_pt: pt_a, child_pt: pt_b, va: uva, pages: 1 },
        during_copy: Some(Box::new(move || {
            assert!(writable(pt_b, uva), "precondition: the copied leaf is writable");
            assert_eq!(mo::memobj_protect_ref(a, r, false), Ok(()));
            let c = mo::memobj_clone(a, r, a, MemPerms::ReadOnly).expect("clone");
            seen.store(mo::memobj_describe_ref(r).unwrap().cow_shared as u32, Ordering::SeqCst);
            assert_eq!(mo::memobj_release_ref(a, c), Ok(()));
        })),
    };
    assert_eq!(mo::memobj_inherit_ref(a, b, r, pt_b, uva, 1, &mut leaves), Ok(MapAccess { write: false, max_write: true }));
    assert_eq!(shared.load(Ordering::SeqCst), 0, "a clone shares a frame under a writable leaf");
    assert!(!writable(pt_b, uva), "the child is booked read-only over a writable leaf");

    // Read-only leaves copied, the parent writable again by the booking.
    assert_eq!(mo::memobj_unmap_begin_ref(b, r), Ok(Some((uva, 1))));
    leaves.remove();
    mo::memobj_unmap_end_ref(b, r);
    leaves.during_copy = Some(Box::new(move || {
        assert!(!writable(pt_b, uva), "precondition: the copied leaf is read-only");
        assert_eq!(mo::memobj_protect_ref(a, r, true), Ok(()));
    }));
    assert_eq!(mo::memobj_inherit_ref(a, b, r, pt_b, uva, 1, &mut leaves), Ok(MapAccess::RW));
    assert!(writable(pt_b, uva), "the child is booked writable over a read-only leaf");
    assert_eq!(sys_shm_release_typed(cap), 0);
}

/// **MOVE through the IPC transfer, end to end.** A task that maps an object
/// and sends its capability by a MOVE entry loses the mapping (the real PTE,
/// through the unmap hook), the receiver holds the references and the ownership,
/// and the charge follows. The window addresses the MOVE freed are the sender's
/// to take back.
///
/// **Canary** `memobj-move-keeps-map-canary`: the sender's mapping survives.
#[test]
fn a_moved_capability_takes_the_senders_mapping_with_it() {
    use azos_mm::vmm::translate_user;
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let _pt_b = ring3(b, SLOT_B);
    fn unmap(root: usize, va: usize, pages: usize) {
        let end = va + pages * azos_arch::PAGE_SIZE;
        azos_mm::vmm::unmap_user_range_keep(root, va, end);
    }
    azos_ipc::memobj::set_unmap_hook(unmap);
    azos_ipc::cap_store::set_move_hook(azos_ipc::memobj::memobj_moved);
    struct Unhook;
    impl Drop for Unhook {
        fn drop(&mut self) {
            azos_ipc::memobj::__clear_hooks_for_tests();
            azos_ipc::cap_store::__clear_move_hook_for_tests();
        }
    }
    let _u = Unhook;

    become_task(a, pt_a);
    let cap = handle(sys_shm_create_typed(1, 1));
    let va = sys_shm_map_typed(cap, 0) as usize;
    assert!(translate_user(pt_a, va, false).is_some(), "mapped");
    let r = resource_of::<Shm>(a, cap);
    let x = azos_ipc::cap_store::CapXfer::new(CapHandle::from_raw(cap as u32), false);
    let mut out = [CapHandle::from_raw(0); 1];
    azos_ipc::cap_store::move_caps(a, b, &[x], false, &mut out).expect("MOVE");
    assert!(translate_user(pt_a, va, false).is_none(), "MOVE left the sender's mapping");
    assert_eq!(azos_ipc::memobj::memobj_owner(azos_ipc::cap::objref::SHM.idx(r)), Some(b), "the receiver owns it");
    assert!(azos_ipc::memobj::memobj_has_mapping_ref(a, r) == Ok(false));
    // The sender's record is stale; its next shm call, `mmap` or `munmap` drops it.
    become_task(a, pt_a);
    let space = azos_sched::shim_space(pt_a);
    assert_eq!(azos_mm::pager::shim_mappings(space), 1, "the sender's record outlives the MOVE until it looks");
    assert!(azos_mm::pager::stale_pending(space));
    crate::ipc_handlers::reap_stale_mappings();
    assert_eq!(azos_mm::pager::shim_mappings(space), 0, "the sender dropped it");
    assert!(!azos_mm::pager::stale_pending(space), "and has looked");
}

/// **No record of a moved mapping outlives the sender's next look, however
/// many moved.** As many MOVEs as the space has records (more than the old
/// table of pending windows had rows): every record is stale, and one reap drops them all, so no address stays
/// blocked.
///
/// **Canary.** `stale-record-kept-canary`: the reap drops nothing.
#[test]
fn every_record_of_a_moved_mapping_is_dropped_by_the_senders_next_look() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let _pt_b = ring3(b, SLOT_B);
    fn unmap(root: usize, va: usize, pages: usize) {
        let end = va + pages * azos_arch::PAGE_SIZE;
        azos_mm::vmm::unmap_user_range_keep(root, va, end);
    }
    azos_ipc::memobj::set_unmap_hook(unmap);
    azos_ipc::cap_store::set_move_hook(azos_ipc::memobj::memobj_moved);
    struct Unhook;
    impl Drop for Unhook {
        fn drop(&mut self) {
            azos_ipc::memobj::__clear_hooks_for_tests();
            azos_ipc::cap_store::__clear_move_hook_for_tests();
        }
    }
    let _u = Unhook;

    become_task(a, pt_a);
    let space = azos_sched::shim_space(pt_a);
    let moves = azos_mm::pager::MAPPINGS_PER_SPACE.min(azos_ipc::memobj::MAX_MEMOBJS_PER_TASK);
    assert!(moves >= 8, "fewer MOVEs than the old table had rows");
    let mut caps = Vec::new();
    for k in 0..moves {
        let cap = handle(sys_shm_create_typed(1, 1));
        let va = sys_shm_map_typed(cap, 0);
        assert!(va > 0, "map {k} returned {va}");
        caps.push(cap);
    }
    for cap in caps {
        let x = azos_ipc::cap_store::CapXfer::new(CapHandle::from_raw(cap as u32), false);
        let mut out = [CapHandle::from_raw(0); 1];
        azos_ipc::cap_store::move_caps(a, b, &[x], false, &mut out).expect("MOVE");
    }
    assert_eq!(azos_mm::pager::shim_mappings(space), moves, "every record is stale");
    crate::ipc_handlers::reap_stale_mappings();
    assert_eq!(azos_mm::pager::shim_mappings(space), 0, "the next look dropped them all");
    let again = sys_shm_create_typed(1, 1);
    let va = sys_shm_map_typed(handle(again), 0);
    assert!(va > 0, "and the space maps again: {va}");
}

/// **A share outlives the sharer's close, and an explicit revoke takes it back
/// (delete is not revoke, owner decision 20-10).** A creates an object, shares
/// it with B by a DUP entry (the spawn's pipe-region share) and B maps it for
/// real. A closes its capability (`SYS_CAP_CLOSE`: its reference goes, its slot
/// goes): B's capability resolves and B's PTEs stay, and B reads what A wrote.
/// In a second setup A revokes what it derived (`SYS_CAP_REVOKE`) instead: B's
/// mapping is unmapped and its capability is stale.
///
/// **Canary** `delete-revokes-canary` (a close revokes the copies): the first
/// half fails. `memobj-sweep-no-hook-canary` (the sweep does not call the
/// hook): the second half fails.
#[test]
fn a_share_survives_the_sharers_close_and_dies_with_an_explicit_revoke() {
    use azos_mm::vmm::translate_user;
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let pt_b = ring3(b, SLOT_B);
    fn unmap(root: usize, va: usize, pages: usize) {
        let end = va + pages * azos_arch::PAGE_SIZE;
        azos_mm::vmm::unmap_user_range_keep(root, va, end);
    }
    azos_ipc::memobj::set_unmap_hook(unmap);
    azos_ipc::cap_store::set_swept_hook(azos_ipc::memobj::memobj_warrant_swept);
    struct Unhook;
    impl Drop for Unhook {
        fn drop(&mut self) {
            azos_ipc::memobj::__clear_hooks_for_tests();
            azos_ipc::cap_store::__clear_swept_hook_for_tests();
        }
    }
    let _u = Unhook;
    let share = |cap: u64| -> u64 {
        let x = azos_ipc::cap_store::CapXfer::new(CapHandle::from_raw(cap as u32), true);
        let mut out = [CapHandle::from_raw(0); 1];
        azos_ipc::cap_store::move_caps(a, b, &[x], true, &mut out).expect("DUP share");
        out[0].0 as u64
    };

    // 1. A closes: B keeps the object, its mapping and its capability.
    become_task(a, pt_a);
    let cap = handle(sys_shm_create_typed(1, 1));
    let shared = share(cap);
    become_task(b, pt_b);
    let bva = sys_shm_map_typed(shared, 0) as usize;
    assert!(translate_user(pt_b, bva, false).is_some(), "B mapped the share");
    become_task(a, pt_a);
    assert_eq!(sys_shm_release_typed(cap), 0, "A closes its capability (SYS_CAP_CLOSE's shm arm)");
    become_task(b, pt_b);
    assert!(translate_user(pt_b, bva, false).is_some(), "B's mapping survived A's close");
    assert!(azos_ipc::cap_store::get(b, azos_ipc::cap::Cap::<Shm>::from_raw(CapHandle::from_raw(shared as u32)),
        CapPerms::READ).is_ok(), "and B's capability resolves");

    // 2. A revokes what it derived: B loses the object and its mapping.
    become_task(a, pt_a);
    let cap = handle(sys_shm_create_typed(1, 1));
    let shared = share(cap);
    become_task(b, pt_b);
    let bva = sys_shm_map_typed(shared, 0) as usize;
    assert!(translate_user(pt_b, bva, false).is_some());
    become_task(a, pt_a);
    assert!(azos_ipc::cap_store::revoke_derived(a, CapHandle::from_raw(cap as u32)).is_ok(), "A revokes what it derived (SYS_CAP_REVOKE)");
    become_task(b, pt_b);
    assert!(translate_user(pt_b, bva, false).is_none(), "B's mapping went with the revoked share");
    assert_eq!(sys_shm_map_typed(shared, 0), errno(Errno::ECAPSTALE), "and its capability is stale");
}

// ═════════════════════════════════════════════════════════════════════════
// Op masks: the op a resolve names
// ═════════════════════════════════════════════════════════════════════════
//
// A capability whose warrant carries an `OP_MASK` is used by the ops of the
// classes the mask lists. Every resolve of the calls above names the op it
// performs (`CapTable::get_op`), so the capability answers an op of a class
// in its mask and refuses one outside it with `-ECAPPERMS`. Before the op was
// threaded these calls resolved with `get`, which refuses an op mask for
// every class: the "allowed" half of each test below was `-ECAPPERMS`.

use super::harness::{classes, op_masked};
use azos_abi::invoke::{CLASS_CTL, CLASS_DRIVER, CLASS_READ, CLASS_WAIT, CLASS_WRITE};

/// The copy of `h` that only `class` may use.
fn only(tid: u32, h: u64, class: u8) -> u64 {
    op_masked(tid, h, classes(&[class]))
}

/// **A port capability answers the ops of the classes its mask lists and only
/// those: `PORT_POLL` is `READ`, `PORT_BIND` and `PORT_DESTROY` are `CTL`, and
/// `SYS_PORT_WAIT`, a numbered syscall with no op, is the class-only op of
/// `WAIT`.** A refusal leaves the port as it was, and the last destroy goes
/// through the one copy that may.
///
/// **Canary.** Resolve any of the four with `get` (no op): its "allowed" half
/// reads `-ECAPPERMS`. Name the wrong class in one (`CLASS_WRITE` for the
/// wait): its allowed half is refused and the half that is not its class is
/// admitted.
#[test]
fn an_op_mask_gates_each_port_op_by_its_class() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    let (rd, ctl, wait, wr) = (
        only(a, port, CLASS_READ),
        only(a, port, CLASS_CTL),
        only(a, port, CLASS_WAIT),
        only(a, port, CLASS_WRITE),
    );
    let denied = errno(Errno::ECAPPERMS);

    // PORT_POLL: READ. An empty port answers -EAGAIN, which is the op running.
    assert_eq!(sys_port_poll_typed(rd, BUF as u64), errno(Errno::EAGAIN));
    for h in [ctl, wait, wr] {
        assert_eq!(sys_port_poll_typed(h, BUF as u64), denied);
    }
    // PORT_BIND: CTL.
    assert_eq!(sys_port_bind_typed(ctl, PORT_SRC_TIMER, u64::MAX, 1, 0), 0);
    for h in [rd, wait, wr] {
        assert_eq!(sys_port_bind_typed(h, PORT_SRC_TIMER, u64::MAX, 1, 0), denied);
    }
    // SYS_PORT_WAIT: WAIT.
    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x61)), Ok(()));
    for h in [rd, ctl, wr] {
        assert_eq!(sys_port_wait(h, BUF as u64, u64::MAX), denied);
    }
    assert_eq!(sys_port_wait(wait, BUF as u64, u64::MAX), 16);
    assert_eq!(key_at_buf(), 0x61, "the refused waits left the event queued");
    // PORT_DESTROY: CTL.
    for h in [rd, wait, wr] {
        assert_eq!(sys_port_destroy_typed(h), denied);
    }
    assert_eq!(sys_port_poll_typed(port, BUF as u64), errno(Errno::EAGAIN), "the refusals left the port");
    assert_eq!(sys_port_destroy_typed(ctl), 0);
    assert_eq!(sys_port_destroy_typed(ctl), errno(Errno::ECAPSTALE), "the destroy revoked the copy that made it");
}

/// **A memory object answers `SYS_MO_MAP`, `SYS_MO_UNMAP`, `MEMOBJ_ACQUIRE` and
/// `MEMOBJ_END_DROP` through a capability whose mask lists `CTL` (they make or
/// end the object's life) and refuses them through one that does not, with
/// the mapping and the references untouched.**
///
/// **Canary.** Resolve the release's mapping lookup (`table.get_op` in
/// `sys_shm_release_typed`) with `get`: the `CTL` copy's release unmaps
/// nothing and the translate below still finds the mapping, or the release
/// reads `-ECAPPERMS`.
#[test]
fn an_op_mask_gates_the_memory_object_ops_by_their_class() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let rw = handle(sys_shm_create_typed(1, 1));
    let (ctl, rd, wr) = (only(a, rw, CLASS_CTL), only(a, rw, CLASS_READ), only(a, rw, CLASS_WRITE));
    let denied = errno(Errno::ECAPPERMS);

    // MEMOBJ_ACQUIRE and MEMOBJ_END_DROP.
    for h in [rd, wr] {
        assert_eq!(sys_shm_acquire_typed(h, BUF as u64), denied);
        assert_eq!(sys_shm_end_drop_typed(h, azos_abi::invoke::SHM_END_READ), denied);
    }
    assert_eq!(sys_shm_acquire_typed(ctl, BUF as u64), 8);
    assert_ne!(
        sys_shm_end_drop_typed(ctl, azos_abi::invoke::SHM_END_READ),
        denied,
        "the CTL copy runs the op (a region that is no pipe has no end to drop: 0)"
    );
    // SYS_MO_MAP.
    for h in [rd, wr] {
        assert_eq!(sys_shm_map_typed(h, 0), denied);
    }
    let va = sys_shm_map_typed(ctl, 0);
    assert!(va > 0, "map returned {va}");
    let va = va as usize;
    assert!(azos_mm::vmm::translate_user(pt, va, true).is_some());
    // SYS_MO_UNMAP.
    for h in [rd, wr] {
        assert_eq!(sys_shm_release_typed(h), denied);
    }
    assert!(azos_mm::vmm::translate_user(pt, va, false).is_some(), "the refusals left the mapping");
    assert_eq!(sys_shm_release_typed(ctl), 0);
    assert!(azos_mm::vmm::translate_user(pt, va, false).is_none(), "the release through the CTL copy unmapped");
}

/// **An interrupt line answers `PORT_SRC_IRQ` and `DEVICE_IRQ_ACK` through
/// a capability whose mask lists `DRIVER`, and the port a bind reports to is a
/// the handle the bind is an op of: `PORT_BIND` steers it (`CTL`).** The port
/// is checked first, then the line.
///
/// **Canary.** Resolve the line with `class_op(ty::IRQ, CLASS_CTL)` in
/// `port_bind_irq`: the bind through the `DRIVER` copy reads `-ECAPPERMS`.
#[test]
fn an_op_mask_gates_the_irq_ops_and_the_port_they_report_to() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);
    let (drv, rd) = (only(a, irq, CLASS_DRIVER), only(a, irq, CLASS_READ));
    let (port_ctl, port_rd) = (only(a, port, CLASS_CTL), only(a, port, CLASS_READ));
    let denied = errno(Errno::ECAPPERMS);
    let any = azos_abi::invoke::DEVICE_IRQ_CPU_ANY;

    // The ACK of a line nobody binds is -ENOENT: the op ran.
    assert_eq!(irq_ack_op(rd), denied);
    assert_eq!(irq_ack_op(drv), errno(Errno::ENOENT));
    // The bind: the port's mask first, then the line's.
    assert_eq!(irq_bind_op(rd, port_ctl, 1, any), denied, "the line's mask excludes DRIVER");
    assert_eq!(irq_bind_op(drv, port_rd, 1, any), denied, "the port's mask excludes CTL");
    assert_eq!(irq_bind_op(drv, port_ctl, 0xCD, any), 0);
    azos_ipc::irq_bind::irq_dispatch(IRQ);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16, "the bind delivers");
    assert_eq!(key_at_buf(), 0xCD);
    assert_eq!(irq_ack_op(drv), 0);
    assert_eq!(irq_ack_op(rd), denied);
}

// ── A map or an unmap under way, against what decides by the recorded mappings ──
//
// `shim_after_shm_map` and `shim_at_mm_lock` run what another hart would at the
// instant the leaves exist and the object's record does not say so.

fn phys_of(r: u32) -> usize {
    azos_ipc::memobj::memobj_page_phys_ref(r, 0).unwrap().unwrap()
}

/// **A clone taken while a write mapping is being built copies.** The mapping's
/// leaves are writable before the object records them, so a clone that shared
/// the frames would change under the mapper's writes.
#[test]
fn a_clone_inside_a_write_map_does_not_share_the_frames() {
    use std::sync::Arc;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let src = handle(sys_shm_create_typed(1, 1));
    let rs = resource_of::<Shm>(a, src);
    unsafe { *(phys_of(rs) as *mut u8) = 0x11 };

    let cloned = Arc::new(AtomicU32::new(0));
    let c = cloned.clone();
    azos_sched::shim_after_shm_map(Box::new(move || {
        let r = azos_ipc::memobj::memobj_clone(a, rs, a, azos_ipc::memobj::MemPerms::ReadWrite).expect("clone");
        c.store(r, Ordering::SeqCst);
    }));
    let va = sys_shm_map_typed(src, 0);
    assert!(va > 0, "map: {va}");
    let rc = cloned.load(Ordering::SeqCst);
    assert_ne!(rc, 0, "the clone ran");
    assert!(azos_mm::vmm::translate_user(pt, va as usize, true).is_some(), "the mapping is writable");
    assert_eq!(azos_ipc::memobj::memobj_describe_ref(rs).unwrap().cow_shared, 0, "a writable mapping over shared frames");
    assert_ne!(phys_of(rc), phys_of(rs), "the clone shares a frame the mapper writes");
    unsafe { *(phys_of(rs) as *mut u8) = 0x22 };
    assert_eq!(unsafe { *(phys_of(rc) as *const u8) }, 0x11, "the snapshot moved");
}

/// **A share is not broken under a mapping being built.** The mapper has read the
/// frame's address; a break in between would give the object another frame and
/// drop the old one, which the last sharer's release then frees under the leaves.
#[test]
fn a_cow_break_inside_a_map_does_not_move_the_frames_under_it() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let ro = handle(sys_shm_create_typed(1, 0));
    let rs = resource_of::<Shm>(a, ro);
    let rc = azos_ipc::memobj::memobj_clone(a, rs, a, azos_ipc::memobj::MemPerms::ReadOnly).expect("clone");
    assert_ne!(azos_ipc::memobj::memobj_describe_ref(rs).unwrap().cow_shared, 0, "precondition: shared");

    azos_sched::shim_after_shm_map(Box::new(move || {
        let _ = azos_ipc::memobj::memobj_cow_break_all(rs);
    }));
    let va = sys_shm_map_typed(ro, 0);
    assert!(va > 0, "map: {va}");
    let leaf = azos_mm::vmm::translate_user(pt, va as usize, false).expect("mapped");
    assert_eq!(leaf, phys_of(rs), "the leaf names a frame the object no longer holds");
    let _ = rc;
}

/// **A clone taken while a write mapping is being torn down copies.** The record
/// goes first and the leaves after; until they are gone another thread of the
/// process can still write through them.
#[test]
fn a_clone_inside_an_unmap_does_not_share_the_frames() {
    use std::sync::Arc;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let _pt = ring3(a, SLOT_A);
    let src = handle(sys_shm_create_typed(1, 1));
    let rs = resource_of::<Shm>(a, src);
    assert!(sys_shm_map_typed(src, 0) > 0);
    let frame = phys_of(rs);

    let cloned = Arc::new(AtomicU32::new(0));
    let c = cloned.clone();
    azos_sched::shim_at_mm_lock(Box::new(move || {
        let r = azos_ipc::memobj::memobj_clone(a, rs, a, azos_ipc::memobj::MemPerms::ReadWrite).expect("clone");
        c.store(r, Ordering::SeqCst);
    }));
    assert_eq!(sys_shm_release_typed(src), 0);
    let rc = cloned.load(Ordering::SeqCst);
    assert_ne!(rc, 0, "the clone ran");
    assert_ne!(phys_of(rc), frame, "the clone shared a frame with writable leaves on it");
}

/// **A holder that loses its references under a map keeps the frames until the
/// leaves are gone.** A MOVE takes the sender's references while its map is
/// installing leaves the record does not name: the map finds no booking, removes
/// them and fails; the reference that stayed behind kept the frames alive.
#[test]
fn a_move_inside_a_map_leaves_no_leaf_and_frees_no_frame_under_it() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_b = ring3(b, SLOT_B);
    let pt = ring3(a, SLOT_A);
    let _ = pt_b;
    let src = handle(sys_shm_create_typed(1, 1));
    let rs = resource_of::<Shm>(a, src);

    azos_sched::shim_after_shm_map(Box::new(move || {
        assert!(azos_ipc::memobj::memobj_move(a, b, rs).expect("move").transferred);
        assert_eq!(azos_ipc::memobj::memobj_release_holder_ref(b, rs), Ok(()));
        assert!(azos_ipc::memobj::memobj_page_phys_ref(rs, 0).is_ok(), "the frames went back under the leaves");
    }));
    assert_eq!(sys_shm_map_typed(src, 0), errno(Errno::EBADF));
    let (_, hi) = azos_sched::user_mmap_area();
    assert!(azos_mm::vmm::translate_user(pt, hi - azos_arch::mmu::PAGE_SIZE, false).is_none(), "a leaf stayed after the failed map");
}

/// **One map at a time per holder**: a second thread's map finds the first in
/// flight, and a release of the holder's references waits for it.
#[test]
fn a_map_or_a_release_inside_a_map_is_refused() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let _pt = ring3(a, SLOT_A);
    let src = handle(sys_shm_create_typed(1, 1));
    let rs = resource_of::<Shm>(a, src);
    azos_sched::shim_after_shm_map(Box::new(move || {
        assert_eq!(sys_shm_map_typed(src, 0), errno(Errno::EBUSY), "the second map");
        assert!(azos_ipc::memobj::memobj_release_holder_ref(a, rs).is_err(), "the release freed the frames");
    }));
    assert!(sys_shm_map_typed(src, 0) > 0);
}

/// **A doorbell names a word of its region, checked against the caller's raw
/// offset.** Misaligned, past the end, straddling it, and an offset whose end
/// overflows (`u64::MAX & !3`) are `-EINVAL`, never a panic; the last aligned
/// word binds. Canary `doorbell-wrap-canary`: the end wraps and the overflowing
/// offset binds.
#[test]
fn a_doorbell_offset_outside_its_region_is_refused() {
    if !azos_limits::FUTEX_SHARED {
        return;
    }
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let shm = handle(sys_shm_create_typed(1, 1));
    let bytes = azos_arch::mmu::PAGE_SIZE as u64;
    for (off, why) in [(2, "misaligned"), (bytes, "past the end"), (bytes - 2, "straddling the end"), (u64::MAX & !3, "an end that overflows")] {
        assert_eq!(sys_port_bind_typed(port, PORT_SRC_DOORBELL, shm, 1, off), errno(Errno::EINVAL), "{why}");
    }
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_DOORBELL, shm, 1, bytes - 4), 0, "the last word");
}

/// **Only the endpoint's server binds its calls to a port.** A task holding a
/// `READ` capability on an endpoint another task serves is refused `-EPERM`;
/// the server binds.
#[test]
fn only_the_server_binds_an_endpoints_calls() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let ep = handle(sys_endpoint_create_typed());
    let r = resource_of::<Endpoint>(a, ep);
    let port_a = handle(sys_port_create_typed());
    ring3(b, SLOT_B);
    let port_b = handle(sys_port_create_typed());
    let theirs = held::<Endpoint>(b, CapPerms::READ, r);
    assert_eq!(sys_port_bind_typed(port_b, PORT_SRC_CALLS, theirs, 1, 0), errno(Errno::EPERM), "not its server");
    become_task(a, pt_a);
    assert_eq!(sys_port_bind_typed(port_a, PORT_SRC_CALLS, ep, 1, 0), 0, "its server");
}

/// **A space maps as many objects as it has records (the monitor's worst case:
/// every MemObj of a guest's RAM, one mapping record each, and an anonymous
/// mapping of its own), a fork's walk passes them all, and the space ends
/// without freeing the objects' frames.** The record count is the build's
/// (Kconfig `MM_REGIONS_PER_SPACE`; `hv-host`'s is 140, which the gate row
/// `shm: monitor worst case, hv-host` runs this under).
///
/// **Canary.** `mm-rmap-missing-canary`: the end leaves the leaves of every
/// object and the sweep frees their frames.
#[test]
fn a_space_maps_as_many_objects_as_it_has_records_and_ends_without_freeing_them() {
    use azos_mm::vmm::translate;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let space = azos_sched::shim_space(pt);
    let objs = (azos_mm::pager::MAPPINGS_PER_SPACE - 1).min(azos_ipc::memobj::MAX_MEMOBJS_PER_TASK);
    let mut vas = Vec::new();
    for k in 0..objs {
        let h = handle(sys_shm_create_typed(1, 1));
        let va = sys_shm_map_typed(h, 0);
        assert!(va > 0, "object {k} of {objs}: map returned {va}");
        vas.push(va as usize);
    }
    assert!(sys_mmap(0, azos_arch::mmu::PAGE_SIZE as u64, 3, 0, u64::MAX, 0) > 0, "and an anonymous mapping");
    assert_eq!(azos_mm::pager::shim_mappings(space), objs + 1);

    let (child, hold) = azos_mm::vmm::fork_cow_shared_held(space, false).expect("the fork's walk");
    for &va in &vas {
        assert!(translate(child, va).is_none(), "the walk gave the child a shared page");
    }
    drop(hold);
    azos_mm::vmm::destroy_user_pagetable(child);

    let in_use = azos_mm::shim_pages_in_use();
    azos_sched::set_current_user_pt(0);
    azos_sched::shim_end_space(pt);
    let released = in_use - azos_mm::shim_pages_in_use();
    assert!(released < objs, "the end of the space freed {released} pages: the objects' frames among them");
}

/// **A `munmap` over more records than one pass of `release_range` cuts takes
/// them all.** Alternating permissions keep neighbours from folding, so the
/// space holds one record per page; one call unmaps them. Under the monitor's
/// record count (140) that is many passes; under 8 it is one.
///
/// **Canary.** `release-one-pass-canary`: one pass of any size, which overruns
/// its pieces when the range holds more than a pass (red under a Kconfig with
/// more than 8 records, which is the hv-host row's).
#[test]
fn a_munmap_over_more_records_than_one_pass_cuts_takes_them_all() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let space = azos_sched::shim_space(pt);
    let page = azos_arch::mmu::PAGE_SIZE;
    let n = azos_mm::pager::MAPPINGS_PER_SPACE - 1;
    let first = sys_mmap(0, page as u64, 3, 0, u64::MAX, 0);
    assert!(first > 0);
    for k in 1..n {
        let prot = if k % 2 == 0 { 3 } else { 1 };
        assert_eq!(sys_mmap(0, page as u64, prot, 0, u64::MAX, 0), first + (k * page) as i64, "mapping {k}");
    }
    assert_eq!(azos_mm::pager::shim_mappings(space), n, "one record per page");
    assert_eq!(sys_munmap(first as u64, (n * page) as u64), 0);
    assert_eq!(azos_mm::pager::shim_mappings(space), 0, "one call took them all");
    assert!(azos_mm::vmm::user_range_vacant(pt, first as usize, first as usize + n * page));
}

/// The unmap and MOVE hooks of a MOVE row, taken off when it ends.
struct MoveHooks;
impl MoveHooks {
    fn install() -> MoveHooks {
        fn unmap(root: usize, va: usize, pages: usize) {
            let end = va + pages * azos_arch::PAGE_SIZE;
            azos_mm::vmm::unmap_user_range_keep(root, va, end);
        }
        azos_ipc::memobj::set_unmap_hook(unmap);
        azos_ipc::cap_store::set_move_hook(azos_ipc::memobj::memobj_moved);
        MoveHooks
    }
}
impl Drop for MoveHooks {
    fn drop(&mut self) {
        azos_ipc::memobj::__clear_hooks_for_tests();
        azos_ipc::cap_store::__clear_move_hook_for_tests();
    }
}

/// **The address of a moved mapping comes back to the sender.** A producer maps
/// a buffer, MOVEs it, and maps the next one: every cycle lands at the same
/// address, so a loop of them never walks the mmap area's cursor down until
/// the area is gone.
///
/// **Canary.** `stale-va-kept-canary`: the reap drops the record and keeps the
/// cursor, and each cycle lands one buffer lower.
#[test]
fn a_moved_mappings_address_comes_back_to_its_sender() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_a = ring3(a, SLOT_A);
    let _pt_b = ring3(b, SLOT_B);
    let _hooks = MoveHooks::install();
    become_task(a, pt_a);
    let pages = azos_ipc::memobj::MAX_MEMOBJ_PAGES;
    let mut first = 0;
    for cycle in 0..12 {
        let cap = handle(sys_shm_create_typed(pages as u64, 1));
        let va = sys_shm_map_typed(cap, 0);
        assert!(va > 0, "cycle {cycle}: map returned {va}");
        if cycle == 0 {
            first = va;
        }
        assert_eq!(va, first, "cycle {cycle}: the moved mapping's address did not come back");
        let x = azos_ipc::cap_store::CapXfer::new(CapHandle::from_raw(cap as u32), false);
        let mut out = [CapHandle::from_raw(0); 1];
        azos_ipc::cap_store::move_caps(a, b, &[x], false, &mut out).expect("MOVE");
    }
}

static EXEC_SIBLING_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static EXEC_SIBLING_SPACE: std::sync::Mutex<Option<azos_mm::aspace::SpaceRef>> = std::sync::Mutex::new(None);
static EXEC_SIBLING_THREAD: std::sync::Mutex<Option<std::thread::JoinHandle<()>>> = std::sync::Mutex::new(None);
static EXEC_SIBLING_RAN_DURING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// What a sibling thread does between the flip's checks and its flips: record a
/// shared mapping over the range. The hook gives it time to finish; it
/// finishes only if the flip let go of the space's lock.
fn exec_sibling() {
    let space = EXEC_SIBLING_SPACE.lock().unwrap().expect("a space");
    let t = std::thread::spawn(move || {
        let page = azos_arch::mmu::PAGE_SIZE;
        let _ = azos_mm::pager::reserve_obj(space, 0x7000_0000, 0x7000_0000 + page, 0);
        EXEC_SIBLING_DONE.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    for _ in 0..200 {
        if EXEC_SIBLING_DONE.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_micros(250));
    }
    EXEC_SIBLING_RAN_DURING.store(EXEC_SIBLING_DONE.load(std::sync::atomic::Ordering::SeqCst), std::sync::atomic::Ordering::SeqCst);
    *EXEC_SIBLING_THREAD.lock().unwrap() = Some(t);
}

/// **The flip to RX is atomic against the space's records.** `set_user_range_exec`
/// holds the space's lock from its look at the records to its last flip, so a
/// sibling cannot record a shared mapping in between: the sibling here, started
/// from a hook between the checks and the flips, is still waiting for the lock
/// when the hook gives up on it.
///
/// **Canary.** `exec-flip-unlocked-canary`: the lock is let go after the look
/// and the sibling gets in during the flip.
#[test]
fn the_flip_to_executable_holds_the_spaces_records_until_it_is_done() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let space = azos_sched::shim_space(pt);
    let page = azos_arch::mmu::PAGE_SIZE;
    let va = sys_mmap(0, page as u64, 3, 0, u64::MAX, 0);
    assert!(va > 0);
    let va = va as usize;
    assert!(azos_mm::vmm::handle_demand_fault(space, va).is_ok(), "the page is there");
    *EXEC_SIBLING_SPACE.lock().unwrap() = Some(space);
    EXEC_SIBLING_DONE.store(false, std::sync::atomic::Ordering::SeqCst);
    EXEC_SIBLING_RAN_DURING.store(false, std::sync::atomic::Ordering::SeqCst);
    azos_mm::vmm::shim_set_exec_hook(Some(exec_sibling));
    let flipped = azos_mm::vmm::set_user_range_exec(pt, va, va + page);
    azos_mm::vmm::shim_set_exec_hook(None);
    EXEC_SIBLING_THREAD.lock().unwrap().take().expect("the sibling").join().unwrap();
    assert_eq!(flipped, Ok(1), "a private page flips");
    assert!(
        !EXEC_SIBLING_RAN_DURING.load(std::sync::atomic::Ordering::SeqCst),
        "a sibling recorded a mapping between the flip's look and its flips"
    );
    assert!(EXEC_SIBLING_DONE.load(std::sync::atomic::Ordering::SeqCst), "and gets in after it");
}
