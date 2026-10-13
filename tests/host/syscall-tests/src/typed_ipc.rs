// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// RFC-0040 gap 1, stage 3: the typed calls that replace the untyped
// shared-memory and port calls. 574 maps a region, 575 binds a source to a
// port, `DEVICE_IRQ_BIND` binds an IRQ to one, 577 waits on a port; 535
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
use azos_abi::syscall_nr::{PORT_SRC_ENDPOINT, PORT_SRC_RING, PORT_SRC_TIMER};
use azos_arch_api::PagePerms;
use azos_ipc::cap::objref::PORT;
use azos_ipc::cap::targets::{Irq, Port, Shm};
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
    PortEvent { key, source_type: 3, source_id: 5, code: 0 }
}

// ═════════════════════════════════════════════════════════════════════════
// 574 and 535
// ═════════════════════════════════════════════════════════════════════════

/// **574 maps a region with the region's own access mode and mints nothing;
/// 535 removes the mapping before it drops the reference.** Before gap 1 the
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
/// `UNMAP_BATCH_PAGES` pages, not one per page, and no frame of the region is
/// freed by the unmap** (the region owns them until its last reference goes).
/// A 64-page region cost 64 shootdowns before.
///
/// **Canary.** Restore the per-page `vmm::unmap` loop in `unmap_user_pages`:
/// the release costs 64 shootdowns, not 2. Pass an empty skip window: the
/// unmap frees the region's frames and the free-page count moves.
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
        unmap_user_pages(mapping.0, mapping.1);
        (mapping.1, SHOOTDOWNS_ON_WATCHED_ROOT.load(Ordering::SeqCst))
    };
    SHOOTDOWN_WATCH_ROOT.store(0, Ordering::SeqCst);
    assert_eq!(unmapped, pages);
    let per_batch = azos_mm::vmm::UNMAP_BATCH_PAGES;
    assert_eq!(batches, pages.div_ceil(per_batch), "shootdowns for a {pages}-page unmap");
    assert_eq!(azos_mm::pmm::free_pages(), region_frames_before, "the unmap freed a region frame");
    for p in 0..pages {
        let at = va + p * azos_arch::mmu::PAGE_SIZE;
        assert!(azos_mm::vmm::translate_user(pt, at, false).is_none(), "page {p} still maps");
    }
    let _ = azos_sched::process::release_user_window(va, pages);
    assert_eq!(sys_shm_release_typed(h), 0, "the release after the unmap");
}

/// **A released mapping gives its window addresses back.** The addresses came
/// from one cursor for the whole board that nothing lowered: about 2,000
/// map/release cycles of the largest region used the window up, and every
/// later shm and MMIO map on the board was refused. Every cycle here maps at
/// the first cycle's address, for more cycles than the window holds without
/// reuse, and the first takes the window's base: the task starts empty.
///
/// **Canary.** Drop the `release_user_window` call in `sys_shm_release_typed`:
/// the second cycle maps one region higher.
#[test]
fn a_released_mapping_gives_its_window_addresses_back() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);

    let pages = azos_ipc::memobj::MAX_MEMOBJ_PAGES;
    let span = pages * azos_arch::mmu::PAGE_SIZE;
    let (lo, hi) = azos_sched::user_shm_window();
    let cycles = (hi - lo) / span + 2;
    let mut first = 0usize;
    for cycle in 0..cycles {
        let h = handle(sys_shm_create_typed(pages as u64, 1));
        let va = sys_shm_map_typed(h, 0);
        assert!(va > 0, "cycle {cycle}: map returned {va}");
        if cycle == 0 {
            first = va as usize;
        }
        assert_eq!(va as usize, first, "cycle {cycle}: the release did not give the addresses back");
        assert_eq!(sys_shm_release_typed(h), 0, "cycle {cycle}: release");
    }
    assert_eq!(first, lo, "the first mapping takes the window's base");
    assert!(azos_mm::vmm::translate_user(pt, first, false).is_none());
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

    let rw_read = held::<Shm>(b, CapPerms::READ, r_rw);
    let rw_write = held::<Shm>(b, CapPerms::WRITE, r_rw);
    let rw_full = held::<Shm>(b, CapPerms::RW, r_rw);
    let ro_read = held::<Shm>(b, CapPerms::READ, r_ro);

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
/// `Cap<Shm>` is minted only to the creator, and a lease books no reference and
/// mints no capability, so no lessee maps a leased region through its lease.
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
    let h_b = held::<Shm>(b, CapPerms::RW, r);

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

/// **A 574 that fails part-way keeps its reference through 535 until the task
/// exits.** `shm_map_user` returns `None` from a partial mapping and nothing
/// records it, so the reference 574 took is all that keeps the mapped frame
/// from the PMM: 574 pins it, 535 gives back the task's other references (the
/// creation reference) and keeps that one, and the exit gives it back. The
/// failure is provoked by mapping the VA of the region's second page first; the
/// VA the map starts at is read off a one-page map just before, whose release
/// gives that address back to the task for the next map.
///
/// **Canary.** Skip `memobj_pin_ref` in `sys_shm_map_typed`: the release frees the
/// region under the live page-0 PTE and the count reads `None`.
#[test]
fn a_map_that_fails_part_way_keeps_its_reference_until_exit() {
    use azos_arch::mmu::PAGE_SIZE;
    use azos_ipc::cap::objref::SHM;
    use azos_mm::vmm::translate_user;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);

    let probe = handle(sys_shm_create_typed(1, 1));
    let probe_va = sys_shm_map_typed(probe, 0);
    assert!(probe_va > 0, "the probe map returned {probe_va}");
    assert_eq!(sys_shm_release_typed(probe), 0);
    let next = probe_va as usize;
    let blocker = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, next + PAGE_SIZE, blocker, PagePerms::USER_RW).expect("the blocker");

    let h = handle(sys_shm_create_typed(2, 1));
    let idx = SHM.idx(resource_of::<Shm>(a, h));
    assert_eq!(sys_shm_map_typed(h, 0), errno(Errno::ENOMEM), "the second page's VA is taken");
    assert!(translate_user(pt, next, false).is_some(), "precondition: page 0 stayed mapped");
    assert_eq!(shm_refs(idx), Some(2), "the creation reference and the failed map's");

    assert_eq!(sys_shm_release_typed(h), 0, "the release");
    assert_eq!(shm_refs(idx), Some(1), "the pinned reference outlives the release");
    assert_eq!(sys_shm_map_typed(h, 0), errno(Errno::ECAPSTALE), "and the capability was revoked");

    // The exit: the address space goes, then the references.
    azos_mm::vmm::unmap(pt, next);
    azos_mm::vmm::unmap(pt, next + PAGE_SIZE);
    azos_ipc::memobj::memobj_release_all(a);
    assert_eq!(shm_refs(idx), None, "the exit gave it back");
}

// ═════════════════════════════════════════════════════════════════════════
// 575
// ═════════════════════════════════════════════════════════════════════════

/// `DEVICE_IRQ_BIND` / `DEVICE_IRQ_ACK` through the entry, in the register
/// form.
fn irq_invoke(line: u64, op: u16, w0: u64, w1: u64, w2: u64) -> i64 {
    let mut out = crate::dispatch::SyscallOut::new();
    crate::invoke::sys_invoke(line, azos_abi::invoke::INVOKE_REGS | op as u64, w0, w1, w2, 0, &mut out)
}

fn irq_bind_op(line: u64, port: u64, key: u64, cpu: u64) -> i64 {
    irq_invoke(line, azos_abi::invoke::DEVICE_IRQ_BIND, port, key, cpu)
}

fn irq_ack_op(line: u64) -> i64 {
    irq_invoke(line, azos_abi::invoke::DEVICE_IRQ_ACK, 0, 0, 0)
}

/// **`DEVICE_IRQ_BIND` binds the IRQ to the port its capability names, and the
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

/// **`DEVICE_IRQ_BIND` refuses in its documented order.** The op first, then
/// the line's capability (its right: `READ`), then the port's (`WRITE`; a
/// bind adds a source, so containment refuses it), then the CPU; a line
/// another task binds is `-EBUSY`. The ACK of a line nobody binds is
/// `-ENOENT`, and containment leaves an ACK live.
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
    let forged_irq = CapHandle::pack(ty::IRQ, CapPerms::READ, 1, 77).as_raw() as u64;
    let forged_port = CapHandle::pack(ty::PORT, CapPerms::WRITE, 1, 78).as_raw() as u64;
    let any = DEVICE_IRQ_CPU_ANY;

    assert_eq!(irq_invoke(irq, op(CapKind::Device, CLASS_DRIVER, 99), 0, 0, 0), errno(Errno::EINVAL), "an unknown op");
    assert_eq!(irq_ack_op(forged_irq), errno(Errno::ECAPSTALE), "a forged line, ACK");
    assert_eq!(irq_bind_op(forged_irq, port, 1, any), errno(Errno::ECAPSTALE), "a forged line, bind");
    assert_eq!(irq_bind_op(wo_irq, port, 1, any), errno(Errno::ECAPPERMS), "a line without READ");
    assert_eq!(irq_ack_op(wo_irq), errno(Errno::ECAPPERMS), "a line without READ, ACK");
    assert_eq!(irq_bind_op(irq, forged_port, 1, any), errno(Errno::ECAPSTALE), "a forged port");
    assert_eq!(irq_bind_op(irq, port | 1 << 32, 1, any), errno(Errno::ECAPSTALE), "a port handle past 32 bits");
    assert_eq!(irq_bind_op(irq, ro_port, 1, any), errno(Errno::ECAPPERMS), "a READ-only port");
    assert_eq!(irq_bind_op(irq, irq, 1, any), errno(Errno::ECAPKIND), "a line as the port");
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
    become_task(a, pt_a);
    azos_ipc::cap::degraded_set(true);
    assert_eq!(irq_ack_op(irq), 0, "an ACK is not contained");
    azos_ipc::cap::degraded_set(false);
}

/// **A message-signalled slot (`MSI_LINE | k`) binds through the same op and
/// answers the message its device writes.** The register form returns the
/// address, the data and the vector in `a1..a3`; the slot's vector is
/// delivered by `irq_msi_dispatch`, as the interrupt handlers do, and arrives
/// on the port with the slot as its source id; the ACK of an MSI is 0 and
/// touches no controller. A platform without MSI answers `-ENODEV`.
///
/// **Canary.** Leave `nrep` at 0 in `irq_op`: the replies read back as the
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
        slot,
        azos_abi::invoke::INVOKE_REGS | azos_abi::invoke::DEVICE_IRQ_BIND as u64,
        port, 0x51, 2, 0, &mut out,
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

    assert_eq!(sys_port_bind_typed(0, PORT_SRC_ENDPOINT, irq, 1), errno(Errno::ECAPSTALE), "a forged port handle first");
    assert_eq!(sys_port_bind_typed(ro_port, PORT_SRC_RING, irq, 1), errno(Errno::ECAPPERMS), "a READ-only port");
    assert_eq!(sys_port_bind_typed(irq, PORT_SRC_RING, irq, 1), errno(Errno::ECAPKIND), "an IRQ handle as the port");
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_ENDPOINT + 1, irq, 1), errno(Errno::EINVAL), "an unknown source type");
    assert_eq!(sys_port_bind_typed(port, u64::MAX, irq, 1), errno(Errno::EINVAL));
    // Wave 11 (PORTWAIT): a ring and an endpoint take their own capability, a
    // timer none (its source is a deadline). Type 0 was the channel: no source;
    // type 2 was the IRQ line, which binds from its own side.
    assert_eq!(sys_port_bind_typed(port, 0, irq, 1), errno(Errno::EINVAL), "source type 0");
    for typed in [PORT_SRC_RING, PORT_SRC_ENDPOINT] {
        assert_eq!(sys_port_bind_typed(port, typed, 0, 1), errno(Errno::ECAPSTALE), "source type {typed}, forged");
        assert_eq!(sys_port_bind_typed(port, typed, irq, 1), errno(Errno::ECAPKIND), "source type {typed}, an IRQ handle");
    }
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, u64::MAX, 1), 0, "a timer needs no capability");
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER | 0x200, 0, 1), errno(Errno::EINVAL), "an unknown flag");

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, u64::MAX, 1), errno(Errno::EAGAIN), "a bind is contained");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, u64::MAX, 1), 0);
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

/// `MEMOBJ_LEASE_GRANT` (603, 2026-09-28): the grant takes the
/// `Cap<Shm>` itself, so ring 3 never needs the raw region id it is not told.
/// The lease records the region the capability names — not another region of
/// the same task, not the packed reference — and a ring-3 lessor gets the
/// `Cap<Lease>` it waits on. A handle of another kind, a forged one and one
/// whose region was released are refused with the capability's errno, and no
/// refusal takes a lease slot or wakes a lessee.
///
/// **Canaries.** Hand `sys_ipc_lease_grant` the packed reference `r` instead of
/// `memobj_index_ref(r)`: the grant reads -1 (the lease table sees no live region
/// under that id). Hand it `shm_id ^ 1` (the task's other region): the accept
/// reports a different region.
#[test]
fn the_typed_lease_grant_leases_the_region_its_capability_names() {
    let _g = serial();
    let a = fresh_tid();
    let lessee = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();

    let first = handle(sys_shm_create_typed(1, 1));
    let second = handle(sys_shm_create_typed(1, 0)); // read-only: READ suffices
    let idx = |h: u64| azos_ipc::memobj::memobj_index_ref(resource_of::<Shm>(a, h)).expect("live region");
    assert_ne!(idx(first), idx(second), "precondition: two regions");

    let before = azos_ipc::cap_store::occupied(a);
    let id = sys_ipc_lease_grant_typed(second, lessee as u64, 0);
    assert!(id >= 0, "the typed grant was refused: {id}");
    assert_eq!(azos_ipc::cap_store::occupied(a), before + 1, "no Cap<Lease> was minted");
    assert_eq!(ipc_sched_shim::shim_take_lease_accept_wakes(), vec![(lessee, a)]);
    assert_eq!(
        azos_ipc::lease::lease_accept(lessee, a),
        Some((id as usize, idx(second) as usize)),
        "the lease names another region than the capability"
    );

    let chan = held::<Irq>(a, CapPerms::RW, IRQ);
    assert_eq!(sys_ipc_lease_grant_typed(chan, lessee as u64, 0), errno(Errno::ECAPKIND), "a handle of another kind");
    assert_eq!(sys_ipc_lease_grant_typed(0, lessee as u64, 0), errno(Errno::ECAPSTALE), "a forged handle");
    assert_eq!(sys_shm_release_typed(first), 0);
    assert_eq!(sys_ipc_lease_grant_typed(first, lessee as u64, 0), errno(Errno::ECAPSTALE), "a released region");
    assert!(ipc_sched_shim::shim_take_lease_accept_wakes().is_empty(), "a refused grant woke a lessee");

    assert_eq!(sys_ipc_lease_free(id as u64), 0, "the lessor frees its lease");
}

/// The seal hook the kernel registers (`kernel/src/boot/sched.rs`), over the
/// real `vmm` this crate runs on the host.
fn host_seal(root: usize, va: usize, pages: usize, write: bool) -> usize {
    let end = va + pages * azos_arch::mmu::PAGE_SIZE;
    azos_mm::vmm::set_user_range_write(root, va, end, write)
}

/// Wave 11 (LEASE3): `LEASE_GRANT_SEAL` in `a1[32..]` of 603. The lessor's
/// own mapping of the region is read-only from the grant (the real PTE,
/// through the real `vmm`) until the lease ends — here by the lessee's return
/// — and writable again after it. Any other flag bit is `-EINVAL` before
/// anything is granted. A mapping the lessor makes DURING the seal is
/// read-only, and stays so. Releasing the mapping forgets the seal, so the
/// lease's end cannot widen what the window holds next.
///
/// **Canaries.** Drop `table.unseal(lease_id)` from `lease_return`: the
/// mapping stays read-only after the return. Drop the
/// `lease_sealed_by` term from `sys_shm_map_typed`: the late mapping is
/// writable. Drop `lease_forget_seal` from `sys_shm_release_typed`: the
/// record survives the release.
#[test]
fn a_sealed_grant_takes_the_lessors_write_until_the_lease_ends() {
    use azos_abi::syscall_nr::LEASE_GRANT_SEAL;
    use azos_mm::vmm::user_write_would_be_permitted as writable;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    azos_ipc::memobj::set_protect_hook(host_seal);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();

    let cap = handle(sys_shm_create_typed(1, 1));
    let va = sys_shm_map_typed(cap, 0);
    assert!(va > 0, "map: {va}");
    let va = va as usize;
    assert!(writable(pt, va), "precondition: the lessor's mapping is writable");

    assert_eq!(sys_ipc_lease_grant_typed(cap, a as u64 | (1u64 << 33), 0), errno(Errno::EINVAL),
        "an unknown grant flag");
    assert!(ipc_sched_shim::shim_take_lease_accept_wakes().is_empty(), "a refused grant woke a lessee");

    let id = sys_ipc_lease_grant_typed(cap, a as u64 | LEASE_GRANT_SEAL, 0);
    assert!(id >= 0, "the sealed grant was refused: {id}");
    let (sealed, m) = azos_ipc::lease::lease_seal_info(id as usize);
    assert!(sealed);
    assert_eq!((m.root, m.va, m.pages), (pt, va, 1), "the seal records the lessor's mapping");
    assert!(!writable(pt, va), "the seal left the lessor's mapping writable");
    assert!(azos_ipc::lease::lease_accept(a, a).is_some());
    assert_eq!(sys_ipc_lease_return(id as u64), 0);
    assert!(writable(pt, va), "the return did not give the lessor its write back");
    assert_eq!(azos_ipc::lease::lease_seal_info(id as usize).1, azos_ipc::lease::SealMap::NONE);
    assert_eq!(sys_ipc_lease_free(id as u64), 0);

    // Sealed again, then the mapping released: the seal is forgotten.
    let id = sys_ipc_lease_grant_typed(cap, a as u64 | LEASE_GRANT_SEAL, 0);
    assert!(id >= 0);
    assert!(!writable(pt, va));
    let late = handle(sys_shm_create_typed(1, 1));
    let id2 = sys_ipc_lease_grant_typed(late, a as u64 | LEASE_GRANT_SEAL, 0);
    assert!(id2 >= 0);
    assert_eq!(azos_ipc::lease::lease_seal_info(id2 as usize).1, azos_ipc::lease::SealMap::NONE,
        "no mapping at grant: nothing to restore");
    let lva = sys_shm_map_typed(late, 0);
    assert!(lva > 0);
    assert!(!writable(pt, lva as usize), "a mapping made under the seal is writable");
    assert_eq!(sys_shm_release_typed(cap), 0);
    assert_eq!(azos_ipc::lease::lease_seal_info(id as usize).1, azos_ipc::lease::SealMap::NONE,
        "the released mapping's seal survived");
    assert_eq!(sys_ipc_lease_free(id as u64), 0);
    assert_eq!(sys_ipc_lease_free(id2 as u64), 0);
    assert!(!writable(pt, lva as usize), "the late mapping stays read-only after the lease");
    assert_eq!(sys_shm_release_typed(late), 0);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();
}

/// Wave 15 (security): a seal is forgotten when its ADDRESS SPACE releases
/// the sealed mapping, whichever thread does it. The seal is recorded under
/// the granting thread, the mapping under the process; matching the release
/// by thread left the record behind when a sibling released the region, the
/// window address was reused, and the lease's end then added write to the
/// read-only page mapped there next.
///
/// The other half: a seal a thread grants on a region its process has not
/// mapped makes the process's later mapping of it read-only, whichever thread
/// maps it.
///
/// **Canaries.** Feature `lease-forget-tid-canary` (match by thread again): the
/// record survives the leader's release and the next page becomes writable.
/// Feature `lease-sealed-by-thread-canary`: the leader maps the sealed region
/// writable.
#[test]
fn a_sibling_threads_release_forgets_the_seal() {
    use azos_abi::syscall_nr::LEASE_GRANT_SEAL;
    use azos_mm::vmm::user_write_would_be_permitted as writable;
    let _g = serial();
    let a = fresh_tid();
    let t2 = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    // `t2` is a thread of `a`: its own pool slot, `a`'s capability table.
    ipc_task_pool::shim_bind(t2, SLOT_B);
    azos_sched::group::shim_set_member(SLOT_B, a);
    azos_sched::group::shim_set_member_tid(t2);
    struct Ungroup;
    impl Drop for Ungroup {
        fn drop(&mut self) {
            azos_sched::group::shim_set_member(0, 0);
            azos_sched::group::shim_set_member_tid(0);
        }
    }
    let _ug = Ungroup;
    azos_ipc::memobj::set_protect_hook(host_seal);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();

    let cap = handle(sys_shm_create_typed(1, 1));
    let va = sys_shm_map_typed(cap, 0);
    assert!(va > 0, "map: {va}");
    let va = va as usize;
    // A seal from thread `t2` on a region the process has not mapped: the
    // leader's mapping made during the seal is read-only too.
    // Canary `lease-sealed-by-thread-canary`: it is writable.
    let late = handle(sys_shm_create_typed(1, 1));
    azos_sched::set_current_task_tid(t2);
    azos_sched::set_current_proc_tid(a);
    let id2 = sys_ipc_lease_grant_typed(late, a as u64 | LEASE_GRANT_SEAL, 0);
    assert!(id2 >= 0, "the second sealed grant was refused: {id2}");
    azos_sched::set_current_proc_tid(0);
    become_task(a, pt);
    let lva = sys_shm_map_typed(late, 0);
    assert!(lva > 0, "map: {lva}");
    assert!(!writable(pt, lva as usize), "a sibling thread's seal let the leader map the region writable");
    azos_sched::set_current_task_tid(t2);
    azos_sched::set_current_proc_tid(a);
    assert_eq!(sys_ipc_lease_free(id2 as u64), 0);
    azos_sched::set_current_proc_tid(0);
    become_task(a, pt);
    assert_eq!(sys_shm_release_typed(late), 0);

    // Thread `t2` of process `a` grants the sealed lease.
    azos_sched::set_current_task_tid(t2);
    azos_sched::set_current_proc_tid(a);
    let id = sys_ipc_lease_grant_typed(cap, a as u64 | LEASE_GRANT_SEAL, 0);
    assert!(id >= 0, "the sealed grant was refused: {id}");
    assert_eq!(azos_ipc::lease::lease_seal_info(id as usize).1.va, va, "the seal names the mapping");
    assert!(!writable(pt, va), "precondition: sealed");
    // The leader releases the region: the seal is forgotten.
    azos_sched::set_current_proc_tid(0);
    become_task(a, pt);
    assert_eq!(sys_shm_release_typed(cap), 0);
    let left = azos_ipc::lease::lease_seal_info(id as usize).1;
    // A read-only page takes the address; the lease's end must not widen it.
    let frame = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, va, frame, PagePerms { accessed: true, ..PagePerms::USER_RO }).expect("map");
    azos_sched::set_current_task_tid(t2);
    azos_sched::set_current_proc_tid(a);
    assert_eq!(sys_ipc_lease_free(id as u64), 0, "the lessor thread frees its lease");
    assert!(!writable(pt, va), "the lease's end made the next read-only mapping writable");
    assert_eq!(left, azos_ipc::lease::SealMap::NONE, "a sibling thread's release left the seal behind");
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();
}

/// Wave 11 (LEASE3): a topology row with `lease_seal = true` refuses an
/// unsealed grant from its task with `-EACCES` before anything is resolved,
/// and lets a sealed one through; another task is not bound by it.
///
/// **Canary.** Make `lease_seal_required` answer `false`: the unsealed grant
/// from the row's task is granted.
#[test]
fn a_row_that_requires_the_seal_refuses_an_unsealed_grant() {
    use azos_abi::syscall_nr::LEASE_GRANT_SEAL;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();
    let cap = handle(sys_shm_create_typed(1, 1));
    crate::handlers::set_lease_seal_resolver(|name| name == "SEALROW.ELF");
    azos_sched::shim_set_task_name("SEALROW.ELF");
    assert_eq!(sys_ipc_lease_grant_typed(cap, a as u64, 0), errno(Errno::EACCES));
    assert!(ipc_sched_shim::shim_take_lease_accept_wakes().is_empty(), "a refused grant woke a lessee");
    let id = sys_ipc_lease_grant_typed(cap, a as u64 | LEASE_GRANT_SEAL, 0);
    assert!(id >= 0, "the sealed grant was refused: {id}");
    assert_eq!(sys_ipc_lease_free(id as u64), 0);
    azos_sched::shim_set_task_name("OTHER.ELF");
    let id = sys_ipc_lease_grant_typed(cap, a as u64, 0);
    assert!(id >= 0, "another row's task was refused: {id}");
    assert_eq!(sys_ipc_lease_free(id as u64), 0);
    crate::handlers::set_lease_seal_resolver(|_| false);
    azos_sched::shim_set_task_name("");
    assert_eq!(sys_shm_release_typed(cap), 0);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();
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

    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, 4_000_000, 0x7), 0, "a timer at 4 ms");
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
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_TIMER, 2_000_000, 0x42), 0);
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
    assert_eq!(sys_port_bind_typed(port, PORT_SRC_ENDPOINT, ep, 0xE1), 0);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), errno(Errno::EAGAIN), "one sender left: nothing");

    // A holder of READ that does not serve the endpoint may not bind it.
    become_task(b, pt_b);
    let port_b = handle(sys_port_create_typed());
    assert_eq!(sys_port_bind_typed(port_b, PORT_SRC_ENDPOINT, b_read, 1), errno(Errno::EPERM));

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
/// The values 0 and 1 keep their meaning; ring 3 creates Anon only (Phys,
/// Contig and Paged are not its to ask for); the volatile attribute is
/// reserved; swappable and NO_KERNEL_MAP are accepted; the clone bit and the
/// source capability go together.
#[test]
fn the_creation_word_has_fields_and_refuses_the_reserved_ones() {
    use azos_abi::syscall_nr::*;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let _pt = ring3(a, SLOT_A);
    let einval = errno(Errno::EINVAL);
    for ok in [0u64, 1, 1 | (SHM_ATTR_SWAPPABLE << SHM_CREATE_ATTR_SHIFT), 1 | (SHM_ATTR_NO_KERNEL_MAP << SHM_CREATE_ATTR_SHIFT)] {
        let h = handle(sys_shm_create_typed(1, ok));
        assert_eq!(sys_shm_release_typed(h), 0, "word {ok:#x}");
    }
    for bad in [
        2u64,
        1 | (1 << SHM_CREATE_KIND_SHIFT),
        1 | (2 << SHM_CREATE_KIND_SHIFT),
        1 | (3 << SHM_CREATE_KIND_SHIFT),
        1 | (SHM_ATTR_VOLATILE << SHM_CREATE_ATTR_SHIFT),
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
    azos_ipc::memobj::set_protect_hook(host_seal);
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
    let ro = held::<Shm>(b, CapPerms::READ, r);
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
        let _ = azos_mm::vmm::unmap_user_range_and_free(root, va, end, va, end);
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
    // The sender's next shm call gives the window back.
    become_task(a, pt_a);
    crate::ipc_handlers::reap_moved_windows();
    assert!(!azos_ipc::memobj::memobj_moved_windows_pending(), "the sender took its window back");
}
