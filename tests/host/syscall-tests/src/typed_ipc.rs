// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// RFC-0040 gap 1, stage 3: the typed calls that replace the untyped channel,
// shared-memory and port calls. 573 creates a channel, 574 maps a region, 575
// binds an IRQ to a port, 577 waits on a port; 566 closes a channel and 535
// unmaps before it releases. Each is driven through the pulled handler as a
// ring-3 caller with its own capability table and a real page table.
//
// `channel.rs` is compiled here as a dependency and reads its caller through
// `shims/ipc_sched`, which forwards to the `shims/sched` registers set below:
// the handlers and the channel layer see one caller, as in the kernel. The
// wait's block is `shims/sched`'s recording `task_block`, whose hook stands for
// what other tasks do while the caller sleeps.

use super::harness::serial;
use crate::ipc_handlers::*;
use azos_abi::cap::{CapHandle, CapKind, CapPerms};
use azos_abi::error::Errno;
use azos_arch_api::PagePerms;
use azos_ipc::cap::objref::{CHANNEL, PORT};
use azos_ipc::cap::targets::{Channel, Irq, Port, Shm};
use azos_ipc::cap::{Cap, CapTarget};
use azos_ipc::channel::channel_owner;
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
/// containment, the block hook, and every channel, port, region, IRQ binding
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
        for ch in 0..azos_ipc::channel::MAX_CHANNELS {
            let _ = azos_ipc::channel_destroy(ch);
        }
        for &t in &self.tids {
            azos_ipc::irq_bind::irq_unbind_all(t);
            azos_ipc::port::port_release_all(t);
            azos_ipc::shm::shm_release_all(t);
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

fn kind_of(h: u64) -> Option<CapKind> {
    CapKind::from_raw(CapHandle::from_raw(h as u32).kind())
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
    PortEvent { key, source_type: 3, source_id: 5 }
}

// ═════════════════════════════════════════════════════════════════════════
// 573 and the Channel arm of 566
// ═════════════════════════════════════════════════════════════════════════

/// **573 mints a working `Cap<Channel>` owned by the caller; 566 destroys the
/// channel and revokes the capability; a capability to it in another table
/// reaches neither the destroyed channel nor the one created next at its
/// index.**
///
/// **Canaries.** Drop the Channel arm from `sys_close_typed`: the close reads
/// `-ECAPKIND`. Skip the revoke in `channel_destroy_cap`: the occupancy does
/// not drop.
#[test]
fn a_typed_channel_carries_messages_and_its_close_destroys_it() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_b = ring3(b, SLOT_B);
    let pt_a = ring3(a, SLOT_A);

    let h = handle(sys_chan_create_typed());
    assert_eq!(kind_of(h), Some(CapKind::Channel));
    let ch = CHANNEL.idx(resource_of::<Channel>(a, h)) as usize;
    assert_eq!(channel_owner(ch), Some(a), "the caller owns the channel");

    put(BUF, b"ping");
    assert_eq!(sys_chan_write_typed(h, BUF as u64, 4), 0);
    assert_eq!(sys_chan_read_typed(h, BUF as u64 + 8, 8), 4);
    assert_eq!(&take16(BUF)[8..12], b"ping");

    let other = azos_ipc::channel::channel_grant_cap(b, ch, CapPerms::RW)
        .expect("a second holder")
        .raw()
        .as_raw() as u64;
    let before = azos_ipc::cap_store::occupied(a);
    assert_eq!(sys_close_typed(h), 0, "the close");
    assert_eq!(azos_ipc::cap_store::occupied(a), before - 1, "the close revoked the capability");
    assert_eq!(channel_owner(ch), None, "the close destroyed the channel");
    assert_eq!(sys_close_typed(h), errno(Errno::ECAPSTALE), "a second close");
    assert_eq!(sys_chan_write_typed(h, BUF as u64, 4), errno(Errno::ECAPSTALE));

    let h2 = handle(sys_chan_create_typed());
    assert_eq!(CHANNEL.idx(resource_of::<Channel>(a, h2)) as usize, ch, "precondition: the index was reused");
    become_task(b, pt_b);
    assert_eq!(sys_chan_write_typed(other, BUF as u64, 4), errno(Errno::ECAPSTALE), "the other table");
    assert_eq!(sys_close_typed(other), errno(Errno::ECAPSTALE), "and its close destroys nothing");
    become_task(a, pt_a);
    assert_eq!(channel_owner(ch), Some(a), "the new channel survived");
    assert_eq!(sys_close_typed(h2), 0);
}

/// **573 answers `-EQUOTA` once a ring-3 caller owns half the pool; a close
/// gives the share back and a kernel caller is exempt.**
///
/// **Canary.** Map `ChannelCreateError::Quota` to `-EMFILE` in
/// `sys_chan_create_typed`: the refusal reads `-EMFILE`.
#[test]
fn the_typed_channel_create_answers_equota_past_half_the_pool() {
    use azos_ipc::channel::{MAX_CHANNELS, MAX_CHANNELS_PER_TASK};
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    assert!(
        MAX_CHANNELS_PER_TASK + 2 < azos_ipc::cap::MAX_CAPS_PER_TASK,
        "precondition: the table is not what refuses"
    );
    let free = (0..MAX_CHANNELS).filter(|&c| channel_owner(c).is_none()).count();
    assert!(free >= MAX_CHANNELS_PER_TASK + 2, "precondition: the pool is not what refuses");

    let hs: Vec<u64> = (0..MAX_CHANNELS_PER_TASK).map(|_| handle(sys_chan_create_typed())).collect();
    assert_eq!(sys_chan_create_typed(), errno(Errno::EQUOTA), "one past the quota");
    assert_eq!(sys_close_typed(hs[0]), 0);
    handle(sys_chan_create_typed());
    assert_eq!(sys_chan_create_typed(), errno(Errno::EQUOTA), "the share given back was taken again");

    azos_sched::set_current_user_pt(0);
    handle(sys_chan_create_typed());
    become_task(a, pt);
}

/// **Closing a channel is a release: live while contained, and it still needs
/// `WRITE`; a write to it stays contained, after its argument check.** A task
/// with no capability for the channel is refused as stale and destroys nothing.
///
/// Ports two unit6 tests whose only reach was an untyped channel call (101, 107):
/// `ipc_destroy_is_live_while_contained` (a stranger's refusal there was the
/// owner stamp; here it is the stranger's own table) and
/// `ipc_send_is_contained_after_its_argument_check`. The typed write copies its
/// buffer before it resolves the capability, so a contained write with an
/// unreadable buffer answers `-EFAULT`, not `-EAGAIN`.
///
/// **Canary.** Resolve `channel_destroy_cap` with `get`: the contained close
/// reads `-EAGAIN`.
#[test]
fn closing_a_channel_is_live_while_contained_and_still_needs_write() {
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_b = ring3(b, SLOT_B);
    let pt_a = ring3(a, SLOT_A);
    let h = handle(sys_chan_create_typed());
    let r = resource_of::<Channel>(a, h);
    let ch = CHANNEL.idx(r) as usize;
    let ro = held::<Channel>(a, CapPerms::READ, r);

    azos_ipc::cap::degraded_set(true);
    put(BUF, b"data");
    assert_eq!(sys_chan_write_typed(h, 0, 4), errno(Errno::EINVAL), "a bad argument keeps its answer");
    // Owner decision O3.3 (2026-09-26): containment stops DEVICE writes, not
    // messages — a channel send resolves uncontained (a channel into a driver
    // task is contained by the driver's own device capability instead).
    assert_eq!(sys_chan_write_typed(h, BUF as u64, 4), 0, "a channel send is a message: not contained (O3.3)");
    assert_eq!(sys_close_typed(ro), errno(Errno::ECAPPERMS), "a READ-only capability");
    become_task(b, pt_b);
    assert_eq!(sys_close_typed(h), errno(Errno::ECAPSTALE), "a task whose table does not name it");
    become_task(a, pt_a);
    assert_eq!(channel_owner(ch), Some(a), "the refusals destroyed nothing");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_chan_read_typed(h, BUF as u64, 8), 4, "the send made under containment was queued (O3.3)");

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_close_typed(h), 0, "the close while contained");
    assert_eq!(channel_owner(ch), None, "the contained close freed the slot");
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
    let va = sys_shm_map_typed(rw);
    assert!(va > 0, "map returned {va}");
    let va = va as usize;
    assert_eq!(azos_ipc::cap_store::occupied(a), before, "the map minted nothing");
    assert!(azos_mm::vmm::translate_user(pt, va, true).is_some(), "a writable region maps writable");
    put(va, b"shared");
    assert_eq!(sys_shm_map_typed(rw), errno(Errno::EBUSY), "one mapping per task and region");

    assert_eq!(sys_shm_release_typed(rw), 0, "the release of a mapped region");
    assert!(azos_mm::vmm::translate_user(pt, va, false).is_none(), "the release unmapped it");
    assert_eq!(sys_shm_map_typed(rw), errno(Errno::ECAPSTALE), "the release revoked the capability");

    let ro = handle(sys_shm_create_typed(1, 0));
    let va = sys_shm_map_typed(ro);
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

    let pages = azos_ipc::shm::MAX_SHM_PAGES;
    let h = handle(sys_shm_create_typed(pages as u64, 1));
    let va = sys_shm_map_typed(h);
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
            azos_ipc::shm::shm_take_mapping_ref(a, r).ok().flatten()
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

    let pages = azos_ipc::shm::MAX_SHM_PAGES;
    let span = pages * azos_arch::mmu::PAGE_SIZE;
    let (lo, hi) = azos_sched::user_shm_window();
    let cycles = (hi - lo) / span + 2;
    let mut first = 0usize;
    for cycle in 0..cycles {
        let h = handle(sys_shm_create_typed(pages as u64, 1));
        let va = sys_shm_map_typed(h);
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

/// **574 needs `READ`, and `WRITE` too for a writable region, which is the
/// only case containment refuses; a kernel caller is refused; a capability to
/// a released region does not map the region created next at its index.**
///
/// **Canaries.** Drop the `WRITE` resolution for a writable region: the
/// READ-only map succeeds. Resolve it with `get_uncontained`: the contained
/// writable map succeeds.
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
    let chan = handle(sys_chan_create_typed());
    let r_rw = resource_of::<Shm>(a, rw);
    let r_ro = resource_of::<Shm>(a, ro);

    let rw_read = held::<Shm>(b, CapPerms::READ, r_rw);
    let rw_write = held::<Shm>(b, CapPerms::WRITE, r_rw);
    let rw_full = held::<Shm>(b, CapPerms::RW, r_rw);
    let ro_read = held::<Shm>(b, CapPerms::READ, r_ro);

    become_task(b, pt_b);
    assert_eq!(sys_shm_map_typed(0), errno(Errno::ECAPSTALE), "a forged handle");
    assert_eq!(sys_shm_map_typed(rw_read), errno(Errno::ECAPPERMS), "a writable region needs WRITE");
    assert_eq!(sys_shm_map_typed(rw_write), errno(Errno::ECAPPERMS), "and READ");
    become_task(a, pt_a);
    assert_eq!(sys_shm_map_typed(chan), errno(Errno::ECAPKIND), "a channel handle");
    become_task(b, pt_b);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_shm_map_typed(rw_full), errno(Errno::EAGAIN), "a writable mapping is contained");
    let va = sys_shm_map_typed(ro_read);
    assert!(va > 0, "a read-only mapping is not contained: {va}");
    azos_ipc::cap::degraded_set(false);
    let va = sys_shm_map_typed(rw_full);
    assert!(va > 0, "map returned {va}");

    azos_sched::set_current_user_pt(0);
    assert_eq!(sys_shm_map_typed(ro_read), errno(Errno::EINVAL), "a kernel caller has no user address space");
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
    assert_eq!(sys_shm_map_typed(rw_read), errno(Errno::ECAPSTALE), "a capability to the released region");
}

/// References the region at `idx` holds in all, or `None` once it is freed.
fn shm_refs(idx: u32) -> Option<u32> {
    azos_ipc::shm::shm_info(idx).map(|(_, refs, _)| refs)
}

/// **535 gives back every reference the releasing task holds on the region —
/// the creation reference, 574's and 534's — so a create/map/release loop never
/// runs out.** The capability is the task's only name for those references and
/// the release revokes it: a reference left behind stays booked to the task,
/// unnameable, until the task exits. Each loop runs past `MAX_SHM_REGIONS`. The
/// per-task share (`MAX_SHM_REGIONS_PER_TASK`, 8) counts the regions a task
/// still has booked, so a release that leaves one reference behind turns the
/// ninth create into `-ENOMEM`; the reference count read after each release
/// shows it on the first round.
///
/// **Canary.** Give back one reference in `shm_release_cap`
/// (`shm_release_ref`): the first round reads `Some(1)` after its release.
#[test]
fn a_typed_release_gives_back_every_reference_the_task_holds() {
    use azos_ipc::cap::objref::SHM;
    use azos_ipc::shm::MAX_SHM_REGIONS;
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    let pt = ring3(a, SLOT_A);
    let occupied = azos_ipc::cap_store::occupied(a);
    let rounds = MAX_SHM_REGIONS + 2;

    for i in 0..rounds {
        let h = sys_shm_create_typed(1, 1);
        assert!(h > 0, "create, map, release: round {i}'s create answered {h}");
        let h = h as u64;
        let idx = SHM.idx(resource_of::<Shm>(a, h));
        let va = sys_shm_map_typed(h);
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
    use azos_ipc::shm::shm_ref;
    use azos_mm::vmm::translate_user;
    let _g = serial();
    let (a, b) = (fresh_tid(), fresh_tid());
    let _s = Scene::new(&[a, b]);
    let pt_b = ring3(b, SLOT_B);
    let pt_a = ring3(a, SLOT_A);

    let h_a = handle(sys_shm_create_typed(1, 1));
    let r = resource_of::<Shm>(a, h_a);
    let idx = SHM.idx(r);
    let va_a = sys_shm_map_typed(h_a);
    assert!(va_a > 0, "A's map returned {va_a}");
    let h_b = held::<Shm>(b, CapPerms::RW, r);

    become_task(b, pt_b);
    let va_b = sys_shm_map_typed(h_b);
    assert!(va_b > 0, "B's map returned {va_b}");
    let va_b = va_b as usize;
    put(va_b, b"held by B");
    assert_eq!(shm_refs(idx), Some(3), "A's two references and B's map");

    become_task(a, pt_a);
    assert_eq!(sys_shm_release_typed(h_a), 0, "the creator's release");
    assert!(translate_user(pt_a, va_a as usize, false).is_none(), "A's mapping is gone");
    assert_eq!(shm_refs(idx), Some(1), "B's reference is all that is left");
    assert_eq!(shm_ref(idx), Some(r), "the region kept its generation");

    become_task(b, pt_b);
    assert!(translate_user(pt_b, va_b, true).is_some(), "B's mapping survived A's release");
    let mut got = [0u8; 9];
    assert!(azos_sched::copy_from_user(got.as_mut_ptr(), va_b, got.len()));
    assert_eq!(&got, b"held by B");
    assert_eq!(sys_shm_map_typed(h_b), errno(Errno::EBUSY), "B's capability still resolves");
    assert_eq!(sys_shm_release_typed(h_b), 0, "the last holder's release");
    assert!(translate_user(pt_b, va_b, false).is_none());
    assert_eq!(shm_refs(idx), None, "the region went with the last reference");
    assert_eq!(shm_ref(idx), None);
    assert_eq!(sys_shm_map_typed(h_b), errno(Errno::ECAPSTALE), "B's release revoked B's capability");
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
/// **Canary.** Skip `shm_pin_ref` in `sys_shm_map_typed`: the release frees the
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
    let probe_va = sys_shm_map_typed(probe);
    assert!(probe_va > 0, "the probe map returned {probe_va}");
    assert_eq!(sys_shm_release_typed(probe), 0);
    let next = probe_va as usize;
    let blocker = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, next + PAGE_SIZE, blocker, PagePerms::USER_RW).expect("the blocker");

    let h = handle(sys_shm_create_typed(2, 1));
    let idx = SHM.idx(resource_of::<Shm>(a, h));
    assert_eq!(sys_shm_map_typed(h), errno(Errno::ENOMEM), "the second page's VA is taken");
    assert!(translate_user(pt, next, false).is_some(), "precondition: page 0 stayed mapped");
    assert_eq!(shm_refs(idx), Some(2), "the creation reference and the failed map's");

    assert_eq!(sys_shm_release_typed(h), 0, "the release");
    assert_eq!(shm_refs(idx), Some(1), "the pinned reference outlives the release");
    assert_eq!(sys_shm_map_typed(h), errno(Errno::ECAPSTALE), "and the capability was revoked");

    // The exit: the address space goes, then the references.
    azos_mm::vmm::unmap(pt, next);
    azos_mm::vmm::unmap(pt, next + PAGE_SIZE);
    azos_ipc::shm::shm_release_all(a);
    assert_eq!(shm_refs(idx), None, "the exit gave it back");
}

// ═════════════════════════════════════════════════════════════════════════
// 575
// ═════════════════════════════════════════════════════════════════════════

/// **575 binds the IRQ to the port its capability names, and the binding
/// delivers to no other port, the one created next at that index included.**
///
/// **Canary.** Bind with the port's index (`PORT.idx(r)`) instead of its
/// reference: `irq_bind_port` refuses the bare index and the bind reads
/// `-ECAPSTALE`.
#[test]
fn a_typed_bind_delivers_to_the_port_its_capability_names() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);

    assert_eq!(sys_port_bind_typed(port, 2, irq, 0xAB), 0);
    azos_ipc::irq_bind::irq_dispatch(IRQ);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16);
    let e = take16(BUF);
    assert_eq!(u64::from_le_bytes(e[..8].try_into().unwrap()), 0xAB, "the key");
    assert_eq!(e[8], 3, "an IRQ event");
    assert_eq!(u32::from_le_bytes(e[12..16].try_into().unwrap()), IRQ, "the IRQ number");

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

/// **575 refuses in its documented order.** The port capability first, then
/// the source type, then the source's capability; containment refuses a bind.
///
/// **Canaries.** Resolve the port with `get_uncontained`: the contained bind
/// reads 0. Resolve a channel or ring source as an IRQ capability: the
/// channel handle as a channel source reads `-ECAPKIND`. Ask `NONE` of the
/// IRQ capability: the one without `READ` binds.
#[test]
fn a_typed_bind_refuses_in_its_documented_order() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    let ro_port = held::<Port>(a, CapPerms::READ, r);
    let irq = held::<Irq>(a, CapPerms::READ, IRQ);
    let wo_irq = held::<Irq>(a, CapPerms::WRITE, IRQ);

    assert_eq!(sys_port_bind_typed(0, 4, irq, 1), errno(Errno::ECAPSTALE), "a forged port handle first");
    assert_eq!(sys_port_bind_typed(ro_port, 2, irq, 1), errno(Errno::ECAPPERMS), "a READ-only port");
    assert_eq!(sys_port_bind_typed(irq, 2, irq, 1), errno(Errno::ECAPKIND), "an IRQ handle as the port");
    assert_eq!(sys_port_bind_typed(port, 4, irq, 1), errno(Errno::EINVAL), "an unknown source type");
    assert_eq!(sys_port_bind_typed(port, u64::MAX, irq, 1), errno(Errno::EINVAL));
    // Wave 11 (PORTWAIT): channel and ring take their own capability, a
    // timer none (its source is a deadline).
    for typed in [0, 1] {
        assert_eq!(sys_port_bind_typed(port, typed, 0, 1), errno(Errno::ECAPSTALE), "source type {typed}, forged");
        assert_eq!(sys_port_bind_typed(port, typed, irq, 1), errno(Errno::ECAPKIND), "source type {typed}, an IRQ handle");
    }
    assert_eq!(sys_port_bind_typed(port, 3, u64::MAX, 1), 0, "a timer needs no capability");
    assert_eq!(sys_port_bind_typed(port, 2 | 0x100, 0, 1), errno(Errno::EINVAL), "IRQ bindings are not removed by key");
    assert_eq!(sys_port_bind_typed(port, 3 | 0x200, 0, 1), errno(Errno::EINVAL), "an unknown flag");
    assert_eq!(sys_port_bind_typed(port, 2, 0, 1), errno(Errno::ECAPSTALE), "a forged IRQ handle");
    assert_eq!(sys_port_bind_typed(port, 2, port, 1), errno(Errno::ECAPKIND), "a port handle as the IRQ");
    assert_eq!(sys_port_bind_typed(port, 2, wo_irq, 1), errno(Errno::ECAPPERMS), "an IRQ capability without READ");

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_port_bind_typed(port, 2, irq, 1), errno(Errno::EAGAIN), "a bind is contained");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(sys_port_bind_typed(port, 2, irq, 1), 0);
}

// ═════════════════════════════════════════════════════════════════════════
// 577
// ═════════════════════════════════════════════════════════════════════════

/// **577 returns an event queued before it blocks without blocking, and one
/// queued while it blocks after one block on `WaitReason::Port` with the
/// port's packed reference.**
///
/// **Canary.** Block on the port's index (`PORT.idx(r)`) in
/// `sys_port_wait_typed`: the recorded reason reads the index.
#[test]
fn a_typed_wait_returns_an_event_queued_before_or_while_it_blocks() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);

    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x11)), Ok(()));
    assert_eq!(sys_port_wait_typed(port, BUF as u64), 16);
    assert_eq!(key_at_buf(), 0x11);
    assert!(azos_sched::shim_take_blocks().is_empty(), "a queued event needs no block");

    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        let _ = azos_ipc::port::port_queue_event_ref(r, event(0x22));
    })));
    assert_eq!(sys_port_wait_typed(port, BUF as u64), 16);
    assert_eq!(key_at_buf(), 0x22);
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Port(r)]);
    assert_ne!(r, PORT.idx(r), "precondition: the reference is not the bare index");
}

/// **577 ends at once when the port is destroyed while it waits, and after
/// eight blocks that bring nothing.**
///
/// **Canary.** Wait on a gone port as on an empty one in `port_wait_ref`
/// (block and go round on any refusal but `Full`): the destroyed port's wait
/// blocks eight times and reads `-EAGAIN`.
#[test]
fn a_typed_wait_ends_on_a_destroy_and_after_eight_empty_wakes() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);

    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        let _ = azos_ipc::port::port_destroy_ref(r);
    })));
    assert_eq!(sys_port_wait_typed(port, BUF as u64), errno(Errno::ECAPSTALE));
    assert_eq!(azos_sched::shim_take_blocks().len(), 1, "a destroyed port is not waited on again");
    azos_sched::shim_set_block_hook(None);

    let port2 = handle(sys_port_create_typed());
    let r2 = resource_of::<Port>(a, port2);
    assert_eq!(sys_port_wait_typed(port2, BUF as u64), errno(Errno::EAGAIN));
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Port(r2); 8]);
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
    let chan = handle(sys_chan_create_typed());

    assert_eq!(sys_port_wait_typed(port, 0), errno(Errno::EINVAL), "a null out pointer");
    assert_eq!(sys_port_wait_typed(0, BUF as u64), errno(Errno::ECAPSTALE), "a forged handle");
    assert_eq!(sys_port_wait_typed(chan, BUF as u64), errno(Errno::ECAPKIND), "a channel handle");
    assert_eq!(sys_port_wait_typed(wo_port, BUF as u64), errno(Errno::ECAPPERMS), "no READ");
    assert!(azos_sched::shim_take_blocks().is_empty(), "no refusal blocked");

    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x33)), Ok(()));
    assert_eq!(sys_port_wait_typed(port, UNMAPPED), errno(Errno::EFAULT));
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16, "the refused wait left the event queued");
    assert_eq!(key_at_buf(), 0x33);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x44)), Ok(()));
    assert_eq!(sys_port_wait_typed(port, BUF as u64), 16, "a wait while contained");
    assert_eq!(key_at_buf(), 0x44);
    azos_ipc::cap::degraded_set(false);

    assert_eq!(azos_ipc::port::port_queue_event_ref(r, event(0x55)), Ok(()));
    azos_sched::set_current_user_pt(0);
    let mut out = [0u8; 16];
    assert_eq!(sys_port_wait_typed(port, out.as_mut_ptr() as u64), 16, "a kernel caller");
    assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), 0x55);
    become_task(a, pt);
}

/// `SYS_IPC_LEASE_GRANT_TYPED` (603, 2026-09-28): the grant takes the
/// `Cap<Shm>` itself, so ring 3 never needs the raw region id it is not told.
/// The lease records the region the capability names — not another region of
/// the same task, not the packed reference — and a ring-3 lessor gets the
/// `Cap<Lease>` it waits on. A handle of another kind, a forged one and one
/// whose region was released are refused with the capability's errno, and no
/// refusal takes a lease slot or wakes a lessee.
///
/// **Canaries.** Hand `sys_ipc_lease_grant` the packed reference `r` instead of
/// `shm_index_ref(r)`: the grant reads -1 (the lease table sees no live region
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
    let idx = |h: u64| azos_ipc::shm::shm_index_ref(resource_of::<Shm>(a, h)).expect("live region");
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

    let chan = handle(sys_chan_create_typed());
    assert_eq!(sys_ipc_lease_grant_typed(chan, lessee as u64, 0), errno(Errno::ECAPKIND), "a channel handle");
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
    azos_ipc::lease::set_seal_hook(host_seal);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();

    let cap = handle(sys_shm_create_typed(1, 1));
    let va = sys_shm_map_typed(cap);
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
    let lva = sys_shm_map_typed(late);
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
    azos_ipc::lease::set_seal_hook(host_seal);
    let _ = ipc_sched_shim::shim_take_lease_accept_wakes();

    let cap = handle(sys_shm_create_typed(1, 1));
    let va = sys_shm_map_typed(cap);
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
    let lva = sys_shm_map_typed(late);
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

/// **575 binds a channel the caller holds `READ` on, and every message sent
/// on it marks the port: one event, type 1, with the channel handle as the
/// source id.** A message queued before the bind is reported; a channel
/// reports to one live port (`-EBUSY` for a second) and moves to another once
/// its port is destroyed; a capability without `READ` is refused; a remove by
/// key unbinds it.
///
/// **Canaries.** Skip the `ready` signal in `bind_object`: the first poll reads
/// `-EAGAIN`. Replace a link without asking `port_link_valid`: the second
/// port's bind reads 0 while the first port lives.
#[test]
fn a_typed_bind_takes_a_channel_and_its_sends_mark_the_port() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let port2 = handle(sys_port_create_typed());
    let chan = handle(sys_chan_create_typed());
    let wo_chan = held::<Channel>(a, CapPerms::WRITE, resource_of::<Channel>(a, chan));

    put(BUF, b"early");
    assert_eq!(sys_chan_write_typed(chan, BUF as u64, 5), 0);
    assert_eq!(sys_port_bind_typed(port, 0, wo_chan, 0xC1), errno(Errno::ECAPPERMS), "no READ");
    assert_eq!(sys_port_bind_typed(port, 0, chan, 0xC1), 0);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16, "the message sent before the bind");
    assert_eq!(event_at_buf(), (0xC1, 1, chan as u32));
    assert_eq!(sys_port_poll_typed(port, BUF as u64), errno(Errno::EAGAIN));

    put(BUF, b"m1");
    assert_eq!(sys_chan_write_typed(chan, BUF as u64, 2), 0);
    assert_eq!(sys_chan_write_typed(chan, BUF as u64, 2), 0);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), 16);
    assert_eq!(sys_port_poll_typed(port, BUF as u64), errno(Errno::EAGAIN), "two sends, one event: drain after it");

    assert_eq!(sys_port_bind_typed(port2, 0, chan, 0xC2), errno(Errno::EBUSY), "one live port per channel");
    assert_eq!(sys_port_destroy_typed(port), 0);
    assert_eq!(sys_port_bind_typed(port2, 0, chan, 0xC2), 0, "the dead port's link is replaced");
    assert_eq!(sys_port_poll_typed(port2, BUF as u64), 16, "two messages are still queued");
    assert_eq!(event_at_buf().0, 0xC2);

    assert_eq!(sys_port_bind_typed(port2, 0 | 0x100, 0, 0xC2), 0, "removed by key");
    assert_eq!(sys_port_bind_typed(port2, 0 | 0x100, 0, 0xC2), errno(Errno::ENOENT), "nothing left to remove");
    put(BUF, b"m2");
    assert_eq!(sys_chan_write_typed(chan, BUF as u64, 2), 0);
    assert_eq!(sys_port_poll_typed(port2, BUF as u64), errno(Errno::EAGAIN), "an unbound channel marks nothing");
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

    assert_eq!(sys_port_wait_until_typed(port, BUF as u64, 0), 0, "a passed deadline polls");
    assert!(azos_sched::shim_take_blocks().is_empty(), "without blocking");

    azos_sched::shim_set_block_hook(Some(to_deadline()));
    assert_eq!(sys_port_wait_until_typed(port, BUF as u64, 3_000_000), 0, "timed out");
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Timer(ticks(3_000_000))]);

    assert_eq!(sys_port_bind_typed(port, 3, 4_000_000, 0x7), 0, "a timer at 4 ms");
    assert_eq!(sys_port_wait_until_typed(port, BUF as u64, 9_000_000), 16);
    assert_eq!(event_at_buf(), (0x7, 4, 0));
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Timer(ticks(4_000_000))], "woke at the timer");

    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        let _ = azos_ipc::port::port_queue_event_ref(r, event(0x99));
    })));
    assert_eq!(sys_port_wait_until_typed(port, BUF as u64, u64::MAX), 16);
    assert_eq!(key_at_buf(), 0x99);
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Port(r)], "no deadline: Port");

    azos_sched::shim_set_block_hook(None);
    azos_sched::shim_arm_block_outcome(azos_sched::BlockOutcome::Refused);
    assert_eq!(sys_port_wait_until_typed(port, BUF as u64, u64::MAX), errno(Errno::EBUSY));
    assert_eq!(azos_sched::shim_take_blocks().len(), 1, "one refused block, no spin");
    azos_sched::shim_disarm_block_outcome();
}

/// **604 checks the out pointer and the capability as 577 does, and an
/// event sent from another task while it sleeps on a channel source is
/// returned with that channel's key.**
#[test]
fn the_deadline_wait_refuses_like_577_and_returns_a_channel_event() {
    let _g = serial();
    let a = fresh_tid();
    let _s = Scene::new(&[a]);
    ring3(a, SLOT_A);
    let port = handle(sys_port_create_typed());
    let r = resource_of::<Port>(a, port);
    let wo_port = held::<Port>(a, CapPerms::WRITE, r);
    let chan = handle(sys_chan_create_typed());
    assert_eq!(sys_port_wait_until_typed(port, 0, 0), errno(Errno::EINVAL));
    assert_eq!(sys_port_wait_until_typed(0, BUF as u64, 0), errno(Errno::ECAPSTALE));
    assert_eq!(sys_port_wait_until_typed(chan, BUF as u64, 0), errno(Errno::ECAPKIND));
    assert_eq!(sys_port_wait_until_typed(wo_port, BUF as u64, 0), errno(Errno::ECAPPERMS));
    assert_eq!(sys_port_wait_until_typed(port, UNMAPPED, 0), errno(Errno::EFAULT));

    assert_eq!(sys_port_bind_typed(port, 0, chan, 0x5EED), 0);
    let ch = resource_of::<Channel>(a, chan);
    azos_sched::shim_arm_block_outcome(azos_sched::BlockOutcome::Returned);
    azos_sched::shim_set_block_hook(Some(Box::new(move |_| {
        // Another task's send, through its own capability.
        let t = azos_ipc::cap::CapTable::empty();
        let c: Cap<Channel> = t.grant(CapPerms::WRITE, ch).unwrap();
        azos_ipc::channel::channel_send_cap(&t, c, b"req").unwrap();
    })));
    assert_eq!(sys_port_wait_until_typed(port, BUF as u64, u64::MAX), 16);
    assert_eq!(event_at_buf(), (0x5EED, 1, chan as u32));
    assert_eq!(sys_chan_read_typed(chan, BUF as u64, 8), 3, "the request is there to drain");
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
    assert_eq!(sys_port_bind_typed(port, 3, 2_000_000, 0x42), 0);
    azos_sched::shim_set_block_hook(Some(Box::new(|reason| match reason {
        WaitReason::Timer(t) => azos_drv_irqchip::clint::set_time(t),
        other => panic!("577 with an armed timer blocked on {other:?}, which no timer ends"),
    })));
    assert_eq!(sys_port_wait_typed(port, BUF as u64), 16);
    assert_eq!(event_at_buf(), (0x42, 4, 0));
    assert_eq!(azos_sched::shim_take_blocks(), vec![WaitReason::Timer(ticks(2_000_000))]);
}
