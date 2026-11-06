// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Clones on one hart against write maps on another, through the object table's
//! real operations with a real table lock: a snapshot never changes while the
//! other hart writes. The writer stores through the frame for as long as its map
//! is in flight (`memobj_map_begin_ref` to `memobj_unmap_end_ref`), as a process
//! does through its leaves. Each clone's byte is watched across two of the
//! writer's stores, so the check holds whatever the two harts' relative speed.
//!
//! **Canary** `memobj-map-unrecorded-canary`: a clone does not see the map in
//! flight, shares the frame and the byte moves: `not ok`.
//!
//! A fork child's inherited mapping, on real page tables: its leaves are copied
//! from the parent's before its booking, the parent's mapping turns read-only in
//! between and a clone is taken. The clone copies, and the child's record and
//! leaves agree with the parent's access at the booking.
//!
//! **Canary** `memobj-inherit-unmarked-canary`: the clone shares the frame
//! under the child's writable leaf: `not ok`.

use azos_ipc::memobj::{
    memobj_acquire_ref, memobj_clone, memobj_cow_break_all, memobj_create_ref, memobj_describe_ref,
    memobj_inherit_begin_ref, memobj_inherit_commit_ref, memobj_map_begin_ref, memobj_map_commit_ref,
    memobj_note_mapping_ref, memobj_page_phys_ref, memobj_protect_ref, memobj_release_ref, memobj_take_mapping_ref,
    memobj_unmap_begin_ref, memobj_unmap_end_ref, MapAccess, MemObjError, MemPerms,
};
use azos_mm::vmm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

const CLONES: u32 = 300;
/// A user address the record names; no leaf is made, no one walks it.
const VA: usize = 0x4000_0000;

static OBJECT: AtomicU32 = AtomicU32::new(0);
static STORES: AtomicU32 = AtomicU32::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static WRITER_DONE: AtomicBool = AtomicBool::new(false);

fn byte_at(phys: usize) -> &'static AtomicU8 {
    // SAFETY: a live frame of an object this task holds; the direct map covers it.
    unsafe { &*(azos_mm::addr::phys_to_virt(phys) as *const AtomicU8) }
}

fn store_a_while(byte: &AtomicU8, seq: &mut u8) {
    for _ in 0..8 {
        *seq = seq.wrapping_add(1);
        byte.store(*seq, Ordering::Relaxed);
        STORES.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

fn writer(_: usize) {
    let me = azos_sched::current_task_tid();
    let r = OBJECT.load(Ordering::Acquire);
    let _ = memobj_acquire_ref(me, r);
    let mut seq = 0u8;
    while !STOP.load(Ordering::Acquire) {
        let mut pages = [0usize; 1];
        match memobj_map_begin_ref(me, r, true, &mut pages) {
            Ok(()) => {}
            Err(MemObjError::Busy) => {
                let _ = memobj_cow_break_all(r);
                continue;
            }
            Err(_) => break,
        }
        // The frame the map read: a break cannot move it under a map in flight.
        let byte = byte_at(pages[0]);
        store_a_while(byte, &mut seq);
        let _ = memobj_map_commit_ref(me, r, 0, VA, 1, MapAccess::RW);
        store_a_while(byte, &mut seq);
        let _ = memobj_unmap_begin_ref(me, r);
        store_a_while(byte, &mut seq);
        memobj_unmap_end_ref(me, r);
        // Out of every map: a clone may share now, and the next map breaks it.
        for _ in 0..64 {
            core::hint::spin_loop();
        }
    }
    let _ = memobj_release_ref(me, r);
    WRITER_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn memobj_clone_stays_a_snapshot_against_maps_in_flight() {
        let cpus = azos_percpu::nr_cpu_ids();
        if cpus < 2 {
            return Err("needs 2 CPUs (the cloner and the mapper)");
        }
        let me = azos_sched::current_task_tid();
        let Some(r) = memobj_create_ref(me, 1, MemPerms::ReadWrite) else {
            return Err("no object");
        };
        OBJECT.store(r, Ordering::Release);
        STOP.store(false, Ordering::Release);
        WRITER_DONE.store(false, Ordering::Release);
        azos_sched::task_create_affinity("mo-flight", writer, 0, azos_sched::DEFAULT_PRIORITY, (cpus - 1) as i8);
        crate::ktest::wait("the mapper never stored", || STORES.load(Ordering::Relaxed) > 0)?;

        let (mut copied, mut result) = (0u32, Ok(()));
        for _ in 0..CLONES {
            let Ok(c) = memobj_clone(me, r, me, MemPerms::ReadOnly) else {
                result = Err("a clone failed");
                break;
            };
            copied += u32::from(memobj_describe_ref(c).map_or(false, |d| d.cow_shared == 0));
            let Ok(Some(phys)) = memobj_page_phys_ref(c, 0) else {
                result = Err("a clone has no frame");
                break;
            };
            let byte = byte_at(phys);
            let seen = byte.load(Ordering::Relaxed);
            let from = STORES.load(Ordering::Relaxed);
            let moved = crate::ktest::wait("the mapper stopped storing", || {
                byte.load(Ordering::Relaxed) != seen || STORES.load(Ordering::Relaxed).wrapping_sub(from) >= 2
            })
            .is_ok() && byte.load(Ordering::Relaxed) != seen;
            let _ = memobj_release_ref(me, c);
            if moved {
                result = Err("a snapshot changed under a mapper's stores");
                break;
            }
        }
        STOP.store(true, Ordering::Release);
        crate::ktest::wait("the mapper never ended", || WRITER_DONE.load(Ordering::Acquire))?;
        let _ = memobj_release_ref(me, r);
        result?;
        if copied == 0 {
            return Err("no clone met a map in flight: the test tested nothing");
        }
        Ok(())
    }
}

/// A TID no task has: the fork child's holder.
const CHILD: u32 = 0x7fff_fff1;

/// The parent's table with the object's frame at `VA`, user read-write, and an
/// empty child's table; `None` when either cannot be made.
fn parent_and_child(frame: usize) -> Option<(usize, usize)> {
    if vmm::va_is_kernel_mapped(VA) {
        return None;
    }
    let parent = vmm::create_pagetable().ok()?;
    let Ok(child) = vmm::create_pagetable() else {
        vmm::destroy_user_pagetable(parent);
        return None;
    };
    if vmm::map(parent, VA, frame, azos_arch::PagePerms::USER_RW).is_err() {
        vmm::destroy_user_pagetable(parent);
        vmm::destroy_user_pagetable(child);
        return None;
    }
    Some((parent, child))
}

fn inherit_once(parent: u32, r: u32, parent_pt: usize, child_pt: usize) -> Result<MapAccess, &'static str> {
    if memobj_inherit_begin_ref(parent, CHILD, r, VA, 1).is_err() {
        return Err("the inheritance did not start");
    }
    if azos_mm::cow::fork_share_range(parent_pt, child_pt, VA, 1).is_err() {
        memobj_unmap_end_ref(CHILD, r);
        return Err("the parent's leaf was not copied");
    }
    let copied_write = vmm::user_write_would_be_permitted(child_pt, VA);
    let _ = memobj_protect_ref(parent, r, !copied_write);
    let clone = memobj_clone(parent, r, parent, MemPerms::ReadOnly).map_err(|_| "a clone failed")?;
    let shared = memobj_describe_ref(r).map_or(true, |d| d.cow_shared != 0);
    let _ = memobj_release_ref(parent, clone);
    if shared && copied_write {
        return Err("a clone shared the frame under the child's writable leaf");
    }
    let access = memobj_inherit_commit_ref(parent, CHILD, r, child_pt, VA, 1).map_err(|_| "the child was not booked")?;
    if access.write == copied_write {
        return Err("the booking took the copied leaf's access, not the parent's");
    }
    if vmm::user_write_would_be_permitted(child_pt, VA) != access.write {
        return Err("the child's leaf and its record disagree");
    }
    Ok(access)
}

azos_ktest::ktest_late! {
    fn memobj_fork_inherit_books_the_parents_access_and_a_clone_copies() {
        let me = azos_sched::current_task_tid();
        let Some(r) = memobj_create_ref(me, 1, MemPerms::ReadWrite) else {
            return Err("no object");
        };
        let Ok(Some(frame)) = memobj_page_phys_ref(r, 0) else {
            let _ = memobj_release_ref(me, r);
            return Err("the object has no frame");
        };
        let Some((parent_pt, child_pt)) = parent_and_child(frame) else {
            let _ = memobj_release_ref(me, r);
            return Err("no page tables");
        };
        let mut result = Ok(());
        if memobj_note_mapping_ref(me, r, parent_pt, VA, 1, MapAccess::RW) != Ok(true) || memobj_acquire_ref(CHILD, r).is_err() {
            result = Err("the parent's mapping was not booked");
        }
        // Writable leaves copied and the parent read-only by the booking, then
        // the reverse.
        for _ in 0..2 {
            if result.is_err() {
                break;
            }
            result = inherit_once(me, r, parent_pt, child_pt).map(|_| ());
            if memobj_unmap_begin_ref(CHILD, r).is_ok() {
                vmm::unmap(child_pt, VA);
                memobj_unmap_end_ref(CHILD, r);
            }
        }
        let _ = memobj_release_ref(CHILD, r);
        let _ = memobj_take_mapping_ref(me, r);
        vmm::unmap(parent_pt, VA);
        vmm::destroy_user_pagetable(parent_pt);
        vmm::destroy_user_pagetable(child_pt);
        let _ = memobj_release_ref(me, r);
        result
    }
}
