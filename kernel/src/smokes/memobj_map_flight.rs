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

use azos_ipc::memobj::{
    memobj_acquire_ref, memobj_clone, memobj_cow_break_all, memobj_create_ref, memobj_describe_ref, memobj_map_begin_ref,
    memobj_map_commit_ref, memobj_page_phys_ref, memobj_release_ref, memobj_unmap_begin_ref, memobj_unmap_end_ref, MapAccess,
    MemObjError, MemPerms,
};
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
