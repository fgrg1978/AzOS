// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the futex calls' one look at a shm word (front
// futex-single-section): the key a call files or acts under and the word it
// checks or swaps are the same word, whatever region another thread maps at
// the address meanwhile.
//
// **The window.** A futex word of a shm region is keyed by (region, offset),
// found from the caller's mapping at the address. The wait used to take the
// key from one lookup and, later, under the futex table lock, read the value
// through a second one. A sibling thread that unmapped the region and mapped
// another at the same address in between left the waiter filed under the
// first region's key against the second region's value: a waker of the word
// it checked wakes the second region's key and never finds it. The Linux PI
// calls likewise keyed the call once and then read and swapped whatever word
// the address resolved to at each step, so one key's PI state could drive
// another region's word.
//
// **How it is made deterministic.** The sched shim's `futex::wait` runs a
// test hook at the start of the wait's section, before its look: the remap
// another hart would do there. The PI step's helper is called directly after
// a remap (linux.rs is not built in this crate). The process has a real page
// table mapping `VA` to the frame of the region mapped there, so the wait's
// first read through the user's mapping (`futex_precheck`) reads that frame.

use super::harness::serial;
use azos_ipc::memobj::{
    memobj_create_ref, memobj_note_mapping_ref, memobj_page_phys_ref, memobj_release_all, memobj_resolve_mapped,
    memobj_take_mapping_ref, MapAccess, MemPerms,
};
use azos_arch_api::PagePerms;
use azos_sched::futex::{shim_set_before_section, shim_take_calls, Call, Key};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering::SeqCst};

/// The process that maps the regions.
const TID: u32 = 0x6D00_0001;
/// Where it maps them, one at a time; the futex word is the page's first.
const VA: usize = 0x4000_0000;
/// The word of each region: the same value, so a wait that reads one and is
/// keyed by the other still matches (what makes the mix-up silent).
const WORD: u32 = 5;

/// The two regions and the page table, for the remap hook (a plain `fn`).
static REGION_FIRST: AtomicU32 = AtomicU32::new(0);
static REGION_NEXT: AtomicU32 = AtomicU32::new(0);
static PT: AtomicUsize = AtomicUsize::new(0);

/// A one-page region holding `v` in its first word.
fn region(v: u32) -> u32 {
    let r = memobj_create_ref(TID, 1, MemPerms::ReadWrite).expect("a region");
    let frame = memobj_page_phys_ref(r, 0).expect("live").expect("a frame");
    unsafe { (azos_mm::addr::phys_to_virt(frame) as *mut u32).write_volatile(v) };
    r
}

fn frame_of(r: u32) -> usize {
    memobj_page_phys_ref(r, 0).expect("live").expect("a frame")
}

fn word_of(r: u32) -> u32 {
    unsafe { (azos_mm::addr::phys_to_virt(frame_of(r)) as *const u32).read_volatile() }
}

/// Record `r`'s mapping at `VA` and put its frame there in the page table.
fn map(r: u32) {
    let pt = PT.load(SeqCst);
    assert_eq!(memobj_note_mapping_ref(TID, r, pt, VA, 1, MapAccess::RW), Ok(true), "the mapping was made");
    azos_mm::vmm::map(pt, VA, frame_of(r), PagePerms::USER_RW).expect("map");
}

/// The sibling's munmap of the first region and mmap of the next at `VA`.
fn remap() {
    assert_eq!(memobj_take_mapping_ref(TID, REGION_FIRST.load(SeqCst)), Ok(Some((VA, 1))), "the first mapping was taken");
    azos_mm::vmm::unmap(PT.load(SeqCst), VA);
    map(REGION_NEXT.load(SeqCst));
}

/// `TID` maps a region holding [`WORD`] at [`VA`]; another, holding the same,
/// waits to be mapped there by [`remap`].
fn setup() {
    let pt = azos_mm::pmm::alloc_page().expect("a page-table root").as_usize();
    PT.store(pt, SeqCst);
    azos_sched::set_current_task_tid(TID);
    azos_sched::set_current_proc_tid(0);
    azos_sched::set_current_user_pt(pt);
    shim_take_calls();
    let (first, next) = (region(WORD), region(WORD));
    REGION_FIRST.store(first, SeqCst);
    REGION_NEXT.store(next, SeqCst);
    map(first);
}

/// Unmap `VA`, release both regions, and leave the shim a kernel task again.
fn teardown() {
    azos_mm::vmm::unmap(PT.load(SeqCst), VA);
    memobj_release_all(TID);
    azos_sched::set_current_user_pt(0);
}

/// A wait on the word at `VA` expecting [`WORD`], with the remap landing at
/// the start of its section: its first read (through the user's mapping, the
/// first region's word) matches, then its look, which decides, sees the next
/// region's word, which matches too. The waiter is filed (here: "is woken"
/// at once) under the NEXT region's key, the key of the word it checked last:
/// a waker of that word finds it.
///
/// **Divergence:** with `futex-key-outside-canary` (the key from a lookup
/// before the section, as the wait took it before this front) the row is
/// filed under the FIRST region's key against the next region's value: no
/// waker of the word it checked wakes it.
#[test]
fn a_wait_is_filed_under_the_key_of_the_word_it_checked() {
    let _g = serial();
    setup();
    shim_set_before_section(Some(remap));
    let rc = crate::vdso_notify::sys_futex_wait(VA as u64, WORD as u64, 0);
    shim_set_before_section(None);
    let next = REGION_NEXT.load(SeqCst);
    let calls = shim_take_calls();
    teardown();
    assert_eq!(rc, 0, "both words hold {WORD}: the wait matched");
    assert_eq!(
        calls,
        vec![Call { is_wait: true, key: Key::Shared { obj: next, offset: 0 }, arg: WORD, deadline: None }],
        "the waiter was filed under another word's key than the one it checked"
    );
}

/// A PI step of a call keyed by the first region's word, after the next
/// region was mapped at `VA`: the swap (the `FUTEX_LOCK_PI` shape, `0 -> TID`,
/// here `WORD -> 9`) refuses, and the next region's word is untouched. Keyed
/// by the next region it goes through.
///
/// **Divergence:** with `futex-key-outside-canary` the step takes whatever
/// word `VA` now resolves to: it swaps the next region's word under the first
/// region's key.
#[test]
fn a_pi_step_never_touches_a_word_mapped_since_its_key_was_taken() {
    let _g = serial();
    setup();
    let key = memobj_resolve_mapped(TID, VA).expect("the first region at VA");
    remap();
    let swap = |key| {
        crate::vdso_notify::with_keyed_shm_word(TID, VA as u64, key, true, |w| {
            match w.compare_exchange(WORD, 9, SeqCst, SeqCst) {
                Ok(v) | Err(v) => v,
            }
        })
    };
    let stale = swap(key);
    let after_stale = word_of(REGION_NEXT.load(SeqCst));
    let fresh = swap(memobj_resolve_mapped(TID, VA).expect("the next region at VA"));
    teardown();
    assert_eq!(stale, None, "a step keyed by the first region swapped the next region's word");
    assert_eq!(after_stale, WORD, "the next region's word changed under the first region's key");
    assert_eq!(fresh, Some(WORD), "a step keyed by the word mapped there now reaches it");
}
