// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the physical page allocator, `crates/core/mm/src/pmm.rs`.
//!
//! **WHY.** `crates/core/mm` is 2209 lines with no test of any kind, and the
//! allocator is where a mistake is not an error but silent corruption: hand
//! the same physical page out twice and two subsystems write over each other,
//! with the symptom appearing arbitrarily far from the cause.
//!
//! The real module is pulled in with `#[path]`, and the `azos_arch` shim
//! re-exports the **real** Sv39 `mmu` module rather than stubbing it — so the
//! allocator computes against the kernel's own `PAGE_SIZE`, not a copy that
//! can drift.

#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/addr.rs"]
mod addr;

// The frame descriptors and the buddy allocator `pmm.rs` is built on; their
// rows are in `buddy_tests` below.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/frame.rs"]
mod frame;
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/buddy.rs"]
mod buddy;
// The type zones of physical frames; `pmm.rs` allocates and frees through
// them, and their rows are in `zone_tests`.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/zone.rs"]
mod zone;

#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/pmm.rs"]
mod pmm;

// `wx.rs` was carved out of `vmm.rs` precisely so it could be pulled in here:
// it touches no page table and dereferences nothing, so the whole W^X boundary
// rule is reachable on the host. `vmm.rs` itself is not — it needs `csr`,
// raw physical pointers and a live MMU.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/wx.rs"]
mod wx;

// The COW refcount table, carved out of `cow.rs` so the host can link the real
// code (see its header). Its own tests are `cow_table_tests` below.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/cow_table.rs"]
mod cow_table;

// Per-task frame budget arithmetic (owner decision 102), carved out of
// `crates/core/sched/src/scheduler.rs`'s `mm_charge`/`mm_discharge`/
// `mm_reset_charge` so the host can link the real code. See its header for
// why the original functions cannot be pulled directly, and for what is (and
// is not yet) wired to production. Depends on `core` alone, so no shim is needed.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/budget.rs"]
mod budget;

// KMEM-CHARGE: host rows for the kernel-memory ledger (`KmemBudget`) in the
// same real `budget.rs` file.
#[cfg(test)]
mod kmem_charge;

// LIVEPATCH: host rows for the pure half of the signed kernel livepatch
// (`crates/core/mm/src/livepatch_fmt.rs`, pulled in by the rows file itself).
#[cfg(test)]
mod livepatch;

// Wave 14 (DEMANDPAGE): the region records of demand-paged `mmap`. Pure
// (only `azos_arch_api::PAGE_SHIFT`), so the real file is tested as is; the
// fault path and table that use it are tested in syscall-tests.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/region.rs"]
mod region;

// Superpage reservations (MM_THP_RESV): the bookkeeping of the reserved
// aligned runs. Its rows are in `thp_resv.rs`.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/resv.rs"]
mod resv;
#[cfg(test)]
mod thp_resv;

// Wave 15 (SLAB): the per-CPU magazine layer of the kernel heap. Depends on
// `core` only; its rows are in `slab_tests.rs`.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/slab.rs"]
mod slab;
#[cfg(test)]
mod slab_tests;
#[cfg(test)]
mod slab_harden;

// N12h: the CAS installs the user mapper and the kernel-half merge race for.
// Depends on `core` only.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/pte_install.rs"]
mod pte_install;

/// N12h: a merge-slot level-1 word two writers race for (the task's mapper
/// and the kernel-half push) is installed by CAS; the loser adopts the
/// winner's word, and the merge copies kernel leaves into a user table.
/// Canary: replace `install`'s compare-exchange with a load-then-store
/// (`slot.store(new)` after checking `seen`) and
/// `a_lost_install_keeps_the_winners_word` and the threaded race go red.
#[cfg(test)]
mod pte_install_tests {
    use super::pte_install::{fill_empty, install};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    const EMPTY: u64 = 0;
    const V: u64 = 1; // valid bit
    const U: u64 = 1 << 4; // user bit
    const MARKER: u64 = 1 << 62; // an invalid, non-empty word (demand marker)
    fn valid(w: u64) -> bool { w & V != 0 }
    fn kernel_leaf(w: u64) -> bool { w & U == 0 }

    #[test]
    fn a_lost_install_keeps_the_winners_word() {
        let slot = AtomicU64::new(EMPTY);
        // Both writers read the slot empty...
        let seen_user = slot.load(Ordering::Relaxed);
        let seen_kernel = slot.load(Ordering::Relaxed);
        // ...the user's table goes in first...
        let user_table = 0x1000 | V;
        assert_eq!(install(&slot, seen_user, user_table), Ok(()));
        // ...and the kernel's install must not overwrite it: it is told the winner.
        let kernel_table = 0x2000 | V;
        assert_eq!(install(&slot, seen_kernel, kernel_table), Err(user_table));
        assert_eq!(slot.load(Ordering::Relaxed), user_table);
    }

    #[test]
    fn two_threads_racing_for_one_word_leave_exactly_one_winner() {
        for round in 0..2000u64 {
            let slot = Arc::new(AtomicU64::new(EMPTY));
            let go = Arc::new(Barrier::new(2));
            let words = [(round << 13) | 0x1000 | V, (round << 13) | 0x2000 | V];
            let hs: Vec<_> = words.iter().map(|&w| {
                let (slot, go) = (slot.clone(), go.clone());
                std::thread::spawn(move || {
                    let seen = slot.load(Ordering::Relaxed);
                    go.wait();
                    match install(&slot, seen, w) { Ok(()) => w, Err(cur) => cur }
                })
            }).collect();
            let adopted: Vec<u64> = hs.into_iter().map(|h| h.join().unwrap()).collect();
            let fin = slot.load(Ordering::Relaxed);
            // Both writers end on the word in the slot: nobody's table was dropped.
            assert_eq!(adopted, vec![fin, fin], "round {round}");
            assert!(words.contains(&fin));
        }
    }

    #[test]
    fn the_merge_copies_kernel_leaves_into_a_user_table_and_keeps_the_users_words() {
        let user: Vec<AtomicU64> = (0..8).map(|_| AtomicU64::new(EMPTY)).collect();
        let kern: Vec<AtomicU64> = (0..8).map(|_| AtomicU64::new(EMPTY)).collect();
        user[0].store(0xa000 | V | U, Ordering::Relaxed); // the user's page
        user[2].store(MARKER, Ordering::Relaxed); // a demand reservation
        kern[0].store(0xb000 | V, Ordering::Relaxed); // collides with the user's page
        kern[1].store(0xc000 | V, Ordering::Relaxed); // device page: copied
        kern[2].store(0xd000 | V, Ordering::Relaxed); // collides with the marker
        kern[3].store(0xe000 | V | U, Ordering::Relaxed); // a USER word: never copied
        kern[4].store(0xf000, Ordering::Relaxed); // invalid: never copied
        let n = fill_empty(&user, &kern, EMPTY, valid, kernel_leaf);
        assert_eq!(n, 1);
        let got: Vec<u64> = user.iter().map(|w| w.load(Ordering::Relaxed)).collect();
        assert_eq!(got[0], 0xa000 | V | U);
        assert_eq!(got[1], 0xc000 | V);
        assert_eq!(got[2], MARKER);
        assert_eq!(&got[3..], &[EMPTY; 5]);
        // Idempotent: a second push writes nothing.
        assert_eq!(fill_empty(&user, &kern, EMPTY, valid, kernel_leaf), 0);
    }
}

// FX7/FX8: the merged-root roster walk `vmm::with_merged_roots` and
// `vmm::propagate_kernel_entries` share. Depends on `core` only.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/roster.rs"]
mod roster;

/// FX8: `resume_walk` takes the lock once per visited entry, never across
/// two, and resumes after the last index it visited, so an entry that dies
/// ahead of the scan is skipped and one born behind it is not revisited.
/// Canary: make `resume_walk` take `hold()` once before its loop and scan
/// under that one guard (the shape `propagate_kernel_entries` had: the whole
/// roster in one `PT_META` hold) and `one_hold_per_visited_entry` goes red.
#[cfg(test)]
mod roster_tests {
    use super::roster::resume_walk;
    use std::cell::Cell;
    use std::sync::{Mutex, MutexGuard};

    const N: usize = 8;

    /// The guard the walk holds, with the number of `visit`s run under it.
    struct G<'a> {
        live: MutexGuard<'a, [bool; N]>,
        visits: Cell<usize>,
    }

    fn walk(
        m: &Mutex<[bool; N]>,
        holds: &Cell<usize>,
        mut on_visit: impl FnMut(usize) -> Result<(), usize>,
        seen: &mut Vec<usize>,
    ) -> Result<usize, usize> {
        resume_walk(
            N,
            || {
                holds.set(holds.get() + 1);
                G { live: m.lock().unwrap(), visits: Cell::new(0) }
            },
            |g, i| g.live[i],
            |g, i| {
                g.visits.set(g.visits.get() + 1);
                assert_eq!(g.visits.get(), 1, "two entries visited under one hold");
                assert!(g.live[i], "visited a dead entry");
                seen.push(i);
                on_visit(i)
            },
        )
    }

    #[test]
    fn one_hold_per_visited_entry() {
        let m = Mutex::new([false, true, false, true, true, false, true, false]);
        let holds = Cell::new(0);
        let mut seen = Vec::new();
        assert_eq!(walk(&m, &holds, |_| Ok(()), &mut seen), Ok(4));
        assert_eq!(seen, [1, 3, 4, 6]);
        // One hold per visit plus the final scan that finds nothing.
        assert_eq!(holds.get(), 5);
        assert!(m.try_lock().is_ok());
    }

    #[test]
    fn the_last_slot_needs_no_extra_scan() {
        let mut live = [false; N];
        live[N - 1] = true;
        let m = Mutex::new(live);
        let holds = Cell::new(0);
        let mut seen = Vec::new();
        assert_eq!(walk(&m, &holds, |_| Ok(()), &mut seen), Ok(1));
        assert_eq!(seen, [N - 1]);
        assert_eq!(holds.get(), 1);
    }

    #[test]
    fn empty_roster_takes_one_hold() {
        let m = Mutex::new([false; N]);
        let holds = Cell::new(0);
        let mut seen = Vec::new();
        assert_eq!(walk(&m, &holds, |_| Ok(()), &mut seen), Ok(0));
        assert!(seen.is_empty());
        assert_eq!(holds.get(), 1);
    }

    /// Between two holds an entry ahead of the scan dies (teardown leaves
    /// the roster) and one behind it is born: the dead one is not visited,
    /// the new one is not revisited, the walk still ends.
    #[test]
    fn changes_between_holds() {
        let m = Mutex::new([true, false, true, false, true, false, false, true]);
        let holds = Cell::new(0);
        let mut seen = Vec::new();
        let mut step = 0;
        let got = resume_walk(
            N,
            || {
                holds.set(holds.get() + 1);
                // The lock is free here: another hart's change lands.
                // After 0 and 2 are visited: scan resumes at 3.
                if step == 2 {
                    let mut l = m.lock().unwrap();
                    l[4] = false;
                    l[1] = true;
                    l[5] = true;
                }
                step += 1;
                m.lock().unwrap()
            },
            |g, i| g[i],
            |g, i| {
                assert!(g[i]);
                seen.push(i);
                Ok::<(), ()>(())
            },
        );
        assert_eq!(got, Ok(4));
        assert_eq!(seen, [0, 2, 5, 7]);
    }

    #[test]
    fn an_error_stops_the_walk_and_frees_the_lock() {
        let m = Mutex::new([true; N]);
        let holds = Cell::new(0);
        let mut seen = Vec::new();
        assert_eq!(walk(&m, &holds, |i| if i == 2 { Err(i) } else { Ok(()) }, &mut seen), Err(2));
        assert_eq!(seen, [0, 1, 2]);
        assert_eq!(holds.get(), 3);
        assert!(m.try_lock().is_ok());
    }
}

/// N12i: a writer walking a user root in step with the kernel root refuses
/// to descend into a table the kernel shares (`shadow_step`, called by
/// `vmm::walk(.., alloc = true)`, `l2_table_alloc_upper` and `map_mega`), and
/// a user unmap path leaves non-USER leaves alone (`user_may_modify`, called
/// by `unmap_inner` and `take_user_leaf`). The model below is `walk`'s
/// allocating descent over a three-level table, with the kernel-half push
/// injected at the two instants it can land: before the writer reads the
/// word, and between that read and its CAS.
/// Canary: make `shadow_step` return `Ok(0)` unconditionally and the two
/// push tests go red (a USER leaf lands in the kernel's table); make
/// `user_may_modify` return `true` and `a_kernel_leaf_is_not_the_users_to_modify`
/// goes red.
#[cfg(test)]
mod kernel_shadow_tests {
    use super::pte_install::{install, shadow_step, user_may_modify};
    use std::sync::atomic::{AtomicU64, Ordering};

    const EMPTY: u64 = 0;
    const V: u64 = 1;
    const LEAF: u64 = 1 << 1;
    const U: u64 = 1 << 4;
    const MARKER: u64 = 1 << 62;
    const N: usize = 8; // entries per model table

    fn is_table(w: u64) -> bool { w & V != 0 && w & LEAF == 0 }
    fn phys(w: u64) -> usize { (w >> 12) as usize }
    fn link(t: usize) -> u64 { ((t as u64) << 12) | V }

    /// Frame `i` is table `i`; frame 0 is never a table (it means "none").
    struct Mem { t: Vec<Vec<AtomicU64>>, next: std::cell::Cell<usize> }
    impl Mem {
        fn new(frames: usize, first_free: usize) -> Self {
            Mem {
                t: (0..frames).map(|_| (0..N).map(|_| AtomicU64::new(EMPTY)).collect()).collect(),
                next: std::cell::Cell::new(first_free),
            }
        }
        fn w(&self, t: usize, i: usize) -> &AtomicU64 { &self.t[t][i] }
        fn alloc(&self) -> usize { let n = self.next.get(); self.next.set(n + 1); n }
        fn snapshot(&self, t: usize) -> Vec<u64> {
            self.t[t].iter().map(|w| w.load(Ordering::Relaxed)).collect()
        }
    }

    /// `walk(root, va, alloc = true)` then the leaf install, at `path`
    /// (vpn2, vpn1, vpn0). `push(level, before_cas)` runs at each level
    /// before the read (`false`) and, when the word was empty, between the
    /// read and the CAS (`true`).
    fn writer_map(m: &Mem, root: usize, kroot: usize, path: [usize; 3], leaf: u64,
                  mut push: impl FnMut(usize, bool)) -> Result<usize, ()> {
        let mut pt = root;
        let mut kt = if kroot == root { 0 } else { kroot };
        for (level, &vpn) in [(2usize, &path[0]), (1, &path[1])] {
            push(level, false);
            let w = m.w(pt, vpn).load(Ordering::Acquire);
            let child = if w & V != 0 {
                phys(w)
            } else {
                let new = m.alloc();
                push(level, true);
                match install(m.w(pt, vpn), w, link(new)) { Ok(()) => new, Err(cur) => phys(cur) }
            };
            kt = shadow_step(kt, child, || m.w(kt, vpn).load(Ordering::Relaxed), is_table, phys)?;
            pt = child;
        }
        install(m.w(pt, path[2]), EMPTY, leaf).map_err(|_| ())?;
        Ok(pt)
    }

    /// Kernel root 1 -> its L1 2 -> its L0 3 at (0, 5), with a device leaf at
    /// 3[0]. User root 4 owns its L1 5 in that merge slot (vpn2 0). Frames 6..
    /// are free.
    fn setup() -> Mem {
        let m = Mem::new(16, 6);
        m.w(1, 0).store(link(2), Ordering::Relaxed);
        m.w(2, 5).store(link(3), Ordering::Relaxed);
        m.w(3, 0).store((0x9 << 12) | V | LEAF, Ordering::Relaxed);
        m.w(4, 0).store(link(5), Ordering::Relaxed);
        m
    }
    /// The push: link the kernel's L0 into the user's L1 word, by CAS from
    /// empty, as `merge_kernel_l2`'s L1 fill does.
    fn push(m: &Mem) { let _ = install(m.w(5, 5), EMPTY, link(3)); }

    const USER_LEAF: u64 = (0x77 << 12) | V | LEAF | U;

    #[test]
    fn a_push_before_the_read_is_refused_and_the_kernel_table_is_untouched() {
        let m = setup();
        let before = m.snapshot(3);
        let r = writer_map(&m, 4, 1, [0, 5, 2], USER_LEAF, |lvl, cas| if lvl == 1 && !cas { push(&m) });
        assert_eq!(r, Err(()));
        assert_eq!(m.snapshot(3), before, "a USER leaf landed in the kernel's shared L0");
    }

    #[test]
    fn a_push_between_the_read_and_the_cas_is_refused_and_the_kernel_table_is_untouched() {
        let m = setup();
        let before = m.snapshot(3);
        let r = writer_map(&m, 4, 1, [0, 5, 2], USER_LEAF, |lvl, cas| if lvl == 1 && cas { push(&m) });
        assert_eq!(r, Err(()));
        assert_eq!(m.snapshot(3), before, "a USER leaf landed in the kernel's shared L0");
    }

    #[test]
    fn without_a_push_the_writer_fills_its_own_table_and_the_push_then_loses() {
        let m = setup();
        let before = m.snapshot(3);
        let l0 = writer_map(&m, 4, 1, [0, 5, 2], USER_LEAF, |_, _| {}).unwrap();
        assert_ne!(l0, 3);
        assert_eq!(m.w(l0, 2).load(Ordering::Relaxed), USER_LEAF);
        push(&m); // loses the CAS: the user's table stays
        assert_eq!(m.w(5, 5).load(Ordering::Relaxed), link(l0));
        assert_eq!(m.snapshot(3), before);
    }

    #[test]
    fn the_kernel_writing_its_own_root_is_not_refused() {
        let m = setup();
        let l0 = writer_map(&m, 1, 1, [0, 5, 2], (0x8 << 12) | V | LEAF, |_, _| {}).unwrap();
        assert_eq!(l0, 3);
    }

    #[test]
    fn a_kernel_leaf_is_not_the_users_to_modify() {
        let valid = |w: u64| w & V != 0;
        let user = |w: u64| w & U != 0;
        let device = (0x9 << 12) | V | LEAF;
        // The merge's copy of the kernel's device window: the kernel maps the same frame.
        assert!(!user_may_modify(device, valid, user, || true));
        // A kernel-permission page only this root maps (the TLB smoke's): the root's own.
        assert!(user_may_modify(device, valid, user, || false));
        // The task's pages and reservations: never asks the kernel.
        assert!(user_may_modify(USER_LEAF, valid, user, || unreachable!()));
        assert!(user_may_modify(EMPTY, valid, user, || unreachable!()));
        assert!(user_may_modify(MARKER, valid, user, || unreachable!()));
    }
}

/// Every test that touches the `pmm` singleton or the frame window it
/// publishes takes this.
#[cfg(test)]
static PMM_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// The allocator over its singleton (`pmm_tests.rs`) and the engine under it
// (`buddy_tests.rs`).
#[cfg(test)]
mod pmm_tests;
#[cfg(test)]
mod buddy_tests;
#[cfg(test)]
mod zone_tests;
#[cfg(test)]
mod rmap;
#[cfg(test)]
mod ro_hooks;

/// The W^X boundary rule (`crates/core/mm/src/wx.rs`).
///
/// **WHY.** `enforce_wx` computed these boundaries inline and returned `()`.
/// Nothing read a PTE back, so "W^X enforced" in the boot log was a `kprintln`
/// placed after the call, not a result — every way the enforcement could fail
/// (a megapage the split skipped on OOM, a page `remap_range` passed over
/// because it was not a valid 4 KiB leaf) printed the same green line. The
/// arithmetic now lives here so the verifier reads the SAME ranges instead of
/// re-deriving them, and these tests hold the rule that both of them obey.
#[cfg(test)]
mod wx_rule {
    use super::wx::{self, PageVerdict, WxReport};
    use azos_arch_api::{PagePerms, PAGE_SIZE};

    /// A kernel image laid out like the real linker script: sections in
    /// order, each starting where the last ended, none page-aligned by
    /// accident. Offsets chosen so `.text`/`.rodata` share a page and
    /// `.rodata`/`.data` share a different one — the only interesting part
    /// of the rule.
    const BASE: usize = 0x8020_0000;
    const TEXT_START: usize = BASE;
    const TEXT_END: usize = BASE + 0x3_0800;      // mid-page
    const RO_START: usize = TEXT_END;
    const RO_END: usize = BASE + 0x4_0400;        // mid-page
    const DATA_START: usize = RO_END;
    const KERNEL_END: usize = BASE + 0x5_0000;    // page-aligned

    fn plan() -> [wx::WxRange; 3] {
        wx::plan(TEXT_START, TEXT_END, RO_START, RO_END, DATA_START, KERNEL_END)
    }

    /// The tie-break the original comment promised: a page holding the end of
    /// `.text` and the start of `.rodata` keeps X, because dropping it would
    /// fault the code in that page's first half.
    #[test]
    fn a_page_shared_by_text_and_rodata_stays_executable() {
        let [text, rodata, _] = plan();
        let shared = TEXT_END & !(PAGE_SIZE - 1);
        assert!(
            shared < text.end,
            ".text must extend past {shared:#x} to cover the shared page",
        );
        assert!(
            rodata.start > shared,
            ".rodata must start after the shared page, not reclaim it: \
             starts {:#x}, shared page {shared:#x}", rodata.start,
        );
        assert!(text.flags.exec);
    }

    /// And the same tie-break one section down.
    #[test]
    fn a_page_shared_by_rodata_and_data_stays_read_only() {
        let [_, rodata, data] = plan();
        let shared = RO_END & !(PAGE_SIZE - 1);
        assert!(shared < rodata.end, ".rodata must cover the shared page");
        assert!(
            data.start >= rodata.end,
            ".data must not reclaim the page .rodata still needs",
        );
        assert!(!rodata.flags.write);
    }

    /// No range the planner emits may be writable and executable — the whole
    /// point, held against the plan itself rather than against a page table.
    #[test]
    fn no_planned_range_is_both_writable_and_executable() {
        for r in plan() {
            assert!(
                !wx::is_write_exec(r.flags),
                "{} was planned W+X: {:?}", r.name, r.flags,
            );
        }
    }

    /// Each section gets the permission its name implies, and nothing more.
    #[test]
    fn each_section_gets_exactly_the_permission_it_needs() {
        let [text, rodata, data] = plan();
        assert!(text.flags.exec && !text.flags.write);
        assert!(!rodata.flags.exec && !rodata.flags.write);
        assert!(data.flags.write && !data.flags.exec);
        // `.rodata`'s flags used to be spelled out as a literal
        // `VALID | READ | ACCESSED`. Same permissions, and this pins that the
        // rename to a named constant did not change them.
        assert_eq!(rodata.flags, PagePerms::KERNEL_RO);
    }

    /// The ranges must tile the image without overlapping, or a later
    /// `remap_range` silently undoes an earlier one somewhere other than the
    /// two boundary pages where that is intended.
    #[test]
    fn the_three_ranges_tile_the_image_without_gaps() {
        let [text, rodata, data] = plan();
        assert_eq!(text.start, TEXT_START & !(PAGE_SIZE - 1));
        assert_eq!(rodata.start, text.end, "gap or overlap between .text and .rodata");
        assert_eq!(data.start, rodata.end, "gap or overlap between .rodata and .data");
        assert_eq!(data.end, KERNEL_END, "the plan must reach the end of the image");
    }

    /// A section that is entirely inside its predecessor's last page produces
    /// an EMPTY range, not a backwards one. `enforce_wx` skips empty ranges;
    /// a range with `end < start` would make its loop run to overflow.
    #[test]
    fn a_section_swallowed_by_the_previous_page_is_empty_not_backwards() {
        // `.text` must end MID-page for this to bite: its range then rounds
        // up over the whole page, and a 16-byte `.rodata` living in that same
        // page has nothing left to claim. (A first version of this test had
        // `.text` ending exactly on a page boundary, where `.rodata` does get
        // its own page — it failed, correctly, and said so.)
        let t_end = BASE + 0x800;
        let p = wx::plan(BASE, t_end, t_end, t_end + 16, t_end + 16, BASE + 0x2000);
        let rodata = p[1];
        assert!(rodata.is_empty(), "expected an empty range, got {rodata:?}");
        assert_eq!(rodata.pages(), 0);
        assert!(
            rodata.start <= rodata.end,
            "a range must never run backwards: enforce_wx would loop past it \
             and verify_wx would walk to overflow — {rodata:?}",
        );
        // And the section after it still lands where it should.
        assert_eq!(p[2].start, BASE + 0x1000, ".data must start on the next whole page");
        assert_eq!(p[2].end, BASE + 0x2000);
    }

    // REQ-013
    /// `is_write_exec` is the security predicate; an invalid PTE is not a
    /// violation no matter which permission bits are left in it.
    #[test]
    fn only_a_valid_mapping_can_violate_wx() {
        assert!(wx::is_write_exec(PagePerms::KERNEL_RWX));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RX));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RW));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RO));
    }

    // REQ-013
    /// A W+X page is reported as a violation even when it is what the plan
    /// asked for — the predicate is about the hardware, not about intent.
    /// Nothing should ever plan W+X (pinned above), so this is the belt to
    /// that test's braces.
    #[test]
    fn write_exec_outranks_a_flag_match() {
        assert_eq!(
            wx::judge(PagePerms::KERNEL_RWX, PagePerms::KERNEL_RWX),
            PageVerdict::WriteExec,
            "matching a W+X plan is still a W+X page",
        );
    }

    /// Flags that differ from the plan but are not W+X are a separate,
    /// weaker finding: the enforcer and the page table disagree.
    #[test]
    fn a_mismatch_that_is_not_write_exec_is_reported_apart() {
        assert_eq!(wx::judge(PagePerms::KERNEL_RX, PagePerms::KERNEL_RX), PageVerdict::Ok);
        assert_eq!(
            wx::judge(PagePerms::KERNEL_RX, PagePerms::KERNEL_RO),
            PageVerdict::WrongFlags,
            "a .text page that lost X is not a W^X violation, and is still wrong",
        );
    }

    /// `is_clean` and `has_wx_violation` are different questions and the
    /// report must not conflate them: an unmapped page inside the image is a
    /// surprise worth failing on, but it is not a security violation.
    #[test]
    fn a_clean_report_and_a_safe_report_are_not_the_same_question() {
        let mut r = WxReport::default();
        r.record(0x1000, PageVerdict::Ok);
        assert!(r.is_clean() && !r.has_wx_violation());

        let mut unmapped = WxReport::default();
        unmapped.record(0x2000, PageVerdict::Unmapped);
        assert!(!unmapped.is_clean(), "an unmapped image page must not read as clean");
        assert!(
            !unmapped.has_wx_violation(),
            "and it must not be reported as a security violation either",
        );

        let mut wx_bad = WxReport::default();
        wx_bad.record(0x3000, PageVerdict::WriteExec);
        assert!(!wx_bad.is_clean() && wx_bad.has_wx_violation());
    }

    /// An unsplit megapage IS a security violation: `remap_range` would write
    /// 4 KiB flags into a 2 MiB leaf and retag the whole span with whichever
    /// section wrote last.
    #[test]
    fn an_unsplit_megapage_counts_as_a_violation_not_a_surprise() {
        let mut r = WxReport::default();
        r.record(0x4000, PageVerdict::UnsplitMegapage);
        assert!(
            r.has_wx_violation(),
            "a 2 MiB leaf under the kernel image means the enforcement did not happen",
        );
    }

    /// The first bad address is kept so the boot line names a page a person
    /// can go look at, and later failures do not overwrite it.
    #[test]
    fn the_report_remembers_the_first_bad_page_not_the_last() {
        let mut r = WxReport::default();
        r.record(0x1000, PageVerdict::Ok);
        r.record(0x2000, PageVerdict::WriteExec);
        r.record(0x3000, PageVerdict::WrongFlags);
        assert_eq!(r.first_bad, 0x2000);
        assert_eq!(r.checked, 3);
        assert_eq!(r.write_exec, 1);
        assert_eq!(r.wrong_flags, 1);
    }
}

/// EXEC outside the kernel image (`crates/core/mm/src/wx.rs`, RAM half).
///
/// **WHY.** `vmm::init` maps every page of RAM `KERNEL_RWX` — it has to, since
/// it runs before `enable_paging()` and the kernel is executing out of that
/// memory. `enforce_wx` then tightened only the image, so on a 128 MiB board
/// ~121 MiB stayed writable AND executable in the kernel's own page table:
/// the heap, every frame `pmm` hands out, every task stack. Measured, not
/// estimated: disabling the sweep reports 60 megapages + 311 pages still
/// executable, first at 0x80000000.
///
/// The sweep itself needs a live page table, so what is testable here is the
/// decision it applies to each leaf — which is the part that must not widen a
/// mapping or drop a bit it was not asked to drop.
#[cfg(test)]
mod nx_outside_image {
    use super::wx::{self, RamExecReport};
    use azos_arch_api::{PagePerms, PAGE_SIZE};

    const MEGA: usize = 2 * 1024 * 1024;

    /// EXEC is the only permission that comes off. A sweep that also cleared,
    /// say, `dirty` would make every stripped page fault on its next write on
    /// a core with software-managed A/D — which is the configuration this
    /// kernel targets (`KERNEL_RW` pre-sets A+D for exactly that reason).
    #[test]
    fn stripping_exec_changes_exec_and_nothing_else() {
        let before = PagePerms::KERNEL_RWX;
        let after = wx::without_exec(before).expect("RWX is executable");
        assert_eq!(after, PagePerms { exec: false, ..before });
        assert_eq!(after, PagePerms::KERNEL_RW, "RWX minus X must BE the RW mapping");
        assert_eq!(before.read, after.read, "the sweep must not touch read");
        assert_eq!(before.write, after.write, "the sweep must not touch write");
        assert_eq!(before.user, after.user, "the sweep must not touch user");
        assert_eq!(before.mem, after.mem, "the sweep must not touch the memory type");
        assert_eq!(before.accessed, after.accessed, "the sweep must not touch accessed");
        assert_eq!(before.dirty, after.dirty, "the sweep must not touch dirty");
    }

    /// A mapping with nothing to strip returns `None`, so the caller counts
    /// mappings it CHANGED rather than addresses it visited. The difference
    /// matters: the second number reads as a measurement and is not one.
    #[test]
    fn a_non_executable_mapping_is_left_alone() {
        assert_eq!(wx::without_exec(PagePerms::KERNEL_RW), None);
        assert_eq!(wx::without_exec(PagePerms::KERNEL_RO), None);
    }

    /// Executable is executable whether or not it is also writable. The image
    /// half of W^X asks "W AND X"; out here every page is data, so the
    /// question is just "X at all" — a KERNEL_RX page in the heap would be
    /// W^X-clean and still has no business existing.
    #[test]
    fn read_execute_counts_as_executable_out_here() {
        assert!(wx::is_exec(PagePerms::KERNEL_RX));
        assert!(!wx::is_write_exec(PagePerms::KERNEL_RX), "and it is NOT a W^X violation");
        assert_eq!(wx::without_exec(PagePerms::KERNEL_RX), Some(PagePerms::KERNEL_RO));
    }

    /// Megapages and pages are counted apart, and the byte total is what gets
    /// printed. Summing the two entry counts would produce a number with no
    /// meaning — one L1 leaf covers 512 times the address space of one L0.
    #[test]
    fn the_report_totals_bytes_not_entries() {
        let mut r = RamExecReport::default();
        for i in 0..60 { r.record_mega(0x8000_0000 + i * MEGA); }
        for i in 0..311 { r.record_page(0x8600_0000 + i * PAGE_SIZE); }
        assert_eq!(r.megapages, 60);
        assert_eq!(r.pages, 311);
        // The figure the boot line prints, and the one measured by disabling
        // the sweep on a real 128 MiB boot.
        assert_eq!(r.bytes() >> 20, 121, "60 megapages + 311 pages is 121 MiB");
        assert!(!r.is_empty());
    }

    /// The first executable address is kept so the failure line names a page
    /// somebody can go look at, and a later find does not overwrite it.
    #[test]
    fn the_report_remembers_the_first_address_across_both_units() {
        let mut r = RamExecReport::default();
        r.record_mega(0x8000_0000);
        r.record_page(0x8010_0000);
        r.record_mega(0x8020_0000);
        assert_eq!(r.first, 0x8000_0000);

        // And a page seen before any megapage sets it just the same.
        let mut p = RamExecReport::default();
        p.record_page(0x8140_0000);
        p.record_mega(0x8000_0000);
        assert_eq!(p.first, 0x8140_0000, "first SEEN, not lowest");
    }

    /// An empty report is the success condition the boot line keys on, so it
    /// must not be confusable with "nothing was walked".
    #[test]
    fn an_empty_report_means_nothing_executable_was_found() {
        let r = RamExecReport::default();
        assert!(r.is_empty());
        assert_eq!(r.bytes(), 0);
    }
}

/// The COW refcount table (`cow_table.rs`), the real code.
///
/// **WHY A MODEL.** The table is now an array indexed by frame number. The
/// strongest test is still the boring one: run the same operations through the
/// real table and through an obviously correct `Vec`, and require identical
/// results at every step. Two frames sharing a counter, an off-by-one in the
/// index, or a wrong initial count each break the equality within a few
/// thousand steps.
///
/// **WHAT IT REPLACED.** A 512-entry table scanned from index 0. It cost a fork
/// of an M-page process M²/2 comparisons and refused any fork past 512 shared
/// pages, so `a_process_past_the_old_512_page_ceiling_can_fork` is the test that
/// could not have passed before.
#[cfg(test)]
mod cow_table_tests {
    use super::cow_table::{page_addref, page_decref, page_getref};
    use super::pmm;
    use azos_arch::mmu::PAGE_SIZE;
    use azos_common::error::KernelError;

    /// Managed frames in the test window. Well past the old 512-entry cap.
    const FRAMES: usize = 4096;
    /// Frames the descriptor array takes at the start of the arena:
    /// `FRAMES + ARRAY` descriptors of 32 bytes, rounded up to whole frames.
    const ARRAY: usize = 33;

    /// Where the window starts. A real, leaked, page-aligned arena: `init`
    /// writes the frame descriptors into the RAM it manages.
    fn base() -> usize {
        use std::sync::OnceLock;
        static BASE: OnceLock<usize> = OnceLock::new();
        *BASE.get_or_init(|| {
            let raw = vec![0u8; (FRAMES + ARRAY + 1) * PAGE_SIZE].leak();
            (raw.as_ptr() as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        })
    }

    /// The window the table indexes by. Holds the crate-wide pmm lock for the
    /// whole test.
    fn window() -> std::sync::MutexGuard<'static, ()> {
        let g = super::PMM_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // The descriptors take the first frames of the arena; the frames the
        // tests count are the ones after them.
        assert_eq!(super::frame::table_bytes(FRAMES + ARRAY), ARRAY * PAGE_SIZE);
        assert!(pmm::init(base(), (FRAMES + ARRAY) * PAGE_SIZE, base()));
        g
    }

    /// The `n`th frame past the descriptor array.
    fn frame(n: usize) -> usize { base() + (ARRAY + n) * PAGE_SIZE }

    /// Drop every frame in `0..n` from the table, whatever its count.
    fn drain(n: usize) {
        for i in 0..n {
            super::cow_table::shim_set_refcount(frame(i), 0);
        }
    }

    /// The semantics as originally written, as a `Vec`.
    #[derive(Default)]
    struct Model(Vec<(usize, u32)>);
    impl Model {
        fn addref(&mut self, p: usize) {
            match self.0.iter_mut().find(|e| e.0 == p) {
                Some(e) => e.1 = e.1.saturating_add(1),
                None => self.0.push((p, 2)),
            }
        }
        fn decref(&mut self, p: usize) -> bool {
            match self.0.iter().position(|e| e.0 == p) {
                Some(i) if self.0[i].1 <= 1 => { self.0.remove(i); true }
                Some(i) => { self.0[i].1 -= 1; false }
                None => true, // untracked: the caller is the sole owner
            }
        }
        fn getref(&self, p: usize) -> u32 {
            self.0.iter().find(|e| e.0 == p).map_or(0, |e| e.1)
        }
    }

    #[test]
    fn matches_a_plain_vec_over_thousands_of_mixed_operations() {
        let _g = window();
        const PAGES: usize = 48;
        drain(PAGES);
        let mut m = Model::default();
        // xorshift: deterministic, so a failure names its step.
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        for step in 0..6000 {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            let p = frame((s >> 8) as usize % PAGES);
            match (s >> 40) % 3 {
                0 => { page_addref(p).unwrap(); m.addref(p); }
                1 => assert_eq!(page_decref(p), m.decref(p), "decref({p:#x}) at step {step}"),
                _ => {}
            }
            assert_eq!(page_getref(p), m.getref(p), "getref({p:#x}) at step {step}");
        }
        for i in 0..PAGES {
            assert_eq!(page_getref(frame(i)), m.getref(frame(i)), "final state of page {i}");
        }
        drain(PAGES);
    }

    /// A fork, a second fork, then both children exiting, in address order, the
    /// shape every real caller has. Nothing may be lost or miscounted.
    #[test]
    fn a_fork_shaped_walk_counts_every_page() {
        let _g = window();
        const N: usize = 200;
        drain(N);
        for _ in 0..3 {
            for i in 0..N { page_addref(frame(i)).unwrap(); }
        }
        // First fork takes a page to 2, later ones add one each: 2 + 1 + 1.
        for i in 0..N { assert_eq!(page_getref(frame(i)), 4, "page {i}"); }
        for round in 0..3 {
            for i in 0..N {
                assert!(!page_decref(frame(i)), "page {i} freed early in round {round}");
            }
        }
        // 4 -> 1 after three drops; the last holder's decref frees it.
        for i in 0..N { assert_eq!(page_getref(frame(i)), 1, "page {i}"); }
        for i in 0..N { assert!(page_decref(frame(i)), "page {i} not freed by its last holder"); }
        for i in 0..N { assert_eq!(page_getref(frame(i)), 0, "page {i} left a count behind"); }
    }

    /// **The test the old table could not pass.** It refused the 513th distinct
    /// shared page with `CapacityFull`, so `fork` of any process past ~2 MiB
    /// failed. Here a process of `FRAMES - 1` shared pages forks and every page
    /// is counted.
    #[test]
    fn a_process_past_the_old_512_page_ceiling_can_fork() {
        let _g = window();
        let n = FRAMES - 1;
        assert!(n > 512, "the test must exceed the old ceiling to mean anything");
        drain(n);
        for i in 0..n {
            assert_eq!(page_addref(frame(i)), Ok(()), "page {i} refused: a ceiling is back");
        }
        for i in 0..n { assert_eq!(page_getref(frame(i)), 2, "page {i}"); }
        for i in 0..n { assert!(!page_decref(frame(i)), "page {i}"); }
        for i in 0..n { assert!(page_decref(frame(i)), "page {i}"); }
        for i in 0..n { assert_eq!(page_getref(frame(i)), 0, "page {i}"); }
    }

    /// Two different frames must never share a counter, and the first and last
    /// frames of the window are both real.
    #[test]
    fn distinct_frames_have_distinct_counters_at_the_window_edges() {
        let _g = window();
        let (first, last) = (frame(0), frame(FRAMES - 1));
        drain(FRAMES);
        page_addref(first).unwrap();
        assert_eq!(page_getref(first), 2);
        assert_eq!(page_getref(last), 0, "the last frame aliased the first");
        assert_eq!(page_getref(frame(1)), 0, "an adjacent frame aliased");
        page_addref(last).unwrap();
        page_addref(last).unwrap();
        assert_eq!(page_getref(last), 3);
        assert_eq!(page_getref(first), 2, "counting the last frame moved the first");
        drain(FRAMES);
    }

    /// Anything that is not a managed, page-aligned frame is refused, and asking
    /// after one answers "untracked, caller owns it" without touching a counter.
    #[test]
    fn a_frame_outside_the_window_or_unaligned_is_refused() {
        let _g = window();
        drain(FRAMES);
        for bad in [base() - PAGE_SIZE, frame(FRAMES), frame(FRAMES) + PAGE_SIZE, frame(0) + 1, frame(0) + PAGE_SIZE - 1, 0] {
            assert_eq!(page_addref(bad), Err(KernelError::InvalidArg), "{bad:#x} was accepted");
            assert_eq!(page_getref(bad), 0, "{bad:#x}");
            assert!(page_decref(bad), "{bad:#x}: not ours to count, so the caller is the sole owner");
        }
        // And the refused calls counted nothing anywhere.
        for i in [0, 1, FRAMES - 1] { assert_eq!(page_getref(frame(i)), 0, "frame {i}"); }
    }

    /// The count is one atomic word with no lock: updates from several threads
    /// to one frame must all land.
    #[test]
    fn concurrent_addrefs_and_decrefs_lose_no_update() {
        let _g = window();
        drain(1);
        let p = frame(0);
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| for _ in 0..5000 { page_addref(p).unwrap(); });
            }
        });
        assert_eq!(page_getref(p), 2 + 19_999, "the first addref makes it 2, every other adds one");
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| for _ in 0..5000 { assert!(!page_decref(p)); });
            }
        });
        assert_eq!(page_getref(p), 1);
        assert!(page_decref(p), "the last holder frees");
        assert_eq!(page_getref(p), 0);
    }

    /// The reuse path of a COW fault clears the count only for the sole
    /// holder; a fork that counted the frame meanwhile makes it refuse.
    #[test]
    fn forget_if_sole_clears_only_a_sole_holders_count() {
        use super::cow_table::{page_forget_if_sole, page_is_shared, page_is_sole};
        let _g = window();
        drain(2);
        let p = frame(1);
        assert!(page_is_sole(p) && !page_is_shared(p), "untracked: one holder");
        assert!(page_forget_if_sole(p));
        super::cow_table::shim_set_refcount(p, 1);
        assert!(page_is_sole(p));
        assert!(page_forget_if_sole(p));
        assert_eq!(page_getref(p), 0);
        page_addref(p).unwrap();
        assert!(!page_is_sole(p) && page_is_shared(p));
        assert!(!page_forget_if_sole(p), "a second holder: refused");
        assert_eq!(page_getref(p), 2, "and the count is untouched");
        let outside = frame(FRAMES);
        assert!(!page_is_sole(outside) && !page_is_shared(outside) && !page_forget_if_sole(outside));
        drain(2);
    }

    /// A count that reaches `u32::MAX` stays there rather than wrapping to 0
    /// (which would read as "untracked" and free a shared frame).
    #[test]
    fn a_count_saturates_and_never_wraps_to_untracked() {
        let _g = window();
        let p = frame(7);
        drain(8);
        super::cow_table::shim_set_refcount(p, u32::MAX - 3);
        for _ in 0..50 { page_addref(p).unwrap(); }
        assert_eq!(page_getref(p), u32::MAX, "saturation lost");
        assert!(!page_decref(p), "a saturated page is still shared");
        assert_eq!(page_getref(p), u32::MAX - 1);
        drain(8);
    }
}

/// The per-task frame budget (`budget.rs`, carved out of `scheduler.rs`'s
/// `mm_charge`/`mm_discharge`/`mm_reset_charge`).
///
/// **WHY THIS CLOSES THE OPEN FINDING.** Scan unit 3 finding 3 (owner decision
/// 102) shipped with the positive half proven in `tests/host/syscall-tests`
/// (`mmap_guards.rs`) and the refusal proven at the QEMU gate
/// (`mem-quota-canary`, `tools/ci_check.sh`) — but neither exercises the REAL
/// `mm_charge`/`mm_discharge` in `scheduler.rs`. `syscall-tests`' own shim says
/// so explicitly: it is "State, not behaviour... SEMANTICS are copied
/// deliberately", proving the WIRING in `handlers.rs`, not this decision. The
/// diagnosis that a per-test arena was missing (the mistake that cost three
/// withdrawn attempts on the write-guard finding) does not apply here: `mm_charge`
/// takes no allocator lock and touches no PMM arena at all, it is three
/// integers behind a task-table index. What was actually missing was a SEAM —
/// the arithmetic was inlined on `TASKS[idx]` inside a file that cannot be
/// `#[path]`-pulled. `budget.rs` is that seam, tested here as the real code
/// `tests/host/mm-tests` links (see its own header for what still has to happen in
/// `scheduler.rs` to make this the code that ships).
#[cfg(test)]
mod budget_tests {
    use super::budget::PageBudget;

    /// `pages == 0` must succeed and touch nothing — not even the peak. A
    /// caller (`sys_mmap` with a zero-length request) must not see a spurious
    /// high-water mark from a no-op call.
    #[test]
    fn charging_zero_pages_is_a_free_no_op() {
        let b = PageBudget::new();
        b.set_limit(4);
        assert!(b.charge(0));
        assert_eq!(b.used(), 0);
        assert_eq!(b.peak(), 0);
    }

    /// `limit == 0` is "no limit" — the state every task without a `mem_pages`
    /// row in its topology gets. A charge that would refuse under any nonzero
    /// limit must still succeed here.
    #[test]
    fn a_zero_limit_means_unlimited() {
        let b = PageBudget::new();
        assert!(b.charge(1_000_000));
        assert_eq!(b.used(), 1_000_000);
    }

    /// The positive half, reproduced at the host: a task that stays within its
    /// budget is charged exactly what it asked for, and the peak tracks the
    /// running total, not the last charge.
    #[test]
    fn charging_within_the_limit_succeeds_and_tracks_the_peak() {
        let b = PageBudget::new();
        b.set_limit(16);
        assert!(b.charge(10));
        assert_eq!(b.used(), 10);
        assert_eq!(b.peak(), 10);
        assert!(b.charge(6));
        assert_eq!(b.used(), 16);
        assert_eq!(b.peak(), 16);
    }

    /// **The runaway-`brk` proof, at the host.** A task that keeps charging
    /// one page at a time (`sys_brk_impl`'s shape) is granted pages up to
    /// EXACTLY the budget and refused — with NOTHING charged — the moment it
    /// would go over. This is the host-level twin of the QEMU
    /// `mem-quota-canary` row (`tools/ci_check.sh`, budget dropped to 16,
    /// `abitest` asks for 256 and is granted 16): same ceiling, same
    /// one-page-at-a-time shape, no QEMU boot needed to see it fail. A quota
    /// wired to refuse everything fails the first assertion; one wired to
    /// refuse nothing never reaches the last one.
    #[test]
    fn a_runaway_charge_one_page_at_a_time_is_refused_exactly_at_the_ceiling() {
        let b = PageBudget::new();
        b.set_limit(16);
        for i in 0..16 {
            assert!(b.charge(1), "page {i} of 16 must be granted");
        }
        assert_eq!(b.used(), 16, "the budget must bind exactly, not early");
        assert!(!b.charge(1), "the 17th page must be refused");
        assert_eq!(b.used(), 16, "a refused charge must charge NOTHING");
        // And the refusal is not a one-shot fluke: the task stays refused, it
        // does not silently get let through on a later attempt.
        assert!(!b.charge(1));
        assert_eq!(b.used(), 16);
    }

    /// `sys_mmap`'s shape: the whole request charged at once, because a
    /// caller that asked for 64 pages cannot use 40. A request that would
    /// exceed the budget must be refused WHOLESALE, not partially charged.
    #[test]
    fn a_whole_request_over_budget_is_refused_wholesale_not_partially_charged() {
        let b = PageBudget::new();
        b.set_limit(16);
        assert!(b.charge(10));
        assert!(!b.charge(10), "10 more would be 20, over a budget of 16");
        assert_eq!(b.used(), 10, "the refused 10-page request must not land any of its pages");
    }

    /// Over-discharge must floor at 0, not wrap to `u32::MAX` and disable the
    /// budget silently — the dangerous direction, since it refuses a task
    /// memory it is entitled to.
    #[test]
    fn discharging_more_than_used_floors_at_zero_instead_of_wrapping() {
        let b = PageBudget::new();
        b.charge(3);
        b.discharge(10);
        assert_eq!(b.used(), 0);
        // And the budget is still usable afterward — a wrap would have left
        // `used` near `u32::MAX`, refusing everything from here on.
        b.set_limit(4);
        assert!(b.charge(4));
    }

    /// `reset` (called on `exec_user` and on exit) must clear BOTH `used` and
    /// `peak` — the address space either one described is gone. Clearing only
    /// `used` would leave a stale peak attributed to whatever runs in that
    /// task slot next.
    #[test]
    fn reset_clears_both_used_and_the_peak() {
        let b = PageBudget::new();
        b.set_limit(0);
        b.charge(50);
        assert_eq!(b.peak(), 50);
        b.reset();
        assert_eq!(b.used(), 0);
        assert_eq!(b.peak(), 0, "a stale peak would misattribute the next task's cost");
    }

    /// **This workspace's overflow rule, held on the real code.** `panic =
    /// "abort"` + `overflow-checks = true` means a plain `+` here is a board
    /// reset, not a caught error (see `note_stalled_tick`,
    /// `crates/core/actuation/src/watchdog.rs`, for the established precedent).
    /// `charge` must saturate instead.
    ///
    /// Canary verified by hand (not left in the tree): replacing
    /// `self.used.saturating_add(pages)` in `budget.rs` with a plain `+`
    /// makes this test abort the whole `cargo test --release` process with
    /// "attempt to add with overflow" instead of failing this assertion —
    /// exactly the undiagnosed-abort class `mm-tests`' own `pmm::init` canary
    /// (see `init_refuses_a_mem_start_past_kernel_end_instead_of_underflowing`)
    /// exists to close off.
    #[test]
    fn charging_near_u32_max_saturates_instead_of_overflowing() {
        let b = PageBudget::new();
        b.set_limit(0); // unlimited: saturation, not the ceiling, is under test
        assert!(b.charge(u32::MAX - 1));
        assert!(b.charge(10), "would overflow u32 with a plain `+`");
        assert_eq!(b.used(), u32::MAX);
        assert_eq!(b.peak(), u32::MAX);
    }

    /// The discharge side of the same rule: `saturating_sub`, not `-`.
    #[test]
    fn discharging_past_zero_saturates_instead_of_underflowing() {
        let b = PageBudget::new();
        b.set_limit(0);
        assert!(b.charge(1));
        b.discharge(u32::MAX); // would underflow u32 with a plain `-`
        assert_eq!(b.used(), 0);
    }

    /// **Charges from several harts at once never pass the limit and never lose
    /// an update.** Eight threads charge one page at a time against a limit of
    /// 1000 while two more discharge-and-recharge: the grants are exactly the
    /// limit, `used` equals grants minus gives, and the peak never exceeded the
    /// limit. A check-then-store charge fails the first two on a multi-core
    /// host; the compare-and-swap does not.
    ///
    /// **Canary** `budget-racy-charge-canary` (feature of the pulled file): the
    /// test and the store are separate steps, and the totals disagree.
    #[test]
    fn concurrent_charges_never_pass_the_limit_or_lose_an_update() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        const LIMIT: u32 = 1000;
        // Many short rounds, the threads released together by a barrier: one
        // long round let the first thread take most of the limit before the
        // others were running, and the racy canary then went unseen on a loaded
        // host. A round is over when the limit is spent (2000 tries per thread).
        for _ in 0..60 {
            let b = Arc::new(PageBudget::new());
            b.set_limit(LIMIT);
            let granted = Arc::new(AtomicU32::new(0));
            let start = Arc::new(std::sync::Barrier::new(8));
            let mut ts = Vec::new();
            for _ in 0..8 {
                let (b, granted, start) = (b.clone(), granted.clone(), start.clone());
                ts.push(std::thread::spawn(move || {
                    start.wait();
                    for _ in 0..2_000 {
                        if b.charge(1) {
                            granted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }));
            }
            for t in ts {
                t.join().unwrap();
            }
            assert_eq!(granted.load(Ordering::Relaxed), LIMIT, "grants passed the limit or fell short");
            assert_eq!(b.used(), LIMIT, "an update was lost");
            assert!(b.peak() <= LIMIT, "the peak passed the limit");
        }

        // Charges and discharges interleaved: nothing is lost either way.
        let b = Arc::new(PageBudget::new());
        let mut ts = Vec::new();
        for _ in 0..4 {
            let b = b.clone();
            ts.push(std::thread::spawn(move || {
                for _ in 0..50_000 {
                    assert!(b.charge(3));
                    b.discharge(3);
                }
            }));
        }
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(b.used(), 0, "a charge or a discharge was lost");
    }
}

/// The COW-break counter (`cow_table.rs`): visibility for the frames a COW
/// break adds to a task's footprint, WITHOUT charging them against the quota.
///
/// **WHY UNCHARGED.** See `crates/core/mm/src/cow_table.rs`'s note on
/// `note_cow_break`:
/// `handle_cow_fault` has four failure paths, three are the calling program's
/// own bug, and the store-page-fault arm kills the task on any of them because
/// there is no signal/upcall ABI to hand a refusal back. Charging (with
/// refusal) would add an indistinguishable fifth kill for a task that broke a
/// page it was entitled to. This counter is the alternative: it moves once,
/// never backward except by an explicit reset, and never refuses anything.
#[cfg(test)]
mod cow_break_tests {
    use super::cow_table::{cow_break_frames, note_cow_break, shim_set_cow_breaks};

    /// Every test in this module touches the same global counter, so they
    /// must not interleave — same rule as `PMM_SERIAL`, a separate lock
    /// because this counter shares no state with the PMM arena or `REFS`.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static COW_BREAK_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
        COW_BREAK_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn note_cow_break_increments_the_visible_count() {
        let _g = serial();
        shim_set_cow_breaks(0);
        note_cow_break();
        note_cow_break();
        note_cow_break();
        assert_eq!(cow_break_frames(), 3);
    }

    /// **The saturation canary.** A plain `AtomicU32::fetch_add` wraps on
    /// overflow — atomics are not covered by `overflow-checks`, unlike every
    /// plain arithmetic op in this workspace's release profile — so a naive
    /// implementation of this counter would silently read `0` ("no COW
    /// breaks") right when it should read "over four billion", the opposite
    /// of what a diagnostic counter must do under pressure.
    ///
    /// This test was RED against exactly that naive implementation before
    /// `note_cow_break` was written to load-saturate-store instead of
    /// `fetch_add`ing (see the RED transcript in the task report).
    #[test]
    fn a_saturated_count_never_wraps_to_zero() {
        let _g = serial();
        shim_set_cow_breaks(u32::MAX);
        note_cow_break();
        assert_eq!(cow_break_frames(), u32::MAX,
            "a wrapped counter reads as \"no COW breaks\" — the wrong direction for a diagnostic");
        shim_set_cow_breaks(0); // leave the shared counter clean for other tests
    }
}

/// Wave 14 (DEMANDPAGE): `region.rs`, the bookkeeping the demand-fault path
/// trusts to say whether an address is reserved and with what permission.
/// Mutation canaries (run by hand, see the front report): `joins` always
/// false turns the fold rows red; dropping the straddle check in
/// `remove_range` turns `a_cut_needs_a_slot` red (index out of bounds);
/// `find` answering the first region whatever `va` turns the lookup rows red.
#[cfg(test)]
mod region_tests {
    use super::region::{Region, RegionError, RegionSet};
    const P: usize = 4096;

    fn anon(a: usize, b: usize, w: bool) -> Region {
        Region::anon(a * P, b * P, w)
    }

    fn spans<const N: usize>(s: &RegionSet<N>) -> Vec<(usize, usize, bool)> {
        s.as_slice().iter().map(|r| (r.start / P, r.end / P, r.write)).collect()
    }

    #[test]
    fn lookup_answers_inside_and_only_inside() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.insert(anon(30, 31, false)).unwrap();
        assert!(s.find(9 * P + P - 1).is_none());
        assert_eq!(s.find(10 * P).map(|r| r.write), Some(true));
        assert_eq!(s.find(20 * P - 1).map(|r| r.write), Some(true));
        assert!(s.find(20 * P).is_none(), "end is exclusive");
        assert_eq!(s.find(30 * P + 5).map(|r| r.write), Some(false));
        assert!(s.find(31 * P).is_none());
        assert_eq!(s.reserved_pages(), 11);
    }

    #[test]
    fn adjacent_compatible_ranges_fold() {
        let mut s = RegionSet::<2>::new();
        s.insert(anon(10, 11, true)).unwrap();
        s.insert(anon(11, 12, true)).unwrap();
        s.insert(anon(9, 10, true)).unwrap();
        assert_eq!(spans(&s), vec![(9, 12, true)]);
        // Filling the gap between two records folds all three into one.
        s.insert(anon(14, 15, true)).unwrap();
        s.insert(anon(12, 14, true)).unwrap();
        assert_eq!(spans(&s), vec![(9, 15, true)]);
        // Different permission: its own record.
        s.insert(anon(15, 16, false)).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.insert(anon(20, 21, true)), Err(RegionError::Full));
        assert_eq!(s.len(), 2, "a refusal changes nothing");
    }

    #[test]
    fn overlap_and_bad_ranges_are_refused() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        assert_eq!(s.insert(anon(19, 21, true)), Err(RegionError::Overlap));
        assert_eq!(s.insert(anon(5, 11, true)), Err(RegionError::Overlap));
        assert_eq!(s.insert(anon(12, 13, false)), Err(RegionError::Overlap));
        assert_eq!(s.insert(Region::anon(P, P, true)), Err(RegionError::Invalid));
        assert_eq!(s.insert(Region::anon(P + 1, 2 * P, true)), Err(RegionError::Invalid));
        assert_eq!(spans(&s), vec![(10, 20, true)]);
    }

    #[test]
    fn remove_range_trims_cuts_and_counts() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.insert(anon(30, 40, false)).unwrap();
        assert_eq!(s.remove_range(12 * P, 14 * P), Ok(2));
        assert_eq!(spans(&s), vec![(10, 12, true), (14, 20, true), (30, 40, false)]);
        assert_eq!(s.remove_range(18 * P, 35 * P), Ok(2 + 5));
        assert_eq!(spans(&s), vec![(10, 12, true), (14, 18, true), (35, 40, false)]);
        assert_eq!(s.remove_range(0, 100 * P), Ok(2 + 4 + 5));
        assert!(s.is_empty());
        assert_eq!(s.remove_range(0, P), Ok(0));
    }

    #[test]
    fn a_cut_needs_a_slot() {
        let mut s = RegionSet::<2>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.insert(anon(30, 40, true)).unwrap();
        assert_eq!(s.remove_range(12 * P, 14 * P), Err(RegionError::Full));
        assert_eq!(spans(&s), vec![(10, 20, true), (30, 40, true)], "nothing changed");
        // Trimming an end needs no slot.
        assert_eq!(s.remove_range(10 * P, 12 * P), Ok(2));
        assert_eq!(s.remove_range(38 * P, 50 * P), Ok(2));
    }

    #[test]
    fn protect_splits_then_folds_back() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.protect_range(12 * P, 14 * P, false).unwrap();
        assert_eq!(spans(&s), vec![(10, 12, true), (12, 14, false), (14, 20, true)]);
        assert_eq!(s.find(13 * P).map(|r| r.write), Some(false));
        s.protect_range(0, 100 * P, true).unwrap();
        assert_eq!(spans(&s), vec![(10, 20, true)], "same permission again: one record");
        // Only region pages change; a hole stays a hole.
        s.protect_range(5 * P, 11 * P, false).unwrap();
        assert_eq!(spans(&s), vec![(10, 11, false), (11, 20, true)]);
        assert_eq!(s.reserved_pages(), 10);
    }

    #[test]
    fn protect_refuses_when_its_cuts_do_not_fit() {
        let mut s = RegionSet::<2>::new();
        s.insert(anon(10, 20, true)).unwrap();
        assert_eq!(s.protect_range(12 * P, 14 * P, false), Err(RegionError::Full));
        assert_eq!(spans(&s), vec![(10, 20, true)]);
        s.protect_range(10 * P, 14 * P, false).unwrap();
        assert_eq!(spans(&s), vec![(10, 14, false), (14, 20, true)]);
    }

    #[test]
    fn a_copy_is_the_same_reservation() {
        let mut a = RegionSet::<4>::new();
        a.insert(anon(10, 20, true)).unwrap();
        a.insert(anon(30, 31, false)).unwrap();
        let mut b = RegionSet::<4>::new();
        b.copy_from(&a);
        assert_eq!(spans(&a), spans(&b));
        a.remove_range(10 * P, 20 * P).unwrap();
        assert_eq!(b.reserved_pages(), 11, "independent after the copy");
    }

    #[test]
    fn page_index_follows_the_cut() {
        let mut s = RegionSet::<4>::new();
        s.insert(anon(10, 20, true)).unwrap();
        s.remove_range(10 * P, 13 * P).unwrap();
        let r = *s.find(15 * P).unwrap();
        assert_eq!(r.page_index(15 * P), 5, "object offset survives the trim");
    }
}

// Kconfig `MM_RECLAIM_COMPRESS`: the compressed-page pool and its host rows.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/zpool.rs"]
mod zpool;
// Page generations for the reclaimer (`aging.rs`) and the storm over them.
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/aging.rs"]
mod aging;
#[cfg(test)]
#[path = "aging.rs"]
mod aging_rows;
#[cfg(test)]
#[path = "zpool.rs"]
mod zpool_rows;
// Kconfig `MM_SWAP_BACKEND`: swap after compression (swap.rs over zpool.rs) and
// the swap partition type (the block crate's partition.rs, which names only core).
#[allow(dead_code)]
#[path = "../../../../crates/core/mm/src/swap.rs"]
mod swap;
#[allow(dead_code)]
#[path = "../../../../crates/drivers/block/src/partition.rs"]
mod partition;
#[cfg(test)]
#[path = "swap.rs"]
mod swap_rows;
// Reclaim into the pool: watermarks, storms (budget.rs + zpool.rs).
#[cfg(test)]
mod compress_reclaim;
// A Domain's level of memory pressure (`Rule::MemPressure`): budget.rs rows.
#[cfg(test)]
mod pressure;
// Owner rule F1 in swap (no lock across the device wait) and the system watermark.
#[cfg(test)]
mod swap_f1;
// The swap file (Kconfig `MM_SWAP_BACKEND_FILE`): an area that grows and shrinks, and the run map.
#[cfg(test)]
mod swap_file;
// The page cache's backing seam (storage L11): `page_backing.rs` rows.
#[cfg(test)]
mod page_cache;
// File regions in an address space (storage L11 part B): `mmap_file.rs` rows.
#[cfg(test)]
mod mmap_file;
// Contiguous runs of mapped frames (pgsz): `pgsz.rs` rows.
#[cfg(test)]
mod pgsz;
// The page-marker protocol, generation-checked lookup, reclaim pass (`marker_pte.rs`).
#[cfg(test)]
mod marker_pte;
