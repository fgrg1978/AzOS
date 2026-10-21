// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Pure decision logic for `EXIT_NOTE` bookkeeping (U02-6).
//!
//! No `unsafe`, no global state: `scheduler::note_exit` holds the real
//! `EXIT_NOTE` lock and calls the real `idx_for_tid` as the `is_alive`
//! predicate; everything here is free code the host test runner
//! (`tests/host/sched-wake-tests`) can exercise directly, the way
//! `elf_bounds.rs` / `hart_set.rs` are — this module cannot leave the
//! target on its own (the caller's lock and predicate are the only
//! `unsafe`-adjacent parts, and neither lives here).

/// One exit notice: `(parent_tid, child_tid, exit_code)`. `parent_tid ==
/// 0` marks an empty slot.
pub type ExitNote = (u32, u32, i32);

/// Should a would-be notice for `parent` even be queued?
///
/// `false` when `parent` is `0` (nobody to notify — the original,
/// unchanged rule) or when `parent` is already dead: `PARENT_TID` used to
/// be cleared only when the CHILD exits, never when the PARENT does, so
/// every child of an already-exited parent queued a notice addressed to
/// a TID no `wait`/`waitpid` will ever present again (TIDs are never
/// reused — see `scheduler::NEXT_TID`'s doc). `is_alive` is the caller's
/// `idx_for_tid(tid).is_some()`.
pub fn should_queue(parent: u32, is_alive: impl Fn(u32) -> bool) -> bool {
    parent != 0 && is_alive(parent)
}

/// Where [`insert`] put a notice.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Placed {
    /// An empty slot: one more entry in use.
    Empty,
    /// An orphan's slot: as many entries in use as before.
    Orphan,
    /// Nowhere: the table is full of live parents' notices.
    Full,
}

/// Insert `note` into `table`: into an empty slot (`e.0 == 0`), else into a
/// slot whose own parent has died. [`Placed::Full`] when neither exists: the
/// caller counts the drop, which admission ([`admits`]) makes impossible.
///
/// Wave 12 (EXIT2): a live parent's notice is never evicted. It used to be,
/// FIFO, once the table (then a 32-entry Kconfig choice) filled — a parent's
/// `wait` silently missed a child that had exited. Unreaped notices are kept
/// now, as Linux keeps zombies, until the parent reaps them or exits
/// ([`purge_parent`]); the table has one entry per task slot and the creation
/// of a child is refused while it could overflow. Evicting an orphan stays:
/// nothing can ever ask for its notice (TIDs are never reused), so it costs
/// no `wait` anything.
pub fn insert(table: &mut [ExitNote], note: ExitNote, is_alive: impl Fn(u32) -> bool) -> Placed {
    if let Some(empty) = table.iter_mut().find(|e| e.0 == 0) {
        *empty = note;
        return Placed::Empty;
    }
    if let Some(orphan) = table.iter_mut().find(|e| !is_alive(e.0)) {
        *orphan = note;
        return Placed::Orphan;
    }
    Placed::Full
}

/// Drop every notice addressed to `parent`, which is exiting: its children's
/// zombies are released with it (Linux reparents them to init, which reaps
/// them). Returns how many were dropped.
pub fn purge_parent(table: &mut [ExitNote], parent: u32) -> usize {
    if parent == 0 {
        return 0;
    }
    let mut n = 0;
    for e in table.iter_mut() {
        if e.0 == parent {
            *e = (0, 0, 0);
            n += 1;
        }
    }
    n
}

/// May a task with a parent be created now, with `free_slots` task slots
/// free and `notices` exit notices queued? Only while every queued notice
/// still has a slot it could have kept, plus one for the new task — the
/// zombie's slot in Linux terms. Then (tasks that may still queue a notice)
/// + (notices queued) never exceeds the task table, so a table of that many
/// notices never fills: a creation is refused instead (`fork`/`spawn` fail,
/// as Linux's `fork` does when unreaped zombies hold the PID space).
pub fn admits(free_slots: usize, notices: usize) -> bool {
    free_slots > notices
}

/// Move every notice addressed to `from`, which is exiting, to `to`, its
/// children's new parent (wave 13, orphan re-parenting): the zombies go with
/// the children, as Linux hands them to the reaper. Returns how many moved;
/// the count of entries in use does not change. `to == 0` moves nothing (the
/// caller purges instead).
pub fn readdress(table: &mut [ExitNote], from: u32, to: u32) -> usize {
    if from == 0 || to == 0 || from == to {
        return 0;
    }
    let mut n = 0;
    for e in table.iter_mut() {
        if e.0 == from {
            e.0 = to;
            n += 1;
        }
    }
    n
}

/// One task as [`reaper_for`] sees it: its parent, whether it is marked a
/// child subreaper, and whether it may take children now (live and not
/// exiting).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ancestor {
    pub parent: u32,
    pub subreaper: bool,
    pub can_adopt: bool,
}

/// Who adopts the children of `dying`, whose parent is `parent` (wave 13,
/// Linux's rule): the nearest ancestor marked a child subreaper that can
/// adopt, within `max` steps; else `init` when it can adopt and is not
/// `dying` itself; else 0, nobody. `look(tid)` is `None` for a TID with no
/// live slot; an ancestor that is exiting is walked past, not stopped at.
pub fn reaper_for(
    dying: u32,
    parent: u32,
    init: u32,
    look: impl Fn(u32) -> Option<Ancestor>,
    max: usize,
) -> u32 {
    let mut p = parent;
    for _ in 0..max {
        if p == 0 || p == dying {
            break;
        }
        let Some(a) = look(p) else { break };
        if a.subreaper && a.can_adopt {
            return p;
        }
        p = a.parent;
    }
    if init != 0 && init != dying && look(init).is_some_and(|a| a.can_adopt) {
        init
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anc(parent: u32, subreaper: bool, can_adopt: bool) -> Option<Ancestor> {
        Some(Ancestor { parent, subreaper, can_adopt })
    }

    // 1 init <- 2 <- 3 (subreaper) <- 4 <- 5 dying; 6 exiting subreaper.
    fn tree(tid: u32) -> Option<Ancestor> {
        match tid {
            1 => anc(0, false, true),
            2 => anc(1, false, true),
            3 => anc(2, true, true),
            4 => anc(3, false, true),
            5 => anc(4, false, true),
            6 => anc(1, true, false),
            7 => anc(6, false, true),
            _ => None,
        }
    }

    #[test]
    fn reaper_is_the_nearest_subreaper_ancestor() {
        assert_eq!(reaper_for(5, 4, 1, tree, 8), 3);
        assert_eq!(reaper_for(4, 3, 1, tree, 8), 3);
    }

    #[test]
    fn reaper_falls_back_to_init_without_a_subreaper() {
        assert_eq!(reaper_for(3, 2, 1, tree, 8), 1);
        assert_eq!(reaper_for(2, 1, 1, tree, 8), 1);
    }

    #[test]
    fn an_exiting_subreaper_is_walked_past() {
        assert_eq!(reaper_for(7, 6, 1, tree, 8), 1);
    }

    #[test]
    fn init_never_adopts_its_own_children_and_no_init_means_nobody() {
        assert_eq!(reaper_for(1, 0, 1, tree, 8), 0);
        assert_eq!(reaper_for(2, 1, 0, tree, 8), 0);
        // A dead or exiting init adopts nothing.
        assert_eq!(reaper_for(2, 1, 99, tree, 8), 0);
        assert_eq!(reaper_for(2, 1, 6, tree, 8), 0);
    }

    #[test]
    fn the_walk_is_bounded() {
        assert_eq!(reaper_for(5, 4, 1, tree, 1), 1);
    }

    #[test]
    fn readdress_moves_only_the_dying_parents_notices() {
        let mut t: [ExitNote; 4] = [(5, 50, 1), (6, 60, 2), (5, 51, 3), (0, 0, 0)];
        assert_eq!(readdress(&mut t, 5, 3), 2);
        assert_eq!(t, [(3, 50, 1), (6, 60, 2), (3, 51, 3), (0, 0, 0)]);
        assert_eq!(readdress(&mut t, 6, 0), 0);
        assert_eq!(t[1], (6, 60, 2));
    }

    fn alive_set(set: &'static [u32]) -> impl Fn(u32) -> bool {
        move |tid| set.contains(&tid)
    }

    #[test]
    fn should_queue_rejects_no_parent() {
        assert!(!should_queue(0, alive_set(&[1, 2, 3])));
    }

    #[test]
    fn should_queue_rejects_dead_parent() {
        assert!(!should_queue(99, alive_set(&[1, 2, 3])));
    }

    #[test]
    fn should_queue_accepts_live_parent() {
        assert!(should_queue(2, alive_set(&[1, 2, 3])));
    }

    #[test]
    fn insert_fills_empty_slot_first() {
        let mut t: [ExitNote; 4] = [(0, 0, 0); 4];
        t[1] = (5, 50, 0);
        assert_eq!(insert(&mut t, (7, 70, 1), alive_set(&[5, 7])), Placed::Empty);
        assert_eq!(t[0], (7, 70, 1));
        assert_eq!(t[1], (5, 50, 0));
    }

    #[test]
    fn insert_evicts_an_orphan_before_a_live_notice() {
        // U02-6: one live parent's notice and three orphans; a new live
        // notice takes an orphan's slot, never the live one.
        let mut t: [ExitNote; 4] = [(1, 10, 0), (99, 20, 0), (98, 30, 0), (97, 40, 0)];
        let alive = alive_set(&[1, 2]);
        assert_eq!(insert(&mut t, (2, 21, 2), &alive), Placed::Orphan);
        assert!(t.contains(&(1, 10, 0)), "the live parent's notice must stay: {t:?}");
        assert!(t.contains(&(2, 21, 2)), "the new notice must be queued: {t:?}");
        let orphans_left = t.iter().filter(|e| [99, 98, 97].contains(&e.0)).count();
        assert_eq!(orphans_left, 2, "exactly one orphan evicted: {t:?}");
    }

    /// Wave 12: a table full of live parents' notices refuses the insert and
    /// keeps every notice — it used to evict the oldest (FIFO).
    ///
    /// **Canary.** Restore the FIFO fallback: `insert` places the notice and
    /// `(1, 10, 0)` is gone.
    #[test]
    fn a_full_table_of_live_notices_refuses_and_keeps_them_all() {
        let mut t: [ExitNote; 3] = [(1, 10, 0), (2, 20, 0), (3, 30, 0)];
        let alive = alive_set(&[1, 2, 3, 4]);
        assert_eq!(insert(&mut t, (4, 40, 0), &alive), Placed::Full);
        assert_eq!(t, [(1, 10, 0), (2, 20, 0), (3, 30, 0)]);
    }

    #[test]
    fn a_burst_of_orphans_never_displaces_the_one_live_notice() {
        let mut t: [ExitNote; 4] = [(0, 0, 0); 4];
        let alive = alive_set(&[1]);
        assert_eq!(insert(&mut t, (1, 10, 0), &alive), Placed::Empty);
        for dead_parent in 100..120u32 {
            assert_ne!(insert(&mut t, (dead_parent, dead_parent + 1000, 0), &alive), Placed::Full);
        }
        assert!(t.contains(&(1, 10, 0)), "20 orphan insertions evicted the live notice: {t:?}");
    }

    #[test]
    fn purge_parent_drops_exactly_that_parents_notices() {
        let mut t: [ExitNote; 5] = [(1, 10, 0), (2, 20, 0), (1, 11, 3), (0, 0, 0), (3, 30, 0)];
        assert_eq!(purge_parent(&mut t, 1), 2);
        assert_eq!(t, [(0, 0, 0), (2, 20, 0), (0, 0, 0), (0, 0, 0), (3, 30, 0)]);
        assert_eq!(purge_parent(&mut t, 0), 0, "0 is the empty marker, never a parent");
        assert_eq!(purge_parent(&mut t, 9), 0);
    }

    /// **The bound, as a model of the machine.** `SLOTS` task slots, one
    /// parent that forks, lets children exit and reaps in a pseudo-random
    /// interleaving (fixed seed), with a creation admitted only by
    /// [`admits`]: across 20,000 steps no notice is ever dropped, and every
    /// child that exited is reaped exactly once.
    ///
    /// **Canary.** Make `admits` answer `true`: children keep being created
    /// while notices pile up, `insert` refuses, and the drop assertion fires.
    #[test]
    fn admission_keeps_a_task_table_sized_notice_table_from_ever_dropping() {
        const SLOTS: usize = 8;
        const PARENT: u32 = 1;
        let mut table = [(0u32, 0u32, 0i32); SLOTS];
        let mut live: Vec<u32> = Vec::new(); // children holding a slot
        let mut next_tid = 2u32;
        let (mut exited, mut reaped, mut refused) = (0u32, 0u32, 0u32);
        let mut rng = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..20_000 {
            rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
            let notices = table.iter().filter(|e| e.0 != 0).count();
            // One slot is the parent's own.
            let free = SLOTS - 1 - live.len();
            match rng % 3 {
                0 => {
                    if free > 0 && admits(free, notices) {
                        live.push(next_tid);
                        next_tid += 1;
                    } else {
                        refused += 1;
                    }
                }
                1 => {
                    if let Some(child) = live.pop() {
                        exited += 1;
                        assert_ne!(insert(&mut table, (PARENT, child, 0), |t| t == PARENT),
                                   Placed::Full, "a notice was dropped: {table:?}");
                    }
                }
                _ => {
                    if let Some(e) = table.iter_mut().find(|e| e.0 == PARENT) {
                        *e = (0, 0, 0);
                        reaped += 1;
                    }
                }
            }
        }
        let left = table.iter().filter(|e| e.0 == PARENT).count() as u32;
        assert_eq!(reaped + left, exited, "every exit is reaped or still queued");
        assert!(refused > 0 && exited > 1000, "the model must exercise both edges");
    }
}
