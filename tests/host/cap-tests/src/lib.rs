// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for `crates/core/ipc/src/cap.rs` and the general (non-delegation)
//! behaviour of `crates/core/ipc/src/cap_store.rs`.
//!
//! The kernel `azos_ipc` crate cannot be compiled for the host
//! (it depends on RV64-only crates). But `cap.rs` itself only depends
//! on `azos_abi`, which is host-friendly. We pull `cap.rs` in
//! directly via `#[path]` and let the embedded `#[cfg(test)] mod tests`
//! run on the host.
//!
//! `cap_store.rs` needs two more crates — `azos_sync` (RV64 CSR asm in
//! `SpinLock`) and `azos_sched` (the whole scheduler) — so those are
//! replaced by the host shims under `shims/` via a Cargo dependency rename.
//! The kernel build never sees them.
//!
//! **History.** This crate used to host 22 tests for `cap_store::delegate`,
//! the kernel side of `SYS_CAP_GRANT` (cross-task capability delegation from
//! ring 3). `SYS_CAP_GRANT` was removed 2026-09-03: RFC-0003 is
//! constitutional and says capabilities are granted at boot, not allocated
//! dynamically, and the syscall contradicted that (it also shipped without
//! the RFC's own gate — a `CapMaster<T>` the issuer must hold — which was
//! never implemented). `delegate`, its error type, its inbound-delegation
//! quota, and the 21 tests that exercised `cap_store::delegate` directly were
//! removed with it.
//!
//! One test survives: `cap_store_tests::a_reused_slot_wipes_the_previous_owners_table`
//! does not call `delegate` at all — it exercises `claim_slot`'s
//! owner-mismatch wipe through the general `grant`/`get`/`occupied` surface,
//! which is unrelated to delegation and stays. It needs the same
//! `shim_kill`/`shim_bind` control surface the delegation tests needed (make
//! a TID live or dead at a chosen slot), which `tests/host/ipc-lease-tests`'
//! scheduler shim does not provide (fixed identity TID→slot map, no way to
//! make a TID dead) — so this crate, not that one, is where it belongs.

#[path = "../../../../crates/core/ipc/src/cap.rs"]
pub mod cap;

#[path = "../../../../crates/core/ipc/src/cap_store.rs"]
pub mod cap_store;

// ──────────────────────────────────────────────────────────────────────────
// cap_store — general (non-delegation) behaviour
// ──────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod cap_store_tests {
    use crate::cap::targets::Channel;
    use crate::cap::{Cap, CapError, CapPerms};
    use crate::cap_store;
    use azos_sched::{shim_bind, shim_kill};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// `cap_store`'s tables, its `OWNER` array and the scheduler shim are all
    /// process-global, and `cargo test` runs test functions in parallel. Every
    /// test in this module takes this lock for its whole body.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Hands out task identities that no other test has used. Slots are never
    /// recycled between tests, so one test can never observe another's
    /// `OWNER` registration or leftover cap slots.
    static NEXT_ID: AtomicU32 = AtomicU32::new(1);

    struct Task {
        tid: u32,
        slot: usize,
    }

    fn fresh_task() -> Task {
        let n = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let slot = n as usize;
        assert!(
            slot < azos_sched::task::MAX_TASKS,
            "this module has outgrown the task pool ({} slots): give tests \
             back their slots or raise MAX_TASKS",
            azos_sched::task::MAX_TASKS
        );
        // TID 0 is the "no current task" sentinel; the allocator starts at 1.
        let tid = n;
        shim_bind(tid, slot);
        Task { tid, slot }
    }

    /// Take the module lock. Deliberately recovers from poisoning: one failing
    /// test should not cascade into the rest.
    fn guard() -> MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ── RFC-0040 gap 2 stage 4: `cap_store::move_cap` ──────────────────
    //
    // Owner decision 38: a MOVE, never a creation. Every test below pins one
    // half of that sentence, because "it worked" for a transfer is also what a
    // silent duplication looks like from the receiver's side.

    #[test]
    fn a_move_installs_in_the_receiver_and_leaves_the_sender_holding_nothing() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 7).unwrap();
        assert_eq!(cap_store::occupied(a.tid), 1);

        let moved = cap_store::move_cap(a.tid, b.tid, src.raw(), Some(CapPerms::RW))
            .expect("the move is allowed");

        // The half that proves it is a move and not a copy: the sender's
        // count goes to zero, and its handle stops resolving.
        assert_eq!(cap_store::occupied(a.tid), 0, "the sender still holds it — this is a COPY");
        assert_eq!(cap_store::occupied(b.tid), 1);
        assert_eq!(
            cap_store::get(a.tid, src, CapPerms::READ),
            Err(CapError::Stale),
            "the sender's old handle still resolves after the move",
        );
        // And the receiver holds the same object, under its own fresh handle.
        let recv: Cap<Channel> = Cap::from_raw(moved);
        assert_eq!(cap_store::get(b.tid, recv, CapPerms::RW), Ok(7));
    }

    #[test]
    fn a_move_may_lower_rights_but_never_raise_them() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Channel> = cap_store::grant(a.tid, CapPerms::READ.union(CapPerms::DUP), 3).unwrap();

        // Raising is refused, and refused BEFORE anything moves. `DUP` is
        // held here so this specifically exercises the RIGHTS check, not the
        // `DUP` gate a missing bit would also trigger.
        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), Some(CapPerms::RW)),
            Err(CapError::MissingPerms),
        );
        assert_eq!(cap_store::occupied(a.tid), 1, "a refused move still took the capability");
        assert_eq!(cap_store::occupied(b.tid), 0, "a refused move still installed one");

        // Lowering to the same rights is allowed, and the receiver gets
        // exactly what was asked for, not what the sender held.
        let c = fresh_task();
        let src2: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 4).unwrap();
        let moved = cap_store::move_cap(a.tid, c.tid, src2.raw(), Some(CapPerms::READ)).unwrap();
        let recv: Cap<Channel> = Cap::from_raw(moved);
        assert_eq!(cap_store::get(c.tid, recv, CapPerms::READ), Ok(4));
        assert_eq!(
            cap_store::get(c.tid, recv, CapPerms::WRITE),
            Err(CapError::MissingPerms),
            "WRITE survived a move that asked for READ",
        );
    }

    #[test]
    fn a_move_with_no_rights_argument_keeps_exactly_what_the_sender_held() {
        let _g = guard();
        // `None` is the shape the SYSCALL path uses: it has not read the
        // sender's slot and cannot name its permissions. Untested, the
        // difference between "keeps them" and "grants RW to everything"
        // is invisible — both make a passing exchange.
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Channel> =
            cap_store::grant(a.tid, CapPerms::READ.union(CapPerms::DUP), 21).unwrap();

        let moved = cap_store::move_cap(a.tid, b.tid, src.raw(), None).unwrap();
        let recv: Cap<Channel> = Cap::from_raw(moved);
        assert_eq!(cap_store::get(b.tid, recv, CapPerms::READ), Ok(21));
        assert_eq!(
            cap_store::get(b.tid, recv, CapPerms::WRITE),
            Err(CapError::MissingPerms),
            "a kept move handed over WRITE the sender never had",
        );
    }

    #[test]
    fn a_move_to_the_same_task_does_not_deadlock_and_still_validates() {
        let _g = guard();
        // THE one that hangs a hart if the branch is missing: both TIDs
        // resolve to one slot, and "lock both tables" takes one
        // non-reentrant spinlock twice. A test that merely returns proves
        // the branch exists — if it regresses, this test never finishes,
        // which is exactly how the board would fail.
        let a = fresh_task();
        let src: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW, 9).unwrap();

        let same = cap_store::move_cap(a.tid, a.tid, src.raw(), Some(CapPerms::RW)).unwrap();
        assert_eq!(same, src.raw(), "a self-move churned the handle");
        assert_eq!(cap_store::occupied(a.tid), 1, "a self-move lost the capability");

        // It is a no-op, but not an unchecked one: a stale handle and a
        // rights escalation are refused on this path too, or the self-move
        // would be the one hole in both rules.
        cap_store::revoke(a.tid, src);
        assert_eq!(
            cap_store::move_cap(a.tid, a.tid, src.raw(), Some(CapPerms::RW)),
            Err(CapError::Stale),
        );
        let src2: Cap<Channel> = cap_store::grant(a.tid, CapPerms::READ, 10).unwrap();
        assert_eq!(
            cap_store::move_cap(a.tid, a.tid, src2.raw(), Some(CapPerms::RW)),
            Err(CapError::MissingPerms),
        );
    }

    #[test]
    fn a_move_with_a_stale_handle_is_refused_and_moves_nothing() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW, 5).unwrap();
        cap_store::revoke(a.tid, src);

        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), Some(CapPerms::RW)),
            Err(CapError::Stale),
        );
        assert_eq!(cap_store::occupied(b.tid), 0, "a stale handle installed something");
    }

    #[test]
    fn a_move_into_a_full_table_refuses_and_the_sender_keeps_it() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 11).unwrap();

        // Fill the receiver.
        let mut filled = 0;
        while cap_store::grant::<Channel>(b.tid, CapPerms::READ, 1).is_some() {
            filled += 1;
            assert!(filled <= crate::cap::MAX_CAPS_PER_TASK, "the table never filled");
        }

        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), Some(CapPerms::RW)),
            Err(CapError::NoSpace),
        );
        // The half decision 38 demands: no half-moved state. The sender still
        // holds it, and its handle still resolves.
        assert_eq!(cap_store::get(a.tid, src, CapPerms::RW), Ok(11),
                   "the sender lost the capability to a move that failed");
    }

    /// Owner decision 2026-09-26 (O3.4): `DUP` gates transfer to a DIFFERENT
    /// task. A capability minted without it — the default for every minter in
    /// the tree today; `grep -rn 'CapPerms::DUP' crates/core/ipc/src` outside this
    /// file and `cap_store.rs` itself finds no grant — cannot be moved at
    /// all, refused before either table is touched, whatever `rights` asks
    /// for. A self-move (`a_move_to_the_same_task_does_not_deadlock_and_still_validates`)
    /// is exempt: it is not a transfer to anyone new.
    ///
    /// **Canary.** Drop the `DUP` check from `move_cap`: this test's `Err`
    /// assertions read `Ok(_)`.
    #[test]
    fn a_capability_without_dup_cannot_be_moved_to_another_task() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW, 13).unwrap();

        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), None),
            Err(CapError::MissingPerms),
            "no DUP, keep rights"
        );
        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), Some(CapPerms::READ)),
            Err(CapError::MissingPerms),
            "no DUP, even asking for fewer rights"
        );
        assert_eq!(cap_store::occupied(a.tid), 1, "the refused move still took the capability");
        assert_eq!(cap_store::occupied(b.tid), 0, "the refused move still installed one");
        assert_eq!(cap_store::get(a.tid, src, CapPerms::RW), Ok(13), "the sender's capability survives");

        // Granting DUP is what makes the very same capability transferable.
        let src2: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 14).unwrap();
        assert!(cap_store::move_cap(a.tid, b.tid, src2.raw(), None).is_ok(), "DUP held: the move succeeds");
    }

    // ── Wave 15 N11: 128-bit slot, badge, all-or-nothing transfer ──────────

    use crate::cap::targets::Endpoint;
    use crate::cap::CapExt;
    use crate::cap_store::CapXfer;
    use azos_abi::cap::CapHandle;

    fn badge_of(tid: u32, h: CapHandle) -> Option<u32> {
        cap_store::with_table(tid, |t| t.ext_of(h).map(|e| e.badge)).flatten()
    }

    #[test]
    fn a_badged_endpoint_cap_keeps_its_badge_across_a_move() {
        let _g = guard();
        let srv = fresh_task();
        let cli = fresh_task();
        let ep: Cap<Endpoint> = cap_store::grant(srv.tid, CapPerms::RW_DUP, 3).unwrap();
        assert_eq!(badge_of(srv.tid, ep.raw()), Some(0), "a granted capability is unbadged");
        let b = cap_store::with_table(srv.tid, |t| t.mint_badged(ep.raw(), 0xC11E, CapPerms::RW_DUP)).unwrap().unwrap();
        assert_eq!(badge_of(srv.tid, b), Some(0xC11E));
        let ext = cap_store::with_table(srv.tid, |t| t.ext_of(b)).flatten().unwrap();
        assert_eq!(ext.parent, ep.raw().slot() as u16 + 1, "the copy links to its parent slot");
        // A badge is set once; a badge of 0 is no badge; rights never grow.
        let again = cap_store::with_table(srv.tid, |t| t.mint_badged(b, 9, CapPerms::RW_DUP)).unwrap();
        assert_eq!(again, Err(CapError::MissingPerms));
        let zero = cap_store::with_table(srv.tid, |t| t.mint_badged(ep.raw(), 0, CapPerms::RW_DUP)).unwrap();
        assert_eq!(zero, Err(CapError::MissingPerms));
        let ch: Cap<Channel> = cap_store::grant(srv.tid, CapPerms::RW_DUP, 1).unwrap();
        let wrong = cap_store::with_table(srv.tid, |t| t.mint_badged(ch.raw(), 5, CapPerms::RW_DUP)).unwrap();
        assert_eq!(wrong, Err(CapError::WrongKind));
        let moved = cap_store::move_cap(srv.tid, cli.tid, b, None).unwrap();
        assert_eq!(badge_of(cli.tid, moved), Some(0xC11E), "the badge is the client's identity");
        let ext = cap_store::with_table(cli.tid, |t| t.ext_of(moved)).flatten().unwrap();
        assert_eq!(ext, CapExt { badge: 0xC11E, ..CapExt::NONE }, "the parent link stays home");
        assert_eq!(badge_of(srv.tid, b), None, "stale in the sender");
    }

    #[test]
    fn a_message_transfer_lands_every_capability_or_none() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let c0: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 10).unwrap();
        let c1: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 11).unwrap();
        let c2: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 12).unwrap();
        let mv = |h: CapHandle| CapXfer { handle: h, dup: false, rights: None };
        let mut out = [CapHandle(0); 4];
        // One bad entry (no DUP right on it) refuses the whole message; with
        // KEEP the sender still holds every capability, the receiver none.
        let nodup: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW, 13).unwrap();
        let xs = [mv(c0.raw()), mv(c1.raw()), mv(nodup.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, true, &mut out), Err(CapError::MissingPerms));
        assert_eq!((cap_store::occupied(a.tid), cap_store::occupied(b.tid)), (4, 0));
        // The same slot twice is refused.
        let xs = [mv(c0.raw()), mv(c0.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, true, &mut out), Err(CapError::MissingPerms));
        // All good: every one lands, rights attenuated where asked, DUP keeps.
        let xs = [mv(c0.raw()), CapXfer { handle: c1.raw(), dup: true, rights: Some(CapPerms::READ) }, mv(c2.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, false, &mut out), Ok(3));
        assert_eq!(cap_store::occupied(b.tid), 3);
        assert_eq!(cap_store::get(a.tid, c0, CapPerms::READ), Err(CapError::Stale), "moved");
        assert_eq!(cap_store::get(a.tid, c1, CapPerms::READ), Ok(11), "duplicated: still held");
        let r1: Cap<Channel> = Cap::from_raw(out[1]);
        assert_eq!(cap_store::get(b.tid, r1, CapPerms::WRITE), Err(CapError::MissingPerms), "attenuated");
        assert_eq!(cap_store::get(b.tid, r1, CapPerms::READ), Ok(11));
        // Without KEEP a refused message consumes the sender's MOVE entries.
        let xs = [mv(c1.raw()), mv(nodup.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, false, &mut out), Err(CapError::MissingPerms));
        assert_eq!(cap_store::get(a.tid, c1, CapPerms::READ), Err(CapError::Stale), "consumed");
        assert_eq!(cap_store::occupied(b.tid), 3, "and nothing landed");
    }

    #[test]
    fn a_message_needs_room_for_every_capability_before_any_moves() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let c0: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 20).unwrap();
        let c1: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 21).unwrap();
        // Fill the receiver to one free slot.
        let free = cap_store::with_table(b.tid, |t| t.free_slots()).unwrap();
        for i in 0..free - 1 {
            let _: Cap<Channel> = cap_store::grant(b.tid, CapPerms::RW, 1000 + i as u32).unwrap();
        }
        let xs = [CapXfer { handle: c0.raw(), dup: false, rights: None }, CapXfer { handle: c1.raw(), dup: false, rights: None }];
        let mut out = [CapHandle(0); 2];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, true, &mut out), Err(CapError::NoSpace));
        assert_eq!(cap_store::get(a.tid, c0, CapPerms::READ), Ok(20), "N-1 free: nothing moved");
        assert_eq!(cap_store::get(a.tid, c1, CapPerms::READ), Ok(21));
    }

    #[test]
    fn a_reused_slot_wipes_the_previous_owners_table() {
        let _g = guard();
        // The `OWNER` backstop, stated as behaviour rather than as a comment.
        // It converts "task B inherits task A's caps" into "task A's caps are
        // destroyed" — fail-closed, and the reason a wrong-slot resolution in
        // this module is a denial-of-service and not capability theft.
        let a = fresh_task();
        let slot = a.slot;
        let src: Cap<Channel> = cap_store::grant(a.tid, CapPerms::RW_DUP, 1).unwrap();
        assert_eq!(cap_store::occupied(a.tid), 1);

        // A dies; a new task draws the same pool slot.
        shim_kill(a.tid);
        let heir_tid = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        shim_bind(heir_tid, slot);

        // The heir sees an empty table, not A's cap.
        assert_eq!(cap_store::occupied(heir_tid), 0);
        assert_eq!(
            cap_store::get(heir_tid, src, CapPerms::READ),
            Err(CapError::Stale)
        );

        // And the flip side, which is the finding worth naming: an operation
        // attributed to the DEAD TID on that slot wipes the live heir's
        // table. Nothing is stolen; something is destroyed.
        let heir_cap: Cap<Channel> =
            cap_store::grant(heir_tid, CapPerms::RW, 2).unwrap();
        assert_eq!(cap_store::get(heir_tid, heir_cap, CapPerms::READ), Ok(2));
        shim_bind(a.tid, slot); // the stale scan matching A again
        assert_eq!(cap_store::occupied(a.tid), 0);
        assert_eq!(
            cap_store::get(heir_tid, heir_cap, CapPerms::READ),
            Err(CapError::Stale),
            "OWNER's wipe-on-mismatch is itself the damage: a live task's \
             capability table is emptied by an operation naming a dead TID"
        );
        shim_kill(a.tid);
    }

    // ── RFC-0040 gap 3: the fork-time bootstrap grant survives slot reuse ──
    //
    // `endpoint::endpoint_inherit_at_fork` (`crates/core/ipc/src/endpoint.rs`)
    // mints a child's capability with `objref::grant_packed`, which is
    // `cap_store::grant` plus an epoch check — the slot-reuse guarantee
    // below is `cap_store`'s, inherited rather than re-implemented, so this
    // test exercises it directly through `grant`/`get` with a real
    // `Cap<Endpoint>` rather than duplicating `tests/host/ipc-lease-tests`'
    // `endpoint.rs` mount (whose identity-mapped `idx_for_tid` shim cannot
    // represent one pool slot outliving the TID that first occupied it —
    // this crate's `shim_bind`/`shim_kill` control surface exists for
    // exactly that, see this module's own history note above).
    //
    // Deliberately does NOT call `cap_store::reset` on the dying child
    // before killing it — same choice
    // `a_reused_slot_wipes_the_previous_owners_table` makes, and for the
    // same reason: `task_release_all`'s exit hook calling `cap_store::reset`
    // is the normal path, but the `OWNER` array's lazy wipe-on-claim is the
    // documented BACKSTOP for when it does not run. A test that resets first
    // would prove the normal path works and say nothing about the backstop
    // RFC-0040 gap 3 leans on to keep a re-let slot from inheriting a dead
    // predecessor's fork grant.
    #[test]
    fn a_re_let_slot_does_not_inherit_a_dead_predecessors_fork_grant() {
        let _g = guard();
        use crate::cap::targets::Endpoint;

        let child = fresh_task();
        let slot = child.slot;
        let inherited: Cap<Endpoint> =
            cap_store::grant(child.tid, CapPerms::WRITE, 0x4242).expect("fresh table has room");
        assert_eq!(cap_store::occupied(child.tid), 1);

        // The child dies with no explicit cleanup, and a new task draws its
        // pool slot — `try_task_create_affinity` reuses the lowest free
        // index, so this is the common case, not a rare one.
        shim_kill(child.tid);
        let heir_tid = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        shim_bind(heir_tid, slot);

        assert_eq!(
            cap_store::occupied(heir_tid), 0,
            "the heir inherited a dead predecessor's fork-granted capability",
        );
        assert_eq!(
            cap_store::get(heir_tid, inherited, CapPerms::WRITE),
            Err(CapError::Stale),
            "the dead child's fork-inherited handle still resolves on the heir's slot",
        );
        shim_kill(heir_tid);
    }
}

/// `azos_limits::nospec` — the Spectre v1 mask `cap.rs` indexes the slot
/// table with. On an aarch64 host (this project's) these run the kernel's own
/// `cmp`/`sbc`/`csdb` sequence; on another host, the portable branch. The
/// riscv64 sequence is checked in the kernel's disassembly (`dispatch_slow`).
/// What these pin is the contract every call site relies on: the masked index
/// is the index when it is in bounds, 0 past it, and `get` answers exactly what
/// `slice::get` answers.
///
/// Canary (run by hand, 2026-10-02, aarch64 host): `sbc {m}, xzr, xzr`
/// replaced by `mov {m}, #-1` fails `the_mask_is_zero_out_of_bounds`; the
/// other three still pass.
#[cfg(test)]
mod nospec_tests {
    use azos_limits::nospec::{array_index_nospec, get, mask, ENABLED};

    #[test]
    fn the_mask_is_all_ones_in_bounds() {
        for size in [1usize, 2, 7, 64, 256, 611] {
            for index in 0..size {
                assert_eq!(mask(index, size), usize::MAX, "{index} < {size}");
                assert_eq!(array_index_nospec(index, size), index);
            }
        }
    }

    #[test]
    fn the_mask_is_zero_out_of_bounds() {
        for size in [1usize, 2, 7, 64, 256, 611] {
            for index in [size, size + 1, 511, usize::MAX / 2, usize::MAX] {
                if index < size { continue; }
                assert_eq!(mask(index, size), 0, "{index} >= {size}");
                if ENABLED {
                    assert_eq!(array_index_nospec(index, size), 0, "{index} >= {size}");
                }
            }
        }
    }

    #[test]
    fn get_answers_what_slice_get_answers() {
        let t = [10u32, 11, 12];
        for i in (0..8).chain([usize::MAX / 2, usize::MAX]) {
            assert_eq!(get(&t, i), t.get(i), "{i}");
        }
    }

    #[test]
    fn a_slot_index_past_the_table_is_stale() {
        use crate::cap::{targets::Gpio, Cap, CapError, CapTable, MAX_CAPS_PER_TASK};
        use azos_abi::cap::{CapHandle, CapKind, CapPerms};
        let t = CapTable::empty();
        let h = t.grant_raw(CapKind::Gpio, CapPerms::READ, 7).unwrap();
        // The same handle with its slot moved past the table (the 9-bit
        // field reaches 511; the table holds `MAX_CAPS_PER_TASK`).
        let past = CapHandle::pack(CapKind::Gpio, CapPerms::READ, h.generation(),
                                   (MAX_CAPS_PER_TASK as u16).min(511));
        if (past.slot() as usize) < MAX_CAPS_PER_TASK { return; } // a 512-slot table
        let cap: Cap<Gpio> = Cap::from_raw(past);
        assert_eq!(t.get(cap, CapPerms::READ), Err(CapError::Stale));
        assert!(t.peek_raw(past).is_none());
        assert!(!t.revoke_raw(past));
        assert_eq!(t.get(Cap::<Gpio>::from_raw(h), CapPerms::READ), Ok(7));
    }
}
