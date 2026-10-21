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
//! ring 3). `SYS_CAP_GRANT` was removed 2026-09-03: the capability model
//! says capabilities are granted at boot, not allocated
//! dynamically, and the syscall contradicted that (it also shipped without
//! the gate it was specified with — a `CapMaster<T>` the issuer must hold — which was
//! never implemented). `delegate`, its error type, its inbound-delegation
//! quota, and the 21 tests that exercised `cap_store::delegate` directly were
//! removed with it.
//!
//! One test survives: `cap_store_tests::a_reused_slot_wipes_the_previous_owners_table`
//! does not call `delegate` at all — it exercises `claim_slot`'s
//! owner-mismatch wipe through the general `grant`/`get`/`occupied` surface,
//! which is unrelated to delegation and stays. It needs the same
//! `shim_kill`/`shim_bind` control surface the delegation tests needed (make
//! a TID live or dead at a chosen slot), which `tests/host/ipc-tests`'
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
    use crate::cap::targets::Port;
    use crate::cap::{Cap, CapError, CapPerms};
    use crate::cap_store;
    use azos_sched::{shim_bind, shim_kill};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Mutex, MutexGuard};

    /// `cap_store`'s tables, its `OWNER` array and the scheduler shim are all
    /// process-global, and `cargo test` runs test functions in parallel. Every
    /// test in this module takes this lock for its whole body.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// The warrant tests below take table slots from here up, with TIDs of
    /// their own, rebinding the same slots test after test (a new TID at a
    /// slot is a new domain: the wipe-on-claim path). The older tests above
    /// keep the slots under it.
    const WARRANT_SLOT0: usize = 44;

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
            slot < WARRANT_SLOT0,
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

    // Macaroon-style caveats (`macaroon.rs`): a child module, so it shares this
    // module's lock, test clock and slot helpers.
    mod macaroon {
        include!("macaroon.rs");
    }

    // Receipt-conditioned warrants and the caveated derive (`b3.rs`), a child
    // module for the same reason.
    mod b3 {
        include!("b3.rs");
    }

    // The provenance label and the one-shot declassify warrant (`b4.rs`).
    mod b4 {
        include!("b4.rs");
    }

    // Rights S3: TRANSFER, DUP and MAP at the table (`rights.rs`).
    mod rights {
        include!("rights.rs");
    }

    // ── capability transfer in fast IPC: `cap_store::move_cap` ──────────────────
    //
    // Owner decision 38: a MOVE, never a creation. Every test below pins one
    // half of that sentence, because "it worked" for a transfer is also what a
    // silent duplication looks like from the receiver's side.

    // ── KMEM-CHARGE: the capability table is kernel memory kept for its Domain ──

    #[test]
    fn a_domain_is_charged_for_its_capability_table_once_when_it_claims_it() {
        use crate::cap_store::{kmem_fake, KMEM_CAP_TABLE};
        let _g = guard();
        kmem_fake::install();
        let a = fresh_task();
        let key = cap_store::domain_key_of(a.tid);
        assert_eq!(kmem_fake::used(key, KMEM_CAP_TABLE), 0, "nothing is charged before the table is used");
        let _c1: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 1).unwrap();
        let _c2: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 2).unwrap();
        assert_eq!(
            kmem_fake::used(key, KMEM_CAP_TABLE),
            kmem_fake::TABLE_BYTES,
            "one table, charged once however many capabilities it holds",
        );
        kmem_fake::forget(key);
    }

    #[test]
    fn a_domain_whose_kernel_memory_limit_cannot_hold_a_table_gets_no_capabilities() {
        use crate::cap_store::{kmem_fake, KMEM_CAP_TABLE};
        let _g = guard();
        kmem_fake::install();
        let a = fresh_task();
        let key = cap_store::domain_key_of(a.tid);
        kmem_fake::set_limit(key, kmem_fake::TABLE_BYTES - 1);
        assert!(cap_store::grant::<Port>(a.tid, CapPerms::RW_DELEGATE, 1).is_none(), "refused at the claim");
        assert_eq!(cap_store::occupied(a.tid), 0);
        assert_eq!(kmem_fake::used(key, KMEM_CAP_TABLE), 0, "a refusal charges nothing");
        kmem_fake::set_limit(key, kmem_fake::TABLE_BYTES);
        assert!(cap_store::grant::<Port>(a.tid, CapPerms::RW_DELEGATE, 1).is_some(), "room for exactly the table");
        assert_eq!(kmem_fake::used(key, KMEM_CAP_TABLE), kmem_fake::TABLE_BYTES);
        kmem_fake::forget(key);
    }

    #[test]
    fn a_move_installs_in_the_receiver_and_leaves_the_sender_holding_nothing() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 7).unwrap();
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
        let recv: Cap<Port> = Cap::from_raw(moved);
        assert_eq!(cap_store::get(b.tid, recv, CapPerms::RW), Ok(7));
    }

    #[test]
    fn a_move_may_lower_rights_but_never_raise_them() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Port> = cap_store::grant(a.tid, CapPerms::READ.union(CapPerms::DELEGATE), 3).unwrap();

        // Raising is refused, and refused BEFORE anything moves. `TRANSFER`
        // is held here so this specifically exercises the RIGHTS check, not
        // the `TRANSFER` gate a missing bit would also trigger.
        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), Some(CapPerms::RW)),
            Err(CapError::MissingPerms),
        );
        assert_eq!(cap_store::occupied(a.tid), 1, "a refused move still took the capability");
        assert_eq!(cap_store::occupied(b.tid), 0, "a refused move still installed one");

        // Lowering to the same rights is allowed, and the receiver gets
        // exactly what was asked for, not what the sender held.
        let c = fresh_task();
        let src2: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 4).unwrap();
        let moved = cap_store::move_cap(a.tid, c.tid, src2.raw(), Some(CapPerms::READ)).unwrap();
        let recv: Cap<Port> = Cap::from_raw(moved);
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
        let src: Cap<Port> =
            cap_store::grant(a.tid, CapPerms::READ.union(CapPerms::DELEGATE), 21).unwrap();

        let moved = cap_store::move_cap(a.tid, b.tid, src.raw(), None).unwrap();
        let recv: Cap<Port> = Cap::from_raw(moved);
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
        let src: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW, 9).unwrap();

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
        let src2: Cap<Port> = cap_store::grant(a.tid, CapPerms::READ, 10).unwrap();
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
        let src: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW, 5).unwrap();
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
        let src: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 11).unwrap();

        // Fill the receiver.
        let mut filled = 0;
        while cap_store::grant::<Port>(b.tid, CapPerms::READ, 1).is_some() {
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

    /// Owner decision 2026-09-26 (O3.4), split 2026-10-17: `TRANSFER` gates the
    /// move to a DIFFERENT task. A capability minted without it — the default
    /// for every minter in the tree today that is not an object's own creator
    /// or a `transfer = true` row — cannot be moved at all, refused before
    /// either table is touched, whatever `rights` asks for. `DUP` is not
    /// `TRANSFER`: a capability that may be copied still may not be given away.
    /// A self-move (`a_move_to_the_same_task_does_not_deadlock_and_still_validates`)
    /// is exempt: it is not a transfer to anyone new.
    ///
    /// **Canary.** Drop the `TRANSFER` check from `move_cap`: this test's `Err`
    /// assertions read `Ok(_)`.
    #[test]
    fn a_capability_without_transfer_cannot_be_moved_to_another_task() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let src: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW, 13).unwrap();

        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), None),
            Err(CapError::MissingPerms),
            "no TRANSFER, keep rights"
        );
        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, src.raw(), Some(CapPerms::READ)),
            Err(CapError::MissingPerms),
            "no TRANSFER, even asking for fewer rights"
        );
        assert_eq!(cap_store::occupied(a.tid), 1, "the refused move still took the capability");
        assert_eq!(cap_store::occupied(b.tid), 0, "the refused move still installed one");
        assert_eq!(cap_store::get(a.tid, src, CapPerms::RW), Ok(13), "the sender's capability survives");

        // DUP alone is the right to copy, not to give away.
        let dup_only: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW.union(CapPerms::DUP), 16).unwrap();
        assert_eq!(
            cap_store::move_cap(a.tid, b.tid, dup_only.raw(), None),
            Err(CapError::MissingPerms),
            "DUP without TRANSFER"
        );

        // TRANSFER alone is enough for a MOVE: a move copies nothing.
        let xfer_only: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW.union(CapPerms::TRANSFER), 17).unwrap();
        assert!(cap_store::move_cap(a.tid, b.tid, xfer_only.raw(), None).is_ok(), "TRANSFER held: the move succeeds");

        // Granting TRANSFER (with DUP) is what makes the very same capability transferable.
        let src2: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 14).unwrap();
        assert!(cap_store::move_cap(a.tid, b.tid, src2.raw(), None).is_ok(), "TRANSFER held: the move succeeds");
    }

    // ── Wave 15 N11: 128-bit slot, badge, all-or-nothing transfer ──────────

    use crate::cap::targets::Endpoint;
    use crate::cap::CapExt;
    use crate::cap_store::CapXfer;
    use azos_abi::cap::CapHandle;

    fn badge_of(tid: u32, h: CapHandle) -> Option<u32> {
        cap_store::with_table(tid, |t| t.ext_of(h).map(|e| e.badge)).flatten()
    }

    // REQ-002
    /// `revoke_derived` revokes every copy derived from a capability (here and
    /// in the task it was moved to) and keeps the capability: the replacement
    /// handle works, the old one and the copies are stale.
    ///
    /// **Canary.** Make `revoke_derived` return the old handle without clearing
    /// the slot: the copies stay live and the stale check is red.
    #[test]
    fn revoking_a_capability_revokes_what_was_derived_from_it_and_keeps_it() {
        let _g = guard();
        if !crate::cap::SLOT_EXT {
            return;
        }
        let srv = fresh_task();
        let cli = fresh_task();
        let ep: Cap<Endpoint> = cap_store::grant(srv.tid, CapPerms::RW_DELEGATE, 3).unwrap();
        let kept = cap_store::mint_badged(srv.tid, ep.raw(), 0xA, CapPerms::WRITE).unwrap();
        let lent = cap_store::mint_badged(srv.tid, ep.raw(), 0xB, CapPerms::RW_DELEGATE).unwrap();
        let moved = cap_store::move_cap(srv.tid, cli.tid, lent, None).unwrap();
        assert!(cap_store::get::<Endpoint>(cli.tid, Cap::from_raw(moved), CapPerms::WRITE).is_ok());

        let fresh = cap_store::revoke_derived(srv.tid, ep.raw()).expect("the capability is held");
        assert_ne!(fresh, ep.raw(), "the old handle value is retired");
        assert!(cap_store::get::<Endpoint>(srv.tid, Cap::from_raw(fresh), CapPerms::RW).is_ok(), "the capability stays");
        let gone = |tid: u32, h: CapHandle, need: CapPerms| {
            matches!(cap_store::get::<Endpoint>(tid, Cap::from_raw(h), need), Err(CapError::Stale | CapError::Revoked))
        };
        assert!(gone(srv.tid, ep.raw(), CapPerms::RW), "the old handle is stale");
        assert!(gone(srv.tid, kept, CapPerms::WRITE), "a copy kept by the holder is revoked");
        assert!(gone(cli.tid, moved, CapPerms::WRITE), "a copy lent to another task is revoked too");
        assert!(matches!(cap_store::revoke_derived(srv.tid, ep.raw()), Err(CapError::Stale | CapError::Revoked)));
    }

    /// A copy derived with a deadline lapses at it, and never later than its
    /// source's.
    #[test]
    fn a_derived_copy_carries_the_earlier_of_the_two_deadlines() {
        let _g = guard();
        if !crate::cap::SLOT_EXT {
            return;
        }
        let srv = fresh_task();
        let ep: Cap<Endpoint> = cap_store::grant(srv.tid, CapPerms::RW_DELEGATE, 3).unwrap();
        let h = cap_store::mint_badged_until(srv.tid, ep.raw(), 0xA, CapPerms::WRITE, 5_000).unwrap();
        let w = cap_store::with_table(srv.tid, |t| t.warrant_of(h)).flatten().unwrap();
        assert_eq!(w.expiry_ns, 5_000);
    }

    #[test]
    fn a_badged_endpoint_cap_keeps_its_badge_across_a_move() {
        let _g = guard();
        let srv = fresh_task();
        let cli = fresh_task();
        let ep: Cap<Endpoint> = cap_store::grant(srv.tid, CapPerms::RW_DELEGATE, 3).unwrap();
        assert_eq!(badge_of(srv.tid, ep.raw()), Some(0), "a granted capability is unbadged");
        if !crate::cap::SLOT_EXT {
            // Kconfig CAP_SLOT_EXT=n: one-word slots, nothing is badged.
            let r = cap_store::mint_badged(srv.tid, ep.raw(), 0xC11E, CapPerms::RW_DELEGATE);
            assert_eq!(r, Err(CapError::MissingPerms));
            assert_eq!(cap_store::with_table(srv.tid, |t| t.ext_of(ep.raw())).flatten(), Some(CapExt::NONE));
            return;
        }
        let b = cap_store::mint_badged(srv.tid, ep.raw(), 0xC11E, CapPerms::RW_DELEGATE).unwrap();
        assert_eq!(badge_of(srv.tid, b), Some(0xC11E));
        let w = cap_store::with_table(srv.tid, |t| t.warrant_of(b)).flatten().unwrap();
        assert_eq!(
            w.parent,
            azos_decision::warrant_ref(azos_sched::task_domain(srv.slot), ep.raw().slot(), ep.raw().generation()),
            "the copy links to its parent slot"
        );
        assert_eq!(w.depth, 1);
        // A badge is set once; a badge of 0 is no badge; rights never grow.
        let again = cap_store::mint_badged(srv.tid, b, 9, CapPerms::RW_DELEGATE);
        assert_eq!(again, Err(CapError::MissingPerms));
        let zero = cap_store::mint_badged(srv.tid, ep.raw(), 0, CapPerms::RW_DELEGATE);
        assert_eq!(zero, Err(CapError::MissingPerms));
        let ch: Cap<Port> = cap_store::grant(srv.tid, CapPerms::RW_DELEGATE, 1).unwrap();
        let wrong = cap_store::mint_badged(srv.tid, ch.raw(), 5, CapPerms::RW_DELEGATE);
        assert_eq!(wrong, Err(CapError::WrongKind));
        let moved = cap_store::move_cap(srv.tid, cli.tid, b, None).unwrap();
        assert_eq!(badge_of(cli.tid, moved), Some(0xC11E), "the badge is the client's identity");
        let ext = cap_store::with_table(cli.tid, |t| t.ext_of(moved)).flatten().unwrap();
        assert_eq!(ext, CapExt { badge: 0xC11E, ..CapExt::NONE });
        let w2 = cap_store::with_table(cli.tid, |t| t.warrant_of(moved)).flatten().unwrap();
        assert_eq!(w2.parent, w.parent, "a move keeps the capability's place in the tree");
        assert_eq!(badge_of(srv.tid, b), None, "stale in the sender");
    }

    /// Wave 15 N11b, the fork rule: a fork child never holds a badge. Its
    /// slots are written by `install_at` into a table `clear_all` wiped,
    /// which leaves the extension words; `install_at` must write NONE.
    /// Canary `canary_install_keeps_ext`: that store is skipped and the
    /// previous owner's badge shows through (the second half below).
    #[test]
    fn a_fork_install_never_inherits_a_stale_badge() {
        let _g = guard();
        if !crate::cap::SLOT_EXT {
            return;
        }
        let badge_after_reuse = || {
            let t = crate::cap::CapTable::empty();
            let ep = t.grant_raw(crate::cap::ty::ENDPOINT, CapPerms::RW_DELEGATE, 3).unwrap();
            let b = t.mint_badged(0x10001, ep, 0xBAD6E, CapPerms::RW_DELEGATE).unwrap();
            assert_eq!(t.ext_of(b).map(|e| e.badge), Some(0xBAD6E));
            // The table goes to a new owner (a fork child's claim wipes it),
            // and the child gets the parent's handle at the same slot.
            t.clear_all();
            assert!(t.install_at(b, 3, &crate::cap::Warrant::ROOT));
            t.ext_of(b).map(|e| e.badge)
        };
        assert_eq!(badge_after_reuse(), Some(0), "a fork child reads a previous owner's badge");
        // The canary bites: without the store the stale badge shows through.
        crate::cap::canary_install_keeps_ext(true);
        let stale = badge_after_reuse();
        crate::cap::canary_install_keeps_ext(false);
        assert_eq!(stale, Some(0xBAD6E), "the canary did not discriminate");
    }

    #[test]
    fn a_message_transfer_lands_every_capability_or_none() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let c0: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 10).unwrap();
        let c1: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 11).unwrap();
        let c2: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 12).unwrap();
        let mv = |h: CapHandle| CapXfer::new(h, false);
        let mut out = [CapHandle(0); 4];
        // One bad entry (no TRANSFER right on it) refuses the whole message; with
        // KEEP the sender still holds every capability, the receiver none.
        let nodup: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW, 13).unwrap();
        let xs = [mv(c0.raw()), mv(c1.raw()), mv(nodup.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, true, &mut out), Err(CapError::MissingPerms));
        assert_eq!((cap_store::occupied(a.tid), cap_store::occupied(b.tid)), (4, 0));
        // The same slot twice is refused.
        let xs = [mv(c0.raw()), mv(c0.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, true, &mut out), Err(CapError::MissingPerms));
        // All good: every one lands, rights attenuated where asked, DUP keeps.
        let xs = [mv(c0.raw()), CapXfer { rights: Some(CapPerms::READ), ..CapXfer::new(c1.raw(), true) }, mv(c2.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, false, &mut out), Ok(3));
        assert_eq!(cap_store::occupied(b.tid), 3);
        assert_eq!(cap_store::get(a.tid, c0, CapPerms::READ), Err(CapError::Stale), "moved");
        assert_eq!(cap_store::get(a.tid, c1, CapPerms::READ), Ok(11), "duplicated: still held");
        let r1: Cap<Port> = Cap::from_raw(out[1]);
        assert_eq!(cap_store::get(b.tid, r1, CapPerms::WRITE), Err(CapError::MissingPerms), "attenuated");
        assert_eq!(cap_store::get(b.tid, r1, CapPerms::READ), Ok(11));
        // Without KEEP a refused message consumes the sender's MOVE entries.
        // (A fresh capability: consuming `c1` would revoke the copy `b` holds
        // of it, which is the warrant tree's rule and not this test's subject.)
        let c3: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 15).unwrap();
        let xs = [mv(c3.raw()), mv(nodup.raw())];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, false, &mut out), Err(CapError::MissingPerms));
        assert_eq!(cap_store::get(a.tid, c3, CapPerms::READ), Err(CapError::Stale), "consumed");
        assert_eq!(cap_store::occupied(b.tid), 3, "and nothing landed");
    }

    #[test]
    fn a_message_needs_room_for_every_capability_before_any_moves() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let c0: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 20).unwrap();
        let c1: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 21).unwrap();
        // Fill the receiver to one free slot.
        let free = cap_store::with_table(b.tid, |t| t.free_slots()).unwrap();
        for i in 0..free - 1 {
            let _: Cap<Port> = cap_store::grant(b.tid, CapPerms::RW, 1000 + i as u32).unwrap();
        }
        let xs = [CapXfer::new(c0.raw(), false), CapXfer::new(c1.raw(), false)];
        let mut out = [CapHandle(0); 2];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, true, &mut out), Err(CapError::NoSpace));
        assert_eq!(cap_store::get(a.tid, c0, CapPerms::READ), Ok(20), "N-1 free: nothing moved");
        assert_eq!(cap_store::get(a.tid, c1, CapPerms::READ), Ok(21));
    }

    #[test]
    fn undoing_a_message_destroys_the_dup_copies_and_moves_the_rest_back() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let d: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 30).unwrap();
        let m: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 31).unwrap();
        // The MOVE entry is attenuated below DUP: putting it back is the
        // kernel's, so the DUP gate of a task's transfer must not refuse it.
        let xs = [
            CapXfer::new(d.raw(), true),
            CapXfer { rights: Some(CapPerms::READ), ..CapXfer::new(m.raw(), false) },
        ];
        let mut got = [CapHandle(0); 2];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, false, &mut got), Ok(2));
        assert_eq!((cap_store::occupied(a.tid), cap_store::occupied(b.tid)), (1, 2));
        assert_eq!(cap_store::undo_move_caps(a.tid, b.tid, &xs, &got), 0, "every MOVE entry went back");
        assert_eq!(cap_store::occupied(b.tid), 0, "the holder keeps a capability of a message it never took");
        assert_eq!(cap_store::get(a.tid, d, CapPerms::RW), Ok(30), "the DUP sender lost its own handle");
        // Exactly one handle each: the DUP copy was destroyed, not returned.
        // (the MOVE entry back plus the DUP original; three when the copy
        // comes back too, one when the MOVE entry does not).
        assert_eq!(cap_store::occupied(a.tid), 2, "the sender holds a DUP capability twice");
    }

    #[test]
    fn undoing_a_message_to_a_gone_sender_leaves_nothing_in_the_holder() {
        let _g = guard();
        let a = fresh_task();
        let b = fresh_task();
        let m: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 40).unwrap();
        let xs = [CapXfer::new(m.raw(), false)];
        let mut got = [CapHandle(0); 1];
        assert_eq!(cap_store::move_caps(a.tid, b.tid, &xs, false, &mut got), Ok(1));
        shim_kill(a.tid);
        assert_eq!(cap_store::undo_move_caps(a.tid, b.tid, &xs, &got), 1, "the MOVE entry had nowhere to go");
        assert_eq!(cap_store::occupied(b.tid), 0, "a capability that cannot go back stays with the holder");
    }

    #[test]
    fn a_reused_slot_wipes_the_previous_owners_table() {
        let _g = guard();
        // The `OWNER` backstop, stated as behaviour rather than as a comment.
        // It converts "domain B inherits domain A's caps" into "domain A's
        // caps are destroyed", fail-closed, on a path that skips `reset`.
        let a = fresh_task();
        let slot = a.slot;
        let src: Cap<Port> = cap_store::grant(a.tid, CapPerms::RW_DELEGATE, 1).unwrap();
        assert_eq!(cap_store::occupied(a.tid), 1);

        // A dies; a new task (a new domain) draws the same pool slot.
        shim_kill(a.tid);
        let heir_tid = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        shim_bind(heir_tid, slot);

        // The heir sees an empty table, not A's cap.
        assert_eq!(cap_store::occupied(heir_tid), 0);
        assert_eq!(
            cap_store::get(heir_tid, src, CapPerms::READ),
            Err(CapError::Stale)
        );

        // The flip side this test used to pin (a dead TID's lookup wiping the
        // live heir's table) is gone with the TID-keyed `OWNER`: the claim is
        // the domain's key now, which a TID does not alter. A dead TID can
        // match a slot only across the 2^32 TID wrap, as before.
        shim_kill(a.tid);
    }

    // ── D2: a thread is in its creator's domain, and so has its table ────

    #[test]
    fn a_threads_table_is_its_domains_and_only_the_last_exit_wipes_it() {
        let _g = guard();
        let lead = fresh_task();
        let thread = fresh_task();
        azos_sched::shim_join(thread.tid, lead.tid);

        // One table, whichever member resolves: a grant by the thread is the
        // leader's, and the leader's is the thread's.
        let c: Cap<Port> = cap_store::grant(thread.tid, CapPerms::RW_DELEGATE, 7).unwrap();
        assert_eq!(cap_store::occupied(lead.tid), 1, "the thread's grant is in the domain's table");
        assert_eq!(cap_store::get(lead.tid, c, CapPerms::READ), Ok(7), "the leader resolves it");
        let d: Cap<Port> = cap_store::grant(lead.tid, CapPerms::RW, 8).unwrap();
        assert_eq!(cap_store::get(thread.tid, d, CapPerms::READ), Ok(8), "and the thread the leader's");
        assert_eq!(cap_store::table_slot(thread.tid), cap_store::table_slot(lead.tid));

        // The thread's exit leaves the table; the last member's wipes it.
        cap_store::reset(thread.tid);
        assert_eq!(cap_store::occupied(lead.tid), 2, "a thread's exit must not take the domain's table");
        shim_kill(thread.tid);
        cap_store::reset(lead.tid);
        assert_eq!(cap_store::occupied(lead.tid), 0, "the last member's exit wipes it");
        shim_kill(lead.tid);
    }

    // ── the fork-time bootstrap grant survives slot reuse ──
    //
    // `endpoint::endpoint_inherit_at_fork` (`crates/core/ipc/src/endpoint.rs`)
    // mints a child's capability with `objref::grant_packed`, which is
    // `cap_store::grant` plus an epoch check — the slot-reuse guarantee
    // below is `cap_store`'s, inherited rather than re-implemented, so this
    // test exercises it directly through `grant`/`get` with a real
    // `Cap<Endpoint>` rather than duplicating `tests/host/ipc-tests`'
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
    // the fork-time bootstrap grant leans on to keep a re-let slot from inheriting a dead
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

    // ── The warrant tree (owner decision D3/L4) ────────────────────────────
    //
    // Derivation attenuates, revoking a warrant revokes its subtree across
    // domains, every holder is told, a deadline fails like a revoke, a reused
    // slot or domain never resurrects a descendant, and the sweep is bounded.
    // Each test names the break that turns it red.

    use crate::cap::{Quota, Warrant, WARRANT_DEPTH_MAX, ty};
    use std::sync::atomic::AtomicU64;

    static NOW: AtomicU64 = AtomicU64::new(0);
    static WTID: AtomicU32 = AtomicU32::new(1000);

    fn clock() -> u64 {
        NOW.load(Ordering::SeqCst)
    }

    /// A domain of its own at table slot `slot` (a fresh TID: if the slot was
    /// used before, this is a new domain at a reused table).
    fn wtask(slot: usize) -> Task {
        assert!((WARRANT_SLOT0..azos_sched::task::MAX_TASKS).contains(&slot), "warrant tests own slots {WARRANT_SLOT0}..");
        crate::cap::set_clock(clock);
        let tid = WTID.fetch_add(1, Ordering::SeqCst);
        shim_bind(tid, slot);
        Task { tid, slot }
    }

    /// The module lock, with the clock back at 0.
    fn wguard() -> MutexGuard<'static, ()> {
        let g = guard();
        NOW.store(0, Ordering::SeqCst);
        g
    }

    fn key(t: &Task) -> u32 {
        azos_sched::task_domain(t.slot)
    }

    fn ch(h: CapHandle) -> Cap<Port> {
        Cap::from_raw(h)
    }

    fn root(t: &Task, perms: CapPerms, res: u32) -> CapHandle {
        cap_store::grant::<Port>(t.tid, perms, res).unwrap().raw()
    }

    /// A root with a deadline and a quota of its own (the kernel's grant API
    /// for a warrant a boot or a manager hands out).
    fn root_with(t: &Task, perms: CapPerms, res: u32, w: Warrant) -> CapHandle {
        cap_store::with_table(t.tid, |tb| tb.grant_warranted(ty::PORT, perms, res, CapExt::NONE, w))
            .unwrap()
            .unwrap()
    }

    fn dup_x(from: &Task, to: &Task, x: CapXfer) -> Result<CapHandle, CapError> {
        let mut out = [CapHandle(0); 1];
        cap_store::move_caps(from.tid, to.tid, &[x], true, &mut out).map(|_| out[0])
    }

    fn dup(from: &Task, to: &Task, h: CapHandle) -> Result<CapHandle, CapError> {
        dup_x(from, to, CapXfer::new(h, true))
    }

    fn dup_rights(from: &Task, to: &Task, h: CapHandle, r: CapPerms) -> Result<CapHandle, CapError> {
        dup_x(from, to, CapXfer { rights: Some(r), ..CapXfer::new(h, true) })
    }

    fn warrant(t: &Task, h: CapHandle) -> Warrant {
        cap_store::with_table(t.tid, |tb| tb.warrant_of(h)).flatten().expect("a live warrant")
    }

    fn live(t: &Task, h: CapHandle) -> bool {
        cap_store::get(t.tid, ch(h), CapPerms::NONE).is_ok()
    }

    fn rref(t: &Task, h: CapHandle) -> u64 {
        azos_decision::warrant_ref(key(t), h.slot(), h.generation())
    }

    /// Derivation attenuates and links. **Canary.** In `narrow_warrant` let
    /// any requested rights through (`Some(r) => r`): the READ-only copy
    /// holds WRITE and the first assertion goes red; drop the parent link in
    /// `derive_warrant` (`parent: 0`): the parent assertion goes red.
    #[test]
    fn derive_attenuates_and_records_its_parent() {
        let _g = wguard();
        let (a, b, c) = (wtask(44), wtask(45), wtask(46));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        assert_eq!(warrant(&a, r), Warrant::ROOT);
        let b1 = dup_rights(&a, &b, r, CapPerms::READ.union(CapPerms::DELEGATE)).unwrap();
        assert_eq!(cap_store::get(b.tid, ch(b1), CapPerms::WRITE), Err(CapError::MissingPerms), "attenuated");
        assert_eq!(cap_store::get(b.tid, ch(b1), CapPerms::READ), Ok(5));
        let w = warrant(&b, b1);
        assert_eq!((w.parent, w.depth), (rref(&a, r), 1), "a child of the source, one link down");
        // The next link: parent is B's slot, depth 2, rights narrow again.
        let c1 = dup_rights(&b, &c, b1, CapPerms::READ).unwrap();
        let w = warrant(&c, c1);
        assert_eq!((w.parent, w.depth), (rref(&b, b1), 2));
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::WRITE), Err(CapError::MissingPerms));
        // A move keeps the place in the tree: the parent stays the parent.
        let d = wtask(47);
        let c2 = cap_store::move_cap(c.tid, d.tid, dup(&b, &c, b1).unwrap(), None).unwrap();
        assert_eq!(warrant(&d, c2).parent, rref(&b, b1), "a moved copy is still a child of where it came from");
    }

    /// Widening is refused, in rights, deadline, quota and depth, and a
    /// refused derive leaves nothing behind. **Canary.** In `derive_warrant`
    /// replace the quota test `spec.quota.amount > src.quota.amount` by
    /// `false`: the quota assertion goes red; make the depth test `>= usize::MAX`: the
    /// depth assertion goes red; make `expiry_ns` `spec.expiry_ns` alone: the
    /// deadline assertion goes red.
    #[test]
    fn widening_is_refused() {
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        let r = root_with(&a, CapPerms::RW_DELEGATE, 6, Warrant { expiry_ns: 1000, quota: Quota { bytes: false, amount: 10 }, ..Warrant::ROOT });
        let read = CapPerms::READ.union(CapPerms::DELEGATE);
        let b1 = dup_rights(&a, &b, r, read).unwrap();
        // Rights: the copy cannot give more than it holds.
        let c = wtask(46);
        assert_eq!(dup_rights(&b, &c, b1, CapPerms::RW), Err(CapError::MissingPerms));
        assert_eq!(cap_store::occupied(c.tid), 0, "a refused derive leaves nothing behind");
        // Deadline: never later than the source's; earlier is honoured.
        let later = dup_x(&a, &b, CapXfer { expiry_ns: 5000, ..CapXfer::new(r, true) }).unwrap();
        assert_eq!(warrant(&b, later).expiry_ns, 1000, "the earlier deadline wins");
        let sooner = dup_x(&a, &b, CapXfer { expiry_ns: 400, ..CapXfer::new(r, true) }).unwrap();
        assert_eq!(warrant(&b, sooner).expiry_ns, 400);
        assert_eq!(warrant(&b, b1).expiry_ns, 1000, "inherited when not asked");
        // Quota: never more, never another unit; none asked inherits.
        let q = |bytes, amount| CapXfer { quota: Quota { bytes, amount }, ..CapXfer::new(r, true) };
        assert_eq!(dup_x(&a, &b, q(false, 11)), Err(CapError::MissingPerms), "more than the source's");
        assert_eq!(dup_x(&a, &b, q(true, 4)), Err(CapError::MissingPerms), "another unit");
        let four = dup_x(&a, &b, q(false, 4)).unwrap();
        assert_eq!(warrant(&b, four).quota, Quota { bytes: false, amount: 4 });
        assert_eq!(warrant(&b, b1).quota, Quota { bytes: false, amount: 10 }, "inherited when not asked");
        // Badged mint is a derive too: it cannot widen.
        if crate::cap::SLOT_EXT {
            let ep: Cap<Endpoint> = cap_store::grant(a.tid, CapPerms::WRITE.union(CapPerms::DUP), 9).unwrap();
            assert_eq!(cap_store::mint_badged(a.tid, ep.raw(), 7, CapPerms::RW), Err(CapError::MissingPerms));
            assert!(cap_store::mint_badged(a.tid, ep.raw(), 7, CapPerms::WRITE).is_ok());
        }
        // Depth: a chain of WARRANT_DEPTH_MAX links is the longest.
        let (x, y) = (wtask(48), wtask(49));
        let mut cur = dup(&a, &x, r).unwrap(); // depth 1, held by x
        let mut from = (&x, &y);
        for _ in 1..WARRANT_DEPTH_MAX {
            cur = dup(from.0, from.1, cur).unwrap();
            from = (from.1, from.0);
        }
        assert_eq!(warrant(from.0, cur).depth as usize, WARRANT_DEPTH_MAX);
        assert_eq!(dup(from.0, from.1, cur), Err(CapError::NoSpace), "one link past the limit");
    }

    /// Revoking a warrant revokes the subtree, across domains; the revoker's
    /// siblings and unrelated capabilities stay. **Canary.** In `warrant_alive`
    /// return `true`: the grandchild survives and the first loop goes red; make
    /// `sweep_dead` stop after the first pass in `sweep` (`0..1`): only the
    /// children go and the grandchild assertion goes red.
    #[test]
    fn revoking_a_warrant_revokes_its_subtree_across_domains() {
        let _g = wguard();
        let (a, b, c) = (wtask(44), wtask(45), wtask(46));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let other = root(&a, CapPerms::RW_DELEGATE, 6);
        let b1 = dup(&a, &b, r).unwrap();
        let b2 = dup(&a, &b, r).unwrap();
        let c1 = dup(&b, &c, b1).unwrap(); // a grandchild in a third domain
        let c2 = dup(&b, &c, b2).unwrap();
        let unrelated = dup(&a, &c, other).unwrap();
        // Revoking a middle warrant takes its subtree only.
        cap_store::revoke(b.tid, ch(b1));
        assert!(!live(&b, b1) && !live(&c, c1), "the subtree of b1 is gone");
        assert!(live(&b, b2) && live(&c, c2) && live(&a, r), "its sibling and its parent are not");
        // Revoking the root takes everything below it, in both domains.
        cap_store::revoke(a.tid, ch(r));
        for (t, h) in [(&a, r), (&b, b2), (&c, c2)] {
            assert!(!live(t, h), "domain {} still holds a descendant of a revoked warrant", t.slot);
        }
        assert!(live(&a, other) && live(&c, unrelated), "another warrant is untouched");
        assert_eq!(cap_store::occupied(b.tid), 0);
    }

    // ── Delete is not revoke (owner decision 20-10) ────────────────────────
    //
    // A close or an exit frees the capability's own slot; what was derived from
    // it stays, hung under the freed slot's own parent. Only an explicit
    // revoke frees a subtree. Each test names the break that turns it red.

    /// Delete `h` from `t`'s table, as a close does.
    fn close(t: &Task, h: CapHandle) {
        cap_store::with_table(t.tid, |tb| tb.delete(ch(h))).unwrap();
    }

    /// Delete `h` and keep the sweep from running: the re-parent row stands.
    fn close_unswept(t: &Task, h: CapHandle) {
        cap_store::with_table(t.tid, |tb| {
            tb.delete(ch(h));
            assert!(crate::cap::sweep_take(), "the delete of a slot with copies owes a sweep");
        })
        .unwrap();
    }

    /// Run the sweep that `close_unswept` held back.
    fn sweep_now() {
        crate::cap::sweep_owed();
        cap_store::sweep();
    }

    /// A close frees the slot and nothing below it; the copy hangs under the
    /// closed slot's parent, keeps its place in the tree, and is reached by an
    /// explicit revoke of any ancestor. **Canary.** Free a deleted slot in
    /// `Free::Revoke` mode (`CapTable::delete`): the copy dies at the first
    /// assertion; make `fate_of` answer `Fate::Free` for a deleted parent: the
    /// same; skip the `Fate::Reparent` store in `sweep_dead`: the parent
    /// assertion goes red; re-parent to 0 always: the last assertion does.
    #[test]
    fn a_close_leaves_what_was_derived_and_an_explicit_revoke_still_reaches_it() {
        let _g = wguard();
        let (a, b, c) = (wtask(44), wtask(45), wtask(46));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        let c1 = dup_rights(&b, &c, b1, CapPerms::READ).unwrap();
        close(&b, b1);
        assert!(!live(&b, b1), "the closed slot is gone");
        assert!(live(&c, c1), "the copy it made stays");
        assert!(live(&a, r), "and its parent");
        let w = warrant(&c, c1);
        assert_eq!((w.parent, w.depth), (rref(&a, r), 1), "hung under the closed slot's parent, one link fewer");
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::WRITE), Err(CapError::MissingPerms), "still attenuated");
        assert!(!crate::cap::revocation_in_flight(), "a delete opens no revocation window");
        cap_store::revoke(a.tid, ch(r));
        assert!(!live(&c, c1), "an explicit revoke of the ancestor reaches the copy");
    }

    /// A close of a root makes its copies roots: nothing is left to revoke
    /// them by, and they keep their own limits. **Canary.** Skip the
    /// `derived` decrement in `sweep_dead`'s root case: the third assertion
    /// goes red (the table's count of derived slots drifts).
    #[test]
    fn closing_a_root_makes_its_copies_roots_with_their_own_limits() {
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let deadline = CapXfer { expiry_ns: 5000, ..CapXfer::new(r, true) };
        let b1 = dup_x(&a, &b, deadline).unwrap();
        close(&a, r);
        assert!(live(&b, b1));
        let w = warrant(&b, b1);
        assert_eq!((w.parent, w.depth, w.expiry_ns), (0, 0, 5000), "a root, deadline kept");
        assert_eq!(cap_store::with_table(b.tid, |t| t.derived()), Some(0), "no longer counted as derived");
        NOW.store(5000, Ordering::SeqCst);
        assert_eq!(cap_store::get(b.tid, ch(b1), CapPerms::READ), Err(CapError::Revoked), "its deadline still ends it");
    }

    /// An exit is a delete of every slot: what the domain shared stays, hung
    /// under each slot's own parent (a root's copies become roots, a copy's
    /// copies keep it as their parent); only a revoke by the holder that
    /// remains reaches them. **Canary.** Make `clear_all` owe a revocation
    /// (`revocation_cleared()` and `SWEEP_PENDING` for `had_kids`, as before
    /// 20-10): the copies die at the first assertion.
    #[test]
    fn a_domains_exit_leaves_what_it_shared() {
        let _g = wguard();
        let (a, b, c) = (wtask(44), wtask(45), wtask(46));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        let c1 = dup(&b, &c, b1).unwrap();
        cap_store::reset(a.tid);
        assert!(live(&b, b1) && live(&c, c1), "A's exit took its own slots only");
        assert_eq!(warrant(&b, b1).parent, 0, "B's copy is a root now");
        assert_eq!(warrant(&c, c1).parent, rref(&b, b1), "C's copy is still under B's");
        assert!(!crate::cap::revocation_in_flight());
        cap_store::revoke(b.tid, ch(b1));
        assert!(!live(&c, c1), "B revokes what it passed on");
    }

    /// While a delete's row stands (the copies not yet hung under their new
    /// parent) and an unrelated revocation is in flight, a copy below the
    /// deleted slot is still used: the walk of the parent chain goes through
    /// the deleted link to the first live one, and a copy of the revoked one
    /// is refused. After the sweep the row is gone and the copy hangs under
    /// the live ancestor. **Canary.** Drop the `step_deleted` fallback in
    /// `warrant_step`: the first assertion goes red (a deleted link read as
    /// revoked).
    #[test]
    fn a_deleted_link_is_not_a_revoked_one_to_the_chain_walk() {
        let _g = wguard();
        let (a, b, c, d) = (wtask(44), wtask(45), wtask(46), wtask(47));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        let c1 = dup(&b, &c, b1).unwrap();
        let own = root(&b, CapPerms::RW_DELEGATE, 6);
        let d1 = dup(&b, &d, own).unwrap();
        // In one locked step: delete b1, revoke `own` (opens the window), and
        // take the sweep's duty so that nothing is swept.
        cap_store::with_table(b.tid, |t| {
            t.delete(ch(b1));
            assert!(t.revoke_raw(own));
            assert!(crate::cap::sweep_take());
        })
        .unwrap();
        assert!(crate::cap::revocation_in_flight() && crate::cap::forwards_standing());
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::READ), Ok(5), "a deleted link is walked through");
        assert_eq!(cap_store::get(d.tid, ch(d1), CapPerms::READ), Err(CapError::Revoked), "a revoked one refuses");
        assert_eq!(warrant(&c, c1).parent, rref(&b, b1), "not re-parented yet");
        sweep_now();
        assert!(!crate::cap::revocation_in_flight() && !crate::cap::forwards_standing(), "window shut, row retired");
        assert_eq!(warrant(&c, c1).parent, rref(&a, r));
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::READ), Ok(5));
        assert!(!live(&d, d1));
    }

    /// Links deleted one after the other with no sweep between resolve to the
    /// first live ancestor, and a copy installed by a move meanwhile names
    /// that ancestor, not a link the sweep is about to retire. **Canary.**
    /// Drop the `warrant_settle` call in `admit_warrant`: the moved copy's
    /// parent is the deleted link and the last assertion goes red; make
    /// `fate_of` stop after one hop: the copy under two deleted links is
    /// freed.
    #[test]
    fn several_deleted_links_resolve_to_the_first_live_ancestor() {
        let _g = wguard();
        let (a, b, c, d, e) = (wtask(44), wtask(45), wtask(46), wtask(47), wtask(48));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        let c1 = dup(&b, &c, b1).unwrap();
        let d1 = dup(&c, &d, c1).unwrap();
        close_unswept(&b, b1);
        close_unswept(&c, c1);
        assert_eq!(cap_store::get(d.tid, ch(d1), CapPerms::READ), Ok(5));
        // A move installs a copy of d1's warrant while both rows stand.
        let moved = cap_store::move_cap(d.tid, e.tid, d1, None).unwrap();
        assert_eq!(warrant(&e, moved).parent, rref(&a, r), "the live ancestor, not a deleted link");
        sweep_now();
        assert!(live(&e, moved) && !crate::cap::forwards_standing());
        cap_store::revoke(a.tid, ch(r));
        assert!(!live(&e, moved));
    }

    /// A MOVE of a slot that has copies keeps their depth: they hang under the
    /// moved slot, which is exactly as deep as the one it left, so a sweep that
    /// lifted them a level (as a delete does) would let repeated moves walk a
    /// chain past `WARRANT_DEPTH_MAX` unseen. The depth stays exact through
    /// many moves, the limit still binds the chain below, an explicit revoke
    /// of the root still reaches the deepest copy, and a DELETE after those
    /// moves lifts the copy by one. **Canary.** `--features
    /// move-lifts-depth-canary` (`sweep_dead` lowers the depth by one for every
    /// re-parent, as it did): the first depth assertion goes red on the first
    /// move.
    #[test]
    fn a_move_with_copies_keeps_their_depth_and_the_limit_binds() {
        let _g = wguard();
        let (a, b, d, c, e) = (wtask(44), wtask(45), wtask(46), wtask(47), wtask(48));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let mut s = dup(&a, &b, r).unwrap(); // depth 1
        let k = dup(&b, &c, s).unwrap(); // depth 2, a copy of `s`
        let mut at = (&b, &d);
        for n in 0..WARRANT_DEPTH_MAX + 4 {
            s = cap_store::move_cap(at.0.tid, at.1.tid, s, None).unwrap();
            sweep_now();
            let w = warrant(&c, k);
            assert_eq!(w.depth, 2, "move {n}: the copy is still two links below the root");
            assert_eq!(w.parent, rref(at.1, s), "move {n}: it follows the capability");
            assert_eq!(warrant(at.1, s).depth, 1, "the moved slot keeps its own depth");
            at = (at.1, at.0);
        }
        // The chain below the copy can still only grow to the limit.
        let (mut cur, mut from) = (k, (&c, &e));
        for _ in 2..WARRANT_DEPTH_MAX {
            cur = dup(from.0, from.1, cur).unwrap();
            from = (from.1, from.0);
        }
        assert_eq!(warrant(from.0, cur).depth as usize, WARRANT_DEPTH_MAX);
        assert_eq!(dup(from.0, from.1, cur), Err(CapError::NoSpace), "no link past the limit after the moves");
        // The deepest copy is still reached by the revoke of the root.
        cap_store::revoke(a.tid, ch(r));
        assert!(!live(from.0, cur) && !live(&c, k) && !live(at.0, s));
    }

    /// A DELETE after a MOVE lifts a copy one level, from the exact depth.
    #[test]
    fn a_close_after_a_move_lifts_the_copy_by_one() {
        let _g = wguard();
        let (a, b, d, c) = (wtask(44), wtask(45), wtask(46), wtask(47));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let s = dup(&a, &b, r).unwrap();
        let k = dup(&b, &c, s).unwrap();
        let moved = cap_store::move_cap(b.tid, d.tid, s, None).unwrap();
        sweep_now();
        assert_eq!(warrant(&c, k).depth, 2);
        close(&d, moved);
        assert_eq!(warrant(&c, k).depth, 1, "hung under the root: one link");
        assert_eq!(warrant(&c, k).parent, rref(&a, r));
    }

    /// A row goes in while its slot is alive and only takes effect once the
    /// slot is gone: a sweep that runs in between (another hart's) neither
    /// retires it nor lets a lookup miss it. **Canary.** Give the row a real
    /// sequence number in `forward_push` (not `ROW_PENDING`): the second
    /// assertion goes red; drop the `seq == ROW_PENDING` test of
    /// `forward_commit`: the row never commits and the last one goes red.
    #[test]
    fn a_pending_row_is_not_retired_before_its_slot_is_freed() {
        let _g = wguard();
        sweep_now();
        let from = azos_decision::warrant_ref(0x7777, 1, 1);
        assert!(crate::cap::forward_push(from, 0));
        assert_eq!(crate::cap::forward_lookup(from), Some(0), "found while its slot is alive");
        sweep_now();
        assert!(crate::cap::forwards_standing(), "a sweep did not retire a row whose slot is not freed yet");
        crate::cap::forward_commit(from);
        cap_store::sweep();
        assert!(!crate::cap::forwards_standing(), "committed, the next sweep retires it");
    }

    /// A delete that finds the row table full revokes instead: the copies go,
    /// never survive unchecked. Standalone tables (two domains' worth of
    /// slots with copies fill the rows, a third delete overflows). **Canary.**
    /// Make `release_warrant` ignore a delete with no row (`forward_refused`): the third delete owes
    /// nothing and the assertions go red.
    #[test]
    fn a_delete_with_no_row_to_spare_revokes_its_copies() {
        let _g = wguard();
        let leak = || -> &'static crate::cap::CapTable { Box::leak(Box::new(crate::cap::CapTable::empty())) };
        let fill = |t: &'static crate::cap::CapTable, key: u32| {
            t.set_owner(key);
            let caps: Vec<_> = (0..crate::cap::MAX_CAPS_PER_TASK)
                .map(|_| {
                    let c = t.grant::<Port>(CapPerms::RW_DELEGATE, 1).unwrap();
                    t.note_child(c.raw());
                    c
                })
                .collect();
            caps
        };
        let (t1, t2, t3) = (leak(), leak(), leak());
        let c1 = fill(t1, 0x7001);
        let c2 = fill(t2, 0x7002);
        let c3 = fill(t3, 0x7003);
        sweep_now();
        assert!(!crate::cap::forwards_standing(), "no row left over from another test");
        c1.iter().for_each(|c| t1.delete(*c));
        c2.iter().for_each(|c| t2.delete(*c));
        assert!(crate::cap::forwards_standing() && !crate::cap::revocation_in_flight(), "they fit the rows");
        t3.delete(c3[0]);
        assert!(crate::cap::revocation_in_flight(), "the overflow opened the revocation window");
        assert!(crate::cap::sweep_take(), "and owes the sweep");
        sweep_now();
        assert!(!crate::cap::revocation_in_flight() && !crate::cap::forwards_standing(), "the sweep shut it");
    }


    /// Every holder whose slot is revoked is told: a pending notice the next
    /// refusal of a dead handle answers as `Revoked`, once per revoked slot, in
    /// every domain it reached (also one that never used the handle).
    /// **Canary.** Remove `self.post_notice()` from `sweep_dead`: the first
    /// assertion goes red.
    #[test]
    fn every_revoked_holder_gets_a_notice() {
        let _g = wguard();
        let (a, b, c) = (wtask(44), wtask(45), wtask(46));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        let c1 = dup(&b, &c, b1).unwrap();
        cap_store::revoke(a.tid, ch(r));
        assert_eq!(cap_store::get(b.tid, ch(b1), CapPerms::READ), Err(CapError::Revoked), "told, in B");
        assert_eq!(cap_store::get(b.tid, ch(b1), CapPerms::READ), Err(CapError::Stale), "once");
        // C never used its handle: the notice waited for it, and is for its
        // slot once. A handle that never existed in C does not spend it.
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::READ), Err(CapError::Revoked), "told, in C");
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::READ), Err(CapError::Stale));
        // The revoker revoked its own slot: nobody to tell.
        assert_eq!(cap_store::get(a.tid, ch(r), CapPerms::READ), Err(CapError::Stale), "the revoker is not a revoked holder");
    }

    /// The lazy-revocation window is closed: a capability derived from a
    /// revoked one is refused on its next use even before the sweep frees it,
    /// at any depth of the chain, on every path a capability is used or held
    /// (resolve, the resolve cache's word, presence, transfer), while a
    /// capability under a live ancestor is not. The sweep's duty is taken
    /// first (the trick of `a_reused_slot_or_domain_does_not_resurrect_a_
    /// descendant`), so nothing below the revoked slot has been freed.
    /// **Canary.** `--features revoke-chain-canary` (`revocation_in_flight`
    /// never open): the first `Revoked` assertion goes red; make
    /// `chain_alive` answer `true` after the first live link
    /// (`Some(_) => return true`): the grandchild goes red;
    /// make `word_grants` ignore `revocation_in_flight`: the cache assertion
    /// goes red; drop the `self.usable(i, w)` of `holds_kind_with`: the
    /// presence assertion goes red; drop the `is_void` test in `xfer_plan`:
    /// the transfer assertion goes red; make the walk's bound
    /// `WARRANT_DEPTH_MAX - 1`: the deepest-chain assertion goes red.
    #[test]
    fn a_descendant_of_a_revoked_warrant_is_refused_before_the_sweep() {
        let _g = wguard();
        let (a, b, c, d) = (wtask(44), wtask(45), wtask(46), wtask(47));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let other = root(&a, CapPerms::RW_DELEGATE, 6);
        let b1 = dup(&a, &b, r).unwrap();
        let c1 = dup(&b, &c, b1).unwrap(); // a grandchild, one more link down
        let live_child = dup(&a, &d, other).unwrap(); // under an ancestor that stays
        let tb = |t: &Task| cap_store::table_slot(t.tid).unwrap();
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::READ), Ok(5), "alive before the revoke");

        // Revoke the root and keep the sweep from running: the child and the
        // grandchild still hold their slots.
        cap_store::with_table(a.tid, |t| {
            assert!(t.revoke_raw(r));
            assert!(crate::cap::sweep_take());
        })
        .unwrap();
        assert_eq!((cap_store::occupied(b.tid), cap_store::occupied(c.tid)), (1, 1), "nothing swept yet");

        assert_eq!(cap_store::get(b.tid, ch(b1), CapPerms::READ), Err(CapError::Revoked), "the child is refused");
        assert_eq!(cap_store::get(c.tid, ch(c1), CapPerms::READ), Err(CapError::Revoked), "so is the grandchild: the walk reaches the root");
        assert_eq!(cap_store::get(d.tid, ch(live_child), CapPerms::READ), Ok(6), "a live ancestor refuses nothing");
        // The cache's view: no word grants while the window is open.
        let (wb, wd) = (cap_store::slot_word(tb(&b), b1), cap_store::slot_word(tb(&d), live_child));
        assert_eq!(crate::cap::CapTable::word_grants(wb, b1, ty::PORT, CapPerms::READ), None);
        assert_eq!(crate::cap::CapTable::word_grants(wd, live_child, ty::PORT, CapPerms::READ), None, "no cache while a sweep is owed");
        // Presence tests do not count it; a transfer of it is refused.
        assert!(cap_store::with_table(c.tid, |t| !t.holds_kind_with(ty::PORT, CapPerms::READ)).unwrap());
        assert!(cap_store::with_table(d.tid, |t| t.holds_kind_with(ty::PORT, CapPerms::READ)).unwrap());
        assert_eq!(dup(&c, &d, c1), Err(CapError::Revoked));
        assert_eq!(cap_store::move_cap(b.tid, d.tid, b1, None), Err(CapError::Revoked));

        // The sweep frees them and shuts the window; the cache resumes.
        crate::cap::sweep_owed();
        cap_store::sweep();
        assert!(!crate::cap::revocation_in_flight(), "a confirming sweep shuts the window");
        assert_eq!((cap_store::occupied(b.tid), cap_store::occupied(c.tid)), (0, 0));
        assert!(cap_store::get(c.tid, ch(c1), CapPerms::READ).is_err());
        let wd = cap_store::slot_word(tb(&d), live_child);
        assert_eq!(crate::cap::CapTable::word_grants(wd, live_child, ty::PORT, CapPerms::READ), Some(6));
    }

    /// The walk's bound: the longest legal chain (`WARRANT_DEPTH_MAX` links)
    /// is walked to its root while another revocation is in flight and is not
    /// refused, and when its own root is revoked its deepest link is.
    /// **Canary.** Make the walk's bound `WARRANT_DEPTH_MAX - 1` in
    /// `chain_alive`: the first assertion goes red (a live chain fails
    /// closed); answer `true` after the first live link: the second does.
    #[test]
    fn the_chain_walk_covers_the_deepest_legal_chain() {
        let _g = wguard();
        let n = WARRANT_DEPTH_MAX + 1;
        assert!(WARRANT_SLOT0 + n + 2 <= azos_sched::task::MAX_TASKS, "the chain needs {n} table slots and two more");
        let tasks: Vec<Task> = (0..n).map(|i| wtask(WARRANT_SLOT0 + n - 1 - i)).collect();
        let r = root(&tasks[0], CapPerms::RW_DELEGATE, 5);
        let mut cur = r;
        for i in 1..n {
            cur = dup(&tasks[i - 1], &tasks[i], cur).unwrap();
        }
        let deepest = &tasks[n - 1];
        assert_eq!(warrant(deepest, cur).depth as usize, WARRANT_DEPTH_MAX);
        // Another warrant is revoked, its sweep not run: the window is open.
        let (x, y) = (wtask(WARRANT_SLOT0 + n), wtask(WARRANT_SLOT0 + n + 1));
        let xr = root(&x, CapPerms::RW_DELEGATE, 7);
        let _xc = dup(&x, &y, xr).unwrap();
        cap_store::with_table(x.tid, |t| {
            assert!(t.revoke_raw(xr));
            assert!(crate::cap::sweep_take());
        })
        .unwrap();
        assert_eq!(cap_store::get(deepest.tid, ch(cur), CapPerms::READ), Ok(5), "a live chain of the longest depth is walked");
        // Its own root revoked, the sweep still not run: the deepest is refused.
        cap_store::with_table(tasks[0].tid, |t| {
            assert!(t.revoke_raw(r));
            assert!(crate::cap::sweep_take());
        })
        .unwrap();
        assert_eq!(cap_store::get(deepest.tid, ch(cur), CapPerms::READ), Err(CapError::Revoked));
        crate::cap::sweep_owed();
        cap_store::sweep();
        assert!(!crate::cap::revocation_in_flight());
        assert!(cap_store::get(deepest.tid, ch(cur), CapPerms::READ).is_err());
    }

    /// A warrant past its deadline fails like a revoked one, on every path a
    /// capability is used or held; a cache keyed on the slot word never holds it.
    /// **Canary.** Drop the `w_expires` test from `get_uncontained`: the
    /// get assertion goes red; drop it from `word_grants`: the cache assertion
    /// goes red; drop `self.usable(i, w)` from `holds_kind_with`: the
    /// presence assertion goes red; drop the `is_void` test in `xfer_plan`:
    /// the transfer assertion goes red.
    #[test]
    fn an_expired_warrant_fails_like_a_revoked_one() {
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        let r = root_with(&a, CapPerms::RW_DELEGATE, 5, Warrant { expiry_ns: 1000, ..Warrant::ROOT });
        let plain = root(&a, CapPerms::RW_DELEGATE, 6);
        let b1 = dup(&a, &b, r).unwrap();
        NOW.store(999, Ordering::SeqCst);
        assert_eq!(cap_store::get(a.tid, ch(r), CapPerms::READ), Ok(5), "before the deadline");
        assert!(cap_store::with_table(a.tid, |t| t.holds_kind_with(ty::PORT, CapPerms::READ)).unwrap());
        NOW.store(1000, Ordering::SeqCst);
        assert_eq!(cap_store::get(a.tid, ch(r), CapPerms::READ), Err(CapError::Revoked), "at the deadline");
        assert_eq!(cap_store::get(b.tid, ch(b1), CapPerms::READ), Err(CapError::Revoked), "the child inherited it");
        assert_eq!(cap_store::get(a.tid, ch(plain), CapPerms::READ), Ok(6), "no deadline, no expiry");
        // Presence tests do not count it.
        assert!(cap_store::with_table(b.tid, |t| !t.holds_kind_with(ty::PORT, CapPerms::READ)).unwrap());
        // It does not move or copy on.
        let c = wtask(46);
        assert_eq!(dup(&a, &c, r), Err(CapError::Revoked));
        assert_eq!(cap_store::move_cap(a.tid, c.tid, r, None), Err(CapError::Revoked));
        // The cache's view: a word with a deadline grants nothing; one without does.
        let w_exp = cap_store::slot_word(cap_store::table_slot(a.tid).unwrap(), r);
        let w_plain = cap_store::slot_word(cap_store::table_slot(a.tid).unwrap(), plain);
        assert_eq!(crate::cap::CapTable::word_grants(w_exp, r, ty::PORT, CapPerms::READ), None);
        assert_eq!(crate::cap::CapTable::word_grants(w_plain, plain, ty::PORT, CapPerms::READ), Some(6));
    }

    /// A slot's generation never repeats and a domain key's does not within
    /// 65,535 reuses, so a reference to a revoked slot, re-granted before the
    /// sweep ran, is dead; so is one to a domain that was replaced, and a
    /// reference to a replaced domain's slot never names the new domain's.
    /// **Canary.** Ignore the generation in `CapTable::parent_of`: the
    /// re-granted slot looks like the parent and the first assertion goes red;
    /// drop the `OWNER` test in `step_slot`: the third does. (A replaced
    /// domain's wipe is a delete: its descendant stays, hung under the root,
    /// `a_domains_exit_leaves_what_it_shared`.)
    #[test]
    fn a_reused_slot_or_domain_does_not_resurrect_a_descendant() {
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        // Free the parent and give the same slot to another capability in one
        // locked step, with the sweep's duty taken: nothing swept yet.
        let again = cap_store::with_table(a.tid, |t| {
            assert!(t.revoke_raw(r));
            assert!(crate::cap::sweep_take());
            t.grant_raw(ty::PORT, CapPerms::RW_DELEGATE, 5).unwrap()
        })
        .unwrap();
        assert_eq!((again.slot(), again.generation() > r.generation()), (r.slot(), true), "same slot, newer generation");
        crate::cap::sweep_owed();
        cap_store::sweep();
        assert!(!live(&b, b1), "a child of generation g outlived a re-grant at g+1");
        assert!(live(&a, again), "and the new occupant is untouched");
        // A replaced domain: its table is wiped when the new one claims it.
        let c = wtask(46);
        let r2 = root(&a, CapPerms::RW_DELEGATE, 7);
        let c1 = dup(&a, &c, r2).unwrap();
        let a2 = wtask(44); // a new domain at A's table slot
        let _ = cap_store::grant::<Port>(a2.tid, CapPerms::RW_DELEGATE, 7).unwrap(); // the same slot and generation, maybe
        assert!(live(&c, c1), "the previous domain's wipe is a delete: its descendant stays");
        assert_eq!(warrant(&c, c1).parent, 0, "hung under the wiped slot's own parent, a root");
        // A reference to a slot of the previous domain, which the new one holds
        // at the same index and generation: the domain key tells them apart.
        let new_root = cap_store::grant::<Port>(a2.tid, CapPerms::RW_DELEGATE, 8).unwrap().raw();
        let stale_ref = azos_decision::warrant_ref(key(&a) ^ 0x10000, new_root.slot(), new_root.generation());
        assert_ne!(stale_ref, rref(&a2, new_root));
        let orphan = root_with(&c, CapPerms::RW_DELEGATE, 8, Warrant { parent: stale_ref, depth: 1, ..Warrant::ROOT });
        crate::cap::sweep_owed();
        cap_store::sweep();
        assert!(!live(&c, orphan), "a reference to a replaced domain's slot named the new domain's");
        assert!(live(&a2, new_root));
    }

    /// Moving a capability out of a slot that was delegated from does not
    /// revoke what it delegated: the copies follow the capability, hung under
    /// its new slot, so revoking it where it is now still reaches them; the
    /// moved capability keeps its own parent, so revoking an ancestor still
    /// reaches it in the new domain. **Canary.** In `move_locked` grant with
    /// `Warrant::ROOT`: the second half goes red; skip `take_out`'s row: the
    /// first half goes red (the copy is orphaned and swept).
    #[test]
    fn a_move_keeps_the_place_and_what_the_slot_delegated_follows() {
        let _g = wguard();
        let (a, b, c, d) = (wtask(44), wtask(45), wtask(46), wtask(47));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        let moved = cap_store::move_cap(a.tid, c.tid, r, None).unwrap();
        assert!(live(&b, b1), "what the moved slot delegated stays");
        assert!(live(&c, moved));
        assert_eq!(warrant(&b, b1).parent, rref(&c, moved), "under the capability's new slot");
        cap_store::revoke(c.tid, ch(moved));
        assert!(!live(&b, b1), "revoking the moved capability reaches its copies");
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let moved = cap_store::move_cap(a.tid, c.tid, r, None).unwrap();
        // A child moved to another domain is still revoked with its ancestor.
        let c1 = dup(&c, &b, moved).unwrap();
        let d1 = cap_store::move_cap(b.tid, d.tid, c1, None).unwrap();
        assert!(live(&d, d1));
        cap_store::revoke(c.tid, ch(moved));
        assert!(!live(&d, d1), "a moved descendant outlived its ancestor");
    }

    /// A fork's copy of a derived descriptor keeps its place in the tree: the
    /// original's parent and depth, and its deadline. Revoking an ancestor
    /// reaches the copy, and forking sheds neither. **Canary.** In
    /// `install_at` store `Warrant::ROOT` again: the copy survives the revoke
    /// and its deadline is gone, and both assertions go red.
    #[test]
    fn a_fork_copy_stays_under_every_ancestor() {
        let _g = wguard();
        let (a, b, child) = (wtask(44), wtask(45), wtask(46));
        let r = root_with(&a, CapPerms::RW_DELEGATE, 5, Warrant { expiry_ns: 1000, ..Warrant::ROOT });
        let b1 = dup(&a, &b, r).unwrap();
        // The fork: the child's table answers to the very handle, carrying the
        // original's warrant (what `natfork::inherit_one` does).
        let w = warrant(&b, b1);
        assert!(cap_store::with_table(child.tid, |t| t.install_at(b1, 5, &w)).unwrap());
        assert_eq!(warrant(&child, b1), w, "the copy is a sibling: same parent, same depth, same deadline");
        NOW.store(1000, Ordering::SeqCst);
        assert_eq!(cap_store::get(child.tid, ch(b1), CapPerms::READ), Err(CapError::Revoked), "forking sheds no deadline");
        NOW.store(0, Ordering::SeqCst);
        assert_eq!(cap_store::get(child.tid, ch(b1), CapPerms::READ), Ok(5));
        cap_store::revoke(a.tid, ch(r));
        assert!(!live(&b, b1) && !live(&child, b1), "forking escaped a revoke of the ancestor");
    }

    /// The sweep is bounded: at most `WARRANT_DEPTH_MAX + 1` passes, each at
    /// most the tables' slots, and it is exactly that when every link of a chain
    /// sits in a lower table than its parent (a pass clears one level). A wide
    /// tree takes two. **Canary.** Run one pass fewer in `sweep`
    /// (`0..WARRANT_DEPTH_MAX`): the chain keeps its deepest link and the
    /// revoked count goes red.
    #[test]
    fn the_sweep_is_bounded_by_the_depth() {
        let _g = wguard();
        let n = WARRANT_DEPTH_MAX + 1;
        assert!(WARRANT_SLOT0 + n <= azos_sched::task::MAX_TASKS, "the chain needs {n} table slots");
        // Root in the highest table; each link in the next lower one.
        let tasks: Vec<Task> = (0..n).map(|i| wtask(WARRANT_SLOT0 + n - 1 - i)).collect();
        let r = root(&tasks[0], CapPerms::RW_DELEGATE, 5);
        let mut cur = r;
        for i in 1..n {
            cur = dup(&tasks[i - 1], &tasks[i], cur).unwrap();
        }
        cap_store::revoke(tasks[0].tid, ch(r));
        let st = cap_store::last_sweep();
        assert_eq!(st.revoked as usize, WARRANT_DEPTH_MAX, "every link went");
        assert_eq!(st.passes as usize, WARRANT_DEPTH_MAX + 1, "one pass a level, and the pass that finds none");
        assert!(
            (st.examined as usize) <= st.passes as usize * azos_sched::task::MAX_TASKS * crate::cap::MAX_CAPS_PER_TASK,
            "the work is bounded by passes x tables x slots"
        );
        assert!(tasks.iter().skip(1).all(|t| cap_store::occupied(t.tid) == 0));
        // Wide: one root, every other slot of a table derived from it.
        let (a, b) = (wtask(44), wtask(45));
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let width = crate::cap::MAX_CAPS_PER_TASK.min(100);
        for _ in 0..width {
            dup(&a, &b, r).unwrap();
        }
        cap_store::revoke(a.tid, ch(r));
        let st = cap_store::last_sweep();
        assert_eq!((st.revoked as usize, st.passes), (width, 2), "a wide tree is one pass and the confirming one");
        assert_eq!(cap_store::occupied(b.tid), 0);
    }

    /// Every derive and every revoke writes a decision record naming the
    /// capability, its parent and the domain, in the provenance form too.
    /// **Canary.** Remove the `Rule::CapDerive` record in `move_caps_locked`:
    /// the derive assertions go red; remove the one in `sweep`: the descendant
    /// assertion goes red; remove the one in `revoke`: the direct one.
    #[test]
    fn derive_and_revoke_are_recorded_with_their_provenance() {
        use azos_decision::{ProvenanceRecord, Rule};
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        let before = azos_decision::total();
        let r = root(&a, CapPerms::RW_DELEGATE, 5);
        let b1 = dup(&a, &b, r).unwrap();
        cap_store::revoke(a.tid, ch(r));
        let mut recs = Vec::new();
        azos_decision::for_each(|x| {
            if x.seq > before {
                recs.push(*x);
            }
        });
        let find = |rule: Rule, subject: u32| recs.iter().find(|x| x.rule == rule as u8 && x.subject == subject).copied();
        let d = find(Rule::CapDerive, key(&b)).expect("the derive left a record");
        assert_eq!((d.n[0], d.n[1]), (rref(&b, b1), rref(&a, r)), "the copy and the warrant it came from");
        let p = ProvenanceRecord::from_record(&d);
        assert_eq!((p.cap_slot[0], p.parent_cap[0]), (rref(&b, b1), rref(&a, r)));
        let direct = find(Rule::CapRevoke, key(&a)).expect("the revoke left a record");
        assert_eq!((direct.n[0], direct.n[1], direct.n[2]), (rref(&a, r), 0, 0), "a root, revoked directly");
        let desc = find(Rule::CapRevoke, key(&b)).expect("so did the descendant it took");
        assert_eq!((desc.n[0], desc.n[1], desc.n[2]), (rref(&b, b1), rref(&a, r), 1), "revoked as a descendant of the root");
    }

    // ── Weak warrants (owner decision 16-10) ──────────────────────────────
    //
    // A weak warrant, and everything derived from it, resolves read-only; the
    // bit survives every derive; a table marked weak (a `shadow = true` row's
    // task) makes everything granted into it weak; a use the mask refuses is a
    // `Rule::ShadowRefusal` record.

    /// The shadow-refusal records written after sequence `since`.
    fn shadow_records(since: u64) -> Vec<azos_decision::Record> {
        let mut v = Vec::new();
        azos_decision::for_each(|x| {
            if x.seq > since && x.rule == azos_decision::Rule::ShadowRefusal as u8 {
                v.push(*x);
            }
        });
        v
    }

    /// A weak root holds the rights it was granted and resolves with `READ`
    /// alone; the same grant strong is unchanged. **Canary.** Drop the `keep`
    /// mask in `slot_word::perms` (abi), or the `WEAK` bit in `hot_flags`
    /// (`canary_weak_drops_mask`, next test): the write assertions go red.
    #[test]
    fn a_weak_root_resolves_read_only_and_a_refused_write_is_recorded() {
        let _g = wguard();
        let a = wtask(44);
        let weak = root_with(&a, CapPerms::RW_DELEGATE, 5, Warrant::WEAK_ROOT);
        let strong = root(&a, CapPerms::RW_DELEGATE, 6);
        assert!(warrant(&a, weak).is_weak() && !warrant(&a, strong).is_weak());
        assert_eq!(cap_store::get(a.tid, ch(weak), CapPerms::READ), Ok(5));
        assert_eq!(cap_store::get(a.tid, ch(strong), CapPerms::WRITE), Ok(6), "a strong slot is untouched");
        let held = cap_store::with_table(a.tid, |t| t.peek_raw(weak)).flatten().unwrap();
        assert_eq!(held.1, CapPerms::READ, "the table reports what the slot resolves with");

        let before = azos_decision::total();
        assert_eq!(cap_store::get(a.tid, ch(weak), CapPerms::WRITE), Err(CapError::MissingPerms));
        assert_eq!(cap_store::get(a.tid, ch(weak), CapPerms::DUP), Err(CapError::MissingPerms), "no DUP: not delegable");
        assert_eq!(cap_store::get(a.tid, ch(strong), CapPerms::WRITE), Ok(6));
        // Two refusals the mask caused: counts 1 and 2 are both records.
        let recs = shadow_records(before);
        assert_eq!(recs.len(), 2, "{recs:?}");
        let w = recs[0].n[2];
        assert_eq!(recs[0].n[0], azos_decision::Rule::CapDenial as u64, "the rule that would have refused");
        assert_eq!((w & 0xff, (w >> 16) & 0xffff, w >> 32), (CapPerms::WRITE.bits() as u64, weak.slot() as u64, 1));
        assert_eq!(recs[1].n[2] >> 32, 2);
        // A loop does not flood the ring: counts 3 and 4 add one record (4).
        for _ in 0..2 {
            let _ = cap_store::get(a.tid, ch(weak), CapPerms::WRITE);
        }
        assert_eq!(shadow_records(before).len(), 3);
    }

    /// A refusal the holder would have had anyway is no shadow refusal: the
    /// record says what the mask took away.
    #[test]
    fn a_weak_slot_that_never_had_write_records_nothing() {
        let _g = wguard();
        let a = wtask(44);
        let ro = root_with(&a, CapPerms::READ, 5, Warrant::WEAK_ROOT);
        let before = azos_decision::total();
        assert_eq!(cap_store::get(a.tid, ch(ro), CapPerms::WRITE), Err(CapError::MissingPerms));
        assert!(shadow_records(before).is_empty());
    }

    /// Canary: with the weak bit left out of the published word the slot keeps
    /// the rights it was granted. The test above fails the same way; this one
    /// shows the canary is what does it.
    #[test]
    fn the_canary_that_drops_the_mask_lets_a_write_through() {
        let _g = wguard();
        let a = wtask(44);
        crate::cap::canary_weak_drops_mask(true);
        let weak = root_with(&a, CapPerms::RW, 5, Warrant::WEAK_ROOT);
        let leaked = cap_store::get(a.tid, ch(weak), CapPerms::WRITE);
        crate::cap::canary_weak_drops_mask(false);
        assert_eq!(leaked, Ok(5), "the canary did not discriminate");
        let weak = root_with(&a, CapPerms::RW, 6, Warrant::WEAK_ROOT);
        assert_eq!(cap_store::get(a.tid, ch(weak), CapPerms::WRITE), Err(CapError::MissingPerms));
    }

    /// Every link below a weak root is weak, whatever the derive asks for, and
    /// no request clears the bit.
    #[test]
    fn a_derive_chain_from_a_weak_warrant_stays_weak() {
        use crate::cap::{derive_warrant, narrow_warrant, DeriveSpec};
        let mut w = Warrant::WEAK_ROOT;
        let mut perms = CapPerms::ALL;
        for (i, spec) in [
            DeriveSpec::SAME,
            DeriveSpec { rights: Some(CapPerms::RW), ..DeriveSpec::SAME },
            DeriveSpec { expiry_ns: 9_000, ..DeriveSpec::SAME },
            DeriveSpec { quota: Quota { bytes: false, amount: 4 }, ..DeriveSpec::SAME },
        ]
        .into_iter()
        .enumerate()
        {
            let (p, d) = derive_warrant(0x1000 + i as u64, perms, &w, &spec).unwrap();
            assert!(d.is_weak(), "link {i} lost the bit");
            assert_eq!(d.depth as usize, i + 1);
            let (_, n) = narrow_warrant(p, &d, &DeriveSpec::SAME).unwrap();
            assert!(n.is_weak(), "a move lost the bit");
            (perms, w) = (p, d);
        }
        // The last link, published in a table, resolves read-only.
        let _g = wguard();
        let a = wtask(44);
        let h = root_with(&a, perms, 7, w);
        assert!(warrant(&a, h).is_weak());
        assert_eq!(cap_store::get(a.tid, ch(h), CapPerms::READ), Ok(7));
        assert_eq!(cap_store::get(a.tid, ch(h), CapPerms::WRITE), Err(CapError::MissingPerms));
        // Rights a weak slot resolves without cannot be asked for.
        let (src, weak) = (CapPerms::READ, Warrant::WEAK_ROOT);
        assert_eq!(derive_warrant(1, src, &weak, &DeriveSpec { rights: Some(CapPerms::WRITE), ..DeriveSpec::SAME }), Err(CapError::MissingPerms));
    }

    /// A task admitted from a `shadow = true` row (its table marked before the
    /// row is seeded): every minter's grant is weak, a strong capability moved in turns weak, a weak one cannot
    /// be handed on, and the mark dies with the table.
    #[test]
    fn a_shadow_tasks_table_makes_every_grant_weak() {
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        let early = root(&a, CapPerms::RW_DELEGATE, 1);
        assert!(!cap_store::mark_weak(a.tid), "a table that holds something is not marked");
        cap_store::revoke(a.tid, ch(early));
        assert!(cap_store::mark_weak(a.tid));
        let first = root(&a, CapPerms::RW_DELEGATE, 1);
        assert_eq!(cap_store::get(a.tid, ch(first), CapPerms::READ), Ok(1));
        let before = azos_decision::total();
        assert_eq!(cap_store::get(a.tid, ch(first), CapPerms::WRITE), Err(CapError::MissingPerms));
        // The first refusal is recorded under the shadow task's TID, a Refuse.
        let recs = shadow_records(before);
        assert_eq!(recs.iter().map(|r| (r.subject, r.verdict)).collect::<Vec<_>>(), vec![(a.tid, azos_decision::Verdict::Refuse as u8)]);
        let seeded = root(&a, CapPerms::RW_DELEGATE, 2);
        let badged: Cap<Port> = cap_store::grant_badged(a.tid, CapPerms::RW, 3, 9).unwrap();
        for (h, res) in [(seeded, 2), (badged.raw(), 3)] {
            assert!(warrant(&a, h).is_weak());
            assert_eq!(cap_store::get(a.tid, ch(h), CapPerms::READ), Ok(res));
            assert_eq!(cap_store::get(a.tid, ch(h), CapPerms::WRITE), Err(CapError::MissingPerms));
        }
        // A strong holder's capability, lent into the shadow task, is weak there.
        let theirs = root(&b, CapPerms::RW_DELEGATE, 4);
        let lent = dup(&b, &a, theirs).unwrap();
        assert!(warrant(&a, lent).is_weak());
        assert_eq!(cap_store::get(a.tid, ch(lent), CapPerms::WRITE), Err(CapError::MissingPerms));
        assert_eq!(cap_store::get(b.tid, ch(theirs), CapPerms::WRITE), Ok(4), "the lender keeps its own");
        // Nothing weak leaves the table.
        assert_eq!(dup(&a, &b, seeded), Err(CapError::MissingPerms));
        // The next owner of the table is strong.
        cap_store::reset(a.tid);
        let c = wtask(44);
        let fresh = root(&c, CapPerms::RW, 8);
        assert!(!warrant(&c, fresh).is_weak());
        assert_eq!(cap_store::get(c.tid, ch(fresh), CapPerms::WRITE), Ok(8));
        assert!(!cap_store::mark_weak(0), "no task, no mark");
    }

    /// A shadow task's slot is released as the right it was granted: the
    /// revoke event and the stored view carry the permissions as granted,
    /// while the authority view (`peek_raw`) carries the masked ones.
    #[test]
    fn a_weak_slot_is_released_as_the_right_it_was_granted() {
        use std::sync::Mutex as M;
        static EVENTS: M<Vec<cap_store::CapEvent>> = M::new(Vec::new());
        fn hook(e: cap_store::CapEvent) {
            EVENTS.lock().unwrap().push(e);
        }
        let _g = wguard();
        let a = wtask(44);
        assert!(cap_store::mark_weak(a.tid));
        let grant = |perms, res| {
            cap_store::with_table(a.tid, |t| t.grant_warranted(ty::SOCKET, perms, res, CapExt::NONE, Warrant::ROOT))
                .flatten()
                .unwrap()
        };
        let (wend, wr_only) = (grant(CapPerms::WRITE, 9), grant(CapPerms::RW, 11));
        let (masked, stored) = cap_store::with_table(a.tid, |t| (t.peek_raw(wend), t.peek_stored(wend))).unwrap();
        assert_eq!(masked.unwrap().1, CapPerms::NONE, "authority: a weak write end holds nothing");
        assert_eq!(stored.unwrap().1, CapPerms::WRITE, "bookkeeping: it is still a write end");
        assert_eq!(wend.perms(), CapPerms::WRITE, "the handle names what was granted");

        // The revoke event names the end that went.
        cap_store::set_cap_event_hook(hook);
        EVENTS.lock().unwrap().clear();
        assert!(cap_store::delete_moved(a.tid, wr_only));
        cap_store::set_cap_event_hook(|_| {});
        let ev = EVENTS.lock().unwrap().clone();
        assert_eq!(
            ev.iter().filter_map(|e| match e {
                cap_store::CapEvent::Revoked { kind, perms, resource, .. } => Some((*kind, *perms, *resource)),
                _ => None,
            }).collect::<Vec<_>>(),
            vec![(ty::SOCKET, CapPerms::RW, 11)]
        );
    }

    /// An endpoint send that misses the cached word falls to the full
    /// resolve, and the full resolve records the refusal. The word of a weak
    /// slot grants nothing (so the send cache never holds it), `get` refuses
    /// and writes the `ShadowRefusal`; a strong slot's word grants.
    /// **Canary.** Remove the `shadow_refusal` call in `get_uncontained`: the
    /// record count goes red.
    #[test]
    fn a_send_the_cached_word_declines_is_recorded_by_the_full_resolve() {
        use crate::cap::targets::Endpoint;
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        assert!(cap_store::mark_weak(a.tid));
        let weak: Cap<Endpoint> = cap_store::grant(a.tid, CapPerms::RW, 3).unwrap();
        let strong: Cap<Endpoint> = cap_store::grant(b.tid, CapPerms::RW, 3).unwrap();
        let word = |t: &Task, c: Cap<Endpoint>| cap_store::slot_word(cap_store::table_of(t.tid).unwrap(), c.raw());
        let grants = |t: &Task, c: Cap<Endpoint>| crate::cap::CapTable::word_grants(word(t, c), c.raw(), ty::ENDPOINT, CapPerms::WRITE);
        assert_eq!(grants(&b, strong), Some(3), "a strong slot's word grants the send");
        assert_eq!(grants(&a, weak), None, "a weak slot's word does not");
        let before = azos_decision::total();
        assert_eq!(cap_store::get(a.tid, weak, CapPerms::WRITE), Err(CapError::MissingPerms));
        let recs = shadow_records(before);
        assert_eq!(recs.len(), 1, "the fall-through recorded it: {recs:?}");
        assert_eq!(recs[0].subject, a.tid);
        let w = recs[0].n[2];
        assert_eq!((w & 0xff) as u8, CapPerms::WRITE.bits());
        assert_eq!(((w >> 8) & 0xff) as u8, ty::ENDPOINT.raw());
        assert_eq!(cap_store::get(b.tid, strong, CapPerms::WRITE), Ok(3));
        assert_eq!(shadow_records(before).len(), 1, "a strong holder is not a shadow refusal");
    }

    /// The presence queries record the refusal the mask caused, once per
    /// query, under the shadow task's TID; a query a strong table fails, or
    /// one the slot would have failed anyway, records nothing.
    /// **Canary.** Delete the `refused_by_mask` tail of `holds_kind_with`: the
    /// first count goes red.
    #[test]
    fn a_presence_query_a_weak_slot_fails_is_recorded() {
        let _g = wguard();
        let (a, b) = (wtask(44), wtask(45));
        assert!(cap_store::mark_weak(a.tid));
        let grant = |t: &Task, kind, perms, res| {
            cap_store::with_table(t.tid, |tb| tb.grant_warranted(kind, perms, res, CapExt::NONE, Warrant::ROOT)).flatten().unwrap()
        };
        let _w = grant(&a, ty::FILE, CapPerms::RW, 6);
        let _ro = grant(&a, ty::SOCKET, CapPerms::READ, 7);
        let _s = grant(&b, ty::FILE, CapPerms::READ, 6);
        let before = azos_decision::total();
        let holds = |t: &Task, f: &dyn Fn(&crate::cap::CapTable) -> bool| cap_store::with_table(t.tid, |tb| f(tb)).unwrap();

        assert!(holds(&a, &|t| t.holds_kind_with(ty::FILE, CapPerms::READ)), "READ survives the mask");
        assert!(shadow_records(before).is_empty(), "a granted query records nothing");
        assert!(!holds(&a, &|t| t.holds_kind_with(ty::FILE, CapPerms::WRITE)));
        assert_eq!(shadow_records(before).len(), 1, "holds_kind_with (count 1)");
        assert!(!holds(&a, &|t| t.holds_kind_resource_with(ty::FILE, 6, CapPerms::WRITE)));
        assert_eq!(shadow_records(before).len(), 2, "holds_kind_resource_with (count 2)");
        assert!(!holds(&a, &|t| t.holds_kind_resource_uncontained(ty::FILE, 6, CapPerms::WRITE)));
        assert_eq!(shadow_records(before).len(), 2, "holds_kind_resource_uncontained (count 3 is not a record)");
        assert!(!holds(&a, &|t| t.holds_kind_where(ty::FILE, CapPerms::WRITE, |r| r == 6)));
        assert_eq!(shadow_records(before).len(), 3, "holds_kind_where (count 4)");
        // The slot never had the right: the mask did not refuse it, no record.
        let n = shadow_records(before).len();
        for _ in 0..4 {
            assert!(!holds(&a, &|t| t.holds_kind_with(ty::SOCKET, CapPerms::WRITE)));
        }
        assert_eq!(shadow_records(before).len(), n);
        // A strong table that fails the same query records nothing either.
        assert!(!holds(&b, &|t| t.holds_kind_with(ty::FILE, CapPerms::WRITE)));
        assert_eq!(shadow_records(before).len(), n);
        for r in shadow_records(before) {
            assert_eq!(r.subject, a.tid);
        }
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
        use crate::cap::{targets::Socket, Cap, CapError, CapTable, MAX_CAPS_PER_TASK};
        use azos_abi::cap::{CapHandle, CapPerms, ty};
        let t = CapTable::empty();
        let h = t.grant_raw(ty::SOCKET, CapPerms::READ, 7).unwrap();
        // The same handle with its slot moved past the table (the 9-bit
        // field reaches 511; the table holds `MAX_CAPS_PER_TASK`).
        let past = CapHandle::pack(ty::SOCKET, CapPerms::READ, h.generation(),
                                   (MAX_CAPS_PER_TASK as u16).min(511));
        if (past.slot() as usize) < MAX_CAPS_PER_TASK { return; } // a 512-slot table
        let cap: Cap<Socket> = Cap::from_raw(past);
        assert_eq!(t.get(cap, CapPerms::READ), Err(CapError::Stale));
        assert!(t.peek_raw(past).is_none());
        assert!(!t.revoke_raw(past));
        assert_eq!(t.get(Cap::<Socket>::from_raw(h), CapPerms::READ), Ok(7));
    }
}
