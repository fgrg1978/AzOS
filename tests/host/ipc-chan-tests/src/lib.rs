// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side runner for `crates/core/ipc/src/{channel,pipe,signal}.rs`.
//!
//! The kernel `azos_ipc` crate cannot be compiled for the host (it pulls
//! in `azos_drv_*` / `azos_sched`, which are RV64-only). The three
//! modules audited in this lane are pure pool manipulation once two things
//! are stood in for:
//!
//!  * **`azos_sync::SpinLock`** — the real one calls `azos_arch::csr`
//!    (`crates/core/sync/src/spinlock.rs:15`) to save/restore `sstatus.SIE`, which
//!    does not exist off RISC-V. `shims/sync` provides the same API
//!    (`const fn new`, `lock`, `lock_irqsave`, `Deref`/`DerefMut` guard) over
//!    a `std::sync::Mutex` under the same *library* name, so the modules
//!    compile unmodified. Mutual exclusion semantics match; only the IRQ
//!    discipline is absent, and nothing under test depends on it.
//!  * **Caller identity** — `current_task_tid()` / `current_user_pt()` live in
//!    `azos_sched`. Each module has a `#[cfg(test)] mod test_ctx` shim
//!    (compiled *only* here, never into the kernel) that drives the identity
//!    from atomics, so a test can say "now I am ring-3 task 7".
//!
//! Everything else — the pools, the ownership fields, the bounds checks — is
//! the real kernel source, byte for byte.
//!
//! Run with:  `cd tests/host/ipc-chan-tests && cargo test`

// `cap.rs` carries `#[cfg(kani)]` proof harnesses for the model checker; that
// cfg is unknown to plain cargo and would otherwise warn on every build.
#![allow(unexpected_cfgs)]

// ---------------------------------------------------------------------------
// The modules under test
// ---------------------------------------------------------------------------

// `channel.rs` references `crate::cap` for the typed `Cap<Channel>` path, so
// cap.rs comes along. Its own embedded suite (also run by `tests/host/cap-tests`)
// therefore executes here too; those tests are not part of this lane's count.
#[path = "../../../../crates/core/ipc/src/cap.rs"]
pub mod cap;

// `cap.rs` declares `objref`, whose minter reaches the per-task tables through
// `crate::cap_store`, so the table module comes along. Its behaviour is
// tested in `tests/host/cap-tests`, not here.
#[path = "../../../../crates/core/ipc/src/cap_store.rs"]
pub mod cap_store;

#[path = "../../../../crates/core/ipc/src/channel.rs"]
pub mod channel;

// The link a channel bound to an event port stores (wave 11, PORTWAIT).
#[path = "../../../../crates/core/ipc/src/port_link.rs"]
pub mod port_link;

/// Host stand-in for the one `crates/core/ipc/src/port.rs` entry `channel.rs`
/// calls after a send on a linked channel. The real port table is tested in
/// `tests/host/ipc-lease-tests`; here each signal is recorded, and the answer
/// ("the port still answers to this link") is settable, so the channel side
/// — signal after the send, clear a dead link — is what these tests pin.
pub mod port {
    use crate::port_link::PortLink;
    use std::sync::Mutex;

    pub static SIGNALS: Mutex<Vec<(PortLink, u32)>> = Mutex::new(Vec::new());
    pub static ANSWER_LIVE: Mutex<bool> = Mutex::new(true);

    /// Record `(link, channel_ref)`; answer the settable liveness.
    pub fn port_signal_channel(link: PortLink, channel_ref: u32) -> bool {
        SIGNALS.lock().unwrap_or_else(|e| e.into_inner()).push((link, channel_ref));
        *ANSWER_LIVE.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drain the recorded signals and answer live again.
    pub fn take_signals() -> Vec<(PortLink, u32)> {
        *ANSWER_LIVE.lock().unwrap_or_else(|e| e.into_inner()) = true;
        std::mem::take(&mut *SIGNALS.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

#[path = "../../../../crates/core/ipc/src/pipe.rs"]
pub mod pipe;

#[path = "../../../../crates/core/ipc/src/signal.rs"]
pub mod signal;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

#[cfg(test)]
mod harness {
    use std::sync::Mutex;

    /// All three modules keep their state in `static` pools, and
    /// `cargo test` runs tests on parallel threads. Every test takes this
    /// lock and starts from a wiped pool, so one test can never observe
    /// another's channels/pipes/signal entries. Reset-without-serialize
    /// (the shape `zerocopy.rs` used before it was deleted, U04-7) is not
    /// enough here, with a shared global pool.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    pub struct Guard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    /// Serialize, wipe all three pools, and start as "kernel task, tid 0".
    pub fn begin() -> Guard {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        crate::channel::__channel_reset_for_tests();
        crate::pipe::__pipe_reset_for_tests();
        crate::signal::__signal_reset_for_tests();
        as_kernel();
        Guard(g)
    }

    /// Become ring-3 task `tid`.
    pub fn as_user(tid: u32) {
        crate::channel::test_ctx::set(tid, false);
        crate::pipe::test_ctx::set(tid, false);
        crate::signal::test_ctx::set(tid, false);
    }

    /// Become a kernel task (`user_pt == 0` ⇒ privileged bypass).
    pub fn as_kernel() {
        crate::channel::test_ctx::set(0, true);
        crate::pipe::test_ctx::set(0, true);
        crate::signal::test_ctx::set(0, true);
    }
}

// ---------------------------------------------------------------------------
// channel.rs
// ---------------------------------------------------------------------------

#[cfg(test)]
mod channel_tests {
    use crate::channel::*;
    use crate::harness::{as_kernel, as_user, begin};

    const OWNER: u32 = 11;
    const STRANGER: u32 = 22;

    /// Create `n` channels as ring-3 task `tid`.
    fn create_as(tid: u32, n: usize) -> Vec<usize> {
        as_user(tid);
        (0..n)
            .map(|i| channel_create().unwrap_or_else(|| panic!("create #{i} failed")))
            .collect()
    }

    // ── Ownership: the decision ──────────────────────────────────────────

    #[test]
    fn create_records_the_calling_tid_as_owner() {
        let _g = begin();
        for ch in create_as(OWNER, 4) {
            assert_eq!(channel_owner(ch), Some(OWNER), "ch {ch}");
        }
    }

    #[test]
    fn owner_of_a_free_slot_is_none() {
        let _g = begin();
        assert_eq!(channel_owner(0), None);
        assert_eq!(channel_owner(MAX_CHANNELS - 1), None);
    }

    // ── Ownership: the action (both halves, over several ids) ────────────

    #[test]
    fn owner_receives_what_was_sent() {
        let _g = begin();
        for ch in create_as(OWNER, 4) {
            as_user(OWNER);
            assert_eq!(channel_send(ch, b"ping"), 0);
            let mut buf = [0u8; 16];
            assert_eq!(channel_recv(ch, &mut buf), 4, "ch {ch}");
            assert_eq!(&buf[..4], b"ping");
        }
    }

    #[test]
    fn stranger_cannot_receive_on_any_id() {
        let _g = begin();
        let chans = create_as(OWNER, 4);
        for &ch in &chans {
            as_user(OWNER);
            assert_eq!(channel_send(ch, b"secret"), 0);
        }
        // A third party sweeps every id it can think of, not just the ones
        // it happens to know about.
        as_user(STRANGER);
        for ch in 0..MAX_CHANNELS {
            let mut buf = [0u8; 16];
            assert_eq!(channel_recv(ch, &mut buf), -1, "stranger drained ch {ch}");
            assert_eq!(buf, [0u8; 16], "stranger read bytes out of ch {ch}");
        }
        // ...and the messages are all still there for the rightful owner.
        as_user(OWNER);
        for &ch in &chans {
            let mut buf = [0u8; 16];
            assert_eq!(channel_recv(ch, &mut buf), 6, "ch {ch} lost its message");
            assert_eq!(&buf[..6], b"secret");
        }
    }

    #[test]
    fn kernel_bypasses_the_owner_check() {
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(channel_send(ch, b"kmsg"), 0);
        // House convention: current_user_pt() == 0 ⇒ privileged.
        as_kernel();
        let mut buf = [0u8; 16];
        assert_eq!(channel_recv(ch, &mut buf), 4);
        assert_eq!(&buf[..4], b"kmsg");
    }

    /// Pins the `owner == 0` sentinel reasoning documented on
    /// `Channel::owner`: a channel created before any task exists (or by the
    /// idle context) records owner 0, and `current_task_tid()` never returns
    /// 0 for a live task — so ring 3 is denied by construction rather than by
    /// an explicit "is it zero" branch.
    #[test]
    fn kernel_created_channel_denies_ring3_by_sentinel() {
        let _g = begin();
        as_kernel(); // tid 0 — the "no current task" value
        let ch = channel_create().unwrap();
        assert_eq!(channel_owner(ch), Some(0));
        assert_eq!(channel_send(ch, b"boot"), 0);

        for tid in [1u32, 22, u32::MAX] {
            as_user(tid);
            let mut buf = [0u8; 8];
            assert_eq!(channel_recv(ch, &mut buf), -1, "tid {tid} drained it");
            assert_eq!(channel_destroy(ch), -1, "tid {tid} destroyed it");
        }
        as_kernel();
        let mut buf = [0u8; 8];
        assert_eq!(channel_recv(ch, &mut buf), 4);
    }

    #[test]
    fn stranger_cannot_destroy_but_owner_and_kernel_can() {
        let _g = begin();
        let chans = create_as(OWNER, 3);

        as_user(STRANGER);
        for &ch in &chans {
            assert_eq!(channel_destroy(ch), -1, "stranger destroyed ch {ch}");
            assert_eq!(channel_owner(ch), Some(OWNER), "ch {ch} survived?");
        }

        as_user(OWNER);
        assert_eq!(channel_destroy(chans[0]), 0);
        assert_eq!(channel_owner(chans[0]), None);

        as_kernel();
        assert_eq!(channel_destroy(chans[1]), 0);
        assert_eq!(channel_owner(chans[1]), None);
    }

    #[test]
    fn recycled_slot_denies_the_previous_owner() {
        let _g = begin();
        // Owner creates, then gives the channel back.
        let ch = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(channel_destroy(ch), 0);

        // A different task grabs the freed slot.
        as_user(STRANGER);
        let ch2 = channel_create().unwrap();
        assert_eq!(ch2, ch, "expected the freed slot to be reused");

        // The stale id in the previous owner's hand is now inert: the slot has
        // a DIFFERENT owner. (An index recycled by the SAME owner passes this
        // compare; `generation` is what tells those incarnations apart — see
        // `the_typed_create_and_destroy_go_through_the_generation`.)
        as_user(OWNER);
        let mut buf = [0u8; 8];
        assert_eq!(channel_recv(ch, &mut buf), -1);
        assert_eq!(channel_destroy(ch), -1);
    }

    /// Ring 3 sends only through a `Cap<Channel>` with `WRITE`.
    ///
    /// Until RFC-0040 gap 1 this test was `send_is_open_to_non_owners_by_design`
    /// and pinned `channel_send`'s open door: `SYS_IPC_SEND`, `SYS_CHAN_WRITE`
    /// and `SYS_IPC_CALL` sent by index for any task. Those numbers are retired
    /// and `channel_send` keeps only kernel callers (`domains/robot/bench`), so the
    /// property that replaces it is the typed send's: a table that does not
    /// name the channel, or names it without `WRITE`, queues nothing.
    ///
    /// **Canary.** Resolve `channel_send_cap` with `READ`: the READ-only send
    /// succeeds.
    #[test]
    fn a_send_from_ring3_needs_a_channel_capability_with_write() {
        use crate::cap::{targets::Channel, Cap, CapError, CapPerms, CapTable};
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        let r = channel_ref(ch).expect("live");
        let stranger = CapTable::empty();
        let ro: Cap<Channel> = stranger.grant(CapPerms::READ, r).unwrap();
        let rw: Cap<Channel> = stranger.grant(CapPerms::RW, r).unwrap();
        let empty = CapTable::empty();

        as_user(STRANGER);
        assert_eq!(channel_send_cap(&empty, rw, b"x"), Err(STALE), "a table that does not name it");
        assert_eq!(
            channel_send_cap(&stranger, ro, b"x"),
            Err(ChannelCapError::Cap(CapError::MissingPerms)),
            "a READ-only capability"
        );
        as_user(OWNER);
        let mut buf = [0u8; 16];
        assert_eq!(channel_recv(ch, &mut buf), 0, "nothing was queued");

        as_user(STRANGER);
        assert_eq!(channel_send_cap(&stranger, rw, b"typed"), Ok(()));
        as_user(OWNER);
        assert_eq!(channel_recv(ch, &mut buf), 5);
    }

    /// Owner decision 2026-09-26 (O3.3): containment stops DEVICE writes, not
    /// messages. `channel_send_cap` resolves `get_uncontained`, so a safety
    /// monitor's outbound report over a channel succeeds even while RFC-0036
    /// degraded-mode containment is armed — the same moment a plain `WRITE`
    /// capability of any other kind, resolved the ordinary way through `get`,
    /// is refused `Contained`. The channel INTO a driver task is itself an
    /// actuation path, contained at the driver's own device capability
    /// instead (not exercised here — no device cap in this crate's pull-in —
    /// see `cap::tests::degraded_mode_contains_writes` for that half).
    ///
    /// **RED before this change.** `channel_send_cap` used to resolve `get`
    /// (contained), so the first assertion below answered `Err(Contained)`.
    ///
    /// **Canary.** Resolve `channel_send_cap` through `get` instead of
    /// `get_uncontained`: the first assertion fails with `Contained`.
    #[test]
    fn containment_does_not_stop_a_channel_send() {
        use crate::cap::{degrade_level_set, targets::{Channel, Motor}, Cap, CapError, CapPerms, CapTable, DEGRADE_LEVEL_CONTAINED};
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        let r = channel_ref(ch).expect("live");
        let monitor = CapTable::empty();
        let report: Cap<Channel> = monitor.grant(CapPerms::RW, r).unwrap();
        // Any ordinary WRITE capability, standing in for a device write:
        // containment is generic in `cap.rs` over the kind, so this alone is
        // the contrast case, without needing a real device cap in this crate.
        let device: Cap<Motor> = monitor.grant(CapPerms::WRITE, 0).unwrap();

        degrade_level_set(DEGRADE_LEVEL_CONTAINED);
        as_user(OWNER);
        assert_eq!(
            channel_send_cap(&monitor, report, b"e-stop tripped"),
            Ok(()),
            "the outbound report is not contained"
        );
        assert_eq!(
            monitor.get(device, CapPerms::WRITE),
            Err(CapError::Contained),
            "precondition: an ordinary device write IS contained"
        );
        degrade_level_set(crate::cap::DEGRADE_LEVEL_FULL);
    }

    /// The typed path must NOT be subject to the legacy owner gate: a cap is
    /// minted by the kernel for a grantee who is by construction not the
    /// creator (the boot seed, `cap_seed`'s Channel arm).
    #[test]
    fn typed_cap_recv_bypasses_the_owner_gate() {
        use crate::cap::{targets::Channel, Cap, CapPerms, CapTable};
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(channel_send(ch, b"typed"), 0);

        // The capability stores the packed (index, generation), RFC-0040 gap 1.
        let r = channel_ref(ch).expect("live");
        let table = CapTable::empty();
        let cap: Cap<Channel> = table.grant(CapPerms::RW, r).unwrap();

        // Grantee is a completely different task.
        as_user(STRANGER);
        let mut buf = [0u8; 16];
        let n = channel_recv_cap(&table, cap, &mut buf).expect("cap recv denied");
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"typed");
    }

    const STALE: ChannelCapError = ChannelCapError::Cap(crate::cap::CapError::Stale);

    /// (1) A `Cap<Channel>` stores the packed `(index, generation)` of the
    /// channel it was granted on (RFC-0040 gap 1). After that channel is
    /// destroyed and another task's channel takes the index, the old capability
    /// answers `Stale` for send and receive in every table that holds it, and
    /// the new channel is untouched.
    ///
    /// Until gap 1 this test was `stale_channel_cap_reaches_a_recreated_index`
    /// and pinned the opposite: the capability stored the bare index, so the
    /// grantee's stale capability wrote into and read out of the stranger's
    /// channel.
    ///
    /// **Canary.** Drop `pool.channels[i].generation != g` from `live_index`:
    /// the stale send reads `Ok(())`.
    #[test]
    fn stale_channel_cap_is_stale_after_its_index_is_recreated() {
        use crate::cap::{targets::Channel, Cap, CapPerms, CapTable};
        const GRANTEE: u32 = 77;
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        let old = channel_ref(ch).expect("precondition: active");

        let table = CapTable::empty();
        let cap: Cap<Channel> = table.grant(CapPerms::RW, old).unwrap();
        let second = CapTable::empty();
        let cap2: Cap<Channel> = second.grant(CapPerms::RW, old).unwrap();

        as_user(OWNER);
        assert_eq!(channel_destroy(ch), 0);
        let recreated = create_as(STRANGER, 1)[0];
        assert_eq!(recreated, ch, "precondition: the index was recycled");
        let new = channel_ref(ch).expect("precondition: active");
        assert_ne!(new, old, "precondition: a different incarnation");

        as_user(GRANTEE);
        assert_eq!(channel_send_cap(&table, cap, b"stale"), Err(STALE), "stale send");
        assert_eq!(channel_send_cap(&second, cap2, b"stale"), Err(STALE), "a second table");

        as_user(STRANGER);
        assert_eq!(channel_send(ch, b"mine"), 0);
        as_user(GRANTEE);
        let mut buf = [0u8; 16];
        assert_eq!(channel_recv_cap(&table, cap, &mut buf), Err(STALE), "stale recv");
        assert_eq!(channel_recv_cap(&second, cap2, &mut buf), Err(STALE), "a second table");
        assert_eq!(buf, [0u8; 16], "nothing was copied");

        as_user(STRANGER);
        assert_eq!(channel_recv(ch, &mut buf), 4, "the stranger's channel kept its message");
        assert_eq!(&buf[..4], b"mine");
    }

    /// (2) A kernel-context destroy (the owner-gate bypass) stales a holder's
    /// capability without any revoke: the slot is free and its generation 0.
    ///
    /// Canary note: keeping the generation across `Channel::zeroed()` does not
    /// discriminate here, by construction — `live_index` also requires the
    /// slot to be active, and a reused slot draws a new generation. The
    /// generation compare itself is (1)'s canary.
    #[test]
    fn a_kernel_destroy_stales_a_holder() {
        use crate::cap::{targets::Channel, Cap, CapPerms, CapTable};
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        let r = channel_ref(ch).unwrap();
        let table = CapTable::empty();
        let cap: Cap<Channel> = table.grant(CapPerms::RW, r).unwrap();
        as_kernel();
        assert_eq!(channel_destroy(ch), 0);
        assert_eq!(channel_ref(ch), None);
        assert_eq!(channel_send_cap(&table, cap, b"x"), Err(STALE));
        let mut buf = [0u8; 4];
        assert_eq!(channel_recv_cap(&table, cap, &mut buf), Err(STALE));
    }

    /// (7) A bare in-range index (generation 0) resolves to nothing, whether
    /// its slot is live or free.
    ///
    /// **Canary.** Drop `g == 0` and the generation compare from `live_index`:
    /// the bare capability sends into the live channel.
    #[test]
    fn a_bare_index_channel_capability_never_resolves() {
        use crate::cap::{targets::Channel, Cap, CapPerms, CapTable};
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        let table = CapTable::empty();
        let bare: Cap<Channel> = table.grant(CapPerms::RW, ch as u32).unwrap();
        let bare_free: Cap<Channel> = table.grant(CapPerms::RW, MAX_CHANNELS as u32 - 1).unwrap();
        as_user(OWNER);
        assert_eq!(channel_send_cap(&table, bare, b"x"), Err(STALE), "a live channel");
        assert_eq!(channel_send_cap(&table, bare_free, b"x"), Err(STALE), "a free slot");
        let mut buf = [0u8; 4];
        assert_eq!(channel_recv(ch, &mut buf), 0, "nothing was queued");
        assert_eq!(channel_destroy_ref(ch as u32), Err(STALE));
        assert_eq!(channel_owner(ch), Some(OWNER), "the live channel survived");
    }

    /// The typed create mints a packed capability into the caller's table and
    /// rolls the channel back when the table is full; the typed destroy goes
    /// through the generation and revokes the capability, and an old
    /// capability destroys nothing.
    ///
    /// **Canaries.** Drop the rollback from `channel_create_cap`: a channel is
    /// left owned with no capability. Resolve `channel_destroy_ref` by index:
    /// the old capability destroys the new channel.
    #[test]
    fn the_typed_create_and_destroy_go_through_the_generation() {
        use crate::cap::{targets::Channel, CapPerms, MAX_CAPS_PER_TASK};
        use crate::cap_store;
        const A: u32 = 21;
        const B: u32 = 22;
        let _g = begin();
        for tid in [A, B] {
            cap_store::reset(tid);
        }

        as_user(A);
        for i in 0..MAX_CAPS_PER_TASK {
            assert!(cap_store::grant::<Channel>(A, CapPerms::READ, 0).is_some(), "fill {i}");
        }
        assert_eq!(channel_create_cap(A).err(), Some(ChannelCreateError::NotMinted), "the cap table is full");
        for ch in 0..MAX_CHANNELS {
            assert_eq!(channel_owner(ch), None, "channel {ch} was left with no capability");
        }
        cap_store::reset(A);

        let cap = channel_create_cap(A).expect("create");
        let r = cap_store::get(A, cap, CapPerms::READ).unwrap();
        let ch = objref_idx(r);
        assert_eq!(channel_ref(ch), Some(r), "the capability stores the packed reference");
        assert_eq!(channel_owner(ch), Some(A));

        let other = channel_grant_cap(B, ch, CapPerms::RW).expect("a second holder");
        assert_eq!(cap_store::with_table(A, |t| channel_destroy_cap(t, cap)), Some(Ok(())));
        assert_eq!(cap_store::get(A, cap, CapPerms::READ), Err(crate::cap::CapError::Stale), "revoked");

        as_user(STRANGER);
        let recreated = channel_create().unwrap();
        assert_eq!(recreated, ch, "precondition: the index was recycled");
        assert_eq!(cap_store::with_table(B, |t| channel_destroy_cap(t, other)), Some(Err(STALE)));
        assert_eq!(channel_owner(ch), Some(STRANGER), "the old capability destroyed nothing");
        assert_eq!(cap_store::occupied(B), 0, "a stale capability is revoked too");
    }

    fn objref_idx(r: u32) -> usize {
        crate::cap::objref::CHANNEL.idx(r) as usize
    }

    /// The typed create (`SYS_CHAN_CREATE_TYPED`) holds a ring-3 task to
    /// `MAX_CHANNELS_PER_TASK` live channels. Every live channel the task owns
    /// counts, however it was created; a destroy gives the share back, another
    /// task has its own, a kernel caller is exempt, and the index create is not
    /// held to it.
    ///
    /// **Canaries.** Drop the quota test from `create_core`: the create past the
    /// quota succeeds. Apply it to kernel callers: the exempt create is refused.
    /// Count every live channel whatever its owner: B's first create is refused.
    #[test]
    fn the_typed_create_holds_a_ring3_task_to_half_the_pool() {
        use crate::cap::MAX_CAPS_PER_TASK;
        use crate::cap_store;
        const A: u32 = 26;
        const B: u32 = 27;
        let _g = begin();
        for tid in [A, B] {
            cap_store::reset(tid);
        }
        assert!(MAX_CHANNELS_PER_TASK < MAX_CAPS_PER_TASK, "precondition: the table is not what refuses");
        assert!(MAX_CHANNELS_PER_TASK + 3 <= MAX_CHANNELS, "precondition: the pool is not what refuses");

        as_user(A);
        let caps: Vec<_> = (0..MAX_CHANNELS_PER_TASK)
            .map(|i| channel_create_cap(A).unwrap_or_else(|e| panic!("create {i}: {e:?}")))
            .collect();
        assert_eq!(channel_create_cap(A).err(), Some(ChannelCreateError::Quota), "one past the quota");

        as_user(B);
        assert!(channel_create_cap(B).is_ok(), "another task has its own quota");

        as_user(A);
        assert_eq!(cap_store::with_table(A, |t| channel_destroy_cap(t, caps[0])), Some(Ok(())));
        assert!(channel_create_cap(A).is_ok(), "a destroyed channel gives its share back");
        assert!(channel_create().is_some(), "the index create is not held to the quota");
        assert_eq!(
            channel_create_cap(A).err(),
            Some(ChannelCreateError::Quota),
            "the channel created by index counts too"
        );

        crate::channel::test_ctx::set(A, true);
        assert!(channel_create_cap(A).is_ok(), "a kernel caller is exempt");
    }

    /// The exit hook's `channel_release_all` frees every channel the exiting
    /// task owns and no other: A's channels lose their owner, B's keeps its
    /// owner and its capability, a capability to one of A's channels answers
    /// `Stale`, and A's share of the pool comes back (its next typed create
    /// passes the quota).
    ///
    /// **Canaries.** Drop the owner compare: B's channel is freed. Drop the
    /// zeroing: A's channels keep their owner.
    #[test]
    fn exit_release_frees_the_exiting_tasks_channels_and_no_other() {
        use crate::cap::{CapError, CapPerms};
        use crate::cap_store;
        const A: u32 = 28;
        const B: u32 = 29;
        let _g = begin();
        for tid in [A, B] {
            cap_store::reset(tid);
        }

        as_user(A);
        let mine: Vec<(usize, _)> = (0..MAX_CHANNELS_PER_TASK)
            .map(|i| {
                let c = channel_create_cap(A).unwrap_or_else(|e| panic!("create {i}: {e:?}"));
                (objref_idx(cap_store::get(A, c, CapPerms::NONE).expect("a live capability")), c)
            })
            .collect();
        assert_eq!(channel_create_cap(A).err(), Some(ChannelCreateError::Quota), "precondition: A is at its quota");
        as_user(B);
        let theirs = channel_create_cap(B).expect("B's create");
        let theirs_idx = objref_idx(cap_store::get(B, theirs, CapPerms::NONE).expect("a live capability"));

        channel_release_all(A);
        for &(ch, _) in &mine {
            assert_eq!(channel_owner(ch), None, "A's channel {ch} survived");
        }
        let (_, first) = mine[0];
        assert_eq!(
            cap_store::with_table(A, |t| channel_send_cap(t, first, b"x")),
            Some(Err(ChannelCapError::Cap(CapError::Stale))),
            "a capability to a released channel still reached it"
        );
        assert_eq!(channel_owner(theirs_idx), Some(B), "another task's channel was freed");
        assert_eq!(
            cap_store::with_table(B, |t| channel_send_cap(t, theirs, b"y")),
            Some(Ok(())),
            "another task's capability stopped working"
        );

        as_user(A);
        assert!(channel_create_cap(A).is_ok(), "the share came back");
    }

    /// (6) U03-1 / U04-1's fix, owner decision 2026-09-26: a slot that reaches
    /// `CHANNEL.gen_max()` is swept **at its own index only**
    /// (`objref::sweep_index`) and then reused from generation 1 — instead of
    /// wrapping the *pool-wide* counter this file used to share across every
    /// index. The old design's create/destroy loop past that wrap called
    /// `objref::sweep_kind(CapKind::Channel)`, which revoked **every**
    /// `Cap<Channel>` in **every** per-task table, live or not — B's own
    /// channel and a capability D holds on it, minted directly with
    /// `cap_store::grant`, included. Reachable from ring 3 in `gen_max`
    /// create/destroy cycles on ONE task's own channel (as few as 2^20 on the
    /// fleet profile) with no runtime re-mint path for a lost capability.
    ///
    /// This test proves the fix two ways: (a) B's and D's capabilities — on a
    /// different slot, never touched by A's loop — read exactly as they did
    /// before A's churn crosses the same generation ceiling that used to
    /// trigger the pool-wide sweep; (b) the targeted sweep still does its one
    /// job — a capability E holds on slot 1's *previous* incarnation, already
    /// unreachable through the generation compare alone, is also gone from
    /// E's table afterward, and slot 1 itself is not lost: it comes back at
    /// generation 1, not skipped forever.
    ///
    /// **RED on the pre-fix code.** Before this change, `create_core`'s
    /// `Sweep` arm ran unconditionally once the pool-wide counter (shared by
    /// every index, not per-slot) passed `gen_max`, regardless of which index
    /// triggered it: assertions (a) below failed with `Stale` against a
    /// checkout before this commit — the same failure the tree's own,
    /// now-deleted `the_channel_wrap_sweeps_every_table_and_resumes_at_one`
    /// asserted as the OLD, intended behaviour (`cap_store::get(B, in_b, ...)`
    /// and `cap_store::get(D, direct, ...)` both `Err(CapError::Stale)`).
    ///
    /// **Canary.** Drop the `pool.next_gen[i] != 0` guard from
    /// `create_core`'s free-slot scan: a concurrent create could select slot 1
    /// while it is marked mid-sweep. Compare `slot.resource == r` instead of
    /// `objref::idx(kind, slot.resource) == idx` in `revoke_kind_at_index`:
    /// assertion (b)'s "not touched" side (a capability at a DIFFERENT index)
    /// would need its own generation to collide to fail, so add a second
    /// canary check: drop the index compare entirely (revoke every `Channel`
    /// cap) and B's and D's capabilities on slot 0 go `Stale` too.
    #[test]
    fn a_slots_own_wrap_sweeps_only_that_index_and_the_slot_still_comes_back() {
        use crate::cap::objref::CHANNEL;
        use crate::cap::{CapError, CapPerms};
        use crate::cap_store;
        const A: u32 = 26;
        const B: u32 = 27;
        const D: u32 = 28;
        const E: u32 = 29;
        let _g = begin();
        for tid in [A, B, D, E] {
            cap_store::reset(tid);
        }

        // B's channel: the "other task's live capability" the old sweep
        // revoked. Created first so it lands on the lowest index (0) and
        // stays there for the whole test — A's churn below never touches it.
        as_user(B);
        let cap_b = channel_create_cap(B).expect("create");
        let r_b = cap_store::get(B, cap_b, CapPerms::READ).unwrap();
        assert_eq!(objref_idx(r_b), 0, "precondition: B's channel is slot 0");

        // D holds a capability on B's channel minted directly with
        // `cap_store::grant`, the same "any table, any path" reach the old
        // sweep had (RFC-0040 gap 1 covers every table, not only the one the
        // typed mint path used).
        let direct = cap_store::grant::<crate::cap::targets::Channel>(D, CapPerms::RW, r_b).unwrap();

        // A churns slot 1 (the next lowest free index) right up to and past
        // its own generation ceiling. Fast-forwarded so the test does not run
        // `CHANNEL.gen_max()` real create/destroy cycles.
        as_user(A);
        let ch = channel_create().expect("create");
        assert_eq!(ch, 1, "precondition: A's churn lands on slot 1");
        assert_eq!(channel_destroy(ch), 0);
        __channel_set_next_gen_for_tests(1, CHANNEL.gen_max() - 1);

        let ch = channel_create().expect("create at the second-to-last generation");
        assert_eq!(ch, 1, "still slot 1");
        assert_eq!(CHANNEL.gen(channel_ref(ch).unwrap()), CHANNEL.gen_max() - 1);
        assert_eq!(channel_destroy(ch), 0);

        let ch = channel_create().expect("create at the last generation");
        assert_eq!(ch, 1, "still slot 1");
        let r_penultimate = channel_ref(ch).unwrap();
        assert_eq!(CHANNEL.gen(r_penultimate), CHANNEL.gen_max(), "the last generation slot 1 can carry");
        // E holds a capability on THIS incarnation of slot 1 — already
        // unreachable through the generation compare the moment it is
        // destroyed below, but still occupying a slot in E's table until
        // something revokes it. The targeted sweep is that something.
        let in_e = cap_store::grant::<crate::cap::targets::Channel>(E, CapPerms::RW, r_penultimate).unwrap();
        assert_eq!(channel_destroy(ch), 0);

        // The next create on slot 1 wraps: `next_gen[1]` is one past
        // `gen_max`, so `create_core` sweeps index 1 only and reuses it.
        let ch = channel_create().expect("slot 1 wraps and is reused, not skipped");
        assert_eq!(ch, 1, "the slot comes back — no permanent loss");
        let r_new = channel_ref(ch).unwrap();
        assert_eq!(CHANNEL.gen(r_new), 1, "reused from generation 1 after its own wrap");

        // (a) B's and D's capabilities, on slot 0, are untouched.
        assert_eq!(cap_store::get(B, cap_b, CapPerms::READ), Ok(r_b), "B's capability");
        assert_eq!(cap_store::get(D, direct, CapPerms::READ), Ok(r_b), "D's capability, minted directly");
        assert_eq!(channel_owner(0), Some(B), "B's channel is still live");

        // (b) E's stale capability on slot 1's previous incarnation is gone —
        // the targeted sweep's one job — and slot 1 itself now answers for
        // the NEW incarnation, not the swept one.
        assert_eq!(cap_store::get(E, in_e, CapPerms::READ), Err(CapError::Stale), "E's stale capability, swept");
        assert_eq!(channel_ref(1), Some(r_new), "slot 1 now answers for the new incarnation");
    }

    // ── Bounds and limits: no panic is the requirement ───────────────────

    #[test]
    fn out_of_range_ids_never_panic() {
        let _g = begin();
        let bad = [MAX_CHANNELS, MAX_CHANNELS + 1, usize::MAX, usize::MAX / 2];
        for who in [true, false] {
            if who { as_kernel() } else { as_user(STRANGER) }
            for &ch in &bad {
                let mut buf = [0u8; 8];
                assert_eq!(channel_send(ch, b"x"), -1, "send {ch}");
                assert_eq!(channel_recv(ch, &mut buf), -1, "recv {ch}");
                assert_eq!(channel_destroy(ch), -1, "destroy {ch}");
                assert_eq!(channel_owner(ch), None, "owner {ch}");
            }
        }
    }

    #[test]
    fn inactive_channel_is_rejected_not_read() {
        let _g = begin();
        as_kernel();
        let mut buf = [0u8; 8];
        for ch in 0..MAX_CHANNELS {
            assert_eq!(channel_recv(ch, &mut buf), -1, "ch {ch}");
            assert_eq!(channel_send(ch, b"x"), -1, "ch {ch}");
        }
    }

    #[test]
    fn payload_at_and_over_the_limit() {
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let exact = [0xABu8; MSG_MAX_LEN];
        assert_eq!(channel_send(ch, &exact), 0, "exactly MSG_MAX_LEN must fit");
        let over = [0xCDu8; MSG_MAX_LEN + 1];
        assert_eq!(channel_send(ch, &over), -1, "MSG_MAX_LEN+1 must be refused");
        // Zero-length is legal and round-trips as zero bytes.
        assert_eq!(channel_send(ch, &[]), 0);

        let mut buf = [0u8; MSG_MAX_LEN];
        assert_eq!(channel_recv(ch, &mut buf), MSG_MAX_LEN as i32);
        assert_eq!(buf, exact);
        assert_eq!(channel_recv(ch, &mut buf), 0, "zero-length message");
    }

    #[test]
    fn ring_fills_and_refuses_without_panicking() {
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        as_user(OWNER);
        // The ring keeps one slot empty to distinguish full from empty.
        for i in 0..RING_CAP - 1 {
            assert_eq!(channel_send(ch, &[i as u8]), 0, "send #{i}");
        }
        for i in 0..8 {
            assert_eq!(channel_send(ch, b"overflow"), -1, "extra send #{i}");
        }
        let mut buf = [0u8; 4];
        for i in 0..RING_CAP - 1 {
            assert_eq!(channel_recv(ch, &mut buf), 1);
            assert_eq!(buf[0], i as u8, "FIFO order broken");
        }
        assert_eq!(channel_recv(ch, &mut buf), 0, "ring should now be empty");
    }

    #[test]
    fn recv_into_short_or_empty_buffer_truncates() {
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(channel_send(ch, b"0123456789"), 0);
        let mut small = [0u8; 4];
        assert_eq!(channel_recv(ch, &mut small), 4);
        assert_eq!(&small, b"0123");

        assert_eq!(channel_send(ch, b"abc"), 0);
        let mut empty: [u8; 0] = [];
        assert_eq!(channel_recv(ch, &mut empty), 0, "empty dst copies 0 bytes");
    }

    #[test]
    fn pool_exhaustion_returns_none_not_panic() {
        let _g = begin();
        as_user(OWNER);
        for i in 0..MAX_CHANNELS {
            assert!(channel_create().is_some(), "create #{i}");
        }
        for _ in 0..4 {
            assert!(channel_create().is_none(), "pool must refuse past capacity");
        }
    }

    #[test]
    fn wrap_around_preserves_order() {
        let _g = begin();
        let ch = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let mut buf = [0u8; 4];
        // Push/pop far past RING_CAP so head and tail wrap several times.
        for round in 0..(RING_CAP as u8 * 5) {
            assert_eq!(channel_send(ch, &[round]), 0, "round {round}");
            assert_eq!(channel_recv(ch, &mut buf), 1, "round {round}");
            assert_eq!(buf[0], round);
        }
    }
}

// ---------------------------------------------------------------------------
// pipe.rs
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pipe_tests {
    use crate::harness::{as_kernel, as_user, begin};
    use crate::pipe::*;

    const OWNER: u32 = 33;
    const STRANGER: u32 = 44;

    fn create_as(tid: u32, n: usize) -> Vec<usize> {
        as_user(tid);
        (0..n)
            .map(|i| pipe_create().unwrap_or_else(|| panic!("create #{i} failed")).0)
            .collect()
    }

    // ── Ownership ────────────────────────────────────────────────────────

    #[test]
    fn create_records_owner_and_round_trips() {
        let _g = begin();
        for idx in create_as(OWNER, 4) {
            assert_eq!(pipe_owner(idx), Some(OWNER), "pipe {idx}");
            as_user(OWNER);
            assert_eq!(pipe_write_buf(idx, b"hello"), 5);
            assert_eq!(pipe_available(idx), 5);
            let mut buf = [0u8; 16];
            assert_eq!(pipe_read_buf(idx, &mut buf), 5);
            assert_eq!(&buf[..5], b"hello");
        }
    }

    #[test]
    fn stranger_cannot_read_write_or_close_any_index() {
        let _g = begin();
        let pipes = create_as(OWNER, 4);
        for &idx in &pipes {
            as_user(OWNER);
            assert_eq!(pipe_write_buf(idx, b"private"), 7);
        }

        as_user(STRANGER);
        for idx in 0..MAX_PIPES {
            let mut buf = [0u8; 16];
            assert_eq!(pipe_read_buf(idx, &mut buf), -1, "read {idx}");
            assert_eq!(buf, [0u8; 16], "stranger got bytes out of pipe {idx}");
            assert_eq!(pipe_write_buf(idx, b"poison"), -1, "write {idx}");
            assert_eq!(pipe_close_read(idx), -1, "close_read {idx}");
            assert_eq!(pipe_close_write(idx), -1, "close_write {idx}");
            assert_eq!(pipe_available(idx), 0, "available {idx} leaked occupancy");
            assert_eq!(pipe_space(idx), 0, "space {idx} leaked occupancy");
        }

        // Nothing the stranger did took effect.
        as_user(OWNER);
        for &idx in &pipes {
            assert_eq!(pipe_available(idx), 7, "pipe {idx} was tampered with");
            let mut buf = [0u8; 16];
            assert_eq!(pipe_read_buf(idx, &mut buf), 7);
            assert_eq!(&buf[..7], b"private");
        }
    }

    #[test]
    fn kernel_bypasses_the_owner_check() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_kernel();
        assert_eq!(pipe_write_buf(idx, b"kernel"), 6);
        let mut buf = [0u8; 16];
        assert_eq!(pipe_read_buf(idx, &mut buf), 6);
        assert!(pipe_space(idx) > 0);
        assert_eq!(pipe_close_write(idx), 0);
        assert_eq!(pipe_close_read(idx), 0);
    }

    /// The block copies wrap at the ring's end: bytes come back in order
    /// across the wrap, and a write takes only what fits (PIPE_BUF_SIZE - 1).
    #[test]
    fn bytes_survive_the_ring_wrap_in_order() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut buf = vec![0u8; 5000];
        assert_eq!(pipe_write_buf(idx, &data[..3000]), 3000);
        assert_eq!(pipe_read_buf(idx, &mut buf[..3000]), 3000);
        assert_eq!(&buf[..3000], &data[..3000]);
        // Starts at 3000 of 4096: 1096 to the end, the rest from the start.
        assert_eq!(pipe_write_buf(idx, &data[..2000]), 2000);
        assert_eq!(pipe_read_buf(idx, &mut buf[..2000]), 2000);
        assert_eq!(&buf[..2000], &data[..2000]);
        assert_eq!(pipe_write_buf(idx, &data), (crate::pipe::PIPE_BUF_SIZE - 1) as i32);
        assert_eq!(pipe_read_buf(idx, &mut buf), (crate::pipe::PIPE_BUF_SIZE - 1) as i32);
        assert_eq!(&buf[..crate::pipe::PIPE_BUF_SIZE - 1], &data[..crate::pipe::PIPE_BUF_SIZE - 1]);
        assert_eq!(pipe_close_write(idx), 0);
        assert_eq!(pipe_close_read(idx), 0);
    }

    #[test]
    fn owner_can_close_each_end_once() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(pipe_write_buf(idx, b"last"), 4);
        assert_eq!(pipe_close_write(idx), 0);
        // Data written before the close is still readable...
        let mut buf = [0u8; 8];
        assert_eq!(pipe_read_buf(idx, &mut buf), 4);
        // ...then EOF, not EAGAIN, because the writer is gone.
        assert_eq!(pipe_read_buf(idx, &mut buf), 0);
        // And writing after the read end closes is EPIPE.
        assert_eq!(pipe_close_read(idx), 0);
        assert_eq!(pipe_write_buf(idx, b"x"), -1);
    }

    #[test]
    fn empty_pipe_with_live_writer_is_eagain() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let mut buf = [0u8; 8];
        assert_eq!(pipe_read_buf(idx, &mut buf), -2, "EAGAIN while writer alive");
    }

    // ── Raw pointers and bounds: no panic, no over-read ──────────────────

    #[test]
    fn null_pointers_are_refused() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        assert_eq!(pipe_read(idx, core::ptr::null_mut(), 16), -1);
        assert_eq!(pipe_write(idx, core::ptr::null(), 16), -1);
        // ...and with count 0 as well, since 0 is the other way a caller
        // says "no buffer".
        assert_eq!(pipe_read(idx, core::ptr::null_mut(), 0), -1);
        assert_eq!(pipe_write(idx, core::ptr::null(), 0), -1);
    }

    #[test]
    fn out_of_range_indices_never_panic() {
        let _g = begin();
        let bad = [MAX_PIPES, MAX_PIPES + 1, usize::MAX, usize::MAX / 2];
        let mut buf = [0u8; 8];
        for who in [true, false] {
            if who { as_kernel() } else { as_user(STRANGER) }
            for &idx in &bad {
                assert_eq!(pipe_read_buf(idx, &mut buf), -1, "read {idx}");
                assert_eq!(pipe_write_buf(idx, b"x"), -1, "write {idx}");
                assert_eq!(pipe_close_read(idx), -1, "close_read {idx}");
                assert_eq!(pipe_close_write(idx), -1, "close_write {idx}");
                assert_eq!(pipe_available(idx), 0, "available {idx}");
                assert_eq!(pipe_space(idx), 0, "space {idx}");
                assert_eq!(pipe_owner(idx), None, "owner {idx}");
            }
        }
    }

    #[test]
    fn free_slot_is_rejected() {
        let _g = begin();
        as_kernel();
        let mut buf = [0u8; 8];
        for idx in 0..MAX_PIPES {
            assert_eq!(pipe_read_buf(idx, &mut buf), -1, "read free {idx}");
            assert_eq!(pipe_write_buf(idx, b"x"), -1, "write free {idx}");
            assert_eq!(pipe_close_read(idx), -1, "close free {idx}");
            assert_eq!(pipe_owner(idx), None);
        }
    }

    #[test]
    fn empty_slices_are_a_no_op() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let mut empty: [u8; 0] = [];
        assert_eq!(pipe_write_buf(idx, &[]), 0);
        assert_eq!(pipe_read_buf(idx, &mut empty), 0);
        assert_eq!(pipe_available(idx), 0);
    }

    /// `count` larger than the buffer is the caller's bug, but the pipe must
    /// still clamp to its own free space and never walk off its ring. The
    /// buffer here is a real `PIPE_BUF_SIZE` array, so the clamped copy stays
    /// inside it — which is exactly the safety contract documented on
    /// `pipe_write`.
    #[test]
    fn oversized_count_clamps_to_ring_capacity() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let src = [0x5Au8; PIPE_BUF_SIZE];
        // Ask for twice the ring; the ring keeps one byte free as the
        // full/empty discriminator.
        let n = pipe_write(idx, src.as_ptr(), PIPE_BUF_SIZE * 2);
        assert_eq!(n, (PIPE_BUF_SIZE - 1) as i32);
        assert_eq!(pipe_space(idx), 0, "ring should now be full");
        // A second write finds no space and writes nothing.
        assert_eq!(pipe_write(idx, src.as_ptr(), PIPE_BUF_SIZE), 0);

        let mut dst = [0u8; PIPE_BUF_SIZE];
        let r = pipe_read(idx, dst.as_mut_ptr(), PIPE_BUF_SIZE * 2);
        assert_eq!(r, (PIPE_BUF_SIZE - 1) as i32);
        assert!(dst[..PIPE_BUF_SIZE - 1].iter().all(|&b| b == 0x5A));
    }

    #[test]
    fn ring_wraps_without_losing_bytes() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        as_user(OWNER);
        let chunk = [0u8; 512];
        let mut out = [0u8; 512];
        // 20 × 512 = 10240 bytes through a 4096-byte ring ⇒ several wraps.
        for round in 0..20u8 {
            let payload: Vec<u8> = chunk.iter().map(|_| round).collect();
            assert_eq!(pipe_write_buf(idx, &payload), 512, "round {round}");
            assert_eq!(pipe_read_buf(idx, &mut out), 512, "round {round}");
            assert!(out.iter().all(|&b| b == round), "round {round} corrupted");
        }
    }

    #[test]
    fn pool_exhaustion_returns_none_not_panic() {
        let _g = begin();
        as_user(OWNER);
        for i in 0..MAX_PIPES {
            assert!(pipe_create().is_some(), "create #{i}");
        }
        for _ in 0..4 {
            assert!(pipe_create().is_none(), "pool must refuse past capacity");
        }
    }

    // ── Slot reuse ───────────────────────────────────────────────────────

    #[test]
    fn closing_both_ends_gives_the_slot_back() {
        let _g = begin();
        as_user(OWNER);
        // Three times the pool: no slot survives its own close.
        for i in 0..3 * MAX_PIPES {
            let (r, w) = pipe_create().unwrap_or_else(|| panic!("create #{i} failed"));
            assert_eq!(pipe_close_write(w), 0, "close_write #{i}");
            assert_eq!(pipe_close_read(r), 0, "close_read #{i}");
        }
    }

    #[test]
    fn an_exhausted_pool_recovers_when_a_pipe_closes() {
        let _g = begin();
        let pipes = create_as(OWNER, MAX_PIPES);
        assert!(pipe_create().is_none(), "pool must be full");
        let idx = pipes[MAX_PIPES / 2];
        assert_eq!(pipe_close_read(idx), 0);
        assert!(pipe_create().is_none(), "an open write end still holds the slot");
        assert_eq!(pipe_close_write(idx), 0);
        let (again, _) = pipe_create().expect("the closed slot must be reusable");
        assert_eq!(again, idx);
    }

    #[test]
    fn a_reused_slot_starts_empty() {
        let _g = begin();
        let idx = create_as(OWNER, 1)[0];
        assert_eq!(pipe_write_buf(idx, b"stale"), 5);
        assert_eq!(pipe_close_write(idx), 0);
        assert_eq!(pipe_close_read(idx), 0);
        let (again, _) = pipe_create().expect("slot reusable");
        assert_eq!(again, idx);
        assert_eq!(pipe_available(again), 0, "bytes of the closed pipe leaked into the new one");
    }

    #[test]
    fn release_all_frees_only_the_dead_tasks_pipes() {
        let _g = begin();
        let mine = create_as(OWNER, 3);
        let theirs = create_as(STRANGER, 2);
        pipe_release_all(OWNER);
        for &idx in &mine {
            assert_eq!(pipe_owner(idx), None, "pipe {idx} of the dead task");
        }
        for &idx in &theirs {
            assert_eq!(pipe_owner(idx), Some(STRANGER), "pipe {idx} of a live task");
        }
        // Every freed slot is creatable again, and not one more.
        as_user(STRANGER);
        for i in 0..MAX_PIPES - theirs.len() {
            assert!(pipe_create().is_some(), "refill #{i}");
        }
        assert!(pipe_create().is_none());
    }
}

// ---------------------------------------------------------------------------
// signal.rs
// ---------------------------------------------------------------------------

#[cfg(test)]
mod signal_tests {
    use crate::harness::{as_kernel, as_user, begin};
    use crate::signal::*;

    const SELF_TID: u32 = 55;
    const VICTIM: u32 = 66;

    // ── Policy: ring 3 signals only itself ───────────────────────────────

    #[test]
    fn ring3_may_signal_itself() {
        let _g = begin();
        as_user(SELF_TID);
        assert_eq!(signal_send(SELF_TID, SIGUSR1), 0);
        assert_eq!(signal_pending() & (1 << SIGUSR1), 1 << SIGUSR1);
    }

    #[test]
    fn ring3_may_not_signal_another_task_and_leaves_no_trace() {
        let _g = begin();
        // The victim exists in the table with a clean slate.
        as_user(VICTIM);
        assert_eq!(signal_send(VICTIM, SIGUSR2), 0);
        let before = signal_table_len();

        as_user(SELF_TID);
        for tid in [VICTIM, 0, 1, 7, 4242, u32::MAX] {
            assert_eq!(signal_send(tid, SIGKILL), -1, "cross-task send to {tid}");
        }
        // Crucially: the refused sends allocated nothing. This is what stops
        // 64 `kill()` calls with invented TIDs from filling the table and
        // aliasing every task onto slot 0.
        assert_eq!(signal_table_len(), before, "denied send still grew the table");

        as_user(VICTIM);
        assert_eq!(signal_pending() & (1 << SIGKILL), 0, "victim got signalled");
    }

    #[test]
    fn kernel_may_signal_any_task() {
        let _g = begin();
        as_kernel();
        for tid in [VICTIM, 1, 2, 3] {
            assert_eq!(signal_send(tid, SIGTERM), 0, "kernel send to {tid}");
        }
        as_user(VICTIM);
        assert_eq!(signal_pending() & (1 << SIGTERM), 1 << SIGTERM);
    }

    // ── Signal numbers: the shift that must never overflow ───────────────

    #[test]
    fn invalid_signal_numbers_are_refused_without_panicking() {
        let _g = begin();
        // `overflow-checks = true` + `panic = "abort"`: a `1u32 << 32` here
        // would reset the board, so this is a safety test, not hygiene.
        let bad = [0u32, NSIG, NSIG + 1, 32, 63, 64, 1000, u32::MAX, u32::MAX - 1];
        for who in [true, false] {
            if who { as_kernel() } else { as_user(SELF_TID) }
            for &s in &bad {
                assert_eq!(signal_send(SELF_TID, s), -1, "signum {s}");
                assert_eq!(signal_set_handler(s, 0xDEAD), SIG_DFL, "handler {s}");
                assert!(!signal_valid(s), "signal_valid({s})");
            }
        }
    }

    #[test]
    fn every_valid_signal_number_is_accepted() {
        let _g = begin();
        as_user(SELF_TID);
        for s in 1..NSIG {
            assert_eq!(signal_send(SELF_TID, s), 0, "signum {s}");
        }
        // All 31 bits set, none of them bit 0.
        assert_eq!(signal_pending(), !1u32);
    }

    // ── Table exhaustion: the index-0 aliasing bug ───────────────────────

    #[test]
    fn full_table_fails_closed_instead_of_aliasing_onto_slot_zero() {
        let _g = begin();
        as_kernel();

        // Task 1 registers first, so under the old code it owned slot 0 —
        // the slot every overflowing caller used to be handed.
        const FIRST: u32 = 1;
        assert_eq!(signal_send(FIRST, SIGUSR1), 0);
        as_user(FIRST);
        assert_eq!(signal_set_mask(0), 0);
        let first_pending_before = signal_pending();
        assert_eq!(first_pending_before, 1 << SIGUSR1);

        // Fill the rest of the table (kernel privilege lets us target any
        // TID; a ring-3 task could do this too before the self-only rule).
        as_kernel();
        let mut filled = 1usize;
        let mut tid = FIRST + 1;
        while signal_send(tid, SIGUSR2) == 0 {
            filled += 1;
            tid += 1;
            assert!(tid < 10_000, "table never filled — is it unbounded?");
        }
        assert_eq!(signal_table_len(), filled, "count disagrees with reality");

        // The overflowing task now fails closed...
        let overflow_tid = tid;
        assert_eq!(signal_send(overflow_tid, SIGKILL), -1);
        as_user(overflow_tid);
        assert_eq!(signal_set_mask(0xFFFF_FFFF), -1, "set_mask must fail closed");
        assert_eq!(
            signal_set_handler(SIGUSR1, 0xBAD),
            SIG_DFL,
            "set_handler must fail closed"
        );

        // ...and, the whole point: task 1's state is untouched. Under the old
        // `get_or_create` these three calls all landed on slot 0.
        as_user(FIRST);
        assert_eq!(signal_pending(), first_pending_before, "slot 0 was clobbered");
        assert_eq!(signal_get_mask(), 0, "slot 0 mask was clobbered");
    }

    #[test]
    fn release_frees_a_slot_and_keeps_the_rest_findable() {
        let _g = begin();
        as_kernel();
        for tid in 1..=5u32 {
            assert_eq!(signal_send(tid, SIGUSR1), 0);
        }
        assert_eq!(signal_table_len(), 5);

        // Drop one from the middle: the compaction moves the last entry into
        // the hole, so `find`'s `0..count` scan must still see it.
        assert!(signal_release(3));
        assert_eq!(signal_table_len(), 4);
        assert!(!signal_release(3), "double release must be a no-op");
        assert!(!signal_release(999), "releasing an unknown tid must be a no-op");

        for tid in [1u32, 2, 4, 5] {
            as_user(tid);
            assert_eq!(
                signal_pending() & (1 << SIGUSR1),
                1 << SIGUSR1,
                "tid {tid} lost its state after compaction"
            );
        }
        as_user(3);
        assert_eq!(signal_pending(), 0, "released tid should have no state");
    }

    #[test]
    fn release_makes_room_again() {
        let _g = begin();
        as_kernel();
        let mut tid = 1u32;
        while signal_send(tid, SIGUSR1) == 0 {
            tid += 1;
            assert!(tid < 10_000);
        }
        let overflow_tid = tid;
        assert_eq!(signal_send(overflow_tid, SIGUSR1), -1);
        assert!(signal_release(1));
        assert_eq!(
            signal_send(overflow_tid, SIGUSR1),
            0,
            "a freed slot must be reusable — this is what task_release_all buys"
        );
    }

    // ── Handlers and masks ───────────────────────────────────────────────

    #[test]
    fn handler_round_trips_but_kill_and_stop_stay_default() {
        let _g = begin();
        as_user(SELF_TID);
        assert_eq!(signal_set_handler(SIGUSR1, 0x1234), SIG_DFL);
        assert_eq!(signal_set_handler(SIGUSR1, 0x5678), 0x1234);
        assert_eq!(signal_set_handler(SIGUSR1, SIG_IGN), 0x5678);

        // Uncatchable signals: the write is silently dropped, the read
        // still reports SIG_DFL.
        for s in [SIGKILL, SIGSTOP] {
            assert_eq!(signal_set_handler(s, 0xDEADBEEF), SIG_DFL, "sig {s}");
            assert_eq!(signal_set_handler(s, 0), SIG_DFL, "sig {s} was stored");
            assert!(!signal_catchable(s));
        }
    }

    #[test]
    fn handlers_are_per_task_not_shared() {
        let _g = begin();
        as_user(SELF_TID);
        assert_eq!(signal_set_handler(SIGUSR1, 0xAAAA), SIG_DFL);
        as_user(VICTIM);
        assert_eq!(
            signal_set_handler(SIGUSR1, 0xBBBB),
            SIG_DFL,
            "second task saw the first task's handler"
        );
        as_user(SELF_TID);
        assert_eq!(signal_set_handler(SIGUSR1, 0), 0xAAAA);
    }

    #[test]
    fn mask_hides_pending_but_never_kill_or_stop() {
        let _g = begin();
        as_user(SELF_TID);
        assert_eq!(signal_send(SELF_TID, SIGUSR1), 0);
        assert_eq!(signal_send(SELF_TID, SIGKILL), 0);
        assert_eq!(signal_send(SELF_TID, SIGSTOP), 0);

        assert_eq!(signal_set_mask(0xFFFF_FFFF), 0);
        let m = signal_get_mask();
        assert_eq!(m & (1 << SIGKILL), 0, "SIGKILL must not be maskable");
        assert_eq!(m & (1 << SIGSTOP), 0, "SIGSTOP must not be maskable");

        let p = signal_pending();
        assert_eq!(p & (1 << SIGUSR1), 0, "SIGUSR1 should be masked out");
        assert_eq!(p & (1 << SIGKILL), 1 << SIGKILL);
        assert_eq!(p & (1 << SIGSTOP), 1 << SIGSTOP);

        assert_eq!(signal_set_mask(0), 0);
        assert_eq!(signal_pending() & (1 << SIGUSR1), 1 << SIGUSR1);
    }

    #[test]
    fn unknown_task_has_no_state_and_no_panic() {
        let _g = begin();
        as_user(4242);
        assert_eq!(signal_pending(), 0);
        assert_eq!(signal_get_mask(), 0);
        assert_eq!(signal_table_len(), 0, "a pure read must not allocate");
    }

    #[test]
    fn default_actions_are_defined_for_every_signal_number() {
        let _g = begin();
        // `signal_default_action` has a catch-all arm; walk the whole u8
        // space plus the edges to prove no arithmetic in there can trap.
        for s in 0..=300u32 {
            let _ = signal_default_action(s);
        }
        let _ = signal_default_action(u32::MAX);
        assert!(matches!(
            signal_default_action(SIGKILL),
            SigDefaultAction::Term
        ));
        assert!(matches!(
            signal_default_action(SIGCONT),
            SigDefaultAction::Cont
        ));
    }
}


/// `channel_destroy`'s answers for the slots it does not free: an in-range
/// free slot is a no-op answered 0 (`domains/robot/bench` destroys its own channels
/// through it and relies on that), whoever asks; out of range is -1; a second
/// destroy is the free-slot case again. The owner compare still applies to a
/// live slot, and the kernel still bypasses it.
///
/// **Canary.** Answer -1 for a free slot: the first assertion reads -1.
#[cfg(test)]
mod channel_destroy_contract {
    use super::channel::{channel_create, channel_destroy, channel_owner, MAX_CHANNELS};
    use super::harness;

    #[test]
    fn a_free_slot_is_a_no_op_and_a_live_one_keeps_its_owner_compare() {
        let _g = harness::begin(); // kernel context
        assert_eq!(channel_destroy(0), 0, "kernel, free slot");
        assert_eq!(channel_destroy(MAX_CHANNELS), -1, "out of range");

        let a = channel_create().expect("pool exhausted");
        assert_eq!(channel_destroy(a), 0, "kernel, live slot");
        assert_eq!(channel_owner(a), None);
        assert_eq!(channel_destroy(a), 0, "kernel, second destroy");

        harness::as_user(11);
        let b = channel_create().expect("pool exhausted");
        harness::as_user(22);
        assert_eq!(channel_destroy(b), -1, "a stranger");
        assert_eq!(channel_owner(b), Some(11), "the stranger's refused destroy freed it");
        harness::as_user(11);
        assert_eq!(channel_destroy(b), 0, "the owner");
        harness::as_user(22);
        assert_eq!(channel_destroy(b), 0, "a stranger, once the slot is free");
    }
}

// ---------------------------------------------------------------------------
// channel.rs: the link to an event port (wave 11, PORTWAIT)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod channel_port_link {
    use crate::channel::*;
    use crate::harness::{as_user, begin};
    use crate::port::take_signals;
    use crate::port_link::{LinkSet, PortLink};

    const OWNER: u32 = 11;
    const P1: PortLink = PortLink { port: 0x21, epoch: 0, slot: 3 };
    const P2: PortLink = PortLink { port: 0x42, epoch: 0, slot: 1 };

    /// A channel and its packed reference, created by ring-3 `OWNER`.
    fn chan() -> (usize, u32) {
        as_user(OWNER);
        let ch = channel_create().expect("create");
        (ch, channel_ref(ch).expect("live"))
    }

    /// Every send on a linked channel — the index form and the typed form —
    /// signals its port once, after the send, with the channel's reference;
    /// an unlinked channel signals nothing.
    ///
    /// **Canary.** Read the link before `push` and signal only when the ring
    /// was empty: the second send records no signal.
    #[test]
    fn every_send_on_a_linked_channel_signals_its_port() {
        let _g = begin();
        let _ = take_signals();
        let (ch, r) = chan();
        assert_eq!(channel_send(ch, b"a"), 0);
        assert!(take_signals().is_empty(), "no link, no signal");

        assert_eq!(channel_set_link(r, P1, PortLink::NONE), Ok(LinkSet::Stored { ready: true }), "one message waits");
        assert_eq!(channel_send(ch, b"b"), 0);
        assert_eq!(channel_send(ch, b"c"), 0);
        assert_eq!(take_signals(), vec![(P1, r), (P1, r)], "one signal per send");

        let table = crate::cap::CapTable::empty();
        let cap: crate::cap::Cap<crate::cap::targets::Channel> =
            table.grant(crate::cap::CapPerms::RW, r).expect("grant");
        assert_eq!(channel_send_cap(&table, cap, b"d"), Ok(()));
        assert_eq!(take_signals(), vec![(P1, r)], "the typed send too");
    }

    /// A send whose port no longer answers to the link clears it, so the next
    /// send pays nothing; a full channel's refused send signals nothing.
    ///
    /// **Canary.** Skip `channel_clear_link` in `signal_bound_port`: the
    /// second send records a signal.
    #[test]
    fn a_dead_link_is_cleared_by_the_send_that_finds_it() {
        let _g = begin();
        let _ = take_signals();
        let (ch, r) = chan();
        assert_eq!(channel_set_link(r, P1, PortLink::NONE), Ok(LinkSet::Stored { ready: false }));
        *crate::port::ANSWER_LIVE.lock().unwrap() = false;
        assert_eq!(channel_send(ch, b"x"), 0);
        assert_eq!(crate::port::SIGNALS.lock().unwrap().len(), 1, "the send signalled once");
        assert_eq!(channel_send(ch, b"y"), 0);
        assert_eq!(take_signals().len(), 1, "the dead link was cleared");
        assert_eq!(channel_set_link(r, P2, PortLink::NONE), Ok(LinkSet::Stored { ready: true }), "and the channel is free");

        while channel_send(ch, b"z") == 0 {}
        let _ = take_signals();
        assert_eq!(channel_send(ch, b"full"), -1);
        assert!(take_signals().is_empty(), "a refused send signals nothing");
    }

    /// One channel reports to one port: a link to another port is `Busy`
    /// unless the binder names it as the dead link to replace; a re-bind to
    /// the same port, and clearing, follow the link; a stale reference is
    /// refused.
    #[test]
    fn a_channel_reports_to_one_port() {
        let _g = begin();
        let (ch, r) = chan();
        assert_eq!(channel_set_link(r, P1, PortLink::NONE), Ok(LinkSet::Stored { ready: false }));
        assert_eq!(channel_set_link(r, P2, PortLink::NONE), Ok(LinkSet::Busy(P1)));
        let p1_again = PortLink { slot: 7, ..P1 };
        assert_eq!(channel_set_link(r, p1_again, PortLink::NONE), Ok(LinkSet::Stored { ready: false }), "same port");
        assert_eq!(channel_set_link(r, P2, P1), Ok(LinkSet::Busy(p1_again)), "replace names an older link");
        assert_eq!(channel_set_link(r, P2, p1_again), Ok(LinkSet::Stored { ready: false }), "the dead link replaced");
        channel_clear_link(r, P1);
        assert_eq!(channel_set_link(r, P1, PortLink::NONE), Ok(LinkSet::Busy(P2)), "clearing another link is a no-op");
        channel_clear_link(r, P2);
        assert_eq!(channel_set_link(r, P1, PortLink::NONE), Ok(LinkSet::Stored { ready: false }));

        assert_eq!(channel_destroy(ch), 0);
        assert!(channel_set_link(r, P1, PortLink::NONE).is_err(), "a destroyed channel");
    }
}

// pipe.rs — capability pipes (RFC-0055, wave 11)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod typed_pipes {
    use crate::harness::begin;
    use crate::pipe::*;

    fn read_all(res: u32, me: u32) -> (PipeIo, Vec<u8>) {
        let mut b = vec![0u8; PIPE_BUF_SIZE];
        let (io, _) = pipe_typed_read(res, &mut b, me);
        if let PipeIo::Done(n) = io {
            b.truncate(n);
            (io, b)
        } else {
            (io, Vec::new())
        }
    }

    #[test]
    fn bytes_flow_and_end_of_file_follows_the_last_write_end() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert_eq!(pipe_typed_write(r, b"hello", 7), (PipeIo::Done(5), 0));
        assert_eq!(read_all(r, 8), (PipeIo::Done(5), b"hello".to_vec()));
        assert_eq!(read_all(r, 8).0, PipeIo::WouldBlock, "empty with a live writer blocks");
        // The writer's handle goes (close, move-and-exit, its task's exit):
        // the parked reader is the one to wake, and it now sees EOF.
        assert_eq!(pipe_typed_drop_end(r, true), 8);
        assert_eq!(read_all(r, 8).0, PipeIo::Eof);
    }

    /// Wave 13: the ring is copied in at most two slices. Bytes that wrap
    /// past the end of the 4 KiB buffer, in both directions, come out in
    /// order, and a partial read leaves the rest for the next.
    #[test]
    fn bytes_wrapping_the_ring_come_out_in_order() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let fill = vec![0xEEu8; PIPE_BUF_SIZE - 10];
        assert_eq!(pipe_typed_write(r, &fill, 7), (PipeIo::Done(fill.len()), 0));
        assert_eq!(read_all(r, 8), (PipeIo::Done(fill.len()), fill));
        // Positions are now 10 bytes short of the end: 100 bytes wrap.
        let data: Vec<u8> = (0..100u8).collect();
        assert_eq!(pipe_typed_write(r, &data, 7), (PipeIo::Done(100), 0));
        let mut part = [0u8; 7];
        assert_eq!(pipe_typed_read(r, &mut part, 8).0, PipeIo::Done(7));
        assert_eq!(&part[..], &data[..7]);
        assert_eq!(read_all(r, 8), (PipeIo::Done(93), data[7..].to_vec()));
        // Full ring, all of it, across the wrap point.
        let full: Vec<u8> = (0..PIPE_BUF_SIZE).map(|i| (i * 7) as u8).collect();
        assert_eq!(pipe_typed_write(r, &full, 7), (PipeIo::Done(PIPE_BUF_SIZE), 0));
        assert_eq!(pipe_typed_write(r, b"x", 7).0, PipeIo::WouldBlock, "full");
        assert_eq!(read_all(r, 8), (PipeIo::Done(PIPE_BUF_SIZE), full));
    }

    /// An inherited or duplicated end is one more reference (RFC-0047 fork,
    /// round 48): closing the original write end leaves the pipe open, data
    /// still flows through the copy, and EOF follows only the last write end.
    #[test]
    fn an_added_end_keeps_the_pipe_open_until_the_last_close() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert!(pipe_typed_add_end(r, true));
        assert_eq!(pipe_typed_state(r).unwrap().1, 2, "two write ends");
        assert_eq!(pipe_typed_drop_end(r, true), 0, "one write end left: nobody to wake");
        assert_eq!(pipe_typed_write(r, b"ab", 9), (PipeIo::Done(2), 0));
        assert_eq!(read_all(r, 8), (PipeIo::Done(2), b"ab".to_vec()));
        assert_eq!(read_all(r, 8).0, PipeIo::WouldBlock, "a write end is still held");
        pipe_typed_drop_end(r, true);
        assert_eq!(read_all(r, 8).0, PipeIo::Eof, "the last write end closed");
    }

    #[test]
    fn a_write_with_no_reader_left_is_broken() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert_eq!(pipe_typed_drop_end(r, false), 0);
        assert_eq!(pipe_typed_write(r, b"x", 7).0, PipeIo::Broken);
    }

    /// The ring holds PIPE_BUF_SIZE bytes (not one fewer), and a write of at
    /// most that size goes in whole or not at all.
    ///
    /// **Canary.** Make `pipe_typed_write` write what fits for a small
    /// write: the 10-byte write into 6 bytes of room returns `Done(6)`.
    #[test]
    fn a_small_write_is_atomic_and_the_ring_is_full_size() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let big = vec![b'a'; PIPE_BUF_SIZE - 6];
        assert_eq!(pipe_typed_write(r, &big, 7).0, PipeIo::Done(PIPE_BUF_SIZE - 6));
        assert_eq!(pipe_typed_write(r, &[b'b'; 10], 7).0, PipeIo::WouldBlock, "10 bytes do not fit in 6");
        assert_eq!(pipe_typed_state(r).unwrap().2, PIPE_BUF_SIZE - 6, "nothing was written");
        assert_eq!(pipe_typed_write(r, &[b'c'; 6], 7).0, PipeIo::Done(6));
        assert_eq!(pipe_typed_state(r).unwrap().2, PIPE_BUF_SIZE, "the ring is full at its size");
        // The writer parked on a full ring is woken by the read that makes room.
        assert_eq!(pipe_typed_write(r, b"d", 9).0, PipeIo::WouldBlock);
        let mut one = [0u8; 1];
        assert_eq!(pipe_typed_read(r, &mut one, 8), (PipeIo::Done(1), 9));
    }

    #[test]
    fn a_large_write_writes_what_fits() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let big = vec![b'z'; PIPE_BUF_SIZE + 100];
        assert_eq!(pipe_typed_write(r, &big, 7).0, PipeIo::Done(PIPE_BUF_SIZE));
    }

    /// Lifetime follows the handles: the creator's exit does not free a pipe
    /// whose ends were moved on; the last end does, and its resource is stale
    /// from then on, also after the slot is reused.
    #[test]
    fn the_last_end_frees_the_slot_and_old_handles_go_stale() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        pipe_release_all(7); // the untyped per-creator release must not touch it
        assert!(pipe_typed_state(r).is_some());
        pipe_typed_drop_end(r, true);
        assert!(pipe_typed_state(r).is_some(), "one end is still held");
        pipe_typed_drop_end(r, false);
        assert!(pipe_typed_state(r).is_none(), "both ends gone: freed");
        let r2 = pipe_create_typed(7).unwrap();
        assert_eq!(r2 & 0xffff, r & 0xffff, "the same slot comes back");
        assert_ne!(r2, r, "with a new generation");
        assert_eq!(pipe_typed_write(r, b"x", 7).0, PipeIo::Stale);
        assert_eq!(read_all(r, 7).0, PipeIo::Stale);
    }

    #[test]
    fn a_task_holds_at_most_its_quota_of_pipes() {
        let _g = begin();
        for _ in 0..PIPE_QUOTA {
            pipe_create_typed(7).unwrap();
        }
        assert_eq!(pipe_create_typed(7), Err(PipeCreateError::Quota));
        assert!(pipe_create_typed(8).is_ok(), "another task is not charged");
        assert_eq!(pipe_typed_held_by(7), PIPE_QUOTA);
    }

    #[test]
    fn the_untyped_calls_cannot_reach_a_capability_pipe() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        let idx = (r & 0xffff) as usize;
        pipe_typed_write(r, b"secret", 7);
        let mut b = [0u8; 8];
        // Even the kernel's privileged untyped path is refused.
        assert_eq!(pipe_read(idx, b.as_mut_ptr(), b.len()), -1);
        assert_eq!(pipe_close_read(idx), -1);
        assert_eq!(pipe_typed_state(r).unwrap().2, 6);
    }

    #[test]
    fn an_abandoned_waiter_is_forgotten() {
        let _g = begin();
        let r = pipe_create_typed(7).unwrap();
        assert_eq!(read_all(r, 8).0, PipeIo::WouldBlock);
        pipe_typed_unwait(r, 8);
        assert_eq!(pipe_typed_write(r, b"x", 7), (PipeIo::Done(1), 0), "no stale waiter to wake");
    }
}
