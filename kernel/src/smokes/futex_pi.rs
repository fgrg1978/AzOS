// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PI futex through the futex table (wave 15 N10w, Kconfig WAIT_GRAPH +
//! FUTEX_PI), every ISA.
//!
//! * `futex_pi_boosts_the_owner`: a fair task owns a PI word (`LOCK_PI` on a
//!   free word); an RT task's `LOCK_PI` blocks on it and the owner's
//!   effective attribute in the wait graph becomes the waiter's; after the
//!   owner's `UNLOCK_PI` the owner is back at its base, the waiter returns
//!   owning the word as `TID | FUTEX_WAITERS` (a handover always sets the
//!   bit, owner 10-10), and its own `UNLOCK_PI` frees the word and the
//!   `pi_state`. With either symbol n the test returns Ok at once.
//!   Canary `canary=futex-pi-no-edge` (`pi_futex::block_commit` drops the
//!   walk): the owner is never boosted, `not ok`.
//! * `futex_pi_owner_exit_hands_over` (N10b): see its section below.
//! * `futex_requeue_pi_hands_the_mutex_over` (N10d): see its section below.

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicUsize, Ordering};

use azos_sched::futex::{pi_call_key, Key, KvaWord};
use azos_sync::pi_futex::{self as pf, PiCmd};
use azos_sync::waitgraph::{self as wg, PiAttr, SchedPi};

/// Fair band: at or above `RT_PRIORITY_THRESHOLD` (12), below idle (31).
const OWNER_PRIO: u32 = 20;
/// RT band, above the standing RT tasks (rt-motor sits at 8).
const WAITER_PRIO: u32 = 4;
/// Any object id no shm region uses: the ktest's own key space.
const KEY: Key = Key::Shared { obj: 0xF17E_0010, offset: 0 };

static WORD: AtomicU32 = AtomicU32::new(0);
static OWNER_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static OWNER_TID: AtomicU32 = AtomicU32::new(0);
static WAITER_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static WAITER_TID: AtomicU32 = AtomicU32::new(0);
static OWNED: AtomicBool = AtomicBool::new(false);
static RELEASE: AtomicBool = AtomicBool::new(false);
static OWNER_DONE: AtomicBool = AtomicBool::new(false);
static WAITER_DONE: AtomicBool = AtomicBool::new(false);
/// The owner's UNLOCK_PI result, and whether it was back at its base
/// right after it (sampled by the owner itself: the reaper races a reader).
static OWNER_UNLOCK_RC: AtomicI64 = AtomicI64::new(i64::MIN);
static OWNER_RESTORED: AtomicBool = AtomicBool::new(false);
/// The waiter's LOCK_PI result, the word it saw on return, its UNLOCK_PI.
static WAITER_LOCK_RC: AtomicI64 = AtomicI64::new(i64::MIN);
static WAITER_SAW: AtomicU32 = AtomicU32::new(0);
static WAITER_UNLOCK_RC: AtomicI64 = AtomicI64::new(i64::MIN);

fn word() -> KvaWord {
    KvaWord(&WORD)
}

fn sleep_ms(ms: u64) {
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let due = azos_drv_sys::timebase::now() + ms * per_ms;
    azos_sched::task_block(azos_sched::WaitReason::Timer(due));
}

fn base_of(slot: usize) -> PiAttr {
    azos_sched::classes::PI.base_attr(slot as wg::TaskId)
}

fn owner(_: usize) {
    let Some(me) = azos_sched::classes::current() else { return };
    OWNER_SLOT.store(me, Ordering::Release);
    OWNER_TID.store(azos_sched::scheduler::current_task_tid(), Ordering::Release);
    if pi_call_key(KEY, &word(), PiCmd::Lock { deadline: None }) != 0 {
        OWNER_DONE.store(true, Ordering::Release);
        return;
    }
    OWNED.store(true, Ordering::Release);
    // Bounded: a runner that never says release still ends the test.
    for _ in 0..10_000 {
        if RELEASE.load(Ordering::Acquire) {
            break;
        }
        sleep_ms(1);
    }
    OWNER_UNLOCK_RC.store(pi_call_key(KEY, &word(), PiCmd::Unlock), Ordering::Release);
    let e = wg::effective(me as wg::TaskId);
    OWNER_RESTORED.store(e.is_none() || e == Some(base_of(me)), Ordering::Release);
    OWNER_DONE.store(true, Ordering::Release);
}

fn waiter(_: usize) {
    let Some(me) = azos_sched::classes::current() else { return };
    WAITER_SLOT.store(me, Ordering::Release);
    WAITER_TID.store(azos_sched::scheduler::current_task_tid(), Ordering::Release);
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let deadline = azos_drv_sys::timebase::now() + 10_000 * per_ms;
    let rc = pi_call_key(KEY, &word(), PiCmd::Lock { deadline: Some(deadline) });
    WAITER_SAW.store(WORD.load(Ordering::Acquire), Ordering::Release);
    WAITER_LOCK_RC.store(rc, Ordering::Release);
    if rc == 0 {
        WAITER_UNLOCK_RC.store(pi_call_key(KEY, &word(), PiCmd::Unlock), Ordering::Release);
    }
    WAITER_DONE.store(true, Ordering::Release);
}

/// Let both tasks finish before a verdict (or a failure) is returned.
fn finish() -> Result<(), &'static str> {
    RELEASE.store(true, Ordering::Release);
    crate::ktest::wait("the PI owner or waiter never finished", || {
        OWNER_DONE.load(Ordering::Acquire) && WAITER_DONE.load(Ordering::Acquire)
    })
}

azos_ktest::ktest_late! {
    fn futex_pi_boosts_the_owner() {
        if !pf::ENABLED || !wg::ENABLED {
            return Ok(());
        }
        if pf::ops().is_none() {
            return Err("FUTEX_PI is y but no PI futex ops are registered");
        }
        WORD.store(0, Ordering::Release);
        let used = pf::states_in_use();
        azos_sched::task_create_affinity("n10-pi-owner", owner, 0, OWNER_PRIO, -1);
        crate::ktest::wait("the fair owner never took the free PI word", || {
            OWNED.load(Ordering::Acquire) || OWNER_DONE.load(Ordering::Acquire)
        })?;
        let (o, otid) = (OWNER_SLOT.load(Ordering::Acquire), OWNER_TID.load(Ordering::Acquire));
        if !OWNED.load(Ordering::Acquire) || WORD.load(Ordering::Acquire) != otid {
            WAITER_DONE.store(true, Ordering::Release);
            finish()?;
            return Err("LOCK_PI on a free word did not write the owner's TID");
        }
        if base_of(o) != PiAttr::Fair {
            WAITER_DONE.store(true, Ordering::Release);
            finish()?;
            return Err("the owner is not in the fair class (OWNER_PRIO)");
        }
        azos_sched::task_create_affinity("n10-pi-waiter", waiter, 0, WAITER_PRIO, -1);
        let boosted = || {
            let w = WAITER_SLOT.load(Ordering::Acquire);
            w != usize::MAX
                && azos_sched::classes::PI.blocked_on(w as wg::TaskId).is_some()
                && wg::effective(o as wg::TaskId) == Some(base_of(w))
        };
        // Bounded well under the late timeout: the walk runs before the
        // waiter sleeps, so a boost that has not come in 1 s never will.
        let ok = azos_syscall::sleep::wait_until_ms(1000, 10, boosted);
        if !ok {
            finish()?;
            return Err("an RT LOCK_PI waiter did not boost the fair owner (no graph edge)");
        }
        finish()?;
        if OWNER_UNLOCK_RC.load(Ordering::Acquire) != 0 {
            return Err("the owner's UNLOCK_PI failed");
        }
        if !OWNER_RESTORED.load(Ordering::Acquire) {
            return Err("the owner kept the waiter's boost after UNLOCK_PI");
        }
        let wtid = WAITER_TID.load(Ordering::Acquire);
        if WAITER_LOCK_RC.load(Ordering::Acquire) != 0 {
            return Err("the RT waiter's LOCK_PI did not return owning the word");
        }
        if WAITER_SAW.load(Ordering::Acquire) != wtid | pf::FUTEX_WAITERS {
            return Err("the handover word was not TID | FUTEX_WAITERS");
        }
        if WAITER_UNLOCK_RC.load(Ordering::Acquire) != 0 || WORD.load(Ordering::Acquire) != 0 {
            return Err("the new owner's UNLOCK_PI did not free the word");
        }
        // The entry returns to the pool after a grace period (`call_rcu`).
        crate::ktest::wait("the pi_state was not retired after the last waiter", || {
            pf::states_in_use() == used
        })
    }
}

// ── N10b: an owner that exits holding the word hands it over ──────────────
//
// `futex_pi_owner_exit_hands_over`: a fair task takes a PI word and exits
// without UNLOCK_PI (no robust list) while an RT task waits on it in
// LOCK_PI. The graph's owner-exit hook (Linux `exit_pi_state_list`, owner
// decision 10-10) makes the waiter the owner: its LOCK_PI returns 0 with
// the word `TID | FUTEX_WAITERS` (no `FUTEX_OWNER_DIED`: the owner had no
// robust entry for the word, owner decision 10-10 as Linux), and its
// UNLOCK_PI frees it. Ok at once with WAIT_GRAPH or FUTEX_PI n. Canary
// `canary=futex-pi-exit-silent`: the hook does nothing, the waiter's
// LOCK_PI times out, `not ok`.

const EXIT_KEY: Key = Key::Shared { obj: 0xF17E_0011, offset: 0 };
static EXIT_WORD: AtomicU32 = AtomicU32::new(0);
static EXIT_OWNED: AtomicBool = AtomicBool::new(false);
static EXIT_GO: AtomicBool = AtomicBool::new(false);
static EXIT_OWNER_DONE: AtomicBool = AtomicBool::new(false);
static EXIT_WAITER_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static EXIT_WAITER_TID: AtomicU32 = AtomicU32::new(0);
static EXIT_WAITER_DONE: AtomicBool = AtomicBool::new(false);
static EXIT_LOCK_RC: AtomicI64 = AtomicI64::new(i64::MIN);
static EXIT_SAW: AtomicU32 = AtomicU32::new(0);
static EXIT_UNLOCK_RC: AtomicI64 = AtomicI64::new(i64::MIN);

fn exit_word() -> KvaWord {
    KvaWord(&EXIT_WORD)
}

/// Takes the word, waits for the go, and returns still holding it: the
/// task's exit is the release.
fn exit_owner(_: usize) {
    if pi_call_key(EXIT_KEY, &exit_word(), PiCmd::Lock { deadline: None }) == 0 {
        EXIT_OWNED.store(true, Ordering::Release);
        for _ in 0..10_000 {
            if EXIT_GO.load(Ordering::Acquire) {
                break;
            }
            sleep_ms(1);
        }
    }
    EXIT_OWNER_DONE.store(true, Ordering::Release);
}

fn exit_waiter(_: usize) {
    let Some(me) = azos_sched::classes::current() else { return };
    EXIT_WAITER_SLOT.store(me, Ordering::Release);
    EXIT_WAITER_TID.store(azos_sched::scheduler::current_task_tid(), Ordering::Release);
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let deadline = azos_drv_sys::timebase::now() + 2_000 * per_ms;
    let rc = pi_call_key(EXIT_KEY, &exit_word(), PiCmd::Lock { deadline: Some(deadline) });
    EXIT_SAW.store(EXIT_WORD.load(Ordering::Acquire), Ordering::Release);
    EXIT_LOCK_RC.store(rc, Ordering::Release);
    if rc == 0 {
        EXIT_UNLOCK_RC.store(pi_call_key(EXIT_KEY, &exit_word(), PiCmd::Unlock), Ordering::Release);
    }
    EXIT_WAITER_DONE.store(true, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn futex_pi_owner_exit_hands_over() {
        if !pf::ENABLED || !wg::ENABLED {
            return Ok(());
        }
        if pf::ops().is_none() {
            return Err("FUTEX_PI is y but no PI futex ops are registered");
        }
        EXIT_WORD.store(0, Ordering::Release);
        azos_sched::task_create_affinity("n10b-pi-owner", exit_owner, 0, OWNER_PRIO, -1);
        crate::ktest::wait("the owner never took the free PI word", || {
            EXIT_OWNED.load(Ordering::Acquire) || EXIT_OWNER_DONE.load(Ordering::Acquire)
        })?;
        if !EXIT_OWNED.load(Ordering::Acquire) {
            return Err("LOCK_PI on a free word failed");
        }
        azos_sched::task_create_affinity("n10b-pi-waiter", exit_waiter, 0, WAITER_PRIO, -1);
        let blocked = || {
            let w = EXIT_WAITER_SLOT.load(Ordering::Acquire);
            w != usize::MAX && azos_sched::classes::PI.blocked_on(w as wg::TaskId).is_some()
        };
        let ok = azos_syscall::sleep::wait_until_ms(1000, 10, blocked);
        // The owner exits holding the word either way.
        EXIT_GO.store(true, Ordering::Release);
        crate::ktest::wait("the waiter never returned from LOCK_PI", || EXIT_WAITER_DONE.load(Ordering::Acquire))?;
        if !ok {
            return Err("the RT waiter never blocked on the owned PI word");
        }
        if EXIT_LOCK_RC.load(Ordering::Acquire) != 0 {
            return Err("the owner exited holding the PI word and its waiter was not handed it");
        }
        let wtid = EXIT_WAITER_TID.load(Ordering::Acquire);
        if EXIT_SAW.load(Ordering::Acquire) != wtid | pf::FUTEX_WAITERS {
            return Err("the heir's word was not TID | FUTEX_WAITERS (OWNER_DIED is the robust list's alone)");
        }
        if EXIT_UNLOCK_RC.load(Ordering::Acquire) != 0 || EXIT_WORD.load(Ordering::Acquire) != 0 {
            return Err("the heir's UNLOCK_PI did not free the word");
        }
        Ok(())
    }
}

// ── N10d/N10e: FUTEX_WAIT_REQUEUE_PI / FUTEX_CMP_REQUEUE_PI ────────────────
//
// `futex_requeue_pi_hands_the_mutex_over`: a fair task holds a PI word
// while two RT tasks wait on a condition word as requeue-PI waiters bound
// for it (Linux semantics, the condition variable of a PI mutex). A plain
// FUTEX_WAKE or FUTEX_REQUEUE that would reach them answers EINVAL taking
// neither (owner decision 10-10, as Linux), and a CMP_REQUEUE_PI with the
// wrong cmpval answers EAGAIN. Then CMP_REQUEUE_PI (nr_requeue INT_MAX)
// takes both (returns 2) and enqueues them on the PI word's graph object
// by proxy (owner decision 10-10, Linux rt_mutex_start_proxy_lock): both
// stay asleep, unwoken, and the fair owner runs boosted to their priority
// at once. Its UNLOCK_PI hands the word to the top one, whose UNLOCK_PI
// hands it to the other: each returns 0 seeing its own TID in the word,
// never both inside at once, the word ends free and the owner loses the
// boost. Ok at once with WAIT_GRAPH or FUTEX_PI n. Canaries:
// `canary=futex-requeue-pi-plain` (the requeue wakes both as plain wakes,
// they return EAGAIN) and `canary=futex-requeue-pi-no-proxy` (they wake
// requeued and lock the word themselves, nobody is proxied): `not ok`.

const RQ_COND_KEY: Key = Key::Shared { obj: 0xF17E_0012, offset: 0 };
const RQ_MUTEX_KEY: Key = Key::Shared { obj: 0xF17E_0013, offset: 0 };
const RQ_WAITERS: usize = 2;
static RQ_COND: AtomicU32 = AtomicU32::new(0);
static RQ_MUTEX: AtomicU32 = AtomicU32::new(0);
static RQ_INSIDE: AtomicU32 = AtomicU32::new(0);
static RQ_OVERLAP: AtomicBool = AtomicBool::new(false);
static RQ_DONE: AtomicUsize = AtomicUsize::new(0);
static RQ_SLOT: [AtomicUsize; RQ_WAITERS] = [const { AtomicUsize::new(usize::MAX) }; RQ_WAITERS];
static RQ_RC: [AtomicI64; RQ_WAITERS] = [const { AtomicI64::new(i64::MIN) }; RQ_WAITERS];
static RQ_OWNED_OWN: [AtomicBool; RQ_WAITERS] = [const { AtomicBool::new(false) }; RQ_WAITERS];
static RQ_UNLOCK_RC: [AtomicI64; RQ_WAITERS] = [const { AtomicI64::new(i64::MIN) }; RQ_WAITERS];
static RQ_OWNER_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static RQ_OWNER_TID: AtomicU32 = AtomicU32::new(0);
static RQ_OWNED: AtomicBool = AtomicBool::new(false);
static RQ_RELEASE: AtomicBool = AtomicBool::new(false);
static RQ_OWNER_DONE: AtomicBool = AtomicBool::new(false);
static RQ_OWNER_UNLOCK_RC: AtomicI64 = AtomicI64::new(i64::MIN);
static RQ_OWNER_RESTORED: AtomicBool = AtomicBool::new(false);

/// The fair owner of the PI word: takes it, holds it until the release.
fn rq_owner(_: usize) {
    let Some(me) = azos_sched::classes::current() else {
        RQ_OWNER_DONE.store(true, Ordering::Release);
        return;
    };
    RQ_OWNER_SLOT.store(me, Ordering::Release);
    RQ_OWNER_TID.store(azos_sched::scheduler::current_task_tid(), Ordering::Release);
    if pi_call_key(RQ_MUTEX_KEY, &KvaWord(&RQ_MUTEX), PiCmd::Lock { deadline: None }) != 0 {
        RQ_OWNER_DONE.store(true, Ordering::Release);
        return;
    }
    RQ_OWNED.store(true, Ordering::Release);
    // Bounded: a runner that never says release still ends the test.
    for _ in 0..10_000 {
        if RQ_RELEASE.load(Ordering::Acquire) {
            break;
        }
        sleep_ms(1);
    }
    RQ_OWNER_UNLOCK_RC.store(pi_call_key(RQ_MUTEX_KEY, &KvaWord(&RQ_MUTEX), PiCmd::Unlock), Ordering::Release);
    let e = wg::effective(me as wg::TaskId);
    RQ_OWNER_RESTORED.store(e.is_none() || e == Some(base_of(me)), Ordering::Release);
    RQ_OWNER_DONE.store(true, Ordering::Release);
}

fn rq_waiter(i: usize) {
    let me = azos_sched::scheduler::current_task_tid();
    if let Some(slot) = azos_sched::classes::current() {
        RQ_SLOT[i].store(slot, Ordering::Release);
    }
    let per_ms = (azos_drv_sys::timebase::TIMER_FREQ / 1000).max(1);
    let deadline = azos_drv_sys::timebase::now() + 4_000 * per_ms;
    let read = || Some(RQ_COND.load(Ordering::Acquire));
    let rc = azos_sched::futex::wait_requeue_pi(RQ_COND_KEY, RQ_MUTEX_KEY, 0, Some(deadline), &read, &KvaWord(&RQ_MUTEX));
    RQ_RC[i].store(rc, Ordering::Release);
    if rc == 0 {
        RQ_OWNED_OWN[i].store(RQ_MUTEX.load(Ordering::Acquire) & pf::FUTEX_TID_MASK == me, Ordering::Release);
        if RQ_INSIDE.fetch_add(1, Ordering::AcqRel) != 0 {
            RQ_OVERLAP.store(true, Ordering::Release);
        }
        sleep_ms(2);
        RQ_INSIDE.fetch_sub(1, Ordering::AcqRel);
        RQ_UNLOCK_RC[i].store(pi_call_key(RQ_MUTEX_KEY, &KvaWord(&RQ_MUTEX), PiCmd::Unlock), Ordering::Release);
    }
    RQ_DONE.fetch_add(1, Ordering::AcqRel);
}

/// Release the owner and let every task finish before a verdict.
fn rq_finish() -> Result<(), &'static str> {
    RQ_RELEASE.store(true, Ordering::Release);
    crate::ktest::wait("a requeue-PI waiter or the PI owner never returned", || {
        RQ_DONE.load(Ordering::Acquire) == RQ_WAITERS && RQ_OWNER_DONE.load(Ordering::Acquire)
    })
}

azos_ktest::ktest_late! {
    fn futex_requeue_pi_hands_the_mutex_over() {
        use azos_sched::futex_table as ft;
        if !pf::ENABLED || !wg::ENABLED {
            return Ok(());
        }
        if pf::ops().is_none() {
            return Err("FUTEX_PI is y but no PI futex ops are registered");
        }
        RQ_COND.store(0, Ordering::Release);
        RQ_MUTEX.store(0, Ordering::Release);
        azos_sched::task_create_affinity("n10e-rq-owner", rq_owner, 0, OWNER_PRIO, -1);
        crate::ktest::wait("the fair owner never took the free PI word", || {
            RQ_OWNED.load(Ordering::Acquire) || RQ_OWNER_DONE.load(Ordering::Acquire)
        })?;
        let o = RQ_OWNER_SLOT.load(Ordering::Acquire);
        let owned = RQ_OWNED.load(Ordering::Acquire) && RQ_MUTEX.load(Ordering::Acquire) == RQ_OWNER_TID.load(Ordering::Acquire);
        for i in 0..RQ_WAITERS {
            azos_sched::task_create_affinity("n10d-rq-waiter", rq_waiter, i, WAITER_PRIO, -1);
        }
        let filed = || ft::TABLE.lock_irqsave().waiters_on(RQ_COND_KEY) == RQ_WAITERS;
        let ok = azos_syscall::sleep::wait_until_ms(1000, 10, filed);
        let read = || Some(RQ_COND.load(Ordering::Acquire));
        let mutex = KvaWord(&RQ_MUTEX);
        // Neither a plain wake, a plain requeue nor a requeue-PI with a
        // stale cmpval takes them.
        let plain = azos_sched::futex::wake_key(RQ_COND_KEY, 8);
        let moved = azos_sched::futex::requeue(RQ_COND_KEY, RQ_MUTEX_KEY, 0, 8, None, &read);
        let stale = azos_sched::futex::cmp_requeue_pi(RQ_COND_KEY, RQ_MUTEX_KEY, i32::MAX as u32, 7, &read, &mutex);
        RQ_COND.store(1, Ordering::Release);
        let n = azos_sched::futex::cmp_requeue_pi(RQ_COND_KEY, RQ_MUTEX_KEY, i32::MAX as u32, 1, &read, &mutex);
        // Proxied: both asleep and enqueued on the PI word's object, the
        // owner boosted to their priority, before anyone is released.
        let proxied = ft::TABLE.lock_irqsave().proxied();
        let boosted = || {
            let w = RQ_SLOT[0].load(Ordering::Acquire);
            w != usize::MAX
                && RQ_SLOT.iter().all(|s| {
                    let s = s.load(Ordering::Acquire);
                    s != usize::MAX && azos_sched::classes::PI.blocked_on(s as wg::TaskId).is_some()
                })
                && wg::effective(o as wg::TaskId) == Some(base_of(w))
        };
        let boost = o != usize::MAX && azos_syscall::sleep::wait_until_ms(1000, 10, boosted);
        let asleep = RQ_DONE.load(Ordering::Acquire) == 0 && RQ_RC.iter().all(|r| r.load(Ordering::Acquire) == i64::MIN);
        rq_finish()?;
        if !owned {
            return Err("LOCK_PI on the free PI word did not write the fair owner's TID");
        }
        if !ok {
            return Err("the requeue-PI waiters never filed on the condition word");
        }
        if plain != -azos_sched::futex::EINVAL {
            return Err("a plain FUTEX_WAKE reaching a requeue-PI waiter did not answer EINVAL");
        }
        if ft::REQUEUE && moved != Err(-azos_sched::futex::EINVAL) {
            return Err("a plain FUTEX_REQUEUE reaching a requeue-PI waiter did not answer EINVAL");
        }
        if stale != -azos_sched::futex::EAGAIN {
            return Err("CMP_REQUEUE_PI with a changed word did not answer EAGAIN");
        }
        if n != RQ_WAITERS as i64 {
            return Err("CMP_REQUEUE_PI did not take both waiters");
        }
        if proxied != RQ_WAITERS {
            return Err("CMP_REQUEUE_PI did not enqueue both waiters on the PI word by proxy");
        }
        if !boost || !asleep {
            return Err("the PI owner was not boosted while the requeued waiters slept");
        }
        for i in 0..RQ_WAITERS {
            if RQ_RC[i].load(Ordering::Acquire) != 0 {
                return Err("a requeue-PI waiter did not return owning the PI word");
            }
            if !RQ_OWNED_OWN[i].load(Ordering::Acquire) {
                return Err("a requeue-PI waiter returned without its TID in the PI word");
            }
            if RQ_UNLOCK_RC[i].load(Ordering::Acquire) != 0 {
                return Err("a requeue-PI waiter's UNLOCK_PI failed");
            }
        }
        if RQ_OWNER_UNLOCK_RC.load(Ordering::Acquire) != 0 {
            return Err("the fair owner's UNLOCK_PI failed");
        }
        if !RQ_OWNER_RESTORED.load(Ordering::Acquire) {
            return Err("the fair owner kept the requeued waiters' boost after UNLOCK_PI");
        }
        if RQ_OVERLAP.load(Ordering::Acquire) {
            return Err("two requeue-PI waiters held the PI word at once");
        }
        if RQ_MUTEX.load(Ordering::Acquire) != 0 || ft::TABLE.lock_irqsave().waiters_on(RQ_COND_KEY) != 0 {
            return Err("the PI word or the condition's chain was left behind");
        }
        Ok(())
    }
}
