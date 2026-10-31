// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The PI futex ops against the kernel's wait graph, with a scripted bucket:
//! an owner whose exit passes while a locker still believes in it, a state made
//! for a block that never slept, and an edge left behind by a word that names
//! its waiter. Its own test binary: the graph and the state pool are process
//! globals. One lock for the tests.

use azos_sync_tests::pi_futex::{block_commit, *};
use azos_sync_tests::waitgraph::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const SLOTS: usize = azos_limits::MAX_TASKS;

struct Sched {
    on: [AtomicUsize; SLOTS],
}

impl SchedPi for Sched {
    fn base_attr(&self, _t: TaskId) -> PiAttr { PiAttr::Fair }
    fn boost(&self, _t: TaskId, _to: PiAttr) {}
    fn unboost(&self, _t: TaskId, _to: PiAttr) {}
    fn set_blocked_on(&self, t: TaskId, on: Option<WaitObj>) {
        self.on[t as usize].store(on.map_or(0, WaitObj::addr), Ordering::Relaxed);
    }
    fn blocked_on(&self, t: TaskId) -> Option<WaitObj> {
        WaitObj::from_addr(self.on[t as usize].load(Ordering::Relaxed))
    }
    fn on_cpu(&self, _t: TaskId) -> bool { false }
}

static S: Sched = Sched { on: [const { AtomicUsize::new(0) }; SLOTS] };
static SERIAL: Mutex<()> = Mutex::new(());

const OWNER: TaskId = 1;
const WAITER: TaskId = 2;
const LOCKER: TaskId = 3;

const fn tid(t: TaskId) -> u32 { t + 100 }

fn tid_of_slot(t: TaskId) -> Option<u32> {
    ((t as usize) < SLOTS).then_some(tid(t))
}

fn setup() -> std::sync::MutexGuard<'static, ()> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ONCE.call_once(|| {
        register_sched(&S);
        register_tid_of(tid_of_slot);
    });
    for t in [OWNER, WAITER, LOCKER] {
        task_reset(t);
    }
    g
}

/// One key's view. `exit_on_lookup` / `exit_on_swap`: the owner's whole exit
/// lands at that point of the locker's hold, the instants the lock does not
/// exclude: the owner's exit takes no futex lock when it holds no robust word.
struct Bucket {
    word: Result<u32, UserFault>,
    slot: u32,
    gone: std::cell::Cell<bool>,
    exit_on_lookup: std::cell::Cell<Option<TaskId>>,
    exit_on_swap: Option<TaskId>,
}

fn bucket(word: u32) -> Bucket {
    Bucket {
        word: Ok(word),
        slot: 0,
        gone: std::cell::Cell::new(false),
        exit_on_lookup: std::cell::Cell::new(None),
        exit_on_swap: None,
    }
}

impl PiBucket for Bucket {
    fn pi_slot(&mut self) -> &mut u32 { &mut self.slot }
    fn read_word(&self) -> Result<u32, UserFault> { self.word }
    fn cmpxchg_word(&mut self, expected: u32, new: u32) -> Result<u32, UserFault> {
        if let Some(t) = self.exit_on_swap.take() {
            task_exit(t);
            self.gone.set(true);
        }
        let w = self.word.as_mut().map_err(|_| UserFault)?;
        let seen = *w;
        if seen == expected {
            *w = new;
        }
        Ok(seen)
    }
    fn task_of_tid(&self, t: u32) -> Option<TaskId> {
        let slot = t.checked_sub(100)?;
        if self.gone.get() {
            return None;
        }
        if let Some(x) = self.exit_on_lookup.take() {
            // Live when looked at; exited by the time the locker acts on it.
            task_exit(x);
            self.gone.set(true);
        }
        Some(slot)
    }
    fn tid_exiting(&self, _t: u32) -> bool { self.gone.get() }
}

fn block(b: &mut Bucket, me: TaskId) -> PendingBlock {
    match PI_FUTEX.lock_pi_prepare(b, me, false) {
        LockPiStep::Block(p) => p,
        _ => panic!("the locker did not block"),
    }
}

/// The waiter sleeping on `b`'s word, its owner [`OWNER`].
fn parked_on(b: &mut Bucket, me: TaskId) {
    let p = block(b, me);
    assert!(block_commit(p).is_ok());
}

/// The owner's exit lands between the locker's look at it and its `set_owner`:
/// the exit found nothing to hand over, so the state may not take it now. The
/// locker sleeps and prepares again, on an edge to nobody it never sleeps.
#[test]
fn an_owner_exiting_after_the_look_is_refused_as_the_new_owner() {
    let _g = setup();
    let mut b = bucket(tid(OWNER));
    b.exit_on_lookup.set(Some(OWNER));
    let step = PI_FUTEX.lock_pi_prepare(&mut b, LOCKER, false);
    assert!(
        matches!(step, LockPiStep::Retry),
        "the locker linked into an owner whose exit is over: it would sleep forever"
    );
    assert_eq!(S.blocked_on(LOCKER), None);
    assert_eq!(b.slot, 0, "no state stays for it");
}

/// The exit lands after `set_owner` recorded the owner, before the block.
#[test]
fn an_owner_exiting_after_set_owner_is_refused_at_the_block() {
    let _g = setup();
    let mut b = bucket(tid(OWNER));
    b.exit_on_swap = Some(OWNER);
    let step = PI_FUTEX.lock_pi_prepare(&mut b, LOCKER, false);
    assert!(
        matches!(step, LockPiStep::Retry),
        "the locker blocked behind an owner whose exit is over: it would sleep forever"
    );
    assert_eq!(S.blocked_on(LOCKER), None);
    assert_eq!(b.slot, 0, "no state stays for it");
}

/// A reused slot is a live task again.
#[test]
fn a_reused_slot_can_own_again() {
    let _g = setup();
    task_exit(OWNER);
    task_reset(OWNER);
    let mut b = bucket(tid(OWNER));
    parked_on(&mut b, LOCKER);
    assert!(S.blocked_on(LOCKER).is_some());
    PI_FUTEX.lock_pi_leave(&mut b, LOCKER);
    assert_eq!(b.slot, 0);
}

/// `EDEADLK` from the walk: the block is undone and the state made for it goes,
/// or a task that repeats the cycle on fresh words empties the pool for
/// everybody.
#[test]
fn a_refused_block_gives_its_state_back() {
    let _g = setup();
    // WAITER holds `mine` and sleeps on OWNER's `other`; OWNER now locks `mine`.
    let mut other = bucket(tid(LOCKER));
    parked_on(&mut other, WAITER);
    let base = states_in_use();
    for _ in 0..POOL_LEN + 2 {
        let mut mine = bucket(tid(WAITER));
        let p = block(&mut mine, LOCKER);
        assert_eq!(block_commit(p).err(), Some(WaitError::Deadlock), "the cycle is seen");
        PI_FUTEX.lock_pi_leave(&mut mine, LOCKER);
        assert_eq!(mine.slot, 0, "the state of a refused block stayed");
        assert_eq!(states_in_use(), base, "the state pool leaks a state per EDEADLK");
    }
    PI_FUTEX.lock_pi_leave(&mut other, WAITER);
}

/// The proxy enqueue's own refused block.
#[test]
fn a_refused_proxy_enqueue_gives_its_state_back() {
    let _g = setup();
    let mut other = bucket(tid(LOCKER));
    parked_on(&mut other, WAITER);
    let base = states_in_use();
    let mut mine = bucket(tid(WAITER));
    assert!(!proxy_enqueue(&mut mine, tid(LOCKER)), "a cycle: it runs its own LOCK_PI");
    assert_eq!((mine.slot, states_in_use()), (0, base), "the state of a refused enqueue stayed");
    PI_FUTEX.lock_pi_leave(&mut other, WAITER);
}

/// User space wrote the waiter's TID into the word and the waiter woke: 0, off
/// the graph. With the edge left it boosts the old owner for good and its next
/// block links it into two lists.
#[test]
fn a_word_naming_its_waiter_ends_the_edge() {
    let _g = setup();
    let mut b = bucket(tid(OWNER));
    parked_on(&mut b, WAITER);
    b.word = Ok(tid(WAITER) | FUTEX_WAITERS);
    assert_eq!(PI_FUTEX.lock_pi_finish(&mut b, WAITER, false), 0);
    assert_eq!(S.blocked_on(WAITER), None, "returned 0 with its wait-graph edge in place");
    assert_eq!(b.slot, 0, "nobody left: the state goes");

    // Another waiter behind it: the state stays and names the word's owner.
    let mut b = bucket(tid(OWNER));
    parked_on(&mut b, WAITER);
    parked_on(&mut b, LOCKER);
    b.word = Ok(tid(WAITER) | FUTEX_WAITERS);
    assert_eq!(PI_FUTEX.lock_pi_finish(&mut b, WAITER, false), 0);
    assert_eq!(S.blocked_on(WAITER), None);
    let ps = state_of_slot(b.slot);
    assert_eq!(ps.waiters().owner(), Some(WAITER), "the state names the word's owner");
    PI_FUTEX.lock_pi_leave(&mut b, LOCKER);
    assert_eq!(b.slot, 0);
}

/// A word that cannot be read after the sleep: the finish does not decide, and
/// leaving (a word gone for good) takes the task off the graph.
#[test]
fn a_finish_on_an_unreadable_word_decides_nothing_and_leave_ends_the_edge() {
    let _g = setup();
    let mut b = bucket(tid(OWNER));
    parked_on(&mut b, WAITER);
    b.word = Err(UserFault);
    assert_eq!(PI_FUTEX.lock_pi_finish(&mut b, WAITER, false), -EFAULT);
    assert!(S.blocked_on(WAITER).is_some(), "the fault-in may still find it the owner");
    PI_FUTEX.lock_pi_leave(&mut b, WAITER);
    assert_eq!(S.blocked_on(WAITER), None);
    assert_eq!(b.slot, 0);
}

/// The heir of an exited owner exits before writing the word: a later locker
/// must not sleep behind it.
#[test]
fn a_heir_that_exited_is_not_waited_for() {
    let _g = setup();
    let mut b = bucket(tid(OWNER));
    parked_on(&mut b, WAITER);
    let ps = state_of_slot(b.slot);
    task_exit(OWNER);
    assert_eq!(exit_handover(&mut b, ps.waiters()), Some(WAITER));
    task_exit(WAITER);
    task_reset(OWNER); // the word's TID resolves to nothing: only `gone` below says so
    b.gone.set(true);
    let step = PI_FUTEX.lock_pi_prepare(&mut b, LOCKER, false);
    assert!(!matches!(step, LockPiStep::Block(_)), "the locker blocked behind a heir whose exit is over");
    assert_eq!(b.slot, 0, "the state of a dead heir stayed");
}

/// The heir that does write its TID, with nobody behind it: no state remains,
/// or its later exit could not find it to give it back.
#[test]
fn a_heir_with_no_waiter_behind_it_drops_the_state() {
    let _g = setup();
    let mut b = bucket(tid(OWNER));
    parked_on(&mut b, WAITER);
    let ps = state_of_slot(b.slot);
    task_exit(OWNER);
    assert_eq!(exit_handover(&mut b, ps.waiters()), Some(WAITER));
    assert_eq!(PI_FUTEX.lock_pi_finish(&mut b, WAITER, false), 0);
    assert_eq!(b.word, Ok(tid(WAITER) | FUTEX_WAITERS));
    assert_eq!(b.slot, 0);
}

fn state_of_slot(slot: u32) -> &'static PiState {
    state_by_id(PiStateId::from_raw(slot).expect("a state"))
}
