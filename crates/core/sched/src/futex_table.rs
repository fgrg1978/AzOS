// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The futex table (wave 15 N9): one table for every word a task can sleep
//! on, whichever call filed it.
//!
//! # Keys
//!
//! * [`Key::Private`]: `(domain, user address)`. The domain is the process
//!   id (`group::proc_of`), so the members of one thread group meet on a
//!   word and nothing outside the group can. What Linux files under
//!   `FUTEX_PRIVATE_FLAG`, and what a "shared" Linux futex on memory that is
//!   not a shm region falls back to (that memory is the process's alone).
//! * [`Key::Shared`]: `(object id, offset)`, the packed reference of a shm
//!   region and the byte offset of the word in it (owner answer Q5). Two
//!   tasks that map the region at different addresses meet on it; no
//!   physical address is ever a key. The native notify calls
//!   (`SYS_NOTIFY_WAIT`/`WAKE`, `azos_ipc::notify`) and a Linux futex without
//!   `FUTEX_PRIVATE_FLAG` on a shm word file here, so they meet each other.
//!   Kconfig `FUTEX_SHARED` n: the Linux call never builds one (the notify
//!   calls still do: they are the native ABI).
//!
//! # Buckets
//!
//! A key hashes to one bucket, a FIFO chain of rows. Private keys hash into
//! the bank of their domain (`FUTEX_DOMAIN_BANKS` banks of
//! `FUTEX_PRIVATE_BUCKETS`), so one process's words never share a chain with
//! another's unless their domain ids collide on a bank; shared keys have
//! their own `FUTEX_SHARED_BUCKETS`. A wake or a requeue walks one chain,
//! not the table. Every bucket carries a [`PiState`] slot, empty until the
//! PI futex (N10) fills it.
//!
//! One lock ([`TABLE`]) covers the table: requeue moves rows between two
//! chains under it with no lock order to get wrong. Per-bucket locks are a
//! later, measured step.
//!
//! # No lost wake
//!
//! A wait reads the word and files its row under the lock; a wake takes the
//! same lock, even when it finds nobody. A waker that stored before the
//! check makes the check fail; one that stores after it finds the row. The
//! TID-directed wake goes out after the lock is released, and a waiter that
//! has not blocked yet is stamped (K-C9), so its block returns at once.
//!
//! The lock is only taken with `lock_irqsave`: a kernel producer may wake a
//! shared key from an interrupt (`vdso_notify::notify_wake_kernel`).

use azos_sync::SpinLock;

/// Private buckets per domain bank (Kconfig `FUTEX_PRIVATE_BUCKETS`).
pub const PRIVATE_BUCKETS: usize = azos_limits::FUTEX_PRIVATE_BUCKETS;
/// Domain banks of private buckets (Kconfig `FUTEX_DOMAIN_BANKS`).
pub const DOMAIN_BANKS: usize = azos_limits::FUTEX_DOMAIN_BANKS;
/// Buckets of shared keys (Kconfig `FUTEX_SHARED_BUCKETS`).
pub const SHARED_BUCKETS: usize = azos_limits::FUTEX_SHARED_BUCKETS;
/// Every bucket of the table.
pub const BUCKETS: usize = DOMAIN_BANKS * PRIVATE_BUCKETS + SHARED_BUCKETS;
/// One row per task: a task waits on one word at a time.
pub const ROWS: usize = azos_limits::MAX_TASKS;
/// Kconfig `FUTEX_SHARED`: a Linux futex without `FUTEX_PRIVATE_FLAG` on a
/// shm word is keyed by the region.
pub const SHARED: bool = azos_limits::FUTEX_SHARED;
/// Kconfig `FUTEX_REQUEUE`: `FUTEX_REQUEUE` / `FUTEX_CMP_REQUEUE` answered.
pub const REQUEUE: bool = azos_limits::FUTEX_REQUEUE;

const _: () = assert!(PRIVATE_BUCKETS > 0 && DOMAIN_BANKS > 0 && SHARED_BUCKETS > 0);
const _: () = assert!(BUCKETS < NIL as usize && ROWS < NIL as usize);

const NIL: u16 = u16::MAX;

const FREE: u8 = 0;
const WAITING: u8 = 1;
const WOKEN: u8 = 2;
/// Taken by the exit sweep of a robust word's owner (`notify_robust_exit`).
const WOKEN_DIED: u8 = 3;

/// What a waiter is filed under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    /// A process-private word: `(process id, user address)`.
    Private { domain: u32, addr: u64 },
    /// A word in a shm region: `(packed region reference, byte offset)`.
    Shared { obj: u32, offset: u32 },
}

#[inline(always)]
fn mix(x: u64) -> u64 {
    // Fibonacci hashing: the high bits of the product are well mixed.
    x.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32
}

impl Key {
    /// The bucket this key is filed in.
    #[inline]
    pub fn bucket(&self) -> usize {
        match *self {
            Key::Private { domain, addr } => {
                let bank = mix(domain as u64) as usize % DOMAIN_BANKS;
                bank * PRIVATE_BUCKETS + mix(addr >> 2) as usize % PRIVATE_BUCKETS
            }
            Key::Shared { obj, offset } => {
                DOMAIN_BANKS * PRIVATE_BUCKETS
                    + mix(((obj as u64) << 32) | (offset >> 2) as u64) as usize % SHARED_BUCKETS
            }
        }
    }

    /// Both keys are of the same kind (a requeue never crosses kinds).
    pub fn same_kind(&self, other: &Key) -> bool {
        matches!((self, other), (Key::Private { .. }, Key::Private { .. }) | (Key::Shared { .. }, Key::Shared { .. }))
    }
}

/// The priority-inheritance state of a bucket's PI word. Empty until N10
/// (PI futex) fills it; the slot exists now so the bucket shape does not
/// change then.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PiState {
    /// TID of the owner the kernel knows of (0: none).
    pub owner_tid: u32,
    /// Waiters the owner is boosted for.
    pub waiters: u16,
}

#[derive(Clone, Copy)]
struct Row {
    state: u8,
    next: u16,
    tid: u32,
    deadline: u64,
    key: Key,
}

const EMPTY: Row = Row { state: FREE, next: NIL, tid: 0, deadline: 0, key: Key::Shared { obj: 0, offset: 0 } };

#[derive(Clone, Copy)]
struct Bucket {
    head: u16,
    tail: u16,
    pi: PiState,
}

const NO_BUCKET: Bucket = Bucket { head: NIL, tail: NIL, pi: PiState { owner_tid: 0, waiters: 0 } };

/// What [`FutexTable::settle`] found for a waiter back from a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Settle {
    /// A wake took it. The row is freed.
    Woken,
    /// The exit sweep of the word's robust owner took it. The row is freed.
    OwnerDied,
    /// Still filed (a spurious return). The row is kept.
    Waiting,
}

/// The table. Pure data and pure methods, so the host suites drive every
/// transition without a scheduler.
pub struct FutexTable {
    rows: [Row; ROWS],
    buckets: [Bucket; BUCKETS],
    /// Rows in `WAITING`. A wake that finds none returns without hashing.
    waiting: usize,
}

impl Default for FutexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexTable {
    pub const fn new() -> Self {
        Self { rows: [EMPTY; ROWS], buckets: [NO_BUCKET; BUCKETS], waiting: 0 }
    }

    fn push(&mut self, b: usize, i: usize) {
        self.rows[i].next = NIL;
        let tail = self.buckets[b].tail;
        if tail == NIL {
            self.buckets[b].head = i as u16;
        } else {
            self.rows[tail as usize].next = i as u16;
        }
        self.buckets[b].tail = i as u16;
    }

    /// Unlink row `i` from bucket `b`, whose chain holds it.
    fn unlink(&mut self, b: usize, i: usize) {
        let mut prev = NIL;
        let mut cur = self.buckets[b].head;
        while cur != NIL && cur as usize != i {
            prev = cur;
            cur = self.rows[cur as usize].next;
        }
        if cur == NIL {
            return;
        }
        let next = self.rows[i].next;
        if prev == NIL {
            self.buckets[b].head = next;
        } else {
            self.rows[prev as usize].next = next;
        }
        if self.buckets[b].tail as usize == i {
            self.buckets[b].tail = prev;
        }
        self.rows[i].next = NIL;
    }

    /// File `tid` as waiting on `key` until `deadline`, at the tail of its
    /// bucket. `None` when every row is taken (unreachable while each task
    /// has at most one waiter; answered rather than assumed).
    pub fn register(&mut self, tid: u32, key: Key, deadline: u64) -> Option<usize> {
        let start = tid as usize % ROWS;
        let i = (0..ROWS).map(|k| (start + k) % ROWS).find(|&i| self.rows[i].state == FREE)?;
        self.rows[i] = Row { state: WAITING, next: NIL, tid, deadline, key };
        self.push(key.bucket(), i);
        self.waiting += 1;
        Some(i)
    }

    /// Take up to `n` waiters on `key`, oldest first, writing each one's
    /// `(tid, deadline)` into `out`; marked owner-died when `died`. Returns
    /// how many. A row taken leaves its chain at once.
    pub fn wake_as(&mut self, key: Key, n: u32, out: &mut [(u32, u64)], died: bool) -> usize {
        if self.waiting == 0 {
            return 0;
        }
        let b = key.bucket();
        let mark = if died { WOKEN_DIED } else { WOKEN };
        let mut k = 0usize;
        let mut cur = self.buckets[b].head;
        while cur != NIL && (k as u64) < n as u64 && k < out.len() {
            let i = cur as usize;
            cur = self.rows[i].next;
            if self.rows[i].state == WAITING && self.rows[i].key == key {
                self.unlink(b, i);
                self.rows[i].state = mark;
                out[k] = (self.rows[i].tid, self.rows[i].deadline);
                k += 1;
            }
        }
        self.waiting -= k;
        k
    }

    /// [`wake_as`](Self::wake_as) for a plain wake.
    pub fn wake(&mut self, key: Key, n: u32, out: &mut [(u32, u64)]) -> usize {
        self.wake_as(key, n, out, false)
    }

    /// Move up to `n` waiters on `from` to `to`, oldest first, keeping their
    /// order; returns how many. They stay asleep: a later wake on `to` takes
    /// them. Nothing moves across key kinds.
    pub fn requeue(&mut self, from: Key, to: Key, n: u32) -> u32 {
        if self.waiting == 0 || n == 0 || from == to || !from.same_kind(&to) {
            return 0;
        }
        let (bf, bt) = (from.bucket(), to.bucket());
        let mut moved = 0u32;
        let mut cur = self.buckets[bf].head;
        while cur != NIL && moved < n {
            let i = cur as usize;
            cur = self.rows[i].next;
            if self.rows[i].state == WAITING && self.rows[i].key == from {
                self.unlink(bf, i);
                self.rows[i].key = to;
                self.push(bt, i);
                moved += 1;
            }
        }
        moved
    }

    /// The waiter in `slot` came back from its block. `tid` guards against
    /// a caller passing somebody else's slot.
    pub fn settle(&mut self, slot: usize, tid: u32) -> Settle {
        let x = self.rows[slot];
        if x.tid != tid || x.state == FREE {
            return Settle::Woken;
        }
        match x.state {
            WOKEN => {
                self.rows[slot] = EMPTY;
                Settle::Woken
            }
            WOKEN_DIED => {
                self.rows[slot] = EMPTY;
                Settle::OwnerDied
            }
            _ => Settle::Waiting,
        }
    }

    /// Withdraw the waiter in `slot` (timeout, refused block, stop), saying
    /// which wake took it first: [`Settle::Waiting`] when none did.
    pub fn cancel_settle(&mut self, slot: usize, tid: u32) -> Settle {
        let x = self.rows[slot];
        if x.tid != tid || x.state == FREE {
            return Settle::Woken;
        }
        let r = match x.state {
            WOKEN => Settle::Woken,
            WOKEN_DIED => Settle::OwnerDied,
            _ => {
                self.unlink(x.key.bucket(), slot);
                self.waiting -= 1;
                Settle::Waiting
            }
        };
        self.rows[slot] = EMPTY;
        r
    }

    /// [`cancel_settle`](Self::cancel_settle): did a wake take it first?
    pub fn cancel(&mut self, slot: usize, tid: u32) -> bool {
        self.cancel_settle(slot, tid) != Settle::Waiting
    }

    /// Rows in use (host tests).
    pub fn in_use(&self) -> usize {
        self.rows.iter().filter(|x| x.state != FREE).count()
    }

    /// Waiters filed on `key` (host tests, ktest).
    pub fn waiters_on(&self, key: Key) -> usize {
        let mut n = 0;
        let mut cur = self.buckets[key.bucket()].head;
        while cur != NIL {
            let r = &self.rows[cur as usize];
            if r.state == WAITING && r.key == key {
                n += 1;
            }
            cur = r.next;
        }
        n
    }

    /// Free every row filed under `key`, woken or not (host tests: rows a
    /// scripted waker took for waiters that never settle).
    pub fn drop_key(&mut self, key: Key) {
        for i in 0..ROWS {
            let x = self.rows[i];
            if x.state != FREE && x.key == key {
                self.cancel_settle(i, x.tid);
            }
        }
    }

    /// The PI slot of `key`'s bucket (N10 fills it).
    pub fn pi_state(&mut self, key: Key) -> &mut PiState {
        &mut self.buckets[key.bucket()].pi
    }
}

/// The one table, under the one lock the lost-wake argument needs.
pub static TABLE: SpinLock<FutexTable> = SpinLock::new(FutexTable::new());

/// How a wait ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WaitResult {
    /// A wake on the key (or on a key it was requeued to) took the waiter.
    Woken,
    /// The exit sweep of the word's robust owner took the waiter.
    OwnerDied,
    /// The deadline passed first.
    TimedOut,
    /// The word did not hold `expected` under the lock: nothing was filed.
    ValueChanged,
    /// The word could not be read: nothing was filed.
    Fault,
    /// The scheduler refused to block (K-C29). Nothing is left filed.
    Refused,
    /// The task was asked to stop (exit_group, a kill). Nothing is left filed.
    Stopped,
    /// Every row is in use.
    NoSpace,
}

/// What the wait and wake need from the rest of the kernel. The kernel's
/// implementations block on `WaitReason::Timer(deadline)` and wake by TID;
/// the host suites script them.
pub trait FutexEnv {
    /// The timebase counter, in the units `deadline` is in.
    fn now(&self) -> u64;
    /// Block the calling task on `WaitReason::Timer(deadline)`; `true` when
    /// the scheduler refused to block (K-C29).
    fn block(&self, deadline: u64) -> bool;
    /// Wake `tid` if it is blocked on `WaitReason::Timer(deadline)` (stamping
    /// it if it has not blocked yet). Must be callable from an interrupt.
    fn wake(&self, tid: u32, deadline: u64);
    /// Has the calling task been asked to stop? A stop ends the wait.
    fn stopped(&self) -> bool {
        false
    }
}

/// Wait on `key` while `read()` holds `expected`, until a wake, `deadline`
/// (`u64::MAX`: none), a stop or a refused block.
pub fn wait_key<E: FutexEnv>(
    env: &E, tid: u32, key: Key, read: &dyn Fn() -> Option<u32>, expected: u32, deadline: u64,
) -> WaitResult {
    let slot = {
        let mut t = TABLE.lock_irqsave();
        match read() {
            None => return WaitResult::Fault,
            Some(v) if v != expected => return WaitResult::ValueChanged,
            Some(_) => {}
        }
        match t.register(tid, key, deadline) {
            Some(s) => s,
            None => return WaitResult::NoSpace,
        }
    };
    let mut refused = false;
    loop {
        {
            let mut t = TABLE.lock_irqsave();
            match t.settle(slot, tid) {
                Settle::Woken => return WaitResult::Woken,
                Settle::OwnerDied => return WaitResult::OwnerDied,
                Settle::Waiting => {}
            }
            // Blocking again after a refusal would be refused again:
            // withdraw, never spin (an infinite timeout would hang this
            // hart). A stop or a deadline is checked BEFORE every block, the
            // first included: a stop raised before the wait is not missed.
            let ended = if refused {
                Some(WaitResult::Refused)
            } else if env.stopped() {
                Some(WaitResult::Stopped)
            } else if deadline != u64::MAX && env.now() >= deadline {
                Some(WaitResult::TimedOut)
            } else {
                None
            };
            if let Some(r) = ended {
                return match t.cancel_settle(slot, tid) {
                    Settle::Woken => WaitResult::Woken,
                    Settle::OwnerDied => WaitResult::OwnerDied,
                    Settle::Waiting => r,
                };
            }
        }
        refused = env.block(deadline);
    }
}

/// Wake-out batch: each batch is taken under one hold and woken after it.
const WAKE_BATCH: usize = 8;

/// Wake up to `n` waiters on `key` (marked owner-died when `died`). Returns
/// how many were taken. Takes the lock even when nobody waits: the ordering
/// argument in the module doc depends on it.
pub fn wake_key<E: FutexEnv>(env: &E, key: Key, n: u32, died: bool) -> u32 {
    let mut total = 0u32;
    loop {
        let mut out = [(0u32, 0u64); WAKE_BATCH];
        let k = TABLE.lock_irqsave().wake_as(key, n - total, &mut out, died);
        for &(tid, deadline) in &out[..k] {
            env.wake(tid, deadline);
        }
        total += k as u32;
        if k < WAKE_BATCH || total >= n {
            return total;
        }
    }
}

/// Linux `FUTEX_CMP_REQUEUE` / `FUTEX_REQUEUE`: under one hold, check that
/// `read()` holds `cmp` (when given), wake up to `nr_wake` waiters on `from`
/// and move up to `nr_requeue` more to `to`. Returns `(woken, moved)`, or
/// `Err(ValueChanged | Fault)` with nothing done.
///
/// `wake_all` is the herd canary: every waiter is woken, nobody is moved
/// (the thundering herd a requeue exists to avoid).
pub fn requeue_key<E: FutexEnv>(
    env: &E, from: Key, to: Key, nr_wake: u32, nr_requeue: u32,
    cmp: Option<(&dyn Fn() -> Option<u32>, u32)>, wake_all: bool,
) -> Result<(u32, u32), WaitResult> {
    let mut out = [(0u32, 0u64); WAKE_BATCH];
    let (k, moved) = {
        let mut t = TABLE.lock_irqsave();
        if let Some((read, want)) = cmp {
            match read() {
                None => return Err(WaitResult::Fault),
                Some(v) if v != want => return Err(WaitResult::ValueChanged),
                Some(_) => {}
            }
        }
        if wake_all {
            (t.wake(from, WAKE_BATCH as u32, &mut out), 0)
        } else {
            let k = t.wake(from, nr_wake.min(WAKE_BATCH as u32), &mut out);
            (k, t.requeue(from, to, nr_requeue))
        }
    };
    for &(tid, deadline) in &out[..k] {
        env.wake(tid, deadline);
    }
    let mut woken = k as u32;
    // The rest of a wake wider than one batch (or the whole herd) is taken
    // after the move; a waiter that arrives on `from` in between is woken
    // like any later waiter would be.
    let more = if wake_all { u32::MAX } else { nr_wake };
    if woken < more && k == WAKE_BATCH {
        woken += wake_key(env, from, more - woken, false);
    }
    Ok((woken, moved))
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn p(domain: u32, addr: u64) -> Key {
        Key::Private { domain, addr }
    }
    const fn s(obj: u32, offset: u32) -> Key {
        Key::Shared { obj, offset }
    }

    #[test]
    fn a_wake_takes_only_its_own_key() {
        let mut t = FutexTable::new();
        let a = t.register(1, p(7, 0x1000), u64::MAX).unwrap();
        let _b = t.register(2, p(8, 0x1000), u64::MAX).unwrap(); // another domain
        let _c = t.register(3, s(7, 0x1000 & 0xffff), u64::MAX).unwrap(); // another kind
        let mut out = [(0, 0); 4];
        assert_eq!(t.wake(p(7, 0x1000), 10, &mut out), 1);
        assert_eq!(out[0].0, 1);
        assert_eq!(t.settle(a, 1), Settle::Woken);
        assert_eq!(t.in_use(), 2);
    }

    #[test]
    fn a_wake_takes_the_oldest_waiters_first() {
        let mut t = FutexTable::new();
        for tid in 10..14 {
            t.register(tid, s(1, 4), u64::MAX).unwrap();
        }
        let mut out = [(0, 0); 4];
        assert_eq!(t.wake(s(1, 4), 2, &mut out), 2);
        assert_eq!((out[0].0, out[1].0), (10, 11));
    }

    #[test]
    fn requeue_moves_the_rest_and_a_wake_on_the_target_takes_them() {
        let mut t = FutexTable::new();
        let cond = p(5, 0x2000);
        let mutex = p(5, 0x2004);
        let rows: Vec<usize> = (20..28).map(|tid| t.register(tid, cond, u64::MAX).unwrap()).collect();
        let mut out = [(0, 0); 8];
        assert_eq!(t.wake(cond, 1, &mut out), 1);
        assert_eq!(t.requeue(cond, mutex, u32::MAX), 7);
        assert_eq!(t.waiters_on(cond), 0);
        assert_eq!(t.waiters_on(mutex), 7);
        // A requeued row settles as still waiting until the target's wake.
        assert_eq!(t.settle(rows[1], 21), Settle::Waiting);
        assert_eq!(t.wake(mutex, 1, &mut out), 1);
        assert_eq!(out[0].0, 21, "the order survives the move");
        assert_eq!(t.settle(rows[1], 21), Settle::Woken);
        // A timeout on a requeued row withdraws it from the TARGET's chain.
        assert_eq!(t.cancel_settle(rows[2], 22), Settle::Waiting);
        assert_eq!(t.waiters_on(mutex), 5);
    }

    #[test]
    fn requeue_never_crosses_key_kinds() {
        let mut t = FutexTable::new();
        t.register(1, p(1, 0x10), u64::MAX).unwrap();
        assert_eq!(t.requeue(p(1, 0x10), s(1, 0x10), 1), 0);
    }

    #[test]
    fn a_wake_that_raced_a_timeout_is_reported_as_a_wake() {
        let mut t = FutexTable::new();
        let a = t.register(4, s(2, 8), 100).unwrap();
        let mut out = [(0, 0); 1];
        assert_eq!(t.wake(s(2, 8), 1, &mut out), 1);
        assert_eq!(out[0], (4, 100));
        assert!(t.cancel(a, 4));
        assert_eq!(t.in_use(), 0);
    }

    #[test]
    fn colliding_keys_share_a_chain_but_not_a_wake() {
        // Fill one bucket with several keys; each wake still takes only its own.
        let mut t = FutexTable::new();
        let base = p(9, 0x4000);
        let mut same = Vec::new();
        let mut addr = 0x4004u64;
        while same.len() < 3 {
            if p(9, addr).bucket() == base.bucket() {
                same.push(addr);
            }
            addr += 4;
        }
        t.register(1, base, u64::MAX).unwrap();
        for (k, a) in same.iter().enumerate() {
            t.register(2 + k as u32, p(9, *a), u64::MAX).unwrap();
        }
        let mut out = [(0, 0); 8];
        assert_eq!(t.wake(p(9, same[1]), 8, &mut out), 1);
        assert_eq!(out[0].0, 3);
        assert_eq!(t.waiters_on(base), 1);
    }

    #[test]
    fn private_keys_of_one_domain_stay_in_its_bank() {
        let bank = |k: Key| k.bucket() / PRIVATE_BUCKETS;
        let b = bank(p(42, 0));
        for a in (0..4096u64).step_by(4) {
            assert_eq!(bank(p(42, a)), b);
            assert!(p(42, a).bucket() < DOMAIN_BANKS * PRIVATE_BUCKETS);
        }
        assert!(s(1, 0).bucket() >= DOMAIN_BANKS * PRIVATE_BUCKETS);
    }

    #[test]
    fn every_bucket_has_an_empty_pi_slot() {
        let mut t = FutexTable::new();
        assert_eq!(*t.pi_state(s(3, 0)), PiState::default());
        assert_eq!(*t.pi_state(p(3, 0)), PiState::default());
    }

    // ── The env loop, on the shared `TABLE` (each test its own keys) ────────

    use std::cell::Cell;

    struct Script {
        t: Cell<u64>,
        on_block: Box<dyn Fn(u32)>,
        n: Cell<u32>,
    }
    impl FutexEnv for Script {
        fn now(&self) -> u64 {
            self.t.get()
        }
        fn block(&self, _d: u64) -> bool {
            self.n.set(self.n.get() + 1);
            (self.on_block)(self.n.get());
            self.t.set(self.t.get() + 10);
            false
        }
        fn wake(&self, _tid: u32, _d: u64) {}
    }
    struct Quiet;
    impl FutexEnv for Quiet {
        fn now(&self) -> u64 {
            0
        }
        fn block(&self, _d: u64) -> bool {
            true
        }
        fn wake(&self, _tid: u32, _d: u64) {}
    }

    /// The herd: 8 waiters on a condition word, a broadcast that wakes one
    /// and requeues the rest onto the mutex word. Exactly one runs. With
    /// the canary (`wake_all`), all 8 run: red.
    fn herd(obj: u32, wake_all: bool) -> u32 {
        let cond = s(obj, 0);
        let mutex = s(obj, 4);
        let rows: Vec<usize> = (0..8).map(|k| TABLE.lock_irqsave().register(100 + k, cond, u64::MAX).unwrap()).collect();
        let (woken, moved) = requeue_key(&Quiet, cond, mutex, 1, u32::MAX, Some((&|| Some(5), 5)), wake_all).unwrap();
        let mut t = TABLE.lock_irqsave();
        let ran = rows.iter().enumerate().filter(|(k, &r)| t.settle(r, 100 + *k as u32) == Settle::Woken).count() as u32;
        assert_eq!(ran, woken);
        assert_eq!(moved as usize, t.waiters_on(mutex));
        for (k, &r) in rows.iter().enumerate() {
            t.cancel_settle(r, 100 + k as u32);
        }
        ran
    }

    #[test]
    fn a_broadcast_by_requeue_runs_one_waiter_not_the_herd() {
        assert_eq!(herd(0xF00, false), 1);
    }

    #[test]
    fn canary_requeue_disabled_runs_the_herd() {
        assert_eq!(herd(0xF01, true), 8, "the canary must make the herd counter red");
    }

    #[test]
    fn cmp_requeue_refuses_a_changed_word_and_does_nothing() {
        let cond = s(0xF02, 0);
        let r = TABLE.lock_irqsave().register(300, cond, u64::MAX).unwrap();
        assert_eq!(requeue_key(&Quiet, cond, s(0xF02, 4), 1, 1, Some((&|| Some(6), 5)), false), Err(WaitResult::ValueChanged));
        assert_eq!(TABLE.lock_irqsave().waiters_on(cond), 1);
        assert_eq!(TABLE.lock_irqsave().cancel_settle(r, 300), Settle::Waiting);
    }

    #[test]
    fn a_wait_woken_on_its_requeue_target_returns_woken() {
        let cond = s(0xF03, 0);
        let mutex = s(0xF03, 4);
        let env = Script {
            t: Cell::new(0),
            n: Cell::new(0),
            on_block: Box::new(move |n| {
                if n == 1 {
                    let _ = requeue_key(&Quiet, cond, mutex, 0, 1, None, false);
                } else {
                    wake_key(&Quiet, mutex, 1, false);
                }
            }),
        };
        assert_eq!(wait_key(&env, 400, cond, &|| Some(0), 0, u64::MAX), WaitResult::Woken);
        assert_eq!(env.n.get(), 2, "the requeue alone did not end the wait");
    }

    #[test]
    fn a_stop_ends_the_wait_and_leaves_nothing_filed() {
        struct Stop;
        impl FutexEnv for Stop {
            fn now(&self) -> u64 {
                0
            }
            fn block(&self, _d: u64) -> bool {
                false
            }
            fn wake(&self, _t: u32, _d: u64) {}
            fn stopped(&self) -> bool {
                true
            }
        }
        let k = s(0xF04, 0);
        assert_eq!(wait_key(&Stop, 500, k, &|| Some(1), 1, u64::MAX), WaitResult::Stopped);
        assert_eq!(TABLE.lock_irqsave().waiters_on(k), 0);
    }

    #[test]
    fn a_changed_or_unreadable_word_files_nothing() {
        let k = s(0xF05, 0);
        assert_eq!(wait_key(&Quiet, 600, k, &|| Some(2), 1, u64::MAX), WaitResult::ValueChanged);
        assert_eq!(wait_key(&Quiet, 600, k, &|| None, 1, u64::MAX), WaitResult::Fault);
        assert_eq!(TABLE.lock_irqsave().waiters_on(k), 0);
    }
}
