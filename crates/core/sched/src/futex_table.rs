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
//!   (`DOMAIN_NOTIFY_WAIT`/`WAKE`, `azos_ipc::notify`) and a Linux futex without
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
//! not the table.
//!
//! # PI slots, one per key
//!
//! Each bucket also chains the keys that have a priority-inheritance state:
//! a `u32` slot per KEY (`azos_sync::pi_futex::PiStateId` raw value, 0 =
//! none), never one for the whole bucket (interface §4,
//! `azos_sync::pi_futex::PiBucket::pi_slot`). The entries come from a pool
//! of `MAX_TASKS` (a PI word has a state only while someone waits on it or
//! owns it through the kernel) when Kconfig `FUTEX_PI` is y, and from an
//! empty pool otherwise. The kernel glue lends one entry to the PI code
//! under the table lock (`futex::with_pi_key`); N10 writes the slot.
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
/// A `FUTEX_WAIT_REQUEUE_PI` waiter (Kconfig `FUTEX_PI`): only
/// `FUTEX_CMP_REQUEUE_PI` to its recorded target takes it; a plain wake or
/// requeue walks past it (Linux refuses them with `EINVAL`).
const WAITING_RQPI: u8 = 4;
/// A requeue-PI took it: it must lock its PI target itself.
const WOKEN_REQUEUED: u8 = 5;
/// A requeue-PI took it and wrote its TID into the free PI target: it
/// returns owning that word.
const WOKEN_PI_OWNER: u8 = 6;
/// A requeue-PI took it and enqueued it on its PI target's wait-graph
/// object on its behalf (owner decision 10-10, Linux
/// `rt_mutex_start_proxy_lock`): it boosts the word's owner while it
/// sleeps on, unlinked from every chain, unwoken. The handover that makes
/// it the owner, a signal or its timeout wakes it; it then finishes its
/// own lock (`pi_futex` `lock_pi_finish`, Linux `rt_mutex_wait_proxy_lock`).
const PROXIED: u8 = 7;

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
    /// The key packed for `azos_sync::pi_futex::PiBucket::key_rec`
    /// (`[0, 0]` is no key): kind in the high half of the first word.
    pub const fn to_rec(&self) -> [u64; 2] {
        match *self {
            Key::Private { domain, addr } => [1 << 32 | domain as u64, addr],
            Key::Shared { obj, offset } => [2 << 32 | obj as u64, offset as u64],
        }
    }

    /// [`Key::to_rec`] back; `None` for anything it never produced.
    pub const fn from_rec(r: [u64; 2]) -> Option<Key> {
        let id = r[0] as u32;
        match r[0] >> 32 {
            1 => Some(Key::Private { domain: id, addr: r[1] }),
            2 if r[1] <= u32::MAX as u64 => Some(Key::Shared { obj: id, offset: r[1] as u32 }),
            _ => None,
        }
    }

    pub fn same_kind(&self, other: &Key) -> bool {
        matches!((self, other), (Key::Private { .. }, Key::Private { .. }) | (Key::Shared { .. }, Key::Shared { .. }))
    }
}

/// Requeue-PI targets, one per row, with Kconfig `FUTEX_PI` (none without).
pub const RQPI_ROWS: usize = if azos_limits::FUTEX_PI { ROWS } else { 0 };

/// What [`FutexTable::requeue_pi_take`] refuses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequeuePiError {
    /// The `from` word could not be read.
    Fault,
    /// The `from` word does not hold `cmpval` (`EAGAIN`).
    ValueChanged,
    /// A waiter on `from` is a plain waiter, or waits to be requeued to
    /// another target (Linux `EINVAL`). Nothing was taken.
    Invalid,
    /// The PI code refused the top waiter's proxy lock (`-errno`).
    Pi(i32),
}

/// PI key entries: one per task with Kconfig `FUTEX_PI`, none without.
pub const PI_KEYS: usize = if azos_limits::FUTEX_PI { ROWS } else { 0 };

/// One key's PI slot, chained from its bucket.
#[derive(Clone, Copy)]
pub struct PiEntry {
    key: Key,
    /// `PiStateId` raw value; 0 = none (the entry is free when it is 0 and
    /// nobody holds it).
    slot: u32,
    next: u16,
    used: bool,
}

pub const PI_FREE: PiEntry = PiEntry { key: Key::Shared { obj: 0, offset: 0 }, slot: 0, next: NIL, used: false };

/// Find `key`'s entry in the chain at `head`, or take a free one from
/// `pool` and chain it. `None` when the pool is exhausted.
pub fn pi_find_or_insert(pool: &mut [PiEntry], head: &mut u16, key: Key) -> Option<usize> {
    let mut cur = *head;
    while cur != NIL {
        if pool[cur as usize].key == key {
            return Some(cur as usize);
        }
        cur = pool[cur as usize].next;
    }
    let i = pool.iter().position(|e| !e.used)?;
    pool[i] = PiEntry { key, slot: 0, next: *head, used: true };
    *head = i as u16;
    Some(i)
}

/// Unchain entry `i` from the chain at `head` if its slot is empty (the PI
/// code left no state for the key). Returns whether it was released.
pub fn pi_release_if_empty(pool: &mut [PiEntry], head: &mut u16, i: usize) -> bool {
    if !pool[i].used || pool[i].slot != 0 {
        return false;
    }
    let mut prev = NIL;
    let mut cur = *head;
    while cur != NIL && cur as usize != i {
        prev = cur;
        cur = pool[cur as usize].next;
    }
    if cur == NIL {
        return false;
    }
    let next = pool[i].next;
    if prev == NIL {
        *head = next;
    } else {
        pool[prev as usize].next = next;
    }
    pool[i] = PI_FREE;
    true
}

#[derive(Clone, Copy)]
struct Row {
    state: u8,
    next: u16,
    tid: u32,
    deadline: u64,
    key: Key,
}

const NO_KEY: Key = Key::Shared { obj: 0, offset: 0 };

const EMPTY: Row = Row { state: FREE, next: NIL, tid: 0, deadline: 0, key: Key::Shared { obj: 0, offset: 0 } };

#[derive(Clone, Copy)]
struct Bucket {
    head: u16,
    tail: u16,
    /// The chain of this bucket's PI key entries ([`PiEntry`]).
    pi_head: u16,
}

const NO_BUCKET: Bucket = Bucket { head: NIL, tail: NIL, pi_head: NIL };

/// What [`FutexTable::settle`] found for a waiter back from a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Settle {
    /// A wake took it. The row is freed.
    Woken,
    /// The exit sweep of the word's robust owner took it. The row is freed.
    OwnerDied,
    /// Still filed (a spurious return). The row is kept.
    Waiting,
    /// A requeue-PI took it: it locks its PI target itself. The row is freed.
    Requeued,
    /// A requeue-PI took it and gave it the free PI target. The row is freed.
    PiOwner,
    /// A requeue-PI enqueued it on its PI target's graph object, asleep;
    /// it finishes that lock itself. The row is freed.
    Proxied,
}

/// The table. Pure data and pure methods, so the host suites drive every
/// transition without a scheduler.
pub struct FutexTable {
    rows: [Row; ROWS],
    buckets: [Bucket; BUCKETS],
    pi: [PiEntry; PI_KEYS],
    /// The PI target of each `WAITING_RQPI` row ([`RQPI_ROWS`]).
    rq_to: [Key; RQPI_ROWS],
    /// Rows in `WAITING` or `WAITING_RQPI`. A wake that finds none returns without hashing.
    waiting: usize,
    /// Rows in `WAITING_RQPI` (always 0 with Kconfig `FUTEX_PI` n): a plain
    /// wake or requeue looks for one in its way only while it is not 0.
    rqpi: usize,
}

impl Default for FutexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FutexTable {
    pub const fn new() -> Self {
        Self { rows: [EMPTY; ROWS], buckets: [NO_BUCKET; BUCKETS], pi: [PI_FREE; PI_KEYS], rq_to: [NO_KEY; RQPI_ROWS], waiting: 0, rqpi: 0 }
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
            WOKEN_REQUEUED => {
                self.rows[slot] = EMPTY;
                Settle::Requeued
            }
            WOKEN_PI_OWNER => {
                self.rows[slot] = EMPTY;
                Settle::PiOwner
            }
            PROXIED => {
                self.rows[slot] = EMPTY;
                Settle::Proxied
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
            WOKEN_REQUEUED => Settle::Requeued,
            WOKEN_PI_OWNER => Settle::PiOwner,
            // Unlinked already; it leaves the graph in its own finish.
            PROXIED => Settle::Proxied,
            _ => {
                if x.state == WAITING_RQPI {
                    self.rqpi -= 1;
                }
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

    /// Waiters filed on `key`, requeue-PI waiters included (host tests, ktest).
    pub fn waiters_on(&self, key: Key) -> usize {
        let mut n = 0;
        let mut cur = self.buckets[key.bucket()].head;
        while cur != NIL {
            let r = &self.rows[cur as usize];
            if (r.state == WAITING || r.state == WAITING_RQPI) && r.key == key {
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

    /// File `tid` as a `FUTEX_WAIT_REQUEUE_PI` waiter on `key` until
    /// `deadline`, to be requeued to the PI word `to` only. `None` when
    /// every row is taken, or with Kconfig `FUTEX_PI` n.
    pub fn register_requeue_pi(&mut self, tid: u32, key: Key, to: Key, deadline: u64) -> Option<usize> {
        if RQPI_ROWS == 0 {
            return None;
        }
        let i = self.register(tid, key, deadline)?;
        self.rows[i].state = WAITING_RQPI;
        self.rq_to[i] = to;
        self.rqpi += 1;
        Some(i)
    }

    /// Is a requeue-PI waiter among the first `n` waiters on `key`? A plain
    /// wake or requeue that would reach one answers `EINVAL` (owner
    /// decision 10-10, Linux `futex_wake` / `futex_requeue`), taking
    /// nobody (Linux wakes the plain waiters ahead of it first). Free
    /// while no requeue-PI row exists (a constant `false` with Kconfig
    /// `FUTEX_PI` n), else one walk of `key`'s chain.
    pub fn rqpi_in_the_way(&self, key: Key, n: u32) -> bool {
        if RQPI_ROWS == 0 || self.rqpi == 0 {
            return false;
        }
        let mut seen = 0u32;
        let mut cur = self.buckets[key.bucket()].head;
        while cur != NIL && seen < n {
            let r = &self.rows[cur as usize];
            cur = r.next;
            if r.key != key || (r.state != WAITING && r.state != WAITING_RQPI) {
                continue;
            }
            if r.state == WAITING_RQPI {
                return true;
            }
            seen += 1;
        }
        false
    }

    /// Rows a requeue-PI enqueued on a PI word's graph object and left
    /// asleep (host tests, ktest).
    pub fn proxied(&self) -> usize {
        self.rows.iter().filter(|x| x.state == PROXIED).count()
    }

    /// The first `n` waiters on `from`, oldest first, if every one of them
    /// is a requeue-PI waiter bound for `to` (Linux checks each waiter it
    /// takes): the top one's `(slot, tid)` and whether another follows it.
    /// `Err(Invalid)` with nothing changed otherwise.
    pub fn requeue_pi_peek(&self, from: Key, to: Key, n: u32) -> Result<Option<(usize, u32, bool)>, RequeuePiError> {
        let mut top = None;
        let mut seen = 0u32;
        let mut cur = self.buckets[from.bucket()].head;
        while cur != NIL && seen < n {
            let i = cur as usize;
            let r = &self.rows[i];
            cur = r.next;
            if r.key != from || (r.state != WAITING && r.state != WAITING_RQPI) {
                continue;
            }
            if r.state != WAITING_RQPI || self.rq_to.get(i) != Some(&to) {
                return Err(RequeuePiError::Invalid);
            }
            match top {
                None => top = Some((i, r.tid, false)),
                Some((s, t, _)) => {
                    top = Some((s, t, true));
                }
            }
            seen += 1;
        }
        Ok(top)
    }

    /// Take up to `n` requeue-PI waiters on `from` (checked by
    /// [`requeue_pi_peek`](Self::requeue_pi_peek)), oldest first. The row in
    /// `owner` (the proxy lock gave it the PI word) settles as
    /// [`Settle::PiOwner`]; each other one is offered to `enqueue` (with the
    /// table and its TID), which enqueues it on the PI word's graph object
    /// on its behalf: `true` and it stays asleep as [`Settle::Proxied`],
    /// `false` and it settles as [`Settle::Requeued`] (`plain`: the canary,
    /// every one as a plain wake, `enqueue` not called). Each one to wake
    /// has its `(tid, deadline)` written into `out`. At most `out.len()` are
    /// taken (one batch per hold). Returns (taken, to wake).
    pub fn requeue_pi_take(
        &mut self, from: Key, n: u32, owner: Option<usize>, plain: bool, out: &mut [(u32, u64)],
        enqueue: &mut dyn FnMut(&mut FutexTable, u32) -> bool,
    ) -> (usize, usize) {
        let b = from.bucket();
        let (mut taken, mut k) = (0usize, 0usize);
        let mut cur = self.buckets[b].head;
        // At most `out.len()` taken per hold, woken or proxied: each proxied
        // one walks the graph with the table held.
        while cur != NIL && (taken as u64) < n as u64 && taken < out.len() {
            let i = cur as usize;
            cur = self.rows[i].next;
            if self.rows[i].state == WAITING_RQPI && self.rows[i].key == from {
                self.unlink(b, i);
                self.waiting -= 1;
                self.rqpi -= 1;
                taken += 1;
                let tid = self.rows[i].tid;
                let state = if plain {
                    WOKEN
                } else if owner == Some(i) {
                    WOKEN_PI_OWNER
                } else if enqueue(self, tid) {
                    PROXIED
                } else {
                    WOKEN_REQUEUED
                };
                self.rows[i].state = state;
                if state != PROXIED {
                    out[k] = (tid, self.rows[i].deadline);
                    k += 1;
                }
            }
        }
        (taken, k)
    }

    /// The PI entry of `key`, chained in its bucket (taken from the pool
    /// if the key has none). `None`: the pool is exhausted, or empty with
    /// Kconfig `FUTEX_PI` n.
    pub fn pi_entry(&mut self, key: Key) -> Option<usize> {
        let b = key.bucket();
        pi_find_or_insert(&mut self.pi, &mut self.buckets[b].pi_head, key)
    }

    /// The `pi_state` slot of entry `i` (0 = none).
    pub fn pi_slot(&mut self, i: usize) -> &mut u32 {
        &mut self.pi[i].slot
    }

    /// Give entry `i` of `key` back if its slot is empty.
    pub fn pi_put(&mut self, key: Key, i: usize) -> bool {
        let b = key.bucket();
        pi_release_if_empty(&mut self.pi, &mut self.buckets[b].pi_head, i)
    }
}

/// The key an exit-path wake files a word of process `proc_id` at `addr`
/// under (the robust walk and the clear-child-tid wake; owner decisions
/// 10-10, Linux keys both shared, `handle_futex_death` and `mm_release`):
/// `shm` is the word's `(region, offset)` when the process maps it from a
/// shm region, and then the key is `Key::Shared` (Kconfig `FUTEX_SHARED`);
/// any other word is the process's private key. A waiter that slept on a
/// shm word with `FUTEX_PRIVATE_FLAG` is not woken by it, as on Linux.
pub fn exit_word_key(proc_id: u32, addr: u64, shm: Option<(u32, u32)>) -> Key {
    match shm {
        Some((obj, offset)) if SHARED => Key::Shared { obj, offset },
        _ => Key::Private { domain: proc_id, addr },
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
    /// A requeue-PI took the waiter: it locks its PI target itself.
    Requeued,
    /// A requeue-PI took the waiter and gave it the free PI target.
    PiOwner,
    /// A requeue-PI enqueued the waiter on its PI target's graph object
    /// while it slept: it finishes that lock (`lock_pi_finish`).
    Proxied,
    /// A plain wake or requeue reached a requeue-PI waiter (`EINVAL`):
    /// nothing was taken.
    Invalid,
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
    wait_as(env, tid, key, None, read, expected, deadline)
}

/// `FUTEX_WAIT_REQUEUE_PI`'s first half: [`wait_key`] on `key` as a
/// requeue-PI waiter bound for the PI word `to`. Ends in
/// [`WaitResult::PiOwner`] or [`WaitResult::Requeued`] when
/// `FUTEX_CMP_REQUEUE_PI` took it (or `Woken`: the canary's plain wake).
pub fn wait_requeue_pi_key<E: FutexEnv>(
    env: &E, tid: u32, key: Key, to: Key, read: &dyn Fn() -> Option<u32>, expected: u32, deadline: u64,
) -> WaitResult {
    wait_as(env, tid, key, Some(to), read, expected, deadline)
}

fn wait_as<E: FutexEnv>(
    env: &E, tid: u32, key: Key, rq_to: Option<Key>, read: &dyn Fn() -> Option<u32>, expected: u32, deadline: u64,
) -> WaitResult {
    let slot = {
        let mut t = TABLE.lock_irqsave();
        match read() {
            None => return WaitResult::Fault,
            Some(v) if v != expected => return WaitResult::ValueChanged,
            Some(_) => {}
        }
        // A stop raised before the wait, or a deadline already past, ends
        // it before it files anything: nothing to cancel, no wake to race.
        if env.stopped() {
            return WaitResult::Stopped;
        }
        if deadline != u64::MAX && env.now() >= deadline {
            return WaitResult::TimedOut;
        }
        let filed = match rq_to {
            None => t.register(tid, key, deadline),
            Some(to) => t.register_requeue_pi(tid, key, to, deadline),
        };
        match filed {
            Some(s) => s,
            None => return WaitResult::NoSpace,
        }
    };
    // Block first, settle after: the row is filed and the lock released in
    // one step, so a wake in between stamps the task and this block
    // consumes the stamp (no stale stamp is left for a later block).
    loop {
        let refused = env.block(deadline);
        let mut t = TABLE.lock_irqsave();
        match t.settle(slot, tid) {
            Settle::Waiting => {}
            s => return settled(s),
        }
        // Blocking again after a refusal would be refused again: withdraw,
        // never spin (an infinite timeout would hang this hart).
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
                Settle::Waiting => r,
                s => settled(s),
            };
        }
    }
}

fn settled(s: Settle) -> WaitResult {
    match s {
        Settle::Woken | Settle::Waiting => WaitResult::Woken,
        Settle::OwnerDied => WaitResult::OwnerDied,
        Settle::Requeued => WaitResult::Requeued,
        Settle::PiOwner => WaitResult::PiOwner,
        Settle::Proxied => WaitResult::Proxied,
    }
}

/// Wake-out batch: each batch is taken under one hold and woken after it.
const WAKE_BATCH: usize = 8;

/// Wake up to `n` waiters on `key` (marked owner-died when `died`). Returns
/// how many were taken. Takes the lock even when nobody waits: the ordering
/// argument in the module doc depends on it.
pub fn wake_key<E: FutexEnv>(env: &E, key: Key, n: u32, died: bool) -> u32 {
    wake_key_as(env, key, n, died, false).unwrap_or(0)
}

/// Linux `FUTEX_WAKE`: [`wake_key`], but `Err(WaitResult::Invalid)` with
/// nobody woken when a requeue-PI waiter is among the first `n` on `key`
/// ([`FutexTable::rqpi_in_the_way`]; owner decision 10-10, as Linux).
pub fn wake_key_checked<E: FutexEnv>(env: &E, key: Key, n: u32) -> Result<u32, WaitResult> {
    wake_key_as(env, key, n, false, true)
}

fn wake_key_as<E: FutexEnv>(env: &E, key: Key, n: u32, died: bool, check: bool) -> Result<u32, WaitResult> {
    let mut total = 0u32;
    let mut first = check;
    loop {
        let mut out = [(0u32, 0u64); WAKE_BATCH];
        let k = {
            let mut t = TABLE.lock_irqsave();
            if first {
                first = false;
                if t.rqpi_in_the_way(key, n) {
                    return Err(WaitResult::Invalid);
                }
            }
            t.wake_as(key, n - total, &mut out, died)
        };
        for &(tid, deadline) in &out[..k] {
            env.wake(tid, deadline);
        }
        total += k as u32;
        if k < WAKE_BATCH || total >= n {
            return Ok(total);
        }
    }
}

/// Linux `FUTEX_CMP_REQUEUE` / `FUTEX_REQUEUE`: check that `read()` holds
/// `cmp` (when given), wake up to `nr_wake` waiters on `from` and move up
/// to `nr_requeue` more to `to`. Returns `(woken, moved)`, or
/// `Err(ValueChanged | Fault)` with nothing done.
///
/// The wakes go out in batches of [`WAKE_BATCH`], each taken under one hold
/// and woken after it; the move happens in the hold that completes the wake
/// quota (or finds the chain exhausted), so the split is Linux's for any
/// `nr_wake`: the oldest `nr_wake` run, the next `nr_requeue` move.
///
/// `wake_all` is the herd canary: every waiter is woken, nobody is moved
/// (the thundering herd a requeue exists to avoid).
pub fn requeue_key<E: FutexEnv>(
    env: &E, from: Key, to: Key, nr_wake: u32, nr_requeue: u32,
    cmp: Option<(&dyn Fn() -> Option<u32>, u32)>, wake_all: bool,
) -> Result<(u32, u32), WaitResult> {
    let mut woken = 0u32;
    let mut moved = 0u32;
    let mut first = true;
    loop {
        let mut out = [(0u32, 0u64); WAKE_BATCH];
        let (k, done) = {
            let mut t = TABLE.lock_irqsave();
            if first {
                if let Some((read, want)) = cmp {
                    match read() {
                        None => return Err(WaitResult::Fault),
                        Some(v) if v != want => return Err(WaitResult::ValueChanged),
                        Some(_) => {}
                    }
                }
                first = false;
                // Every waiter it would wake or move is checked first.
                if t.rqpi_in_the_way(from, nr_wake.saturating_add(nr_requeue)) {
                    return Err(WaitResult::Invalid);
                }
            }
            let want = if wake_all { WAKE_BATCH as u32 } else { (nr_wake - woken).min(WAKE_BATCH as u32) };
            let k = t.wake(from, want, &mut out);
            let exhausted = (k as u32) < want || want == 0;
            let quota = !wake_all && woken + k as u32 >= nr_wake;
            let done = exhausted || quota;
            if done && !wake_all {
                moved = t.requeue(from, to, nr_requeue);
            }
            (k, done)
        };
        for &(tid, deadline) in &out[..k] {
            env.wake(tid, deadline);
        }
        woken += k as u32;
        if done {
            return Ok((woken, moved));
        }
    }
}

/// Linux `FUTEX_CMP_REQUEUE_PI` (Kconfig `FUTEX_PI`): check that `cmp.0()`
/// holds `cmp.1`, then take up to `n` (1 + `nr_requeue`) requeue-PI waiters
/// on `from`, all bound for the PI word `to`. Under the one table lock
/// (both keys' chains, so no bucket order to get wrong) `proxy` first
/// tries to take the free `to` word for the top waiter (Linux
/// `futex_proxy_trylock_atomic`; its arguments: the table, the top's TID,
/// whether another waiter follows): `Ok(true)` and the top wakes owning it.
/// Every other waiter is handed to `enqueue` (the table, its TID), which
/// enqueues it on `to`'s wait-graph object on its behalf and boosts the
/// owner at once (owner decision 10-10, Linux `rt_mutex_start_proxy_lock`):
/// it is not woken. Lock order: the table, then the graph. A waiter
/// `enqueue` refuses (no owner to wait for, a deadlock) wakes requeued and
/// runs its own `LOCK_PI` on `to`. Returns how many were taken (Linux's
/// woken + requeued). `plain` is the canary: no proxy lock, every waiter
/// wakes as a plain wake.
pub fn requeue_pi_key<E: FutexEnv>(
    env: &E, from: Key, to: Key, n: u32, cmp: (&dyn Fn() -> Option<u32>, u32), plain: bool,
    proxy: &mut dyn FnMut(&mut FutexTable, u32, bool) -> Result<bool, i32>,
    enqueue: &mut dyn FnMut(&mut FutexTable, u32) -> bool,
) -> Result<u32, RequeuePiError> {
    let mut total = 0u32;
    let mut first = true;
    loop {
        let mut out = [(0u32, 0u64); WAKE_BATCH];
        let want = n - total;
        let (taken, k) = {
            let mut t = TABLE.lock_irqsave();
            let mut owner = None;
            if first {
                first = false;
                match (cmp.0)() {
                    None => return Err(RequeuePiError::Fault),
                    Some(v) if v != cmp.1 => return Err(RequeuePiError::ValueChanged),
                    Some(_) => {}
                }
                // Every waiter it would take is checked before any is taken.
                if let Some((slot, tid, more)) = t.requeue_pi_peek(from, to, n)? {
                    if !plain && proxy(&mut t, tid, more).map_err(RequeuePiError::Pi)? {
                        owner = Some(slot);
                    }
                }
            } else if t.requeue_pi_peek(from, to, want).is_err() {
                // A waiter filed between two batches is bound elsewhere:
                // stop at what was taken.
                return Ok(total);
            }
            t.requeue_pi_take(from, want, owner, plain, &mut out, enqueue)
        };
        for &(tid, deadline) in &out[..k] {
            env.wake(tid, deadline);
        }
        total += taken as u32;
        // A full batch (WAKE_BATCH taken, woken or proxied): more may follow.
        if taken < WAKE_BATCH || total >= n {
            return Ok(total);
        }
    }
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
    fn the_exit_wake_of_a_shm_word_takes_its_shared_waiter_not_a_private_one() {
        // Owner decision 10-10 (Linux mm_release / handle_futex_death): the
        // clear-tid and robust wakes key a shm word by its region; a waiter
        // that used FUTEX_PRIVATE_FLAG on that word sleeps on.
        let mut t = FutexTable::new();
        let k = exit_word_key(3, 0x7000, Some((9, 0x40)));
        let private = t.register(1, p(3, 0x7000), u64::MAX).unwrap();
        let shared = t.register(2, s(9, 0x40), u64::MAX).unwrap();
        let mut out = [(0, 0); 4];
        if SHARED {
            assert_eq!(k, s(9, 0x40));
            assert_eq!(t.wake(k, 2, &mut out), 1);
            assert_eq!(out[0].0, 2);
            assert_eq!(t.settle(shared, 2), Settle::Woken);
            assert_eq!(t.waiters_on(p(3, 0x7000)), 1, "the private waiter is not woken");
            assert_eq!(t.settle(private, 1), Settle::Waiting);
        } else {
            assert_eq!(k, p(3, 0x7000));
        }
        // A word of no shm region keeps the process's private key.
        assert_eq!(exit_word_key(3, 0x8000, None), p(3, 0x8000));
    }

    #[test]
    fn a_requeue_pi_waiter_is_taken_only_by_a_requeue_pi_to_its_target() {
        if RQPI_ROWS == 0 {
            let mut t = FutexTable::new();
            assert!(t.register_requeue_pi(1, p(1, 0x10), p(1, 0x20), u64::MAX).is_none());
            return;
        }
        let (cond, mutex, other) = (p(6, 0x100), p(6, 0x104), p(6, 0x108));
        let mut t = FutexTable::new();
        let a = t.register_requeue_pi(30, cond, mutex, u64::MAX).unwrap();
        let b = t.register_requeue_pi(31, cond, mutex, 77).unwrap();
        let c = t.register_requeue_pi(32, cond, mutex, u64::MAX).unwrap();
        let mut out = [(0, 0); 4];
        // A plain wake or requeue that would reach them answers EINVAL
        // (the callers ask first); the table's own walks pass them by.
        assert!(t.rqpi_in_the_way(cond, 1));
        assert!(!t.rqpi_in_the_way(other, 8), "another key's chain is clear");
        assert_eq!(t.wake(cond, 8, &mut out), 0);
        assert_eq!(t.requeue(cond, mutex, 8), 0);
        // A requeue-PI to another target takes nobody.
        assert_eq!(t.requeue_pi_peek(cond, other, 8), Err(RequeuePiError::Invalid));
        assert_eq!(t.requeue_pi_peek(cond, mutex, 8), Ok(Some((a, 30, true))));
        // The top got the free PI word; the next one is enqueued on the PI
        // word's graph object by proxy and stays asleep; the third stays
        // filed (n = 2: nr_requeue 1).
        let mut offered = [0u32; 4];
        let mut m = 0;
        let mut enqueue = |_: &mut FutexTable, tid: u32| {
            offered[m] = tid;
            m += 1;
            true
        };
        assert_eq!(t.requeue_pi_take(cond, 2, Some(a), false, &mut out, &mut enqueue), (2, 1));
        assert_eq!(out[0], (30, u64::MAX), "only the owner is woken");
        assert_eq!((m, offered[0]), (1, 31), "the owner is never offered to the graph");
        assert_eq!(t.proxied(), 1);
        assert!(t.rqpi_in_the_way(cond, 1), "the third is still filed");
        assert_eq!(t.settle(a, 30), Settle::PiOwner);
        // A proxied waiter back from its block (the handover, a signal, its
        // timeout) finishes the lock itself; a withdraw says the same.
        assert_eq!(t.cancel_settle(b, 31), Settle::Proxied);
        assert_eq!(t.settle(c, 32), Settle::Waiting);
        // A timeout withdraws a requeue-PI row like any other.
        assert_eq!(t.cancel_settle(c, 32), Settle::Waiting);
        assert!(!t.rqpi_in_the_way(cond, 8));
        assert_eq!(t.in_use(), 0);
    }

    #[test]
    fn a_requeue_pi_waiter_the_graph_refuses_wakes_requeued() {
        if RQPI_ROWS == 0 {
            return;
        }
        let (cond, mutex) = (p(6, 0x400), p(6, 0x404));
        let mut t = FutexTable::new();
        let a = t.register_requeue_pi(50, cond, mutex, u64::MAX).unwrap();
        let b = t.register_requeue_pi(51, cond, mutex, 9).unwrap();
        let mut out = [(0, 0); 4];
        let mut refuse = |_: &mut FutexTable, _: u32| false;
        assert_eq!(t.requeue_pi_take(cond, 8, None, false, &mut out, &mut refuse), (2, 2));
        assert_eq!((out[0], out[1]), ((50, u64::MAX), (51, 9)));
        assert_eq!(t.proxied(), 0);
        assert_eq!(t.settle(a, 50), Settle::Requeued);
        assert_eq!(t.settle(b, 51), Settle::Requeued);
        assert_eq!(t.in_use(), 0);
    }

    #[test]
    fn a_requeue_pi_hold_takes_one_batch_even_when_nobody_is_woken() {
        if RQPI_ROWS == 0 || ROWS < 10 {
            return;
        }
        let (cond, mutex) = (p(6, 0x600), p(6, 0x604));
        let mut t = FutexTable::new();
        for tid in 70..80 {
            t.register_requeue_pi(tid, cond, mutex, u64::MAX).unwrap();
        }
        let mut out = [(0, 0); WAKE_BATCH];
        let mut proxy = |_: &mut FutexTable, _: u32| true;
        assert_eq!(t.requeue_pi_take(cond, 100, None, false, &mut out, &mut proxy), (WAKE_BATCH, 0));
        assert_eq!(t.waiters_on(cond), 10 - WAKE_BATCH);
        assert_eq!(t.proxied(), WAKE_BATCH);
    }

    #[test]
    fn a_plain_waiter_ahead_of_a_requeue_pi_waiter_is_not_in_the_way() {
        if RQPI_ROWS == 0 {
            return;
        }
        let (cond, mutex) = (p(6, 0x500), p(6, 0x504));
        let mut t = FutexTable::new();
        t.register(60, cond, u64::MAX).unwrap();
        t.register_requeue_pi(61, cond, mutex, u64::MAX).unwrap();
        assert!(!t.rqpi_in_the_way(cond, 1), "a wake of one stops at the plain waiter");
        assert!(t.rqpi_in_the_way(cond, 2));
    }

    #[test]
    fn a_plain_waiter_on_the_condition_refuses_a_requeue_pi() {
        if RQPI_ROWS == 0 {
            return;
        }
        let (cond, mutex) = (p(6, 0x200), p(6, 0x204));
        let mut t = FutexTable::new();
        t.register(40, cond, u64::MAX).unwrap();
        t.register_requeue_pi(41, cond, mutex, u64::MAX).unwrap();
        assert_eq!(t.requeue_pi_peek(cond, mutex, 8), Err(RequeuePiError::Invalid));
        assert_eq!(t.requeue_pi_peek(p(6, 0x300), mutex, 8), Ok(None));
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

    /// The PI slot is per KEY: two keys in one bucket get two slots.
    #[test]
    fn a_pi_slot_is_per_key_not_per_bucket() {
        let mut pool = [PI_FREE; 4];
        let mut head = NIL;
        let a = p(3, 0x100);
        let mut b_addr = 0x104u64;
        while p(3, b_addr).bucket() != a.bucket() {
            b_addr += 4;
        }
        let b = p(3, b_addr);
        let ia = pi_find_or_insert(&mut pool, &mut head, a).unwrap();
        let ib = pi_find_or_insert(&mut pool, &mut head, b).unwrap();
        assert_ne!(ia, ib);
        pool[ia].slot = 7;
        assert_eq!(pi_find_or_insert(&mut pool, &mut head, a), Some(ia), "the same key finds its entry");
        assert_eq!(pool[ib].slot, 0, "the other key's slot is its own");
        assert!(pi_release_if_empty(&mut pool, &mut head, ib));
        assert!(!pi_release_if_empty(&mut pool, &mut head, ia), "a slot in use is kept");
        assert_eq!(pi_find_or_insert(&mut pool, &mut head, a), Some(ia));
        pool[ia].slot = 0;
        assert!(pi_release_if_empty(&mut pool, &mut head, ia));
        assert_eq!(head, NIL);
    }

    #[test]
    fn a_key_record_round_trips_and_zero_is_none() {
        for k in [p(7, 0x1000), p(u32::MAX, u64::MAX), s(3, 0), s(u32::MAX, u32::MAX)] {
            assert_eq!(Key::from_rec(k.to_rec()), Some(k));
        }
        assert_eq!(Key::from_rec([0, 0]), None);
        assert_eq!(Key::from_rec([2 << 32, 1 << 32]), None);
        assert_ne!(p(1, 2).to_rec(), s(1, 2).to_rec());
    }

    #[test]
    fn the_pi_pool_follows_kconfig() {
        let mut t = FutexTable::new();
        assert_eq!(t.pi_entry(s(3, 0)).is_some(), azos_limits::FUTEX_PI);
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

    /// More wakes than one batch: Linux's split, not one batch then a move.
    #[test]
    fn a_requeue_wider_than_a_batch_wakes_exactly_nr_wake() {
        let cond = s(0xF06, 0);
        let mutex = s(0xF06, 4);
        let rows: Vec<usize> = (0..20).map(|k| TABLE.lock_irqsave().register(700 + k, cond, u64::MAX).unwrap()).collect();
        assert_eq!(requeue_key(&Quiet, cond, mutex, 10, u32::MAX, None, false), Ok((10, 10)));
        let mut t = TABLE.lock_irqsave();
        assert_eq!(t.waiters_on(mutex), 10);
        for (k, &r) in rows.iter().enumerate() {
            t.cancel_settle(r, 700 + k as u32);
        }
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
