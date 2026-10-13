// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Domains (owner decision D2): the unit that owns a capability table, a
//! memory charge and a security boundary. A task is a thread of execution;
//! the domain is what its threads share.
//!
//! Every task belongs to exactly one domain, named by a [`Key`] kept in
//! `Task::domain`. A task created on its own (a spawn, a fork, a kernel task)
//! gets a fresh domain; a thread joins its creator's (`TaskInit::domain`).
//! The domain lives until its last member has gone, then its slot is free for
//! the next one under a new generation, so a key held past its domain's end
//! answers "no domain" instead of naming the successor.
//!
//! What lives here, and who reads it:
//!
//! * the capability table: `azos_ipc::cap_store` indexes its tables by
//!   [`index`] (one table per domain slot, wiped when the last member exits),
//!   so a thread, an exec'ing thread that takes its process over, and the
//!   process id all reach one table with no hand-over;
//! * the frame budget ([`PageBudget`]): charged by brk, mmap, page tables, shm
//!   and fork, whichever thread of whichever Domain runs the call;
//! * the memory policy (`mem = "locked"`);
//! * hooks with no logic yet, each named for the decision that fills it:
//!   `owner_root` (D10, the user root warrant id; 0 for the system),
//!   `security_boundary` and `partition_id` (the L4 warrant tree hangs off
//!   the domain), `vm` (reserved), `measurement` (DICE).
//!
//! # Concurrency
//!
//! `gen` and `live` change under [`LIFECYCLE`]; the rest of a domain is
//! written while it is being created (by the creator, before any member
//! runs) and afterwards by its members. **The budget is atomic**
//! (`azos_mm::budget::PageBudget`): [`charge`] is a compare-and-swap loop, so
//! charges from different harts, and from other Domains (a MemObj MOVE charges
//! the receiver from the sender's thread; the last reference to an object gives
//! its charge back to the holder from whichever task drops it), can neither pass
//! the limit together nor lose an update. A discharge takes effect at once, from
//! any context. `LIFECYCLE` is a leaf: taken alone, never around another lock.
//! (`table_hook` charges without the group's memory lock, which is now safe.)
//!
//! A key's generation is 16 bits: a slot reused 65,535 times can name a key
//! of a dead domain again, the same class of acceptance as the 2^32 TID wrap.
//!
//! This file has no dependency on the task table, a hart or the scheduler, so
//! `tests/host/sched-wake-tests` compiles it unchanged.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

use azos_mm::budget::PageBudget;
use azos_sync::spinlock::SpinLock;

use crate::task::MAX_TASKS;

/// Most domains alive at once. One per task slot: a domain needs a member, a
/// member needs a slot, so a task that got its slot always finds a domain.
pub const DOMAINS_MAX: usize = MAX_TASKS;

/// A domain's name: its table index in the low 16 bits and its generation in
/// the high 16. `0` ([`NONE`]) is no domain.
pub type Key = u32;

/// No domain: a slot that holds no task, a key already ended.
pub const NONE: Key = 0;

const INDEX_BITS: u32 = 16;
const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
const _: () = assert!(DOMAINS_MAX <= (INDEX_MASK as usize) + 1);

/// [`Domain::mem_policy`] bit: `mem = "locked"`, refused `SYS_FOREIGN_FORK`
/// and the demand reservation.
pub const MEM_LOCKED: u8 = 1;

/// The fields only a domain's own members write.
struct State {
    mem_policy: u8,
    /// D10 (multi-user): the user root warrant id; 0 for the system.
    owner_root: u32,
    /// L4: the security boundary this domain sits in.
    security_boundary: u8,
    /// L4: the partition this domain belongs to.
    partition_id: u16,
    /// Reserved: the virtual-machine context, when a domain is a guest.
    vm: Option<u32>,
    /// DICE: the measurement of the image the domain started from.
    measurement: [u8; 32],
}

impl State {
    const fn new() -> Self {
        Self {
            mem_policy: 0,
            owner_root: 0,
            security_boundary: 0,
            partition_id: 0,
            vm: None,
            measurement: [0; 32],
        }
    }
}

struct Domain {
    /// Generation of the current or last occupant, 1..=0xFFFF (0 = never used).
    gen: AtomicU32,
    /// Live members; 0 = free.
    live: AtomicU32,
    /// The frame budget: atomic, shared by every hart that charges the Domain.
    budget: PageBudget,
    state: UnsafeCell<State>,
}

// SAFETY: `state` follows the discipline in the module doc (it is not
// race-free against two members charging at once; that is the budget's
// pre-existing behaviour); the rest is atomic.
unsafe impl Sync for Domain {}

impl Domain {
    const fn new() -> Self {
        Self {
            gen: AtomicU32::new(0),
            live: AtomicU32::new(0),
            budget: PageBudget::new(),
            state: UnsafeCell::new(State::new()),
        }
    }
}

static DOMAINS: [Domain; DOMAINS_MAX] = [const { Domain::new() }; DOMAINS_MAX];

/// Serialises create, join and leave.
static LIFECYCLE: SpinLock<()> = SpinLock::new(());

/// Table index of `key` (what the capability store indexes its tables by).
#[inline(always)]
pub const fn index(key: Key) -> usize {
    (key & INDEX_MASK) as usize
}

#[inline(always)]
const fn gen_of(key: Key) -> u32 {
    key >> INDEX_BITS
}

/// The domain `key` names, if it is still alive.
#[inline(always)]
fn get(key: Key) -> Option<&'static Domain> {
    let d = DOMAINS.get(index(key))?;
    (key != NONE && d.gen.load(Ordering::Acquire) == gen_of(key) && d.live.load(Ordering::Acquire) != 0)
        .then_some(d)
}

/// Run `f` on the state of the domain `key` names; `None` for a key that
/// names none.
#[inline(always)]
fn with<R>(key: Key, f: impl FnOnce(&Domain, &mut State) -> R) -> Option<R> {
    let d = get(key)?;
    // SAFETY: the module doc's single-writer discipline.
    Some(f(d, unsafe { &mut *d.state.get() }))
}

/// Create a domain with one member (the creator of the task that will hold
/// the key). `None` when every slot is in use.
pub fn create() -> Option<Key> {
    let _g = LIFECYCLE.lock();
    for (i, d) in DOMAINS.iter().enumerate() {
        if d.live.load(Ordering::Relaxed) != 0 {
            continue;
        }
        let mut gen = (d.gen.load(Ordering::Relaxed) + 1) & INDEX_MASK;
        if gen == 0 {
            gen = 1;
        }
        // SAFETY: a free domain has no member, so nobody else touches its state.
        // (A late discharge aimed at the old occupant saturates at zero.)
        unsafe { *d.state.get() = State::new() };
        d.budget.reset();
        d.budget.set_limit(0);
        d.gen.store(gen, Ordering::Release);
        d.live.store(1, Ordering::Release);
        return Some((gen << INDEX_BITS) | i as u32);
    }
    None
}

/// One more member in the domain `key` names (`thread_create`). `false`,
/// nothing changed, when the key names no live domain.
pub fn join(key: Key) -> bool {
    let _g = LIFECYCLE.lock();
    match get(key) {
        Some(d) => {
            d.live.fetch_add(1, Ordering::AcqRel);
            true
        }
        None => false,
    }
}

/// A member of the domain `key` names has gone. `true` when it was the last:
/// the domain is then free and `key` names none. A key that names no live
/// domain changes nothing and answers `false`.
pub fn leave(key: Key) -> bool {
    let _g = LIFECYCLE.lock();
    match get(key) {
        Some(d) => d.live.fetch_sub(1, Ordering::AcqRel) == 1,
        None => false,
    }
}

/// Live members of the domain `key` names (0 for none).
#[inline]
pub fn live(key: Key) -> u32 {
    get(key).map_or(0, |d| d.live.load(Ordering::Acquire))
}

/// Does the domain `key` names have a member besides the caller's? What
/// decides whether an exiting task takes the capability table with it.
#[inline]
pub fn shared(key: Key) -> bool {
    live(key) > 1
}

// ── The frame budget ───────────────────────────────────────────────────────

/// Charge `pages` to the budget of the domain `key` names, all or nothing
/// (`PageBudget::charge`, a compare-and-swap loop). `Some(used)` when charged,
/// `None` when refused or when the key names no domain.
pub fn charge(key: Key, pages: u32) -> Option<u32> {
    let d = get(key)?;
    d.budget.charge(pages).then(|| d.budget.used())
}

/// Give `pages` back to the budget of the domain `key names`, from any
/// context and any Domain.
pub fn discharge(key: Key, pages: u32) {
    if let Some(d) = get(key) {
        d.budget.discharge(pages);
    }
}

/// Forget the used count and the peak: the address space they described is
/// gone. The limit stays.
pub fn reset_budget(key: Key) {
    if let Some(d) = get(key) {
        d.budget.reset();
    }
}

/// Declare the budget limit, in 4 KiB pages (0 = none).
pub fn set_limit(key: Key, limit: u32) {
    if let Some(d) = get(key) {
        d.budget.set_limit(limit);
    }
}

/// `(used, limit)`; zeroes for a key that names no domain.
pub fn used_limit(key: Key) -> (u32, u32) {
    get(key).map_or((0, 0), |d| (d.budget.used(), d.budget.limit()))
}

/// The high-water mark of the budget.
pub fn peak(key: Key) -> u32 {
    get(key).map_or(0, |d| d.budget.peak())
}

/// Set or clear [`MEM_LOCKED`].
pub fn set_mem_locked(key: Key, locked: bool) {
    let _ = with(key, |_, s| {
        s.mem_policy = if locked { s.mem_policy | MEM_LOCKED } else { s.mem_policy & !MEM_LOCKED };
    });
}

/// Is the domain `mem = "locked"`?
pub fn mem_locked(key: Key) -> bool {
    with(key, |_, s| s.mem_policy & MEM_LOCKED != 0).unwrap_or(false)
}

// ── The hooks ──────────────────────────────────────────────────────────────

/// A copy of a domain's hook fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub live: u32,
    pub owner_root: u32,
    pub security_boundary: u8,
    pub partition_id: u16,
    pub vm: Option<u32>,
    pub measurement: [u8; 32],
}

/// The hook fields of the domain `key` names.
pub fn info(key: Key) -> Option<Info> {
    with(key, |d, s| Info {
        live: d.live.load(Ordering::Acquire),
        owner_root: s.owner_root,
        security_boundary: s.security_boundary,
        partition_id: s.partition_id,
        vm: s.vm,
        measurement: s.measurement,
    })
}

/// Set the D10 owner root and the L4 boundary and partition of a domain.
pub fn set_identity(key: Key, owner_root: u32, security_boundary: u8, partition_id: u16) {
    let _ = with(key, |_, s| {
        s.owner_root = owner_root;
        s.security_boundary = security_boundary;
        s.partition_id = partition_id;
    });
}

/// Record the DICE measurement of the image a domain started from.
pub fn set_measurement(key: Key, measurement: [u8; 32]) {
    let _ = with(key, |_, s| s.measurement = measurement);
}

/// Domains alive right now.
pub fn count() -> usize {
    DOMAINS.iter().filter(|d| d.live.load(Ordering::Relaxed) != 0).count()
}
