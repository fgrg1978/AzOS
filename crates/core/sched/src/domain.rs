// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Domains (owner decision D2): the unit that owns a capability table, a
//! memory charge and a security boundary. A task is a thread of execution;
//! the domain is what its threads share.
//!
//! Every task belongs to exactly one domain, named by a [`Key`] kept in
//! `Task::domain`. A task created on its own (a spawn, a fork, a kernel task)
//! gets a fresh domain, a child of its creator's (see "Subtree policy"); a
//! thread joins its creator's (`TaskInit::domain`).
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
//! * the kernel-memory ledger ([`KmemBudget`], KMEM-CHARGE): what the kernel
//!   keeps for the domain (its capability table, endpoint queues, MemObj
//!   metadata, page tables grown at run time), charged per object class and
//!   bounded by the row's `kmem_kib`; a charge past the limit is refused and
//!   leaves a `kmem-charge` decision record;
//! * the pressure Port ([`PressureBind`]): where the reclaim task tells the
//!   Domain its frame budget changed level (`azos_mm::budget::Pressure`),
//!   bound by `PORT_BIND` with `PORT_SRC_PRESSURE`. This file only holds the
//!   reference; `azos_ipc` depends on this crate, so the task that queues the
//!   event (`kernel/src/tasks/reclaim.rs`) is where both are in sight;
//! * the write ledger ([`add_written`]): the bytes of block writes the device
//!   completed for the Domain (`azos_drv_block::write_observer::account`, fed
//!   by the request layer's completion), the storage side of its energy cost
//!   (flash wear and write power) as the entries counters are the kernel side;
//!   the `metrics/storage` subtree publishes them;
//! * the memory policy (`mem = "locked"`);
//! * the resource partition (`partition_id`, [`set_partition`], read by
//!   [`partition_of`]): the hardware tag the Domain's tasks run under (Ssqosid
//!   `srmcfg`, MPAM PARTID, RDT CLOS; `azos_sched::qos` writes it on every
//!   context switch). Set from the task row's `partition_id`, inherited by a
//!   child Domain, 0 (the default partition) otherwise. Atomic, not in
//!   [`State`]: the switch path of any hart reads it;
//! * hooks with no logic yet, each named for the decision that fills it:
//!   `owner_root` (D10, the user root warrant id; 0 for the system), `vm`
//!   (reserved), `measurement` (DICE);
//! * the parent link and the subtree policy (below).
//!
//! # Subtree policy (SUBTREE-POLICY)
//!
//! A Domain created by a task of another Domain is that Domain's **child**
//! ([`create_child`]; a spawn and a fork are, a kernel task is a root). A
//! topology `[policy.NAME]` row binds [`Limits`] to the Domain of the task row
//! it names ([`set_policy`]): with `scope = "self"` they bind that Domain, with
//! `scope = "subtree"` they bind it and every Domain beneath it. A limit only
//! narrows: [`check_create`] refuses what the actor's own limits, or the
//! subtree limits of any ancestor, refuse, whatever the actor was granted.
//!
//! **The walk is bounded: at most [`WALK_MAX`] = 8 ancestors.** A bound must
//! not be a hole, so the chain is kept within it by construction instead of
//! failing a deep process tree: a Domain created under one already
//! [`WALK_MAX`] levels deep is attached to that Domain's parent, and the
//! limits that parent's subtree carried are folded into the new Domain's
//! `floor`, which the walk applies as part of the Domain itself. The same
//! fold runs when a Domain ends with children (its last member leaves): they
//! are re-attached to its parent and take its subtree limits with them, so a
//! limit outlives the Domain that carried it and an orphan does not escape.
//! The cost is a scan of the table when a Domain with children ends.
//! An ancestor's depth is reported in a refusal as it stands when the
//! refusal is made (0 = the actor's own words, a folded limit included).
//!
//! # Kernel entries by case
//!
//! Every native syscall is a syscall for one of two foundational reasons (its
//! case, `azos_abi::syscall_nr::syscall_case`: authority, or block/wake). The
//! one prologue of the trap layer (`kernel/src/trap`) calls [`enter`] for each,
//! which counts the entry in the Domain's [`ENTRY_SLOTS`] counters (Kconfig
//! `DOMAIN_ENTRY_COUNTERS`; slot 0 holds the calls with no case: a Linux
//! task's, which `seccomp` rules). [`entries`] reads them back: the
//! kernel-fault report prints what a task did with the kernel before it died,
//! and the `metrics/syscalls` subtree of the introspection tree publishes them
//! ([`slot_entries`]): kernel entries per operation is the measure of the
//! principle that a syscall is for changing authority or for sleeping.
//! Plain relaxed atomics, written without [`LIFECYCLE`].
//!
//! # The pledge (`DOMAIN_PLEDGE`)
//!
//! A Domain also holds a **pledge mask** (`azos_abi::invoke::PLEDGE_*`): which
//! cases, and which op classes of `SYS_INVOKE`, its members may still ask the
//! kernel for. A program sets up with all of it (it opens, looks up, maps),
//! then narrows the mask to what its steady state does; [`pledge_narrow`] is the
//! only setter and only clears bits, so no member can widen what any member
//! narrowed. A Domain created beneath another starts with its creator's mask
//! ([`create_child`]); `exec` keeps it. A call outside the mask is not run: the
//! prologue's [`enter`] says so, the call answers `-EACCES`, and the refusal is
//! a `pledge` decision record (`Rule::Pledge`, its subject the calling task and
//! its action word naming the [`Door`] the call came through), a durable
//! receipt the first time a mask refuses a bit and a ring record after that (a
//! loop of refused calls must not flood the medium). This is the per-Domain half of
//! what a task may call: `seccomp` is per task and fixed by the image, the
//! pledge is per Domain and chosen by the program, and either one refusing
//! ends the call. That holds for the operations a `SYS_RING_ENTER` runs in the
//! kernel as much as for the traps: the ring is one trap of case block/wake,
//! but each of its entries stands for a typed call, and [`admit`] asks the mask
//! about that call's bit before the entry runs (the ring's owner's Domain, so
//! the SQ poller is bound the same).
//!
//! # Concurrency
//!
//! `gen`, `live`, the parent link, the child count and the three policy words
//! change under [`LIFECYCLE`] (and are read without it: single words, and a
//! fold narrows the child before the Domain it came from is marked free); the
//! rest of a domain is
//! written while it is being created (by the creator, before any member
//! runs) and afterwards by its members. **The budget is atomic**
//! (`azos_mm::budget::PageBudget`): [`charge`] is a compare-and-swap loop, so
//! charges from different harts, and from other Domains (a MemObj MOVE charges
//! the receiver from the sender's thread; the last reference to an object gives
//! its charge back to the holder from whichever task drops it), can neither pass
//! the limit together nor lose an update. A discharge takes effect at once, from
//! any context. `LIFECYCLE` is a leaf but for `pressure_port`, which
//! `create_child` clears under it (a leaf beneath `LIFECYCLE`: nothing holding
//! it takes `LIFECYCLE`); it is never taken around any other lock.
//! (`table_hook` charges without the group's memory lock, which is now safe.)
//!
//! **Lock order for the kernel-memory ledger.** Neither ledger has a lock:
//! [`kmem_charge`] is a compare-and-swap loop on atomics and `get` is lock-free
//! (`LIFECYCLE` is not taken), so charging can never wait for a lock a caller
//! holds. What can wait is the REFUSAL's decision record: it is lock-free
//! into the ring, but with durable refusals (Kconfig
//! `DECISION_REFUSALS_DURABLE`) it goes on to the sink, which pushes to the
//! logger and flushes to the medium, as for every `Refuse` record. So the rule
//! for a caller is: **charge before taking a spinlock, never under one**, and
//! on a failure found under the lock, release it first, then discharge. The
//! capability store claims a table before it locks it (`claim_table`), the
//! endpoint pool charges before `ENDPOINTS` (`KmemPrecharge`) and MemObj
//! before `MEMOBJS` (`charge_region`). A DISCHARGE is two atomic subtractions
//! and writes nothing, so it may run from under any lock and any context. The
//! budget is therefore a leaf in every order: nothing is ever taken while it
//! is held, because it is never held.
//!
//! A key's generation is 16 bits: a slot reused 65,535 times can name a key
//! of a dead domain again, the same class of acceptance as the 2^32 TID wrap.
//!
//! This file has no dependency on the task table, a hart or the scheduler, so
//! `tests/host/sched-wake-tests` compiles it unchanged.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

use azos_abi::invoke::{PLEDGE_ALL, PLEDGE_ALWAYS};
use azos_abi::syscall_nr::CASES;
use azos_decision::{Rule, Verdict};
pub use azos_mm::budget::KmemClass;
use azos_mm::budget::{KmemBudget, PageBudget};
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

/// Counters per Domain: slot 0 for calls with no case, slots `1..=CASES` by case.
pub const ENTRY_SLOTS: usize = CASES + 1;

/// How many ancestors [`check_create`] looks at. The chain is kept within it
/// by construction (module doc), so nothing a deeper tree binds is out of
/// sight of the walk.
pub const WALK_MAX: usize = 8;

/// What a subtree policy row may forbid a Domain to create (CAPS.TOML format
/// 7 `[policy.NAME]`). [`Limits::NONE`] forbids nothing and is the identity
/// of [`Limits::narrow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `create_endpoints`: may it create endpoints?
    pub create_endpoints: bool,
    /// `create_ports`: may it create ports?
    pub create_ports: bool,
    /// `memobj_max_pages`: the largest MemObj, in 4 KiB pages. 0 = no ceiling.
    pub memobj_max_pages: u32,
}

/// One creation a Domain asks for: what [`check_create`] judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Create {
    /// `DOMAIN_CREATE_ENDPOINT`.
    Endpoint,
    /// `DOMAIN_CREATE_PORT`.
    Port,
    /// `SYS_MO_CREATE`, of this many 4 KiB pages. A request that does not
    /// state the size (a clone of an object, size 0 = the source's) is asked
    /// as `u32::MAX`, so a ceiling refuses it.
    MemObj(u32),
}

/// The door a call met the pledge mask at: bit 8 of the `action` word of a
/// `pledge` record (its low byte is what the mask did, 0: refused with the
/// error), so one rule tells a trapped call from an `io_ring` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Door {
    /// The trap's prologue ([`enter`]).
    Trap = 0,
    /// An `io_ring` entry ([`admit`]).
    Ring = 1,
}

impl Door {
    /// The `action` word of a `pledge` record that refused a call at this door.
    pub const fn refused(self) -> u64 {
        (self as u64) << 8
    }
}

impl Create {
    /// The `action` word of a `subtree-policy` record: the kind in the low
    /// byte (1 endpoint, 2 port, 3 MemObj)
    /// and, for a MemObj, the pages asked in the bits above it.
    pub const fn action(self) -> u64 {
        match self {
            Create::Endpoint => 1,
            Create::Port => 2,
            Create::MemObj(pages) => 3 | (pages as u64) << 8,
        }
    }
}

impl Limits {
    /// No limit.
    pub const NONE: Self = Self { create_endpoints: true, create_ports: true, memobj_max_pages: 0 };

    /// Both limits at once: what neither allows is refused. A ceiling of 0 is
    /// none, so the smaller nonzero one holds.
    pub const fn narrow(self, o: Self) -> Self {
        let pages = match (self.memobj_max_pages, o.memobj_max_pages) {
            (0, b) => b,
            (a, 0) => a,
            (a, b) => if a < b { a } else { b },
        };
        Self {
            create_endpoints: self.create_endpoints && o.create_endpoints,
            create_ports: self.create_ports && o.create_ports,
            memobj_max_pages: pages,
        }
    }

    /// Do these limits refuse `what`?
    pub const fn refuses(self, what: Create) -> bool {
        match what {
            Create::Endpoint => !self.create_endpoints,
            Create::Port => !self.create_ports,
            Create::MemObj(pages) => self.memobj_max_pages != 0 && pages > self.memobj_max_pages,
        }
    }

    /// Bit 0: no endpoints. Bit 1: no ports. Bits 32..: the ceiling. All zero
    /// is [`Limits::NONE`], what a fresh Domain's words hold.
    const fn pack(self) -> u64 {
        (!self.create_endpoints as u64) | (!self.create_ports as u64) << 1 | (self.memobj_max_pages as u64) << 32
    }

    const fn unpack(w: u64) -> Self {
        Self { create_endpoints: w & 1 == 0, create_ports: w & 2 == 0, memobj_max_pages: (w >> 32) as u32 }
    }
}

/// A refused creation: whose limit refused it. What the `subtree-policy`
/// record carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The Domain whose words hold the limit (the actor's own, or an ancestor).
    pub policy: Key,
    /// Levels above the actor: 0 = the actor's own limits.
    pub depth: u8,
    /// [`Create::action`] of the refused creation.
    pub action: u64,
}

/// A Domain's pressure Port: the packed `(index, generation)` reference of the
/// Port, the epoch of its slot (`azos_ipc::port::port_ref_epoch`, which tells
/// two incarnations of a wrapped slot apart) and the key the event carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PressureBind {
    pub port: u32,
    pub epoch: u32,
    pub key: u64,
}

/// The fields only a domain's own members write.
struct State {
    mem_policy: u8,
    /// D10 (multi-user): the user root warrant id; 0 for the system.
    owner_root: u32,
    /// Console login: the one-shot grant the `keys` interface's `login` op
    /// armed for this Domain, `(owner_root of the session it admits, the second
    /// it lapses at)`. Spent by the next `SPAWN_F_USER` spawn
    /// ([`take_login_grant`]); a slot reused by another Domain starts without.
    login_grant: Option<(u32, u64)>,
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
            login_grant: None,
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
    /// The kernel-memory ledger: atomic, shared like `budget`.
    kmem: KmemBudget,
    /// The Domain that created this one ([`NONE`]: a root). Names a live
    /// Domain or none; kept so by [`create_child`] and [`leave`].
    parent: AtomicU32,
    /// Levels below its root, at most [`WALK_MAX`].
    depth: AtomicU8,
    /// Live Domains whose `parent` is this one.
    kids: AtomicU32,
    /// [`Limits`] on this Domain itself (its `self` and `subtree` rows).
    own: AtomicU64,
    /// [`Limits`] on every Domain beneath it (its `subtree` row).
    down: AtomicU64,
    /// [`Limits`] folded in from ancestors left out of the chain (module doc);
    /// they bind this Domain and every Domain beneath it. Survives a
    /// [`set_policy`]: a new image does not shed what an ancestor imposed.
    floor: AtomicU64,
    /// Kernel entries counted by case ([`count_entry`]).
    entries: [AtomicU64; ENTRY_SLOTS],
    /// Bytes of block writes the device completed for it ([`add_written`]).
    written: AtomicU64,
    /// The pledge mask (`azos_abi::invoke::PLEDGE_*`): bits only ever leave it.
    pledge: AtomicU32,
    /// The mask bits that have refused a call and left their durable receipt.
    refused: AtomicU32,
    /// The Port told when the frame budget changes level (a lock, not atomics:
    /// the three words go together, set by a member and read by the reclaim
    /// task; a leaf lock, taken alone and never around another).
    pressure_port: SpinLock<Option<PressureBind>>,
    /// The hardware resource partition its tasks run under ([`set_partition`]).
    /// Atomic: the context-switch path of any hart reads it ([`partition_of`]).
    partition: AtomicU16,
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
            kmem: KmemBudget::new(),
            parent: AtomicU32::new(NONE),
            depth: AtomicU8::new(0),
            kids: AtomicU32::new(0),
            own: AtomicU64::new(0),
            down: AtomicU64::new(0),
            floor: AtomicU64::new(0),
            entries: [const { AtomicU64::new(0) }; ENTRY_SLOTS],
            written: AtomicU64::new(0),
            pledge: AtomicU32::new(PLEDGE_ALL),
            refused: AtomicU32::new(0),
            pressure_port: SpinLock::new(None),
            partition: AtomicU16::new(0),
            state: UnsafeCell::new(State::new()),
        }
    }

    /// What this Domain's subtree is bound by: its `subtree` row and its floor.
    fn reach(&self) -> Limits {
        Limits::unpack(self.down.load(Ordering::Acquire)).narrow(Limits::unpack(self.floor.load(Ordering::Acquire)))
    }
}

static DOMAINS: [Domain; DOMAINS_MAX] = [const { Domain::new() }; DOMAINS_MAX];

/// Bytes written for the kernel itself, or for a Domain that had ended when
/// the device completed the write, plus what the Domains that ended had
/// written when their slots were taken again ([`create_child`]). With the
/// slots' own counters it makes the device total ([`written_totals`]).
static WRITTEN_UNOWNED: AtomicU64 = AtomicU64::new(0);

/// Wakes of the tasks of each Domain, by table slot ([`count_wake`]): a table of
/// their own, a power of two long, so the hand-off's count is a mask, an address
/// and an atomic add. Reset when the slot is taken again ([`create_child`]).
const WAKES_LEN: usize = DOMAINS_MAX.next_power_of_two();
const _: () = assert!(WAKES_LEN <= (INDEX_MASK as usize) + 1);
static WAKES: [AtomicU64; WAKES_LEN] = [const { AtomicU64::new(0) }; WAKES_LEN];

/// Wakes of tasks with no Domain (the kernel's own), and those of the Domains
/// that ended, counted in when their slots were taken again: with the slots'
/// own counters they make the machine's total ([`wakes_total`]).
static WAKES_UNOWNED: AtomicU64 = AtomicU64::new(0);
static WAKES_ENDED: AtomicU64 = AtomicU64::new(0);

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

/// Create a root domain with one member (the creator of the task that will
/// hold the key): a kernel task's. `None` when every slot is in use.
pub fn create() -> Option<Key> {
    create_child(NONE)
}

/// [`create`] a domain beneath `parent`, the Domain of the task creating it (a
/// spawn, a fork). A `parent` that names no live domain makes a root. Beneath
/// a Domain already [`WALK_MAX`] levels deep the new one is attached to that
/// Domain's parent instead, carrying its subtree limits (module doc).
pub fn create_child(parent: Key) -> Option<Key> {
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
        // A user's session is a subtree: a Domain created beneath one is the
        // same user's (`owner_root`, D10). Only the login path ever writes a
        // non-zero root, and only on the session's own Domain
        // ([`set_owner_root`]); everything below inherits it here, before the
        // new Domain is visible.
        if let Some(root) = with(parent, |_, s| s.owner_root) {
            // SAFETY: as above.
            unsafe { (*d.state.get()).owner_root = root };
        }
        d.budget.reset();
        d.budget.set_limit(0);
        d.kmem.reset();
        d.kids.store(0, Ordering::Relaxed);
        d.own.store(0, Ordering::Relaxed);
        d.down.store(0, Ordering::Relaxed);
        d.floor.store(0, Ordering::Relaxed);
        for e in &d.entries {
            e.store(0, Ordering::Relaxed);
        }
        // What the previous occupant wrote stays in the total.
        WRITTEN_UNOWNED.fetch_add(d.written.swap(0, Ordering::Relaxed), Ordering::Relaxed);
        WAKES_ENDED.fetch_add(WAKES[i].swap(0, Ordering::Relaxed), Ordering::Relaxed);
        d.pledge.store(get(parent).map_or(PLEDGE_ALL, |p| p.pledge.load(Ordering::Acquire)), Ordering::Relaxed);
        d.refused.store(0, Ordering::Relaxed);
        // A child runs where its creator does until its own row says otherwise.
        d.partition.store(get(parent).map_or(0, |p| p.partition.load(Ordering::Relaxed)), Ordering::Relaxed);
        *d.pressure_port.lock() = None;
        d.parent.store(NONE, Ordering::Relaxed);
        d.depth.store(0, Ordering::Relaxed);
        if let Some(p) = get(parent) {
            let (mut up, mut depth) = (parent, p.depth.load(Ordering::Relaxed) + 1);
            if depth as usize > WALK_MAX {
                // The bound: leave the parent out of the chain, and keep what
                // binds beneath it.
                d.floor.store(p.reach().pack(), Ordering::Relaxed);
                up = p.parent.load(Ordering::Relaxed);
                depth = WALK_MAX as u8;
            }
            d.parent.store(up, Ordering::Relaxed);
            d.depth.store(depth, Ordering::Relaxed);
            if let Some(u) = get(up) {
                u.kids.fetch_add(1, Ordering::Relaxed);
            }
        }
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
        Some(d) => {
            if d.live.load(Ordering::Relaxed) == 1 {
                // Before the Domain is marked free, so a walk never sees a
                // child whose limits are not yet its own.
                detach(key, d);
            }
            d.live.fetch_sub(1, Ordering::AcqRel) == 1
        }
        None => false,
    }
}

/// The last member of `d` (named `key`) is going: its children become its
/// parent's, carrying the limits of its subtree, and it stops being a child.
/// Under [`LIFECYCLE`].
fn detach(key: Key, d: &Domain) {
    let up = d.parent.load(Ordering::Relaxed);
    let kids = d.kids.load(Ordering::Relaxed);
    if kids != 0 {
        let reach = d.reach();
        for c in DOMAINS.iter() {
            if c.live.load(Ordering::Relaxed) != 0 && c.parent.load(Ordering::Relaxed) == key {
                let floor = Limits::unpack(c.floor.load(Ordering::Relaxed)).narrow(reach);
                c.floor.store(floor.pack(), Ordering::Release);
                c.parent.store(up, Ordering::Release);
            }
        }
    }
    if let Some(u) = get(up) {
        // One less child (this one), `kids` more.
        u.kids.fetch_add(kids, Ordering::Relaxed);
        u.kids.fetch_sub(1, Ordering::Relaxed);
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
        // The page tables grown by the old address space went with it. The
        // rest of the kernel-memory ledger (capability table, endpoints,
        // MemObjs) belongs to the Domain and survives an exec.
        d.kmem.discharge_all(KmemClass::PageTable);
    }
}

/// Declare the budget limit, in 4 KiB pages (0 = none).
pub fn set_limit(key: Key, limit: u32) {
    if let Some(d) = get(key) {
        // The row's limit is also where reclaim starts and stops: the high and
        // low watermarks follow from it (none for no limit, or with reclaim off).
        d.budget.set_limit_marked(limit, RECLAIM_HIGH_PCT, RECLAIM_LOW_PCT);
    }
}

/// Where a Domain's reclaim starts and stops, in percent of its frame limit
/// (Kconfig `MM_RECLAIM_HIGH_PCT` / `MM_RECLAIM_LOW_PCT`); 0 with reclaim off.
const RECLAIM_HIGH_PCT: u32 = if azos_limits::MM_RECLAIM_COMPRESS { azos_limits::MM_RECLAIM_HIGH_PCT as u32 } else { 0 };
const RECLAIM_LOW_PCT: u32 = if azos_limits::MM_RECLAIM_COMPRESS { azos_limits::MM_RECLAIM_LOW_PCT as u32 } else { 0 };

/// The frame budget of the domain `key` names, for the reclaimer: it opens
/// the Domain's storms on it and reads its pressure. `None` for a key that
/// names no live domain.
pub fn budget(key: Key) -> Option<&'static PageBudget> {
    get(key).map(|d| &d.budget)
}

/// The frame budget of the live Domain in table slot `slot`. For a holder of a
/// slot rather than a key, as [`slot_mem_locked`]: the compressed-page pool's
/// entries name the Domain they were charged to by [`index`], and a restore
/// charges that one.
pub fn slot_budget(slot: usize) -> Option<&'static PageBudget> {
    DOMAINS.get(slot).filter(|d| d.live.load(Ordering::Acquire) != 0).map(|d| &d.budget)
}

/// Make `bind` the Port the domain `key` names is told its pressure on; one
/// Port per Domain, a second bind replaces the first. `false` for a key that
/// names no live domain.
pub fn set_pressure_port(key: Key, bind: PressureBind) -> bool {
    match get(key) {
        Some(d) => {
            *d.pressure_port.lock() = Some(bind);
            true
        }
        None => false,
    }
}

/// Stop telling the Port about the domain `key` names, if one is bound and
/// `is` says it is the one meant: the unbind of a program names its Port and
/// key, the reclaim task names the binding it found stale, and neither may
/// take away a binding made since. `true` when one was cleared.
pub fn clear_pressure_port(key: Key, is: impl FnOnce(&PressureBind) -> bool) -> bool {
    let Some(d) = get(key) else { return false };
    let mut slot = d.pressure_port.lock();
    if slot.as_ref().is_some_and(is) {
        *slot = None;
        true
    } else {
        false
    }
}

/// The Port the domain `key` names is told its pressure on, if one is bound.
pub fn pressure_port(key: Key) -> Option<PressureBind> {
    get(key).and_then(|d| *d.pressure_port.lock())
}

/// `(used, limit)`; zeroes for a key that names no domain.
pub fn used_limit(key: Key) -> (u32, u32) {
    get(key).map_or((0, 0), |d| (d.budget.used(), d.budget.limit()))
}

/// The high-water mark of the budget.
pub fn peak(key: Key) -> u32 {
    get(key).map_or(0, |d| d.budget.peak())
}

// ── The kernel-memory ledger ───────────────────────────────────────────────

/// Charge `bytes` of `class` to the kernel-memory ledger of the domain `key`
/// names, all or nothing. `false`, nothing charged, and a `kmem-charge`
/// `Refuse` record (subject: the key; `bytes`, `used`, `limit`: a receipt, durable
/// where refusals are) when it would take the ledger past a nonzero limit. A
/// key that names no live domain (the kernel's own objects, a domain whose
/// last member just went) has nothing to bill: `true`, and the matching
/// [`kmem_discharge`] is a no-op as well.
///
/// Call it with no spinlock held (see the module doc): the durable record can
/// flush. From a context that may hold one, use [`kmem_charge_atomic`].
pub fn kmem_charge(key: Key, class: KmemClass, bytes: u64) -> bool {
    charge_with(key, class, bytes, Verdict::Refuse)
}

/// [`kmem_charge`] for a context that may hold a spinlock or run with
/// interrupts off (the page-table hook of the mapping paths): the refusal is
/// recorded as `Deny`, which stays in the lock-free ring and never reaches the
/// durable sink.
pub fn kmem_charge_atomic(key: Key, class: KmemClass, bytes: u64) -> bool {
    charge_with(key, class, bytes, Verdict::Deny)
}

fn charge_with(key: Key, class: KmemClass, bytes: u64, verdict: Verdict) -> bool {
    let Some(d) = get(key) else { return true };
    match d.kmem.charge(class, bytes) {
        Ok(()) => true,
        Err(r) => {
            azos_decision::record(Rule::KmemCharge, verdict, key, [r.bytes, r.used, r.limit]);
            false
        }
    }
}

/// Give `bytes` of `class` back to the domain `key` names, from any context
/// and any Domain. At most what the class holds; a key that names no live
/// domain needs nothing.
pub fn kmem_discharge(key: Key, class: KmemClass, bytes: u64) {
    if let Some(d) = get(key) {
        d.kmem.discharge(class, bytes);
    }
}

/// Declare the kernel-memory limit, in KiB (0 = none).
pub fn set_kmem_limit_kib(key: Key, kib: u32) {
    if let Some(d) = get(key) {
        d.kmem.set_limit_kib(kib);
    }
}

/// The kernel-memory limit in KiB (0 = none), saturated to `u32::MAX`.
pub fn kmem_limit_kib(key: Key) -> u32 {
    get(key).map_or(0, |d| (d.kmem.limit() / 1024).min(u64::from(u32::MAX)) as u32)
}

/// `(used, limit)` in bytes of the kernel-memory ledger, and the bytes held by
/// `class`; zeroes for a key that names no domain.
pub fn kmem_used_limit(key: Key, class: KmemClass) -> (u64, u64, u64) {
    get(key).map_or((0, 0, 0), |d| (d.kmem.used(), d.kmem.limit(), d.kmem.used_of(class)))
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

/// Is the domain in table slot `slot` alive and `mem = "locked"`? For a holder
/// of a slot rather than a key: the compressed-page pool's ledgers are indexed
/// by [`index`], and swap asks whether the Domain a page was charged to is
/// pinned. Reads the flag the way [`mem_locked`] does.
pub fn slot_mem_locked(slot: usize) -> bool {
    DOMAINS.get(slot).is_some_and(|d| {
        // SAFETY: as `with`: the single-writer discipline of the module doc.
        d.live.load(Ordering::Acquire) != 0 && unsafe { &*d.state.get() }.mem_policy & MEM_LOCKED != 0
    })
}

// ── The subtree policy ─────────────────────────────────────────────────────

/// Bind the limits of the Domain `key` names: `self_row` from its `scope =
/// "self"` row, `subtree_row` from its `scope = "subtree"` row ([`Limits::NONE`]
/// for a row it has not). Replaces what an earlier image bound, so a new image
/// is bound by its own rows only; what an ancestor imposes (its subtree row
/// and the floor) is not here and stays.
pub fn set_policy(key: Key, self_row: Limits, subtree_row: Limits) {
    let _g = LIFECYCLE.lock();
    if let Some(d) = get(key) {
        d.own.store(self_row.narrow(subtree_row).pack(), Ordering::Release);
        d.down.store(subtree_row.pack(), Ordering::Release);
    }
}

/// The first limit that refuses `what` for the Domain `key` names: its own
/// words (its `self` and `subtree` rows and its floor), then the `subtree`
/// rows and floors of its ancestors, nearest first, at most [`WALK_MAX`] of
/// them. `None` allows it, and for a key that names no domain (the kernel's own
/// objects).
pub fn refusal(key: Key, what: Create) -> Option<Refusal> {
    let d = get(key)?;
    let hit = |policy: Key, depth: u8| Some(Refusal { policy, depth, action: what.action() });
    if Limits::unpack(d.own.load(Ordering::Acquire)).narrow(Limits::unpack(d.floor.load(Ordering::Acquire))).refuses(what) {
        return hit(key, 0);
    }
    let mut up = d.parent.load(Ordering::Acquire);
    for hop in 1..=WALK_MAX {
        // [`NONE`] names no domain: the root ends the walk.
        let Some(a) = get(up) else { break };
        if a.reach().refuses(what) {
            return hit(up, hop as u8);
        }
        up = a.parent.load(Ordering::Acquire);
    }
    None
}

/// May the Domain `key` names create `what`? A refusal leaves a
/// `subtree-policy` `Refuse` record (subject: the actor's Domain; `policy`:
/// the Domain whose limit refused, `depth`: how far above the actor it is,
/// `action`: [`Create::action`]), durable where refusals are, so call it
/// holding no spinlock.
pub fn check_create(key: Key, what: Create) -> Result<(), Refusal> {
    match refusal(key, what) {
        None => Ok(()),
        Some(r) => {
            azos_decision::record(Rule::SubtreePolicy, Verdict::Refuse, key, [u64::from(r.policy), u64::from(r.depth), r.action]);
            Err(r)
        }
    }
}

// ── Kernel entries by case, and the pledge ──────────────────────────────

/// The syscall prologue's call: count one entry of `case` (`0`: no case) in the
/// Domain `key` names. A key that names no domain (a kernel task) counts
/// nothing.
///
/// Reads the slot straight from the key's index, with no generation check: the
/// key is the running task's own, whose Domain cannot end under it.
#[inline(always)]
pub fn count_entry(key: Key, case: u8) {
    if key == NONE || !azos_limits::DOMAIN_ENTRY_COUNTERS {
        return;
    }
    if let Some(d) = DOMAINS.get(index(key)) {
        d.entries[(case as usize).min(CASES)].fetch_add(1, Ordering::Relaxed);
    }
}

/// The whole prologue entry of one syscall in the running task's Domain `key`:
/// count it ([`count_entry`], `case`) and judge it by the pledge mask. `bit` is
/// the mask bit that judges the call (`azos_abi::invoke::pledge_bit`), `nr` its
/// number, `tid` the calling task (the receipt's subject). `true`: run it. `false`: the mask refuses it and the receipt is
/// written (see the module doc); the caller answers `-EACCES`. A refused call
/// is counted too: it entered the kernel.
///
/// The common case is a Domain nobody narrowed: one relaxed load and a
/// compare. Like [`count_entry`] it trusts the key to be the running task's.
#[inline(always)]
pub fn enter(key: Key, tid: u32, nr: u64, case: u8, bit: u8) -> bool {
    let Some(d) = DOMAINS.get(index(key)).filter(|_| key != NONE) else { return true };
    if azos_limits::DOMAIN_ENTRY_COUNTERS {
        d.entries[(case as usize).min(CASES)].fetch_add(1, Ordering::Relaxed);
    }
    judge(d, tid, Door::Trap, nr, bit)
}

/// The pledge mask's judgment of one operation that is not a trap of its own: a
/// `io_ring` entry (its twin is a typed call the mask judges the same way, see
/// [`enter`]). `key` the Domain of the ring's owner and `tid` the owner (never
/// the SQ poller), `nr` the syscall number the entry stands for and `bit` the mask bit of it (`azos_abi::invoke::pledge_bit`).
/// Nothing is counted: the ring's one `SYS_RING_ENTER` already was. `false`: the
/// mask refuses it, the receipt is written, the entry completes refused. A key
/// that names no Domain refuses nothing.
pub fn admit(key: Key, tid: u32, nr: u64, bit: u8) -> bool {
    match DOMAINS.get(index(key)).filter(|_| key != NONE) {
        Some(d) => judge(d, tid, Door::Ring, nr, bit),
        None => true,
    }
}

/// The mask against one bit: the common case (a Domain nobody narrowed) is one
/// relaxed load and a compare.
#[inline(always)]
fn judge(d: &Domain, tid: u32, door: Door, nr: u64, bit: u8) -> bool {
    let mask = d.pledge.load(Ordering::Relaxed);
    if mask == PLEDGE_ALL || mask >> bit & 1 != 0 {
        return true;
    }
    refuse(d, mask, tid, door, nr, bit);
    false
}

/// A call the mask refused: the `pledge` record (subject the calling task,
/// `mask` the mask in force, the action word the `door`). The first refusal of
/// each mask bit is a `Refuse` (durable where refusals are: it is the one that
/// says a program stepped outside what it promised); the rest are `Deny`, which
/// stays in the ring. Called from the prologue and from a ring entry's dispatch
/// ([`admit`]), neither of which holds a spinlock.
#[cold]
#[inline(never)]
fn refuse(d: &Domain, mask: u32, tid: u32, door: Door, nr: u64, bit: u8) {
    let first = d.refused.fetch_or(1 << bit, Ordering::Relaxed) >> bit & 1 == 0;
    let verdict = if first { Verdict::Refuse } else { Verdict::Deny };
    azos_decision::record(Rule::Pledge, verdict, tid, [u64::from(mask), door.refused(), nr]);
}

/// Why [`pledge_narrow`] changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PledgeError {
    /// The key names no live Domain.
    NoDomain,
    /// The request holds a bit no mask has.
    Unknown,
    /// The request holds a bit the Domain's mask has already lost.
    Widen,
}

/// Narrow the pledge mask of the Domain `key` names to `req` (plus
/// [`PLEDGE_ALWAYS`], which no mask loses). All or nothing: a request that
/// holds one bit the mask no longer has changes none. Returns the mask now in
/// force. Atomic against another member narrowing at the same time.
pub fn pledge_narrow(key: Key, req: u32) -> Result<u32, PledgeError> {
    let d = get(key).ok_or(PledgeError::NoDomain)?;
    if req & !PLEDGE_ALL != 0 {
        return Err(PledgeError::Unknown);
    }
    let req = req | PLEDGE_ALWAYS;
    let mut cur = d.pledge.load(Ordering::Acquire);
    loop {
        if req & !cur != 0 {
            return Err(PledgeError::Widen);
        }
        match d.pledge.compare_exchange_weak(cur, req, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(req),
            Err(now) => cur = now,
        }
    }
}

/// Entries counted for the Domain `key` names, by slot ([`ENTRY_SLOTS`]);
/// zeroes for a key that names no domain.
pub fn entries(key: Key) -> [u64; ENTRY_SLOTS] {
    match get(key) {
        Some(d) => core::array::from_fn(|i| d.entries[i].load(Ordering::Relaxed)),
        None => [0; ENTRY_SLOTS],
    }
}

/// The Domain in table slot `slot` and its entries, if it is alive. For a
/// walk of the table rather than a holder of a key (the introspection tree).
pub fn slot_entries(slot: usize) -> Option<(Key, [u64; ENTRY_SLOTS])> {
    let d = DOMAINS.get(slot).filter(|d| d.live.load(Ordering::Acquire) != 0)?;
    let key = (d.gen.load(Ordering::Acquire) << INDEX_BITS) | slot as u32;
    Some((key, core::array::from_fn(|i| d.entries[i].load(Ordering::Relaxed))))
}

/// A task of the Domain `key` names was woken (`scheduler::wake`, Kconfig
/// `WAKE_RING_ENTRIES`): the wakes counted before this one, 0 for the first, in
/// the Domain, or among the wakes of tasks that have none (a kernel task's: a
/// key that names no domain). Like [`count_entry`] it trusts the key to be the
/// woken task's own, which keeps its Domain alive for as long as the wake is
/// being made.
#[inline(always)]
pub fn count_wake(key: Key) -> u64 {
    if key == NONE {
        return WAKES_UNOWNED.fetch_add(1, Ordering::Relaxed);
    }
    // One mask is the index and the bound (`WAKES` is a power of two long).
    WAKES[key as usize & (WAKES_LEN - 1)].fetch_add(1, Ordering::Relaxed)
}

/// Wakes since boot, all of them: the Domains' (live, and ended and not yet
/// taken again), the kernel tasks', and those of the Domains that ended
/// (counted in when their slots were taken again, [`create_child`]). A walk of
/// the table: one that meets a slot being taken again can count what its
/// occupant woke twice or not at all, so the reader that publishes a counter
/// keeps the larger of two readings.
pub fn wakes_total() -> u64 {
    let slots: u64 = WAKES.iter().map(|w| w.load(Ordering::Relaxed)).sum();
    slots + WAKES_UNOWNED.load(Ordering::Relaxed) + WAKES_ENDED.load(Ordering::Relaxed)
}

/// The Domain in table slot `slot` and the wakes of its tasks, if it is alive.
/// For a walk of the table (the introspection tree), like [`slot_entries`].
pub fn slot_wakes(slot: usize) -> Option<(Key, [u64; 1])> {
    let d = DOMAINS.get(slot).filter(|d| d.live.load(Ordering::Acquire) != 0)?;
    let key = (d.gen.load(Ordering::Acquire) << INDEX_BITS) | slot as u32;
    Some((key, [WAKES[slot].load(Ordering::Relaxed)]))
}

/// The device completed a write of `bytes` for the Domain `key` names. A key
/// that names no live Domain (`OWNER_KERNEL`, a kernel task's, or a Domain that
/// ended while its request was queued) goes to the unowned total, never to the
/// Domain that took the slot after it: the completion is asynchronous, so the
/// generation is checked, unlike [`count_entry`] whose key is the running
/// task's. Atomics only, callable under any lock.
pub fn add_written(key: Key, bytes: u64) {
    match get(key) {
        Some(d) => d.written.fetch_add(bytes, Ordering::Relaxed),
        None => WRITTEN_UNOWNED.fetch_add(bytes, Ordering::Relaxed),
    };
}

/// `(total, unowned)` bytes of completed block writes since boot: all of them,
/// and those that belong to no live Domain (the kernel's, and those of the
/// Domains that ended). The difference is what the live Domains wrote. Whoever
/// ends, the sum is the same; but a walk that meets a slot being taken again
/// can count what its occupant wrote twice or not at all, so the reader that
/// publishes a counter keeps the larger of two readings. A walk of the table.
pub fn written_totals() -> (u64, u64) {
    let (mut live, mut dead) = (0u64, 0u64);
    for d in DOMAINS.iter() {
        let n = d.written.load(Ordering::Relaxed);
        if d.live.load(Ordering::Acquire) != 0 {
            live += n;
        } else {
            dead += n;
        }
    }
    let unowned = WRITTEN_UNOWNED.load(Ordering::Relaxed) + dead;
    (live + unowned, unowned)
}

/// The Domain in table slot `slot` and the bytes written for it, if it is
/// alive. For a walk of the table (the introspection tree), like
/// [`slot_entries`].
pub fn slot_written(slot: usize) -> Option<(Key, [u64; 1])> {
    let d = DOMAINS.get(slot).filter(|d| d.live.load(Ordering::Acquire) != 0)?;
    let key = (d.gen.load(Ordering::Acquire) << INDEX_BITS) | slot as u32;
    Some((key, [d.written.load(Ordering::Relaxed)]))
}

// ── The hooks ──────────────────────────────────────────────────────────────

/// A copy of a domain's hook fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub live: u32,
    /// The Domain that created this one ([`NONE`]: a root).
    pub parent: Key,
    /// Levels below its root, at most [`WALK_MAX`].
    pub depth: u8,
    pub owner_root: u32,
    pub partition_id: u16,
    pub vm: Option<u32>,
    pub measurement: [u8; 32],
}

/// The hook fields of the domain `key` names.
pub fn info(key: Key) -> Option<Info> {
    with(key, |d, s| Info {
        live: d.live.load(Ordering::Acquire),
        parent: d.parent.load(Ordering::Acquire),
        depth: d.depth.load(Ordering::Acquire),
        owner_root: s.owner_root,
        partition_id: d.partition.load(Ordering::Relaxed),
        vm: s.vm,
        measurement: s.measurement,
    })
}

/// Make the domain `key` names the session of the user whose root is
/// `owner_root` (D10): its keystore scope, and the root every Domain created
/// beneath it inherits ([`create_child`]). Called by the spawn that a login
/// grant admits (`SPAWN_F_USER`), on the child before it runs. `false`, nothing
/// changed, when `key` names no live domain.
pub fn set_owner_root(key: Key, owner_root: u32) -> bool {
    with(key, |_, s| s.owner_root = owner_root).is_some()
}

/// Arm the one-shot login grant of the domain `key` names: its next
/// `SPAWN_F_USER` spawn may start the session of the user whose root is
/// `owner_root` (0: the system's own session, when nobody is enrolled) until
/// second `until_s`. A grant already armed is replaced, never stacked: one
/// credential, one session. `false`, nothing armed, when `key` names no live
/// domain.
pub fn arm_login_grant(key: Key, owner_root: u32, until_s: u64) -> bool {
    with(key, |_, s| s.login_grant = Some((owner_root, until_s))).is_some()
}

/// Spend the login grant of the domain `key` names at second `now_s`: the root
/// it admits, or `None` when none is armed or it has lapsed. The grant is gone
/// either way (a lapsed one is not kept for a later look).
pub fn take_login_grant(key: Key, now_s: u64) -> Option<u32> {
    with(key, |_, s| s.login_grant.take()).flatten().filter(|&(_, until)| now_s <= until).map(|(root, _)| root)
}

/// Put the domain `key` names in resource partition `partition` (0: the
/// default partition). The value is stored as given: whether the hardware can
/// tag it is [`crate::qos::fit`]'s question, asked by the callers that hold
/// the machine (`scheduler::set_task_partition`), so this table stays free of
/// any arch dependency.
pub fn set_partition(key: Key, partition: u16) {
    if let Some(d) = get(key) {
        d.partition.store(partition, Ordering::Relaxed);
    }
}

/// The partition of the Domain `key` names; 0 for none. The context-switch
/// path of [`count_entry`]'s kind: read straight from the key's slot with no
/// generation check, since the key is the incoming task's own and its Domain
/// cannot end before the task runs.
#[inline(always)]
pub fn partition_of(key: Key) -> u16 {
    if key == NONE {
        return 0;
    }
    DOMAINS.get(index(key)).map_or(0, |d| d.partition.load(Ordering::Relaxed))
}

/// Record the DICE measurement of the image a domain started from.
pub fn set_measurement(key: Key, measurement: [u8; 32]) {
    let _ = with(key, |_, s| s.measurement = measurement);
}

/// The DICE measurement of the image the domain `key` names started from;
/// `None` for a key that names no domain. All zeros: none was recorded.
pub fn measurement(key: Key) -> Option<[u8; 32]> {
    with(key, |_, s| s.measurement)
}

/// Domains alive right now.
pub fn count() -> usize {
    DOMAINS.iter().filter(|d| d.live.load(Ordering::Relaxed) != 0).count()
}
