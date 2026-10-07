// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// Lease-based IPC — zero-copy large transfers (M04).
///
/// A **lease** is a time-bounded grant of a shared memory region from a sender
/// (the "lessor") to a receiver (the "lessee").  While the lease is active:
///
/// - A lessee that accepted with `SYS_IPC_LEASE_ACCEPT_MAP` has the region
///   mapped, by the lease, until the lease ends (see "Leases that bite" below).
/// - The lessor is expected not to write the buffer. A lessor that granted
///   with the seal (`LEASE_GRANT_SEAL`) cannot: its own mapping is read-only
///   until the lease ends ("The producer-side seal" below). A lessor that
///   calls `lease_wait_return()` blocks until the lease is returned or expires.
/// - When the lessee calls `lease_return()` the lessor is woken.
///
/// This allows camera frames, sensor buffers, and inference inputs to be passed
/// between tasks without any copying.  It is inspired by the ownership transfer
/// semantics of seL4 Reply+RecvWait and Midori's promise-based IPC.
///
/// ## Usage
///
/// ```text
/// Lessor (producer):
///   cap = shm_create_typed(...)           // allocate buffer
///   lease_id = lease_grant(cap, lessee_tid, expire_ticks)
///   // ... the lessor's own write access is taken away only with the seal
///   lease_wait(Cap<Lease>)                // blocks until lessee returns or expires
///
/// Lessee (consumer):
///   (lease_id, va) = lease_accept_map(lessor_tid)  // blocks; maps the region
///   // ... read/process the buffer through `va`
///   lease_return(lease_id)               // wake lessor; `va` is unmapped
/// ```
///
/// ## Leases that bite (wave 11, LEASE2; RFC-0049 P4)
///
/// A lessee that accepts with `SYS_IPC_LEASE_ACCEPT_MAP` gets a mapping of the region
/// that BELONGS TO THE LEASE ([`LeaseMap`]): the kernel records the lessee's
/// page-table root, address and size in the entry, and books the frames under
/// a holder that is not a task ([`lease_holder_tid`]), so nothing the lessee
/// does with its own `Cap<Shm>` (if it has one) can free them early. When the
/// lease ends — the lessee's return, the lessor's free or exit, an expiry
/// (the timer interrupt only marks it; the kernel's lease worker,
/// [`lease_reap_expired`], or the lessor's `lease_wait` wake, whichever runs
/// first, removes it) — the mapping is removed from the
/// lessee's page table and shot down on every hart through the boot-registered
/// [`UnmapHook`], then the window is remembered ([`Revoked`]) so the lessee's
/// next touch of it is attributed: the fault kills the task as any unresolved
/// fault does, and [`lease_revoked_fault`] records it. P4 asked for "forced
/// switch, then unmap"; with the satp-root shootdown in the tree the switch is
/// not needed — the shootdown is what guarantees no hart keeps the old
/// translation.
///
/// What this does NOT do: a mapping the lessee made itself with a `Cap<Shm>`
/// is not the lease's and is not touched. A plain accept maps nothing.
///
/// ## The producer-side seal (wave 11, LEASE3)
///
/// A grant with `LEASE_GRANT_SEAL` (a topology row may require it) makes the
/// lessor's own mapping of the region read-only in the hold that allocates
/// the lease, with a shootdown on every hart ([`SealHook`]), and every end of
/// the lease gives the write back the same way. A lessor write in between
/// faults, is recorded ([`lease_sealed_fault`]) and kills the lessor, as a
/// store to any read-only page does. A lessor with no mapping at grant that
/// maps the region during the seal gets a read-only mapping that stays so
/// ([`lease_sealed_by`]). Other holders of the region are not sealed.
///
/// ## Page-table lifetime (the invariant every revoke depends on)
///
/// A revoke edits the LESSEE's page table from whatever context ends the lease
/// (the lessor's syscall, another task's exit) — never from the timer
/// interrupt: `vmm`'s kernel-table guard takes `KERNEL_PT`'s plain lock. Address
/// spaces are not reference counted (`destroy_user_address_space` frees on
/// exit-slot reuse and on exec), so:
///
///  1. every PTE clear of a lease mapping happens while `LEASES` is held, and
///  2. every path that ends a lessee's address space clears that address
///     space's lease mappings under `LEASES` first: the task-exit hook
///     ([`lease_release_all`], before the address space is torn down) and
///     `exec` ([`lease_exec`], before the exec hand-off frees the old root).
///
/// So a revoke that finds a recorded root under `LEASES` finds a live one.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use azos_sync::SpinLock;
use azos_sched::task::MAX_TASKS;
pub use azos_limits::MAX_LEASES;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel TID for "no owner".
const NO_TID: u32 = u32::MAX;

/// Most table entries ONE ring-3 lessor may occupy at once.
///
/// `MAX_LEASES` bounds the table for the WHOLE MACHINE, so without this a
/// single task that owns one region could grant it `MAX_LEASES` times and
/// every other lessor's grant would fail: *minting without a per-task quota
/// is exhaustion* (RFC-0003 addendum), the rule `MAX_PORTS_PER_TASK`,
/// `MAX_SHM_REGIONS_PER_TASK` and `MAX_MCAST_GROUPS_PER_TASK` apply to their
/// own pools. Half the table, as they do (owner decision 2026-09-14).
///
/// **What counts is occupancy: every entry that is not `Free` and names this
/// lessor** — `Pending`, `Active`, `Returned` and `Expired` alike, the way
/// `port_create` and `shm_create` count allocated slots. A `Returned` or
/// `Expired` entry holds its slot until the lessor calls `lease_free` (or
/// exits), so it is charged until then. Counting only the leases in flight
/// left the table exhaustible by one task: grant to itself, accept, return,
/// and repeat, until every slot held a `Returned` entry of that lessor and
/// every other grant got `NoSlot`.
///
/// Kernel grants (`privileged`) are exempt, as kernel-owned sockets are from
/// `MAX_MCAST_GROUPS_PER_TASK`, the precedent this quota's `-EQUOTA` follows:
/// kernel lessors are bounded by their own call sites (the i3 lease probe
/// grants one), and `privileged` is already the bypass [`lease_grant_as`]
/// gives the owner check.
pub const MAX_LEASES_PER_LESSOR: usize = MAX_LEASES / 2;

/// Why [`lease_grant_as`] refused a grant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseGrantError {
    /// A ring-3 lessor does not own the region (or the id names none).
    NotOwner,
    /// The lessor already occupies [`MAX_LEASES_PER_LESSOR`] entries of the
    /// table. `SYS_IPC_LEASE_GRANT_TYPED` returns `-EQUOTA` for this one.
    Quota,
    /// Every slot of the table is taken.
    NoSlot,
}

impl LeaseGrantError {
    /// The value `SYS_IPC_LEASE_GRANT_TYPED` returns for this refusal: `-EQUOTA`
    /// for [`LeaseGrantError::Quota`], the errno multicast returns for its
    /// per-task quota (`handlers.rs`, `McastError::SocketFull`), and `-1` for
    /// the other two, as the arm answered before the quota existed.
    pub const fn syscall_ret(self) -> i64 {
        match self {
            LeaseGrantError::Quota => azos_abi::error::Errno::EQUOTA.to_syscall_ret(),
            LeaseGrantError::NotOwner | LeaseGrantError::NoSlot => -1,
        }
    }
}

/// Wakes [`lease_accept_wait`] waits through before it answers
/// [`LeaseAcceptError::TurnsExhausted`].
///
/// A wake with no lease from the named lessor does not end the wait: a stamp
/// left by a concurrent grant, a grant from another lessor landing before the
/// block (its stamp consults no predicate) and a K-C29 refusal all return from
/// the block with nothing to take. Eight turns, as `SYS_IPC_FAST_CALL` has.
pub const LEASE_ACCEPT_TURNS: u32 = 8;

/// What [`lease_accept_begin`] found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseAcceptBegin {
    /// A lease from the named lessor was pending and is now `Active`:
    /// `(lease_id, shm_id)`. Nothing was registered.
    Got(usize, usize),
    /// Nothing pending; the wait is registered and the caller may block on
    /// `WaitReason::LeaseAccept(lessee, lessor)`.
    Registered,
    /// Nothing pending and no free registration slot. Nothing was registered,
    /// so the caller must not block.
    NoRoom,
}

/// What [`lease_accept_poll`] found after a block returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseAcceptPoll {
    /// The named lessor exited while this wait was registered.
    LessorGone,
    /// A lease from the named lessor was pending and is now `Active`:
    /// `(lease_id, shm_id)`.
    Got(usize, usize),
    /// Still registered, nothing pending: block again.
    StillWaiting,
    /// No registration for this `(lessee, lessor)`. Not produced by
    /// [`lease_accept_wait`], which registers before its first block and
    /// deregisters only at its exit; answered so that no caller ever blocks
    /// on a wait the exit sweep cannot see.
    NotRegistered,
}

/// Why [`lease_accept_wait`] returned without a lease. `SYS_IPC_LEASE_ACCEPT`
/// answers -1 for every one of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseAcceptError {
    /// The named lessor exited while the caller waited.
    LessorGone,
    /// No registration slot: refused before blocking.
    RegistryFull,
    /// [`LEASE_ACCEPT_TURNS`] wakes and no lease from the named lessor.
    TurnsExhausted,
    /// See [`LeaseAcceptPoll::NotRegistered`].
    NotRegistered,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Lifecycle state of a lease.
#[derive(Clone, Copy, PartialEq)]
pub enum LeaseState {
    /// Slot is unused.
    Free,
    /// Granted but lessee has not accepted yet.
    Pending,
    /// Lessee has accepted; buffer is in use.
    Active,
    /// Lessee has returned the buffer; lessor can reclaim.
    Returned,
    /// Lease timed out (expire_ticks reached).
    Expired,
}

/// The lease's own mapping of its region in the lessee (accept-and-map).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LeaseMap {
    /// The lessee's page-table root the PTEs live in; `0` = no PTEs (never
    /// mapped, or already revoked). Non-zero only while that root is a live
    /// address space of the lessee (module doc, "Page-table lifetime").
    pub root:  usize,
    pub va:    usize,
    pub pages: usize,
    /// A region reference is booked under [`lease_holder_tid`] for this
    /// mapping and has not been given back yet. Given back only once `root`
    /// is 0 (no PTE left), and never from the timer interrupt.
    pub ref_held: bool,
}

impl LeaseMap {
    pub const NONE: LeaseMap = LeaseMap { root: 0, va: 0, pages: 0, ref_held: false };
}

/// A single lease entry.
pub struct LeaseEntry {
    pub shm_id:       usize,
    pub lessor_tid:   u32,
    pub lessee_tid:   u32,
    pub expire_ticks: u64,   // absolute deadline in CLINT ticks (0 = no expiry)
    pub state:        LeaseState,
    /// The region's packed `(index, generation)` reference when it was
    /// granted (`0`: none resolved). Accept-and-map maps THIS region, never
    /// whatever later took the index.
    pub shm_ref:      u32,
    /// The lessee's mapping may be writable: the region is read-write AND the
    /// lessor's capability held `WRITE` at grant (a kernel grant: the region's
    /// mode). A lease never hands out more than its lessor had.
    pub writable:     bool,
    /// The lease's mapping in the lessee, if it accepted with the map flag.
    pub map:          LeaseMap,
    /// The lessor asked for a producer-side write seal at grant (wave 11,
    /// LEASE3; `LEASE_GRANT_SEAL`): its own mapping of the region is
    /// read-only while the lease is in flight.
    pub sealed:       bool,
    /// The lessor's mapping the seal made read-only, to be given its write
    /// back when the lease ends; `root == 0` when nothing was downgraded.
    pub seal:         SealMap,
}

/// The lessor's mapping a sealed lease made read-only ([`LeaseEntry::seal`]).
/// `root` is the lessor's page-table root, non-zero only while that root is a
/// live address space of the lessor (module doc, "Page-table lifetime").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SealMap {
    pub root:  usize,
    pub va:    usize,
    pub pages: usize,
}

impl SealMap {
    pub const NONE: SealMap = SealMap { root: 0, va: 0, pages: 0 };
}

impl LeaseEntry {
    pub const fn empty() -> Self {
        LeaseEntry {
            shm_id:       0,
            lessor_tid:   NO_TID,
            lessee_tid:   NO_TID,
            expire_ticks: 0,
            state:        LeaseState::Free,
            shm_ref:      0,
            writable:     false,
            map:          LeaseMap::NONE,
            sealed:       false,
            seal:         SealMap::NONE,
        }
    }
}

/// A lease mapping the kernel removed, kept so the lessee's next touch of the
/// window is attributed ([`lease_revoked_fault`]) and so its window addresses
/// can be given back by the lessee itself ([`lease_take_revoked`]; only the
/// current task can release its own window). `tid == NO_TID` is a free row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Revoked {
    pub tid:   u32,
    pub lease: u32,
    pub va:    usize,
    pub pages: usize,
}

impl Revoked {
    const FREE: Revoked = Revoked { tid: NO_TID, lease: 0, va: 0, pages: 0 };
}

/// Rows of the revoked-window table: one per lease entry. A row lives from a
/// revoke until the lessee's next accept-and-map (which gives the window
/// back) or its exit/exec; a row that finds the table full is not recorded
/// ([`REVOKED_UNRECORDED`]) — the window then stays reserved in the lessee
/// until it exits, and a fault in it is killed unattributed.
const REVOKED_ROWS: usize = MAX_LEASES;

/// The pseudo holder a lease mapping's region reference is booked under:
/// `LEASE_HOLDER_BASE + lease_id`. Never a task's TID (TIDs are allocated
/// upwards from 1 and never reach it), so neither the lessee's typed release
/// (`shm_release_holder_ref` gives back EVERY reference its TID holds) nor
/// any task's exit sweep can give it back while the lease's PTEs exist.
pub const LEASE_HOLDER_BASE: u32 = 0xF000_0000;
const _: () = assert!(MAX_LEASES as u64 <= (NO_TID - LEASE_HOLDER_BASE) as u64);

/// The pseudo holder of lease `id`'s mapping reference.
pub const fn lease_holder_tid(id: usize) -> u32 {
    LEASE_HOLDER_BASE + id as u32
}

/// Remove `pages` pages at `va` from the user page table rooted at `root` and
/// shoot the range down on every hart that may hold it. Frees no frame.
/// Called with `LEASES` held (never from an interrupt), so it must not block
/// and must take no lock that is held while `LEASES` is being taken. The kernel registers
/// `vmm::unmap_user_range_and_free(root, va, end, va, end)` (the skip range is
/// the whole range, so nothing is freed and `page_decref` is never reached).
pub type UnmapHook = fn(root: usize, va: usize, pages: usize);

static UNMAP_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Register the [`UnmapHook`]. Boot, once. Without it a revoke records the
/// window but removes no PTE (the host suite's default).
pub fn set_unmap_hook(f: UnmapHook) {
    UNMAP_HOOK.store(f as usize, Ordering::Release);
}

fn call_unmap(root: usize, va: usize, pages: usize) {
    let raw = UNMAP_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `set_unmap_hook` stores here, and it stores an `UnmapHook`.
        let f: UnmapHook = unsafe { core::mem::transmute::<usize, UnmapHook>(raw) };
        f(root, va, pages);
    }
}

/// Set (`write == false`) or give back (`write == true`) the write permission
/// of the user leaves in `pages` pages at `va` of the page table rooted at
/// `root`, then shoot the range down on every hart that may hold it. Returns
/// how many leaves changed. Called with `LEASES` held, never from an
/// interrupt, under the same rules as [`UnmapHook`]. The kernel registers
/// `vmm::set_user_range_write` plus the shootdown.
pub type SealHook = fn(root: usize, va: usize, pages: usize, write: bool) -> usize;

static SEAL_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Register the [`SealHook`]. Boot, once. Without it a sealed grant records
/// the seal but changes no PTE (the host suite's default).
pub fn set_seal_hook(f: SealHook) {
    SEAL_HOOK.store(f as usize, Ordering::Release);
}

fn call_seal(root: usize, va: usize, pages: usize, write: bool) -> usize {
    let raw = SEAL_HOOK.load(Ordering::Acquire);
    if raw == 0 {
        // No PTE to change: report the whole range, so the record (and a
        // host test of it) is exercised as the kernel's would be.
        return pages;
    }
    // SAFETY: only `set_seal_hook` stores here, and it stores a `SealHook`.
    let f: SealHook = unsafe { core::mem::transmute::<usize, SealHook>(raw) };
    f(root, va, pages, write)
}

/// Lessor writes that faulted on a sealed lease (`SYS_EXIT_STATS` selector
/// `EXIT_STAT_LEASE_SEAL_FAULTS`).
static SEAL_FAULTS: AtomicU64 = AtomicU64::new(0);

/// User faults attributed to a revoked lease mapping (`SYS_EXIT_STATS`
/// selector `EXIT_STAT_LEASE_REVOKED_FAULTS`).
static REVOKED_FAULTS: AtomicU64 = AtomicU64::new(0);

/// Revokes that found the revoked-window table full (see [`REVOKED_ROWS`]).
pub static REVOKED_UNRECORDED: AtomicU64 = AtomicU64::new(0);

/// State of one [`AcceptWaiter`] slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WaiterState {
    Free,
    /// Registered by [`lease_accept_begin`]; the lessor has not exited since.
    Waiting,
    /// [`lease_release_all`] ran for the lessor while this wait was registered.
    LessorGone,
}

/// One registered `SYS_IPC_LEASE_ACCEPT` wait: `lessee` waits for a lease
/// from `lessor`.
///
/// **WHY a registry (owner decision 2026-09-14).** A wake alone cannot end an
/// accept whose lessor exited. The woken lessee polls, finds nothing, and its
/// next turn blocks on `LeaseAccept(lessee, lessor)` again, a reason no later
/// wake matches: TIDs are not reused, so no later grant names that lessor. A
/// broadcast wake of `LeaseAccept(_, lessor)` from the exit sweep was
/// considered and withdrawn for that reason. The registry gives the sweep
/// something to mark, so the woken lessee's next poll reads
/// [`LeaseAcceptPoll::LessorGone`] and the accept answers at once.
///
/// **Bound: `MAX_TASKS` slots, one per lessee TID.** A registration exists
/// only while its lessee is inside [`lease_accept_wait`]: the wait removes it
/// on its way out, and [`lease_release_all`] removes it when the lessee
/// exits (the exit hook runs before the task is marked `Zombie`). A task has
/// one syscall in flight, so the other registrations belong to at most
/// `MAX_TASKS - 1` other live tasks and a new one always finds a slot while
/// the task pool holds `MAX_TASKS`. [`LeaseAcceptBegin::NoRoom`] is answered
/// anyway, before any block, so a wait is never left unregistered.
#[derive(Clone, Copy)]
struct AcceptWaiter {
    lessee: u32,
    lessor: u32,
    state:  WaiterState,
}

impl AcceptWaiter {
    const FREE: AcceptWaiter = AcceptWaiter {
        lessee: NO_TID,
        lessor: NO_TID,
        state:  WaiterState::Free,
    };
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

struct LeaseTable {
    entries: [LeaseEntry; MAX_LEASES],
    /// Registered accept waits ([`AcceptWaiter`]). Under the same lock as
    /// `entries` on purpose: an accept's poll and its registration are one
    /// hold, and so is the exit sweep's "free the lessor's leases, mark its
    /// waiters". `lease_tick` never reads this field, so the ISR path is
    /// unchanged.
    waiters: [AcceptWaiter; MAX_TASKS],
    /// Lease mappings removed and not yet reaped by their lessee ([`Revoked`]).
    revoked: [Revoked; REVOKED_ROWS],
}

impl LeaseTable {
    const fn new() -> Self {
        const E: LeaseEntry = LeaseEntry::empty();
        const W: AcceptWaiter = AcceptWaiter::FREE;
        LeaseTable {
            entries: [E; MAX_LEASES],
            waiters: [W; MAX_TASKS],
            revoked: [Revoked::FREE; REVOKED_ROWS],
        }
    }

    /// Remove entry `id`'s lease mapping from the lessee's page table, shoot
    /// it down, and remember the window for the lessee. With `LEASES` held
    /// (the caller holds `self` through it) — the page-table-lifetime
    /// invariant. A no-op when the entry has no PTEs. The region reference
    /// stays booked ([`LeaseMap::ref_held`]); see [`take_map_ref`].
    fn revoke_map(&mut self, id: usize) {
        let m = self.entries[id].map;
        if m.root == 0 {
            return;
        }
        call_unmap(m.root, m.va, m.pages);
        self.entries[id].map.root = 0;
        let tid = self.entries[id].lessee_tid;
        match self.revoked.iter().position(|r| r.tid == NO_TID) {
            Some(i) => self.revoked[i] = Revoked { tid, lease: id as u32, va: m.va, pages: m.pages },
            None => {
                REVOKED_UNRECORDED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Give entry `id`'s lessor its write permission back, if the seal took
    /// it: the lease is over (returned, expired, freed, or its lessee died).
    /// With `LEASES` held — the page-table-lifetime invariant covers the
    /// lessor's root as it covers the lessee's. Idempotent.
    fn unseal(&mut self, id: usize) {
        let m = self.entries[id].seal;
        if m.root == 0 {
            return;
        }
        let _ = call_seal(m.root, m.va, m.pages, true);
        self.entries[id].seal = SealMap::NONE;
    }

    /// Take the first pending lease from `lessor` to `lessee`
    /// (`Pending → Active`): `(lease_id, shm_id)`.
    fn take_pending(&mut self, lessee: u32, lessor: u32) -> Option<(usize, usize)> {
        let idx = self.find_pending(lessee, lessor)?;
        let shm_id = self.entries[idx].shm_id;
        self.entries[idx].state = LeaseState::Active;
        // Pending → Active cannot change the count (both are counted), but the
        // invariant is "every writer of `state` refreshes", and an invariant
        // with an exception is an invariant nobody can check by inspection.
        refresh_deadline_count(self);
        Some((idx, shm_id))
    }

    /// The registry slot holding `lessee`'s wait, if it has one.
    fn waiter_of(&self, lessee: u32) -> Option<usize> {
        self.waiters
            .iter()
            .position(|w| w.state != WaiterState::Free && w.lessee == lessee)
    }

    fn alloc(&mut self, shm_id: usize, lessor: u32, lessee: u32, expire: u64) -> Option<usize> {
        for (i, e) in self.entries.iter_mut().enumerate() {
            if e.state == LeaseState::Free {
                *e = LeaseEntry { shm_id, lessor_tid: lessor, lessee_tid: lessee,
                                  expire_ticks: expire, state: LeaseState::Pending,
                                  shm_ref: 0, writable: false, map: LeaseMap::NONE,
                                  sealed: false, seal: SealMap::NONE };
                return Some(i);
            }
        }
        None
    }

    /// The first pending lease from `lessor` to `lessee`. Both TIDs must
    /// match: a lease another lessor granted to the same lessee is not this
    /// accept's to take.
    fn find_pending(&self, lessee: u32, lessor: u32) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.state == LeaseState::Pending && e.lessee_tid == lessee && e.lessor_tid == lessor
        })
    }

    /// Entries `lessor` occupies: every non-`Free` entry naming it, whatever
    /// its state. The count [`MAX_LEASES_PER_LESSOR`] bounds.
    fn occupancy_for_lessor(&self, lessor: u32) -> usize {
        let mut n = 0usize;
        for e in self.entries.iter() {
            if e.lessor_tid == lessor && e.state != LeaseState::Free {
                n += 1;
            }
        }
        n
    }
}


/// Take entry `e`'s booked mapping reference if its PTEs are gone: the packed
/// region reference to give back with `shm_release_ref(lease_holder_tid(id),
/// r)` once `LEASES` is released.
fn take_map_ref(e: &mut LeaseEntry) -> Option<u32> {
    if e.map.root == 0 && e.map.ref_held {
        e.map.ref_held = false;
        Some(e.shm_ref)
    } else {
        None
    }
}

/// Give back a lease mapping's region reference. Never with `LEASES` held
/// (the shm table lock is not nested inside it), never from an interrupt
/// (the last reference frees frames).
fn release_map_ref(id: usize, r: u32) {
    let _ = crate::shm::shm_release_ref(lease_holder_tid(id), r);
}

/// Batches of [`release_refs_where`].
const REF_BATCH: usize = 8;

/// Give back every booked mapping reference of an entry `pick` selects, in
/// batches of [`REF_BATCH`] taken under one `LEASES` hold each and released
/// after it. `pick(id, entry)` runs with the lock held, only on entries whose
/// reference is still booked; it may change the entry (clear `map.root` for
/// an address space that is going away, free the entry) and answers whether
/// to take the reference. It must leave `map.root == 0` on what it picks.
fn release_refs_where(mut pick: impl FnMut(usize, &mut LeaseEntry) -> bool) {
    loop {
        let mut out = [(0usize, 0u32); REF_BATCH];
        let mut n = 0usize;
        {
            let mut table = LEASES.lock_irqsave();
            for (i, e) in table.entries.iter_mut().enumerate() {
                if n == REF_BATCH {
                    break;
                }
                if !e.map.ref_held {
                    continue;
                }
                let r = e.shm_ref;
                if pick(i, e) {
                    debug_assert!(e.map.root == 0);
                    e.map.ref_held = false;
                    out[n] = (i, r);
                    n += 1;
                }
            }
            refresh_deadline_count(&table);
        }
        for &(i, r) in &out[..n] {
            release_map_ref(i, r);
        }
        if n < REF_BATCH {
            return;
        }
    }
}

// IRQ-safe: `lease_tick()` runs from the timer ISR (kernel `handle_interrupt`),
// while every other accessor runs in task/syscall context on the same hart with
// interrupts enabled. A plain `lock()` in task context would let a timer tick
// re-enter `lease_tick()` → `lock()` → same-hart deadlock. Every accessor below
// therefore uses `lock_irqsave()`, never plain `lock()` (see `crates/core/ipc/port.rs`
// for the same pattern).
static LEASES: SpinLock<LeaseTable> = SpinLock::new(LeaseTable::new());

/// Number of table entries `lease_tick` could possibly act on: state is
/// `Pending | Active` **and** `expire_ticks != 0`.
///
/// **WHY (audit: "the common case pays 157 instructions to do nothing").**
/// `lease_tick` runs inside the timer ISR. On this robot the normal table
/// state is "no lease with a deadline", and the old shape paid the full
/// 157-instruction cost anyway: 61 fixed (of which 32 were the unconditional
/// stores that materialise the 256-byte return array) plus 16 loop iterations
/// that all fall through. This counter is what makes an early exit possible
/// *before* the lock and before any buffer exists.
///
/// Measured on the RV64 artifact, common case, callee + caller drain loop:
/// **242 → 32 instructions** (157 + 85 before, 6 + 26 after). The 157 figure
/// was re-derived here from a byte-for-byte copy of the old body compiled in
/// the same invocation as the new one, not taken from the audit on trust —
/// it came out identical.
static DEADLINE_LEASES: AtomicUsize = AtomicUsize::new(0);

/// Is this entry in the set [`DEADLINE_LEASES`] counts?
#[inline]
fn has_deadline(e: &LeaseEntry) -> bool {
    matches!(e.state, LeaseState::Pending | LeaseState::Active) && e.expire_ticks != 0
}

/// Recompute [`DEADLINE_LEASES`] from the table. **Call at the end of every
/// operation that writes `state` or `expire_ticks`, with the lock still
/// held.**
///
/// **WHY a full recount rather than incremental +1/−1 deltas.** Six call
/// sites mutate lease state (`lease_grant`, `lease_accept`, `lease_return`,
/// `lease_free`, `lease_release_all`, `lease_tick`), some of them with two
/// branches. A single missed decrement costs only wasted ISR work, but a
/// single missed *increment* means a lease with a deadline that the ISR never
/// looks at again — `lease_wait_return` sleeps forever on the exact bound
/// `expire_ticks` exists to provide. Exactness by construction is worth more
/// than the arithmetic: every one of those sites is cold (a grant, a return,
/// a task exit — each already ending in a cross-task wake that costs
/// thousands of nanoseconds), and this is 16 iterations under a lock the
/// caller already holds. Nothing is added to the ISR path.
#[inline]
fn refresh_deadline_count(table: &LeaseTable) {
    let mut n = 0usize;
    for e in table.entries.iter() {
        // `wrapping_add` and not `+`: the kernel builds with
        // `overflow-checks = true`, and a plain increment makes rustc emit a
        // branch to `panic::add_overflow` that `lease_tick` would carry
        // *inside the timer ISR* (verified on the RV64 artifact). `n` is
        // bounded by `MAX_LEASES`, so the two are equivalent here.
        if has_deadline(e) { n = n.wrapping_add(1); }
    }
    // `Release` pairs with nothing in particular — correctness comes from
    // `LEASES`, which every reader of the table takes. See `lease_tick` for
    // why the load side is `Relaxed`.
    DEADLINE_LEASES.store(n, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Grant a lease of `shm_id` to `lessee_tid`, taking the caller's privilege
/// from the scheduler: [`lease_grant_as`] with `privileged` set for a kernel
/// task (`current_user_pt() == 0`).
///
/// For in-kernel callers, such as the lease bench in `kernel/src/smokes/i3_probe.rs`.
/// `SYS_IPC_LEASE_GRANT_TYPED` calls [`lease_grant_as`] and decides the
/// privilege in its handler, as the `LEASE_RETURN` and `LEASE_FREE` handlers do.
pub fn lease_grant(shm_id: usize, lessor_tid: u32, lessee_tid: u32, expire_ticks: u64) -> Option<usize> {
    let privileged = azos_sched::current_user_pt() == 0;
    lease_grant_as(shm_id, lessor_tid, lessee_tid, expire_ticks, privileged).ok()
}

/// Grant a lease of `shm_id` from `lessor_tid` to `lessee_tid`.
///
/// `expire_ticks`: absolute CLINT tick at which the lease auto-expires (0 = never).
/// Returns `Ok(lease_id)`, or the reason for the refusal:
/// [`LeaseGrantError::NotOwner`], [`LeaseGrantError::Quota`] or
/// [`LeaseGrantError::NoSlot`].
///
/// **Quota: at most [`MAX_LEASES_PER_LESSOR`] occupied entries per ring-3
/// lessor** (every non-`Free` entry naming it: `Pending`, `Active`, `Returned`
/// and `Expired`). Counted in the same `LEASES` hold that allocates the slot, so two
/// grants from one lessor on two harts cannot both pass the count and both
/// allocate (the rule `port_create` and `shm_create` follow). A `privileged`
/// grant is neither checked nor refused by it; see the constant for why.
///
/// **Wakes the lessee, and only an accept waiting for this lessor.** After the
/// lock is dropped, a successful grant calls
/// `azos_sched::wait::wake_lease_acceptor(lessee_tid, lessor_tid)`: a task
/// blocked on `WaitReason::LeaseAccept(lessee_tid, lessor_tid)` is dispatched,
/// one blocked on anything else (a fast-IPC server wait on the same TID, or an
/// accept naming another lessor) is left asleep and unmarked, and a lessee
/// that has not blocked yet is stamped `wake_pending`, so a grant that lands
/// between its `lease_accept` poll and its `task_block` is not lost. The wake
/// is here rather than in the syscall arm so the host suite asserts it.
///
/// **Authority: the lessor must hold a live `Cap<Shm>` naming the region.**
/// Unless `privileged` (a kernel caller),
/// the lessor's own capability table must hold a `Cap<Shm>` with `READ` whose
/// stored reference is the region's current `(index, generation)`
/// (`shm_ref`), so a capability to a freed or reissued region does not count.
/// One capability authority (RFC-0040 gap 1, stage 2): the owner stamp this
/// replaced is a second record of the same fact. `Cap<Shm>` is minted only into
/// the creating task (`shm_create_cap`), so the holders are the creators;
/// a region created without a capability cannot be leased from ring 3.
///
/// `READ`, not `WRITE`: `shm_create_cap` mints `READ` for a read-only region
/// and `READ | WRITE` otherwise, and a read-only region was leasable under the
/// owner stamp. A plain accept hands out no access; an accept with
/// `SYS_IPC_LEASE_ACCEPT_MAP` maps the region into the lessee for the life of the
/// lease, WRITABLE only if the region is read-write and the lessor's
/// capability held `WRITE` here ([`LeaseEntry::writable`]): a lease never
/// hands out more than its lessor had.
///
/// The grant syscall (111 took a raw `a0`; 603, since 2026-09-28, the index its
/// `Cap<Shm>` resolves to) passes `shm_id` and its own caller as
/// `lessor_tid`, so without this a task could advertise a lease over another
/// task's region, wake the named lessee with it, and spend a slot of this
/// table on it. The check is here rather than in the dispatch arm so that
/// every caller goes through it, the host suite included.
///
/// `shm_id` arrives as a `usize` and region ids are `u32`: an id that does not
/// fit is refused rather than truncated, so `0x1_0000_0000` cannot stand for
/// region 0.
///
/// **No lock is nested, and it is not one hold.** `shm_ref` takes and drops
/// `SHM_REGIONS`; the lessor's table lock is taken after it and dropped before
/// `LEASES` (the capability table's lock is never held with a pool lock taken
/// inside it here). In between, the region can be released and its index
/// reissued; the capability then names the old generation, so the check
/// answers for the region that was live when `shm_ref` read it. The same holds
/// for any lease after it is granted, because a region's teardown does not
/// touch this table. Neither case grants access: nothing that maps or reads a
/// region consults this table.
///
/// `privileged` is a parameter, as in [`lease_return`] and [`lease_free`], so
/// the decision is made once at the syscall boundary and the host suites do
/// not depend on the scheduler shim's current task.
pub fn lease_grant_as(
    shm_id: usize,
    lessor_tid: u32,
    lessee_tid: u32,
    expire_ticks: u64,
    privileged: bool,
) -> Result<usize, LeaseGrantError> {
    lease_grant_sealed_as(shm_id, lessor_tid, lessee_tid, expire_ticks, privileged, None)
}

/// [`lease_grant_as`], with the producer-side write seal when `seal` is
/// `Some` (wave 11, LEASE3; `LEASE_GRANT_SEAL`). `seal` names the lessor's
/// own mapping of the region (`root`, `va`, `pages`; `SealMap::NONE` when it
/// has none): in the `LEASES` hold that allocates the entry, before the
/// lessee is woken, the [`SealHook`] makes those leaves read-only and shoots
/// them down, and the entry remembers what it changed. Every end of the lease
/// gives the write back the same way (return, expiry — the lease worker's
/// reap or the lessor's wake —, free, the lessee's exit); the lessor's own
/// exit or exec only forgets it, its address space going with it. A mapping
/// that was read-only already is recorded as nothing to restore.
///
/// The caller passes `root` = the lessor's live page-table root (the lessor is
/// the calling task) and the mapping its shm record names.
pub fn lease_grant_sealed_as(
    shm_id: usize,
    lessor_tid: u32,
    lessee_tid: u32,
    expire_ticks: u64,
    privileged: bool,
    seal: Option<SealMap>,
) -> Result<usize, LeaseGrantError> {
    // The packed reference first, under `SHM_REGIONS` alone; then the
    // lessor's table, under its own lock alone. Recorded in the entry, so an
    // accept-and-map maps the region granted, never a later one at its index.
    let live = u32::try_from(shm_id).ok().and_then(crate::shm::shm_ref);
    let region_rw = live.is_some_and(|r| {
        matches!(crate::shm::shm_perms_ref(r), Ok(crate::shm::ShmPerms::ReadWrite))
    });
    let writable = if !privileged {
        let perms = live.and_then(|r| {
            crate::cap_store::with_table(lessor_tid, |t| {
                use azos_abi::cap::CapKind;
                use crate::cap::CapPerms;
                (
                    t.holds_packed_ref(CapKind::Shm, r, CapPerms::READ),
                    t.holds_packed_ref(CapKind::Shm, r, CapPerms::WRITE),
                )
            })
        });
        match perms {
            Some((true, w)) => region_rw && w,
            _ => return Err(LeaseGrantError::NotOwner),
        }
    } else {
        region_rw
    };
    let id = {
        let mut table = LEASES.lock_irqsave();
        if !privileged && table.occupancy_for_lessor(lessor_tid) >= MAX_LEASES_PER_LESSOR {
            // Nothing was written, so the deadline count is still exact.
            return Err(LeaseGrantError::Quota);
        }
        let id = table.alloc(shm_id, lessor_tid, lessee_tid, expire_ticks);
        if let Some(i) = id {
            table.entries[i].shm_ref = live.unwrap_or(0);
            table.entries[i].writable = writable;
            if let Some(m) = seal {
                table.entries[i].sealed = true;
                if m.root != 0 && m.pages != 0 && call_seal(m.root, m.va, m.pages, false) != 0 {
                    table.entries[i].seal = m;
                }
            }
        }
        // A grant is the only way a deadline enters the table, so skipping this
        // is the one mistake that would make `lease_tick`'s early exit unsound.
        refresh_deadline_count(&table);
        id.ok_or(LeaseGrantError::NoSlot)?
    }; // guard dropped — never wake while holding LEASES.
    azos_sched::wait::wake_lease_acceptor(lessee_tid, lessor_tid);
    Ok(id)
}

/// Lessee accepts a pending lease from `lessor_tid`, and from no other lessor.
///
/// Returns `Some((lease_id, shm_id))` if a lease from `lessor_tid` to
/// `lessee_tid` is pending, and `None` otherwise. A lease another lessor
/// granted to the same lessee stays `Pending`, for an accept that names that
/// lessor. There is no wildcard (owner decision 2026-09-14).
///
/// A plain poll: it registers nothing, so a caller that blocks after a `None`
/// from here is invisible to [`lease_release_all`] and sleeps for good if its
/// lessor exits. A caller that waits uses [`lease_accept_wait`]. The i3 lease
/// probe in `kernel/src/smokes/i3_probe.rs` polls this and yields; it never blocks.
pub fn lease_accept(lessee_tid: u32, lessor_tid: u32) -> Option<(usize, usize)> {
    LEASES.lock_irqsave().take_pending(lessee_tid, lessor_tid)
}

/// The first poll of an accept that may wait: take a pending lease from
/// `lessor_tid`, or register the wait, in **one** `LEASES` hold.
///
/// **Why one hold.** [`lease_release_all`] frees a dying lessor's leases and
/// marks the registrations naming it under the same lock. With the poll and
/// the registration in one hold, an exit of `lessor_tid` either runs before
/// it (the poll then sees the table after the exit) or after it (the exit
/// sees this registration, marks it and wakes the lessee). Split in two
/// holds, a grant and the lessor's exit could both land between them: the
/// poll missed the lease, the exit missed the registration, and the lessee
/// would block for good on a lessor that was alive when it polled.
///
/// A registration already held by `lessee_tid` is overwritten, not
/// duplicated (one per lessee TID; see [`AcceptWaiter`] for the bound).
/// [`LeaseAcceptBegin::Got`] registers nothing.
pub fn lease_accept_begin(lessee_tid: u32, lessor_tid: u32) -> LeaseAcceptBegin {
    let mut table = LEASES.lock_irqsave();
    if let Some((lease_id, shm_id)) = table.take_pending(lessee_tid, lessor_tid) {
        return LeaseAcceptBegin::Got(lease_id, shm_id);
    }
    let slot = match table.waiter_of(lessee_tid) {
        Some(i) => Some(i),
        None => table.waiters.iter().position(|w| w.state == WaiterState::Free),
    };
    match slot {
        Some(i) => {
            table.waiters[i] = AcceptWaiter {
                lessee: lessee_tid,
                lessor: lessor_tid,
                state:  WaiterState::Waiting,
            };
            LeaseAcceptBegin::Registered
        }
        None => LeaseAcceptBegin::NoRoom,
    }
}

/// Poll a registered accept again after its block returned, in one `LEASES`
/// hold.
///
/// Order: a lessor that exited ends the wait ([`LeaseAcceptPoll::LessorGone`])
/// before the table is searched, so a lease a kernel caller grants in the
/// name of a TID that has already exited is not taken; then a pending lease
/// ([`LeaseAcceptPoll::Got`]); then [`LeaseAcceptPoll::StillWaiting`]. A
/// registration naming another lessor does not cover this wait
/// ([`LeaseAcceptPoll::NotRegistered`]).
///
/// `LessorGone` and `Got` drop the registration in the same hold: once the
/// accept has its answer, a later exit of the lessor finds nothing to mark
/// and leaves no `wake_pending` stamp on a task that is no longer waiting.
pub fn lease_accept_poll(lessee_tid: u32, lessor_tid: u32) -> LeaseAcceptPoll {
    let mut table = LEASES.lock_irqsave();
    let slot = match table.waiter_of(lessee_tid) {
        Some(i) if table.waiters[i].lessor == lessor_tid => Some(i),
        _ => None,
    };
    if let Some(i) = slot {
        if table.waiters[i].state == WaiterState::LessorGone {
            table.waiters[i] = AcceptWaiter::FREE;
            return LeaseAcceptPoll::LessorGone;
        }
    }
    if let Some((lease_id, shm_id)) = table.take_pending(lessee_tid, lessor_tid) {
        if let Some(i) = slot {
            table.waiters[i] = AcceptWaiter::FREE;
        }
        return LeaseAcceptPoll::Got(lease_id, shm_id);
    }
    match slot {
        Some(_) => LeaseAcceptPoll::StillWaiting,
        None => LeaseAcceptPoll::NotRegistered,
    }
}

/// Drop `lessee_tid`'s registration, whatever lessor it names. Idempotent.
pub fn lease_accept_cancel(lessee_tid: u32) {
    let mut table = LEASES.lock_irqsave();
    if let Some(i) = table.waiter_of(lessee_tid) {
        table.waiters[i] = AcceptWaiter::FREE;
    }
}

/// `SYS_IPC_LEASE_ACCEPT`'s wait: take a lease from `lessor_tid`, blocking
/// through `block` until one arrives, the lessor exits, or
/// [`LEASE_ACCEPT_TURNS`] wakes pass.
///
/// `block` is the syscall arm's
/// `task_block(WaitReason::LeaseAccept(lessee_tid, lessor_tid))`, the reason
/// [`lease_grant_as`] and [`lease_release_all`] wake through
/// `wait::wake_lease_acceptor`. It is a parameter so the host suite drives
/// this loop itself. It is called with no lock held.
///
///  1. [`lease_accept_begin`]: a pending lease is returned at once; no room
///     is [`LeaseAcceptError::RegistryFull`] before any block.
///  2. Up to [`LEASE_ACCEPT_TURNS`] times: `block()`, then
///     [`lease_accept_poll`]. `StillWaiting` goes round; `Got`, `LessorGone`
///     and `NotRegistered` end the wait.
///  3. [`lease_accept_cancel`], once, on the single way out after a
///     registration, whatever the answer.
///
/// **Why the lessor's exit ends the wait at once.** [`lease_release_all`]
/// marks the registration before it wakes, and the wake is TID-directed: a
/// lessee blocked on the reason is dispatched, and one between its poll and
/// its block is stamped, so that block returns at once. Either way the next
/// poll reads `LessorGone`.
///
/// Properties kept from the arm's earlier loop (owner decisions 2026-09-14):
///
///  * **A grant from another lessor can cost a turn.** A grant stamps a
///    lessee that has not committed to `Blocked` yet whatever lessor its
///    accept names (the stamp consults no predicate), so a grant from B that
///    lands between an accept-from-A's poll and its block is consumed by that
///    block, and the loop goes round. Bounded by that window and by the turns;
///    no lease is lost to it.
///  * **`a0 > u32::MAX` is refused with -1** by the arm, before this function,
///    rather than truncated onto a TID.
///
/// **Not covered: a lessor that exited before step 1.** Its exit ran before
/// the registration existed, so nothing marks or wakes this wait, and it
/// sleeps until the lessee itself exits, as an accept naming a TID that never
/// grants does. The first poll cannot tell such a TID from a live lessor that
/// has not granted yet: the exit hook runs before the task is marked `Zombie`
/// and its pool slot stays valid until `do_schedule` frees it, so a liveness
/// lookup answers "alive" in part of that window, and it cannot be made under
/// `LEASES` without nesting the scheduler's pool inside it.
pub fn lease_accept_wait(
    lessee_tid: u32,
    lessor_tid: u32,
    mut block: impl FnMut(),
) -> Result<(usize, usize), LeaseAcceptError> {
    match lease_accept_begin(lessee_tid, lessor_tid) {
        LeaseAcceptBegin::Got(lease_id, shm_id) => return Ok((lease_id, shm_id)),
        LeaseAcceptBegin::NoRoom => return Err(LeaseAcceptError::RegistryFull),
        LeaseAcceptBegin::Registered => {}
    }
    let mut result = Err(LeaseAcceptError::TurnsExhausted);
    for _ in 0..LEASE_ACCEPT_TURNS {
        block();
        match lease_accept_poll(lessee_tid, lessor_tid) {
            LeaseAcceptPoll::StillWaiting => {}
            LeaseAcceptPoll::Got(lease_id, shm_id) => {
                result = Ok((lease_id, shm_id));
                break;
            }
            LeaseAcceptPoll::LessorGone => {
                result = Err(LeaseAcceptError::LessorGone);
                break;
            }
            LeaseAcceptPoll::NotRegistered => {
                result = Err(LeaseAcceptError::NotRegistered);
                break;
            }
        }
    }
    // Every answer after a registration leaves through here, so none of them
    // can leave a slot behind. A no-op after `Got` and `LessorGone`, which
    // dropped the registration in their own hold.
    lease_accept_cancel(lessee_tid);
    result
}

/// Lessee returns the lease.  Wakes the lessor.
///
/// `caller_tid` is the TID of the task asking for the return; `privileged` is
/// `true` for kernel callers (`current_user_pt() == 0`), which bypass the
/// ownership check — the same convention as `cap_store`'s typed callers.
///
/// Returns `Some(lessor_tid)`, already woken here through `wq_wake_by_tid`,
/// or `None` if the lease_id is invalid, not Active, or does not belong to
/// `caller_tid`.
///
/// **WHY the ownership check exists (IPC-6):** this used to take a bare
/// `lease_id` from `a0` of `SYS_IPC_LEASE_RETURN` and validate nothing but
/// `< MAX_LEASES` — and `MAX_LEASES` is 16, small and dense, so there is
/// nothing to guess. Any ring-3 task could therefore "return" a lease
/// belonging to two *other* tasks. That is not a nuisance: the lessor is
/// woken believing the buffer is back and resumes writing it, while the
/// legitimate lessee still has the very same SHM pages mapped and is still
/// reading them. A ring-3-triggerable data race on shared memory, on the path
/// this kernel uses to hand camera frames and sensor buffers around. Only the
/// **lessee** may return: it is the party that holds the buffer, and the
/// return is the act of giving it back.
pub fn lease_return(lease_id: usize, caller_tid: u32, privileged: bool) -> Option<u32> {
    if lease_id >= MAX_LEASES { return None; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let lease_id = azos_limits::nospec::array_index_nospec(lease_id, MAX_LEASES);
    let (lessor, map_ref) = {
        let mut table = LEASES.lock_irqsave();
        let e = &mut table.entries[lease_id];
        if e.state != LeaseState::Active { return None; }
        // Two integer comparisons inside a lock we already hold: ~2 ns against
        // a measured 1879 ns/op syscall floor, and this is the *slow* half of
        // the lease path (it ends with a cross-task wake).
        if !privileged && e.lessee_tid != caller_tid { return None; }
        e.state = LeaseState::Returned;
        let lessor = e.lessor_tid;
        // Wave 11: the lease's mapping goes with the buffer — PTEs removed and
        // shot down before the lessor can be woken believing it has the
        // buffer back.
        table.revoke_map(lease_id);
        // Wave 11 (LEASE3): and a sealed lessor gets its write back.
        table.unseal(lease_id);
        let map_ref = take_map_ref(&mut table.entries[lease_id]);
        refresh_deadline_count(&table);
        (lessor, map_ref)
    };
    if let Some(r) = map_ref {
        release_map_ref(lease_id, r);
    }
    // Wake a lessor blocked in `lease_wait_return` (WaitQueue), the only wait a
    // lessor has. Released the lock first — never wake while holding it. A
    // lessor blocked on any other reason is left asleep and unmarked
    // (`wq_wake_by_tid` dispatches only `WaitReason::WaitQueue`); one that has
    // not blocked yet is stamped, so its `wq_block_current` returns at once.
    // This is the return's only wake: `SYS_IPC_LEASE_RETURN` adds none, and a
    // `wake_fast_ipc_server(lessor)` would dispatch a lessor blocked serving
    // fast IPC (owner decision 2026-09-14).
    if lessor != NO_TID {
        azos_sched::wq_wake_by_tid(lessor);
    }
    Some(lessor)
}

/// Lessor: block until the lessee returns the lease (or it expires), applying
/// **lease priority inheritance** (RFC-0031; on by default since owner
/// decision round 17).
///
/// While the (typically high-priority) lessor is blocked on a lease held by a
/// lower-priority lessee, the lessee inherits the lessor's priority — and is
/// re-positioned in the ready queue (`boost_ready_task`, since the legacy
/// bitmap scheduler buckets by priority at enqueue time) — so it is scheduled
/// ahead of mid-priority work and can return the buffer promptly instead of
/// being starved (unbounded inversion for a non-expiring lease). The boost is
/// undone on wake (return, exit, or expiry).
///
/// Gated by `azos_limits::LEASE_PRIORITY_INHERITANCE` (const-eliminated
/// when off → a plain block-until-returned loop). Wakeups come via
/// `wq_wake_by_tid(lessor)` from `lease_return` callers and the expiry path.
///
/// Must NOT be called holding any lock (it blocks).
///
/// **Authorization (IPC-6, same class as `lease_return` / `lease_free`):**
/// only the **lessor** of `lease_id` may wait on it. Waiting on a stranger's
/// lease donates *this* task's priority to that lease's lessee
/// (`donate_priority`) — an unauthenticated priority boost of an arbitrary
/// task — and parks the caller on a wake it has no claim to. Kernel callers
/// (the lease bench in `kernel/src/smokes/i3_probe.rs`) come through here; ring 3 comes
/// through `SYS_IPC_LEASE_WAIT` and [`lease_wait_return_as`], which takes the
/// caller explicitly after the `Cap<Lease>` check.
pub fn lease_wait_return(lease_id: usize) {
    let privileged = azos_sched::current_user_pt() == 0;
    let me = azos_sched::current_task_tid();
    let _ = lease_wait_return_as(lease_id, me, privileged);
}

/// How [`lease_wait_return_as`] ended.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeaseWaitEnd {
    /// The lessee returned the buffer.
    Returned,
    /// The lease expired (or its lessee exited) before a return.
    Expired,
    /// Nothing to wait on: out of range, or the slot is `Free`.
    NoLease,
    /// `caller` is not the lease's lessor (and is not privileged).
    NotLessor,
}

/// [`lease_wait_return`] with the caller named: the body `SYS_IPC_LEASE_WAIT`
/// runs after it has checked the `Cap<Lease>`. The lessor check is repeated
/// here, against the table, because the capability names a lease id and the
/// id could in principle name a later lease (it cannot today: `lease_free`
/// revokes the capability before the id is reissued).
///
/// Blocks until the lease is `Returned` or `Expired`, donating `caller`'s
/// priority to the lessee for the span of the wait (RFC-0031, the shared
/// `donate_priority` rule — including the wave-9 ring-3 floor).
pub fn lease_wait_return_as(lease_id: usize, caller: u32, privileged: bool) -> LeaseWaitEnd {
    if lease_id >= MAX_LEASES {
        return LeaseWaitEnd::NoLease;
    }
    let lease_id = azos_limits::nospec::array_index_nospec(lease_id, MAX_LEASES);
    let me = caller;
    // Snapshot the lessee under the lock, then release before blocking. Wait
    // for any in-flight lease (Pending = granted-not-yet-accepted, or Active);
    // only short-circuit if it is already finished or the slot is free.
    let lessee = {
        let table = LEASES.lock_irqsave();
        let e = &table.entries[lease_id];
        if e.state == LeaseState::Free {
            return LeaseWaitEnd::NoLease;
        }
        if !privileged && e.lessor_tid != me {
            return LeaseWaitEnd::NotLessor;
        }
        match e.state {
            LeaseState::Pending | LeaseState::Active => e.lessee_tid,
            LeaseState::Returned => return LeaseWaitEnd::Returned,
            _ => {
                drop(table);
                return lease_wait_expired(lease_id);
            }
        }
    };

    // Priority inheritance: boost the lessee to our priority if ours is higher
    // (lower number). We do NOT remember the lessee's observed priority to
    // restore later — that was the bug. Two lessors donating to the same lessee
    // each captured whatever they happened to observe, and since each blocks on
    // its own lease id and leases can be returned in any order, an out-of-LIFO
    // restore both dropped the lessee below a still-active donor and left it
    // boosted at a stale value forever. The scheduler now counts donations and
    // decides when the base priority comes back.
    //
    // The rule and the boost are `azos_sched::donate_priority`, shared
    // with the user-driver proxy (a kernel client waiting on a ring-3 driver's
    // reply): one rule (`crates/core/sched/src/donation.rs`), one counter, so a
    // lessee that is also a driver serving a client stacks both donations.
    let donated = azos_limits::LEASE_PRIORITY_INHERITANCE
        && lessee != NO_TID
        && azos_sched::donate_priority(me, lessee);

    // Block until the buffer is back (returned or expired). Woken by
    // wq_wake_by_tid from the returner / expiry path.
    while !lease_is_returned(lease_id) {
        azos_sched::wq_block_current();
    }

    // Undo the inherited boost. No-op if the lessee already exited. Must be
    // called exactly once per successful boost — the scheduler's donation
    // counter only returns the task to its base priority when it hits zero.
    if donated {
        azos_sched::return_donation(lessee);
    }
    let returned = LEASES.lock_irqsave().entries[lease_id].state == LeaseState::Returned;
    if returned { LeaseWaitEnd::Returned } else { lease_wait_expired(lease_id) }
}

/// A lessor's wait found its lease expired (or its lessee gone): remove the
/// lessee's lease mapping, if it still has one, and give its reference back.
/// Wave 11: an expiry is only marked in the timer interrupt, which edits no
/// page table (the PTE walk's kernel-table guard takes `KERNEL_PT`'s plain
/// lock, which a same-hart interrupt could deadlock on); the lessor's wake is
/// where the mapping goes. A lessor that never waits revokes at its free.
fn lease_wait_expired(lease_id: usize) -> LeaseWaitEnd {
    let map_ref = {
        let mut table = LEASES.lock_irqsave();
        if table.entries[lease_id].state == LeaseState::Expired {
            table.revoke_map(lease_id);
            table.unseal(lease_id);
        }
        take_map_ref(&mut table.entries[lease_id])
    };
    if let Some(r) = map_ref {
        release_map_ref(lease_id, r);
    }
    LeaseWaitEnd::Expired
}

/// Lessor checks if the lease has been returned.
///
/// Should be called after being woken from `WaitReason::Timer` or a dedicated
/// lease-wait reason.  Returns `true` if the buffer is safely reclaimed.
pub fn lease_is_returned(lease_id: usize) -> bool {
    if lease_id >= MAX_LEASES { return false; }
    let lease_id = azos_limits::nospec::array_index_nospec(lease_id, MAX_LEASES);
    let table = LEASES.lock_irqsave();
    matches!(table.entries[lease_id].state, LeaseState::Returned | LeaseState::Expired)
}

/// Free a lease entry (called by the lessor after reclaiming the buffer).
///
/// Returns `true` if the slot was freed, `false` if `lease_id` is out of
/// range, already free, or does not belong to `caller_tid`.
///
/// **WHY the ownership check exists (IPC-6):** `SYS_IPC_LEASE_FREE` passed
/// `a0` straight through and this function validated only `< MAX_LEASES`, so
/// any ring-3 task could destroy an in-progress SHM cession between two other
/// tasks — the lessor then blocks in `lease_wait_return` on a slot that has
/// gone `Free` (it returns early, so the lessor "reclaims" a buffer the
/// lessee is still using), and the id is immediately re-issued by
/// `lease_grant` to somebody else. Only the **lessor** may free: the entry is
/// the lessor's bookkeeping of its own buffer, and `lease_grant` is what
/// allocated it.
///
/// **WHY freeing an Active lease is still allowed:** the buffer belongs to
/// the lessor, `MAX_LEASES` is 16, and refusing would let a lessee that
/// simply never returns (grant with `expire_ticks == 0`) pin a slot for the
/// life of the board — a 16-deep table is trivially exhausted that way. The
/// recycled id is safe *because* of the ownership checks added here: the
/// abandoned lessee's stale `lease_id` no longer matches the new entry's
/// `lessee_tid`, so its `lease_return` is rejected instead of corrupting the
/// next pair of tasks. Remove either check and slot recycling becomes a
/// confused-deputy primitive again.
///
/// `privileged` (kernel, `current_user_pt() == 0`) bypasses the check, per
/// the house convention shared with `cap_store`'s typed callers.
pub fn lease_free(lease_id: usize, caller_tid: u32, privileged: bool) -> bool {
    if lease_id >= MAX_LEASES { return false; }
    let lease_id = azos_limits::nospec::array_index_nospec(lease_id, MAX_LEASES);
    let (lessor, map_ref) = {
        let mut table = LEASES.lock_irqsave();
        let e = &table.entries[lease_id];
        if e.state == LeaseState::Free { return false; }
        if !privileged && e.lessor_tid != caller_tid { return false; }
        let lessor = e.lessor_tid;
        // Wave 11: freeing an Active lease revokes the lessee's mapping (a
        // lessor-side revoke), as does freeing an expired one its lessor
        // never waited on (the timer interrupt only marked it).
        table.revoke_map(lease_id);
        table.unseal(lease_id);
        let map_ref = take_map_ref(&mut table.entries[lease_id]);
        table.entries[lease_id] = LeaseEntry::empty();
        refresh_deadline_count(&table);
        (lessor, map_ref)
    };
    if let Some(r) = map_ref {
        release_map_ref(lease_id, r);
    }
    // Wave 9: the lessor's `Cap<Lease>` names this id, and the id is free to
    // be reissued now. Revoked after `LEASES` is released — `lease_grant_as`
    // takes a cap table and `LEASES` one after the other, never nested, and
    // this keeps it that way.
    if lessor != NO_TID {
        let _ = crate::cap_store::with_table(lessor, |t| {
            t.revoke_kind_resource(azos_abi::cap::CapKind::Lease, lease_id as u32)
        });
    }
    true
}

/// Reclaim every lease `tid` participates in — task-exit hook (IPC-3).
///
/// **WHY this exists (IPC-3):** `LEASES` is a fixed 16-entry BSS table and
/// nothing reclaimed it. `task_release_all` called only `handle_revoke_all`,
/// `cap_store::reset` and `shm_release_all`, so every task that died holding
/// a lease burned a slot permanently; sixteen such deaths and `lease_grant`
/// returns `None` forever, with no diagnostic. Worse than the leak is the
/// blocked peer, which is why the two roles are treated differently:
///
///  * **The lessee dies** (this task held the buffer). The lessor may be
///    parked in `lease_wait_return`, which loops on `lease_is_returned` and
///    only exits for `Returned | Expired`. Nobody will ever return the
///    buffer, so the lessor sleeps forever — on a robot that is a control
///    task that stops actuating, not a hung shell. We mark the lease
///    `Expired` (**not** `Returned`: the buffer was never handed back, and
///    `Expired` is the state `lease_tick` already uses for exactly this
///    "the lessee did not give it back" outcome, so the lessor's post-wake
///    code cannot mistake an abandoned buffer for a clean handover) and wake
///    the lessor. The entry is deliberately **left allocated** so the lessor
///    frees it through the normal `lease_free` path, identical to the timer
///    expiry flow; if the lessor later dies too, the lessor branch below
///    reclaims the slot, so nothing leaks either way.
///  * **The lessor dies** (this task owns the buffer). Free the slot
///    outright. The lessee may still have the region mapped, but that is
///    governed by the SHM refcount (`shm_release_all` gives back the dead
///    lessor's reference; the region survives while the lessee holds one),
///    not by this table. Keeping the entry alive would buy nothing — there
///    is no lessor left to wake or to free it — and would leak the slot.
///
/// **Accept waits ([`AcceptWaiter`]), in the same hold, before the leases.**
///
///  * **`tid` is waiting in an accept itself:** its registration is dropped.
///    It is exiting, so nothing will poll it again, and a wake of a dying
///    task is no use. This comes first, so a self-accept (`lessee == lessor
///    == tid`) is dropped rather than marked and woken.
///  * **`tid` is the lessor another task's accept names:** the registration
///    is marked `LessorGone` and that lessee is woken with
///    `wait::wake_lease_acceptor(lessee, tid)`. Its next
///    [`lease_accept_poll`] reads `LessorGone`, so `SYS_IPC_LEASE_ACCEPT`
///    answers -1 at once instead of blocking again. Blocked, the lessee is
///    dispatched; between its poll and its block, it is stamped and that
///    block returns at once. This covers a lessee whose lease from `tid` was
///    still `Pending` (freed above): an accept that could take that lease is
///    registered naming `tid`. A lessee with a pending lease that is not in
///    an accept is not woken: nothing of its waits on this lessor, and a
///    stamp would make its next unrelated block return at once. (A wake
///    without the mark, for every accept naming `tid`, was considered and
///    withdrawn on 2026-09-14: the woken lessee re-polled, found nothing and
///    blocked again on a reason no later wake matches.)
///
/// A self-lease (`lessor == lessee == tid`) hits the lessor branch and is
/// freed; that is why the lessor test comes first.
///
/// **Wakes happen after the guard is dropped.** Lock order: `LEASES` is taken
/// and released, then each wake takes the scheduler's side; `LEASES` is never
/// held across a wake, which would invert the order against the scheduler's
/// task pool (`lease_return` documents the same rule). TIDs are buffered on
/// the stack first: lessors in `[u32; MAX_LEASES]` (one per lease entry),
/// acceptors in `[u32; MAX_TASKS]` (one per registry slot, not per lease: a
/// lessor that granted nothing can still be named by many accepts).
///
/// **The two roles get different wakes, on purpose.** A stranded *lessor* is
/// woken **only** through `wq_wake_by_tid`, as `lease_return` and the timer
/// expiry drain in `kernel/src/trap/interrupt.rs` wake it: `lease_wait_return`
/// (WaitQueue) is the only wait a lessor has, and no lease path blocks on
/// `WaitReason::FastIpcServer`. A `wake_fast_ipc_server(lessor)` here would
/// reach no lease waiter and would dispatch a lessor blocked serving fast IPC
/// (owner decision 2026-09-14). A registered *acceptor* is woken
/// **only** through `wait::wake_lease_acceptor(lessee, tid)`, because
/// `SYS_IPC_LEASE_ACCEPT` is its only wait path: it blocks on
/// `WaitReason::LeaseAccept(lessee, lessor)` and never uses the WaitQueue. The
/// wake names the dying lessor, so a lessee accepting from someone else is not
/// disturbed. That restraint matters:
/// `wq_wake_by_tid` on a task that is *not* currently blocked latches
/// `wake_pending` (the K-C9 lost-wakeup fix), which the task then consumes to
/// skip its next block — a spurious non-block injected into a task that was
/// never waiting on us.
///
/// Cost: exit path only, bounded by `MAX_LEASES` (16) entries and `MAX_TASKS`
/// registry slots. The grant and return paths are unchanged; an accept that
/// finds its lease pending does not touch the registry.
pub fn lease_release_all(tid: u32) {
    // Lessors: parked in `lease_wait_return` (WaitQueue), their only wait.
    // Woken through `wq_wake_by_tid` alone.
    let mut wake_lessor: [u32; MAX_LEASES] = [NO_TID; MAX_LEASES];
    let mut n_lessor = 0usize;

    // Registered acceptors naming `tid` as their lessor, parked (or about to
    // park) in `SYS_IPC_LEASE_ACCEPT` on `LeaseAccept(lessee, tid)`, are
    // collected and woken in batches. One buffer entry per registry slot is
    // `MAX_TASKS` × 4 bytes: 16 KiB on the fleet profile, the whole kernel
    // stack of the exiting task. A pass marks what it collects `LessorGone`,
    // so the next pass skips it, and the loop ends on a pass that fills less
    // than a batch.
    const ACCEPTOR_BATCH: usize = 32;
    let mut first_pass = true;
    loop {
        let mut wake_acceptor: [u32; ACCEPTOR_BATCH] = [NO_TID; ACCEPTOR_BATCH];
        let mut n_acceptor = 0usize;
        let mut batch_full = false;
        {
            let mut table = LEASES.lock_irqsave();
            for w in table.waiters.iter_mut() {
                if w.state == WaiterState::Free { continue; }
                // The dying task's own wait first: dropped, never marked or woken.
                if w.lessee == tid {
                    *w = AcceptWaiter::FREE;
                    continue;
                }
                if w.lessor == tid && w.state == WaiterState::Waiting {
                    if n_acceptor == ACCEPTOR_BATCH {
                        batch_full = true;
                        break;
                    }
                    w.state = WaiterState::LessorGone;
                    wake_acceptor[n_acceptor] = w.lessee;
                    n_acceptor += 1;
                }
            }
            if first_pass {
                release_leases_of(&mut *table, tid, &mut wake_lessor, &mut n_lessor);
            }
            refresh_deadline_count(&table);
        } // guard dropped — never wake while holding LEASES.

        if first_pass {
            for i in 0..n_lessor {
                azos_sched::wq_wake_by_tid(wake_lessor[i]);
            }
            first_pass = false;
        }
        for i in 0..n_acceptor {
            azos_sched::wait::wake_lease_acceptor(wake_acceptor[i], tid);
        }
        if !batch_full {
            break;
        }
    }

    // Wave 11: the mapping references booked for leases `tid` was party to
    // and whose PTEs are gone, given back outside `LEASES`; an entry `tid`
    // was the lessor of is freed in the same hold its reference is taken.
    release_refs_where(|_, e| {
        if e.map.root != 0 {
            return false;
        }
        if e.lessor_tid == tid {
            *e = LeaseEntry::empty();
            return true;
        }
        e.lessee_tid == tid
    });
    // And the windows it had not reaped: its address space goes with it.
    let mut table = LEASES.lock_irqsave();
    for r in table.revoked.iter_mut() {
        if r.tid == tid {
            *r = Revoked::FREE;
        }
    }
}

/// The lease-table half of [`lease_release_all`]: free the leases `tid` holds
/// as lessor, expire the ones it holds as lessee, and collect the lessors to
/// wake once the lock is dropped.
fn release_leases_of(
    table: &mut LeaseTable,
    tid: u32,
    wake_lessor: &mut [u32; MAX_LEASES],
    n_lessor: &mut usize,
) {
    for id in 0..MAX_LEASES {
        if table.entries[id].state == LeaseState::Free { continue; }

        // Wave 11: the lease mapping. A live lessee whose lessor is dying
        // loses its mapping exactly as on a lessor's free. The dying lessee's
        // own PTEs are removed and shot down as well, although its address
        // space is about to go: the exit hook is not guaranteed to run on the
        // hart the task last ran on, and the reference given back below may
        // free the frames those PTEs name.
        if table.entries[id].map.root != 0
            && (table.entries[id].lessee_tid == tid || table.entries[id].lessor_tid == tid)
        {
            table.revoke_map(id);
        }
        // Wave 11 (LEASE3): the seal. A dying lessor's address space is about
        // to go, so its record is only forgotten; a dying lessee ends the
        // lease (Expired below), so its lessor gets its write back.
        if table.entries[id].lessor_tid == tid {
            table.entries[id].seal = SealMap::NONE;
        } else if table.entries[id].lessee_tid == tid {
            table.unseal(id);
        }
        let e = &mut table.entries[id];

        // Lessor first: a self-lease must be freed, not expired. A lessee
        // accepting this lease is woken through its registration. An entry
        // whose mapping reference is still booked is freed by the reference
        // pass in `lease_release_all`, which takes the reference first.
        if e.lessor_tid == tid {
            if !e.map.ref_held {
                *e = LeaseEntry::empty();
            } else {
                e.state = LeaseState::Expired;
            }
            continue;
        }

        if e.lessee_tid == tid
            && matches!(e.state, LeaseState::Pending | LeaseState::Active)
        {
            // `Pending` counts as lessee-held: `lease_wait_return` blocks
            // on `Pending | Active`, so a lessee that dies before ever
            // accepting strands the lessor just as thoroughly.
            e.state = LeaseState::Expired;
            if e.lessor_tid != NO_TID && *n_lessor < MAX_LEASES {
                wake_lessor[*n_lessor] = e.lessor_tid;
                *n_lessor += 1;
            }
        }
    }
}

/// Expire every lease past its deadline; write the affected lessors' TIDs
/// into `expired_lessors` and return how many were written.
///
/// Call this from the timer ISR alongside `wake_expired_timers()`. The caller
/// wakes the first `n` entries; this function does no wakes of its own,
/// because waking under `LEASES` inverts the lock order against the
/// scheduler's task pool.
///
/// The drain loop:
///
/// ```ignore
/// let mut expired = [0u32; azos_ipc::MAX_LEASES];
/// let n = azos_ipc::lease_tick(now, &mut expired);
/// for &lessor_tid in expired.iter().take(n) {
///     azos_sched::wq_wake_by_tid(lessor_tid);
/// }
/// ```
///
/// The caller figures below were measured on a loop whose body also called
/// `wake_fast_ipc_server(lessor_tid)`; that call was removed on 2026-09-14
/// (a lessor waits only on the WaitQueue) and the figures were not
/// re-measured. The body runs only for an expired lease, so the no-deadline
/// row does not execute it.
///
/// `iter().take(n)` and **not** `&expired[..n]`: `n` comes from an opaque
/// cross-crate call (`lto = false`), so LLVM cannot discharge the slice-range
/// check and emits a call to `panic` — inside the timer ISR, under
/// `panic = "abort"`. Verified on the artifact: the `take` form emits no
/// panic path and costs the same 26 instructions.
///
/// # WHY the signature changed (audit: 157 instructions to do nothing)
///
/// The old shape returned `[(usize, u32); MAX_LEASES]` by value. Measured on
/// the RV64 artifact, the common case on this robot — *no lease with a
/// deadline* — cost **157 instructions**, 61 of them fixed, and **32 of those
/// 61 were unconditional stores** that zero-fill the 256-byte return array in
/// the prologue, fully unrolled.
///
/// That is why a bare early exit would have saved nothing: the array is
/// materialised through the caller's `sret` pointer *before* any test can
/// skip it. The array had to leave the return position for the exit to have
/// anything to skip.
///
/// Counted honestly — callee **plus** the caller's own drain loop, because
/// the caller's cost is forced by this signature and `lto = false` means
/// nothing sinks it:
///
/// | case | callee | caller | total |
/// |---|---:|---:|---:|
/// | before | 157 | 85 | **242** |
/// | after (no deadline armed) | 6 | 26 | **32** |
///
/// The worst case moved too, and in the right direction: 16 leases expiring
/// on the same tick costs **291** instructions, against **349** before.
///
/// Two further decisions behind this exact signature:
///
///  * **Lessor TIDs only, not `(lease_id, lessor_tid)` pairs.** The one
///    caller in the tree — the drain loop in `kernel/src/trap/interrupt.rs` — ends with
///    `let _ = lease_id;`: it never used the id. Dropping it halves the
///    buffer the caller must materialise every tick, from 256 B (32 stores)
///    to 64 B (8), and the caller's buffer is real cost — the kernel builds
///    with `lto = false`, so nothing sinks it past this call.
///  * **`&mut [u32; MAX_LEASES]`, not a slice.** A slice would need a
///    capacity check per write and could silently drop expiries on a short
///    buffer. A fixed array of exactly the table's size cannot.
///
/// # WHY `Pending` expires too
///
/// (Unchanged from the previous revision.) This used to test `state ==
/// Active` only, but `lease_wait_return` blocks on `Pending | Active`. A
/// lessor that granted with a deadline and whose lessee never called
/// `lease_accept` therefore had its own deadline silently not apply — it
/// slept forever on a lease the ISR refused to expire, the exact failure mode
/// `expire_ticks` exists to bound.
pub fn lease_tick(now_ticks: u64, expired_lessors: &mut [u32; MAX_LEASES]) -> usize {
    // The early exit. `Relaxed` on purpose: this load carries no
    // synchronisation duty — every reader and writer of the table itself goes
    // through `LEASES`, and the authoritative deadline test is inside the
    // loop below. The only consequence of reading a stale value is a
    // *one-tick* lag on a deadline armed concurrently on another hart, which
    // is smaller than the granularity `expire_ticks` already has: nothing in
    // the tree arms a timer at grant time, so a deadline has never been
    // observable before the next tick anyway. A stale value can never be
    // stale forever — the store is a plain atomic write, not a cached local.
    if DEADLINE_LEASES.load(Ordering::Relaxed) == 0 {
        return 0;
    }

    let mut count = 0usize;
    let mut table = LEASES.lock_irqsave();
    for e in table.entries.iter_mut() {
        if has_deadline(e) && now_ticks >= e.expire_ticks {
            e.state = LeaseState::Expired;
            // The `count < MAX_LEASES` guard is redundant — the loop runs at
            // most `MAX_LEASES` times and writes at most once per iteration —
            // but it is **not** free to drop. Verified on the RV64 artifact:
            // without it LLVM cannot prove the index in range and emits a
            // call to `panic_bounds_check` on the expiry path. Under
            // `panic = "abort"` that is a board reset sitting in the timer
            // ISR, reachable only through a compiler bug or a future edit,
            // and it costs an extra instruction per expiry anyway. The guard
            // makes the range provable and the panic path disappears.
            if count < MAX_LEASES {
                expired_lessors[count] = e.lessor_tid;
                count += 1;
            }
        }
    }
    // **The one place that adjusts the counter by a delta instead of
    // recounting, and why it is safe here specifically.** The argument that
    // rules out deltas everywhere else — six mutation sites, a missed
    // increment is a lease that never expires — does not apply to this one:
    // the delta is not inferred from a state machine, it is `count`, and
    // every entry counted in it was `has_deadline` on the way in and is
    // `Expired` on the way out, so the decrement is exact by construction and
    // provable in three lines.
    //
    // It is worth an exception because this is the ISR. Measured on the RV64
    // artifact: a full recount here costs **101 instructions** every time the
    // early exit does not fire, and it is what would have pushed the worst
    // case (16 leases expiring on one tick) from 349 instructions to 390.
    // With the delta the worst case is 289 — *below* the pre-change ceiling.
    if count != 0 {
        DEADLINE_LEASES.fetch_sub(count, Ordering::Release);
    }
    count
}

/// Diagnostic: count active leases.
pub fn lease_active_count() -> usize {
    LEASES.lock_irqsave().entries.iter().filter(|e| e.state == LeaseState::Active).count()
}

/// Diagnostic: the value of [`lease_tick`]'s early-exit counter — the number
/// of leases that are `Pending | Active` with a non-zero deadline.
///
/// Lock-free by design: this is exactly what the ISR reads. Exposed so a test
/// can assert the invariant `DEADLINE_LEASES == |{counted entries}|` directly
/// instead of inferring it from behaviour — a counter that is stale *upwards*
/// still ticks correctly and would hide behind a purely behavioural test,
/// while silently restoring the 157-instruction cost this counter removed.
pub fn lease_deadline_count() -> usize {
    DEADLINE_LEASES.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Accept-and-map (wave 11, LEASE2)
// ---------------------------------------------------------------------------

/// What the lessee needs to map an accepted lease: the region granted and
/// whether the mapping may be writable. `None` unless `lease_id` is `Active`,
/// `lessee` is its lessee, it has no mapping yet, and its region resolved at
/// grant.
pub fn lease_map_target(lease_id: usize, lessee: u32) -> Option<(u32, bool)> {
    if lease_id >= MAX_LEASES {
        return None;
    }
    let lease_id = azos_limits::nospec::array_index_nospec(lease_id, MAX_LEASES);
    let table = LEASES.lock_irqsave();
    let e = &table.entries[lease_id];
    (e.state == LeaseState::Active
        && e.lessee_tid == lessee
        && e.map.root == 0
        && !e.map.ref_held
        && e.shm_ref != 0)
        .then_some((e.shm_ref, e.writable))
}

/// Record the mapping the lessee made of `lease_id` (`root`, `va`, `pages`),
/// whose region reference is booked under [`lease_holder_tid`]. `false` when
/// the lease is no longer this lessee's `Active` lease (it expired or was
/// freed between the accept and the map): nothing is recorded, and the caller
/// undoes its mapping and gives the reference back itself.
///
/// `shm_ref` is the region [`lease_map_target`] answered: an entry freed and
/// granted again to the same lessee in between, over another region, is not
/// this mapping's lease.
pub fn lease_note_map(
    lease_id: usize, lessee: u32, shm_ref: u32, root: usize, va: usize, pages: usize,
) -> bool {
    if lease_id >= MAX_LEASES || root == 0 {
        return false;
    }
    let lease_id = azos_limits::nospec::array_index_nospec(lease_id, MAX_LEASES);
    let mut table = LEASES.lock_irqsave();
    let e = &mut table.entries[lease_id];
    if e.state != LeaseState::Active || e.lessee_tid != lessee || e.shm_ref != shm_ref
        || e.map.root != 0 || e.map.ref_held
    {
        return false;
    }
    e.map = LeaseMap { root, va, pages, ref_held: true };
    true
}

/// The lessee's revoked windows, removed from the table: `(va, pages)` of
/// each, written into `out`; returns how many (at most `out.len()`, the rest
/// stay for the next call). The lessee releases those addresses from its own
/// window — only the current task can.
pub fn lease_take_revoked(tid: u32, out: &mut [(usize, usize)]) -> usize {
    let mut n = 0usize;
    let mut table = LEASES.lock_irqsave();
    for r in table.revoked.iter_mut() {
        if n == out.len() {
            break;
        }
        if r.tid == tid {
            out[n] = (r.va, r.pages);
            n += 1;
            *r = Revoked::FREE;
        }
    }
    n
}

/// A user fault of `tid` at `va`: was it a touch of a lease mapping the kernel
/// revoked? `Some(lease_id)` and the fault is counted
/// ([`lease_revoked_faults`]); the caller kills the task as for any unresolved
/// fault. Called from the page-fault kill path of both ISAs, with no lock
/// held.
pub fn lease_revoked_fault(tid: u32, va: usize) -> Option<usize> {
    let page = azos_arch::PAGE_SIZE;
    let table = LEASES.lock_irqsave();
    let hit = table.revoked.iter().find(|r| {
        r.tid == tid && va >= r.va && va < r.va.saturating_add(r.pages.saturating_mul(page))
    })?;
    REVOKED_FAULTS.fetch_add(1, Ordering::Relaxed);
    Some(hit.lease as usize)
}

/// User faults attributed to a revoked lease mapping since boot.
pub fn lease_revoked_faults() -> u64 {
    REVOKED_FAULTS.load(Ordering::Relaxed)
}

/// `tid` exec'd: its old address space is about to be freed by the exec
/// hand-off, so every lease mapping in it is forgotten (no shootdown: the
/// task is switching away from that root and nothing else runs in it), its
/// references given back, and its revoked windows dropped (they named
/// addresses of the old image). The leases themselves stay as they were — an
/// `Active` one can still be returned. Must run before the old root is freed
/// (module doc, "Page-table lifetime").
pub fn lease_exec(tid: u32) {
    release_refs_where(|_, e| {
        if e.lessee_tid != tid {
            return false;
        }
        e.map.root = 0;
        true
    });
    let mut table = LEASES.lock_irqsave();
    for r in table.revoked.iter_mut() {
        if r.tid == tid {
            *r = Revoked::FREE;
        }
    }
    // Wave 11 (LEASE3): the seals of this task's grants named its old address
    // space; forgotten, not restored (that root is about to be freed).
    for e in table.entries.iter_mut() {
        if e.lessor_tid == tid {
            e.seal = SealMap::NONE;
        }
    }
}

// ---------------------------------------------------------------------------
// Expiry without the lessor (wave 11, LEASE3)
// ---------------------------------------------------------------------------

/// Revoke what every expired lease still holds: the lessee's lease mapping
/// (removed and shot down, its reference given back) and a sealed lessor's
/// write (given back). Returns how many leases it acted on.
///
/// The kernel's lease worker calls this after the timer interrupt's
/// [`lease_tick`] expired something: the interrupt edits no page table, and
/// before the worker an expired lessee kept its mapping until its lessor
/// waited or freed. Task context only — the same rules as every revoke
/// (`LEASES` held across each PTE edit, references given back after it). The
/// entry stays `Expired` for its lessor's `lease_wait`/`lease_free`, which
/// find nothing left to revoke.
pub fn lease_reap_expired() -> usize {
    let mut n = 0usize;
    {
        let mut table = LEASES.lock_irqsave();
        for id in 0..MAX_LEASES {
            let e = &table.entries[id];
            if e.state != LeaseState::Expired || (e.map.root == 0 && e.seal.root == 0) {
                continue;
            }
            table.revoke_map(id);
            table.unseal(id);
            n += 1;
        }
    }
    release_refs_where(|_, e| e.state == LeaseState::Expired && e.map.root == 0);
    n
}

// ---------------------------------------------------------------------------
// The producer-side seal (wave 11, LEASE3)
// ---------------------------------------------------------------------------

/// Is `tid` the lessor of an in-flight sealed lease on the region `shm_ref`
/// names? `SYS_SHM_MAP_TYPED` maps the region read-only for it then, so a
/// lessor that had no mapping at grant cannot map one writable during the
/// seal. That mapping is not the seal's: it stays read-only after the lease.
pub fn lease_sealed_by(tid: u32, shm_ref: u32) -> bool {
    let table = LEASES.lock_irqsave();
    table.entries.iter().any(|e| {
        e.sealed && e.lessor_tid == tid && e.shm_ref == shm_ref
            && matches!(e.state, LeaseState::Pending | LeaseState::Active)
    })
}

/// `tid` is removing its mapping at `va` (`SYS_SHM_RELEASE_TYPED`, before the
/// PTEs go and the window is given back): a seal naming it is forgotten, so a
/// later end of the lease cannot widen whatever is mapped at `va` next.
pub fn lease_forget_seal(tid: u32, va: usize) {
    let mut table = LEASES.lock_irqsave();
    for e in table.entries.iter_mut() {
        if e.lessor_tid == tid && e.seal.root != 0 && e.seal.va == va {
            e.seal = SealMap::NONE;
        }
    }
}

/// A user fault of `tid` at `va`: was it a lessor writing its own buffer
/// under a seal? `Some(lease_id)` and the fault is counted
/// ([`lease_seal_faults`]); the caller kills the task as for any unresolved
/// fault. Called from the page-fault kill path of both ISAs, with no lock
/// held. A fault that races the lease's end is killed unattributed (the
/// write was issued under the seal).
pub fn lease_sealed_fault(tid: u32, va: usize) -> Option<usize> {
    let page = azos_arch::PAGE_SIZE;
    let table = LEASES.lock_irqsave();
    let id = table.entries.iter().position(|e| {
        e.lessor_tid == tid && e.seal.root != 0
            && va >= e.seal.va && va < e.seal.va.saturating_add(e.seal.pages.saturating_mul(page))
    })?;
    SEAL_FAULTS.fetch_add(1, Ordering::Relaxed);
    Some(id)
}

/// Lessor writes refused by a seal since boot.
pub fn lease_seal_faults() -> u64 {
    SEAL_FAULTS.load(Ordering::Relaxed)
}

/// Diagnostic: `(sealed, the seal's record)` of `lease_id`.
pub fn lease_seal_info(lease_id: usize) -> (bool, SealMap) {
    if lease_id >= MAX_LEASES {
        return (false, SealMap::NONE);
    }
    let table = LEASES.lock_irqsave();
    (table.entries[lease_id].sealed, table.entries[lease_id].seal)
}

/// Diagnostic: the mapping record of `lease_id` (`LeaseMap::NONE` out of range).
pub fn lease_map_info(lease_id: usize) -> LeaseMap {
    if lease_id >= MAX_LEASES {
        return LeaseMap::NONE;
    }
    LEASES.lock_irqsave().entries[lease_id].map
}

/// Diagnostic: copy the revoked-window rows in use into `out`; returns how
/// many were copied.
pub fn lease_revoked_rows(out: &mut [Revoked]) -> usize {
    let table = LEASES.lock_irqsave();
    let mut n = 0usize;
    for r in table.revoked.iter() {
        if r.tid != NO_TID && n < out.len() {
            out[n] = *r;
            n += 1;
        }
    }
    n
}

/// Wipe the whole lease table. Host-test hygiene only — the suite shares one
/// static `LEASES`, so each test must start from a known state. Never built
/// into the kernel: a reachable "cancel every lease on the board" entry point
/// is exactly the cross-task teardown the ownership checks above close.
#[cfg(test)]
pub fn __lease_reset_for_tests() {
    let mut table = LEASES.lock_irqsave();
    for e in table.entries.iter_mut() {
        *e = LeaseEntry::empty();
    }
    for w in table.waiters.iter_mut() {
        *w = AcceptWaiter::FREE;
    }
    for r in table.revoked.iter_mut() {
        *r = Revoked::FREE;
    }
    refresh_deadline_count(&table);
}

/// Every registered accept wait as `(lessee, lessor, lessor_gone)`, in slot
/// order (host tests).
#[cfg(test)]
fn __lease_waiters_for_tests() -> Vec<(u32, u32, bool)> {
    LEASES
        .lock_irqsave()
        .waiters
        .iter()
        .filter(|w| w.state != WaiterState::Free)
        .map(|w| (w.lessee, w.lessor, w.state == WaiterState::LessorGone))
        .collect()
}

/// Read a lease's state without going through the public API (host tests).
#[cfg(test)]
pub fn __lease_state_for_tests(lease_id: usize) -> LeaseState {
    if lease_id >= MAX_LEASES { return LeaseState::Free; }
    LEASES.lock_irqsave().entries[lease_id].state
}

#[cfg(test)]
mod tests {
    use super::*;

    const LESSOR: u32 = 1;
    const LESSEE: u32 = 2;
    const STRANGER: u32 = 3;

    /// Ring-3 identities are the default; `privileged` is passed explicitly.
    ///
    /// The lease table is one process-wide static, and the io_ring, port and
    /// irq_bind suites in this binary share the scheduler shim whose wakes
    /// these tests assert on. `crate::harness::serial()` serialises those
    /// suites and resets that shim.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        __lease_reset_for_tests();
        // Non-zero user page table = ring 3.
        azos_sched::shim_set_current(STRANGER, 0x1000);
        g
    }

    /// The bookkeeping tests below grant as the kernel. The authority check is
    /// tested in `tests/host/ipc-lease-tests/tests/lease_grant_authority.rs`.
    /// Explicit rather than read from the scheduler shim, which `setup` sets to
    /// a ring-3 caller.
    fn lease_grant(shm_id: usize, lessor: u32, lessee: u32, expire: u64) -> Option<usize> {
        lease_grant_as(shm_id, lessor, lessee, expire, true).ok()
    }

    fn grant_and_accept(lessor: u32, lessee: u32) -> usize {
        let id = lease_grant(0, lessor, lessee, 0).expect("free lease slot");
        let (accepted, _shm) = lease_accept(lessee, lessor).expect("pending lease");
        assert_eq!(accepted, id);
        id
    }

    // ── IPC-6: lease_return is the lessee's ────────────────────────────────

    #[test]
    fn return_accepted_from_lessee_denied_from_anyone_else() {
        let _g = setup();
        // Walk several ids so a pass cannot be luck with slot 0.
        for shift in 0..4u32 {
            __lease_reset_for_tests();
            let lessor = LESSOR + shift * 10;
            let lessee = LESSEE + shift * 10;
            // Burn `shift` slots first so the id under test moves.
            for _ in 0..shift {
                lease_grant(0, 900, 901, 0).unwrap();
            }
            let id = grant_and_accept(lessor, lessee);
            assert_eq!(id, shift as usize);

            // A third party may not return it.
            assert!(lease_return(id, STRANGER, false).is_none());
            // Neither may the lessor: returning is the act of giving the
            // buffer back, and the lessor never had it.
            assert!(lease_return(id, lessor, false).is_none());
            // The lease is untouched — this is the half that matters. A
            // rejected call that still flipped the state would wake the
            // lessor while the real lessee still holds the pages.
            assert!(__lease_state_for_tests(id) == LeaseState::Active);
            assert!(!lease_is_returned(id));
            assert!(!azos_sched::shim_was_woken(lessor));

            // The legitimate lessee can.
            assert_eq!(lease_return(id, lessee, false), Some(lessor));
            assert!(__lease_state_for_tests(id) == LeaseState::Returned);
            assert!(lease_is_returned(id));
            assert!(azos_sched::shim_was_woken(lessor));
        }
    }

    /// The return's wake is `wq_wake_by_tid(lessor)` and nothing else, the
    /// wake `lease_wait_return` (WaitQueue) waits for. `SYS_IPC_LEASE_RETURN`
    /// adds no wake of its own (owner decision 2026-09-14); that half is
    /// covered by the kernel build only.
    ///
    /// Canary: add `wake_fast_ipc_server(lessor)` beside the `wq_wake_by_tid`
    /// in `lease_return`, or drop the `wq_wake_by_tid`.
    #[test]
    fn a_return_wakes_the_lessor_through_the_wait_queue_only() {
        let _g = setup();
        let id = grant_and_accept(LESSOR, LESSEE);
        // Forget the grant's own wake of the lessee.
        azos_sched::shim_reset();
        assert_eq!(lease_return(id, LESSEE, false), Some(LESSOR));
        assert_eq!(azos_sched::shim_wq_wakes(), vec![LESSOR]);
        assert!(azos_sched::shim_fast_ipc_wakes().is_empty());
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());
    }

    #[test]
    fn return_is_bypassed_for_kernel_callers() {
        let _g = setup();
        let id = grant_and_accept(LESSOR, LESSEE);
        // House convention: kernel (`current_user_pt() == 0`) skips the check.
        assert_eq!(lease_return(id, STRANGER, true), Some(LESSOR));
        assert!(lease_is_returned(id));
    }

    #[test]
    fn return_rejects_non_active_states() {
        let _g = setup();
        // Pending: the lessee never accepted, so it never held the buffer.
        let pending = lease_grant(0, LESSOR, LESSEE, 0).unwrap();
        assert!(lease_return(pending, LESSEE, false).is_none());
        assert!(__lease_state_for_tests(pending) == LeaseState::Pending);

        // Free slot.
        assert!(lease_return(MAX_LEASES - 1, LESSEE, false).is_none());

        // A different lessee, because `lease_accept` takes the *first*
        // pending lease for a (lessee, lessor) pair and slot 0 above is still
        // outstanding.
        let id = grant_and_accept(LESSOR, LESSEE + 100);
        assert!(lease_return(id, LESSEE + 100, false).is_some());
        // Double-return must not re-wake the lessor a second time.
        assert!(lease_return(id, LESSEE + 100, false).is_none());
        assert_eq!(azos_sched::shim_wq_wakes().len(), 1);
    }

    // ── IPC-6: lease_free is the lessor's ──────────────────────────────────

    #[test]
    fn free_accepted_from_lessor_denied_from_anyone_else() {
        let _g = setup();
        for shift in 0..4u32 {
            __lease_reset_for_tests();
            let lessor = LESSOR + shift * 10;
            let lessee = LESSEE + shift * 10;
            for _ in 0..shift {
                lease_grant(0, 900, 901, 0).unwrap();
            }
            let id = grant_and_accept(lessor, lessee);

            assert!(!lease_free(id, STRANGER, false));
            assert!(!lease_free(id, lessee, false));
            // Denied means *nothing happened* — the slot is still the pair's.
            assert!(__lease_state_for_tests(id) == LeaseState::Active);

            assert!(lease_free(id, lessor, false));
            assert!(__lease_state_for_tests(id) == LeaseState::Free);
            // Freeing twice is not success.
            assert!(!lease_free(id, lessor, false));
        }
    }

    #[test]
    fn free_is_bypassed_for_kernel_callers() {
        let _g = setup();
        let id = grant_and_accept(LESSOR, LESSEE);
        assert!(lease_free(id, STRANGER, true));
        assert!(__lease_state_for_tests(id) == LeaseState::Free);
    }

    // ── IPC-6: lease_wait_return only for the lessor ───────────────────────

    #[test]
    fn wait_return_from_a_stranger_returns_without_blocking_or_boosting() {
        let _g = setup();
        let id = grant_and_accept(LESSOR, LESSEE);
        azos_sched::shim_set_priority(STRANGER, 1);
        azos_sched::shim_set_priority(LESSEE, 9);
        azos_sched::shim_set_current(STRANGER, 0x1000);
        // If the guard were missing this would donate STRANGER's priority to
        // LESSEE and then park on `wq_block_current`, which the shim panics
        // on — so reaching the assertions at all is part of the assertion.
        lease_wait_return(id);
        assert!(azos_sched::shim_boosts().is_empty());
        assert!(__lease_state_for_tests(id) == LeaseState::Active);
    }

    // ── Owner decision 2026-09-14 (2): an accept names its lessor ──────────

    /// Canary: drop `e.lessor_tid == lessor` from `find_pending`. B's lease is
    /// first in table order, so the accept naming A returns it.
    #[test]
    fn accept_takes_only_the_lease_of_the_named_lessor() {
        let _g = setup();
        const A: u32 = 21;
        const B: u32 = 22;
        // B grants first: an accept that ignored the lessor would take B's.
        let from_b = lease_grant(0, B, LESSEE, 0).unwrap();
        let from_a = lease_grant(0, A, LESSEE, 0).unwrap();
        assert!(from_b < from_a);

        assert_eq!(
            lease_accept(LESSEE, A).map(|(id, _)| id),
            Some(from_a),
            "an accept naming A took a lease another lessor granted"
        );
        // B's lease was neither consumed nor returned: still pending, for B.
        assert!(__lease_state_for_tests(from_b) == LeaseState::Pending);
        // A has nothing more pending for LESSEE, and B's lease does not stand in.
        assert_eq!(lease_accept(LESSEE, A), None);
        assert!(__lease_state_for_tests(from_b) == LeaseState::Pending);
        assert_eq!(lease_accept(LESSEE, B).map(|(id, _)| id), Some(from_b));
    }

    /// Canary: same mutation as above; each `None` below then reads `Some`.
    #[test]
    fn accept_naming_a_lessor_with_nothing_pending_returns_none() {
        let _g = setup();
        let other = lease_grant(0, 22, LESSEE, 0).unwrap();
        assert_eq!(lease_accept(LESSEE, 21), None, "lessor 21 granted nothing");
        assert_eq!(lease_accept(LESSEE, NO_TID), None, "no lease names NO_TID");
        // A lease *to* LESSEE from 22 is not a lease *to* 22 from LESSEE.
        assert_eq!(lease_accept(22, LESSEE), None);
        assert!(__lease_state_for_tests(other) == LeaseState::Pending);
        // And the region id travels with the lease the pair names.
        let with_shm = lease_grant(7, 21, LESSEE, 0).unwrap();
        assert_eq!(lease_accept(LESSEE, 21), Some((with_shm, 7)));
    }

    // ── Owner decision 2026-09-14 (3): the grant's wake names the accept ───

    /// Canary: in `lease_grant_as`, call `wake_fast_ipc_server(lessee_tid)`
    /// instead of `wait::wake_lease_acceptor(lessee_tid, lessor_tid)`; or
    /// swap the two arguments.
    #[test]
    fn a_grant_wakes_the_lessee_through_the_lease_accept_wake_only() {
        let _g = setup();
        lease_grant(0, LESSOR, LESSEE, 0).unwrap();
        assert_eq!(
            azos_sched::shim_lease_accept_wakes(),
            vec![(LESSEE, LESSOR)],
            "a grant must wake LeaseAccept(lessee, lessor), addressed to the lessee"
        );
        // Not the fast-IPC server wake: that one dispatches a task blocked as
        // a fast-IPC server on the lessee's TID.
        assert!(azos_sched::shim_fast_ipc_wakes().is_empty());
        assert!(azos_sched::shim_wq_wakes().is_empty());
    }

    /// Canary: wake before the allocation result is checked (the wake call
    /// moved inside the guarded block, above `id.ok_or(..)?`).
    #[test]
    fn a_refused_grant_wakes_nobody() {
        let _g = setup();
        // Ring 3, an id that names no region: refused by the owner check.
        assert_eq!(
            lease_grant_as(usize::MAX, LESSOR, LESSEE, 0, false),
            Err(LeaseGrantError::NotOwner)
        );
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());
        // Table full: refused for want of a slot.
        for i in 0..MAX_LEASES {
            lease_grant(0, 100 + i as u32, 200, 0).unwrap();
        }
        azos_sched::shim_reset();
        assert_eq!(
            lease_grant_as(0, LESSOR, LESSEE, 0, true),
            Err(LeaseGrantError::NoSlot)
        );
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());
        assert!(!azos_sched::shim_was_woken(LESSEE));
    }

    // ── Owner decision 2026-09-14 (1): how the quota refusal surfaces ──────

    /// Canary: map `Quota` to `-1` in `LeaseGrantError::syscall_ret`.
    #[test]
    fn only_the_quota_refusal_surfaces_as_equota() {
        let equota = -(azos_abi::error::Errno::EQUOTA as i64);
        assert_eq!(LeaseGrantError::Quota.syscall_ret(), equota);
        assert_eq!(LeaseGrantError::NotOwner.syscall_ret(), -1);
        assert_eq!(LeaseGrantError::NoSlot.syscall_ret(), -1);
    }

    // ── Bounds: no reachable panic (panic = "abort" resets the board) ──────

    #[test]
    fn out_of_range_and_boundary_ids_never_panic() {
        let _g = setup();
        for id in [MAX_LEASES, MAX_LEASES + 1, usize::MAX, usize::MAX - 1] {
            assert!(lease_return(id, LESSEE, false).is_none());
            assert!(lease_return(id, LESSEE, true).is_none());
            assert!(!lease_free(id, LESSOR, false));
            assert!(!lease_free(id, LESSOR, true));
            assert!(!lease_is_returned(id));
            lease_wait_return(id); // must return, not block
        }
        // Last valid index must still behave, and a free slot must not block
        // `lease_wait_return` either.
        let last = MAX_LEASES - 1;
        assert!(!lease_is_returned(last));
        assert!(!lease_free(last, LESSOR, false));
        lease_wait_return(last);
    }

    // ── IPC-3: the lessee dies ─────────────────────────────────────────────

    #[test]
    fn lessee_death_expires_the_lease_and_wakes_the_lessor() {
        let _g = setup();
        let id = grant_and_accept(LESSOR, LESSEE);

        lease_release_all(LESSEE);

        // THE DECISION, PINNED: an abandoned buffer becomes `Expired`, never
        // `Returned`. `Returned` would tell the lessor the lessee handed the
        // pages back cleanly; it did not, it died holding them.
        assert!(__lease_state_for_tests(id) == LeaseState::Expired);
        // And the lessor's wait must actually terminate — a lessor asleep
        // forever is a control task that stops actuating.
        assert!(lease_is_returned(id));
        // Through the WaitQueue, `lease_wait_return`'s wait, and nothing else
        // (owner decision 2026-09-14): a fast-IPC server wake reaches no lease
        // waiter and would dispatch a lessor blocked serving fast IPC.
        //
        // Canary: restore `wake_fast_ipc_server(lessor)` in the sweep's lessor
        // loop, or drop its `wq_wake_by_tid`.
        assert_eq!(azos_sched::shim_wq_wakes(), vec![LESSOR]);
        assert!(azos_sched::shim_fast_ipc_wakes().is_empty());
        // The slot stays allocated so the lessor frees it through the normal
        // path, exactly like a timer expiry.
        assert!(lease_free(id, LESSOR, false));
    }

    #[test]
    fn lessee_death_while_still_pending_also_expires_and_wakes() {
        let _g = setup();
        // Never accepted: `lease_wait_return` blocks on Pending too, so this
        // strands the lessor just as thoroughly as the Active case.
        let id = lease_grant(0, LESSOR, LESSEE, 0).unwrap();
        lease_release_all(LESSEE);
        assert!(__lease_state_for_tests(id) == LeaseState::Expired);
        assert!(azos_sched::shim_was_woken(LESSOR));
    }

    // ── IPC-3: the lessor dies ─────────────────────────────────────────────

    /// Canary: restore the sweep's wake of every lessee holding a `Pending`
    /// lease from the dying lessor, registered or not.
    #[test]
    fn lessor_death_frees_a_pending_lease_and_wakes_no_lessee_that_is_not_accepting() {
        let _g = setup();
        let id = lease_grant(0, LESSOR, LESSEE, 0).unwrap(); // Pending
        // The grant itself wakes the lessee. Forget that wake, so what is
        // asserted below is the exit sweep's own.
        azos_sched::shim_reset();

        lease_release_all(LESSOR);

        // THE DECISION, PINNED: no lessor left to wake or to free the entry,
        // so the slot goes back to the table immediately.
        assert!(__lease_state_for_tests(id) == LeaseState::Free);
        // LESSEE holds a pending lease but is not in an accept: nothing of it
        // waits on LESSOR, and a stamp would make its next unrelated block
        // return at once. An accept that could take this lease is registered
        // and woken through that; see
        // `a_pending_lease_from_a_dying_lessor_wakes_and_ends_the_accept`.
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());
        assert!(!azos_sched::shim_was_woken(LESSEE));
    }

    #[test]
    fn lessor_death_on_an_active_lease_frees_the_slot_without_waking() {
        let _g = setup();
        let id = grant_and_accept(LESSOR, LESSEE);
        // Forget the grant's own wake of the lessee (see above).
        azos_sched::shim_reset();
        lease_release_all(LESSOR);
        assert!(__lease_state_for_tests(id) == LeaseState::Free);
        // The lessee is not blocked on anything here — it holds the buffer.
        assert!(!azos_sched::shim_was_woken(LESSEE));
        // Its stale lease_id is now harmless: the slot may be re-granted to a
        // different pair, and the ownership check rejects the old lessee.
        let reused = lease_grant(0, 40, 41, 0).unwrap();
        assert_eq!(reused, id);
        let (_a, _s) = lease_accept(41, 40).unwrap();
        assert!(lease_return(reused, LESSEE, false).is_none());
        assert!(__lease_state_for_tests(reused) == LeaseState::Active);
    }

    // ── Owner decision 2026-09-14: the accept waiter registry ──────────────
    //
    // `lease_accept_wait` takes its block as a closure, so these tests drive
    // the loop `SYS_IPC_LEASE_ACCEPT` runs, turn by turn. A closure call is
    // one `task_block`; what the closure does is what happens while the
    // lessee is parked (or just before it parks). What the host cannot show
    // is the scheduler half: that `wake_lease_acceptor` dispatches a blocked
    // lessee and stamps one that has not blocked yet. That half is the real
    // `wake_transition`, pinned in `tests/host/sched-wake-tests`
    // (`a_grant_before_the_lessee_blocks_is_not_lost`, same wake function).

    const OTHER_LESSOR: u32 = 4;

    /// Canaries: (a) the exit sweep wakes the registered lessee but does not
    /// mark the registration (the withdrawn broadcast); (b) the poll ignores
    /// `LessorGone`. Either way turn 3 blocks again and the closure fails.
    #[test]
    fn a_lessee_blocked_on_an_earlier_turn_returns_when_its_lessor_exits() {
        let _g = setup();
        // Turns 0 and 1 come back with nothing (a stamp from another lessor's
        // grant, a K-C29 refusal); the lessor exits during turn 2.
        const EXIT_TURN: u32 = 2;
        assert!(EXIT_TURN + 1 < LEASE_ACCEPT_TURNS, "must end before the turns run out");
        let mut turns = 0u32;
        let r = lease_accept_wait(LESSEE, LESSOR, || {
            let k = turns;
            turns += 1;
            assert!(
                k <= EXIT_TURN,
                "turn {k}: the accept blocked again after its lessor exited, and no wake names that lessor"
            );
            if k == EXIT_TURN {
                assert_eq!(__lease_waiters_for_tests(), vec![(LESSEE, LESSOR, false)]);
                azos_sched::shim_reset();
                lease_release_all(LESSOR);
                assert_eq!(
                    azos_sched::shim_lease_accept_wakes(),
                    vec![(LESSEE, LESSOR)],
                    "the exit did not wake the registered lessee"
                );
            }
        });
        assert_eq!(r, Err(LeaseAcceptError::LessorGone));
        assert_eq!(turns, EXIT_TURN + 1);
        assert!(__lease_waiters_for_tests().is_empty());
    }

    /// The exit lands after the accept's first poll and before its first
    /// block (the window a stamp covers in the scheduler).
    ///
    /// Canaries: (a) register on the first poll AFTER a block instead of in
    /// `lease_accept_begin`: nothing is registered when the exit runs, so it
    /// marks and wakes nothing; (b) the poll keeps a `LessorGone`
    /// registration, so a second poll no longer reads as terminal.
    #[test]
    fn a_lessor_exit_between_the_poll_and_the_block_ends_the_accept() {
        let _g = setup();
        // Function level.
        assert_eq!(lease_accept_begin(LESSEE, LESSOR), LeaseAcceptBegin::Registered);
        lease_release_all(LESSOR); // before the lessee's `task_block`
        assert_eq!(__lease_waiters_for_tests(), vec![(LESSEE, LESSOR, true)]);
        assert_eq!(azos_sched::shim_lease_accept_wakes(), vec![(LESSEE, LESSOR)]);
        // The stamp makes the block return; the poll after it ends the wait,
        assert_eq!(lease_accept_poll(LESSEE, LESSOR), LeaseAcceptPoll::LessorGone);
        assert!(__lease_waiters_for_tests().is_empty());
        // and nothing is left that a later poll could read as "still waiting".
        assert_eq!(lease_accept_poll(LESSEE, LESSOR), LeaseAcceptPoll::NotRegistered);

        // Loop level: the exit is the first thing that happens after the
        // first poll.
        __lease_reset_for_tests();
        azos_sched::shim_reset();
        let mut turns = 0u32;
        let r = lease_accept_wait(LESSEE, LESSOR, || {
            turns += 1;
            assert_eq!(turns, 1, "the accept blocked again after its lessor exited");
            assert_eq!(
                __lease_waiters_for_tests(),
                vec![(LESSEE, LESSOR, false)],
                "the wait reached its first block unregistered: no exit could end it"
            );
            lease_release_all(LESSOR);
        });
        assert_eq!(r, Err(LeaseAcceptError::LessorGone));
        assert_eq!(turns, 1);
        assert!(__lease_waiters_for_tests().is_empty());
    }

    /// A grant reaches the blocked lessee and its lessor exits before the
    /// lessee polls: the lease is freed with the lessor, and the accept ends.
    ///
    /// Canary: the sweep keeps the pre-registry shape (wake the lessee of a
    /// `Pending` lease, mark nothing): the poll finds no lease and no mark,
    /// and turn 2 blocks again.
    #[test]
    fn a_pending_lease_from_a_dying_lessor_wakes_and_ends_the_accept() {
        let _g = setup();
        let mut granted = None;
        let mut turns = 0u32;
        let r = lease_accept_wait(LESSEE, LESSOR, || {
            turns += 1;
            assert_eq!(turns, 1, "the accept blocked again after its lessor exited");
            let id = lease_grant(0, LESSOR, LESSEE, 0).unwrap();
            assert!(__lease_state_for_tests(id) == LeaseState::Pending);
            granted = Some(id);
            azos_sched::shim_reset();
            lease_release_all(LESSOR);
            assert_eq!(azos_sched::shim_lease_accept_wakes(), vec![(LESSEE, LESSOR)]);
        });
        assert_eq!(r, Err(LeaseAcceptError::LessorGone));
        assert!(__lease_state_for_tests(granted.expect("granted")) == LeaseState::Free);
        assert!(__lease_waiters_for_tests().is_empty());
    }

    /// Canaries: (a) with no free slot, overwrite slot 0 instead of answering
    /// `NoRoom` (a registered waiter silently evicted); (b) size the sweep's
    /// wake buffer by `MAX_LEASES` (acceptors past the 16th never woken).
    #[test]
    fn a_full_registry_refuses_before_blocking_and_loses_no_waiter() {
        let _g = setup();
        const LESSOR_A: u32 = 2000;
        const LESSOR_B: u32 = 2001;
        const LATE: u32 = 3000;
        for i in 0..MAX_TASKS as u32 {
            assert_eq!(lease_accept_begin(1000 + i, LESSOR_A), LeaseAcceptBegin::Registered, "slot {i}");
        }
        let full = __lease_waiters_for_tests();
        assert_eq!(full.len(), MAX_TASKS);

        // One more lessee: refused, and the loop never reaches a block.
        let r = lease_accept_wait(LATE, LESSOR_A, || {
            panic!("blocked with no registration: no exit sweep could end this wait")
        });
        assert_eq!(r, Err(LeaseAcceptError::RegistryFull));
        assert_eq!(lease_accept_begin(LATE, LESSOR_A), LeaseAcceptBegin::NoRoom);
        // Nobody was evicted to make room.
        assert_eq!(__lease_waiters_for_tests(), full);

        // A lessee already registered re-registers in its own slot.
        assert_eq!(lease_accept_begin(1000, LESSOR_B), LeaseAcceptBegin::Registered);
        assert_eq!(__lease_waiters_for_tests().len(), MAX_TASKS);

        // A pending lease needs no slot: taken even with the registry full.
        let id = lease_grant(0, LESSOR_A, LATE, 0).unwrap();
        let r = lease_accept_wait(LATE, LESSOR_A, || panic!("blocked with a lease pending"));
        assert_eq!(r, Ok((id, 0)));

        // Every registered waiter is reached by its lessor's exit.
        azos_sched::shim_reset();
        lease_release_all(LESSOR_A);
        let woken = azos_sched::shim_lease_accept_wakes();
        assert_eq!(woken.len(), MAX_TASKS - 1, "the exit dropped registered acceptors");
        for i in 1..MAX_TASKS as u32 {
            assert!(woken.contains(&(1000 + i, LESSOR_A)), "acceptor {} not woken", 1000 + i);
        }
        azos_sched::shim_reset();
        lease_release_all(LESSOR_B);
        assert_eq!(azos_sched::shim_lease_accept_wakes(), vec![(1000, LESSOR_B)]);
    }

    /// Canaries: (a) the poll that takes the lease keeps the registration;
    /// (b) `lease_accept_wait` returns without `lease_accept_cancel` (turn
    /// exhaustion then leaves a slot behind, next test).
    #[test]
    fn a_granted_accept_leaves_no_registration_behind() {
        let _g = setup();
        // Function level: the poll that takes the lease drops the registration
        // in its own hold, so the lessor's later exit wakes nobody.
        assert_eq!(lease_accept_begin(LESSEE, LESSOR), LeaseAcceptBegin::Registered);
        let id = lease_grant(0, LESSOR, LESSEE, 0).unwrap();
        assert_eq!(lease_accept_poll(LESSEE, LESSOR), LeaseAcceptPoll::Got(id, 0));
        assert!(
            __lease_waiters_for_tests().is_empty(),
            "the poll that took the lease left its registration"
        );
        azos_sched::shim_reset();
        lease_release_all(LESSOR);
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());

        // Loop level: the grant arrives during the first block.
        __lease_reset_for_tests();
        let mut granted = None;
        let mut turns = 0u32;
        let r = lease_accept_wait(LESSEE, LESSOR, || {
            turns += 1;
            granted = lease_grant(0, LESSOR, LESSEE, 0);
        });
        let granted = granted.expect("granted");
        assert_eq!(r, Ok((granted, 0)));
        assert_eq!(turns, 1);
        assert!(__lease_state_for_tests(granted) == LeaseState::Active);
        assert!(__lease_waiters_for_tests().is_empty());

        // Already pending: the fast path never blocks and registers nothing.
        __lease_reset_for_tests();
        let pending = lease_grant(0, LESSOR, LESSEE, 0).unwrap();
        let r = lease_accept_wait(LESSEE, LESSOR, || panic!("blocked with a lease pending"));
        assert_eq!(r, Ok((pending, 0)));
        assert!(__lease_waiters_for_tests().is_empty());
    }

    /// Normal exhaustion is unchanged: eight wakes with nothing from the
    /// named lessor, then an answer.
    ///
    /// Canary: drop the `lease_accept_cancel` at `lease_accept_wait`'s exit.
    #[test]
    fn an_accept_nobody_grants_to_gives_up_after_its_turns_and_deregisters() {
        let _g = setup();
        let mut from_other = Vec::new();
        let r = lease_accept_wait(LESSEE, LESSOR, || {
            // Each turn: another lessor's grant stamps the lessee before its
            // block, which returns with nothing from LESSOR.
            from_other.push(lease_grant(0, OTHER_LESSOR, LESSEE, 0).unwrap());
        });
        assert_eq!(r, Err(LeaseAcceptError::TurnsExhausted));
        assert_eq!(from_other.len(), LEASE_ACCEPT_TURNS as usize);
        assert!(
            __lease_waiters_for_tests().is_empty(),
            "an accept that ran out of turns left its registration"
        );
        // The other lessor's leases were neither taken nor dropped.
        for id in from_other {
            assert!(__lease_state_for_tests(id) == LeaseState::Pending);
        }
    }

    /// Canary: drop the sweep's `w.lessee == tid` branch. The dead lessee's
    /// registration then outlives it, and the self-accept is marked and woken.
    #[test]
    fn a_lessee_that_exits_while_accepting_leaves_no_registration() {
        let _g = setup();
        assert_eq!(lease_accept_begin(LESSEE, LESSOR), LeaseAcceptBegin::Registered);
        lease_release_all(LESSEE); // the lessee's own exit hook
        assert!(__lease_waiters_for_tests().is_empty());
        azos_sched::shim_reset();
        lease_release_all(LESSOR);
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());

        // A self-accept (lessee == lessor) is dropped, not marked and woken.
        assert_eq!(lease_accept_begin(7, 7), LeaseAcceptBegin::Registered);
        azos_sched::shim_reset();
        lease_release_all(7);
        assert!(__lease_waiters_for_tests().is_empty());
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());
    }

    /// Canary: drop `w.lessor == tid` from the sweep's mark.
    #[test]
    fn another_lessors_exit_neither_marks_nor_wakes_an_accept() {
        let _g = setup();
        assert_eq!(lease_accept_begin(LESSEE, LESSOR), LeaseAcceptBegin::Registered);
        azos_sched::shim_reset();
        lease_release_all(OTHER_LESSOR);
        assert_eq!(__lease_waiters_for_tests(), vec![(LESSEE, LESSOR, false)]);
        assert!(azos_sched::shim_lease_accept_wakes().is_empty());
        assert_eq!(lease_accept_poll(LESSEE, LESSOR), LeaseAcceptPoll::StillWaiting);
        // A registration naming LESSOR does not cover a wait on another lessor.
        assert_eq!(lease_accept_poll(LESSEE, OTHER_LESSOR), LeaseAcceptPoll::NotRegistered);
    }

    /// `lease_accept_begin` polls and registers in ONE `LEASES` hold.
    ///
    /// No outcome test separates this from two holds: the interleavings a
    /// split adds (a grant and the lessor's exit both landing between the
    /// poll and the registration) end in the table and registry state the
    /// single hold also reaches from another order (an accept that started
    /// after the grant and the exit). So the shape is pinned on the source,
    /// as `tests/host/sched-policy-tests` pins text of `scheduler.rs`.
    ///
    /// Canary: take the lock twice, once around `take_pending` and once
    /// around the registration.
    #[test]
    fn accept_begin_polls_and_registers_in_one_hold() {
        let src = include_str!("lease.rs");
        let start = src.find("pub fn lease_accept_begin(").expect("lease_accept_begin");
        let rest = &src[start..];
        let body = &rest[..rest.find("\n}\n").expect("end of lease_accept_begin")];
        assert_eq!(body.matches("lock_irqsave").count(), 1, "more than one LEASES hold");
        assert!(!body.contains("drop("), "the guard is dropped inside the function");
        let lock = body.find("lock_irqsave").unwrap();
        let poll = body.find("take_pending(").expect("the poll");
        let register = body.find("WaiterState::Waiting").expect("the registration");
        assert!(lock < poll && poll < register, "poll and registration not under the one hold");
    }

    #[test]
    fn self_lease_is_freed_not_expired() {
        let _g = setup();
        let id = grant_and_accept(7, 7);
        lease_release_all(7);
        assert!(__lease_state_for_tests(id) == LeaseState::Free);
    }

    #[test]
    fn release_all_ignores_uninvolved_tasks_and_free_slots() {
        let _g = setup();
        let id = grant_and_accept(LESSOR, LESSEE);
        lease_release_all(999);
        assert!(__lease_state_for_tests(id) == LeaseState::Active);
        assert!(azos_sched::shim_wq_wakes().is_empty());
        // NO_TID must never be treated as an owner of the free slots.
        lease_release_all(NO_TID);
        assert!(__lease_state_for_tests(id) == LeaseState::Active);
        for i in 1..MAX_LEASES {
            assert!(__lease_state_for_tests(i) == LeaseState::Free);
        }
    }

    // ── IPC-3: the leak this closes ────────────────────────────────────────

    #[test]
    fn exhausting_the_table_then_killing_the_owner_makes_slots_grantable_again() {
        let _g = setup();
        for i in 0..MAX_LEASES {
            assert!(lease_grant(0, LESSOR, LESSEE, 0).is_some(), "slot {i}");
        }
        // Table full — this is the state a board reached permanently before
        // IPC-3, after MAX_LEASES tasks died holding a lease.
        assert!(lease_grant(0, LESSOR, LESSEE, 0).is_none());

        lease_release_all(LESSOR);

        assert!(lease_grant(0, 50, 51, 0).is_some());
        assert_eq!(lease_active_count(), 0);
    }

    #[test]
    fn exhausting_via_dead_lessees_is_reclaimed_by_the_lessor_freeing() {
        let _g = setup();
        for _ in 0..MAX_LEASES {
            let id = lease_grant(0, LESSOR, LESSEE, 0).unwrap();
            lease_accept(LESSEE, LESSOR).unwrap();
            let _ = id;
        }
        assert!(lease_grant(0, LESSOR, LESSEE, 0).is_none());
        // Lessee dies: entries become Expired but stay allocated by design.
        lease_release_all(LESSEE);
        assert!(lease_grant(0, LESSOR, LESSEE, 0).is_none());
        // The lessor then dies (or frees) and the table comes back.
        lease_release_all(LESSOR);
        assert!(lease_grant(0, 60, 61, 0).is_some());
    }

    // ── lease_tick ─────────────────────────────────────────────────────────

    /// Scratch buffer for the out-param, plus the ISR's own drain shape.
    fn tick(now: u64) -> Vec<u32> {
        let mut out = [NO_TID; MAX_LEASES];
        let n = lease_tick(now, &mut out);
        assert!(n <= MAX_LEASES);
        out[..n].to_vec()
    }

    #[test]
    fn tick_expires_active_and_pending_leases_past_their_deadline() {
        let _g = setup();
        // Accepted, with a deadline. Granted through the public API rather
        // than by poking `expire_ticks` under the lock: a direct write would
        // bypass `refresh_deadline_count` and leave the early-exit counter
        // stale — the test would then be exercising a state the kernel can
        // never reach.
        let active = lease_grant(0, LESSOR, LESSEE, 100).unwrap();
        assert_eq!(lease_accept(LESSEE, LESSOR).unwrap().0, active);
        let pending = lease_grant(0, 20, 21, 100).unwrap();
        let never = lease_grant(0, 30, 31, 0).unwrap(); // 0 = no expiry

        let expired = tick(200);

        assert!(__lease_state_for_tests(active) == LeaseState::Expired);
        // Pending used to be skipped, so a lessor that granted with a deadline
        // to a lessee that never accepted slept past its own deadline.
        assert!(__lease_state_for_tests(pending) == LeaseState::Expired);
        assert!(__lease_state_for_tests(never) == LeaseState::Pending);
        assert!(expired.contains(&LESSOR));
        assert!(expired.contains(&20));
        assert!(!expired.contains(&30), "a lease with no deadline was expired");
        assert_eq!(expired.len(), 2);
    }

    #[test]
    fn tick_before_the_deadline_changes_nothing() {
        let _g = setup();
        let id = lease_grant(0, LESSOR, LESSEE, 500).unwrap();
        assert!(tick(499).is_empty());
        assert!(__lease_state_for_tests(id) == LeaseState::Pending);
    }

    // ── The early-exit counter (the 157-instruction fix) ───────────────────
    //
    // The counter is what lets `lease_tick` return before it touches the
    // lock. If it can ever read low while a deadline is live, a lease stops
    // expiring and `lease_wait_return` sleeps past the bound `expire_ticks`
    // exists to provide — so the invariant is asserted directly, on every
    // path that writes lease state, and not merely inferred from behaviour.

    /// Ground truth, recomputed from the table by a route that shares no code
    /// with `refresh_deadline_count`.
    fn counted_by_hand() -> usize {
        let t = LEASES.lock_irqsave();
        t.entries
            .iter()
            .filter(|e| {
                (e.state == LeaseState::Pending || e.state == LeaseState::Active)
                    && e.expire_ticks != 0
            })
            .count()
    }

    fn assert_counter_agrees(what: &str) {
        assert_eq!(
            lease_deadline_count(),
            counted_by_hand(),
            "DEADLINE_LEASES drifted from the table after {what}"
        );
    }

    #[test]
    fn the_early_exit_counter_tracks_every_state_transition() {
        let _g = setup();
        assert_eq!(lease_deadline_count(), 0);

        let a = lease_grant(0, LESSOR, LESSEE, 500).unwrap();
        assert_counter_agrees("grant with a deadline");
        assert_eq!(lease_deadline_count(), 1);

        // A lease with no deadline is invisible to the ISR and must not arm it.
        let b = lease_grant(0, 40, 41, 0).unwrap();
        assert_counter_agrees("grant without a deadline");
        assert_eq!(lease_deadline_count(), 1);

        // Pending → Active keeps the deadline live.
        assert_eq!(lease_accept(LESSEE, LESSOR).unwrap().0, a);
        assert_counter_agrees("accept");
        assert_eq!(lease_deadline_count(), 1);

        // Active → Returned retires it.
        assert_eq!(lease_return(a, LESSEE, false), Some(LESSOR));
        assert_counter_agrees("return");
        assert_eq!(lease_deadline_count(), 0);

        // ...and with the counter at zero the ISR really does nothing.
        assert!(tick(u64::MAX).is_empty());

        // Free of a deadline-less lease leaves it at zero.
        assert!(lease_free(b, 40, false));
        assert_counter_agrees("free");

        // Expiry through the tick itself retires the deadline.
        lease_grant(0, 50, 51, 10).unwrap();
        assert_eq!(lease_deadline_count(), 1);
        assert_eq!(tick(10), vec![50]);
        assert_counter_agrees("tick expiry");
        assert_eq!(lease_deadline_count(), 0);

        // Free of a still-armed lease retires it too.
        let d = lease_grant(0, 60, 61, 900).unwrap();
        assert_eq!(lease_deadline_count(), 1);
        assert!(lease_free(d, 60, false));
        assert_counter_agrees("free of an armed lease");
        assert_eq!(lease_deadline_count(), 0);

        // And both branches of the task-exit sweep.
        let e = lease_grant(0, 70, 71, 900).unwrap();
        let f = lease_grant(0, 80, 81, 900).unwrap();
        assert_eq!(lease_deadline_count(), 2);
        lease_release_all(71); // lessee dies → Expired
        assert_counter_agrees("lessee exit");
        assert_eq!(lease_deadline_count(), 1);
        lease_release_all(80); // lessor dies → slot freed
        assert_counter_agrees("lessor exit");
        assert_eq!(lease_deadline_count(), 0);
        let _ = (e, f);
    }

    /// A full table of armed leases: the counter saturates at `MAX_LEASES`,
    /// the tick writes exactly `MAX_LEASES` TIDs, and nothing overruns the
    /// caller's buffer.
    #[test]
    fn a_full_table_expiring_at_once_fills_the_buffer_exactly() {
        let _g = setup();
        for i in 0..MAX_LEASES {
            lease_grant(0, 100 + i as u32, 200 + i as u32, 5).unwrap();
        }
        assert_eq!(lease_deadline_count(), MAX_LEASES);

        let mut out = [NO_TID; MAX_LEASES];
        let n = lease_tick(5, &mut out);
        assert_eq!(n, MAX_LEASES);
        for i in 0..MAX_LEASES {
            assert_eq!(out[i], 100 + i as u32);
        }
        assert_eq!(lease_deadline_count(), 0);
        // Idempotent: a second tick expires nothing and takes the early exit.
        assert!(tick(u64::MAX).is_empty());
    }

    /// The early exit must never skip a deadline that is genuinely live: with
    /// the counter armed, every `now` from before to after the deadline
    /// behaves exactly as the unconditional loop would have.
    #[test]
    fn the_early_exit_never_skips_a_live_deadline() {
        let _g = setup();
        for deadline in [1u64, 2, 1000, u64::MAX] {
            __lease_reset_for_tests();
            let id = lease_grant(0, LESSOR, LESSEE, deadline).unwrap();
            assert_eq!(lease_deadline_count(), 1);
            // Every tick strictly before the deadline leaves it armed.
            for now in [0u64, deadline.saturating_sub(1)] {
                if now < deadline {
                    assert!(tick(now).is_empty(), "deadline {deadline} fired early at {now}");
                    assert_eq!(lease_deadline_count(), 1);
                }
            }
            // The tick *at* the deadline fires it (`now >= expire`).
            assert_eq!(tick(deadline), vec![LESSOR]);
            assert!(__lease_state_for_tests(id) == LeaseState::Expired);
            assert_eq!(lease_deadline_count(), 0);
        }
    }
}
