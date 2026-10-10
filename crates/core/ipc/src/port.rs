// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Event Ports — multiplex wait on multiple sources (AQ5).
//!
//! Inspired by Zircon `zx_port` and macOS `kqueue`.
//! A port aggregates events from channels, rings, timers, and IRQs.
//! `port_wait()` blocks until ANY bound source has an event.
//!
//! # Object generation (RFC-0040 gap 1)
//!
//! Every port carries a generation, stamped at create from its own slot's
//! generation source (`PortTable::next_gen`, per slot, never reset) and
//! cleared when the slot is freed. A `Cap<Port>`, an IRQ→port binding and the
//! `SYS_PORT_WAIT` sleeper hold the packed `(index, generation)` reference
//! (`objref::PORT`), and every `_ref` function compares it inside the `PORTS`
//! hold that does the work: a reference to a destroyed port, or to its index
//! after another port took it, answers `Stale` and touches nothing.
//!
//! # Waiters
//!
//! A task waiting on a port (`SYS_PORT_WAIT`) registers as a waiter of the
//! port's packed reference, keyed by its task-pool slot, in the same `PORTS`
//! hold as its empty poll ([`port_wait_begin_at`]). Queueing an event and
//! destroying or releasing the port detach the port's waiters under `PORTS`
//! and wake each by TID after releasing it
//! (`azos_sched::wait::wake_port_waiter`), which stamps a waiter that has
//! not blocked yet: an event between the poll and the block is not lost.
//! [`port_wait_end_at`] deregisters on every exit.
//!
//! # Sources (wave 11, PORTWAIT)
//!
//! A port reports four kinds of source; the 16-byte event carries the key the
//! source was bound with and its type (`PORT_EVENT_*`):
//!
//! - **IRQ** (`irq_bind`): every delivery queues one event on the port's
//!   bounded queue ([`PORT_MAX_SOURCES`] deep; a delivery that finds it full
//!   is dropped, and still wakes). Edge-triggered, one event per interrupt.
//! - **Channel** and **io_ring**: a slot of the port's source table, holding
//!   one `pending` bit. Every message sent on the channel, and every submit
//!   or poller pass that writes at least one completion on the ring, sets the
//!   bit (`port_signal`, through the object's [`PortLink`]); delivering the
//!   event clears it. Edge-triggered and coalesced: one event stands for "at
//!   least one message (completion) arrived since the last event from this
//!   source", so the receiver drains the channel (CQ) until it is empty after
//!   each event. A message sent after the event was taken sets the bit again,
//!   which is why that drain cannot lose one. The bit is also set at bind
//!   time when the object already holds a message (completion), checked under
//!   the object's own lock in the hold that stores the link.
//! - **Timer**: a slot holding an absolute deadline in nanoseconds on the
//!   time counter (`SYS_SLEEP_UNTIL`'s unit). Evaluated lazily, by every poll
//!   and wait against the caller's clock; a waiter's sleep is bounded by the
//!   earliest armed deadline. One-shot: delivering the event frees the slot.
//!   Binding a timer with a key already armed re-arms it.
//!
//! Queued (IRQ) events and table sources alternate when both are ready, so a
//! storm on one class does not starve the other; the table is scanned
//! round-robin from the slot after the last one delivered.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use azos_sync::SpinLock;
pub use azos_limits::MAX_PORTS;
use azos_limits::MAX_TASKS;

use crate::cap::objref;
use crate::cap::{CapError, CapKind, CapPerms};
pub use crate::port_link::PortLink;

/// How a `Cap<Port>` packs `(index, generation)`: the smallest index width
/// holding `0..MAX_PORTS`, the rest generation (`objref::PORT`; edge 5 + 27,
/// fleet 9 + 23).
const LAYOUT: objref::Layout = objref::PORT;
const _: () = assert!(MAX_PORTS as u64 <= 1u64 << LAYOUT.idx_bits());

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum sources bound to one port, and the depth of its queue of IRQ
/// events. Kconfig `MAX_PORT_SOURCES` (default 16, range 2..=64).
pub const PORT_MAX_SOURCES: usize = azos_limits::MAX_PORT_SOURCES;
// A source's slot travels in `PortLink::slot`, a `u8`.
const _: () = assert!(PORT_MAX_SOURCES >= 2 && PORT_MAX_SOURCES <= 64);

// `PortEvent::source_type` values (`azos_abi::syscall_nr`, their one home):
// a channel, an io_ring, an IRQ (the value `irq_bind` writes), a timer, an
// endpoint's no-senders notice, a source that is gone (wave 15 N5b).
pub use azos_abi::syscall_nr::{
    PORT_EVENT_CHANNEL, PORT_EVENT_IRQ, PORT_EVENT_NO_SENDERS, PORT_EVENT_RING, PORT_EVENT_SOURCE_GONE,
    PORT_EVENT_TIMER,
};

/// The code of a no-senders notice (`PortEvent::code`, a positive errno).
const CODE_NO_SENDERS: u16 = azos_abi::error::Errno::ENOSENDERS as u16;

/// Runtime canary `port-no-vanish`: a gone source is left bound and silent
/// ([`port_source_gone`] and [`port_post_gone`] do nothing).
static CANARY_NO_VANISH: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Arm the `port-no-vanish` canary (runtime `canary=` flag, boot only).
pub fn canary_no_vanish() {
    CANARY_NO_VANISH.store(true, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// What kind of source is bound to the port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortSourceKind {
    None,
    /// A channel, by its packed `(index, generation)` reference.
    Channel(u32),
    /// An io_ring, by its packed `(index, generation)` reference.
    Ring(u32),
    /// A PLIC IRQ number. Only the untyped [`port_bind`] stores it; the typed
    /// bind keeps IRQ bindings in `irq_bind`, which queues events instead.
    Irq(u32),
    /// An absolute deadline, in nanoseconds on the time counter.
    Timer(u64),
    /// An endpoint's notices, by its packed `(index, generation)` reference
    /// (wave 15 N5b): pending when no send capability to it is left.
    Endpoint(u32),
}

impl PortSourceKind {
    /// The `PortEvent::source_type` this kind reports, 0 for `None`.
    pub const fn event_type(&self) -> u8 {
        match self {
            PortSourceKind::None => 0,
            PortSourceKind::Channel(_) => PORT_EVENT_CHANNEL,
            PortSourceKind::Ring(_) => PORT_EVENT_RING,
            PortSourceKind::Irq(_) => PORT_EVENT_IRQ,
            PortSourceKind::Timer(_) => PORT_EVENT_TIMER,
            PortSourceKind::Endpoint(_) => PORT_EVENT_NO_SENDERS,
        }
    }
}

/// A source bound to a port.
#[derive(Clone, Copy)]
pub struct PortSource {
    pub kind: PortSourceKind,
    pub user_key: u64,    // opaque key returned with events
    /// A channel or io_ring source has something to report (see the module
    /// doc, "Sources").
    pub pending: bool,
    /// The capability handle the source was bound with, reported as the
    /// event's `source_id` (0 for a timer).
    pub handle: u32,
    /// Whose capability made this binding (wave 11, LEASE3): the holder's
    /// cap-table slot + 1, `0` for none (a timer, an untyped or kernel bind).
    /// The binding dies when that capability is revoked or its table wiped,
    /// and follows it when it moves ([`port_cap_event`]).
    pub binder: u16,
    /// Not 0: the source is gone (wave 15 N5b) — destroyed (`EREVOKED`) or
    /// its owner died (`EPEERDIED`) — and this is the code its one
    /// `PORT_EVENT_SOURCE_GONE` event carries. The slot is ready until that
    /// event is taken, then freed; no producer reaches it meanwhile
    /// ([`link_slot_locked`] skips it).
    pub gone: u16,
}

/// An event delivered from a port.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct PortEvent {
    pub key: u64,         // user_key from the source
    pub source_type: u8,  // PORT_EVENT_*: 1=channel, 2=ring, 3=irq, 4=timer, 5=no senders, 6=gone
    pub source_id: u32,
    /// A positive errno for a notice (`ENOSENDERS`, `EREVOKED`,
    /// `EPEERDIED`), 0 for an ordinary event. Wire bytes 10..12.
    pub code: u16,
}

/// Kernel state for one port.
pub struct Port {
    pub sources: [PortSource; PORT_MAX_SOURCES],
    /// Occupied entries of `sources` (kind not `None`).
    pub source_count: usize,
    /// The source-table slot the next scan starts from.
    pub cursor: u8,
    /// The next delivery tries the source table before the IRQ queue: set
    /// after a queued event was delivered, cleared after a source's was.
    pub sources_first: bool,
    pub owner_task: usize,
    pub active: bool,
    /// Pending events (written by wake, read by port_wait).
    pub pending: [PortEvent; PORT_MAX_SOURCES],
    pub pending_count: AtomicU32,
    /// Stamped at create from this slot's own entry in
    /// `PortTable::next_gen`, 0 while the slot is free (RFC-0040 gap 1,
    /// revised): per-slot, so this index's generation only ever grows
    /// *between wraps*. Within one wrap cycle no two incarnations at this
    /// index share a generation, but a wrap (this slot's own targeted sweep,
    /// `objref::sweep_index`, owner decision 2026-09-26) resets it to 1 —
    /// deliberately, so the slot is reused rather than lost — which is why
    /// `epoch` below still exists, scoped to this one slot now instead of the
    /// whole pool.
    pub generation: u32,
    /// This slot's own wrap counter, stamped at create from
    /// `PortTable::epoch[i]`. Bumped only when slot `i` itself wraps (never on
    /// an ordinary create/destroy), so it is what tells apart two incarnations
    /// that legitimately drew the same post-wrap generation at the same
    /// index. Needed because a port binding
    /// ([`crate::irq_bind::IrqTarget::QueueToPortRef`]) or a waiter
    /// registration ([`PortWaiter`]) can outlive the port it names and is not
    /// reached by `sweep_index` (which clears `Cap<Port>` entries in cap
    /// tables, not these); `(index, generation)` alone would let a binding
    /// made before a wrap match an unrelated port made after it, at the same
    /// index and generation.
    pub epoch: u32,
    /// Head of this port's waiter list: a task-pool slot in
    /// `PortTable::waiters`, or `NO_WAITER`.
    pub waiter_head: u16,
    /// Registrations on the list, at most [`PORT_MAX_WAITERS`].
    pub waiter_count: u8,
}

/// A free source-table entry.
const EMPTY_SRC: PortSource = PortSource {
    kind: PortSourceKind::None,
    user_key: 0,
    pending: false,
    handle: 0,
    binder: 0,
    gone: 0,
};

/// Sources whose `binder` is set, machine-wide; changed only with `PORTS`
/// held. Lets [`port_cap_event`] — called on every revoke, move and table
/// wipe (each task exit) — return without walking the table when no binding
/// was made through a capability.
static CAP_BOUND: AtomicUsize = AtomicUsize::new(0);
// `PortSource::binder` is a cap-table slot + 1 in a `u16`.
const _: () = assert!(MAX_TASKS < u16::MAX as usize);

/// Sources of `port` bound through a capability.
fn cap_bound_in(port: &Port) -> usize {
    port.sources.iter().filter(|s| s.kind != PortSourceKind::None && s.binder != 0).count()
}

/// Clear port `i` (`Port::empty()`), keeping [`CAP_BOUND`] exact. `PORTS` held.
fn clear_port_locked(t: &mut PortTable, i: usize) {
    let n = cap_bound_in(&t[i]);
    if n != 0 {
        CAP_BOUND.fetch_sub(n, Ordering::Relaxed);
    }
    t[i] = Port::empty();
}

impl Port {
    pub const fn empty() -> Self {
        const EMPTY_EVT: PortEvent = PortEvent { key: 0, source_type: 0, source_id: 0, code: 0 };
        Self {
            sources: [EMPTY_SRC; PORT_MAX_SOURCES],
            source_count: 0,
            cursor: 0,
            sources_first: false,
            owner_task: usize::MAX,
            active: false,
            pending: [EMPTY_EVT; PORT_MAX_SOURCES],
            pending_count: AtomicU32::new(0),
            generation: 0,
            epoch: 0,
            waiter_head: NO_WAITER,
            waiter_count: 0,
        }
    }
}

/// Most tasks one port may have waiting at once.
///
/// A task waits in one syscall at a time. The waiters of a port are kernel
/// callers and the holders of a `Cap<Port>` naming it, waiting in
/// `SYS_PORT_WAIT_TYPED`, and they are bounded by this. It fixes the stack a wake needs (`[u32; PORT_MAX_WAITERS]`),
/// which runs in IRQ context (`irq_bind::irq_dispatch` → [`port_queue_event_bound`]).
/// A wait past it is refused with `Full` before the caller blocks.
pub const PORT_MAX_WAITERS: usize = 8;

/// The end of a port's waiter list.
const NO_WAITER: u16 = u16::MAX;
const _: () = assert!(MAX_TASKS < NO_WAITER as usize);
const _: () = assert!(PORT_MAX_WAITERS <= u8::MAX as usize);

/// Where a waiter registration stands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WaiterState {
    /// No registration in this task-pool slot.
    Free,
    /// On its port's waiter list.
    Waiting,
    /// Detached by an event queued on the port; its wake follows.
    Woken,
    /// Detached because the port was destroyed or released; the second half
    /// answers `Stale` without polling.
    Gone,
}

/// One task's registration as a waiter of a port, indexed by task-pool slot.
#[derive(Clone, Copy)]
struct PortWaiter {
    tid: u32,
    /// The packed `(index, generation)` reference the task blocks on.
    port: u32,
    /// The port's epoch at registration: with `port`, the incarnation. Needed
    /// because a wrap resets `generation` to 1 (per-slot, not pool-wide) —
    /// without this, a waiter registered before a wrap could match a
    /// different port that legitimately drew the same post-wrap generation
    /// at the same index.
    epoch: u32,
    /// Next slot on the same port's list, or `NO_WAITER`.
    next: u16,
    state: WaiterState,
    /// The task blocks on `WaitReason::Timer` (its wait has a deadline, or the
    /// port an armed timer), not on `WaitReason::Port`: its wake is
    /// `wake_port_timed_waiter`, whose predicate matches that reason.
    timed: bool,
}

impl PortWaiter {
    const fn empty() -> Self {
        Self { tid: 0, port: 0, epoch: 0, next: NO_WAITER, state: WaiterState::Free, timed: false }
    }
}

/// The port pool and its waiter registry, under one lock (`PORTS`), so a
/// registration adds no lock and no lock-order edge.
///
/// `waiters` has one entry per task-pool slot, since a task waits in at most
/// one syscall: 16 B each, `MAX_TASKS` × 16 B = 512 B / 1 KiB / 64 KiB of BSS
/// for embedded / edge / fleet (32 / 64 / 4096 tasks). The registry therefore
/// cannot fill. Each port threads its waiters through `next`
/// (`Port::waiter_head: u16`, `Port::waiter_count: u8`).
struct PortTable {
    ports: [Port; MAX_PORTS],
    waiters: [PortWaiter; MAX_TASKS],
    /// Per-slot generation source (RFC-0040 gap 1, revised, owner decision
    /// 2026-09-26): entry `i` is the generation index `i`'s *next* create
    /// will stamp. Starts at 1 (`0` doubles as "mid-sweep"), never reset by an
    /// ordinary destroy — only by that slot's own targeted wrap sweep. See
    /// `objref`'s module doc ("Per-slot generations...").
    next_gen: [u32; MAX_PORTS],
    /// Per-slot wrap counter: entry `i` is bumped only when slot `i` itself
    /// wraps, stamped into `Port::epoch` at create. See `Port::epoch`.
    epoch: [u32; MAX_PORTS],
}

impl core::ops::Index<usize> for PortTable {
    type Output = Port;
    fn index(&self, i: usize) -> &Port {
        &self.ports[i]
    }
}

impl core::ops::IndexMut<usize> for PortTable {
    fn index_mut(&mut self, i: usize) -> &mut Port {
        &mut self.ports[i]
    }
}

/// The TIDs of the waiters detached from one port, woken after `PORTS` is
/// released.
struct Detached {
    /// `(tid, timed)` of each detached waiter.
    tids: [(u32, bool); PORT_MAX_WAITERS],
    n: usize,
}

/// Wake one detached waiter the way it blocks: on `Timer` (a deadline) or on
/// `Port(r)`.
#[inline]
fn wake_waiter(tid: u32, timed: bool, r: u32) {
    if timed {
        azos_sched::wait::wake_port_timed_waiter(tid);
    } else {
        azos_sched::wait::wake_port_waiter(tid, r);
    }
}

impl Detached {
    const NONE: Detached = Detached { tids: [(0, false); PORT_MAX_WAITERS], n: 0 };

    /// Wake each detached waiter by TID with the reason it blocks on.
    /// Called with `PORTS` released.
    fn wake(&self, r: u32) {
        for &(tid, timed) in &self.tids[..self.n] {
            wake_waiter(tid, timed, r);
        }
    }
}

/// Global port array.
///
/// Protected by a single `SpinLock` covering the whole table (coarse-
/// grained, same shape as `channel.rs`'s `POOL`). Unlike `POOL` though,
/// this lock is shared with IRQ context: `port_queue_event_bound()` is called
/// from `irq_bind::irq_dispatch()`, itself invoked from the PLIC IRQ
/// handler, while `port_bind()` / `port_poll()` / `port_create()` /
/// `port_destroy()` / `port_owner()` / `port_has_events()` all run in
/// syscall context. Every accessor below therefore uses `lock_irqsave()`,
/// never plain `lock()`: if a syscall on hart N took a plain lock and an
/// IRQ then fired on that same hart N before release, the IRQ handler
/// would spin forever on a lock whose holder can't run again until the
/// IRQ handler returns — a same-hart deadlock. `lock_irqsave()` avoids
/// this by disabling local interrupts for the duration of the critical
/// section (see `azos_sync::spinlock`).
///
/// **Wakes run after `PORTS` is released** (`Detached::wake`), never under
/// it: no path nests `PORTS` with the scheduler's `CPU_LOCKS`.
/// `azos_sched` does not depend on `azos_ipc`
/// (`crates/core/sched/Cargo.toml`), so no scheduler path can take `PORTS` either.
/// The waiter registry lives inside this lock ([`PortTable`]).
const EMPTY_PORT: Port = Port::empty();
const EMPTY_WAITER: PortWaiter = PortWaiter::empty();
static PORTS: SpinLock<PortTable> = SpinLock::new(PortTable {
    ports: [EMPTY_PORT; MAX_PORTS],
    waiters: [EMPTY_WAITER; MAX_TASKS],
    next_gen: [1u32; MAX_PORTS],
    epoch: [0u32; MAX_PORTS],
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new port. Returns port_id or None.
/// Most ports ONE task may hold at once.
///
/// **The obligation the minting rule creates.** RFC-0003's addendum states it
/// plainly: a task may be handed a capability over an object it just created,
/// and *minting without a per-task quota is exhaustion*. `MAX_PORTS` bounds
/// the pool for the WHOLE MACHINE, so before this a single ring-3 program
/// calling `port_create` in a loop took every slot and denied ports to
/// everyone — the kernel's own users included.
///
/// Half the pool, mirroring `MAX_SOCKETS_PER_TASK` and `MAX_FDS_PER_TASK`:
/// enough for a program doing ordinary work, never enough for one task to lock
/// the machine out.
pub const MAX_PORTS_PER_TASK: usize = MAX_PORTS / 2;

pub fn port_create(owner_task: usize) -> Option<u32> {
    create_core(owner_task).map(|(r, _)| LAYOUT.idx(r))
}

/// [`port_create`], answering the packed `(index, generation)` reference of
/// the new port: the value a `Cap<Port>` stores.
pub fn port_create_ref(owner_task: usize) -> Option<u32> {
    create_core(owner_task).map(|(r, _)| r)
}

/// The create body: `(packed reference, epoch)` — the epoch is this slot's
/// own wrap counter at the moment of this create (`Port::epoch`'s doc), which
/// a port binding or a waiter registration must carry alongside the
/// reference.
///
/// **Per-slot generation, swept only at its own index (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26).** Each slot's generation is its own
/// (`PortTable::next_gen`); when slot `i`'s reaches `LAYOUT.gen_max()`, this
/// marks it mid-sweep (`next_gen[i] = 0`, which the free-slot scan already
/// treats as unavailable), releases `PORTS`, runs
/// `objref::sweep_index(CapKind::Port, i)` — which revokes only the stale
/// `Cap<Port>`s left over at index `i`, nothing live — bumps `epoch[i]` (so a
/// binding or waiter recorded before the wrap cannot match the port that
/// reuses index `i` at the same post-wrap generation), resets `next_gen[i]`
/// to `1`, and retries. At most two passes: the second always finds `Gen(1)`.
/// See `objref`'s module doc for the full protocol and the accepted
/// O(`MAX_TASKS`) cost of that walk.
fn create_core(owner_task: usize) -> Option<(u32, u32)> {
    // Two passes at most: the second runs only after this call's own
    // per-slot wrap sweep finishes.
    for _ in 0..2 {
        let mut ports = PORTS.lock_irqsave();
        // Counted under the SAME lock that allocates. Checking the quota and
        // then taking the lock would let two of a task's own threads both
        // pass the check and both allocate, which is the bug one level down.
        // Same rule and same reasoning as `socket_create`'s quota.
        let held = ports.ports.iter().filter(|p| p.active && p.owner_task == owner_task).count();
        if held >= MAX_PORTS_PER_TASK {
            return None;
        }
        // `next_gen[i] != 0` excludes a slot this call has marked mid-sweep.
        let slot = (0..MAX_PORTS).find(|&i| !ports[i].active && ports.next_gen[i] != 0)?;
        // Taken once a free slot is known, so a full table or a quota
        // refusal consumes none.
        let gen = match objref::take_slot_gen(ports.next_gen[slot], LAYOUT) {
            objref::SlotGen::Gen(g) => g,
            objref::SlotGen::Wrap => {
                ports.next_gen[slot] = 0;
                drop(ports);
                objref::sweep_index(CapKind::Port, slot as u32);
                ports = PORTS.lock_irqsave();
                ports.epoch[slot] = ports.epoch[slot].wrapping_add(1);
                ports.next_gen[slot] = 1;
                continue;
            }
        };
        ports.next_gen[slot] = gen + 1;
        let epoch = ports.epoch[slot];
        ports[slot] = Port::empty();
        ports[slot].owner_task = owner_task;
        ports[slot].active = true;
        ports[slot].generation = gen;
        ports[slot].epoch = epoch;
        return Some((LAYOUT.pack(slot as u32, gen), epoch));
    }
    None
}

/// Resolve a packed reference to its slot, with `PORTS` held by the caller.
///
/// `Stale` unless the slot is active and carries the reference's generation: a
/// freed slot (generation 0), a slot reused by another port, and a bare
/// in-range index (generation 0) all answer `Stale`.
fn live_index(ports: &PortTable, r: u32) -> Result<usize, PortCapError> {
    let i = LAYOUT.idx(r) as usize;
    let g = LAYOUT.gen(r);
    if g == 0 || i >= MAX_PORTS || !ports[i].active || ports[i].generation != g {
        return Err(PortCapError::Cap(CapError::Stale));
    }
    Ok(i)
}

/// The packed reference of live port `port_id`, or `None` if its slot is not
/// active: for a caller holding a validated index that needs the value a
/// `Cap<Port>` stores. Do not mint a capability from it (see
/// [`port_ref_epoch`]).
pub fn port_ref(port_id: u32) -> Option<u32> {
    port_ref_epoch(port_id).map(|(r, _)| r)
}

/// [`port_ref`] and this slot's own wrap epoch ([`Port::epoch`]), from one
/// `PORTS` hold.
pub fn port_ref_epoch(port_id: u32) -> Option<(u32, u32)> {
    if port_id as usize >= MAX_PORTS { return None; }
    // Masked after the check (Spectre v1, `azos_limits::nospec`).
    let port_id = azos_limits::nospec::array_index_nospec(port_id as usize, MAX_PORTS) as u32;
    let ports = PORTS.lock_irqsave();
    let port = &ports[port_id as usize];
    if port.active { Some((LAYOUT.pack(port_id, port.generation), port.epoch)) } else { None }
}

/// The epoch of the live port a packed reference names; `Stale` otherwise.
pub fn port_live_epoch(r: u32) -> Result<u32, PortCapError> {
    let ports = PORTS.lock_irqsave();
    let i = live_index(&ports, r)?;
    Ok(ports[i].epoch)
}

/// Detach every waiter of port `i`, marking each `state`; the TIDs are woken
/// after `PORTS` is released ([`Detached::wake`]). `PORTS` held.
///
/// With nobody waiting this is one read of `waiter_head`: the gate that keeps
/// an event or a destroy from waking anyone. (Before the registry each of
/// them ran `wake_by_port`'s sweep of all `MAX_TASKS` slots.)
fn detach_waiters_locked(t: &mut PortTable, i: usize, state: WaiterState) -> Detached {
    let mut d = Detached::NONE;
    let mut cur = t.ports[i].waiter_head;
    if cur == NO_WAITER {
        return d;
    }
    // The list never holds more than `PORT_MAX_WAITERS` (`port_wait_begin`).
    while cur != NO_WAITER && d.n < PORT_MAX_WAITERS {
        let w = &mut t.waiters[cur as usize];
        d.tids[d.n] = (w.tid, w.timed);
        d.n += 1;
        w.state = state;
        cur = w.next;
        w.next = NO_WAITER;
    }
    t.ports[i].waiter_head = NO_WAITER;
    t.ports[i].waiter_count = 0;
    d
}

/// Remove the registration in task-pool slot `slot`, unlinking it from its
/// port's list if it is still on one (a `Woken` or `Gone` registration is
/// detached already). `PORTS` held.
fn clear_waiter_locked(t: &mut PortTable, slot: usize) {
    let w = t.waiters[slot];
    if w.state == WaiterState::Waiting {
        // A `Waiting` registration is on the list of the port its reference
        // indexes: every path that frees a port detaches its waiters first.
        let i = LAYOUT.idx(w.port) as usize;
        if i < MAX_PORTS {
            let mut prev = NO_WAITER;
            let mut cur = t.ports[i].waiter_head;
            let mut steps = 0;
            while cur != NO_WAITER && steps < PORT_MAX_WAITERS {
                let next = t.waiters[cur as usize].next;
                if cur as usize == slot {
                    if prev == NO_WAITER {
                        t.ports[i].waiter_head = next;
                    } else {
                        t.waiters[prev as usize].next = next;
                    }
                    t.ports[i].waiter_count = t.ports[i].waiter_count.saturating_sub(1);
                    break;
                }
                prev = cur;
                cur = next;
                steps += 1;
            }
        }
    }
    t.waiters[slot] = PortWaiter::empty();
}

/// Destroy a port.
///
/// Its registered waiters are detached as gone and woken after `PORTS` is
/// released; their [`port_wait_end`] answers `Stale` (`-ECAPSTALE` from
/// `SYS_PORT_WAIT_TYPED`) instead of sleeping on a reference nothing will ever wake
/// again.
pub fn port_destroy(port_id: u32) {
    if port_id as usize >= MAX_PORTS { return; }
    let port_id = azos_limits::nospec::array_index_nospec(port_id as usize, MAX_PORTS) as u32;
    let (r, gone) = {
        let mut ports = PORTS.lock_irqsave();
        let i = port_id as usize;
        let r = LAYOUT.pack(port_id, ports[i].generation);
        // A port that is not active has no waiters: the detach reads the gate.
        let gone = detach_waiters_locked(&mut ports, i, WaiterState::Gone);
        clear_port_locked(&mut ports, i);
        (r, gone)
    };
    gone.wake(r);
}

/// [`port_destroy`] through a packed reference: `Stale` if the port at its
/// index is not the one it names (nothing is destroyed, nobody is woken).
pub fn port_destroy_ref(r: u32) -> Result<(), PortCapError> {
    let gone = {
        let mut ports = PORTS.lock_irqsave();
        let i = live_index(&ports, r)?;
        let gone = detach_waiters_locked(&mut ports, i, WaiterState::Gone);
        clear_port_locked(&mut ports, i);
        gone
    };
    gone.wake(r);
    Ok(())
}

/// Bind a source to a port.
pub fn port_bind(port_id: u32, kind: PortSourceKind, user_key: u64) -> bool {
    if port_id as usize >= MAX_PORTS { return false; }
    let port_id = azos_limits::nospec::array_index_nospec(port_id as usize, MAX_PORTS) as u32;
    // IRQ-safe: PORTS is shared with port_queue_event_bound(), which runs from
    // PLIC IRQ dispatch on the same hart. See the comment on `PORTS`.
    let mut ports = PORTS.lock_irqsave();
    let port = &mut ports[port_id as usize];
    if !port.active { return false; }
    insert_source_locked(port, kind, user_key, 0, 0).is_some()
}

/// [`port_bind`] through a packed reference: `Stale` for another incarnation,
/// `Full` when the port already has `PORT_MAX_SOURCES` sources.
pub fn port_bind_ref(r: u32, kind: PortSourceKind, user_key: u64) -> Result<(), PortCapError> {
    let mut ports = PORTS.lock_irqsave();
    let i = live_index(&ports, r)?;
    insert_source_locked(&mut ports[i], kind, user_key, 0, 0)
        .map(|_| ())
        .ok_or(PortCapError::Full)
}

/// Store a source in the first free slot of `port`'s table; its index, or
/// `None` when every slot is taken. `PORTS` held.
fn insert_source_locked(port: &mut Port, kind: PortSourceKind, user_key: u64, handle: u32, binder: u16) -> Option<usize> {
    let s = port.sources.iter().position(|src| src.kind == PortSourceKind::None)?;
    port.sources[s] = PortSource { kind, user_key, pending: false, handle, binder, gone: 0 };
    port.source_count += 1;
    if binder != 0 {
        CAP_BOUND.fetch_add(1, Ordering::Relaxed);
    }
    Some(s)
}

/// Free source slot `s` of `port`. `PORTS` held.
fn free_source_locked(port: &mut Port, s: usize) {
    if port.sources[s].kind != PortSourceKind::None {
        if port.sources[s].binder != 0 {
            CAP_BOUND.fetch_sub(1, Ordering::Relaxed);
        }
        port.sources[s] = EMPTY_SRC;
        port.source_count -= 1;
    }
}

/// Bind a channel or io_ring (`kind` names it by packed reference) to the port
/// `r` names, with `user_key` and the capability `handle` it was bound
/// through; answers the [`PortLink`] the object stores, and whether this call
/// added the source (`false`: the object was bound already and only its key
/// and handle changed — one object occupies one slot of a port).
///
/// `Stale` for another incarnation of the port, `Full` when the table has no
/// free slot. The caller stores the link in the object; if that fails it
/// undoes an added source with [`port_unbind_link`].
///
/// No binder: the binding outlives every capability. The syscall binds with
/// [`port_bind_object_as`].
pub fn port_bind_object(r: u32, kind: PortSourceKind, handle: u32, user_key: u64) -> Result<(PortLink, bool), PortCapError> {
    port_bind_object_as(r, kind, handle, user_key, None)
}

/// [`port_bind_object`] made through the capability held in cap-table slot
/// `binder` (wave 11, LEASE3): the binding is removed when that capability is
/// revoked or the table wiped, and follows it when it moves
/// ([`port_cap_event`]). The caller re-checks its capability after the bind
/// (a revoke between its resolve and this store found no binding to remove).
pub fn port_bind_object_as(
    r: u32, kind: PortSourceKind, handle: u32, user_key: u64, binder: Option<usize>,
) -> Result<(PortLink, bool), PortCapError> {
    let binder = binder.map_or(0u16, |b| (b as u16).wrapping_add(1));
    let mut ports = PORTS.lock_irqsave();
    let i = live_index(&ports, r)?;
    let epoch = ports[i].epoch;
    let port = &mut ports[i];
    let link = |s: usize| PortLink { port: r, epoch, slot: s as u8 };
    if let Some(s) = port.sources.iter().position(|src| src.kind == kind && src.gone == 0) {
        let old = port.sources[s].binder;
        if old != 0 && binder == 0 {
            CAP_BOUND.fetch_sub(1, Ordering::Relaxed);
        } else if old == 0 && binder != 0 {
            CAP_BOUND.fetch_add(1, Ordering::Relaxed);
        }
        port.sources[s].user_key = user_key;
        port.sources[s].handle = handle;
        port.sources[s].binder = binder;
        return Ok((link(s), false));
    }
    let s = insert_source_locked(port, kind, user_key, handle, binder).ok_or(PortCapError::Full)?;
    Ok((link(s), true))
}

/// The [`crate::cap_store::CapEventHook`] the kernel registers (wave 11,
/// LEASE3; PORTWAIT's owner question 1): a channel or io_ring binding dies
/// with the capability it was made through and survives a move of it.
///
///  * `Revoked` of a `Cap<Channel>`/`Cap<IoRing>`: every source that names
///    the same object and was bound from that table is freed. The object's
///    stored link then names a free slot, so its next send signals nothing
///    (`port_signal` answers false) and clears it.
///  * `Moved`: those sources now name the receiver's table, so a later revoke
///    there removes them.
///  * `Wiped` (the exit reset, a reused slot): every source bound from that
///    table is freed.
///
/// Runs with the cap-table lock(s) held; takes `PORTS` (table → pool), wakes
/// nobody. A port waiter keeps waiting for its other sources. With no
/// capability-made binding anywhere it is one atomic load.
pub fn port_cap_event(e: crate::cap_store::CapEvent) {
    use crate::cap_store::CapEvent;
    // The host canary: nothing follows or dies with the capability.
    if cfg!(feature = "port-revoke-canary") || CAP_BOUND.load(Ordering::Relaxed) == 0 {
        return;
    }
    let object = |kind: CapKind, resource: u32| match kind {
        CapKind::Channel => Some(PortSourceKind::Channel(resource)),
        CapKind::IoRing => Some(PortSourceKind::Ring(resource)),
        CapKind::Endpoint => Some(PortSourceKind::Endpoint(resource)),
        _ => None,
    };
    let tag = |slot: usize| (slot as u16).wrapping_add(1);
    let (from, to, kind) = match e {
        CapEvent::Revoked { slot, kind, resource } => match object(kind, resource) {
            Some(k) => (tag(slot), 0u16, Some(k)),
            None => return,
        },
        CapEvent::Moved { from, to, kind, resource } => match object(kind, resource) {
            Some(k) => (tag(from), tag(to), Some(k)),
            None => return,
        },
        CapEvent::Wiped { slot } => (tag(slot), 0u16, None),
    };
    let mut ports = PORTS.lock_irqsave();
    for i in 0..MAX_PORTS {
        if !ports[i].active || ports[i].source_count == 0 {
            continue;
        }
        let port = &mut ports[i];
        for s in 0..PORT_MAX_SOURCES {
            let src = port.sources[s];
            if src.kind == PortSourceKind::None || src.binder != from {
                continue;
            }
            if kind.is_some_and(|k| k != src.kind) {
                continue;
            }
            if to != 0 {
                port.sources[s].binder = to;
            } else {
                free_source_locked(port, s);
            }
        }
    }
}

/// Sources bound through a capability, machine-wide (diagnostic, host tests).
pub fn port_cap_bound_count() -> usize {
    CAP_BOUND.load(Ordering::Relaxed)
}

/// Free the source `link` names, if its slot still holds `kind` in the port
/// incarnation it names (the undo of an added [`port_bind_object`]).
pub fn port_unbind_link(link: PortLink, kind: PortSourceKind) {
    let mut ports = PORTS.lock_irqsave();
    if let Some((i, s)) = link_slot_locked(&ports, link, kind) {
        free_source_locked(&mut ports[i], s);
    }
}

/// The `(port index, source slot)` `link` names, if the port is live, of the
/// link's epoch, and the slot holds `kind`. `PORTS` held.
fn link_slot_locked(ports: &PortTable, link: PortLink, kind: PortSourceKind) -> Option<(usize, usize)> {
    let i = live_index(ports, link.port).ok()?;
    let s = link.slot as usize;
    if ports[i].epoch != link.epoch || s >= PORT_MAX_SOURCES || ports[i].sources[s].kind != kind
        || ports[i].sources[s].gone != 0
    {
        return None;
    }
    Some((i, s))
}

/// Does `link` still name a live source slot holding `kind`? The binder asks
/// before replacing a link an object already stores (`port_link::LinkSet::Busy`):
/// a link to a destroyed port, or to a slot since freed or reused, is dead and
/// may be replaced; a live one makes the object busy.
pub fn port_link_valid(link: PortLink, kind: PortSourceKind) -> bool {
    if link.is_none() {
        return false;
    }
    let ports = PORTS.lock_irqsave();
    link_slot_locked(&ports, link, kind).is_some()
}

/// The producer side of a channel or io_ring source: mark the source `link`
/// names pending and wake the port's registered waiters (after releasing
/// `PORTS`). Called after the producer's own lock is released, never under it.
///
/// Answers whether the link named a live source holding `kind`; `false`
/// (nothing marked, nobody woken) tells the producer its link is dead, and it
/// may clear it.
///
/// With nobody waiting, the cost is one `PORTS` hold, the generation, epoch
/// and kind compares, and one read of the waiter-list head.
pub fn port_signal(link: PortLink, kind: PortSourceKind) -> bool {
    let woken = {
        let mut ports = PORTS.lock_irqsave();
        let Some((i, s)) = link_slot_locked(&ports, link, kind) else { return false };
        ports[i].sources[s].pending = true;
        detach_waiters_locked(&mut ports, i, WaiterState::Woken)
    };
    woken.wake(link.port);
    true
}

/// [`port_signal`] for channel `channel_ref` (its packed reference): one
/// message was sent on it (`channel.rs`, after the send's `POOL` hold).
pub fn port_signal_channel(link: PortLink, channel_ref: u32) -> bool {
    port_signal(link, PortSourceKind::Channel(channel_ref))
}

/// [`port_signal`] for io_ring `ring_ref` (its packed reference): a pass wrote
/// at least one completion (`io_ring.rs`, after the claim is released).
pub fn port_signal_ring(link: PortLink, ring_ref: u32) -> bool {
    port_signal(link, PortSourceKind::Ring(ring_ref))
}

/// The source `link` names (holding `kind`) is gone (wave 15 N5b): its
/// object was destroyed (`code` = `EREVOKED`) or its owner died
/// (`EPEERDIED`). The slot is marked gone, so the next poll or wait takes
/// one `PORT_EVENT_SOURCE_GONE` event with the binding's key and handle and
/// `code`, and frees the slot; the port's waiters are woken. Never dropped:
/// the event rides in the source's own slot, not the bounded IRQ queue.
///
/// Called by the object's destroy paths after the object's own lock is
/// released, never under it (`port_signal`'s rule). `false` when the link
/// named no live source (unbound, or the port is gone). Canary
/// `port-no-vanish`: nothing is marked.
pub fn port_source_gone(link: PortLink, kind: PortSourceKind, code: u16) -> bool {
    if !azos_limits::IPC_PORT_NOTICES || link.is_none() || CANARY_NO_VANISH.load(Ordering::Relaxed) {
        return false;
    }
    let woken = {
        let mut ports = PORTS.lock_irqsave();
        let Some((i, s)) = link_slot_locked(&ports, link, kind) else { return false };
        ports[i].sources[s].gone = code.max(1);
        ports[i].sources[s].pending = false;
        detach_waiters_locked(&mut ports, i, WaiterState::Woken)
    };
    woken.wake(link.port);
    true
}

/// [`port_source_gone`] for a source that has no slot of its own: an IRQ
/// binding (`irq_bind`) to the port `r` names, under `epoch`, removed because
/// its owner exited. A gone slot is added for it (`key`, `handle` = the
/// line), so the event is not lost; with the table full it is queued
/// instead, as the line's own events are. `false` when the port is gone.
pub fn port_post_gone(r: u32, epoch: u32, kind: PortSourceKind, key: u64, handle: u32, code: u16) -> bool {
    if !azos_limits::IPC_PORT_NOTICES || CANARY_NO_VANISH.load(Ordering::Relaxed) {
        return false;
    }
    let woken = {
        let mut ports = PORTS.lock_irqsave();
        let Ok(i) = live_index(&ports, r) else { return false };
        if ports[i].epoch != epoch {
            return false;
        }
        let port = &mut ports[i];
        match insert_source_locked(port, kind, key, handle, 0) {
            Some(s) => port.sources[s].gone = code.max(1),
            None => queue_locked(
                port,
                PortEvent { key, source_type: PORT_EVENT_SOURCE_GONE, source_id: handle, code: code.max(1) },
            ),
        }
        detach_waiters_locked(&mut ports, i, WaiterState::Woken)
    };
    woken.wake(r);
    true
}

/// Arm (or re-arm) the timer source keyed `user_key` on the port `r` names, to
/// fire at `deadline_ns` (absolute, nanoseconds on the time counter). A timer
/// already armed with that key gets the new deadline; otherwise a free slot
/// takes it (`Full` when there is none).
///
/// The port's registered waiters are detached and woken: each computed the
/// deadline its sleep ends at from the timers armed when it registered, and
/// goes round to compute it again.
pub fn port_arm_timer(r: u32, user_key: u64, deadline_ns: u64) -> Result<(), PortCapError> {
    let woken = {
        let mut ports = PORTS.lock_irqsave();
        let i = live_index(&ports, r)?;
        let port = &mut ports[i];
        let armed = port.sources.iter().position(|src| {
            matches!(src.kind, PortSourceKind::Timer(_)) && src.user_key == user_key
        });
        match armed {
            Some(s) => port.sources[s].kind = PortSourceKind::Timer(deadline_ns),
            None => {
                insert_source_locked(port, PortSourceKind::Timer(deadline_ns), user_key, 0, 0)
                    .ok_or(PortCapError::Full)?;
            }
        }
        detach_waiters_locked(&mut ports, i, WaiterState::Woken)
    };
    woken.wake(r);
    Ok(())
}

/// The sources [`port_unbind_key`] removed: for each channel or io_ring, its
/// packed reference and the link it stored, so the caller can clear the
/// object's side (a timer has no object side).
pub struct Unbound {
    /// `(kind, link)` of each removed source.
    pub items: [(PortSourceKind, PortLink); PORT_MAX_SOURCES],
    /// How many entries of `items` are filled.
    pub n: usize,
}

/// Remove every source of event type `event_type` (`PORT_EVENT_CHANNEL`,
/// `PORT_EVENT_RING` or `PORT_EVENT_TIMER`) bound with `user_key` from the
/// port `r` names. `Stale` for another incarnation of the port.
pub fn port_unbind_key(r: u32, event_type: u8, user_key: u64) -> Result<Unbound, PortCapError> {
    let mut out = Unbound { items: [(PortSourceKind::None, PortLink::NONE); PORT_MAX_SOURCES], n: 0 };
    let mut ports = PORTS.lock_irqsave();
    let i = live_index(&ports, r)?;
    let epoch = ports[i].epoch;
    let port = &mut ports[i];
    for s in 0..PORT_MAX_SOURCES {
        let src = port.sources[s];
        if src.kind != PortSourceKind::None
            && src.kind.event_type() == event_type
            && src.user_key == user_key
        {
            out.items[out.n] = (src.kind, PortLink { port: r, epoch, slot: s as u8 });
            out.n += 1;
            free_source_locked(port, s);
        }
    }
    Ok(out)
}

/// The earliest deadline of a timer armed on `port`, `u64::MAX` for none.
/// `PORTS` held.
fn next_timer_locked(port: &Port) -> u64 {
    if port.source_count == 0 {
        return u64::MAX;
    }
    let mut next = u64::MAX;
    for src in port.sources.iter() {
        if let PortSourceKind::Timer(d) = src.kind {
            next = next.min(d);
        }
    }
    next
}

/// Take the event of the first ready source-table entry at or after the
/// cursor: a pending channel or io_ring (its bit cleared) or a timer whose
/// deadline is at or before `now_ns` (its slot freed). `PORTS` held.
fn take_source_locked(port: &mut Port, now_ns: u64) -> Option<PortEvent> {
    if port.source_count == 0 {
        return None;
    }
    let start = port.cursor as usize;
    for k in 0..PORT_MAX_SOURCES {
        let s = (start + k) % PORT_MAX_SOURCES;
        let src = port.sources[s];
        let ready = src.kind != PortSourceKind::None && src.gone != 0 || match src.kind {
            PortSourceKind::Channel(_) | PortSourceKind::Ring(_) | PortSourceKind::Endpoint(_) => src.pending,
            PortSourceKind::Timer(d) => d <= now_ns,
            PortSourceKind::Irq(_) | PortSourceKind::None => false,
        };
        if !ready {
            continue;
        }
        let event = if src.gone != 0 {
            // The source's last event: it is gone, and so is its slot.
            PortEvent { key: src.user_key, source_type: PORT_EVENT_SOURCE_GONE, source_id: src.handle, code: src.gone }
        } else {
            let code = if let PortSourceKind::Endpoint(_) = src.kind { CODE_NO_SENDERS } else { 0 };
            PortEvent { key: src.user_key, source_type: src.kind.event_type(), source_id: src.handle, code }
        };
        if src.gone != 0 || matches!(src.kind, PortSourceKind::Timer(_)) {
            free_source_locked(port, s);
        } else {
            port.sources[s].pending = false;
        }
        port.cursor = ((s + 1) % PORT_MAX_SOURCES) as u8;
        return Some(event);
    }
    None
}

/// The next event of `port` at `now_ns`: a queued IRQ event or a ready
/// source, alternating between the two when both have one (see the module
/// doc). `PORTS` held.
fn take_event_locked(port: &mut Port, now_ns: u64) -> Option<PortEvent> {
    let taken = if port.sources_first {
        take_source_locked(port, now_ns).map(|e| (e, true)).or_else(|| dequeue_locked(port).map(|e| (e, false)))
    } else {
        dequeue_locked(port).map(|e| (e, false)).or_else(|| take_source_locked(port, now_ns).map(|e| (e, true)))
    };
    let (event, from_table) = taken?;
    port.sources_first = !from_table;
    Some(event)
}

/// Append `event` to `port`'s pending queue if there is room. `PORTS` held.
#[inline]
fn queue_locked(port: &mut Port, event: PortEvent) {
    let idx = port.pending_count.load(Ordering::Relaxed) as usize;
    if idx < PORT_MAX_SOURCES {
        port.pending[idx] = event;
        port.pending_count.store((idx + 1) as u32, Ordering::Release);
    }
}

/// Queue an event on a port, by index, and wake the port's registered waiters
/// (after releasing `PORTS`).
///
/// Must use the same `lock_irqsave()` discipline as the syscall-side
/// accessors — see the comment on `PORTS`. The IRQ path uses
/// [`port_queue_event_bound`].
pub fn port_queue_event(port_id: u32, event: PortEvent) {
    if port_id as usize >= MAX_PORTS { return; }
    let port_id = azos_limits::nospec::array_index_nospec(port_id as usize, MAX_PORTS) as u32;
    let (r, woken) = {
        let mut ports = PORTS.lock_irqsave();
        let i = port_id as usize;
        if !ports[i].active { return; }
        queue_locked(&mut ports[i], event);
        let r = LAYOUT.pack(port_id, ports[i].generation);
        (r, detach_waiters_locked(&mut ports, i, WaiterState::Woken))
    };
    woken.wake(r);
}

/// Queue an event through a packed reference and wake the port's registered
/// waiters. `Stale` (nothing queued, nobody woken) for another incarnation. A
/// full queue drops the event, as [`port_queue_event`] does, and still wakes.
pub fn port_queue_event_ref(r: u32, event: PortEvent) -> Result<(), PortCapError> {
    let woken = {
        let mut ports = PORTS.lock_irqsave();
        let i = live_index(&ports, r)?;
        queue_locked(&mut ports[i], event);
        detach_waiters_locked(&mut ports, i, WaiterState::Woken)
    };
    woken.wake(r);
    Ok(())
}

/// The IRQ binding's delivery (`irq_bind::irq_dispatch`, IRQ context): queue
/// `event` only if the port `r` names is live **and** its slot's generation
/// was taken under `epoch`, then wake the tasks blocked on `r`. Answers
/// whether the binding named the live port; `false` queues and wakes nothing.
///
/// The epoch is compared because a binding outlives its port (it is removed
/// only when its owner exits) and is not reached by `objref::sweep_index`
/// (which clears `Cap<Port>` entries in cap tables, not bindings): after that
/// slot's own wrap, a later port at the same index can draw the same
/// post-wrap generation, and only the epoch tells the two apart.
///
/// Cost in the PLIC handler: with nobody waiting, one read of the port's
/// waiter-list head inside the `PORTS` hold that queues. With `k` registered
/// waiters, `k` TID-directed wakes after the hold, each a scan of the task
/// pool that stops at the addressee plus a CAS. The first delivery detaches
/// the waiters, so further bindings of the same IRQ to the same port read the
/// gate only.
pub fn port_queue_event_bound(r: u32, epoch: u32, event: PortEvent) -> bool {
    let woken = {
        let mut ports = PORTS.lock_irqsave();
        let i = match live_index(&ports, r) {
            Ok(i) => i,
            Err(_) => return false,
        };
        if ports[i].epoch != epoch {
            return false;
        }
        queue_locked(&mut ports[i], event);
        detach_waiters_locked(&mut ports, i, WaiterState::Woken)
    };
    woken.wake(r);
    true
}

/// Dequeue the oldest pending event of `port`. `PORTS` held.
#[inline]
fn dequeue_locked(port: &mut Port) -> Option<PortEvent> {
    let count = port.pending_count.load(Ordering::Acquire);
    if count == 0 { return None; }
    let event = port.pending[0];
    // Shift remaining events down
    for i in 1..count as usize {
        port.pending[i - 1] = port.pending[i];
    }
    port.pending_count.store(count - 1, Ordering::Release);
    Some(event)
}

/// Dequeue one event from a port. Returns None if no events pending.
pub fn port_poll(port_id: u32) -> Option<PortEvent> {
    if port_id as usize >= MAX_PORTS { return None; }
    let port_id = azos_limits::nospec::array_index_nospec(port_id as usize, MAX_PORTS) as u32;
    // IRQ-safe: shares PORTS with port_queue_event_bound(). See comment on `PORTS`.
    let mut ports = PORTS.lock_irqsave();
    let port = &mut ports[port_id as usize];
    if !port.active { return None; }
    take_event_locked(port, 0)
}

/// [`port_poll`] through a packed reference: `Stale` for another incarnation,
/// `Empty` when nothing is pending. No clock: only a timer armed at 0 is due.
pub fn port_poll_ref(r: u32) -> Result<PortEvent, PortCapError> {
    port_poll_ref_at(r, 0)
}

/// [`port_poll_ref`] at `now_ns` (the time counter, in nanoseconds): a timer
/// whose deadline is at or before it is due.
pub fn port_poll_ref_at(r: u32, now_ns: u64) -> Result<PortEvent, PortCapError> {
    let mut ports = PORTS.lock_irqsave();
    let i = live_index(&ports, r)?;
    take_event_locked(&mut ports[i], now_ns).ok_or(PortCapError::Empty)
}

/// What the first half of a port wait found ([`port_wait_begin_at`]).
#[derive(Debug, PartialEq, Eq)]
pub enum PortWaitStart {
    /// An event was taken and is returned; nothing was registered.
    Event(PortEvent),
    /// Nothing was ready and the deadline had passed; nothing was registered.
    TimedOut,
    /// Nothing was ready; the caller is registered and blocks next, until the
    /// wake or `until` (nanoseconds on the time counter): the earlier of its
    /// own deadline and the port's earliest armed timer. `u64::MAX` means no
    /// deadline at all: the caller blocks on `WaitReason::Port(r)`, and on
    /// `WaitReason::Timer` otherwise (the registration records which, so the
    /// wake matches the reason).
    Registered { slot: PortWaitSlot, until: u64 },
}

/// A waiter registration made by [`port_wait_begin_at`] (the waiter's
/// task-pool slot), to hand to [`port_wait_end_at`] after the block.
#[must_use = "a registered waiter is deregistered by port_wait_end_at"]
#[derive(Debug, PartialEq, Eq)]
pub struct PortWaitSlot(u16);

/// Host-test seam for the race between the first half's check and the block:
/// called once per [`port_wait_begin_at`] that registers, after the empty
/// check. With `port-recheck-canary` it runs inside the gap the canary opens
/// between the check and the registration; without it, after the hold that
/// did both, before the caller blocks. Either way "after the check, before the
/// sleep".
#[cfg(test)]
pub static WAIT_RACE_HOOK: std::sync::Mutex<Option<fn()>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn wait_race_hook() {
    let hook = *WAIT_RACE_HOOK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(f) = hook {
        f();
    }
}

/// First half of a wait on the port `r` names, at `now_ns`, ending at
/// `deadline_ns` (both nanoseconds on the time counter): take an event if one
/// is ready and, when none is and the deadline has not passed, register `tid`
/// as a waiter of `r` **in the same `PORTS` hold**. An event that arrives
/// after this check — queued by an IRQ, a channel send or a ring completion
/// (`port_signal`), or a destroy — finds the registration and wakes `tid` by
/// TID, which stamps a task that has not blocked yet, so its block returns at
/// once: the check and the sleep cannot be separated by a lost wakeup.
///
/// The caller blocks per `until` and then calls [`port_wait_end_at`] with the
/// slot, on every path. Answers:
/// - `Ok(Event)`: taken; nothing registered, do not block;
/// - `Ok(TimedOut)`: nothing ready and `now_ns >= deadline_ns`;
/// - `Ok(Registered)`: registered;
/// - `Err(Cap(Stale))`: `r` is not the live port at its index;
/// - `Err(Full)`: [`PORT_MAX_WAITERS`] tasks already wait on the port, or
///   `tid` has no task-pool slot (`idx_for_tid`); nothing registered, do not
///   block.
///
/// A registration still in `tid`'s slot (left by the slot's previous tenant)
/// is removed first. Call with no cap-table lock held: the caller blocks next.
pub fn port_wait_begin_at(r: u32, tid: u32, now_ns: u64, deadline_ns: u64) -> Result<PortWaitStart, PortCapError> {
    // Resolved before `PORTS`: `idx_for_tid` is an unlocked task-pool scan.
    let slot = match azos_sched::idx_for_tid(tid) {
        Some(s) if s < MAX_TASKS => s,
        _ => return Err(PortCapError::Full),
    };
    let mut ports = PORTS.lock_irqsave();
    let i = live_index(&ports, r)?;
    if let Some(event) = take_event_locked(&mut ports[i], now_ns) {
        return Ok(PortWaitStart::Event(event));
    }
    if now_ns >= deadline_ns {
        return Ok(PortWaitStart::TimedOut);
    }
    // The canary: the check above and the registration below in two holds.
    // An event in the gap finds no waiter to wake and only sets its bit; the
    // caller then registers and sleeps past it.
    #[cfg(all(test, feature = "port-recheck-canary"))]
    let (mut ports, i) = {
        drop(ports);
        wait_race_hook();
        let ports = PORTS.lock_irqsave();
        let i = live_index(&ports, r)?;
        (ports, i)
    };
    clear_waiter_locked(&mut ports, slot);
    if ports[i].waiter_count as usize >= PORT_MAX_WAITERS {
        return Err(PortCapError::Full);
    }
    let until = deadline_ns.min(next_timer_locked(&ports[i]));
    let head = ports[i].waiter_head;
    let epoch = ports[i].epoch;
    ports.waiters[slot] = PortWaiter {
        tid,
        port: r,
        epoch,
        next: head,
        state: WaiterState::Waiting,
        timed: until != u64::MAX,
    };
    ports[i].waiter_head = slot as u16;
    ports[i].waiter_count += 1;
    drop(ports);
    #[cfg(all(test, not(feature = "port-recheck-canary")))]
    wait_race_hook();
    Ok(PortWaitStart::Registered { slot: PortWaitSlot(slot as u16), until })
}

/// Second half of a port wait: deregister the slot [`port_wait_begin_at`]
/// returned and, in the same `PORTS` hold, take one event at `now_ns`.
///
/// - `Ok(event)`: taken;
/// - `Err(Empty)`: the port is live and nothing is ready (another waiter
///   took the event, the wake was spurious or a timer re-arm's, the block
///   was refused, K-C29, or a deadline ended it);
/// - `Err(Cap(Stale))`: the port was destroyed or released while this task
///   was registered (answered without polling); `r` no longer names the live
///   port; the port at `r` drew its generation under another epoch (a later
///   port after that slot's own wrap); or the slot does not hold `tid`'s
///   registration for `r` (nothing is touched then).
pub fn port_wait_end_at(slot: PortWaitSlot, tid: u32, r: u32, now_ns: u64) -> Result<PortEvent, PortCapError> {
    const STALE: PortCapError = PortCapError::Cap(CapError::Stale);
    let s = slot.0 as usize;
    if s >= MAX_TASKS {
        return Err(STALE);
    }
    let mut ports = PORTS.lock_irqsave();
    let w = ports.waiters[s];
    if w.state == WaiterState::Free || w.tid != tid || w.port != r {
        return Err(STALE);
    }
    clear_waiter_locked(&mut ports, s);
    if w.state == WaiterState::Gone {
        return Err(STALE);
    }
    let i = live_index(&ports, r)?;
    if ports[i].epoch != w.epoch {
        return Err(STALE);
    }
    take_event_locked(&mut ports[i], now_ns).ok_or(PortCapError::Empty)
}

/// [`port_wait_begin_at`] with no clock and no deadline, for callers that
/// block on `WaitReason::Port` and ports with no timer (the host suites).
#[cfg(test)]
pub fn port_wait_begin(r: u32, tid: u32) -> Result<PortWaitStart, PortCapError> {
    port_wait_begin_at(r, tid, 0, u64::MAX)
}

/// [`port_wait_end_at`] with no clock (only a timer armed at 0 is due).
pub fn port_wait_end(slot: PortWaitSlot, tid: u32, r: u32) -> Result<PortEvent, PortCapError> {
    port_wait_end_at(slot, tid, r, 0)
}

/// Most blocks [`port_wait_ref_at`] makes before it answers `Empty`.
pub const PORT_WAIT_TURNS: usize = 8;

/// A blocking wait on the port `r` names, for `SYS_PORT_WAIT_TYPED` (577):
/// [`port_wait_begin_at`] with no deadline, then, while registered,
/// `block(until)` and [`port_wait_end_at`], at most [`PORT_WAIT_TURNS`]
/// times. `now` reads the time counter in nanoseconds.
///
/// `block` receives `None` when the caller blocks on `WaitReason::Port(r)`,
/// `Some(until)` when it blocks on `WaitReason::Timer` until that instant (an
/// armed timer source: the wait must not sleep past it). The loop lives here
/// so the host suite drives it (the `lease_accept_wait` shape). Every
/// registration reaches [`port_wait_end_at`] before this returns. Answers:
/// - `Ok(event)`: taken, before any block or after one;
/// - `Err(Cap(Stale))`: `r` is not the live port, or the port was destroyed or
///   released while the caller was registered; answered at once, never after
///   another block;
/// - `Err(Full)`: no room to register ([`port_wait_begin_at`]); nothing blocked;
/// - `Err(Empty)`: [`PORT_WAIT_TURNS`] blocks returned with nothing ready
///   (another waiter took the event, a spurious wake, a K-C29 refusal).
///
/// The bound exists because a return from `block` need not carry an event.
/// Call with no cap-table lock held: the caller sleeps in `block`.
pub fn port_wait_ref_at(
    r: u32,
    tid: u32,
    now: impl Fn() -> u64,
    mut block: impl FnMut(Option<u64>),
) -> Result<PortEvent, PortCapError> {
    for _ in 0..PORT_WAIT_TURNS {
        match port_wait_begin_at(r, tid, now(), u64::MAX)? {
            PortWaitStart::Event(event) => return Ok(event),
            // Unreachable with no deadline; answered as an empty turn.
            PortWaitStart::TimedOut => {}
            PortWaitStart::Registered { slot, until } => {
                block(if until == u64::MAX { None } else { Some(until) });
                match port_wait_end_at(slot, tid, r, now()) {
                    Err(PortCapError::Empty) => {}
                    answer => return answer,
                }
            }
        }
    }
    Err(PortCapError::Empty)
}

/// [`port_wait_ref_at`] with no clock, blocking through `block` (the host
/// suites' form, for ports with no timer).
#[cfg(test)]
pub fn port_wait_ref(r: u32, tid: u32, mut block: impl FnMut()) -> Result<PortEvent, PortCapError> {
    port_wait_ref_at(r, tid, || 0, |_| block())
}

/// A wait on the port `r` names that ends at `deadline_ns` (absolute,
/// nanoseconds on the time counter; `u64::MAX` for none, any instant already
/// passed for a poll), for `SYS_PORT_WAIT_UNTIL_TYPED` (604).
///
/// Loops [`port_wait_begin_at`] / `block(until)` / [`port_wait_end_at`] until
/// an event is taken or the deadline passes. `block` receives `None` to block
/// on `WaitReason::Port(r)`, `Some(until)` to block on `WaitReason::Timer`
/// until that instant, and answers whether the scheduler **refused** the block
/// (K-C29). `now` reads the time counter in nanoseconds. Unlike
/// [`port_wait_ref_at`] the number of turns is not bounded: every turn is a
/// block, and the deadline bounds them. Answers:
/// - `Ok(Some(event))`: taken;
/// - `Ok(None)`: the deadline passed with nothing ready;
/// - `Err(Refused)`: a block was refused (preemption disabled) and nothing was
///   ready after it: answered at once instead of spinning to the deadline;
/// - `Err(Cap(Stale))` / `Err(Full)`: as [`port_wait_ref_at`].
pub fn port_wait_until_ref(
    r: u32,
    tid: u32,
    deadline_ns: u64,
    now: impl Fn() -> u64,
    mut block: impl FnMut(Option<u64>) -> bool,
) -> Result<Option<PortEvent>, PortCapError> {
    loop {
        match port_wait_begin_at(r, tid, now(), deadline_ns)? {
            PortWaitStart::Event(event) => return Ok(Some(event)),
            PortWaitStart::TimedOut => return Ok(None),
            PortWaitStart::Registered { slot, until } => {
                let refused = block(if until == u64::MAX { None } else { Some(until) });
                match port_wait_end_at(slot, tid, r, now()) {
                    Ok(event) => return Ok(Some(event)),
                    Err(PortCapError::Empty) if refused => return Err(PortCapError::Refused),
                    Err(PortCapError::Empty) => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// Check if a port has pending events: a queued IRQ event or a pending
/// channel or io_ring source (timers need a clock and are not counted).
pub fn port_has_events(port_id: u32) -> bool {
    if port_id as usize >= MAX_PORTS { return false; }
    let port_id = azos_limits::nospec::array_index_nospec(port_id as usize, MAX_PORTS) as u32;
    let ports = PORTS.lock_irqsave();
    let port = &ports[port_id as usize];
    port.active
        && (port.pending_count.load(Ordering::Relaxed) > 0 || port.sources.iter().any(|s| s.pending))
}

/// Release every port owned by `tid` — task-exit hook (IPC-3).
///
/// **WHY this exists (IPC-3):** `PORTS` is a fixed `MAX_PORTS`-entry BSS
/// table and nothing ever reclaimed it. `task_release_all` called only
/// `handle_revoke_all`, `cap_store::reset` and `shm_release_all`, so a task
/// that died holding a port burned that slot for the life of the board:
/// `port_create` scans for `!active` and simply starts returning `None`.
/// There is no diagnostic for that — a robot that has restarted a crashing
/// driver `MAX_PORTS` times silently loses the ability to create event ports
/// at all.
///
/// It also bounds an inheritance hazard. `owner_task` holds a **TID**. TIDs are
/// monotone and a value is reissued only after `NEXT_TID` wraps at 2^32 (see
/// `cap_store.rs`'s module doc), so a dead task's port left active would be
/// inherited — bound sources and the opaque `user_key`s the original owner
/// used to correlate events included — only by the task that draws that TID
/// after the wrap.
///
/// Freeing the slot clears its generation (`Port::empty()`), so a `Cap<Port>`
/// or IRQ binding naming one of these ports answers `Stale` / is dropped from
/// here on (RFC-0040 gap 1).
///
/// **Waiters.** The dying task's own registration, if one is left, is removed
/// first. The exit hook runs on the dying task's own context
/// (`scheduler::task_exit_with_code`), outside `SYS_PORT_WAIT_TYPED`, whose
/// [`port_wait_ref_at`] deregisters on every return, so none is left on the paths
/// in the tree; the
/// removal keeps a registration from outliving its task however it exits.
/// The waiters of each port freed here are detached as gone and woken, as
/// [`port_destroy`] does: they are other tasks holding a capability to the
/// port, and none is left asleep on a freed reference.
///
/// Cost: exit path only. One pass over `MAX_PORTS` under the lock the table
/// already uses, split into further holds only when the freed ports' waiters
/// exceed one batch of `PORT_MAX_WAITERS` (woken between holds), plus one
/// `idx_for_tid` scan and hold for the dying task's own registration. Nothing
/// added to `port_poll`.
pub fn port_release_all(tid: u32) {
    if let Some(slot) = azos_sched::idx_for_tid(tid) {
        if slot < MAX_TASKS {
            let mut ports = PORTS.lock_irqsave();
            if ports.waiters[slot].state != WaiterState::Free && ports.waiters[slot].tid == tid {
                clear_waiter_locked(&mut ports, slot);
            }
        }
    }
    let mut start = 0usize;
    loop {
        let mut batch = [(0u32, false, 0u32); PORT_MAX_WAITERS];
        let mut n = 0usize;
        let mut resume = None;
        {
            let mut ports = PORTS.lock_irqsave();
            for i in start..MAX_PORTS {
                // `owner_task` is a TID widened to `usize` (`port_create(tid as usize)`
                // at every call site, `port_create_cap` here included). Compare in `usize` so the `usize::MAX`
                // "unowned" sentinel can never alias a real u32 TID.
                if !(ports[i].active && ports[i].owner_task == tid as usize) {
                    continue;
                }
                if n + ports[i].waiter_count as usize > PORT_MAX_WAITERS {
                    // Freed in the next hold, after this batch is woken. The
                    // batch is not empty here (one port's waiters always fit),
                    // so every hold frees at least one port.
                    resume = Some(i);
                    break;
                }
                let r = LAYOUT.pack(i as u32, ports[i].generation);
                let gone = detach_waiters_locked(&mut ports, i, WaiterState::Gone);
                for &(w, timed) in &gone.tids[..gone.n] {
                    batch[n] = (w, timed, r);
                    n += 1;
                }
                clear_port_locked(&mut ports, i);
            }
        }
        for &(w, timed, r) in &batch[..n] {
            wake_waiter(w, timed, r);
        }
        match resume {
            Some(i) => start = i,
            None => break,
        }
    }
}

/// Get the owner task of a port.
pub fn port_owner(port_id: u32) -> usize {
    if port_id as usize >= MAX_PORTS { return usize::MAX; }
    let port_id = azos_limits::nospec::array_index_nospec(port_id as usize, MAX_PORTS) as u32;
    PORTS.lock_irqsave()[port_id as usize].owner_task
}

// ──────────────────────────────────────────────────────────────────────────
// Cap<Port> typed wrappers (RFC-0003 W5)
// ──────────────────────────────────────────────────────────────────────────
//
// Mirrors the pattern established by `channel_send_cap` in W3:
// the typed entry validates the cap against the calling task's
// `CapTable`, then resolves the packed reference it stores inside the
// pool lock that does the work.

/// Errors returned by the typed `port_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortCapError {
    /// Capability dereference failed (stale, wrong kind, missing perms). A
    /// reference to a destroyed or reused port is `Cap(Stale)`.
    Cap(crate::cap::CapError),
    /// Underlying port slot is full / port slot table exhausted.
    Full,
    /// No events pending for receive.
    Empty,
    /// Port doesn't exist or isn't active.
    Closed,
    /// The scheduler refused to block the waiter (K-C29: preemption disabled
    /// on its hart) and nothing was ready: `-EBUSY` from 604.
    Refused,
}

impl From<crate::cap::CapError> for PortCapError {
    fn from(e: crate::cap::CapError) -> Self {
        Self::Cap(e)
    }
}

/// Typed `port_create`: allocates a port and mints a `Cap<Port>`
/// into the calling task's cap-table with `RW` permissions.
///
/// Returns the cap handle on success, or `None` if the port table (or every
/// remaining slot) is full, or the cap-table is full.
///
/// **A refused grant destroys the port it was for.** The port is allocated
/// first, so a full cap table used to leave it allocated and owned with no
/// capability anywhere to reach it — one leaked slot per call, and the port
/// table is machine-wide. `sys_shm_create_typed` and
/// `sys_ioring_create_typed` already roll back this way.
///
/// The capability stores the packed `(index, generation)`, minted through
/// `objref::grant_packed`. Must not be called with a cap-table lock held.
pub fn port_create_cap(tid: u32) -> Option<crate::cap::Cap<crate::cap::targets::Port>> {
    let (r, _epoch) = create_core(tid as usize)?;
    // `RW_DUP` (owner decision 2026-09-26, O3.4): the creator may gift its
    // own port.
    match objref::grant_packed::<crate::cap::targets::Port>(tid, CapPerms::RW_DUP, r) {
        Some(cap) => Some(cap),
        None => {
            let _ = port_destroy_ref(r);
            None
        }
    }
}

/// Typed `port_poll`: validates the cap (requires `READ`) and dequeues one
/// event; the port's generation is compared inside the `PORTS` hold that
/// dequeues.
pub fn port_poll_cap(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Port>,
) -> Result<PortEvent, PortCapError> {
    port_poll_cap_at(table, cap, 0)
}

/// [`port_poll_cap`] at `now_ns` (nanoseconds on the time counter): a timer
/// source due at or before it fires.
pub fn port_poll_cap_at(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Port>,
    now_ns: u64,
) -> Result<PortEvent, PortCapError> {
    let r = table.get(cap, CapPerms::READ)?;
    port_poll_ref_at(r, now_ns)
}

/// Typed `port_destroy`: validates the cap (requires `WRITE`), frees the
/// port slot, **and revokes the cap**.
///
/// **WHY the revoke is here (W3-F5):** `port_create` allocates the
/// first free index, and destroying a port does not touch the *cap table*
/// slot's generation — which is the only thing `CapTable::get` validates.
/// So a cap left live after its port is destroyed kept dereferencing to the
/// same integer id, and the next `port_create` by any task handed that id
/// straight back out. Since RFC-0040 gap 1 the port's own generation refuses
/// such a cap in every table; the revoke still frees the caller's slot, and it
/// is applied for a `Stale` answer too (the capability names nothing).
///
/// **Not contained.** Destroying is a release, so it resolves through
/// `CapTable::get_uncontained`: it still needs `WRITE`, and it stays live
/// while RFC-0036 containment is armed, the way closing a socket does (owner
/// decision 2026-09-13). The untyped `SYS_PORT_UNBIND` it paired with was
/// retired in RFC-0040 gap 1.
pub fn port_destroy_cap(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Port>,
) -> Result<(), PortCapError> {
    let r = table.get_uncontained(cap, CapPerms::WRITE)?;
    let destroyed = port_destroy_ref(r);
    table.revoke(cap);
    destroyed
}

/// Wipe the port table and its per-slot generation sources. Host-test hygiene
/// only — the suite shares one static `PORTS`. Never built into the kernel: a
/// reachable "destroy every port on the board" entry point is the DoS
/// a port's capability exists to prevent.
#[cfg(test)]
pub fn __port_reset_for_tests() {
    let mut ports = PORTS.lock_irqsave();
    CAP_BOUND.store(0, Ordering::Relaxed);
    for i in 0..MAX_PORTS {
        ports[i] = Port::empty();
        ports.next_gen[i] = 1;
        ports.epoch[i] = 0;
    }
    for w in ports.waiters.iter_mut() {
        *w = PortWaiter::empty();
    }
}

/// Fast-forward slot `i`'s own generation source, so a host test reaches its
/// wrap without `LAYOUT.gen_max()` create/destroy cycles at that index.
#[cfg(test)]
pub fn __port_set_next_gen_for_tests(i: usize, next_gen: u32) {
    PORTS.lock_irqsave().next_gen[i] = next_gen;
}

/// The generation stamped in slot `port_id` (host tests).
#[cfg(test)]
pub fn __port_generation_for_tests(port_id: u32) -> u32 {
    PORTS.lock_irqsave()[port_id as usize].generation
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate-wide serial lock (`tests/host/ipc-lease-tests`): the port table,
    /// `cap_store` and the scheduler shim's port-wake record are shared with
    /// the `irq_bind`, shm and io_ring suites, and a wrap sweep walks every cap
    /// table.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        __port_reset_for_tests();
        azos_sched::shim_reset_port_wakes();
        g
    }

    #[test]
    fn release_all_frees_only_the_dying_tasks_ports() {
        let _g = setup();
        let a = port_create(1).unwrap();
        let b = port_create(2).unwrap();
        let c = port_create(1).unwrap();
        assert!(port_bind(a, PortSourceKind::Irq(7), 0xF00D));

        port_release_all(1);

        // Freed: slot back in the pool, owner reset to the unowned sentinel.
        assert_eq!(port_owner(a), usize::MAX);
        assert_eq!(port_owner(c), usize::MAX);
        // A stale bind must not survive the owner — `port_queue_event` from
        // IRQ context would otherwise deliver a dead task's events.
        assert!(!port_bind(a, PortSourceKind::Irq(7), 0xF00D));
        // The other task's port is untouched.
        assert_eq!(port_owner(b), 2);
        assert!(port_bind(b, PortSourceKind::Irq(8), 1));
    }

    #[test]
    fn released_slots_are_reusable_and_carry_no_stale_events() {
        let _g = setup();
        let p = port_create(1).unwrap();
        port_queue_event(p, PortEvent { key: 0xDEAD, source_type: 3, source_id: 7, code: 0 });
        assert!(port_has_events(p));

        port_release_all(1);

        let reused = port_create(9).unwrap();
        assert_eq!(reused, p);
        assert_eq!(port_owner(reused), 9);
        // The new owner must not inherit the dead task's queued events — the
        // `user_key` is how the old owner correlated them.
        assert!(!port_has_events(reused));
        assert!(port_poll(reused).is_none());
    }

    #[test]
    fn exhausting_the_table_then_killing_an_owner_makes_ports_creatable_again() {
        let _g = setup();
        // TWO owners, because one can no longer fill the table: the per-task
        // quota landed the day RFC-0003 wrote down that minting without one is
        // exhaustion. This test used to fill every slot from task 1 and its
        // premise WAS the behaviour the quota removes — so it is rewritten
        // rather than relaxed, and it still asserts the thing it was written
        // for: reclaiming a dead task's ports returns capacity.
        for i in 0..MAX_PORTS_PER_TASK {
            assert!(port_create(1).is_some(), "owner 1, slot {i}");
        }
        for i in 0..MAX_PORTS_PER_TASK {
            assert!(port_create(2).is_some(), "owner 2, slot {i}");
        }
        // The permanent-failure state before IPC-3: nothing reclaimed ports,
        // so enough driver restarts killed port creation for good.
        assert!(port_create(3).is_none(), "the table is full");

        port_release_all(1);

        assert!(port_create(3).is_some());
    }

    #[test]
    fn one_task_cannot_take_every_port_on_the_machine() {
        let _g = setup();
        for i in 0..MAX_PORTS_PER_TASK {
            assert!(port_create(1).is_some(), "slot {i}");
        }
        // The quota, and the negative half below it: the refusal must be the
        // QUOTA and not a table that is simply full, or this would pass
        // against a pool that had run out for an unrelated reason.
        assert!(port_create(1).is_none(), "one task took more than its share");
        assert!(port_create(2).is_some(), "another task still has room");
    }

    /// A full cap table must not cost a port. `port_create_cap` allocates the
    /// port before it asks for the capability, and used to return `None`
    /// with the port still allocated and owned — unreachable, because no
    /// capability to it existed anywhere, and held until the task died.
    #[test]
    fn a_refused_grant_does_not_leak_the_port() {
        let _g = setup();
        const TID: u32 = 5;
        crate::cap_store::reset(TID);
        for i in 0..crate::cap::MAX_CAPS_PER_TASK {
            assert!(
                crate::cap_store::grant::<crate::cap::targets::Port>(
                    TID, crate::cap::CapPerms::READ, 0).is_some(),
                "filling the cap table, slot {i}");
        }

        assert!(port_create_cap(TID).is_none(), "the cap table is full");
        for id in 0..MAX_PORTS as u32 {
            assert_ne!(port_owner(id), TID as usize,
                       "port {id} was left allocated with no capability to reach it");
        }

        crate::cap_store::reset(TID);
        assert!(port_create_cap(TID).is_some(), "with room, the call still works");
        crate::cap_store::reset(TID);
    }

    #[test]
    fn release_all_ignores_uninvolved_tasks() {
        let _g = setup();
        let a = port_create(1).unwrap();
        port_release_all(42);
        assert_eq!(port_owner(a), 1);
        // `usize::MAX` is the unowned sentinel; a u32 TID can never equal it,
        // so passing an absurd TID must not sweep inactive slots into a state
        // that looks owned.
        port_release_all(u32::MAX);
        assert_eq!(port_owner(a), 1);
        assert_eq!(port_owner(MAX_PORTS as u32 - 1), usize::MAX);
    }

    #[test]
    fn out_of_range_and_boundary_port_ids_never_panic() {
        let _g = setup();
        for id in [MAX_PORTS as u32, MAX_PORTS as u32 + 1, u32::MAX, u32::MAX - 1] {
            assert_eq!(port_owner(id), usize::MAX);
            assert!(!port_bind(id, PortSourceKind::Irq(1), 0));
            assert!(port_poll(id).is_none());
            assert!(!port_has_events(id));
            port_queue_event(id, PortEvent::default());
            port_destroy(id);
            assert_eq!(port_ref(id), None);
        }
        // Last valid index must still work.
        let last = MAX_PORTS as u32 - 1;
        assert!(!port_has_events(last));
        port_destroy(last);
    }

    #[test]
    fn binding_is_bounded_by_port_max_sources() {
        let _g = setup();
        let p = port_create(1).unwrap();
        for i in 0..PORT_MAX_SOURCES {
            assert!(port_bind(p, PortSourceKind::Irq(i as u32), i as u64));
        }
        assert!(!port_bind(p, PortSourceKind::Irq(99), 99));
    }

    #[test]
    fn queued_events_are_bounded_and_polled_in_order() {
        let _g = setup();
        let p = port_create(1).unwrap();
        for i in 0..PORT_MAX_SOURCES + 4 {
            port_queue_event(p, PortEvent { key: i as u64, source_type: 1, source_id: 0, code: 0 });
        }
        for i in 0..PORT_MAX_SOURCES {
            assert_eq!(port_poll(p).unwrap().key, i as u64);
        }
        assert!(port_poll(p).is_none());
    }

    // ── RFC-0040 gap 1: the port generation ───────────────────────────────

    use crate::cap::targets::Port as PortTarget;
    use crate::cap::Cap;
    use crate::cap_store;

    // `tests/host/ipc-lease-tests`' scheduler shim maps a TID below `MAX_TASKS` to
    // the task-pool slot of the same number.
    const A: u32 = 31;
    const B: u32 = 32;
    const C: u32 = 33;
    const D: u32 = 34;
    const STALE: PortCapError = PortCapError::Cap(CapError::Stale);

    fn fresh_tables() {
        for tid in [A, B, C, D] {
            cap_store::reset(tid);
        }
    }

    /// A port created by `tid` through the typed path: its capability and the
    /// packed reference the capability stores.
    fn create(tid: u32) -> (Cap<PortTarget>, u32) {
        let cap = port_create_cap(tid).expect("create");
        (cap, cap_store::get(tid, cap, CapPerms::READ).expect("a fresh capability resolves"))
    }

    /// Another holder's capability for the live port `r`.
    fn mint(tid: u32, r: u32) -> Cap<PortTarget> {
        objref::grant_packed::<PortTarget>(tid, CapPerms::RW, r).expect("mint")
    }

    fn poll(tid: u32, cap: Cap<PortTarget>) -> Result<PortEvent, PortCapError> {
        cap_store::with_table(tid, |t| port_poll_cap(t, cap)).expect("a live tid")
    }

    fn destroy(tid: u32, cap: Cap<PortTarget>) -> Result<(), PortCapError> {
        cap_store::with_table(tid, |t| port_destroy_cap(t, cap)).expect("a live tid")
    }

    fn evt(key: u64) -> PortEvent {
        PortEvent { key, source_type: 3, source_id: 9, code: 0 }
    }

    /// (1) A port destroyed and recreated at the same index is another object:
    /// the old capability is `Stale` in the creator's table and in a second
    /// table, and the new port keeps its event. The destroy is the untyped
    /// `port_destroy`, which revokes nothing, so only the generation refuses.
    ///
    /// **Canary.** Drop `ports[i].generation != g` from `live_index`: both old
    /// capabilities poll the new port's event.
    #[test]
    fn a_recreated_index_is_stale_in_every_table_that_named_the_old_port() {
        let _g = setup();
        fresh_tables();
        let (cap_a, old) = create(A);
        let in_b = mint(B, old);
        assert_eq!(poll(B, in_b).map(|e| e.key), Err(PortCapError::Empty), "precondition: B's capability resolves");
        port_destroy(LAYOUT.idx(old));

        let (cap_c, new) = create(C);
        assert_eq!(LAYOUT.idx(new), LAYOUT.idx(old), "precondition: the index was reused");
        assert_ne!(LAYOUT.gen(new), LAYOUT.gen(old), "precondition: another generation");
        port_queue_event(LAYOUT.idx(new), evt(0xC0));

        assert_eq!(poll(A, cap_a).map(|e| e.key), Err(STALE), "the creator's table");
        assert_eq!(poll(B, in_b).map(|e| e.key), Err(STALE), "a second table");
        assert_eq!(destroy(B, in_b), Err(STALE), "an old destroy frees nothing");
        assert_eq!(poll(C, cap_c).map(|e| e.key), Ok(0xC0), "the new port kept its event");
    }

    /// (2) A kernel-context destroy (a kernel caller's bypass) stales a
    /// ring-3 holder: the freed slot's generation is 0.
    ///
    /// **Canary.** Keep the generation across `*port = Port::empty()` in
    /// `port_destroy`: the slot's generation reads non-zero. (B's poll stays
    /// `Stale` under that mutation, by construction: `live_index` also requires
    /// the slot to be active.)
    #[test]
    fn a_kernel_destroy_stales_a_holder() {
        let _g = setup();
        fresh_tables();
        let (_cap_a, r) = create(A);
        let in_b = mint(B, r);
        port_destroy(LAYOUT.idx(r));
        assert_eq!(__port_generation_for_tests(LAYOUT.idx(r)), 0, "the freed slot is vacant");
        assert_eq!(poll(B, in_b).map(|e| e.key), Err(STALE));
    }

    /// (3) The owner's exit (`port_release_all`) stales the capabilities in
    /// other tables.
    ///
    /// **Canary.** Skip the reset in `port_release_all`: B's poll reads
    /// `Empty`.
    #[test]
    fn the_owners_exit_stales_the_other_tables() {
        let _g = setup();
        fresh_tables();
        let (_cap_a, r) = create(A);
        let in_b = mint(B, r);
        port_release_all(A);
        assert_eq!(port_owner(LAYOUT.idx(r)), usize::MAX, "precondition: A's exit freed the port");
        assert_eq!(poll(B, in_b).map(|e| e.key), Err(STALE));
    }

    /// (6) U03-1 / U04-1's fix, owner decision 2026-09-26, mirrored from
    /// `ipc-chan-tests`: a slot that reaches `LAYOUT.gen_max()` is swept **at
    /// its own index only** (`objref::sweep_index`) and reused from
    /// generation 1 — instead of the old design's pool-wide counter, whose
    /// exhaustion swept every `Cap<Port>` in every table, live or not (one
    /// minted with `cap_store::grant` directly, bypassing `grant_packed`,
    /// included). A's churn on slot 1 crosses the same ceiling; B's and D's
    /// capabilities, on slot 0, read exactly as before it, and C's stale
    /// capability on slot 1's previous incarnation — the sweep's one job — is
    /// gone afterward. Reachable from ring 3 in `gen_max` create/destroy
    /// cycles on one task's own port.
    ///
    /// **Canary.** Drop the `ports.next_gen[i] != 0` guard from
    /// `create_core`'s free-slot scan: a concurrent create could select slot 1
    /// while it is mid-sweep. Compare the whole packed value instead of the
    /// index alone in `revoke_kind_at_index`: C's capability (a different,
    /// already-dead generation at the same index) would not be swept, and
    /// `cap_store::occupied(C)` below would read 1, not 0.
    #[test]
    fn a_slots_own_wrap_sweeps_only_that_index_and_the_slot_still_comes_back() {
        let _g = setup();
        fresh_tables();

        // B's port: the "other task's live capability" the old sweep
        // revoked. Created first so it lands on slot 0.
        let (cap_b, r_b) = create(B);
        assert_eq!(LAYOUT.idx(r_b), 0, "precondition: B's port is slot 0");
        let direct: Cap<PortTarget> = cap_store::grant(D, CapPerms::RW, r_b).unwrap();

        // A churns slot 1 right up to and past its own generation ceiling.
        let r1 = port_create_ref(A as usize).expect("create");
        assert_eq!(LAYOUT.idx(r1), 1, "precondition: A's churn lands on slot 1");
        assert!(port_destroy_ref(r1).is_ok());
        __port_set_next_gen_for_tests(1, LAYOUT.gen_max() - 1);

        let r1 = port_create_ref(A as usize).expect("create at the second-to-last generation");
        assert_eq!(LAYOUT.idx(r1), 1);
        assert_eq!(LAYOUT.gen(r1), LAYOUT.gen_max() - 1);
        assert!(port_destroy_ref(r1).is_ok());

        let r1 = port_create_ref(A as usize).expect("create at the last generation");
        assert_eq!(LAYOUT.idx(r1), 1);
        assert_eq!(LAYOUT.gen(r1), LAYOUT.gen_max(), "the last generation slot 1 can carry");
        // C holds a capability on THIS incarnation, already unreachable
        // through the generation compare the moment it is destroyed below.
        let in_c: Cap<PortTarget> = cap_store::grant(C, CapPerms::RW, r1).unwrap();
        assert!(port_destroy_ref(r1).is_ok());

        // The next create on slot 1 wraps: swept at index 1 only, then reused.
        let r_next = port_create_ref(A as usize).expect("slot 1 wraps and is reused, not skipped");
        assert_eq!(LAYOUT.idx(r_next), 1, "the slot comes back — no permanent loss");
        assert_eq!(LAYOUT.gen(r_next), 1, "reused from generation 1 after its own wrap");

        assert_eq!(cap_store::get(B, cap_b, CapPerms::READ), Ok(r_b), "B's capability");
        assert_eq!(cap_store::get(D, direct, CapPerms::READ), Ok(r_b), "D's capability, minted directly");
        assert_eq!(port_ref(0), Some(r_b), "B's port is still live");
        assert_eq!(cap_store::get(C, in_c, CapPerms::READ), Err(CapError::Stale), "C's stale capability, swept");
        assert_eq!(port_ref(1), Some(r_next), "slot 1 now answers for the new incarnation");
    }

    /// (7) A bare in-range index (generation 0) resolves to nothing, whether
    /// its slot is live or free.
    ///
    /// **Canary.** Drop `g == 0` and the generation compare from `live_index`:
    /// the bare capability polls A's live port.
    #[test]
    fn a_bare_index_capability_never_resolves() {
        let _g = setup();
        fresh_tables();
        let (_cap_a, r) = create(A);
        let idx = LAYOUT.idx(r);
        port_queue_event(idx, evt(1));
        let bare: Cap<PortTarget> = cap_store::grant(B, CapPerms::RW, idx).unwrap();
        let bare_free: Cap<PortTarget> = cap_store::grant(B, CapPerms::RW, MAX_PORTS as u32 - 1).unwrap();
        assert_eq!(poll(B, bare).map(|e| e.key), Err(STALE), "a live port");
        assert_eq!(poll(B, bare_free).map(|e| e.key), Err(STALE), "a free slot");
        assert_eq!(port_poll_ref(idx).map(|e| e.key), Err(STALE));
        assert!(port_has_events(idx), "the event is still queued");
    }

    /// The packed-reference forms answer like their index forms for a live
    /// reference, and `Stale` for an old one without touching the port now at
    /// that index.
    ///
    /// **Canary.** Resolve `port_bind_ref` by `LAYOUT.idx` instead of
    /// `live_index`: the stale bind reads `Ok`.
    #[test]
    fn the_reference_forms_refuse_an_old_reference() {
        let _g = setup();
        fresh_tables();
        let old = port_create_ref(A as usize).expect("create");
        assert_eq!(port_bind_ref(old, PortSourceKind::Timer(5), 7), Ok(()));
        assert_eq!(port_queue_event_ref(old, evt(2)), Ok(()));
        assert_eq!(port_poll_ref(old).map(|e| e.key), Ok(2));
        assert_eq!(port_poll_ref(old).map(|e| e.key), Err(PortCapError::Empty));
        assert_eq!(port_destroy_ref(old), Ok(()));

        let new = port_create_ref(B as usize).expect("create");
        assert_eq!(LAYOUT.idx(new), LAYOUT.idx(old), "precondition: the index was reused");
        port_queue_event_ref(new, evt(3)).unwrap();
        assert_eq!(port_bind_ref(old, PortSourceKind::Timer(5), 7), Err(STALE), "bind");
        assert_eq!(port_queue_event_ref(old, evt(4)), Err(STALE), "queue");
        assert_eq!(port_poll_ref(old).map(|e| e.key), Err(STALE), "poll");
        assert_eq!(port_destroy_ref(old), Err(STALE), "destroy");
        assert_eq!(port_poll_ref(new).map(|e| e.key), Ok(3), "the new port kept its one event");
        assert_eq!(port_owner(LAYOUT.idx(new)), B as usize, "and its owner");
    }

    // ── Waiters (R8.1): registration, TID-directed wakes, deregistration ──
    //
    // The scheduler shim records `wait::wake_port_waiter(tid, r)` as
    // `(tid, r)`. Its TID-to-slot map is the identity below `MAX_TASKS`.

    fn wakes() -> Vec<(u32, u32)> {
        azos_sched::shim_port_waiter_wakes()
    }

    fn registered(r: u32, tid: u32) -> PortWaitSlot {
        match port_wait_begin(r, tid) {
            Ok(PortWaitStart::Registered { slot, .. }) => slot,
            other => panic!("tid {tid} did not register on {r:#x}: {other:?}"),
        }
    }

    fn waiter_count(r: u32) -> u8 {
        PORTS.lock_irqsave()[LAYOUT.idx(r) as usize].waiter_count
    }

    fn waiter_state(tid: u32) -> WaiterState {
        PORTS.lock_irqsave().waiters[tid as usize].state
    }

    /// (a) The lost wakeup R8.1 closes. An event lands after the waiter's
    /// empty poll and before its block (here the IRQ delivery form): the
    /// registration made in the poll's hold is found, the waiter is woken by
    /// TID with the reference it blocks on — a TID-directed wake stamps a task
    /// that has not blocked (`tests/host/sched-wake-tests`,
    /// `a_port_event_before_the_waiter_blocks_is_not_lost`) — and the second
    /// half returns the event and deregisters.
    ///
    /// **Canaries.** Skip the registration in `port_wait_begin`: no wake is
    /// recorded. Wake through the broadcast `wake_by_port` in
    /// `Detached::wake`: no TID-directed wake is recorded.
    #[test]
    fn an_event_between_the_poll_and_the_block_wakes_the_waiter_and_is_returned() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let slot = registered(r, A);
        assert_eq!(waiter_count(r), 1, "registered in the poll's hold");
        assert!(port_queue_event_bound(r, port_live_epoch(r).unwrap(), evt(7)));
        assert_eq!(wakes(), vec![(A, r)], "woken by TID, with the packed reference");
        assert_eq!(waiter_state(A), WaiterState::Woken);
        assert_eq!(port_wait_end(slot, A, r).map(|e| e.key), Ok(7), "the event is returned, not lost");
        assert_eq!(waiter_state(A), WaiterState::Free, "deregistered");
        assert_eq!(waiter_count(r), 0);
    }

    /// Each queue form wakes the port's registered waiters once and detaches
    /// them; a port nobody waits on wakes nobody (the gate); a waiter that
    /// leaves without a wake unlinks itself and answers `Empty`.
    ///
    /// **Canaries.** Skip the detach in `port_queue_event`: the index form
    /// records no wake. Keep the list head in `detach_waiters_locked`: the
    /// second event wakes the detached waiters again. Skip the unlink in
    /// `clear_waiter_locked`: the port still counts D.
    #[test]
    fn each_queue_form_wakes_its_waiters_once_and_nobody_when_none_wait() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        port_queue_event_ref(r, evt(1)).unwrap();
        port_queue_event(LAYOUT.idx(r), evt(2));
        assert_eq!(wakes(), vec![], "nobody waits, nobody is woken");
        assert_eq!(port_poll_ref(r).map(|e| e.key), Ok(1));
        assert_eq!(port_poll_ref(r).map(|e| e.key), Ok(2));

        let sa = registered(r, A);
        let sb = registered(r, B);
        port_queue_event(LAYOUT.idx(r), evt(3));
        let mut w = wakes();
        w.sort();
        assert_eq!(w, vec![(A, r), (B, r)], "the index form wakes both, with the reference");
        assert_eq!(waiter_count(r), 0, "detached");
        port_queue_event_ref(r, evt(4)).unwrap();
        assert_eq!(wakes().len(), 2, "a detached waiter is not woken again");
        assert_eq!(port_wait_end(sb, B, r).map(|e| e.key), Ok(3));
        assert_eq!(port_wait_end(sa, A, r).map(|e| e.key), Ok(4));

        let sc = registered(r, C);
        port_queue_event_ref(r, evt(5)).unwrap();
        assert_eq!(wakes().last(), Some(&(C, r)), "the reference form");
        assert_eq!(port_wait_end(sc, C, r).map(|e| e.key), Ok(5));

        let sd = registered(r, D);
        assert_eq!(port_wait_end(sd, D, r).map(|e| e.key), Err(PortCapError::Empty), "no wake, nothing queued");
        assert_eq!(waiter_count(r), 0, "a waiter that leaves unwoken unlinks itself");
        assert_eq!(wakes().len(), 3);
    }

    /// (b) A destroy between the poll and the block wakes the waiter, marks its
    /// registration gone, and the second half answers `Stale` — both destroy
    /// forms.
    ///
    /// **Canaries.** Skip the detach in `port_destroy_ref`: no wake is
    /// recorded, the waiter would sleep on a reference nothing wakes. Mark
    /// destroyed waiters `Woken`: the state reads `Woken` (the answer stays
    /// `Stale` through `live_index`, by construction).
    #[test]
    fn a_destroy_between_the_poll_and_the_block_ends_the_wait_with_stale() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let slot = registered(r, B);
        assert_eq!(port_destroy_ref(r), Ok(()));
        assert_eq!(wakes(), vec![(B, r)], "the waiter is woken");
        assert_eq!(waiter_state(B), WaiterState::Gone);
        assert_eq!(port_wait_end(slot, B, r).map(|e| e.key), Err(STALE));
        assert_eq!(waiter_state(B), WaiterState::Free);

        let r2 = port_create_ref(A as usize).expect("create");
        let slot2 = registered(r2, C);
        port_destroy(LAYOUT.idx(r2));
        assert_eq!(wakes().last(), Some(&(C, r2)), "the index form");
        assert_eq!(waiter_state(C), WaiterState::Gone);
        assert_eq!(port_wait_end(slot2, C, r2).map(|e| e.key), Err(STALE));
    }

    /// (c) A waiter of one incarnation of an index is not woken by an event on
    /// a later incarnation, an old reference registers nothing, and the second
    /// half refuses a slot that does not hold the caller's registration for
    /// that reference.
    ///
    /// **Canaries.** Wake with `LAYOUT.idx(r)` in `Detached::wake`: the
    /// recorded reference reads the index. Drop the `tid`/`port` test in
    /// `port_wait_end`: B's call on C's slot deregisters C.
    // ── The bounded wait (`SYS_PORT_WAIT_TYPED`, 577) ───────────────────────

    /// A queued event is returned without blocking, and one queued during the
    /// block is returned after it, with the registration gone either way.
    ///
    /// **Canary.** Skip `port_wait_end` after the block (poll again with
    /// `port_wait_begin`): the event still returns, but the registration is
    /// left and `waiter_count` reads 1.
    #[test]
    fn the_wait_returns_an_event_queued_before_or_during_the_block() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        assert_eq!(port_queue_event_ref(r, evt(5)), Ok(()));
        let mut blocks = 0;
        assert_eq!(port_wait_ref(r, A, || blocks += 1).map(|e| e.key), Ok(5));
        assert_eq!(blocks, 0, "an event already queued needs no block");

        let mut blocks = 0;
        let got = port_wait_ref(r, A, || {
            blocks += 1;
            assert_eq!(port_queue_event_ref(r, evt(6)), Ok(()));
        });
        assert_eq!(got.map(|e| e.key), Ok(6));
        assert_eq!(blocks, 1);
        assert_eq!(wakes(), vec![(A, r)], "the registered waiter was woken by TID");
        assert_eq!(waiter_count(r), 0, "deregistered");
        assert_eq!(waiter_state(A), WaiterState::Free);
    }

    /// A destroy while the caller is registered ends the wait at once with
    /// `Stale`, after one block, not after the remaining turns; an old
    /// reference is refused before any block.
    ///
    /// **Canary.** Wait on a gone port as on an empty one (block and go round
    /// on any refusal but `Full`): the destroyed port's wait blocks
    /// `PORT_WAIT_TURNS` times. Treating only `port_wait_end`'s `Stale` as
    /// another turn does not discriminate: the next `port_wait_begin` checks the
    /// reference and answers `Stale` before any second block.
    #[test]
    fn a_destroy_during_the_wait_answers_stale_at_once() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let mut blocks = 0;
        let got = port_wait_ref(r, B, || {
            blocks += 1;
            assert_eq!(port_destroy_ref(r), Ok(()));
        });
        assert_eq!(got.map(|e| e.key), Err(STALE));
        assert_eq!(blocks, 1, "a destroyed port is not waited on again");
        assert_eq!(waiter_state(B), WaiterState::Free, "deregistered");

        let r2 = port_create_ref(A as usize).expect("create");
        assert_eq!(LAYOUT.idx(r2), LAYOUT.idx(r), "precondition: the index was reused");
        let mut blocks = 0;
        assert_eq!(port_wait_ref(r, B, || blocks += 1).map(|e| e.key), Err(STALE));
        assert_eq!(blocks, 0);
        assert_eq!(waiter_count(r2), 0, "nothing registered on the port now at the index");
    }

    /// Wakes that bring nothing end the wait after `PORT_WAIT_TURNS` blocks
    /// with `Empty`, deregistered; a full waiter list refuses before any block.
    ///
    /// **Canaries.** Loop without a bound (`PORT_WAIT_TURNS` raised past the
    /// hook's limit): the hook's turn assertion fires. Block before
    /// `port_wait_begin` answers: the full list blocks once.
    #[test]
    fn empty_wakes_end_the_wait_after_the_bound_and_a_full_list_never_blocks() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let mut blocks = 0;
        let got = port_wait_ref(r, A, || {
            blocks += 1;
            assert!(blocks <= 8, "the wait blocked a ninth time");
        });
        assert_eq!(got.map(|e| e.key), Err(PortCapError::Empty));
        assert_eq!(blocks, 8);
        assert_eq!(PORT_WAIT_TURNS, 8, "the bound 577's contract states");
        assert_eq!(waiter_count(r), 0, "deregistered");

        let slots: Vec<PortWaitSlot> = (1..=PORT_MAX_WAITERS as u32).map(|t| registered(r, t)).collect();
        let mut blocks = 0;
        assert_eq!(port_wait_ref(r, 20, || blocks += 1).map(|e| e.key), Err(PortCapError::Full));
        assert_eq!(blocks, 0);
        for (t, s) in (1..=PORT_MAX_WAITERS as u32).zip(slots) {
            assert_eq!(port_wait_end(s, t, r).err(), Some(PortCapError::Empty));
        }
    }

    #[test]
    fn a_waiter_of_another_incarnation_of_the_index_is_not_woken() {
        let _g = setup();
        let old = port_create_ref(A as usize).expect("create");
        let s_old = registered(old, A);
        port_destroy(LAYOUT.idx(old));
        let new = port_create_ref(B as usize).expect("create");
        assert_eq!(LAYOUT.idx(new), LAYOUT.idx(old), "precondition: the index was reused");
        assert_ne!(new, old);
        azos_sched::shim_reset_port_wakes();

        assert_eq!(port_wait_begin(old, C).err(), Some(STALE), "an old reference registers nothing");
        let s_new = registered(new, B);
        port_queue_event(LAYOUT.idx(new), evt(4));
        assert_eq!(wakes(), vec![(B, new)], "only the new incarnation's waiter");
        assert_ne!(new, LAYOUT.idx(new), "precondition: the reference is not the bare index");

        assert_eq!(port_wait_end(s_old, A, old).err(), Some(STALE));
        assert_eq!(port_wait_end(s_new, B, new).map(|e| e.key), Ok(4));

        let s_c = registered(new, C);
        assert_eq!(port_wait_end(PortWaitSlot(C as u16), B, new).err(), Some(STALE), "another task's slot");
        assert_eq!(port_wait_end(PortWaitSlot(C as u16), C, old).err(), Some(STALE), "another reference");
        assert_eq!(waiter_count(new), 1, "C is still registered");
        assert_eq!(port_wait_end(s_c, C, new).err(), Some(PortCapError::Empty));
    }

    /// A port refuses a waiter past `PORT_MAX_WAITERS` before it blocks, and a
    /// TID with no task slot registers nothing; the refusals leave the
    /// registered waiters intact and an event wakes every one. (The registry
    /// itself cannot fill: one entry per task-pool slot.)
    ///
    /// **Canary.** Drop the `waiter_count` test from `port_wait_begin`: the
    /// extra waiter registers.
    #[test]
    fn a_full_waiter_list_refuses_the_wait_before_it_blocks() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let tids: Vec<u32> = (1..=PORT_MAX_WAITERS as u32).collect();
        let slots: Vec<PortWaitSlot> = tids.iter().map(|&t| registered(r, t)).collect();
        assert_eq!(port_wait_begin(r, 20).err(), Some(PortCapError::Full), "one waiter too many");
        assert_eq!(waiter_state(20), WaiterState::Free);
        assert_eq!(port_wait_begin(r, 0).err(), Some(PortCapError::Full), "TID 0 names no task");
        assert_eq!(port_wait_begin(r, u32::MAX).err(), Some(PortCapError::Full), "no task slot");
        assert_eq!(waiter_count(r), PORT_MAX_WAITERS as u8);

        port_queue_event_ref(r, evt(9)).unwrap();
        let mut w = wakes();
        w.sort();
        assert_eq!(w, tids.iter().map(|&t| (t, r)).collect::<Vec<_>>(), "every registered waiter");
        let got: Vec<_> = tids.iter().zip(slots).map(|(&t, s)| port_wait_end(s, t, r).map(|e| e.key)).collect();
        assert_eq!(got.iter().filter(|g| **g == Ok(9)).count(), 1, "one waiter takes the event");
        assert_eq!(got.iter().filter(|g| **g == Err(PortCapError::Empty)).count(), PORT_MAX_WAITERS - 1);
    }

    /// Task exit (`port_release_all`) removes the dying task's own
    /// registration on a port it does not own, and wakes the waiters of the
    /// ports it owned, over more than one batch of `PORT_MAX_WAITERS`; they
    /// then answer `Stale`.
    ///
    /// **Canaries.** Skip the dying task's own registration: B's port still
    /// counts A. Stop after the first batch (`break` instead of resuming): the
    /// third port keeps its waiters and stays live.
    #[test]
    fn exit_removes_the_tasks_registration_and_wakes_the_waiters_of_its_ports() {
        let _g = setup();
        let theirs = port_create_ref(B as usize).expect("create");
        let _a_waits = registered(theirs, A);
        let mine: Vec<u32> = (0..3).map(|_| port_create_ref(A as usize).expect("create")).collect();
        let mut waiting = Vec::new();
        for (k, &r) in mine.iter().enumerate() {
            for j in 0..3u32 {
                let tid = 1 + k as u32 * 3 + j;
                waiting.push((tid, r, registered(r, tid)));
            }
        }

        port_release_all(A);

        assert_eq!(waiter_count(theirs), 0, "A's own registration is gone");
        assert_eq!(waiter_state(A), WaiterState::Free);
        let mut w = wakes();
        w.sort();
        let mut want: Vec<(u32, u32)> = waiting.iter().map(|&(t, r, _)| (t, r)).collect();
        want.sort();
        assert_eq!(w, want, "every waiter of every port A owned, over two batches");
        for &r in &mine {
            assert_eq!(port_owner(LAYOUT.idx(r)), usize::MAX, "freed");
        }
        for (t, r, s) in waiting {
            assert_eq!(port_wait_end(s, t, r).err(), Some(STALE));
        }
        port_queue_event_ref(theirs, evt(1)).unwrap();
        assert_eq!(wakes().len(), 9, "nobody waits on B's port any more");
    }

    /// A waiter that reaches its second half only after its port was destroyed
    /// and a later port drew the same packed reference after a generation wrap
    /// answers `Stale` and leaves that port's event queued: the epoch recorded
    /// at registration.
    ///
    /// **Canary.** Drop the epoch compare from `port_wait_end`: the late
    /// waiter takes the later port's event.
    #[test]
    fn a_late_waiter_does_not_take_an_event_from_a_port_that_reused_its_reference_after_a_wrap() {
        let _g = setup();
        fresh_tables();
        let old = port_create_ref(A as usize).expect("create");
        let slot = registered(old, B);
        port_queue_event_ref(old, evt(8)).unwrap();
        assert_eq!(wakes(), vec![(B, old)], "precondition: B was woken, and runs late");
        assert_eq!(port_poll_ref(old).map(|e| e.key), Ok(8), "another caller takes the event");
        port_destroy_ref(old).unwrap();
        __port_set_next_gen_for_tests(LAYOUT.idx(old) as usize, LAYOUT.gen_max() + 1);
        let later = port_create_ref(C as usize).expect("create");
        assert_eq!(later, old, "precondition: the same index and generation, another epoch");
        port_queue_event_ref(later, evt(9)).unwrap();

        assert_eq!(port_wait_end(slot, B, old).err(), Some(STALE));
        assert_eq!(port_poll_ref(later).map(|e| e.key), Ok(9), "the later port kept its event");
    }

    /// A `port_wait_begin` from a slot that still holds a registration (left
    /// by the slot's previous tenant) replaces it and unlinks it from its
    /// port.
    ///
    /// **Canary.** Drop `clear_waiter_locked` from `port_wait_begin`: the first
    /// port still counts the waiter, and its event wakes it.
    #[test]
    fn a_leftover_registration_in_the_slot_is_replaced_and_unlinked() {
        let _g = setup();
        let p = port_create_ref(A as usize).expect("create");
        let q = port_create_ref(A as usize).expect("create");
        let _left = registered(p, B);
        let s = registered(q, B);
        assert_eq!(waiter_count(p), 0, "unlinked from the first port");
        port_queue_event_ref(p, evt(1)).unwrap();
        assert_eq!(wakes(), vec![], "nobody waits on the first port");
        assert_eq!(port_wait_end(s, B, q).err(), Some(PortCapError::Empty));
    }

    // ── Wave 11 (PORTWAIT): channel, io_ring and timer sources ─────────────

    fn timed_wakes() -> Vec<u32> {
        azos_sched::shim_port_timed_wakes()
    }

    fn sources(r: u32) -> usize {
        PORTS.lock_irqsave()[LAYOUT.idx(r) as usize].source_count
    }

    const CH: PortSourceKind = PortSourceKind::Channel(0x0C01);
    const CH2: PortSourceKind = PortSourceKind::Channel(0x0C02);
    const RING: PortSourceKind = PortSourceKind::Ring(0x0A01);

    /// A timer fires once, at the first poll at or after its deadline, with
    /// its key and type 4, and its slot is freed.
    ///
    /// **Canary.** Keep the slot after delivery (`pending`-style instead of
    /// `free_source_locked`): the third poll returns the timer again.
    #[test]
    fn a_timer_fires_once_at_its_deadline_and_frees_its_slot() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        assert_eq!(port_arm_timer(r, 0x71, 1_000), Ok(()));
        assert_eq!(sources(r), 1);
        assert_eq!(port_poll_ref_at(r, 999), Err(PortCapError::Empty), "one ns early");
        assert_eq!(
            port_poll_ref_at(r, 1_000),
            Ok(PortEvent { key: 0x71, source_type: PORT_EVENT_TIMER, source_id: 0, code: 0 }),
        );
        assert_eq!(port_poll_ref_at(r, u64::MAX), Err(PortCapError::Empty), "one-shot");
        assert_eq!(sources(r), 0, "the slot is free again");
    }

    /// Binding a timer with a key already armed moves its deadline (one slot),
    /// and every arm wakes the registered waiters so they recompute the
    /// instant their sleep ends: a waiter asleep with no deadline is woken on
    /// `Port`, one asleep until an older deadline on `Timer`.
    ///
    /// **Canaries.** Drop the detach from `port_arm_timer`: no wake is
    /// recorded, the first waiter sleeps past the new timer. Register every
    /// waiter untimed: the second wake is recorded as a `Port` wake.
    #[test]
    fn re_arming_a_key_moves_its_deadline_and_wakes_the_waiters() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let first = match port_wait_begin_at(r, A, 0, u64::MAX) {
            Ok(PortWaitStart::Registered { slot, until }) => {
                assert_eq!(until, u64::MAX, "no deadline, no timer: blocks on Port");
                slot
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(port_arm_timer(r, 9, 500), Ok(()));
        assert_eq!(wakes(), vec![(A, r)], "the untimed waiter is woken on Port");
        assert_eq!(port_wait_end_at(first, A, r, 10).err(), Some(PortCapError::Empty));

        let second = match port_wait_begin_at(r, A, 10, u64::MAX) {
            Ok(PortWaitStart::Registered { slot, until }) => {
                assert_eq!(until, 500, "bounded by the armed timer");
                slot
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(port_arm_timer(r, 9, 800), Ok(()));
        assert_eq!(timed_wakes(), vec![A], "the timed waiter is woken on Timer");
        assert_eq!(sources(r), 1, "the same key re-armed, not a second timer");
        assert_eq!(port_wait_end_at(second, A, r, 600).err(), Some(PortCapError::Empty), "500 no longer fires");
        match port_wait_begin_at(r, A, 600, 700) {
            Ok(PortWaitStart::Registered { slot, until }) => {
                assert_eq!(until, 700, "the wait's own deadline is earlier");
                assert_eq!(port_wait_end_at(slot, A, r, 800).map(|e| e.key), Ok(9));
            }
            other => panic!("{other:?}"),
        }
    }

    /// A channel or io_ring source is edge-triggered and coalesced: any number
    /// of signals before the event is one event (type 1, the bound handle as
    /// `source_id`), and a signal after it is another.
    ///
    /// **Canary.** Leave `pending` set in `take_source_locked`: the second poll
    /// returns the channel again with no signal in between.
    #[test]
    fn a_channel_source_is_edge_triggered_and_coalesced() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let (link, added) = port_bind_object(r, CH, 0x77, 0xC0).expect("bind");
        assert!(added);
        assert!(port_has_events(LAYOUT.idx(r)) == false);
        for _ in 0..3 {
            assert!(port_signal_channel(link, 0x0C01));
        }
        assert!(port_has_events(LAYOUT.idx(r)), "a pending source counts as an event");
        assert_eq!(port_poll_ref(r), Ok(PortEvent { key: 0xC0, source_type: PORT_EVENT_CHANNEL, source_id: 0x77, code: 0 }));
        assert_eq!(port_poll_ref(r), Err(PortCapError::Empty), "three sends, one event");
        assert!(port_signal_channel(link, 0x0C01));
        assert_eq!(port_poll_ref(r).map(|e| e.key), Ok(0xC0), "a send after the event is another");

        let (rl, _) = port_bind_object(r, RING, 0x55, 0xA0).expect("bind ring");
        assert!(port_signal_ring(rl, 0x0A01));
        assert_eq!(port_poll_ref(r), Ok(PortEvent { key: 0xA0, source_type: PORT_EVENT_RING, source_id: 0x55, code: 0 }));
    }

    /// A signal through a link that no longer names a live source answers
    /// `false` and marks nothing: the port destroyed, the source removed, the
    /// slot holding another object, the link of another epoch.
    /// `port_link_valid` answers the same.
    ///
    /// **Canary.** Drop the kind compare from `link_slot_locked`: the signal
    /// for `CH` through `CH2`'s slot reads `true`.
    #[test]
    fn a_signal_through_a_dead_link_marks_nothing() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let (link, _) = port_bind_object(r, CH, 1, 1).expect("bind");
        assert!(port_link_valid(link, CH));
        assert!(!port_signal(link, CH2), "another object's ref");
        assert!(!port_signal(PortLink { epoch: link.epoch + 1, ..link }, CH), "another epoch");
        assert!(!port_link_valid(PortLink::NONE, CH));

        let gone = port_unbind_key(r, PORT_EVENT_CHANNEL, 1).expect("unbind");
        assert_eq!(gone.n, 1);
        assert_eq!(gone.items[0], (CH, link));
        assert!(!port_signal(link, CH), "removed");
        let (link2, _) = port_bind_object(r, CH2, 2, 2).expect("bind the slot to another channel");
        assert_eq!(link2.slot, link.slot, "precondition: the slot was reused");
        assert!(!port_signal(link, CH), "the slot now holds another channel");
        assert_eq!(port_poll_ref(r), Err(PortCapError::Empty));

        assert_eq!(port_destroy_ref(r), Ok(()));
        assert!(!port_signal(link2, CH2), "the port is gone");
        assert!(!port_link_valid(link2, CH2));
    }

    /// One object occupies one slot: a second bind updates its key and
    /// handle. The table holds `PORT_MAX_SOURCES` sources and refuses the
    /// next with `Full`; `port_unbind_link` frees an added slot; removing by
    /// key takes only that type and key.
    #[test]
    fn the_source_table_is_bounded_and_one_object_takes_one_slot() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let (first, added) = port_bind_object(r, CH, 1, 0x10).unwrap();
        assert!(added);
        let (again, added) = port_bind_object(r, CH, 2, 0x11).unwrap();
        assert!(!added, "a second bind of the same channel adds nothing");
        assert_eq!(again, first);
        assert!(port_signal(first, CH));
        assert_eq!(port_poll_ref(r).map(|e| (e.key, e.source_id)), Ok((0x11, 2)), "the new key and handle");

        for i in 1..PORT_MAX_SOURCES as u32 {
            port_arm_timer(r, 0x100 + i as u64, u64::MAX).expect("room");
        }
        assert_eq!(sources(r), PORT_MAX_SOURCES);
        assert_eq!(port_bind_object(r, CH2, 3, 3).err(), Some(PortCapError::Full));
        assert_eq!(port_arm_timer(r, 0x999, 5), Err(PortCapError::Full));

        assert_eq!(port_unbind_key(r, PORT_EVENT_RING, 0x10).map(|g| g.n), Ok(0), "wrong type");
        assert_eq!(port_unbind_key(r, PORT_EVENT_TIMER, 0x101).map(|g| g.n), Ok(1));
        let (l2, added) = port_bind_object(r, CH2, 3, 3).unwrap();
        assert!(added, "the freed slot takes it");
        port_unbind_link(l2, CH2);
        assert_eq!(sources(r), PORT_MAX_SOURCES - 1, "the undo freed it");
    }

    /// IRQ events (the queue) and table sources alternate when both are
    /// ready, so neither class starves the other.
    ///
    /// **Canary.** Always try the queue first in `take_event_locked`: the
    /// channel comes out after all three IRQ events.
    #[test]
    fn queued_events_and_table_sources_alternate() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let (link, _) = port_bind_object(r, CH, 0, 0xC).unwrap();
        for k in 1..=3 {
            port_queue_event_ref(r, evt(k)).unwrap();
        }
        assert!(port_signal(link, CH));
        let mut order = Vec::new();
        while let Ok(e) = port_poll_ref(r) {
            order.push(e.key);
            if e.key == 0xC {
                assert!(port_signal(link, CH), "the channel is busy again at once");
            }
            if order.len() == 6 {
                break;
            }
        }
        assert_eq!(order, vec![1, 0xC, 2, 0xC, 3, 0xC]);
    }

    /// 604's loop: a deadline with nothing bound times out after one block
    /// until that deadline; a timer earlier than the deadline ends the block
    /// at the timer and returns its event; a passed deadline polls without
    /// blocking; a refused block answers `Refused` at once.
    ///
    /// **Canaries.** Pass `deadline_ns` instead of `until` to `block`: the
    /// timer case blocks until 10 000. Ignore `refused`: the refused wait loops
    /// (the hook's turn assertion fires). Fire a timer only strictly after its
    /// deadline (`d < now_ns`): the timer case blocks a second time at 4 000.
    #[test]
    fn the_deadline_wait_blocks_until_the_earlier_of_its_deadline_and_a_timer() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let now = std::cell::Cell::new(0u64);
        let mut blocks = Vec::new();
        let got = port_wait_until_ref(r, A, 10_000, || now.get(), |until| {
            blocks.push(until);
            assert!(blocks.len() <= 1, "blocked again after the deadline: {blocks:?}");
            now.set(until.expect("a deadline bounds the block"));
            false
        });
        assert_eq!(got, Ok(None), "timed out");
        assert_eq!(blocks, vec![Some(10_000)]);
        assert_eq!(waiter_count(r), 0, "deregistered");

        port_arm_timer(r, 0x7, 4_000).unwrap();
        now.set(1_000);
        blocks.clear();
        let got = port_wait_until_ref(r, A, 10_000, || now.get(), |until| {
            blocks.push(until);
            assert!(blocks.len() <= 1, "blocked again at the timer's deadline: {blocks:?}");
            now.set(until.unwrap());
            false
        });
        assert_eq!(got.map(|e| e.map(|e| (e.key, e.source_type))), Ok(Some((0x7, PORT_EVENT_TIMER))));
        assert_eq!(blocks, vec![Some(4_000)], "woke at the timer, not the deadline");

        let mut blocked = false;
        assert_eq!(port_wait_until_ref(r, A, 0, || now.get(), |_| { blocked = true; false }), Ok(None));
        assert!(!blocked, "a passed deadline polls");

        let mut turns = 0;
        let got = port_wait_until_ref(r, A, u64::MAX, || now.get(), |until| {
            turns += 1;
            assert!(turns <= 1, "a refused block was retried");
            assert_eq!(until, None, "no deadline and no timer: blocks on Port");
            true
        });
        assert_eq!(got, Err(PortCapError::Refused));
        assert_eq!(waiter_state(A), WaiterState::Free);
    }

    /// The race 604 must not lose: an event arrives after the waiter found
    /// nothing and before it blocks. The hook fires in exactly that gap (see
    /// `WAIT_RACE_HOOK`); the waiter's block must then find a wake addressed to
    /// it (a TID-directed wake stamps a task that has not blocked yet, so its
    /// block returns at once — `tests/host/sched-wake-tests`), and the second
    /// half must return the event.
    ///
    /// **Canary.** `--features port-recheck-canary`: `port_wait_begin_at`
    /// checks and registers in two holds; the signal in the gap wakes nobody
    /// and this test fails at "no wake reached the waiter".
    #[test]
    fn an_event_between_the_check_and_the_sleep_is_not_lost() {
        let _g = setup();
        let r = port_create_ref(A as usize).expect("create");
        let (link, _) = port_bind_object(r, CH, 0x31, 0xEE).unwrap();
        *RACE_LINK.lock().unwrap() = Some(link);
        *WAIT_RACE_HOOK.lock().unwrap() = Some(race_signal);
        let mut blocks = 0;
        let got = port_wait_until_ref(r, A, u64::MAX, || 0, |_| {
            blocks += 1;
            let woken = wakes().contains(&(A, r)) || timed_wakes().contains(&A);
            *WAIT_RACE_HOOK.lock().unwrap() = None;
            assert!(woken, "no wake reached the waiter: the event in the gap is lost");
            false
        });
        *WAIT_RACE_HOOK.lock().unwrap() = None;
        assert_eq!(blocks, 1);
        assert_eq!(got.map(|e| e.map(|e| e.key)), Ok(Some(0xEE)), "the event is returned");
    }

    static RACE_LINK: std::sync::Mutex<Option<PortLink>> = std::sync::Mutex::new(None);

    fn race_signal() {
        let link = RACE_LINK.lock().unwrap().take();
        if let Some(link) = link {
            assert!(port_signal(link, CH), "the race hook's signal");
        }
    }

    // ── Wave 11 (LEASE3): a binding dies with its capability ─────────────

    /// A channel binding made through a capability follows that capability
    /// when it MOVES (events still arrive, and the binding now belongs to the
    /// receiver's table), and dies when it is REVOKED there (`revoke_moved`,
    /// the path a moved capability whose message is never delivered takes):
    /// the source slot is freed, a signal through the object's link answers
    /// false, and nothing is delivered. A binding made through a second
    /// capability, and an IRQ-free timer, are untouched. The exit reset
    /// (`Wiped`) drops every binding of the dying table.
    ///
    /// **Canary.** `--features port-revoke-canary` (`port_cap_event` ignores
    /// every event): the revoked binding still delivers and the count stays.
    #[test]
    fn a_binding_dies_when_its_capability_is_revoked_and_survives_a_move() {
        use crate::cap::targets::Channel as ChannelTarget;
        let _g = setup();
        fresh_tables();
        cap_store::set_cap_event_hook(port_cap_event);
        const CH_A: PortSourceKind = PortSourceKind::Channel(0x0C01);
        const CH_B: PortSourceKind = PortSourceKind::Channel(0x0C02);
        let r = port_create_ref(A as usize).expect("create");
        let slot_a = cap_store::table_slot(A).expect("A's table");
        let slot_b = cap_store::table_slot(B).expect("B's table");
        let ca: Cap<ChannelTarget> = cap_store::grant(A, CapPerms::RW_DUP, 0x0C01).expect("grant");
        let cb: Cap<ChannelTarget> = cap_store::grant(A, CapPerms::RW_DUP, 0x0C02).expect("grant");
        let (la, _) = port_bind_object_as(r, CH_A, ca.raw().as_raw(), 0xA, Some(slot_a)).expect("bind a");
        let (lb, _) = port_bind_object_as(r, CH_B, cb.raw().as_raw(), 0xB, Some(slot_a)).expect("bind b");
        assert_eq!(port_cap_bound_count(), 2);

        // MOVE: the binding follows the capability into B's table.
        let moved = cap_store::move_cap(A, B, ca.raw(), None).expect("move");
        assert!(port_signal(la, CH_A), "the binding survived the move");
        assert_eq!(port_poll_ref(r).map(|e| e.key), Ok(0xA));
        // A revoke in A's table of what A no longer holds removes nothing.
        cap_store::revoke(A, ca);
        assert!(port_link_valid(la, CH_A), "A's stale handle is not the binding's capability");

        // REVOKE where the capability now lives: the binding goes.
        assert!(cap_store::revoke_moved(B, moved));
        assert!(!port_link_valid(la, CH_A), "the revoked capability's binding is gone");
        assert!(!port_signal(la, CH_A), "a send through the dead link marks nothing");
        assert_eq!(port_poll_ref(r), Err(PortCapError::Empty));
        assert_eq!(port_cap_bound_count(), 1);
        let _ = slot_b;

        // The other capability's binding was not touched; a timer neither.
        assert_eq!(port_arm_timer(r, 0x7, u64::MAX), Ok(()));
        assert!(port_signal(lb, CH_B));
        assert_eq!(port_poll_ref(r).map(|e| e.key), Ok(0xB));

        // The exit reset wipes A's table: its remaining binding goes.
        cap_store::reset(A);
        assert!(!port_link_valid(lb, CH_B), "the wiped table's binding is gone");
        assert_eq!(port_cap_bound_count(), 0);
        assert_eq!(
            port_unbind_key(r, PORT_EVENT_TIMER, 0x7).map(|g| g.n), Ok(1),
            "the timer source is still bound",
        );
        cap_store::set_cap_event_hook(|_| {});
    }

    /// An untyped/kernel bind (no binder) survives every capability event,
    /// and the count of capability-made bindings stays exact across a
    /// rebind and a port destroy.
    #[test]
    fn a_binding_without_a_binder_is_not_tied_to_any_capability() {
        let _g = setup();
        fresh_tables();
        cap_store::set_cap_event_hook(port_cap_event);
        let slot_a = cap_store::table_slot(A).expect("A's table");
        let r = port_create_ref(A as usize).expect("create");
        let (l, _) = port_bind_object(r, CH, 1, 1).expect("bind");
        cap_store::reset(A);
        assert!(port_link_valid(l, CH), "no binder: not dropped by a wipe");
        let (_, added) = port_bind_object_as(r, CH, 1, 1, Some(slot_a)).expect("rebind");
        assert!(!added);
        assert_eq!(port_cap_bound_count(), 1, "the rebind gave it a binder");
        assert_eq!(port_destroy_ref(r), Ok(()));
        assert_eq!(port_cap_bound_count(), 0, "a destroyed port's bindings are uncounted");
        cap_store::set_cap_event_hook(|_| {});
    }
}
