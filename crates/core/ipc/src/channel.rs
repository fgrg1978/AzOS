// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// IPC message-passing channels — a fixed pool of ring buffers, one per
/// channel, all behind one lock (U03-6: NOT lock-free — every send and
/// receive on every channel in the pool serialises on the single `POOL`
/// `SpinLock` below; a per-channel lock would need its own free-slot
/// bitmap and is a design change, not a comment fix, so this is left for
/// that decision rather than made here).
///
/// Each channel holds up to 8 messages of up to 64 bytes each.
/// Thread-safe via `SpinLock` from `azos_sync`.
///
/// API:
///   channel_create()             — allocate a channel, return index
///   channel_send(ch, data)       — enqueue up to 64 bytes
///   channel_recv(ch, buf)        — dequeue one message
///   channel_destroy(ch)          — free the channel
///   channel_info()               — print channel pool stats

use azos_sync::SpinLock;
use wcet_macro::wcet;
pub use azos_limits::MAX_CHANNELS;

use crate::cap::objref;
use crate::cap::{CapError, CapKind, CapPerms};
use crate::port_link::{LinkSet, PortLink};

/// How a `Cap<Channel>` packs `(index, generation)` (RFC-0040 gap 1): the
/// smallest index width holding `0..MAX_CHANNELS`, the rest generation
/// (`objref::CHANNEL`; edge 4 + 28, fleet 12 + 20).
const LAYOUT: objref::Layout = objref::CHANNEL;
const _: () = assert!(MAX_CHANNELS as u64 <= 1u64 << LAYOUT.idx_bits());

// ── Caller attribution ───────────────────────────────────────────────────────
//
// **WHY this exists (Carril D / channel ownership).** `channel_recv` and
// `channel_destroy` take a raw pool index and used to authorize nothing, so
// any ring-3 task could walk `0..MAX_CHANNELS` and steal another task's
// messages or free its channel out from under it. To authorize, the function
// must know *who* is calling.
//
// The caller is read here rather than passed in as a parameter, matching what
// `signal.rs` already does in this same crate. Explicit `(caller_tid,
// privileged)` parameters would change the arity of functions called from
// `domains/robot/bench/src/ipc.rs` and `kernel/src/main.rs`. Nothing inside
// `crates/core/ipc` ever calls these on behalf of another task, so self-attribution
// denies nothing legitimate.
//
// Cost: `current_task_tid()` and `current_user_pt()` are both a per-CPU index
// load plus one array read — no locks, no scans, ~4 loads total. The global
// handle table's check it was chosen over was a 256-entry locked sweep
// (+2.5 µs typical, +97.8 µs on a miss, measured then). Channels are the
// optimized IPC path; a scan here would be a regression, a field compare is
// noise against the 1879 ns syscall floor.
//
/// Returns `(caller_tid, privileged)`. `privileged` is the house convention:
/// a kernel task (`current_user_pt() == 0`) bypasses every ownership check,
/// exactly as `cap_check` and `cap_store`'s typed callers do.
#[cfg(not(test))]
#[inline(always)]
fn caller_ctx() -> (u32, bool) {
    (
        // Wave 15 (plan 4a): the process, so a thread's channel or pipe is
        // its process's, as a descriptor is, and outlives the thread.
        azos_sched::current_proc_tid(),
        azos_sched::current_user_pt() == 0,
    )
}

/// Host-test stand-in for [`caller_ctx`]. `azos_sched` cannot be built for
/// the host (RV64-only dependencies), so the host suite drives the identity
/// through these atomics instead. Never compiled into the kernel.
#[cfg(test)]
pub mod test_ctx {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    pub static TID: AtomicU32 = AtomicU32::new(0);
    pub static PRIVILEGED: AtomicBool = AtomicBool::new(true);

    /// Pretend the next calls come from `tid`, kernel-mode iff `privileged`.
    pub fn set(tid: u32, privileged: bool) {
        TID.store(tid, Ordering::SeqCst);
        PRIVILEGED.store(privileged, Ordering::SeqCst);
    }
}

#[cfg(test)]
#[inline(always)]
fn caller_ctx() -> (u32, bool) {
    use core::sync::atomic::Ordering;
    (
        test_ctx::TID.load(Ordering::SeqCst),
        test_ctx::PRIVILEGED.load(Ordering::SeqCst),
    )
}

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum payload bytes per message.
pub const MSG_MAX_LEN: usize = 64;

/// Number of message slots per channel (ring buffer capacity).
pub const RING_CAP: usize = 8;

// ── Message ──────────────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct Message {
    data: [u8; MSG_MAX_LEN],
    len:  u16,
}

impl Message {
    const fn zeroed() -> Self {
        Message { data: [0u8; MSG_MAX_LEN], len: 0 }
    }
}

// ── Channel ──────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, PartialEq)]
enum ChannelState {
    Free,
    Active,
}

#[derive(Copy, Clone)]
struct Channel {
    state:    ChannelState,
    ring:     [Message; RING_CAP],
    head:     u32,    // read  position (consumer)
    tail:     u32,    // write position (producer)
    tx_count: u32,    // total messages sent
    rx_count: u32,    // total messages received
    /// TID of the task that called [`channel_create`] — the **receiving**
    /// end. Read by [`channel_recv`] and [`channel_destroy`] to authorize.
    ///
    /// `0` is the vacant marker: `current_task_tid()` returns 0 only for
    /// "no current task", and `NEXT_TID` starts at 1 and skips 0 on wrap,
    /// so no live task can ever match it. A free or kernel-boot-time slot
    /// therefore denies every ring-3 caller by construction (fail-closed).
    ///
    /// A stale index whose slot was recycled by ANOTHER task fails the
    /// compare instead of silently aliasing. It does not tell apart two
    /// incarnations with the same owner; see `generation` below.
    owner:    u32,
    /// Stamped by [`channel_create`] from this slot's own entry in
    /// `ChannelPool::next_gen`, masked to `LAYOUT.gen_bits()`, and packed with
    /// the index into a `Cap<Channel>` (RFC-0040 gap 1). Per-slot: this index's
    /// generation only ever grows, so no two incarnations at this index ever
    /// share one, and no counterpart at another index ever draws from the same
    /// source either.
    ///
    /// `owner` was documented as doubling for this, and it does not: it
    /// distinguishes a DIFFERENT owner, not a different *incarnation*. A task
    /// that destroys its own channel and creates another landing on the same
    /// index keeps the same `owner`, so an owner-compare sees continuity where
    /// there is none.
    ///
    /// 0 is the vacant value, so a freed slot matches no capability.
    generation: u32,
    /// The event port this channel is bound to as a source
    /// (`SYS_PORT_BIND_TYPED`, type 0), or `PortLink::NONE`. Every send reads
    /// it in the hold that enqueues and, after releasing `POOL`, signals that
    /// port (`port::port_signal_channel`). Cleared with the slot, and by the
    /// first send that finds the port gone.
    link: PortLink,
}

impl Channel {
    const fn zeroed() -> Self {
        Channel {
            state:    ChannelState::Free,
            ring:     [Message::zeroed(); RING_CAP],
            head:     0,
            tail:     0,
            tx_count: 0,
            rx_count: 0,
            owner:    0,
            generation: 0,
            link:     PortLink::NONE,
        }
    }

    /// Number of messages in the ring.
    fn count(&self) -> usize {
        let t = self.tail as usize;
        let h = self.head as usize;
        if t >= h { t - h } else { RING_CAP - h + t }
    }

    /// True when ring is full.
    fn is_full(&self) -> bool {
        (self.tail + 1) % RING_CAP as u32 == self.head
    }

    /// True when ring is empty.
    fn is_empty(&self) -> bool {
        self.head == self.tail
    }
}

// ── Global channel pool ──────────────────────────────────────────────────────

struct ChannelPool {
    channels: [Channel; MAX_CHANNELS],
    /// Per-slot generation source for `Channel::generation` (RFC-0040 gap 1,
    /// revised, owner decision 2026-09-26): entry `i` is the generation index
    /// `i`'s *next* create will stamp. Starts at 1 (0 doubles as the vacant
    /// value and, transiently, as "mid-sweep") and is never reset by a
    /// destroy, so no two incarnations at the same index ever share a
    /// generation without a targeted sweep of that one index
    /// (`objref::sweep_index`) — never a pool-wide one. See `objref`'s module
    /// doc ("Per-slot generations...").
    next_gen: [u32; MAX_CHANNELS],
}

impl ChannelPool {
    const fn new() -> Self {
        ChannelPool {
            channels: [Channel::zeroed(); MAX_CHANNELS],
            next_gen: [1u32; MAX_CHANNELS],
        }
    }
}

static POOL: SpinLock<ChannelPool> = SpinLock::new(ChannelPool::new());

// ── Public API ───────────────────────────────────────────────────────────────

/// Allocate a new channel from the fixed pool.
/// Returns `Some(index)` on success, `None` if the pool is exhausted (every
/// slot occupied).
///
/// The calling task becomes the channel's **owner**: the only task allowed
/// to [`channel_recv`] from it or [`channel_destroy`] it. See
/// [`channel_send`] for why the *send* direction stays open.
pub fn channel_create() -> Option<usize> {
    create_core(false).ok().map(|r| LAYOUT.idx(r) as usize)
}

/// Most live channels a ring-3 task may own when it creates through
/// [`channel_create_cap`] (`SYS_CHAN_CREATE_TYPED`): half the pool, so one task
/// cannot take every channel on the machine. Every live channel the task owns
/// counts, however it was created. Kernel callers are exempt.
pub const MAX_CHANNELS_PER_TASK: usize = MAX_CHANNELS / 2;

/// Why [`channel_create_cap`] left the caller with no capability.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChannelCreateError {
    /// The ring-3 caller already owns [`MAX_CHANNELS_PER_TASK`] live channels.
    Quota,
    /// No free channel slot (every slot occupied, or mid-sweep on this hart's
    /// own wrap — see `create_core`).
    Exhausted,
    /// The capability could not be minted (a full cap table); the channel was
    /// destroyed.
    NotMinted,
}

/// The create body: the new channel's packed `(index, generation)` reference.
///
/// **Per-slot generation, swept only at its own index (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26).** Each slot's generation is its own
/// (`ChannelPool::next_gen`); when slot `i`'s reaches `LAYOUT.gen_max()`, this
/// marks it mid-sweep (`next_gen[i] = 0`, which the free-slot scan already
/// treats as unavailable, so no concurrent create can select it meanwhile),
/// releases `POOL`, runs `objref::sweep_index(CapKind::Channel, i)` — which
/// revokes only the stale `Cap<Channel>`s left over at index `i`, nothing live
/// — resets `next_gen[i]` to `1`, and retries. At most two passes: the second
/// always finds `Gen(1)`. See `objref`'s module doc for the full protocol and
/// the accepted O(`MAX_TASKS`) cost of that walk.
///
/// **Quota (`per_task_quota`, the `SYS_CHAN_CREATE_TYPED` path only).** A
/// ring-3 caller that already owns [`MAX_CHANNELS_PER_TASK`] live channels is
/// refused with `Quota`. Counted in the same `POOL` hold as the allocation, in
/// the pass that looks for the free slot, so two creates by one task cannot
/// both pass the count. Cost: that pass reads every slot while the quota
/// applies, where the free-slot search stops at the first free one.
/// [`channel_create`] passes `false`: its kernel callers (`domains/robot/bench`) and
/// the host suites create by index with no quota.
fn create_core(per_task_quota: bool) -> Result<u32, ChannelCreateError> {
    // Read the caller before taking the lock — neither accessor locks, but
    // keeping the critical section to pure pool work is the house style.
    let (owner, privileged) = caller_ctx();
    let counted = per_task_quota && !privileged;
    // Two passes at most: the second runs only after this call's own
    // per-slot wrap sweep finishes.
    for _ in 0..2 {
        let mut pool = POOL.lock();
        let mut free = None;
        let mut owned = 0usize;
        for i in 0..MAX_CHANNELS {
            let c = &pool.channels[i];
            // `next_gen[i] != 0` excludes a slot this call (or, in
            // principle, a concurrent one) has marked mid-sweep.
            if c.state == ChannelState::Free && pool.next_gen[i] != 0 {
                if free.is_none() {
                    free = Some(i);
                    if !counted {
                        break;
                    }
                }
            } else if counted && c.state == ChannelState::Active && c.owner == owner {
                owned += 1;
            }
        }
        if counted && owned >= MAX_CHANNELS_PER_TASK {
            return Err(ChannelCreateError::Quota);
        }
        let slot = free.ok_or(ChannelCreateError::Exhausted)?;
        // Taken once a free slot is known, so a full pool consumes none.
        let gen = match objref::take_slot_gen(pool.next_gen[slot], LAYOUT) {
            objref::SlotGen::Gen(g) => g,
            objref::SlotGen::Wrap => {
                pool.next_gen[slot] = 0;
                drop(pool);
                objref::sweep_index(CapKind::Channel, slot as u32);
                pool = POOL.lock();
                pool.next_gen[slot] = 1;
                continue;
            }
        };
        pool.next_gen[slot] = gen + 1;
        pool.channels[slot] = Channel::zeroed();
        pool.channels[slot].state = ChannelState::Active;
        pool.channels[slot].owner = owner;
        pool.channels[slot].generation = gen;
        return Ok(LAYOUT.pack(slot as u32, gen));
    }
    Err(ChannelCreateError::Exhausted)
}

/// The packed reference of live channel `ch`, or `None` for an out-of-range or
/// inactive slot. One `POOL` hold.
///
/// For a caller holding a validated index that needs the value a
/// `Cap<Channel>` stores. Mint through [`channel_grant_cap`].
pub fn channel_ref(ch: usize) -> Option<u32> {
    if ch >= MAX_CHANNELS {
        return None;
    }
    let pool = POOL.lock();
    let chan = &pool.channels[ch];
    if chan.state == ChannelState::Active {
        Some(LAYOUT.pack(ch as u32, chan.generation))
    } else {
        None
    }
}

/// Mint a `Cap<Channel>` with `perms` on live channel `ch` into `tid`'s table.
///
/// The capability carries the channel's current generation, read under `POOL`.
/// `None` for an out-of-range or inactive channel, or a full table.
/// The boot-time topology seed (`cap_seed`) mints through here.
pub fn channel_grant_cap(
    tid: u32,
    ch: usize,
    perms: CapPerms,
) -> Option<crate::cap::Cap<crate::cap::targets::Channel>> {
    let r = channel_ref(ch)?;
    objref::grant_packed::<crate::cap::targets::Channel>(tid, perms, r)
}

/// Create a channel owned by the calling task and mint a `Cap<Channel>` with
/// `RW` into `tid`'s table, which must be the calling task's.
///
/// `Quota` when a ring-3 caller already owns [`MAX_CHANNELS_PER_TASK`] live
/// channels; `Exhausted` if the pool (or every remaining slot) is exhausted;
/// `NotMinted` if the cap table is full: a refused mint destroys the channel
/// it was for (the rule `port_create_cap` follows). For
/// `SYS_CHAN_CREATE_TYPED`.
pub fn channel_create_cap(
    tid: u32,
) -> Result<crate::cap::Cap<crate::cap::targets::Channel>, ChannelCreateError> {
    let r = create_core(true)?;
    // `DUP` (owner decision 2026-09-26, O3.4): the creator of an object may
    // gift it — `move_cap` refuses a transfer for any capability lacking
    // this bit, and a self-created object's own creator is the one holder
    // that decision does not mean to freeze in place.
    match objref::grant_packed::<crate::cap::targets::Channel>(tid, CapPerms::RW_DUP, r) {
        Some(cap) => Ok(cap),
        None => {
            let _ = channel_destroy_ref(r);
            Err(ChannelCreateError::NotMinted)
        }
    }
}

/// Resolve a packed reference to its slot, with `POOL` held by the caller.
///
/// `Stale` unless the slot is active and carries the reference's generation: a
/// freed slot (generation 0), a slot reused by another channel, and a bare
/// in-range index (generation 0) all answer `Stale`.
fn live_index(pool: &ChannelPool, r: u32) -> Result<usize, ChannelCapError> {
    let i = LAYOUT.idx(r) as usize;
    let g = LAYOUT.gen(r);
    if g == 0 || i >= MAX_CHANNELS
        || pool.channels[i].state != ChannelState::Active
        || pool.channels[i].generation != g
    {
        return Err(ChannelCapError::Cap(CapError::Stale));
    }
    Ok(i)
}

/// TID that owns channel `ch`, or `None` for an out-of-range or inactive
/// slot.
///
/// Mirrors `port_owner` so the syscall layer can build a `channel_access_ok`
/// guard at the dispatch boundary if it wants the check in both places.
pub fn channel_owner(ch: usize) -> Option<u32> {
    if ch >= MAX_CHANNELS {
        return None;
    }
    let pool = POOL.lock();
    if pool.channels[ch].state == ChannelState::Active {
        Some(pool.channels[ch].owner)
    } else {
        None
    }
}

/// Send up to 64 bytes on channel `ch`.
///
/// Returns 0 on success, -1 on error (invalid index, channel not active,
/// data too long, or ring full).
///
/// # No ownership check, and no ring-3 caller
///
/// Sending to a channel the sender does not own was the **protocol** of the
/// untyped channel calls: `SYS_IPC_CALL` had the *client* call `channel_send`
/// on the *server's* channel and then block for a reply, and `SYS_IPC_SEND` /
/// `SYS_CHAN_WRITE` sent by index for any task. RFC-0040 gap 1 retired all
/// three (owner decision 2026-09-14). Ring 3 sends only through
/// [`channel_send_cap`], with a `Cap<Channel>` carrying `WRITE`, which
/// `SYS_CHAN_CREATE_TYPED` mints into the creator's table; this function keeps
/// its kernel callers (`domains/robot/bench`).
///
/// A `HANDLES` send right was never usable: `HandleKind::Channel` was deleted
/// (2026-08-24) as dead code, and its check would have cost a 256-entry sweep
/// under `lock_irqsave` (+2.5 µs typical, +97.8 µs on a miss, historical
/// numbers). Receiving and destroying by index are gated below at O(1).
#[wcet(40_us)]
pub fn channel_send(ch: usize, data: &[u8]) -> i32 {
    if ch >= MAX_CHANNELS || data.len() > MSG_MAX_LEN {
        return -1;
    }

    let mut pool = POOL.lock();
    let chan = &mut pool.channels[ch];

    if chan.state != ChannelState::Active {
        return -1;
    }
    if chan.is_full() {
        return -1;
    }

    push(chan, data);
    let (link, r) = (chan.link, LAYOUT.pack(ch as u32, chan.generation));
    drop(pool);
    if !link.is_none() {
        signal_bound_port(r, link);
    }
    0
}

/// Signal the port channel `r` is bound to, after a send; a link the port no
/// longer answers to (the port destroyed, the source unbound) is cleared, so
/// later sends stop paying for it. Called with `POOL` released.
fn signal_bound_port(r: u32, link: PortLink) {
    if !crate::port::port_signal_channel(link, r) {
        channel_clear_link(r, link);
    }
}

/// Store `link` as the port channel `r` reports to (`SYS_PORT_BIND_TYPED`).
///
/// Stored when the channel has no link, when its link names the same port
/// (a re-bind), or when its link equals `replace` — a link the binder found
/// dead (`port::port_link_valid`) after an earlier `Busy`. Otherwise
/// `Busy(current)`: one channel reports to one port. `Stored { ready }` tells
/// whether a message was already queued, read in the same `POOL` hold, so a
/// message sent before the link existed is still reported once.
pub fn channel_set_link(r: u32, link: PortLink, replace: PortLink) -> Result<LinkSet, ChannelCapError> {
    let mut pool = POOL.lock();
    let i = live_index(&pool, r)?;
    let chan = &mut pool.channels[i];
    let cur = chan.link;
    if cur.is_none() || cur.port == link.port || cur == replace {
        chan.link = link;
        return Ok(LinkSet::Stored { ready: !chan.is_empty() });
    }
    Ok(LinkSet::Busy(cur))
}

/// Clear channel `r`'s link if it is still `link` (a source unbound from its
/// port, or a link a send found dead). Nothing for a stale `r`.
pub fn channel_clear_link(r: u32, link: PortLink) {
    let mut pool = POOL.lock();
    if let Ok(i) = live_index(&pool, r) {
        if pool.channels[i].link == link {
            pool.channels[i].link = PortLink::NONE;
        }
    }
}

/// Enqueue `data` on `chan`. `POOL` held; the caller checked that the channel
/// is active, not full, and `data.len() <= MSG_MAX_LEN`.
#[inline]
fn push(chan: &mut Channel, data: &[u8]) {
    let slot = chan.tail as usize;
    // Copy payload into ring slot
    let dst = &mut chan.ring[slot];
    let n = data.len();
    dst.data[..n].copy_from_slice(data);
    dst.len = n as u16;

    chan.tail = (chan.tail + 1) % RING_CAP as u32;
    chan.tx_count = chan.tx_count.wrapping_add(1);
}

/// Dequeue one message from `chan` into `buf`, returning the bytes copied.
/// `POOL` held; the caller checked that the channel is active and not empty.
#[inline]
fn pop(chan: &mut Channel, buf: &mut [u8]) -> usize {
    let slot = chan.head as usize;
    let msg = &chan.ring[slot];
    let n = (msg.len as usize).min(buf.len());
    buf[..n].copy_from_slice(&msg.data[..n]);

    chan.head = (chan.head + 1) % RING_CAP as u32;
    chan.rx_count = chan.rx_count.wrapping_add(1);
    n
}

// ──────────────────────────────────────────────────────────────────────────
// Cap<Channel> typed wrappers (RFC-0003 W3 reference path)
// ──────────────────────────────────────────────────────────────────────────
//
// # Reference flow
//
// ```ignore
// use azos_ipc::cap::{Cap, CapPerms, CapTable, targets::Channel};
// use azos_ipc::channel::{channel_create, channel_send_cap};
//
// // 1. Create the resource; read its packed reference (index and
// //    generation, RFC-0040 gap 1).
// let ch_id = channel_create().unwrap();
// let r = channel_ref(ch_id).unwrap();
//
// // 2. Mint a typed cap. Into a per-task table the kernel mints through
// //    `channel_grant_cap` or `channel_create_cap`.
// let mut table = CapTable::empty();
// let cap: Cap<Channel> = table.grant(CapPerms::RW, r).unwrap();
//
// // 3. Send via the typed entry — the kind, the cap-table slot's
// //    generation and the perms are checked on dereference, and the
// //    channel's generation inside the pool lock.
// channel_send_cap(&table, cap, b"hello").unwrap();
// ```
//
// Wave W4+ will replace `CapTable::empty()` here with the per-task
// table populated from the static topology declared in CAPS.TOML
// (RFC-0005). Until then, callers construct an explicit table.

/// Errors returned by the typed `channel_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChannelCapError {
    /// Capability dereference failed (stale, wrong kind, missing perms). A
    /// capability whose channel was destroyed, or whose index another channel
    /// took, is `Cap(Stale)`.
    Cap(crate::cap::CapError),
    /// Underlying channel is closed or the channel index is invalid. The
    /// typed calls no longer answer it since RFC-0040 gap 1 (a closed channel
    /// fails the generation compare); kept for the error mapping.
    Closed,
    /// Send buffer is full.
    Full,
    /// Receive buffer was empty.
    Empty,
    /// Data exceeds [`MSG_MAX_LEN`] or buffer is undersized.
    BadArg,
}

impl From<crate::cap::CapError> for ChannelCapError {
    fn from(e: crate::cap::CapError) -> Self {
        Self::Cap(e)
    }
}

/// Typed `channel_send` taking a `Cap<Channel>` instead of an integer
/// handle. RFC-0003 reference migration path.
///
/// The cap is dereferenced through `table` with `WRITE` permission; the
/// resource stored in the slot is the packed `(index, generation)` of the
/// channel it was granted on.
///
/// # A capability names an incarnation (RFC-0040 gap 1)
///
/// `CapTable::get_uncontained` validates the capability's own cap-table slot
/// (kind, slot generation, perms). The channel's generation is compared here,
/// under the one `POOL` hold that also enqueues, so a capability to a
/// destroyed channel, or to its index after another channel took it, answers
/// `Stale` in every table that holds it. Until gap 1 the capability stored
/// the bare index and reached the next channel created at that index;
/// `tests/host/ipc-chan-tests`,
/// `stale_channel_cap_is_stale_after_its_index_is_recreated`, pins the change.
///
/// # Not contained (owner decision 2026-09-26, O3.3)
///
/// Resolves through `get_uncontained`, so a message send is never itself
/// refused by RFC-0036 degraded-mode containment: containment stops DEVICE
/// writes, not messages between tasks. A channel into a driver task is
/// already an actuation path, and it is contained at the driver's own device
/// capability (`gpio_cap`, `motor_cap`, `pwm_cap`, ... each resolve through
/// `get`), which is the place that can tell a command from a report.
/// Containing the message too would freeze a safety monitor's outbound
/// alert — a READ-only observation — for the same reason it should freeze a
/// motor command, which is the opposite of what containment exists to do.
pub fn channel_send_cap(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Channel>,
    data: &[u8],
) -> Result<(), ChannelCapError> {
    if data.len() > MSG_MAX_LEN {
        return Err(ChannelCapError::BadArg);
    }
    let r = table.get_uncontained(cap, CapPerms::WRITE)?;
    let mut pool = POOL.lock();
    let i = live_index(&pool, r)?;
    let chan = &mut pool.channels[i];
    if chan.is_full() {
        return Err(ChannelCapError::Full);
    }
    push(chan, data);
    let link = chan.link;
    drop(pool);
    if !link.is_none() {
        signal_bound_port(r, link);
    }
    Ok(())
}

/// Typed `channel_recv`. Requires `READ` permission. Returns the number
/// of bytes copied into `buf`, or an error. The channel's generation is
/// compared under the `POOL` hold that dequeues (see [`channel_send_cap`]).
pub fn channel_recv_cap(
    table: &crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Channel>,
    buf: &mut [u8],
) -> Result<usize, ChannelCapError> {
    let r = table.get(cap, CapPerms::READ)?;
    // No owner gate — the cap *is* the authorization. Routing this through
    // the legacy owner check would break the topology model the typed path
    // exists for: the boot seed mints a READ cap on a channel the kernel seed
    // task created, so the grantee is by definition not the owner. A cap that
    // has passed kind + slot generation + perms + channel generation is a
    // stronger proof than the owner field, not a weaker one.
    let mut pool = POOL.lock();
    let i = live_index(&pool, r)?;
    let chan = &mut pool.channels[i];
    if chan.is_empty() {
        return Err(ChannelCapError::Empty);
    }
    // A zero-byte copy (an empty message, or an empty `buf`) consumes the
    // message and answers `Empty`, as this call did before gap 1.
    match pop(chan, buf) {
        0 => Err(ChannelCapError::Empty),
        n => Ok(n),
    }
}

/// Destroy the channel a packed reference names. No owner gate: the caller
/// resolved a capability, which is the authority.
///
/// `Stale` if the slot does not carry the reference's generation.
pub fn channel_destroy_ref(r: u32) -> Result<(), ChannelCapError> {
    let mut pool = POOL.lock();
    let i = live_index(&pool, r)?;
    pool.channels[i] = Channel::zeroed();
    Ok(())
}

/// Free every channel `tid` owns, for the task-exit hook (`task_release_all`).
///
/// Each freed slot is zeroed as the destroy paths zero it, so its generation
/// goes to the vacant value and a `Cap<Channel>` still naming it answers
/// `Stale` in every table; the slots stop counting toward the task's
/// [`MAX_CHANNELS_PER_TASK`] share. Every owner, kernel TIDs included, the
/// filter `port_release_all` and `shm_release_all` apply.
///
/// One `POOL` hold over the whole table: nothing is woken and no other lock is
/// taken, so there is nothing to release the lock for between slots. Cost: one
/// pass over `MAX_CHANNELS` slots on the exit path.
pub fn channel_release_all(tid: u32) {
    let mut pool = POOL.lock();
    for chan in pool.channels.iter_mut() {
        if chan.state == ChannelState::Active && chan.owner == tid {
            *chan = Channel::zeroed();
        }
    }
}

/// Typed channel destroy: resolves the capability uncontained with `WRITE`
/// (a release stays live while RFC-0036 containment is armed, as
/// `port_destroy_cap` does), destroys the channel through its generation, and
/// revokes the capability, `Stale` included (a capability to a gone channel
/// names nothing). For the Channel arm of `SYS_CLOSE_TYPED`.
pub fn channel_destroy_cap(
    table: &mut crate::cap::CapTable,
    cap: crate::cap::Cap<crate::cap::targets::Channel>,
) -> Result<(), ChannelCapError> {
    let r = table.get_uncontained(cap, CapPerms::WRITE)?;
    let destroyed = channel_destroy_ref(r);
    table.revoke(cap);
    destroyed
}

/// Receive one message from channel `ch` into `buf`.
///
/// Returns the number of bytes copied (> 0) on success,
/// 0 if the ring is empty, -1 on error (invalid index, channel not active,
/// or the caller is not the owner).
///
/// # WHY the ownership check exists
///
/// `SYS_IPC_RECEIVE` / `SYS_CHAN_READ` (retired in RFC-0040 gap 1) passed a raw ring-3
/// integer bounded only by `MAX_CHANNELS`, and receiving is **destructive** —
/// the message is popped. Without this check any task could sweep
/// `0..MAX_CHANNELS` and drain every other task's inbox: it reads the
/// payloads (confidentiality) *and* the rightful receiver never sees them
/// (integrity). Same class as the
/// `port` / `io_ring` / `shm` fixes: the owner field existed nowhere, so the
/// call could not authorize even in principle.
///
/// Cost: one `u32` compare against a field already in the cache line being
/// touched, plus the two O(1) scheduler loads in [`caller_ctx`].
#[wcet(40_us)]
pub fn channel_recv(ch: usize, buf: &mut [u8]) -> i32 {
    let (caller, privileged) = caller_ctx();
    // Kernel tasks bypass, exactly as `cap_check` does.
    recv_core(ch, buf, if privileged { None } else { Some(caller) })
}

/// Shared receive body. `gate == Some(tid)` enforces `owner == tid`;
/// `gate == None` means the caller has already been authorized by a
/// stronger mechanism (kernel privilege, or a typed `Cap<Channel>`).
#[inline]
fn recv_core(ch: usize, buf: &mut [u8], gate: Option<u32>) -> i32 {
    if ch >= MAX_CHANNELS {
        return -1;
    }

    let mut pool = POOL.lock();
    let chan = &mut pool.channels[ch];

    if chan.state != ChannelState::Active {
        return -1;
    }
    if let Some(caller) = gate {
        if chan.owner != caller {
            return -1;
        }
    }
    if chan.is_empty() {
        return 0;
    }

    pop(chan, buf) as i32
}

/// Free channel `ch`, returning it to the pool.
///
/// Returns 0 on success, -1 if the index is out of range or the caller is
/// neither the owner nor a kernel task.
///
/// # WHY the ownership check exists
///
/// `SYS_IPC_DESTROY` (retired in RFC-0040 gap 1) took a raw ring-3 index and
/// unconditionally zeroed the slot. That is a one-instruction denial of
/// service against any other task on the board — including a userspace
/// driver's command channel — and worse, the slot is immediately
/// re-allocatable, so the attacker can then `channel_create` it back and
/// become the owner of an id the victim still believes it holds. On a robot
/// that is a control-path outage, not a nuisance.
///
/// Signature changed from `()` to `i32` so the syscall layer could report the
/// refusal instead of a silent success, as `-1` to ring 3.
///
/// An in-range slot that is not active is a no-op answered with 0: the kernel
/// callers in `domains/robot/bench` destroy their own channels through this and rely
/// on that. Ring 3 destroys a channel through `SYS_CLOSE_TYPED`
/// ([`channel_destroy_cap`]).
pub fn channel_destroy(ch: usize) -> i32 {
    if ch >= MAX_CHANNELS {
        return -1;
    }
    let (caller, privileged) = caller_ctx();
    let mut pool = POOL.lock();
    if !privileged
        && pool.channels[ch].state == ChannelState::Active
        && pool.channels[ch].owner != caller
    {
        return -1;
    }
    pool.channels[ch] = Channel::zeroed();
    0
}

/// Wipe the whole pool. Host-test hygiene only — the suite shares one static
/// `POOL`, so each test starts from a known state. Never built into the
/// kernel: a reachable "free every channel on the board" entry point is
/// precisely the DoS that [`channel_destroy`] above closes.
#[cfg(test)]
pub fn __channel_reset_for_tests() {
    let mut pool = POOL.lock();
    for i in 0..MAX_CHANNELS {
        pool.channels[i] = Channel::zeroed();
        pool.next_gen[i] = 1;
    }
}

/// Fast-forward slot `i`'s own generation source, so a host test reaches its
/// wrap without `LAYOUT.gen_max()` create/destroy cycles at that index.
#[cfg(test)]
pub fn __channel_set_next_gen_for_tests(i: usize, next_gen: u32) {
    POOL.lock().next_gen[i] = next_gen;
}

/// Print channel pool statistics to the console via SBI legacy putchar.
///
/// Uses the RISC-V SBI legacy console putchar (EID 0x01) so the IPC crate
/// does not need a dependency on `azos_drv_*`.
pub fn channel_info() {
    let pool = POOL.lock();

    let mut active = 0usize;
    for i in 0..MAX_CHANNELS {
        if pool.channels[i].state == ChannelState::Active {
            active += 1;
        }
    }

    sbi_puts("[IPC] Channel pool: ");
    sbi_put_usize(active);
    sbi_puts("/");
    sbi_put_usize(MAX_CHANNELS);
    sbi_puts(" active  (ring_cap=");
    sbi_put_usize(RING_CAP);
    sbi_puts(", msg_max=");
    sbi_put_usize(MSG_MAX_LEN);
    sbi_puts(")\n");

    for i in 0..MAX_CHANNELS {
        let ch = &pool.channels[i];
        if ch.state == ChannelState::Active {
            sbi_puts("[IPC]   ch[");
            sbi_put_usize(i);
            sbi_puts("]  queued=");
            sbi_put_usize(ch.count());
            sbi_puts("  tx=");
            sbi_put_u32(ch.tx_count);
            sbi_puts("  rx=");
            sbi_put_u32(ch.rx_count);
            sbi_puts("\n");
        }
    }
}

// ── SBI legacy console putchar (EID=0x01) ────────────────────────────────────
//
// Minimal self-contained printing so this crate does not depend on
// azos_drv_*.  SBI legacy putchar is universally supported on
// QEMU virt, VF2, and K1.

#[cfg(target_arch = "riscv64")]
fn sbi_putchar(c: u8) {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") 0x01usize,   // SBI legacy extension: console putchar
            in("a0") c as usize,
            options(nomem, nostack),
        );
    }
}

/// Non-RISC-V builds have no SBI. The only such build is the host test
/// runner (`tests/host/ipc-chan-tests`), which pulls this file in with `#[path]`;
/// `a7`/`a0` are RISC-V register names and will not assemble anywhere else.
/// `channel_info` is a diagnostic print, so dropping the output is the
/// correct degradation — the pool logic under test is untouched.
#[cfg(not(target_arch = "riscv64"))]
fn sbi_putchar(_c: u8) {}

fn sbi_puts(s: &str) {
    for b in s.bytes() {
        sbi_putchar(b);
    }
}

fn sbi_put_usize(mut v: usize) {
    if v == 0 {
        sbi_putchar(b'0');
        return;
    }
    let mut buf = [0u8; 20]; // max digits for u64
    let mut pos = buf.len();
    while v > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    for &b in &buf[pos..] {
        sbi_putchar(b);
    }
}

fn sbi_put_u32(v: u32) {
    sbi_put_usize(v as usize);
}
