// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fast-IPC **endpoints**: the object a client must hold a capability to
//! before it may send a request (RFC-0040 gap 2, stage 1).
//!
//! # The hole this exists to close
//!
//! Fast IPC is addressed by TID. `fast_ipc_call(caller, server, words)`
//! checked two things about its destination, and both are
//! liveness: that it is not the caller itself, and that
//! `sched_seam::tid_exists` says a task with that TID is alive. **Neither is
//! authority.** Any task whose seccomp profile grants `SYS_IPC_FAST_CALL` can
//! call any live task in the system.
//!
//! The asymmetry is what makes it a defect rather than a design: the REPLY
//! direction of the same exchange does check authority —
//! `if !privileged && slot.server_tid != replier_tid { return Refused; }`,
//! plus a per-exchange generation. The pattern is already written, twenty
//! lines away, on the other half of the same call.
//!
//! An endpoint is the name a client is given instead of a TID. Holding
//! `Cap<Endpoint>` with `WRITE` is the right to send a request to whatever
//! service listens on it; holding nothing is the right to send nothing.
//!
//! # Why a new kind and not one of the three that look like it
//!
//! * `Cap<Channel>` is a message ring with **no task binding at all** and no
//!   per-exchange identity — it cannot express "this reply answers that
//!   request".
//! * `Cap<Port>` is a one-way event queue (`bind` / `queue_event` / `poll`).
//!   No reply channel.
//! * `Cap<Task>` is authority over a TASK, which is a different authority from
//!   "may ask this service for something" — and it names the server by its
//!   TID, which is exactly the coupling this removes. `ty::TASK` is also
//!   the cautionary tale: it was declared, `CAPS.TOML` accepted the name
//!   `"task"`, and `seed_one_cap` dropped it on `_ => None`, so a topology
//!   could ask for one and silently receive nothing (until wave 12, which
//!   mints the one target `"tasks"`). This module is minted and seeded from
//!   its first commit for that reason.
//!
//! # What stage 1 does and does not do
//!
//! This is the object, its capability and its lifetime. It does **not** change
//! `fast_ipc` — 108/109/110 and 580 still take a TID after this commit, and
//! the hole above is still open. Stage 2 is what makes the call take a
//! `Cap<Endpoint>`; the untyped call stays alongside it during the migration
//! and is retired afterwards, the way `Cap<File>` shipped beside `SYS_OPEN`
//! and 20 was retired once nothing issued it. Landing the object first keeps
//! the gate meaningful at each step.

use azos_sync::SpinLock;

use crate::cap::objref;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cap::{ty, CapError, CapPerms, CapTable};

/// How a `Cap<Endpoint>` packs `(index, generation)`: 8 index bits, 24 of
/// generation (`objref::ENDPOINT`).
const LAYOUT: objref::Layout = objref::ENDPOINT;

/// Endpoints the machine may have live at once (Kconfig `IPC_ENDPOINTS`;
/// the per-endpoint call queues, `ep_queue.rs`, have the same size).
pub const MAX_ENDPOINTS: usize = azos_limits::IPC_ENDPOINTS;

/// Endpoints ONE task may own at once (Kconfig `IPC_ENDPOINTS_PER_TASK`).
///
/// A quota, and counted under the same lock that allocates — the same rule
/// `port::create_core` follows, and for the same reason: checking a quota and
/// *then* taking the lock lets two harts both pass the check and both
/// allocate. Without it one task could take every slot and no other service
/// could ever be created.
pub const MAX_ENDPOINTS_PER_TASK: usize = azos_limits::IPC_ENDPOINTS_PER_TASK;

const _: () = assert!(MAX_ENDPOINTS as u64 <= 1u64 << LAYOUT.idx_bits());
const _: () = assert!(MAX_ENDPOINTS_PER_TASK >= 1);
const _: () = assert!(MAX_ENDPOINTS_PER_TASK < MAX_ENDPOINTS);

/// Longest endpoint name the topology may use. Names are compared whole, so
/// a longer one is REFUSED rather than truncated — two services whose names
/// agree for 24 bytes would otherwise silently share one endpoint, which is
/// the worst possible way for this to fail.
pub const ENDPOINT_NAME_MAX: usize = 24;

/// The prefix of a proxy endpoint's name (`endpoint.rpc-<service>`, the
/// topology's `PROXY_PREFIX`: one test pins the two spellings together).
/// An endpoint created under such a name is a **proxy**: the local face of a
/// service on another node, served by the RPC server. The topology decides
/// which endpoints are proxies by naming them, and `neverallow` decides who
/// may serve one; the kernel only remembers the fact for the call path
/// ([`is_proxy`]).
pub const PROXY_NAME_PREFIX: &[u8] = b"rpc-";

/// Kernel state for one endpoint.
#[derive(Clone, Copy)]
pub struct Endpoint {
    /// The task serving it, or `UNCLAIMED` for a named endpoint no server has
    /// taken yet. `0` while the slot is free.
    pub owner_tid: u32,
    /// The topology name, for an endpoint created by name. Empty (`name_len`
    /// 0) for one created anonymously.
    pub name: [u8; ENDPOINT_NAME_MAX],
    /// Bytes of `name` in use.
    pub name_len: u8,
    /// Stamped at create from this slot's own entry in
    /// `EndpointTable::next_gen`, `0` while the slot is free (RFC-0040 gap 1,
    /// revised, owner decision 2026-09-26): per-slot, so no external,
    /// non-cap_store holder of a packed endpoint reference exists (unlike
    /// `port.rs`'s IRQ bindings and waiters) — a targeted per-index sweep
    /// (`objref::sweep_index`) is the whole fix here, no epoch needed.
    pub generation: u32,
    /// Whether the slot holds a live endpoint.
    pub active: bool,
    /// The port source the serving task bound this endpoint's notices to
    /// (`PORT_BIND`, source 4; wave 15 N5b), `PortLink::NONE` for
    /// none.
    pub link: crate::port_link::PortLink,
    /// Live update: `0` for none; [`SWAP_OPEN`] while the supervisor has
    /// opened a swap of this endpoint's server and the successor has not
    /// appeared; else the successor's TID (granted `READ` from the signed
    /// row, serving nothing until [`endpoint_rebind_all`]). `owner_tid` and
    /// the identity word keep naming the old server meanwhile.
    pub successor: u32,
    /// The handover has begun (`ep_queue::begin_handover`): new calls wait
    /// for `successor`.
    pub handover: bool,
}

/// [`Endpoint::successor`]: a swap is open, no successor named yet.
pub const SWAP_OPEN: u32 = u32::MAX - 1;

impl Endpoint {
    const fn empty() -> Self {
        Self {
            owner_tid: 0,
            name: [0u8; ENDPOINT_NAME_MAX],
            name_len: 0,
            generation: 0,
            active: false,
            link: crate::port_link::PortLink::NONE,
            successor: 0,
            handover: false,
        }
    }

    /// The name as bytes, empty for an anonymous endpoint.
    fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

const EMPTY_ENDPOINT: Endpoint = Endpoint::empty();

/// The endpoint table plus its per-slot generation sources (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26), under the same lock. `Deref`/
/// `DerefMut` to the endpoint array so every existing `eps[i]` / `eps.iter()`
/// accessor below is unchanged; only `create_core` reads `next_gen`.
struct EndpointTable {
    eps: [Endpoint; MAX_ENDPOINTS],
    /// Entry `i` is the generation index `i`'s *next* create will stamp.
    /// Starts at 1 (`0` doubles as the mid-sweep marker), never reset by an
    /// ordinary release — only by that slot's own targeted wrap sweep. See
    /// `objref`'s module doc ("Per-slot generations...").
    next_gen: [u32; MAX_ENDPOINTS],
}

impl core::ops::Deref for EndpointTable {
    type Target = [Endpoint; MAX_ENDPOINTS];
    fn deref(&self) -> &Self::Target {
        &self.eps
    }
}

impl core::ops::DerefMut for EndpointTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.eps
    }
}

static ENDPOINTS: SpinLock<EndpointTable> = SpinLock::new(EndpointTable {
    eps: [EMPTY_ENDPOINT; MAX_ENDPOINTS],
    next_gen: [1u32; MAX_ENDPOINTS],
});

/// Per slot, the endpoint's identity in one word for a lookup that takes no
/// lock (wave 15 N5): `generation << 32 | owner_tid` while the slot is
/// active, 0 otherwise. Written under `ENDPOINTS` by [`publish`] wherever
/// the slot's activity, generation or owner changes; read by
/// [`endpoint_dest_for`] in a QSBR read section. A reader sees one store
/// whole, and the generation it compares makes a reused slot answer
/// `Stale`, never another endpoint's owner.
static LOOKUP: [AtomicU64; MAX_ENDPOINTS] = [const { AtomicU64::new(0) }; MAX_ENDPOINTS];

/// Per slot: the endpoint there is a proxy (its name starts with
/// [`PROXY_NAME_PREFIX`]). Written under `ENDPOINTS` at create and at
/// unpublish; read without a lock on the v2 call path.
static PROXY: [AtomicBool; MAX_ENDPOINTS] = [const { AtomicBool::new(false) }; MAX_ENDPOINTS];

/// Is the endpoint `d` names a proxy? Takes no lock. A slot reused between
/// the lookup that made `d` and this read answers for its new endpoint, which
/// is the worst case of a check the call repeats against the generation.
#[inline]
pub fn is_proxy(d: &Dest) -> bool {
    PROXY.get(d.index()).is_some_and(|p| p.load(Ordering::Relaxed))
}

/// Per slot: destroyed, and not yet reusable. A destroyed endpoint's slot
/// goes back to the pool only after a grace period ([`glue::retire`]), so a
/// lookup that read the old word before the destroy, and is still inside its
/// read section, can never meet a new endpoint in the same slot.
static HELD: [AtomicBool; MAX_ENDPOINTS] = [const { AtomicBool::new(false) }; MAX_ENDPOINTS];

/// Per slot, the send capabilities to the live endpoint there (wave 15 N5b,
/// Kconfig `IPC_PORT_NOTICES`; `cap::senders` says what one is):
/// `generation << 32 | count`, written `(generation, 0)` at create and 0 at
/// destroy. [`sender_delta`] changes the count only while the generation
/// matches the capability's, so a stale capability of an earlier endpoint
/// at this index, revoked or wiped later, counts for nothing.
static SENDERS: [AtomicU64; MAX_ENDPOINTS] = [const { AtomicU64::new(0) }; MAX_ENDPOINTS];

/// Endpoints whose count fell to zero since the last [`flush_notices`], one
/// bit per slot.
const NOTICE_WORDS: usize = MAX_ENDPOINTS.div_ceil(64);
static NOTICE: [AtomicU64; NOTICE_WORDS] = [const { AtomicU64::new(0) }; NOTICE_WORDS];

/// `EREVOKED` / `EPEERDIED` as the positive codes a gone port
/// event carries.
const CODE_REVOKED: u16 = azos_abi::error::Errno::EREVOKED as u16;
const CODE_PEER_DIED: u16 = azos_abi::error::Errno::EPEERDIED as u16;

/// The [`crate::cap::senders::DeltaHook`] the kernel registers: a send
/// capability to the endpoint `r` names came (`d = 1`) or went (`d = -1`).
/// Runs under the cap table's lock and takes none: one CAS on the slot's
/// count. `true` when the count fell to zero (the endpoint is marked for
/// [`flush_notices`]). A capability whose generation is not the live
/// endpoint's changes nothing.
pub fn sender_delta(r: u32, d: i32) -> bool {
    let i = LAYOUT.idx(r) as usize;
    let g = u64::from(LAYOUT.gen(r));
    let Some(cell) = SENDERS.get(i) else { return false };
    let mut w = cell.load(Ordering::Acquire);
    loop {
        if g == 0 || w >> 32 != g {
            return false;
        }
        let n = w & 0xFFFF_FFFF;
        let m = if d > 0 { n + 1 } else if n == 0 { return false } else { n - 1 };
        match cell.compare_exchange_weak(w, (g << 32) | m, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(cur) => w = cur,
        }
    }
    if d < 0 && w & 0xFFFF_FFFF == 1 {
        NOTICE[i / 64].fetch_or(1u64 << (i % 64), Ordering::AcqRel);
        return true;
    }
    false
}

/// The send capabilities to the endpoint `r` names, `None` for a stale
/// reference. Tests and diagnostics.
pub fn senders_of(r: u32) -> Option<u32> {
    let i = LAYOUT.idx(r) as usize;
    let w = SENDERS.get(i)?.load(Ordering::Acquire);
    (LAYOUT.gen(r) != 0 && w >> 32 == u64::from(LAYOUT.gen(r))).then_some(w as u32)
}

/// The [`crate::cap::senders::FlushHook`] the kernel registers: for each
/// endpoint marked by [`sender_delta`], if it is still live, still has no
/// sender and is bound to a port, mark its port source pending
/// (`PORT_EVENT_NO_SENDERS`, code `ENOSENDERS`) and wake the port's
/// waiters. Coalesced: a count that fell to zero twice between two flushes
/// is one notice, and one that rose again before the flush is none.
/// Called with no cap-table or pool lock held.
pub fn flush_notices() {
    for (wi, word) in NOTICE.iter().enumerate() {
        let mut bits = word.swap(0, Ordering::AcqRel);
        while bits != 0 {
            let i = wi * 64 + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            let target = {
                let eps = ENDPOINTS.lock_irqsave();
                let e = &eps[i];
                let none_left = SENDERS[i].load(Ordering::Acquire) == u64::from(e.generation) << 32;
                (e.active && none_left && !e.link.is_none())
                    .then(|| (e.link, LAYOUT.pack(i as u32, e.generation)))
            };
            if let Some((link, r)) = target {
                let _ = crate::port::port_signal(link, crate::port::PortSourceKind::Endpoint(r));
            }
        }
    }
}

/// Store `link` as the port source endpoint `r` reports its notices to
/// (`PORT_BIND`, source 4), for its serving task `tid` only
/// (`NotOwner` otherwise). The rules of `channel::channel_set_link`: stored
/// when there is no link, the link names the same port, or it equals
/// `replace`; `Busy(current)` otherwise. `Stored { ready }` is whether the
/// endpoint has no sender now, so a bind made after the last sender went
/// still reports it once.
pub fn endpoint_set_link(
    r: u32,
    tid: u32,
    link: crate::port_link::PortLink,
    replace: crate::port_link::PortLink,
) -> Result<crate::port_link::LinkSet, EndpointCapError> {
    let mut eps = ENDPOINTS.lock_irqsave();
    let i = live_index(&eps, r)?;
    if eps[i].owner_tid != tid {
        return Err(EndpointCapError::NotOwner);
    }
    let cur = eps[i].link;
    if cur.is_none() || cur.port == link.port || cur == replace {
        eps[i].link = link;
        let none_left = SENDERS[i].load(Ordering::Acquire) == u64::from(eps[i].generation) << 32;
        return Ok(crate::port_link::LinkSet::Stored { ready: none_left });
    }
    Ok(crate::port_link::LinkSet::Busy(cur))
}

/// Clear endpoint `r`'s link if it is still `link`. Nothing for a stale `r`.
pub fn endpoint_clear_link(r: u32, link: crate::port_link::PortLink) {
    let mut eps = ENDPOINTS.lock_irqsave();
    if let Ok(i) = live_index(&eps, r) {
        if eps[i].link == link {
            eps[i].link = crate::port_link::PortLink::NONE;
        }
    }
}

/// The endpoint at slot `i` (reference `r`) is gone: its port source, if it
/// had one, reports `PORT_EVENT_SOURCE_GONE` with `code`. No lock held.
fn post_gone(link: crate::port_link::PortLink, r: u32, code: u16) {
    if !link.is_none() {
        let _ = crate::port::port_source_gone(link, crate::port::PortSourceKind::Endpoint(r), code);
    }
}

/// Publish slot `i`'s identity word (under `ENDPOINTS`).
fn publish(eps: &[Endpoint; MAX_ENDPOINTS], i: usize) {
    let e = &eps[i];
    let w = if e.active { (u64::from(e.generation) << 32) | u64::from(e.owner_tid) } else { 0 };
    LOOKUP[i].store(w, Ordering::Release);
}

/// Take slot `i`'s endpoint out of service (under `ENDPOINTS`): no lookup
/// finds it, no call queues on it, and the slot is held out of the pool
/// until [`glue::retire`]'s grace period has passed.
fn unpublish(eps: &mut [Endpoint; MAX_ENDPOINTS], i: usize) {
    eps[i] = Endpoint::empty();
    LOOKUP[i].store(0, Ordering::Release);
    SENDERS[i].store(0, Ordering::Release);
    PROXY[i].store(false, Ordering::Relaxed);
    HELD[i].store(true, Ordering::Relaxed);
    glue::close(i);
}

/// The kernel side of the endpoint lifecycle: the per-endpoint call queues
/// (`ep_queue.rs`), the QSBR read section of
/// the lookup and the grace period before a slot is reused. The host suites
/// that `#[path]`-pull this file have none of it, and their stand-ins
/// release a slot at once.
#[cfg(target_os = "none")]
mod glue {
    use core::cell::UnsafeCell;
    use core::sync::atomic::Ordering;

    use azos_sync::qsbr::{self, RcuHead};

    /// Load slot `i`'s identity word in a QSBR read section. The section is
    /// held by masking interrupts (no preemption, so this CPU passes no
    /// quiescent state), which costs two CSR writes where `qsbr::read`'s
    /// preemption count costs two atomic read-modify-write loops.
    #[inline(always)]
    pub fn load_word(i: usize) -> u64 {
        let irq = azos_sync::scope::IrqOff::new();
        let _rd = qsbr::read_in(&irq);
        match super::LOOKUP.get(i) {
            Some(w) => w.load(Ordering::Acquire),
            None => 0,
        }
    }
    pub fn open(i: usize, gen: u32, owner: u32) {
        crate::ep_queue::open(i, gen, owner)
    }
    pub fn set_owner(i: usize, gen: u32, owner: u32) {
        crate::ep_queue::set_owner(i, gen, owner)
    }
    pub fn close(i: usize) {
        crate::ep_queue::close(i)
    }
    /// Complete the calls on slot `i` with `code`, `ENDPOINTS` released.
    pub fn drain(i: usize, code: i32, server: u32) {
        crate::fastcall::drain_endpoint(i, code, server)
    }
    use super::HandoverError;
    fn map(e: crate::ep_queue::HandoverError) -> HandoverError {
        use crate::ep_queue::HandoverError as Q;
        match e {
            Q::Stale => HandoverError::Stale,
            Q::NotOwner => HandoverError::NotOwner,
            Q::NotInHandover => HandoverError::NotInHandover,
            Q::Busy => HandoverError::Busy,
            Q::InService(n) => HandoverError::InService(n),
        }
    }
    pub fn begin_handover(i: usize, gen: u32, old: u32, new: u32) -> Result<(), HandoverError> {
        crate::ep_queue::begin_handover(i, gen, old, new).map_err(map)
    }
    pub fn abort_handover(i: usize, gen: u32, old_idx: usize) -> Result<(), HandoverError> {
        crate::ep_queue::abort_handover(i, gen, old_idx).map_err(map)
    }
    pub fn rebind(i: usize, gen: u32, new: u32, old_idx: usize, new_idx: usize) -> Result<(), HandoverError> {
        crate::ep_queue::rebind(i, gen, new, old_idx, new_idx, |caller_idx, old| {
            crate::fastcall::retarget_donation(caller_idx, old, new, new_idx)
        })
        .map_err(map)
    }
    pub fn represent(i: usize, gen: u32, old: u32) -> Result<(usize, usize), HandoverError> {
        crate::ep_queue::represent(i, gen, old).map_err(map)
    }
    pub fn in_service(i: usize, old: u32) -> usize {
        crate::ep_queue::in_service(i, old)
    }

    #[repr(C)]
    struct Head(UnsafeCell<RcuHead>);
    // SAFETY: a head is touched only by `call_rcu` and its callback, one at a
    // time: a slot is retired once and not again until the callback ran
    // (`HELD` keeps it out of the pool until then).
    unsafe impl Sync for Head {}
    static HEADS: [Head; super::MAX_ENDPOINTS] =
        [const { Head(UnsafeCell::new(RcuHead::new())) }; super::MAX_ENDPOINTS];

    /// The callback: slot `i` may be reused.
    unsafe fn release(head: *mut RcuHead) {
        let base = HEADS.as_ptr() as usize;
        let i = (head as usize - base) / core::mem::size_of::<Head>();
        if let Some(h) = super::HELD.get(i) {
            h.store(false, Ordering::Release);
        }
    }

    /// Give slot `i` back to the pool after a grace period (the first
    /// `call_rcu` user, wave 15 N5). With Kconfig `RCU_QSBR` off it is
    /// given back at once.
    pub fn retire(i: usize) {
        if let Some(h) = HEADS.get(i) {
            // SAFETY: see `Head`; `HEADS` is static.
            unsafe { qsbr::call_rcu(h.0.get(), release) };
        }
    }
}

#[cfg(not(target_os = "none"))]
mod glue {
    pub fn load_word(i: usize) -> u64 {
        match super::LOOKUP.get(i) {
            Some(w) => w.load(core::sync::atomic::Ordering::Acquire),
            None => 0,
        }
    }
    pub fn open(_i: usize, _gen: u32, _owner: u32) {}
    pub fn set_owner(_i: usize, _gen: u32, _owner: u32) {}
    pub fn close(_i: usize) {}
    pub fn drain(_i: usize, _code: i32, _server: u32) {}
    use super::HandoverError;
    pub fn begin_handover(_i: usize, _gen: u32, _old: u32, _new: u32) -> Result<(), HandoverError> { Ok(()) }
    pub fn abort_handover(_i: usize, _gen: u32, _old_idx: usize) -> Result<(), HandoverError> { Ok(()) }
    pub fn rebind(_i: usize, _gen: u32, _new: u32, _old_idx: usize, _new_idx: usize) -> Result<(), HandoverError> {
        Ok(())
    }
    pub fn represent(_i: usize, _gen: u32, _old: u32) -> Result<(usize, usize), HandoverError> { Ok((0, 0)) }
    pub fn in_service(_i: usize, _old: u32) -> usize { 0 }
    pub fn retire(i: usize) {
        if let Some(h) = super::HELD.get(i) {
            h.store(false, core::sync::atomic::Ordering::Release);
        }
    }
}

/// `-EPEERDIED` and `-EREVOKED` (`azos_abi::error::Errno`), the codes a call
/// in flight is completed with when its server dies or its endpoint goes.
const PEER_DIED: i32 = -(azos_abi::error::Errno::EPEERDIED as i32);
const REVOKED: i32 = -(azos_abi::error::Errno::EREVOKED as i32);

/// Why an endpoint operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EndpointCapError {
    /// Capability dereference failed. A reference to a destroyed or reused
    /// endpoint is `Cap(Stale)`.
    Cap(CapError),
    /// The pool is full, or this task already owns `MAX_ENDPOINTS_PER_TASK`.
    Full,
    /// The caller is not the endpoint's owner.
    NotOwner,
    /// The endpoint exists and the caller may send to it, but no task serves
    /// it yet. NOT a denial: the caller holds a real capability, so this must
    /// not reach the flight recorder as a program reaching past its authority.
    Unserved,
}

/// Resolve a packed reference to its slot, with `ENDPOINTS` held by the caller.
///
/// `Stale` unless the slot is active and carries the reference's generation, so
/// a freed slot (generation 0), a slot reused by another endpoint, and a bare
/// in-range index (generation 0) all answer `Stale` rather than the wrong
/// endpoint.
fn live_index(eps: &[Endpoint; MAX_ENDPOINTS], r: u32) -> Result<usize, EndpointCapError> {
    let i = LAYOUT.idx(r) as usize;
    let g = LAYOUT.gen(r);
    if g == 0 || i >= MAX_ENDPOINTS || !eps[i].active || eps[i].generation != g {
        return Err(EndpointCapError::Cap(CapError::Stale));
    }
    Ok(i)
}

/// The create body: the new endpoint's packed `(index, generation)`
/// reference.
///
/// **Per-slot generation, swept only at its own index (RFC-0040 gap 1,
/// revised, owner decision 2026-09-26).** Each slot's generation is its own
/// (`EndpointTable::next_gen`); when slot `i`'s reaches `LAYOUT.gen_max()`,
/// this marks it mid-sweep (`next_gen[i] = 0`, which the free-slot scan
/// already treats as unavailable), releases `ENDPOINTS`, runs
/// `objref::sweep_index(ty::ENDPOINT, i)` — which revokes only the stale
/// `Cap<Endpoint>`s left over at index `i`, nothing live — resets
/// `next_gen[i]` to `1`, and retries. Must not be called with a cap-table
/// lock held.
fn create_core(owner_tid: u32, name: Option<&[u8]>, quota: bool) -> Option<u32> {
    // Two passes at most: the second runs only after this call's own
    // per-slot wrap sweep finishes.
    for _ in 0..2 {
        let mut eps = ENDPOINTS.lock_irqsave();
        // A named endpoint that already exists is never created twice: the
        // whole point of a name is that both sides reach the SAME object.
        if let Some(n) = name {
            if eps.iter().any(|e| e.active && e.name_bytes() == n) {
                return None;
            }
        }
        if quota {
            let held = eps.iter().filter(|e| e.active && e.owner_tid == owner_tid).count();
            if held >= MAX_ENDPOINTS_PER_TASK {
                return None;
            }
        }
        // `next_gen[i] != 0` excludes a slot this call has marked mid-sweep.
        let slot = (0..MAX_ENDPOINTS)
            .find(|&i| !eps[i].active && eps.next_gen[i] != 0 && !HELD[i].load(Ordering::Acquire))?;
        // Taken once a free slot is known, so a full pool or a quota refusal
        // consumes no generation.
        let gen = match objref::take_slot_gen(eps.next_gen[slot], LAYOUT) {
            objref::SlotGen::Gen(g) => g,
            objref::SlotGen::Wrap => {
                eps.next_gen[slot] = 0;
                drop(eps);
                objref::sweep_index(ty::ENDPOINT, slot as u32);
                eps = ENDPOINTS.lock_irqsave();
                eps.next_gen[slot] = 1;
                continue;
            }
        };
        eps.next_gen[slot] = gen + 1;
        let mut e = Endpoint::empty();
        e.owner_tid = owner_tid;
        e.generation = gen;
        e.active = true;
        if let Some(n) = name {
            e.name[..n.len()].copy_from_slice(n);
            e.name_len = n.len() as u8;
        }
        eps[slot] = e;
        PROXY[slot].store(name.is_some_and(|n| n.starts_with(PROXY_NAME_PREFIX)), Ordering::Relaxed);
        SENDERS[slot].store(u64::from(gen) << 32, Ordering::Release);
        publish(&eps, slot);
        glue::open(slot, gen, owner_tid);
        return Some(LAYOUT.pack(slot as u32, gen));
    }
    None
}

/// Create an endpoint owned by `owner_tid` and return its packed reference,
/// minting no capability.
///
/// The value a `Cap<Endpoint>` *stores*, for the kernel-side caller that has
/// already established the right to create one. Ring 3 never sees this: a
/// capability handle names a slot in the caller's own table, and the reference
/// below is what that slot holds. `port_create` is the same split.
pub fn endpoint_create(owner_tid: u32) -> Option<u32> {
    create_core(owner_tid, None, true)
}

/// Create an endpoint owned by `tid` and mint its `Cap<Endpoint>` into that
/// task's own table with `perms`.
///
/// `perms` is taken rather than fixed at `RW` because the seeder passes what
/// the topology asked for, and a seed that requests `READ` must not quietly
/// receive `WRITE` as well. A server needs `WRITE` to be callable and `READ`
/// to accept; `RW` is what `CAPS.TOML` will normally say.
///
/// **A refused grant destroys the endpoint it was for.** The endpoint is
/// allocated first, so a full cap table would otherwise leave it active and
/// owned with no capability anywhere able to reach it — one leaked slot per
/// call, out of a machine-wide pool of 32. `port_create_cap`,
/// `sys_shm_create_typed` and `sys_ioring_create_typed` all roll back this
/// way.
///
/// Must not be called with a cap-table lock held.
pub fn endpoint_create_cap(
    tid: u32,
    perms: CapPerms,
) -> Option<crate::cap::Cap<crate::cap::targets::Endpoint>> {
    let r = create_core(tid, None, true)?;
    // `DUP` (owner decision 2026-09-26, O3.4): the creator of an anonymous
    // endpoint may gift it. This is distinct from `endpoint_inherit_at_fork`
    // (never `DUP`) and from a NAMED endpoint's grant (`endpoint_named_cap`,
    // topology-controlled — see `CapSpec::transfer`): this path exists only
    // for a task minting a capability over an object it just created itself.
    match objref::grant_packed::<crate::cap::targets::Endpoint>(tid, perms.union(CapPerms::DUP), r) {
        Some(cap) => Some(cap),
        None => {
            let _ = destroy_ref(r);
            None
        }
    }
}

/// A named endpoint that exists but no server has claimed. Never a real TID:
/// `NEXT_TID` does not issue `u32::MAX`, and `endpoint_release_all` refuses it
/// explicitly so a stray call cannot sweep every unclaimed endpoint at once.
pub const UNCLAIMED: u32 = u32::MAX;

/// Owners at and above this value are not tasks: the endpoint is served by the
/// kernel itself (an interface the kernel hosts, `azos_devif`), and the low
/// 16 bits of the owner are the interface's host key. No TID reaches this
/// range (`NEXT_TID` is far below it); [`UNCLAIMED`] and the hand-over and
/// swap sentinels sit above the key range.
pub const KERNEL_HOST_BASE: u32 = 0xFFFF_0000;
/// Host keys are `1..KERNEL_HOST_KEYS`.
pub const KERNEL_HOST_KEYS: u16 = 0xFFF0;

/// The owner word of an endpoint the kernel serves under host key `key`.
pub const fn kernel_host(key: u16) -> u32 {
    KERNEL_HOST_BASE | key as u32
}

/// The host key of an endpoint owner that is the kernel, `None` for a task
/// (or a sentinel).
#[inline(always)]
pub const fn host_key(owner: u32) -> Option<u16> {
    let k = owner.wrapping_sub(KERNEL_HOST_BASE);
    if owner >= KERNEL_HOST_BASE && k >= 1 && k < KERNEL_HOST_KEYS as u32 { Some(k as u16) } else { None }
}

/// The host key of the endpoint the packed reference `r` names, if the kernel
/// serves it (and `r` is not stale): what a lookup by interface asks.
pub fn host_key_of_ref(r: u32) -> Option<u16> {
    let i = LAYOUT.idx(r) as usize;
    if i >= MAX_ENDPOINTS {
        return None;
    }
    host_key(lookup_ref(r).ok()?)
}

/// Does `table` hold a capability to the endpoint the kernel hosts under `key`
/// with every right of `need`? The kernel's own gates ask this of a task's
/// table where a syscall's `cap_check` would prove nothing (it answers `true`
/// for a kernel task): the recovery console's `pm suspend`, `reboot`,
/// `shutdown` and `flight arm`.
///
/// Inherits RFC-0036 containment: while it is armed a `need` with `WRITE`
/// answers `false` even with the capability held, as `CapTable::get` refuses
/// it. The predicate returns `bool`, so a caller cannot tell "no grant" from
/// "contained".
pub fn table_holds_host_right(table: &CapTable, key: u16, need: CapPerms) -> bool {
    if need.contains(CapPerms::WRITE) && crate::cap::degraded_active() {
        return false;
    }
    table
        .lookup_where(ty::ENDPOINT, |r, _, perms| perms.contains(need) && host_key_of_ref(r) == Some(key))
        .is_some()
}

/// Does `table` hold a capability to the endpoint the kernel hosts under `key`,
/// carrying `badge`, with every right of `need`? A device interface asks this
/// of a caller's table for the second wheel of a pair rule and for the ring's
/// per-op authority: the badge is the resource, so "holds the gpio endpoint"
/// and "holds pin 17" are different questions.
///
/// Inherits RFC-0036 containment as [`table_holds_host_right`] does.
pub fn table_holds_host_badge_right(table: &CapTable, key: u16, badge: u32, need: CapPerms) -> bool {
    if need.contains(CapPerms::WRITE) && crate::cap::degraded_active() {
        return false;
    }
    table_holds_host_badge_right_uncontained(table, key, badge, need)
}

/// [`table_holds_host_badge_right`] without the containment step: for a gate
/// whose refusal is made one level down (the motor layer's halt rule, the
/// ring's own containment check after the capability).
pub fn table_holds_host_badge_right_uncontained(table: &CapTable, key: u16, badge: u32, need: CapPerms) -> bool {
    table
        .lookup_where(ty::ENDPOINT, |r, b, perms| {
            b == badge && perms.contains(need) && host_key_of_ref(r) == Some(key)
        })
        .is_some()
}

/// Grant `tid` a capability to the endpoint the kernel hosts under `key`,
/// creating that endpoint on the first grant. `perms` are the holder's rights
/// (the interface's op classes: `READ` observe, `WRITE` act, `EXEC` control);
/// `badge` names the resource the capability stands for (a pin, a bus and
/// address, a wheel pair, a partition: the interface says), 0 meaning
/// resource 0. Boot-time or task-spawn seeding only: ring 3 never mints one.
///
/// `None`, nothing granted, when the key is out of range, the pool or the cap
/// table is full, or a non-zero badge is asked of a build without Kconfig
/// CAP_SLOT_EXT. A refused grant destroys an endpoint this call created.
///
/// Must not be called with a cap-table lock held.
pub fn kernel_endpoint_cap(
    tid: u32,
    perms: CapPerms,
    key: u16,
    badge: u32,
) -> Option<crate::cap::Cap<crate::cap::targets::Endpoint>> {
    let owner = kernel_host(key);
    host_key(owner)?;
    let (r, created) = {
        let found = {
            let eps = ENDPOINTS.lock_irqsave();
            eps.iter()
                .position(|e| e.active && e.owner_tid == owner)
                .map(|i| LAYOUT.pack(i as u32, eps[i].generation))
        };
        match found {
            Some(r) => (r, false),
            None => (create_core(owner, None, false)?, true),
        }
    };
    let granted = if badge == 0 {
        objref::grant_packed::<crate::cap::targets::Endpoint>(tid, perms, r)
    } else {
        crate::cap_store::grant_badged::<crate::cap::targets::Endpoint>(tid, perms, r, badge)
    };
    if granted.is_none() && created {
        let _ = destroy_ref(r);
    }
    granted
}

/// `SYS_CAP_DERIVE`'s authority step: mint, in `tid`'s table, a badged
/// copy of its unbadged endpoint capability `handle`
/// ([`crate::cap_store::mint_badged`]'s rules) **provided a task serves the
/// endpoint**. On a kernel-hosted endpoint the badge IS the resource (a pin, a
/// bus address, a wheel pair, a partition, a sensor type), so a free choice of
/// badge by the holder of an unbadged capability with `DUP` would reach every
/// resource of the interface: only the kernel stamps those badges
/// ([`kernel_endpoint_cap`]). Refused with `MissingPerms`, as the other
/// refusals of a mint are.
pub fn mint_badged(
    tid: u32,
    handle: azos_abi::cap::CapHandle,
    badge: u32,
    rights: CapPerms,
) -> Result<azos_abi::cap::CapHandle, CapError> {
    mint_badged_until(tid, handle, badge, rights, 0)
}

/// [`mint_badged`] with a deadline for the copy (absolute ns on the MONO
/// clock, 0 none).
pub fn mint_badged_until(
    tid: u32,
    handle: azos_abi::cap::CapHandle,
    badge: u32,
    rights: CapPerms,
    expiry_ns: u64,
) -> Result<azos_abi::cap::CapHandle, CapError> {
    let hosted = crate::cap_store::read_table(tid, |t| {
        t.peek_raw(handle).is_some_and(|(kind, _, r)| kind == ty::ENDPOINT && host_key_of_ref(r).is_some())
    })
    .unwrap_or(false);
    if hosted {
        return Err(CapError::MissingPerms);
    }
    crate::cap_store::mint_badged_until(tid, handle, badge, rights, expiry_ns)
}

/// Create the endpoint called `name`, unclaimed, unless it exists already.
/// `true` = created. Boot only, through
/// [`crate::cap_seed::declare_topology_endpoint`]: every name the topology
/// declares takes its pool slot in row order before any task is seeded, so
/// its index (what `cap_lookup` matches) does not depend on which task is
/// spawned first. [`endpoint_named_cap`] then finds it and a `READ` grant
/// claims it.
pub fn endpoint_declare(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > ENDPOINT_NAME_MAX {
        return false;
    }
    create_core(UNCLAIMED, Some(name), false).is_some()
}

/// Grant `tid` a capability to the endpoint called `name`, creating it if this
/// is the first grant for that name.
///
/// **This is the half that lets a client reach a server's endpoint.** Stage 1's
/// anonymous create mints an endpoint into its creator's own table and nowhere
/// else, and `fork` copies no capabilities (a native child is seeded from its
/// row and inherits only descriptors, `azos_syscall::natfork`; a runtime
/// object such as an anonymous endpoint is in no row), so
/// without a name there is no way for two tasks to hold capabilities to one
/// endpoint. A name in `CAPS.TOML` is that way, and it puts the service graph
/// where the rest of this kernel's authority already lives: in the signed
/// topology, declared, auditable, and fixed before anything runs.
///
/// **The permission is the role**, which is why no separate "server" field is
/// needed in the topology:
///
/// * `READ` — may accept requests on it. Claims the endpoint for `tid`, and is
///   refused if another live task already serves it. One server per endpoint.
/// * `WRITE` — may send a request to it. Claims nothing.
///
/// A grant of `RW` is a server that may also call its own endpoint.
///
/// Returns `None` — and grants nothing — for an empty or over-long name, for a
/// second server on the same name, and when the pool or the cap table is full.
/// A name that does not fit is refused rather than truncated: two services
/// whose names agree for `ENDPOINT_NAME_MAX` bytes would otherwise share one
/// endpoint without either of them saying so.
///
/// Must not be called with a cap-table lock held.
pub fn endpoint_named_cap(
    tid: u32,
    perms: CapPerms,
    name: &[u8],
) -> Option<crate::cap::Cap<crate::cap::targets::Endpoint>> {
    named_cap_core(tid, perms, name, 0)
}

/// [`endpoint_named_cap`] with a badge: every call made through the granted
/// capability shows its server `badge` (non-zero). The kernel stamps it from
/// the signed topology at spawn (the importing row's identity,
/// `cap_seed::seed_names_import`), so it is not something the holder chose.
/// Refused (`None`, nothing granted) for a badge of 0, a `READ` grant (a
/// server's own capability carries no badge), and Kconfig CAP_SLOT_EXT off.
pub fn endpoint_named_cap_badged(
    tid: u32,
    perms: CapPerms,
    name: &[u8],
    badge: u32,
) -> Option<crate::cap::Cap<crate::cap::targets::Endpoint>> {
    if badge == 0 || perms.contains(CapPerms::READ) {
        return None;
    }
    named_cap_core(tid, perms, name, badge)
}

fn named_cap_core(
    tid: u32,
    perms: CapPerms,
    name: &[u8],
    badge: u32,
) -> Option<crate::cap::Cap<crate::cap::targets::Endpoint>> {
    if name.is_empty() || name.len() > ENDPOINT_NAME_MAX {
        return None;
    }
    let serves = perms.contains(CapPerms::READ);

    // Existing name, or a fresh endpoint. `created` is carried so that a
    // failed mint rolls back only what THIS call brought into being — an
    // endpoint another task is already using must survive our failure.
    let (r, created) = {
        let found = {
            let eps = ENDPOINTS.lock_irqsave();
            eps.iter()
                .position(|e| e.active && e.name_bytes() == name)
                .map(|i| LAYOUT.pack(i as u32, eps[i].generation))
        };
        match found {
            Some(r) => (r, false),
            None => {
                // The quota does not apply: a named endpoint comes from the
                // signed topology, not from ring 3, and the pool bounds it.
                // Applying the per-task quota here would also charge the
                // endpoint to whichever side happened to be seeded first.
                let owner = if serves { tid } else { UNCLAIMED };
                let r = create_core(owner, Some(name), false)?;
                (r, true)
            }
        }
    };

    // Claim, for a server grant on an endpoint this call did not create.
    if serves && !created {
        let mut eps = ENDPOINTS.lock_irqsave();
        let i = live_index(&eps, r).ok()?;
        if eps[i].owner_tid != UNCLAIMED && eps[i].owner_tid != tid {
            // Served by someone else, unless a live update of its server is
            // open and this is the successor its signed row grants: it holds
            // the capability and claims nothing, the rebind makes it the
            // server.
            if eps[i].successor != SWAP_OPEN && eps[i].successor != tid {
                return None;
            }
            eps[i].successor = tid;
        } else {
            eps[i].owner_tid = tid;
            publish(&eps, i);
            glue::set_owner(i, eps[i].generation, tid);
        }
    }

    let granted = if badge == 0 {
        objref::grant_packed::<crate::cap::targets::Endpoint>(tid, perms, r)
    } else {
        crate::cap_store::grant_badged::<crate::cap::targets::Endpoint>(tid, perms, r, badge)
    };
    match granted {
        Some(cap) => Some(cap),
        None => {
            if created {
                let _ = destroy_ref(r);
            } else if serves {
                // Give the claim back: the grant failed, so this task is not
                // serving anything, and leaving its TID on the endpoint would
                // lock every future server out of a name nobody answers.
                let mut eps = ENDPOINTS.lock_irqsave();
                if let Ok(i) = live_index(&eps, r) {
                    if eps[i].owner_tid == tid {
                        eps[i].owner_tid = UNCLAIMED;
                        publish(&eps, i);
                        glue::set_owner(i, eps[i].generation, UNCLAIMED);
                    }
                }
            }
            None
        }
    }
}

/// The TID serving the endpoint that `cap_raw` names in `caller_tid`'s own
/// capability table, or `None` if the caller may not send to it.
///
/// **This is the authority check `fast_ipc_call` never had** (RFC-0040 gap 2,
/// stage 2). It lives here rather than in the dispatcher for two reasons: the
/// rule belongs with the object it is about, and `tests/host/syscall-tests` does
/// not compile `dispatch.rs`, so a copy in the dispatcher would be the one
/// part of the change with no test behind it.
///
/// Three things must hold, and each `None` is one of them:
///
/// 1. the caller's table resolves `cap_raw` as a live `Cap<Endpoint>` — the
///    generation packed in the reference is what makes a stale one fail;
/// 2. it carries `WRITE`, which is what "may send a request" means; `get`
///    also refuses `WRITE` under RFC-0036 degraded containment, so a contained
///    task may still report on the console but may not open new requests;
/// 3. some live task serves the endpoint. A named endpoint the topology
///    created for a server that has not started is [`UNCLAIMED`], and a call
///    must fail rather than pick a task.
///
/// The caller collapses all three into one refusal on purpose: which one it
/// was would report on capabilities the caller does not hold.
pub fn endpoint_dest_for(caller_tid: u32, cap_raw: u32) -> Result<u32, EndpointCapError> {
    endpoint_resolve(caller_tid, cap_raw).map(|d| d.owner)
}

/// A call's destination: the endpoint (its packed reference) and the task
/// serving it when it was looked up.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dest {
    /// The packed `(index, generation)` reference.
    pub r: u32,
    /// The serving task.
    pub owner: u32,
}

impl Dest {
    /// The endpoint's pool index.
    #[inline(always)]
    pub fn index(&self) -> usize {
        LAYOUT.idx(self.r) as usize
    }
    /// The endpoint's generation.
    #[inline(always)]
    pub fn generation(&self) -> u32 {
        LAYOUT.gen(self.r)
    }
}

/// [`endpoint_dest_for`], with the endpoint's reference: what the fast call
/// queues on. Takes no lock: the capability
/// read is lock-free (N4) and the endpoint's identity word is read in a QSBR
/// read section ([`lookup_ref`]).
#[inline]
pub fn endpoint_resolve(caller_tid: u32, cap_raw: u32) -> Result<Dest, EndpointCapError> {
    let cap: crate::cap::Cap<crate::cap::targets::Endpoint> =
        crate::cap::Cap::from_raw(azos_abi::cap::CapHandle::from_raw(cap_raw));
    let r = match crate::cap_store::get(caller_tid, cap, CapPerms::WRITE) {
        Ok(r) => r,
        // An endpoint the kernel hosts is called with any right (its op
        // classes are checked per op), and containment (which stops a task
        // from opening new requests) does not stop it: the op class that
        // acts is refused inside the call when contained. Only a refusal
        // for want of `WRITE`, or by containment, comes here.
        Err(e @ (CapError::MissingPerms | CapError::Contained)) => {
            return kernel_hosted(caller_tid, cap).ok_or(EndpointCapError::Cap(e));
        }
        Err(e) => return Err(EndpointCapError::Cap(e)),
    };
    let owner = lookup_ref(r)?;
    if owner == UNCLAIMED {
        return Err(EndpointCapError::Unserved);
    }
    Ok(Dest { r, owner })
}

/// `cap` of `caller_tid` names an endpoint the kernel hosts and holds some
/// right on it.
#[cold]
fn kernel_hosted(caller_tid: u32, cap: crate::cap::Cap<crate::cap::targets::Endpoint>) -> Option<Dest> {
    let (r, perms) = crate::cap_store::read_table(caller_tid, |t| {
        let p = t.peek_raw(cap.raw()).map(|(_, p, _)| p)?;
        t.get_uncontained(cap, CapPerms::NONE).ok().map(|r| (r, p))
    })??;
    if perms == CapPerms::NONE {
        return None;
    }
    let owner = lookup_ref(r).ok()?;
    host_key(owner)?;
    Some(Dest { r, owner })
}

/// The task serving the endpoint `r` names, without `ENDPOINTS`: one load of
/// the slot's identity word in a QSBR read section. `Cap(Stale)` unless the
/// slot is active with `r`'s generation.
#[inline]
fn lookup_ref(r: u32) -> Result<u32, EndpointCapError> {
    let i = LAYOUT.idx(r) as usize;
    let g = LAYOUT.gen(r);
    let w = glue::load_word(i);
    if g == 0 || (w >> 32) as u32 != g {
        return Err(EndpointCapError::Cap(CapError::Stale));
    }
    Ok(w as u32)
}

/// The endpoint resolve cache (Kconfig `IPC_RESOLVE_CACHE`, Chain E
/// commit 5): per caller task slot, the last destination its task's
/// [`endpoint_resolve`] accepted, with the two words that resolution read.
///
/// # What a hit proves
///
/// A full resolution reads two words: the caller's capability slot (one
/// atomic word: kind, rights, generation and the endpoint's reference) and
/// the endpoint's identity word `LOOKUP[i]` (its generation and serving
/// task), and decides from those two alone, plus the global containment
/// level. An entry keeps `(caller tid, cap_raw)`, the table slot the
/// caller's capabilities live in, and the two words as a resolution
/// accepted them. A hit reloads both words and requires each to be equal
/// to the cached one, and containment to be off: the full resolution would
/// then read the same words and give the same answer. So everything that
/// changes the answer misses on its own: a revoke, a move out, a rights
/// change or a re-grant changes the slot word; an endpoint destroyed,
/// reused, orphaned or claimed by another server changes `LOOKUP[i]`.
///
/// What the words do not show is which table the caller reads, and that is
/// fixed for a task's life: the table of its domain, which a thread shares
/// with its process and an exec that swaps TIDs leaves where it is. The entry
/// is keyed by the caller's TID (monotone, so a reused slot misses) and
/// cleared at task exit and at exec.
///
/// # Who writes it
///
/// The slot's own task fills it (on a miss, after the full resolution) and
/// reads it; the clears run on that task's own exit and exec paths. No two
/// writers race, so the words
/// are Relaxed atomics; the key is cleared first and written last.
///
/// A miss is the full resolution, unchanged: the refusals and their
/// recording stay there (`azos_syscall::handlers`), so a refused call is
/// recorded once, as without the cache.
pub mod resolve_cache {
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};

    use azos_abi::cap::CapHandle;

    use super::{Dest, LAYOUT, LOOKUP, UNCLAIMED};
    use crate::cap::{ty, CapPerms, CapTable};

    /// Kconfig `IPC_RESOLVE_CACHE`.
    pub const ENABLED: bool = azos_limits::IPC_RESOLVE_CACHE;

    const SLOTS: usize = azos_sched::task::MAX_TASKS;

    /// One task slot's entry, one 32-byte line.
    #[repr(C, align(32))]
    struct Entry {
        /// `(tid << 32) | cap_raw`; 0 for none (a null handle never fills).
        key: AtomicU64,
        /// The capability table slot the word was read from.
        table: AtomicU32,
        /// The serving task's slot when the entry was filled (`u32::MAX`:
        /// none found), a hint for the IPC fast path ([`hit_at`]). In the
        /// line's padding.
        server: AtomicU32,
        /// The capability slot word the resolution accepted.
        cap: AtomicU64,
        /// `LOOKUP[i]` as the resolution accepted it.
        lookup: AtomicU64,
    }

    const EMPTY: Entry =
        Entry {
            key: AtomicU64::new(0),
            table: AtomicU32::new(0),
            server: AtomicU32::new(u32::MAX),
            cap: AtomicU64::new(0),
            lookup: AtomicU64::new(0),
        };
    static ENTRIES: [Entry; if ENABLED { SLOTS } else { 0 }] = [EMPTY; if ENABLED { SLOTS } else { 0 }];

    #[inline(always)]
    fn key(tid: u32, cap_raw: u32) -> u64 {
        (u64::from(tid) << 32) | u64::from(cap_raw)
    }

    /// The destination task `tid` in slot `idx` resolved for `cap_raw`
    /// last, if neither word it was resolved from has changed since and
    /// containment is off; `None` sends the caller to the full resolution.
    #[inline(always)]
    pub fn hit(idx: usize, tid: u32, cap_raw: u32) -> Option<Dest> {
        hit_at(idx, tid, cap_raw).map(|(d, _)| d)
    }

    /// [`hit`], with the serving task's slot as the entry's fill found it
    /// (`u32::MAX`: none): a hint only, which the caller checks still holds
    /// `Dest::owner` (`azos_sched::scheduler::slot_holds`). The owner's TID
    /// is the entry's (the endpoint's lookup word is checked), but a TID can
    /// change slots (an exec's hand-over), which the entry does not see.
    #[inline(always)]
    pub fn hit_at(idx: usize, tid: u32, cap_raw: u32) -> Option<(Dest, u32)> {
        if !ENABLED {
            return None;
        }
        let e = ENTRIES.get(idx)?;
        if e.key.load(Relaxed) != key(tid, cap_raw) {
            return None;
        }
        let w = crate::cap_store::slot_word(e.table.load(Relaxed) as usize, CapHandle(cap_raw));
        if w != e.cap.load(Relaxed) {
            return None;
        }
        let r = CapTable::word_resource(w);
        // A plain load where the full resolution opens a QSBR read section:
        // the word is a static atomic read whole, nothing it names is
        // dereferenced here, and the call re-checks the endpoint's
        // generation and owner under the endpoint's queue lock.
        let lw = LOOKUP.get(LAYOUT.idx(r) as usize)?.load(core::sync::atomic::Ordering::Acquire);
        if lw != e.lookup.load(Relaxed) || crate::cap::degraded_active() {
            return None;
        }
        Some((Dest { r, owner: lw as u32 }, e.server.load(Relaxed)))
    }

    /// After a full resolution of `cap_raw` to `d` by task `tid` in slot
    /// `idx`: keep it, with the two words it was read from, if they still
    /// say exactly that (a change in between keeps nothing).
    #[inline(never)]
    pub fn fill(idx: usize, tid: u32, cap_raw: u32, d: Dest) {
        if !ENABLED {
            return;
        }
        let Some(e) = ENTRIES.get(idx) else { return };
        let Some(table) = crate::cap_store::table_of(tid) else { return };
        let raw = CapHandle(cap_raw);
        let w = crate::cap_store::slot_word(table, raw);
        if CapTable::word_grants(w, raw, ty::ENDPOINT, CapPerms::WRITE) != Some(d.r) {
            return;
        }
        let Some(l) = LOOKUP.get(d.index()) else { return };
        let lw = l.load(core::sync::atomic::Ordering::Acquire);
        if d.generation() == 0 || lw != (u64::from(d.generation()) << 32) | u64::from(d.owner) || d.owner == UNCLAIMED {
            return;
        }
        e.key.store(0, Relaxed);
        e.table.store(table as u32, Relaxed);
        e.server.store(azos_sched::idx_for_tid(d.owner).map_or(u32::MAX, |s| s as u32), Relaxed);
        e.cap.store(w, Relaxed);
        e.lookup.store(lw, Relaxed);
        e.key.store(key(tid, cap_raw), Relaxed);
    }

    /// Forget task slot `idx`'s entry: the task in it exits or execs.
    #[inline]
    pub fn clear(idx: usize) {
        if let Some(e) = ENTRIES.get(idx) {
            e.key.store(0, Relaxed);
        }
    }

    /// [`clear`] for live task `tid`'s slot (an exec, after its commit).
    pub fn clear_task(tid: u32) {
        if let Some(idx) = azos_sched::idx_for_tid(tid) {
            clear(idx);
        }
    }

    /// `(tid, cap_raw)` slot `idx`'s entry is for, if any: for the tests.
    pub fn cached(idx: usize) -> Option<(u32, u32)> {
        let k = ENTRIES.get(idx)?.key.load(Relaxed);
        (k != 0).then_some(((k >> 32) as u32, k as u32))
    }
}

/// The name and the serving task of the endpoint at pool index `i`, for a
/// named, live endpoint: what the name server's view (`/proc/names`) prints
/// for a capability it holds. `UNCLAIMED` when no server has taken it.
pub fn endpoint_name_owner(i: usize) -> Option<([u8; ENDPOINT_NAME_MAX], usize, u32)> {
    let eps = ENDPOINTS.lock_irqsave();
    let e = eps.get(i)?;
    (e.active && e.name_len != 0).then(|| (e.name, e.name_len as usize, e.owner_tid))
}

/// The reference of the endpoint called `name`, or `None`. For the kernel-side
/// caller that needs to reach a named endpoint without holding a capability —
/// a boot report, and the tests.
pub fn endpoint_ref_by_name(name: &[u8]) -> Option<u32> {
    let eps = ENDPOINTS.lock_irqsave();
    eps.iter()
        .position(|e| e.active && e.name_bytes() == name)
        .map(|i| LAYOUT.pack(i as u32, eps[i].generation))
}

/// The TID serving the endpoint `r` names, or `Cap(Stale)`.
///
/// This is the whole point of the object and what stage 2 calls: it turns a
/// reference the CALLER could only obtain by holding a capability into the
/// destination `fast_ipc_call` needs, without the caller ever naming a TID.
pub fn endpoint_owner_ref(r: u32) -> Result<u32, EndpointCapError> {
    lookup_ref(r)
}

/// Free the endpoint `r` names. Idempotent only in the sense that a second
/// call is `Cap(Stale)` — the generation makes the reference dead, not the
/// index.
pub fn destroy_ref(r: u32) -> Result<(), EndpointCapError> {
    let (i, owner, link) = {
        let mut eps = ENDPOINTS.lock_irqsave();
        let i = live_index(&eps, r)?;
        let (owner, link) = (eps[i].owner_tid, eps[i].link);
        unpublish(&mut eps, i);
        (i, owner, link)
    };
    retire_after_drain(i, REVOKED, owner);
    post_gone(link, r, CODE_REVOKED);
    Ok(())
}

/// After [`unpublish`], with `ENDPOINTS` released: complete the calls queued
/// on slot `i` or in service there with `code`, then give the slot back to
/// the pool after a grace period.
fn retire_after_drain(i: usize, code: i32, server: u32) {
    glue::drain(i, code, server);
    glue::retire(i);
}

/// Destroy `r`, but only for its owner.
///
/// Holding a capability to an endpoint is the right to SEND to it, not the
/// right to take the service down: a client granted `Cap<Endpoint>` so it can
/// call a driver must not be able to destroy that driver's endpoint. That is
/// the same separation `fast_ipc_reply` draws when it refuses a reply from a
/// task that is not the addressed server.
pub fn destroy_ref_as(r: u32, tid: u32) -> Result<(), EndpointCapError> {
    let mut eps = ENDPOINTS.lock_irqsave();
    let i = live_index(&eps, r)?;
    if eps[i].owner_tid != tid {
        return Err(EndpointCapError::NotOwner);
    }
    let link = eps[i].link;
    unpublish(&mut eps, i);
    drop(eps);
    // The owner destroyed its own endpoint: its callers' calls end REVOKED.
    retire_after_drain(i, REVOKED, tid);
    post_gone(link, r, CODE_REVOKED);
    Ok(())
}

/// Free every endpoint owned by `tid`. Called when a task dies, so a service
/// that exits does not hold its slots for the life of the machine.
///
/// The capabilities other tasks hold to those endpoints are not walked: they
/// go stale on their own, because the generation the reference carries no
/// longer matches a freed slot. That is what the generation is for, and
/// walking every table instead would need a cap-table lock while `ENDPOINTS`
/// is held.
pub fn endpoint_release_all(tid: u32) {
    // `UNCLAIMED` is not a task. Without this guard a call with `u32::MAX`
    // would sweep every named endpoint no server has taken yet — the sentinel
    // is a value, and a filter on `owner_tid == tid` cannot tell the two apart.
    if tid == UNCLAIMED {
        return;
    }
    // One endpoint a hold (wave 15 N5b): each one's notice link is posted
    // after its own hold, so nothing is buffered per endpoint.
    let mut from = 0usize;
    while from < MAX_ENDPOINTS {
        let mut hit = None;
        {
            let mut eps = ENDPOINTS.lock_irqsave();
            while from < MAX_ENDPOINTS && hit.is_none() {
                let i = from;
                from += 1;
                if eps[i].active && eps[i].owner_tid == tid {
                    hit = Some((i, LAYOUT.pack(i as u32, eps[i].generation), eps[i].link));
                    unpublish(&mut eps, i);
                }
            }
        }
        // The server died: its callers' calls end PEER_DIED (wave 15 N5), and
        // a port its notices were bound to hears that the endpoint is gone.
        if let Some((i, r, link)) = hit {
            retire_after_drain(i, PEER_DIED, tid);
            post_gone(link, r, CODE_PEER_DIED);
        }
    }
}

/// [`endpoint_release_all`] for a server the M4 supervisor is restarting: a
/// **named** endpoint `tid` served survives it, unclaimed; an anonymous one is
/// freed as before. Returns how many named endpoints were kept.
///
/// "An endpoint may outlive the task that first served it" (`abi/src/cap.rs`)
/// is what this makes true. The slot, and therefore the generation packed into
/// every `Cap<Endpoint>` a client holds, is unchanged, so no client capability
/// goes stale. During the gap a call answers `Unserved` ([`endpoint_dest_for`]),
/// the answer a named endpoint gives before its server first starts. The
/// successor re-claims it the way the first server did: its topology grant
/// carries `READ`, and [`endpoint_named_cap`] accepts a `READ` grant on an
/// `UNCLAIMED` endpoint. That grant comes only from the signed topology, so
/// holding an orphaned name open does not let an arbitrary task serve it.
///
/// An anonymous endpoint has no name to be found by again, so no successor
/// could reach it: it is freed, exactly as at any other death.
pub fn endpoint_orphan_all(tid: u32) -> usize {
    if tid == UNCLAIMED || tid == 0 {
        return 0;
    }
    let mut kept = 0usize;
    // One endpoint a hold (wave 15 N5b), as `endpoint_release_all`.
    let mut from = 0usize;
    while from < MAX_ENDPOINTS {
        let mut hit = None;
        {
            let mut eps = ENDPOINTS.lock_irqsave();
            while from < MAX_ENDPOINTS && hit.is_none() {
                let i = from;
                from += 1;
                if !(eps[i].active && eps[i].owner_tid == tid) {
                    continue;
                }
                // The dead server's notice binding goes with it, kept or not:
                // its successor binds its own.
                let (r, link) = (LAYOUT.pack(i as u32, eps[i].generation), eps[i].link);
                if eps[i].name_len > 0 {
                    eps[i].owner_tid = UNCLAIMED;
                    eps[i].link = crate::port_link::PortLink::NONE;
                    // A death during a swap ends it (the queue's owner state is
                    // overwritten by the same `set_owner`): the legacy path
                    // below drains with `PEER_DIED`.
                    eps[i].successor = 0;
                    eps[i].handover = false;
                    publish(&eps, i);
                    glue::set_owner(i, eps[i].generation, UNCLAIMED);
                    kept += 1;
                    hit = Some((i, false, r, link));
                } else {
                    unpublish(&mut eps, i);
                    hit = Some((i, true, r, link));
                }
            }
        }
        // (slot, freed): a kept endpoint's calls end PEER_DIED as a freed
        // one's do, so its successor starts with an empty queue.
        if let Some((i, freed, r, link)) = hit {
            if freed {
                retire_after_drain(i, PEER_DIED, tid);
            } else {
                glue::drain(i, PEER_DIED, tid);
            }
            post_gone(link, r, CODE_PEER_DIED);
        }
    }
    kept
}

// ── Live update (Level 1 hooks): change an endpoint's server, no drain ─────

/// Why a handover step was refused (`ep_queue::HandoverError`, plus the
/// endpoint layer's own).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandoverError {
    /// The reference is stale, or the slot's queue is of another generation.
    Stale,
    /// The caller is not the server, or the successor is not a task.
    NotOwner,
    /// No handover to this successor is under way.
    NotInHandover,
    /// A handover is under way already.
    Busy,
    /// The old server still has this many calls in service.
    InService(usize),
    /// A named endpoint of the old server was not granted to this successor
    /// (the signed row of the successor does not name it).
    NotGranted,
}

/// A task's slot for the ready masks: where `ep_queue` looks for its bits.
fn slot_of(tid: u32) -> usize {
    azos_sched::idx_for_tid(tid).unwrap_or(usize::MAX)
}

/// Open a swap of `old`'s server: every **named** endpoint `old` serves
/// accepts a `READ` grant for a successor from the signed topology
/// ([`endpoint_named_cap`]) without making it the server. Call before
/// the successor is created (its row's grants are seeded before it can
/// run). Returns how many endpoints. Undone by [`endpoint_swap_cancel`] or
/// [`endpoint_handover_begin_all`].
pub fn endpoint_swap_open(old: u32) -> usize {
    if old == UNCLAIMED || old == 0 {
        return 0;
    }
    let mut eps = ENDPOINTS.lock_irqsave();
    let mut n = 0;
    for e in eps.iter_mut() {
        if e.active && e.owner_tid == old && e.name_len > 0 && e.successor == 0 {
            e.successor = SWAP_OPEN;
            n += 1;
        }
    }
    n
}

/// Start the handover of every endpoint `old` serves to `new`: new calls
/// queue and wait, `old` finishes what it has in service, nothing is
/// drained. A named endpoint must have been granted to `new`
/// ([`endpoint_swap_open`]); an anonymous one goes with the capability
/// table the supervisor hands over. All or none: a refusal undoes what was
/// started. Returns how many endpoints.
pub fn endpoint_handover_begin_all(old: u32, new: u32) -> Result<usize, HandoverError> {
    if old == UNCLAIMED || old == 0 || new == UNCLAIMED || new == 0 || new == old {
        return Err(HandoverError::NotOwner);
    }
    let mut eps = ENDPOINTS.lock_irqsave();
    let mut done: [usize; MAX_ENDPOINTS] = [0; MAX_ENDPOINTS];
    let mut n = 0usize;
    let mut fail = None;
    for i in 0..MAX_ENDPOINTS {
        if !(eps[i].active && eps[i].owner_tid == old) {
            continue;
        }
        let named = eps[i].name_len > 0;
        if eps[i].handover {
            fail = Some(HandoverError::Busy);
            break;
        }
        if named && eps[i].successor != new {
            fail = Some(HandoverError::NotGranted);
            break;
        }
        if let Err(e) = glue::begin_handover(i, eps[i].generation, old, new) {
            fail = Some(e);
            break;
        }
        eps[i].successor = new;
        eps[i].handover = true;
        done[n] = i;
        n += 1;
    }
    if let Some(e) = fail {
        for &i in &done[..n] {
            let _ = glue::abort_handover(i, eps[i].generation, slot_of(old));
            eps[i].successor = if eps[i].name_len > 0 { SWAP_OPEN } else { 0 };
            eps[i].handover = false;
        }
        return Err(e);
    }
    Ok(n)
}

/// How many calls `old` still has in service on its endpoints (the
/// supervisor waits for 0, or [`endpoint_handover_represent_all`]s).
pub fn endpoint_handover_in_service(old: u32) -> usize {
    let eps = ENDPOINTS.lock_irqsave();
    (0..MAX_ENDPOINTS).filter(|&i| eps[i].active && eps[i].owner_tid == old).map(|i| glue::in_service(i, old)).sum()
}

/// Hand the calls `old` has in service back to the queue for its successor
/// (`ep_queue::represent`): `(re-presented, left with the old server)`.
pub fn endpoint_handover_represent_all(old: u32) -> (usize, usize) {
    let eps = ENDPOINTS.lock_irqsave();
    let (mut moved, mut kept) = (0, 0);
    for i in 0..MAX_ENDPOINTS {
        if eps[i].active && eps[i].owner_tid == old {
            if let Ok((m, k)) = glue::represent(i, eps[i].generation, old) {
                moved += m;
                kept += k;
            }
        }
    }
    (moved, kept)
}

/// Finish the handover: `new` serves every endpoint `old` served, from this
/// instant. No drain, no new generation: every capability, queued call and
/// handle stays valid. The identity word changes (the resolve cache's
/// entries for these endpoints miss on their own, and a task that resolved
/// the old server and calls after the flip is refused like a call to an
/// endpoint that changed server, not lost). The old server's notice binding
/// is dropped; the successor binds its own. All or none: refused while
/// `old` has a call in service on any of them.
pub fn endpoint_rebind_all(old: u32, new: u32) -> Result<usize, HandoverError> {
    let mut eps = ENDPOINTS.lock_irqsave();
    // Nothing accepts during a handover, so the count only falls: checked
    // for all first, then flipped.
    let mut busy = 0usize;
    for i in 0..MAX_ENDPOINTS {
        if eps[i].active && eps[i].owner_tid == old && eps[i].handover && eps[i].successor == new {
            busy += glue::in_service(i, old);
        }
    }
    if busy != 0 {
        return Err(HandoverError::InService(busy));
    }
    let (old_idx, new_idx) = (slot_of(old), slot_of(new));
    let mut n = 0usize;
    for i in 0..MAX_ENDPOINTS {
        if !(eps[i].active && eps[i].owner_tid == old && eps[i].handover && eps[i].successor == new) {
            continue;
        }
        // The identity word first, so a call that resolves from here on
        // names the successor, which `ep_queue::call` accepts during the
        // handover; then the queue.
        let (gen, owner_before) = (eps[i].generation, eps[i].owner_tid);
        eps[i].owner_tid = new;
        publish(&eps, i);
        if let Err(e) = glue::rebind(i, gen, new, old_idx, new_idx) {
            eps[i].owner_tid = owner_before;
            publish(&eps, i);
            return Err(e);
        }
        eps[i].successor = 0;
        eps[i].handover = false;
        eps[i].link = crate::port_link::PortLink::NONE;
        n += 1;
    }
    Ok(n)
}

/// Undo a swap that was opened or begun and not rebound: `old` serves as it
/// did, its queued calls are delivered to it.
pub fn endpoint_swap_cancel(old: u32) -> usize {
    let mut eps = ENDPOINTS.lock_irqsave();
    let mut n = 0;
    for i in 0..MAX_ENDPOINTS {
        if eps[i].active && eps[i].owner_tid == old && eps[i].successor != 0 {
            if eps[i].handover {
                let _ = glue::abort_handover(i, eps[i].generation, slot_of(old));
            }
            eps[i].successor = 0;
            eps[i].handover = false;
            n += 1;
        }
    }
    n
}

/// Mint `child_tid` a `WRITE`-only capability to every endpoint `parent_tid`
/// itself **owns**, at `fork()` (RFC-0040 gap 3).
///
/// **The relation, not the class.** An earlier fork-inheritance design was
/// reverted on 2026-09-21 for filtering by capability CLASS ("inherit every
/// `Endpoint` cap the parent holds"), which hands the child every endpoint
/// the parent merely holds `WRITE` on — including ones a THIRD PARTY owns.
/// The property that makes inheritance safe is `owner_tid == parent_tid`:
/// the child may reach *its parent*, and nothing else. A capability the
/// parent holds on someone else's endpoint is not touched here, whatever
/// permission bits it carries.
///
/// **`WRITE` only, never the parent's own permission set.** The relation
/// fork preserves is "the child may send to its parent", not "the child may
/// serve in its parent's place". `owner_tid` on the `Endpoint` itself is
/// what actually determines who may serve it ([`endpoint_dest_for`],
/// [`endpoint_owner_ref`]) and this function never touches it — the child's
/// minted capability cannot make it the server however wide the perms are,
/// but granting only what the relation needs keeps that true by
/// construction rather than by the object's own gate.
///
/// **Scan cost.** Walks the fixed 32-entry [`ENDPOINTS`] pool once under one
/// `lock_irqsave` — the same cost [`create_core`]'s per-task quota check
/// already pays on every endpoint create. This is *not* a scan of the
/// parent's cap table (up to `MAX_CAPS_PER_TASK` slots, today 256): the
/// object pool this walks does not grow with how many capabilities of other
/// kinds the parent holds, or with `MAX_CAPS_PER_TASK` itself.
///
/// Matches are collected into a small stack buffer under the lock and
/// minted after it is dropped — the same two-step [`endpoint_named_cap`]
/// uses for its own claim-then-grant, and for the same reason: no cap-table
/// lock may be taken while [`ENDPOINTS`] is held (the lock-order rule
/// [`crate::cap_store::move_cap`] documents).
///
/// Called from [`crate::task_fork_grant`], the callback `crates/core/sched`
/// invokes through its `TASK_FORK_HOOK` indirection (mirroring
/// `TASK_EXIT_HOOK`) from inside `sys_fork_impl`, while the caller is still
/// the parent — so `parent_tid` needs no lookup, and the grant lands before
/// the child is ever dispatched (`fork_child_entry` only SRETs to user code
/// once `set_task_fork_ctx` publishes, which happens after this call
/// returns). A failed mint here must never fail the fork: this returns a
/// count, not a `Result`, and a grant that could not be minted (the child's
/// table race is impossible this early, but a generation-wrap sweep landing
/// between the scan and the mint is not) is simply not counted.
///
/// Returns how many capabilities were minted, for the caller's own
/// diagnostics — never consulted for correctness.
pub fn endpoint_inherit_at_fork(parent_tid: u32, child_tid: u32) -> usize {
    // `0` is never a live task's TID (see `cap_store::NO_OWNER`) and
    // `UNCLAIMED` is a sentinel, not an owner `create_core` ever stamps —
    // belt-and-braces, since neither can appear as a live `owner_tid`
    // (`active` gates a free slot's owner_tid=0 out of the scan below, and
    // `endpoint_release_all` shows `UNCLAIMED` is the one value that must
    // never be treated as "a task").
    if parent_tid == 0 || parent_tid == UNCLAIMED || child_tid == 0 {
        return 0;
    }
    // At most `MAX_ENDPOINTS_PER_TASK` slots can carry this owner (the quota
    // `create_core` enforces at create time), so that bounds the buffer.
    let mut matches: [u32; MAX_ENDPOINTS_PER_TASK] = [0; MAX_ENDPOINTS_PER_TASK];
    let mut n = 0usize;
    {
        let eps = ENDPOINTS.lock_irqsave();
        for (i, e) in eps.iter().enumerate() {
            if e.active && e.owner_tid == parent_tid && n < MAX_ENDPOINTS_PER_TASK {
                matches[n] = LAYOUT.pack(i as u32, e.generation);
                n += 1;
            }
        }
    }
    let mut minted = 0usize;
    for &r in &matches[..n] {
        // `WRITE` only, no `DUP` (owner decision 2026-09-26, O3.4): the
        // child may send to its parent, but may not hand that right to a
        // third party via `move_cap`, which now refuses any cap lacking
        // `DUP`. See the struct-level doc above for why `WRITE` alone is
        // already the right scope; `DUP`'s absence is what makes it stick.
        if objref::grant_packed::<crate::cap::targets::Endpoint>(child_tid, CapPerms::WRITE, r).is_some() {
            minted += 1;
        }
    }
    minted
}

/// Slot `i` was destroyed and is still waiting out its grace period before
/// it may be reused (the ktest `ipc_endpoint_slot_reused_after_grace`).
pub fn slot_held(i: usize) -> bool {
    HELD.get(i).is_some_and(|h| h.load(Ordering::Acquire))
}

/// How many endpoints are live. For tests and for a boot-time report.
pub fn endpoint_live_count() -> usize {
    ENDPOINTS.lock_irqsave().iter().filter(|e| e.active).count()
}

/// Reset the pool and its per-slot generation sources. Tests only: the host
/// suites share one process.
#[doc(hidden)]
pub fn __endpoint_reset_for_tests() {
    let mut eps = ENDPOINTS.lock_irqsave();
    for i in 0..MAX_ENDPOINTS {
        eps[i] = Endpoint::empty();
        eps.next_gen[i] = 1;
        LOOKUP[i].store(0, Ordering::Relaxed);
        HELD[i].store(false, Ordering::Relaxed);
        SENDERS[i].store(0, Ordering::Relaxed);
    }
    for w in NOTICE.iter() {
        w.store(0, Ordering::Relaxed);
    }
}

/// Fast-forward slot `i`'s own generation source, so a host test reaches its
/// wrap without `LAYOUT.gen_max()` create/destroy cycles at that index.
#[doc(hidden)]
pub fn __endpoint_set_next_gen_for_tests(i: usize, next_gen: u32) {
    ENDPOINTS.lock_irqsave().next_gen[i] = next_gen;
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: u32 = 1;
    const CLIENT: u32 = 2;
    const THIRD: u32 = 3;
    /// The successor in `a_supervised_servers_named_endpoint_survives_it_for_the_successor`.
    const HEIR: u32 = 4;

    /// The crate-wide serial lock (`tests/host/ipc-lease-tests`): minting walks
    /// `cap_store`, and a generation wrap sweep walks every cap table, both of
    /// which the port, shm and io_ring suites share.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        // Publish the fixed TIDs in the scheduler shim, slot = TID. Under
        // `tests/host/topology-tests` the shim resolves only bound TIDs, and
        // nothing here bound these: the suite passed only when
        // `cap_seed::tests_support::fresh_tid` (a counter from 1 that binds
        // as it goes) had already run four times, so run alone every test
        // failed its first grant, and under load some did (topology-tests
        // 197/198). `ipc-lease-tests`' shim is identity-mapped and its
        // `shim_bind` only checks the slot.
        for tid in [SERVER, CLIENT, THIRD, HEIR] {
            azos_sched::shim_bind(tid, tid as usize);
        }
        __endpoint_reset_for_tests();
        crate::cap_store::reset(SERVER);
        crate::cap_store::reset(CLIENT);
        crate::cap_store::reset(THIRD);
        crate::cap_store::reset(HEIR);
        for tid in [SERVER, CLIENT, THIRD, HEIR] {
            resolve_cache::clear(tid as usize);
        }
        g
    }

    /// **Send capabilities (`WRITE` without `READ`) are counted exactly
    /// through every way a table changes** (wave 15 N5b): a grant, a move that
    /// keeps or lowers the rights (`RW` lowered to `WRITE` becomes a sender),
    /// a kind-erased grant and slot clear under `with_table` (the fork copy's
    /// path), a revoke, and the exit wipe (`cap_store::reset`). The server's
    /// own `RW` is not a sender. The fall to zero marks a notice; a stale
    /// capability of a destroyed endpoint changes nothing.
    ///
    /// **Canaries.** Skip the walk in `CapTable::clear_all`: the count stays 2
    /// after `reset(THIRD)`. Count `RW` as a sender: the first count reads 1.
    #[test]
    fn send_capabilities_are_counted_exactly_through_every_table_change() {
        use crate::cap::targets::Endpoint as Ep;
        let _g = setup();
        crate::cap::senders::set_hooks(sender_delta, flush_notices);
        let r = endpoint_create(SERVER).unwrap();
        let srv = objref::grant_packed::<Ep>(SERVER, CapPerms::RW_DUP, r).unwrap();
        assert_eq!(senders_of(r), Some(0), "the server's RW is its receive right, not a sender");
        let c = objref::grant_packed::<Ep>(CLIENT, CapPerms::WRITE.union(CapPerms::DUP), r).unwrap();
        assert_eq!(senders_of(r), Some(1));
        // A move that keeps WRITE keeps the count.
        let moved = crate::cap_store::move_cap(CLIENT, THIRD, c.raw(), None).unwrap();
        assert_eq!(senders_of(r), Some(1), "a move is not a new sender");
        // The server's RW moved with its rights lowered to WRITE: a sender now.
        crate::cap_store::move_cap(SERVER, CLIENT, srv.raw(), Some(CapPerms::WRITE)).unwrap();
        assert_eq!(senders_of(r), Some(2));
        // The fork copy's path: a kind-erased grant and a slot clear.
        let h = crate::cap_store::with_table(THIRD, |t| t.grant_raw(ty::ENDPOINT, CapPerms::WRITE, r))
            .flatten()
            .unwrap();
        assert_eq!(senders_of(r), Some(3));
        crate::cap_store::with_table(THIRD, |t| t.clear_slot(h.slot() as usize));
        assert_eq!(senders_of(r), Some(2));
        // The exit wipe counts THIRD's out.
        let _ = moved;
        crate::cap_store::reset(THIRD);
        assert_eq!(senders_of(r), Some(1), "the table wipe did not count its send capability out");
        assert_eq!(NOTICE[0].load(Ordering::Relaxed), 0, "no notice with a sender left");
        // Fork inheritance: a child of the server (THIRD, its table wiped
        // above) gets a WRITE capability, a sender; its exit wipe
        // takes it back.
        assert_eq!(endpoint_inherit_at_fork(SERVER, THIRD), 1);
        assert_eq!(senders_of(r), Some(2), "the fork grant is a sender");
        crate::cap_store::reset(THIRD);
        assert_eq!(senders_of(r), Some(1));
        // CLIENT's: the last one. Its fall to zero marked a notice, and the
        // flush after the revoke took it (the endpoint is bound to no port).
        crate::cap_store::reset(CLIENT);
        assert_eq!(senders_of(r), Some(0));
        // A stale capability (another endpoint once at this index) counts
        // for nothing.
        let stale = objref::grant_packed::<Ep>(CLIENT, CapPerms::WRITE, r).unwrap();
        destroy_ref(r).unwrap();
        crate::cap_store::revoke(CLIENT, stale);
        assert_eq!(senders_of(r), None);
    }

    /// **A kernel-hosted endpoint is one object per interface, owned by the
    /// kernel.** The first grant creates it, every later grant (another task,
    /// another badge) reuses it, a different interface gets its own, and the
    /// owner word decodes back to the host key and to nothing a task could
    /// be. A badge of 0 is the unbadged resource 0; a non-zero one is stamped
    /// in the slot.
    ///
    /// **Canaries.** Create a new endpoint per grant: the equality of the two
    /// references fails. Let `host_key` accept `UNCLAIMED`: the sentinel line
    /// fails.
    #[test]
    fn a_kernel_hosted_endpoint_is_one_object_per_interface_owned_by_the_kernel() {
        use crate::cap::targets::Endpoint as Ep;
        let _g = setup();
        assert_eq!(host_key(kernel_host(7)), Some(7));
        assert_eq!(host_key(UNCLAIMED), None, "the unclaimed sentinel is not a kernel host");
        assert_eq!(host_key(SWAP_OPEN), None);
        assert_eq!(host_key(SERVER), None, "a task is not a kernel host");
        assert_eq!(host_key(KERNEL_HOST_BASE), None, "key 0 names nothing");
        let a = kernel_endpoint_cap(CLIENT, CapPerms::READ, 3, 0).expect("first grant creates");
        let b = kernel_endpoint_cap(THIRD, CapPerms::READ, 3, 9).expect("second grant reuses");
        let c = kernel_endpoint_cap(CLIENT, CapPerms::READ, 4, 0).expect("another interface");
        let r_of = |tid, cap: crate::cap::Cap<Ep>| crate::cap_store::with_table(tid, |t| t.peek_raw(cap.raw()).map(|x| x.2)).flatten();
        assert_eq!(r_of(CLIENT, a), r_of(THIRD, b), "one endpoint per interface");
        assert_ne!(r_of(CLIENT, a), r_of(CLIENT, c));
        assert_eq!(endpoint_live_count(), 2);
        assert_eq!(host_key_of_ref(r_of(CLIENT, a).unwrap()), Some(3));
        assert_eq!(host_key_of_ref(r_of(CLIENT, c).unwrap()), Some(4));
        // The badge is the resource: 0 is unbadged, 9 is stamped.
        assert_eq!(crate::cap_store::with_table(THIRD, |t| t.ext_of(b.raw()).map(|e| e.badge)).flatten(), Some(9));
        assert_eq!(crate::cap_store::with_table(CLIENT, |t| t.ext_of(a.raw()).map(|e| e.badge)).flatten(), Some(0));
        // A key outside the range grants nothing.
        assert!(kernel_endpoint_cap(CLIENT, CapPerms::READ, 0, 0).is_none());
        assert!(kernel_endpoint_cap(CLIENT, CapPerms::READ, KERNEL_HOST_KEYS, 0).is_none());
    }

    /// **Any right calls a kernel-hosted endpoint; a task-hosted one still
    /// needs `WRITE`.** The op class is checked per op, inside the call. A
    /// capability with no right at all calls nothing, and containment (which
    /// stops a task opening new requests) does not stop the call of a
    /// kernel-hosted endpoint: the acting class is refused inside it.
    ///
    /// **Canaries.** Drop the fallback in `endpoint_resolve`: the `READ`-only
    /// and the contained rows fail. Let the fallback accept a task-hosted
    /// endpoint: the last assertion fails.
    #[test]
    fn any_right_calls_a_kernel_hosted_endpoint_and_a_task_hosted_one_needs_write() {
        let _g = setup();
        crate::cap::degraded_set(false);
        let host = kernel_endpoint_cap(CLIENT, CapPerms::READ, 3, 5).unwrap();
        let d = endpoint_resolve(CLIENT, host.raw().as_raw()).expect("READ alone calls it");
        assert_eq!(host_key(d.owner), Some(3));
        let ex = kernel_endpoint_cap(CLIENT, CapPerms::EXEC, 3, 6).unwrap();
        assert!(endpoint_resolve(CLIENT, ex.raw().as_raw()).is_ok(), "EXEC alone calls it");
        let none = kernel_endpoint_cap(CLIENT, CapPerms::NONE, 3, 7).unwrap();
        assert!(endpoint_resolve(CLIENT, none.raw().as_raw()).is_err(), "no right, no call");

        // Contained: WRITE would be refused for a task-hosted endpoint, and
        // is not for a kernel-hosted one.
        let rw = kernel_endpoint_cap(CLIENT, CapPerms::RW, 3, 8).unwrap();
        crate::cap::degraded_set(true);
        let contained = endpoint_resolve(CLIENT, rw.raw().as_raw());
        crate::cap::degraded_set(false);
        assert_eq!(host_key(contained.expect("containment does not stop the call").owner), Some(3));

        // A task-hosted endpoint: READ alone does not call it.
        let r = endpoint_create(SERVER).unwrap();
        let ro = objref::grant_packed::<crate::cap::targets::Endpoint>(CLIENT, CapPerms::READ, r).unwrap();
        assert_eq!(
            endpoint_resolve(CLIENT, ro.raw().as_raw()),
            Err(EndpointCapError::Cap(CapError::MissingPerms)),
        );
    }

    /// `SYS_CAP_INFO`'s kernel-endpoint form: a task's capability to the
    /// interface with a given host key and badge, and none for another badge
    /// or key.
    ///
    /// **Canary.** Ignore the badge in the predicate: the wrong-badge row
    /// finds the capability.
    #[test]
    fn lookup_by_interface_and_badge_finds_the_right_capability() {
        let _g = setup();
        let a = kernel_endpoint_cap(CLIENT, CapPerms::READ, 3, 5).unwrap();
        let b = kernel_endpoint_cap(CLIENT, CapPerms::READ, 3, 6).unwrap();
        let other = kernel_endpoint_cap(CLIENT, CapPerms::READ, 4, 5).unwrap();
        let find = |key: u16, badge: u32| {
            crate::cap_store::with_table(CLIENT, |t| {
                t.lookup_where(ty::ENDPOINT, |r, bd, _| bd == badge && host_key_of_ref(r) == Some(key))
            })
            .flatten()
        };
        assert_eq!(find(3, 5), Some(a.raw()));
        assert_eq!(find(3, 6), Some(b.raw()));
        assert_eq!(find(4, 5), Some(other.raw()));
        assert_eq!(find(3, 7), None, "no capability carries badge 7");
        assert_eq!(find(5, 5), None, "no capability to interface 5");
    }

    /// **A holder of an unbadged, `DUP`-carrying capability to a kernel-hosted
    /// endpoint cannot mint a badge on it.** On such an endpoint the badge is
    /// the resource (a pin, a partition), so a free badge would be authority
    /// the topology never granted. The same rights on a task-served endpoint
    /// mint normally, and the holder of a badge the kernel stamped keeps it
    /// (the dup path is not the mint path).
    ///
    /// **Canaries.** Drop the `host_key_of_ref` test in `mint_badged`: the
    /// first assertion fails (the mint succeeds). Refuse every mint: the
    /// task-served row fails.
    #[test]
    fn a_badge_cannot_be_minted_on_a_kernel_hosted_endpoint() {
        let _g = setup();
        if !crate::cap::SLOT_EXT {
            return;
        }
        let gpio = kernel_endpoint_cap(CLIENT, CapPerms::RW_DUP, 3, 0).unwrap();
        assert_eq!(
            mint_badged(CLIENT, gpio.raw(), 17, CapPerms::READ),
            Err(CapError::MissingPerms),
            "badge 17 would be pin 17"
        );
        assert_eq!(crate::cap_store::occupied(CLIENT), 1, "a refused mint leaves nothing behind");
        let r = endpoint_create(SERVER).unwrap();
        let own = objref::grant_packed::<crate::cap::targets::Endpoint>(CLIENT, CapPerms::RW_DUP, r).unwrap();
        let b = mint_badged(CLIENT, own.raw(), 17, CapPerms::READ).expect("a task-served endpoint mints");
        assert_eq!(crate::cap_store::with_table(CLIENT, |t| t.ext_of(b).map(|e| e.badge)).flatten(), Some(17));
    }

    /// The reference a capability carries resolves to the task that created
    /// the endpoint — the one thing stage 2 will ask of this module.
    #[test]
    fn an_endpoints_reference_names_the_task_that_serves_it() {
        let _g = setup();
        // Through the capability path, so the mint is exercised too: the
        // handle names a table SLOT, and the packed reference the slot holds is
        // what resolves. `endpoint_create` returns that reference directly, and
        // the rest of this suite uses it to reach the pool without a table.
        assert!(endpoint_create_cap(SERVER, CapPerms::RW).is_some(), "a fresh pool has room");
        let packed = endpoint_create(SERVER).expect("still room");
        assert_eq!(endpoint_owner_ref(packed), Ok(SERVER));
    }

    /// **The property the whole object exists for.** A destroyed endpoint's
    /// reference must not answer for whatever later takes its slot. The
    /// generation is what closes it; the index alone would not.
    #[test]
    fn a_destroyed_endpoints_reference_goes_stale_and_does_not_follow_the_slot() {
        let _g = setup();
        let first = endpoint_create(SERVER).unwrap();
        assert_eq!(endpoint_owner_ref(first), Ok(SERVER));
        destroy_ref(first).expect("the owner's own reference destroys it");
        assert_eq!(
            endpoint_owner_ref(first),
            Err(EndpointCapError::Cap(CapError::Stale)),
            "a destroyed endpoint still answered",
        );

        // Re-create: the pool is empty, so this takes the SAME index.
        let second = endpoint_create(CLIENT).unwrap();
        assert_eq!(
            LAYOUT.idx(second),
            LAYOUT.idx(first),
            "the test's premise is gone: the second endpoint did not reuse the slot",
        );
        assert_ne!(LAYOUT.gen(second), LAYOUT.gen(first), "the generation did not move");
        assert_eq!(endpoint_owner_ref(second), Ok(CLIENT));
        assert_eq!(
            endpoint_owner_ref(first),
            Err(EndpointCapError::Cap(CapError::Stale)),
            "the OLD reference resolved to the NEW endpoint's owner — the ABA this closes",
        );
    }

    /// A bare in-range index carries generation 0 and must not resolve. This is
    /// the forged reference: an index is guessable, a generation is not.
    #[test]
    fn a_bare_index_with_no_generation_resolves_to_nothing() {
        let _g = setup();
        let _live = endpoint_create(SERVER).unwrap();
        for idx in 0..MAX_ENDPOINTS as u32 {
            assert_eq!(
                endpoint_owner_ref(idx),
                Err(EndpointCapError::Cap(CapError::Stale)),
                "bare index {idx} resolved",
            );
        }
    }

    /// Holding a capability to an endpoint is the right to SEND to it, never
    /// the right to take the service down.
    #[test]
    fn a_holder_that_is_not_the_owner_cannot_destroy_the_endpoint() {
        let _g = setup();
        let r = endpoint_create(SERVER).unwrap();
        assert_eq!(destroy_ref_as(r, CLIENT), Err(EndpointCapError::NotOwner));
        assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "the refused destroy still took it down");
        assert_eq!(destroy_ref_as(r, SERVER), Ok(()));
        assert_eq!(endpoint_owner_ref(r), Err(EndpointCapError::Cap(CapError::Stale)));
    }

    /// One task must not be able to take the whole machine-wide pool.
    #[test]
    fn the_per_task_quota_refuses_the_next_one_and_leaves_room_for_another_task() {
        let _g = setup();
        for i in 0..MAX_ENDPOINTS_PER_TASK {
            assert!(endpoint_create(SERVER).is_some(), "own slot {i}");
        }
        assert!(
            endpoint_create(SERVER).is_none(),
            "the quota did not refuse the {}th",
            MAX_ENDPOINTS_PER_TASK + 1,
        );
        // The refusal is the TASK's, not the pool's: another task still fits.
        assert!(
            endpoint_create(CLIENT).is_some(),
            "the quota refused a different task as well — that is a full pool, not a quota",
        );
    }

    /// A service that exits gives its slots back; another task's do not move.
    #[test]
    fn release_all_frees_only_the_dying_tasks_endpoints() {
        let _g = setup();
        let mine = endpoint_create(SERVER).unwrap();
        let theirs = endpoint_create(CLIENT).unwrap();
        assert_eq!(endpoint_live_count(), 2);

        endpoint_release_all(SERVER);

        assert_eq!(endpoint_owner_ref(mine), Err(EndpointCapError::Cap(CapError::Stale)));
        assert_eq!(endpoint_owner_ref(theirs), Ok(CLIENT), "the other task's endpoint was swept too");
        assert_eq!(endpoint_live_count(), 1);
    }

    /// **The client half.** Two tasks seeded from the same name must reach the
    /// SAME endpoint — that is the whole reason names exist, since `fork`
    /// copies no capabilities and the anonymous create mints into one table.
    #[test]
    fn two_tasks_seeded_with_one_name_reach_the_same_endpoint() {
        let _g = setup();
        let server = endpoint_named_cap(SERVER, CapPerms::READ, b"chat").expect("server grant");
        let client = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"chat").expect("client grant");
        // Different handles — each names a slot in its own table — but one
        // object underneath.
        let r = endpoint_ref_by_name(b"chat").expect("the name is registered");
        assert_eq!(endpoint_live_count(), 1, "the second grant created a second endpoint");
        assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "READ did not claim the endpoint");
        // Each handle names a slot in its OWNER's table, so the two are not
        // required to differ as integers; what must hold is that both resolve
        // to one endpoint, which `endpoint_live_count() == 1` above states.
        let _ = (server, client);
    }

    /// One server per endpoint. A second `READ` grant from another task is
    /// refused rather than silently taking the service over.
    #[test]
    fn a_second_server_on_the_same_name_is_refused() {
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"chat").is_some());
        assert!(
            endpoint_named_cap(CLIENT, CapPerms::READ, b"chat").is_none(),
            "two tasks both serve `chat`",
        );
        // The first server still serves it, and a caller is still admitted.
        let r = endpoint_ref_by_name(b"chat").unwrap();
        assert_eq!(endpoint_owner_ref(r), Ok(SERVER));
        assert!(endpoint_named_cap(CLIENT, CapPerms::WRITE, b"chat").is_some());
    }

    /// A client may be seeded BEFORE its server exists — boot order is not the
    /// topology's business. The endpoint is created unclaimed and the server's
    /// later grant claims it.
    #[test]
    fn a_client_seeded_first_leaves_the_endpoint_unclaimed_for_its_server() {
        let _g = setup();
        assert!(endpoint_named_cap(CLIENT, CapPerms::WRITE, b"chat").is_some());
        let r = endpoint_ref_by_name(b"chat").unwrap();
        assert_eq!(endpoint_owner_ref(r), Ok(UNCLAIMED), "a WRITE grant claimed the endpoint");
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"chat").is_some());
        assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "the server's grant did not claim it");
    }

    /// Two different names are two different endpoints, and a name that does
    /// not fit is refused rather than truncated onto a neighbour.
    #[test]
    fn names_are_compared_whole_and_an_overlong_one_is_refused() {
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"chat").is_some());
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"chat2").is_some());
        assert_eq!(endpoint_live_count(), 2, "two names collapsed onto one endpoint");

        let too_long = [b'x'; ENDPOINT_NAME_MAX + 1];
        assert!(endpoint_named_cap(CLIENT, CapPerms::WRITE, &too_long).is_none());
        assert!(endpoint_named_cap(CLIENT, CapPerms::WRITE, b"").is_none());
        assert_eq!(endpoint_live_count(), 2, "a refused name still created something");
    }

    /// `UNCLAIMED` is a sentinel, not a task: sweeping it must free nothing.
    #[test]
    fn releasing_the_unclaimed_sentinel_frees_no_endpoint() {
        let _g = setup();
        assert!(endpoint_named_cap(CLIENT, CapPerms::WRITE, b"chat").is_some());
        assert_eq!(endpoint_live_count(), 1);
        endpoint_release_all(UNCLAIMED);
        assert_eq!(
            endpoint_live_count(), 1,
            "a release of the sentinel swept every unclaimed endpoint",
        );
    }

    // ── The authority check itself (gap 2 stage 2) ──────────────────────────

    /// **The property the whole gap exists for.** A task holding a `WRITE`
    /// capability reaches the server; a task holding nothing reaches nothing.
    /// Under `SYS_IPC_FAST_CALL` both could call any live TID.
    #[test]
    fn a_holder_reaches_the_server_and_a_task_with_no_capability_reaches_nothing() {
        let _g = setup();
        let server_ep = endpoint_named_cap(SERVER, CapPerms::READ, b"chat").unwrap();
        let client_ep = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"chat").unwrap();

        assert_eq!(
            endpoint_dest_for(CLIENT, client_ep.raw().as_raw()),
            Ok(SERVER),
            "a WRITE holder could not reach the server",
        );
        // The same handle VALUE in a table that was never granted it. This is
        // the forgery: handles are small integers, so a task can simply try
        // its neighbour's.
        crate::cap_store::reset(THIRD);
        assert_eq!(
            endpoint_dest_for(THIRD, client_ep.raw().as_raw()),
            Err(EndpointCapError::Cap(CapError::Stale)),
            "a task holding nothing reached the server by reusing a handle value",
        );
        let _ = server_ep;
    }

    /// `WRITE` is what "may send" means. A server's own grant is `READ` only
    /// in this test, and `READ` alone must not be a licence to call.
    #[test]
    fn read_alone_does_not_authorise_a_call() {
        let _g = setup();
        let ep = endpoint_named_cap(SERVER, CapPerms::READ, b"chat").unwrap();
        assert_eq!(
            endpoint_dest_for(SERVER, ep.raw().as_raw()),
            Err(EndpointCapError::Cap(CapError::MissingPerms)),
            "a READ-only capability authorised a call",
        );
    }

    /// An endpoint the topology created for a server that has not started is
    /// `UNCLAIMED`. A call to it must fail, never pick a task.
    #[test]
    fn a_call_to_an_unserved_endpoint_reaches_nobody() {
        let _g = setup();
        let ep = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"chat").unwrap();
        assert_eq!(
            endpoint_dest_for(CLIENT, ep.raw().as_raw()),
            Err(EndpointCapError::Unserved),
            "unserved endpoint answered",
        );
        // The server starts; the same capability now resolves.
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"chat").is_some());
        assert_eq!(endpoint_dest_for(CLIENT, ep.raw().as_raw()), Ok(SERVER));
    }

    /// When the server exits, the client's capability stops resolving — it
    /// does not silently follow the slot to whatever service takes it next.
    #[test]
    fn a_clients_capability_stops_resolving_when_its_server_exits() {
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"chat").is_some());
        let ep = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"chat").unwrap();
        assert_eq!(endpoint_dest_for(CLIENT, ep.raw().as_raw()), Ok(SERVER));

        endpoint_release_all(SERVER);

        assert_eq!(
            endpoint_dest_for(CLIENT, ep.raw().as_raw()),
            Err(EndpointCapError::Cap(CapError::Stale)),
            "the capability still resolved after its server died",
        );
        // A different service takes the freed slot: the old capability must
        // STILL reach nothing, which is what the generation buys.
        assert!(endpoint_named_cap(THIRD, CapPerms::READ, b"other").is_some());
        assert_eq!(
            endpoint_dest_for(CLIENT, ep.raw().as_raw()),
            Err(EndpointCapError::Cap(CapError::Stale)),
            "the dead capability followed its slot to the next service",
        );
    }

    /// RFC-0049 M4: a supervised server's NAMED endpoint outlives it. The
    /// client's capability keeps resolving to the same slot and generation:
    /// `Unserved` during the gap, then the successor, once its topology `READ`
    /// grant re-claims the name. An anonymous endpoint is freed as at any death.
    ///
    /// **Canary**: make `endpoint_orphan_all` free named endpoints too, and the
    /// client's capability answers `Stale` instead of `Unserved`.
    #[test]
    fn a_supervised_servers_named_endpoint_survives_it_for_the_successor() {
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"svc").is_some());
        let ep = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"svc").unwrap();
        let anon = endpoint_create(SERVER).unwrap();
        assert_eq!(endpoint_dest_for(CLIENT, ep.raw().as_raw()), Ok(SERVER));

        assert_eq!(endpoint_orphan_all(SERVER), 1, "the named endpoint was not kept");

        assert_eq!(
            endpoint_dest_for(CLIENT, ep.raw().as_raw()),
            Err(EndpointCapError::Unserved),
            "the client's capability did not survive its server",
        );
        assert_eq!(endpoint_owner_ref(anon), Err(EndpointCapError::Cap(CapError::Stale)),
            "an anonymous endpoint outlived its server");
        // Nobody but a topology READ grant claims it: the successor's.
        assert!(endpoint_named_cap(HEIR, CapPerms::READ, b"svc").is_some());
        assert_eq!(endpoint_dest_for(CLIENT, ep.raw().as_raw()), Ok(HEIR));
        assert!(endpoint_named_cap(THIRD, CapPerms::READ, b"svc").is_none(), "a second server");
        crate::cap_store::reset(HEIR);
    }

    /// A refused quota must not consume a slot's generation (RFC-0040 gap 1,
    /// revised, owner decision 2026-09-26: the source is per-slot now, not
    /// pool-wide, so a refusal never reaching `take_slot_gen` at all is the
    /// property — a task spinning on a refusal cannot walk ANY slot's
    /// generation toward its own wrap, let alone force one).
    ///
    /// **Canary.** Take a generation before the quota check in `create_core`:
    /// `after`'s generation jumps by more than 1 over `before`'s.
    #[test]
    fn a_refused_create_consumes_no_generation() {
        let _g = setup();
        for _ in 0..MAX_ENDPOINTS_PER_TASK {
            endpoint_create(SERVER).unwrap();
        }
        let before = endpoint_create(CLIENT).unwrap();
        let idx = LAYOUT.idx(before);
        // Free CLIENT's slot again so it is the lowest free index once more —
        // the refusals below must take no slot, so the next create lands
        // right back on it.
        destroy_ref(before).unwrap();
        for _ in 0..8 {
            assert!(endpoint_create(SERVER).is_none(), "quota");
        }
        let after = endpoint_create(CLIENT).unwrap();
        assert_eq!(LAYOUT.idx(after), idx, "precondition: the refusals took no slot");
        assert_eq!(
            LAYOUT.gen(after),
            LAYOUT.gen(before) + 1,
            "eight refused creates moved the generation by more than the one grant between them",
        );
    }

    // ── The resolve cache (Kconfig IPC_RESOLVE_CACHE) ───────────────────────
    //
    // `resolve` is what `azos_syscall::handlers::endpoint_dest_at` does with
    // the cache (that crate is not compiled here): a hit, else the full
    // resolution and a fill. Slot = TID, as `setup` binds them.

    fn resolve(tid: u32, raw: u32) -> Result<Dest, EndpointCapError> {
        if let Some(d) = resolve_cache::hit(tid as usize, tid, raw) {
            return Ok(d);
        }
        let d = endpoint_resolve(tid, raw)?;
        resolve_cache::fill(tid as usize, tid, raw, d);
        Ok(d)
    }

    /// The client of `svc` (served by `SERVER`): its handle, resolved once,
    /// so the cache holds it.
    fn cached_client() -> u32 {
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"svc").is_some());
        let raw = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"svc").unwrap().raw().as_raw();
        assert_eq!(resolve(CLIENT, raw).map(|d| d.owner), Ok(SERVER));
        raw
    }

    /// **A resolution is kept and the next one hits**, with the answer the
    /// full resolution gives, for that task and that handle only.
    ///
    /// **Canary.** `hit` always `None`: the hit assertion fails.
    #[test]
    fn a_resolved_endpoint_is_kept_and_the_next_call_hits() {
        if !resolve_cache::ENABLED {
            return;
        }
        let _g = setup();
        let raw = cached_client();
        assert_eq!(resolve_cache::cached(CLIENT as usize), Some((CLIENT, raw)));
        let full = endpoint_resolve(CLIENT, raw).unwrap();
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw), Some(full), "no hit");
        assert_eq!(resolve_cache::hit(CLIENT as usize, THIRD, raw), None, "another TID in the slot hit");
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw ^ 1), None, "another handle hit");
    }

    /// **A change of the capability slot word misses**: revoked, the cached
    /// handle misses and the full resolution refuses it; re-granted into
    /// the same slot (a new generation), the old handle still misses.
    ///
    /// **Canary.** Skip the slot word compare in `hit`: the revoked handle
    /// hits.
    #[test]
    fn a_revoked_capability_misses_after_a_hit() {
        if !resolve_cache::ENABLED {
            return;
        }
        let _g = setup();
        let raw = cached_client();
        let cap: crate::cap::Cap<crate::cap::targets::Endpoint> =
            crate::cap::Cap::from_raw(azos_abi::cap::CapHandle(raw));
        crate::cap_store::revoke(CLIENT, cap);
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw), None, "a revoked capability hit");
        assert_eq!(resolve(CLIENT, raw), Err(EndpointCapError::Cap(CapError::Stale)));
        let again = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"svc").unwrap().raw().as_raw();
        assert_ne!(again, raw, "precondition: a new generation");
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw), None, "the old handle hit after a re-grant");
        assert_eq!(resolve(CLIENT, again).map(|d| d.owner), Ok(SERVER));
    }

    /// **A change of the endpoint's `LOOKUP` word misses**: orphaned
    /// (unserved), re-owned by a successor (the call reaches the new
    /// owner), then destroyed (stale).
    ///
    /// **Canary.** Skip the `LOOKUP` compare in `hit`: the re-owned
    /// endpoint still answers `SERVER`.
    #[test]
    fn an_endpoint_re_owned_or_destroyed_misses() {
        if !resolve_cache::ENABLED {
            return;
        }
        let _g = setup();
        let raw = cached_client();
        assert_eq!(endpoint_orphan_all(SERVER), 1);
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw), None, "an orphaned endpoint hit");
        assert_eq!(resolve(CLIENT, raw), Err(EndpointCapError::Unserved));
        assert!(endpoint_named_cap(HEIR, CapPerms::READ, b"svc").is_some());
        assert_eq!(resolve(CLIENT, raw).map(|d| d.owner), Ok(HEIR), "the call did not reach the new owner");
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw).map(|d| d.owner), Some(HEIR));
        let r = endpoint_ref_by_name(b"svc").unwrap();
        destroy_ref(r).unwrap();
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw), None, "a destroyed endpoint hit");
        assert_eq!(resolve(CLIENT, raw), Err(EndpointCapError::Cap(CapError::Stale)));
        crate::cap_store::reset(HEIR);
    }

    /// **A live update flips the owner and keeps the identity**: the open
    /// swap lets only the successor's `READ` grant in, without claiming; the
    /// handover leaves the owner as it was; the rebind makes the successor
    /// the owner, with the same slot and generation, so the client's
    /// capability and its resolve-cache entry neither go stale nor keep
    /// answering the old server.
    ///
    /// **Canaries.** Make the successor's grant claim the endpoint: `owner`
    /// is HEIR before the rebind. Skip `publish` in the rebind: the client
    /// still resolves SERVER (and the cache hits it). Bump the generation
    /// in the rebind: the client's capability answers `Stale`.
    #[test]
    fn a_rebind_changes_the_owner_and_keeps_the_endpoint() {
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"svc").is_some());
        let ep = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"svc").unwrap();
        let raw = ep.raw().as_raw();
        let r = endpoint_ref_by_name(b"svc").unwrap();
        let anon = endpoint_create(SERVER).unwrap();
        // Closed swap: a second server is refused, as ever.
        assert!(endpoint_named_cap(THIRD, CapPerms::READ, b"svc").is_none());
        assert_eq!(endpoint_swap_open(SERVER), 1, "the named endpoint only");
        assert!(endpoint_named_cap(HEIR, CapPerms::READ, b"svc").is_some(), "the successor's grant");
        assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "a grant claims nothing during a swap");
        assert!(endpoint_named_cap(THIRD, CapPerms::READ, b"svc").is_none(), "one successor only");
        assert_eq!(endpoint_handover_begin_all(SERVER, HEIR), Ok(2), "named and anonymous");
        assert_eq!(endpoint_handover_begin_all(SERVER, HEIR), Err(HandoverError::Busy));
        assert_eq!(endpoint_dest_for(CLIENT, raw), Ok(SERVER), "callers still resolve the old server");
        let before = LOOKUP[LAYOUT.idx(r) as usize].load(Ordering::Relaxed);
        let cached = if resolve_cache::ENABLED {
            let d = resolve(CLIENT, raw).unwrap();
            assert_eq!(d.owner, SERVER);
            assert!(resolve_cache::hit(CLIENT as usize, CLIENT, raw).is_some(), "precondition: a hit");
            true
        } else {
            false
        };

        assert_eq!(endpoint_rebind_all(SERVER, HEIR), Ok(2));

        let after = LOOKUP[LAYOUT.idx(r) as usize].load(Ordering::Relaxed);
        assert_eq!(after >> 32, before >> 32, "same generation");
        assert_eq!(after as u32, HEIR);
        assert_eq!(endpoint_owner_ref(r), Ok(HEIR));
        assert_eq!(endpoint_owner_ref(anon), Ok(HEIR), "the anonymous one moved with it");
        if cached {
            assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw), None, "the old owner still hit");
        }
        assert_eq!(resolve(CLIENT, raw).map(|d| d.owner), Ok(HEIR), "the client's capability is still good");
        assert_eq!(endpoint_rebind_all(SERVER, HEIR), Ok(0), "nothing left to move");
        crate::cap_store::reset(HEIR);
    }

    /// A server that dies during a swap ends the swap: the endpoint is kept
    /// for its restart, and a swap of the restarted server can be opened.
    ///
    /// **Canary.** Leave `successor` set in `endpoint_orphan_all`: the last
    /// `endpoint_swap_open` finds no endpoint.
    #[test]
    fn a_death_during_a_swap_ends_it() {
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"svc").is_some());
        assert_eq!(endpoint_swap_open(SERVER), 1);
        assert!(endpoint_named_cap(HEIR, CapPerms::READ, b"svc").is_some());
        assert_eq!(endpoint_handover_begin_all(SERVER, HEIR), Ok(1));
        assert_eq!(endpoint_orphan_all(SERVER), 1);
        assert!(endpoint_named_cap(THIRD, CapPerms::READ, b"svc").is_some(), "the restart claims it");
        assert_eq!(endpoint_swap_open(THIRD), 1, "and a swap of it can be opened");
        crate::cap_store::reset(HEIR);
        crate::cap_store::reset(THIRD);
    }

    /// **A successor that joins the old server's domain counts its own
    /// seeded table's send capabilities out exactly once**: the successor's
    /// table is wiped before it joins (the swap's step 4), the old server's
    /// stay counted as they were, and the table they live in is not touched.
    ///
    /// **Canary.** Skip the count-out in `CapTable::clear_all` (the
    /// `ipc-no-senders-wipe` feature): the count stays 3 after the wipe.
    #[test]
    fn a_successor_joining_the_domain_counts_its_replaced_senders_out_once() {
        use crate::cap::targets::Endpoint as Ep;
        let _g = setup();
        crate::cap::senders::set_hooks(sender_delta, flush_notices);
        let r = endpoint_create(THIRD).unwrap();
        let w = CapPerms::WRITE.union(CapPerms::DUP);
        // The old server's table: two send capabilities; the successor's own: one.
        let _a = objref::grant_packed::<Ep>(SERVER, w, r).unwrap();
        let _b = objref::grant_packed::<Ep>(SERVER, w, r).unwrap();
        let _c = objref::grant_packed::<Ep>(HEIR, w, r).unwrap();
        assert_eq!(senders_of(r), Some(3));
        crate::cap_store::reset(HEIR);
        assert_eq!(senders_of(r), Some(2), "the successor's own went, the old server's two stayed");
        crate::cap_store::reset(SERVER);
        assert_eq!(senders_of(r), Some(0), "counted once, not twice");
    }

    /// A swap that is cancelled leaves the server as it was.
    #[test]
    fn a_cancelled_swap_leaves_the_server_in_place() {
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"svc").is_some());
        let ep = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"svc").unwrap();
        assert_eq!(endpoint_swap_open(SERVER), 1);
        assert!(endpoint_named_cap(HEIR, CapPerms::READ, b"svc").is_some());
        assert_eq!(endpoint_handover_begin_all(SERVER, HEIR), Ok(1));
        assert_eq!(endpoint_swap_cancel(SERVER), 1);
        assert_eq!(endpoint_dest_for(CLIENT, ep.raw().as_raw()), Ok(SERVER));
        assert_eq!(endpoint_rebind_all(SERVER, HEIR), Ok(0), "cancelled: nothing to rebind");
        // And the successor is refused again: the swap is closed.
        assert!(endpoint_named_cap(THIRD, CapPerms::READ, b"svc").is_none());
        crate::cap_store::reset(HEIR);
    }

    /// **Cleared at reuse and exec, and refused under containment**: a
    /// cleared slot misses; containment (RFC-0036) makes a kept entry miss,
    /// so the full resolution refuses it.
    ///
    /// **Canaries.** `clear` a no-op: the cleared entry hits. Skip the
    /// containment test in `hit`: the contained call hits.
    #[test]
    fn a_cleared_slot_and_a_contained_task_miss() {
        if !resolve_cache::ENABLED {
            return;
        }
        let _g = setup();
        let raw = cached_client();
        crate::cap::degraded_set(true);
        let contained = resolve_cache::hit(CLIENT as usize, CLIENT, raw);
        let full = endpoint_resolve(CLIENT, raw);
        crate::cap::degraded_set(false);
        assert_eq!(contained, None, "a contained task hit");
        assert_eq!(full, Err(EndpointCapError::Cap(CapError::Contained)));
        assert!(resolve_cache::hit(CLIENT as usize, CLIENT, raw).is_some(), "precondition: a hit");
        resolve_cache::clear(CLIENT as usize);
        assert_eq!(resolve_cache::cached(CLIENT as usize), None);
        assert_eq!(resolve_cache::hit(CLIENT as usize, CLIENT, raw), None, "a cleared slot hit");
    }

    /// **A fill keeps only words that still say what was resolved**: a
    /// destination resolved before a revoke is not kept after it.
    ///
    /// **Canary.** Skip `word_grants` in `fill`: the revoked handle is kept.
    #[test]
    fn a_fill_after_a_change_keeps_nothing() {
        if !resolve_cache::ENABLED {
            return;
        }
        let _g = setup();
        assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"svc").is_some());
        let raw = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"svc").unwrap().raw().as_raw();
        let d = endpoint_resolve(CLIENT, raw).unwrap();
        let cap: crate::cap::Cap<crate::cap::targets::Endpoint> =
            crate::cap::Cap::from_raw(azos_abi::cap::CapHandle(raw));
        crate::cap_store::revoke(CLIENT, cap);
        resolve_cache::fill(CLIENT as usize, CLIENT, raw, d);
        assert_eq!(resolve_cache::cached(CLIENT as usize), None, "a stale resolution was kept");
    }
}
