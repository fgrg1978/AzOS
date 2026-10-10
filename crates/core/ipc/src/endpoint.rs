// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Fast-IPC **endpoints**: the object a client must hold a capability to
//! before it may send a request (RFC-0040 gap 2, stage 1).
//!
//! # The hole this exists to close
//!
//! Fast IPC is addressed by TID. `fast_ipc_call(caller, server, words)`
//! (`crate::fast_ipc`) checks two things about its destination, and both are
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
//!   TID, which is exactly the coupling this removes. `CapKind::Task` is also
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

use crate::cap::{CapError, CapKind, CapPerms};

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
}

impl Endpoint {
    const fn empty() -> Self {
        Self {
            owner_tid: 0,
            name: [0u8; ENDPOINT_NAME_MAX],
            name_len: 0,
            generation: 0,
            active: false,
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

/// Per slot: destroyed, and not yet reusable. A destroyed endpoint's slot
/// goes back to the pool only after a grace period ([`glue::retire`]), so a
/// lookup that read the old word before the destroy, and is still inside its
/// read section, can never meet a new endpoint in the same slot.
static HELD: [AtomicBool; MAX_ENDPOINTS] = [const { AtomicBool::new(false) }; MAX_ENDPOINTS];

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
    HELD[i].store(true, Ordering::Relaxed);
    glue::close(i);
}

/// The kernel side of the endpoint lifecycle: the per-endpoint call queues
/// (Kconfig `IPC_ENDPOINT_QUEUES`, `ep_queue.rs`), the QSBR read section of
/// the lookup and the grace period before a slot is reused. The host suites
/// that `#[path]`-pull this file have none of it, and their stand-ins
/// release a slot at once.
#[cfg(target_os = "none")]
mod glue {
    use core::cell::UnsafeCell;
    use core::sync::atomic::Ordering;

    use azos_sync::qsbr::{self, RcuHead};

    const QUEUES: bool = azos_limits::IPC_ENDPOINT_QUEUES;

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
        if QUEUES { crate::ep_queue::open(i, gen, owner) }
    }
    pub fn set_owner(i: usize, gen: u32, owner: u32) {
        if QUEUES { crate::ep_queue::set_owner(i, gen, owner) }
    }
    pub fn close(i: usize) {
        if QUEUES { crate::ep_queue::close(i) }
    }
    /// Complete the calls on slot `i` with `code`, `ENDPOINTS` released.
    pub fn drain(i: usize, code: i32, server: u32) {
        if QUEUES { crate::fastcall::drain_endpoint(i, code, server) }
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
/// `objref::sweep_index(CapKind::Endpoint, i)` — which revokes only the stale
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
                objref::sweep_index(CapKind::Endpoint, slot as u32);
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
            return None; // already served by someone else
        }
        eps[i].owner_tid = tid;
        publish(&eps, i);
        glue::set_owner(i, eps[i].generation, tid);
    }

    match objref::grant_packed::<crate::cap::targets::Endpoint>(tid, perms, r) {
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
/// queues on (Kconfig `IPC_ENDPOINT_QUEUES`). Takes no lock: the capability
/// read is lock-free (N4) and the endpoint's identity word is read in a QSBR
/// read section ([`lookup_ref`]).
#[inline]
pub fn endpoint_resolve(caller_tid: u32, cap_raw: u32) -> Result<Dest, EndpointCapError> {
    let cap: crate::cap::Cap<crate::cap::targets::Endpoint> =
        crate::cap::Cap::from_raw(azos_abi::cap::CapHandle::from_raw(cap_raw));
    let r = crate::cap_store::get(caller_tid, cap, CapPerms::WRITE)
        .map_err(EndpointCapError::Cap)?;
    let owner = lookup_ref(r)?;
    if owner == UNCLAIMED {
        return Err(EndpointCapError::Unserved);
    }
    Ok(Dest { r, owner })
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
    let (i, owner) = {
        let mut eps = ENDPOINTS.lock_irqsave();
        let i = live_index(&eps, r)?;
        let owner = eps[i].owner_tid;
        unpublish(&mut eps, i);
        (i, owner)
    };
    retire_after_drain(i, REVOKED, owner);
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
    unpublish(&mut eps, i);
    drop(eps);
    // The owner destroyed its own endpoint: its callers' calls end REVOKED.
    retire_after_drain(i, REVOKED, tid);
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
    let mut gone = [0u16; MAX_ENDPOINTS];
    let mut n = 0usize;
    {
        let mut eps = ENDPOINTS.lock_irqsave();
        for i in 0..MAX_ENDPOINTS {
            if eps[i].active && eps[i].owner_tid == tid {
                unpublish(&mut eps, i);
                gone[n] = i as u16;
                n += 1;
            }
        }
    }
    // The server died: its callers' calls end PEER_DIED (wave 15 N5).
    for &i in &gone[..n] {
        retire_after_drain(i as usize, PEER_DIED, tid);
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
    // (slot, freed): a kept endpoint's calls end PEER_DIED as a freed one's
    // do, so its successor starts with an empty queue.
    let mut hit = [(0u16, false); MAX_ENDPOINTS];
    let mut n = 0usize;
    {
        let mut eps = ENDPOINTS.lock_irqsave();
        for i in 0..MAX_ENDPOINTS {
            if eps[i].active && eps[i].owner_tid == tid {
                if eps[i].name_len > 0 {
                    eps[i].owner_tid = UNCLAIMED;
                    publish(&eps, i);
                    glue::set_owner(i, eps[i].generation, UNCLAIMED);
                    kept += 1;
                    hit[n] = (i as u16, false);
                } else {
                    unpublish(&mut eps, i);
                    hit[n] = (i as u16, true);
                }
                n += 1;
            }
        }
    }
    for &(i, freed) in &hit[..n] {
        if freed {
            retire_after_drain(i as usize, PEER_DIED, tid);
        } else {
            glue::drain(i as usize, PEER_DIED, tid);
        }
    }
    kept
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

    /// The crate-wide serial lock (`tests/host/ipc-lease-tests`): minting walks
    /// `cap_store`, and a generation wrap sweep walks every cap table, both of
    /// which the port, shm and io_ring suites share.
    fn setup() -> std::sync::MutexGuard<'static, ()> {
        let g = crate::harness::serial();
        __endpoint_reset_for_tests();
        crate::cap_store::reset(SERVER);
        crate::cap_store::reset(CLIENT);
        crate::cap_store::reset(THIRD);
        g
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
        const HEIR: u32 = 4;
        crate::cap_store::reset(HEIR);
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
}
