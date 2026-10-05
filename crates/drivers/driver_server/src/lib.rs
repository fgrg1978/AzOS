// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! Userspace driver framework.
//!
//! The in-kernel registry that lets a ring-3 task register as the driver for
//! a hardware kind (`SYS_DRIVER_REGISTER_TYPED`, with a capability), and the
//! queue through which in-kernel clients reach it: a typed hardware call
//! whose driver runs in ring 3 is turned into a [`DriverRequest`] by
//! `azos_drv_sys::user_driver_proxy`, queued here
//! ([`driver_submit_request`]), and the client blocks until the reply is
//! published.
//!
//! # Architecture
//! ```text
//!   ring-3 driver                        kernel
//!   ─────────────                        ──────
//!   SYS_DRIVER_REGISTER_TYPED(cap) ────► registry[kind]
//!
//!                                        typed hardware call (client)
//!                                          └─► user_driver_proxy
//!                                               └─► driver_submit_request
//!   SYS_DRIVER_REPLY_WAIT(kind,         ◄─── request queued, parked
//!     reply, req)                             driver woken
//!   [ driver handles the request ]
//!   SYS_DRIVER_REPLY_WAIT(...)  ────────► reply published, client woken;
//!     (publishes the reply and              the same call waits for the
//!      waits for the next request)          next request
//! ```
//!
//! The untyped `SYS_DRIVER_REGISTER`, the ring-3 `SYS_DRIVER_REQUEST` and
//! `SYS_DRIVER_TRY_REPLY` are retired (`RETIRED_SYSCALLS` in `azos_abi`).
//!
//! # IRQ routing
//! When a hardware IRQ fires, [`driver_signal_irq`] marks it for the driver
//! registered for that IRQ number; the driver collects it with
//! `SYS_DRIVER_POLL_EVENT`.
//!
//! # Placement
//! Whether a driver runs in the kernel or in a ring-3 server is chosen per
//! driver at build time (`config/Kconfig.drivers`); the in-kernel drivers in
//! the `azos_drv_*` crates remain the default.

use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use azos_sync::SpinLock;

pub mod reply_wait;
use reply_wait::{ReplyWaiter, ReplyWaiters};

// ───────────────────────────────────────────────────────────────────────────
// Driver kind IDs — every subsystem we expect to see in userspace gets one.
// ───────────────────────────────────────────────────────────────────────────

// Moved to `crates/core/abi/src/drv_kind.rs` on 2026-09-06 and re-exported here so
// every `azos_driver_server::DRV_KIND_*` path still resolves. They are
// ABI — ring 3 passes them in a register — and this crate's dependency on
// `azos_sync` (→ `azos_arch`, RV64-only) put them out of reach of
// every host test. See that module's doc.
pub use azos_abi::drv_kind::{
    DRIVER_MAX_KINDS, DRV_KIND_ADC, DRV_KIND_CAN, DRV_KIND_CSI_CAM, DRV_KIND_DMA, DRV_KIND_GPIO,
    DRV_KIND_GPS, DRV_KIND_I2C, DRV_KIND_IMU, DRV_KIND_LIDAR, DRV_KIND_MOTOR_PID, DRV_KIND_NPU,
    DRV_KIND_ML, DRV_KIND_PWM, DRV_KIND_SPI, DRV_KIND_UART, DRV_KIND_USB_XHCI, DRV_KIND_BUZZER,
    DRV_KIND_POWER_MON,
};

// ───────────────────────────────────────────────────────────────────────────
// Request queue size per driver (per-kind pending ring).
// ───────────────────────────────────────────────────────────────────────────

pub const DRIVER_REQUEST_QUEUE_DEPTH: usize = 8;

// ───────────────────────────────────────────────────────────────────────────
// Payload + reply buffer sizes (inline in request, small — larger transfers
// should use the F15 zero-copy pipeline).
// ───────────────────────────────────────────────────────────────────────────

pub const DRIVER_REQUEST_PAYLOAD_BYTES: usize = 64;
pub const DRIVER_REPLY_PAYLOAD_BYTES:   usize = 64;

// ───────────────────────────────────────────────────────────────────────────
// Event taxonomy received by driver's `sys_driver_wait()`.
// ───────────────────────────────────────────────────────────────────────────

/// No event pending.
pub const DRV_EVENT_NONE:    u32 = 0;
/// A new client request is ready to be processed.
pub const DRV_EVENT_REQUEST: u32 = 1;
/// Hardware IRQ fired.
pub const DRV_EVENT_IRQ:     u32 = 2;
/// Driver should shut down (kernel teardown).
pub const DRV_EVENT_SHUTDOWN: u32 = 3;

// ───────────────────────────────────────────────────────────────────────────
// Types.
// ───────────────────────────────────────────────────────────────────────────

/// One pending client request awaiting driver dispatch.
///
/// `#[repr(C)]` is mandatory: this struct is copied verbatim across the
/// user/kernel boundary (`sys_driver_fetch_request` does a `write_volatile`
/// into a userspace pointer), so a userspace driver process must see the exact
/// same field layout. A userspace mirror lives in `userspace/drivers/gpio_drv`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DriverRequest {
    /// Monotonic token used to match reply → waiter.
    pub token:      u64,
    /// Client task id — for wake after reply.
    pub client_tid: u32,
    /// Driver-defined op code (e.g. GPIO_WRITE, I2C_READ).
    pub op:         u32,
    /// Inline payload byte count.
    pub in_len:     u16,
    /// Reply buffer size (upper bound).
    pub out_cap:    u16,
    pub input:      [u8; DRIVER_REQUEST_PAYLOAD_BYTES],
}

impl DriverRequest {
    pub const fn zeroed() -> Self {
        Self {
            token: 0, client_tid: 0, op: 0,
            in_len: 0, out_cap: 0,
            input: [0; DRIVER_REQUEST_PAYLOAD_BYTES],
        }
    }
}

/// Reply produced by a userspace driver for a given token.
///
/// `#[repr(C)]` is mandatory — same cross-boundary reason as [`DriverRequest`]
/// (`sys_driver_reply` does a `read_volatile` from a userspace pointer).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DriverReply {
    pub token:      u64,
    pub status:     i32,
    pub out_len:    u16,
    pub _pad:       u16,
    pub output:     [u8; DRIVER_REPLY_PAYLOAD_BYTES],
}

impl DriverReply {
    pub const fn zeroed() -> Self {
        Self {
            token: 0, status: 0, out_len: 0, _pad: 0,
            output: [0; DRIVER_REPLY_PAYLOAD_BYTES],
        }
    }
}

/// Per-kind driver slot with its pending-request ring and IRQ latch.
pub struct DriverSlot {
    pub kind:         u32,
    /// The registered driver. `0` while the slot is orphaned: its driver died
    /// under the M4 supervisor, which holds the slot — active, its queue and
    /// waiters kept — for the successor it is creating ([`driver_orphan_all`],
    /// [`driver_adopt`]).
    pub driver_tid:   u32,
    /// The TID whose death orphaned this slot; `0` when it is not orphaned.
    /// What [`driver_adopt`] and [`driver_release_orphans`] match on.
    pub orphan_of:    u32,
    pub mmio_base:    u64,
    pub mmio_size:    u64,
    pub irq:          u32,
    pub active:       AtomicBool,

    /// Pending requests (client → driver).
    pub queue:        SpinLock<DriverQueue>,

    /// Replies published for a token no in-kernel client is armed on (read
    /// by [`driver_try_take_reply`]; its ring-3 door, `SYS_DRIVER_TRY_REPLY`
    /// (526), was retired in wave 11 — no capability, guessable tokens). One entry per
    /// token, [`REPLY_RING_DEPTH`] of them (was one per kind: a second
    /// concurrent client's reply overwrote the first's). An armed in-kernel
    /// client's reply goes to its own waiter row instead (`reply_wait`).
    pub replies:      SpinLock<ReplyRing>,

    /// Latched IRQ flag — set by IRQ handler, cleared on `sys_driver_wait`.
    pub irq_pending:  AtomicBool,

    /// Monotonic per-driver token counter: the LAST token issued, `0` before
    /// the first. A token is `fetch_add(1) + 1` ([`issue_token`]), so the
    /// first is 1 and 0 is never a token (`REPLY_POSTED`'s "nothing posted"),
    /// exactly as when this started at 1 and handed out the old value. It
    /// starts at 0 so that `DriverSlot::empty()` is all zero bytes and
    /// `REGISTRY` is placed in `.bss`, not `.data` (owner decision
    /// 2026-09-28).
    pub next_token:   AtomicU64,

    /// The kernel asked this driver to stop ([`driver_request_stop`]); it
    /// exits at its next driver-side call ([`driver_take_stop`]).
    pub stop_requested: AtomicBool,

    /// The exit code the stopped driver exits with. `KILLED_KILL` (137) for
    /// [`driver_request_stop`]; [`driver_request_stop_code`] names another.
    pub stop_code: AtomicI32,

    /// In-kernel clients blocked on a reply (`reply_wait`). Guarded by
    /// `REGISTRY`, like `driver_tid`: armed in the hold that queues the
    /// request, taken in the hold that publishes the reply.
    pub waiters:      ReplyWaiters,

    /// The driver itself, parked in `SYS_DRIVER_REPLY_WAIT` on an empty
    /// queue. Guarded by `REGISTRY`: set in the hold that found the queue
    /// empty, taken in the hold that queues the next request. See
    /// [`driver_fetch_or_park`].
    pub parked:       Option<ParkedDriver>,
}

/// A driver blocked on its own empty queue until `deadline`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParkedDriver {
    pub tid: u32,
    pub deadline: u64,
}

impl DriverSlot {
    pub const fn empty() -> Self {
        Self {
            kind:        0,
            driver_tid:  0,
            orphan_of:   0,
            mmio_base:   0,
            mmio_size:   0,
            irq:         0,
            active:      AtomicBool::new(false),
            queue:       SpinLock::new(DriverQueue::new()),
            replies:     SpinLock::new(ReplyRing::new()),
            irq_pending: AtomicBool::new(false),
            next_token:  AtomicU64::new(0),
            stop_requested: AtomicBool::new(false),
            stop_code: AtomicI32::new(azos_abi::exit_status::KILLED_KILL),
            waiters:     ReplyWaiters::new(),
            parked:      None,
        }
    }
}

/// The next token of `slot`: 1, 2, 3, … for the life of the boot, never 0.
#[inline]
pub fn issue_token(slot: &DriverSlot) -> u64 {
    slot.next_token.fetch_add(1, Ordering::Relaxed) + 1
}

pub struct DriverQueue {
    pub entries: [DriverRequest; DRIVER_REQUEST_QUEUE_DEPTH],
    pub head:    usize,
    pub tail:    usize,
    pub count:   usize,
}

impl DriverQueue {
    pub const fn new() -> Self {
        Self {
            entries: [DriverRequest::zeroed(); DRIVER_REQUEST_QUEUE_DEPTH],
            head: 0, tail: 0, count: 0,
        }
    }

    pub fn push(&mut self, req: DriverRequest) -> bool {
        if self.count == DRIVER_REQUEST_QUEUE_DEPTH { return false; }
        self.entries[self.head] = req;
        self.head = (self.head + 1) % DRIVER_REQUEST_QUEUE_DEPTH;
        self.count += 1;
        true
    }

    pub fn pop(&mut self) -> Option<DriverRequest> {
        if self.count == 0 { return None; }
        let r = self.entries[self.tail];
        self.tail = (self.tail + 1) % DRIVER_REQUEST_QUEUE_DEPTH;
        self.count -= 1;
        Some(r)
    }
}

/// Replies kept for polling clients: [`REPLY_RING_DEPTH`] entries, each
/// keyed by its token.
///
/// 4, not the queue depth (8): owner decision 2026-09-28, which traded the
/// depth for kernel image size (one ring per kind, `DRIVER_MAX_KINDS` of
/// them). A fifth polling client with a reply outstanding evicts the oldest
/// entry, as a ninth did before.
pub const REPLY_RING_DEPTH: usize = 4;

/// The published replies of one kind that no armed waiter took.
///
/// Reading is not destructive (a reader must survive a failed copy-out,
/// U07-2; written for `SYS_DRIVER_TRY_REPLY`, retired in wave 11). A reply for a token already on file replaces that entry
/// only; a new token takes a free entry, else the OLDEST one. So up to
/// [`REPLY_RING_DEPTH`] clients with a reply outstanding each find their own,
/// and a driver's duplicate reply can no longer overwrite another token's.
#[derive(Clone, Copy)]
pub struct ReplyRing {
    entries: [DriverReply; REPLY_RING_DEPTH],
    /// Publication order per entry; 0 = empty.
    seq: [u64; REPLY_RING_DEPTH],
    next_seq: u64,
}

impl ReplyRing {
    pub const fn new() -> Self {
        ReplyRing {
            entries: [DriverReply::zeroed(); REPLY_RING_DEPTH],
            seq: [0; REPLY_RING_DEPTH],
            // The LAST sequence number handed out, 0 before the first:
            // `publish` pre-increments, so the first entry is 1 as before and
            // a fresh ring is all zero bytes (`REGISTRY` in `.bss`).
            next_seq: 0,
        }
    }

    /// File `reply` under its token.
    pub fn publish(&mut self, reply: DriverReply) {
        let mut pick = None;
        for i in 0..REPLY_RING_DEPTH {
            if self.seq[i] != 0 && self.entries[i].token == reply.token {
                pick = Some(i);
                break;
            }
        }
        let i = match pick {
            Some(i) => i,
            None => {
                // A free entry (seq 0) sorts first; otherwise the oldest.
                let mut best = 0;
                for j in 1..REPLY_RING_DEPTH {
                    if self.seq[j] < self.seq[best] {
                        best = j;
                    }
                }
                best
            }
        };
        self.next_seq = self.next_seq.wrapping_add(1).max(1);
        self.entries[i] = reply;
        self.seq[i] = self.next_seq;
    }

    /// Copy the reply for `token` out, if one is on file. Not destructive.
    pub fn lookup(&self, token: u64, out: &mut DriverReply) -> bool {
        for i in 0..REPLY_RING_DEPTH {
            if self.seq[i] != 0 && self.entries[i].token == token {
                *out = self.entries[i];
                return true;
            }
        }
        false
    }
}

/// Lock-free "the reply for this token is in its row" flags, one per waiter
/// row per registry slot: the delivering hold stores the token here (Release)
/// after writing the reply into the row, so a client polling for its reply
/// (the proxy's bounded spin) reads one atomic instead of taking `REGISTRY`,
/// which the driver on the other hart needs for every fetch and reply. Tokens
/// are unique per slot for the life of the boot (`next_token` is never
/// reset), so a stale value can never equal a live client's token.
static REPLY_POSTED: [[AtomicU64; reply_wait::MAX_REPLY_WAITERS]; DRIVER_MAX_KINDS] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    const ROW: [AtomicU64; reply_wait::MAX_REPLY_WAITERS] = [Z; reply_wait::MAX_REPLY_WAITERS];
    [ROW; DRIVER_MAX_KINDS]
};

/// Has the reply for `token` been delivered to waiter row `row` of registry
/// slot `slot`? Lock-free; the reply itself is taken under `REGISTRY` with
/// [`driver_withdraw_waiter`].
#[inline]
pub fn reply_posted(slot: usize, row: usize, token: u64) -> bool {
    match REPLY_POSTED.get(slot).and_then(|r| r.get(row)) {
        Some(a) => a.load(Ordering::Acquire) == token,
        None => false,
    }
}

/// Driver-side fetches that found the queue empty, per registry slot: a 581
/// or 523 call that returned "no request", or a 610 call that parked (once
/// per park, whether it then ended at a submit, a stamp or its deadline). The
/// count of times a driver ran its serve loop for nothing — what a 10 ms poll
/// spends ~100 times a second and a parked driver ~once per park bound.
/// Telemetry: the AQ3 and DRV1 smokes read it over a quiet window.
static EMPTY_FETCHES: [AtomicU32; DRIVER_MAX_KINDS] = {
    const Z: AtomicU32 = AtomicU32::new(0);
    [Z; DRIVER_MAX_KINDS]
};

fn note_empty_fetch(slot: usize) {
    if let Some(c) = EMPTY_FETCHES.get(slot) {
        c.fetch_add(1, Ordering::Relaxed);
    }
}

/// [`EMPTY_FETCHES`] of the slot `kind` is registered in, while it is.
/// Monotonic for the life of the boot (a slot's count is not reset when it
/// is released): read it twice and subtract.
pub fn driver_empty_fetches(kind: u32) -> Option<u32> {
    let reg = REGISTRY.lock();
    let idx = reg.find_kind_idx(kind)?;
    Some(EMPTY_FETCHES[idx].load(Ordering::Relaxed))
}

fn reset_posted(slot: usize) {
    if let Some(r) = REPLY_POSTED.get(slot) {
        for a in r.iter() {
            a.store(0, Ordering::Relaxed);
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Registry (indexed by kind).
// ───────────────────────────────────────────────────────────────────────────

pub static REGISTRY: SpinLock<DriverRegistry> = SpinLock::new(DriverRegistry::new());

pub struct DriverRegistry {
    pub slots: [DriverSlot; DRIVER_MAX_KINDS],
}

impl DriverRegistry {
    pub const fn new() -> Self {
        const S: DriverSlot = DriverSlot::empty();
        Self { slots: [S; DRIVER_MAX_KINDS] }
    }

    fn find_kind(&mut self, kind: u32) -> Option<&mut DriverSlot> {
        self.slots.iter_mut().find(|s| {
            s.active.load(Ordering::Relaxed) && s.kind == kind
        })
    }

    fn find_kind_idx(&self, kind: u32) -> Option<usize> {
        self.slots.iter().position(|s| {
            s.active.load(Ordering::Relaxed) && s.kind == kind
        })
    }

    fn find_free(&mut self) -> Option<&mut DriverSlot> {
        self.slots.iter_mut().find(|s| !s.active.load(Ordering::Relaxed))
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Syscall-layer entry points.
// ───────────────────────────────────────────────────────────────────────────

/// Register `tid` as the driver for `kind`.  Returns `true` on success.
///
/// A task registering a kind it already holds succeeds and refreshes the
/// slot's MMIO/IRQ fields. That is how a successor the M4 supervisor created
/// takes up the slot its predecessor held: [`driver_adopt`] made it the owner
/// before it ran, and its image registers exactly as the first one did. Any
/// other task asking for a registered kind — orphaned or not — is refused.
pub fn driver_register(
    kind: u32,
    tid: u32,
    mmio_base: u64,
    mmio_size: u64,
    irq: u32,
) -> bool {
    let mut reg = REGISTRY.lock();
    if let Some(slot) = reg.find_kind(kind) {
        if tid != 0 && slot.driver_tid == tid {
            slot.mmio_base = mmio_base;
            slot.mmio_size = mmio_size;
            slot.irq       = irq;
            return true;
        }
        return false; // already registered, to another task or orphaned
    }
    if let Some(slot) = reg.find_free() {
        slot.kind       = kind;
        slot.driver_tid = tid;
        slot.mmio_base  = mmio_base;
        slot.mmio_size  = mmio_size;
        slot.irq        = irq;
        slot.orphan_of  = 0;
        slot.active.store(true, Ordering::Release);
        true
    } else {
        false
    }
}

/// Is `tid` the task that registered `kind`?
///
/// `driver_tid` was recorded at registration and then read nowhere in the
/// tree — write-only. So `fetch`/`poll`/`reply` had no notion of an owner, and
/// any task could drain another driver's request queue (fetch POPS, so the
/// real driver never saw it) or write its reply. On a robot whose ring-3
/// drivers are meant to serve sensors and actuators, that is the control loop
/// acting on a reading nobody measured, or believing an actuator acknowledged
/// a command that was never written.
///
/// An unregistered kind has no owner, so this is false for everyone —
/// including tid 0, which is why `FD_NO_OWNER`-style sentinels are not
/// special-cased here.
pub fn driver_is_owner(kind: u32, tid: u32) -> bool {
    let mut reg = REGISTRY.lock();
    match reg.find_kind(kind) {
        // `driver_tid == 0` is an orphaned slot: nobody owns it, and 0 is
        // never a live TID to compare equal to.
        Some(slot) => slot.active.load(Ordering::Acquire) && slot.driver_tid != 0
            && slot.driver_tid == tid,
        None => false,
    }
}

/// The TID of the task that registered `kind`, while it is registered.
///
/// Diagnostics: the AQ3 smoke reads the live ring-3 driver's scheduling state
/// through it (wave 7). Routing never uses it — requests are routed by kind.
pub fn driver_owner_tid(kind: u32) -> Option<u32> {
    let mut reg = REGISTRY.lock();
    match reg.find_kind(kind) {
        Some(slot) if slot.active.load(Ordering::Acquire) && slot.driver_tid != 0 => {
            Some(slot.driver_tid)
        }
        _ => None,
    }
}

/// Release every driver slot owned by `tid`. Returns how many.
///
/// Called from the kernel's task-exit path, like the handle, port, io_ring,
/// socket and descriptor tables. Nothing called `driver_unregister` on exit —
/// the comment at `user_driver_proxy.rs:199` saying otherwise was false — so a
/// driver that crashed left its slot `active` forever. With ownership now
/// enforced, that is worse than untidy: the kind becomes permanently
/// unclaimable, and every client of it pays the proxy's full reply timeout
/// before giving up.
pub fn driver_release_all(tid: u32) -> usize {
    if tid == 0 { return 0; }
    let mut reg = REGISTRY.lock();
    let mut freed = 0usize;
    for (i, slot) in reg.slots.iter_mut().enumerate() {
        if slot.active.load(Ordering::Acquire) && slot.driver_tid == tid {
            slot.active.store(false, Ordering::Release);
            slot.driver_tid = 0;
            slot.orphan_of = 0;
            clear_stop(slot);
            slot.irq_pending.store(false, Ordering::Relaxed);
            // Nobody will answer these tokens now; each client ends at its
            // own deadline. The rows and the queued requests are cleared so a
            // later registration of this slot — possibly for another kind —
            // is not handed requests addressed to the driver that died.
            let _ = slot.waiters.clear();
            reset_posted(i);
            slot.parked = None;
            *slot.queue.lock() = DriverQueue::new();
            *slot.replies.lock() = ReplyRing::new();
            freed += 1;
        }
    }
    freed
}

// ───────────────────────────────────────────────────────────────────────────
// RFC-0049 M4: a supervised driver's slot outlives the driver.
// ───────────────────────────────────────────────────────────────────────────

/// Orphan every slot `tid` owns: the slot stays active, with its queue and its
/// armed waiters, and nobody owns it (`driver_tid = 0`, `orphan_of = tid`).
/// Returns how many.
///
/// The exit path calls this instead of [`driver_release_all`] for a driver the
/// M4 supervisor is restarting. A client that submits during the gap is queued
/// (up to [`DRIVER_REQUEST_QUEUE_DEPTH`]) and served by the successor, instead
/// of being told the kind does not exist. The request the dead driver had
/// fetched but not answered is not replayed: its client's wait ends at its own
/// deadline. The latched IRQ is dropped: it was for the dead task's view of
/// the device, which the successor re-initialises.
pub fn driver_orphan_all(tid: u32) -> usize {
    if tid == 0 { return 0; }
    let mut reg = REGISTRY.lock();
    let mut n = 0usize;
    for slot in reg.slots.iter_mut() {
        if slot.active.load(Ordering::Acquire) && slot.driver_tid == tid {
            slot.driver_tid = 0;
            slot.orphan_of = tid;
            clear_stop(slot);
            slot.irq_pending.store(false, Ordering::Relaxed);
            // The dead task's park, if it died parked: a submit during the
            // gap must not wake its TID (possibly reused by then). The
            // successor parks for itself.
            slot.parked = None;
            n += 1;
        }
    }
    n
}

/// Hand every slot orphaned by `dead_tid` to `heir`, before `heir` runs.
/// Returns how many. `heir` then registers the kind as its image always does,
/// and [`driver_register`] accepts it as the owner.
pub fn driver_adopt(dead_tid: u32, heir: u32) -> usize {
    if dead_tid == 0 || heir == 0 { return 0; }
    let mut reg = REGISTRY.lock();
    let mut n = 0usize;
    for slot in reg.slots.iter_mut() {
        if slot.active.load(Ordering::Acquire) && slot.driver_tid == 0
            && slot.orphan_of == dead_tid
        {
            slot.driver_tid = heir;
            slot.orphan_of = 0;
            n += 1;
        }
    }
    n
}

/// Release every slot orphaned by `dead_tid`, as [`driver_release_all`] would
/// have at its death: the supervisor could not create a successor.
pub fn driver_release_orphans(dead_tid: u32) -> usize {
    if dead_tid == 0 { return 0; }
    let mut reg = REGISTRY.lock();
    let mut n = 0usize;
    for slot in reg.slots.iter_mut() {
        if slot.active.load(Ordering::Acquire) && slot.driver_tid == 0
            && slot.orphan_of == dead_tid
        {
            slot.active.store(false, Ordering::Release);
            slot.orphan_of = 0;
            slot.irq_pending.store(false, Ordering::Relaxed);
            let _ = slot.waiters.clear();
            slot.parked = None;
            *slot.queue.lock() = DriverQueue::new();
            n += 1;
        }
    }
    n
}

/// Slots with a stop request not yet taken. Lets [`driver_take_stop`] answer
/// "no" with one load, without `REGISTRY`, on every driver-side call.
static STOP_PENDING: AtomicU32 = AtomicU32::new(0);

fn clear_stop(slot: &DriverSlot) {
    if slot.stop_requested.swap(false, Ordering::AcqRel) {
        STOP_PENDING.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Ask the driver registered for `kind` to stop. Returns its TID, or `None`
/// when the kind has no live driver. Kernel-only: no syscall reaches it.
///
/// The driver exits at its next driver-side call — fetch, reply, reply+fetch,
/// reply+wait or poll, the calls its serve loop is made of — through
/// [`driver_take_stop`].
/// A driver that never makes one of those calls again (a ring-3 loop with no
/// syscall) is not stopped by this; nothing in this kernel can interrupt ring 3
/// from outside yet.
///
/// A driver parked in `SYS_DRIVER_REPLY_WAIT` on its empty queue is woken, so
/// it reaches that call's stop point now rather than at its park deadline.
pub fn driver_request_stop(kind: u32) -> Option<u32> {
    driver_request_stop_code(kind, azos_abi::exit_status::KILLED_KILL)
}

/// [`driver_request_stop`], with the exit code the driver exits with. The
/// kernel's own stop is a kill (`KILLED_KILL`); the supervisor's gate row
/// also asks for a clean `0`, the code a driver's own `exit(0)` gives the
/// same `task_exit_with_code`, to show that one is not restarted.
pub fn driver_request_stop_code(kind: u32, code: i32) -> Option<u32> {
    let mut reg = REGISTRY.lock();
    let slot = reg.find_kind(kind)?;
    if slot.driver_tid == 0 { return None; }
    slot.stop_code.store(code, Ordering::Release);
    if !slot.stop_requested.swap(true, Ordering::AcqRel) {
        STOP_PENDING.fetch_add(1, Ordering::AcqRel);
    }
    let tid = slot.driver_tid;
    let parked = slot.parked.take();
    drop(reg);
    wake_parked(parked);
    Some(tid)
}

/// Whether any driver has a stop request not yet taken. One atomic load: what
/// the driver-side syscalls test before anything else.
#[inline]
pub fn driver_stop_pending() -> bool {
    STOP_PENDING.load(Ordering::Acquire) != 0
}

/// Whether `tid`, the driver of `kind`, has been asked to stop. Consumes the
/// request. One atomic load when no stop is pending anywhere.
pub fn driver_take_stop(kind: u32, tid: u32) -> bool {
    driver_take_stop_code(kind, tid).is_some()
}

/// [`driver_take_stop`], answering the exit code the stop asked for.
pub fn driver_take_stop_code(kind: u32, tid: u32) -> Option<i32> {
    if STOP_PENDING.load(Ordering::Acquire) == 0 { return None; }
    let mut reg = REGISTRY.lock();
    match reg.find_kind(kind) {
        Some(slot) if slot.driver_tid != 0 && slot.driver_tid == tid => {
            if slot.stop_requested.swap(false, Ordering::AcqRel) {
                STOP_PENDING.fetch_sub(1, Ordering::AcqRel);
                Some(slot.stop_code.swap(azos_abi::exit_status::KILLED_KILL, Ordering::AcqRel))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Unregister a driver. Called on process exit / explicit unregister.
pub fn driver_unregister(kind: u32) -> bool {
    let mut reg = REGISTRY.lock();
    if let Some(i) = reg.find_kind_idx(kind) {
        let slot = &mut reg.slots[i];
        slot.active.store(false, Ordering::Release);
        slot.driver_tid = 0;
        slot.orphan_of = 0;
        clear_stop(slot);
        slot.irq_pending.store(false, Ordering::Relaxed);
        // Same reason as `driver_release_all`.
        let _ = slot.waiters.clear();
        reset_posted(i);
        slot.parked = None;
        *slot.queue.lock() = DriverQueue::new();
        *slot.replies.lock() = ReplyRing::new();
        true
    } else {
        false
    }
}

/// Enqueue a client request. Returns the issued token, or 0 on failure
/// (no such driver / queue full).
pub fn driver_submit_request(
    kind: u32,
    client_tid: u32,
    op: u32,
    input: &[u8],
    out_cap: u16,
) -> u64 {
    let mut reg = REGISTRY.lock();
    let slot = match reg.find_kind(kind) {
        Some(s) => s,
        None    => return 0,
    };

    let token = issue_token(slot);
    let mut req = DriverRequest::zeroed();
    req.token      = token;
    req.client_tid = client_tid;
    req.op         = op;
    req.out_cap    = out_cap;
    let n = core::cmp::min(input.len(), DRIVER_REQUEST_PAYLOAD_BYTES);
    req.input[..n].copy_from_slice(&input[..n]);
    req.in_len = n as u16;

    if !slot.queue.lock().push(req) {
        return 0;
    }
    let parked = slot.parked.take();
    drop(reg);
    wake_parked(parked);
    token
}

/// What [`driver_submit_request_armed`] queued and armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArmedRequest {
    pub token: u64,
    /// The registered driver, read in the same hold: the task the caller
    /// donates to.
    pub driver_tid: u32,
    /// Registry slot and waiter row: where [`reply_posted`] looks.
    pub slot: usize,
    pub row: usize,
}

/// [`driver_submit_request`] for an in-kernel client that will block on the
/// reply: queue the request and arm `waiter_tid` as its waiter in the SAME
/// `REGISTRY` hold, so the driver cannot fetch — let alone answer — the
/// request before the waiter exists (`reply_wait`'s lost-wake argument).
///
/// The waiter row is also where the reply lands ([`driver_reply`]): each
/// armed request owns its reply slot until its client withdraws it, so two
/// clients of one kind waiting at once each get their own reply.
///
/// `None` when the kind is not registered, its queue is full, or every waiter
/// row is taken. Nothing is queued or armed on `None`.
pub fn driver_submit_request_armed(
    kind: u32,
    client_tid: u32,
    op: u32,
    input: &[u8],
    out_cap: u16,
    waiter_tid: u32,
    deadline: u64,
) -> Option<ArmedRequest> {
    let mut reg = REGISTRY.lock();
    let idx = reg.find_kind_idx(kind)?;
    let slot = &mut reg.slots[idx];
    if slot.waiters.armed() == reply_wait::MAX_REPLY_WAITERS {
        return None;
    }
    let token = issue_token(slot);
    let mut req = DriverRequest::zeroed();
    req.token      = token;
    req.client_tid = client_tid;
    req.op         = op;
    req.out_cap    = out_cap;
    let n = core::cmp::min(input.len(), DRIVER_REQUEST_PAYLOAD_BYTES);
    req.input[..n].copy_from_slice(&input[..n]);
    req.in_len = n as u16;

    if !slot.queue.lock().push(req) {
        return None;
    }
    // Cannot fail: checked above, and the hold has not been released.
    let row = slot.waiters.arm(ReplyWaiter { tid: waiter_tid, token, deadline })?;
    let driver_tid = slot.driver_tid;
    let parked = slot.parked.take();
    drop(reg);
    wake_parked(parked);
    Some(ArmedRequest { token, driver_tid, slot: idx, row })
}

/// Wake a driver parked on its empty queue, after the `REGISTRY` hold that
/// took it is released (the wake takes run-queue locks — the `driver_reply`
/// order). Same hook, same predicate as a reply's wake: the driver blocked on
/// `Timer(deadline)`, and a driver that has not blocked yet is stamped, so
/// its block returns at once and it re-tests the queue.
fn wake_parked(parked: Option<ParkedDriver>) {
    if let Some(p) = parked {
        if let Some(h) = reply_wait::proxy_hooks() {
            (h.wake)(p.tid, p.deadline);
        }
    }
}

/// What [`driver_fetch_or_park`] found.
#[derive(Clone, Copy)]
pub enum FetchOrPark {
    /// The next request, taken off the queue.
    Request(DriverRequest),
    /// The queue was empty and the caller is now parked: block on
    /// `Timer(deadline)`, then call again.
    Parked,
    /// `kind` is not registered to `tid` (any more): nothing was parked.
    NotOwner,
}

/// The driver side of `SYS_DRIVER_REPLY_WAIT`: take the next request, or
/// park `tid` as the one to wake when a request is queued.
///
/// # The lost-wake argument, the proxy's own
///
/// The park is recorded in the `REGISTRY` hold that found the queue empty,
/// and both submit paths take it in the hold that queues a request. So every
/// request queued after this call either is found by it or wakes the parked
/// task. The wake may arrive before the task blocks: the scheduler stamps it
/// (K-C9) and the block returns at once, and the caller's next call finds the
/// request. A wake is never lost, only early.
pub fn driver_fetch_or_park(kind: u32, tid: u32, deadline: u64) -> FetchOrPark {
    let mut reg = REGISTRY.lock();
    let Some(idx) = reg.find_kind_idx(kind) else { return FetchOrPark::NotOwner };
    let slot = &mut reg.slots[idx];
    if slot.driver_tid != tid {
        return FetchOrPark::NotOwner;
    }
    let popped = slot.queue.lock().pop();
    match popped {
        Some(req) => {
            slot.parked = None;
            FetchOrPark::Request(req)
        }
        None => {
            slot.parked = Some(ParkedDriver { tid, deadline });
            note_empty_fetch(idx);
            FetchOrPark::Parked
        }
    }
}

/// End a park that no request ended (its deadline passed, or the scheduler
/// refused to block). `true` when a park of `tid` was withdrawn.
pub fn driver_unpark(kind: u32, tid: u32) -> bool {
    let mut reg = REGISTRY.lock();
    match reg.find_kind(kind) {
        Some(slot) if matches!(slot.parked, Some(p) if p.tid == tid) => {
            slot.parked = None;
            true
        }
        _ => false,
    }
}

/// Client side, when its wait ends: withdraw its waiter row and take the
/// reply delivered to it, if any. After this the row is free and a reply for
/// `token` goes to the ring ([`ReplyRing`]) instead — answered into the void.
pub fn driver_withdraw_waiter(kind: u32, tid: u32, token: u64) -> reply_wait::Withdrawn {
    let mut reg = REGISTRY.lock();
    match reg.find_kind(kind) {
        Some(slot) => slot.waiters.withdraw(tid, token),
        None => reply_wait::Withdrawn::NotArmed,
    }
}

/// [`driver_withdraw_waiter`] for a caller that only needs to know whether a
/// row was still armed (delivered or not).
pub fn driver_disarm_waiter(kind: u32, tid: u32, token: u64) -> bool {
    !matches!(driver_withdraw_waiter(kind, tid, token), reply_wait::Withdrawn::NotArmed)
}

/// Signal an IRQ to the registered driver for `irq`, if any.
pub fn driver_signal_irq(irq: u32) -> bool {
    let mut reg = REGISTRY.lock();
    for s in reg.slots.iter_mut() {
        if s.active.load(Ordering::Relaxed) && s.irq == irq {
            s.irq_pending.store(true, Ordering::Release);
            return true;
        }
    }
    false
}

/// Driver polls for the next event. Returns (event_kind, payload_word).
/// The payload word meaning depends on event kind:
///   - `DRV_EVENT_REQUEST` → first u64 of the payload (token)
///   - `DRV_EVENT_IRQ`     → irq number
///   - `DRV_EVENT_NONE`    → 0 (caller should block via sched)
pub fn driver_poll_event(kind: u32) -> (u32, u64) {
    let mut reg = REGISTRY.lock();
    if let Some(slot) = reg.find_kind(kind) {
        if slot.irq_pending.swap(false, Ordering::AcqRel) {
            return (DRV_EVENT_IRQ, slot.irq as u64);
        }
        if slot.queue.lock().count > 0 {
            // Return just the token of the oldest pending request.
            let q = slot.queue.lock();
            let tail_req = q.entries[q.tail];
            return (DRV_EVENT_REQUEST, tail_req.token);
        }
    }
    (DRV_EVENT_NONE, 0)
}

/// Consume the next pending request (driver picks it up from the queue).
/// An empty queue is counted in [`driver_empty_fetches`].
pub fn driver_fetch_request(kind: u32) -> Option<DriverRequest> {
    let reg = REGISTRY.lock();
    let idx = reg.find_kind_idx(kind)?;
    let popped = reg.slots[idx].queue.lock().pop();
    if popped.is_none() {
        note_empty_fetch(idx);
    }
    popped
}

/// [`driver_fetch_request`] for the last look a 610 call takes after its park
/// ended with no wake: not counted, because that park already was.
pub fn driver_fetch_after_park(kind: u32) -> Option<DriverRequest> {
    let mut reg = REGISTRY.lock();
    let slot = reg.find_kind(kind)?;
    let mut q = slot.queue.lock();
    q.pop()
}

/// Publish a reply for a previously-submitted token, and wake the in-kernel
/// client blocked on that token, if one is armed (`reply_wait`).
///
/// An armed client's reply is written into ITS waiter row, and the row's
/// posted flag set, in one `REGISTRY` hold; the wake runs after the hold is
/// released, because it takes run-queue locks. A second reply to a token
/// already delivered is dropped (the first one woke the client). A token with
/// no armed row — a ring-3 client (`sys_driver_request` +
/// `sys_driver_try_reply`), or a kernel client that already gave up — goes to
/// the kind's [`ReplyRing`].
pub fn driver_reply(kind: u32, reply: DriverReply) -> bool {
    let waiter = {
        let mut reg = REGISTRY.lock();
        let idx = match reg.find_kind_idx(kind) {
            Some(i) => i,
            None    => return false,
        };
        let slot = &mut reg.slots[idx];
        match slot.waiters.deliver(reply) {
            reply_wait::Delivery::ToWaiter(row, w) => {
                REPLY_POSTED[idx][row].store(reply.token, Ordering::Release);
                Some(w)
            }
            reply_wait::Delivery::Duplicate => None,
            reply_wait::Delivery::NoWaiter => {
                slot.replies.lock().publish(reply);
                None
            }
        }
    };
    if let Some(w) = waiter {
        if let Some(h) = reply_wait::proxy_hooks() {
            (h.wake)(w.tid, w.deadline);
        }
    }
    true
}

/// Check if a reply for `token` has been published for a polling client; if
/// so, copy it out. Not destructive. Replies delivered to an armed in-kernel
/// client's row are not visible here: that client takes them with
/// [`driver_withdraw_waiter`].
pub fn driver_try_take_reply(kind: u32, token: u64, out: &mut DriverReply) -> bool {
    let mut reg = REGISTRY.lock();
    if let Some(slot) = reg.find_kind(kind) {
        return slot.replies.lock().lookup(token, out);
    }
    false
}

// ───────────────────────────────────────────────────────────────────────────
// Statistics / diagnostic.
// ───────────────────────────────────────────────────────────────────────────

pub static TOTAL_REQUESTS: AtomicU32 = AtomicU32::new(0);
pub static TOTAL_IRQS:     AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
pub struct DriverServerStats {
    pub active_drivers:   u32,
    pub total_requests:   u32,
    pub total_irqs:       u32,
    pub queue_high_water: u32,
}

pub fn stats() -> DriverServerStats {
    let reg = REGISTRY.lock();
    let mut active = 0u32;
    let mut high = 0u32;
    for s in reg.slots.iter() {
        if s.active.load(Ordering::Relaxed) {
            active += 1;
            let c = s.queue.lock().count as u32;
            if c > high { high = c; }
        }
    }
    DriverServerStats {
        active_drivers:   active,
        total_requests:   TOTAL_REQUESTS.load(Ordering::Relaxed),
        total_irqs:       TOTAL_IRQS.load(Ordering::Relaxed),
        queue_high_water: high,
    }
}
