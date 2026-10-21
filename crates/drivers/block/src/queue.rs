// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The block request layer: per-hart submission queues, merge, plug, and the
//! [`HwQueue`] a device implements (Kconfig `BLK_QUEUE_DEPTH`,
//! `BLK_MERGE_MAX`, `BLK_IOSCHED`).
//!
//! ```text
//!   blkdev::read/write/flush      (the synchronous facade, `BlockDevice`)
//!        |  BlockRequest + kernel buffer
//!        v
//!   ReqQueue: one submission queue per hart  --pick-->  merged command
//!        |                                                   |
//!        |  Ticket, wait()                                   v
//!        +<------------ completion (reap) ------------  HwQueue (NVMe, ...)
//! ```
//!
//! # Requests
//!
//! A request is `azos_devif::block::BlockRequest` plus the kernel buffer that
//! travels beside it. [`ReqQueue::submit`] refuses a malformed request, and in
//! particular one **without an owner** (`BlockRequest::check`): every request
//! is some Domain's (or the kernel's, `OWNER_KERNEL`), and only requests of one
//! owner are merged. The synchronous facade stamps the owner itself
//! (`blkdev::set_owner_source`), so the refusal bites the direct users of the
//! queue: the write-back path and anything that builds its own request. A
//! request that names a MemObj is answered `UNSUPPORTED`: this layer reaches
//! kernel buffers only, until the kernel registers a way to map a MemObj range.
//!
//! A request is at most one device command long. [`ReqQueue::transfer`] cuts a
//! longer one into requests of the device's largest command and keeps up to
//! `BLK_QUEUE_DEPTH` of them in flight. The slots of a hart's queue are shared
//! by every task that runs there, so a task that holds tickets never sleeps for
//! a slot (`Failure::Full`: it collects one of its own and tries again); two
//! such tasks asleep for slots would each wait on the finished requests of the
//! other.
//!
//! # Queues, and who runs the device
//!
//! Each hart has `BLK_QUEUE_DEPTH` slots behind a spinlock held for a push or
//! a pop and never across a wait (owner rule F1). A slot belongs to a request
//! from its submit until its submitter collects the outcome ([`ReqQueue::wait`]).
//!
//! There is no I/O thread. Whoever submits or waits runs [`ReqQueue::pump`]:
//! it reaps the completions the device has posted, then (if no other task is
//! dispatching) picks work from every hart's queue and starts it. Which
//! request is picked is the scheduler's rule ([`Sched`], below); requests of
//! one owner and class, of the same operation, adjacent on the medium and
//! queued by any hart become ONE command (up to the device's largest command
//! and `BLK_MERGE_MAX` requests).
//! A waiter sleeps on a timer for at most a slice and is woken early by TID
//! ([`Sleepers`]), except one task at a time which holds the *reaper* role and
//! sleeps in the device ([`HwQueue::wait`], the completion interrupt) for at
//! most a slice, then wakes the rest. No sleep here is unbounded: a wake that
//! never arrives delays a waiter by a slice.
//!
//! **A submitter never leaves while its request is started.** The buffer it
//! lent is read and written by whichever task completes the command, so a
//! request is done only when the outcome is final: a command that never
//! completes is the device's to declare dead (and fail), not the waiter's to
//! abandon. The budget of a *started* command belongs to the device (the
//! driver times each command it holds, resets the controller when one runs out
//! and answers [`HwStatus::Timeout`] for it, [`HwStatus::Io`] for the others it
//! held); a request's own deadline ([`BlockRequest::deadline_ns`]) is a
//! **start-by** time and ends a request that is still queued (`Outcome::Deadline`),
//! which is this layer's whole cancel: a started request is never recalled.
//!
//! # A device that stops answering
//!
//! The layer fails the request (`Outcome::Io`, the caller sees an error and
//! nothing hangs) and tells the kernel through the sink it registers
//! ([`set_timeout_sink`]) when
//!
//! * a command is reported [`HwStatus::Timeout`]: [`TimeoutAction::Failed`],
//!   with the command's first sector and how long it was in the device;
//! * the device answers [`Claim::Dead`] for the first time: the device is
//!   offline for good, [`TimeoutAction::Offline`], with the sector of the
//!   request that found it so. Every request after it ends `Outcome::Io` at
//!   once.
//!
//! The sink runs with no queue lock held and must not do block I/O (it would
//! enter this layer, whose device just died).
//!
//! # Scheduler and request class
//!
//! Kconfig `BLK_IOSCHED` chooses the pick rule ([`Sched`]):
//!
//! * `none`: the oldest queued request. A request's own deadline still ends
//!   it with a miss when it passes before the request is started, but no
//!   longer moves it ahead of older ones.
//! * `mq-deadline`: the earliest deadline, then the oldest (a request with
//!   no deadline sorts after every request with one).
//! * `rt-deadline`: `mq-deadline`, with the **real-time class** first and a
//!   slot of every hart's queue kept for it.
//!
//! The class belongs to the request, not to the task that issues it: it is
//! stamped at submit, by a source only the kernel registers
//! ([`set_rt_class_source`]), and no Domain can claim it. The source says yes
//! to the requests that serve a durable record waiting for the medium (the
//! flight recorder's e-stop latch, the operator-release nonce floor): the
//! writes and the fsync of the flush that carries it, and the write-back
//! passes that must write its cache lines first (the `fs-wb` task, or any
//! task that runs a pass in that window). The same task's requests are
//! ordinary again once the record is on the medium. A real-time task does not
//! come in by this door: it still never does block I/O
//! (`blkdev::rt_io_check`, run before a request is even built), so its record
//! reaches the medium through the ring and the log flusher.
//!
//! The reserved slot is what keeps such a request from sleeping for a free
//! slot behind bulk traffic: with fewer than two free slots on a hart an
//! ordinary request is refused (`try_submit`: [`Failure::Full`]) or put to
//! sleep (`submit`), and the last slot is the real-time class's. Hardware
//! command slots are not reserved: a real-time request waits at most for the
//! earliest command in flight to complete, then goes first.
//!
//! # Plug
//!
//! [`ReqQueue::plug`] holds a task's submissions back until the plug drops, so
//! one transfer's requests are all queued before the first is started. That is
//! what lets them be merged with their neighbours and, for a write that must
//! follow a flush ([`FLAG_PREFLUSH`](azos_devif::block::FLAG_PREFLUSH)), lets
//! ONE flush serve all of them: a flush covers every request submitted before
//! it started.
//!
//! # Ordering
//!
//! Requests are not ordered. A caller that needs order waits for the first
//! before it submits the second, or says `PREFLUSH`: the write is started only
//! after every write that completed before it was submitted is durable.
//! `FUA` is native in the device command; a device that cannot honour it
//! says so in [`HwCaps::fua`] and the layer refuses a request that asks for
//! it (`UNSUPPORTED`), instead of faking the guarantee with a flush the
//! caller did not ask for.
//!
//! # Discard
//!
//! [`ReqQueue::discard`] cuts ranges into requests of the device's largest
//! discard ([`HwCaps::max_discard_sectors`]; 0 refuses). A discard is a hint:
//! the request layer neither orders it against writes nor knows which sectors
//! are still wanted. The caller does (FAT32 discards a chain still allocated;
//! the swap area keeps its slot reserved), and every discard is waited for
//! before the call returns.
//!
//! Lives in its own file, with no dependency beyond the sync primitives, the
//! request type and the device types of `azos_drv_api::block`, so `tests/host/drivers-tests` pulls this exact code.

use azos_devif::block::{BlockRequest, FLAG_FUA, FLAG_PREFLUSH, REQ_DISCARD, REQ_READ, REQ_WRITE};
use azos_devif::outcome;
use azos_sync::kmutex::Mutex;
use azos_sync::waitstat::Site;
use azos_sync::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Bytes per sector.
pub const SECTOR: usize = 512;
/// Harts that have a submission queue (Kconfig `NR_CPUS`).
const HARTS: usize = azos_limits::NR_CPUS;
/// Request slots per hart (Kconfig `BLK_QUEUE_DEPTH`).
const DEPTH: usize = azos_limits::BLK_QUEUE_DEPTH as usize;
/// Requests merged into one command (Kconfig `BLK_MERGE_MAX`).
const MERGE_MAX: usize = azos_limits::BLK_MERGE_MAX as usize;
/// Longest sleep of the reaper between completion checks: a slice, never a
/// deadline (an idle CPU under `-icount sleep=off` jumps its clock to the next
/// timer, and one sleep to a deadline would declare a live device dead).
/// Kconfig `WAIT_SLICE_US`.
const SLICE_NS: u64 = azos_sync::waitstat::SLICE_NS;
/// Longest sleep of a submitter that waits for a free slot: nobody is bound to
/// wake it (the slots are held by tickets whose owners may not be waiting), so
/// the wake is only the fast path and this is the bound.
const SPACE_SLICE_NS: u64 = 10 * SLICE_NS;
/// Tasks that can be registered on one [`Sleepers`] list at once. A task that
/// finds it full still sleeps (for its slice), it just is not woken early.
const SLEEPERS: usize = 16;

/// Slots of each hart's queue that only the real-time class may take
/// (`rt-deadline`).
const RT_RESERVE: usize = 1;

const _: () = assert!(DEPTH >= 2 && DEPTH <= 64 && MERGE_MAX >= 1 && MERGE_MAX <= 16 && HARTS >= 1);
const _: () = assert!(DEPTH > RT_RESERVE);

// ── The scheduler ───────────────────────────────────────────────────────

/// How the request layer picks the next request (Kconfig `BLK_IOSCHED`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sched {
    /// The oldest request first.
    None,
    /// The earliest deadline first, then the oldest.
    MqDeadline,
    /// [`Sched::MqDeadline`] with the real-time class ahead of every other,
    /// and a reserved slot per hart for it.
    RtDeadline,
}

impl Sched {
    /// The scheduler Kconfig `BLK_IOSCHED` chose.
    pub const CONFIGURED: Sched = if azos_limits::BLK_IOSCHED_RT_DEADLINE {
        Sched::RtDeadline
    } else if azos_limits::BLK_IOSCHED_MQ_DEADLINE {
        Sched::MqDeadline
    } else {
        Sched::None
    };
}

azos_common::ro_hook! {
    /// "Does the calling task's request serve a durable record that waits for
    /// the medium?" (the kernel's answer from the flight recorder and the
    /// FAT32 write-back). Read at submit, under `rt-deadline` only: a request
    /// made while it answers `true` is of the real-time class. Unset until
    /// the kernel registers it (boot): no request is then real-time.
    static RT_CLASS_SRC: fn() -> bool;
}

/// Register the source of the real-time class (the kernel, at boot). Only
/// `rt-deadline` reads it.
pub fn set_rt_class_source(f: fn() -> bool) {
    RT_CLASS_SRC.set(f);
}

azos_common::ro_hook! {
    /// Where a timed-out command and a device found dead are reported (the
    /// kernel: the `Rule::BlockTimeout` decision record). Unset: not reported.
    static TIMEOUT_SINK: fn(TimeoutAction, u64, u64);
}

/// What the layer did about a device that stopped answering; the values are
/// the `action` field of the `block-timeout` decision record
/// (`azos_decision::Rule::BlockTimeout`; 1 retried and 2 reset the device are
/// the driver's, not this layer's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TimeoutAction {
    /// The request was failed: its command did not complete in time.
    Failed = 3,
    /// The device was taken offline: it is dead, nothing is started on it.
    Offline = 4,
}

/// Register where timeouts are reported (the kernel, at boot): called as
/// `sink(action, first sector, milliseconds the command was in the device)`;
/// the milliseconds are 0 for [`TimeoutAction::Offline`].
pub fn set_timeout_sink(f: fn(TimeoutAction, u64, u64)) {
    TIMEOUT_SINK.set(f);
}

azos_common::ro_hook! {
    /// The kernel's sleep: block the caller until a TID wake or `deadline`
    /// (timebase ticks); `false` when the caller cannot block. Unset (before
    /// the scheduler): a waiter spins.
    static SLEEP_BLOCK: fn(u64) -> bool;
}
azos_common::ro_hook! {
    /// The kernel's wake of a task asleep in [`SLEEP_BLOCK`], by TID. It
    /// leaves a stamp when the task has not blocked yet, so a wake between a
    /// sleeper's last look and its block is not lost.
    static SLEEP_WAKE: fn(u32);
}

/// Register how a waiter sleeps and is woken (the kernel, at boot):
/// `block_until(deadline)` and `wake(tid)`, the pair the device drivers use for
/// their completion interrupt.
pub fn set_sleep_hooks(block_until: fn(u64) -> bool, wake: fn(u32)) {
    SLEEP_BLOCK.set(block_until);
    SLEEP_WAKE.set(wake);
}

/// The tasks asleep for "something changed" on one queue, by TID.
///
/// **Why not a `WaitQueue`.** A `WaitQueue` sleep has no deadline, and one
/// hang is on record (an OTA receive with QEMU paused, 20-10: the waiter
/// asleep, the queue empty, `done_epoch` 300 signals on) whose cause is not
/// found; `WaitQueue::wait_if` lists what it fixed and what is still open. A
/// sleeper here blocks on a timer ([`SLEEP_BLOCK`]) for at most a slice, so
/// whatever drops a wake costs the slice, and the waiter looks again. This
/// bounds the hang, it does not explain it.
///
/// Lock-free: a sleeper stores its TID, then looks at the epoch; a waker bumps
/// the epoch, then reads the TIDs (all `SeqCst`). One of the two sees the
/// other, so a change is never missed between the look and the sleep.
struct Sleepers {
    tids: [AtomicU32; SLEEPERS],
    /// Which counter an expiry with no wake is booked to.
    site: Site,
}

impl Sleepers {
    const fn new(site: Site) -> Self {
        Sleepers { tids: [const { AtomicU32::new(0) }; SLEEPERS], site }
    }

    /// Sleep for at most `slice_ns` unless `changed()` already holds once this
    /// task is registered; a wake through [`Sleepers::wake_all`] ends it early.
    ///
    /// A sleep that ends at its deadline is counted (`waitstat`): one with
    /// `changed()` already true then is a wake that did not come within the
    /// slice, the evidence of a lost wake at this site.
    fn sleep(&self, slice_ns: u64, changed: impl Fn() -> bool) {
        let tid = azos_sync::waitqueue::caller_tid();
        let block = SLEEP_BLOCK.get().filter(|_| tid != 0 && tid != u32::MAX);
        let slot = block.and_then(|_| {
            self.tids.iter().position(|s| s.compare_exchange(0, tid, Ordering::SeqCst, Ordering::SeqCst).is_ok())
        });
        let blocked = match block {
            Some(block) if !changed() => {
                let f = azos_drv_sys::timebase::TIMER_FREQ;
                let deadline = azos_drv_sys::timebase::now().saturating_add(slice_ns.saturating_mul(f) / 1_000_000_000);
                let blocked = block(deadline);
                if blocked && azos_drv_sys::timebase::now() >= deadline {
                    azos_sync::waitstat::note_expiry(self.site, changed());
                }
                blocked
            }
            // Nothing to wait for any more.
            Some(_) => true,
            None => false,
        };
        if let Some(i) = slot {
            self.tids[i].store(0, Ordering::SeqCst);
        }
        if !blocked {
            // No scheduler, or the task cannot block: look again at once.
            core::hint::spin_loop();
        }
    }

    /// Wake every registered sleeper (after the epoch they re-check moved).
    fn wake_all(&self) {
        let Some(wake) = SLEEP_WAKE.get() else { return };
        for s in &self.tids {
            let tid = s.load(Ordering::SeqCst);
            if tid != 0 {
                wake(tid);
            }
        }
    }
}

// ── What a device offers ────────────────────────────────────────────────
//
// The types a device driver implements live in `azos_drv_api::block`, which
// the drivers (NVMe here, virtio-blk in its own crate) and this layer share.
pub use azos_drv_api::block::{Claim, HwCaps, HwCmd, HwDone, HwOp, HwQueue, HwStatus, HW_TAGS_MAX};

// ── Tickets, outcomes ───────────────────────────────────────────────────

/// How a request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    /// The device failed the request, or died.
    Io,
    /// The device does not implement it (see [`HwStatus::Unsupported`]).
    Unsupported,
    /// The request's deadline passed before it was started.
    Deadline,
}

impl Outcome {
    /// The interface layer's code for it (`azos_devif::outcome`).
    pub const fn code(self) -> u32 {
        match self {
            Outcome::Ok => outcome::OK,
            Outcome::Io => outcome::FAULT,
            Outcome::Unsupported => outcome::UNSUPPORTED,
            Outcome::Deadline => outcome::BUSY,
        }
    }
}

/// Why a transfer or a submit did not succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Refused before it was queued: the interface layer's code
    /// (`REFUSED` for no owner, `BAD_ARGUMENT`, `UNSUPPORTED`).
    Refused(u32),
    /// Queued, and ended this way.
    Ended(Outcome),
    /// Not queued: the hart's queue has no free slot. Only [`ReqQueue::try_submit`]
    /// and [`Plug::submit`] answer it, to a caller that may hold tickets of its
    /// own: collect one (`wait`) and try again. Sleeping for a slot while
    /// holding finished requests would starve the others who share the queue.
    Full,
}

/// The handle of a submitted request: [`ReqQueue::wait`] takes it. The slot is
/// held until then.
#[derive(Clone, Copy, Debug)]
pub struct Ticket {
    hart: u8,
    idx: u8,
    gen: u32,
}

// ── The queues ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Free,
    /// Waiting to be picked.
    Queued,
    /// In a command the device holds (or is being handed to it).
    Picked,
    /// Over; the submitter has not collected it yet.
    Done,
}

/// The submitter's buffer, as a raw pointer. The submitter is blocked in
/// [`ReqQueue::wait`] until the request is `Done`, which is what makes every
/// access to it by another task sound.
#[derive(Clone, Copy)]
struct BufPtr(*mut u8);
// SAFETY: see the type's doc; the pointer is only dereferenced while its
// owner waits for the request that carries it.
unsafe impl Send for BufPtr {}

#[derive(Clone, Copy)]
struct Entry {
    st: St,
    gen: u32,
    /// Arrival order (wrapping).
    seq: u32,
    /// Absolute monotonic nanoseconds the request must be started by.
    due_ns: u64,
    /// The plug that holds it back, 0 for none.
    plug: u32,
    /// The flush `PREFLUSH` asks for has happened.
    preflushed: bool,
    /// The real-time class (`rt-deadline`): see the module doc.
    rt: bool,
    out: Outcome,
    req: BlockRequest,
    buf: BufPtr,
}

const EMPTY_ENTRY: Entry = Entry {
    st: St::Free,
    gen: 0,
    seq: 0,
    due_ns: u64::MAX,
    plug: 0,
    preflushed: false,
    rt: false,
    out: Outcome::Ok,
    req: BlockRequest {
        op: 0,
        flags: 0,
        sector: 0,
        count: 0,
        deadline_ns: 0,
        owner: 0,
        mem: 0,
        mem_off: 0,
    },
    buf: BufPtr(core::ptr::null_mut()),
};

impl Entry {
    fn needs_preflush(&self) -> bool {
        self.req.flags & FLAG_PREFLUSH != 0 && !self.preflushed
    }
}

/// `a` arrived before `b` (wrapping order).
fn older(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// A queued request's place in the pick order ([`ReqQueue::rank`]).
#[derive(Clone, Copy)]
struct Rank {
    /// 0 for the real-time class under `rt-deadline`, else 1 (0 for all
    /// others: the class does not order them).
    class: u8,
    /// Absolute deadline, `u64::MAX` for none (and under `none`).
    due: u64,
    seq: u32,
}

/// `a` is started before `b`: lower class, then earlier deadline, then
/// older.
fn goes_before(a: &Rank, b: &Rank) -> bool {
    if a.class != b.class {
        return a.class < b.class;
    }
    if a.due != b.due {
        return a.due < b.due;
    }
    older(a.seq, b.seq)
}

#[derive(Clone, Copy)]
struct Member {
    hart: u8,
    idx: u8,
    gen: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    Write,
    Discard,
    /// A flush request of a submitter.
    Flush,
    /// The flush that `PREFLUSH` requests submitted before `before` wait for.
    PreFlush { before: u32 },
}

/// A command in the device: the requests it carries.
#[derive(Clone, Copy)]
struct Group {
    kind: Kind,
    n: u8,
    m: [Member; MERGE_MAX],
    lba: u64,
    sectors: u32,
    fua: bool,
    /// Timebase tick at which it was handed to the device.
    started: u64,
}

const NO_MEMBER: Member = Member { hart: 0, idx: 0, gen: 0 };

enum Pick {
    Nothing,
    Group(Group),
}

/// The request layer for one device. Usable as a `static`.
pub struct ReqQueue {
    sched: Sched,
    harts: [SpinLock<[Entry; DEPTH]>; HARTS],
    /// Slots in use on each hart: a scan skips the harts that hold none (an
    /// 8-hart or 64-hart machine mostly has idle queues).
    used: [AtomicU32; HARTS],
    /// Next arrival number.
    seq: AtomicU32,
    /// Next ticket generation, and next plug token (never 0).
    gen: AtomicU32,
    /// The commands the device holds, by tag.
    inflight: SpinLock<[Option<Group>; HW_TAGS_MAX]>,
    /// One task dispatches at a time.
    dispatch: Mutex<()>,
    /// Someone queued work since the dispatcher last looked.
    pending: AtomicBool,
    /// A flush for `PREFLUSH` requests is in the device: one serves all.
    preflush_busy: AtomicBool,
    /// The device answered [`Claim::Dead`]: reported once.
    offline: AtomicBool,
    /// The task that sleeps in the device for everyone.
    reaper: AtomicBool,
    /// Bumped before every wake of `done` / `space`: a sleeper registers,
    /// then asks "did anything happen since I last looked?" of the epoch, so
    /// a wake can never fall between its check and its sleep; and a wake
    /// that does not arrive costs a slice, not the task ([`Sleepers`]).
    done_epoch: AtomicU32,
    space_epoch: AtomicU32,
    /// Waiters for `done_epoch` to move, and submitters for `space_epoch`.
    done: Sleepers,
    space: Sleepers,
}

impl ReqQueue {
    /// A queue under the scheduler Kconfig `BLK_IOSCHED` chose.
    pub const fn new() -> Self {
        Self::with_sched(Sched::CONFIGURED)
    }

    /// A queue under `sched`: for a test that drives each of them.
    pub const fn with_sched(sched: Sched) -> Self {
        ReqQueue {
            sched,
            harts: [const { SpinLock::new([EMPTY_ENTRY; DEPTH]) }; HARTS],
            used: [const { AtomicU32::new(0) }; HARTS],
            seq: AtomicU32::new(0),
            gen: AtomicU32::new(1),
            inflight: SpinLock::new([None; HW_TAGS_MAX]),
            dispatch: Mutex::new(()),
            pending: AtomicBool::new(false),
            preflush_busy: AtomicBool::new(false),
            offline: AtomicBool::new(false),
            reaper: AtomicBool::new(false),
            done_epoch: AtomicU32::new(0),
            space_epoch: AtomicU32::new(0),
            done: Sleepers::new(Site::BlockDone),
            space: Sleepers::new(Site::BlockSpace),
        }
    }

    // ── Submit ──────────────────────────────────────────────────────────

    /// Is the request being submitted of the real-time class? Only under
    /// `rt-deadline`, and as the kernel's source answers for the caller.
    fn is_rt(&self) -> bool {
        self.sched == Sched::RtDeadline && RT_CLASS_SRC.get().is_some_and(|serves_record| serves_record())
    }

    /// Queue `req` and start it as soon as the device can take it. `buf` is
    /// the kernel buffer of a read (written) or a write (read), `count * 512`
    /// bytes; null for a flush or a discard. Sleeps for a free slot, so a caller
    /// that holds tickets of its own uses [`try_submit`](Self::try_submit).
    ///
    /// # Safety
    ///
    /// `buf` must stay valid, and for a read untouched, until [`wait`](Self::wait)
    /// returns for the ticket.
    pub unsafe fn submit(&self, hw: &dyn HwQueue, req: &BlockRequest, buf: *mut u8) -> Result<Ticket, Failure> {
        let t = self.enqueue(hw, hw.cpu() % HARTS, req, buf, 0, true)?;
        self.pump(hw);
        Ok(t)
    }

    /// [`submit`](Self::submit) that answers [`Failure::Full`] instead of
    /// sleeping when the hart's queue has no free slot.
    ///
    /// # Safety
    ///
    /// As [`submit`](Self::submit).
    pub unsafe fn try_submit(&self, hw: &dyn HwQueue, req: &BlockRequest, buf: *mut u8) -> Result<Ticket, Failure> {
        let t = self.enqueue(hw, hw.cpu() % HARTS, req, buf, 0, false)?;
        self.pump(hw);
        Ok(t)
    }

    /// [`try_submit`](Self::try_submit) without the pump: queue `req` and
    /// return, touching no device register. Whoever next runs
    /// [`pump`](Self::pump) or [`wait`](Self::wait) starts it. For a submitter
    /// that must not do device work (an io_ring submit: owner rule, only
    /// enqueue) and hands the ticket to a task that does.
    ///
    /// # Safety
    ///
    /// As [`submit`](Self::submit).
    pub unsafe fn enqueue_only(&self, hw: &dyn HwQueue, req: &BlockRequest, buf: *mut u8) -> Result<Ticket, Failure> {
        self.enqueue(hw, hw.cpu() % HARTS, req, buf, 0, false)
    }

    /// Hold back this task's submissions until the plug drops. Submit through
    /// [`Plug::submit`].
    pub fn plug<'q>(&'q self, hw: &'q dyn HwQueue) -> Plug<'q> {
        let mut token = self.gen.fetch_add(1, Ordering::Relaxed);
        if token == 0 {
            token = self.gen.fetch_add(1, Ordering::Relaxed);
        }
        Plug { q: self, hw, hart: hw.cpu() % HARTS, token }
    }

    /// Put `req` in a slot of `hart`'s queue. With no free slot: sleep for one
    /// (`block`, the caller holds no ticket) or answer [`Failure::Full`].
    fn enqueue(&self, hw: &dyn HwQueue, hart: usize, req: &BlockRequest, buf: *mut u8, plug: u32, block: bool) -> Result<Ticket, Failure> {
        req.check().map_err(Failure::Refused)?;
        let caps = hw.caps();
        if req.mem != 0 {
            return Err(Failure::Refused(outcome::UNSUPPORTED));
        }
        if req.op == REQ_DISCARD && caps.max_discard_sectors == 0 {
            return Err(Failure::Refused(outcome::UNSUPPORTED));
        }
        // FUA is a bit of the write command: a device that has none (virtio-blk)
        // is not asked, and says so here instead of making the write durable
        // some other way behind the caller's back.
        if req.flags & FLAG_FUA != 0 && !caps.fua {
            return Err(Failure::Refused(outcome::UNSUPPORTED));
        }
        if req.op == REQ_DISCARD && req.count > caps.max_discard_sectors {
            return Err(Failure::Refused(outcome::BAD_ARGUMENT));
        }
        if req.has_data() && (buf.is_null() || req.count > caps.max_sectors) {
            return Err(Failure::Refused(outcome::BAD_ARGUMENT));
        }
        if req.count != 0 && req.sector.checked_add(req.count as u64).map_or(true, |end| end > caps.sectors) {
            return Err(Failure::Refused(outcome::BAD_ARGUMENT));
        }
        let due_ns = if req.deadline_ns == 0 { u64::MAX } else { now_ns().saturating_add(req.deadline_ns) };
        loop {
            let seen = self.space_epoch.load(Ordering::SeqCst);
            // Asked again after every sleep: a durable record may have come
            // to wait meanwhile.
            let rt = self.is_rt();
            // Free slots an ordinary request leaves for the real-time class.
            let keep = if self.sched == Sched::RtDeadline && !rt { RT_RESERVE } else { 0 };
            {
                let mut q = self.harts[hart].lock();
                let (mut free, mut first) = (0usize, None);
                for (i, e) in q.iter().enumerate() {
                    if e.st == St::Free {
                        free += 1;
                        first.get_or_insert(i);
                    }
                }
                if let Some(idx) = first.filter(|_| free > keep) {
                    let gen = self.gen.fetch_add(1, Ordering::Relaxed);
                    q[idx] = Entry {
                        st: St::Queued,
                        gen,
                        seq: self.seq.fetch_add(1, Ordering::Relaxed),
                        due_ns,
                        plug,
                        preflushed: false,
                        rt,
                        out: Outcome::Ok,
                        req: *req,
                        buf: BufPtr(buf),
                    };
                    self.used[hart].fetch_add(1, Ordering::Release);
                    return Ok(Ticket { hart: hart as u8, idx: idx as u8, gen });
                }
            }
            // Full: the slots are held by submitters who have not collected.
            if !block {
                return Err(Failure::Full);
            }
            self.pump(hw);
            self.space.sleep(SPACE_SLICE_NS, || self.space_epoch.load(Ordering::SeqCst) != seen);
        }
    }

    /// Release the requests plug `token` holds back on `hart`.
    fn unplug(&self, hart: usize, token: u32) {
        let mut q = self.harts[hart].lock();
        for e in q.iter_mut().filter(|e| e.plug == token) {
            e.plug = 0;
        }
    }

    // ── Wait ────────────────────────────────────────────────────────────

    /// Collect the outcome of `t`, running the device meanwhile. Frees the
    /// request's slot.
    pub fn wait(&self, hw: &dyn HwQueue, t: Ticket) -> Outcome {
        azos_sync::lockdep::might_wait_device("block request wait");
        loop {
            let seen = self.done_epoch.load(Ordering::SeqCst);
            if let Some(o) = self.collect(t) {
                return o;
            }
            self.pump(hw);
            if let Some(o) = self.collect(t) {
                return o;
            }
            self.sleep(hw, seen);
        }
    }

    fn collect(&self, t: Ticket) -> Option<Outcome> {
        let mut q = self.harts[t.hart as usize].lock();
        let e = &mut q[t.idx as usize];
        if e.gen != t.gen || e.st == St::Free {
            // A ticket that is not live: nothing can complete it.
            return Some(Outcome::Io);
        }
        if e.st != St::Done {
            return None;
        }
        let out = e.out;
        *e = EMPTY_ENTRY;
        self.used[t.hart as usize].fetch_sub(1, Ordering::Release);
        drop(q);
        self.space_epoch.fetch_add(1, Ordering::SeqCst);
        self.space.wake_all();
        Some(out)
    }

    /// Something a waiter may be waiting for happened.
    fn signal_done(&self) {
        self.done_epoch.fetch_add(1, Ordering::SeqCst);
        self.done.wake_all();
    }

    /// Wait for something to change: as the reaper, in the device; else asleep
    /// on the list the reaper wakes, for at most a slice.
    ///
    /// `seen` is the `done_epoch` the caller read before it last looked at
    /// its request.
    fn sleep(&self, hw: &dyn HwQueue, seen: u32) {
        if self.reaper.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            let slept = hw.wait(now_ns().saturating_add(SLICE_NS));
            self.reaper.store(false, Ordering::Release);
            if !slept {
                core::hint::spin_loop();
            }
            self.signal_done();
        } else {
            self.done.sleep(SLICE_NS, || self.done_epoch.load(Ordering::SeqCst) != seen || !self.reaper.load(Ordering::Acquire));
        }
    }

    // ── Run the device ──────────────────────────────────────────────────

    /// Reap what the device finished, then start whatever is queued and the
    /// device can take.
    pub fn pump(&self, hw: &dyn HwQueue) {
        self.pending.store(true, Ordering::SeqCst);
        loop {
            self.reap(hw);
            let Some(guard) = self.dispatch.try_lock() else {
                // The dispatcher re-checks `pending` after it lets go.
                return;
            };
            self.pending.store(false, Ordering::SeqCst);
            self.dispatch_all(hw);
            drop(guard);
            if !self.pending.load(Ordering::SeqCst) {
                return;
            }
        }
    }

    fn reap(&self, hw: &dyn HwQueue) {
        let mut out = [HwDone { tag: 0, status: HwStatus::Ok }; HW_TAGS_MAX];
        let n = hw.reap(&mut out);
        for d in &out[..n.min(HW_TAGS_MAX)] {
            let Some(g) = self.inflight.lock().get_mut(d.tag as usize).and_then(|s| s.take()) else {
                continue;
            };
            self.complete(hw, d.tag, g, d.status);
        }
        if n > 0 {
            self.signal_done();
        }
    }

    fn complete(&self, hw: &dyn HwQueue, tag: u8, g: Group, status: HwStatus) {
        let out = match status {
            HwStatus::Ok => Outcome::Ok,
            HwStatus::Unsupported => Outcome::Unsupported,
            HwStatus::Io | HwStatus::Timeout => Outcome::Io,
        };
        match g.kind {
            Kind::Read if status == HwStatus::Ok => {
                let mut off = 0usize;
                for m in &g.m[..g.n as usize] {
                    let Some((count, buf)) = self.member(m) else { continue };
                    let len = count as usize * SECTOR;
                    // SAFETY: the member's submitter waits for this request
                    // (`BufPtr`), and `submit` checked the buffer is `count *
                    // 512` bytes.
                    let dst = unsafe { core::slice::from_raw_parts_mut(buf.0, len) };
                    hw.copy_out(tag, off, dst);
                    off += len;
                }
                hw.release(tag);
                self.finish(&g, Outcome::Ok);
            }
            Kind::PreFlush { before } => {
                hw.release(tag);
                self.preflush_busy.store(false, Ordering::SeqCst);
                // A device that has nothing to flush (`Unsupported`) has
                // nothing to order either.
                self.cover(before, if matches!(status, HwStatus::Io | HwStatus::Timeout) { Outcome::Io } else { Outcome::Ok });
            }
            _ => {
                hw.release(tag);
                self.finish(&g, out);
            }
        }
        if status == HwStatus::Timeout {
            let waited = azos_drv_sys::timebase::now().saturating_sub(g.started);
            let ms = waited.saturating_mul(1000) / azos_drv_sys::timebase::TIMER_FREQ.max(1);
            report(TimeoutAction::Failed, g.lba, ms);
        }
    }

    /// Sector count and buffer of a live member.
    fn member(&self, m: &Member) -> Option<(u32, BufPtr)> {
        let q = self.harts[m.hart as usize].lock();
        let e = &q[m.idx as usize];
        (e.gen == m.gen && e.st == St::Picked).then_some((e.req.count, e.buf))
    }

    /// Every member of `g` is over with `out`.
    fn finish(&self, g: &Group, out: Outcome) {
        for m in &g.m[..g.n as usize] {
            let mut q = self.harts[m.hart as usize].lock();
            let e = &mut q[m.idx as usize];
            if e.gen == m.gen && e.st == St::Picked {
                e.st = St::Done;
                e.out = out;
                if g.kind == Kind::Write && out == Outcome::Ok {
                    // The write ledger (`write_observer::account`): a leaf
                    // sink that does atomics only, so the hart lock may be held.
                    crate::write_observer::account(e.req.owner, e.req.count as u64 * SECTOR as u64);
                }
            }
        }
        self.signal_done();
    }

    /// The flush that started when sequence `before` was next is over: the
    /// `PREFLUSH` requests queued before it may go (`Ok`), or fail with it.
    fn cover(&self, before: u32, out: Outcome) {
        for h in 0..HARTS {
            if self.used[h].load(Ordering::Acquire) == 0 {
                continue;
            }
            let mut q = self.harts[h].lock();
            for e in q.iter_mut() {
                if e.st == St::Queued && e.needs_preflush() && older(e.seq, before) {
                    if out == Outcome::Ok {
                        e.preflushed = true;
                    } else {
                        e.st = St::Done;
                        e.out = out;
                    }
                }
            }
        }
        self.signal_done();
    }

    fn dispatch_all(&self, hw: &dyn HwQueue) {
        let caps = hw.caps();
        loop {
            let Pick::Group(mut g) = self.pick(&caps) else { return };
            let tag = match hw.claim() {
                Claim::Tag(t) if (t as usize) < HW_TAGS_MAX => t,
                Claim::Tag(_) => {
                    // A device offering more tags than the layer tracks
                    // breaks the `HwQueue` contract; nothing can be started
                    // on it.
                    self.fail(&g, Outcome::Io);
                    continue;
                }
                Claim::Busy => {
                    self.give_back(&g);
                    return;
                }
                Claim::Dead => {
                    self.fail(&g, Outcome::Io);
                    if !self.offline.swap(true, Ordering::SeqCst) {
                        report(TimeoutAction::Offline, g.lba, 0);
                    }
                    continue;
                }
            };
            g.started = azos_drv_sys::timebase::now();
            self.inflight.lock()[tag as usize] = Some(g);
            if !self.start(hw, tag, &g) {
                self.inflight.lock()[tag as usize] = None;
                hw.release(tag);
                self.fail(&g, Outcome::Io);
            }
        }
    }

    /// The group could not be started: back to the queue, or over.
    fn give_back(&self, g: &Group) {
        if let Kind::PreFlush { .. } = g.kind {
            self.preflush_busy.store(false, Ordering::SeqCst);
            return;
        }
        for m in &g.m[..g.n as usize] {
            let mut q = self.harts[m.hart as usize].lock();
            let e = &mut q[m.idx as usize];
            if e.gen == m.gen && e.st == St::Picked {
                e.st = St::Queued;
            }
        }
    }

    fn fail(&self, g: &Group, out: Outcome) {
        if let Kind::PreFlush { before } = g.kind {
            self.preflush_busy.store(false, Ordering::SeqCst);
            self.cover(before, out);
        } else {
            self.finish(g, out);
        }
    }

    fn start(&self, hw: &dyn HwQueue, tag: u8, g: &Group) -> bool {
        let op = match g.kind {
            Kind::Read => HwOp::Read,
            Kind::Write => HwOp::Write,
            Kind::Discard => HwOp::Discard,
            Kind::Flush | Kind::PreFlush { .. } => HwOp::Flush,
        };
        let empty: &[u8] = &[];
        let mut segs = [empty; MERGE_MAX];
        let mut n = 0;
        if g.kind == Kind::Write {
            for m in &g.m[..g.n as usize] {
                let Some((count, buf)) = self.member(m) else { return false };
                // SAFETY: the submitter waits for this request (`BufPtr`); the
                // buffer holds `count * 512` bytes (checked at submit) and a
                // write's is not modified while the request is queued.
                segs[n] = unsafe { core::slice::from_raw_parts(buf.0 as *const u8, count as usize * SECTOR) };
                n += 1;
            }
        }
        let cmd = HwCmd { op, lba: g.lba, sectors: g.sectors, fua: g.fua, segs: &segs[..n] };
        hw.start(tag, &cmd).is_ok()
    }

    /// Where a queued request stands in the scheduler's order: smaller goes
    /// first ([`goes_before`]).
    fn rank(&self, e: &Entry) -> Rank {
        match self.sched {
            Sched::None => Rank { class: 0, due: u64::MAX, seq: e.seq },
            Sched::MqDeadline => Rank { class: 0, due: e.due_ns, seq: e.seq },
            Sched::RtDeadline => Rank { class: if e.rt { 0 } else { 1 }, due: e.due_ns, seq: e.seq },
        }
    }

    /// Choose the next command: the queued request the scheduler ranks
    /// first ([`Sched`]), with its neighbours merged into it. Marks what it
    /// takes `Picked`. Requests past their deadline end here.
    fn pick(&self, caps: &HwCaps) -> Pick {
        let now = now_ns();
        let flush_busy = self.preflush_busy.load(Ordering::SeqCst);
        // The head: (rank, hart, idx).
        let mut head: Option<(Rank, usize, usize)> = None;
        let mut expired = false;
        for h in 0..HARTS {
            if self.used[h].load(Ordering::Acquire) == 0 {
                continue;
            }
            let mut q = self.harts[h].lock();
            for (i, e) in q.iter_mut().enumerate() {
                if e.st != St::Queued || e.plug != 0 {
                    continue;
                }
                if e.due_ns != u64::MAX && now >= e.due_ns {
                    e.st = St::Done;
                    e.out = Outcome::Deadline;
                    expired = true;
                    continue;
                }
                if e.needs_preflush() && flush_busy {
                    continue;
                }
                let rank = self.rank(e);
                if head.map_or(true, |(best, _, _)| goes_before(&rank, &best)) {
                    head = Some((rank, h, i));
                }
            }
        }
        if expired {
            self.signal_done();
        }
        let Some((_, h0, i0)) = head else { return Pick::Nothing };

        let mut g = Group { kind: Kind::Read, n: 0, m: [NO_MEMBER; MERGE_MAX], lba: 0, sectors: 0, fua: false, started: 0 };
        let (hreq, hgen, hneeds, hrt) = {
            let q = self.harts[h0].lock();
            let e = &q[i0];
            (e.req, e.gen, e.needs_preflush(), e.rt)
        };
        if hneeds {
            // The flush comes first, for every PREFLUSH request queued so far.
            self.preflush_busy.store(true, Ordering::SeqCst);
            g.kind = Kind::PreFlush { before: self.seq.load(Ordering::Relaxed) };
            return Pick::Group(g);
        }
        let take = |this: &Self, h: usize, i: usize, gen: u32| {
            let mut q = this.harts[h].lock();
            q[i].st = St::Picked;
            Member { hart: h as u8, idx: i as u8, gen }
        };
        g.m[0] = take(self, h0, i0, hgen);
        g.n = 1;
        g.lba = hreq.sector;
        g.sectors = hreq.count;
        g.fua = hreq.flags & FLAG_FUA != 0;
        g.kind = match hreq.op {
            REQ_READ => Kind::Read,
            REQ_WRITE => Kind::Write,
            REQ_DISCARD => Kind::Discard,
            _ => Kind::Flush,
        };
        if !matches!(g.kind, Kind::Read | Kind::Write) {
            return Pick::Group(g);
        }
        // Merge: neighbours of the same owner and operation, adjacent at
        // either end, while the command stays within the device's largest.
        while (g.n as usize) < MERGE_MAX {
            let mut found: Option<(usize, usize, u32, BlockRequest)> = None;
            'scan: for h in 0..HARTS {
                if self.used[h].load(Ordering::Acquire) == 0 {
                    continue;
                }
                let q = self.harts[h].lock();
                for (i, e) in q.iter().enumerate() {
                    if e.st != St::Queued || e.plug != 0 || e.needs_preflush() {
                        continue;
                    }
                    if e.due_ns != u64::MAX && now >= e.due_ns {
                        continue;
                    }
                    let r = &e.req;
                    if e.rt != hrt
                        || r.op != hreq.op
                        || r.owner != hreq.owner
                        || (r.flags & FLAG_FUA) != (hreq.flags & FLAG_FUA)
                        || g.sectors.checked_add(r.count).map_or(true, |t| t > caps.max_sectors)
                    {
                        continue;
                    }
                    if r.sector == g.lba + g.sectors as u64 || r.sector + r.count as u64 == g.lba {
                        found = Some((h, i, e.gen, *r));
                        break 'scan;
                    }
                }
            }
            let Some((h, i, gen, r)) = found else { break };
            let m = take(self, h, i, gen);
            if r.sector < g.lba {
                // In front: shift the members up.
                let n = g.n as usize;
                g.m.copy_within(0..n, 1);
                g.m[0] = m;
                g.lba = r.sector;
            } else {
                g.m[g.n as usize] = m;
            }
            g.n += 1;
            g.sectors += r.count;
        }
        Pick::Group(g)
    }

    // ── Transfers ───────────────────────────────────────────────────────

    /// Read or write `count` sectors from `sector` for `owner`, `flags`
    /// ([`FLAG_FUA`], [`FLAG_PREFLUSH`]) on every request, and wait. Cut into
    /// requests of the device's largest command, up to `BLK_QUEUE_DEPTH` of
    /// them in flight; the first ones are plugged, so they are queued before
    /// the first is started.
    ///
    /// `buf` holds `buf_len >= count * 512` bytes; a write only reads it.
    pub fn transfer(
        &self,
        hw: &dyn HwQueue,
        owner: u32,
        write: bool,
        sector: u64,
        count: u32,
        flags: u32,
        buf: *mut u8,
        buf_len: usize,
    ) -> Result<(), Failure> {
        let total = (count as usize).checked_mul(SECTOR).ok_or(Failure::Refused(outcome::BAD_ARGUMENT))?;
        if buf_len < total {
            return Err(Failure::Refused(outcome::BAD_ARGUMENT));
        }
        let max = hw.caps().max_sectors.max(1);
        let chunks = (count as usize).div_ceil(max as usize);
        let mut ring: [Option<Ticket>; DEPTH] = [None; DEPTH];
        let mut result: Result<(), Failure> = Ok(());
        // Requests submitted, and collected.
        let (mut next, mut waited) = (0usize, 0usize);
        let request = |k: usize| -> BlockRequest {
            let first = k as u32 * max;
            let mut req = BlockRequest::rw(write, sector + first as u64, (count - first).min(max), owner);
            req.flags = flags;
            req
        };
        // The request `k` covers `[k * max, k * max + n)` sectors of `buf`,
        // which holds `count` (checked above). Every submit below lends that
        // range, and every ticket is waited for before this function returns.
        //
        // SAFETY: `k < chunks = ceil(count / max)`, so `k * max < count`, and
        // `buf_len >= count * SECTOR` was checked above: the offset stays
        // inside the caller's buffer.
        let ptr = |k: usize| unsafe { buf.add(k * max as usize * SECTOR) };
        // The first requests are plugged, so they are all queued before the
        // first is started.
        {
            let plug = self.plug(hw);
            while next < chunks && next - waited < DEPTH {
                // SAFETY: `ptr(next)` lies in `buf`, which the caller keeps
                // valid for the whole call, and every ticket made here is
                // waited for before the call returns (the loops below, also
                // after a failure), so the buffer outlives each `wait`.
                match unsafe { plug.submit(&request(next), ptr(next)) } {
                    Ok(t) => ring[next % DEPTH] = Some(t),
                    Err(Failure::Full) => break,
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
                next += 1;
            }
        }
        // Collect the oldest, submit another in its place. A full queue (the
        // slots are shared with other tasks on this hart) is answered by
        // collecting, never by sleeping with tickets in hand; with none in
        // hand, sleeping for a slot is safe.
        while result.is_ok() && waited < chunks {
            while result.is_ok() && next < chunks && next - waited < DEPTH {
                let r = if next == waited {
                    // SAFETY: as the plugged submit above: `ptr(next)` is in
                    // `buf`, and this ticket is waited for before returning.
                    unsafe { self.submit(hw, &request(next), ptr(next)) }
                } else {
                    // SAFETY: as the plugged submit above.
                    unsafe { self.try_submit(hw, &request(next), ptr(next)) }
                };
                match r {
                    Ok(t) => {
                        ring[next % DEPTH] = Some(t);
                        next += 1;
                    }
                    Err(Failure::Full) => break,
                    Err(e) => result = Err(e),
                }
            }
            if waited < next {
                if let Some(t) = ring[waited % DEPTH].take() {
                    let o = self.wait(hw, t);
                    if o != Outcome::Ok && result.is_ok() {
                        result = Err(Failure::Ended(o));
                    }
                }
                waited += 1;
            }
        }
        // After a failure, every request already submitted is still waited
        // for: the device may be writing to their buffers.
        while waited < next {
            if let Some(t) = ring[waited % DEPTH].take() {
                self.wait(hw, t);
            }
            waited += 1;
        }
        result
    }

    /// Make every write that completed so far durable.
    pub fn flush(&self, hw: &dyn HwQueue, owner: u32) -> Result<(), Failure> {
        // SAFETY: a flush has no buffer.
        let t = unsafe { self.submit(hw, &BlockRequest::flush(owner), core::ptr::null_mut())? };
        match self.wait(hw, t) {
            Outcome::Ok => Ok(()),
            o => Err(Failure::Ended(o)),
        }
    }

    /// Deallocate the sectors of `ranges` (`(first sector, sectors)`; a hint),
    /// in requests of at most the device's largest discard. `together`: up
    /// to `BLK_QUEUE_DEPTH` requests are in the device at once and the call
    /// waits for the last; otherwise one at a time. Every request is waited
    /// for before this returns, and the first failure is the answer.
    pub fn discard(&self, hw: &dyn HwQueue, owner: u32, ranges: &[(u64, u32)], together: bool) -> Result<(), Failure> {
        let max = hw.caps().max_discard_sectors;
        if max == 0 {
            return Err(Failure::Refused(outcome::UNSUPPORTED));
        }
        let depth = if together { DEPTH } else { 1 };
        let mut ring: [Option<Ticket>; DEPTH] = [None; DEPTH];
        let mut result: Result<(), Failure> = Ok(());
        // The next piece: `ranges[ri]` from sector `roff` of it.
        let (mut ri, mut roff) = (0usize, 0u32);
        // Requests submitted, and collected.
        let (mut next, mut waited) = (0usize, 0usize);
        loop {
            while result.is_ok() && next - waited < depth {
                while ri < ranges.len() && roff >= ranges[ri].1 {
                    ri += 1;
                    roff = 0;
                }
                let Some(&(first, count)) = ranges.get(ri) else { break };
                let n = (count - roff).min(max);
                let req = BlockRequest { op: REQ_DISCARD, ..BlockRequest::rw(false, first + roff as u64, n, owner) };
                // A full queue is answered by collecting, never by sleeping
                // with tickets in hand (see `transfer`).
                // SAFETY: a discard has no buffer.
                let r = unsafe {
                    if next == waited {
                        self.submit(hw, &req, core::ptr::null_mut())
                    } else {
                        self.try_submit(hw, &req, core::ptr::null_mut())
                    }
                };
                match r {
                    Ok(t) => {
                        ring[next % DEPTH] = Some(t);
                        next += 1;
                        roff += n;
                    }
                    Err(Failure::Full) => break,
                    Err(e) => result = Err(e),
                }
            }
            if waited == next {
                return result;
            }
            if let Some(t) = ring[waited % DEPTH].take() {
                let o = self.wait(hw, t);
                if o != Outcome::Ok && result.is_ok() {
                    result = Err(Failure::Ended(o));
                }
            }
            waited += 1;
        }
    }
}

impl Default for ReqQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A task's held-back submissions on one hart. Dropping it releases them and
/// runs the device.
pub struct Plug<'q> {
    q: &'q ReqQueue,
    hw: &'q dyn HwQueue,
    hart: usize,
    token: u32,
}

impl Plug<'_> {
    /// [`ReqQueue::try_submit`], held back until the plug drops. A full queue
    /// answers [`Failure::Full`]; the held-back requests are released by
    /// dropping the plug, so a caller that is `Full` drops it, then waits.
    ///
    /// # Safety
    ///
    /// As [`ReqQueue::submit`]: the buffer outlives the ticket's `wait`.
    pub unsafe fn submit(&self, req: &BlockRequest, buf: *mut u8) -> Result<Ticket, Failure> {
        self.q.enqueue(self.hw, self.hart, req, buf, self.token, false)
    }
}

impl Drop for Plug<'_> {
    fn drop(&mut self) {
        self.q.unplug(self.hart, self.token);
        self.q.pump(self.hw);
    }
}

// ── The device the kernel drives through the queue ──────────────────────

static GLOBAL: ReqQueue = ReqQueue::new();
static BOUND: SpinLock<Option<&'static dyn HwQueue>> = SpinLock::new(None);

/// Drive `hw` through the request layer from now on: `blkdev`'s reads,
/// writes and flushes become requests on it. Once, at the device's bring-up.
pub fn bind(hw: &'static dyn HwQueue) {
    *BOUND.lock() = Some(hw);
}

/// The device bound by [`bind`], if any.
pub fn bound() -> Option<&'static dyn HwQueue> {
    *BOUND.lock()
}

/// [`ReqQueue::transfer`] on the bound device's queue: a read.
pub fn read(hw: &dyn HwQueue, owner: u32, sector: u64, count: u32, buf: &mut [u8]) -> Result<(), Failure> {
    GLOBAL.transfer(hw, owner, false, sector, count, 0, buf.as_mut_ptr(), buf.len())
}

/// [`ReqQueue::transfer`] on the bound device's queue: a write, with `flags`.
/// `buf` is only read.
pub fn write(hw: &dyn HwQueue, owner: u32, sector: u64, count: u32, flags: u32, buf: &[u8]) -> Result<(), Failure> {
    // The queue only reads a write's buffer: the pointer is lent as the
    // `*mut u8` a request carries and never stored through.
    GLOBAL.transfer(hw, owner, true, sector, count, flags, buf.as_ptr() as *mut u8, buf.len())
}

/// [`ReqQueue::enqueue_only`] on the bound device's queue: a read or a write
/// of `count` sectors at `sector` for `owner`, queued and not started. `buf`
/// is `count * 512` bytes that stay valid, and for a read untouched, until
/// [`wait`] returns for the ticket.
///
/// # Safety
///
/// As [`ReqQueue::submit`].
pub unsafe fn enqueue(hw: &dyn HwQueue, owner: u32, write: bool, sector: u64, count: u32, buf: *mut u8) -> Result<Ticket, Failure> {
    GLOBAL.enqueue_only(hw, &BlockRequest::rw(write, sector, count, owner), buf)
}

/// [`ReqQueue::wait`] on the bound device's queue.
pub fn wait(hw: &dyn HwQueue, t: Ticket) -> Outcome {
    GLOBAL.wait(hw, t)
}

/// [`ReqQueue::flush`] on the bound device's queue.
pub fn flush(hw: &dyn HwQueue, owner: u32) -> Result<(), Failure> {
    GLOBAL.flush(hw, owner)
}

/// [`ReqQueue::discard`] on the bound device's queue.
pub fn discard(hw: &dyn HwQueue, owner: u32, ranges: &[(u64, u32)], together: bool) -> Result<(), Failure> {
    GLOBAL.discard(hw, owner, ranges, together)
}

/// Tell the kernel's sink, if it registered one ([`set_timeout_sink`]).
fn report(action: TimeoutAction, sector: u64, waited_ms: u64) {
    if let Some(sink) = TIMEOUT_SINK.get() {
        sink(action, sector, waited_ms);
    }
}

/// Monotonic nanoseconds.
fn now_ns() -> u64 {
    let t = azos_drv_sys::timebase::now();
    let f = azos_drv_sys::timebase::TIMER_FREQ;
    (t / f).saturating_mul(1_000_000_000).saturating_add((t % f) * 1_000_000_000 / f)
}
