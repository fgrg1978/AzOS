// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wake attribution: every Blocked -> Ready transition is logged with the
//! source that caused it, in a ring the introspection tree publishes
//! (`metrics/wake/`, Kconfig `WAKE_RING_ENTRIES`; 0 compiles all of it out).
//!
//! Pure: no scheduler state, so `tests/host/sched-wake-tests` compiles this
//! file as is. `wake.rs` reads the facts (the woken task's wait reason, the
//! waker's context) and calls in.
//!
//! # What a wake is attributed to
//!
//! [`Src`], decided where the wake is made, never guessed afterwards:
//!
//! | source      | the wake                                              | `detail`      |
//! |-------------|-------------------------------------------------------|---------------|
//! | `timer`     | a sleeper's deadline passed (the tick's sweep)        | 0             |
//! | `irq`       | an event of a bound interrupt line reached its port   | the line      |
//! | `isr`       | an interrupt handler of the kernel itself woke a task | 0             |
//! | `ipc_call`  | a call woke the server blocked in accept              | caller TID    |
//! | `ipc_reply` | a reply woke the client blocked on it                 | server TID    |
//! | `futex`     | a futex wake                                          | waker TID     |
//! | `notify`    | a notify-word wake                                    | waker TID     |
//! | `ring`      | a ring doorbell                                       | waker TID     |
//! | `port`      | an event posted to a port a task waited on            | waker TID     |
//! | `waitq`     | a wait queue woke a task                              | waker TID     |
//! | `wake`      | any other targeted wake of a timed sleeper (a signal, a stop request, a kernel task poking another) | waker TID |
//! | `reap`      | the K-C25 reaper delivered a wake stamped earlier     | 0             |
//!
//! # What is logged
//!
//! Every wake is counted in the Domain of the task it woke (`domain::count_wake`,
//! exact). The ring is the sample: the machine's own wakes (`timer`, `irq`,
//! `isr`, `reap`) are all in it; the wakes tasks make (`ipc_call`, `ipc_reply`,
//! `futex`, `notify`, `ring`, `port`, `waitq`, `wake`) are logged one in
//! `2^WAKE_RING_SAMPLE_LOG2` per woken Domain (the first of a Domain among them),
//! by the Domain's own count ([`logged`] is the rule, per path). They are the commonest wakes by far (an IPC round
//! trip makes two), they cost the same each time, and logging each would put a
//! ticket, a clock read and four stores on the IPC hand-off for entries that
//! would fill the ring in a few hundred microseconds and push out the rare wakes
//! `why woke` is for. `WAKE_RING_SAMPLE_LOG2` 0 logs them all.
//!
//! A wake that finds its target not yet asleep is stamped, not delivered
//! (`wake_transition`): nothing was woken, so nothing is logged. A task that
//! consumes such a stamp never slept.
//!
//! The IRQ line is known only to `irq_bind::irq_dispatch`, which publishes it
//! in a per-CPU cell around the delivery ([`irq_enter`]/[`irq_leave`]); the
//! wake that delivery makes reads the cell. A wake from interrupt context with
//! no cell is `isr` and names no waker: the task the interrupt happened to
//! interrupt is not the waker.
//!
//! # The ring
//!
//! One ring for the machine, lock-free, a seqlock per slot. A wake claims a
//! ticket with one `fetch_add` (slot = ticket mod `ENTRIES`), then takes the
//! slot by swapping its `tag` to `BUSY` ([`Ring::open`]), writes the words, and
//! publishes the entry by writing the `tag` last with `Release` (the low 32
//! bits of its ticket in the high half). The swap is the writers' exclusion: a
//! wake preempted between its claim and its stores can arrive a whole lap late,
//! when the slot already belongs to a later ticket or to a writer in the middle
//! of its stores, and then it writes nothing (a sample lost, never a word
//! overwritten). A reader takes the head, copies the newest entries whose tag
//! carries the ticket of their position, and reads the tag again: a changed tag
//! means a writer took the slot while it copied, and the entry is dropped, so a
//! mixed entry never gets out. The writer never waits for a reader or another
//! writer.
//!
//! Cost of the writer, over the plain ticket and four stores it had before the
//! exclusion: one atomic swap and two compares with their branches (the refusal
//! is out of line). See `Ring::open`.

use core::sync::atomic::{fence, AtomicU64, Ordering};

use crate::task::WaitReason;

/// Slots of the ring (Kconfig `WAKE_RING_ENTRIES`); 0 is off.
pub const ENTRIES: usize = azos_limits::WAKE_RING_ENTRIES as usize;
/// Whether wakes are attributed at all.
pub const ENABLED: bool = ENTRIES != 0;
const _: () = assert!(ENTRIES == 0 || ENTRIES.is_power_of_two(), "WAKE_RING_ENTRIES must be a power of two");

/// Where a wake came from (module doc). The numbers are published
/// (`metrics/wake/r<N>`) with their names (`metrics/wake/sources`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Src {
    Timer = 0,
    Irq,
    Isr,
    IpcCall,
    IpcReply,
    Futex,
    Notify,
    Ring,
    Port,
    WaitQueue,
    Wake,
    Reap,
}

impl Src {
    /// Every source, by number.
    pub const ALL: [Src; 12] = [
        Src::Timer, Src::Irq, Src::Isr, Src::IpcCall, Src::IpcReply, Src::Futex,
        Src::Notify, Src::Ring, Src::Port, Src::WaitQueue, Src::Wake, Src::Reap,
    ];

    /// The name the tree and `why woke` print.
    pub const fn name(self) -> &'static str {
        match self {
            Src::Timer => "timer",
            Src::Irq => "irq",
            Src::Isr => "isr",
            Src::IpcCall => "ipc_call",
            Src::IpcReply => "ipc_reply",
            Src::Futex => "futex",
            Src::Notify => "notify",
            Src::Ring => "ring",
            Src::Port => "port",
            Src::WaitQueue => "waitq",
            Src::Wake => "wake",
            Src::Reap => "reap",
        }
    }

    pub const fn from_u8(n: u8) -> Option<Src> {
        if (n as usize) < Self::ALL.len() { Some(Self::ALL[n as usize]) } else { None }
    }
}

/// What the woken task was blocked on, read before the wake clears it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    None,
    Ring,
    Timer,
    Port,
    WaitQueue,
    FastIpcServer,
    FastIpcClient,
}

impl Reason {
    #[inline(always)]
    pub fn of(r: &WaitReason) -> Reason {
        match r {
            WaitReason::None => Reason::None,
            WaitReason::Ring(_) => Reason::Ring,
            WaitReason::Timer(_) => Reason::Timer,
            WaitReason::Port(_) => Reason::Port,
            WaitReason::WaitQueue => Reason::WaitQueue,
            WaitReason::FastIpcServer(_) => Reason::FastIpcServer,
            WaitReason::FastIpcClient(_) => Reason::FastIpcClient,
        }
    }
}

/// How the wake was made: what the call site knows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Via {
    /// `wake_task_by_tid`: the addressee is known, the cause is read from the
    /// task's reason and the waker's context ([`classify_targeted`]).
    Targeted,
    /// `wake_task_by_tid_ipc`: the IPC hand-off.
    Ipc,
    /// `try_wake_task`: a sweep over the pool for a predicate (the tick's
    /// timer sweep, a ring or port broadcast).
    Sweep,
    /// `wq_wake_by_tid`.
    WaitQueue,
    /// The K-C25 reaper.
    Reap,
    /// The caller names the source (`wake_task_by_tid_as`).
    As(Src),
}

/// The source of a wake whose [`Via`] fixes it, or the best the reason gives
/// when it does not. Interrupt context is judged by [`classify_targeted`].
#[inline(always)]
pub const fn classify(via: Via, reason: Reason) -> Src {
    match via {
        Via::Ipc => match reason {
            Reason::FastIpcClient => Src::IpcReply,
            _ => Src::IpcCall,
        },
        Via::Sweep => match reason {
            Reason::Timer => Src::Timer,
            Reason::Ring => Src::Ring,
            Reason::Port => Src::Port,
            Reason::WaitQueue => Src::WaitQueue,
            // The orphan sweep of a dead server's clients.
            Reason::FastIpcClient | Reason::FastIpcServer => Src::IpcReply,
            Reason::None => Src::Wake,
        },
        Via::WaitQueue => Src::WaitQueue,
        Via::Reap => Src::Reap,
        Via::As(s) => s,
        Via::Targeted => classify_targeted(reason, false, false),
    }
}

/// The source of a TID-directed wake that is not an IPC hand-off: `irq` when a
/// bound line's delivery is in flight on this CPU, `isr` for any other wake
/// made from interrupt context, else what the woken task was waiting on says.
#[inline(always)]
pub const fn classify_targeted(reason: Reason, isr: bool, irq_line_in_flight: bool) -> Src {
    // The canary: the line is never recognised, so an interrupt-line wake is
    // taken for the port event of a task. `an_irq_wake_names_its_line` must fail.
    let irq_line_in_flight = irq_line_in_flight && !cfg!(feature = "wake-attrib-canary");
    if irq_line_in_flight {
        return Src::Irq;
    }
    if isr && !cfg!(feature = "wake-attrib-canary") {
        return Src::Isr;
    }
    match reason {
        Reason::Port => Src::Port,
        Reason::Ring => Src::Ring,
        Reason::FastIpcServer => Src::IpcCall,
        Reason::FastIpcClient => Src::IpcReply,
        Reason::WaitQueue => Src::WaitQueue,
        Reason::Timer | Reason::None => Src::Wake,
    }
}

/// The source of a wake made `via` a path, in the context the waker is in:
/// `isr` is interrupt context, `line_in_flight` a bound line's delivery on the
/// waking CPU ([`irq_line`]). Only a TID-directed wake that is not an IPC
/// hand-off can be an interrupt's.
#[inline(always)]
pub const fn source(via: Via, reason: Reason, isr: bool, line_in_flight: bool) -> Src {
    match via {
        Via::Targeted => classify_targeted(reason, isr, line_in_flight),
        v => classify(v, reason),
    }
}

/// Whether a wake of `src` is one a task makes (and can name its waker); the
/// others are the machine's own: a deadline, a line, an interrupt handler, the
/// reaper.
#[inline(always)]
pub const fn names_waker(src: Src) -> bool {
    !matches!(src, Src::Timer | Src::Irq | Src::Isr | Src::Reap)
}

/// Wakes a task makes are logged one in `2^SAMPLE_LOG2` per woken Domain (Kconfig
/// `WAKE_RING_SAMPLE_LOG2`), the first of each Domain among them; the machine's
/// own are all logged. The count of every wake is kept in its Domain whatever is
/// logged. See the module doc for why.
pub const SAMPLE_LOG2: u32 = azos_limits::WAKE_RING_SAMPLE_LOG2 as u32;
const _: () = assert!(SAMPLE_LOG2 < 16);

/// Is the wake that is the `n`-th (counting from 0) of its Domain one of those a
/// task makes that are logged?
#[inline(always)]
pub const fn sampled_in(n: u64) -> bool {
    n & ((1u64 << SAMPLE_LOG2) - 1) == 0
}

/// Does the ring take the wake that is the `nth` (from 0) of its Domain, made
/// `via` a path for a sleeper that waited on `reason`; `isr` tells whether the
/// waker is an interrupt handler (read only when it decides).
///
/// Sampled: what tasks make and what repeats at the rate of the work (the IPC
/// hand-off, a named source, a TID-directed wake, a ring or port broadcast, a
/// wait queue). Logged in full: the machine's own (a deadline, the reaper, an
/// interrupt handler's wake) and the sweep's wakes that are neither a timer nor
/// a ring, port or wait-queue sleeper.
#[inline(always)]
pub fn logged(via: Via, reason: Reason, nth: u64, isr: impl FnOnce() -> bool) -> bool {
    match via {
        Via::Ipc | Via::As(_) | Via::WaitQueue => sampled_in(nth),
        Via::Targeted => sampled_in(nth) || isr(),
        Via::Sweep => match reason {
            Reason::Ring | Reason::Port | Reason::WaitQueue => sampled_in(nth),
            _ => true,
        },
        Via::Reap => true,
    }
}

/// The `detail` of an entry: the line for `irq`; the waker's TID, read only
/// when it is wanted, for a source that has one and a waker that is a task (in
/// interrupt context the task running is not the waker); else 0.
#[inline(always)]
pub fn detail(src: Src, line: Option<u32>, isr: bool, waker: impl FnOnce() -> u32) -> u32 {
    match src {
        Src::Irq => line.unwrap_or(0),
        s if isr || !names_waker(s) => 0,
        _ => waker(),
    }
}

// ── The ring ────────────────────────────────────────────────────────────────

/// One logged wake, as a reader gets it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Entry {
    /// The wake's number: 0 for the first of the boot.
    pub seq: u64,
    /// The clock, in ticks (`timebase::now`).
    pub at: u64,
    /// The task woken.
    pub tid: u32,
    /// The Domain key of the task woken (`domain::Key`, 0 for a kernel task's):
    /// logged with the wake, since the task can be gone when the entry is read.
    pub domain: u32,
    /// The line (`irq`), the waker's TID, or 0 ([`Src`]).
    pub detail: u32,
    pub src: u8,
    /// The CPU the woken task was queued on.
    pub target_cpu: u8,
    /// The CPU that made the wake.
    pub waker_cpu: u8,
}

#[repr(C, align(32))]
struct Slot {
    at: AtomicU64,
    /// `tid | detail << 32`.
    who: AtomicU64,
    /// The Domain key of the task woken.
    domain: AtomicU64,
    /// The slot's state, and the only word a reader trusts: [`EMPTY`], [`BUSY`]
    /// (a writer owns the words), or `(ticket + 1 as u32) << 32 | src << 16 |
    /// target_cpu << 8 | waker_cpu` (the entry of that ticket is whole).
    tag: AtomicU64,
}

impl Slot {
    const EMPTY: Slot = Slot { at: AtomicU64::new(0), who: AtomicU64::new(0), domain: AtomicU64::new(0), tag: AtomicU64::new(EMPTY) };
}

/// A slot nobody has written.
const EMPTY: u64 = 0;
/// A writer owns the slot's words. No finished tag is this value: its `src`
/// byte (bits 16..24) is below 12.
const BUSY: u64 = u64::MAX;

/// Is the ticket of tag half `a` later than the one of `b` (the tag halves are
/// tickets + 1 modulo 2^32, so compared as a signed distance)?
#[inline(always)]
const fn later(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// A ring of `N` slots (a power of two).
pub struct Ring<const N: usize> {
    /// Tickets issued: the next wake's number.
    head: AtomicU64,
    slots: [Slot; N],
}

/// A slot its writer owns: [`Ring::open`] made it, [`Open::commit`] ends it.
#[must_use = "a slot that is opened and never committed stays busy for ever"]
pub(crate) struct Open<'a> {
    slot: &'a Slot,
    ticket: u64,
}

impl Open<'_> {
    /// Write the entry and publish it: the tag goes last, `Release`.
    #[inline(always)]
    pub(crate) fn commit(self, at: u64, tid: u32, domain: u32, detail: u32, src: Src, waker_cpu: u8, target_cpu: u8) {
        let s = self.slot;
        s.at.store(at, Ordering::Relaxed);
        s.who.store(u64::from(tid) | u64::from(detail) << 32, Ordering::Relaxed);
        s.domain.store(u64::from(domain), Ordering::Relaxed);
        let tag = (self.ticket.wrapping_add(1) << 32) | u64::from(src as u8) << 16 | u64::from(target_cpu) << 8 | u64::from(waker_cpu);
        s.tag.store(tag, Ordering::Release);
    }
}

impl<const N: usize> Ring<N> {
    pub const fn new() -> Self {
        assert!(N.is_power_of_two());
        Ring { head: AtomicU64::new(0), slots: [Slot::EMPTY; N] }
    }

    /// Log one wake. Lock-free, never waits: a ticket, a slot claim, four
    /// stores. A wake that cannot take its slot ([`Ring::open`]) is not logged.
    #[inline(always)]
    pub fn push(&self, at: u64, tid: u32, domain: u32, detail: u32, src: Src, waker_cpu: u8, target_cpu: u8) {
        let ticket = self.claim();
        if let Some(w) = self.open(ticket) {
            w.commit(at, tid, domain, detail, src, waker_cpu, target_cpu);
        }
    }

    /// The next wake's number, taken: the ticket of the entry it will write.
    #[inline(always)]
    pub(crate) fn claim(&self) -> u64 {
        self.head.fetch_add(1, Ordering::Relaxed)
    }

    /// Take the slot of `ticket` for writing, or `None` when the wake must not
    /// write it: another writer owns it (a writer of the lap before that was
    /// preempted in the middle of its four stores, or a writer a lap ahead
    /// has already come), or the slot already holds a later ticket (this
    /// writer was preempted between its claim and here for a whole lap).
    ///
    /// The slot is owned from the swap of its tag to [`BUSY`] to the commit's
    /// tag store: the words are written by one wake at a time, so a word of an
    /// entry is never overwritten by another wake's, and a reader that copied
    /// a word written after the swap sees a changed tag on its re-read
    /// (`snapshot`). Wakes of one slot are tickets `t`, `t + N`, `t + 2N`:
    /// the swap is what orders them, not the claim, which a preempted wake
    /// can hold for any time before it gets here.
    #[inline(always)]
    pub(crate) fn open(&self, ticket: u64) -> Option<Open<'_>> {
        let slot = &self.slots[(ticket as usize) & (N - 1)];
        if cfg!(feature = "wake-ring-canary") {
            // The canary: the slot is written by whoever comes, as before the
            // exclusion. `a_late_writer_does_not_clobber_a_newer_entry` must fail.
            return Some(Open { slot, ticket });
        }
        let old = slot.tag.swap(BUSY, Ordering::Acquire);
        if old == BUSY || later((old >> 32) as u32, ticket.wrapping_add(1) as u32) {
            return Self::refuse(slot, old);
        }
        // The swap is seen before any word of the slot changes.
        fence(Ordering::Release);
        Some(Open { slot, ticket })
    }

    /// The slot is not this wake's. If the swap took it from a finished later
    /// entry, that entry goes back (nobody else wrote while it was [`BUSY`]).
    #[cold]
    #[inline(never)]
    fn refuse(slot: &Slot, old: u64) -> Option<Open<'_>> {
        if old != BUSY {
            slot.tag.store(old, Ordering::Release);
        }
        None
    }

    /// Wakes offered to the ring since boot: the ones its sampling rule chose to
    /// log. The ring keeps the last `N`; a wake that found its slot owned is
    /// counted here and not logged, so the `seq`s of the entries have a gap
    /// where it was. Published as `metrics/wake/offered`.
    pub fn offered(&self) -> u64 {
        self.head.load(Ordering::Acquire)
    }

    /// The newest entries, newest first, into `out`; how many were read. A
    /// slot a writer owns is skipped, and so is one a later wake took while it
    /// was copied, so the count can be short of `min(out.len(), N, total)`
    /// under a wake storm; it never holds a mixed entry.
    pub fn snapshot(&self, out: &mut [Entry]) -> usize {
        let h = self.head.load(Ordering::Acquire);
        let want = out.len().min(N).min(h as usize);
        let mut n = 0;
        for k in 0..want {
            let ticket = h - 1 - k as u64;
            let s = &self.slots[(ticket as usize) & (N - 1)];
            let t1 = s.tag.load(Ordering::Acquire);
            if t1 == BUSY || (t1 >> 32) as u32 != ticket.wrapping_add(1) as u32 {
                continue;
            }
            let (at, who, domain) =
                (s.at.load(Ordering::Relaxed), s.who.load(Ordering::Relaxed), s.domain.load(Ordering::Relaxed));
            // A word written after a writer took the slot is seen with the tag
            // that writer left (BUSY, or its own): the entry is dropped.
            fence(Ordering::Acquire);
            if s.tag.load(Ordering::Relaxed) != t1 {
                continue;
            }
            out[n] = Entry {
                seq: ticket,
                at,
                tid: who as u32,
                domain: domain as u32,
                detail: (who >> 32) as u32,
                src: (t1 >> 16) as u8,
                target_cpu: (t1 >> 8) as u8,
                waker_cpu: t1 as u8,
            };
            n += 1;
        }
        n
    }
}

/// Slots allocated (one when the ring is off, so the type stays inhabited).
const SLOTS: usize = if ENABLED { ENTRIES } else { 1 };

/// The machine's ring.
pub static RING: Ring<SLOTS> = Ring::new();

// ── The interrupt line in flight ────────────────────────────────────────────

const LINE_SET: u64 = 1 << 32;
const NO_LINE: AtomicU64 = AtomicU64::new(0);
static IRQ_LINE: [AtomicU64; azos_limits::NR_CPUS as usize] = [NO_LINE; azos_limits::NR_CPUS as usize];

/// `irq_dispatch` on `cpu` is about to queue the event of `line`: the wakes it
/// makes are that line's. Interrupts are masked on the CPU for the whole
/// delivery, so the cell has one writer.
#[inline]
pub fn irq_enter(cpu: usize, line: u32) {
    if ENABLED {
        if let Some(c) = IRQ_LINE.get(cpu) {
            c.store(LINE_SET | u64::from(line), Ordering::Relaxed);
        }
    }
}

/// The delivery is over.
#[inline]
pub fn irq_leave(cpu: usize) {
    if ENABLED {
        if let Some(c) = IRQ_LINE.get(cpu) {
            c.store(0, Ordering::Relaxed);
        }
    }
}

/// The line a delivery on `cpu` is making wakes for, if one is.
#[inline(always)]
pub fn irq_line(cpu: usize) -> Option<u32> {
    let v = IRQ_LINE.get(cpu)?.load(Ordering::Relaxed);
    if v & LINE_SET != 0 { Some(v as u32) } else { None }
}
