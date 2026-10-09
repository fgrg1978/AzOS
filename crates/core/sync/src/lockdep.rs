// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Lockdep-lite (wave 15, N1 part a; `rfcs/survey/MUTEX.md` §5.6).
//!
//! # Classes
//!
//! A lock's class is where its constructor was called: `SpinLock::new`,
//! `PiMutex::new`, `SleepLock::new` and `WaitQueue::new` are
//! `#[track_caller]` (with the `lockdep` feature only), so a `static` is its
//! own class and a lock built inside another type's constructor takes the
//! site of that constructor (Linux's one class per `spin_lock_init` site;
//! Zircon's type+line). The key is a hash of file, line, column and the
//! lock's kind, computed at construction (a `const fn`), so acquisition pays
//! no hashing for it. A lock whose memory was zero-filled instead of built
//! (key 0) is classed by its address.
//!
//! # What is checked, inline, at each acquisition
//!
//! * Each CPU keeps the stack of locks it holds (`HeldStack`). A task's part
//!   of it is saved and restored at the context switch (`switch`), so a
//!   sleeping lock held across a block stays with its task.
//! * A global, fixed-size, lock-free table records "A held, B taken" class
//!   pairs (`Graph`). Taking B while holding A when B→A is recorded is an
//!   inversion (ABBA), reported before the spin, so a real one is reported
//!   instead of hanging. Longer cycles are N1 part b's background pass.
//! * A hash of the held classes plus the new one (the chain) is cached: a
//!   chain already checked skips the walk (Linux's chain key).
//! * Taking a lock its holder already holds is reported (it would spin on
//!   itself). Two locks of one class nested is a note, not a failure: the
//!   way to say that is legal (`lock_pair`, subclasses) is part b.
//! * Locks taken in interrupt context form edges only with each other.
//!
//! # Elsewhere
//!
//! * [`might_sleep`]: a sleep or a device wait with a SpinLock (the
//!   RawSpinLock role) held, with interrupts off or in an interrupt.
//!   [`might_wait_device`] also notes a PiMutex held across a device wait.
//! * [`user_return`]: no lock held when a trap returns to user mode.
//!
//! # Reports
//!
//! Never printed from here: the console takes locks, and this runs inside
//! lock paths. Each distinct violation is queued once ([`drain`]) and
//! counted ([`stats`]); the ktest runner prints them, one line each, and
//! fails the test that was running (or the run). Notes (same-class nesting,
//! a PiMutex held across a device wait) are printed and counted apart, and
//! fail nothing.
//!
//! # Configuration
//!
//! Kconfig LOCKDEP n / ktest / y and the cargo feature `lockdep` (pulled in by
//! the kernel's `ktest` and `lockdep` features). Without the feature nothing
//! here is reachable from a lock: no field, no call. With it, [`ON`] decides
//! (LOCKDEP_KTEST checks only in a `ktest` kernel), and every table is sized
//! 0 when it is false.

use core::cell::UnsafeCell;
use core::panic::Location;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

/// Whether lockdep checks in this build (see the module docs).
pub const ON: bool = cfg!(feature = "lockdep")
    && (azos_limits::LOCKDEP_Y || (azos_limits::LOCKDEP_KTEST && cfg!(feature = "ktest")));

/// Kconfig `LOCK_MAX_HOLD_US`: the SpinLock hold bound part b enforces.
pub const MAX_HOLD_US: u64 = azos_limits::LOCK_MAX_HOLD_US as u64;

const DEPTH: usize = if ON { azos_limits::LOCKDEP_MAX_DEPTH as usize } else { 0 };
const NCPU: usize = if ON { azos_limits::NR_CPUS as usize } else { 0 };
const NTASK: usize = if ON { azos_limits::MAX_TASKS as usize } else { 0 };
const NEDGES: usize = if ON { azos_limits::LOCKDEP_EDGES as usize } else { 0 };
const NCHAINS: usize = if ON { azos_limits::LOCKDEP_CHAINS as usize } else { 0 };
const NREPORTS: usize = if ON { azos_limits::LOCKDEP_REPORTS as usize } else { 0 };

// ── Classes ──────────────────────────────────────────────────────────────

/// What a lock is. Part of the class key: a `PiMutex` and the `SpinLock` its
/// constructor builds share a site but not a class.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// `SpinLock` (the RawSpinLock role: preemption off, bounded).
    Spin = 1,
    /// `PiMutex` (sleeping, priority inheritance).
    PiMutex = 2,
    /// `SleepLock` (sleeping, no inheritance).
    Sleep = 3,
}

impl Kind {
    pub const fn name(self) -> &'static str {
        match self {
            Kind::Spin => "SpinLock",
            Kind::PiMutex => "PiMutex",
            Kind::Sleep => "SleepLock",
        }
    }
}

/// A lock's class: its key and the declaration site it came from.
#[derive(Clone, Copy)]
pub struct LockClass {
    key: u32,
    /// `None` is all-zero bits, so a zero-filled lock is still a valid value.
    loc: Option<&'static Location<'static>>,
}

impl LockClass {
    /// The class of a lock of `kind` built by the caller.
    #[track_caller]
    #[inline(always)]
    pub const fn here(kind: Kind) -> Self {
        let loc = Location::caller();
        LockClass { key: class_key(loc.file(), loc.line(), loc.column(), kind as u8), loc: Some(loc) }
    }

    pub fn key(&self) -> u32 { self.key }
}

/// FNV-1a over the site and the kind, never 0.
pub const fn class_key(file: &str, line: u32, col: u32, kind: u8) -> u32 {
    let f = file.as_bytes();
    let mut x: u32 = 0x811c_9dc5;
    let mut i = 0;
    while i < f.len() {
        x = (x ^ f[i] as u32).wrapping_mul(0x0100_0193);
        i += 1;
    }
    x = (x ^ line).wrapping_mul(0x0100_0193);
    x = (x ^ col).wrapping_mul(0x0100_0193);
    x = (x ^ kind as u32).wrapping_mul(0x0100_0193);
    if x == 0 { 1 } else { x }
}

fn loc_of(p: usize) -> Option<&'static Location<'static>> {
    // SAFETY: only `site_word` stores non-zero values in the words read
    // here, and it stores a `&'static Location`.
    if p == 0 { None } else { Some(unsafe { &*(p as *const Location<'static>) }) }
}

fn site_word(l: Option<&'static Location<'static>>) -> usize {
    l.map_or(0, |l| l as *const Location<'static> as usize)
}

// ── The held-lock stack ──────────────────────────────────────────────────

/// One lock held.
#[derive(Clone, Copy)]
pub struct Held {
    pub addr: usize,
    pub key: u32,
    pub kind: Kind,
    /// Taken with `lock_irqsave` (an IRQs-off section).
    pub irqsave: bool,
    /// Taken in interrupt context.
    pub irq_ctx: bool,
    /// Declaration site.
    pub class: Option<&'static Location<'static>>,
    /// Acquisition site.
    pub site: Option<&'static Location<'static>>,
}

impl Held {
    pub const EMPTY: Held = Held { addr: 0, key: 0, kind: Kind::Spin, irqsave: false, irq_ctx: false, class: None, site: None };

    /// The entry for taking the lock at `addr` of class `c`.
    ///
    /// Identity is the address AND the kind: a `PiMutex` or `SleepLock` may
    /// share its address with the SpinLock inside it (its first field after
    /// reordering), and taking that inner lock while the wrapper is held is
    /// not the holder taking it again.
    pub fn new(c: &LockClass, addr: usize, kind: Kind, irqsave: bool, irq_ctx: bool,
               site: &'static Location<'static>) -> Self {
        // A zero-filled lock (no constructor ran) is classed by address.
        let key = if c.key != 0 { c.key } else { (mix64(addr as u64) as u32) | 1 };
        Held { addr, key, kind, irqsave, irq_ctx, class: c.loc, site: Some(site) }
    }

}

/// The locks one context holds, innermost last.
#[derive(Clone, Copy)]
pub struct HeldStack<const D: usize> {
    n: usize,
    /// Pushes past `D`, not recorded; their pops are absorbed.
    lost: usize,
    e: [Held; D],
}

impl<const D: usize> HeldStack<D> {
    pub const fn new() -> Self { HeldStack { n: 0, lost: 0, e: [Held::EMPTY; D] } }

    pub fn held(&self) -> &[Held] { &self.e[..self.n] }

    pub fn is_empty(&self) -> bool { self.n == 0 && self.lost == 0 }

    /// Record `h`; `false` when the stack is full (counted in `lost`).
    pub fn push(&mut self, h: Held) -> bool {
        if self.n < D {
            self.e[self.n] = h;
            self.n += 1;
            true
        } else {
            self.lost += 1;
            false
        }
    }

    /// Forget the innermost entry for the `kind` lock at `addr` (guards are
    /// not always dropped in order). `false` when there is none and no lost
    /// push to absorb it.
    pub fn pop(&mut self, addr: usize, kind: Kind) -> bool {
        let mut i = self.n;
        while i > 0 {
            i -= 1;
            if self.e[i].addr == addr && self.e[i].kind == kind {
                self.e.copy_within(i + 1..self.n, i);
                self.n -= 1;
                return true;
            }
        }
        if self.lost > 0 {
            self.lost -= 1;
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) { self.n = 0; self.lost = 0; }

    /// Copy `o`'s entries (only the used ones).
    pub fn copy_from(&mut self, o: &Self) {
        self.e[..o.n].copy_from_slice(&o.e[..o.n]);
        self.n = o.n;
        self.lost = o.lost;
    }
}

impl<const D: usize> Default for HeldStack<D> {
    fn default() -> Self { Self::new() }
}

// ── Reports ──────────────────────────────────────────────────────────────

/// What a report says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum What {
    /// `taken` under `held`, after `held` was taken under `taken`.
    Inversion = 1,
    /// `taken` is a lock its holder already holds (`held`).
    Recursive = 2,
    /// A sleep or a device wait (`note`) with the SpinLock `held` held.
    SleepUnderSpin = 3,
    /// A sleep or a device wait (`note`) with interrupts off.
    SleepIrqsOff = 4,
    /// A sleep or a device wait (`note`) in interrupt context.
    SleepInIrq = 5,
    /// `held` still held on a return to user mode.
    HeldOnUserReturn = 6,
    /// A task switched away for the last time holding `held`.
    ExitHolding = 7,
    /// More than LOCKDEP_MAX_DEPTH locks held; `taken` was not recorded.
    DepthOverflow = 8,
    /// LOCKDEP_EDGES is full: an order (`held` → `taken`) went unrecorded.
    TableFull = 9,
    /// Note, not a failure: two locks of one class nested.
    SameClass = 10,
    /// Note, not a failure (yet): a device wait (`note`) with the PiMutex
    /// `held` held, which lends the device's latency to every waiter it
    /// boosts (owner rule F1, `rfcs/survey/MUTEX.md`; a SleepLock is the
    /// lock to hold across one).
    PiAcrossDeviceWait = 11,
}

impl What {
    /// Notes are counted, not failed (see the module docs).
    pub const fn is_note(self) -> bool { matches!(self, What::SameClass | What::PiAcrossDeviceWait) }

    pub const fn text(self) -> &'static str {
        match self {
            What::Inversion => "lock order inversion (ABBA)",
            What::Recursive => "lock taken again by its holder",
            What::SleepUnderSpin => "sleep or device wait under a SpinLock",
            What::SleepIrqsOff => "sleep or device wait with interrupts off",
            What::SleepInIrq => "sleep or device wait in interrupt context",
            What::HeldOnUserReturn => "lock held on return to user mode",
            What::ExitHolding => "task exited holding a lock",
            What::DepthOverflow => "held-lock stack full (LOCKDEP_MAX_DEPTH)",
            What::TableFull => "edge table full (LOCKDEP_EDGES)",
            What::SameClass => "two locks of one class nested (note)",
            What::PiAcrossDeviceWait => "PiMutex held across a device wait (note, rule F1)",
        }
    }
}

/// One violation: what, the held lock, the lock being taken and where the
/// reverse order was seen (inversions).
#[derive(Clone, Copy)]
pub struct Report {
    pub what: What,
    pub held: Held,
    pub taken: Held,
    /// Inversion: where `held` was taken while `taken`'s class was held.
    pub reverse_site: usize,
    /// Where `taken`'s class was taken in that reverse order.
    pub reverse_held_site: usize,
    /// might_sleep: what was about to sleep.
    pub note: &'static str,
}

impl Report {
    pub const EMPTY: Report = Report {
        what: What::Inversion, held: Held::EMPTY, taken: Held::EMPTY,
        reverse_site: 0, reverse_held_site: 0, note: "",
    };

    fn new(what: What, held: Held, taken: Held) -> Self {
        Report { what, held, taken, ..Report::EMPTY }
    }

    pub fn reverse_site_loc(&self) -> Option<&'static Location<'static>> { loc_of(self.reverse_site) }
    pub fn reverse_held_site_loc(&self) -> Option<&'static Location<'static>> { loc_of(self.reverse_held_site) }

    /// The key a report is deduplicated by (top bit set: never a chain key).
    fn dedup_key(&self) -> u64 {
        let site = if matches!(self.what, What::SleepUnderSpin | What::SleepIrqsOff | What::SleepInIrq | What::PiAcrossDeviceWait) {
            site_word(self.taken.site) as u64
        } else {
            0
        };
        let k = mix64(((self.what as u64) << 56) ^ ((self.held.key as u64) << 32) ^ self.taken.key as u64 ^ mix64(site));
        k | (1 << 63)
    }
}

// ── The dependency graph and the chain cache ─────────────────────────────

#[inline]
pub fn mix64(mut x: u64) -> u64 {
    // splitmix64's finaliser.
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

enum Probe { Found(usize), Inserted(usize), Absent, Full }

/// Fixed-size, lock-free tables of edges and of checked chains.
pub struct Graph<const E: usize, const C: usize> {
    edges: [AtomicU64; E],
    /// Per edge: where the "from" lock had been taken, and where the "to"
    /// lock was taken, the first time the order was seen.
    from_site: [AtomicUsize; E],
    to_site: [AtomicUsize; E],
    chains: [AtomicU64; C],
    n_edges: AtomicU32,
    n_chains: AtomicU32,
}

impl<const E: usize, const C: usize> Graph<E, C> {
    pub const fn new() -> Self {
        Graph {
            edges: [const { AtomicU64::new(0) }; E],
            from_site: [const { AtomicUsize::new(0) }; E],
            to_site: [const { AtomicUsize::new(0) }; E],
            chains: [const { AtomicU64::new(0) }; C],
            n_edges: AtomicU32::new(0),
            n_chains: AtomicU32::new(0),
        }
    }

    /// Open addressing, linear probing; 0 is the empty key.
    fn probe(t: &[AtomicU64], key: u64, insert: bool) -> Probe {
        let n = t.len();
        if n == 0 {
            return Probe::Full;
        }
        let mut i = (mix64(key) as usize) % n;
        for _ in 0..n {
            let cur = t[i].load(Ordering::Acquire);
            if cur == key {
                return Probe::Found(i);
            }
            if cur == 0 {
                if !insert {
                    return Probe::Absent;
                }
                match t[i].compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Probe::Inserted(i),
                    Err(v) if v == key => return Probe::Found(i),
                    Err(_) => {}
                }
            }
            i = if i + 1 == n { 0 } else { i + 1 };
        }
        Probe::Full
    }

    fn edge_key(a: u32, b: u32) -> u64 { ((a as u64) << 32) | b as u64 }

    /// The slot of edge `a → b`, if recorded.
    pub fn edge(&self, a: u32, b: u32) -> Option<usize> {
        match Self::probe(&self.edges, Self::edge_key(a, b), false) {
            Probe::Found(i) => Some(i),
            _ => None,
        }
    }

    /// Record `a → b`. `Err` when the table is full.
    pub fn add_edge(&self, a: u32, b: u32, from_site: usize, to_site: usize) -> Result<(), ()> {
        match Self::probe(&self.edges, Self::edge_key(a, b), true) {
            Probe::Inserted(i) => {
                self.from_site[i].store(from_site, Ordering::Relaxed);
                self.to_site[i].store(to_site, Ordering::Relaxed);
                self.n_edges.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Probe::Found(_) => Ok(()),
            Probe::Absent | Probe::Full => Err(()),
        }
    }

    pub fn chain_seen(&self, h: u64) -> bool {
        matches!(Self::probe(&self.chains, h, false), Probe::Found(_))
    }

    /// Insert `h`; `true` only if it was not there before (a full cache
    /// also answers `true`: the caller treats it as new).
    pub fn chain_insert(&self, h: u64) -> bool {
        match Self::probe(&self.chains, h, true) {
            Probe::Inserted(_) => { self.n_chains.fetch_add(1, Ordering::Relaxed); true }
            Probe::Found(_) => false,
            Probe::Absent | Probe::Full => true,
        }
    }

    pub fn counts(&self) -> (u32, u32) {
        (self.n_edges.load(Ordering::Relaxed), self.n_chains.load(Ordering::Relaxed))
    }

    /// The checks for taking `new` while `held` is held, in order: the same
    /// lock again; then, for a chain not checked before, every held lock of
    /// the same context against the edge table (an inversion stops the walk;
    /// otherwise the new orders are recorded and the chain cached).
    pub fn check(&self, held: &[Held], new: &Held) -> Option<Report> {
        if let Some(h) = held.iter().rev().find(|h| h.addr == new.addr && h.kind == new.kind) {
            return Some(Report::new(What::Recursive, *h, *new));
        }
        let mut ch: u64 = 0x6c6f_636b_6465_7031 ^ new.irq_ctx as u64;
        for h in held.iter().filter(|h| h.irq_ctx == new.irq_ctx) {
            ch = mix64(ch ^ h.key as u64);
        }
        ch = mix64(ch ^ new.key as u64) & !(1 << 63);
        if ch == 0 {
            ch = 1;
        }
        if self.chain_seen(ch) {
            return None;
        }
        let mut out = None;
        for h in held.iter().filter(|h| h.irq_ctx == new.irq_ctx) {
            if h.key == new.key {
                out.get_or_insert(Report::new(What::SameClass, *h, *new));
                continue;
            }
            if let Some(i) = self.edge(new.key, h.key) {
                let mut r = Report::new(What::Inversion, *h, *new);
                r.reverse_held_site = self.from_site[i].load(Ordering::Relaxed);
                r.reverse_site = self.to_site[i].load(Ordering::Relaxed);
                return Some(r);
            }
            if self.add_edge(h.key, new.key, site_word(h.site), site_word(new.site)).is_err() {
                return Some(Report::new(What::TableFull, *h, *new));
            }
        }
        self.chain_insert(ch);
        out
    }
}

impl<const E: usize, const C: usize> Default for Graph<E, C> {
    fn default() -> Self { Self::new() }
}

// ── The kernel's instance ────────────────────────────────────────────────

struct Cpu {
    held: HeldStack<DEPTH>,
    /// The scheduler has switched on this CPU: from here a sleep is real.
    live: bool,
    /// Inside a check (or a report): nested acquisitions are recorded, not
    /// checked.
    busy: bool,
}

struct CpuCell(UnsafeCell<Cpu>);
// SAFETY: each cell is touched only by its own CPU, with interrupts off.
unsafe impl Sync for CpuCell {}

struct TaskCell(UnsafeCell<HeldStack<DEPTH>>);
// SAFETY: a task's cell is written by the CPU switching it out and read by
// the CPU switching it in; the scheduler orders the two.
unsafe impl Sync for TaskCell {}

struct ReportCell(UnsafeCell<Report>);
// SAFETY: a cell is written once by the claimant of its index, published
// through `READY`, and read only after that by the single drainer.
unsafe impl Sync for ReportCell {}

static CPUS: [CpuCell; NCPU] = [const { CpuCell(UnsafeCell::new(Cpu { held: HeldStack::new(), live: false, busy: false })) }; NCPU];
static TASKS: [TaskCell; NTASK] = [const { TaskCell(UnsafeCell::new(HeldStack::new())) }; NTASK];
static GRAPH: Graph<NEDGES, NCHAINS> = Graph::new();
static REPORTS: [ReportCell; NREPORTS] = [const { ReportCell(UnsafeCell::new(Report::EMPTY)) }; NREPORTS];
static READY: [AtomicBool; NREPORTS] = [const { AtomicBool::new(false) }; NREPORTS];
static QUEUED: AtomicUsize = AtomicUsize::new(0);
static DRAINED: AtomicUsize = AtomicUsize::new(0);
static VIOLATIONS: AtomicU32 = AtomicU32::new(0);
static NOTES: AtomicU32 = AtomicU32::new(0);
static UNMATCHED: AtomicU32 = AtomicU32::new(0);
/// How often each check ran: the evidence it is reached at all.
static SWITCHES: AtomicU32 = AtomicU32::new(0);
static SLEEP_CHECKS: AtomicU32 = AtomicU32::new(0);
static USER_RETURNS: AtomicU32 = AtomicU32::new(0);

/// Run `f` on this CPU's state with interrupts off. `None` off-range.
#[inline]
fn with_cpu<R>(f: impl FnOnce(&mut Cpu, usize) -> R) -> Option<R> {
    use azos_arch::{Cpu as _, Interrupts as _};
    let prev = azos_arch::ARCH.disable_all();
    let cpu = azos_arch::ARCH.hart_id();
    let r = CPUS.get(cpu).map(|c| {
        // SAFETY: this CPU's cell, interrupts off (see `CpuCell`).
        f(unsafe { &mut *c.0.get() }, cpu)
    });
    azos_arch::ARCH.restore(prev);
    r
}

fn record(r: Report) {
    if !GRAPH.chain_insert(r.dedup_key()) {
        return; // reported before
    }
    // Notes are queued and printed too, but fail nothing.
    let counter = if r.what.is_note() { &NOTES } else { &VIOLATIONS };
    counter.fetch_add(1, Ordering::Relaxed);
    let i = QUEUED.fetch_add(1, Ordering::Relaxed);
    if i < NREPORTS {
        // SAFETY: index `i` was claimed by this call alone (see `ReportCell`).
        unsafe { *REPORTS[i].0.get() = r };
        READY[i].store(true, Ordering::Release);
    }
}

/// Check taking the lock at `addr` (class `c`, `kind`) against what this CPU
/// holds, then record it held. Before the spin or the wait: an inversion is
/// reported instead of deadlocking.
#[inline]
pub fn acquire(c: &LockClass, addr: usize, kind: Kind, irqsave: bool, site: &'static Location<'static>) {
    if ON {
        acquire_slow(c, addr, kind, irqsave, site, true);
    }
}

/// [`acquire`]'s checks only (a sleeping lock checks before it waits and
/// records itself held with [`acquired`] once it has the lock).
#[inline]
pub fn check(c: &LockClass, addr: usize, kind: Kind, site: &'static Location<'static>) {
    if ON {
        with_cpu(|cpu, n| {
            if !cpu.busy {
                cpu.busy = true;
                let new = Held::new(c, addr, kind, false, crate::isr_depth::in_isr(n), site);
                if let Some(r) = GRAPH.check(cpu.held.held(), &new) {
                    record(r);
                }
                cpu.busy = false;
            }
        });
    }
}

/// Record a lock held without checking its order (a `try_lock` cannot
/// deadlock; a sleeping lock checked before its wait).
#[inline]
pub fn acquired(c: &LockClass, addr: usize, kind: Kind, irqsave: bool, site: &'static Location<'static>) {
    if ON {
        acquire_slow(c, addr, kind, irqsave, site, false);
    }
}

#[inline(never)]
fn acquire_slow(c: &LockClass, addr: usize, kind: Kind, irqsave: bool, site: &'static Location<'static>, check: bool) {
    with_cpu(|cpu, n| {
        let new = Held::new(c, addr, kind, irqsave, crate::isr_depth::in_isr(n), site);
        if check && !cpu.busy {
            cpu.busy = true;
            if let Some(r) = GRAPH.check(cpu.held.held(), &new) {
                record(r);
            }
            cpu.busy = false;
        }
        if !cpu.held.push(new) {
            let top = cpu.held.held().last().copied().unwrap_or(Held::EMPTY);
            record(Report::new(What::DepthOverflow, top, new));
        }
    });
}

/// The `kind` lock at `addr` was released.
#[inline]
pub fn release(addr: usize, kind: Kind) {
    if ON {
        release_slow(addr, kind);
    }
}

#[inline(never)]
fn release_slow(addr: usize, kind: Kind) {
    with_cpu(|cpu, _| {
        if !cpu.held.pop(addr, kind) {
            UNMATCHED.fetch_add(1, Ordering::Relaxed);
        }
    });
}

/// The caller is about to sleep or wait for a device (`what`). Reported if
/// this CPU holds a SpinLock, runs with interrupts off or is in an interrupt.
/// Nothing before the scheduler first switched on this CPU (boot waits spin).
#[inline]
#[track_caller]
pub fn might_sleep(what: &'static str) {
    if ON {
        might_sleep_at(what, Location::caller(), false);
    }
}

/// [`might_sleep`] for a wait on a device (the block layer, the virtio-blk
/// completion wait): also notes a PiMutex held across it (rule F1).
#[inline]
#[track_caller]
pub fn might_wait_device(what: &'static str) {
    if ON {
        might_sleep_at(what, Location::caller(), true);
    }
}

#[inline(never)]
fn might_sleep_at(what: &'static str, site: &'static Location<'static>, device: bool) {
    use azos_arch::Interrupts as _;
    let irqs_on = azos_arch::ARCH.interrupts_enabled();
    with_cpu(|cpu, n| {
        if !cpu.live || cpu.busy {
            return;
        }
        SLEEP_CHECKS.fetch_add(1, Ordering::Relaxed);
        let here = Held { site: Some(site), ..Held::EMPTY };
        let r = if crate::isr_depth::in_isr(n) {
            Some(Report::new(What::SleepInIrq, Held::EMPTY, here))
        } else if let Some(h) = cpu.held.held().iter().rev().find(|h| h.kind == Kind::Spin && !h.irq_ctx) {
            Some(Report::new(What::SleepUnderSpin, *h, here))
        } else if !irqs_on {
            Some(Report::new(What::SleepIrqsOff, Held::EMPTY, here))
        } else if let Some(h) = cpu.held.held().iter().rev().find(|h| device && h.kind == Kind::PiMutex) {
            Some(Report::new(What::PiAcrossDeviceWait, *h, here))
        } else {
            None
        };
        if let Some(mut r) = r {
            r.note = what;
            record(r);
        }
    });
}

/// A trap is about to return to user mode: no lock may be held.
#[inline]
pub fn user_return() {
    if ON {
        user_return_slow();
    }
}

#[inline(never)]
fn user_return_slow() {
    USER_RETURNS.fetch_add(1, Ordering::Relaxed);
    with_cpu(|cpu, _| {
        if let Some(h) = cpu.held.held().iter().find(|h| !h.irq_ctx) {
            record(Report::new(What::HeldOnUserReturn, *h, Held::EMPTY));
        }
    });
}

/// Runs [`user_return`] when dropped, if armed. One goes at the top of each
/// trap handler a return to user mode passes through (`arm` with "the trap
/// came from user mode"), so every exit of the handler is checked.
/// Without the `lockdep` feature it is an empty type with no `Drop`: a
/// guard with drop glue, even a no-op one, changed riscv64's inlining of
/// the trap handler (measured: `handle_interrupt` was inlined into
/// `riscv64_trap_handler`, the syscall entry).
pub struct UserReturn(#[cfg(feature = "lockdep")] bool);

impl UserReturn {
    #[inline(always)]
    pub fn arm(to_user: impl FnOnce() -> bool) -> Self {
        #[cfg(feature = "lockdep")]
        {
            UserReturn(ON && to_user())
        }
        #[cfg(not(feature = "lockdep"))]
        {
            let _ = to_user;
            UserReturn()
        }
    }
}

#[cfg(feature = "lockdep")]
impl Drop for UserReturn {
    #[inline(always)]
    fn drop(&mut self) {
        if ON && self.0 {
            user_return_slow();
        }
    }
}

/// The scheduler is about to switch this CPU to task `next`. `save`: the
/// outgoing task's index when it will run again (`None`: first dispatch, or
/// a task that exited; then it must hold nothing). Task indices are the
/// scheduler's slots, `< MAX_TASKS`.
#[inline]
pub fn switch(save: Option<usize>, next: usize) {
    if ON {
        switch_slow(save, next);
    }
}

#[inline(never)]
fn switch_slow(save: Option<usize>, next: usize) {
    SWITCHES.fetch_add(1, Ordering::Relaxed);
    with_cpu(|cpu, _| {
        cpu.live = true;
        match save.and_then(|i| TASKS.get(i)) {
            // SAFETY: see `TaskCell`.
            Some(t) => unsafe { (*t.0.get()).copy_from(&cpu.held) },
            None => {
                if let Some(h) = cpu.held.held().iter().find(|h| !h.irq_ctx) {
                    record(Report::new(What::ExitHolding, *h, Held::EMPTY));
                }
            }
        }
        cpu.held.clear();
        if let Some(t) = TASKS.get(next) {
            // SAFETY: see `TaskCell`. Consumed: a slot's copy is valid only
            // from its task's switch-out to its next switch-in.
            let t = unsafe { &mut *t.0.get() };
            cpu.held.copy_from(t);
            t.clear();
        }
    });
}

/// Lockdep's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub violations: u32,
    /// Same-class nesting seen (not failures).
    pub notes: u32,
    pub edges: u32,
    pub chains: u32,
    /// Releases of a lock the CPU's stack did not hold.
    pub unmatched: u32,
    /// Context switches, `might_sleep` checks and returns to user checked.
    pub switches: u32,
    pub sleep_checks: u32,
    pub user_returns: u32,
}

pub fn stats() -> Stats {
    let (edges, chains) = GRAPH.counts();
    let l = |a: &AtomicU32| a.load(Ordering::Relaxed);
    Stats {
        violations: l(&VIOLATIONS), notes: l(&NOTES), edges, chains, unmatched: l(&UNMATCHED),
        switches: l(&SWITCHES), sleep_checks: l(&SLEEP_CHECKS), user_returns: l(&USER_RETURNS),
    }
}

/// Violations so far.
pub fn violations() -> u32 { VIOLATIONS.load(Ordering::Relaxed) }

/// Hand each queued report not handed out before to `f`, in order. One
/// drainer at a time (the ktest runner).
pub fn drain(mut f: impl FnMut(&Report)) {
    let end = QUEUED.load(Ordering::Acquire).min(NREPORTS);
    let mut i = DRAINED.load(Ordering::Relaxed);
    while i < end && READY[i].load(Ordering::Acquire) {
        // SAFETY: published through `READY` (see `ReportCell`).
        f(unsafe { &*REPORTS[i].0.get() });
        i += 1;
    }
    DRAINED.store(i, Ordering::Relaxed);
}

/// Reports that were counted but did not fit LOCKDEP_REPORTS.
pub fn dropped() -> usize { QUEUED.load(Ordering::Relaxed).saturating_sub(NREPORTS) }

/// Format `l` as `file:line` (or `?`).
pub struct Site(pub Option<&'static Location<'static>>);

impl core::fmt::Display for Site {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.0 {
            Some(l) => write!(f, "{}:{}", l.file(), l.line()),
            None => f.write_str("?"),
        }
    }
}

impl core::fmt::Display for Report {
    /// One line: what, then each lock as `Kind <class site> taken at <site>`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "lockdep: {}", self.what.text())?;
        if !self.note.is_empty() {
            write!(f, " ({})", self.note)?;
        }
        let lock = |f: &mut core::fmt::Formatter<'_>, tag: &str, h: &Held| -> core::fmt::Result {
            if h.key == 0 && h.site.is_none() {
                return Ok(());
            }
            if h.key == 0 {
                return write!(f, "; {} at {}", tag, Site(h.site));
            }
            write!(f, "; {} {} {}{} taken at {}", tag, h.kind.name(), Site(h.class),
                   if h.irqsave { " (irqsave)" } else { "" }, Site(h.site))
        };
        lock(f, "holding", &self.held)?;
        let sleep = matches!(self.what, What::SleepUnderSpin | What::SleepIrqsOff | What::SleepInIrq | What::PiAcrossDeviceWait);
        lock(f, if sleep { "waiting" } else { "taking" }, &self.taken)?;
        if self.what == What::Inversion {
            write!(f, "; reverse order seen: {} taken at {} under the other, taken at {}",
                   Site(self.held.class), Site(self.reverse_site_loc()),
                   Site(self.reverse_held_site_loc()))?;
        }
        Ok(())
    }
}
