// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-task frame budget arithmetic (owner decision 102, scan unit 3 finding 3).
//!
//! **WHY THIS FILE EXISTS.** The enforcement — `mm_charge` / `mm_discharge` /
//! `mm_reset_charge` / `set_current_user_page_limit`, all in
//! `crates/core/sched/src/scheduler.rs` — now delegates to `PageBudget`, held by the
//! task's domain (`crates/core/sched/src/domain.rs`, owner decision D2), which
//! all of a process's threads share, behind `PER_CPU[cpu].current_idx`.
//! `scheduler.rs` is RV64 context-switch machinery (asm, CSRs, PLIC, a
//! 4000-line global task table) and cannot be `#[path]`-pulled onto the host —
//! the same reason `tests/host/syscall-tests` stands up a hand-written stub for
//! `azos_sched` instead of linking the real crate. So this file is what
//! gives the arithmetic that decides "does this charge succeed" a host test of
//! the REAL code, not a transcription like
//! `tests/host/syscall-tests/shims/sched/src/lib.rs`, which says plainly it is
//! proving the WIRING in `handlers.rs`, not this decision.
//!
//! `PageBudget` is that decision, factored out to where it has no dependency on
//! a task table, a hart, or a scheduler at all — three plain counters and three
//! methods. `tests/host/mm-tests` pulls this file with `#[path]`, the same pattern
//! as `wx.rs` and `cow_table.rs`, and tests the actual shipping code: the twin
//! that used to live inline on `TASKS[idx].{user_pages, user_pages_peak,
//! user_page_limit}` is gone, replaced by the four call sites (`mm_charge`,
//! `mm_discharge`, `mm_reset_charge`, `set_current_user_page_limit`,
//! `current_user_pages`, `mm_peak_pages`, plus the four reset-on-reuse sites:
//! creation of a domain, `set_current_user_info` (exec), `set_task_user_info`
//! (fork), and `mm_reset_charge` itself) all reading/writing the task's domain.
//! `MM_QUOTA_REFUSALS` and `MM_PEAK_GLOBAL` stay in `scheduler.rs` — they are
//! cross-task globals, not per-task budget state.
//!
//! Semantics are a byte-for-byte transcription of the three functions above,
//! checked against them line by line:
//!   - `pages == 0` is always a no-op success, and never touches the peak.
//!   - `limit == 0` means unlimited.
//!   - the add is **saturating**: this workspace builds with
//!     `overflow-checks = true` and `panic = "abort"` (see `mm-tests`'s own
//!     `[profile.release]`, which reproduces it), so a plain `+` here would be
//!     a board reset on the target, not a caught error. Precedent:
//!     `note_stalled_tick` in `crates/core/actuation/src/watchdog.rs`.
//!   - a charge that would exceed the limit charges **nothing** — partial
//!     charges would leave the counter describing memory the caller did not
//!     get.
//!   - discharge is also saturating: an over-discharge floors at 0 instead of
//!     wrapping to `u32::MAX` and silently disabling the budget.
//!   - `reset` clears both `used` and `peak` — matching `mm_reset_charge`,
//!     which is called on `exec_user` and on exit, where the address space the
//!     peak described is gone too.
//!
//! **Reclaim** (Kconfig `MM_RECLAIM_COMPRESS`): the same ledger also carries the
//! Domain's watermarks and the bookkeeping of one reclaim
//! storm. The charge counts RESIDENT frames: a page the reclaimer compressed is
//! discharged (its bytes are the pool's quota, `zpool.rs`, H5) and a restore
//! charges it again with [`PageBudget::charge_restore`], which cannot be
//! refused, because a fault that finds its page compressed has nowhere to
//! report a quota failure (the task would die for memory it was promised); the
//! overshoot is at most the Domain's compressed pages, and the charge being
//! over `high` starts the next storm. The decisions (when a storm may start,
//! what the one record of a storm says) live here so the host tests run the
//! shipping code; the loop that picks victims, unmaps and stores them needs the
//! pager and is not in this file. A Domain with no frame limit has no watermarks and never reclaims.
//! This file depends on `core` alone (the sched-wake and syscall-tests shims
//! pull it); the percentages are `zpool.rs`'s.
//!
//! **Pressure** (Rule `MemPressure`): the same ledger names the Domain's level of
//! pressure, [`Pressure`], from the charge and the marks above it: `Warning`
//! from the high watermark (where reclaim starts), `Critical` at the limit
//! (the next charge is refused), `Normal` below. [`PageBudget::pressure_change`]
//! is the one place a level changes: it moves the Domain's remembered level
//! and answers the change once, so the reclaim task can tell the Domain's
//! Port about it BEFORE it opens a storm (the program trims its own caches
//! first, `azos_ualloc`). The way down has hysteresis ([`pressure_after`]).
//!
//! **Kernel memory** (`KmemBudget`, below) is the second ledger of the same
//! Domain: the bytes the kernel keeps FOR the Domain (its capability table,
//! endpoint queues, MemObj metadata, page tables grown at run time), bounded by
//! the row's `kmem_kib`. Same rules: atomic, all-or-nothing, saturating.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// How hard a Domain's frame budget is pressed. The value is what a pressure
/// event carries in its `source_id` (`PORT_EVENT_PRESSURE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Pressure {
    /// Below the high watermark (or no marks: no limit, reclaim off).
    Normal = 0,
    /// At or above the high watermark: reclaim is due. A program still has
    /// room to give memory back before the limit refuses it.
    Warning = 1,
    /// At the limit: the next charge is refused.
    Critical = 2,
}

impl Pressure {
    /// The level with this wire value.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Pressure> {
        match v {
            0 => Some(Pressure::Normal),
            1 => Some(Pressure::Warning),
            2 => Some(Pressure::Critical),
            _ => None,
        }
    }
}

/// The level a Domain at `cur` moves to when `used` pages are charged against
/// `limit` with watermarks `low < high`. `limit == 0` or `high == 0` (no
/// marks): always `Normal`.
///
/// Up is immediate: `used >= limit` is `Critical`, `used >= high` is at least
/// `Warning`. Down needs room, so a Domain does not flap at a boundary a
/// storm just left: `Critical` stays until the charge is below `high`, and
/// `Warning` until it is at or below `low` (where a storm stops).
#[must_use]
pub const fn pressure_after(cur: Pressure, used: u32, low: u32, high: u32, limit: u32) -> Pressure {
    if limit == 0 || high == 0 {
        Pressure::Normal
    } else if used >= limit {
        Pressure::Critical
    } else if used >= high {
        if matches!(cur, Pressure::Critical) { Pressure::Critical } else { Pressure::Warning }
    } else if !matches!(cur, Pressure::Normal) && used > low {
        Pressure::Warning
    } else {
        Pressure::Normal
    }
}

/// One Domain's frame accounting: how much it has charged, the high-water
/// mark, and its declared ceiling. `0` limit means unlimited — the state every
/// task whose topology row does not declare `mem_pages` starts in.
///
/// **Atomic.** A Domain is charged from every hart its members run on, and now
/// from other Domains too (a MemObj MOVE charges the receiver from the sender's
/// thread; a freed object gives back to the holder from whichever task drops
/// the last reference). `charge` is a compare-and-swap loop on `used`, so two
/// harts can never both pass the limit test on the same headroom and the count
/// never loses an update; `discharge` is a saturating atomic subtract. Every
/// method takes `&self`.
#[derive(Debug, Default)]
#[repr(C)]
pub struct PageBudget {
    used: AtomicU32,
    peak: AtomicU32,
    limit: AtomicU32,
    /// Reclaim starts at this charge (`0`: never). Declared with the limit.
    high: AtomicU32,
    /// A reclaim storm stops at this charge.
    low: AtomicU32,
    /// `STORM_IDLE`, `STORM_OPEN` ([`PageBudget::storm_begin`]) or
    /// `STORM_CLOSING` ([`PageBudget::storm_end`] is draining the counters).
    storm: AtomicU8,
    storm_pages: AtomicU32,
    storm_out: AtomicU64,
    /// The level last reported by [`PageBudget::pressure_change`] (a
    /// [`Pressure`]).
    level: AtomicU8,
    /// When the Domain's pages were last aged (`aging.rs`), in the caller's
    /// ticks; `0`: never ([`PageBudget::aging_due`]).
    aged: AtomicU64,
}

const STORM_IDLE: u8 = 0;
const STORM_OPEN: u8 = 1;
const STORM_CLOSING: u8 = 2;

/// Why a reclaim storm did not start ([`PageBudget::storm_begin`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoStorm {
    /// The Domain is on a `mem = "locked"` row: its pages are never reclaimed.
    Locked,
    /// The caller runs on a real-time hart: reclaim never does.
    RtHart,
    /// The charge is below the high watermark, or there is none (no frame
    /// limit, or reclaim is off).
    BelowHigh,
    /// A storm of this Domain is already running.
    Busy,
}

/// What one reclaim storm did: the fields of its single `Rule::Compress`
/// decision record (`pages`, `bytes_in`, `bytes_out`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StormRecord {
    /// Pages taken out of the Domain's frames and stored.
    pub pages: u32,
    /// What they were, uncompressed.
    pub bytes_in: u64,
    /// What the pool holds for them (zero for a same-filled page).
    pub bytes_out: u64,
    /// The storm ended because the pool had no room (not because the Domain
    /// reached its low watermark or the source ran dry): the next reclaim
    /// stage, writing a segment to swap, is due. Not one of the decision
    /// record's fields.
    pub full: bool,
    /// The pool said no to a page: it did not compress or there was no room.
    /// Not one of the decision record's fields.
    pub refused: bool,
}

/// How a storm ended, for its `Rule::Compress` verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StormOutcome {
    /// A page was stored: `Admit`.
    Paid,
    /// Candidates, and the pool stored none of them: the rule's `Refuse`.
    Refused,
    /// Nothing reached the pool: not a refusal, and nothing the medium needs.
    NoCandidate,
}

impl StormRecord {
    /// A storm that stored a page was compression that paid.
    #[must_use]
    pub const fn paid(&self) -> bool { self.pages != 0 }

    #[must_use]
    pub const fn outcome(&self) -> StormOutcome {
        if self.paid() {
            StormOutcome::Paid
        } else if self.refused {
            StormOutcome::Refused
        } else {
            StormOutcome::NoCandidate
        }
    }

    /// The record's three numbers, in the rule's field order.
    #[must_use]
    pub const fn fields(&self) -> [u64; 3] { [self.pages as u64, self.bytes_in, self.bytes_out] }
}

/// Is `pct` percent or more of `total` frames in use (`free` are not)? The
/// system watermark test, with the arithmetic of a Domain's: the reclaim task
/// (`kernel/src/tasks/reclaim.rs`) asks it against `MM_RECLAIM_HIGH_PCT` to
/// know a pass is due, and against `MM_RECLAIM_LOW_PCT` to know it may stop.
/// Never true for a machine with no frames.
#[must_use]
pub const fn used_at_least(free: usize, total: usize, pct: u32) -> bool {
    total != 0 && total.saturating_sub(free).saturating_mul(100) >= total.saturating_mul(pct as usize)
}

impl PageBudget {
    pub const fn new() -> Self {
        Self {
            used: AtomicU32::new(0),
            peak: AtomicU32::new(0),
            limit: AtomicU32::new(0),
            high: AtomicU32::new(0),
            low: AtomicU32::new(0),
            storm: AtomicU8::new(0),
            storm_pages: AtomicU32::new(0),
            storm_out: AtomicU64::new(0),
            level: AtomicU8::new(Pressure::Normal as u8),
            aged: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn used(&self) -> u32 { self.used.load(Ordering::Acquire) }

    #[must_use]
    pub fn peak(&self) -> u32 { self.peak.load(Ordering::Relaxed) }

    #[must_use]
    pub fn limit(&self) -> u32 { self.limit.load(Ordering::Relaxed) }

    /// Declare the budget, in 4 KiB pages. `0` = no limit. Mirrors
    /// `set_current_user_page_limit`. A limit declared this way has no
    /// watermarks (and a Domain slot that is reused for a new one cannot keep
    /// the marks of the old limit): [`set_limit_marked`](Self::set_limit_marked)
    /// is the declaration that gives it reclaim.
    pub fn set_limit(&self, limit: u32) {
        self.limit.store(limit, Ordering::Relaxed);
        self.set_watermarks(0, 0);
        // A new occupant of the slot has told nobody anything yet, and its
        // pages have not been aged.
        self.level.store(Pressure::Normal as u8, Ordering::Relaxed);
        self.aged.store(0, Ordering::Relaxed);
    }

    /// Declare the budget and, with it, where reclaim starts and stops: the
    /// high and low watermarks are `high_pct` and `low_pct` percent of `limit`
    /// ([`watermarks_for`]; `high_pct == 0`: reclaim is off, none). The one call
    /// the Domain's frame limit goes through when its topology row is applied.
    pub fn set_limit_marked(&self, limit: u32, high_pct: u32, low_pct: u32) {
        self.limit.store(limit, Ordering::Relaxed);
        let (low, high) = watermarks_for(limit, high_pct, low_pct);
        self.set_watermarks(low, high);
        self.aged.store(0, Ordering::Relaxed);
    }

    /// Declare where reclaim starts and stops, in pages (`high == 0`: never;
    /// otherwise `low < high`). [`watermarks_for`] derives them from a limit.
    pub fn set_watermarks(&self, low: u32, high: u32) {
        debug_assert!(high == 0 || low < high);
        self.low.store(low, Ordering::Relaxed);
        self.high.store(high, Ordering::Relaxed);
    }

    #[must_use]
    pub fn high(&self) -> u32 { self.high.load(Ordering::Relaxed) }

    #[must_use]
    pub fn low(&self) -> u32 { self.low.load(Ordering::Relaxed) }

    /// Is the charge at or above the high watermark? Two loads: the trigger
    /// site (after a charge) asks it without a lock.
    #[must_use]
    pub fn over_high(&self) -> bool {
        let high = self.high.load(Ordering::Relaxed);
        high != 0 && self.used.load(Ordering::Relaxed) >= high
    }

    /// The level the charge puts the Domain at now, given the level it was last
    /// reported at. Two loads and the arithmetic of [`pressure_after`].
    #[must_use]
    pub fn pressure(&self) -> Pressure {
        pressure_after(
            self.reported(),
            self.used.load(Ordering::Relaxed),
            self.low.load(Ordering::Relaxed),
            self.high.load(Ordering::Relaxed),
            self.limit.load(Ordering::Relaxed),
        )
    }

    /// The level last reported by [`pressure_change`](Self::pressure_change).
    #[must_use]
    pub fn reported(&self) -> Pressure {
        Pressure::from_u8(self.level.load(Ordering::Acquire)).unwrap_or(Pressure::Normal)
    }

    /// If the level is not the one last reported, report it: `Some((from, to))`
    /// exactly once per change, whichever hart asks (a compare-and-swap on the
    /// remembered level), `None` when nothing changed. The reclaim task calls
    /// it before it opens a storm, and tells the Domain's Port about a `Some`.
    pub fn pressure_change(&self) -> Option<(Pressure, Pressure)> {
        let from = self.reported();
        let to = self.pressure();
        if to == from {
            return None;
        }
        self.level.compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Relaxed).ok().map(|_| (from, to))
    }

    /// Do the Domain's pages need aging at `now` (`aging.rs`; ticks of the
    /// caller's clock, `interval` of them between passes)? Only a Domain with
    /// watermarks whose charge is above `low` is aged: below it nothing can be
    /// asked of it soon, and the pass costs a walk and, without a hardware
    /// Accessed bit, a fault per page. A Domain never aged is due at once.
    #[must_use]
    pub fn aging_due(&self, now: u64, interval: u64) -> bool {
        if !self.wants_aging() {
            return false;
        }
        let last = self.aged.load(Ordering::Relaxed);
        last == 0 || now.saturating_sub(last) >= interval
    }

    /// Does the Domain keep page ages at all: it has watermarks and its
    /// charge is above `low`? The part of [`aging_due`](Self::aging_due) that
    /// does not depend on the clock. What stops being true drops the Domain's
    /// chunks from the age table (`AgeTable::retain_owners`).
    #[must_use]
    pub fn wants_aging(&self) -> bool {
        self.high.load(Ordering::Relaxed) != 0 && self.used.load(Ordering::Relaxed) > self.low.load(Ordering::Relaxed)
    }

    /// The Domain's pages were aged at `now` (never recorded as `0`, which
    /// means "never").
    pub fn note_aged(&self, now: u64) {
        self.aged.store(now.max(1), Ordering::Relaxed);
    }

    /// Open a reclaim storm: the one running reclaim of this Domain. `Ok`
    /// only when the Domain is not on a locked row, the caller
    /// is not on a real-time hart, the charge is at or above `high`, and no
    /// storm is open. Close it with [`storm_end`](Self::storm_end), which
    /// answers the storm's one decision record.
    ///
    /// `locked` and `rt_hart` are the caller's facts (`domain::mem_locked`, the
    /// hart's class); they are arguments so that the rule "locked rows and RT
    /// harts are never reclaimed" is one decision with one test, not two
    /// checks at two call sites.
    pub fn storm_begin(&self, locked: bool, rt_hart: bool) -> Result<(), NoStorm> {
        if locked {
            return Err(NoStorm::Locked);
        }
        if rt_hart {
            return Err(NoStorm::RtHart);
        }
        if !self.over_high() {
            return Err(NoStorm::BelowHigh);
        }
        self.storm
            .compare_exchange(STORM_IDLE, STORM_OPEN, Ordering::AcqRel, Ordering::Relaxed)
            .map(|_| ())
            .map_err(|_| NoStorm::Busy)
    }

    /// Pages the open storm still has to free: the charge above `low`. `0`
    /// with no storm open, and once the charge is at or below `low`; the
    /// storm's loop runs while this is nonzero and a victim exists.
    #[must_use]
    pub fn reclaim_target(&self) -> u32 {
        if self.storm.load(Ordering::Acquire) != STORM_OPEN {
            return 0;
        }
        self.used.load(Ordering::Relaxed).saturating_sub(self.low.load(Ordering::Relaxed))
    }

    /// A page left the Domain's frames for the pool, `bytes_out` bytes there
    /// (`0`: same-filled). Gives the frame's charge back and counts it in the
    /// open storm. Called by the storm's driver only, after the frame is freed.
    pub fn storm_note_stored(&self, bytes_out: u32) {
        self.discharge(1);
        self.storm_pages.fetch_add(1, Ordering::Relaxed);
        self.storm_out.fetch_add(u64::from(bytes_out), Ordering::Relaxed);
    }

    /// Close the storm and answer its record, exactly once per
    /// [`storm_begin`](Self::storm_begin); `None` when none is open.
    /// `page_bytes` is the page size (the ISA's, not this file's to know).
    pub fn storm_end(&self, page_bytes: u32) -> Option<StormRecord> {
        // The flag is released LAST: while it reads CLOSING no `storm_begin`
        // can win, so the next storm never notes a page into counters this
        // call is about to take. The Release store publishes the zeroed
        // counters to whoever then wins the CAS in `storm_begin`.
        self.storm.compare_exchange(STORM_OPEN, STORM_CLOSING, Ordering::AcqRel, Ordering::Relaxed).ok()?;
        let pages = self.storm_pages.swap(0, Ordering::Relaxed);
        let bytes_out = self.storm_out.swap(0, Ordering::Relaxed);
        self.storm.store(STORM_IDLE, Ordering::Release);
        Some(StormRecord { pages, bytes_in: u64::from(pages) * u64::from(page_bytes), bytes_out, full: false, refused: false })
    }

    /// Charge `pages` for a restore (the fault found its page compressed and
    /// gave it a frame): saturating, never refused, and the peak follows. See
    /// the header for why the limit is not tested here.
    pub fn charge_restore(&self, pages: u32) {
        if pages == 0 { return; }
        let prev = self.used.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |u| Some(u.saturating_add(pages)));
        let next = prev.unwrap_or(u32::MAX).saturating_add(pages);
        self.peak.fetch_max(next, Ordering::Relaxed);
    }

    /// Charge `pages` frames. Returns `false` and charges NOTHING if that would
    /// exceed a nonzero limit. Mirrors `mm_charge` exactly (the cross-task
    /// `MM_QUOTA_REFUSALS`/`MM_PEAK_GLOBAL` counters in `scheduler.rs` are the
    /// caller's job on a `false`/`true` result respectively — this struct only
    /// holds the one Domain's numbers).
    pub fn charge(&self, pages: u32) -> bool {
        if pages == 0 { return true; }
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_add(pages);
            let limit = self.limit.load(Ordering::Relaxed);
            // Canary `budget-racy-charge-canary`: the test and the store are
            // two steps again, so two harts can both pass the same headroom.
            if cfg!(feature = "budget-racy-charge-canary") {
                if limit != 0 && next > limit {
                    return false;
                }
                self.used.store(self.used.load(Ordering::Relaxed).saturating_add(pages), Ordering::Release);
                self.peak.fetch_max(next, Ordering::Relaxed);
                return true;
            }
            if limit != 0 && next > limit {
                return false;
            }
            match self.used.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    self.peak.fetch_max(next, Ordering::Relaxed);
                    return true;
                }
                Err(now) => cur = now,
            }
        }
    }

    /// Give `pages` frames back. Mirrors `mm_discharge`. A saturating atomic
    /// subtract: concurrent discharges and charges never lose an update.
    pub fn discharge(&self, pages: u32) {
        if pages == 0 { return; }
        let _ = self.used.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |u| Some(u.saturating_sub(pages)));
    }

    /// Forget the used count AND the peak — the address space either
    /// described is gone. Mirrors `mm_reset_charge`. Not for a Domain that is
    /// being charged: it runs at creation, exec and exit. The reported level
    /// stays: a Domain that was told `Warning` is told `Normal` by the next
    /// [`pressure_change`](Self::pressure_change), not left believing it.
    pub fn reset(&self) {
        self.used.store(0, Ordering::Release);
        self.peak.store(0, Ordering::Relaxed);
    }
}

// ── Kernel memory (KMEM-CHARGE) ────────────────────────────────────────────

/// The object classes whose kernel memory is charged to the Domain they are
/// made for. The classes are the structures a Domain's own operations make the
/// kernel keep, not the allocator they come from: the capability tables, the
/// endpoint queues and the MemObj metadata are fixed pools, so each object has
/// a constant size, charged when the object is claimed for the Domain and
/// returned when it is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KmemClass {
    /// The Domain's capability table, charged once when the Domain first
    /// claims its table.
    CapTable = 0,
    /// One endpoint's call queue and slot, charged to the Domain that creates
    /// (or, for a named endpoint, first claims) the endpoint.
    EpQueue = 1,
    /// One MemObj region's metadata (its page table of frames and holder
    /// records), charged to the Domain that holds the object's charge.
    MemObjMeta = 2,
    /// A page-table frame the Domain's own mappings grew after its address
    /// space was installed. The frame is ALSO in the frame budget
    /// ([`PageBudget`]): two ledgers, two limits, by design (the frame budget
    /// bounds memory the Domain can map, this one bounds what the kernel keeps
    /// for it).
    PageTable = 3,
}

/// Number of [`KmemClass`] values.
pub const KMEM_CLASSES: usize = 4;

impl KmemClass {
    /// Every class, by index.
    pub const ALL: [KmemClass; KMEM_CLASSES] =
        [KmemClass::CapTable, KmemClass::EpQueue, KmemClass::MemObjMeta, KmemClass::PageTable];

    /// The class with index `i`.
    #[must_use]
    pub const fn from_index(i: u8) -> Option<KmemClass> {
        match i {
            0 => Some(KmemClass::CapTable),
            1 => Some(KmemClass::EpQueue),
            2 => Some(KmemClass::MemObjMeta),
            3 => Some(KmemClass::PageTable),
            _ => None,
        }
    }
}

/// What a refused kernel-memory charge reports: exactly the three numbers of
/// the `kmem-charge` decision record (`bytes`, `used`, `limit`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KmemRefusal {
    pub class: KmemClass,
    /// The charge that was refused.
    pub bytes: u64,
    /// Bytes the Domain held when it was refused.
    pub used: u64,
    /// The ceiling it would have gone past.
    pub limit: u64,
}

/// One Domain's kernel-memory ledger: bytes held per [`KmemClass`], the sum,
/// and the declared ceiling (`kmem_kib` of the task row, in bytes; `0` =
/// none). Bytes, `u64`: `kmem_kib` is a `u32` of KiB and a ceiling in bytes
/// does not fit 32 bits.
///
/// **No lock.** `charge` is a compare-and-swap loop on `used`, like
/// [`PageBudget::charge`]; `discharge` is a saturating atomic subtract. Neither
/// takes a lock nor waits, so a caller may charge or discharge from under any
/// other lock (the capability-store table lock, the endpoint table lock)
/// without a lock order to keep, from any hart, from any Domain.
///
/// `used` always equals the sum of the classes: a discharge removes at most
/// what its class holds, and takes that same amount off `used`, so an
/// over-discharge of one class cannot eat another class's bytes.
#[derive(Debug, Default)]
pub struct KmemBudget {
    used: AtomicU64,
    limit: AtomicU64,
    by_class: [AtomicU64; KMEM_CLASSES],
}

impl KmemBudget {
    pub const fn new() -> Self {
        Self {
            used: AtomicU64::new(0),
            limit: AtomicU64::new(0),
            by_class: [const { AtomicU64::new(0) }; KMEM_CLASSES],
        }
    }

    /// Bytes held, all classes.
    #[must_use]
    pub fn used(&self) -> u64 { self.used.load(Ordering::Acquire) }

    /// Bytes held by `class`.
    #[must_use]
    pub fn used_of(&self, class: KmemClass) -> u64 { self.by_class[class as usize].load(Ordering::Acquire) }

    /// The ceiling in bytes; `0` = none.
    #[must_use]
    pub fn limit(&self) -> u64 { self.limit.load(Ordering::Relaxed) }

    /// Declare the ceiling, in KiB (the unit of the topology row's
    /// `kmem_kib`). `0` = none.
    pub fn set_limit_kib(&self, kib: u32) {
        self.limit.store(u64::from(kib) * 1024, Ordering::Relaxed);
    }

    /// Charge `bytes` to `class`, all or nothing. A charge that would take the
    /// ledger past a nonzero limit changes nothing and answers the refusal the
    /// caller records. `bytes == 0` always succeeds. Saturating: the workspace
    /// builds with `overflow-checks`, so a plain add would be a reset.
    pub fn charge(&self, class: KmemClass, bytes: u64) -> Result<(), KmemRefusal> {
        if bytes == 0 { return Ok(()); }
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_add(bytes);
            let limit = self.limit.load(Ordering::Relaxed);
            if limit != 0 && next > limit {
                return Err(KmemRefusal { class, bytes, used: cur, limit });
            }
            match self.used.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => {
                    self.by_class[class as usize].fetch_add(bytes, Ordering::AcqRel);
                    return Ok(());
                }
                Err(now) => cur = now,
            }
        }
    }

    /// Give `bytes` of `class` back; at most what the class holds. Returns the
    /// bytes actually given back.
    pub fn discharge(&self, class: KmemClass, bytes: u64) -> u64 {
        if bytes == 0 { return 0; }
        let took = match self.by_class[class as usize]
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |u| Some(u.saturating_sub(bytes)))
        {
            Ok(before) | Err(before) => before.min(bytes),
        };
        let _ = self.used.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |u| Some(u.saturating_sub(took)));
        took
    }

    /// Give back everything `class` holds (a class whose objects all went
    /// at once). Returns the bytes given back.
    pub fn discharge_all(&self, class: KmemClass) -> u64 {
        let held = self.by_class[class as usize].swap(0, Ordering::AcqRel);
        let _ = self.used.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |u| Some(u.saturating_sub(held)));
        held
    }

    /// Forget every charge and the limit: the Domain that held them is gone
    /// and its slot is being reused. Not for a Domain that is being charged.
    pub fn reset(&self) {
        for c in &self.by_class { c.store(0, Ordering::Relaxed); }
        self.used.store(0, Ordering::Release);
        self.limit.store(0, Ordering::Relaxed);
    }
}

/// The `(low, high)` watermarks, in pages, of a frame budget of `limit` pages
/// whose reclaim starts at `high_pct` percent of it and stops at `low_pct`
/// percent. `(0, 0)` for no limit (a Domain without one never reclaims) and for
/// `high_pct == 0` (reclaim is off). Always `low < high`, and `high` at least
/// one page: a limit too small to take a percentage of still has a watermark.
#[must_use]
pub const fn watermarks_for(limit: u32, high_pct: u32, low_pct: u32) -> (u32, u32) {
    if limit == 0 || high_pct == 0 {
        return (0, 0);
    }
    let mut high = (limit as u64 * high_pct as u64 / 100) as u32;
    if high == 0 {
        high = 1;
    }
    let mut low = (limit as u64 * low_pct as u64 / 100) as u32;
    if low >= high {
        low = high - 1;
    }
    (low, high)
}
