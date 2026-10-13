// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Masked-window tracer: the longest stretch each hart spent with interrupts
//! masked, and the longest with preemption disabled (Linux's `irqsoff` and
//! `preemptoff` tracers, reduced to what a worst-case latency budget needs).
//!
//! Compiled only with the `lat-trace` feature (Kconfig `LAT_TRACE`). Without
//! it this module does not exist and no hook calls it, so the default kernel
//! carries no code and no data for it.
//!
//! # Model
//!
//! Two independent tracks per hart, [`Kind::Irq`] and [`Kind::Preempt`]. The
//! ISA crates call [`open`] on the transition into the masked state and
//! [`close`] on the transition out of it, passing their own hart id, the
//! counter value and a *site*: an opaque `usize` (the kernel passes
//! `&'static core::panic::Location` pointers). This module never interprets a
//! site; it only keeps them.
//!
//! Per track: the current window (open flag, start time, start site), the
//! longest window seen (length, start site, end site), a window count, and a
//! small table keyed by start site holding each site's longest window. The
//! table is what answers "which call sites are the worst", which a single
//! maximum cannot.
//!
//! # Missed transitions
//!
//! Not every transition goes through a hook: `sret`/`eret` into a task's first
//! run and the instructions between a trap handler's return and the
//! `sret`/`eret` re-enable interrupts without one. A window whose end was not
//! seen must not be reported as one long window, so [`open`] on a track that
//! is already open discards the stale window and counts it in `unpaired`
//! instead of extending it. The tracer therefore under-reports (a lost window)
//! rather than over-reports; `unpaired` says how many were lost.
//!
//! # Concurrency
//!
//! Each track is written only by its own hart, with interrupts masked (the IRQ
//! track is updated while still masked; the ISA crates mask around the
//! preempt hooks). Readers on other harts see a racy but word-consistent
//! snapshot: every field is an atomic accessed with `Relaxed`. [`reset`] from
//! one hart while another hart is closing a window can leave that one window
//! recorded after the reset; it is a measurement aid, not a barrier.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};

/// Tracked harts: the CPU ceiling (Kconfig `NR_CPUS`), as `MAX_HARTS` and
/// `azos_sync::preempt::SLOTS` are.
pub const HARTS: usize = azos_limits::NR_CPUS;
/// Distinct start sites remembered per hart and track. A full table evicts
/// its shortest entry for a longer window (see [`close`]), so the longest
/// sites are always kept whatever the number of distinct sites.
pub const SITES: usize = 64;

/// Which masked state a window measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Interrupts masked on the hart (`sstatus.SIE` clear / `DAIF.I` set).
    Irq = 0,
    /// Preemption disabled (`azos_sync::preempt` depth above zero).
    Preempt = 1,
}

struct SiteSlot {
    site: AtomicUsize,
    max: AtomicU64,
    end: AtomicUsize,
    count: AtomicU32,
}

impl SiteSlot {
    const fn new() -> Self {
        Self { site: AtomicUsize::new(0), max: AtomicU64::new(0),
               end: AtomicUsize::new(0), count: AtomicU32::new(0) }
    }
}

#[repr(align(64))]
struct Track {
    open: AtomicBool,
    t0: AtomicU64,
    site0: AtomicUsize,
    max: AtomicU64,
    max_start: AtomicUsize,
    max_end: AtomicUsize,
    windows: AtomicU64,
    unpaired: AtomicU32,
    sites_full: AtomicU32,
    sites: [SiteSlot; SITES],
}

impl Track {
    const fn new() -> Self {
        Self {
            open: AtomicBool::new(false),
            t0: AtomicU64::new(0),
            site0: AtomicUsize::new(0),
            max: AtomicU64::new(0),
            max_start: AtomicUsize::new(0),
            max_end: AtomicUsize::new(0),
            windows: AtomicU64::new(0),
            unpaired: AtomicU32::new(0),
            sites_full: AtomicU32::new(0),
            sites: [const { SiteSlot::new() }; SITES],
        }
    }
}

/// Wave 15 (TRACE): called with `(kind, hart, length, open site, close
/// site)` each time [`close`] measures a new longest window on a track. The
/// kernel tracer installs it (Kconfig `KTRACE_CLASS_LAT`); 0 means none.
/// A function address rather than a dependency: this crate sits below the
/// tracer.
static NEW_MAX_HOOK: AtomicUsize = AtomicUsize::new(0);

/// The new-maximum hook's signature: `(kind, hart, length, open site, close site)`.
pub type NewMaxHook = fn(Kind, usize, u64, usize, usize);

/// Install the new-maximum hook (once, at boot).
pub fn set_new_max_hook(f: NewMaxHook) {
    NEW_MAX_HOOK.store(f as usize, core::sync::atomic::Ordering::Release);
}

static TRACKS: [[Track; 2]; HARTS] = [const { [const { Track::new() }, const { Track::new() }] }; HARTS];

#[inline]
fn track(kind: Kind, hart: usize) -> Option<&'static Track> {
    TRACKS.get(hart).map(|t| &t[kind as usize])
}

/// A masked window starts on `hart` at counter value `now`, at `site`.
///
/// If a window is already open on this track its end was never seen: it is
/// discarded (counted in `unpaired`), not extended.
#[inline]
pub fn open(kind: Kind, hart: usize, now: u64, site: usize) {
    let Some(t) = track(kind, hart) else { return };
    if t.open.load(Relaxed) {
        t.unpaired.fetch_add(1, Relaxed);
    }
    t.t0.store(now, Relaxed);
    t.site0.store(site, Relaxed);
    t.open.store(true, Relaxed);
}

/// The window open on `hart` ends at counter value `now`, at `site`.
/// No-op when no window is open.
pub fn close(kind: Kind, hart: usize, now: u64, site: usize) {
    let Some(t) = track(kind, hart) else { return };
    if !t.open.load(Relaxed) {
        return;
    }
    t.open.store(false, Relaxed);
    let len = now.saturating_sub(t.t0.load(Relaxed));
    let start = t.site0.load(Relaxed);
    t.windows.fetch_add(1, Relaxed);
    if len > t.max.load(Relaxed) {
        t.max.store(len, Relaxed);
        t.max_start.store(start, Relaxed);
        t.max_end.store(site, Relaxed);
        let h = NEW_MAX_HOOK.load(Relaxed);
        if h != 0 {
            // SAFETY: only `set_new_max_hook` stores here, from a `NewMaxHook`.
            let f: NewMaxHook = unsafe { core::mem::transmute::<usize, NewMaxHook>(h) };
            f(kind, hart, len, start, site);
        }
    }
    // Open addressing on the site value: the probe starts at its hash and
    // stops at its own slot or the first empty one, so the common case is a
    // couple of loads rather than a scan of the table.
    let h = start.wrapping_mul(0x9E37_79B9_7F4A_7C15_u64 as usize) >> 7;
    let mut shortest = 0usize;
    for i in 0..SITES {
        let k = (h.wrapping_add(i)) % SITES;
        let s = &t.sites[k];
        let cur = s.site.load(Relaxed);
        if cur == start || cur == 0 {
            if cur == 0 {
                s.site.store(start, Relaxed);
            }
            s.count.fetch_add(1, Relaxed);
            if len > s.max.load(Relaxed) {
                s.max.store(len, Relaxed);
                s.end.store(site, Relaxed);
            }
            return;
        }
        if s.max.load(Relaxed) < t.sites[shortest].max.load(Relaxed) {
            shortest = k;
        }
    }
    // Full: a window longer than the shortest kept one replaces it. The
    // evicted site's count is lost; its maximum was below every kept one.
    t.sites_full.fetch_add(1, Relaxed);
    let s = &t.sites[shortest];
    if len > s.max.load(Relaxed) {
        s.site.store(start, Relaxed);
        s.max.store(len, Relaxed);
        s.end.store(site, Relaxed);
        s.count.store(1, Relaxed);
    }
}

/// Is a window open on this track right now?
pub fn is_open(kind: Kind, hart: usize) -> bool {
    track(kind, hart).map(|t| t.open.load(Relaxed)).unwrap_or(false)
}

/// One hart's track, as read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Longest closed window, in counter ticks.
    pub max: u64,
    /// Site that opened it.
    pub max_start: usize,
    /// Site that closed it.
    pub max_end: usize,
    /// Windows closed.
    pub windows: u64,
    /// Windows discarded because their end was never seen.
    pub unpaired: u32,
    /// Windows whose start site found the site table full (each either
    /// evicted the shortest entry or was not kept).
    pub sites_full: u32,
}

/// Read one hart's track.
pub fn summary(kind: Kind, hart: usize) -> Summary {
    let Some(t) = track(kind, hart) else { return Summary::default() };
    Summary {
        max: t.max.load(Relaxed),
        max_start: t.max_start.load(Relaxed),
        max_end: t.max_end.load(Relaxed),
        windows: t.windows.load(Relaxed),
        unpaired: t.unpaired.load(Relaxed),
        sites_full: t.sites_full.load(Relaxed),
    }
}

/// One start site, merged over every hart.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SiteRecord {
    /// The site that opened the windows.
    pub site: usize,
    /// Longest window it opened, in counter ticks, on any hart.
    pub max: u64,
    /// The site that closed that longest window.
    pub end: usize,
    /// Windows it opened, all harts.
    pub count: u32,
}

/// Fill `out` with the start sites of `kind`, longest window first. Returns
/// how many entries were written (at most `out.len()`).
pub fn top_sites(kind: Kind, out: &mut [SiteRecord]) -> usize {
    let mut n = 0usize;
    for h in 0..HARTS {
        let t = &TRACKS[h][kind as usize];
        for s in t.sites.iter() {
            let site = s.site.load(Relaxed);
            if site == 0 {
                continue;
            }
            let rec = SiteRecord { site, max: s.max.load(Relaxed),
                                   end: s.end.load(Relaxed), count: s.count.load(Relaxed) };
            if let Some(e) = out[..n].iter_mut().find(|e| e.site == site) {
                e.count = e.count.saturating_add(rec.count);
                if rec.max > e.max {
                    e.max = rec.max;
                    e.end = rec.end;
                }
                continue;
            }
            if n < out.len() {
                out[n] = rec;
                n += 1;
            } else if let Some(min_i) = (0..n).min_by_key(|&i| out[i].max) {
                if rec.max > out[min_i].max {
                    out[min_i] = rec;
                }
            }
        }
    }
    out[..n].sort_unstable_by(|a, b| b.max.cmp(&a.max));
    n
}

/// Forget every maximum, count and site on every hart. Open windows stay
/// open, so the window in progress on the calling hart is still measured.
pub fn reset() {
    for h in TRACKS.iter() {
        for t in h.iter() {
            t.max.store(0, Relaxed);
            t.max_start.store(0, Relaxed);
            t.max_end.store(0, Relaxed);
            t.windows.store(0, Relaxed);
            t.unpaired.store(0, Relaxed);
            t.sites_full.store(0, Relaxed);
            for s in t.sites.iter() {
                s.site.store(0, Relaxed);
                s.max.store(0, Relaxed);
                s.end.store(0, Relaxed);
                s.count.store(0, Relaxed);
            }
        }
    }
}
