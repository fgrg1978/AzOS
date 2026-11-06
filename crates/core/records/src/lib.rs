// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The kernel's record substrate: where the kernel log, the decision records
//! and the actuation telemetry are written, one ring per source behind one
//! envelope (the layout, the protocol and the reader are
//! `azos_rings::region::record`).
//!
//! # Two regions, one handover
//!
//! The first records are written before the page allocator exists, so until
//! [`attach`] they go to a small region in `.bss` (the kernel log's ring of
//! Kconfig `KLOG_EARLY_ENTRIES`, the decisions' ring at its full depth).
//! `attach` is called once from `kernel_main` with a kernel-owned memory
//! object that ring 3 maps read-only (`MemObj klog.ring`, `logd`'s row): it
//! formats it, copies every record of the early region into it under its own
//! sequence number (a decision's id names the same record before and after),
//! and switches the producers over. Without the kernel log (Kconfig `KLOG`
//! off) there is no sink to read a shared region and the early region is
//! where the records stay.
//!
//! The ring set is Kconfig's: a source the build does not keep has no ring.

#![no_std]

use azos_rings::region::record::{self as rec, Ring, RingSpec, Writer, ENV_BYTES};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicPtr, Ordering};

pub use azos_rings::region::record::{self as record, Head, Payload, CLOCK_TIMEBASE, SOURCE_DECISION, SOURCE_KLOG, SOURCE_TELEMETRY};

/// The kernel log keeps records (Kconfig `KLOG`); its sink, `logd`, reads
/// the shared region, which exists exactly then.
pub const KLOG: bool = azos_limits::KLOG;
/// The decision records keep a ring (Kconfig `DECISION_RECORDS_DEV`).
pub const DECISIONS: bool = azos_limits::DECISION_RECORDS_DEV;

/// Payload bytes of a kernel log record (`azos_drv_sys::klog::wire`'s layout).
pub const KLOG_PAYLOAD: usize = 288;
/// Payload bytes of a decision record (`azos_decision`'s layout).
pub const DECISION_PAYLOAD: usize = 32;

const fn ring(source: u8, payload: usize, entries: usize) -> RingSpec {
    RingSpec { source, slot_bytes: (ENV_BYTES + payload) as u32, entries: entries as u32 }
}

const MAX: usize = 2;

const fn layout(early: bool) -> ([RingSpec; MAX], usize) {
    let mut r = [ring(0, 8, 1); MAX];
    let mut n = 0;
    if KLOG {
        let e = if early { azos_limits::KLOG_EARLY_ENTRIES } else { azos_limits::KLOG_ENTRIES };
        r[n] = ring(SOURCE_KLOG, KLOG_PAYLOAD, e as usize);
        n += 1;
    }
    if DECISIONS {
        r[n] = ring(SOURCE_DECISION, DECISION_PAYLOAD, azos_limits::DECISION_RECORDS_ENTRIES as usize);
        n += 1;
    }
    (r, n)
}

const EARLY_L: ([RingSpec; MAX], usize) = layout(true);
const FULL_L: ([RingSpec; MAX], usize) = layout(false);
/// The rings of the `.bss` region, in order.
pub const EARLY_RINGS: &[RingSpec] = EARLY_L.0.split_at(EARLY_L.1).0;
/// The rings of the shared region, in order.
pub const RINGS: &[RingSpec] = FULL_L.0.split_at(FULL_L.1).0;

const _: () = {
    let mut i = 0;
    while i < RINGS.len() {
        assert!(RINGS[i].entries.is_power_of_two(), "KLOG_ENTRIES, KLOG_EARLY_ENTRIES and DECISION_RECORDS_ENTRIES must be powers of two");
        assert!(EARLY_RINGS[i].entries.is_power_of_two(), "KLOG_EARLY_ENTRIES must be a power of two");
        i += 1;
    }
};

/// Bytes of the shared region.
pub const REGION_BYTES: usize = rec::region_bytes(RINGS);
const EARLY_BYTES: usize = if RINGS.is_empty() { 0 } else { rec::region_bytes(EARLY_RINGS) };

const fn index(rings: &[RingSpec], source: u8) -> Option<usize> {
    let mut i = 0;
    while i < rings.len() {
        if rings[i].source == source {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[repr(C, align(64))]
struct Early(UnsafeCell<[u8; EARLY_BYTES]>);

// SAFETY: every access is through the record protocol's atomics.
unsafe impl Sync for Early {}

/// The early region: its header built at compile time, its slots zero.
static EARLY: Early = Early(UnsafeCell::new(early_image()));

const fn early_image() -> [u8; EARLY_BYTES] {
    let mut img = [0u8; EARLY_BYTES];
    if EARLY_BYTES != 0 {
        let h = rec::header(EARLY_RINGS, 0);
        let mut i = 0;
        while i < rec::HDR_BYTES {
            img[i] = h[i];
            i += 1;
        }
    }
    img
}

/// The shared region once [`attach`]ed; null before (the producers write
/// [`EARLY`]).
static CURRENT: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());

#[inline(always)]
fn place(source: u8) -> Option<(*mut u8, RingSpec)> {
    let p = CURRENT.load(Ordering::Acquire);
    let (base, rings) = if p.is_null() { (EARLY.0.get() as *mut u8, EARLY_RINGS) } else { (p, RINGS) };
    let i = index(rings, source)?;
    // SAFETY: the ring's offset inside the region its layout describes.
    Some((unsafe { base.add(rec::ring_offset(rings, i)) }, rings[i]))
}

/// The ring of `source`, to write; `None` when the build keeps none.
#[inline(always)]
pub fn writer(source: u8) -> Option<Writer> {
    // SAFETY: the kernel owns both regions; they live for the whole run.
    place(source).map(|(r, spec)| unsafe { Writer::at(r, spec) })
}

/// The ring of `source`, to read.
#[inline]
pub fn reader(source: u8) -> Option<Ring> {
    // SAFETY: as `writer`.
    place(source).map(|(r, spec)| unsafe { Ring::at(r, spec) })
}

/// What [`attach`] could not carry over: per source, the records the early
/// region had already overwritten (or the shared ring is too small to keep).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Handover {
    pub klog_lost: u64,
    pub decisions_lost: u64,
}

/// Hand the records over to the region at `base` (`bytes` long, zeroed,
/// 64-aligned, kernel-owned and never freed): format it, copy every early
/// record into it under its own sequence number, and switch the producers.
/// `None` without the kernel log, when the region is too small, or the
/// second time.
///
/// # Safety
/// Boot, once, on the boot hart with interrupts masked and no other hart
/// started: no producer is mid-store in either region while the pointer
/// changes. `base` is used by nothing else.
pub unsafe fn attach(base: *mut u8, bytes: usize, ts_hz: u64) -> Option<Handover> {
    if !KLOG || bytes < REGION_BYTES || !CURRENT.load(Ordering::Relaxed).is_null() {
        return None;
    }
    let early = EARLY.0.get() as *mut u8;
    let mut h = Handover::default();
    // SAFETY: the caller's region, zeroed and ours; the early one is idle.
    unsafe { rec::format(base, RINGS, ts_hz) };
    for (i, spec) in RINGS.iter().enumerate() {
        let Some(e) = index(EARLY_RINGS, spec.source) else { continue };
        // SAFETY: both rings lie inside their regions, by their layouts.
        let (from, to) = unsafe {
            (
                Ring::at(early.add(rec::ring_offset(EARLY_RINGS, e)), EARLY_RINGS[e]),
                Writer::at(base.add(rec::ring_offset(RINGS, i)), *spec),
            )
        };
        // SAFETY: the new ring is empty; nothing writes either meanwhile.
        unsafe { to.replay(&from) };
        // SAFETY: the ring just written.
        let kept = unsafe { Ring::at(base.add(rec::ring_offset(RINGS, i)), *spec) }.oldest();
        match spec.source {
            SOURCE_KLOG => h.klog_lost = kept,
            SOURCE_DECISION => h.decisions_lost = kept,
            _ => {}
        }
    }
    CURRENT.store(base, Ordering::Release);
    Some(h)
}
