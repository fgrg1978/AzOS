// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-site counters of bounded sleeps that ended by their expiry with no
//! wake: the signature of a lost wake.
//!
//! A sleep that waits for another task or a device carries a deadline of one
//! slice ([`SLICE_NS`], Kconfig `WAIT_SLICE_US`): [`WaitQueue::wait_if_for`]
//! and the block request layer's sleepers. A dropped wake then costs the
//! sleeper one slice instead of the task. That makes it survivable, and
//! invisible; these counters make it visible. Per site class, two numbers
//! that never decrease:
//!
//! * **expired**: the sleep ended at its deadline and nobody had woken the
//!   task (for a `WaitQueue` sleeper: its entry was still on the list, so no
//!   waker had popped it). A long wait for a slow event ends this way
//!   legitimately, again and again.
//! * **lost**: of those, the ones whose condition had **already become true**
//!   by the time the slice ended. The event happened and the wake did not
//!   come within a slice: a dropped wake, or a waker that was delayed past
//!   the slice between publishing the event and waking (so a high count under
//!   load is a lower-quality signal than a nonzero count on an idle board).
//!
//! The kernel exports them through the introspection tree
//! (`metrics/sync/<site>/{expired, lost}`, `kernel/src/boot/inspect_metrics.rs`),
//! so a boot can confirm or refute a lost wake at a site by reading two
//! words, with no probe in the sleeping path beyond one relaxed add on expiry.
//!
//! [`WaitQueue::wait_if_for`]: crate::waitqueue::WaitQueue::wait_if_for

use core::sync::atomic::{AtomicU64, Ordering};

/// Longest a bounded sleep lasts without a wake (Kconfig `WAIT_SLICE_US`).
pub const SLICE_NS: u64 = azos_limits::WAIT_SLICE_US as u64 * 1_000;

/// The places that sleep on a deadline and are counted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Site {
    /// A waiter for a block request to finish (`queue::ReqQueue::sleep`).
    BlockDone,
    /// A submitter waiting for a free slot of its hart's queue.
    BlockSpace,
    /// An updater waiting for a FAT-sector claim (`fat32::fat_sector_claim`).
    FatSector,
    /// A flusher waiting for the FAT write-back claim (`fat32::wb_claim`).
    FatWriteback,
    /// A task waiting for a `claim::Claim` (the F1 exchange).
    Claim,
    /// A request waiting for its turn at a controller (`dev_queue::DevQueue`).
    DevQueue,
    /// A unit waiting for its turn at the ADS1115 bus.
    Ads1115,
    /// A fault or fork waiting for a page store to end (`pager::MARKER_WAIT`).
    PagerStore,
    /// A fault waiting for a swap step to end (`pager::SWAP_WAIT`).
    PagerSwap,
}

/// How many sites there are.
pub const SITES: usize = 9;

impl Site {
    /// Every site, in the order of the counters.
    pub const ALL: [Site; SITES] = [
        Site::BlockDone,
        Site::BlockSpace,
        Site::FatSector,
        Site::FatWriteback,
        Site::Claim,
        Site::DevQueue,
        Site::Ads1115,
        Site::PagerStore,
        Site::PagerSwap,
    ];

    /// The node name under `metrics/sync/`.
    pub const fn name(self) -> &'static str {
        match self {
            Site::BlockDone => "block_done",
            Site::BlockSpace => "block_space",
            Site::FatSector => "fat_sector",
            Site::FatWriteback => "fat_writeback",
            Site::Claim => "claim",
            Site::DevQueue => "dev_queue",
            Site::Ads1115 => "ads1115",
            Site::PagerStore => "pager_store",
            Site::PagerSwap => "pager_swap",
        }
    }
}

static EXPIRED: [AtomicU64; SITES] = [const { AtomicU64::new(0) }; SITES];
static LOST: [AtomicU64; SITES] = [const { AtomicU64::new(0) }; SITES];

/// A sleep at `site` ended by its deadline with no wake; `condition_met`: its
/// condition had already become true.
#[inline]
pub fn note_expiry(site: Site, condition_met: bool) {
    EXPIRED[site as usize].fetch_add(1, Ordering::Relaxed);
    if condition_met {
        LOST[site as usize].fetch_add(1, Ordering::Relaxed);
    }
}

/// `(expired, lost)` of `site` since boot.
pub fn stats(site: Site) -> (u64, u64) {
    (EXPIRED[site as usize].load(Ordering::Relaxed), LOST[site as usize].load(Ordering::Relaxed))
}
