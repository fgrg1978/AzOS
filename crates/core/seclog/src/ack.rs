// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The sink's page (`MemObj klog.ack`): where `logd` says which security
//! records it lost, so the kernel declares that loss in the chain
//! ([`crate::kind::SINK_LOSS`]) with the classes only the kernel knows.
//!
//! `logd` writes, the kernel's sealer reads. A claim is a range of sequence
//! numbers the sink never wrote: the ring lapped its reader, or it started
//! (a boot, a restart) after the ring had dropped records the previous
//! reader had not written. The kernel declares only the part of a claim the
//! ring has really dropped and the sealer folded, so a sink that claims a
//! loss to hide records it has can hide only what was gone anyway; and the
//! classes it declares say what the hidden records were.

use core::sync::atomic::{AtomicU64, Ordering};

/// Claims the page holds: the kernel reads them every pass.
pub const CLAIMS: usize = 8;

/// The page's layout.
#[repr(C)]
pub struct Page {
    /// The sequence number of the next security record the sink will read:
    /// every one before it is written or claimed lost. What a new reader
    /// starts from.
    pub next: AtomicU64,
    /// Claims written since the page was made; claim `k` is in slot
    /// `k % CLAIMS`.
    pub claims: AtomicU64,
    /// `(first, count)` of each claim.
    pub ranges: [[AtomicU64; 2]; CLAIMS],
}

const _: () = assert!(core::mem::size_of::<Page>() <= 4096);

impl Page {
    /// The sink: it lost `count` records from `first`.
    pub fn claim(&self, first: u64, count: u64) {
        if count == 0 {
            return;
        }
        let k = self.claims.load(Ordering::Relaxed);
        let slot = &self.ranges[(k % CLAIMS as u64) as usize];
        slot[0].store(first, Ordering::Relaxed);
        slot[1].store(count, Ordering::Relaxed);
        self.claims.store(k + 1, Ordering::Release);
    }

    /// The kernel: the claims after the `seen` first ones, oldest first, and
    /// how many there are now. A sink that wrote more than [`CLAIMS`] since
    /// the last read loses the oldest: `f` is given `None` for each.
    pub fn read_claims(&self, seen: u64, mut f: impl FnMut(Option<(u64, u64)>)) -> u64 {
        let now = self.claims.load(Ordering::Acquire);
        let from = seen.max(now.saturating_sub(CLAIMS as u64));
        for _ in seen..from {
            f(None);
        }
        for k in from..now {
            let slot = &self.ranges[(k % CLAIMS as u64) as usize];
            f(Some((slot[0].load(Ordering::Relaxed), slot[1].load(Ordering::Relaxed))));
        }
        now
    }
}
