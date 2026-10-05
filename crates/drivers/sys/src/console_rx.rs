// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Who reads console input (RFC-0055 §5.4): one owner, claimed atomically.
//!
//! The UART fills one RX ring, and two readers of one ring steal bytes from
//! each other: a byte the kernel shell's `readline` takes is a byte the user
//! shell never sees. So input has exactly one owner at a time. The user shell
//! claims it with its first `SYS_CONSOLE_WAIT`; the recovery console claims it
//! as [`RX_OWNER_KERNEL`] before its first `readline`. Whoever claims second
//! is refused (`-EBUSY` for ring 3; the recovery console stays parked). The
//! owner's exit releases it (the kernel's task-exit hook).
//!
//! Pure (core atomics only), so `tests/host/drivers-tests` pulls it in with
//! `#[path]`.

use core::sync::atomic::{AtomicU32, Ordering};

/// No owner yet: the next claim wins.
pub const RX_OWNER_NONE: u32 = 0;
/// The recovery console (a kernel task, named by this marker rather than by
/// its TID so a ring-3 TID can never equal it).
pub const RX_OWNER_KERNEL: u32 = u32::MAX;

/// What a claim found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    /// The caller is now the owner.
    Got,
    /// The caller already was.
    Already,
    /// Someone else is: their identity.
    Busy(u32),
}

/// The input owner, and (wave 13) the task it lent input to.
pub struct RxOwner(AtomicU32, AtomicU32);

impl RxOwner {
    /// No owner.
    pub const fn new() -> Self {
        Self(AtomicU32::new(RX_OWNER_NONE), AtomicU32::new(0))
    }

    /// Wave 13: the owner `owner` lends input to task `to` (its foreground
    /// Linux job). Refused unless `owner` owns input now and nothing is lent.
    pub fn lend(&self, owner: u32, to: u32) -> bool {
        to != 0
            && owner != RX_OWNER_NONE
            && self.owner() == owner
            && self.1.compare_exchange(0, to, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// The task input is lent to, 0 if none.
    pub fn lendee(&self) -> u32 {
        self.1.load(Ordering::Acquire)
    }

    /// End the lend if `who` holds it (its exit). Returns whether it did.
    pub fn end_lend(&self, who: u32) -> bool {
        who != 0 && self.1.compare_exchange(who, 0, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Claim input for `who` (a TID, or [`RX_OWNER_KERNEL`]). `who` must not
    /// be [`RX_OWNER_NONE`].
    pub fn claim(&self, who: u32) -> Claim {
        if who == RX_OWNER_NONE {
            return Claim::Busy(self.owner());
        }
        match self.0.compare_exchange(RX_OWNER_NONE, who, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Claim::Got,
            Err(cur) if cur == who => Claim::Already,
            Err(cur) => Claim::Busy(cur),
        }
    }

    /// Release input if `who` owns it. Returns whether it did.
    pub fn release(&self, who: u32) -> bool {
        let r = who != RX_OWNER_NONE
            && self.0.compare_exchange(who, RX_OWNER_NONE, Ordering::AcqRel, Ordering::Acquire).is_ok();
        if r {
            // An owner that goes takes its lend with it.
            self.1.store(0, Ordering::Release);
        }
        r
    }

    /// The current owner, [`RX_OWNER_NONE`] if none.
    pub fn owner(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }
}

impl Default for RxOwner {
    fn default() -> Self {
        Self::new()
    }
}
