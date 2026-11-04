// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The monitor's frozen-after-boot state: the invariant mask `probe` reports,
//! the violation ring, and the one PSCI entry the kernel is allowed to resume
//! at. All of it lives in the image's `.bss` (zero-filled into the blob), so
//! the monitor carves it at link time and never allocates.

use azos_hyp_api::{Ring, Violation};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Records held in the ring before the oldest is overwritten.
pub const RING_LEN: usize = 64;

pub struct Hyp {
    inv: AtomicU64,
    /// The one EL1 entry a `CPU_ON`/resume may use (F3). 0 = not yet set.
    legal_entry: AtomicU64,
    ring_lock: SpinLock,
    ring: UnsafeCell<Ring<RING_LEN>>,
    inited: AtomicBool,
}

// The monitor is single-threaded per PE at init and serializes the ring with
// its own lock; the UnsafeCell is reached only under that lock.
unsafe impl Sync for Hyp {}

pub static HYP: Hyp = Hyp {
    inv: AtomicU64::new(0),
    legal_entry: AtomicU64::new(0),
    ring_lock: SpinLock::new(),
    ring: UnsafeCell::new(Ring::new()),
    inited: AtomicBool::new(false),
};

impl Hyp {
    /// Primary-only, once: nothing to pre-fill today beyond marking the ring
    /// live, but it is the single place later fronts seed frozen state.
    pub fn init_once(&self) {
        self.inited.store(true, Ordering::Release);
    }

    pub fn set_invariant(&self, bit: u64) {
        self.inv.fetch_or(bit, Ordering::AcqRel);
    }

    pub fn invariants(&self) -> u64 {
        self.inv.load(Ordering::Acquire)
    }

    /// F3: record the single legal entry on the first `CPU_ON`, refuse a change.
    /// Returns the entry in force.
    pub fn legal_entry_or_set(&self, entry: u64) -> u64 {
        match self.legal_entry.compare_exchange(0, entry, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => entry,
            Err(cur) => cur,
        }
    }

    pub fn ring_push(&self, v: Violation) {
        self.ring_lock.lock();
        unsafe { (*self.ring.get()).push(v) };
        self.ring_lock.unlock();
    }

    pub fn ring_read(&self, cursor: u64) -> Option<(u64, Violation)> {
        self.ring_lock.lock();
        let r = unsafe { (*self.ring.get()).read(cursor) };
        self.ring_lock.unlock();
        r
    }
}

/// A bare test-and-set lock; EL2 runs with interrupts masked, so it is never
/// held across a sleep and the bounded critical sections keep it short.
pub struct SpinLock(AtomicBool);

impl SpinLock {
    pub const fn new() -> Self {
        SpinLock(AtomicBool::new(false))
    }

    pub fn lock(&self) {
        while self.0.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
    }

    pub fn unlock(&self) {
        self.0.store(false, Ordering::Release);
    }
}
