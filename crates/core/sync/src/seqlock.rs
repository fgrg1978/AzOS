// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// SeqLock — single-writer, multi-reader lock-free synchronization.
///
/// The writer never blocks. Readers detect concurrent writes via an
/// atomic sequence counter and retry. Ideal for data published at high
/// frequency (sensor samples, timestamps) read by many consumers.
///
/// # Protocol
///
/// Writer:
///   1. Increment sequence to odd  (signals "write in progress")
///   2. Write data
///   3. Increment sequence to even (signals "write complete")
///
/// Reader:
///   1. Read sequence (retry if odd — write in progress)
///   2. Copy data
///   3. Re-read sequence — if changed, data may be torn → retry
///
/// # Memory ordering
///
/// - Writer uses `Release` after data write so readers see updated data.
/// - Reader uses `Acquire` before data read so it observes the writer's stores.
/// - Inner spin on odd uses `Relaxed` (TTAS pattern).

use crate::preempt::{critical_section, PreemptGuard};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

/// A SeqLock protecting data of type `T`.
///
/// `T` must be `Copy` because readers may observe partially-written data
/// and must be able to discard and retry without running destructors.
pub struct SeqLock<T: Copy> {
    seq:  AtomicU32,
    data: UnsafeCell<T>,
}

// Safety: SeqLock provides its own synchronization protocol.
// T: Send + Copy is sufficient — writer has exclusive mutable access,
// readers only get copies.
unsafe impl<T: Copy + Send> Send for SeqLock<T> {}
unsafe impl<T: Copy + Send> Sync for SeqLock<T> {}

impl<T: Copy> SeqLock<T> {
    /// Create a new SeqLock with initial data.
    pub const fn new(data: T) -> Self {
        Self {
            seq:  AtomicU32::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Read the protected data, retrying if a write is in progress.
    ///
    /// This never blocks the writer. If contention is high the reader
    /// spins, but each iteration is just two atomic loads + a memcpy.
    #[inline]
    pub fn read(&self) -> T {
        loop {
            // Step 1: wait for even sequence (no write in progress).
            let s1 = self.seq.load(Ordering::Acquire);
            if s1 & 1 != 0 {
                // Writer active — spin until it finishes.
                core::hint::spin_loop();
                continue;
            }

            // Step 2: copy data.
            // Safety: we only read; torn reads are detected by the seq check
            // below — but only if the read is ordered before that check, which
            // is what step 2b exists for.
            let value = unsafe { core::ptr::read_volatile(self.data.get()) };

            // Step 2b: **the fence this reader was missing.**
            //
            // An `Acquire` LOAD orders accesses that come after it. It says
            // nothing about accesses that come before, so nothing stopped the
            // data read above from being reordered past the `s2` load below.
            // On a weakly ordered machine — and RISC-V's RVWMO is one, as is
            // AArch64 — the check could then compare two sequence values taken
            // around a data read that actually happened outside that window:
            // a torn read that the mechanism reports as clean.
            //
            // x86-64's TSO would hide this entirely, which is why it is worth
            // writing down rather than just fixing: the bug is invisible on the
            // machine most people would reach for to reproduce it.
            //
            // `world_state.rs`'s hand-rolled reader already had this fence.
            // One class, two instances, and the broken one was the general
            // primitive rather than the copy — which is the direction that
            // matters, since this is the one anything new would reuse.
            core::sync::atomic::fence(Ordering::Acquire);

            // Step 3: verify sequence didn't change during our read.
            let s2 = self.seq.load(Ordering::Relaxed);
            if s1 == s2 {
                return value;
            }
            // Sequence changed — data may be torn, retry.
            core::hint::spin_loop();
        }
    }

    /// Begin a write. Returns a guard that must be used to complete the write.
    ///
    /// # Safety contract
    /// Only ONE writer may call this at a time. If multiple writers are
    /// possible, the caller must serialize them externally (e.g. with a
    /// SpinLock around the write call, or by design — single producer).
    #[inline]
    pub fn write(&self) -> SeqLockWriteGuard<'_, T> {
        // Preemption off for the write, and taken BEFORE the sequence goes odd.
        //
        // A reader spins while the counter is odd. If the writer is preempted
        // between the two bumps by a HIGHER-PRIORITY reader on the SAME hart,
        // that reader spins forever: strict priority without aging never lets
        // the writer back on to finish. It is the identical hazard K-C29 closed
        // for `SpinLock`, and this hand-rolled spin simply never got the same
        // treatment -- `scheduler.rs` even names this exact deadlock as its
        // reason for NOT using a `SeqLock` for the ready ring.
        //
        // No live task/hart pairing materialises it today: every `Channel<T>`
        // publisher either runs on a different hart from its readers or
        // outranks them. That is a fact about the current placement table, not
        // about this type, and nothing in the API stops the next reassignment
        // from creating the pairing.
        //
        // The cost is proportional to the WRITE, not the read -- a few stores --
        // which is what makes this affordable for a type whose whole value is
        // that the writer never blocks.
        let _preempt = critical_section();
        self.seq.fetch_add(1, Ordering::Acquire);
        SeqLockWriteGuard { lock: self, _preempt }
    }
}

/// RAII guard for a SeqLock write operation.
///
/// Dereferences to `&mut T` for writing. Completes the write (bumps
/// sequence to even) on drop.
pub struct SeqLockWriteGuard<'a, T: Copy> {
    lock: &'a SeqLock<T>,
    /// Declared last so it drops last: the sequence returns to even, and only
    /// then is preemption re-enabled. The other order would leave a window
    /// where a reader can still see an odd counter with the writer
    /// preemptible.
    _preempt: PreemptGuard,
}

impl<T: Copy> core::ops::Deref for SeqLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: Copy> core::ops::DerefMut for SeqLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: Copy> Drop for SeqLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        // Even sequence = write complete. Release ensures data stores
        // are visible before the sequence update.
        self.lock.seq.fetch_add(1, Ordering::Release);
    }
}
