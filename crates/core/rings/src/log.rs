// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! [`Log`]: one writer, overwrite-oldest, per-reader cursors.
//!
//! Item `s` (1-based; item 0 is the initial value) lives in slot `s % N` and
//! that slot's stamp is `2s - 1` while the writer is storing it and `2s` once
//! it is whole. A reader that wants item `c` expects stamp `2c`:
//!
//! * `2c`     — whole: copy it out, then re-read the stamp; unchanged = no tear.
//! * `2c - 1` — the writer is mid-store of exactly this item: spin.
//! * `< 2c-1` — not published yet.
//! * `> 2c`   — a newer item has taken the slot (or is taking it): overrun.
//!
//! The writer never reads a stamp it did not write and never waits.

use crate::{Doorbell, Pad, CLAIM_PRODUCER};
use core::cell::UnsafeCell;
use core::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};

pub struct Log<T: Copy, const N: usize, D: Doorbell = ()> {
    /// Items published (the writer owns it), on a line of its own.
    head: Pad<AtomicU64>,
    claims: AtomicU32,
    stamps: [AtomicU64; N],
    data: UnsafeCell<[T; N]>,
    bell: D,
}

// Safety: the writer is unique (claimed once) and readers only copy out under
// the stamp protocol.
unsafe impl<T: Copy + Send, const N: usize, D: Doorbell + Sync> Sync for Log<T, N, D> {}
unsafe impl<T: Copy + Send, const N: usize, D: Doorbell + Send> Send for Log<T, N, D> {}

enum Try<T> {
    Got(T),
    /// Not published yet.
    Empty,
    /// The slot has moved on to a newer item.
    Overrun,
    /// The writer is mid-store of this very item.
    Spin,
}

impl<T: Copy, const N: usize> Log<T, N, ()> {
    /// A log whose item 0 is `init` (what `latest` returns before any publish).
    pub const fn new(init: T) -> Self {
        Self::with_bell(init, ())
    }
}

impl<T: Copy, const N: usize, D: Doorbell> Log<T, N, D> {
    pub const fn with_bell(init: T, bell: D) -> Self {
        assert!(N >= 1);
        Log {
            head: Pad(AtomicU64::new(0)),
            claims: AtomicU32::new(0),
            stamps: [const { AtomicU64::new(0) }; N],
            data: UnsafeCell::new([init; N]),
            bell,
        }
    }

    /// Items published so far (the newest item's sequence number; 0 = none).
    #[inline]
    pub fn head(&self) -> u64 {
        self.head.0.load(Ordering::Acquire)
    }

    /// The one writer. `None` if it is already out.
    pub fn writer(&self) -> Option<Writer<'_, T, N, D>> {
        let old = self.claims.fetch_or(CLAIM_PRODUCER, Ordering::AcqRel);
        if old & CLAIM_PRODUCER != 0 {
            return None;
        }
        Some(Writer { log: self })
    }

    /// A reader that sees items published from now on.
    pub fn reader(&self) -> Reader<'_, T, N, D> {
        Reader { log: self, cursor: self.head() + 1 }
    }

    /// A reader that starts at the oldest item still retained.
    pub fn reader_oldest(&self) -> Reader<'_, T, N, D> {
        let h = self.head();
        Reader { log: self, cursor: (h + 1).saturating_sub(N as u64).max(1) }
    }

    /// The newest item and its sequence number (0 = the initial value).
    /// Never blocks the writer; retries while the writer is storing.
    pub fn latest(&self) -> (u64, T) {
        loop {
            let h = self.head();
            match self.try_read(h) {
                Try::Got(v) => return (h, v),
                // Mid-store, or already one item behind: look again.
                _ => core::hint::spin_loop(),
            }
        }
    }

    /// [`latest`](Self::latest) into the caller's storage: for a big `T` (a
    /// whole lidar revolution) the copy lands where the caller keeps it,
    /// not in a frame of this function and again in the caller's. Returns
    /// the item's sequence number.
    pub fn latest_into(&self, out: &mut T) -> u64 {
        loop {
            let h = self.head();
            match self.try_read_into(h, out) {
                Try::Got(()) => return h,
                // Mid-store, or already one item behind: look again.
                _ => core::hint::spin_loop(),
            }
        }
    }

    fn try_read(&self, c: u64) -> Try<T> {
        let mut v = core::mem::MaybeUninit::<T>::uninit();
        match self.try_read_into(c, v.as_mut_ptr()) {
            // Safety: `Got` means the whole item was copied in.
            Try::Got(()) => Try::Got(unsafe { v.assume_init() }),
            Try::Empty => Try::Empty,
            Try::Overrun => Try::Overrun,
            Try::Spin => Try::Spin,
        }
    }

    /// Copy item `c` into `*out`. `Got(())` means `*out` holds that whole
    /// item; any other answer leaves `*out` unspecified.
    fn try_read_into(&self, c: u64, out: *mut T) -> Try<()> {
        let slot = (c % N as u64) as usize;
        let s1 = self.stamps[slot].load(Ordering::Acquire);
        let want = 2 * c;
        if s1 == want {
            // Safety: copy-out of a plain `Copy` value straight into the
            // caller's storage (no stack temporary, so a big `T` costs one
            // copy); a concurrent store is caught by the stamp re-read below.
            unsafe { core::ptr::copy_nonoverlapping((self.data.get() as *const T).add(slot), out, 1) };
            #[cfg(not(feature = "canary-no-fence"))]
            fence(Ordering::Acquire);
            #[cfg(feature = "canary-no-recheck")]
            return Try::Got(());
            #[cfg(not(feature = "canary-no-recheck"))]
            {
                // A tear means the slot moved to a newer item.
                if self.stamps[slot].load(Ordering::Relaxed) == s1 {
                    Try::Got(())
                } else {
                    Try::Overrun
                }
            }
        } else if c > 0 && s1 == want - 1 {
            Try::Spin
        } else if s1 < want {
            Try::Empty
        } else {
            Try::Overrun
        }
    }
}

/// The only handle that can publish. Not `Clone`; dropping it lets
/// [`Log::writer`] hand out another.
pub struct Writer<'a, T: Copy, const N: usize, D: Doorbell = ()> {
    log: &'a Log<T, N, D>,
}

impl<T: Copy, const N: usize, D: Doorbell> Writer<'_, T, N, D> {
    /// Store the next item, overwriting the oldest when the log is full.
    /// Never waits. Returns the item's sequence number.
    pub fn publish(&mut self, v: T) -> u64 {
        let log = self.log;
        let s = log.head.0.load(Ordering::Relaxed) + 1;
        let slot = (s % N as u64) as usize;
        log.stamps[slot].store(2 * s - 1, Ordering::Relaxed);
        fence(Ordering::Release);
        // Safety: this is the only writer, and readers tolerate a torn copy.
        unsafe { core::ptr::write_volatile((log.data.get() as *mut T).add(slot), v) };
        log.stamps[slot].store(2 * s, Ordering::Release);
        log.head.0.store(s, Ordering::Release);
        log.bell.ring(s);
        s
    }

    /// Items published so far.
    pub fn head(&self) -> u64 {
        self.log.head.0.load(Ordering::Relaxed)
    }
}

impl<T: Copy, const N: usize, D: Doorbell> Drop for Writer<'_, T, N, D> {
    fn drop(&mut self) {
        self.log.claims.fetch_and(!CLAIM_PRODUCER, Ordering::AcqRel);
    }
}

/// What [`Reader::next`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next<T> {
    /// Nothing newer than the cursor.
    Empty,
    Item(T),
    /// The reader fell behind: this many items were overwritten before it saw
    /// them. The cursor has jumped to the oldest retained item.
    Overrun(u64),
}

/// A private cursor into a [`Log`]. Any number may exist; they never affect
/// the writer or each other.
pub struct Reader<'a, T: Copy, const N: usize, D: Doorbell = ()> {
    log: &'a Log<T, N, D>,
    cursor: u64,
}

impl<T: Copy, const N: usize, D: Doorbell> Reader<'_, T, N, D> {
    /// The sequence number of the item `next` will return.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn next(&mut self) -> Next<T> {
        loop {
            match self.log.try_read(self.cursor) {
                Try::Got(v) => {
                    self.cursor += 1;
                    return Next::Item(v);
                }
                Try::Empty => return Next::Empty,
                Try::Spin => core::hint::spin_loop(),
                Try::Overrun => {
                    let h = self.log.head();
                    let oldest = (h + 1).saturating_sub(N as u64).max(1);
                    let lost = oldest.saturating_sub(self.cursor);
                    // Already past `oldest` (the writer is mid-store of the
                    // head): nothing was lost yet; look again.
                    if lost == 0 {
                        core::hint::spin_loop();
                        continue;
                    }
                    self.cursor = oldest;
                    // Canary: skip ahead silently, the loss goes unreported.
                    #[cfg(feature = "canary-no-overrun")]
                    continue;
                    #[cfg(not(feature = "canary-no-overrun"))]
                    return Next::Overrun(lost);
                }
            }
        }
    }
}
