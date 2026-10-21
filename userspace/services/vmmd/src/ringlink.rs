// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The virtual interface a guest NIC is bridged to: a pair of frame rings in
//! shared memory.
//!
//! The interface is a region two parties map: vmmd holds one end (the
//! guest's NIC: it sends into `out`, receives from `in`) and whoever bridges
//! it to a network holds the other (it takes from `out`, sends into `in`).
//! Frames move through the rings with no call; neither side sleeps on the
//! other, the bridge is polled at the model's cadence.
//!
//! Layout (little-endian): four free-running `u32` at 0 (`out_head`,
//! `out_tail`, `in_head`, `in_tail`; the consumer writes a head, the producer
//! a tail), then at [`DATA_AT`] [`SLOTS`] slots of [`SLOT_BYTES`] for `out`
//! and as many for `in`. A slot is `len u16 | pad u16 | frame`.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::net::{Link, FRAME_MAX};

pub const SLOTS: u32 = 8;
pub const SLOT_BYTES: usize = 2048;
const OUT_HEAD: usize = 0;
const OUT_TAIL: usize = 4;
const IN_HEAD: usize = 8;
const IN_TAIL: usize = 12;
const DATA_AT: usize = 0x1000;
/// Bytes of the shared region.
pub const REGION_BYTES: usize = DATA_AT + 2 * SLOTS as usize * SLOT_BYTES;
const _: () = assert!(FRAME_MAX + 4 <= SLOT_BYTES);

/// vmmd's end of the interface.
pub struct RingLink {
    base: *mut u8,
}

impl RingLink {
    /// # Safety
    /// `base` is the start of [`REGION_BYTES`] bytes, 4-aligned, valid for
    /// reads and writes for as long as the link lives, whose other end
    /// follows the layout above.
    pub unsafe fn new(base: *mut u8) -> RingLink {
        RingLink { base }
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        // SAFETY: a 4-aligned `u32` of the region (`new`'s contract).
        unsafe { &*(self.base.add(off) as *const AtomicU32) }
    }

    fn slot(&self, ring_in: bool, i: u32) -> *mut u8 {
        let ring = if ring_in { SLOTS as usize } else { 0 };
        // SAFETY: inside the region.
        unsafe { self.base.add(DATA_AT + (ring + (i % SLOTS) as usize) * SLOT_BYTES) }
    }
}

/// Put `frame` in the next slot of a ring.
fn push(link: &RingLink, ring_in: bool, frame: &[u8]) -> bool {
    let (head, tail) = if ring_in { (IN_HEAD, IN_TAIL) } else { (OUT_HEAD, OUT_TAIL) };
    let t = link.word(tail).load(Ordering::Relaxed);
    if t.wrapping_sub(link.word(head).load(Ordering::Acquire)) >= SLOTS || frame.len() > FRAME_MAX {
        return false;
    }
    let s = link.slot(ring_in, t);
    // SAFETY: the slot is inside the region and is the producer's until the
    // tail moves.
    unsafe {
        core::ptr::copy_nonoverlapping((frame.len() as u16).to_le_bytes().as_ptr(), s, 2);
        core::ptr::copy_nonoverlapping(frame.as_ptr(), s.add(4), frame.len());
    }
    link.word(tail).store(t.wrapping_add(1), Ordering::Release);
    true
}

/// Take the oldest slot of a ring into `buf`: `None` when the ring is empty,
/// `Some(None)` for a slot whose length cannot be (skipped), else the frame's
/// length.
fn pop(link: &RingLink, ring_in: bool, buf: &mut [u8]) -> Option<Option<usize>> {
    let (head, tail) = if ring_in { (IN_HEAD, IN_TAIL) } else { (OUT_HEAD, OUT_TAIL) };
    let h = link.word(head).load(Ordering::Relaxed);
    let avail = link.word(tail).load(Ordering::Acquire).wrapping_sub(h);
    if avail == 0 || avail > SLOTS {
        return None;
    }
    let s = link.slot(ring_in, h);
    let mut l = [0u8; 2];
    // SAFETY: the slot is inside the region and is the consumer's until the
    // head moves.
    unsafe { core::ptr::copy_nonoverlapping(s, l.as_mut_ptr(), 2) };
    // The other end wrote the length; a lie is a dropped slot, not a read.
    let len = u16::from_le_bytes(l) as usize;
    let got = if len <= buf.len() && len <= FRAME_MAX {
        // SAFETY: as above; `len` is within the slot and `buf`.
        unsafe { core::ptr::copy_nonoverlapping(s.add(4), buf.as_mut_ptr(), len) };
        Some(len)
    } else {
        None
    };
    link.word(head).store(h.wrapping_add(1), Ordering::Release);
    Some(got)
}

impl Link for RingLink {
    fn send(&mut self, frame: &[u8]) -> bool {
        push(self, false, frame)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Option<usize> {
        // A slot the other end filled wrongly is skipped, not reported as the
        // end; a ring holds at most SLOTS of them.
        for _ in 0..SLOTS {
            if let Some(n) = pop(self, true, buf)? {
                return Some(n);
            }
        }
        None
    }
}

/// The bridge's end, as the tests play it.
#[cfg(test)]
pub struct Peer(pub RingLink);

#[cfg(test)]
impl Peer {
    /// Take a frame the guest sent.
    pub fn take(&self, buf: &mut [u8]) -> Option<usize> {
        pop(&self.0, false, buf).flatten()
    }

    /// Deliver a frame to the guest.
    pub fn give(&self, frame: &[u8]) -> bool {
        push(&self.0, true, frame)
    }
}
