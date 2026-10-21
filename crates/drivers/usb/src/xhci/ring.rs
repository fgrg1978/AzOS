// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The rings of an xHCI controller (xHCI 1.2, section 4.9): the producer ring
//! (command ring, transfer rings) with its cycle bit and Link TRB, and the
//! consumer side of the event ring.
//!
//! One page is one ring: [`RING_TRBS`] entries, the last of which is a Link
//! TRB back to the first that toggles the cycle bit. A TRB belongs to the
//! consumer while its cycle bit equals the consumer's cycle state; the
//! producer starts at cycle 1 over a zeroed page and flips its state each time
//! it wraps over the Link TRB, so a stale entry from the previous lap never
//! looks valid.

use super::trb::{Trb, C_CYCLE, TRB_BYTES};
use crate::hw::{DmaBuf, Memory, PAGE};

/// TRBs in a one-page ring, Link TRB included.
pub const RING_TRBS: usize = PAGE / TRB_BYTES;

/// Writing a TRB: parameter and status first, the control word (which holds
/// the cycle bit) last and behind a fence, so the controller never sees a
/// half-written entry as valid.
fn put(buf: &DmaBuf, idx: usize, t: Trb, cycle: bool) {
    let o = idx * TRB_BYTES;
    buf.w64(o, t.param);
    buf.w32(o + 8, t.status);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    buf.w32(o + 12, (t.control & !C_CYCLE) | cycle as u32);
}

fn get(buf: &DmaBuf, idx: usize) -> Trb {
    let o = idx * TRB_BYTES;
    let control = buf.r32(o + 12);
    core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
    Trb { param: buf.r64(o), status: buf.r32(o + 8), control }
}

/// A ring the driver writes and the controller reads.
pub struct ProducerRing {
    buf: DmaBuf,
    enq: usize,
    cycle: bool,
}

impl ProducerRing {
    /// A ring over the zeroed page `buf`.
    pub fn new(buf: DmaBuf) -> ProducerRing {
        debug_assert!(buf.len() >= PAGE);
        ProducerRing { buf, enq: 0, cycle: true }
    }

    pub fn buf(&self) -> DmaBuf {
        self.buf
    }
    /// The bus address of the first TRB: what a context's dequeue pointer is
    /// set to.
    pub fn base(&self) -> u64 {
        self.buf.bus()
    }
    /// The dequeue pointer value for a context: the enqueue position and the
    /// cycle state the controller must start with there.
    pub fn enqueue_ptr(&self) -> (u64, bool) {
        (self.buf.bus_at(self.enq * TRB_BYTES), self.cycle)
    }
    pub fn cycle(&self) -> bool {
        self.cycle
    }

    /// Index of the TRB at bus address `bus`, if it lies in this ring.
    pub fn index_of(&self, bus: u64) -> Option<usize> {
        let off = bus.checked_sub(self.buf.bus())? as usize;
        (off < RING_TRBS * TRB_BYTES && off % TRB_BYTES == 0).then_some(off / TRB_BYTES)
    }

    /// TRB positions one transfer descriptor may take at most. A TD longer
    /// than this cannot be queued whatever is in flight.
    pub const MAX_TD: usize = RING_TRBS - 4;

    fn advance<M: Memory>(&mut self, m: &M) {
        self.enq += 1;
        if self.enq == RING_TRBS - 1 {
            // The Link TRB takes the current cycle so the controller follows
            // it, then the producer flips: the next lap's entries carry the
            // other value.
            put(&self.buf, self.enq, Trb::link(self.buf.bus(), true), self.cycle);
            m.to_device(self.buf.cpu().wrapping_add(self.enq * TRB_BYTES), TRB_BYTES);
            #[cfg(not(feature = "canary-cycle"))]
            {
                self.cycle = !self.cycle;
            }
            self.enq = 0;
        }
    }

    /// Queue one TRB; the bus address it was written at.
    pub fn push<M: Memory>(&mut self, m: &M, t: Trb) -> u64 {
        let at = self.buf.bus_at(self.enq * TRB_BYTES);
        put(&self.buf, self.enq, t, self.cycle);
        m.to_device(self.buf.cpu().wrapping_add(self.enq * TRB_BYTES), TRB_BYTES);
        self.advance(m);
        at
    }

    /// Queue the TRBs of one transfer descriptor so the controller sees them
    /// all or none: the first TRB's cycle bit is written last. Returns the
    /// bus address of the first TRB and of the last.
    pub fn push_td<M: Memory>(&mut self, m: &M, td: &[Trb]) -> (u64, u64) {
        debug_assert!(!td.is_empty() && td.len() <= Self::MAX_TD);
        let first_idx = self.enq;
        let first_cycle = self.cycle;
        let first_at = self.buf.bus_at(first_idx * TRB_BYTES);
        let mut last_at = first_at;
        for (i, t) in td.iter().enumerate() {
            if i == 0 {
                // Written with the cycle the controller does not accept yet.
                let at = self.buf.bus_at(self.enq * TRB_BYTES);
                put(&self.buf, self.enq, *t, !self.cycle);
                m.to_device(self.buf.cpu().wrapping_add(self.enq * TRB_BYTES), TRB_BYTES);
                last_at = at;
                self.advance(m);
            } else {
                last_at = self.push(m, *t);
            }
        }
        // Publish: flip the first TRB's cycle bit to the real one.
        let o = first_idx * TRB_BYTES + 12;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        let c = self.buf.r32(o);
        self.buf.w32(o, (c & !C_CYCLE) | first_cycle as u32);
        m.to_device(self.buf.cpu().wrapping_add(first_idx * TRB_BYTES), TRB_BYTES);
        (first_at, last_at)
    }

    /// Reset the ring to empty at its start (after the controller's copy of
    /// the dequeue pointer was set there by Set TR Dequeue Pointer).
    pub fn reset<M: Memory>(&mut self, m: &M) {
        self.buf.zero();
        m.to_device(self.buf.cpu(), PAGE);
        self.enq = 0;
        self.cycle = true;
    }
}

/// The driver's side of the event ring (one segment).
pub struct EventRing {
    buf: DmaBuf,
    deq: usize,
    ccs: bool,
}

impl EventRing {
    pub fn new(buf: DmaBuf) -> EventRing {
        EventRing { buf, deq: 0, ccs: true }
    }

    pub fn base(&self) -> u64 {
        self.buf.bus()
    }

    /// The next event, if the controller has written one.
    pub fn pop<M: Memory>(&mut self, m: &M) -> Option<Trb> {
        m.from_device(self.buf.cpu().wrapping_add(self.deq * TRB_BYTES), TRB_BYTES);
        let t = get(&self.buf, self.deq);
        if t.cycle() != self.ccs {
            return None;
        }
        self.deq += 1;
        if self.deq == RING_TRBS {
            self.deq = 0;
            self.ccs = !self.ccs;
        }
        Some(t)
    }

    /// The Event Ring Dequeue Pointer to write back after draining: the next
    /// TRB to read, with Event Handler Busy set to clear it (a controller
    /// raises no further interrupt while EHB is set).
    pub fn erdp(&self) -> u64 {
        let p = self.buf.bus_at(self.deq * TRB_BYTES);
        #[cfg(feature = "canary-erdp-ehb")]
        {
            p
        }
        #[cfg(not(feature = "canary-erdp-ehb"))]
        {
            p | super::regs::ERDP_EHB
        }
    }
}
