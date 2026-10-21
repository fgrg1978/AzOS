// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The monitor's end of the trap and completion rings ([`crate::trapwire`]).
//!
//! [`RawPage`] is the producer of traps and the consumer of completions over
//! the page vmmd shares; [`Mailbox`] hands each completion to the vCPU it
//! answers, because the completion ring is one ring for all of a VM's vCPUs.
//!
//! The page is the other side's to write: every index and record in it is
//! untrusted. The consumer reads a completion only when the producer's index
//! is within the ring's reach of its own, and a completion for a vCPU that
//! waits for nothing is dropped.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::trapwire::{
    Completion, Trap, CPL_AT, CPL_BYTES, CPL_HEAD, CPL_TAIL, PAGE_BYTES, TRAPS, TRAP_AT, TRAP_BYTES, TRAP_HEAD,
    TRAP_TAIL,
};

/// A vCPU's trap sequence number: `counter << 8 | vcpu`. The completion
/// carries only the sequence number, and the vCPU index in it is how
/// [`Mailbox`] finds the waiter.
pub const fn seq_of(counter: u32, vcpu: u8) -> u32 {
    counter << 8 | vcpu as u32
}

/// The vCPU a sequence number belongs to.
pub const fn seq_vcpu(seq: u32) -> u8 {
    seq as u8
}

/// The trap ring is full: the other side has not taken what was posted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// The shared page, as the monitor reads and writes it.
pub struct RawPage {
    page: *mut u8,
}

impl RawPage {
    /// # Safety
    /// `page` is the start of [`PAGE_BYTES`] bytes, 4-aligned, valid for reads
    /// and writes for as long as the `RawPage` lives (the kernel builds one
    /// inside the region table's lock, which pins the frame), whose other end
    /// follows the layout of [`crate::trapwire`].
    pub unsafe fn new(page: *mut u8) -> RawPage {
        RawPage { page }
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        // SAFETY: a 4-aligned `u32` of the page (`new`'s contract).
        unsafe { &*(self.page.add(off) as *const AtomicU32) }
    }

    /// Post a trap. [`Full`] when [`TRAPS`] are waiting.
    pub fn post_trap(&mut self, t: &Trap) -> Result<(), Full> {
        let tail = self.word(TRAP_TAIL).load(Ordering::Relaxed);
        let head = self.word(TRAP_HEAD).load(Ordering::Acquire);
        // A consumer index past the producer's is wrong; the ring is then
        // treated as full rather than overwritten.
        if tail.wrapping_sub(head) >= TRAPS {
            return Err(Full);
        }
        let at = TRAP_AT + (tail % TRAPS) as usize * TRAP_BYTES;
        for (i, x) in t.encode().iter().enumerate() {
            // SAFETY: inside the trap area of the page.
            unsafe { core::ptr::write_volatile(self.page.add(at + i), *x) };
        }
        self.word(TRAP_TAIL).store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Take the oldest completion.
    pub fn take_completion(&mut self) -> Option<Completion> {
        let head = self.word(CPL_HEAD).load(Ordering::Relaxed);
        let tail = self.word(CPL_TAIL).load(Ordering::Acquire);
        if tail == head || tail.wrapping_sub(head) > TRAPS {
            return None;
        }
        let mut b = [0u8; CPL_BYTES];
        let at = CPL_AT + (head % TRAPS) as usize * CPL_BYTES;
        for (i, x) in b.iter_mut().enumerate() {
            // SAFETY: inside the completion area of the page.
            *x = unsafe { core::ptr::read_volatile(self.page.add(at + i)) };
        }
        self.word(CPL_HEAD).store(head.wrapping_add(1), Ordering::Release);
        Some(Completion::decode(&b))
    }

    /// Bytes the page must have.
    pub const BYTES: usize = PAGE_BYTES;
}

/// Completions taken off the ring and not yet collected, one slot per vCPU of
/// the pool (a vCPU has at most one trap in flight). The VM table keeps one
/// for all its VMs, so what it costs does not grow with the number of VMs; the
/// slots are the pool's, and a VM's vCPU `k` is slot `first_vcpu + k`.
#[derive(Clone, Copy, Debug)]
pub struct Mailbox {
    slots: [Option<Completion>; crate::vm::MAX_VCPUS],
    /// Traps numbered so far, per vCPU: the counter in the next sequence number.
    counters: [u32; crate::vm::MAX_VCPUS],
    /// Traps posted and not yet answered, per vCPU: the sequence number.
    waiting: [Option<u32>; crate::vm::MAX_VCPUS],
}

impl Mailbox {
    pub const fn new() -> Mailbox {
        Mailbox { slots: [None; crate::vm::MAX_VCPUS], counters: [0; crate::vm::MAX_VCPUS], waiting: [None; crate::vm::MAX_VCPUS] }
    }

    /// The sequence number of the next trap of vCPU `vcpu` of the VM whose
    /// vCPUs start at slot `base`. The counter runs on across the vCPU's stops
    /// and starts and restarts only when the VM is destroyed ([`Mailbox::reset`]),
    /// so a late answer to a trap of an earlier run matches no wait of this
    /// one.
    pub fn next_seq(&mut self, base: usize, vcpu: u8) -> u32 {
        match self.counters.get_mut(base + vcpu as usize) {
            Some(c) => {
                *c = c.wrapping_add(1);
                seq_of(*c, vcpu)
            }
            None => 0,
        }
    }

    /// vCPU `k` has posted trap `seq` and now waits for its answer.
    pub fn expect(&mut self, k: usize, seq: u32) {
        if let Some(w) = self.waiting.get_mut(k) {
            *w = Some(seq);
        }
        if let Some(s) = self.slots.get_mut(k) {
            *s = None;
        }
    }

    /// Move every completion on the ring of the VM whose vCPUs start at slot
    /// `base` to the vCPU it answers; the VM has `vcpus` of them. One for a
    /// vCPU that is not waiting for that sequence number is the other side's
    /// mistake and is dropped, and so is one whose vCPU byte (written by the
    /// ring-3 monitor) names a vCPU past the VM's own: `base + byte` would
    /// land in the next VM's slot and could answer a trap that VM is waiting
    /// on, when the sequence number happens to match.
    pub fn fill(&mut self, page: &mut RawPage, base: usize, vcpus: usize) {
        while let Some(c) = page.take_completion() {
            let v = seq_vcpu(c.seq) as usize;
            if v >= vcpus {
                continue;
            }
            let k = base + v;
            if self.waiting.get(k).copied().flatten() == Some(c.seq) {
                self.slots[k] = Some(c);
            }
        }
    }

    /// vCPU `k`'s answer, if it is here; the vCPU then waits for nothing.
    pub fn take(&mut self, k: usize) -> Option<Completion> {
        let c = self.slots.get_mut(k)?.take()?;
        self.waiting[k] = None;
        Some(c)
    }

    /// Forget slot `k` entirely: nothing it waited for, no numbering.
    pub fn reset(&mut self, k: usize) {
        self.forget(k);
        if let Some(c) = self.counters.get_mut(k) {
            *c = 0;
        }
    }

    /// Forget a vCPU that stopped while it waited.
    pub fn forget(&mut self, k: usize) {
        if let Some(w) = self.waiting.get_mut(k) {
            *w = None;
        }
        if let Some(s) = self.slots.get_mut(k) {
            *s = None;
        }
    }
}

impl Default for Mailbox {
    fn default() -> Self {
        Mailbox::new()
    }
}
