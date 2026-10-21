// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The device-model protocol: what a guest's access to a device window looks
//! like to vmmd, and the answer.
//!
//! The wire form (the records and the page they travel on) is
//! `azos_hv::trapwire`, one file both this program and the kernel's monitor
//! include, so the layout has one source; see there for the layout. This
//! module is vmmd's end: the consumer of the trap ring and the producer of the
//! completion ring.

use core::sync::atomic::{AtomicU32, Ordering};

pub use crate::wire::{
    cpl, Completion, Trap, CPL_AT, CPL_BYTES, CPL_HEAD, CPL_TAIL, PAGE_BYTES, TRAPS, TRAP_AT, TRAP_BYTES, TRAP_HEAD,
    TRAP_TAIL,
};

/// vmmd's end of the two rings over the shared page.
pub struct Rings {
    page: *mut u8,
}

impl Rings {
    /// # Safety
    /// `page` is the start of [`PAGE_BYTES`] bytes, 4-aligned, valid for reads
    /// and writes for as long as the `Rings` lives, whose other end follows
    /// the layout above.
    pub unsafe fn new(page: *mut u8) -> Rings {
        Rings { page }
    }

    fn word(&self, off: usize) -> &AtomicU32 {
        // SAFETY: a 4-aligned `u32` of the page (`new`'s contract).
        unsafe { &*(self.page.add(off) as *const AtomicU32) }
    }

    /// Take the oldest trap.
    pub fn pop_trap(&mut self) -> Option<Trap> {
        let head = self.word(TRAP_HEAD).load(Ordering::Relaxed);
        let tail = self.word(TRAP_TAIL).load(Ordering::Acquire);
        // A producer that claims more than the ring holds is wrong; read
        // nothing from it.
        if tail == head || tail.wrapping_sub(head) > TRAPS {
            return None;
        }
        let mut b = [0u8; TRAP_BYTES];
        let at = TRAP_AT + (head % TRAPS) as usize * TRAP_BYTES;
        for (i, x) in b.iter_mut().enumerate() {
            // SAFETY: inside the trap area of the page.
            *x = unsafe { core::ptr::read_volatile(self.page.add(at + i)) };
        }
        self.word(TRAP_HEAD).store(head.wrapping_add(1), Ordering::Release);
        Some(Trap::decode(&b))
    }

    /// Answer a trap. `false` when the completion ring is full.
    pub fn push_completion(&mut self, c: &Completion) -> bool {
        let tail = self.word(CPL_TAIL).load(Ordering::Relaxed);
        let head = self.word(CPL_HEAD).load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= TRAPS {
            return false;
        }
        let at = CPL_AT + (tail % TRAPS) as usize * CPL_BYTES;
        for (i, x) in c.encode().iter().enumerate() {
            // SAFETY: inside the completion area of the page.
            unsafe { core::ptr::write_volatile(self.page.add(at + i), *x) };
        }
        self.word(CPL_TAIL).store(tail.wrapping_add(1), Ordering::Release);
        true
    }
}
