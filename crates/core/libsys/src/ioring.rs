// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Ring-3 view of an io_ring page: the layout `io_ring::IoRing` in
//! `crates/core/ipc/src/io_ring.rs` pins with compile-time offset assertions, and
//! the opcodes and flags that file defines.
//!
//! [`Ring`] is a thin producer/consumer over that page: it writes SQEs, moves
//! `sq_tail`, reads CQEs and moves `cq_head`. It **never enters the kernel**:
//! the caller creates, submits and destroys with [`crate::ioring_create_typed`],
//! [`crate::ioring_submit_typed`] and [`crate::ioring_destroy_typed`] itself, so
//! every syscall a program issues is a `sys::NAME(..)` call its seccomp row can
//! be checked against (`tests/host/seccomp-tests` derives the rows that way).

use core::sync::atomic::{AtomicU32, Ordering};

// The page layout, opcodes and flags: one definition in `crates/core/abi`, which the
// kernel's `IoRing` is asserted against at compile time.
pub use azos_abi::io_ring::{
    CQ_ENTRIES, CQ_HEAD, CQ_SIZE, CQ_TAIL, CQE_F_REFUSED, DATA, DATA_SIZE, OP_CHAN_RECV,
    OP_CHAN_SEND, OP_FILE_READ, OP_FILE_WRITE, OP_NOP, OP_NOTIFY_WAIT, OP_READ_GPIO,
    OP_READ_SENSOR, OP_SQPOLL_START, OP_TIMER, OP_WRITE_GPIO, SQ_ENTRIES, SQ_FLAGS,
    SQ_F_NEED_WAKEUP, SQ_F_SQPOLL, SQ_HEAD, SQ_SIZE, SQ_TAIL,
};

/// One completion: `(user_data, result, flags)`.
pub type Cqe = (u64, i32, u32);

/// A ring this task created: its capability and the address its page is
/// mapped at.
pub struct Ring {
    pub cap: u32,
    pub va: usize,
}

impl Ring {
    /// The ring `ioring_create_typed` answered: its capability (a positive
    /// return) and the address it wrote into `addr_out`.
    pub fn new(cap: u32, addr_out: [u8; 8]) -> Ring {
        Ring { cap, va: u64::from_le_bytes(addr_out) as usize }
    }

    #[inline(always)]
    fn word(&self, off: usize) -> &AtomicU32 {
        // SAFETY: `va` is the ring page, mapped user RW until `destroy`, and
        // every offset used is a 4-aligned field of it.
        unsafe { &*((self.va + off) as *const AtomicU32) }
    }

    /// Queue one entry. `false` when the SQ holds `SQ_SIZE` unconsumed ones.
    #[inline(always)]
    pub fn push(&self, opcode: u16, p0: u32, p1: u32, p2: u32, user_data: u64) -> bool {
        let tail = self.word(SQ_TAIL).load(Ordering::Relaxed);
        let head = self.word(SQ_HEAD).load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= SQ_SIZE {
            return false;
        }
        let e = self.va + SQ_ENTRIES + (tail % SQ_SIZE) as usize * 32;
        // SAFETY: an SQ slot of the ring page; the kernel reads it only after
        // the `sq_tail` store below publishes it.
        unsafe {
            core::ptr::write_volatile(e as *mut u32, opcode as u32); // opcode, flags = 0
            core::ptr::write_volatile((e + 4) as *mut u32, p0);
            core::ptr::write_volatile((e + 8) as *mut u32, p1);
            core::ptr::write_volatile((e + 12) as *mut u32, p2);
            core::ptr::write_volatile((e + 16) as *mut u32, 0); // addr, reg
            core::ptr::write_volatile((e + 24) as *mut u64, user_data);
        }
        self.word(SQ_TAIL).store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Does an SQ poller run this ring (`OP_SQPOLL_START` completed 0)?
    #[inline(always)]
    pub fn polled(&self) -> bool {
        self.word(SQ_FLAGS).load(Ordering::Acquire) & SQ_F_SQPOLL != 0
    }

    /// For a polled ring, after [`Ring::push`]: has the poller parked, so that
    /// one `ioring_submit_typed` is needed to wake it? The fence orders the
    /// `sq_tail` store before the flag read — the mirror of the poller's own
    /// (set the flag, fence, re-read `sq_tail`), so an entry is never left with
    /// the poller asleep and no wake-up sent.
    #[inline(always)]
    pub fn needs_wakeup(&self) -> bool {
        core::sync::atomic::fence(Ordering::SeqCst);
        self.word(SQ_FLAGS).load(Ordering::SeqCst) & SQ_F_NEED_WAKEUP != 0
    }

    /// Take the oldest completion, if any.
    #[inline(always)]
    pub fn pop(&self) -> Option<Cqe> {
        let head = self.word(CQ_HEAD).load(Ordering::Relaxed);
        let tail = self.word(CQ_TAIL).load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let c = self.va + CQ_ENTRIES + (head % CQ_SIZE) as usize * 16;
        // SAFETY: a CQ slot the kernel published before the `cq_tail` load.
        let cqe = unsafe {
            (
                core::ptr::read_volatile(c as *const u64),
                core::ptr::read_volatile((c + 8) as *const i32),
                core::ptr::read_volatile((c + 12) as *const u32),
            )
        };
        self.word(CQ_HEAD).store(head.wrapping_add(1), Ordering::Release);
        Some(cqe)
    }

    /// Completions published and not yet taken.
    #[inline(always)]
    pub fn ready(&self) -> u32 {
        self.word(CQ_TAIL).load(Ordering::Acquire).wrapping_sub(self.word(CQ_HEAD).load(Ordering::Relaxed))
    }

    /// The data buffer, where buffer entries read and write.
    #[inline(always)]
    pub fn data(&self) -> *mut u8 {
        (self.va + DATA) as *mut u8
    }
}
