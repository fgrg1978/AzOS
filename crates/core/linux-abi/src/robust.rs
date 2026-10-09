// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The robust futex list a Linux thread registers with `set_robust_list`
//! (wave 15), walked when the thread ends: its pure half.
//!
//! The list lives in the thread's memory (`struct robust_list_head`: the
//! list's `next`, a signed `futex_offset`, `list_op_pending`; 24 bytes on a
//! 64-bit ISA). Each entry is a `struct robust_list` (`next` first); the
//! lock word of an entry is at `entry + futex_offset`. Bit 0 of a pointer
//! marks a priority-inheritance lock. A word whose owner TID (the low 30
//! bits) is the dying thread's becomes `FUTEX_OWNER_DIED`, keeping
//! `FUTEX_WAITERS`, and one waiter is woken when that bit was set, so the
//! next locker sees `EOWNERDEAD` instead of sleeping forever. This is Linux's
//! `exit_robust_list` and `handle_futex_death` (kernel/futex/core.c).
//!
//! Everything it reads comes from the user and is untrusted: every access
//! goes through [`RobustMem`] (which refuses an address the thread does not
//! map), the walk stops at the first unreadable entry, and it visits at
//! most `limit` entries, so a cyclic or endless list cannot hold the exit.

/// `sizeof(struct robust_list_head)` on a 64-bit ISA: the only length
/// `set_robust_list` accepts (`-EINVAL` otherwise, as Linux).
pub const HEAD_LEN: u64 = 24;
/// The owner's TID in a robust lock word.
pub const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;
/// The owner died holding the lock.
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// Someone sleeps (or is about to) on the word.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;

/// The dying thread's memory, as the walk reaches it.
pub trait RobustMem {
    /// The 64-bit value at `addr`; `None` if the thread cannot read it.
    fn read_u64(&mut self, addr: u64) -> Option<u64>;
    /// The 32-bit value at `addr` (4-aligned); `None` if unreadable.
    fn read_u32(&mut self, addr: u64) -> Option<u32>;
    /// Atomically replace `old` with `new` at `addr` (4-aligned): `Ok(())`
    /// on success, `Err(Some(current))` when the word held another value,
    /// `Err(None)` when it cannot be written.
    fn cas_u32(&mut self, addr: u64, old: u32, new: u32) -> Result<(), Option<u32>>;
    /// Wake one waiter on the word at `addr`.
    fn wake_one(&mut self, addr: u64);
}

/// What one walk did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Walked {
    /// Entries visited (the pending one included).
    pub entries: u32,
    /// Words the dying thread held, now `FUTEX_OWNER_DIED`.
    pub owner_died: u32,
    /// Waiters woken.
    pub woken: u32,
}

/// Linux `handle_futex_death` for the word at `uaddr`. `pending`: the word
/// is the list's `list_op_pending` (an acquire or release that was in
/// flight): a word left 0 there still wakes one waiter, who may have been
/// handed the lock by an unlock the thread did not finish.
fn word_death(mem: &mut impl RobustMem, uaddr: u64, tid: u32, pi: bool, pending: bool, w: &mut Walked) {
    if uaddr & 3 != 0 {
        return;
    }
    let Some(mut uval) = mem.read_u32(uaddr) else { return };
    loop {
        if pending && !pi && uval == 0 {
            mem.wake_one(uaddr);
            w.woken += 1;
            return;
        }
        if uval & FUTEX_TID_MASK != tid {
            return;
        }
        let new = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        match mem.cas_u32(uaddr, uval, new) {
            Ok(()) => break,
            // A waiter set FUTEX_WAITERS meanwhile: decide again on what is
            // there now (Linux retries the same way).
            Err(Some(now)) => uval = now,
            Err(None) => return,
        }
    }
    w.owner_died += 1;
    // A priority-inheritance word's waiters are the PI state's to wake; this
    // kernel answers no PI futex, so none sleep on it.
    if !pi && uval & FUTEX_WAITERS != 0 {
        mem.wake_one(uaddr);
        w.woken += 1;
    }
}

/// Fetch the `struct robust_list *` at `addr`: the entry, and its PI bit.
fn fetch_entry(mem: &mut impl RobustMem, addr: u64) -> Option<(u64, bool)> {
    let v = mem.read_u64(addr)?;
    Some((v & !1, v & 1 != 0))
}

/// Walk the robust list whose head is at `head` for the thread `tid`, at
/// most `limit` entries plus the pending one (Linux `exit_robust_list`).
/// `head` 0: nothing registered.
pub fn exit_robust_list(mem: &mut impl RobustMem, head: u64, tid: u32, limit: u32) -> Walked {
    let mut w = Walked::default();
    if head == 0 || tid == 0 || tid > FUTEX_TID_MASK {
        return w;
    }
    let Some((mut entry, mut pi)) = fetch_entry(mem, head) else { return w };
    let Some(off) = mem.read_u64(head.wrapping_add(8)) else { return w };
    let Some((pending, pending_pi)) = fetch_entry(mem, head.wrapping_add(16)) else { return w };
    let mut left = limit;
    while entry != head && left > 0 {
        let next = fetch_entry(mem, entry);
        if entry != pending {
            w.entries += 1;
            word_death(mem, entry.wrapping_add(off), tid, pi, false, &mut w);
        }
        // An unreadable `next` ends the walk, the pending word unvisited (Linux).
        let Some((n, npi)) = next else { return w };
        entry = n;
        pi = npi;
        left -= 1;
    }
    if pending != 0 {
        w.entries += 1;
        word_death(mem, pending.wrapping_add(off), tid, pending_pi, true, &mut w);
    }
    w
}
