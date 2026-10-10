// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The queued (MCS) contended half of `SpinLock` (wave 15, N3; Kconfig
//! `SPINLOCK_IMPL` = mcs): Linux's qspinlock (kernel/locking/qspinlock.c),
//! on one 32-bit word with no sub-word atomic.
//!
//! ```text
//!  31        18 17  16 15     9  8  7       0
//! | tail cpu+1 | idx  | 0      | P | locked   |
//! ```
//!
//! * `locked` (byte 0): the holder. The fast path is one `fetch_or(1)`
//!   (Acquire): `amoor.w.aq` on riscv64 (base A), LSE `LDSETA` or LL/SC on
//!   aarch64 (`SpinWait::qlock_acquire32`; x86_64 uses `LOCK CMPXCHG`
//!   0 -> 1). It took the lock when the old word was 0. Unlock is a release
//!   store of 0 to byte 0 (`SpinWait::unlock_low_byte32`: `fence rw,w; sb`,
//!   `STLRB`, `MOV`), a plain store, not a sub-word AMO.
//! * `P` (bit 8, Kconfig `SPINLOCK_MCS_PENDING`): one waiter that spins on
//!   the word itself instead of taking a queue node.
//! * `tail` (bits 16-31): the last queued waiter, as CPU + 1 and the index of
//!   its node. Changed only by full-word CAS loops (`SpinWait::cas32`), never
//!   a 16-bit exchange: riscv64 has no sub-word AMO without Zabha.
//!
//! Each CPU owns `SPINLOCK_MCS_NODES` nodes, one per nesting level of
//! contended acquisition (task, softirq-like deferred work, interrupt,
//! NMI-like); a nesting counter in node 0 picks the next free one. A waiter
//! spins on its own node until its predecessor hands the queue head over,
//! then on the lock word until the holder and the pending waiter are gone,
//! takes the lock, hands the head to its successor and frees its node: the
//! node is never held while the lock is (Linux's design, why a guard needs
//! no node). A CPU out of nodes spins on a trylock, as Linux does.
//!
//! The fast path's `fetch_or` can set `locked` on a word that is free but
//! not 0 (a pending or queued waiter owns the next turn). The slow path
//! then gives the lock back at once, no critical section having run, and
//! queues: FIFO is kept, and every transition that sets `locked` on a
//! non-zero word (the pending waiter's, the queue head's) is a CAS that
//! requires `locked` clear, so a give-back only delays it. Each CPU makes
//! at most one such give-back per acquisition.
//!
//! Orderings (rfcs/survey/MUTEX.md §5.2): Acquire on every CAS that takes
//! the lock and after each wait that observes a hand-off, Release on the
//! unlock, on the tail CAS (publishes the initialized node) and on the
//! hand-off store; never SeqCst. Nothing here takes a lock or reaches
//! lockdep: the guard's lockdep hooks run around the whole acquisition.

use core::sync::atomic::{compiler_fence, fence, AtomicU32, Ordering};
use azos_arch::{CasOrder, Cpu as _, SpinWait as _, ARCH};

/// Kconfig `SPINLOCK_IMPL`: the queued lock is the SpinLock.
pub const ON: bool = azos_limits::SPINLOCK_IMPL_MCS;
/// Kconfig `SPINLOCK_MCS_PENDING`.
pub const PENDING_ON: bool = azos_limits::SPINLOCK_MCS_PENDING;
/// Kconfig `SPINLOCK_MCS_NODES`: nesting levels per CPU.
pub const NODES: usize = azos_limits::SPINLOCK_MCS_NODES as usize;

pub const LOCKED: u32 = 1;
pub const LOCKED_MASK: u32 = 0xff;
pub const PENDING: u32 = 1 << 8;
const TAIL_IDX_SHIFT: u32 = 16;
const TAIL_IDX_BITS: u32 = 2;
const TAIL_CPU_SHIFT: u32 = TAIL_IDX_SHIFT + TAIL_IDX_BITS;
pub const TAIL_MASK: u32 = !0xffff;

const _: () = assert!(NODES >= 1 && NODES <= 1 << TAIL_IDX_BITS);
const _: () = assert!((azos_limits::NR_CPUS as u64) < (1u64 << (32 - TAIL_CPU_SHIFT)));
// `SpinWait::qlock_acquire32` sets bit 0; `unlock_low_byte32` clears byte 0.
const _: () = assert!(LOCKED == 1 && LOCKED_MASK == 0xff);

/// One queue node: 16 bytes, so a CPU's four fill one 64-byte line.
#[repr(C)]
struct QNode {
    /// 0 while waiting; the predecessor stores 1 to hand the head over.
    locked: AtomicU32,
    /// The successor's tail code (0: none yet).
    next: AtomicU32,
    /// Node 0 only: the nesting depth (the next free index). Touched only by
    /// its own CPU with preemption off; an interrupt that nests restores it.
    count: AtomicU32,
    _pad: u32,
}

#[repr(C, align(64))]
struct CpuNodes([QNode; NODES]);

/// RAM: `NR_CPUS * 64` bytes with the queued lock, none without.
const NCPU: usize = if ON { azos_limits::NR_CPUS as usize } else { 0 };

static QNODES: [CpuNodes; NCPU] = [const {
    CpuNodes([const { QNode { locked: AtomicU32::new(0), next: AtomicU32::new(0), count: AtomicU32::new(0), _pad: 0 } }; NODES])
}; NCPU];

#[inline(always)]
fn encode_tail(cpu: usize, idx: u32) -> u32 {
    ((cpu as u32 + 1) << TAIL_CPU_SHIFT) | (idx << TAIL_IDX_SHIFT)
}

#[inline(always)]
fn node_of(tail: u32) -> &'static QNode {
    let cpu = (tail >> TAIL_CPU_SHIFT) as usize - 1;
    let idx = ((tail >> TAIL_IDX_SHIFT) & ((1 << TAIL_IDX_BITS) - 1)) as usize;
    &QNODES[cpu].0[idx]
}

/// Uncontended trylock: only a word of 0 (no holder, no waiter) is taken,
/// so a trylock never passes a queued waiter.
#[inline(always)]
pub fn try_acquire(lock: &AtomicU32) -> bool {
    ARCH.cas32(lock, 0, LOCKED, CasOrder::Acquire).is_ok()
}

/// Wait (reading only) until none of `mask`'s bits is set; the word read.
#[inline(always)]
fn wait_clear(lock: &AtomicU32, mask: u32) -> u32 {
    let mut v = lock.load(Ordering::Relaxed);
    while v & mask != 0 {
        v = ARCH.wait_while32(lock, v);
    }
    v
}

/// The contended acquisition. `old` is the word the fast path's
/// `fetch_or(LOCKED)` returned (not 0); a fast path that wrote nothing (a
/// failed CAS) passes its observed word with `LOCKED` set, which is the
/// same thing to this function: no lock was taken by it.
#[inline(never)]
#[cold]
pub fn slow(lock: &AtomicU32, mut val: u32) {
    if val & LOCKED_MASK == 0 {
        // The fetch_or set `locked` on a free word whose pending or queued
        // waiter owns the next turn: give it back (nothing ran under it).
        ARCH.unlock_low_byte32(lock);
        val = lock.load(Ordering::Relaxed);
    }

    if PENDING_ON && val & !LOCKED_MASK == 0 {
        // Only a holder (or nothing): try to become the pending waiter.
        val = lock.fetch_or(PENDING, Ordering::Acquire);
        if val & !LOCKED_MASK == 0 {
            // Ours. Wait for the holder, then take the lock and clear
            // pending in one CAS that requires `locked` clear (a give-back
            // in flight may have set it).
            let mut v = wait_clear(lock, LOCKED_MASK);
            loop {
                match ARCH.cas32(lock, v, (v & !PENDING) | LOCKED, CasOrder::Acquire) {
                    Ok(_) => return,
                    Err(o) => v = if o & LOCKED_MASK != 0 { wait_clear(lock, LOCKED_MASK) } else { o },
                }
            }
        }
        // Another waiter is pending or queued: undo ours, if we set it.
        if val & PENDING == 0 {
            lock.fetch_and(!PENDING, Ordering::Relaxed);
        }
    }

    // ── Queue ────────────────────────────────────────────────────────────
    let cpu = ARCH.hart_id();
    if cpu >= NCPU {
        spin_trylock(lock);
        return;
    }
    let set = &QNODES[cpu].0;
    let idx = set[0].count.load(Ordering::Relaxed);
    set[0].count.store(idx + 1, Ordering::Relaxed);
    // An interrupt on this CPU from here on sees the count taken (Linux's
    // barrier()): it uses the next node, never this one.
    compiler_fence(Ordering::AcqRel);
    if idx as usize >= NODES {
        // Out of nodes (deeper nesting than SPINLOCK_MCS_NODES).
        spin_trylock(lock);
        set[0].count.store(idx, Ordering::Relaxed);
        return;
    }
    let node = &set[idx as usize];
    node.locked.store(0, Ordering::Relaxed);
    node.next.store(0, Ordering::Relaxed);
    let tail = encode_tail(cpu, idx);

    // The tail, in a full-word CAS loop. Release publishes the node's
    // initialization to the successor that reads this tail; Acquire pairs
    // with the predecessor's, so its node is initialized before we link.
    let mut v = lock.load(Ordering::Relaxed);
    let old = loop {
        match ARCH.cas32(lock, v, (v & !TAIL_MASK) | tail, CasOrder::AcqRel) {
            Ok(o) => break o,
            Err(o) => v = o,
        }
    };

    let mut next = 0;
    if old & TAIL_MASK != 0 {
        node_of(old).next.store(tail, Ordering::Release);
        // Our turn: the predecessor's hand-off store (local spin).
        ARCH.wait_while32(&node.locked, 0);
        fence(Ordering::Acquire);
        next = node.next.load(Ordering::Acquire);
    }

    // The queue head: wait for the holder and the pending waiter.
    let mut val = wait_clear(lock, LOCKED_MASK | PENDING);
    loop {
        if val & TAIL_MASK == tail {
            // The last waiter: take the lock and clear the tail together.
            match ARCH.cas32(lock, val, LOCKED, CasOrder::Acquire) {
                Ok(_) => {
                    set[0].count.store(idx, Ordering::Relaxed);
                    return;
                }
                Err(o) => val = o,
            }
        } else {
            match ARCH.cas32(lock, val, val | LOCKED, CasOrder::Acquire) {
                Ok(_) => break,
                Err(o) => val = o,
            }
        }
        // Lost to a give-back in flight, a pending bit being undone or a new
        // tail: wait again if the word is held.
        if val & (LOCKED_MASK | PENDING) != 0 {
            val = wait_clear(lock, LOCKED_MASK | PENDING);
        }
    }

    // Hand the head to the successor (it may still be linking itself).
    if next == 0 {
        next = ARCH.wait_while32(&node.next, 0);
        fence(Ordering::Acquire);
    }
    node_of(next).locked.store(1, Ordering::Release);
    set[0].count.store(idx, Ordering::Relaxed);
}

/// No node (deeper nesting than the nodes, or a CPU id past NR_CPUS):
/// spin on the uncontended trylock, as Linux does.
#[inline(never)]
fn spin_trylock(lock: &AtomicU32) {
    loop {
        if lock.load(Ordering::Relaxed) == 0 && try_acquire(lock) {
            return;
        }
        ARCH.cpu_relax();
    }
}

/// The contended half the ISAs' `SpinLock` trampolines reach
/// (`azos_spin_tas_slow32` dispatches here when `SPINLOCK_IMPL` is mcs,
/// and the trait's portable `qlock_acquire32` calls it). Always defined, so
/// the TTAS build links; the linker drops it there.
#[no_mangle]
pub extern "C" fn azos_spin_mcs_slow32(lock: &AtomicU32, old: u32) {
    slow(lock, old);
}

/// The nesting depth of this CPU's queue nodes (ktest/host tests: 0 when no
/// contended acquisition is in flight on this CPU).
pub fn depth(cpu: usize) -> u32 {
    QNODES.get(cpu).map_or(0, |s| s.0[0].count.load(Ordering::Relaxed))
}
