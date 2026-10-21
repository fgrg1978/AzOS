// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Waiting on a network event instead of sleep-polling for it (wave 15 N7).
//!
//! A task that waits for a handshake, a send window, an ARP reply, a DNS
//! answer or an incoming connection used to sleep 1 ms (or yield) and look
//! again, up to its budget: ~1,000 wakes a second per waiter, and up to a
//! scheduler tick of latency after the event. Now the waiter puts its TID in
//! a [`WaitQueue`] slot **before** it checks its condition, then blocks until its
//! deadline; the receive path that makes the condition true (`tcp::handle`,
//! `arp::handle`, `dns::handle_response`) calls [`WaitQueue::notify`] after it
//! drops its lock, which wakes the waiter. The deadline stays the bound.
//!
//! **No lost wake-up.** The slot is armed before the condition is read. An
//! event that lands between that read and the block finds the TID and wakes a
//! task that is still running; the scheduler stamps that wake (K-C9) and the
//! block that follows returns at once. Same protocol as `net_timer_kick`.
//!
//! **Memory order: a store-buffer (Dekker) pair.** Each side stores and then
//! loads what the other stored: the waiter registers (`armed`) then reads its
//! condition; the notifier stores the event (the caller's store, before the
//! call) then reads `armed`. Acquire/release does not order a store before a
//! later load, on any ISA (x86 TSO reorders exactly that pair; ARM and RISC-V
//! more), so both loads could read the old value: the waiter misses the event,
//! the notifier sees nobody armed, and the waiter sleeps to its deadline. A
//! `SeqCst` fence on each side, between the store and the load, forbids it:
//! one of the two sees the other. `arm` and `notify` are the only places that
//! carry them, and every caller keeps the arm-then-check order.
//!
//! **Scheduler-agnostic.** This crate does not link the scheduler: the kernel
//! registers three hooks ([`set_hooks`]). With none registered (host tests,
//! a boot before the scheduler) and when every slot of a kind is held by other
//! waiters, the caller's own `yield_fn` is the wait, exactly as before.

use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, Ordering};

azos_common::ro_hook! {
    static CURRENT_TID: fn() -> u32;
}
azos_common::ro_hook! {
    static BLOCK_UNTIL: fn(u64) -> bool;
}
azos_common::ro_hook! {
    static WAKE: fn(u32);
}

/// Register the kernel's side: the caller's TID (0 = not a task), "block the
/// caller until this tick or a wake, `false` if it could not block", and
/// "wake this TID if it is blocked on a timer". `wake` runs in the receive
/// path with no network lock held.
pub fn set_hooks(current_tid: fn() -> u32, block_until: fn(u64) -> bool, wake: fn(u32)) {
    CURRENT_TID.set(current_tid);
    WAKE.set(wake);
    // Last: `arm` reads this one first, so a waiter never sees half the set.
    BLOCK_UNTIL.set(block_until);
}

/// The net-poll task is running: it is the receive path's consumer.
static POLLER_RUNNING: AtomicBool = AtomicBool::new(false);

/// The net-poll task calls this when it starts (the hooks are installed at
/// boot, before it runs, and `poller_running` must not report it early).
pub fn note_poller_started() {
    POLLER_RUNNING.store(true, Ordering::Release);
}

/// Whether the net-poll task has started ([`note_poller_started`]).
pub fn poller_started() -> bool {
    POLLER_RUNNING.load(Ordering::Acquire)
}

/// Unregister the hooks: every wait is the caller's `yield_fn` again. For
/// host tests that install fakes and must leave the next test as it found it.
#[cfg(not(target_os = "none"))]
pub fn clear_hooks() {
    BLOCK_UNTIL.clear_for_tests();
    WAKE.clear_for_tests();
    CURRENT_TID.clear_for_tests();
}

/// Wait statistics: `[waits that blocked on an armed slot, waits that fell
/// back to the caller's yield_fn, notifies that woke a waiter]`.
static STATS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// [`STATS`], in its order.
pub fn stats() -> [u64; 3] {
    core::array::from_fn(|i| STATS[i].load(Ordering::Relaxed))
}

/// Up to `N` waiters for one kind of event, each a TID (0 = free slot).
///
/// Waiters do not name what exactly they wait for: a notify wakes every one,
/// and each re-checks its own condition and blocks again. There are few (a
/// connect, a sender held by the window, an accept), so a spurious wake costs
/// less than the per-connection bookkeeping it would take to avoid it, and
/// `armed` keeps a notify with nobody waiting at one atomic load.
pub struct WaitQueue<const N: usize> {
    slots: [AtomicU32; N],
    armed: AtomicU32,
}

impl<const N: usize> WaitQueue<N> {
    pub const fn new() -> Self {
        WaitQueue { slots: [const { AtomicU32::new(0) }; N], armed: AtomicU32::new(0) }
    }

    /// Wake every waiter. One fence and one atomic load when there is none.
    ///
    /// The caller stored the event before this call; the fence orders that
    /// store before the `armed` load below, the other half of `arm`'s fence.
    pub fn notify(&self) {
        fence(Ordering::SeqCst);
        if self.armed.load(Ordering::Acquire) == 0 { return; }
        let Some(wake) = WAKE.get() else { return; };
        for s in &self.slots {
            let tid = s.load(Ordering::Acquire);
            if tid != 0 {
                wake(tid);
                STATS[2].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Register the calling task in a free slot, before it checks the
    /// condition it waits for. Unarmed (the caller's `yield_fn` stays the
    /// wait) when no hooks are registered, the caller is not a task, or every
    /// slot is taken.
    pub fn arm(&self) -> Armed<'_> {
        let none = Armed { slot: None, armed: &self.armed, tid: 0, block: None };
        let (Some(block), Some(cur)) = (BLOCK_UNTIL.get(), CURRENT_TID.get()) else { return none; };
        let tid = cur();
        if tid == 0 { return none; }
        for s in &self.slots {
            if s.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                // Before the caller reads its condition: the registration
                // (`AcqRel` publishes the slot to `notify`'s `Acquire` load)
                // then a full fence, so the condition read cannot be
                // satisfied ahead of it (module docs, store-buffer pair).
                self.armed.fetch_add(1, Ordering::AcqRel);
                fence(Ordering::SeqCst);
                return Armed { slot: Some(s), armed: &self.armed, tid, block: Some(block) };
            }
        }
        none
    }
}

/// A waiter registered in one slot; leaves it when dropped.
pub struct Armed<'a> {
    slot: Option<&'a AtomicU32>,
    armed: &'a AtomicU32,
    tid: u32,
    block: Option<fn(u64) -> bool>,
}

impl Armed<'_> {
    /// Wait for the event or `deadline` (an absolute tick), whichever is
    /// first; unarmed, or if the task cannot block, run `fallback` once.
    /// The caller re-checks its condition and its deadline either way.
    pub fn wait<F: FnMut()>(&self, deadline: u64, fallback: &mut F) {
        if let (Some(_), Some(block)) = (self.slot, self.block) {
            if block(deadline) {
                STATS[0].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        STATS[1].fetch_add(1, Ordering::Relaxed);
        fallback();
    }

    /// Whether a notify can end this wait (else it is the old poll).
    pub fn is_armed(&self) -> bool { self.slot.is_some() }
}

impl Drop for Armed<'_> {
    fn drop(&mut self) {
        if let Some(s) = self.slot {
            if s.compare_exchange(self.tid, 0, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                self.armed.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}

/// Waiters per kind of event (`CONFIG_NET_WAIT_SLOTS`): more than this many
/// tasks waiting on the same kind at once fall back to their `yield_fn`.
pub const NET_WAIT_SLOTS: usize = azos_limits::NET_WAIT_SLOTS;

/// Tasks waiting on a TCP connection: a handshake (connect), an incoming
/// connection (accept), the send window. Notified after every segment
/// `tcp::handle_checked` processed and every `tcp_tick`.
pub static TCP_WAITERS: WaitQueue<NET_WAIT_SLOTS> = WaitQueue::new();

/// Tasks waiting for an ARP reply. Notified when `arp::handle` learns an
/// address.
pub static ARP_WAITERS: WaitQueue<NET_WAIT_SLOTS> = WaitQueue::new();

/// The task waiting for the one DNS answer in flight (`dns::DNS_QUERY` holds
/// one query). Notified when `dns::handle_response` latches it.
pub static DNS_WAITERS: WaitQueue<1> = WaitQueue::new();
