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
//! **Scheduler-agnostic.** This crate does not link the scheduler: the kernel
//! registers three hooks ([`set_hooks`]). With none registered (host tests,
//! a boot before the scheduler) and when every slot of a kind is held by other
//! waiters, the caller's own `yield_fn` is the wait, exactly as before.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

static CURRENT_TID: AtomicUsize = AtomicUsize::new(0);
static BLOCK_UNTIL: AtomicUsize = AtomicUsize::new(0);
static WAKE: AtomicUsize = AtomicUsize::new(0);

/// Register the kernel's side: the caller's TID (0 = not a task), "block the
/// caller until this tick or a wake, `false` if it could not block", and
/// "wake this TID if it is blocked on a timer". `wake` runs in the receive
/// path with no network lock held.
pub fn set_hooks(current_tid: fn() -> u32, block_until: fn(u64) -> bool, wake: fn(u32)) {
    CURRENT_TID.store(current_tid as usize, Ordering::Release);
    WAKE.store(wake as usize, Ordering::Release);
    // Last: `arm` reads this one first, so a waiter never sees half the set.
    BLOCK_UNTIL.store(block_until as usize, Ordering::Release);
}

/// Unregister the hooks: every wait is the caller's `yield_fn` again. For
/// host tests that install fakes and must leave the next test as it found it.
pub fn clear_hooks() {
    BLOCK_UNTIL.store(0, Ordering::Release);
    WAKE.store(0, Ordering::Release);
    CURRENT_TID.store(0, Ordering::Release);
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

    /// Wake every waiter. One atomic load when there is none.
    pub fn notify(&self) {
        if self.armed.load(Ordering::Acquire) == 0 { return; }
        let p = WAKE.load(Ordering::Acquire);
        if p == 0 { return; }
        // SAFETY: only `set_hooks` stores a non-zero value, and it stores a
        // `fn(u32)`.
        let wake: fn(u32) = unsafe { core::mem::transmute::<usize, fn(u32)>(p) };
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
        let none = Armed { slot: None, armed: &self.armed, tid: 0, block: 0 };
        let block = BLOCK_UNTIL.load(Ordering::Acquire);
        let cur = CURRENT_TID.load(Ordering::Acquire);
        if block == 0 || cur == 0 { return none; }
        // SAFETY: only `set_hooks` stores a non-zero value, and it stores a
        // `fn() -> u32`.
        let tid = unsafe { core::mem::transmute::<usize, fn() -> u32>(cur) }();
        if tid == 0 { return none; }
        for s in &self.slots {
            if s.compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire).is_ok() {
                // Before the caller reads its condition (`AcqRel` here,
                // `Acquire` in `notify`): a notify that follows the event
                // sees this waiter.
                self.armed.fetch_add(1, Ordering::AcqRel);
                return Armed { slot: Some(s), armed: &self.armed, tid, block };
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
    block: usize,
}

impl Armed<'_> {
    /// Wait for the event or `deadline` (an absolute tick), whichever is
    /// first; unarmed, or if the task cannot block, run `fallback` once.
    /// The caller re-checks its condition and its deadline either way.
    pub fn wait<F: FnMut()>(&self, deadline: u64, fallback: &mut F) {
        if self.slot.is_some() {
            // SAFETY: `block` came from `BLOCK_UNTIL`, which only `set_hooks`
            // stores, as a `fn(u64) -> bool`.
            let block: fn(u64) -> bool =
                unsafe { core::mem::transmute::<usize, fn(u64) -> bool>(self.block) };
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
