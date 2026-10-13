// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A FIFO request queue in front of one polled controller, split into
//! submit and wait (owner rule F1: no mutex across a device wait).
//!
//! A controller that runs one command at a time (the SD/eMMC PIO driver,
//! `mmc.rs`) needs two different exclusions, and they have different costs:
//!
//! - **Ownership of the controller** for a whole request: from the first
//!   command to the last `TRANSFER_DONE`, including the device waits and the
//!   PIO data phase. A second caller must not program `ARGUMENT`/`COMMAND`
//!   while a transfer is in flight. This is the queue: a ticket taken at
//!   [`DevQueue::submit`], served in order. A caller whose ticket is not
//!   served yet sleeps on a [`WaitQueue`] holding no lock; the queue holds
//!   the request, nobody spins on a mutex.
//! - **The register-programming critical section**: a [`Mutex`] taken by
//!   [`Turn::program`] only, around the writes that start a command, and by
//!   [`DevQueue::submit`] only to take the ticket. [`Turn::wait`] runs its
//!   device wait with the lock released, so a `Mutex` holder never blocks
//!   behind a device.
//!
//! The queue has no depth constant: a ticket is a `u32` counter, and a
//! sleeping waiter costs one entry of the `WaitQueue` (Kconfig
//! `WAITQUEUE_CAPACITY`; past it a waiter re-checks in a loop instead of
//! sleeping, the `wait_if` contract).
//!
//! Cost per request: one Mutex round trip for the ticket, one per
//! [`Turn::program`], one atomic store and a `wake_all` at the end; no
//! extra instructions inside the polled waits.

use core::sync::atomic::{AtomicU32, Ordering};

use azos_sync::waitqueue::WaitQueue;
use azos_sync::kmutex::Mutex;

/// One controller's request queue. Usable as a `static`.
pub struct DevQueue {
    lock: Mutex<()>,
    /// The next ticket. Taken under the lock (the "queue the request" half
    /// of submit); an atomic so [`DevQueue::pending`] reads it without it.
    next: AtomicU32,
    /// The ticket that owns the controller. Written only by the owner when
    /// its [`Turn`] drops; read without the lock by the waiters.
    serving: AtomicU32,
    turn: WaitQueue,
}

/// Ownership of the controller for one request, in queue order. Dropping
/// it hands the controller to the next ticket.
pub struct Turn<'a> {
    q: &'a DevQueue,
    ticket: u32,
}

impl DevQueue {
    pub const fn new() -> Self {
        DevQueue {
            lock: Mutex::new(()),
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
            turn: WaitQueue::new(),
        }
    }

    /// Queue a request and return when the controller is its. The lock is
    /// held only to take the ticket; the wait for the turn holds nothing.
    pub fn submit(&self) -> Turn<'_> {
        let ticket = {
            let _g = self.lock.lock();
            self.next.fetch_add(1, Ordering::AcqRel)
        };
        while self.serving.load(Ordering::Acquire) != ticket {
            self.turn.wait_if(|| self.serving.load(Ordering::Acquire) != ticket);
            core::hint::spin_loop();
        }
        Turn { q: self, ticket }
    }

    /// Requests submitted and not finished, the one being served included.
    pub fn pending(&self) -> u32 {
        self.next.load(Ordering::Acquire).wrapping_sub(self.serving.load(Ordering::Acquire))
    }

    /// `true` if the programming lock is free right now (the F1 probe the
    /// host test runs from inside a device wait).
    pub fn lock_free(&self) -> bool {
        self.lock.try_lock().is_some()
    }
}

impl Default for DevQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Turn<'_> {
    /// Program the controller: `f` runs with the lock held. `f` must only
    /// write registers, never wait for the device.
    #[inline]
    pub fn program<R>(&self, f: impl FnOnce() -> R) -> R {
        let _g = self.q.lock.lock();
        f()
    }

    /// A device wait (polled or otherwise): `f` runs with no lock held.
    /// The controller is still this request's.
    #[inline]
    pub fn wait<R>(&self, f: impl FnOnce() -> R) -> R {
        azos_sync::lockdep::might_wait_device("dev_queue wait");
        f()
    }

    /// This request's position in the queue's order.
    pub fn ticket(&self) -> u32 {
        self.ticket
    }
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        self.q.serving.store(self.ticket.wrapping_add(1), Ordering::Release);
        self.q.turn.wake_all();
    }
}
