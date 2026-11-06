// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 server runtime: one thread, one event port, one wait.
//!
//! A server binds everything it serves to one port: its endpoint's queued
//! calls (`PORT_SRC_CALLS`), its interrupt lines (`PORT_SRC_IRQ`), its
//! timers (`PORT_SRC_TIMER`, one-shot, re-armed by the handler) and the
//! doorbell words of the shared rings it consumes (`PORT_SRC_DOORBELL`).
//! [`Server::turn`] waits on the port once and hands what woke it to the
//! [`Handler`]'s typed entry point; [`Server::run`] turns for ever.
//!
//! **Calls.** The port reports the call that finds the queue empty, once;
//! the runtime then takes calls with the poll accept until the kernel says
//! none is queued behind the last one (`MSG_MORE` clear) or the accept finds
//! nothing (a caller withdrew). At most [`CALL_BATCH`] calls are taken per
//! turn; while calls are owed the next wait only polls the port, so an
//! interrupt or a timer is handled between two batches and a storm of
//! either still leaves a batch of calls per turn. The kernel alternates its
//! own queued events (interrupts) with its table sources (calls, timers,
//! doorbells) for the same reason.
//!
//! **Doorbells.** A consumer of a shared ring announces its sleep on the
//! ring's index word before the port wait ([`Handler::idle`]) exactly as it
//! would before a futex wait; the producer's wake of that word rings the
//! doorbell. A push between the announcement and the wait is not lost: its
//! wake marks the source pending and the wait returns at once.
//!
//! A server with no source but its calls runs the same loop sleeping in the
//! accept instead ([`Server::calls_only`]), at the cost of the loop it
//! replaces.
//!
//! The kernel side is the [`Kernel`] trait: [`sys::Port`] and [`sys::Calls`]
//! over libsys (feature `libsys`), a fake in the host suite
//! (`tests/host/srv-tests`).

#![no_std]

use azos_abi::ipc_msg::{MsgDesc, MSG_MORE};
use azos_abi::syscall_nr::{PORT_EVENT_CALLS, PORT_EVENT_DOORBELL, PORT_EVENT_IRQ, PORT_EVENT_TIMER};

/// A port event, decoded.
pub use azos_abi::syscall_nr::PortEventInfo as Event;

/// Calls taken in one turn before the port is looked at again.
pub const CALL_BATCH: usize = 8;

/// [`CALL_BATCH`], or every queued call with the host canary `batch-canary`
/// (a storm of calls then starves the other sources).
const TAKE: usize = if cfg!(feature = "batch-canary") { usize::MAX } else { CALL_BATCH };

/// What the runtime needs of the kernel.
pub trait Kernel {
    /// Wait on the server's port until `deadline_ns` (absolute, the time
    /// counter's nanoseconds; `u64::MAX` none, 0 polls): the event, `None`
    /// when the deadline passed with nothing ready, or `Err(-errno)`.
    fn wait(&mut self, deadline_ns: u64) -> Result<Option<Event>, isize>;
    /// Take a queued call without blocking, writing it into `req`: its
    /// handle, `None` when no call is queued, or `Err(-errno)`.
    fn accept(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize>;
    /// Sleep in the accept until a call is queued and take it, as
    /// [`Kernel::accept`] answers (`None`: woken with nothing). The wait of a
    /// server with no source but its calls ([`Server::calls_only`]): the
    /// IPC fast path hands a call straight to a server parked there.
    fn accept_blocking(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize>;
    /// Answer call `handle` with `rep`: 0 or a negative code.
    fn reply(&mut self, handle: u64, rep: &MsgDesc) -> isize;
    /// A wait failed: back off before the next one rather than spin.
    fn pause(&mut self) {}
}

/// A server's entry points, one per kind of source.
pub trait Handler<K: Kernel> {
    /// Serve call `handle`: `req` as accepted, the answer into `rep`, which
    /// the runtime replies with.
    fn call(&mut self, k: &mut K, handle: u64, req: &MsgDesc, rep: &mut MsgDesc);
    /// An interrupt on the line bound with `key`, routed to `cpu`.
    fn irq(&mut self, _k: &mut K, _key: u64, _cpu: u8) {}
    /// The timer armed with `key` fired (it is one-shot: re-arm it here).
    fn timer(&mut self, _k: &mut K, _key: u64) {}
    /// The doorbell word bound with `key` was woken.
    fn doorbell(&mut self, _k: &mut K, _key: u64) {}
    /// Any other event: a notice, a source that is gone, a ring, pressure.
    fn other(&mut self, _k: &mut K, _ev: &Event) {}
    /// Called before every wait: do the work that needs no event, announce
    /// the sleeps the doorbells stand for, and say how long the wait may be.
    fn idle(&mut self, _k: &mut K) -> Idle {
        Idle::Sleep
    }
}

/// How long the wait after [`Handler::idle`] may sleep.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Idle {
    /// Work is left: the wait only polls.
    Busy,
    /// Until an event.
    Sleep,
    /// Until an event or the deadline (absolute, the time counter's ns): a
    /// backstop for a wake that went astray.
    Until(u64),
}

/// What one [`Server::turn`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Turn {
    /// The source type of the event the wait returned, if any.
    pub event: Option<u8>,
    /// Calls served.
    pub calls: usize,
    /// The wait's refusal.
    pub error: Option<isize>,
}

/// The loop over one port.
pub struct Server<K: Kernel> {
    pub kernel: K,
    /// A calls event was taken and the calls it announced are not all served.
    owed: bool,
    /// No source but the calls: the turn sleeps in the accept, not on a port.
    calls_only: bool,
}

impl<K: Kernel> Server<K> {
    /// A server whose calls and other sources are bound to one port.
    pub const fn new(kernel: K) -> Self {
        Self { kernel, owed: false, calls_only: false }
    }

    /// A server with no source but its calls: each turn sleeps in the accept
    /// (the cost of the loop it replaces, the IPC fast path's hand-off
    /// included) and serves up to [`CALL_BATCH`] calls. The handler's `idle`
    /// still runs before each sleep; only its work is done, the sleep is the
    /// accept's.
    pub const fn calls_only(kernel: K) -> Self {
        Self { kernel, owed: false, calls_only: true }
    }

    /// Wait once (only poll while calls are owed or the handler has work
    /// left; otherwise until an event or the handler's deadline), dispatch
    /// the event, then serve up to [`CALL_BATCH`] calls.
    pub fn turn<H: Handler<K>>(&mut self, h: &mut H) -> Turn {
        let mut t = Turn::default();
        if self.calls_only {
            let _ = h.idle(&mut self.kernel);
            t.calls = self.serve(h, true);
            if t.calls == 0 {
                self.kernel.pause();
            }
            return t;
        }
        let deadline = match h.idle(&mut self.kernel) {
            _ if self.owed => 0,
            Idle::Busy => 0,
            Idle::Sleep => u64::MAX,
            Idle::Until(ns) => ns,
        };
        match self.kernel.wait(deadline) {
            Ok(Some(ev)) => {
                t.event = Some(ev.source_type);
                self.dispatch(h, &ev);
            }
            Ok(None) => {}
            Err(e) => {
                t.error = Some(e);
                self.kernel.pause();
                return t;
            }
        }
        if self.owed {
            t.calls = self.serve(h, false);
        }
        t
    }

    /// Turn for ever.
    pub fn run<H: Handler<K>>(&mut self, h: &mut H) -> ! {
        loop {
            self.turn(h);
        }
    }

    fn dispatch<H: Handler<K>>(&mut self, h: &mut H, ev: &Event) {
        let k = &mut self.kernel;
        match ev.source_type {
            PORT_EVENT_CALLS => self.owed = true,
            PORT_EVENT_IRQ => h.irq(k, ev.key, ev.cpu),
            PORT_EVENT_TIMER => h.timer(k, ev.key),
            PORT_EVENT_DOORBELL => h.doorbell(k, ev.key),
            _ => h.other(k, ev),
        }
    }

    /// Take calls until none is queued behind the last (`MSG_MORE` clear) or
    /// the accept finds none, at most [`CALL_BATCH`]; the first in the
    /// blocking accept when `sleep`.
    fn serve<H: Handler<K>>(&mut self, h: &mut H, sleep: bool) -> usize {
        for n in 0..TAKE {
            let mut req = MsgDesc::default();
            let taken = if sleep && n == 0 { self.kernel.accept_blocking(&mut req) } else { self.kernel.accept(&mut req) };
            let handle = match taken {
                Ok(Some(handle)) => handle,
                Ok(None) => {
                    self.owed = false;
                    return n;
                }
                // A refused accept says nothing of the queue: the calls stay
                // owed, so the next turn polls and takes them, after a back-off
                // (a calls-only turn backs off itself). Canary
                // `owed-drop-canary` (host): the refusal clears them, and the
                // server sleeps with calls queued that no event announces.
                Err(_) if cfg!(feature = "owed-drop-canary") => {
                    self.owed = false;
                    return n;
                }
                Err(_) => {
                    if !self.calls_only {
                        self.kernel.pause();
                    }
                    return n;
                }
            };
            let mut rep = MsgDesc::default();
            h.call(&mut self.kernel, handle, &req, &mut rep);
            let _ = self.kernel.reply(handle, &rep);
            if req.flags & MSG_MORE == 0 {
                self.owed = false;
                return n + 1;
            }
        }
        TAKE
    }
}

/// The home of a server's state when it is too big for the stack: a static,
/// written once by the server's one thread before it serves.
pub struct State<T>(core::cell::UnsafeCell<Option<T>>);

// SAFETY: `install` hands out the one reference, to the thread that serves;
// `T: Send` because that thread need not be the one the static was made on.
unsafe impl<T: Send> Sync for State<T> {}

impl<T> State<T> {
    pub const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(None))
    }

    /// Store `v` and return the one reference to it.
    ///
    /// # Safety
    /// Called once, by the thread that then serves, before any other thread
    /// of the process exists.
    pub unsafe fn install(&'static self, v: T) -> &'static mut T {
        // SAFETY: the caller's contract: no other reference exists or will.
        unsafe { (*self.0.get()).insert(v) }
    }
}

/// The kernel side over libsys.
#[cfg(feature = "libsys")]
pub mod sys;
