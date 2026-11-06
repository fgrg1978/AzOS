// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 server runtime: one thread, one event port, one wait.
//!
//! A server binds everything it serves to one port: its endpoint's queued
//! calls (`PORT_SRC_CALLS`), its interrupt lines (`DEVICE_IRQ_BIND`), its
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
//! The kernel side is the [`Kernel`] trait: [`sys::Port`] over libsys (feature
//! `libsys`), a fake in the host suite (`tests/host/srv-tests`).

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
    /// Answer call `handle` with `rep`: 0 or a negative code.
    fn reply(&mut self, handle: u64, rep: &MsgDesc) -> isize;
    /// A wait failed: back off before the next one rather than spin.
    fn pause(&mut self) {}
}

/// What a call handler did with the call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    /// The answer is in `rep`: the runtime replies.
    Reply,
    /// The handler keeps the handle and answers (or delegates) it later.
    Held,
}

/// A server's entry points, one per kind of source.
pub trait Handler<K: Kernel> {
    /// Serve call `handle`: `req` as accepted, the answer into `rep`.
    fn call(&mut self, k: &mut K, handle: u64, req: &MsgDesc, rep: &mut MsgDesc) -> Answer;
    /// An interrupt on the line bound with `key`, routed to `cpu`.
    fn irq(&mut self, _k: &mut K, _key: u64, _cpu: u8) {}
    /// The timer armed with `key` fired (it is one-shot: re-arm it here).
    fn timer(&mut self, _k: &mut K, _key: u64) {}
    /// The doorbell word bound with `key` was woken.
    fn doorbell(&mut self, _k: &mut K, _key: u64) {}
    /// Any other event: a notice, a source that is gone, a ring, pressure.
    fn other(&mut self, _k: &mut K, _ev: &Event) {}
    /// Called before every wait: do the work that needs no event and
    /// announce the sleeps the doorbells stand for. `true`: work is left, so
    /// the wait only polls.
    fn idle(&mut self, _k: &mut K) -> bool {
        false
    }
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
}

impl<K: Kernel> Server<K> {
    pub const fn new(kernel: K) -> Self {
        Self { kernel, owed: false }
    }

    /// Wait once (only poll while calls are owed or the handler has work
    /// left), dispatch the event, then serve up to [`CALL_BATCH`] calls.
    pub fn turn<H: Handler<K>>(&mut self, h: &mut H) -> Turn {
        let mut t = Turn::default();
        let busy = h.idle(&mut self.kernel);
        let deadline = if self.owed || busy { 0 } else { u64::MAX };
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
            t.calls = self.serve(h);
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

    fn serve<H: Handler<K>>(&mut self, h: &mut H) -> usize {
        for n in 0..TAKE {
            let mut req = MsgDesc::default();
            let Ok(Some(handle)) = self.kernel.accept(&mut req) else {
                self.owed = false;
                return n;
            };
            let mut rep = MsgDesc::default();
            if h.call(&mut self.kernel, handle, &req, &mut rep) == Answer::Reply {
                let _ = self.kernel.reply(handle, &rep);
            }
            if req.flags & MSG_MORE == 0 {
                self.owed = false;
                return n + 1;
            }
        }
        TAKE
    }
}

/// The kernel side over libsys.
#[cfg(feature = "libsys")]
pub mod sys {
    use super::{Event, Kernel, MsgDesc};
    use azos_libsys as sys;

    /// How long a server backs off after a refused wait, ms.
    const PAUSE_MS: u64 = 10;

    const E_AGAIN: isize = azos_abi::error::Errno::EAGAIN.to_syscall_ret() as isize;

    /// A server's event port.
    #[derive(Clone, Copy)]
    pub struct Port {
        pub cap: u32,
    }

    /// `r` as a result: the value, or the negative code.
    fn ok(r: isize) -> Result<(), isize> {
        if r < 0 { Err(r) } else { Ok(()) }
    }

    impl Port {
        /// A new port of this task's.
        pub fn create() -> Result<Port, isize> {
            let cap = sys::port_create_typed();
            if cap <= 0 { Err(cap.min(-1)) } else { Ok(Port { cap: cap as u32 }) }
        }

        /// Report the calls queued on the endpoint `ep` this task serves.
        pub fn bind_calls(&self, ep: u32, key: u64) -> Result<(), isize> {
            ok(sys::port_bind_calls(self.cap, ep, key))
        }

        /// Report the wakes of the word at `offset` of the region `region`.
        pub fn bind_doorbell(&self, region: u32, offset: u32, key: u64) -> Result<(), isize> {
            ok(sys::port_bind_doorbell(self.cap, region, offset, key))
        }

        /// Report the interrupts of the line `line` (routed to `cpu`): the
        /// CPU the kernel routed it to.
        pub fn bind_irq(&self, line: u32, key: u64, cpu: u64) -> Result<u32, isize> {
            let r = sys::irq_bind(line, self.cap, key, cpu);
            ok(r).map(|()| r as u32)
        }

        /// Arm (or re-arm) the one-shot timer `key` for `deadline_ns`.
        pub fn arm(&self, key: u64, deadline_ns: u64) -> Result<(), isize> {
            ok(sys::port_bind_timer(self.cap, deadline_ns, key))
        }
    }

    impl Kernel for Port {
        fn wait(&mut self, deadline_ns: u64) -> Result<Option<Event>, isize> {
            let mut b = [0u8; sys::PORT_EVENT_BYTES];
            match sys::port_wait_until_typed(self.cap, &mut b, deadline_ns) {
                0 => Ok(None),
                n if n < 0 => Err(n),
                _ => Ok(Some(sys::port_event_decode(&b))),
            }
        }

        fn accept(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize> {
            match sys::ipc_accept_poll(req) {
                h if h >= 0 => Ok(Some(h as u64)),
                E_AGAIN => Ok(None),
                e => Err(e),
            }
        }

        fn reply(&mut self, handle: u64, rep: &MsgDesc) -> isize {
            sys::ipc_reply_v2(handle, rep)
        }

        fn pause(&mut self) {
            sys::sleep(PAUSE_MS);
        }
    }
}
