// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The runtime's dispatch over the kernel's call queues (see the crate doc).
//! An integration test, so `ep_queue.rs`'s own suite (`tests/host/ipc-fast-tests`)
//! is not compiled in beside it to race on the same queues.

use azos_srv_tests::ep_queue::{self, Collected, NO_DONEE};
use azos_srv_tests::port_link::{LinkSet, PortLink};
use azos_abi::ipc_msg::{MsgDesc, MSG_MORE};
use azos_abi::syscall_nr::{PortEventInfo, PORT_EVENT_CALLS, PORT_EVENT_DOORBELL, PORT_EVENT_IRQ, PORT_EVENT_TIMER};
use azos_srv::{Event, Handler, Idle, Kernel, Server, CALL_BATCH};
use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

const SERVER: u32 = 7;
const SERVER_IDX: usize = 3;
const EP: usize = 5;
const GEN: u32 = 9;
const LINK: PortLink = PortLink { port: 0x41, epoch: 1, slot: 0 };
const CALLS_KEY: u64 = 0xCA11;

static SERIAL: Mutex<()> = Mutex::new(());

/// The stand-in port and the kernel calls the runtime makes.
#[derive(Default)]
struct Fake {
    /// Queued events: interrupts.
    queued: VecDeque<Event>,
    /// The calls source's pending bit.
    calls: bool,
    /// Timers and doorbells that are due, in table order.
    table: VecDeque<Event>,
    sources_first: bool,
    /// Waits that found nothing and had no deadline: a sleep in the kernel.
    slept: usize,
    accepts: usize,
    /// The deadline of every wait, in order.
    deadlines: Vec<u64>,
    /// Accepts to refuse (`-EFAULT`) before the next one is served.
    refuse: usize,
}

fn ev(source_type: u8, key: u64) -> Event {
    PortEventInfo { key, source_type, code: 0, cpu: 0, source_id: 0 }
}

impl Fake {
    fn take_table(&mut self) -> Option<Event> {
        if self.calls {
            self.calls = false;
            return Some(ev(PORT_EVENT_CALLS, CALLS_KEY));
        }
        self.table.pop_front()
    }

    fn take(&mut self) -> Option<Event> {
        let (e, from_table) = if self.sources_first {
            match self.take_table() {
                Some(e) => (e, true),
                None => (self.queued.pop_front()?, false),
            }
        } else {
            match self.queued.pop_front() {
                Some(e) => (e, false),
                None => (self.take_table()?, true),
            }
        };
        self.sources_first = !from_table;
        Some(e)
    }
}

impl Kernel for Fake {
    fn wait(&mut self, deadline_ns: u64) -> Result<Option<Event>, isize> {
        self.deadlines.push(deadline_ns);
        let e = self.take();
        if e.is_none() && deadline_ns == u64::MAX {
            self.slept += 1;
        }
        Ok(e)
    }

    fn accept(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize> {
        self.accepts += 1;
        if self.refuse > 0 {
            self.refuse -= 1;
            return Err(-14);
        }
        let Some((h, _caller, words, _cap)) = ep_queue::accept::<false>(SERVER_IDX, SERVER, |_| {}) else {
            return Ok(None);
        };
        req.words[..4].copy_from_slice(&words);
        req.n_words = 4;
        if ep_queue::more_queued(SERVER_IDX) {
            req.flags |= MSG_MORE;
        }
        Ok(Some(h))
    }

    /// The host cannot sleep: the accept that would, returns.
    fn accept_blocking(&mut self, req: &mut MsgDesc) -> Result<Option<u64>, isize> {
        let taken = self.accept(req);
        if matches!(taken, Ok(None)) {
            self.slept += 1;
        }
        taken
    }

    fn reply(&mut self, handle: u64, rep: &MsgDesc) -> isize {
        match ep_queue::reply(handle, SERVER, false, [rep.words[0], 0, 0, 0]) {
            ep_queue::Reply::Woke { .. } => 0,
            _ => -1,
        }
    }
}

/// A server that answers `w0 + 1` and records what reached it.
#[derive(Default)]
struct Echo {
    calls: Vec<u64>,
    irqs: Vec<u64>,
    timers: Vec<u64>,
    doorbells: Vec<u64>,
    /// A doorbell's sleep is announced before every wait.
    announced: usize,
    /// Work left after `idle`: the next wait polls.
    busy: bool,
    /// A backstop `idle` asks for.
    until: Option<u64>,
}

impl Handler<Fake> for Echo {
    fn call(&mut self, _k: &mut Fake, _h: u64, req: &MsgDesc, rep: &mut MsgDesc) {
        self.calls.push(req.words[0]);
        rep.words[0] = req.words[0] + 1;
        rep.n_words = 1;
    }
    fn irq(&mut self, _k: &mut Fake, key: u64, _cpu: u8) {
        self.irqs.push(key);
    }
    fn timer(&mut self, _k: &mut Fake, key: u64) {
        self.timers.push(key);
    }
    fn doorbell(&mut self, _k: &mut Fake, key: u64) {
        self.doorbells.push(key);
    }
    fn idle(&mut self, _k: &mut Fake) -> Idle {
        self.announced += 1;
        match (core::mem::take(&mut self.busy), self.until) {
            (true, _) => Idle::Busy,
            (false, Some(ns)) => Idle::Until(ns),
            (false, None) => Idle::Sleep,
        }
    }
}

struct Scene {
    srv: Server<Fake>,
    h: Echo,
    /// Task slots of this test's callers start here (a slot's call record
    /// is its own, so tests do not share one).
    base: usize,
    _g: MutexGuard<'static, ()>,
}

impl Scene {
    /// A fresh endpoint whose calls are bound to the port.
    fn new(base: usize) -> Self {
        let mut s = Self::unbound(base);
        s.bind();
        s
    }

    /// A fresh endpoint, not bound yet.
    fn unbound(base: usize) -> Self {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        ep_queue::close(EP);
        let _ = ep_queue::drain(EP, -1, SERVER, |_| {});
        ep_queue::open(EP, GEN, SERVER);
        Scene { srv: Server::new(Fake::default()), h: Echo::default(), base, _g: g }
    }

    /// The bind (`PORT_BIND` of `PORT_SRC_CALLS`): a call queued before it is
    /// signalled by the binder.
    fn bind(&mut self) {
        if let Ok(LinkSet::Stored { ready: true }) = ep_queue::set_call_link(EP, GEN, SERVER, LINK, PortLink::NONE) {
            self.srv.kernel.calls = true;
        }
    }

    fn client(&self, i: usize) -> (usize, u32) {
        (self.base + i, 1000 + (self.base + i) as u32)
    }

    /// Client `i` calls with `w0`; the link it hands back signals the port
    /// (`fastcall::call`'s `port_signal`).
    fn call(&mut self, i: usize, w0: u64) -> u64 {
        let (idx, tid) = self.client(i);
        let (h, link) = ep_queue::call_linked(idx, tid, EP, GEN, SERVER, SERVER_IDX, [w0, 0, 0, 0], 0, NO_DONEE)
            .expect("the call is queued");
        if link == LINK {
            self.srv.kernel.calls = true;
        }
        h
    }

    fn answer(&self, i: usize, h: u64) -> Option<u64> {
        match ep_queue::collect(h, self.client(i).1) {
            Collected::Reply(w, _) => Some(w[0]),
            _ => None,
        }
    }

    /// Turn until `done` or `turns` run out (the timeout of a server that
    /// would sleep for ever).
    fn turn_until(&mut self, turns: usize, done: impl Fn(&Echo) -> bool) -> bool {
        for _ in 0..turns {
            if done(&self.h) {
                return true;
            }
            self.srv.turn(&mut self.h);
        }
        done(&self.h)
    }
}

/// The F14 row on the host: one thread serves a call and an interrupt
/// that reach one port. **Canary** `port-calls-canary`: the call never
/// signals the port, the server sleeps, and the timeout fails the test.
#[test]
fn a_call_and_an_irq_on_one_port_are_served_by_one_thread() {
    let mut s = Scene::new(10);
    s.srv.kernel.queued.push_back(ev(PORT_EVENT_IRQ, 0x1E));
    let h = s.call(0, 41);
    assert!(s.turn_until(4, |e| e.calls.len() == 1 && e.irqs.len() == 1), "the call or the interrupt was not served in time");
    assert_eq!(s.answer(0, h), Some(42));
    assert_eq!(s.h.irqs, [0x1E]);
    // Nothing is left: the next turn sleeps.
    s.srv.turn(&mut s.h);
    assert_eq!(s.srv.kernel.slept, 1);
}

/// Calls are served in the order they were queued, all of them on one
/// event: `MSG_MORE` says one is behind, and no empty accept is paid.
#[test]
fn queued_calls_are_served_in_order_without_an_empty_accept() {
    let mut s = Scene::new(20);
    let hs: Vec<u64> = (0..3).map(|i| s.call(i, 100 + i as u64)).collect();
    let t = s.srv.turn(&mut s.h);
    assert_eq!((t.event, t.calls), (Some(PORT_EVENT_CALLS), 3));
    assert_eq!(s.h.calls, [100, 101, 102]);
    assert_eq!(s.srv.kernel.accepts, 3, "the last accept had MSG_MORE clear");
    for (i, h) in hs.into_iter().enumerate() {
        assert_eq!(s.answer(i, h), Some(101 + i as u64));
    }
    // A call after the queue emptied signals the port again.
    let h = s.call(5, 7);
    assert!(s.turn_until(2, |e| e.calls.len() == 4));
    assert_eq!(s.answer(5, h), Some(8));
}

/// Calls queued before the bind are reported by it.
#[test]
fn a_call_queued_before_the_bind_is_served() {
    let mut s = Scene::unbound(30);
    let (idx, tid) = s.client(0);
    let h = ep_queue::call(idx, tid, EP, GEN, SERVER, SERVER_IDX, [5, 0, 0, 0], 0, NO_DONEE).unwrap();
    s.bind();
    assert!(s.turn_until(2, |e| e.calls == [5]));
    assert_eq!(s.answer(0, h), Some(6));
}

/// A storm of calls does not starve a timer, and a storm of interrupts
/// does not starve the calls: each turn takes one port event and at most
/// a batch of calls, and the port alternates its two classes.
#[test]
fn neither_calls_nor_interrupts_starve_the_other() {
    let mut s = Scene::new(40);
    let n = 3 * CALL_BATCH;
    let hs: Vec<u64> = (0..n).map(|i| s.call(i, i as u64)).collect();
    s.srv.kernel.table.push_back(ev(PORT_EVENT_TIMER, 0x7));
    for k in 0..50 {
        s.srv.kernel.queued.push_back(ev(PORT_EVENT_IRQ, k));
    }
    s.srv.turn(&mut s.h);
    s.srv.turn(&mut s.h);
    assert!(!s.h.calls.is_empty(), "the interrupts starved the calls");
    assert!(s.h.calls.len() <= 2 * CALL_BATCH, "a turn takes one batch");
    assert!(!s.h.irqs.is_empty(), "the calls starved the interrupts");
    assert!(s.turn_until(4, |e| e.timers == [0x7]), "the calls starved the timer");
    assert!(s.turn_until(n, |e| e.calls.len() == n));
    for (i, h) in hs.into_iter().enumerate() {
        assert_eq!(s.answer(i, h), Some(i as u64 + 1));
    }
    assert!(s.turn_until(60, |e| e.irqs.len() == 50));
}

/// A call withdrawn between the event and the accept costs one empty
/// accept, and the server sleeps again instead of blocking in it.
#[test]
fn a_withdrawn_call_leaves_the_server_waiting_on_its_port() {
    let mut s = Scene::new(70);
    let h = s.call(0, 1);
    let _ = ep_queue::abandon(h, s.client(0).1);
    let t = s.srv.turn(&mut s.h);
    assert_eq!((t.event, t.calls), (Some(PORT_EVENT_CALLS), 0));
    s.srv.turn(&mut s.h);
    assert_eq!(s.srv.kernel.slept, 1, "the next wait sleeps on the port");
    s.srv.kernel.table.push_back(ev(PORT_EVENT_DOORBELL, 0xD));
    s.srv.turn(&mut s.h);
    assert_eq!(s.h.doorbells, [0xD], "and another source still reaches it");
}

/// The handler's `idle` runs before every wait; work it leaves makes the
/// wait a poll.
#[test]
fn work_left_by_idle_makes_the_wait_a_poll() {
    let mut s = Scene::new(80);
    s.h.busy = true;
    s.srv.turn(&mut s.h);
    assert_eq!(s.srv.kernel.slept, 0, "busy: the wait polled");
    s.srv.turn(&mut s.h);
    assert_eq!(s.srv.kernel.slept, 1);
    assert_eq!(s.h.announced, 2);
}

/// A backstop deadline from `idle` bounds the wait, unless calls are owed.
#[test]
fn a_deadline_from_idle_bounds_the_wait_and_owed_calls_poll() {
    let mut s = Scene::new(90);
    s.h.until = Some(77);
    s.srv.turn(&mut s.h);
    let n = CALL_BATCH + 2;
    let hs: Vec<u64> = (0..n).map(|i| s.call(i, i as u64)).collect();
    s.srv.turn(&mut s.h);
    s.srv.turn(&mut s.h);
    assert_eq!(s.srv.kernel.deadlines, [77, 77, 0], "a batch left calls owed: the third wait polls");
    for (i, h) in hs.into_iter().enumerate() {
        assert_eq!(s.answer(i, h), Some(i as u64 + 1));
    }
}

/// A server with no source but its calls sleeps in the accept, never on a
/// port, and still serves its queue in batches with `MSG_MORE`.
#[test]
fn a_calls_only_server_sleeps_in_the_accept() {
    let mut s = Scene::unbound(110);
    s.srv = Server::calls_only(Fake::default());
    let n = CALL_BATCH + 1;
    let hs: Vec<u64> = (0..n).map(|i| s.call(i, 10 * i as u64)).collect();
    let t = s.srv.turn(&mut s.h);
    assert_eq!((t.event, t.calls), (None, CALL_BATCH));
    let t = s.srv.turn(&mut s.h);
    assert_eq!(t.calls, 1);
    assert_eq!(s.srv.kernel.accepts, n, "no empty accept after the last call (MSG_MORE clear)");
    s.srv.turn(&mut s.h);
    assert_eq!(s.srv.kernel.slept, 1, "an empty queue sleeps in the accept");
    assert!(s.srv.kernel.deadlines.is_empty(), "and never on a port");
    assert_eq!(s.h.announced, 3, "idle ran before every sleep");
    for (i, h) in hs.into_iter().enumerate() {
        assert_eq!(s.answer(i, h), Some(10 * i as u64 + 1));
    }
}

/// A refused accept (a fault writing the descriptor) says nothing of the
/// queue: the calls stay owed and the next turn polls for them instead of
/// sleeping. **Canary** `owed-drop-canary`: the refusal clears them, the
/// queued call announces nothing more, and the server sleeps.
#[test]
fn a_refused_accept_keeps_the_calls_owed() {
    let mut s = Scene::new(130);
    let h = s.call(0, 20);
    s.srv.kernel.refuse = 1;
    let t = s.srv.turn(&mut s.h);
    assert_eq!((t.event, t.calls), (Some(PORT_EVENT_CALLS), 0));
    s.srv.turn(&mut s.h);
    assert_eq!(s.srv.kernel.deadlines, [u64::MAX, 0], "the second wait only polls");
    assert_eq!(s.answer(0, h), Some(21));
}
