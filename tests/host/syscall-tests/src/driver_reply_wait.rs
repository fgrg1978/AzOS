// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The user-driver proxy's blocking wait (`crates/drivers/driver_server/src/reply_wait.rs`)
// against the REAL registry: the waiter is armed with the submit, the reply
// path takes it and wakes it, and the wait loop never loses a wake that lands
// between its test and its block.
//
// The scheduler is modelled, not run: `FakeEnv::block` sleeps until the
// deadline (a timer sweep) unless a wake stamped the task first, which is the
// K-C9 behaviour the kernel's `wake_task_by_tid` gives a task that has not yet
// committed to `Blocked`. A lost wake therefore shows up as time passing to
// the deadline, which every test below measures.
//
// Canaries (each run by hand, see the wave-8 PROXY report):
//   * `driver_reply` stops taking/waking the waiter → the two lost-wake tests
//     and the syscall-path test fail (the clock reaches the deadline; no wake
//     recorded).
//   * `wait_for_reply` blocks before re-testing → the pre-block reply test
//     fails (one block where none is due).
//   * `wait_for_reply` loops again on a refused block → the refused test
//     fails (more than one block).

use super::harness::serial;
use core::cell::{Cell, RefCell};
use azos_driver_server::reply_wait::{
    proxy_hooks, set_proxy_hooks, wait_for_reply, ProxyHooks, ReplyWaitEnv, WaitOutcome,
    Withdrawn, MAX_REPLY_WAITERS,
};
use azos_driver_server::{
    driver_disarm_waiter, driver_fetch_request, driver_register, driver_submit_request_armed,
    driver_try_take_reply, driver_unregister, driver_withdraw_waiter, reply_posted, ArmedRequest,
    DriverReply, DriverRequest,
};
use std::sync::Mutex;

/// Wakes the reply path issued, in order: `(tid, deadline)`.
static WAKES: Mutex<Vec<(u32, u64)>> = Mutex::new(Vec::new());
/// Tasks woken before they blocked: their next block returns at once (K-C9).
static STAMPS: Mutex<Vec<u32>> = Mutex::new(Vec::new());

fn t_wake(tid: u32, deadline: u64) {
    WAKES.lock().unwrap().push((tid, deadline));
    STAMPS.lock().unwrap().push(tid);
}
fn t_block(_deadline: u64) -> bool {
    unreachable!("the tests block through FakeEnv, not the hook")
}
fn t_tid() -> u32 {
    0
}
fn t_donate(_donor: u32, _target: u32) -> bool {
    false
}
fn t_undonate(_target: u32) {}
fn t_peer_running(_tid: u32) -> bool {
    false
}

static TEST_HOOKS: ProxyHooks = ProxyHooks {
    block: t_block,
    wake: t_wake,
    current_tid: t_tid,
    donate: t_donate,
    undonate: t_undonate,
    peer_running: t_peer_running,
};

/// Install the recording hooks and clear what the last test recorded.
fn hooks_reset() {
    set_proxy_hooks(&TEST_HOOKS);
    WAKES.lock().unwrap().clear();
    STAMPS.lock().unwrap().clear();
}

fn wakes() -> Vec<(u32, u64)> {
    WAKES.lock().unwrap().clone()
}

/// A task `tid` blocking on `Timer(deadline)`. `on_block` runs inside the
/// first block, before the task commits — the window a reply can land in.
struct FakeEnv {
    tid: u32,
    now: Cell<u64>,
    blocks: Cell<u32>,
    refuse: bool,
    on_block: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl FakeEnv {
    fn new(tid: u32) -> Self {
        FakeEnv { tid, now: Cell::new(0), blocks: Cell::new(0), refuse: false, on_block: RefCell::new(None) }
    }
}

impl ReplyWaitEnv for FakeEnv {
    fn now(&self) -> u64 {
        self.now.get()
    }
    fn block(&self, deadline: u64) -> bool {
        self.blocks.set(self.blocks.get() + 1);
        if let Some(f) = self.on_block.borrow_mut().take() {
            f();
        }
        if self.refuse {
            // A loop that ignores refusals would spin here forever with the
            // clock stopped; end it at the deadline so the test fails on its
            // assertions instead of hanging.
            if self.blocks.get() > 3 {
                self.now.set(deadline);
            }
            return true;
        }
        let mut st = STAMPS.lock().unwrap();
        if let Some(i) = st.iter().position(|&t| t == self.tid) {
            st.remove(i); // the stamp is consumed; no time passes
        } else {
            self.now.set(deadline); // slept until the timer sweep
        }
        false
    }
}

fn reply_for(token: u64) -> DriverReply {
    let mut r = DriverReply::zeroed();
    r.token = token;
    r.out_len = 2;
    r.output[0] = 0xA5;
    r
}

const DEADLINE: u64 = 1_000;
const CLIENT: u32 = 77;
const DRIVER: u32 = 5;

/// Register `kind` to `DRIVER` and queue one armed request from `CLIENT`.
fn armed_req(kind: u32) -> ArmedRequest {
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    let a = driver_submit_request_armed(kind, u32::MAX, 0, &[0x42], 8, CLIENT, DEADLINE)
        .expect("armed submit refused");
    assert_eq!(a.driver_tid, DRIVER, "the submit must name the registered driver (the donation target)");
    a
}

fn armed(kind: u32) -> u64 {
    armed_req(kind).token
}

/// The proxy's wait, as `UserDriverProxy::call` runs it: poll the lock-free
/// posted flag, and take the reply out of the row on the way out.
fn wait_as(env: &FakeEnv, kind: u32, tid: u32, a: ArmedRequest) -> (WaitOutcome, Option<DriverReply>) {
    let got: Cell<Option<DriverReply>> = Cell::new(None);
    let o = wait_for_reply(
        env,
        DEADLINE,
        || got.get().is_some() || reply_posted(a.slot, a.row, a.token),
        || {
            if let Withdrawn::Replied(r) = driver_withdraw_waiter(kind, tid, a.token) {
                got.set(Some(r));
            }
        },
    );
    (o, got.get())
}

fn wait(env: &FakeEnv, kind: u32, token: u64) -> WaitOutcome {
    let a = find_armed(kind, token);
    let (o, r) = wait_as(env, kind, CLIENT, a);
    if o == WaitOutcome::Replied {
        assert_eq!(r.map(|r| r.token), Some(token), "Replied without the reply in hand");
    }
    o
}

/// The `ArmedRequest` of the one request `armed` queued on a fresh kind: its
/// registry slot, and row 0 (the first row armed).
fn find_armed(kind: u32, token: u64) -> ArmedRequest {
    ArmedRequest { token, driver_tid: DRIVER, slot: slot_of(kind), row: 0 }
}

fn slot_of(kind: u32) -> usize {
    let reg = azos_driver_server::REGISTRY.lock();
    reg.slots
        .iter()
        .position(|s| s.active.load(core::sync::atomic::Ordering::Relaxed) && s.kind == kind)
        .expect("kind not registered")
}

/// THE lost-wake case: the reply lands after the wait's test and before its
/// block. The wake stamps the not-yet-blocked task, the block returns at once,
/// the re-test finds the reply — no time passes.
#[test]
fn a_reply_between_the_test_and_the_block_is_not_lost() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A01;
    let token = armed(kind);
    let env = FakeEnv::new(CLIENT);
    *env.on_block.borrow_mut() = Some(Box::new(move || {
        assert!(azos_driver_server::driver_reply(kind, reply_for(token)));
    }));
    assert_eq!(wait(&env, kind, token), WaitOutcome::Replied);
    assert_eq!(env.now.get(), 0, "the client slept to its deadline: the wake was lost");
    assert_eq!(wakes(), vec![(CLIENT, DEADLINE)]);
    assert!(driver_unregister(kind));
}

/// Through the syscall the ring-3 driver actually issues
/// (`sys_driver_reply_fetch`, gpio_drv's one trap per request): the reply it
/// posts wakes the armed kernel client.
#[test]
fn the_drivers_reply_fetch_wakes_the_armed_client() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A02;
    let token = armed(kind);
    let env = FakeEnv::new(CLIENT);
    *env.on_block.borrow_mut() = Some(Box::new(move || {
        // Kernel context (user_pt 0), so the handler reads/writes these
        // host buffers directly.
        let reply = reply_for(token);
        let mut next = DriverRequest::zeroed();
        let _ = sys_driver_reply_fetch(
            kind as u64,
            &reply as *const DriverReply as u64,
            &mut next as *mut DriverRequest as u64,
        );
    }));
    // The driver takes the request first, as gpio_drv does.
    assert!(driver_fetch_request(kind).is_some());
    assert_eq!(wait(&env, kind, token), WaitOutcome::Replied);
    assert_eq!(env.now.get(), 0, "sys_driver_reply_fetch published without waking the client");
    assert_eq!(wakes(), vec![(CLIENT, DEADLINE)]);
    assert!(driver_unregister(kind));
}

/// A reply that is already there needs no block at all.
#[test]
fn a_reply_before_the_first_test_needs_no_block() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A03;
    let token = armed(kind);
    assert!(azos_driver_server::driver_reply(kind, reply_for(token)));
    let env = FakeEnv::new(CLIENT);
    assert_eq!(wait(&env, kind, token), WaitOutcome::Replied);
    assert_eq!(env.blocks.get(), 0, "blocked although the reply was already published");
    assert!(driver_unregister(kind));
}

/// No reply: the wait ends at the deadline, withdraws its row, and a reply
/// that arrives afterwards wakes nobody.
#[test]
fn a_timeout_disarms_and_a_late_reply_wakes_nobody() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A04;
    let token = armed(kind);
    let env = FakeEnv::new(CLIENT);
    assert_eq!(wait(&env, kind, token), WaitOutcome::TimedOut);
    assert_eq!(env.now.get(), DEADLINE);
    assert!(!driver_disarm_waiter(kind, CLIENT, token), "the timed-out waiter is still armed");
    assert!(azos_driver_server::driver_reply(kind, reply_for(token)));
    assert!(wakes().is_empty(), "a late reply woke a client that had stopped waiting");
    assert!(driver_unregister(kind));
}

/// Wave 15 (COHERENCE-AUDIT, dead client): a client that gives up cancels
/// the request it queued, if the driver has not fetched it. Two requests
/// queued, the FIRST one's client times out: the driver's next fetch is the
/// second one, and then the queue is empty — the abandoned operation never
/// runs. Canary `driver-cancel-skip-canary` (the dequeue skipped): the fetch
/// returns the abandoned request first.
#[test]
fn a_client_that_gives_up_cancels_its_queued_request() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A0C;
    let first = armed_req(kind);
    let second = driver_submit_request_armed(kind, u32::MAX, 0, &[0x43], 8, CLIENT + 1, DEADLINE)
        .expect("second armed submit refused");
    let env = FakeEnv::new(CLIENT);
    assert_eq!(wait(&env, kind, first.token), WaitOutcome::TimedOut);
    let next = driver_fetch_request(kind).map(|r| r.token);
    assert_eq!(next, Some(second.token),
               "the driver fetched the request its client abandoned (or lost the live one)");
    assert!(driver_fetch_request(kind).is_none(), "the abandoned request is still queued");
    // A fetched request cannot be recalled: withdrawing after the fetch
    // leaves nothing else changed and the queue stays empty.
    assert!(driver_disarm_waiter(kind, CLIENT + 1, second.token));
    assert!(driver_fetch_request(kind).is_none());
    assert!(driver_unregister(kind));
}

/// `DriverQueue::remove_token` keeps FIFO order across the ring's wrap.
#[test]
fn removing_a_token_keeps_the_queue_order_across_the_wrap() {
    use azos_driver_server::{DriverQueue, DRIVER_REQUEST_QUEUE_DEPTH as D};
    let mut q = DriverQueue::new();
    let req = |t: u64| { let mut r = DriverRequest::zeroed(); r.token = t; r };
    // Advance the tail so the live entries straddle the end of the array.
    for t in 0..(D as u64 - 2) { assert!(q.push(req(1000 + t))); }
    for _ in 0..(D - 2) { q.pop(); }
    for t in 1..=(D as u64) { assert!(q.push(req(t))); }
    assert!(!q.push(req(99)), "the queue holds DEPTH entries");
    assert!(q.remove_token(3));
    assert!(!q.remove_token(3), "a token is removed once");
    assert!(q.push(req(99)), "the removal freed one entry");
    let mut got = Vec::new();
    while let Some(r) = q.pop() { got.push(r.token); }
    let mut want: Vec<u64> = (1..=(D as u64)).filter(|&t| t != 3).collect();
    want.push(99);
    assert_eq!(got, want);
}

/// K-C29: the scheduler refuses to block. The wait gives up after ONE block
/// instead of spinning on refusals, and withdraws its row.
#[test]
fn a_refused_block_returns_without_spinning() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A05;
    let token = armed(kind);
    let mut env = FakeEnv::new(CLIENT);
    env.refuse = true;
    assert_eq!(wait(&env, kind, token), WaitOutcome::Refused);
    assert_eq!(env.blocks.get(), 1);
    assert!(!driver_disarm_waiter(kind, CLIENT, token));
    assert!(driver_unregister(kind));
}

/// A reply racing the deadline counts as a reply: the verdict is read after
/// the row is withdrawn.
#[test]
fn a_reply_that_races_the_deadline_is_still_a_reply() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A06;
    let token = armed(kind);
    let env = FakeEnv::new(CLIENT);
    env.now.set(DEADLINE); // already due at the first test
    let a = find_armed(kind, token);
    let got: Cell<Option<DriverReply>> = Cell::new(None);
    let mut first = true;
    let outcome = wait_for_reply(
        &env,
        DEADLINE,
        || {
            if first {
                first = false;
                false
            } else {
                got.get().is_some() || reply_posted(a.slot, a.row, token)
            }
        },
        || {
            assert!(azos_driver_server::driver_reply(kind, reply_for(token)));
            if let Withdrawn::Replied(r) = driver_withdraw_waiter(kind, CLIENT, token) {
                got.set(Some(r));
            }
        },
    );
    assert_eq!(outcome, WaitOutcome::Replied);
    assert_eq!(got.get().map(|r| r.token), Some(token), "the racing reply was not taken");
    assert!(driver_unregister(kind));
}

/// Every waiter row armed: the next armed submit is refused and queues
/// nothing, rather than queueing a request whose client could not be woken.
#[test]
fn a_full_waiter_table_refuses_the_submit_and_queues_nothing() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A07;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    for i in 0..MAX_REPLY_WAITERS as u32 {
        assert!(driver_submit_request_armed(kind, u32::MAX, 0, &[], 0, 100 + i, DEADLINE).is_some());
    }
    // The driver drains the queue; the clients are still waiting.
    for _ in 0..MAX_REPLY_WAITERS {
        assert!(driver_fetch_request(kind).is_some());
    }
    assert!(driver_submit_request_armed(kind, u32::MAX, 0, &[], 0, 999, DEADLINE).is_none());
    assert!(driver_fetch_request(kind).is_none(), "a refused submit queued its request");
    assert!(driver_unregister(kind));
}

/// The hooks the kernel installs are what the reply path uses.
#[test]
fn installed_hooks_are_read_back() {
    let _g = serial();
    hooks_reset();
    let h = proxy_hooks().expect("hooks not installed");
    assert!(core::ptr::eq(h, &TEST_HOOKS));
}

/// A released kind leaves nothing behind: a later registration of the same
/// slot, possibly for another kind, is not handed requests or waiters
/// addressed to the driver that went away.
#[test]
fn release_clears_the_queue_and_the_waiters() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A08;
    let _ = armed(kind);
    assert!(azos_driver_server::driver_release_all(DRIVER) >= 1);
    let other = 0x9A09;
    assert!(driver_register(other, DRIVER + 1, 0, 0, 0));
    assert!(driver_fetch_request(other).is_none(), "the new driver inherited a dead driver's request");
    assert!(driver_unregister(other));
}

/// Plan item 7: a driver that dies with a client armed on it wakes that
/// client, which ends its wait at once with no reply (the proxy's "posted but
/// gone" arm, reported `TimedOut`) instead of sleeping out its reply budget.
///
/// Canary: `--features azos_driver_server/driver-release-nowake-canary` (the
/// release clears the rows and wakes nobody): no wake is recorded and the
/// client's clock reads its deadline.
#[test]
fn a_released_driver_wakes_its_armed_clients() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A0A;
    const DYING: u32 = DRIVER + 40;
    assert!(driver_register(kind, DYING, 0, 0, 0));
    let a = driver_submit_request_armed(kind, u32::MAX, 0, &[0x42], 8, CLIENT, DEADLINE)
        .expect("armed submit refused");
    let env = FakeEnv::new(CLIENT);
    *env.on_block.borrow_mut() = Some(Box::new(move || {
        // The driver dies while the client sleeps: its exit hook's release.
        assert_eq!(azos_driver_server::driver_release_all(DYING), 1);
    }));
    let (o, r) = wait_as(&env, kind, CLIENT, a);
    assert_eq!(wakes(), vec![(CLIENT, DEADLINE)], "the release woke no armed client");
    assert_eq!(env.now.get(), 0, "the client slept out its reply budget");
    assert_eq!((o, r.is_none()), (WaitOutcome::Replied, true), "a released kind delivered a reply");
}

// ── One reply slot per request (wave 9, item 4b) ─────────────────────────────
//
// Before: `last_reply` was one per kind, so with two clients of one driver
// waiting at once, a reply to the second published before the first took its
// own overwrote it, and the first client slept to its deadline.
//
// Canary (run by hand, wave-9 PROXY2 report): `ReplyWaiters::deliver` writing
// every reply into row 0 (one slot per kind again) fails the two tests below —
// client A's withdraw returns B's reply or nothing.

/// Two kernel clients of one kind wait at once; the driver answers B before A
/// has taken its reply. Each takes its OWN payload.
#[test]
fn two_concurrent_clients_each_get_their_own_reply() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A0A;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    let a = driver_submit_request_armed(kind, u32::MAX, 0, &[1], 8, 201, DEADLINE).unwrap();
    let b = driver_submit_request_armed(kind, u32::MAX, 0, &[2], 8, 202, DEADLINE).unwrap();
    assert_ne!(a.row, b.row);
    let mut ra = reply_for(a.token);
    ra.output[1] = 0xAA;
    let mut rb = reply_for(b.token);
    rb.output[1] = 0xBB;
    assert!(azos_driver_server::driver_reply(kind, ra));
    assert!(azos_driver_server::driver_reply(kind, rb));
    assert!(reply_posted(a.slot, a.row, a.token) && reply_posted(b.slot, b.row, b.token));
    match driver_withdraw_waiter(kind, 201, a.token) {
        Withdrawn::Replied(r) => assert_eq!((r.token, r.output[1]), (a.token, 0xAA),
                                            "client A was handed another request's reply"),
        other => panic!("client A lost its reply: {:?}", other.is_armed_only()),
    }
    match driver_withdraw_waiter(kind, 202, b.token) {
        Withdrawn::Replied(r) => assert_eq!((r.token, r.output[1]), (b.token, 0xBB)),
        other => panic!("client B lost its reply: {:?}", other.is_armed_only()),
    }
    assert_eq!(wakes(), vec![(201, DEADLINE), (202, DEADLINE)]);
    assert!(driver_unregister(kind));
}

/// The same through the wait loop: the second client's reply arriving while
/// the first is inside its block does not cost the first its reply.
#[test]
fn a_second_clients_reply_does_not_end_the_first_clients_wait_empty() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A0B;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    let a = driver_submit_request_armed(kind, u32::MAX, 0, &[1], 8, 211, DEADLINE).unwrap();
    let b = driver_submit_request_armed(kind, u32::MAX, 0, &[2], 8, 212, DEADLINE).unwrap();
    let env = FakeEnv::new(211);
    *env.on_block.borrow_mut() = Some(Box::new(move || {
        assert!(azos_driver_server::driver_reply(kind, reply_for(a.token)));
        assert!(azos_driver_server::driver_reply(kind, reply_for(b.token)));
    }));
    let (o, r) = wait_as(&env, kind, 211, a);
    assert_eq!(o, WaitOutcome::Replied);
    assert_eq!(r.map(|r| r.token), Some(a.token));
    assert_eq!(env.now.get(), 0, "client A slept to its deadline");
    let env_b = FakeEnv::new(212);
    let (ob, rb) = wait_as(&env_b, kind, 212, b);
    assert_eq!((ob, rb.map(|r| r.token)), (WaitOutcome::Replied, Some(b.token)));
    assert!(driver_unregister(kind));
}

/// A duplicate reply to a token already delivered changes nothing: the first
/// reply stays in the row and the client is woken once.
#[test]
fn a_duplicate_reply_neither_overwrites_nor_wakes_again() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A0C;
    let a = armed_req(kind);
    let mut first = reply_for(a.token);
    first.output[1] = 1;
    let mut dup = reply_for(a.token);
    dup.output[1] = 2;
    assert!(azos_driver_server::driver_reply(kind, first));
    assert!(azos_driver_server::driver_reply(kind, dup));
    match driver_withdraw_waiter(kind, CLIENT, a.token) {
        Withdrawn::Replied(r) => assert_eq!(r.output[1], 1, "the duplicate overwrote the reply"),
        _ => panic!("no reply in the row"),
    }
    assert_eq!(wakes().len(), 1);
    assert!(driver_unregister(kind));
}

/// Polling (ring-3) clients: each token keeps its own entry, so a reply for a
/// second token does not erase the first one's.
#[test]
fn polling_clients_keep_one_reply_per_token() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A0D;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    let t1 = azos_driver_server::driver_submit_request(kind, 31, 0, &[], 8);
    let t2 = azos_driver_server::driver_submit_request(kind, 32, 0, &[], 8);
    assert!(azos_driver_server::driver_reply(kind, reply_for(t1)));
    assert!(azos_driver_server::driver_reply(kind, reply_for(t2)));
    let mut out = DriverReply::zeroed();
    assert!(driver_try_take_reply(kind, t1, &mut out), "the second reply erased the first");
    assert_eq!(out.token, t1);
    assert!(driver_try_take_reply(kind, t2, &mut out));
    assert_eq!(out.token, t2);
    assert!(driver_unregister(kind));
}

/// The ring keeps the newest `REPLY_RING_DEPTH` tokens: one more evicts the
/// oldest, and only it.
#[test]
fn the_polling_ring_evicts_only_the_oldest_token() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A0E;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    let n = azos_driver_server::REPLY_RING_DEPTH as u64;
    for t in 1..=n + 1 {
        assert!(azos_driver_server::driver_reply(kind, reply_for(1000 + t)));
    }
    let mut out = DriverReply::zeroed();
    assert!(!driver_try_take_reply(kind, 1001, &mut out), "the oldest survived a full ring");
    for t in 2..=n + 1 {
        assert!(driver_try_take_reply(kind, 1000 + t, &mut out), "token {} was evicted", 1000 + t);
    }
    assert!(driver_unregister(kind));
}

trait ArmedOnly {
    fn is_armed_only(&self) -> &'static str;
}
impl ArmedOnly for Withdrawn {
    fn is_armed_only(&self) -> &'static str {
        match self {
            Withdrawn::NotArmed => "NotArmed",
            Withdrawn::Armed => "Armed (no reply)",
            Withdrawn::Replied(_) => "Replied",
        }
    }
}

// ── The bounded spin before the block (wave 9, item 1) ───────────────────────
//
// `SpinEnv` is `FakeEnv` plus a driver that is "running on another hart" for
// as long as `running` says, and a clock that advances one tick per `now()`.
// `polls` counts the reply tests.
//
// Canaries (run by hand, wave-9 PROXY2 report):
//   * drop both `env.peer_running()` checks (spin always) → the not-running
//     test fails: it polls before blocking;
//   * drop the `end` bound → the bounded test runs the clock to the deadline;
//   * drop the "one spin per block" shape (spin at the loop top without a
//     block after it) → the one-spin-per-block test counts no block.

struct SpinEnv {
    now: Cell<u64>,
    running: bool,
    spin: u64,
    blocks: Cell<u32>,
    hits: Cell<u32>,
    /// Tick at which the reply "lands" (checked by the test's closure).
    reply_at: u64,
}

impl ReplyWaitEnv for SpinEnv {
    fn now(&self) -> u64 {
        let t = self.now.get();
        self.now.set(t + 1);
        t
    }
    fn block(&self, deadline: u64) -> bool {
        self.blocks.set(self.blocks.get() + 1);
        // Asleep until the reply wakes us, or the deadline.
        let wake = if self.reply_at < deadline { self.reply_at } else { deadline };
        if self.now.get() < wake {
            self.now.set(wake);
        }
        false
    }
    fn peer_running(&self) -> bool {
        self.running
    }
    fn spin_ticks(&self) -> u64 {
        self.spin
    }
    fn note_spin_hit(&self) {
        self.hits.set(self.hits.get() + 1);
    }
}

fn spin_env(running: bool, spin: u64, reply_at: u64) -> SpinEnv {
    SpinEnv { now: Cell::new(0), running, spin, blocks: Cell::new(0), hits: Cell::new(0), reply_at }
}

/// Runs the loop with a reply that is ready from tick `env.reply_at`; returns
/// (outcome, reply tests made before the first block).
fn spin_wait(env: &SpinEnv) -> (WaitOutcome, u32) {
    let polls_before_block = Cell::new(0u32);
    let o = wait_for_reply(
        env,
        DEADLINE,
        || {
            if env.blocks.get() == 0 {
                polls_before_block.set(polls_before_block.get() + 1);
            }
            env.now.get() >= env.reply_at
        },
        || {},
    );
    (o, polls_before_block.get())
}

/// Driver running elsewhere, reply 5 ticks in, bound 20: found by the spin,
/// no block at all.
#[test]
fn a_running_driver_is_spun_on_and_the_block_is_skipped() {
    let env = spin_env(true, 20, 5);
    let (o, _) = spin_wait(&env);
    assert_eq!(o, WaitOutcome::Replied);
    assert_eq!(env.blocks.get(), 0, "blocked although the reply landed inside the spin");
    assert_eq!(env.hits.get(), 1);
}

/// Driver NOT running: exactly one reply test (the loop's own), then the
/// block — no spin.
#[test]
fn a_driver_that_is_not_running_is_never_spun_on() {
    let env = spin_env(false, 20, 5);
    let (o, polls) = spin_wait(&env);
    assert_eq!(o, WaitOutcome::Replied);
    assert_eq!(polls, 1, "spun on a driver that was not running");
    assert_eq!(env.blocks.get(), 1);
    assert_eq!(env.hits.get(), 0);
}

/// Reply beyond the bound: the spin stops at it, then the loop blocks, and
/// the time spent spinning is the bound, not the deadline.
#[test]
fn the_spin_is_bounded_and_then_blocks() {
    let env = spin_env(true, 20, 500);
    let (o, polls) = spin_wait(&env);
    assert_eq!(o, WaitOutcome::Replied);
    assert!(env.blocks.get() >= 1, "never blocked");
    assert!(polls <= 25, "spun {} polls for a bound of 20 ticks", polls);
    assert_eq!(env.hits.get(), 0);
}

/// No reply at all: one spin per block, and the wait still ends at the
/// deadline with a timeout rather than spinning to it.
#[test]
fn one_spin_per_block_and_a_timeout_still_times_out() {
    let env = spin_env(true, 20, u64::MAX);
    let (o, polls) = spin_wait(&env);
    assert_eq!(o, WaitOutcome::TimedOut);
    assert_eq!(env.blocks.get(), 1, "the loop must block after its spin");
    assert!(polls <= 25);
}

// ── The driver's own park (`SYS_DRIVER_REPLY_WAIT`, wave 9) ────────────────
//
// A driver on 610 blocks while its queue is empty; every submit takes the
// park in the hold that queues the request and wakes it after. Same model as
// above: a wake is recorded (and stamps the driver) or it is lost.
//
// Canaries (run by hand, wave 9 MLR3 report):
//   * `driver_submit_request_armed` no longer takes/wakes the park → the
//     armed-submit test fails (no wake recorded).
//   * `driver_fetch_or_park` does not record the park → same.

use azos_driver_server::{driver_fetch_or_park, driver_submit_request, driver_unpark, FetchOrPark};

const PARK: u64 = 5_000;

#[test]
fn a_submit_wakes_the_driver_parked_on_its_empty_queue() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A20;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Parked));
    let token = driver_submit_request_armed(kind, u32::MAX, 1, &[1, 2, 3, 4], 16, CLIENT, DEADLINE)
        .expect("armed submit refused")
        .token;
    assert_eq!(wakes(), vec![(DRIVER, PARK)], "the parked driver was not woken by the submit");
    // Woken (or stamped): the driver's next look takes the request.
    match driver_fetch_or_park(kind, DRIVER, PARK) {
        FetchOrPark::Request(r) => assert_eq!(r.token, token),
        _ => panic!("the queued request was not handed to the woken driver"),
    }
    assert!(driver_unregister(kind));
}

#[test]
fn a_ring3_clients_submit_wakes_the_parked_driver_too() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A21;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Parked));
    assert_ne!(driver_submit_request(kind, CLIENT, 1, &[9], 8), 0);
    assert_eq!(wakes(), vec![(DRIVER, PARK)]);
    assert!(driver_unregister(kind));
}

#[test]
fn a_queued_request_is_taken_without_parking_and_wakes_nobody() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A22;
    let token = armed(kind);
    match driver_fetch_or_park(kind, DRIVER, PARK) {
        FetchOrPark::Request(r) => assert_eq!(r.token, token),
        _ => panic!("a queued request must be taken, not parked on"),
    }
    // Nothing is parked now, so the next submit wakes nobody.
    let _ = driver_submit_request_armed(kind, u32::MAX, 1, &[1], 8, CLIENT + 1, DEADLINE);
    assert_eq!(wakes(), vec![]);
    assert!(driver_unregister(kind));
}

#[test]
fn an_ended_park_is_withdrawn_and_a_later_submit_wakes_nobody() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A23;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Parked));
    assert!(driver_unpark(kind, DRIVER));
    assert!(!driver_unpark(kind, DRIVER), "a park is withdrawn once");
    assert_ne!(driver_submit_request(kind, CLIENT, 1, &[9], 8), 0);
    assert_eq!(wakes(), vec![]);
    assert!(driver_unregister(kind));
}

#[test]
fn only_the_kinds_driver_parks_and_a_release_clears_the_park() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A24;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    assert!(matches!(driver_fetch_or_park(kind, DRIVER + 9, PARK), FetchOrPark::NotOwner));
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Parked));
    assert!(azos_driver_server::driver_release_all(DRIVER) >= 1);
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::NotOwner));
    // Re-registered by a new task: the dead driver's park is gone with it.
    assert!(driver_register(kind, DRIVER + 1, 0, 0, 0));
    assert_ne!(driver_submit_request(kind, CLIENT, 1, &[9], 8), 0);
    assert_eq!(wakes(), vec![], "a submit woke the task that released the kind");
    assert!(driver_unregister(kind));
}

/// Through the syscall: a request already queued is handed over at once, the
/// reply owed is published (waking its client), and nothing blocks.
#[test]
fn reply_wait_publishes_the_reply_and_takes_a_queued_request_without_blocking() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A25;
    let token = armed(kind);
    assert!(driver_fetch_request(kind).is_some());
    let next = driver_submit_request_armed(kind, u32::MAX, 7, &[5], 8, CLIENT + 1, DEADLINE)
        .expect("second submit refused")
        .token;
    WAKES.lock().unwrap().clear();
    let reply = reply_for(token);
    let mut req = DriverRequest::zeroed();
    let rc = sys_driver_reply_wait(
        kind as u64,
        &reply as *const DriverReply as u64,
        &mut req as *mut DriverRequest as u64,
        0,
    );
    assert_eq!(rc, 0);
    assert_eq!(req.token, next, "the queued request was not written");
    assert_eq!(req.op, 7);
    assert_eq!(wakes(), vec![(CLIENT, DEADLINE)], "the reply's client was not woken");
    assert!(driver_unregister(kind));
}

// ── The park and the M4 supervisor (wave 9 integration) ─────────────────────
//
// SUP stops a driver at its next driver-side call and orphans its slot at the
// death; MLR3 parks a driver on its empty queue. A parked driver must be woken
// by the stop (else it sleeps to its park deadline before it can exit), and an
// orphaned slot must not keep the dead task's park (a submit in the gap would
// wake a TID that may be reused).
//
// Canaries (run by hand, integration report): drop the park wake from
// `driver_request_stop` → the first test records no wake; drop the
// `parked = None` in `driver_orphan_all` → the second records the dead TID.

#[test]
fn a_stop_request_wakes_the_parked_driver() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A26;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Parked));
    assert_eq!(azos_driver_server::driver_request_stop(kind), Some(DRIVER));
    assert_eq!(wakes(), vec![(DRIVER, PARK)], "the stop left the driver parked to its deadline");
    assert!(azos_driver_server::driver_take_stop(kind, DRIVER));
    assert!(driver_unregister(kind));
}

#[test]
fn an_orphaned_slot_drops_the_dead_drivers_park() {
    let _g = serial();
    hooks_reset();
    let kind = 0x9A27;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Parked));
    assert_eq!(azos_driver_server::driver_orphan_all(DRIVER), 1);
    // Queued for the successor, and nobody woken: the parked task is dead.
    assert_ne!(driver_submit_request(kind, CLIENT, 1, &[9], 8), 0);
    assert_eq!(wakes(), vec![], "a submit in the gap woke the dead driver's TID");
    assert_eq!(azos_driver_server::driver_adopt(DRIVER, DRIVER + 1), 1);
    match driver_fetch_or_park(kind, DRIVER + 1, PARK) {
        FetchOrPark::Request(r) => assert_eq!(r.op, 1),
        _ => panic!("the successor did not get the request queued in the gap"),
    }
    assert!(driver_unregister(kind));
}

/// Owner decision 2026-09-28: a fresh `DriverSlot` and `ReplyRing` are all
/// zero (so `REGISTRY` lands in `.bss`), and that changed no number handed
/// out. The first token of a slot is 1, the next 2 — 0 stays "no token", the
/// value `REPLY_POSTED` starts at — and the first reply filed in a fresh ring
/// gets a non-zero sequence, so it is found (sequence 0 means "empty").
///
/// **Canaries.** Drop the `+ 1` in `issue_token`: the first token reads 0.
/// Put `publish`'s increment back after the store: the reply is filed under
/// sequence 0 and `lookup` misses it.
#[test]
fn a_zeroed_slot_still_issues_token_one_first_and_files_the_first_reply() {
    use azos_driver_server::{issue_token, DriverSlot, ReplyRing};
    use std::sync::atomic::Ordering;
    let slot = DriverSlot::empty();
    assert_eq!(slot.next_token.load(Ordering::Relaxed), 0, "a fresh slot's counter is zero");
    assert_eq!(issue_token(&slot), 1, "the first token");
    assert_eq!(issue_token(&slot), 2, "the second token");

    let mut ring = ReplyRing::new();
    ring.publish(reply_for(7));
    let mut out = DriverReply::zeroed();
    assert!(ring.lookup(7, &mut out), "the first reply of a fresh ring was not filed");
    assert_eq!(out.token, 7);
}

// ── The idle-pass counter (wave 10, DRV2) ───────────────────────────────────
//
// `driver_empty_fetches` is what the AQ3 and DRV1 smokes assert a parked
// driver's idleness with, so it must count one per idle pass and no more: an
// empty 581/523 fetch, or a 610 park, but not the last look a 610 call takes
// after its park ended (that park was already counted), and never a fetch
// that took a request.
//
// Canary (by hand, DRV2 report): count in `driver_fetch_after_park` too → the
// per-park count reads 2.

#[test]
fn the_idle_counter_counts_one_per_idle_pass() {
    use azos_driver_server::{driver_empty_fetches, driver_fetch_after_park};
    let _g = serial();
    hooks_reset();
    let kind = 0x9A28;
    assert!(driver_register(kind, DRIVER, 0, 0, 0));
    let c0 = driver_empty_fetches(kind).expect("registered kind has a count");
    // A 581 poll that finds nothing: one.
    assert!(driver_fetch_request(kind).is_none());
    assert_eq!(driver_empty_fetches(kind), Some(c0 + 1));
    // A 610 park that ends at its deadline: the park, then the last look.
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Parked));
    assert!(driver_unpark(kind, DRIVER));
    assert!(driver_fetch_after_park(kind).is_none());
    assert_eq!(driver_empty_fetches(kind), Some(c0 + 2), "one park counted other than once");
    // Fetches that take a request are not idle.
    assert_ne!(driver_submit_request(kind, CLIENT, 1, &[9], 8), 0);
    assert!(matches!(driver_fetch_or_park(kind, DRIVER, PARK), FetchOrPark::Request(_)));
    assert_ne!(driver_submit_request(kind, CLIENT, 1, &[9], 8), 0);
    assert!(driver_fetch_request(kind).is_some());
    assert_eq!(driver_empty_fetches(kind), Some(c0 + 2), "a fetch that took a request was counted");
    assert!(driver_unregister(kind));
    assert_eq!(driver_empty_fetches(kind), None, "an unregistered kind has no count");
}
