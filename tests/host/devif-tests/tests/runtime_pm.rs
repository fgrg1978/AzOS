// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Device runtime power management (`azos_devif::power::runtime`): the idle
//! clock and the autosuspend, the resume on use, the wakelock ledger (quota,
//! deadline, record) and `DevicePower` through its wire form.
//!
//! The state machine takes the time as an argument, so every test here picks
//! its own clock. Canaries are written next to each test: the edit that must
//! turn it red.

use azos_devif::outcome;
use azos_devif::power::runtime::{
    classes_of, Event, PmDevice, PmError, PmServer, Quota, Record, RuntimePm, CLASS_ALL, CLASS_EXEC, CLASS_READ,
    CLASS_WRITE, LEASES, RECORDS,
};
use azos_devif::power::{
    DevicePowerCall, DevicePowerClient, DevicePowerIdl, PM_ACTIVE, PM_STAT_AUTO_SUSPENDS, PM_STAT_EXPIRED,
    PM_STAT_GRANTED, PM_STAT_HELD, PM_STAT_RECORDED, PM_STAT_RECORD_BASE, PM_STAT_REFUSED, PM_STAT_RESUMES,
    PM_STAT_SUSPENDS, PM_SUSPENDED,
};
use azos_devif::{IdlError, MsgDesc, Out, PowerIdl, Transport};
use std::cell::RefCell;

const fn ms(n: u64) -> u64 {
    n * 1_000_000
}

/// A device that counts its transitions and fails them on demand.
#[derive(Default)]
struct Dev {
    suspends: u32,
    resumes: u32,
    fail_suspend: bool,
    fail_resume: bool,
}

impl PmDevice for Dev {
    fn suspend(&mut self) -> bool {
        self.suspends += 1;
        !self.fail_suspend
    }
    fn resume(&mut self) -> bool {
        self.resumes += 1;
        !self.fail_resume
    }
}

fn pm(idle_ms: u32) -> RuntimePm {
    let mut p = RuntimePm::new(Quota::new(2, 1_000), 0);
    p.set_idle_timeout_ms(idle_ms).unwrap();
    p
}

/// A device nobody used for its idle timeout suspends, once, and says why.
///
/// **Canaries.** Drop the `idle_ns` comparison in `due`: the first assertion
/// goes red. Count an automatic suspend as an explicit one: the auto counter
/// goes red.
#[test]
fn autosuspend_after_idle() {
    let mut p = pm(100);
    let mut d = Dev::default();
    p.tick(&mut d, ms(99));
    assert!(!p.is_suspended(), "99 ms of 100 is not idle enough");
    p.tick(&mut d, ms(100));
    assert!(p.is_suspended());
    assert_eq!((d.suspends, p.counters.suspends, p.counters.auto_suspends), (1, 1, 1));
    assert_eq!(p.record_at(0), Some(Record { t_ns: ms(100), event: Event::AutoSuspend, arg: 0 }));
    // A suspended device is not suspended again.
    p.tick(&mut d, ms(5_000));
    assert_eq!(d.suspends, 1);
}

/// Without a timeout (the default) nothing suspends by itself.
///
/// **Canary.** Treat 0 as "suspend at once": red.
#[test]
fn no_timeout_never_autosuspends() {
    let mut p = pm(0);
    let mut d = Dev::default();
    p.tick(&mut d, ms(3_600_000));
    assert!(!p.is_suspended());
    assert_eq!(p.next_deadline_ns(), None, "nothing timed");
}

/// A use restarts the clock; an idle mark does too, and neither suspends.
///
/// **Canary.** Skip the `last_busy_ns` update in `on_use`: the second
/// assertion goes red.
#[test]
fn use_restarts_the_idle_clock() {
    let mut p = pm(100);
    let mut d = Dev::default();
    p.on_use(&mut d, ms(60)).unwrap();
    p.tick(&mut d, ms(150));
    assert!(!p.is_suspended(), "90 ms since the use");
    p.idle(ms(140));
    p.tick(&mut d, ms(239));
    assert!(!p.is_suspended());
    p.tick(&mut d, ms(240));
    assert!(p.is_suspended());
    assert_eq!(d.resumes, 0, "using an active device resumes nothing");
}

/// A suspended device resumes when it is used, before the use; a resume the
/// device fails leaves it suspended and fails the use.
///
/// **Canaries.** Skip the resume in `on_use`: the first assertion goes red.
/// Mark the device active before the callback answers: the failure part goes
/// red.
#[test]
fn a_suspended_device_resumes_on_use() {
    let mut p = pm(100);
    let mut d = Dev::default();
    p.tick(&mut d, ms(100));
    assert!(p.is_suspended());
    assert_eq!(p.on_use(&mut d, ms(500)), Ok(()));
    assert!(!p.is_suspended());
    assert_eq!((d.resumes, p.counters.resumes), (1, 1));
    assert_eq!(p.record_at(0).map(|r| r.event), Some(Event::ResumeOnUse));
    // The clock restarted at the resume: 99 ms later it is still active.
    p.tick(&mut d, ms(599));
    assert!(!p.is_suspended());
    // A resume that fails.
    p.tick(&mut d, ms(600));
    assert!(p.is_suspended());
    d.fail_resume = true;
    assert_eq!(p.on_use(&mut d, ms(700)), Err(PmError::Callback));
    assert!(p.is_suspended(), "it stays suspended");
    assert_eq!(p.counters.callback_fails, 1);
    assert_eq!(p.record_at(0), Some(Record { t_ns: ms(700), event: Event::CallbackFailed, arg: 1 }));
    assert_eq!(PmError::Callback.outcome(), outcome::FAULT);
}

/// A suspend the device fails leaves it active and does not retry every tick.
///
/// **Canary.** Leave `last_busy_ns` alone on a failed suspend: the callback
/// count goes red.
#[test]
fn a_failed_suspend_is_tried_once_per_timeout() {
    let mut p = pm(100);
    let mut d = Dev { fail_suspend: true, ..Dev::default() };
    p.tick(&mut d, ms(100));
    p.tick(&mut d, ms(101));
    p.tick(&mut d, ms(150));
    assert!(!p.is_suspended());
    assert_eq!(d.suspends, 1);
    p.tick(&mut d, ms(200));
    assert_eq!(d.suspends, 2, "one timeout later");
    assert_eq!(p.counters.callback_fails, 2);
}

/// A live wakelock holds the device awake past its idle timeout and refuses
/// an explicit suspend; the device suspends when the lease is over, not
/// before and not later than the later of the two clocks.
///
/// **Canaries.** Ignore the leases in `due`: the first assertion goes red.
/// Ignore them in `suspend`: the `Held` assertion goes red.
#[test]
fn a_wakelock_holds_the_device_awake() {
    let mut p = pm(100);
    let mut d = Dev::default();
    let id = p.hold(ms(10), 500).unwrap();
    assert_ne!(id, 0);
    p.tick(&mut d, ms(300));
    assert!(!p.is_suspended(), "idle for 290 ms, but held");
    assert_eq!(p.suspend(&mut d, ms(300)), Err(PmError::Held));
    assert_eq!(p.record_at(0), Some(Record { t_ns: ms(300), event: Event::SuspendHeld, arg: 1 }));
    assert_eq!(PmError::Held.outcome(), outcome::BUSY);
    assert_eq!(p.next_deadline_ns(), Some(ms(510)), "the lease's deadline, which is also when it may suspend");
    p.tick(&mut d, ms(509));
    assert!(!p.is_suspended());
    p.tick(&mut d, ms(510));
    assert!(p.is_suspended(), "the lease lapsed and the clock had run out");
    assert_eq!(p.counters.auto_suspends, 1);
}

/// Releasing the lease lets the device suspend once the idle clock runs out
/// from the release.
///
/// **Canary.** Leave `last_busy_ns` alone in `release`: the 100 ms assertion
/// goes red (it suspends at once).
#[test]
fn a_released_wakelock_restarts_the_clock() {
    let mut p = pm(100);
    let mut d = Dev::default();
    let id = p.hold(0, 1_000).unwrap();
    p.tick(&mut d, ms(500));
    assert!(!p.is_suspended());
    assert_eq!(p.release(ms(500), id), Ok(()));
    p.tick(&mut d, ms(599));
    assert!(!p.is_suspended());
    p.tick(&mut d, ms(600));
    assert!(p.is_suspended());
    assert_eq!((p.counters.granted, p.counters.released, p.counters.expired), (1, 1, 0));
    // A second release of the same lease names nothing.
    assert_eq!(p.release(ms(700), id), Err(PmError::NoLease));
    assert_eq!(p.release(ms(700), 0), Err(PmError::NoLease));
    assert_eq!(PmError::NoLease.outcome(), outcome::NO_RESOURCE);
}

/// The quota bounds the live leases and the longest deadline; a refusal is
/// counted and recorded; a released or lapsed lease frees its place.
///
/// **Canaries.** Compare against `LEASES` instead of the quota: the `Quota`
/// assertion goes red. Skip `reap` in `hold`: a full ledger of lapsed leases
/// refuses the next hold and the last block goes red.
#[test]
fn the_wakelock_quota() {
    let mut p = pm(0);
    let a = p.hold(0, 100).unwrap();
    let b = p.hold(0, 1_000).unwrap();
    assert_ne!(a, b);
    assert_eq!(p.hold(0, 10), Err(PmError::Quota), "quota 2");
    assert_eq!(PmError::Quota.outcome(), outcome::BUSY);
    assert_eq!(p.record_at(0), Some(Record { t_ns: 0, event: Event::Refuse, arg: 10 }));
    // Ttl: 0 and past the ledger's longest.
    assert_eq!(p.hold(0, 0), Err(PmError::Ttl));
    assert_eq!(p.hold(0, 1_001), Err(PmError::Ttl));
    assert_eq!(PmError::Ttl.outcome(), outcome::BAD_ARGUMENT);
    assert_eq!(p.counters.refused, 3);
    // A release frees a place.
    assert_eq!(p.release(ms(1), a), Ok(()));
    let c = p.hold(ms(1), 50).unwrap();
    assert!(c != 0 && c != b);
    // A lapse frees one too: `b` is live until 1000 ms, `c` until 51 ms.
    assert_eq!(p.hold(ms(2), 50), Err(PmError::Quota));
    assert!(p.hold(ms(51), 50).is_ok(), "c lapsed at 51 ms");
    // A ledger full of lapsed leases takes a new one, and records the lapses.
    let mut full = RuntimePm::new(Quota::new(LEASES as u32, 1_000), 0);
    for _ in 0..LEASES {
        full.hold(0, 10).unwrap();
    }
    assert_eq!(full.hold(ms(5), 10), Err(PmError::Quota));
    assert!(full.hold(ms(10), 10).is_ok());
    assert_eq!(full.counters.expired as usize, LEASES);
}

/// A lease whose holder forgot it lapses at its deadline: counted, recorded
/// with the deadline as its time and the lease as its argument, and no longer
/// held.
///
/// **Canary.** Never reap: the held count, the `expired` counter and the
/// record all go red.
#[test]
fn a_wakelock_expires_and_is_recorded() {
    let mut p = pm(0);
    let id = p.hold(ms(100), 250).unwrap();
    assert_eq!(p.held(ms(349)), 1);
    assert_eq!(p.held(ms(350)), 0, "a deadline is exclusive");
    let mut d = Dev::default();
    p.tick(&mut d, ms(400));
    assert_eq!(p.counters.expired, 1);
    assert_eq!(p.record_at(0), Some(Record { t_ns: ms(350), event: Event::Lapse, arg: id }));
    assert_eq!(p.release(ms(400), id), Err(PmError::NoLease), "a lapsed lease cannot be released");
    assert_eq!(p.counters.released, 0);
}

/// The next instant the driver must wake: the soonest lease deadline, or the
/// autosuspend instant.
///
/// **Canary.** Report the idle instant while suspended: the last assertion
/// goes red.
#[test]
fn the_next_deadline() {
    let mut p = pm(100);
    let mut d = Dev::default();
    assert_eq!(p.next_deadline_ns(), Some(ms(100)));
    p.idle(ms(30));
    assert_eq!(p.next_deadline_ns(), Some(ms(130)));
    p.hold(ms(30), 40).unwrap();
    assert_eq!(p.next_deadline_ns(), Some(ms(70)), "the lease first");
    p.tick(&mut d, ms(70));
    assert_eq!(p.next_deadline_ns(), Some(ms(130)));
    p.tick(&mut d, ms(130));
    assert!(p.is_suspended());
    assert_eq!(p.next_deadline_ns(), None);
}

/// Explicit suspend and resume are idempotent and restart the clock.
#[test]
fn explicit_suspend_and_resume() {
    let mut p = pm(0);
    let mut d = Dev::default();
    assert_eq!(p.suspend(&mut d, ms(1)), Ok(()));
    assert_eq!(p.suspend(&mut d, ms(2)), Ok(()), "already suspended");
    assert_eq!(d.suspends, 1);
    assert_eq!(p.resume(&mut d, ms(3)), Ok(()));
    assert_eq!(p.resume(&mut d, ms(4)), Ok(()), "already active");
    assert_eq!(d.resumes, 1);
    assert_eq!((p.counters.suspends, p.counters.auto_suspends, p.counters.resumes), (1, 0, 1));
    assert_eq!(p.set_idle_timeout_ms(3_600_001), Err(PmError::Ttl));
}

/// The record ring keeps the newest `RECORDS`; the packed word round-trips.
///
/// **Canary.** Index the ring from the oldest: `record_at(0)` goes red.
#[test]
fn the_record_ring_keeps_the_newest() {
    let mut p = pm(0);
    for i in 0..(RECORDS as u32 + 5) {
        let id = p.hold(ms(i as u64), 10).unwrap();
        p.release(ms(i as u64), id).unwrap();
    }
    assert_eq!(p.counters.recorded as usize, 2 * (RECORDS + 5));
    let newest = p.record_at(0).unwrap();
    assert_eq!(newest.event, Event::Release);
    assert_eq!(newest.t_ns, ms(RECORDS as u64 + 4));
    assert!(p.record_at(RECORDS - 1).is_some());
    assert_eq!(p.record_at(RECORDS), None, "older ones are gone");
    let w = newest.pack();
    assert_eq!(Record::unpack(w), Some((RECORDS as u32 + 4, Event::Release, newest.arg)));
    assert_eq!(Record::unpack(0), None, "an empty word is no record");
}

/// Lease ids are never 0 and never repeat while live, across wrap.
#[test]
fn lease_ids_are_unique() {
    let mut p = RuntimePm::new(Quota::new(LEASES as u32, 1_000), 0);
    let mut seen = Vec::new();
    for _ in 0..LEASES {
        let id = p.hold(0, 10).unwrap();
        assert_ne!(id, 0);
        assert!(!seen.contains(&id));
        seen.push(id);
    }
    assert_eq!(Quota::new(0, 0), Quota { max_held: 1, max_ttl_ms: 1 }, "clamped");
    assert_eq!(Quota::new(99, 5).max_held as usize, LEASES);
}

// --- the wire form ---------------------------------------------------------

struct Host {
    pm: RuntimePm,
    dev: Dev,
    now_ns: u64,
    /// The badge the kernel stamps on the requests (`None`: a request that
    /// carries none).
    badge: Option<u64>,
}

/// The ring-3 host as the test sees it: the generated dispatcher over a
/// `PmServer`, at the host's clock.
struct Loop<'a>(&'a RefCell<Host>);

impl Transport for Loop<'_> {
    fn call(&self, msg: &mut MsgDesc) -> azos_idl::Result {
        let mut req = *msg;
        let mut h = self.0.borrow_mut();
        let Host { pm, dev, now_ns, badge } = &mut *h;
        if let Some(b) = *badge {
            // What `SYS_IPC_ACCEPT_V2` writes for a call through a badged capability.
            req.flags |= azos_abi::ipc_msg::MSG_BADGED;
            req.badge = b;
        }
        let mut srv = PmServer { pm, dev, now_ns: *now_ns, classes: classes_of(&req) };
        DevicePowerIdl::dispatch(&mut srv, &req, msg).map_err(|_| IdlError::Malformed)
    }
}

fn host(idle_ms: u32) -> RefCell<Host> {
    RefCell::new(Host { pm: pm(idle_ms), dev: Dev::default(), now_ns: 0, badge: Some(CLASS_ALL as u64) })
}

/// Every op of `DevicePower` through the client stub, the dispatcher and the
/// server, with its outcome.
#[test]
fn the_interface_round_trips() {
    let h = host(0);
    let mut c = DevicePowerClient::new(Loop(&h));
    assert_eq!(c.state(), Ok(Out::ok(PM_ACTIVE)));
    assert_eq!(c.set_idle_timeout(250), Ok(Out::ok(())));
    assert_eq!(c.set_idle_timeout(3_600_001), Ok(Out::err(outcome::BAD_ARGUMENT)));
    assert_eq!(c.stats(azos_devif::power::PM_STAT_IDLE_TIMEOUT_MS), Ok(Out::ok(250)));
    let lease = c.hold(500).unwrap().value;
    assert_ne!(lease, 0);
    assert_eq!(c.stats(PM_STAT_HELD), Ok(Out::ok(1)));
    assert_eq!(c.suspend(), Ok(Out::err(outcome::BUSY)), "a wakelock is live");
    assert_eq!(c.hold(0), Ok(Out::err(outcome::BAD_ARGUMENT)));
    assert_eq!(c.release(lease), Ok(Out::ok(())));
    assert_eq!(c.release(lease), Ok(Out::err(outcome::NO_RESOURCE)));
    assert_eq!(c.suspend(), Ok(Out::ok(())));
    assert_eq!(c.state(), Ok(Out::ok(PM_SUSPENDED)));
    assert_eq!(c.resume(), Ok(Out::ok(())));
    assert_eq!(c.state(), Ok(Out::ok(PM_ACTIVE)));
    assert_eq!(c.idle(), Ok(Out::ok(())));
    // The counters and the newest record through the selectors.
    assert_eq!(c.stats(PM_STAT_SUSPENDS), Ok(Out::ok(1)));
    assert_eq!(c.stats(PM_STAT_RESUMES), Ok(Out::ok(1)));
    assert_eq!(c.stats(PM_STAT_GRANTED), Ok(Out::ok(1)));
    assert_eq!(c.stats(PM_STAT_REFUSED), Ok(Out::ok(1)));
    assert_eq!(c.stats(PM_STAT_AUTO_SUSPENDS), Ok(Out::ok(0)));
    assert_eq!(c.stats(PM_STAT_EXPIRED), Ok(Out::ok(0)));
    let n = c.stats(PM_STAT_RECORDED).unwrap().value;
    assert!(n >= 5);
    let newest = c.stats(PM_STAT_RECORD_BASE).unwrap().value;
    assert_eq!(Record::unpack(newest).map(|r| r.1), Some(Event::Resume));
    assert_eq!(c.stats(PM_STAT_RECORD_BASE + RECORDS as u32), Ok(Out::err(outcome::BAD_ARGUMENT)));
    assert_eq!(c.stats(9_999), Ok(Out::err(outcome::BAD_ARGUMENT)));
}

/// The time of a request reaches the ledger: a lease granted over the wire
/// lapses at its deadline.
#[test]
fn a_lease_taken_over_the_wire_lapses() {
    let h = host(0);
    let id;
    {
        let mut c = DevicePowerClient::new(Loop(&h));
        id = c.hold(100).unwrap().value;
    }
    h.borrow_mut().now_ns = ms(100);
    let mut c = DevicePowerClient::new(Loop(&h));
    assert_eq!(c.stats(PM_STAT_HELD), Ok(Out::ok(0)));
    assert_eq!(c.release(id), Ok(Out::err(outcome::NO_RESOURCE)));
    assert_eq!(c.stats(PM_STAT_EXPIRED), Ok(Out::ok(1)));
}

/// What a retrying layer reads from the op table: `hold` is `at_most_once`
/// (a resend must not mint a second lease), the readers and the state setters
/// are `idempotent`.
#[test]
fn the_op_table_says_how_each_op_may_be_resent() {
    let t = DevicePowerIdl::OPS;
    assert_eq!(t.len(), 8);
    for o in t {
        assert!(o.on_failure.is_some() && o.deadline_ns > 0 && o.budget_us > 0, "{}", o.name);
        assert!(u64::from(o.budget_us) * 1000 <= o.deadline_ns, "{} fits its deadline", o.name);
        assert!(!o.once_only(), "{}: nothing here is irreversible", o.name);
        assert_eq!(o.at_most_once(), o.name == "hold", "{}", o.name);
        assert_eq!(o.idempotent(), o.name != "hold", "{}", o.name);
    }
}

/// `DevicePower`'s dispatcher refuses another interface's request with
/// `BadInterface` and answers it with that status, so an endpoint that serves
/// two interfaces must pick the dispatcher by the header's id first
/// (`azos_idl::header_id`), not by trying them in turn.
#[test]
fn a_foreign_request_is_refused_with_its_status() {
    let mut p = pm(0);
    let mut d = Dev::default();
    let mut srv = PmServer { pm: &mut p, dev: &mut d, now_ns: 0, classes: CLASS_ALL };
    let mut req = MsgDesc { version: azos_idl::MSG_VERSION, n_words: 1, ..MsgDesc::default() };
    req.words[0] = azos_idl::header(azos_devif::POWER_ID, PowerIdl::LEVEL, 1);
    let mut rep = MsgDesc::default();
    assert_eq!(DevicePowerIdl::dispatch(&mut srv, &req, &mut rep), Err(IdlError::BadInterface));
    assert_ne!(rep.words[0], 0, "the reply carries the refusal status");
    assert_ne!(azos_idl::header_id(req.words[0]), azos_devif::power::DEVICE_POWER_ID);
}

// --- the op classes ----------------------------------------------------------

/// Every op of the interface through the stub, with the outcome each answers
/// to a request that carries `badge`: `(name, outcome of that op)`.
fn all_ops(badge: Option<u64>) -> (RefCell<Host>, Vec<(&'static str, u32)>) {
    let h = host(0);
    h.borrow_mut().badge = badge;
    let mut c = DevicePowerClient::new(Loop(&h));
    let ops = vec![
        ("state", c.state().unwrap().code),
        ("stats", c.stats(PM_STAT_HELD).unwrap().code),
        ("suspend", c.suspend().unwrap().code),
        ("resume", c.resume().unwrap().code),
        ("idle", c.idle().unwrap().code),
        ("set_idle_timeout", c.set_idle_timeout(250).unwrap().code),
        ("hold", c.hold(500).unwrap().code),
        ("release", c.release(1).unwrap().code),
    ];
    drop(c);
    (h, ops)
}

fn denied(ops: &[(&str, u32)]) -> Vec<&'static str> {
    let names = ["state", "stats", "suspend", "resume", "idle", "set_idle_timeout", "hold", "release"];
    ops.iter().zip(names).filter(|((_, o), _)| *o == outcome::DENIED).map(|(_, n)| n).collect()
}

/// A request that carries no badge, or a badge with no class, may do nothing:
/// every op is `DENIED` and no counter, timeout or lease moved. The check
/// fails closed. Canary: `classes_of` returning `CLASS_ALL` for a request with
/// no `MSG_BADGED` turns this red.
#[test]
fn a_request_with_no_class_does_nothing() {
    for badge in [None, Some(0), Some(8), Some(0x100)] {
        let (h, ops) = all_ops(badge);
        assert_eq!(denied(&ops).len(), 8, "badge {badge:?}: {ops:?}");
        let h = h.borrow();
        assert_eq!(h.pm.counters, Default::default(), "nothing was recorded");
        assert_eq!(h.pm.idle_timeout_ms(), 0, "the idle timeout did not move");
        assert_eq!(h.dev.suspends + h.dev.resumes, 0);
    }
}

/// Each class opens exactly its ops, and a request carrying a class bit
/// without `MSG_BADGED` carries nothing. Canary: mapping `suspend` to
/// `CLASS_WRITE` in `PmServer` turns the exec case red.
#[test]
fn each_class_opens_its_own_ops() {
    let cases = [
        (CLASS_READ, vec!["suspend", "resume", "idle", "set_idle_timeout", "hold", "release"]),
        (CLASS_WRITE, vec!["state", "stats", "suspend", "resume", "set_idle_timeout"]),
        (CLASS_EXEC, vec!["state", "stats", "idle", "hold", "release"]),
        (CLASS_ALL, vec![]),
    ];
    for (class, want) in cases {
        let (_, ops) = all_ops(Some(class as u64));
        assert_eq!(denied(&ops), want, "class {class:#b}");
    }
    let mut bare = MsgDesc::default();
    bare.badge = CLASS_ALL as u64;
    assert_eq!(classes_of(&bare), 0, "a badge the kernel did not set is not a badge");
}

/// A holder with only `WRITE` (a wakelock client) cannot set the idle timeout
/// or suspend the device, and one with only `READ` cannot take a lease: the
/// attack the grant alone did not stop. Canary: `set_idle_timeout` without its
/// class check turns this red.
#[test]
fn a_wakelock_client_cannot_reconfigure_the_device() {
    let h = host(0);
    h.borrow_mut().badge = Some(CLASS_WRITE as u64);
    let mut c = DevicePowerClient::new(Loop(&h));
    assert_eq!(c.set_idle_timeout(0), Ok(Out::err(outcome::DENIED)));
    assert_eq!(c.set_idle_timeout(3_600_000), Ok(Out::err(outcome::DENIED)));
    assert_eq!(c.suspend(), Ok(Out::err(outcome::DENIED)));
    let lease = c.hold(100).unwrap().value;
    assert_ne!(lease, 0, "its own class works");
    drop(c);
    assert_eq!(h.borrow().pm.idle_timeout_ms(), 0);
    assert!(!h.borrow().pm.is_suspended());
    h.borrow_mut().badge = Some(CLASS_READ as u64);
    let mut c = DevicePowerClient::new(Loop(&h));
    assert_eq!(c.hold(100), Ok(Out::err(outcome::DENIED)));
    assert_eq!(c.release(lease), Ok(Out::err(outcome::DENIED)));
    assert_eq!(c.stats(PM_STAT_HELD), Ok(Out::ok(1)), "READ still observes the lease");
}
