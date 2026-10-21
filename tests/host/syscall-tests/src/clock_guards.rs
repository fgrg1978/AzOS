// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `Clock` interface (the clock discipline's
// door for the PTP daemon) -- `crates/core/syscall/src/clock.rs::Server`, and
// `khost::serve` in front of it. The loops themselves are tested in
// `tests/host/drivers-tests/src/discipline.rs`; this is the authority and the
// answers.
//
// Included inside `mod handlers { .. }` like `entropy_guards.rs`.
//
// The vDSO page is not initialised on the host, so the page setters are no-ops
// and `status` is the observable.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::clock::{FILTERED, SLEWED, STATE_SYNCED, STATE_UNSET, STEPPED};
use azos_devif::{key, outcome, Clock, ClockIdl, Out};
use azos_idl::{header, MsgDesc, Writer, MSG_VERSION};
use crate::khost::Caller;

const SLOT: usize = 48;
const UNIX_2026: i64 = 1_789_257_600_000_000_000;
const MS: i64 = 1_000_000;

fn setup() -> u32 {
    crate::clock::__clock_reset_for_tests();
    let tid = 0x7e45_0001;
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn server(tid: u32, rights: CapPerms) -> crate::clock::Server {
    crate::clock::Server(Caller { tid, badge: 0, rights })
}

/// `sample` needs `WRITE` and `status` `READ`; a refusal changes nothing.
/// **Canary:** skip the gate: the `READ`-only caller sets the clock.
#[test]
fn the_right_is_checked_first() {
    let _g = serial();
    let tid = setup();
    for rights in [CapPerms::NONE, CapPerms::READ, CapPerms::EXEC] {
        assert_eq!(server(tid, rights).sample(UNIX_2026, 100_000, 1), Out::err(outcome::DENIED), "{rights:?}");
    }
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        assert_eq!(server(tid, rights).status().code, outcome::DENIED, "{rights:?}");
    }
    let st = server(tid, CapPerms::READ).status();
    assert!(st.is_ok());
    assert_eq!((st.value.state, st.value.steps), (STATE_UNSET, 0), "nothing was taken from a refused call");
}

/// A source the interface does not name is `BAD_ARGUMENT` and counts for
/// nothing.
#[test]
fn an_unknown_source_is_refused_before_the_discipline() {
    let _g = serial();
    let tid = setup();
    let mut s = server(tid, CapPerms::WRITE);
    for src in [0, 3, u32::MAX] {
        assert_eq!(s.sample(UNIX_2026, 100_000, src), Out::err(outcome::BAD_ARGUMENT), "source {src}");
    }
    assert_eq!(server(tid, CapPerms::READ).status().value.state, STATE_UNSET);
}

/// The answers, in order: the first sample sets the clock (STEPPED), a small
/// offset is slewed (and `status` shows the phase and the source), an offset
/// over the threshold needs a second to agree (FILTERED, then STEPPED), and a
/// jump past the panic threshold is `REFUSED` and counted.
/// **Canary:** `confirm = 1` makes the FILTERED row a STEPPED.
#[test]
fn the_discipline_answers_through_the_interface() {
    let _g = serial();
    let tid = setup();
    let mut w = server(tid, CapPerms::WRITE);
    let r = server(tid, CapPerms::READ);

    assert_eq!(w.sample(UNIX_2026, 100_000, 1), Out::ok(STEPPED), "the first sample is the boot step");
    let st = r.status().value;
    assert_eq!((st.state, st.steps, st.source), (STATE_SYNCED, 1, 1));

    assert_eq!(w.sample(5 * MS, 100_000, 2), Out::ok(SLEWED));
    let st = r.status().value;
    assert_eq!((st.source, st.phase_ns), (2, 5 * MS), "the phase to remove is the offset, from the PTP source");

    assert_eq!(w.sample(-500 * MS, 100_000, 2), Out::ok(FILTERED), "the first of a step");
    assert_eq!(w.sample(-500 * MS, 100_000, 2), Out::ok(STEPPED), "agreed");
    assert_eq!(r.status().value.steps, 2);

    assert_eq!(w.sample(2_000_000 * MS, 100_000, 2), Out::err(outcome::REFUSED), "2000 s after boot");
    assert_eq!(r.status().value.steps, 2);
    assert!(r.status().value.rejected >= 2, "the filtered and the refused");
}

/// A delay the discipline does not trust is FILTERED and moves nothing.
#[test]
fn a_late_sample_is_filtered() {
    let _g = serial();
    let tid = setup();
    let mut w = server(tid, CapPerms::WRITE);
    assert_eq!(w.sample(UNIX_2026, 5_000_000_000, 1), Out::ok(FILTERED), "over the delay ceiling, even the first");
    assert_eq!(server(tid, CapPerms::READ).status().value.state, STATE_UNSET);
}

/// Through the dispatcher: the op's two words and signed offset travel the
/// wire form, and `status` comes back as six words.
#[test]
fn the_wire_form_round_trips() {
    let _g = serial();
    let tid = setup();
    let who = Caller { tid, badge: 0, rights: CapPerms::RW };
    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(ClockIdl::ID, ClockIdl::LEVEL, ClockIdl::OP_SAMPLE));
        w.word(UNIX_2026 as u64);
        w.word(100_000);
        w.word(1);
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::CLOCK, &who, &req, &mut rep);
    assert_eq!((rep.words[0], rep.words[1] as u32, rep.words[2] as u32), (azos_idl::STATUS_OK, outcome::OK, STEPPED));

    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(ClockIdl::ID, ClockIdl::LEVEL, ClockIdl::OP_STATUS));
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::CLOCK, &who, &req, &mut rep);
    assert_eq!((rep.words[0], rep.words[1] as u32), (azos_idl::STATUS_OK, outcome::OK));
    assert_eq!((rep.words[2], rep.words[3], rep.words[6]), (STATE_SYNCED as u64, 1, 1), "state, source, steps");
}

/// Records of the clock-step rule, oldest first.
fn step_records() -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == azos_decision::Rule::ClockStep as u8 {
            v.push(*r);
        }
    });
    v
}

/// **A step is a decision on the record**: the boot step and a confirmed one
/// are written `Admit`, a refused one `Refuse`, each with the clock, the size
/// of the jump and the threshold it crossed (0 for the boot step); a slewed,
/// a filtered and a rejected sample write nothing.
/// **Canary:** drop the `record` call: the counts do not move.
#[test]
fn steps_and_refusals_are_recorded() {
    use azos_decision::Verdict;
    let _g = serial();
    let tid = setup();
    let before = step_records().len();
    let mut w = server(tid, CapPerms::WRITE);
    assert_eq!(w.sample(UNIX_2026, 100_000, 1), Out::ok(STEPPED));
    assert_eq!(w.sample(5 * MS, 100_000, 1), Out::ok(SLEWED));
    assert_eq!(w.sample(-500 * MS, 100_000, 1), Out::ok(FILTERED));
    assert_eq!(step_records().len(), before + 1, "only the boot step so far");
    assert_eq!(w.sample(-500 * MS, 100_000, 1), Out::ok(STEPPED));
    assert_eq!(w.sample(2_000_000 * MS, 100_000, 1), Out::err(outcome::REFUSED));
    let all = step_records();
    let mine = &all[before..];
    assert_eq!(mine.len(), 3);
    let clock = azos_abi::time::ClockId::REAL.raw() as u64;
    assert_eq!((mine[0].verdict, mine[0].n), (Verdict::Admit as u8, [clock, UNIX_2026 as u64, 0]), "boot step");
    assert_eq!((mine[1].verdict, mine[1].n), (Verdict::Admit as u8, [clock, 500 * MS as u64, 128 * MS as u64]), "over the threshold");
    assert_eq!((mine[2].verdict, mine[2].n), (Verdict::Refuse as u8, [clock, 2_000_000 * MS as u64, 1_000_000 * MS as u64]), "past the panic threshold");
    assert!(mine.iter().all(|r| r.subject == clock as u32));
}

// ── The real-time clock: the seed, the write-back and the two ops ────────────
//
// `crates/core/syscall/src/clock.rs` (`seed_wall`, `persist_wall`, `RtcHost`,
// `Server::rtc_read` / `rtc_set`). The chips are `tests/host/drivers-tests`'
// (`rtc.rs`); here the host is a fake that answers what a chip can answer and
// remembers what it was asked.

use azos_devif::clock::STATE_SEEDED;
use crate::clock::{RtcFault, RtcHost};
use std::sync::Mutex;

struct FakeRtc {
    read: Mutex<Result<u64, RtcFault>>,
    set_result: Mutex<Result<(), RtcFault>>,
    /// Every `set`: the time and the task charged.
    sets: Mutex<Vec<(u64, u32)>>,
}

impl RtcHost for FakeRtc {
    fn read(&self) -> Result<u64, RtcFault> {
        *self.read.lock().unwrap()
    }
    fn set(&self, unix_secs: u64, tid: u32) -> Result<(), RtcFault> {
        self.sets.lock().unwrap().push((unix_secs, tid));
        *self.set_result.lock().unwrap()
    }
}

/// Install a fresh fake as the machine's RTC (leaked: it is `'static` like the
/// kernel's).
fn fake_rtc(read: Result<u64, RtcFault>) -> &'static FakeRtc {
    let f: &'static FakeRtc = Box::leak(Box::new(FakeRtc {
        read: Mutex::new(read),
        set_result: Mutex::new(Ok(())),
        sets: Mutex::new(Vec::new()),
    }));
    crate::clock::install_rtc(f);
    f
}

const SECS_2026: u64 = 1_789_257_600;

/// **The right comes first, as for `sample`**: `rtc_read` needs `READ`,
/// `rtc_set` needs `WRITE`, and a refused call reaches no chip.
/// **Canary:** skip the gate in `rtc_set`: the `READ`-only caller sets the chip.
#[test]
fn the_rtc_ops_check_the_right_first() {
    let _g = serial();
    let tid = setup();
    let rtc = fake_rtc(Ok(SECS_2026));
    for rights in [CapPerms::NONE, CapPerms::WRITE, CapPerms::EXEC] {
        assert_eq!(server(tid, rights).rtc_read().code, outcome::DENIED, "{rights:?}");
    }
    for rights in [CapPerms::NONE, CapPerms::READ, CapPerms::EXEC] {
        assert_eq!(server(tid, rights).rtc_set(SECS_2026), Out::err(outcome::DENIED), "{rights:?}");
    }
    assert!(rtc.sets.lock().unwrap().is_empty(), "a refused set reached the chip");
}

/// A machine without an RTC answers `NO_RESOURCE`, to both ops.
#[test]
fn the_rtc_ops_without_a_chip_say_so() {
    let _g = serial();
    let tid = setup();
    assert_eq!(server(tid, CapPerms::READ).rtc_read().code, outcome::NO_RESOURCE);
    assert_eq!(server(tid, CapPerms::WRITE).rtc_set(SECS_2026), Out::err(outcome::NO_RESOURCE));
}

/// What the chip says becomes what the caller is told: a time, "lost" as
/// `NOT_READY` (a dead battery is not a fault of the call), a bus failure as
/// `FAULT`, a time the chip cannot hold as `BAD_ARGUMENT`, a refused effect
/// record as `REFUSED`; and `rtc_set` charges the caller.
#[test]
fn the_rtc_ops_map_the_chips_answers() {
    let _g = serial();
    let tid = setup();
    let rtc = fake_rtc(Ok(SECS_2026));
    assert_eq!(server(tid, CapPerms::READ).rtc_read(), Out::ok(SECS_2026));
    for (fault, code) in [(RtcFault::Lost, outcome::NOT_READY), (RtcFault::Bus, outcome::FAULT)] {
        *rtc.read.lock().unwrap() = Err(fault);
        assert_eq!(server(tid, CapPerms::READ).rtc_read().code, code, "{fault:?}");
    }
    let mut w = server(tid, CapPerms::WRITE);
    assert_eq!(w.rtc_set(SECS_2026 + 1), Out::ok(()));
    assert_eq!(*rtc.sets.lock().unwrap(), [(SECS_2026 + 1, tid)]);
    for (fault, code) in [(RtcFault::Range, outcome::BAD_ARGUMENT), (RtcFault::Refused, outcome::REFUSED), (RtcFault::Bus, outcome::FAULT)] {
        *rtc.set_result.lock().unwrap() = Err(fault);
        assert_eq!(w.rtc_set(SECS_2026), Out::err(code), "{fault:?}");
    }
    // `rtc_set` moves the chip, not the wall clock.
    assert_eq!(server(tid, CapPerms::READ).status().value.state, STATE_UNSET);
}

/// **The boot seed**: the wall clock takes the RTC's time as a recorded step
/// with no threshold, `status` says SEEDED, and the discipline is not told (no
/// step counted, the state still unset below the status), so a second seed is
/// refused and the first reference still steps without confirming.
/// **Canary:** seed through `feed`: `status` says SYNCED and `steps` is 1.
#[test]
fn the_seed_is_a_recorded_step_the_discipline_does_not_know() {
    use azos_decision::Verdict;
    let _g = serial();
    let tid = setup();
    let before = step_records().len();
    assert!(crate::clock::seed_wall(SECS_2026));
    let st = server(tid, CapPerms::READ).status().value;
    assert_eq!((st.state, st.steps, st.source), (STATE_SEEDED, 0, 0));
    let all = step_records();
    assert_eq!(all.len(), before + 1);
    let clock = azos_abi::time::ClockId::REAL.raw() as u64;
    let r = all.last().unwrap();
    assert_eq!((r.verdict, r.subject, r.n[0], r.n[2]), (Verdict::Admit as u8, clock as u32, clock, 0), "limit 0: no threshold");
    // The page is not initialised on the host, so the wall clock starts at the
    // counter: the jump is the time minus the counter, within a minute of it.
    let ns = SECS_2026 * 1_000_000_000;
    assert!(r.n[1] <= ns && r.n[1] > ns - 60_000_000_000, "delta {}", r.n[1]);

    assert!(!crate::clock::seed_wall(SECS_2026 + 5), "a seeded clock is not seeded again");
    assert_eq!(step_records().len(), before + 1);

    assert_eq!(server(tid, CapPerms::WRITE).sample(7_000 * MS, 100_000, 1), Out::ok(STEPPED), "the first reference steps, 7 s off, unconfirmed");
    assert_eq!(server(tid, CapPerms::READ).status().value.state, STATE_SYNCED);
}

/// A clock a reference already set is not seeded; nor is a time that does not
/// fit the nanosecond count.
#[test]
fn the_seed_is_only_for_a_clock_nobody_set() {
    let _g = serial();
    let tid = setup();
    assert!(!crate::clock::seed_wall(u64::MAX), "past the i64 nanosecond count");
    assert!(!crate::clock::seed_wall(i64::MAX as u64 / 1_000_000_000 + 1));
    assert_eq!(server(tid, CapPerms::READ).status().value.state, STATE_UNSET);
    server(tid, CapPerms::WRITE).sample(UNIX_2026, 100_000, 1);
    assert!(!crate::clock::seed_wall(SECS_2026), "a reference did better");
    assert_eq!(server(tid, CapPerms::READ).status().value.state, STATE_SYNCED);
}

/// **A reference that steps the clock leaves the RTC set**: one write-back per
/// step, charged to the kernel (task 0), with the wall clock's seconds; a
/// slewed sample, a filtered one and a refused one write nothing.
/// **Canary:** drop the `persist_wall` call: no write-back after the step.
#[test]
fn a_step_is_written_back_to_the_rtc() {
    let _g = serial();
    let tid = setup();
    let rtc = fake_rtc(Ok(SECS_2026));
    let mut w = server(tid, CapPerms::WRITE);
    assert_eq!(w.sample(UNIX_2026, 100_000, 1), Out::ok(STEPPED));
    let sets = rtc.sets.lock().unwrap().clone();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].1, 0, "charged to the kernel");
    // The page does not exist on the host: the wall clock is the counter.
    assert!(sets[0].0 <= 60, "the wall clock's seconds, not the sample's: {}", sets[0].0);
    assert_eq!(w.sample(5 * MS, 100_000, 1), Out::ok(SLEWED));
    assert_eq!(w.sample(2_000_000 * MS, 100_000, 1), Out::err(outcome::REFUSED));
    assert_eq!(w.sample(-500 * MS, 100_000, 1), Out::ok(FILTERED));
    assert_eq!(rtc.sets.lock().unwrap().len(), 1, "only a step writes back");
    assert_eq!(w.sample(-500 * MS, 100_000, 1), Out::ok(STEPPED));
    assert_eq!(rtc.sets.lock().unwrap().len(), 2);
    // A chip that fails the write-back costs a line, not the step.
    *rtc.set_result.lock().unwrap() = Err(RtcFault::Bus);
    assert_eq!(w.sample(500 * MS, 100_000, 1), Out::ok(FILTERED));
    assert_eq!(w.sample(500 * MS, 100_000, 1), Out::ok(STEPPED));
    assert_eq!(rtc.sets.lock().unwrap().len(), 3);
}

/// Through the dispatcher: `rtc_read` is a header and answers the time in the
/// first reply word; `rtc_set` takes the time as a word.
#[test]
fn the_rtc_ops_round_trip_the_wire_form() {
    let _g = serial();
    let tid = setup();
    let rtc = fake_rtc(Ok(SECS_2026));
    let who = Caller { tid, badge: 0, rights: CapPerms::RW };

    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(ClockIdl::ID, ClockIdl::LEVEL, ClockIdl::OP_RTC_READ));
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::CLOCK, &who, &req, &mut rep);
    assert_eq!((rep.words[0], rep.words[1] as u32, rep.words[2]), (azos_idl::STATUS_OK, outcome::OK, SECS_2026));

    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(ClockIdl::ID, ClockIdl::LEVEL, ClockIdl::OP_RTC_SET));
        w.word(SECS_2026 + 9);
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::CLOCK, &who, &req, &mut rep);
    assert_eq!((rep.words[0], rep.words[1] as u32), (azos_idl::STATUS_OK, outcome::OK));
    assert_eq!(*rtc.sets.lock().unwrap(), [(SECS_2026 + 9, tid)]);
}
