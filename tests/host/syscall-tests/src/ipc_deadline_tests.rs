// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The deadline a call carries (`ipc_deadline::check`): refused before it is
// queued when it has passed, with a decision record; a clock the kernel does
// not serve is refused.
//
// The record half is the point: a test that only checked the return code
// would pass with `record` deleted. Each case reads the ring back, keyed by a
// tid no other test uses, so a concurrent test's records cannot satisfy it.

use super::harness::serial;
use crate::ipc_deadline::{
    admit, admit_rule, check, check_caps, check_proxy, refused_desc, Alt, Lent, Refused, ServerSc, ALT_BUDGET,
    ALT_DEADLINE, DENIAL_REALTIME_ON_PROXY, REFUSED_WORDS,
};
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP, MSG_VERSION};
use azos_abi::time::ClockId;
use azos_decision::{Rule, Verdict};

const NOW: u64 = 1_000_000;

fn desc(deadline: u64, clock: ClockId) -> MsgDesc {
    MsgDesc { version: MSG_VERSION, deadline, clock_id: clock.raw(), ..MsgDesc::default() }
}

/// Records of the deadline rule written for `tid`, oldest first.
fn records_for(tid: u32) -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::DeadlineExpired as u8 && r.subject == tid {
            v.push(*r);
        }
    });
    v
}

#[test]
fn the_ring_is_live_in_this_suite() {
    let _g = serial();
    let before = azos_decision::total();
    azos_decision::record(Rule::DeadlineExpired, Verdict::Refuse, 0xD0_0000, [0; 3]);
    assert_eq!(azos_decision::total(), before + 1, "decision `on` is not enabled: the record tests would be vacuous");
}

#[test]
fn an_expired_deadline_is_refused_and_recorded() {
    let _g = serial();
    let tid = 0xD1_0001;
    let r = check(&desc(NOW - 1, ClockId::MONO), NOW, tid);
    assert_eq!(r, Err(Errno::EDEADLINE.to_syscall_ret()));
    let rs = records_for(tid);
    assert_eq!(rs.len(), 1, "one record per refused call");
    assert_eq!(rs[0].verdict, Verdict::Refuse as u8);
    assert_eq!(rs[0].n, [NOW - 1, NOW, 0]);
    assert_eq!(rs[0].rule_info().map(|i| i.name), Some("deadline-expired"));
}

#[test]
fn a_deadline_equal_to_now_has_passed() {
    let _g = serial();
    let tid = 0xD1_0002;
    assert_eq!(check(&desc(NOW, ClockId::MONO), NOW, tid), Err(Errno::EDEADLINE.to_syscall_ret()));
    assert_eq!(records_for(tid).len(), 1);
}

#[test]
fn a_future_deadline_and_no_deadline_proceed_and_write_nothing() {
    let _g = serial();
    let tid = 0xD1_0003;
    assert_eq!(check(&desc(NOW + 1, ClockId::MONO), NOW, tid), Ok(()));
    assert_eq!(check(&desc(0, ClockId::MONO), NOW, tid), Ok(()), "0 = none, even when now is 0 or large");
    assert_eq!(check(&desc(0, ClockId::MONO), u64::MAX, tid), Ok(()));
    assert!(records_for(tid).is_empty());
}

#[test]
fn a_clock_other_than_mono_is_refused_as_unsupported_whatever_the_deadline() {
    let _g = serial();
    let tid = 0xD1_0004;
    let einval = Err(Errno::EINVAL.to_syscall_ret());
    for c in [ClockId::REAL, ClockId::TSC_RAW, ClockId::ptp(0), ClockId::tsn_domain(2), ClockId::vcpu(1)] {
        assert_eq!(check(&desc(NOW + 1, c), NOW, tid), einval, "{c:?}, future deadline");
        assert_eq!(check(&desc(0, c), NOW, tid), einval, "{c:?}, no deadline");
        assert_eq!(check(&desc(NOW - 1, c), NOW, tid), einval, "{c:?}, past deadline: the clock is refused first");
    }
    assert!(records_for(tid).is_empty(), "an unsupported clock is not an expired deadline");
}

#[test]
fn a_reserved_label_bit_is_refused() {
    let _g = serial();
    let mut d = desc(NOW + 1, ClockId::MONO);
    d.label = 1 << 4;
    assert_eq!(check(&d, NOW, 0xD1_0005), Err(Errno::EINVAL.to_syscall_ret()));
}

/// A descriptor carrying `n` capability entries, entry `i` expiring at `exp[i]`.
fn with_caps(exp: &[u64]) -> MsgDesc {
    let mut d = MsgDesc { version: MSG_VERSION, n_caps: exp.len() as u8, ..MsgDesc::default() };
    for (i, e) in exp.iter().enumerate() {
        d.caps[i] = CapDesc { handle: 0x40 + i as u32, mode: CAP_MODE_DUP, _pad: 0, rights: 2, expiry_ns: *e };
    }
    d
}

/// **A copy born expired is refused, and recorded with the entry's handle.**
///
/// Canaries: compare with `<` instead of `<=` and the equal-to-now case goes
/// red; read `d.caps` without `take(n_caps)` and the stale entry past the
/// counted ones is wrongly refused; skip the `record` and the ring assertion
/// goes red.
#[test]
fn a_capability_entry_born_expired_is_refused_and_recorded() {
    let _g = serial();
    let tid = 0xD1_0006;
    let r = check_caps(&with_caps(&[0, NOW - 1]), NOW, tid);
    assert_eq!(r, Err(Errno::EDEADLINE.to_syscall_ret()));
    let rs = records_for(tid);
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].verdict, Verdict::Refuse as u8);
    assert_eq!(rs[0].n, [NOW - 1, NOW, 0x41], "the entry that was late, not the first");
    assert_eq!(check_caps(&with_caps(&[NOW]), NOW, tid), Err(Errno::EDEADLINE.to_syscall_ret()), "equal to now has passed");
}

#[test]
fn a_later_or_absent_entry_deadline_proceeds_and_writes_nothing() {
    let _g = serial();
    let tid = 0xD1_0007;
    assert_eq!(check_caps(&with_caps(&[NOW + 1, 0, u64::MAX]), NOW, tid), Ok(()));
    assert_eq!(check_caps(&with_caps(&[]), NOW, tid), Ok(()));
    // An entry past the counted ones is not read.
    let mut d = with_caps(&[0]);
    d.caps[1] = CapDesc { handle: 9, mode: CAP_MODE_DUP, _pad: 0, rights: 2, expiry_ns: 1 };
    assert_eq!(check_caps(&d, NOW, tid), Ok(()));
    assert!(records_for(tid).is_empty());
}

/// Records of the cap-denial rule written for `tid`.
fn denials_for(tid: u32) -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::CapDenial as u8 && r.subject == tid {
            v.push(*r);
        }
    });
    v
}

/// **A real-time caller is refused on a proxy endpoint, with a record; an
/// ordinary caller on a proxy, and anyone on an ordinary endpoint, is not.**
///
/// **Canaries.** Make `check_proxy` ignore `is_proxy`: the "ordinary
/// endpoint" assertion goes red. Compare with `<` instead of `<=`: the soft
/// real-time (class 2) row goes red. Delete the `record` call: the record
/// assertions go red.
#[test]
fn a_realtime_caller_is_refused_on_a_proxy_endpoint() {
    let _g = serial();
    let tid = 0xD0_0010;
    let want = Err(Errno::ERTPROXY.to_syscall_ret());
    // Safety-critical (0), hard real-time (1) and soft real-time (2).
    for (i, class) in [0u8, 1, 2].into_iter().enumerate() {
        assert_eq!(check_proxy(true, || class, tid), want, "class {class}");
        let d = denials_for(tid);
        assert_eq!(d.len(), i + 1, "one record per refusal");
        let r = d.last().unwrap();
        assert_eq!((r.verdict, r.n[0], r.n[1]), (Verdict::Deny as u8, azos_abi::cap::CapKind::Endpoint.denial_code() as u64, DENIAL_REALTIME_ON_PROXY));
    }
    // Best effort (3) and idle (4) may call a proxy.
    assert_eq!(check_proxy(true, || 3, tid), Ok(()));
    assert_eq!(check_proxy(true, || 4, tid), Ok(()));
    // Nobody is refused on an ordinary endpoint.
    assert_eq!(check_proxy(false, || panic!("the class of a caller of an ordinary endpoint is not read"), tid), Ok(()));
    assert_eq!(denials_for(tid).len(), 3, "an admitted call leaves no record");
}

// ── Rule 4: the server's scheduling context admits the time left ───────────

const MS: u64 = 1_000_000;

/// Records of the call-admission rule written for `tid`.
fn admissions_for(tid: u32) -> Vec<azos_decision::Record> {
    let mut v = Vec::new();
    azos_decision::for_each(|r| {
        if r.rule == Rule::CallAdmission as u8 && r.subject == tid {
            v.push(*r);
        }
    });
    v
}

/// **A two-hop call is refused, with a counter-offer receipt, at the hop
/// that cannot finish in the time left.**
///
/// A (a deadline task, 2 ms of budget left in a server period that ends at
/// 5 ms) calls B with a deadline of 10 ms. B is a passive server (no
/// reservation, 1 ms per call): it runs on A's reservation, which has the
/// budget and ends before the call's deadline, so hop 1 is admitted. B works
/// 3 ms (on A's budget, 1 ms of it, and on its own priority after) and calls
/// C with the deadline it was given. C is an active server: its own
/// reservation serves a call within 8 ms of a release, more than the 7 ms
/// left. Hop 2 is refused: `Refused { receipt, alt: Deadline(3 + 8 ms) }`,
/// the record the receipt names says the same, and the descriptor B reads
/// back carries the offer.
///
/// **Canary** `ipc-admit-canary` (`cargo test --features ipc-admit-canary`):
/// every call is admitted and this test goes red at hop 2. The other canaries:
/// compare `d < left` (a deadline that just fits, `exactly_fitting_*`, goes
/// red); drop the record (the ring assertions go red).
#[test]
fn a_two_hop_call_is_refused_at_the_hop_that_cannot_finish() {
    let _g = serial();
    let (a, b, c) = (0xD2_0001u32, 0xD2_0002u32, 0xD2_0003u32);
    let t0 = 100 * MS;
    let deadline = t0 + 10 * MS;
    let lent_by_a = Lent { budget: 2 * MS, deadline: t0 + 5 * MS };
    let passive_b = ServerSc::Passive { call_budget: MS };
    let active_c = ServerSc::Reserved { budget: 2 * MS, deadline: 8 * MS };

    // Hop 1: A -> B, admitted, nothing written.
    assert_eq!(admit(t0, deadline, passive_b, Some(lent_by_a), a, b), Ok(()));
    assert!(admissions_for(a).is_empty(), "an admitted call writes no record");

    // Hop 2: B -> C at t0 + 3 ms, B still on A's reservation (1 ms left).
    let t1 = t0 + 3 * MS;
    let lent_on_b = Lent { budget: MS, deadline: lent_by_a.deadline };
    let r = admit(t1, deadline, active_c, Some(lent_on_b), b, c);
    let Err(Refused { receipt, alt }) = r else { panic!("hop 2 admitted: {r:?}") };
    assert_eq!(alt, Alt::Deadline(t1 + 8 * MS), "the nearest deadline C admits");
    assert_ne!(receipt, 0, "a refusal hands back a receipt");
    let rec = azos_decision::get(receipt).expect("the receipt names a record in the ring");
    assert_eq!((rec.rule, rec.verdict, rec.subject), (Rule::CallAdmission as u8, Verdict::Refuse as u8, b));
    assert_eq!(rec.n, [deadline, t1 + 8 * MS, ALT_DEADLINE << 32 | c as u64]);
    assert_eq!(rec.rule_info().map(|i| i.name), Some("call-admission"));
    assert_eq!(admissions_for(b).len(), 1, "one record per refusal");

    // What B reads back: the receipt and the offer, the offered deadline in
    // the descriptor's own field, no capability.
    let req = desc(deadline, ClockId::MONO);
    let out = refused_desc(&req, Refused { receipt, alt });
    assert_eq!((out.n_words, out.n_caps), (REFUSED_WORDS, 0));
    assert_eq!(&out.words[..3], &[receipt, ALT_DEADLINE, t1 + 8 * MS]);
    assert_eq!(out.deadline, t1 + 8 * MS);

    // B accepts the offer for its own answer: a deadline that late is
    // admitted by C (and is then A's to accept or refuse, at hop 1).
    assert_eq!(admit_rule(t1, t1 + 8 * MS, active_c, Some(lent_on_b)), Ok(()));
}

#[test]
fn exactly_fitting_deadlines_and_budgets_are_admitted() {
    let _g = serial();
    let now = 10 * MS;
    assert_eq!(admit_rule(now, now + 8 * MS, ServerSc::Reserved { budget: MS, deadline: 8 * MS }, None), Ok(()));
    let l = Lent { budget: MS, deadline: now + 4 * MS };
    assert_eq!(admit_rule(now, now + 4 * MS, ServerSc::Passive { call_budget: MS }, Some(l)), Ok(()));
}

/// **A passive server is refused what the lent reservation cannot carry.**
/// Each refusal names the alternative that would be admitted.
#[test]
fn a_passive_server_is_admitted_against_the_lent_reservation() {
    let _g = serial();
    let now = 10 * MS;
    let p = ServerSc::Passive { call_budget: 2 * MS };
    // Not enough budget left: the offer is the budget the call needs.
    let thin = Lent { budget: MS, deadline: now + 4 * MS };
    assert_eq!(admit_rule(now, now + 9 * MS, p, Some(thin)), Err(Alt::Budget(2 * MS)));
    let tid = 0xD2_0010;
    let Err(r) = admit(now, now + 9 * MS, p, Some(thin), tid, 7) else { panic!("admitted") };
    let out = refused_desc(&desc(now + 9 * MS, ClockId::MONO), r);
    assert_eq!(&out.words[1..3], &[ALT_BUDGET, 2_000], "a budget offer is in microseconds");
    assert_eq!(out.deadline, now + 9 * MS, "a budget offer keeps the call's deadline");
    // The reservation's period ends after the call's deadline: its budget is
    // promised only by then, so that is the offer.
    let late = Lent { budget: 3 * MS, deadline: now + 12 * MS };
    assert_eq!(admit_rule(now, now + 9 * MS, p, Some(late)), Err(Alt::Deadline(now + 12 * MS)));
    // The work does not fit the time left at all.
    assert_eq!(admit_rule(now, now + MS, p, None), Err(Alt::Deadline(now + 2 * MS)));
    // A caller with no reservation lends nothing: only the time is checked.
    assert_eq!(admit_rule(now, now + 9 * MS, p, None), Ok(()));
    assert_eq!(admissions_for(tid).len(), 1);
}

/// No deadline, or a server that promises nothing: never refused, never
/// recorded (the call path does not even ask without a deadline).
#[test]
fn no_deadline_or_no_promise_is_admitted_without_a_record() {
    let _g = serial();
    let tid = 0xD2_0020;
    let tight = ServerSc::Reserved { budget: MS, deadline: 50 * MS };
    assert_eq!(admit(10 * MS, 0, tight, None, tid, 1), Ok(()));
    assert_eq!(admit(10 * MS, 11 * MS, ServerSc::None, None, tid, 1), Ok(()));
    assert!(admissions_for(tid).is_empty());
}
