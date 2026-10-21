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
use crate::ipc_deadline::{check, check_caps, check_proxy, DENIAL_REALTIME_ON_PROXY};
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
