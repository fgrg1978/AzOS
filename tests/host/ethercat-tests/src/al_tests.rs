// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! AL state table and the INIT-to-OP sequencer, against the scripted chain.

use crate::harness::Harness;
use crate::model::{Bus, Esc, Script};
use azos_ethercat::al::{status_code, transition_allowed, AlState, Bringup, BringupError, Step};
use azos_ethercat::frame::Cmd;
use azos_ethercat::reg::{self, sm_control, Fmmu, FmmuDir, SyncManager};

use AlState::*;

#[test]
fn transition_table() {
    let all = [Init, PreOp, Boot, SafeOp, Op];
    let legal = [
        (Init, PreOp), (Init, Boot), (Boot, Init), (PreOp, SafeOp), (SafeOp, Op),
        (PreOp, Init), (SafeOp, Init), (SafeOp, PreOp), (Op, Init), (Op, PreOp), (Op, SafeOp),
    ];
    for &a in &all {
        for &b in &all {
            let want = a == b || legal.contains(&(a, b));
            assert_eq!(transition_allowed(a, b), want, "{a:?} -> {b:?}");
        }
    }
    // The two that matter most: no skipping up, no leaving BOOT sideways.
    assert!(!transition_allowed(Init, SafeOp));
    assert!(!transition_allowed(PreOp, Op));
    assert!(!transition_allowed(Boot, PreOp));
}

#[test]
fn status_decoding() {
    assert_eq!(AlState::from_status(0x01), Some(Init));
    assert_eq!(AlState::from_status(0x14), Some(SafeOp), "error bit is not part of the state");
    assert_eq!(AlState::from_status(0x08), Some(Op));
    assert_eq!(AlState::from_status(0x00), None);
    assert_eq!(AlState::from_status(0x05), None);
}

fn mailbox_and_pd() -> ([(u8, SyncManager); 4], [(u8, Fmmu); 2]) {
    (
        [
            (0, SyncManager::new(0x1000, 128, sm_control::MAILBOX_OUT)),
            (1, SyncManager::new(0x1080, 128, sm_control::MAILBOX_IN)),
            (2, SyncManager::new(0x1100, 4, sm_control::PROCESS_OUT)),
            (3, SyncManager::new(0x1180, 4, sm_control::PROCESS_IN)),
        ],
        [
            (0, Fmmu::new(FmmuDir::Write, 0, 4, 0x1100)),
            (1, Fmmu::new(FmmuDir::Read, 0x10, 4, 0x1180)),
        ],
    )
}

fn bus(n: usize, script: Script) -> Harness {
    let mut h = Harness::new(Bus::new((0..n).map(|_| Esc::new(script.clone(), 0)).collect(), 200));
    h.assign_stations(0x1000);
    h
}

#[test]
fn enumerate_then_bring_every_slave_to_op() {
    let mut h = bus(3, Script { polls_before_change: 2, ..Script::default() });
    // Slaves are counted by a broadcast read's working counter.
    let (wkc, _) = h.single(Cmd::Brd, azos_ethercat::frame::Addr::broadcast(reg::TYPE), &[0]);
    assert_eq!(wkc, 3);
    let (sms, fmmus) = mailbox_and_pd();
    for i in 0..3u16 {
        let mut b = Bringup::new(0x1000 + i, Op, &sms, &fmmus, 10).unwrap();
        let frames = h.run(&mut b).unwrap();
        // INIT is where it starts: write + 1 poll. PRE-OP, SAFE-OP, OP: write +
        // 2 stale polls + 1 that shows the state; 4 SM + 2 FMMU writes between.
        assert_eq!(frames, 2 + 4 + 6 + 4 + 4);
    }
    for s in &h.bus.slaves {
        assert_eq!(s.state(), Op);
        assert!(!s.error());
        let sm2: [u8; 8] = s.mem[reg::sm_addr(2) as usize..][..8].try_into().unwrap();
        assert_eq!(SyncManager::decode(&sm2), sms[2].1);
        let f1: [u8; 16] = s.mem[reg::fmmu_addr(1) as usize..][..16].try_into().unwrap();
        assert_eq!(Fmmu::decode(&f1), Some(fmmus[1].1));
    }
}

#[test]
fn bringup_stops_at_each_target() {
    let (sms, fmmus) = mailbox_and_pd();
    for (target, frames, configured) in [(PreOp, 4, false), (SafeOp, 12, true), (Op, 14, true)] {
        let mut h = bus(1, Script::default());
        let mut b = Bringup::new(0x1000, target, &sms, &fmmus, 4).unwrap();
        assert_eq!(h.run(&mut b), Ok(frames), "{target:?}");
        assert_eq!(h.bus.slaves[0].state(), target);
        assert_eq!(h.bus.slaves[0].mem[reg::sm_addr(3) as usize + 6] & 1 == 1, configured);
        // Done is sticky and sends nothing more.
        b.on_reply(1, &[0, 0]);
        assert_eq!(b.request(), Step::Done);
    }
}

#[test]
fn without_records_the_sequence_is_just_the_states() {
    let mut h = bus(1, Script::default());
    let mut b = Bringup::new(0x1000, Op, &[], &[], 4).unwrap();
    assert_eq!(h.run(&mut b), Ok(2 + 2 + 2 + 2));
    assert_eq!(h.bus.slaves[0].state(), Op);
}

#[test]
fn sm_must_be_configured_before_safe_op() {
    // The slave insists on SM2 and SM3, the master never writes them.
    let mut h = bus(1, Script { require_sm: vec![2, 3], ..Script::default() });
    let mut b = Bringup::new(0x1000, Op, &[], &[], 4).unwrap();
    assert_eq!(h.run(&mut b), Err(BringupError::Refused { want: SafeOp, code: status_code::INVALID_OUTPUT_CONFIG }));
    let s = &h.bus.slaves[0];
    assert_eq!(s.state(), PreOp);
    assert!(!s.error(), "the error was acknowledged");
    assert_eq!(s.u16_at(reg::AL_STATUS_CODE), 0);

    // With the records it goes through: the order of writes is what matters.
    let (sms, fmmus) = mailbox_and_pd();
    let mut h = bus(1, Script { require_sm: vec![2, 3], ..Script::default() });
    let mut b = Bringup::new(0x1000, Op, &sms, &fmmus, 4).unwrap();
    assert!(h.run(&mut b).is_ok());
}

#[test]
fn refusal_carries_the_status_code_and_is_acknowledged() {
    let mut h = bus(1, Script { refuse: vec![(Op, status_code::SM_WATCHDOG)], ..Script::default() });
    let mut b = Bringup::new(0x1000, Op, &[], &[], 4).unwrap();
    assert_eq!(h.run(&mut b), Err(BringupError::Refused { want: Op, code: status_code::SM_WATCHDOG }));
    assert_eq!(h.bus.slaves[0].state(), SafeOp);
    assert!(!h.bus.slaves[0].error());
    // Failed is sticky.
    b.on_reply(1, &[8, 0]);
    assert!(matches!(b.request(), Step::Failed(BringupError::Refused { .. })));
}

#[test]
fn a_slave_that_never_changes_state_times_out() {
    let mut h = bus(1, Script { polls_before_change: 100, ..Script::default() });
    let mut b = Bringup::new(0x1000, PreOp, &[], &[], 5).unwrap();
    // INIT is where it already is: the first poll answers. PRE-OP never arrives.
    assert_eq!(h.run(&mut b), Err(BringupError::Timeout { want: PreOp }));
    // 2 for INIT, then the write and exactly 5 polls.
    assert_eq!(h.bus.frames - 1 /* station assignment */, 2 + 1 + 5);
}

#[test]
fn an_absent_slave_is_no_response() {
    let mut h = bus(2, Script::default());
    let mut b = Bringup::new(0x4242, Op, &[], &[], 4).unwrap();
    assert_eq!(h.run(&mut b), Err(BringupError::NoResponse));
    assert!(h.bus.slaves.iter().all(|s| s.state() == Init));
}

#[test]
fn a_latched_error_is_cleared_by_the_opening_init() {
    let mut h = bus(1, Script::default());
    h.bus.slaves[0].force_state(SafeOp, true);
    let mut b = Bringup::new(0x1000, Op, &[], &[], 4).unwrap();
    assert!(h.run(&mut b).is_ok());
    assert_eq!(h.bus.slaves[0].state(), Op);
    assert!(!h.bus.slaves[0].error());
}

#[test]
fn only_pre_op_safe_op_and_op_are_targets() {
    for t in [Init, Boot] {
        assert!(matches!(Bringup::new(1, t, &[], &[], 1), Err(BringupError::BadTarget)));
    }
    for t in [PreOp, SafeOp, Op] {
        assert!(Bringup::new(1, t, &[], &[], 1).is_ok());
    }
}

#[test]
fn request_is_idempotent_until_the_reply() {
    let b = Bringup::new(0x1000, Op, &[], &[], 3).unwrap();
    let a = b.request();
    assert_eq!(a, b.request());
    let Step::Send(r) = a else { panic!() };
    // The opening datagram: FPWR of AL control = INIT | acknowledge.
    assert_eq!(r.cmd, Cmd::Fpwr);
    assert_eq!((r.addr.adp(), r.addr.ado()), (0x1000, reg::AL_CONTROL));
    assert_eq!(r.data(), &[0x11, 0x00]);
}

#[test]
fn a_wrong_working_counter_on_a_config_write_fails() {
    let (sms, fmmus) = mailbox_and_pd();
    let mut b = Bringup::new(0x1000, SafeOp, &sms, &fmmus, 4).unwrap();
    // INIT write, INIT poll (state reached), PRE-OP write, PRE-OP poll.
    b.on_reply(1, &[]);
    b.on_reply(1, &[1, 0]);
    b.on_reply(1, &[]);
    b.on_reply(1, &[2, 0]);
    let Step::Send(r) = b.request() else { panic!() };
    assert_eq!(r.addr.ado(), reg::sm_addr(0));
    b.on_reply(0, &[]);
    assert_eq!(b.request(), Step::Failed(BringupError::NoResponse));
}
