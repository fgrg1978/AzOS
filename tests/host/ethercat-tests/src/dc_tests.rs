// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Distributed clocks: the arithmetic alone, then the whole procedure against
//! a chain whose skews and hop delay are known.

use crate::harness::Harness;
use crate::model::{Bus, Esc, Script};
use azos_ethercat::dc::*;
use azos_ethercat::frame::{Addr, Cmd};
use azos_ethercat::reg;
use azos_ethercat::Error;

#[test]
fn offset_is_target_minus_local_plus_delay_and_wraps() {
    assert_eq!(system_time_offset(1_000, 400, 0), 600);
    assert_eq!(system_time_offset(1_000, 400, 25), 625);
    assert_eq!(system_time_offset(400, 1_000, 0), 600u64.wrapping_neg());
    assert_eq!(system_time_offset(5, u64::MAX, 0), 6);
    assert_eq!(system_time_offset(0, 1, u32::MAX), u64::from(u32::MAX) - 1);
}

#[test]
fn line_delays_accumulate_half_the_gap_difference() {
    // 4 slaves, hop 100: gaps are 600, 400, 200, last loops (p1 unused).
    let t = [
        PortTimes { p0: 1_000, p1: 1_600 },
        PortTimes { p0: 1_100, p1: 1_500 },
        PortTimes { p0: 1_200, p1: 1_400 },
        PortTimes { p0: 1_300, p1: 0xDEAD },
    ];
    let mut out = [9u32; 4];
    line_delays(&t, &mut out).unwrap();
    assert_eq!(out, [0, 100, 200, 300]);
}

#[test]
fn line_delays_survive_32_bit_wrap() {
    let base = u32::MAX - 150;
    let t = [
        PortTimes { p0: base, p1: base.wrapping_add(400) },
        PortTimes { p0: base.wrapping_add(100), p1: base.wrapping_add(300) },
        PortTimes { p0: base.wrapping_add(200), p1: 0 },
    ];
    let mut out = [0u32; 3];
    line_delays(&t, &mut out).unwrap();
    assert_eq!(out, [0, 100, 200]);
}

#[test]
fn line_delays_edge_cases() {
    let mut none: [u32; 0] = [];
    line_delays(&[], &mut none).unwrap();
    let mut one = [7u32];
    line_delays(&[PortTimes { p0: 5, p1: 0 }], &mut one).unwrap();
    assert_eq!(one, [0]);
    let mut two = [0u32; 2];
    line_delays(&[PortTimes { p0: 0, p1: 0 }; 2], &mut two).unwrap();
    assert_eq!(two, [0, 0]);
    let mut wrong = [0u32; 1];
    assert_eq!(line_delays(&[PortTimes { p0: 0, p1: 0 }; 2], &mut wrong), Err(Error::BufferTooSmall));
    // A slave whose gap is larger than its parent's cannot be in a line.
    let bad = [PortTimes { p0: 0, p1: 100 }, PortTimes { p0: 10, p1: 500 }, PortTimes { p0: 20, p1: 0 }];
    assert_eq!(line_delays(&bad, &mut [0u32; 3]), Err(Error::BadTimestamps));
}

fn chain(skews: &[u64], hop: u64) -> Harness {
    let slaves = skews.iter().map(|&k| Esc::new(Script::default(), k)).collect();
    let mut h = Harness::new(Bus::new(slaves, hop));
    h.assign_stations(0x1000);
    h
}

#[test]
fn full_procedure_recovers_hop_delay_and_aligns_system_time() {
    let skews = [0x0123_4567_89AB, 5_000_000, 0u64.wrapping_sub(123_456), 1 << 40, 77];
    let hop = 640u64;
    let mut h = chain(&skews, hop);
    // Close to the 32-bit wrap so the p0/p1 arithmetic is exercised.
    h.now = 0xFFFF_FF00 - 10 * hop;
    let n = skews.len();

    // 1. One broadcast write latches every slave.
    let t_latch = h.now;
    let (wkc, _) = h.single(Cmd::Bwr, Addr::broadcast(reg::RX_TIME_P0), &[0; 4]);
    assert_eq!(usize::from(wkc), n);

    // 2. Read each slave's receive times back.
    let mut pu = Vec::new();
    let mut ports = Vec::new();
    for i in 0..n as u16 {
        let st = 0x1000 + i;
        let (w, d) = h.single(Cmd::Fprd, Addr::node(st, reg::RX_TIME_PU), &[0; 8]);
        assert_eq!(w, 1);
        pu.push(u64::from_le_bytes(d.try_into().unwrap()));
        let (w, d) = h.single(Cmd::Fprd, Addr::node(st, reg::RX_TIME_P0), &[0; 8]);
        assert_eq!(w, 1);
        ports.push(PortTimes {
            p0: u32::from_le_bytes(d[0..4].try_into().unwrap()),
            p1: u32::from_le_bytes(d[4..8].try_into().unwrap()),
        });
    }

    // 3. The reference clock is slave 0; the master wants system time 42 s at its latch.
    let target = 42_000_000_000u64;
    let mut delays = vec![0u32; n];
    line_delays(&ports, &mut delays).unwrap();
    for (i, d) in delays.iter().enumerate() {
        assert_eq!(u64::from(*d), i as u64 * hop, "delay of slave {i}");
    }
    for i in 0..n {
        let st = 0x1000 + i as u16;
        let off = system_time_offset(target, pu[i], delays[i]);
        let (w, _) = h.single(Cmd::Fpwr, Addr::node(st, reg::SYS_TIME_OFFSET), &off.to_le_bytes());
        assert_eq!(w, 1);
        let (w, _) = h.single(Cmd::Fpwr, Addr::node(st, reg::SYS_TIME_DELAY), &delays[i].to_le_bytes());
        assert_eq!(w, 1);
    }

    // 4. All slaves now read the same system time at the same true instant,
    //    and the reference reads `target` at its latch.
    assert_eq!(h.bus.slaves[0].sys_time_at(t_latch), target);
    for t in [t_latch, t_latch + 3_000_000, t_latch + 9_999_999_999] {
        let reference = h.bus.slaves[0].sys_time_at(t);
        for (i, s) in h.bus.slaves.iter().enumerate() {
            assert_eq!(u64::from(s.u32_at(reg::SYS_TIME_DELAY)), i as u64 * hop);
            assert_eq!(s.sys_time_at(t), reference, "slave {i} at {t}");
        }
    }
}

#[test]
fn without_the_delay_term_slaves_lag_by_their_delay() {
    // The same chain, offsets computed ignoring the propagation delay: this is
    // what the delay argument buys.
    let skews = [10, 20, 30];
    let mut h = chain(&skews, 500);
    let t0 = h.now;
    h.single(Cmd::Bwr, Addr::broadcast(reg::RX_TIME_P0), &[0; 4]);
    let pu: Vec<u64> = (0..3u16)
        .map(|i| u64::from_le_bytes(h.single(Cmd::Fprd, Addr::node(0x1000 + i, reg::RX_TIME_PU), &[0; 8]).1.try_into().unwrap()))
        .collect();
    for (i, s) in h.bus.slaves.iter_mut().enumerate() {
        let off = system_time_offset(pu[0], pu[i], 0);
        s.mem[reg::SYS_TIME_OFFSET as usize..][..8].copy_from_slice(&off.to_le_bytes());
    }
    let t = t0 + 1_000;
    let r = h.bus.slaves[0].sys_time_at(t);
    for (i, s) in h.bus.slaves.iter().enumerate() {
        assert_eq!(s.sys_time_at(t), r.wrapping_sub(i as u64 * 500));
    }
}
