// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Process data over the scripted chain: auto-increment and node reads,
//! working-counter arithmetic and LRW through the FMMUs.

use crate::harness::{Harness, MASTER_MAC};
use crate::model::{Bus, Esc, Script};
use azos_ethercat::al::{AlState, Bringup};
use azos_ethercat::frame::{self, Addr, Cmd, FrameBuilder, BROADCAST_MAC};
use azos_ethercat::reg::{self, sm_control, Fmmu, FmmuDir, SyncManager};

fn bus(n: usize) -> Harness {
    let mut h = Harness::new(Bus::new((0..n).map(|_| Esc::new(Script::default(), 0)).collect(), 100));
    h.assign_stations(0x1000);
    h
}

#[test]
fn aprd_reaches_exactly_the_slave_at_that_position() {
    let mut h = bus(3);
    for (i, s) in h.bus.slaves.iter_mut().enumerate() {
        s.mem[0x0E00] = 0xA0 + i as u8; // some register with a per-slave value
    }
    for i in 0..3u16 {
        let (wkc, d) = h.single(Cmd::Aprd, Addr::position(i, 0x0E00), &[0]);
        assert_eq!((wkc, d[0]), (1, 0xA0 + i as u8));
    }
    // Position 3 does not exist: nobody answers.
    let (wkc, _) = h.single(Cmd::Aprd, Addr::position(3, 0x0E00), &[0]);
    assert_eq!(wkc, 0);
}

#[test]
fn auto_increment_address_is_incremented_by_every_slave() {
    let mut h = bus(3);
    let mut buf = [0u8; 64];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, MASTER_MAC).unwrap();
    fb.push_zeroed(Cmd::Aprd, 1, Addr::position(1, 0x0E00), 1).unwrap();
    let n = fb.finish().unwrap();
    h.bus.exchange(&mut buf, n, 0);
    let d = frame::parse(&buf[..n]).unwrap().datagrams().next().unwrap().unwrap();
    // Sent as -1, three slaves each added one.
    assert_eq!(d.addr.adp(), 2);
}

#[test]
fn fprd_matches_the_station_address() {
    let mut h = bus(3);
    h.bus.slaves[1].mem[0x0E00] = 0x77;
    let (wkc, d) = h.single(Cmd::Fprd, Addr::node(0x1001, 0x0E00), &[0]);
    assert_eq!((wkc, d[0]), (1, 0x77));
    assert_eq!(h.single(Cmd::Fprd, Addr::node(0x2000, 0x0E00), &[0]).0, 0);
}

#[test]
fn broadcast_counts_slaves_and_ors_reads() {
    let mut h = bus(4);
    h.bus.slaves[0].mem[0x0E00] = 0b0001;
    h.bus.slaves[2].mem[0x0E00] = 0b0100;
    let (wkc, d) = h.single(Cmd::Brd, Addr::broadcast(0x0E00), &[0]);
    assert_eq!((wkc, d[0]), (4, 0b0101));
    let (wkc, _) = h.single(Cmd::Bwr, Addr::broadcast(0x0E01), &[0x5A]);
    assert_eq!(wkc, 4);
    assert!(h.bus.slaves.iter().all(|s| s.mem[0x0E01] == 0x5A));
}

#[test]
fn physical_read_write_counts_three() {
    let mut h = bus(1);
    h.bus.slaves[0].mem[0x0E00] = 0x11;
    let (wkc, d) = h.single(Cmd::Fprw, Addr::node(0x1000, 0x0E00), &[0x22]);
    assert_eq!((wkc, d[0]), (3, 0x11), "reads the old value, writes the new");
    assert_eq!(h.bus.slaves[0].mem[0x0E00], 0x22);
}

#[test]
fn out_of_range_register_access_is_ignored() {
    let mut h = bus(1);
    let (wkc, _) = h.single(Cmd::Fprd, Addr::node(0x1000, 0x1FFF), &[0, 0]);
    assert_eq!(wkc, 0);
}

/// Two slaves with 4 output bytes and 4 input bytes each, outputs at logical
/// 0x00..0x08, inputs at 0x10..0x18.
fn running_pair(target: AlState) -> Harness {
    let mut h = bus(2);
    for i in 0..2u16 {
        let sms = [
            (2, SyncManager::new(0x1100, 4, sm_control::PROCESS_OUT)),
            (3, SyncManager::new(0x1180, 4, sm_control::PROCESS_IN)),
        ];
        let fmmus = [
            (0, Fmmu::new(FmmuDir::Write, u32::from(i) * 4, 4, 0x1100)),
            (1, Fmmu::new(FmmuDir::Read, 0x10 + u32::from(i) * 4, 4, 0x1180)),
        ];
        let mut b = Bringup::new(0x1000 + i, target, &sms, &fmmus, 4).unwrap();
        h.run(&mut b).unwrap();
        h.bus.slaves[usize::from(i)].mem[0x1180..0x1184].copy_from_slice(&[i as u8 + 1; 4]);
    }
    h
}

#[test]
fn lrw_in_op_writes_outputs_reads_inputs_and_counts_three_per_slave() {
    let mut h = running_pair(AlState::Op);
    let mut img = vec![0u8; 0x18];
    img[0..8].copy_from_slice(&[10, 11, 12, 13, 20, 21, 22, 23]);
    let (wkc, d) = h.single(Cmd::Lrw, Addr::logical(0), &img);
    assert_eq!(wkc, 6, "2 slaves x (read 1 + write 2)");
    assert_eq!(&h.bus.slaves[0].mem[0x1100..0x1104], &[10, 11, 12, 13]);
    assert_eq!(&h.bus.slaves[1].mem[0x1100..0x1104], &[20, 21, 22, 23]);
    assert_eq!(&d[0x10..0x14], &[1; 4]);
    assert_eq!(&d[0x14..0x18], &[2; 4]);
    assert_eq!(&d[0..8], &[10, 11, 12, 13, 20, 21, 22, 23], "outputs travel through unchanged");
}

#[test]
fn lrw_in_safe_op_reads_but_does_not_drive_outputs() {
    let mut h = running_pair(AlState::SafeOp);
    let mut img = vec![0u8; 0x18];
    img[0..4].copy_from_slice(&[9; 4]);
    let (wkc, d) = h.single(Cmd::Lrw, Addr::logical(0), &img);
    assert_eq!(wkc, 2, "inputs only");
    assert_eq!(&h.bus.slaves[0].mem[0x1100..0x1104], &[0; 4]);
    assert_eq!(&d[0x10..0x14], &[1; 4]);
}

#[test]
fn lrd_and_lwr_count_one_each() {
    let mut h = running_pair(AlState::Op);
    let (wkc, d) = h.single(Cmd::Lrd, Addr::logical(0x10), &[0; 8]);
    assert_eq!((wkc, &d[..]), (2, &[1, 1, 1, 1, 2, 2, 2, 2][..]));
    let (wkc, _) = h.single(Cmd::Lwr, Addr::logical(0), &[5; 8]);
    assert_eq!(wkc, 2);
    assert_eq!(&h.bus.slaves[1].mem[0x1100..0x1104], &[5; 4]);
}

#[test]
fn a_datagram_covering_part_of_the_mapping_touches_only_that_part() {
    let mut h = running_pair(AlState::Op);
    // Logical 2..6 overlaps slave 0's bytes 2,3 and slave 1's bytes 0,1.
    let (wkc, _) = h.single(Cmd::Lwr, Addr::logical(2), &[0xEE; 4]);
    assert_eq!(wkc, 2);
    assert_eq!(&h.bus.slaves[0].mem[0x1100..0x1104], &[0, 0, 0xEE, 0xEE]);
    assert_eq!(&h.bus.slaves[1].mem[0x1100..0x1104], &[0xEE, 0xEE, 0, 0]);
    // Nothing maps at 0x100.
    assert_eq!(h.single(Cmd::Lrw, Addr::logical(0x100), &[0; 4]).0, 0);
}

#[test]
fn several_datagrams_in_one_frame_each_get_their_own_wkc() {
    let mut h = running_pair(AlState::Op);
    let mut buf = [0u8; 256];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, MASTER_MAC).unwrap();
    fb.push(Cmd::Lrw, 1, Addr::logical(0), &[0u8; 0x18]).unwrap();
    fb.push_zeroed(Cmd::Brd, 2, Addr::broadcast(reg::AL_STATUS), 1).unwrap();
    fb.push_zeroed(Cmd::Fprd, 3, Addr::node(0x1000, reg::AL_STATUS), 2).unwrap();
    let n = fb.finish().unwrap();
    h.bus.exchange(&mut buf, n, 0);
    let d: Vec<_> = frame::parse(&buf[..n]).unwrap().datagrams().collect::<Result<_, _>>().unwrap();
    assert_eq!(d.iter().map(|x| (x.idx, x.wkc)).collect::<Vec<_>>(), [(1, 6), (2, 2), (3, 1)]);
    assert_eq!(d[1].data[0], AlState::Op as u8);
}
