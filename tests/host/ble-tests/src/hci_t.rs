// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_ble::hci::*;
use azos_ble::{Error, PeerAddr};

fn enc(c: Cmd) -> (u16, Vec<u8>) {
    let mut p = [0u8; CMD_PARAM_MAX];
    let (op, n) = c.encode(&mut p);
    (op, p[..n].to_vec())
}

#[test]
fn opcodes_are_ogf_and_ocf() {
    assert_eq!(OP_RESET, 0x0C03);
    assert_eq!(OP_READ_BD_ADDR, 0x1009);
    assert_eq!(OP_LE_SET_ADV_ENABLE, 0x200A);
    assert_eq!(OP_LE_CREATE_CONNECTION, 0x200D);
    assert_eq!(OP_LE_START_ENCRYPTION, 0x2019);
    assert_eq!(OP_DISCONNECT, 0x0406);
}

#[test]
fn commands_encode_to_the_documented_layouts() {
    assert_eq!(enc(Cmd::Reset), (0x0C03, vec![]));
    assert_eq!(enc(Cmd::LeSetAdvEnable(true)), (0x200A, vec![1]));
    assert_eq!(enc(Cmd::Disconnect { handle: 0x0041, reason: 0x13 }), (0x0406, vec![0x41, 0x00, 0x13]));
    let (op, p) = enc(Cmd::LeSetAdvParams(AdvParams {
        interval_min: 0x0800,
        interval_max: 0x0800,
        kind: ADV_IND,
        own_addr_type: 1,
        channel_map: 7,
    }));
    assert_eq!(op, 0x2006);
    assert_eq!(p.len(), 15);
    assert_eq!(&p[..6], &[0x00, 0x08, 0x00, 0x08, 0x00, 0x01]);
    assert_eq!((p[13], p[14]), (7, 0), "channel map, any-device filter");
    let (op, p) = enc(Cmd::LeCreateConnection {
        peer: PeerAddr { kind: 1, addr: [1, 2, 3, 4, 5, 6] },
        own_addr_type: 0,
        params: ConnParams { interval_min: 24, interval_max: 40, latency: 3, timeout: 400 },
    });
    assert_eq!(op, 0x200D);
    assert_eq!(p.len(), 25);
    assert_eq!(&p[4..12], &[0, 1, 1, 2, 3, 4, 5, 6], "filter policy, peer type, peer address");
    assert_eq!(&p[13..21], &[24, 0, 40, 0, 3, 0, 0x90, 0x01]);
    let (op, p) = enc(Cmd::LeStartEncryption { handle: 5, rand: [0; 8], ediv: 0, ltk: [0xAA; 16] });
    assert_eq!((op, p.len()), (0x2019, 28));
    assert_eq!(&p[12..], &[0xAA; 16]);
    let (_, p) = enc(Cmd::LeSetAdvData { len: 3, data: [7; 31] });
    assert_eq!((p.len(), p[0]), (32, 3));
    assert_eq!(enc(Cmd::SetEventMask(EVENT_MASK)).1.len(), 8);
}

#[test]
fn connection_parameters_are_range_checked() {
    let ok = ConnParams { interval_min: 24, interval_max: 40, latency: 0, timeout: 400 };
    assert!(ok.valid());
    assert!(!ConnParams { interval_min: 5, ..ok }.valid());
    assert!(!ConnParams { interval_max: 3201, ..ok }.valid());
    assert!(!ConnParams { interval_min: 41, ..ok }.valid());
    assert!(!ConnParams { latency: 500, ..ok }.valid());
    assert!(!ConnParams { timeout: 9, ..ok }.valid());
    // 1 + latency intervals of 40 * 1.25 ms, doubled, must fit in the supervision timeout.
    assert!(!ConnParams { latency: 4, timeout: 30, ..ok }.valid());
}

fn pkt(code: u8, p: &[u8]) -> Vec<u8> {
    let mut v = vec![code, p.len() as u8];
    v.extend_from_slice(p);
    v
}

#[test]
fn command_complete_and_status() {
    let b = pkt(EVT_COMMAND_COMPLETE, &[1, 0x09, 0x10, 0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(
        Event::parse(&b),
        Ok(Event::CommandComplete { ncmd: 1, opcode: 0x1009, ret: &[0, 1, 2, 3, 4, 5, 6] })
    );
    let b = pkt(EVT_COMMAND_STATUS, &[0x0C, 1, 0x0D, 0x20]);
    assert_eq!(Event::parse(&b), Ok(Event::CommandStatus { status: 0x0C, ncmd: 1, opcode: 0x200D }));
}

#[test]
fn malformed_events_are_errors_not_panics() {
    assert_eq!(Event::parse(&[]), Err(Error::Short));
    assert_eq!(Event::parse(&[0x0E, 0x03, 1, 2]), Err(Error::Invalid), "length field disagrees");
    assert_eq!(Event::parse(&pkt(EVT_COMMAND_COMPLETE, &[1, 2])), Err(Error::Short));
    assert_eq!(Event::parse(&pkt(EVT_NUM_COMPLETED_PACKETS, &[2, 1, 0, 1, 0])), Err(Error::Short));
    assert_eq!(Event::parse(&pkt(EVT_LE_META, &[])), Err(Error::Short));
    assert_eq!(Event::parse(&pkt(EVT_LE_META, &[LE_CONNECTION_COMPLETE, 0, 1])), Err(Error::Short));
    assert_eq!(Event::parse(&pkt(0x77, &[1])), Ok(Event::Other(0x77)));
}

#[test]
fn le_connection_complete_decodes() {
    let mut p = vec![LE_CONNECTION_COMPLETE, 0, 0x41, 0x10, 1, 0];
    p.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
    p.extend_from_slice(&[24, 0, 0, 0, 0x90, 0x01, 0]);
    match Event::parse(&pkt(EVT_LE_META, &p)).unwrap() {
        Event::LeConnectionComplete(c) => {
            assert_eq!(c.handle, 0x0041, "the flag bits above 12 are not part of the handle");
            assert_eq!((c.status, c.role, c.interval, c.timeout), (0, 1, 24, 400));
            assert_eq!(c.peer, PeerAddr { kind: 0, addr: [1, 2, 3, 4, 5, 6] });
        }
        e => panic!("{e:?}"),
    }
}

#[test]
fn advertising_reports_use_the_spec_layout_of_arrays() {
    // Two reports: the fields are grouped, not interleaved.
    let mut p = vec![LE_ADVERTISING_REPORT, 2];
    p.extend_from_slice(&[0x00, 0x04]); // event types
    p.extend_from_slice(&[0x00, 0x01]); // address types
    p.extend_from_slice(&[1, 1, 1, 1, 1, 1]);
    p.extend_from_slice(&[2, 2, 2, 2, 2, 2]);
    p.extend_from_slice(&[3, 2]); // data lengths
    p.extend_from_slice(&[0xA1, 0xA2, 0xA3]);
    p.extend_from_slice(&[0xB1, 0xB2]);
    p.extend_from_slice(&[(-60i8) as u8, (-70i8) as u8]);
    let b = pkt(EVT_LE_META, &p);
    let Event::LeAdvertisingReport(r) = Event::parse(&b).unwrap() else { panic!() };
    assert_eq!(r.len(), 2);
    let r0 = r.get(0).unwrap();
    assert_eq!((r0.kind, r0.peer.kind, r0.data, r0.rssi), (0, 0, &[0xA1, 0xA2, 0xA3][..], -60));
    let r1 = r.get(1).unwrap();
    assert_eq!((r1.kind, r1.peer, r1.data, r1.rssi), (4, PeerAddr { kind: 1, addr: [2; 6] }, &[0xB1, 0xB2][..], -70));
    assert!(r.get(2).is_none());
    // A data length that runs past the packet is refused.
    let mut bad = p.clone();
    bad.truncate(bad.len() - 4);
    assert!(Event::parse(&pkt(EVT_LE_META, &bad)).is_err());
}

#[test]
fn number_of_completed_packets_lists_handles_and_counts() {
    let p = [2, 0x41, 0x10, 0x42, 0x00, 3, 0, 1, 0];
    let b = pkt(EVT_NUM_COMPLETED_PACKETS, &p);
    let Event::NumCompletedPackets(c) = Event::parse(&b).unwrap() else { panic!() };
    assert_eq!((c.len(), c.get(0), c.get(1), c.get(2)), (2, Some((0x41, 3)), Some((0x42, 1)), None));
}

#[test]
fn ltk_request_and_encryption_change_decode() {
    let mut p = vec![LE_LTK_REQUEST, 0x41, 0x00];
    p.extend_from_slice(&[9; 8]);
    p.extend_from_slice(&[0x34, 0x12]);
    assert_eq!(
        Event::parse(&pkt(EVT_LE_META, &p)),
        Ok(Event::LeLtkRequest { handle: 0x41, rand: [9; 8], ediv: 0x1234 })
    );
    assert_eq!(
        Event::parse(&pkt(EVT_ENCRYPTION_CHANGE, &[0, 0x41, 0, 1])),
        Ok(Event::EncryptionChange { status: 0, handle: 0x41, enabled: 1 })
    );
    assert_eq!(
        Event::parse(&pkt(EVT_DISCONNECTION_COMPLETE, &[0, 0x41, 0, 0x13])),
        Ok(Event::DisconnectionComplete { status: 0, handle: 0x41, reason: 0x13 })
    );
}
