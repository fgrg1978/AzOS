// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_ble::l2cap::*;
use azos_ble::{Error, L2CAP_MTU};

#[test]
fn acl_header() {
    let (h, d) = parse_acl(&[0x41, 0x20, 0x02, 0x00, 7, 8]).unwrap();
    assert_eq!((h.handle, h.pb, d), (0x41, 2, &[7u8, 8][..]));
    assert_eq!(parse_acl(&[1, 2, 3]).unwrap_err(), Error::Short);
    assert_eq!(parse_acl(&[0x41, 0x00, 0x05, 0x00, 7]).unwrap_err(), Error::Invalid);
}

fn first(len: u16, cid: u16, data: &[u8]) -> Vec<u8> {
    let mut v = len.to_le_bytes().to_vec();
    v.extend_from_slice(&cid.to_le_bytes());
    v.extend_from_slice(data);
    v
}

#[test]
fn a_frame_in_three_fragments_is_reassembled() {
    let mut r = Reassembler::new();
    assert_eq!(r.push(PB_FIRST, &first(10, CID_ATT, &[1, 2, 3])), Reassembled::Pending);
    assert_eq!(r.push(PB_CONTINUATION, &[4, 5, 6, 7]), Reassembled::Pending);
    let done = r.push(PB_CONTINUATION, &[8, 9, 10]);
    assert_eq!(done, Reassembled::Frame { cid: CID_ATT, len: 10 });
    assert_eq!(r.frame(10), &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
}

#[test]
fn a_whole_frame_in_one_fragment() {
    let mut r = Reassembler::new();
    assert_eq!(r.push(0b10, &first(2, CID_SMP, &[9, 9])), Reassembled::Frame { cid: CID_SMP, len: 2 });
}

#[test]
fn broken_sequences_drop_the_frame_and_the_next_one_works() {
    let mut r = Reassembler::new();
    // A continuation with nothing begun.
    assert_eq!(r.push(PB_CONTINUATION, &[1]), Reassembled::Dropped);
    // A new frame inside one.
    assert_eq!(r.push(PB_FIRST, &first(10, CID_ATT, &[1])), Reassembled::Pending);
    assert_eq!(r.push(PB_FIRST, &first(1, CID_ATT, &[1])), Reassembled::Dropped);
    // More data than announced.
    assert_eq!(r.push(PB_FIRST, &first(3, CID_ATT, &[1, 2])), Reassembled::Pending);
    assert_eq!(r.push(PB_CONTINUATION, &[3, 4]), Reassembled::Dropped);
    // Larger than the MTU, and a header cut short.
    assert_eq!(r.push(PB_FIRST, &first(L2CAP_MTU as u16 + 1, CID_ATT, &[1])), Reassembled::Dropped);
    assert_eq!(r.push(PB_FIRST, &[1, 0]), Reassembled::Dropped);
    // More than announced in the first fragment itself.
    assert_eq!(r.push(PB_FIRST, &first(1, CID_ATT, &[1, 2])), Reassembled::Dropped);
    assert_eq!(r.dropped, 6);
    assert_eq!(r.push(PB_FIRST, &first(1, CID_ATT, &[5])), Reassembled::Frame { cid: CID_ATT, len: 1 });
}

#[test]
fn frame_builder() {
    let mut o = [0u8; 300];
    let n = frame(CID_SMP, &[1, 2, 3], &mut o).unwrap();
    assert_eq!(&o[..n], &[3, 0, 6, 0, 1, 2, 3]);
    assert!(frame(CID_SMP, &[0; L2CAP_MTU + 1], &mut o).is_none());
    assert!(frame(CID_SMP, &[0; 10], &mut o[..8]).is_none());
}

#[test]
fn signalling_codec() {
    let mut o = [0u8; 32];
    let n = Signal::ConnectionParameterUpdateReq { id: 7, interval_min: 24, interval_max: 40, latency: 1, timeout: 400 }
        .encode(&mut o)
        .unwrap();
    assert_eq!(&o[..n], &[0x12, 7, 8, 0, 24, 0, 40, 0, 1, 0, 0x90, 0x01]);
    assert_eq!(
        Signal::parse(&o[..n]).unwrap(),
        Signal::ConnectionParameterUpdateReq { id: 7, interval_min: 24, interval_max: 40, latency: 1, timeout: 400 }
    );
    let n = Signal::ConnectionParameterUpdateRsp { id: 7, result: sig::UPDATE_ACCEPTED }.encode(&mut o).unwrap();
    assert_eq!(&o[..n], &[0x13, 7, 2, 0, 0, 0]);
    let n = Signal::CommandReject { id: 3, reason: sig::REASON_NOT_UNDERSTOOD }.encode(&mut o).unwrap();
    assert_eq!(&o[..n], &[0x01, 3, 2, 0, 0, 0]);
    let n = Signal::LeCreditConnectionRsp { id: 9, result: sig::RESULT_PSM_NOT_SUPPORTED }.encode(&mut o).unwrap();
    assert_eq!(&o[..n], &[0x15, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0]);
    assert!(matches!(Signal::parse(&[0x14, 1, 10, 0, 0x80, 0, 0x41, 0, 23, 0, 23, 0, 5, 0]), Ok(Signal::LeCreditConnectionReq { id: 1, psm: 0x80, scid: 0x41 })));
    assert_eq!(Signal::parse(&[0x77, 4, 0, 0]), Ok(Signal::Other { code: 0x77, id: 4 }));
    assert_eq!(Signal::parse(&[0x12, 7, 8, 0, 1]), Err(Error::Invalid));
    assert_eq!(Signal::parse(&[0x12, 7]), Err(Error::Short));
    assert_eq!(Signal::parse(&[0x12, 7, 2, 0, 1, 0]), Err(Error::Short));
}
