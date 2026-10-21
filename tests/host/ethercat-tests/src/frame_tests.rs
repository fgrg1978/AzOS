// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Codec: byte-exact layouts, round trips and every rejection.

use azos_ethercat::frame::*;
use azos_ethercat::Error;

const SRC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

#[test]
fn aprd_frame_bytes() {
    let mut buf = [0xAAu8; 128];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, SRC).unwrap();
    // First slave on the wire, AL status register, 2 bytes.
    let off = fb.push_zeroed(Cmd::Aprd, 7, Addr::position(0, 0x0130), 2).unwrap();
    assert_eq!(off, 16 + 10);
    let n = fb.finish().unwrap();
    assert_eq!(n, 60, "padded to the Ethernet minimum");
    let mut want = vec![
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // dst
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src
        0x88, 0xA4, // ethertype, big endian
        0x0E, 0x10, // length 14, type 1
        0x01, 0x07, // APRD, idx 7
        0x00, 0x00, 0x30, 0x01, // ADP 0, ADO 0x0130
        0x02, 0x00, // len 2, no flags
        0x00, 0x00, // irq
        0x00, 0x00, // data
        0x00, 0x00, // wkc
    ];
    want.resize(60, 0);
    assert_eq!(&buf[..n], &want[..]);
}

#[test]
fn chained_datagrams_set_more_on_all_but_the_last() {
    let mut buf = [0u8; 256];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, SRC).unwrap();
    let o1 = fb.push(Cmd::Fpwr, 1, Addr::node(0x1001, 0x0120), &[0x02, 0x00]).unwrap();
    let o2 = fb.push(Cmd::Lrw, 2, Addr::logical(0x0001_0000), &[1, 2, 3, 4, 5]).unwrap();
    let o3 = fb.push_zeroed(Cmd::Brd, 3, Addr::broadcast(0), 1).unwrap();
    let n = fb.finish().unwrap();
    assert_eq!((o1, o2, o3), (26, 40, 57));
    let f = parse(&buf[..n]).unwrap();
    let d: Vec<_> = f.datagrams().collect::<Result<_, _>>().unwrap();
    assert_eq!(d.len(), 3);
    assert_eq!((d[0].more, d[1].more, d[2].more), (true, true, false));
    assert_eq!((d[0].cmd, d[1].cmd, d[2].cmd), (Cmd::Fpwr, Cmd::Lrw, Cmd::Brd));
    assert_eq!(d[0].addr, Addr::node(0x1001, 0x0120));
    assert_eq!((d[0].addr.adp(), d[0].addr.ado()), (0x1001, 0x0120));
    assert_eq!(d[1].addr, Addr::logical(0x0001_0000));
    assert_eq!(d[1].data, &[1, 2, 3, 4, 5]);
    assert_eq!(d[1].data_offset, o2);
    assert_eq!(&buf[o2..o2 + 5], &[1, 2, 3, 4, 5]);
    assert_eq!(d[2].data_offset, o3);
    assert!(d.iter().all(|x| x.wkc == 0 && !x.circulating && x.irq == 0));
}

#[test]
fn datagram_offsets_are_where_the_bytes_are() {
    let mut buf = [0u8; 256];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, SRC).unwrap();
    let a = fb.push(Cmd::Lwr, 9, Addr::logical(0), &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    let b = fb.push(Cmd::Lrd, 10, Addr::logical(0x40), &[0; 8]).unwrap();
    // 16 header + (10 + 4 + 2) for the first datagram, data after its 10 header bytes.
    assert_eq!(a, 16 + 10);
    assert_eq!(b, 16 + 16 + 10);
    let n = fb.finish().unwrap();
    // A cyclic master rewrites process data in place.
    buf[a..a + 4].copy_from_slice(&[1, 2, 3, 4]);
    let d: Vec<_> = parse(&buf[..n]).unwrap().datagrams().collect::<Result<_, _>>().unwrap();
    assert_eq!(d[0].data, &[1, 2, 3, 4]);
}

#[test]
fn builder_overwrites_a_dirty_buffer_completely() {
    let mut dirty = [0xFFu8; 200];
    let mut clean = [0x00u8; 200];
    for b in [&mut dirty, &mut clean] {
        let mut fb = FrameBuilder::new(&mut b[..], BROADCAST_MAC, SRC).unwrap();
        fb.push_zeroed(Cmd::Nop, 0, Addr(0), 0).unwrap();
        fb.push_zeroed(Cmd::Brd, 1, Addr::broadcast(0), 3).unwrap();
        assert_eq!(fb.finish().unwrap(), 60);
    }
    assert_eq!(dirty[..60], clean[..60]);
}

#[test]
fn position_addresses_count_down() {
    assert_eq!(Addr::position(0, 0x130).adp(), 0);
    assert_eq!(Addr::position(1, 0x130).adp(), 0xFFFF);
    assert_eq!(Addr::position(3, 0x130).adp(), 0xFFFD);
    assert_eq!(Addr::position(3, 0x130).ado(), 0x130);
    assert_eq!(Addr::position(1, 0x0130), Addr(0x0130_FFFF));
}

#[test]
fn command_codes_and_classes() {
    for v in 0..=14u8 {
        assert_eq!(Cmd::from_u8(v).unwrap() as u8, v);
    }
    assert_eq!(Cmd::from_u8(15), Err(Error::UnknownCmd(15)));
    assert_eq!(Cmd::from_u8(255), Err(Error::UnknownCmd(255)));
    assert_eq!(Cmd::Aprd.addressing(), Addressing::Position);
    assert_eq!(Cmd::Fprw.addressing(), Addressing::Node);
    assert_eq!(Cmd::Bwr.addressing(), Addressing::Broadcast);
    assert_eq!(Cmd::Lrw.addressing(), Addressing::Logical);
    assert_eq!(Cmd::Nop.addressing(), Addressing::None);
    assert_eq!(Cmd::Armw.addressing(), Addressing::Position);
    assert_eq!(Cmd::Frmw.addressing(), Addressing::Node);
    assert!(Cmd::Aprd.reads() && !Cmd::Aprd.writes());
    assert!(!Cmd::Fpwr.reads() && Cmd::Fpwr.writes());
    assert!(Cmd::Lrw.reads() && Cmd::Lrw.writes());
    assert!(!Cmd::Nop.reads() && !Cmd::Nop.writes());
}

#[test]
fn max_frame_fits_and_one_more_byte_does_not() {
    let mut buf = [0u8; MAX_FRAME];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, SRC).unwrap();
    let max = MAX_PAYLOAD - DG_OVERHEAD;
    assert_eq!(max, 1486);
    fb.push(Cmd::Lrw, 0, Addr::logical(0), &vec![0x5A; max + 1]).unwrap_err();
    fb.push(Cmd::Lrw, 0, Addr::logical(0), &vec![0x5A; max]).unwrap();
    assert_eq!(fb.push_zeroed(Cmd::Nop, 1, Addr(0), 0), Err(Error::TooLong));
    let n = fb.finish().unwrap();
    assert_eq!(n, MAX_FRAME);
    let f = parse(&buf[..n]).unwrap();
    let d = f.datagrams().next().unwrap().unwrap();
    assert_eq!(d.data.len(), max);
}

#[test]
fn builder_rejections() {
    let mut tiny = [0u8; 59];
    assert!(matches!(FrameBuilder::new(&mut tiny, BROADCAST_MAC, SRC), Err(Error::BufferTooSmall)));
    let mut small = [0u8; 70];
    let mut fb = FrameBuilder::new(&mut small, BROADCAST_MAC, SRC).unwrap();
    assert_eq!(fb.push_zeroed(Cmd::Lrd, 0, Addr::logical(0), 43), Err(Error::BufferTooSmall));
    fb.push_zeroed(Cmd::Lrd, 0, Addr::logical(0), 42).unwrap();
    let mut buf = [0u8; 100];
    let fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, SRC).unwrap();
    assert_eq!(fb.finish(), Err(Error::Empty));
    // An 11-bit length field cannot hold 2048.
    let mut big = [0u8; 4096];
    let mut fb = FrameBuilder::new(&mut big, BROADCAST_MAC, SRC).unwrap();
    assert_eq!(fb.push_zeroed(Cmd::Lrd, 0, Addr::logical(0), 2048), Err(Error::TooLong));
}

fn one_frame() -> ([u8; 100], usize) {
    let mut buf = [0u8; 100];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, SRC).unwrap();
    fb.push(Cmd::Fprd, 4, Addr::node(0x1000, 0x130), &[0, 0]).unwrap();
    let n = fb.finish().unwrap();
    (buf, n)
}

#[test]
fn parser_rejections() {
    let (good, n) = one_frame();
    assert!(parse(&good[..n]).is_ok());

    assert!(matches!(parse(&good[..15]), Err(Error::Truncated)));

    let mut b = good;
    b[12] = 0x08;
    b[13] = 0x00;
    assert!(matches!(parse(&b[..n]), Err(Error::NotEthercat)));

    let mut b = good;
    b[15] = (b[15] & 0x0F) | 0x40; // type 4: network variables
    assert!(matches!(parse(&b[..n]), Err(Error::UnsupportedType(4))));

    // Length field larger than the bytes present.
    let mut b = good;
    b[14] = 0xFF;
    b[15] = 0x17;
    assert!(matches!(parse(&b[..n]), Err(Error::Truncated)));

    // Unknown command.
    let mut b = good;
    b[16] = 15;
    let f = parse(&b[..n]).unwrap();
    assert_eq!(f.datagrams().next().unwrap().unwrap_err(), Error::UnknownCmd(15));

    // Datagram claims more data than the EtherCAT length covers.
    let mut b = good;
    b[22] = 40;
    let f = parse(&b[..n]).unwrap();
    assert_eq!(f.datagrams().next().unwrap().unwrap_err(), Error::Truncated);

    // "More" set on the last datagram.
    let mut b = good;
    b[23] |= 0x80;
    let f = parse(&b[..n]).unwrap();
    let mut it = f.datagrams();
    assert_eq!(it.next().unwrap().unwrap_err(), Error::BadChain);
    assert!(it.next().is_none(), "the iterator ends after an error");

    // "More" clear but bytes follow: second datagram hidden after the first.
    let mut buf = [0u8; 100];
    let mut fb = FrameBuilder::new(&mut buf, BROADCAST_MAC, SRC).unwrap();
    fb.push_zeroed(Cmd::Nop, 0, Addr(0), 0).unwrap();
    fb.push_zeroed(Cmd::Nop, 1, Addr(0), 0).unwrap();
    let n = fb.finish().unwrap();
    buf[23] &= 0x7F;
    let f = parse(&buf[..n]).unwrap();
    assert_eq!(f.datagrams().next().unwrap().unwrap_err(), Error::BadChain);
}

#[test]
fn circulating_flag_and_irq_are_decoded() {
    let (mut b, n) = one_frame();
    b[23] |= 0x40;
    b[24] = 0x34;
    b[25] = 0x12;
    let f = parse(&b[..n]).unwrap();
    let d = f.datagrams().next().unwrap().unwrap();
    assert!(d.circulating && !d.more);
    assert_eq!(d.irq, 0x1234);
}

#[test]
fn macs_round_trip_and_padding_is_not_counted() {
    let (b, n) = one_frame();
    let f = parse(&b[..n]).unwrap();
    assert_eq!((f.dst, f.src), (BROADCAST_MAC, SRC));
    assert_eq!(f.datagrams().count(), 1);
    // The 60-byte frame has padding after the 14-byte payload; a parse of the
    // padded frame sees exactly the one datagram.
    assert!(n > FIRST_DG_OFFSET + DG_OVERHEAD + 2);
}
