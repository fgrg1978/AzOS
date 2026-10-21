// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The NTB-16 parser and builder, and the class-specific descriptor parser,
//! on bytes: no controller, no device.

use azos_usb::class::cdc::ntb::{
    NtbError, Params, Rx16, Tx16, TxParams, NDP16_SIG, NTH16_SIG, TX_MAX_DATAGRAMS,
};
use azos_usb::class::cdc::{mac_from_string, parse_comm, CommInfo};

use crate::fixtures::{cs, ep, iface, AcmFn, NetFn};

// ---- Blocks as a device builds them ----

fn nth(seq: u16, block: usize, ndp: usize) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend(NTH16_SIG.to_le_bytes());
    h.extend(12u16.to_le_bytes());
    h.extend(seq.to_le_bytes());
    h.extend((block as u16).to_le_bytes());
    h.extend((ndp as u16).to_le_bytes());
    h
}

fn ndp(sig: u32, len: usize, next: usize, entries: &[(usize, usize)]) -> Vec<u8> {
    let mut n = Vec::new();
    n.extend(sig.to_le_bytes());
    n.extend((len as u16).to_le_bytes());
    n.extend((next as u16).to_le_bytes());
    for (i, l) in entries {
        n.extend((*i as u16).to_le_bytes());
        n.extend((*l as u16).to_le_bytes());
    }
    n
}

/// The layout the reference host's peers use: the NTH, the NDP right after
/// it, then the datagrams on 4-byte boundaries.
fn block(dgs: &[&[u8]]) -> Vec<u8> {
    let ndp_len = 8 + 4 * (dgs.len() + 1);
    let mut off = 12 + ndp_len;
    let mut entries = Vec::new();
    let mut body = Vec::new();
    for d in dgs {
        entries.push((off, d.len()));
        body.extend(*d);
        while body.len() % 4 != 0 {
            body.push(0);
        }
        off = 12 + ndp_len + body.len();
    }
    entries.push((0, 0));
    let mut b = nth(7, 12 + ndp_len + body.len(), 12);
    b.extend(ndp(NDP16_SIG, ndp_len, 0, &entries));
    b.extend(body);
    b
}

fn frame(n: usize, tag: u8) -> Vec<u8> {
    (0..n).map(|i| tag.wrapping_add(i as u8)).collect()
}

/// Every datagram of `b` (of which `actual` bytes arrived), or the error that
/// ended the block, with what was yielded before it.
fn read(b: &[u8], actual: usize) -> (Vec<Vec<u8>>, Option<NtbError>) {
    let mut r = match Rx16::open(b, actual) {
        Ok(r) => r,
        Err(e) => return (vec![], Some(e)),
    };
    let mut out = vec![];
    loop {
        match r.next(b) {
            Ok(Some((o, l))) => out.push(b[o..o + l].to_vec()),
            Ok(None) => return (out, None),
            Err(e) => return (out, Some(e)),
        }
    }
}

// ---- Receive ----

#[test]
fn a_block_with_several_datagrams_is_read_in_order() {
    let (a, b, c) = (frame(60, 1), frame(61, 2), frame(1514, 3));
    let blk = block(&[&a, &b, &c]);
    let (got, err) = read(&blk, blk.len());
    assert_eq!(err, None);
    assert_eq!(got, vec![a, b, c]);
    assert_eq!(Rx16::open(&blk[..], blk.len()).unwrap().sequence, 7);
}

#[test]
fn a_block_that_arrived_longer_than_it_states_is_cut_at_its_length() {
    // The pad byte after a block on a packet boundary is outside it.
    let a = frame(60, 1);
    let mut blk = block(&[&a]);
    let n = blk.len();
    blk.push(0);
    let (got, err) = read(&blk, n + 1);
    assert_eq!((got, err), (vec![a], None));
}

#[test]
fn a_block_length_of_zero_means_what_arrived() {
    let a = frame(60, 1);
    let mut blk = block(&[&a]);
    blk[8] = 0;
    blk[9] = 0;
    let (got, err) = read(&blk, blk.len());
    assert_eq!((got, err), (vec![a], None));
}

#[test]
fn a_block_longer_than_what_arrived_is_refused() {
    let blk = block(&[&frame(60, 1)]);
    assert_eq!(read(&blk, blk.len() - 1).1, Some(NtbError::BlockLength));
}

#[test]
fn headers_that_lie_are_refused() {
    let blk = block(&[&frame(60, 1)]);
    let n = blk.len();
    // Shorter than an NTH.
    assert_eq!(read(&blk[..8], 8).1, Some(NtbError::Short));
    // Not an NTH16 (an NTH32 is "ncmh").
    let mut b = blk.clone();
    b[0] = b'n';
    assert_eq!(read(&b, n).1, Some(NtbError::Signature));
    // wHeaderLength.
    let mut b = blk.clone();
    b[4] = 16;
    assert_eq!(read(&b, n).1, Some(NtbError::HeaderLength));
    // wNdpIndex inside the NTH, and past the block.
    for idx in [0usize, 8, n - 8, n + 4] {
        let mut b = blk.clone();
        b[10..12].copy_from_slice(&(idx as u16).to_le_bytes());
        assert_eq!(read(&b, n).1, Some(NtbError::NdpIndex), "ndp index {idx}");
    }
    // An NDP with a CRC ("NCM1"), which this host does not negotiate.
    let mut b = blk.clone();
    b[12 + 3] = b'1';
    assert_eq!(read(&b, n).1, Some(NtbError::NdpSignature));
    // wLength of the NDP: under the minimum, past the block.
    for len in [8usize, 12, n] {
        let mut b = blk.clone();
        b[16..18].copy_from_slice(&(len as u16).to_le_bytes());
        assert_eq!(read(&b, n).1, Some(NtbError::NdpLength), "ndp length {len}");
    }
}

#[test]
fn a_datagram_past_the_end_of_the_block_ends_the_block() {
    let (a, b) = (frame(60, 1), frame(60, 2));
    let mut blk = block(&[&a, &b]);
    let n = blk.len();
    // The second entry claims 200 bytes: it runs past the block.
    let e2 = 12 + 8 + 4;
    blk[e2 + 2..e2 + 4].copy_from_slice(&200u16.to_le_bytes());
    let (got, err) = read(&blk, n);
    // The first datagram stands; the bad one ends the block.
    assert_eq!(got, vec![a]);
    assert_eq!(err, Some(NtbError::Datagram));
}

#[test]
fn a_datagram_inside_the_headers_is_refused() {
    let a = frame(60, 1);
    let mut blk = block(&[&a]);
    let n = blk.len();
    blk[20..22].copy_from_slice(&4u16.to_le_bytes()); // index 4: inside the NTH
    assert_eq!(read(&blk, n), (vec![], Some(NtbError::Datagram)));
}

#[test]
fn an_empty_block_has_no_datagrams() {
    // An NDP of the minimum length whose first entry is already the terminator.
    let mut blk = nth(1, 28, 12);
    blk.extend(ndp(NDP16_SIG, 16, 0, &[(0, 0), (0, 0)]));
    assert_eq!(read(&blk, blk.len()), (vec![], None));
}

#[test]
fn an_entry_table_without_a_terminator_ends_with_the_ndp() {
    let a = frame(60, 1);
    let mut blk = block(&[&a]);
    // wLength covers the entry only: no (0, 0) after it.
    let n = blk.len();
    blk[16..18].copy_from_slice(&16u16.to_le_bytes());
    assert_eq!(read(&blk, n), (vec![a], None));
}

#[test]
fn chained_ndps_are_followed_in_order() {
    // NTH, NDP 1 at 12 (one datagram, next = 36), NDP 2 at 36, datagrams.
    let (a, b) = (frame(60, 1), frame(60, 2));
    let mut blk = nth(1, 0, 12);
    blk.extend(ndp(NDP16_SIG, 16, 36, &[(60, 60), (0, 0)]));
    blk.extend([0u8; 8]); // 28..36
    blk.extend(ndp(NDP16_SIG, 16, 0, &[(120, 60), (0, 0)]));
    blk.extend([0u8; 8]); // 52..60
    blk.extend(&a);
    blk.extend(&b);
    let n = blk.len();
    blk[8..10].copy_from_slice(&(n as u16).to_le_bytes());
    assert_eq!(read(&blk, n), (vec![a, b], None));
}

#[test]
fn an_ndp_chain_that_loops_or_runs_on_is_cut() {
    // NDP 1 points back at itself.
    let mut blk = nth(1, 0, 12);
    blk.extend(ndp(NDP16_SIG, 16, 12, &[(28, 20), (0, 0)]));
    blk.extend(frame(20, 0));
    let n = blk.len();
    blk[8..10].copy_from_slice(&(n as u16).to_le_bytes());
    let (got, err) = read(&blk, n);
    assert_eq!((got.len(), err), (1, Some(NtbError::Chain)));
    // A forward chain longer than the limit: each NDP is 16 bytes.
    let mut blk = nth(1, 0, 12);
    for i in 0..8usize {
        let next = if i == 7 { 0 } else { 12 + 16 * (i + 1) };
        blk.extend(ndp(NDP16_SIG, 16, next, &[(12 + 16 * 8, 20), (0, 0)]));
    }
    blk.extend(frame(20, 0));
    let n = blk.len();
    blk[8..10].copy_from_slice(&(n as u16).to_le_bytes());
    let (got, err) = read(&blk, n);
    assert_eq!(err, Some(NtbError::Chain));
    assert!(got.len() <= 5, "the chain is cut after a few NDPs, not read to the end");
}

// ---- Build ----

fn build(p: TxParams, frames: &[Vec<u8>]) -> (Vec<u8>, usize) {
    let mut t = Tx16::new(p);
    let mut buf = vec![0xeeu8; 65536];
    for f in frames {
        assert!(t.add(f, &mut |o, b| buf[o..o + b.len()].copy_from_slice(b)), "fits");
    }
    let n = t.finish(&mut |o, b| buf[o..o + b.len()].copy_from_slice(b));
    buf.truncate(n);
    (buf, n)
}

fn plain() -> TxParams {
    TxParams { max_size: 16384, ndp_align: 4, divisor: 4, remainder: 0, max_datagrams: 0 }
}

#[test]
fn one_frame_makes_the_block_the_wire_expects() {
    let f = frame(60, 9);
    let (b, n) = build(plain(), std::slice::from_ref(&f));
    // NTH (12), the frame at 12, the NDP at 72 (aligned), 16 bytes of it.
    let mut want = nth(0, 88, 72);
    want.extend(&f);
    want.extend(ndp(NDP16_SIG, 16, 0, &[(12, 60), (0, 0)]));
    assert_eq!((n, b), (88, want));
}

#[test]
fn the_divisor_and_the_remainder_place_each_datagram() {
    // Datagrams start at 2 modulo 8; the NDP at a multiple of 16.
    let p = TxParams { divisor: 8, remainder: 2, ndp_align: 16, ..plain() };
    let frames = vec![frame(61, 1), frame(77, 2), frame(60, 3)];
    let (b, _) = build(p, &frames);
    let mut r = Rx16::open(&b[..], b.len()).unwrap();
    let mut at = vec![];
    while let Some((o, l)) = r.next(&b[..]).unwrap() {
        assert_eq!(o % 8, 2, "datagram at {o}");
        at.push(b[o..o + l].to_vec());
    }
    assert_eq!(at, frames);
    let ndp_at = u16::from_le_bytes([b[10], b[11]]) as usize;
    assert_eq!(ndp_at % 16, 0);
}

#[test]
fn what_is_built_is_read_back_for_any_parameters() {
    for (divisor, remainder, align) in [(1, 0, 4), (4, 0, 4), (4, 2, 8), (8, 6, 16), (16, 15, 64), (64, 1, 4)] {
        for lens in [vec![14], vec![60], vec![1514], vec![60, 61, 62, 63], vec![1514, 14, 700, 99, 3]] {
            let p = TxParams { divisor, remainder, ndp_align: align, ..plain() };
            let frames: Vec<Vec<u8>> = lens.iter().enumerate().map(|(i, l)| frame(*l, i as u8 * 40)).collect();
            let (b, _) = build(p, &frames);
            let (got, err) = read(&b, b.len());
            assert_eq!((got, err), (frames, None), "divisor {divisor} remainder {remainder} align {align} lens {lens:?}");
        }
    }
}

#[test]
fn a_block_does_not_outgrow_its_limits() {
    let mut t = Tx16::new(TxParams { max_size: 400, ..plain() });
    let mut buf = vec![0u8; 1024];
    let f = frame(100, 0);
    let mut n = 0;
    while t.add(&f, &mut |o, b| buf[o..o + b.len()].copy_from_slice(b)) {
        n += 1;
    }
    // 12 + n * 100 + the NDP (8 + 4 * (n + 1)) <= 400.
    assert_eq!(n, 3);
    let total = t.finish(&mut |o, b| buf[o..o + b.len()].copy_from_slice(b));
    assert!(total <= 400, "{total}");
    // The datagram limit of the device.
    let mut t = Tx16::new(TxParams { max_datagrams: 2, ..plain() });
    assert!(t.add(&frame(60, 0), &mut |_, _| {}));
    assert!(t.add(&frame(60, 0), &mut |_, _| {}));
    assert!(!t.can_add(60));
    // Ours.
    let mut t = Tx16::new(TxParams { max_size: 60000, ..plain() });
    for _ in 0..TX_MAX_DATAGRAMS {
        assert!(t.add(&frame(14, 0), &mut |_, _| {}));
    }
    assert!(!t.can_add(14));
    // A frame that is nothing, or more than a block holds.
    assert!(!t.can_add(0));
    assert!(!Tx16::new(plain()).can_add(70000));
}

#[test]
fn the_sequence_counts_blocks_and_a_block_after_a_block_starts_clean() {
    let mut t = Tx16::new(plain());
    let mut buf = vec![0u8; 4096];
    for want in 0..3u16 {
        assert!(t.add(&frame(60, want as u8), &mut |o, b| buf[o..o + b.len()].copy_from_slice(b)));
        let n = t.finish(&mut |o, b| buf[o..o + b.len()].copy_from_slice(b));
        let r = Rx16::open(&buf[..], n).unwrap();
        assert_eq!(r.sequence, want);
        assert!(t.is_empty());
        assert_eq!(read(&buf[..n], n).0, vec![frame(60, want as u8)], "no leftover of the block before");
    }
}

// ---- GET_NTB_PARAMETERS ----

#[test]
fn the_parameters_are_parsed_and_the_odd_ones_normalized() {
    let raw = crate::fixtures::ntb_params(3, 16384, 8192, 8, 2, 16, 5);
    let p = Params::parse(&raw).unwrap();
    assert_eq!(
        p,
        Params { formats: 3, in_max: 16384, out_max: 8192, out_divisor: 8, out_remainder: 2, out_align: 16, out_datagrams: 5 }
    );
    // The device's limit counts the pad byte the host may add after a block.
    let tx = p.tx(60000);
    assert_eq!(tx, TxParams { max_size: 8191, ndp_align: 16, divisor: 8, remainder: 2, max_datagrams: 5 });
    // Our buffer is the smaller limit.
    assert_eq!(p.tx(4000).max_size, 4000);
    // An alignment that is not a power of two, a divisor of 0, a remainder
    // past the divisor: the reference host's defaults.
    let odd = Params { out_align: 6, out_divisor: 0, out_remainder: 9, ..p };
    let tx = odd.tx(60000);
    assert_eq!((tx.ndp_align, tx.divisor, tx.remainder), (4, 4, 0));
    // A device that states no size takes ours; blocks count in 16 bits.
    assert_eq!(Params { out_max: 0, ..p }.tx(100_000).max_size, 65535);
    // Too short a table.
    assert_eq!(Params::parse(&raw[..27]), None);
    let mut short = raw.clone();
    short[0] = 12;
    assert_eq!(Params::parse(&short), None);
}

// ---- Class-specific descriptors ----

fn cfg(body: Vec<u8>) -> Vec<u8> {
    crate::fixtures::config(2, body)
}

#[test]
fn an_ecm_interface_names_its_data_interface_mac_and_segment() {
    let c = cfg(NetFn::ecm().bytes());
    let i = parse_comm(&c[..], 0);
    assert_eq!(
        i,
        CommInfo { data_iface: 1, has_union: true, mac_string: 3, max_segment: 1514, ..CommInfo::default() }
    );
}

#[test]
fn an_ncm_interface_adds_its_capabilities() {
    let c = cfg(NetFn { ncm: Some(0x11), ..NetFn::ncm() }.bytes());
    let i = parse_comm(&c[..], 0);
    assert!(i.has_ncm);
    assert_eq!(i.ncm_caps, 0x11);
}

#[test]
fn an_acm_interface_reports_its_capabilities() {
    let c = cfg(AcmFn { caps: Some(0x06), ..AcmFn::new() }.bytes());
    let i = parse_comm(&c[..], 0);
    assert_eq!((i.has_acm, i.acm_caps, i.data_iface, i.has_union), (true, 0x06, 1, true));
    let c = cfg(AcmFn { caps: None, ..AcmFn::new() }.bytes());
    assert!(!parse_comm(&c[..], 0).has_acm);
}

#[test]
fn the_union_wins_over_the_next_interface_and_its_absence_falls_back_to_it() {
    let c = cfg(NetFn { union_data: 5, ..NetFn::ecm() }.bytes());
    assert_eq!(parse_comm(&c[..], 0).data_iface, 5);
    let c = cfg(NetFn { union: false, ..NetFn::ecm() }.bytes());
    let i = parse_comm(&c[..], 0);
    assert_eq!((i.data_iface, i.has_union), (1, false));
}

#[test]
fn descriptors_of_another_interface_are_not_this_ones() {
    // Two functions: the second's descriptors do not leak into the first.
    let mut body = NetFn::ecm().bytes();
    body.extend(NetFn { comm: 2, data: 3, union_data: 3, mac_idx: 9, segment: 1500, base: 4, ..NetFn::ncm() }.bytes());
    let c = crate::fixtures::config(4, body);
    let a = parse_comm(&c[..], 0);
    let b = parse_comm(&c[..], 2);
    assert_eq!((a.mac_string, a.max_segment, a.has_ncm, a.data_iface), (3, 1514, false, 1));
    assert_eq!((b.mac_string, b.max_segment, b.has_ncm, b.data_iface), (9, 1500, true, 3));
}

#[test]
fn a_damaged_descriptor_ends_the_walk_without_a_panic() {
    let mut c = cfg(NetFn::ecm().bytes());
    // Truncate in the middle of the Ethernet descriptor, then lie about a length.
    let i = parse_comm(&c[..30], 0);
    assert_eq!(i.mac_string, 0);
    let at = c.iter().position(|w| *w == 0x0f).unwrap() - 2;
    c[at] = 0xff;
    let _ = parse_comm(&c[..], 0);
    c[at] = 0;
    let _ = parse_comm(&c[..], 0);
    assert_eq!(parse_comm(&[][..], 0).data_iface, 1);
    assert_eq!(parse_comm(&c[..5], 0).data_iface, 1);
    // Anything else in there is skipped.
    let mut body = iface(0, 0, 0, 2, 6);
    body.extend(cs(0x99, &[1, 2, 3]));
    body.extend(ep(0x81, 3, 16, 8));
    let _ = parse_comm(&cfg(body)[..], 0);
}

#[test]
fn the_mac_is_twelve_hex_digits_in_utf16() {
    use azos_usb_tests::devices::string_desc;
    assert_eq!(mac_from_string(&string_desc("02a1b2c3d4e5")), Some([0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5]));
    assert_eq!(mac_from_string(&string_desc("02A1B2C3D4E5")), Some([0x02, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5]));
    assert_eq!(mac_from_string(&string_desc("02a1b2c3d4e")), None, "eleven digits");
    assert_eq!(mac_from_string(&string_desc("02a1b2c3d4eg")), None, "not hex");
    assert_eq!(mac_from_string(&string_desc("")), None);
    // A non-ASCII UTF-16 unit.
    let mut d = string_desc("02a1b2c3d4e5");
    d[3] = 1;
    assert_eq!(mac_from_string(&d), None);
    // bLength under what the buffer holds.
    let mut d = string_desc("02a1b2c3d4e5");
    d[0] = 10;
    assert_eq!(mac_from_string(&d), None);
}
