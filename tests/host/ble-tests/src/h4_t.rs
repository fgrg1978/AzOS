// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
use azos_ble::h4::*;

fn feed(d: &mut Deframer, bytes: &[u8]) -> Vec<(Kind, Vec<u8>)> {
    let mut out = vec![];
    for &b in bytes {
        if let Some(k) = d.push(b) {
            out.push((k, d.body().to_vec()));
        }
    }
    out
}

#[test]
fn a_packet_straddling_every_split_point_is_delivered_once() {
    let evt = [0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00];
    let acl = [0x02, 0x01, 0x20, 0x05, 0x00, 1, 2, 3, 4, 5];
    for split in 1..evt.len() {
        let mut d = Deframer::new();
        assert!(feed(&mut d, &evt[..split]).is_empty());
        let got = feed(&mut d, &evt[split..]);
        assert_eq!(got, vec![(Kind::Event, evt[1..].to_vec())]);
    }
    for split in 1..acl.len() {
        let mut d = Deframer::new();
        assert!(feed(&mut d, &acl[..split]).is_empty());
        let got = feed(&mut d, &acl[split..]);
        assert_eq!(got, vec![(Kind::Acl, acl[1..].to_vec())]);
    }
}

#[test]
fn back_to_back_packets_and_an_empty_event() {
    let mut d = Deframer::new();
    let s = [0x04, 0x05, 0x00, 0x04, 0x13, 0x01, 0xAA, 0x02, 0x00, 0x00, 0x00, 0x00];
    let got = feed(&mut d, &s);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0].1, vec![0x05, 0x00]);
    assert_eq!(got[2], (Kind::Acl, vec![0, 0, 0, 0]));
    assert_eq!(d.stats.frames, 3);
}

#[test]
fn garbage_where_an_indicator_is_due_is_dropped_and_counted() {
    let mut d = Deframer::new();
    let got = feed(&mut d, &[0x00, 0x03, 0x05, 0xFF, 0x04, 0x05, 0x00]);
    assert_eq!(got, vec![(Kind::Event, vec![0x05, 0x00])]);
    assert_eq!(d.stats.bad_indicator, 4, "SCO and ISO indicators are garbage to this host too");
}

#[test]
fn an_acl_length_past_the_limit_is_skipped_whole() {
    let mut d = Deframer::new();
    let mut s = vec![0x02, 0x01, 0x00, 0xFF, 0x00]; // 255 > 251
    s.extend(std::iter::repeat(0xEE).take(255));
    s.extend_from_slice(&[0x04, 0x05, 0x00]);
    let got = feed(&mut d, &s);
    assert_eq!(got, vec![(Kind::Event, vec![0x05, 0x00])], "the stream stays in step");
    assert_eq!(d.stats.oversize, 1);
}

#[test]
fn a_half_packet_is_dropped_by_reset_and_the_next_byte_is_an_indicator() {
    let mut d = Deframer::new();
    assert!(feed(&mut d, &[0x04, 0x0E, 0x04, 0x01]).is_empty());
    assert!(d.partial());
    d.reset();
    assert!(!d.partial());
    assert_eq!(d.stats.resets, 1);
    assert_eq!(feed(&mut d, &[0x04, 0x05, 0x00]).len(), 1);
    d.reset();
    assert_eq!(d.stats.resets, 1, "nothing half read: nothing counted");
}

#[test]
fn encoders() {
    let mut out = [0u8; 300];
    let n = command(0x0C03, &[], &mut out).unwrap();
    assert_eq!(&out[..n], &[0x01, 0x03, 0x0C, 0x00]);
    let n = command(0x200A, &[1], &mut out).unwrap();
    assert_eq!(&out[..n], &[0x01, 0x0A, 0x20, 0x01, 0x01]);
    assert!(command(0x0C03, &[0; 3], &mut out[..6]).is_none());
    let n = acl(0x0041, PB_FIRST_FOR_TEST, &[9, 8, 7], &mut out).unwrap();
    assert_eq!(&out[..n], &[0x02, 0x41, 0x00, 0x03, 0x00, 9, 8, 7]);
    let n = acl(0x0041, 1, &[9], &mut out).unwrap();
    assert_eq!(&out[..n], &[0x02, 0x41, 0x10, 0x01, 0x00, 9]);
    assert!(acl(1, 0, &[0; 252], &mut out).is_none());
}

const PB_FIRST_FOR_TEST: u8 = 0;
