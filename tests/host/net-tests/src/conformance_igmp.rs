// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Byte-level wire conformance for IGMP (`crates/net/net/src/igmp.rs`).
//!
//! **What exists is IGMPv2 (RFC 2236)**: Membership Report 0x16 and Leave
//! Group 0x17. There is no IGMPv3 (RFC 3376) encoder in the tree — no 0x22
//! report, no group records — so nothing here tests one. What IS tested from
//! RFC 3376 is the other direction: a v3 querier's 12-octet query arriving at
//! this v2 host.
//!
//! Every expected array below is derived by hand from the RFC packet format,
//! with the derivation beside it. Every checksum is checked with `rfc1071`
//! in this file, never with `ip::checksum`: verifying the kernel's checksum
//! with the kernel's checksum function proves only that it agrees with itself.

use crate::NET_SERIAL as SERIAL;
use crate::{igmp, ip, raw};

const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const OUR_IP: [u8; 4] = [10, 0, 0, 2];
const QUERIER_IP: [u8; 4] = [10, 0, 0, 1];

const GROUP: [u8; 4] = [239, 1, 2, 3];
const OTHER_GROUP: [u8; 4] = [239, 1, 2, 4];

/// V2 Membership Report for 239.1.2.3 (RFC 2236 §2).
///
/// ```text
/// off 0  Type           0x16        V2 Membership Report (§2.1)
/// off 1  Max Resp Time  0x00        zero in every non-query message (§2.2)
/// off 2  Checksum       0xF8 0xFA   see below (§2.3)
/// off 4  Group Address  EF 01 02 03 239.1.2.3, the group reported (§2.4)
///
/// Checksum, RFC 1071 over the whole message with the field zeroed:
///   0x1600 + 0x0000 + 0xEF01 + 0x0203 = 0x1_0704
///   end-around carry: 0x0704 + 0x1 = 0x0705
///   one's complement: 0xF8FA
/// ```
const REPORT_GROUP: [u8; 8] = [0x16, 0x00, 0xF8, 0xFA, 0xEF, 0x01, 0x02, 0x03];

/// V2 Membership Report for 239.1.2.4. Same layout as `REPORT_GROUP`.
///
/// ```text
///   0x1600 + 0xEF01 + 0x0204 = 0x1_0705 -> 0x0706 -> ~ 0xF8F9
/// ```
const REPORT_OTHER: [u8; 8] = [0x16, 0x00, 0xF8, 0xF9, 0xEF, 0x01, 0x02, 0x04];

/// Leave Group for 239.1.2.3 (RFC 2236 §2).
///
/// ```text
/// off 0  Type           0x17        Leave Group (§2.1)
/// off 1  Max Resp Time  0x00        zero in every non-query message (§2.2)
/// off 2  Checksum       0xF7 0xFA
/// off 4  Group Address  EF 01 02 03 the group being left (§2.4)
///
///   0x1700 + 0xEF01 + 0x0203 = 0x1_0804 -> 0x0805 -> ~ 0xF7FA
/// ```
const LEAVE_GROUP: [u8; 8] = [0x17, 0x00, 0xF7, 0xFA, 0xEF, 0x01, 0x02, 0x03];

/// V2 General Query, as a querier sends it (RFC 2236 §2).
///
/// ```text
/// off 0  Type           0x11        Membership Query (§2.1)
/// off 1  Max Resp Time  0x64        100 = 10.0 s, the default (§8.3)
/// off 2  Checksum       0xEE 0x9B
/// off 4  Group Address  00 00 00 00 zero in a General Query (§2.4)
///
///   0x1164 + 0x0000 + 0x0000 = 0x1164 -> ~ 0xEE9B
/// ```
const GENERAL_QUERY: [u8; 8] = [0x11, 0x64, 0xEE, 0x9B, 0x00, 0x00, 0x00, 0x00];

/// V2 Group-Specific Query for 239.1.2.3.
///
/// ```text
/// off 1  Max Resp Time  0x0A        10 = 1.0 s, Last Member Query Interval (§8.8)
/// off 2  Checksum       0xFD 0xF0
/// off 4  Group Address  EF 01 02 03 the group being queried (§2.4)
///
///   0x110A + 0xEF01 = 0x1_000B -> 0x000C
///   0x000C + 0x0203 = 0x020F    -> ~ 0xFDF0
/// ```
const GROUP_QUERY: [u8; 8] = [0x11, 0x0A, 0xFD, 0xF0, 0xEF, 0x01, 0x02, 0x03];

/// IGMPv3 General Query with no sources (RFC 3376 §4.1), 12 octets.
///
/// ```text
/// off 0  Type                 0x11
/// off 1  Max Resp Code        0x64   < 128, so literally 100 = 10.0 s (§4.1.1)
/// off 2  Checksum             0xEC 0x1E
/// off 4  Group Address        00 00 00 00
/// off 8  Resv(4)|S(1)|QRV(3)  0x02   QRV = 2, the default Robustness Variable (§8.1)
/// off 9  QQIC                 0x7D   125 s, the default Query Interval (§8.2)
/// off 10 Number of Sources    00 00
///
/// Checksum over all 12 octets (RFC 2236 §2.3: "the whole IGMP message"):
///   0x1164 + 0x0000 + 0x0000 + 0x0000 + 0x027D + 0x0000 = 0x13E1 -> ~ 0xEC1E
/// ```
///
/// RFC 2236 §2.5 is what makes this reach a v2 host: a recognised Type is
/// processed on its first 8 octets, but "the IGMP checksum is always computed
/// over the whole IP payload, not just over the first 8 octets."
const V3_GENERAL_QUERY: [u8; 12] = [
    0x11, 0x64, 0xEC, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7D, 0x00, 0x00,
];

/// RFC 1071 §4.1, written independently of `ip::checksum`.
///
/// Sums 16-bit big-endian words (an odd trailing octet is padded with zero on
/// the right), folds the carries back in, and complements. A message whose
/// checksum field is correct therefore yields 0.
fn rfc1071(bytes: &[u8]) -> u16 {
    let mut acc: u64 = 0;
    for pair in bytes.chunks(2) {
        let hi = u64::from(pair[0]) << 8;
        let lo = if pair.len() == 2 { u64::from(pair[1]) } else { 0 };
        acc += hi | lo;
    }
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

fn begin() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    igmp::clear();
    crate::inbound::reset();
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(700_000);
    g
}

/// One IGMP datagram as it left on the wire.
struct OnWire {
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype: [u8; 2],
    ip_hdr: Vec<u8>,
    msg: Vec<u8>,
}

/// Every IPv4 frame carrying protocol 2, split at the layer boundaries. The
/// IGMP message is cut at the IP Total Length, not at the frame end, so
/// Ethernet padding cannot pass for message octets.
fn igmp_on_wire() -> Vec<OnWire> {
    raw::all()
        .into_iter()
        .filter_map(|f| {
            if f.len() < 14 + 20 || f[12..14] != [0x08, 0x00] { return None; }
            let ihl = usize::from(f[14] & 0x0F) * 4;
            if ihl < 20 || 14 + ihl > f.len() || f[14 + 9] != 2 { return None; }
            let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
            if total < ihl || 14 + total > f.len() { return None; }
            Some(OnWire {
                dst_mac: f[0..6].try_into().unwrap(),
                src_mac: f[6..12].try_into().unwrap(),
                ethertype: [f[12], f[13]],
                ip_hdr: f[14..14 + ihl].to_vec(),
                msg: f[14 + ihl..14 + total].to_vec(),
            })
        })
        .collect()
}

/// Deliver an IGMP message the way a querier sends it (RFC 2236 §2): TTL 1,
/// Router Alert option present, to 224.0.0.1.
///
/// ```text
/// IPv4 header, 24 octets (RFC 791 §3.1):
/// off 0   Version|IHL   0x46       v4, 6 words: 20 fixed + 4 of options
/// off 1   TOS           0x00
/// off 2   Total Length  24 + message length
/// off 4   Identification, Flags|Fragment Offset: zero
/// off 8   TTL           0x01       RFC 2236 §2
/// off 9   Protocol      0x02       IGMP
/// off 10  Header Checksum          rfc1071 over the 24 octets
/// off 12  Source        10.0.0.1
/// off 16  Destination   224.0.0.1  all-systems
/// off 20  Router Alert  94 04 00 00  RFC 2113 §2.1: type 148, length 4, value 0
/// ```
fn deliver(msg: &[u8]) {
    let mut p = vec![0u8; 24];
    p[0] = 0x46;
    p[2..4].copy_from_slice(&((24 + msg.len()) as u16).to_be_bytes());
    p[8] = 1;
    p[9] = 2;
    p[12..16].copy_from_slice(&QUERIER_IP);
    p[16..20].copy_from_slice(&igmp::ALL_HOSTS);
    p[20..24].copy_from_slice(&[0x94, 0x04, 0x00, 0x00]);
    let ck = rfc1071(&p);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    p.extend_from_slice(msg);
    ip::handle(&p, &OUR_MAC, &OUR_IP);
}

/// The hand-derived arrays above are self-consistent under an independent
/// RFC 1071 computation. If one of the derivations were wrong, every test
/// using it would be testing the kernel against a typo.
#[test]
fn the_hand_derived_checksums_verify_under_rfc_1071() {
    for (name, m) in [
        ("REPORT_GROUP", &REPORT_GROUP[..]),
        ("REPORT_OTHER", &REPORT_OTHER[..]),
        ("LEAVE_GROUP", &LEAVE_GROUP[..]),
        ("GENERAL_QUERY", &GENERAL_QUERY[..]),
        ("GROUP_QUERY", &GROUP_QUERY[..]),
        ("V3_GENERAL_QUERY", &V3_GENERAL_QUERY[..]),
    ] {
        assert_eq!(rfc1071(m), 0, "{name} does not sum to 0xFFFF");
    }
}

/// **Encode: the unsolicited V2 Membership Report on join.**
///
/// The IGMP message is compared byte for byte. Around it: RFC 1112 §6.4 maps
/// 239.1.2.3 to `01:00:5E` plus the low 23 bits, `01:00:5E:01:02:03`; RFC 2236
/// §2 sends it with TTL 1; §9 addresses a report to the group being reported.
#[test]
fn a_join_emits_a_byte_exact_v2_membership_report() {
    let _g = begin();
    assert_eq!(igmp::join(&GROUP), 0);

    let sent = igmp_on_wire();
    assert_eq!(sent.len(), 1, "one unsolicited report per join");
    let w = &sent[0];

    assert_eq!(w.msg, REPORT_GROUP, "IGMP octets 0..8");
    assert_eq!(rfc1071(&w.msg), 0, "the message checksum must verify");

    assert_eq!(w.dst_mac, [0x01, 0x00, 0x5E, 0x01, 0x02, 0x03], "RFC 1112 §6.4 group MAC");
    assert_eq!(w.src_mac, OUR_MAC);
    assert_eq!(w.ethertype, [0x08, 0x00]);

    let h = &w.ip_hdr;
    assert_eq!(h[0] >> 4, 4, "IP version");
    assert_eq!(
        usize::from(u16::from_be_bytes([h[2], h[3]])), h.len() + 8,
        "Total Length is the header plus exactly 8 IGMP octets",
    );
    assert_eq!(&h[6..8], &[0, 0], "not fragmented");
    assert_eq!(h[8], 1, "RFC 2236 §2: TTL 1");
    assert_eq!(h[9], 2, "protocol 2 = IGMP");
    assert_eq!(&h[12..16], &OUR_IP, "source");
    assert_eq!(&h[16..20], &GROUP, "RFC 2236 §9: a report goes to the group reported");
    assert_eq!(rfc1071(h), 0, "the IP header checksum must verify");
}

/// **Encode: Leave Group.** RFC 2236 §9 sends it to all-routers, 224.0.0.2,
/// whose RFC 1112 §6.4 MAC is `01:00:5E:00:00:02`.
#[test]
fn a_leave_emits_a_byte_exact_leave_group_to_all_routers() {
    let _g = begin();
    assert_eq!(igmp::join(&GROUP), 0);
    raw::reset();
    assert_eq!(igmp::leave(&GROUP), 0);

    let sent = igmp_on_wire();
    assert_eq!(sent.len(), 1, "one Leave Group per leave");
    let w = &sent[0];
    assert_eq!(w.msg, LEAVE_GROUP, "IGMP octets 0..8");
    assert_eq!(w.dst_mac, [0x01, 0x00, 0x5E, 0x00, 0x00, 0x02]);
    assert_eq!(w.ip_hdr[8], 1, "RFC 2236 §2: TTL 1");
    assert_eq!(&w.ip_hdr[16..20], &[224, 0, 0, 2], "RFC 2236 §9: ALL-ROUTERS");
    assert_eq!(rfc1071(&w.ip_hdr), 0);
}

/// **RFC 2236 §2: every IGMP message carries the IP Router Alert option.**
///
/// RFC 2113 §2.1 defines it as the four octets `94 04 00 00`, which makes the
/// header 24 octets:
///
/// ```text
/// off 0   Version|IHL   0x46       v4, 6 words = 20 fixed + 4 of options
/// off 2   Total Length  24 + 8 = 32
/// off 8   TTL           0x01       RFC 2236 §2
/// off 9   Protocol      0x02
/// off 10  Header Checksum          RFC 791 §3.1: over the whole header, all 24
/// off 20  Router Alert  94 04 00 00
/// off 24  IGMP message, 8 octets
/// ```
///
/// Checked on both messages this host originates, the report and the leave.
#[test]
fn a_membership_report_carries_the_router_alert_option() {
    let _g = begin();
    assert_eq!(igmp::join(&GROUP), 0);
    let sent = igmp_on_wire();
    assert_eq!(sent.len(), 1);
    raw::reset();
    assert_eq!(igmp::leave(&GROUP), 0);
    let left = igmp_on_wire();
    assert_eq!(left.len(), 1);

    for (name, w) in [("report", &sent[0]), ("leave", &left[0])] {
        let h = &w.ip_hdr;
        assert_eq!(h.len(), 24, "{name}: the header is cut at IHL, and IHL is 6");
        assert_eq!(h[0], 0x46, "{name}: IHL 6, 20 octets plus the 4-octet option");
        assert_eq!(&h[20..24], &[0x94, 0x04, 0x00, 0x00], "{name}: RFC 2113 §2.1 Router Alert");
        assert_eq!(&h[2..4], &[0x00, 32], "{name}: Total Length 24 + 8");
        assert_eq!(h[8], 1, "{name}: RFC 2236 §2 TTL 1");
        assert_eq!(rfc1071(h), 0, "{name}: the checksum covers all 24 header octets");
        assert_eq!(w.msg.len(), 8, "{name}: the option is not counted as IGMP octets");
    }
}

/// **Decode: a General Query.** Group 0.0.0.0 asks for every membership, and
/// each joined group draws exactly its own byte-exact report.
#[test]
fn a_hand_built_general_query_draws_one_exact_report_per_group() {
    let _g = begin();
    igmp::join(&GROUP);
    igmp::join(&OTHER_GROUP);
    raw::reset();

    deliver(&GENERAL_QUERY);

    let mut got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    got.sort();
    let mut want = vec![REPORT_GROUP.to_vec(), REPORT_OTHER.to_vec()];
    want.sort();
    assert_eq!(got, want);
}

/// **Decode: a Group-Specific Query.** The Group Address field at offset 4 is
/// the group asked about; only that group is reported.
#[test]
fn a_hand_built_group_specific_query_draws_a_report_for_that_group_only() {
    let _g = begin();
    igmp::join(&GROUP);
    igmp::join(&OTHER_GROUP);
    raw::reset();

    deliver(&GROUP_QUERY);

    let got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    assert_eq!(got, vec![REPORT_GROUP.to_vec()], "239.1.2.3 was asked about, 239.1.2.4 was not");
}

/// **Malformed: truncated, empty, and a checksum one off.** Each must be
/// refused — no report — and none may read past the datagram.
#[test]
fn a_truncated_or_corrupt_query_draws_nothing() {
    let _g = begin();
    igmp::join(&GROUP);
    raw::reset();

    deliver(&GENERAL_QUERY[..7]);
    assert!(igmp_on_wire().is_empty(), "7 octets is short of the 8-octet message");

    deliver(&[]);
    assert!(igmp_on_wire().is_empty(), "an empty IGMP payload");

    let mut bad = GENERAL_QUERY;
    bad[3] = 0x9A; // 0xEE9A: the sum is now 0xFFFE, not 0xFFFF
    assert_ne!(rfc1071(&bad), 0);
    deliver(&bad);
    assert!(igmp_on_wire().is_empty(), "a checksum that does not verify");
}

/// **Decode: an IGMPv3 General Query reaching this v2 host.**
///
/// RFC 2236 §2.5: the host MUST process a recognised Type on its first 8
/// octets, and the checksum covers the whole IP payload. `igmp::handle`
/// verifies `ip::checksum(&data[..8])` instead, so a correct 12-octet query
/// fails the check and is dropped: a v3 querier never hears this host's
/// memberships and ages them out.
#[test]
fn an_igmpv3_general_query_is_answered() {
    let _g = begin();
    igmp::join(&GROUP);
    raw::reset();

    deliver(&V3_GENERAL_QUERY);

    let got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    assert_eq!(got, vec![REPORT_GROUP.to_vec()]);
}

/// The same defect from the other side: a 12-octet query whose checksum is
/// correct over the first 8 octets only must be REFUSED, because over the
/// whole message it does not verify.
///
/// ```text
/// GENERAL_QUERY (sums to 0xFFFF) followed by 02 7D 00 00:
///   0xFFFF + 0x027D + 0x0000 = 0x1_027C -> 0x027D -> ~ 0xFD82, not 0
/// ```
#[test]
fn a_checksum_covering_only_the_first_eight_octets_is_refused() {
    let _g = begin();
    igmp::join(&GROUP);
    raw::reset();

    let mut m = GENERAL_QUERY.to_vec();
    m.extend_from_slice(&[0x02, 0x7D, 0x00, 0x00]);
    assert_ne!(rfc1071(&m), 0, "the whole-message checksum does not verify");

    deliver(&m);
    assert!(igmp_on_wire().is_empty(), "a message whose checksum fails must be ignored");
}

// ── IGMPv1 querier compatibility (RFC 2236 §4) ─────────────────────────────

/// IGMPv1 General Query (RFC 1112 Appendix I), as a v1 router sends it.
///
/// ```text
/// off 0  Version|Type   0x11        version 1, type 1 = Host Membership Query
/// off 1  Unused         0x00        the octet v2 calls Max Resp Time; 0 marks v1
/// off 2  Checksum       0xEE 0xFF
/// off 4  Group Address  00 00 00 00 zero in a query
///
///   0x1100 + 0x0000 + 0x0000 = 0x1100 -> ~ 0xEEFF
/// ```
///
/// RFC 3376 §7.1: 8 octets with Max Resp Code 0 is a v1 query.
const V1_QUERY: [u8; 8] = [0x11, 0x00, 0xEE, 0xFF, 0x00, 0x00, 0x00, 0x00];

/// Version 1 Membership Report for 239.1.2.3 (RFC 1112 Appendix I).
///
/// ```text
/// off 0  Version|Type   0x12        version 1, type 2 = Host Membership Report
/// off 1  Unused         0x00
/// off 2  Checksum       0xFC 0xFA
/// off 4  Group Address  EF 01 02 03
///
///   0x1200 + 0x0000 + 0xEF01 + 0x0203 = 0x1_0304 -> 0x0305 -> ~ 0xFCFA
/// ```
const V1_REPORT_GROUP: [u8; 8] = [0x12, 0x00, 0xFC, 0xFA, 0xEF, 0x01, 0x02, 0x03];

/// Version 1 Membership Report for 239.1.2.4.
///
/// ```text
///   0x1200 + 0xEF01 + 0x0204 = 0x1_0305 -> 0x0306 -> ~ 0xFCF9
/// ```
const V1_REPORT_OTHER: [u8; 8] = [0x12, 0x00, 0xFC, 0xF9, 0xEF, 0x01, 0x02, 0x04];

/// IGMPv3 General Query with Max Resp Code 0, 12 octets (RFC 3376 §4.1).
///
/// ```text
/// 11 00 | EC 82 | 00 00 00 00 | 02 7D | 00 00
///   0x1100 + 0x027D = 0x137D -> ~ 0xEC82
/// ```
const V3_QUERY_CODE_ZERO: [u8; 12] = [
    0x11, 0x00, 0xEC, 0x82, 0x00, 0x00, 0x00, 0x00, 0x02, 0x7D, 0x00, 0x00,
];

/// RFC 2236 §8.11, Version 1 Router Present Timeout: 400 s, in the ticks of
/// the host clock (`TIMER_FREQ`, 10 MHz in the drivers shim).
const V1_TIMEOUT: u64 = 400 * azos_drv_sys::timebase::TIMER_FREQ;

/// The instant `begin` pins the clock to.
const T0: u64 = 700_000;

#[test]
fn the_v1_arrays_verify_under_rfc_1071() {
    for (name, m) in [
        ("V1_QUERY", &V1_QUERY[..]),
        ("V1_REPORT_GROUP", &V1_REPORT_GROUP[..]),
        ("V1_REPORT_OTHER", &V1_REPORT_OTHER[..]),
        ("V3_QUERY_CODE_ZERO", &V3_QUERY_CODE_ZERO[..]),
    ] {
        assert_eq!(rfc1071(m), 0, "{name} does not sum to 0xFFFF");
    }
}

/// **After a v1 query, reports are Version 1.** Both kinds RFC 2236 §4 names:
/// the answer to the query itself, and a later unsolicited report on join.
#[test]
fn after_an_igmpv1_query_reports_are_version_1() {
    let _g = begin();
    assert_eq!(igmp::join(&GROUP), 0);
    raw::reset();

    deliver(&V1_QUERY);
    let got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    assert_eq!(got, vec![V1_REPORT_GROUP.to_vec()], "the answer to a v1 query is a v1 report");

    raw::reset();
    assert_eq!(igmp::join(&OTHER_GROUP), 0);
    let sent = igmp_on_wire();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].msg, V1_REPORT_OTHER, "an unsolicited report is v1 too");
    assert_eq!(sent[0].ip_hdr[0], 0x46, "and still carries the Router Alert option");
}

/// **v1 mode lasts 400 s after the last v1 query, and then ends.**
///
/// One tick before the timeout a v2 General Query is still answered with a v1
/// report: RFC 2236 §4 bases the state on a v1 query heard within the timeout,
/// and says it "MUST NOT be based upon the type of the last Query heard". At
/// exactly 400 s the timer has run out and the answer is a v2 report again.
#[test]
fn four_hundred_seconds_after_the_last_v1_query_reports_are_version_2_again() {
    let _g = begin();
    assert_eq!(igmp::join(&GROUP), 0);
    deliver(&V1_QUERY);

    azos_drv_irqchip::clint::set_test_time(T0 + V1_TIMEOUT - 1);
    raw::reset();
    deliver(&GENERAL_QUERY);
    let got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    assert_eq!(got, vec![V1_REPORT_GROUP.to_vec()], "399.9999999 s: still v1, whatever queried last");

    azos_drv_irqchip::clint::set_test_time(T0 + V1_TIMEOUT);
    raw::reset();
    deliver(&GENERAL_QUERY);
    let got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    assert_eq!(got, vec![REPORT_GROUP.to_vec()], "400 s: the timeout has run out, v2 again");
}

/// **No Leave Group while a v1 querier is present.** The membership is still
/// dropped; only the message is withheld. Once the timeout has run out the
/// same leave is sent, so the suppression is tied to the v1 state and not
/// permanent.
#[test]
fn no_leave_is_sent_while_a_v1_querier_is_present() {
    let _g = begin();
    assert_eq!(igmp::join(&GROUP), 0);
    deliver(&V1_QUERY);
    raw::reset();

    assert_eq!(igmp::leave(&GROUP), 0);
    assert!(igmp_on_wire().is_empty(), "IGMPv1 has no Leave; nothing may go out");
    assert!(!igmp::is_joined(&GROUP), "the membership is gone all the same");

    azos_drv_irqchip::clint::set_test_time(T0 + V1_TIMEOUT);
    assert_eq!(igmp::join(&GROUP), 0);
    raw::reset();
    assert_eq!(igmp::leave(&GROUP), 0);
    let got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    assert_eq!(got, vec![LEAVE_GROUP.to_vec()], "after the timeout the Leave goes out again");
}

/// **A 12-octet v3 query with Max Resp Code 0 is not a v1 query.** RFC 3376
/// §7.1 tells the versions apart by length as well as by that field. It is
/// answered with a v2 report, and it leaves the host in v2 mode.
#[test]
fn a_v3_query_with_max_resp_code_zero_is_not_taken_for_v1() {
    let _g = begin();
    assert_eq!(igmp::join(&GROUP), 0);
    raw::reset();

    deliver(&V3_QUERY_CODE_ZERO);
    let got: Vec<Vec<u8>> = igmp_on_wire().into_iter().map(|w| w.msg).collect();
    assert_eq!(got, vec![REPORT_GROUP.to_vec()], "a v3 query draws a v2 report");
    assert!(!igmp::v1_querier_present());
}
