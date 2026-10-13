// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Byte-level wire conformance for DNS (`crates/net/net/src/dns.rs`).
//!
//! Encode: the query `resolve` puts on the wire, compared octet for octet
//! with RFC 1035 §4.1.1 (header) and §4.1.2 (question), names encoded per
//! §3.1. `build_query` is private, so the query is read back off the wire.
//! The ID is runtime entropy (`dns::new_tx_id`) and is the one field not
//! derived by hand; everything from offset 2 on is.
//!
//! Decode: `parse_response` fed responses built by hand from §4.1.1–§4.1.4,
//! including a CNAME in front of the A record and compression pointers, and
//! truncated and looping ones.

use crate::NET_SERIAL as SERIAL;
use crate::{arp, dns, inbound, raw, wire};

const SERVER_IP: [u8; 4] = [10, 0, 0, 53];
const SERVER_MAC: [u8; 6] = [0x02, 0x35, 0x35, 0x35, 0x35, 0x35];

fn begin() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    inbound::reset();
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(900_000);
    arp::insert(SERVER_IP, SERVER_MAC);
    dns::set_dns_server(SERVER_IP);
    g
}

/// (UDP header, DNS message) of every datagram sent to port 53.
fn queries_on_wire() -> Vec<(Vec<u8>, Vec<u8>)> {
    wire::sent()
        .into_iter()
        .filter(|s| s.proto == 17 && s.dst_ip == SERVER_IP && s.payload.len() >= 8)
        .filter(|s| s.payload[2..4] == [0x00, 0x35])
        .map(|s| (s.payload[..8].to_vec(), s.payload[8..].to_vec()))
        .collect()
}

/// Query for `www.example.com` A IN, from offset 2 (the ID precedes it).
///
/// ```text
/// off 2   flags    01 00   QR=0 Opcode=0 AA=0 TC=0 RD=1 | RA=0 Z=0 RCODE=0 (§4.1.1)
/// off 4   QDCOUNT  00 01
/// off 6   ANCOUNT  00 00
/// off 8   NSCOUNT  00 00
/// off 10  ARCOUNT  00 00
/// off 12  QNAME    03 77 77 77                     3 "www"
///                  07 65 78 61 6D 70 6C 65         7 "example"
///                  03 63 6F 6D                     3 "com"
///                  00                              the root label (§3.1)
/// off 29  QTYPE    00 01   A (§3.2.2)
/// off 31  QCLASS   00 01   IN (§3.2.4)
/// length 33
/// ```
const QUERY_WWW_EXAMPLE_COM_FROM_2: [u8; 31] = [
    0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x77, 0x77, 0x77,
    0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
    0x03, 0x63, 0x6F, 0x6D,
    0x00,
    0x00, 0x01,
    0x00, 0x01,
];

/// **Encode: a recursive A query.** Header flags, counts, QNAME labels,
/// QTYPE and QCLASS octet for octet; UDP length 8 + 33 = 41 = `00 29`.
#[test]
fn a_query_is_byte_exact_rfc_1035() {
    let _g = begin();
    assert_eq!(dns::resolve("www.example.com"), None, "nobody answers");

    let q = queries_on_wire();
    assert_eq!(q.len(), 1, "one query per resolve");
    let (udp, msg) = &q[0];
    assert_eq!(&udp[4..6], &[0x00, 0x29], "UDP length 41");
    assert_eq!(msg.len(), 33);
    assert_eq!(&msg[2..], &QUERY_WWW_EXAMPLE_COM_FROM_2[..]);
}

/// **Encode: a single label, and a refused name.**
///
/// ```text
/// "robot": 05 72 6F 62 6F 74 00 | 00 01 | 00 01    at off 12, length 23
/// ```
///
/// `a..b` has an empty label in the middle. §3.1 allows only one null label,
/// the root, and it ends the name, so this name has no encoding: nothing may
/// be sent.
#[test]
fn a_single_label_encodes_exactly_and_an_empty_label_sends_nothing() {
    let _g = begin();
    assert_eq!(dns::resolve("robot"), None);
    let q = queries_on_wire();
    assert_eq!(q.len(), 1);
    assert_eq!(
        &q[0].1[12..],
        &[0x05, 0x72, 0x6F, 0x62, 0x6F, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01],
    );

    raw::reset();
    assert_eq!(dns::resolve("a..b"), None);
    assert!(queries_on_wire().is_empty(), "an empty label has no wire form");
}

/// Response to ID 0xBEEF for `www.example.com`, one A record.
///
/// ```text
/// off 0   ID       BE EF
/// off 2   flags    81 80   QR=1 Opcode=0 AA=0 TC=0 RD=1 | RA=1 Z=0 RCODE=0
/// off 4   QDCOUNT  00 01, ANCOUNT 00 01, NSCOUNT 00 00, ARCOUNT 00 00
/// off 12  question, as sent: 03 www 07 example 03 com 00 | 00 01 | 00 01
/// off 33  NAME     C0 0C         pointer (§4.1.4) to offset 12
/// off 35  TYPE     00 01         A
/// off 37  CLASS    00 01         IN
/// off 39  TTL      00 00 0E 10   3600 s
/// off 43  RDLENGTH 00 04
/// off 45  RDATA    5D B8 D8 22   93.184.216.34
/// length 49
/// ```
const RESPONSE_A: [u8; 49] = [
    0xBE, 0xEF, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
    0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04,
    0x5D, 0xB8, 0xD8, 0x22,
];

/// **Decode: the canonical A response.**
#[test]
fn a_hand_built_a_response_yields_the_address() {
    assert_eq!(dns::parse_response(&RESPONSE_A, 0xBEEF), Some([93, 184, 216, 34]));
    assert_eq!(dns::parse_response(&RESPONSE_A, 0xBEEE), None, "a different ID is not ours");
}

/// **Decode: a CNAME in front of the A record.** The parser must step over a
/// record that is not an A by its RDLENGTH, not by any assumed size.
///
/// ```text
/// header: BE EF 81 80 | QDCOUNT 00 01 | ANCOUNT 00 02 | 00 00 | 00 00
/// off 12  question as in RESPONSE_A (21 octets, to offset 33)
/// off 33  C0 0C | 00 05 CNAME | 00 01 | 00 00 0E 10 | RDLENGTH 00 02 | C0 10
///         www.example.com is an alias for the name at offset 16: example.com
/// off 47  C0 10 | 00 01 A | 00 01 | 00 00 0E 10 | RDLENGTH 00 04 | 5D B8 D8 22
///         example.com has address 93.184.216.34
/// length 63
/// ```
#[test]
fn a_cname_before_the_a_record_is_stepped_over_by_its_rdlength() {
    let resp: [u8; 63] = [
        0xBE, 0xEF, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
        0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x02,
        0xC0, 0x10,
        0xC0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x04,
        0x5D, 0xB8, 0xD8, 0x22,
    ];
    assert_eq!(dns::parse_response(&resp, 0xBEEF), Some([93, 184, 216, 34]));
}

/// **Malformed and refused responses.**
///
/// * RCODE 2 (Server failure, §4.1.1) with an A record still attached:
///   flags `81 82`. The RCODE decides, not the presence of an answer.
/// * Every truncation of `RESPONSE_A`: only the full 49 octets hold the
///   whole RDATA.
/// * A NAME that is a pointer to itself (`C0 21` at offset 33), and one that
///   points past the end of the message (`C0 FF`). Both must end in a
///   refusal, not a loop or a read out of bounds.
#[test]
fn error_truncated_and_looping_responses_are_refused() {
    let mut servfail = RESPONSE_A;
    servfail[3] = 0x82;
    assert_eq!(dns::parse_response(&servfail, 0xBEEF), None, "RCODE 2");

    for n in 0..RESPONSE_A.len() {
        assert_eq!(
            dns::parse_response(&RESPONSE_A[..n], 0xBEEF), None,
            "{n} octets is a truncated response",
        );
    }

    let mut self_loop = RESPONSE_A;
    self_loop[33..35].copy_from_slice(&[0xC0, 0x21]);
    assert_eq!(dns::parse_response(&self_loop, 0xBEEF), None, "a pointer to itself");

    let mut past_end = RESPONSE_A;
    past_end[33..35].copy_from_slice(&[0xC0, 0xFF]);
    assert_eq!(dns::parse_response(&past_end, 0xBEEF), None, "a pointer past the message");
}
