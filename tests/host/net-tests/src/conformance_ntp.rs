// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Byte-level wire conformance for NTP (`crates/net/net/src/ntp.rs`).
//!
//! Encode: the client request, compared with the RFC 5905 §7.3 header
//! layout and RFC 4330 §5 ("all the NTP header fields ... are set to 0,
//! except the Mode, VN, and optional Transmit Timestamp fields").
//!
//! The Transmit Timestamp is the one field not derived by hand: it carries a
//! runtime nonce by design (`ntp::new_tx_nonce`). Its position and length are
//! pinned, and so is that each attempt carries a different one.
//!
//! Decode: a full server reply built by hand, and a truncated one. Then the
//! RFC 4330 §3 era rule, on both sides of 2036-02-07T06:28:16Z, and the
//! RFC 4330 §5 refusal of a zero Transmit Timestamp.

use crate::NET_SERIAL as SERIAL;
use crate::{arp, inbound, ntp, raw, wire};
use std::sync::Mutex;

const OUR_IP: [u8; 4] = [10, 0, 0, 2];
const SERVER_IP: [u8; 4] = [10, 0, 0, 124];
const SERVER_MAC: [u8; 6] = [0x02, 0x7C, 0x7C, 0x7C, 0x7C, 0x7C];

/// Octets 0..40 of a v4 client request.
///
/// ```text
/// off 0   LI|VN|Mode           0x23 = 00 100 011: LI 0, VN 4, Mode 3 client
/// off 1   Stratum              00
/// off 2   Poll                 00
/// off 3   Precision            00
/// off 4   Root Delay           00 00 00 00
/// off 8   Root Dispersion      00 00 00 00
/// off 12  Reference ID         00 00 00 00
/// off 16  Reference Timestamp  8 x 00
/// off 24  Origin Timestamp     8 x 00
/// off 32  Receive Timestamp    8 x 00
/// off 40  Transmit Timestamp   8 octets: the nonce (not in this array)
/// length 48: no extension fields, no MAC
/// ```
const REQUEST_HEAD: [u8; 40] = {
    let mut h = [0u8; 40];
    h[0] = 0x23;
    h
};

fn begin() -> std::sync::MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    inbound::reset();
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(1_000_000);
    arp::insert(SERVER_IP, SERVER_MAC);
    ntp::set_ntp_server(SERVER_IP);
    *REPLY_LEN.lock().unwrap() = None;
    *ANSWERED.lock().unwrap() = Vec::new();
    *TRANSMIT.lock().unwrap() = TS_2026_09_13;
    g
}

/// (UDP header, NTP packet) of every datagram sent to port 123.
fn requests_on_wire() -> Vec<(Vec<u8>, Vec<u8>)> {
    wire::sent()
        .into_iter()
        .filter(|s| s.proto == 17 && s.dst_ip == SERVER_IP && s.payload.len() >= 8)
        .filter(|s| s.payload[2..4] == [0x00, 0x7B])
        .map(|s| (s.payload[..8].to_vec(), s.payload[8..].to_vec()))
        .collect()
}

/// **Encode: the client request, on every attempt.**
///
/// Unanswered, `ntp_sync` makes `NTP_MAX_RETRIES` = 3 attempts. Each must be
/// 48 octets in a UDP datagram of length 56 (`00 38`), with octets 0..40 as
/// derived above and a non-zero Transmit Timestamp that differs per attempt.
#[test]
fn every_client_request_is_byte_exact_rfc_5905() {
    let _g = begin();
    assert_eq!(ntp::ntp_sync(), 0, "nobody answers");

    let reqs = requests_on_wire();
    assert_eq!(reqs.len(), 3, "three attempts");
    let mut nonces = Vec::new();
    for (i, (udp, pkt)) in reqs.iter().enumerate() {
        assert_eq!(&udp[4..6], &[0x00, 0x38], "attempt {i}: UDP length 56");
        assert_eq!(pkt.len(), 48, "attempt {i}: 48 octets");
        assert_eq!(&pkt[..40], &REQUEST_HEAD[..], "attempt {i}: octets 0..40");
        assert_ne!(&pkt[40..48], &[0u8; 8], "attempt {i}: a zero Transmit Timestamp cannot be echoed");
        nonces.push(pkt[40..48].to_vec());
    }
    nonces.sort();
    nonces.dedup();
    assert_eq!(nonces.len(), 3, "each attempt carries its own Transmit Timestamp");
}

/// A server reply for 2026-09-13T00:00:00Z, as RFC 5905 §7.3 lays it out.
///
/// ```text
/// Unix 1 789 257 600 = 2026-09-13T00:00:00Z
///   + 2 208 988 800 (1900-01-01 to 1970-01-01) = NTP 3 998 246 400 = 0xEE506600
///
/// off 0   LI|VN|Mode           0x24 = 00 100 100: LI 0, VN 4, Mode 4 server
/// off 1   Stratum              02    secondary server
/// off 2   Poll                 06    2^6 s
/// off 3   Precision            EC    -20: about 1 us
/// off 4   Root Delay           00 00 00 10   16.16 fixed point
/// off 8   Root Dispersion      00 00 00 20
/// off 12  Reference ID         C0 A8 01 01   stratum >= 2: the upstream's IPv4 address
/// off 16  Reference Timestamp  EE 50 65 00 00 00 00 00   256 s before transmit
/// off 24  Origin Timestamp     the request's Transmit Timestamp, echoed
/// off 32  Receive Timestamp    EE 50 65 FF 80 00 00 00   half a second before transmit
/// off 40  Transmit Timestamp   EE 50 66 00 00 00 00 00   2026-09-13T00:00:00.0Z
/// ```
///
/// The Receive Timestamp's seconds differ from the Transmit Timestamp's, so
/// a client reading the wrong one of the two cannot return the right time.
fn server_reply(origin: &[u8]) -> Vec<u8> {
    let mut p = vec![
        0x24, 0x02, 0x06, 0xEC,
        0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x20,
        0xC0, 0xA8, 0x01, 0x01,
        0xEE, 0x50, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    p.extend_from_slice(origin);
    p.extend_from_slice(&[0xEE, 0x50, 0x65, 0xFF, 0x80, 0x00, 0x00, 0x00]);
    p.extend_from_slice(&TS_2026_09_13);
    assert_eq!(p.len(), 48, "derivation: a reply is 48 octets");
    p
}

const UNIX_2026_09_13: u32 = 1_789_257_600;

/// Octets 40..48 of the reply above: `EE 50 66 00`, fraction 0.
const TS_2026_09_13: [u8; 8] = [0xEE, 0x50, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00];

/// How many octets of the reply the far end sends; `None` answers nothing.
static REPLY_LEN: Mutex<Option<usize>> = Mutex::new(None);
/// The Transmit Timestamp the far end puts at offset 40. The other fields
/// stay as derived for 2026; the client reads none of them for the time.
static TRANSMIT: Mutex<[u8; 8]> = Mutex::new([0; 8]);
/// Transmit Timestamps already answered, so each request draws one reply.
static ANSWERED: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// The far end: answer the newest request, once, from port 123 to whatever
/// source port the request came from.
fn answer_newest_request() {
    let len = match *REPLY_LEN.lock().unwrap() {
        Some(n) => n,
        None => return,
    };
    let (udp, pkt) = match requests_on_wire().pop() {
        Some(r) => r,
        None => return,
    };
    if pkt.len() < 48 { return; }
    let nonce = pkt[40..48].to_vec();
    {
        let mut done = ANSWERED.lock().unwrap();
        if done.contains(&nonce) { return; }
        done.push(nonce.clone());
    }

    let mut reply = server_reply(&nonce);
    reply[40..48].copy_from_slice(&*TRANSMIT.lock().unwrap());
    let body = &reply[..len];

    // UDP (RFC 768): source 123, destination the request's source port,
    // length 8 + body, checksum 0 (none, permitted on IPv4).
    let mut u = vec![0x00, 0x7B, udp[0], udp[1]];
    u.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0x00, 0x00]);
    u.extend_from_slice(body);

    // IPv4 (RFC 791), 20 octets; checksum by RFC 1071 below.
    let mut p = vec![0x45, 0x00];
    p.extend_from_slice(&((20 + u.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 64, 17, 0x00, 0x00]);
    p.extend_from_slice(&SERVER_IP);
    p.extend_from_slice(&OUR_IP);
    let mut acc: u32 = 0;
    for w in p.chunks(2) {
        acc += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    p[10..12].copy_from_slice(&(!(acc as u16)).to_be_bytes());
    p.extend_from_slice(&u);
    inbound::push_ipv4(&p);
}

/// **Decode: a full server reply.** The time adopted is the Transmit
/// Timestamp's seconds at offset 40, less the 1900-to-1970 offset.
#[test]
fn a_hand_built_server_reply_sets_the_time_from_the_transmit_timestamp() {
    let _g = begin();
    *REPLY_LEN.lock().unwrap() = Some(48);
    inbound::on_poll(answer_newest_request);

    assert_eq!(ntp::ntp_sync(), UNIX_2026_09_13);
    assert_eq!(requests_on_wire().len(), 1, "answered on the first attempt");
}

/// **Malformed: a reply one octet short.** 47 octets is not an NTP packet;
/// it must be refused on every attempt, without reading an octet past it.
#[test]
fn a_truncated_server_reply_is_refused() {
    let _g = begin();
    *REPLY_LEN.lock().unwrap() = Some(47);
    inbound::on_poll(answer_newest_request);

    assert_eq!(ntp::ntp_sync(), 0);
    assert_eq!(requests_on_wire().len(), 3, "every attempt was answered short and refused");
}

/// Answer every request with a full reply whose Transmit Timestamp is `ts`.
fn reply_with(ts: [u8; 8]) {
    *REPLY_LEN.lock().unwrap() = Some(48);
    *TRANSMIT.lock().unwrap() = ts;
    inbound::on_poll(answer_newest_request);
}

/// **Decode: era 1** (RFC 4330 §3: bit 0 clear, "the time is in the range
/// 2036-2104 and UTC time is reckoned from 6h 28m 16s UTC on 7 February 2036").
///
/// ```text
/// 2040-01-01T00:00:00Z = Unix 25 567 d x 86 400 = 2 208 988 800
///   (70 years, 17 of them leap: 1972 .. 2036)
/// 2040-03-01T00:00:00Z = + (31 d Jan + 29 d Feb, 2040 is leap) x 86 400
///                      = Unix 2 214 172 800
/// + 2 208 988 800 (1900-01-01 to 1970-01-01) = 4 423 161 600 s since 1900
/// - 4 294 967 296 (2^32: all of era 0)       =   128 194 304 = 0x07A41700
///
/// off 40  07 A4 17 00 00 00 00 00   octet 40 = 0x07: bit 0 clear, era 1
/// ```
///
/// Read as era 0 this is 1904, below the plausibility floor, so a client
/// without the era rule refuses it.
#[test]
fn an_era_1_reply_sets_the_time_after_2036() {
    let _g = begin();
    reply_with([0x07, 0xA4, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(ntp::ntp_sync(), 2_214_172_800, "2040-03-01T00:00:00Z");
    assert_eq!(requests_on_wire().len(), 1, "answered on the first attempt");
}

/// **Decode: the first second of era 1 is a time, not a zero timestamp.**
///
/// ```text
/// off 40  00 00 00 00 80 00 00 00   seconds 0 of era 1, fraction 0.5
///         = 2036-02-07T06:28:16.5Z
///         = Unix 4 294 967 296 - 2 208 988 800 = 2 085 978 496 (fraction dropped)
/// ```
///
/// RFC 4330 §5 refuses a Transmit Timestamp that is zero, and that is all
/// eight octets: this one's fraction is not.
#[test]
fn the_first_second_of_era_1_is_not_a_zero_timestamp() {
    let _g = begin();
    reply_with([0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]);
    assert_eq!(ntp::ntp_sync(), 2_085_978_496, "2036-02-07T06:28:16Z");
}

/// **Decode: era 0 keeps working, up to its last second.**
///
/// ```text
/// off 40  FF FF FF FF 00 00 00 00   bit 0 set, era 0
///         = 4 294 967 295 s since 1900 = 2036-02-07T06:28:15Z
///         = Unix 4 294 967 295 - 2 208 988 800 = 2 085 978 495
/// ```
///
/// One second before the previous test's time: the two eras meet with no gap
/// and no overlap. The 2026 reply above is the everyday era-0 case.
#[test]
fn the_last_second_of_era_0_still_sets_the_time() {
    let _g = begin();
    reply_with([0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(ntp::ntp_sync(), 2_085_978_495, "2036-02-07T06:28:15Z");
}

/// **Refused: an all-zero Transmit Timestamp** (RFC 4330 §5), on every
/// attempt. Under the era rule its seconds alone would read as
/// 2036-02-07T06:28:16Z, so only the zero check stands between it and the
/// clock.
#[test]
fn an_all_zero_transmit_timestamp_is_refused() {
    let _g = begin();
    reply_with([0; 8]);
    assert_eq!(ntp::ntp_sync(), 0);
    assert_eq!(requests_on_wire().len(), 3, "every attempt was answered with zero and refused");
}
