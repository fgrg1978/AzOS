// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Byte-level wire conformance for DHCP (`crates/net/net/src/dhcp.rs`).
//!
//! Encode: the DISCOVER and the SELECTING-state REQUEST, compared octet for
//! octet — Ethernet, IPv4, UDP and all 300 BOOTP octets — with layouts
//! derived by hand from RFC 2131 §2 (Figure 1) and Table 5, RFC 2132 for the
//! options, and RFC 1542 §2.1 for the 300-octet minimum.
//!
//! The transaction id is the one field not derived by hand: it is runtime
//! entropy by design (`dhcp::new_xid`). Its POSITION is pinned, and so is the
//! rule that the REQUEST carries the same value as the DISCOVER (Table 5).
//!
//! Decode: an OFFER and an ACK built by hand from RFC 2131 Table 3, and
//! every truncation of an OFFER.
//!
//! **Option 55 (Parameter Request List) is not sent.** Table 5 marks it MAY
//! in both messages, so its absence is not a violation; the expected option
//! bytes below simply do not contain it.

use crate::NET_SERIAL as SERIAL;
use crate::{dhcp, dns, netcfg, raw, tcp};

const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const SERVER_ID: [u8; 4] = [10, 0, 0, 1];
const OFFERED: [u8; 4] = [10, 0, 0, 42];

/// Ethernet (14) + IPv4 without options (20) + UDP (8).
const BOOTP_AT: usize = 42;
/// RFC 1542 §2.1: "the minimal BOOTP header of 300 octets".
const BOOTP_LEN: usize = 300;

/// RFC 1071 §4.1, written independently of `ip::checksum`.
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
    raw::reset();
    netcfg::reset();
    // `DNS_SERVER` is process-wide and other modules set it; state the
    // precondition so option 6 has to be what moves it.
    dns::set_dns_server([0, 0, 0, 0]);
    azos_drv_irqchip::clint::set_test_time(800_000);
    tcp::init(OUR_MAC, [0, 0, 0, 0]);
    g
}

fn last_frame() -> Vec<u8> {
    raw::all().last().cloned().expect("a DHCP frame must have been transmitted")
}

/// A client BOOTREQUEST as this client must send it (RFC 2131 §2 Figure 1,
/// Table 5), with `options` placed after the cookie and zero padding to 300.
///
/// ```text
/// off 0    op      01          BOOTREQUEST
/// off 1    htype   01          Ethernet, "Assigned Numbers"
/// off 2    hlen    06          octets in an Ethernet address
/// off 3    hops    00          Table 5: 0
/// off 4    xid     (4)         runtime; supplied by the caller
/// off 8    secs    00 00       Table 5: "0 or seconds since DHCP process started"
/// off 10   flags   80 00       BROADCAST, the leftmost bit (Figure 2): no address yet
/// off 12   ciaddr  00 00 00 00 Table 5: 0 in DISCOVER and in a SELECTING REQUEST
/// off 16   yiaddr  00 00 00 00 Table 5: 0
/// off 20   siaddr  00 00 00 00 Table 5: 0
/// off 24   giaddr  00 00 00 00 Table 5: 0
/// off 28   chaddr  02 00 00 00 00 02, then 10 x 00 (16 octets)
/// off 44   sname   64 x 00     unused
/// off 108  file    128 x 00    unused
/// off 236  cookie  63 82 53 63 99.130.83.99 (§3)
/// off 240  options
/// ```
fn expected_request(xid: [u8; 4], options: &[u8]) -> Vec<u8> {
    let mut e = Vec::with_capacity(BOOTP_LEN);
    e.extend_from_slice(&[0x01, 0x01, 0x06, 0x00]);
    e.extend_from_slice(&xid);
    e.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]);
    e.extend_from_slice(&[0x00; 16]);
    assert_eq!(e.len(), 28, "derivation: chaddr starts at 28");
    e.extend_from_slice(&OUR_MAC);
    e.extend_from_slice(&[0x00; 10]);
    e.extend_from_slice(&[0x00; 64]);
    e.extend_from_slice(&[0x00; 128]);
    assert_eq!(e.len(), 236, "derivation: the cookie starts at 236");
    e.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    e.extend_from_slice(options);
    assert!(e.len() <= BOOTP_LEN, "derivation: options fit in 300 octets");
    e.resize(BOOTP_LEN, 0x00);
    e
}

/// The Ethernet, IPv4 and UDP headers around a client broadcast.
///
/// ```text
/// Ethernet: dst FF FF FF FF FF FF, src our MAC, type 08 00
/// IPv4 (RFC 791): off 0 0x45, off 2 Total Length 00 01 48 = 20+8+300 = 328,
///   off 6 flags/offset 00 00, off 9 protocol 0x11 UDP,
///   off 12 source 0.0.0.0 (RFC 2131 §4.1: no address yet),
///   off 16 destination 255.255.255.255
/// UDP (RFC 768): src port 00 44 = 68, dst port 00 43 = 67,
///   length 01 34 = 8+300 = 308, checksum 00 00 ("no checksum", permitted on IPv4)
/// ```
fn assert_broadcast_envelope(f: &[u8]) {
    assert_eq!(f.len(), BOOTP_AT + BOOTP_LEN, "342 octets: no more, no less");
    assert_eq!(&f[0..6], &[0xFF; 6], "Ethernet broadcast");
    assert_eq!(&f[6..12], &OUR_MAC);
    assert_eq!(&f[12..14], &[0x08, 0x00]);

    let ip = &f[14..34];
    assert_eq!(ip[0], 0x45);
    assert_eq!(&ip[2..4], &[0x01, 0x48], "IPv4 Total Length 328");
    assert_eq!(&ip[6..8], &[0x00, 0x00]);
    assert_eq!(ip[9], 0x11, "UDP");
    assert_eq!(&ip[12..16], &[0, 0, 0, 0], "RFC 2131 §4.1: source 0.0.0.0");
    assert_eq!(&ip[16..20], &[255, 255, 255, 255]);
    assert_eq!(rfc1071(ip), 0, "the IPv4 header checksum must verify");

    let udp = &f[34..42];
    assert_eq!(udp, &[0x00, 0x44, 0x00, 0x43, 0x01, 0x34, 0x00, 0x00]);
}

/// **Encode: DHCPDISCOVER.**
///
/// ```text
/// off 240  35 01 01   option 53, length 1, DHCPDISCOVER (RFC 2132 §9.6)
/// off 243  FF         End (RFC 2132 §3.2)
/// off 244  56 x 00    padding to 300
/// ```
#[test]
fn a_discover_is_byte_exact() {
    let _g = begin();
    dhcp::dhcp_discover();
    let f = last_frame();
    assert_broadcast_envelope(&f);

    let body = &f[BOOTP_AT..];
    let xid: [u8; 4] = body[4..8].try_into().unwrap();
    let expected = expected_request(xid, &[0x35, 0x01, 0x01, 0xFF]);
    assert_eq!(body, &expected[..]);
}

/// **Encode: DHCPREQUEST in SELECTING.**
///
/// ```text
/// off 240  35 01 03             option 53, DHCPREQUEST
/// off 243  32 04 0A 00 00 2A    option 50, requested address 10.0.0.42
///                               (Table 5: MUST in SELECTING)
/// off 249  36 04 0A 00 00 01    option 54, server identifier 10.0.0.1
///                               (Table 5: MUST after SELECTING)
/// off 255  FF                   End
/// off 256  44 x 00              padding to 300
/// ```
///
/// Table 5 also says the REQUEST's xid is the one from the OFFER — which,
/// for an OFFER answering our DISCOVER, is the DISCOVER's.
#[test]
fn a_selecting_request_is_byte_exact_and_reuses_the_discover_xid() {
    let _g = begin();
    dhcp::dhcp_discover();
    let discover_xid: [u8; 4] = last_frame()[BOOTP_AT + 4..BOOTP_AT + 8].try_into().unwrap();

    assert!(dhcp::dhcp_handle_offer(&offer(discover_xid)).is_some());
    raw::reset();
    dhcp::dhcp_request(OFFERED, SERVER_ID);

    let f = last_frame();
    assert_broadcast_envelope(&f);
    let expected = expected_request(
        discover_xid,
        &[
            0x35, 0x01, 0x03,
            0x32, 0x04, 0x0A, 0x00, 0x00, 0x2A,
            0x36, 0x04, 0x0A, 0x00, 0x00, 0x01,
            0xFF,
        ],
    );
    assert_eq!(&f[BOOTP_AT..], &expected[..]);
}

/// A server BOOTREPLY (RFC 2131 Table 3), built by hand.
///
/// ```text
/// off 0    op      02          BOOTREPLY
/// off 1    htype   01, hlen 06, hops 00
/// off 4    xid     from the client's message
/// off 8    secs    00 00       Table 3: 0
/// off 10   flags   80 00       Table 3: 'flags' from the client
/// off 12   ciaddr  00 00 00 00
/// off 16   yiaddr  0A 00 00 2A 10.0.0.42, the address offered
/// off 20   siaddr  00 00 00 00 no next server
/// off 24   giaddr  00 00 00 00 no relay
/// off 28   chaddr  the client's MAC, then 10 x 00
/// off 44   sname   64 x 00, off 108 file 128 x 00
/// off 236  cookie  63 82 53 63
/// off 240  options, then 00 padding to 300 if shorter
/// ```
fn server_reply(xid: [u8; 4], options: &[u8]) -> Vec<u8> {
    let mut d = Vec::with_capacity(BOOTP_LEN);
    d.extend_from_slice(&[0x02, 0x01, 0x06, 0x00]);
    d.extend_from_slice(&xid);
    d.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]);
    d.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    d.extend_from_slice(&[0x0A, 0x00, 0x00, 0x2A]);
    d.extend_from_slice(&[0x00; 8]);
    d.extend_from_slice(&OUR_MAC);
    d.extend_from_slice(&[0x00; 10]);
    d.extend_from_slice(&[0x00; 64]);
    d.extend_from_slice(&[0x00; 128]);
    assert_eq!(d.len(), 236, "derivation: the cookie starts at 236");
    d.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    d.extend_from_slice(options);
    if d.len() < BOOTP_LEN {
        d.resize(BOOTP_LEN, 0x00);
    }
    d
}

/// OFFER options (RFC 2131 Table 3: 51 and 54 are MUST in an OFFER).
///
/// ```text
/// off 240  35 01 02                        53 message type: DHCPOFFER
/// off 243  36 04 0A 00 00 01               54 server identifier 10.0.0.1
/// off 249  33 04 00 00 0E 10               51 lease time 3600 s (RFC 2132 §9.2)
/// off 255  01 04 FF FF FF 00               1  subnet mask (§3.3)
/// off 261  03 04 0A 00 00 01               3  router (§3.5)
/// off 267  06 08 0A 00 00 35 0A 00 00 36   6  two DNS servers (§3.8)
/// off 277  FF                              End
/// ```
const OFFER_OPTIONS: [u8; 38] = [
    0x35, 0x01, 0x02,
    0x36, 0x04, 0x0A, 0x00, 0x00, 0x01,
    0x33, 0x04, 0x00, 0x00, 0x0E, 0x10,
    0x01, 0x04, 0xFF, 0xFF, 0xFF, 0x00,
    0x03, 0x04, 0x0A, 0x00, 0x00, 0x01,
    0x06, 0x08, 0x0A, 0x00, 0x00, 0x35, 0x0A, 0x00, 0x00, 0x36,
    0xFF,
];

/// Offset one past option 54 in `OFFER_OPTIONS`: 240 + 3 + 6.
const OFFER_SERVER_ID_END: usize = 249;

fn offer(xid: [u8; 4]) -> Vec<u8> {
    server_reply(xid, &OFFER_OPTIONS)
}

/// **Decode: DHCPOFFER.** `yiaddr` at offset 16 is the address, option 54 the
/// server the exchange binds to.
#[test]
fn a_hand_built_offer_yields_yiaddr_and_the_server_identifier() {
    let _g = begin();
    dhcp::dhcp_discover();
    let xid: [u8; 4] = last_frame()[BOOTP_AT + 4..BOOTP_AT + 8].try_into().unwrap();

    assert_eq!(dhcp::dhcp_handle_offer(&offer(xid)), Some((OFFERED, SERVER_ID)));
}

/// **Decode: DHCPACK.** Every value the lease applies is chosen to differ
/// from the parser's defaults — a /23 mask, not the /24 `DhcpInfo::new`
/// starts from — so a field the parser failed to read cannot pass by luck.
///
/// ```text
/// off 240  35 01 05                        53 message type: DHCPACK
/// off 243  00                              Pad (RFC 2132 §3.1): one octet, no length field
/// off 244  36 04 0A 00 00 01               54 server identifier
/// off 250  33 04 00 00 0E 10               51 lease time 3600 s
/// off 256  01 04 FF FF FE 00               1  subnet mask 255.255.254.0
/// off 262  03 04 0A 00 00 FE               3  router 10.0.0.254
/// off 268  06 08 0A 00 00 4D 0A 00 00 4E   6  DNS 10.0.0.77, 10.0.0.78
/// off 278  FF                              End
/// ```
///
/// ONE Pad octet, not two: a parser that stepped over Pad as if it had a
/// length octet would land back in step after an even run of them.
#[test]
fn a_hand_built_ack_configures_address_mask_router_and_resolver() {
    let _g = begin();
    dhcp::dhcp_discover();
    let xid: [u8; 4] = last_frame()[BOOTP_AT + 4..BOOTP_AT + 8].try_into().unwrap();
    assert!(dhcp::dhcp_handle_offer(&offer(xid)).is_some());
    dhcp::dhcp_request(OFFERED, SERVER_ID);
    netcfg::reset();

    let ack = server_reply(
        xid,
        &[
            0x35, 0x01, 0x05,
            0x00,
            0x36, 0x04, 0x0A, 0x00, 0x00, 0x01,
            0x33, 0x04, 0x00, 0x00, 0x0E, 0x10,
            0x01, 0x04, 0xFF, 0xFF, 0xFE, 0x00,
            0x03, 0x04, 0x0A, 0x00, 0x00, 0xFE,
            0x06, 0x08, 0x0A, 0x00, 0x00, 0x4D, 0x0A, 0x00, 0x00, 0x4E,
            0xFF,
        ],
    );
    assert_eq!(dns::get_dns_server(), [0, 0, 0, 0], "precondition");
    assert!(dhcp::dhcp_handle_ack(&ack), "a well-formed ACK from the bound server");
    assert_eq!(
        netcfg::last(),
        Some((OFFERED, [255, 255, 254, 0], [10, 0, 0, 254])),
        "yiaddr, option 1 and option 3",
    );
    assert_eq!(dns::get_dns_server(), [10, 0, 0, 77], "the first address of option 6");
}

/// **Malformed: every truncation of the OFFER.**
///
/// The OFFER is acceptable exactly when its datagram still holds option 54
/// whole, i.e. at least `OFFER_SERVER_ID_END` octets. Shorter than that the
/// option is cut — its length octet or its value runs past the datagram — and
/// the OFFER must be refused without reading past the end. The End option
/// and the padding are not required for acceptance: RFC 1542 §2.1 has the
/// receiver trust the UDP length, and a datagram ending right after a whole
/// option is still whole.
#[test]
fn every_truncation_of_an_offer_short_of_option_54_is_refused() {
    let _g = begin();
    dhcp::dhcp_discover();
    let xid: [u8; 4] = last_frame()[BOOTP_AT + 4..BOOTP_AT + 8].try_into().unwrap();
    let full = offer(xid);

    for n in 0..=full.len() {
        let got = dhcp::dhcp_handle_offer(&full[..n]);
        if n < OFFER_SERVER_ID_END {
            assert_eq!(got, None, "{n} octets: option 54 is not whole");
        } else {
            assert_eq!(got, Some((OFFERED, SERVER_ID)), "{n} octets: option 54 is whole");
        }
    }
}
