// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Keeping a DHCP lease (RFC 2131 §4.4.5): T1 and T2 from options 58 and 59
//! or the RFC's defaults, a RENEWING REQUEST unicast to the lease's server at
//! T1, its retransmission after half the time left, a REBINDING broadcast at
//! T2 that any server may answer, and the address given up on a NAK or at the
//! lease's end. The server is played by the poll hook, as for `dhcp_start`.
//!
//! **Canary**: `dhcp_maintain` returning at once (the client before this
//! change, which never renewed) fails every test here but the first.

use super::conformance_dhcp::{begin, last_frame, offer, server_reply, BOOTP_AT, OFFERED, SERVER_ID};
use super::{arp, dhcp, inbound, netcfg, raw};
use std::sync::Mutex;

const TICKS_PER_S: u64 = 10_000_000;
const SERVER_MAC: [u8; 6] = [0x02, 0x5E, 0x00, 0x00, 0x00, 0x01];
const OTHER_SERVER: [u8; 4] = [10, 0, 0, 9];

fn nop() {}

/// What the poll hook answers a REQUEST with.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    Nothing,
    /// An ACK from `server` for a lease of `secs`.
    Ack { server: [u8; 4], secs: u32 },
    /// A NAK from `server`.
    Nak { server: [u8; 4] },
}

static ANSWER: Mutex<Answer> = Mutex::new(Answer::Nothing);
/// The xid already answered, so one REQUEST draws one reply.
static ANSWERED: Mutex<Option<[u8; 4]>> = Mutex::new(None);

/// The BOOTP octets of a client frame: after Ethernet, IPv4 and UDP.
fn bootp(f: &[u8]) -> Option<&[u8]> {
    let dhcp_client = f.len() > BOOTP_AT + 240 && f[12..14] == [0x08, 0x00] && f[23] == 17
        && f[34..36] == 68u16.to_be_bytes() && f[36..38] == 67u16.to_be_bytes();
    dhcp_client.then(|| &f[BOOTP_AT..])
}

/// The value of DHCP option `code` in a BOOTP message, if present.
fn option(b: &[u8], code: u8) -> Option<Vec<u8>> {
    let mut o = 240;
    while o + 1 < b.len() && b[o] != 0xFF {
        if b[o] == 0 { o += 1; continue; }
        let len = b[o + 1] as usize;
        if b[o] == code { return Some(b[o + 2..o + 2 + len].to_vec()); }
        o += 2 + len;
    }
    None
}

/// The client's REQUESTs on the wire, oldest first: (Ethernet + IP header
/// octets 0..34, BOOTP).
fn requests() -> Vec<(Vec<u8>, Vec<u8>)> {
    raw::all()
        .iter()
        .filter_map(|f| bootp(f).filter(|b| option(b, 53) == Some(vec![3])).map(|b| (f[..34].to_vec(), b.to_vec())))
        .collect()
}

/// The poll hook: answer the newest REQUEST once, as `ANSWER` says, in a
/// limited broadcast from the server's port 67.
fn serve() {
    let Some((_, b)) = requests().pop() else { return };
    let xid: [u8; 4] = b[4..8].try_into().unwrap();
    if *ANSWERED.lock().unwrap() == Some(xid) { return; }
    let (server, opts) = match *ANSWER.lock().unwrap() {
        Answer::Nothing => return,
        Answer::Ack { server, secs } => {
            let mut o = vec![0x35, 1, 5, 0x36, 4];
            o.extend_from_slice(&server);
            o.extend_from_slice(&[0x33, 4]);
            o.extend_from_slice(&secs.to_be_bytes());
            o.extend_from_slice(&[0x01, 4, 255, 255, 255, 0, 0xFF]);
            (server, o)
        }
        Answer::Nak { server } => {
            let mut o = vec![0x35, 1, 6, 0x36, 4];
            o.extend_from_slice(&server);
            o.push(0xFF);
            (server, o)
        }
    };
    *ANSWERED.lock().unwrap() = Some(xid);
    let body = server_reply(xid, &opts);
    let mut udp = Vec::new();
    udp.extend_from_slice(&67u16.to_be_bytes());
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&body);
    let mut h = [0u8; 20];
    super::ip::build_header(&mut h, super::ip::IP_PROTO_UDP, &server, &[255; 4], udp.len() as u16);
    let mut d = h.to_vec();
    d.extend_from_slice(&udp);
    inbound::push_ipv4(&d);
}

/// Take a lease from SERVER_ID through the real exchange, its ACK carrying
/// `extra` options (51, 58, 59). Returns the clock at the ACK.
fn bind(extra: &[u8]) -> u64 {
    dhcp::dhcp_discover();
    let xid: [u8; 4] = last_frame()[BOOTP_AT + 4..BOOTP_AT + 8].try_into().unwrap();
    assert!(dhcp::dhcp_handle_offer(&offer(xid)).is_some());
    dhcp::dhcp_request(OFFERED, SERVER_ID);
    let mut opts = vec![0x35, 1, 5, 0x36, 4, 10, 0, 0, 1, 0x01, 4, 255, 255, 255, 0];
    opts.extend_from_slice(extra);
    opts.push(0xFF);
    assert!(dhcp::dhcp_handle_ack(&server_reply(xid, &opts)), "precondition: bound");
    azos_drv_sys::timebase::now()
}

fn secs(code: u8, s: u32) -> Vec<u8> {
    let mut o = vec![code, 4];
    o.extend_from_slice(&s.to_be_bytes());
    o
}

/// A test's server: answers `a`, from a resolved MAC, through the poll hook.
fn serve_with(a: Answer) {
    *ANSWER.lock().unwrap() = a;
    *ANSWERED.lock().unwrap() = None;
    arp::insert(SERVER_ID, SERVER_MAC);
    arp::insert(OTHER_SERVER, SERVER_MAC);
    inbound::on_poll(serve);
}

fn at(t: u64) {
    azos_drv_irqchip::clint::set_test_time(t);
}

/// T1 is option 58, or half the lease; T2 option 59, or 7/8; out of order
/// they are the defaults; a lease of all ones never needs renewing.
#[test]
fn t1_and_t2_follow_options_58_and_59_or_the_rfc_defaults() {
    let _g = begin();
    let t = bind(&secs(51, 1000));
    assert_eq!(dhcp::lease_deadline(), Some(t + 500 * TICKS_PER_S), "T1 = lease / 2");
    let t = bind(&[secs(51, 1000), secs(58, 100), secs(59, 800)].concat());
    assert_eq!(dhcp::lease_deadline(), Some(t + 100 * TICKS_PER_S), "option 58");
    let t = bind(&[secs(51, 1000), secs(58, 900), secs(59, 800)].concat());
    assert_eq!(dhcp::lease_deadline(), Some(t + 500 * TICKS_PER_S), "T1 past T2: the defaults");
    bind(&secs(51, 0xFFFF_FFFF));
    assert_eq!(dhcp::lease_deadline(), None, "an infinite lease");
    inbound::reset();
}

/// At T1 the client asks the lease's server, by unicast, with `ciaddr` its
/// address, the BROADCAST flag clear and neither option 50 nor 54 (RFC 2131
/// Table 5); the ACK renews the lease from now.
#[test]
fn at_t1_the_lease_is_renewed_with_its_server_by_unicast() {
    let _g = begin();
    let t = bind(&secs(51, 100));
    serve_with(Answer::Ack { server: SERVER_ID, secs: 100 });
    dhcp::dhcp_maintain(nop);
    assert!(dhcp::dhcp_state() == dhcp::DhcpState::Bound, "nothing to do before T1");
    raw::reset();
    netcfg::reset();

    at(t + 50 * TICKS_PER_S);
    dhcp::dhcp_maintain(nop);
    let r = requests();
    assert_eq!(r.len(), 1, "one RENEWING REQUEST");
    let (hdr, b) = &r[0];
    assert_eq!(&hdr[0..6], &SERVER_MAC, "unicast to the server");
    assert_eq!(&hdr[30..34], &SERVER_ID);
    assert_eq!(&b[12..16], &OFFERED, "ciaddr: the lease's address");
    assert_eq!(&b[10..12], &[0, 0], "no BROADCAST flag");
    assert_eq!((option(b, 50), option(b, 54)), (None, None), "Table 5: neither 50 nor 54");
    assert!(dhcp::dhcp_state() == dhcp::DhcpState::Bound, "renewed");
    assert_eq!(netcfg::last().map(|c| c.0), Some(OFFERED));
    // The ACK was taken inside the last poll, which then moved the clock on.
    let now = azos_drv_sys::timebase::now();
    let d = dhcp::lease_deadline().expect("a lease");
    assert!((now + 50 * TICKS_PER_S).abs_diff(d) <= inbound::TICKS_PER_POLL,
        "the new T1 counts from the renewal");
    inbound::reset();
}

/// Unanswered in RENEWING, the REQUEST goes again after half the time left to
/// T2; at T2 the client broadcasts from its address, and an ACK from another
/// server rebinds the lease to that server.
#[test]
fn an_unanswered_renewal_retries_then_rebinds_by_broadcast_with_any_server() {
    let _g = begin();
    let t = bind(&secs(51, 1000));
    serve_with(Answer::Nothing);
    at(t + 500 * TICKS_PER_S);
    dhcp::dhcp_maintain(nop);
    assert!(dhcp::dhcp_state() == dhcp::DhcpState::Renewing);
    let now = azos_drv_sys::timebase::now();
    let t2 = t + 875 * TICKS_PER_S;
    assert_eq!(dhcp::lease_deadline(), Some(now + (t2 - now) / 2), "half the time left to T2");

    raw::reset();
    serve_with(Answer::Ack { server: OTHER_SERVER, secs: 1000 });
    at(t2);
    dhcp::dhcp_maintain(nop);
    let r = requests();
    assert_eq!(r.len(), 1, "one REBINDING REQUEST");
    let (hdr, b) = &r[0];
    assert_eq!(&hdr[0..6], &[0xFF; 6], "broadcast");
    assert_eq!((&hdr[26..30], &hdr[30..34]), (&OFFERED[..], &[255u8; 4][..]), "from the lease's address");
    assert_eq!(&b[12..16], &OFFERED);
    assert_eq!((option(b, 50), option(b, 54)), (None, None));
    assert!(dhcp::dhcp_state() == dhcp::DhcpState::Bound, "any server may answer a rebinding");

    // The next renewal asks the server that answered.
    raw::reset();
    serve_with(Answer::Ack { server: OTHER_SERVER, secs: 1000 });
    at(dhcp::lease_deadline().unwrap());
    dhcp::dhcp_maintain(nop);
    assert_eq!(&requests()[0].0[30..34], &OTHER_SERVER);
    inbound::reset();
}

/// A NAK, and a lease that ends unanswered, both give the address up (it is
/// configured to 0.0.0.0) and start over with a DISCOVER.
#[test]
fn a_nak_or_the_end_of_the_lease_drops_the_address_and_starts_over() {
    let _g = begin();
    for (what, answer, when) in [
        ("NAK", Answer::Nak { server: SERVER_ID }, 50u64),
        ("end", Answer::Nothing, 100),
    ] {
        let t = bind(&secs(51, 100));
        serve_with(answer);
        raw::reset();
        netcfg::reset();
        at(t + when * TICKS_PER_S);
        dhcp::dhcp_maintain(nop);
        // Read before asserting: a guard held across a failing assertion
        // poisons the record for every later test.
        let first = netcfg::SET.lock().unwrap().first().map(|c| c.0);
        assert_eq!(first, Some([0; 4]), "{what}: address dropped");
        assert!(
            raw::all().iter().filter_map(|f| bootp(f)).any(|b| option(b, 53) == Some(vec![1])),
            "{what}: a DISCOVER follows",
        );
        assert_eq!(dhcp::lease_deadline(), None, "{what}: no lease is held");
    }
    inbound::reset();
}
