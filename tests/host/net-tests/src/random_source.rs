// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The installed random source drives the fields an off-path forger has to
//! guess: the DHCP xid, the DNS id and source port, the NTP nonce and the TCP
//! ISN secret.
//!
//! Each test installs a source that writes a known pattern and reads the field
//! back off the wire, so a consumer still minting from its counters fails
//! here even though its output "looks random". A source answering `false` —
//! the unseeded pool — must leave the consumer on that counter fallback.

use super::NET_SERIAL as SERIAL;
use super::{arp, dhcp, dns, inbound, ntp, random, raw, tcp, wire};
use std::sync::atomic::{AtomicU64, Ordering};

/// Bytes the seeded source writes: `SEED`'s little-endian bytes, repeating.
static SEED: AtomicU64 = AtomicU64::new(0);

fn seeded_source(buf: &mut [u8]) -> bool {
    let s = SEED.load(Ordering::Relaxed).to_le_bytes();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = s[i % 8];
    }
    true
}

fn unseeded_source(_buf: &mut [u8]) -> bool {
    false
}

/// Uninstalls the source when the test ends, pass or fail, so no other test
/// inherits it.
struct Installed;

impl Drop for Installed {
    fn drop(&mut self) {
        *random::SOURCE.lock().unwrap() = None;
    }
}

fn install(f: fn(&mut [u8]) -> bool, seed: u64) -> Installed {
    SEED.store(seed, Ordering::Relaxed);
    *random::SOURCE.lock().unwrap() = Some(f);
    Installed
}

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const SEED_A: u64 = 0x0123_4567_89AB_CDEF;
const SEED_B: u64 = 0xFEDC_BA98_7654_3210;

// ---------------------------------------------------------------------------

fn xid_from_the_wire() -> u32 {
    let frames = raw::all();
    let f = frames.last().expect("a DISCOVER must have been transmitted");
    // Ethernet(14) + IP(20) + UDP(8) = 42 bytes before the BOOTP header; xid at 4.
    u32::from_be_bytes([f[46], f[47], f[48], f[49]])
}

fn discover_xid() -> u32 {
    for idx in 0..azos_limits::TCP_MAX_CONNS {
        tcp::close(idx);
        tcp::close(idx);
    }
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(300_000);
    tcp::init([0x02, 0, 0, 0, 0, 0x02], [0, 0, 0, 0]);
    dhcp::dhcp_discover();
    xid_from_the_wire()
}

#[test]
fn the_installed_source_supplies_the_dhcp_xid() {
    let _g = serial();
    {
        let _s = install(seeded_source, SEED_A);
        assert_eq!(discover_xid(), SEED_A as u32, "the xid did not come from the source");
    }
    {
        let _s = install(seeded_source, SEED_B);
        assert_eq!(discover_xid(), SEED_B as u32);
    }
    let _s = install(unseeded_source, SEED_A);
    let (x1, x2) = (discover_xid(), discover_xid());
    assert_ne!(x1, SEED_A as u32,
               "a source answering false must leave the xid to the counter fallback");
    assert_ne!(x1, x2, "the fallback must still mint a fresh xid per exchange");
}

// ---------------------------------------------------------------------------

const DNS_SERVER_IP: [u8; 4] = [10, 0, 0, 53];
const DNS_SERVER_MAC: [u8; 6] = [0x02, 0x53, 0x53, 0x53, 0x53, 0x53];

/// (tx_id, source port) of the query put on the wire by a resolve nobody answers.
fn unanswered_query() -> (u16, u16) {
    inbound::reset();
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(200_000);
    arp::insert(DNS_SERVER_IP, DNS_SERVER_MAC);
    dns::set_dns_server(DNS_SERVER_IP);
    assert_eq!(dns::resolve("pool.test"), None, "nobody answers");
    wire::sent()
        .iter()
        .find_map(|s| {
            if s.proto != 17 || s.payload.len() < 8 + 12 { return None; }
            if u16::from_be_bytes([s.payload[2], s.payload[3]]) != 53 { return None; }
            Some((u16::from_be_bytes([s.payload[8], s.payload[9]]),
                  u16::from_be_bytes([s.payload[0], s.payload[1]])))
        })
        .expect("a query must have been transmitted")
}

#[test]
fn the_installed_source_supplies_the_dns_id_and_source_port() {
    let _g = serial();
    let h = SEED_A as u32;
    // The same folds `new_tx_id` and `new_source_port` apply to 32 bits.
    let want_id = ((h >> 16) ^ h) as u16;
    let want_port = 1024 + ((h as u64 * (65536 - 1024)) >> 32) as u16;
    {
        let _s = install(seeded_source, SEED_A);
        assert_eq!(unanswered_query(), (want_id, want_port),
                   "the id and port did not come from the source");
    }
    let _s = install(unseeded_source, SEED_A);
    let (id, _) = unanswered_query();
    assert_ne!(id, want_id, "a source answering false must leave the id to the counters");
}

// ---------------------------------------------------------------------------

const NTP_SERVER_IP: [u8; 4] = [10, 0, 0, 123];
const NTP_SERVER_MAC: [u8; 6] = [0x02, 0x12, 0x33, 0x44, 0x55, 0x66];

/// The transmit-timestamp nonce of the first request of a sync nobody answers.
fn unanswered_nonce() -> [u8; 8] {
    inbound::reset();
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(500_000);
    arp::insert(NTP_SERVER_IP, NTP_SERVER_MAC);
    ntp::set_ntp_server(NTP_SERVER_IP);
    assert_eq!(ntp::ntp_sync(), 0, "nobody answers");
    wire::sent()
        .iter()
        .find_map(|s| {
            if s.proto != 17 || s.payload.len() < 8 + 48 { return None; }
            if u16::from_be_bytes([s.payload[2], s.payload[3]]) != 123 { return None; }
            let mut n = [0u8; 8];
            n.copy_from_slice(&s.payload[8 + 40..8 + 48]);
            Some(n)
        })
        .expect("a request must have been transmitted")
}

#[test]
fn the_installed_source_supplies_the_ntp_nonce() {
    let _g = serial();
    {
        let _s = install(seeded_source, SEED_A);
        assert_eq!(unanswered_nonce(), SEED_A.to_le_bytes(),
                   "the nonce did not come from the source");
    }
    let _s = install(unseeded_source, SEED_A);
    assert_ne!(unanswered_nonce(), SEED_A.to_le_bytes(),
               "a source answering false must leave the nonce to the counters");
}

// ---------------------------------------------------------------------------

const OUR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
const OUR_IP: [u8; 4] = [10, 0, 0, 2];
const PEER_IP: [u8; 4] = [10, 0, 0, 77];
const PEER_MAC: [u8; 6] = [0x02, 0x77, 0x77, 0x77, 0x77, 0x77];

/// Initialise TCP with `f` installed and dial one fixed 4-tuple at one fixed
/// instant; the SYN's sequence number is the ISN.
fn isn_with(f: fn(&mut [u8]) -> bool, seed: u64) -> u32 {
    for idx in 0..azos_limits::TCP_MAX_CONNS {
        tcp::close(idx);
        tcp::close(idx);
    }
    raw::reset();
    azos_drv_irqchip::clint::set_test_time(700_000);
    arp::insert(PEER_IP, PEER_MAC);
    let _s = install(f, seed);
    tcp::init(OUR_MAC, OUR_IP);
    assert!(tcp::connect(PEER_IP, 7700, 47700) >= 0, "no slot to dial from");
    wire::sent()
        .iter()
        .find_map(|s| {
            let p = &s.payload;
            if s.proto != 6 || p.len() < 20 || p[13] & 0x02 == 0 { return None; }
            Some(u32::from_be_bytes([p[4], p[5], p[6], p[7]]))
        })
        .expect("connect must put a SYN on the wire")
}

/// Same 4-tuple, same clock: the ISN can only move with the secret. It must
/// follow the source (A, B, A again), and a source answering `false` must
/// leave the secret the last seeded source installed.
#[test]
fn the_installed_source_supplies_the_tcp_isn_secret() {
    let _g = serial();
    let a = isn_with(seeded_source, SEED_A);
    let b = isn_with(seeded_source, SEED_B);
    let a_again = isn_with(seeded_source, SEED_A);
    assert_ne!(a, b, "the ISN did not change with the source");
    assert_eq!(a, a_again, "the ISN is not a function of the source's bytes");
    assert_eq!(isn_with(unseeded_source, SEED_B), a,
               "a source answering false must leave the secret untouched");
}
