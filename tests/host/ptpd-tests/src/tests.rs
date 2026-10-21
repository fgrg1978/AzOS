// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The tests. Each states what it would catch if the code under test were
//! wrong; the sign and the timescale of the offered sample are pinned by
//! arithmetic on a model, not by re-deriving the formula the code uses.

use crate::bmc::{self, Dataset, Table};
use crate::link;
use crate::port::{self, Config, Event, Host, Port, Sampled};
use crate::wire::{self, flag, mt, Announce, Body, Header, ParseError, PortId, MSG_MAX};
use core::cmp::Ordering;

const SEC: i128 = 1_000_000_000;
const US: i128 = 1_000;
/// A time in 2026 (UTC, ns since the Unix epoch): large enough that a 48-bit
/// second count and the i128 arithmetic are exercised.
const T0: i128 = 1_790_000_000 * SEC;
const LEAP: i16 = 37;

const SLAVE: [u8; 8] = [0x5A; 8];
const GM_A: [u8; 8] = [0xA1; 8];
const GM_B: [u8; 8] = [0xB2; 8];

fn pid(clock: [u8; 8]) -> PortId {
    PortId { clock, port: 1 }
}

fn slave_port() -> PortId {
    pid(SLAVE)
}

// ── The model ───────────────────────────────────────────────────────────────

/// The recording host.
struct World {
    sent: Vec<Vec<u8>>,
    /// What the next send reports as its transmit timestamp.
    tx_wall: i128,
    refuse_send: bool,
    samples: Vec<(i64, u64)>,
    events: Vec<Event>,
    verdict: Sampled,
}

impl World {
    fn new() -> World {
        World { sent: Vec::new(), tx_wall: 0, refuse_send: false, samples: Vec::new(), events: Vec::new(), verdict: Sampled::Slewed }
    }

    fn last_sent(&self) -> (Header, Body) {
        wire::parse(self.sent.last().expect("something was sent")).expect("what the port sends parses")
    }
}

impl Host for World {
    fn send(&mut self, msg: &[u8]) -> Option<i128> {
        if self.refuse_send {
            return None;
        }
        self.sent.push(msg.to_vec());
        Some(self.tx_wall)
    }

    fn sample(&mut self, offset_ns: i64, delay_ns: u64) -> Sampled {
        self.samples.push((offset_ns, delay_ns));
        self.verdict
    }

    fn event(&mut self, e: Event) {
        self.events.push(e);
    }
}

/// Two clocks and a path.
#[derive(Clone, Copy)]
struct Net {
    /// The slave's wall clock minus the true UTC time. Negative: behind.
    theta: i128,
    /// Master to slave delay.
    d_ms: i128,
    /// Slave to master delay.
    d_sm: i128,
}

fn flags_utc() -> u16 {
    flag::PTP_TIMESCALE | flag::UTC_OFFSET_VALID
}

fn announce_body(gm: [u8; 8], p1: u8) -> Announce {
    Announce {
        utc_offset: LEAP,
        priority1: p1,
        class: 6,
        accuracy: 0x21,
        variance: 0x4E5D,
        priority2: 128,
        identity: gm,
        steps_removed: 0,
        time_source: 0x20,
    }
}

fn hdr(ts: u8, ty: u8, domain: u8, src: PortId, seq: u16) -> Header {
    Header::new(ts, ty, domain, src, seq)
}

fn announce_msg(ts: u8, domain: u8, src: PortId, seq: u16, flags: u16, a: &Announce) -> Vec<u8> {
    let mut h = hdr(ts, mt::ANNOUNCE, domain, src, seq);
    h.flags = flags;
    h.log_interval = 0;
    let mut out = [0u8; MSG_MAX];
    let n = wire::encode_announce(&mut out, &h, a);
    out[..n].to_vec()
}

fn time_msg(ts: u8, ty: u8, domain: u8, src: PortId, seq: u16, flags: u16, corr_ns: i64, t: i128) -> Vec<u8> {
    let mut h = hdr(ts, ty, domain, src, seq);
    h.flags = flags;
    h.correction = corr_ns << 16;
    let mut out = [0u8; MSG_MAX];
    let n = wire::encode_time(&mut out, &h, t);
    out[..n].to_vec()
}

fn response_msg(ts: u8, ty: u8, domain: u8, src: PortId, seq: u16, flags: u16, corr_ns: i64, t: i128, req: PortId) -> Vec<u8> {
    let mut h = hdr(ts, ty, domain, src, seq);
    h.flags = flags;
    h.correction = corr_ns << 16;
    h.log_interval = 0;
    let mut out = [0u8; MSG_MAX];
    let n = wire::encode_response(&mut out, &h, t, req);
    out[..n].to_vec()
}

fn e2e_port(domain: u8) -> Port {
    Port::new(Config { domain, identity: SLAVE })
}

/// Two Announces from `gm` (it qualifies), at monotonic 1 s and 2 s. The
/// port's monotonic clock is then at 2 s.
fn qualify(p: &mut Port, w: &mut World, ts: u8, domain: u8, src: PortId, flags: u16, a: &Announce) -> u64 {
    for (i, now) in [SEC as u64, 2 * SEC as u64].into_iter().enumerate() {
        let m = announce_msg(ts, domain, src, i as u16, flags, a);
        p.rx(w, now, 0, &m);
    }
    2 * SEC as u64
}

/// One Sync / Follow_Up pair the master sends at true time `t` (UTC): the
/// departure time on its TAI scale, arrival at the slave `d_ms` later, read on
/// the slave's wall clock.
fn deliver_sync(p: &mut Port, w: &mut World, net: Net, now: u64, src: PortId, seq: u16, t: i128, corr_ns: i64) {
    let t1_tai = t + LEAP as i128 * SEC;
    let t2 = t + net.d_ms + net.theta;
    let s = time_msg(0, mt::SYNC, 0, src, seq, flag::TWO_STEP, 0, 0);
    p.rx(w, now, t2, &s);
    let f = time_msg(0, mt::FOLLOW_UP, 0, src, seq, 0, corr_ns, t1_tai);
    p.rx(w, now, 0, &f);
}

/// The slave's Delay_Req sent at true time `t` (monotonic `now`), answered by
/// the master at once: the answer reaches the slave a round trip later, on
/// both clocks.
fn answer_delay_req(p: &mut Port, w: &mut World, net: Net, now: u64, src: PortId, t: i128) {
    let (h, body) = w.last_sent();
    assert_eq!(body, Body::DelayReq);
    let t4_tai = t + net.d_sm + LEAP as i128 * SEC;
    let r = response_msg(0, mt::DELAY_RESP, 0, src, h.seq, 0, 0, t4_tai, slave_port());
    let trip = net.d_sm + net.d_ms;
    p.rx(w, now + trip as u64, t + trip + net.theta, &r);
}

// ── The codec ───────────────────────────────────────────────────────────────

#[test]
fn announce_round_trips_with_the_header() {
    let a = announce_body(GM_A, 100);
    let m = announce_msg(1, 7, pid(GM_A), 513, flags_utc(), &a);
    assert_eq!(m.len(), 64);
    let (h, body) = wire::parse(&m).unwrap();
    assert_eq!((h.transport_specific, h.msg_type, h.domain, h.seq, h.len), (1, mt::ANNOUNCE, 7, 513, 64));
    assert_eq!((h.flags, h.source), (flags_utc(), pid(GM_A)));
    assert_eq!(body, Body::Announce(a));
    // A canary on the byte layout the standard fixes (IEEE 1588 Table 43):
    // grandmasterPriority1 at 47, the identity at 53, stepsRemoved at 61.
    assert_eq!((m[47], &m[53..61], m[1]), (100, &GM_A[..], 2));
}

#[test]
fn timestamps_use_the_48_bit_seconds_and_32_bit_nanoseconds() {
    let t = T0 + 123_456_789;
    let m = time_msg(0, mt::SYNC, 0, pid(GM_A), 1, 0, 0, t);
    assert_eq!(&m[34..40], &((T0 / SEC) as u64).to_be_bytes()[2..8]);
    assert_eq!(&m[40..44], &123_456_789u32.to_be_bytes());
    assert_eq!(wire::parse(&m).unwrap().1, Body::Sync { origin: t });
}

#[test]
fn correction_field_is_nanoseconds_times_2_to_the_16() {
    let m = time_msg(0, mt::FOLLOW_UP, 0, pid(GM_A), 1, 0, 1500, 0);
    let (h, _) = wire::parse(&m).unwrap();
    assert_eq!(h.correction, 1500 << 16);
    assert_eq!(h.correction_ns(), 1500);
    // A negative correction floors, it does not wrap.
    let m = time_msg(0, mt::FOLLOW_UP, 0, pid(GM_A), 1, 0, -3, 0);
    assert_eq!(wire::parse(&m).unwrap().0.correction_ns(), -3);
}

#[test]
fn responses_carry_the_requesting_port() {
    let r = response_msg(0, mt::DELAY_RESP, 0, pid(GM_B), 9, 0, 0, T0 + 5, slave_port());
    assert_eq!(wire::parse(&r).unwrap().1, Body::DelayResp { receive: T0 + 5, requesting: slave_port() });
}

#[test]
fn a_malformed_message_is_refused_not_misread() {
    let good = time_msg(0, mt::SYNC, 0, pid(GM_A), 1, 0, 0, T0);
    // Shorter than the header, and shorter than the body the type needs.
    assert_eq!(wire::parse(&good[..20]), Err(ParseError::Short));
    assert_eq!(wire::parse(&good[..40]), Err(ParseError::Short));
    // A message whose own length field claims less than its type needs.
    let mut lies = good.clone();
    lies[3] = 40;
    assert_eq!(wire::parse(&lies), Err(ParseError::Short));
    // PTP version 1, and a message type the slave does not read (Signaling).
    let mut v1 = good.clone();
    v1[1] = 1;
    assert_eq!(wire::parse(&v1), Err(ParseError::Version));
    let mut sig = good.clone();
    sig[0] = 0x0C;
    assert_eq!(wire::parse(&sig), Err(ParseError::Type));
    // Peer delay is 802.1AS's and not read.
    let mut pd = good.clone();
    pd[0] = 0x02;
    assert_eq!(wire::parse(&pd), Err(ParseError::Type));
    // Trailing bytes (a TLV) are not an error.
    let mut padded = good;
    padded.extend_from_slice(&[0u8; 20]);
    assert!(wire::parse(&padded).is_ok());
}

// ── The arithmetic ──────────────────────────────────────────────────────────

#[test]
fn e2e_symmetric_path_gives_exact_offset_and_delay() {
    // Slave 5 ms behind true time; legs of 200 us each.
    let net = Net { theta: -5_000 * US, d_ms: 200 * US, d_sm: 200 * US };
    let (t1, t2) = (T0, T0 + net.d_ms + net.theta);
    let (t3, t4) = (T0 + 1_000 * US + net.theta, T0 + 1_000 * US + net.d_sm);
    let m = port::e2e_measure(t1, t2, t3, t4);
    // Behind means the reference is ahead: a POSITIVE offset, the wall clock
    // must move forward by it.
    assert_eq!(m.offset_ns as i128, 5_000 * US);
    assert_eq!(m.delay_ns as i128, 400 * US);
}

#[test]
fn e2e_asymmetric_path_biases_the_offset_by_half_the_asymmetry_and_not_the_delay() {
    // 300 us master to slave, 100 us back: no measurement on this path can see
    // it, and the error is the known half of the difference.
    let net = Net { theta: -5_000 * US, d_ms: 300 * US, d_sm: 100 * US };
    let (t1, t2) = (T0, T0 + net.d_ms + net.theta);
    let (t3, t4) = (T0 + 1_000 * US + net.theta, T0 + 1_000 * US + net.d_sm);
    let m = port::e2e_measure(t1, t2, t3, t4);
    assert_eq!(m.offset_ns as i128, 5_000 * US + (net.d_sm - net.d_ms) / 2, "off by (d_sm - d_ms) / 2");
    assert_eq!(m.delay_ns as i128, 400 * US, "the round trip is exact either way");
    // Opposite asymmetry, opposite error.
    let net = Net { d_ms: 100 * US, d_sm: 300 * US, ..net };
    let (t2, t4) = (T0 + net.d_ms + net.theta, T0 + 1_000 * US + net.d_sm);
    assert_eq!(port::e2e_measure(t1, t2, t3, t4).offset_ns as i128, 5_000 * US + 100 * US);
}

// ── Best master clock ───────────────────────────────────────────────────────

fn data(p1: u8, class: u8, acc: u8, var: u16, p2: u8, id: [u8; 8], steps: u16) -> Dataset {
    Dataset { priority1: p1, class, accuracy: acc, variance: var, priority2: p2, identity: id, steps_removed: steps }
}

#[test]
fn dataset_comparison_follows_the_standards_order() {
    let base = data(128, 6, 0x21, 0x4000, 128, GM_B, 0);
    let s = pid(GM_B);
    let better = |a: Dataset| bmc::compare(&a, s, &base, s) == Ordering::Less;
    // Each wins on its own field though everything below it, the identity
    // included, is worse (HI sorts after GM_B): priority1 beats everything...
    const HI: [u8; 8] = [0xFF; 8];
    assert!(better(data(100, 248, 0xFE, 0xFFFF, 255, HI, 0)));
    // ... class beats accuracy, accuracy beats variance, variance priority2.
    assert!(better(data(128, 5, 0xFE, 0xFFFF, 255, HI, 0)));
    assert!(better(data(128, 6, 0x20, 0xFFFF, 255, HI, 0)));
    assert!(better(data(128, 6, 0x21, 0x3000, 255, HI, 0)));
    assert!(better(data(128, 6, 0x21, 0x4000, 100, HI, 0)));
    // Everything equal: the smaller identity wins, and not the reverse.
    assert!(better(data(128, 6, 0x21, 0x4000, 128, GM_A, 0)));
    assert!(!bmc::compare(&base, s, &data(128, 6, 0x21, 0x4000, 128, GM_A, 0), s).is_lt());
    // A worse priority1 loses despite a better everything else.
    assert!(!better(data(129, 0, 0, 0, 0, GM_A, 0)));
}

#[test]
fn one_grandmaster_through_two_paths_prefers_fewer_steps_then_the_lower_sender() {
    let (near, far) = (data(128, 6, 0x21, 0x4000, 128, GM_A, 1), data(128, 6, 0x21, 0x4000, 128, GM_A, 3));
    let (s1, s2) = (pid([1; 8]), pid([2; 8]));
    assert_eq!(bmc::compare(&near, s2, &far, s1), Ordering::Less, "steps removed first");
    assert_eq!(bmc::compare(&near, s1, &near, s2), Ordering::Less, "then the sender's port identity");
    assert_eq!(bmc::compare(&near, s1, &near, s1), Ordering::Equal);
}

#[test]
fn a_master_qualifies_on_two_announces_and_expires_after_three_silent_intervals() {
    let mut t = Table::new();
    let a = announce_body(GM_A, 128);
    let s = pid(GM_A);
    let iv = SEC as u64;
    t.announce(s, flags_utc(), &a, iv, 10 * iv);
    assert!(t.best(10 * iv).is_none(), "one Announce selects nothing");
    t.announce(s, flags_utc(), &a, iv, 11 * iv);
    assert_eq!(t.best(11 * iv).map(|f| f.sender), Some(s));
    // Two Announces further apart than the window do not qualify.
    let mut t = Table::new();
    t.announce(s, flags_utc(), &a, iv, 10 * iv);
    t.announce(s, flags_utc(), &a, iv, 15 * iv);
    assert!(t.best(15 * iv).is_none(), "5 intervals apart is outside the 4-interval window");
    // Expiry: still there at 3 intervals of silence, gone after.
    let mut t = Table::new();
    t.announce(s, flags_utc(), &a, iv, 10 * iv);
    t.announce(s, flags_utc(), &a, iv, 11 * iv);
    assert!(t.best(14 * iv).is_some());
    assert!(t.best(14 * iv + 1).is_none());
}

#[test]
fn the_table_follows_the_better_master_and_returns_to_the_other_when_it_goes() {
    let mut t = Table::new();
    let iv = SEC as u64;
    let (a, b) = (announce_body(GM_A, 128), announce_body(GM_B, 100));
    let mut now = 10 * iv;
    for _ in 0..2 {
        t.announce(pid(GM_A), flags_utc(), &a, iv, now);
        now += iv;
    }
    assert_eq!(t.best(now).unwrap().data.identity, GM_A);
    // B has the lower priority1: it takes over as soon as it qualifies, not before.
    t.announce(pid(GM_B), flags_utc(), &b, iv, now);
    t.announce(pid(GM_A), flags_utc(), &a, iv, now);
    assert_eq!(t.best(now).unwrap().data.identity, GM_A, "B has sent one Announce");
    now += iv;
    t.announce(pid(GM_B), flags_utc(), &b, iv, now);
    t.announce(pid(GM_A), flags_utc(), &a, iv, now);
    assert_eq!(t.best(now).unwrap().data.identity, GM_B);
    // B goes silent, A keeps announcing.
    for _ in 0..5 {
        now += iv;
        t.announce(pid(GM_A), flags_utc(), &a, iv, now);
    }
    assert_eq!(t.best(now).unwrap().data.identity, GM_A);
}

// ── The slave engine, end to end ────────────────────────────────────────────

#[test]
fn e2e_exchange_offers_the_offset_in_utc_and_the_round_trip() {
    let net = Net { theta: -5_000 * US, d_ms: 300 * US, d_sm: 100 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let mut now = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    assert_eq!(w.events, vec![Event::Master(GM_A)]);
    // No Sync yet: nothing to ask the master about, so no Delay_Req.
    p.tick(&mut w, now);
    assert!(w.sent.is_empty());
    deliver_sync(&mut p, &mut w, net, now, gm, 7, T0, 0);
    // The Delay_Req goes out 1 ms (true time) after the Sync left; its
    // transmit stamp is the slave's wall clock then.
    let t_req = T0 + 1_000 * US;
    w.tx_wall = t_req + net.theta;
    now += 1_000_000;
    p.tick(&mut w, now);
    assert_eq!(w.sent.len(), 1);
        let (h, body) = w.last_sent();
    assert_eq!((body, h.domain, h.transport_specific, h.source), (Body::DelayReq, 0, 0, slave_port()));
    answer_delay_req(&mut p, &mut w, net, now, gm, t_req);
    assert_eq!(w.samples.len(), 1);
    let (off, delay) = w.samples[0];
    // The wall clock is 5 ms behind: positive offset. The master's time is TAI
    // and 37 s ahead of UTC: if the leap offset were not removed the sample
    // would be 37 s off. The asymmetry shows as the known (d_sm - d_ms) / 2.
    assert_eq!(off as i128, 5_000 * US + (net.d_sm - net.d_ms) / 2);
    assert_eq!(delay as i128, 400 * US);
    assert!(matches!(w.events.last(), Some(Event::Sample { how: Sampled::Slewed, .. })));
}

#[test]
fn a_clock_ahead_of_the_master_gets_a_negative_offset() {
    let net = Net { theta: 12 * 1_000 * US, d_ms: 50 * US, d_sm: 50 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let now = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    deliver_sync(&mut p, &mut w, net, now, gm, 1, T0, 0);
    w.tx_wall = T0 + 100 * US + net.theta;
    p.tick(&mut w, now);
    answer_delay_req(&mut p, &mut w, net, now, gm, T0 + 100 * US);
    assert_eq!(w.samples, vec![(-12_000_000, 100_000)]);
}

#[test]
fn correction_fields_of_the_sync_and_the_delay_response_are_taken_out() {
    // A transparent clock added 40 us of residence to the Sync and 25 us to the
    // Delay_Resp. The Sync's arrival includes its 40 us; the Delay_Req's
    // arrival at the master (t4) is stated 25 us later than it was by the
    // residence the response accumulated.
    let net = Net { theta: 0, d_ms: 100 * US, d_sm: 100 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let now = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    // Sync residence 40 us: it arrives 40 us later than the plain path.
    let t1_tai = T0 + LEAP as i128 * SEC;
    let t2 = T0 + net.d_ms + 40 * US;
    p.rx(&mut w, now, t2, &time_msg(0, mt::SYNC, 0, gm, 3, flag::TWO_STEP, 0, 0));
    p.rx(&mut w, now, 0, &time_msg(0, mt::FOLLOW_UP, 0, gm, 3, 0, 40_000, t1_tai));
    w.tx_wall = T0 + 1_000 * US;
    p.tick(&mut w, now);
    let (h, _) = w.last_sent();
    let t4_tai = T0 + 1_000 * US + net.d_sm + 25 * US + LEAP as i128 * SEC;
    let t_rx = w.tx_wall;
    p.rx(&mut w, now, t_rx, &response_msg(0, mt::DELAY_RESP, 0, gm, h.seq, 0, 25_000, t4_tai, slave_port()));
    assert_eq!(w.samples, vec![(0, 200_000)], "clocks equal, 100 us each way: residence is not delay");
}

#[test]
fn a_master_without_a_valid_utc_offset_gives_no_sample_and_one_report() {
    let net = Net { theta: -5_000 * US, d_ms: 100 * US, d_sm: 100 * US };
    for flags in [0u16, flag::PTP_TIMESCALE, flag::UTC_OFFSET_VALID] {
        let (mut p, mut w) = (e2e_port(0), World::new());
        let gm = pid(GM_A);
        let now = qualify(&mut p, &mut w, 0, 0, gm, flags, &announce_body(GM_A, 128));
        for seq in 0..3u16 {
            let at = now + seq as u64 * 2 * SEC as u64;
            deliver_sync(&mut p, &mut w, net, at, gm, seq, T0, 0);
            w.tx_wall = T0 + 1_000 * US + net.theta;
            p.tick(&mut w, at + 1_000_000);
            answer_delay_req(&mut p, &mut w, net, at + 1_000_000, gm, T0 + 1_000 * US);
        }
        assert!(w.samples.is_empty(), "flags {flags:#x}: 37 s would be stepped into the clock");
        assert_eq!(w.events.iter().filter(|e| **e == Event::NoUtc).count(), 1, "reported once");
    }
}

#[test]
fn another_domain_another_transport_and_our_own_echo_are_ignored() {
    let (mut p, mut w) = (e2e_port(4), World::new());
    let a = announce_body(GM_A, 128);
    // Domain 0 while we serve 4; an 802.1AS (transportSpecific 1) message on the
    // UDP port; our own Announce back from a multicast loop.
    for (ts, dom, src) in [(0, 0, pid(GM_A)), (1, 4, pid(GM_A)), (0, 4, slave_port())] {
        for i in 0..3 {
            p.rx(&mut w, (i + 1) * SEC as u64, 0, &announce_msg(ts, dom, src, i as u16, flags_utc(), &a));
        }
    }
    p.tick(&mut w, 4 * SEC as u64);
    assert!(w.events.is_empty(), "no master selected from any of them");
    // The right domain is taken.
    for i in 0..2 {
        p.rx(&mut w, (i + 1) * SEC as u64, 0, &announce_msg(0, 4, pid(GM_A), i as u16, flags_utc(), &a));
    }
    assert_eq!(w.events, vec![Event::Master(GM_A)]);
}

#[test]
fn an_alternate_master_is_not_followed() {
    let (mut p, mut w) = (e2e_port(0), World::new());
    qualify(&mut p, &mut w, 0, 0, pid(GM_A), flags_utc() | flag::ALTERNATE_MASTER, &announce_body(GM_A, 128));
    assert!(w.events.is_empty());
}

#[test]
fn sync_from_a_port_that_is_not_the_selected_master_is_ignored() {
    let net = Net { theta: -1_000 * US, d_ms: 100 * US, d_sm: 100 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let now = qualify(&mut p, &mut w, 0, 0, pid(GM_A), flags_utc(), &announce_body(GM_A, 128));
    deliver_sync(&mut p, &mut w, net, now, pid(GM_B), 1, T0, 0);
    p.tick(&mut w, now);
    assert!(w.sent.is_empty(), "a Sync from a stranger starts no exchange");
}

#[test]
fn a_follow_up_with_another_sequence_number_completes_nothing() {
    let net = Net { theta: -1_000 * US, d_ms: 100 * US, d_sm: 100 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let now = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    let t2 = T0 + net.d_ms + net.theta;
    p.rx(&mut w, now, t2, &time_msg(0, mt::SYNC, 0, gm, 10, flag::TWO_STEP, 0, 0));
    p.rx(&mut w, now, 0, &time_msg(0, mt::FOLLOW_UP, 0, gm, 11, 0, 0, T0 + LEAP as i128 * SEC));
    p.tick(&mut w, now);
    assert!(w.sent.is_empty());
}

#[test]
fn a_delay_response_for_another_request_or_another_slave_is_ignored() {
    let net = Net { theta: -1_000 * US, d_ms: 100 * US, d_sm: 100 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let now = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    deliver_sync(&mut p, &mut w, net, now, gm, 1, T0, 0);
    w.tx_wall = T0 + net.theta;
    p.tick(&mut w, now);
    let (h, _) = w.last_sent();
    let t4 = T0 + net.d_sm + LEAP as i128 * SEC;
    // Wrong sequence, then the right one addressed to somebody else.
    let t_rx = w.tx_wall;
    p.rx(&mut w, now, t_rx, &response_msg(0, mt::DELAY_RESP, 0, gm, h.seq.wrapping_add(1), 0, 0, t4, slave_port()));
    p.rx(&mut w, now, t_rx, &response_msg(0, mt::DELAY_RESP, 0, gm, h.seq, 0, 0, t4, pid([9; 8])));
    assert!(w.samples.is_empty());
    // The right one still works afterwards (the request was not consumed).
    p.rx(&mut w, now, t_rx, &response_msg(0, mt::DELAY_RESP, 0, gm, h.seq, 0, 0, t4, slave_port()));
    assert_eq!(w.samples.len(), 1);
}

#[test]
fn delay_requests_follow_the_interval_the_master_states() {
    let net = Net { theta: 0, d_ms: 10 * US, d_sm: 10 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let start = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    let mut now = start;
    // The master syncs every second, as the clocks run on (true time = T0 plus
    // the monotonic time elapsed since the first Sync).
    let sync = |p: &mut Port, w: &mut World, now: u64| {
        let t = T0 + (now - start) as i128;
        deliver_sync(p, w, net, now, gm, 1, t, 0);
        w.tx_wall = t + net.d_ms;
        p.rx(w, now, 0, &announce_msg(0, 0, gm, 9, flags_utc(), &announce_body(GM_A, 128)));
        p.tick(w, now);
    };
    sync(&mut p, &mut w, now);
    let (h, _) = w.last_sent();
    // The Delay_Resp states logMessageInterval 2: one request every 4 s.
    let mut r = response_msg(0, mt::DELAY_RESP, 0, gm, h.seq, 0, 0, T0 + LEAP as i128 * SEC, slave_port());
    r[33] = 2;
    let t_rx = w.tx_wall;
    p.rx(&mut w, now, t_rx, &r);
    for _ in 0..3 {
        now += SEC as u64;
        sync(&mut p, &mut w, now);
    }
    assert_eq!(w.sent.len(), 1, "not before 4 s after the request it answers");
    now += SEC as u64;
    sync(&mut p, &mut w, now);
    assert_eq!(w.sent.len(), 2);
    let (h2, _) = w.last_sent();
    assert_eq!(h2.seq, h.seq.wrapping_add(1));
}

#[test]
fn a_better_master_replaces_the_old_one_and_drops_what_was_measured_against_it() {
    let net = Net { theta: -1_000 * US, d_ms: 100 * US, d_sm: 100 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let (a, b) = (pid(GM_A), pid(GM_B));
    let mut now = qualify(&mut p, &mut w, 0, 0, a, flags_utc(), &announce_body(GM_A, 128));
    deliver_sync(&mut p, &mut w, net, now, a, 1, T0, 0);
    // B arrives with a lower priority1 (and A keeps announcing).
    for _ in 0..2 {
        now += SEC as u64;
        p.rx(&mut w, now, 0, &announce_msg(0, 0, a, 5, flags_utc(), &announce_body(GM_A, 128)));
        p.rx(&mut w, now, 0, &announce_msg(0, 0, b, 5, flags_utc(), &announce_body(GM_B, 100)));
    }
    assert_eq!(w.events, vec![Event::Master(GM_A), Event::Master(GM_B)]);
    // The Sync of the old master does not start an exchange with the new one.
    p.tick(&mut w, now);
    assert!(w.sent.is_empty(), "the old master's Sync was dropped with it");
}

#[test]
fn a_silent_master_is_lost_and_the_delay_requests_stop() {
    let net = Net { theta: 0, d_ms: 10 * US, d_sm: 10 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let now = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    deliver_sync(&mut p, &mut w, net, now, gm, 1, T0, 0);
    p.tick(&mut w, now + 3 * SEC as u64);
    assert_eq!(w.events, vec![Event::Master(GM_A)], "still within 3 intervals");
    let sent = w.sent.len();
    p.tick(&mut w, now + 3 * SEC as u64 + 1);
    assert_eq!(w.events, vec![Event::Master(GM_A), Event::MasterLost]);
    p.tick(&mut w, now + 60 * SEC as u64);
    assert_eq!(w.sent.len(), sent, "no request to a master that is gone");
}

#[test]
fn a_refused_send_leaves_no_exchange_waiting() {
    let net = Net { theta: 0, d_ms: 10 * US, d_sm: 10 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let now = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    deliver_sync(&mut p, &mut w, net, now, gm, 1, T0, 0);
    w.refuse_send = true;
    p.tick(&mut w, now);
    // A Delay_Resp for a request that never left must not produce a sample
    // from a transmit time that does not exist.
    let r = response_msg(0, mt::DELAY_RESP, 0, gm, 1, 0, 0, T0 + LEAP as i128 * SEC, slave_port());
    p.rx(&mut w, now, 0, &r);
    assert!(w.samples.is_empty());
}

// ── What an exchange may pair ───────────────────────────────────────────────

const MS: u64 = 1_000_000;

/// A port following GM_A, a Sync delivered at monotonic `start + 0`, true time
/// T0, on clocks that agree (theta 0) over a 10 us path.
fn synced_port() -> (Port, World, Net, PortId, u64) {
    let net = Net { theta: 0, d_ms: 10 * US, d_sm: 10 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let start = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    deliver_sync(&mut p, &mut w, net, start, gm, 1, T0, 0);
    (p, w, net, gm, start)
}

/// The master keeps announcing (so it is not lost) for `ms` more milliseconds
/// in steps of 500 ms, ticking the port, with the wall clock running true.
fn announce_only(p: &mut Port, w: &mut World, gm: PortId, start: u64, from_ms: u64, to_ms: u64) {
    let mut ms = from_ms;
    while ms <= to_ms {
        let now = start + ms * MS;
        p.rx(w, now, 0, &announce_msg(0, 0, gm, 9, flags_utc(), &announce_body(GM_A, 128)));
        w.tx_wall = T0 + ms as i128 * 1_000_000 + 10 * US;
        p.tick(w, now);
        ms += 500;
    }
}

/// **Canary.** Without the age limit the master that stops syncing keeps
/// getting Delay_Reqs paired with its last Sync: the request due at 4 s goes
/// out with `t3` four seconds after `t2`, and the offset it yields is wrong by
/// half the drift in between.
#[test]
fn a_master_that_stops_syncing_has_its_last_sync_dropped() {
    let (mut p, mut w, _net, gm, start) = synced_port();
    w.tx_wall = T0 + 10 * US;
    p.tick(&mut w, start);
    assert_eq!(w.sent.len(), 1, "a fresh Sync starts an exchange");
    // Announces go on, Syncs do not. Within 3 Sync intervals (1 s, none stated)
    // a request is still paired with the last one.
    announce_only(&mut p, &mut w, gm, start, 500, 3_000);
    assert_eq!(w.sent.len(), 4, "requests at 0, 1, 2 and 3 s: the Sync is not older than 3 intervals yet");
    let sent = w.sent.len();
    announce_only(&mut p, &mut w, gm, start, 3_500, 8_000);
    assert_eq!(w.sent.len(), sent, "older than 3 Sync intervals: no request, whatever the Announces say");
    assert_eq!(w.events, vec![Event::Master(GM_A)], "the master is still the master");
    // The next Sync starts it again.
    let now = start + 8_500 * MS;
    let t = T0 + 8_500 * 1_000_000;
    deliver_sync(&mut p, &mut w, Net { theta: 0, d_ms: 10 * US, d_sm: 10 * US }, now, gm, 2, t, 0);
    w.tx_wall = t + 10 * US;
    p.tick(&mut w, now);
    assert_eq!(w.sent.len(), sent + 1);
}

#[test]
fn the_sync_interval_the_master_states_sets_how_old_a_sync_may_get() {
    let net = Net { theta: 0, d_ms: 10 * US, d_sm: 10 * US };
    let (mut p, mut w) = (e2e_port(0), World::new());
    let gm = pid(GM_A);
    let start = qualify(&mut p, &mut w, 0, 0, gm, flags_utc(), &announce_body(GM_A, 128));
    // logMessageInterval -3: 125 ms between Syncs, stale after 375 ms.
    let mut s = time_msg(0, mt::SYNC, 0, gm, 1, 0, 0, T0 + LEAP as i128 * SEC);
    s[33] = (-3i8) as u8;
    p.rx(&mut w, start, T0 + net.d_ms, &s);
    w.tx_wall = T0 + 10 * US;
    p.tick(&mut w, start + 300 * MS);
    assert_eq!(w.sent.len(), 1);
    w.tx_wall = T0 + 400 * 1_000_000;
    p.tick(&mut w, start + 1_300 * MS);
    assert_eq!(w.sent.len(), 1, "1.3 s after a Sync that comes every 125 ms");
}

/// **Canary.** Without the step test the request goes out paired with a `t2`
/// stamped on the clock as it was: the offset would come out half the step
/// off and be fed back to the discipline.
#[test]
fn a_wall_clock_set_between_the_stamps_drops_the_exchange() {
    let (mut p, mut w, net, gm, start) = synced_port();
    // The clock was stepped forward 10 s between the Sync and the request.
    w.tx_wall = T0 + 10 * US + 10 * SEC;
    p.tick(&mut w, start + MS);
    assert_eq!(w.sent.len(), 1);
    answer_delay_req(&mut p, &mut w, net, start + MS, gm, T0 + MS as i128);
    assert!(w.samples.is_empty(), "no sample from a pair that straddles a step");
    // Nothing from before the step is used again: no request until a new Sync.
    announce_only(&mut p, &mut w, gm, start, 1_500, 2_500);
    assert_eq!(w.sent.len(), 1);
}

#[test]
fn a_slew_between_the_stamps_is_not_a_step() {
    let (mut p, mut w, net, gm, start) = synced_port();
    // 1 s later the wall clock has gained 400 us (400 ppm): the discipline's own
    // slew.
    w.tx_wall = T0 + 10 * US + SEC + 400 * US;
    p.tick(&mut w, start + 1_000 * MS);
    answer_delay_req(&mut p, &mut w, net, start + 1_000 * MS, gm, T0 + SEC + 400 * US);
    assert_eq!(w.samples.len(), 1);
}

#[test]
fn a_wall_clock_set_while_the_request_is_in_flight_gives_no_sample() {
    let (mut p, mut w, gm_net, gm, start) = {
        let (p, w, n, g, s) = synced_port();
        (p, w, n, g, s)
    };
    w.tx_wall = T0 + 10 * US;
    p.tick(&mut w, start);
    let (h, _) = w.last_sent();
    let t4 = T0 + gm_net.d_sm + LEAP as i128 * SEC;
    // The answer arrives 20 us (monotonic) later, but the wall clock reads 5 s
    // more than it did at the request.
    let r = response_msg(0, mt::DELAY_RESP, 0, gm, h.seq, 0, 0, t4, slave_port());
    p.rx(&mut w, start + 20_000, T0 + 10 * US + 5 * SEC, &r);
    assert!(w.samples.is_empty());
}

/// The kernel stepped the clock in answer to a sample: the Sync that sample was
/// made from and every stamp since are on the old clock.
#[test]
fn after_a_step_the_old_stamps_are_not_paired_again() {
    for (verdict, requests) in [(Sampled::Slewed, 2), (Sampled::Stepped, 1)] {
        let (mut p, mut w, net, gm, start) = synced_port();
        w.verdict = verdict;
        w.tx_wall = T0 + 10 * US;
        p.tick(&mut w, start);
        answer_delay_req(&mut p, &mut w, net, start, gm, T0 + 10 * US);
        assert_eq!(w.samples.len(), 1);
        // The next request is due 1 s later, the Sync 1 s old.
        w.tx_wall = T0 + 10 * US + SEC;
        p.rx(&mut w, start + 1_000 * MS, 0, &announce_msg(0, 0, gm, 9, flags_utc(), &announce_body(GM_A, 128)));
        p.tick(&mut w, start + 1_000 * MS);
        assert_eq!(w.sent.len(), requests, "{verdict:?}");
    }
}

#[test]
fn clock_moved_tolerates_jitter_and_slew_and_nothing_more() {
    let m = 1_000_000_000u64;
    assert!(!port::clock_moved(0, 0, SEC, m), "equal");
    assert!(!port::clock_moved(0, 0, SEC + 1_900_000, m), "stamp jitter");
    assert!(!port::clock_moved(0, 0, SEC + 1_400_000, m), "a slew at the limit");
    assert!(port::clock_moved(0, 0, SEC + 5_000_000, m), "5 ms in a second is a step");
    assert!(port::clock_moved(0, 0, SEC - 5_000_000, m), "backwards too");
    assert!(port::clock_moved(0, 0, 30 * SEC, m), "set forward");
}

// ── The transport helpers ───────────────────────────────────────────────────

#[test]
fn the_domain_comes_from_the_clock_row_view() {
    assert_eq!(link::domain_of(Some(0)), Some(0));
    assert_eq!(link::domain_of(Some(127)), Some(127));
    // A row without a domain has no node.
    assert_eq!(link::domain_of(None), None);
    // Out of u8 range is not truncated into a domain.
    assert_eq!(link::domain_of(Some(300)), None);
}

#[test]
fn identities_are_unique_per_address() {
    assert_ne!(link::ip_identity([10, 0, 2, 15]), link::ip_identity([10, 0, 2, 16]));
}
