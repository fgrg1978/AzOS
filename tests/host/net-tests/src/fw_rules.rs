// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The built-in firewall (`crates/net/net/src/filter.rs`, `Firewall`): the rule
//! table compiled from the topology's `[firewall.NAME]` rows, the default
//! policy, the flow table that lets the answer to an accepted flow through, and
//! its bound.
//!
//! Most tests call the filter the way the stack does at each hook, with whole
//! IPv4 packets; the last ones put it on the real stack (`ip::handle`,
//! `ip::send`) and read the wire.
//!
//! **Canary discipline.** A pass that depends on the flow table has its mirror:
//! the same packet with no flow behind it is refused, so a table that lets
//! everything through (or a policy that never refuses) fails the mirror.

use crate::NET_SERIAL as SERIAL;
use crate::filter::{self, Firewall, Hook, PacketFilter, PacketView, FwRule, Verdict};
use crate::{arp, ip, wire};

const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
const OUR_IP: [u8; 4] = [10, 0, 0, 2];
const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const PEER_IP: [u8; 4] = [10, 0, 0, 9];
const FAR_IP: [u8; 4] = [192, 168, 7, 7];
const T0: u64 = 50_000;
const SEC: u64 = azos_drv_sys::timebase::TIMER_FREQ;
const UDP_S: u64 = azos_limits::FIREWALL_UDP_TIMEOUT_S as u64;
const TCP_S: u64 = azos_limits::FIREWALL_TCP_TIMEOUT_S as u64;
const HALF_OPEN_S: u64 = 20;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;
const PROTO_TCP: u8 = ip::IP_PROTO_TCP;
const PROTO_UDP: u8 = ip::IP_PROTO_UDP;

struct Session(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

impl Drop for Session {
    fn drop(&mut self) {
        filter::reset_for_test();
    }
}

fn begin() -> Session {
    let g = Session(SERIAL.lock().unwrap_or_else(|e| e.into_inner()));
    filter::reset_for_test();
    azos_drv_irqchip::clint::set_test_time(T0);
    crate::inbound::reset();
    wire::reset();
    arp::cache_reset_for_test();
    arp::insert(PEER_IP, PEER_MAC);
    ip::arp_txq_reset_for_test();
    g
}

fn at(secs_after_t0: u64) {
    azos_drv_irqchip::clint::set_test_time(T0 + secs_after_t0 * SEC);
}

fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

// ── Packets and rules ───────────────────────────────────────────────────────

fn ip_packet(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut hdr = [0u8; 20];
    ip::build_header(&mut hdr, proto, &src, &dst, l4.len() as u16);
    let mut p = hdr.to_vec();
    p.extend_from_slice(l4);
    p
}

fn udp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&8u16.to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    ip_packet(src, dst, PROTO_UDP, &l4)
}

fn tcp(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&sport.to_be_bytes());
    l4[2..4].copy_from_slice(&dport.to_be_bytes());
    l4[12] = 5 << 4;
    l4[13] = flags;
    ip_packet(src, dst, PROTO_TCP, &l4)
}

fn icmp_echo(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut l4 = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
    let mut acc: u32 = 0;
    for pair in l4.chunks(2) {
        acc += u32::from(pair[0]) << 8 | u32::from(pair[1]);
    }
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    let cs = (!(acc as u16)).to_be_bytes();
    l4[2] = cs[0];
    l4[3] = cs[1];
    ip_packet(src, dst, ip::IP_PROTO_ICMP, &l4)
}

fn judge(fw: &Firewall, hook: Hook, pkt: &[u8]) -> Verdict {
    fw.check(hook, &PacketView::parse(pkt).expect("a whole IPv4 packet"), None)
}

fn rule(hook: Hook, proto: u8, ports: Option<(u16, u16)>, net: Option<([u8; 4], u8)>, action: Verdict) -> FwRule {
    let (port_lo, port_hi) = ports.unwrap_or((0, 0));
    let (addr, net_len) = net.unwrap_or(([0; 4], 0));
    FwRule { hook, proto, port_lo, port_hi, net: u32::from_be_bytes(addr), net_len, action }
}

fn firewall(inbound: Verdict, rules: &[FwRule]) -> Firewall {
    let fw = Firewall::new();
    assert_eq!(fw.load(inbound, rules.iter().copied(), 0x5EED_1234), Some(rules.len()));
    fw
}

/// A gateway: inbound dropped unless a rule or a flow lets it in.
fn gateway(rules: &[FwRule]) -> Firewall {
    firewall(Verdict::Drop, rules)
}

// ── Rules ───────────────────────────────────────────────────────────────────

#[test]
fn first_matching_rule_decides_and_order_matters() {
    let _g = begin();
    let deny_ten = rule(Hook::Ingress, PROTO_TCP, Some((22, 22)), Some(([10, 0, 0, 0], 8)), Verdict::Drop);
    let allow_ssh = rule(Hook::Ingress, PROTO_TCP, Some((22, 22)), None, Verdict::Accept);
    let from_ten = tcp(PEER_IP, 40000, OUR_IP, 22, SYN);
    let from_far = tcp(FAR_IP, 40000, OUR_IP, 22, SYN);

    let a = firewall(Verdict::Drop, &[deny_ten, allow_ssh]);
    assert_eq!(judge(&a, Hook::Ingress, &from_ten), Verdict::Drop, "the specific rule first");
    assert_eq!(judge(&a, Hook::Ingress, &from_far), Verdict::Accept, "the general rule for the rest");

    // The same two rules the other way round: the general one shadows.
    let b = firewall(Verdict::Drop, &[allow_ssh, deny_ten]);
    assert_eq!(judge(&b, Hook::Ingress, &from_ten), Verdict::Accept);
    assert_eq!(judge(&b, Hook::Ingress, &from_far), Verdict::Accept);
}

#[test]
fn a_rule_matches_on_hook_protocol_port_range_and_prefix() {
    let _g = begin();
    let fw = firewall(Verdict::Drop, &[
        rule(Hook::Ingress, PROTO_TCP, Some((8000, 8010)), Some(([10, 0, 0, 0], 24)), Verdict::Accept),
    ]);
    let ok = |p: &[u8]| judge(&fw, Hook::Ingress, p) == Verdict::Accept;
    assert!(ok(&tcp(PEER_IP, 1, OUR_IP, 8000, SYN)), "first port");
    assert!(ok(&tcp(PEER_IP, 1, OUR_IP, 8010, SYN)), "last port");
    assert!(!ok(&tcp(PEER_IP, 1, OUR_IP, 7999, SYN)), "below the range");
    assert!(!ok(&tcp(PEER_IP, 1, OUR_IP, 8011, SYN)), "above the range");
    assert!(!ok(&udp(PEER_IP, 1, OUR_IP, 8005)), "another protocol");
    assert!(!ok(&tcp([10, 0, 1, 9], 1, OUR_IP, 8005, SYN)), "outside the /24");
    assert!(ok(&tcp([10, 0, 0, 255], 1, OUR_IP, 8005, SYN)), "last address of the /24");
    // The port is the destination port: a source port in the range is not enough.
    assert!(!ok(&tcp(PEER_IP, 8005, OUR_IP, 9, SYN)));
    // The rule is for ingress: the same packet out is judged by the egress default.
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, 1, PEER_IP, 8005, SYN)), Verdict::Accept);
}

#[test]
fn remote_prefix_is_the_destination_of_an_outbound_packet() {
    let _g = begin();
    let fw = firewall(Verdict::Accept, &[
        rule(Hook::Egress, 0, None, Some(([192, 168, 0, 0], 16)), Verdict::Reject),
        rule(Hook::Forward, PROTO_UDP, Some((53, 53)), None, Verdict::Drop),
    ]);
    assert_eq!(judge(&fw, Hook::Egress, &udp(OUR_IP, 5, FAR_IP, 9)), Verdict::Reject);
    assert_eq!(judge(&fw, Hook::Egress, &udp(OUR_IP, 5, PEER_IP, 9)), Verdict::Accept);
    // Mirror: as a source address the prefix means nothing to an egress rule.
    assert_eq!(judge(&fw, Hook::Egress, &udp(FAR_IP, 5, PEER_IP, 9)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Forward, &udp(PEER_IP, 5, FAR_IP, 53)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Forward, &udp(PEER_IP, 5, FAR_IP, 54)), Verdict::Accept);
}

#[test]
fn every_verdict_a_row_can_name_is_returned() {
    let _g = begin();
    let fw = firewall(Verdict::Accept, &[
        rule(Hook::Ingress, PROTO_UDP, Some((1, 1)), None, Verdict::Accept),
        rule(Hook::Ingress, PROTO_UDP, Some((2, 2)), None, Verdict::Drop),
        rule(Hook::Ingress, PROTO_UDP, Some((3, 3)), None, Verdict::Reject),
    ]);
    let v = |port| judge(&fw, Hook::Ingress, &udp(PEER_IP, 9, OUR_IP, port));
    assert_eq!((v(1), v(2), v(3)), (Verdict::Accept, Verdict::Drop, Verdict::Reject));
}

#[test]
fn a_full_rule_table_loads_and_one_more_is_refused_unchanged() {
    let _g = begin();
    let allow = rule(Hook::Ingress, PROTO_UDP, Some((7, 7)), None, Verdict::Accept);
    let fw = Firewall::new();
    assert_eq!(fw.load(Verdict::Drop, core::iter::repeat(allow).take(filter::MAX_RULES), 1), Some(filter::MAX_RULES));
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 9, OUR_IP, 7)), Verdict::Accept);
    // filter::MAX_RULES + 1 rules: refused, and the table that was loaded still answers.
    assert_eq!(fw.load(Verdict::Accept, core::iter::repeat(allow).take(filter::MAX_RULES + 1), 1), None);
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 9, OUR_IP, 8)), Verdict::Drop, "policy still Drop");
}

// ── Default policy ──────────────────────────────────────────────────────────

#[test]
fn gateway_policy_drops_inbound_and_accepts_outbound() {
    let _g = begin();
    let fw = gateway(&[]);
    assert!(fw.needed());
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 9, OUR_IP, 5000)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 9, OUR_IP, 22, SYN)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Ingress, &icmp_echo(PEER_IP, OUR_IP)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Forward, &udp(PEER_IP, 9, FAR_IP, 53)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Egress, &udp(OUR_IP, 9, PEER_IP, 5000)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Egress, &icmp_echo(OUR_IP, PEER_IP)), Verdict::Accept);
}

#[test]
fn accepting_policy_with_nothing_to_refuse_is_not_needed() {
    let _g = begin();
    assert!(!firewall(Verdict::Accept, &[]).needed(), "no rows: not installed at all");
    let allow = rule(Hook::Ingress, PROTO_TCP, Some((22, 22)), None, Verdict::Accept);
    assert!(!firewall(Verdict::Accept, &[allow]).needed(), "rows that only accept");
    // Mirrors: any refusing row, or a dropping policy, makes it needed.
    let deny_out = rule(Hook::Egress, PROTO_TCP, Some((25, 25)), None, Verdict::Drop);
    assert!(firewall(Verdict::Accept, &[allow, deny_out]).needed());
    assert!(firewall(Verdict::Drop, &[]).needed());
    let fw = firewall(Verdict::Accept, &[]);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 9, OUR_IP, 22, SYN)), Verdict::Accept);
}

#[test]
fn rows_win_over_the_policy_both_ways() {
    let _g = begin();
    let fw = gateway(&[rule(Hook::Ingress, PROTO_TCP, Some((22, 22)), None, Verdict::Accept)]);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 9, OUR_IP, 22, SYN)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 9, OUR_IP, 23, SYN)), Verdict::Drop);

    let fw = firewall(Verdict::Accept, &[rule(Hook::Ingress, PROTO_TCP, Some((23, 23)), None, Verdict::Drop)]);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 9, OUR_IP, 23, SYN)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 9, OUR_IP, 22, SYN)), Verdict::Accept);
}

// ── Established flows ───────────────────────────────────────────────────────

#[test]
fn the_answer_to_an_outbound_udp_datagram_passes_and_strangers_do_not() {
    let _g = begin();
    let fw = gateway(&[]);
    let request = udp(OUR_IP, 4444, PEER_IP, 53);
    let answer = udp(PEER_IP, 53, OUR_IP, 4444);

    // Mirror: the same answer with nothing behind it is dropped.
    assert_eq!(judge(&fw, Hook::Ingress, &answer), Verdict::Drop);

    assert_eq!(judge(&fw, Hook::Egress, &request), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &answer), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &answer), Verdict::Accept, "and the next one");
    assert_eq!(judge(&fw, Hook::Egress, &request), Verdict::Accept);
    // Not the flow: another peer, another port on the same peer, another protocol.
    assert_eq!(judge(&fw, Hook::Ingress, &udp(FAR_IP, 53, OUR_IP, 4444)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 54, OUR_IP, 4444)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 53, OUR_IP, 4445)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 53, OUR_IP, 4444, ACK)), Verdict::Drop);
    assert_eq!(fw.tracked(now()), 1);
}

#[test]
fn an_outbound_tcp_connection_passes_both_ways_once_answered() {
    let _g = begin();
    let fw = gateway(&[]);
    let (c, s) = (40000, 443);
    // Mirrors: mid-stream segments and a bare SYN-ACK with no SYN before them.
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, SYN | ACK)), Verdict::Drop);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Drop);

    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, SYN)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, SYN | ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Accept);
    // A different connection of the same peer is not this one.
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c + 1, ACK)), Verdict::Drop);
    assert_eq!(fw.tracked(now()), 1);
}

#[test]
fn an_inbound_flow_a_rule_opened_is_answered_whatever_the_rules_say_outbound() {
    let _g = begin();
    let fw = gateway(&[
        rule(Hook::Egress, 0, None, None, Verdict::Drop), // nothing may be started from here ...
        rule(Hook::Ingress, PROTO_TCP, Some((22, 22)), None, Verdict::Accept),
    ]);
    // ... so a SYN-ACK of our own, as a fresh egress packet, is refused ...
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, 22, FAR_IP, 5555, SYN | ACK)), Verdict::Drop);
    // ... but once the peer's SYN was accepted, it is the answer to that flow.
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(FAR_IP, 5555, OUR_IP, 22, SYN)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, 22, FAR_IP, 5555, SYN | ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(FAR_IP, 5555, OUR_IP, 22, ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, 22, FAR_IP, 5555, ACK)), Verdict::Accept);
    // The rule still decides for a peer that has no flow.
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(FAR_IP, 6666, OUR_IP, 23, SYN)), Verdict::Drop);
}

#[test]
fn a_syn_in_the_original_direction_is_judged_by_the_rules_again() {
    let _g = begin();
    // Port 22 open to the 10/8 only.
    let fw = gateway(&[rule(Hook::Ingress, PROTO_TCP, Some((22, 22)), Some(([10, 0, 0, 0], 8)), Verdict::Accept)]);
    let syn = tcp(PEER_IP, 5555, OUR_IP, 22, SYN);
    assert_eq!(judge(&fw, Hook::Ingress, &syn), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, 22, PEER_IP, 5555, SYN | ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, 5555, OUR_IP, 22, ACK)), Verdict::Accept);
    // A SYN again on the answered tuple is a new connection attempt, judged by
    // the rules: from the same address it is allowed; the flow starts over.
    assert_eq!(judge(&fw, Hook::Ingress, &syn), Verdict::Accept);
    // Mirror: only the SYN loses the pass; the table never let a stranger in.
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(FAR_IP, 5555, OUR_IP, 22, SYN)), Verdict::Drop);
    assert_eq!(fw.tracked(now()), 1, "the same flow, started over, not a second entry");

    // Started over means unanswered again: with no SYN-ACK to the new SYN the
    // flow is gone after the half-open time, not after the TCP timeout.
    let out = gateway(&[]);
    let (c, s) = (40000, 443);
    judge(&out, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, SYN));
    judge(&out, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, SYN | ACK));
    at(100);
    assert_eq!(judge(&out, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, SYN)), Verdict::Accept);
    at(100 + HALF_OPEN_S + 1);
    assert_eq!(judge(&out, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Drop);
    // Mirror: the same gap with no new SYN leaves the established flow alone.
    let quiet = gateway(&[]);
    at(0);
    judge(&quiet, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, SYN));
    judge(&quiet, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, SYN | ACK));
    at(100 + HALF_OPEN_S + 1);
    assert_eq!(judge(&quiet, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Accept);
}

#[test]
fn a_flow_with_only_refusing_outbound_rules_is_not_tracked() {
    let _g = begin();
    let fw = firewall(Verdict::Accept, &[rule(Hook::Egress, PROTO_TCP, Some((25, 25)), None, Verdict::Drop)]);
    assert!(fw.needed());
    assert_eq!(judge(&fw, Hook::Egress, &udp(OUR_IP, 4444, PEER_IP, 53)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, 4444, PEER_IP, 25, SYN)), Verdict::Drop);
    assert_eq!(fw.tracked(now()), 0, "nothing inbound can be refused: nothing to remember");
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 53, OUR_IP, 4444)), Verdict::Accept);
}

#[test]
fn a_flow_beats_an_inbound_refusal_under_an_accepting_policy() {
    let _g = begin();
    let fw = firewall(Verdict::Accept, &[rule(Hook::Ingress, 0, None, Some(([10, 0, 0, 0], 8)), Verdict::Drop)]);
    // Mirror: unsolicited from the refused prefix is dropped ...
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 53, OUR_IP, 4444)), Verdict::Drop);
    // ... the answer to our own datagram is not.
    assert_eq!(judge(&fw, Hook::Egress, &udp(OUR_IP, 4444, PEER_IP, 53)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &udp(PEER_IP, 53, OUR_IP, 4444)), Verdict::Accept);
}

#[test]
fn a_host_talking_to_itself_passes_both_ways_and_a_stranger_with_the_tuple_does_not() {
    let _g = begin();
    let fw = gateway(&[]);
    let hello = tcp(OUR_IP, 1000, OUR_IP, 2000, SYN);
    // Mirror: the same packet arriving with no egress behind it.
    assert_eq!(judge(&fw, Hook::Ingress, &hello), Verdict::Drop);

    assert_eq!(judge(&fw, Hook::Egress, &hello), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &hello), Verdict::Accept, "the copy the stack loops back");
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, 2000, OUR_IP, 1000, SYN | ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(OUR_IP, 2000, OUR_IP, 1000, SYN | ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(OUR_IP, 1001, OUR_IP, 2000, SYN)), Verdict::Drop, "another port");
}

// ── Lifetimes ───────────────────────────────────────────────────────────────

#[test]
fn a_udp_flow_idles_out_and_every_packet_renews_it() {
    let _g = begin();
    let fw = gateway(&[]);
    let (req, ans) = (udp(OUR_IP, 4444, PEER_IP, 53), udp(PEER_IP, 53, OUR_IP, 4444));
    assert_eq!(judge(&fw, Hook::Egress, &req), Verdict::Accept);
    at(UDP_S - 1);
    assert_eq!(judge(&fw, Hook::Ingress, &ans), Verdict::Accept, "just inside the timeout");
    at(2 * UDP_S - 2);
    assert_eq!(judge(&fw, Hook::Ingress, &ans), Verdict::Accept, "renewed by the answer");
    at(3 * UDP_S - 2 + 1);
    assert_eq!(judge(&fw, Hook::Ingress, &ans), Verdict::Drop, "idle for the whole timeout");
    assert_eq!(fw.tracked(now()), 0);
}

#[test]
fn an_unanswered_syn_is_held_for_twenty_seconds_an_established_flow_for_the_tcp_timeout() {
    let _g = begin();
    let fw = gateway(&[]);
    let syn = tcp(OUR_IP, 40000, PEER_IP, 443, SYN);
    let synack = tcp(PEER_IP, 443, OUR_IP, 40000, SYN | ACK);
    let data = tcp(PEER_IP, 443, OUR_IP, 40000, ACK);
    assert!(HALF_OPEN_S < TCP_S && HALF_OPEN_S < UDP_S * 100, "the constants are what the test assumes");

    assert_eq!(judge(&fw, Hook::Egress, &syn), Verdict::Accept);
    at(HALF_OPEN_S + 1);
    assert_eq!(judge(&fw, Hook::Ingress, &synack), Verdict::Drop, "the SYN-ACK came too late");
    assert_eq!(fw.tracked(now()), 0);

    // Answered in time: the flow now lives for the TCP timeout.
    assert_eq!(judge(&fw, Hook::Egress, &syn), Verdict::Accept);
    at(HALF_OPEN_S + 1 + 5);
    assert_eq!(judge(&fw, Hook::Ingress, &synack), Verdict::Accept);
    at(HALF_OPEN_S + 1 + 5 + TCP_S - 1);
    assert_eq!(judge(&fw, Hook::Ingress, &data), Verdict::Accept);
    at(HALF_OPEN_S + 1 + 5 + 2 * TCP_S);
    assert_eq!(judge(&fw, Hook::Ingress, &data), Verdict::Drop);
}

#[test]
fn a_closing_flow_still_passes_the_last_packets_and_then_goes() {
    let _g = begin();
    let fw = gateway(&[]);
    let (c, s) = (40000, 443);
    judge(&fw, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, SYN));
    judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, SYN | ACK));
    // The peer closes: its FIN and our last ACK pass ...
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, FIN | ACK)), Verdict::Accept);
    at(HALF_OPEN_S - 1);
    assert_eq!(judge(&fw, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, ACK)), Verdict::Accept);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Accept);
    // ... and the entry does not outlive the half-open time by the TCP timeout.
    at(2 * HALF_OPEN_S);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Drop);
}

#[test]
fn an_rst_shortens_the_flow_but_does_not_end_it_outright() {
    let _g = begin();
    let fw = gateway(&[]);
    let (c, s) = (40001, 443);
    judge(&fw, Hook::Egress, &tcp(OUR_IP, c, PEER_IP, s, SYN));
    judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, SYN | ACK));
    // An RST nobody checked (the table does not see sequence numbers) passes ...
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, RST)), Verdict::Accept);
    // ... and the flow it names is still there for a moment.
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Accept);
    at(HALF_OPEN_S + 1);
    assert_eq!(judge(&fw, Hook::Ingress, &tcp(PEER_IP, s, OUR_IP, c, ACK)), Verdict::Drop);
}

// ── The bound ───────────────────────────────────────────────────────────────

/// Open flow number `n`: one egress datagram, one answer. `true` if the
/// datagram was let out.
fn open_answered_udp(fw: &Firewall, n: usize) -> bool {
    let (sport, peer) = (1024 + (n % 60000) as u16, [172, 16, (n / 60000) as u8, 1]);
    if judge(fw, Hook::Egress, &udp(OUR_IP, sport, peer, 9)) != Verdict::Accept {
        return false;
    }
    assert_eq!(judge(fw, Hook::Ingress, &udp(peer, 9, OUR_IP, sport)), Verdict::Accept);
    true
}

#[test]
fn the_flow_table_never_holds_more_than_its_bound_and_refuses_what_does_not_fit() {
    let _g = begin();
    let fw = gateway(&[]);
    let offered = 8 * filter::CT_SLOTS;
    let opened = (0..offered).filter(|&n| open_answered_udp(&fw, n)).count();

    assert!(opened <= filter::CT_SLOTS, "{opened} flows opened, the bound is {}", filter::CT_SLOTS);
    assert_eq!(fw.tracked(now()), opened, "every flow let out is a flow remembered");
    assert!(opened < offered, "a table that takes everything is not bounded");
    assert!(opened >= filter::CT_SLOTS / 2, "{opened} of {}: the sets fill evenly enough to be useful", filter::CT_SLOTS);

    // Full of answered flows: the next one is refused at the egress hook ...
    assert_eq!(judge(&fw, Hook::Egress, &udp(OUR_IP, 5, FAR_IP, 5)), Verdict::Drop, "not tracked, not started");
    // ... and the flows that are in still pass.
    assert!(!open_answered_udp(&fw, 0) || fw.tracked(now()) == opened);

    // Idle long enough, the table empties and takes new flows again.
    at(UDP_S + 1);
    assert_eq!(fw.tracked(now()), 0);
    assert_eq!(judge(&fw, Hook::Egress, &udp(OUR_IP, 5, FAR_IP, 5)), Verdict::Accept);
}

#[test]
fn a_flood_of_unanswered_flows_cannot_push_out_an_established_one() {
    let _g = begin();
    let fw = gateway(&[rule(Hook::Ingress, PROTO_UDP, Some((9000, 9000)), None, Verdict::Accept)]);
    // One established flow, first.
    assert!(open_answered_udp(&fw, 0));
    let (sport, peer) = (1024u16, [172, 16, 0, 1]);

    // A flood of datagrams from strangers to the open port: each a new flow, none answered.
    for n in 0..8 * filter::CT_SLOTS {
        let src = [100, 64, (n / 250) as u8, (n % 250) as u8 + 1];
        assert_eq!(judge(&fw, Hook::Ingress, &udp(src, 4000, OUR_IP, 9000)), Verdict::Accept);
    }
    let held = fw.tracked(now());
    assert!(held <= filter::CT_SLOTS, "{held} flows held, the bound is {}", filter::CT_SLOTS);
    assert!(held > filter::CT_SLOTS * 3 / 4, "{held} of {}: the flood really did fill the sets", filter::CT_SLOTS);
    assert_eq!(judge(&fw, Hook::Ingress, &udp(peer, 9, OUR_IP, sport)), Verdict::Accept, "the answered flow stayed");
}

#[test]
fn loading_forgets_every_flow() {
    let _g = begin();
    let fw = gateway(&[]);
    assert!(open_answered_udp(&fw, 3));
    assert_eq!(fw.tracked(now()), 1);
    assert_eq!(fw.load(Verdict::Drop, core::iter::empty(), 7), Some(0));
    assert_eq!(fw.tracked(now()), 0);
    assert_eq!(judge(&fw, Hook::Ingress, &udp([172, 16, 0, 1], 9, OUR_IP, 1027)), Verdict::Drop);
}

// ── On the stack ────────────────────────────────────────────────────────────

fn install(fw: &'static Firewall) {
    filter::set_filter(fw);
}

fn leaked(inbound: Verdict, rules: &[FwRule]) -> &'static Firewall {
    Box::leak(Box::new(firewall(inbound, rules)))
}

#[test]
fn on_the_stack_a_gateway_does_not_answer_a_ping_until_a_row_says_so() {
    let _g = begin();
    install(leaked(Verdict::Drop, &[]));
    ip::handle(&icmp_echo(PEER_IP, OUR_IP), &OUR_MAC, &OUR_IP);
    assert_eq!(wire::sent_count(), 0, "ICMP is stateless: no row, no answer");
    assert_eq!(filter::stats().refused, 1);

    // Mirror: the same ping with a row for it is answered.
    install(leaked(Verdict::Drop, &[rule(Hook::Ingress, ip::IP_PROTO_ICMP, None, Some((PEER_IP, 32)), Verdict::Accept)]));
    ip::handle(&icmp_echo(PEER_IP, OUR_IP), &OUR_MAC, &OUR_IP);
    assert_eq!(wire::sent_count(), 1);
    assert_eq!(wire::sent()[0].proto, ip::IP_PROTO_ICMP);
}

#[test]
fn on_the_stack_an_outbound_row_drops_or_rejects_what_the_caller_sent() {
    let _g = begin();
    install(leaked(Verdict::Accept, &[
        rule(Hook::Egress, PROTO_UDP, Some((7, 7)), None, Verdict::Drop),
        rule(Hook::Egress, PROTO_UDP, Some((8, 8)), None, Verdict::Reject),
    ]));
    let datagram = |port: u16| {
        let mut l4 = vec![0u8; 8];
        l4[2..4].copy_from_slice(&port.to_be_bytes());
        l4[5] = 8;
        ip::send(&OUR_MAC, &OUR_IP, &PEER_IP, PROTO_UDP, &l4)
    };
    assert_eq!(datagram(7), 0, "dropped: reads as sent");
    assert_eq!(wire::sent_count(), 0);
    assert_eq!(datagram(8), -1, "rejected: the caller is told");
    assert_eq!(wire::sent_count(), 0);
    assert_eq!(datagram(9), 0, "mirror: another port leaves");
    assert_eq!(wire::sent_count(), 1);
}
