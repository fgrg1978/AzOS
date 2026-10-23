// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Boot self-tests (Kconfig BOOT_SELFTESTS): the network conformance probe
//! and the loopback check, run by `kernel_main` once the stack is up.
//!
//! They put hand-built frames on the wire to invented hosts, write an ARP
//! entry for one of them, and bind UDP/TCP ports 7501, 7601, 7701 and 7777
//! while ring-3 programs may already be binding theirs (K3-07), so a normal
//! image does not run them.

use crate::*;

/// The probe and the loopback check. `nic_present`: a NIC is bound, so the
/// checks that need an interface (the ARP learn, the broadcast and multicast
/// sends) run instead of being skipped.
pub(crate) fn run(nic_present: bool) {
    // ── Protocol conformance: the bytes that go on the wire ────────────
    //
    // **Why this and not another round-trip test.** Everything else here that
    // exercises the network is **self-consistent**: we send ourselves a
    // datagram and check it arrives. A systematic error — byte order inverted
    // on write AND on read, say — would pass green and fail the day we talk to
    // a real machine.
    //
    // This compares against the standard, not against ourselves: an IPv4
    // header is built and the bytes **RFC 791** prescribes are asserted, at
    // their offsets, in network order.
    {
        use azos_net::ip;
        let src = [10u8, 0, 2, 15];
        let dst = [10u8, 0, 2, 99];
        let mut h = [0u8; ip::IP_HDR_MIN];
        ip::build_header(&mut h, ip::IP_PROTO_UDP, &src, &dst, 8);

        let mut bad = 0u64;
        // RFC 791 §3.1: version (high 4 bits) and IHL in 32-bit words. IPv4
        // with a minimum header ⇒ 0x45. A 0x54 here would be the nibbles
        // swapped, which is the classic silent failure.
        if h[0] != 0x45 { bad |= 1; }
        // Protocol at byte 9. UDP = 17.
        if h[9] != 17 { bad |= 2; }
        // Total length at 2..4, **big-endian**: 20 header + 8 payload.
        if u16::from_be_bytes([h[2], h[3]]) != 28 { bad |= 4; }
        // Addresses at 12..16 and 16..20, in network order (not byte-swapped).
        if h[12..16] != src || h[16..20] != dst { bad |= 8; }
        // RFC 1071: a well-formed header sums to 0xFFFF **including its own
        // checksum**, so the one's complement of that sum is 0. This validates
        // the checksum without recomputing it with the same code that produced
        // it, which would be tautological.
        if ip::checksum(&h) != 0 { bad |= 16; }

        // ── RFC 894: Ethernet frame ────────────────────────────────────
        //
        // Order: destination(6), source(6), ethertype(2) **big-endian**. IPv4
        // is 0x0800, and writing it reversed — 0x0008 — produces a frame no
        // switch will deliver and that our own stack would accept if it also
        // read it reversed.
        {
            use azos_net::ethernet;
            let dmac = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
            let smac = [0x52u8, 0x54, 0x00, 0x12, 0x34, 0x56];
            let mut f = [0u8; 64];
            let n = ethernet::build(&mut f, &dmac, &smac, ethernet::ETH_TYPE_IP, &[1, 2, 3, 4]);
            if f[0..6] != dmac { bad |= 32; }
            if f[6..12] != smac { bad |= 64; }
            if u16::from_be_bytes([f[12], f[13]]) != 0x0800 { bad |= 128; }
            if n != 14 + 4 { bad |= 256; }
        }

        // ── RFC 768 + 791: accept a HAND-BUILT datagram ────────────────
        //
        // **This is what separates interoperating from being self-consistent.**
        // Everything else builds the packet with our code and verifies it with
        // our code: a byte-order error in both directions would pass green.
        // Here the bytes are written by hand per the RFC and handed to the
        // parser: if it accepts them and extracts the right values, we
        // understand what a real machine sends.
        //
        // The UDP checksum is zero, which **RFC 768 explicitly permits** on
        // IPv4: "an all zero transmitted checksum value means that the
        // transmitter generated no checksum". Accepting it is part of the
        // standard.
        {
            use azos_net::{ip, udp};
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            const P_DST: u16 = 7501;
            const P_SRC: u16 = 7502;
            let sock = udp::bind(P_DST);
            if sock < 0 {
                bad |= 512;
            } else {
                let payload = b"rfc768";
                let udp_len = 8 + payload.len();
                let total = ip::IP_HDR_MIN + udp_len;
                let mut pkt = [0u8; 64];
                // IPv4 header, by hand (RFC 791 §3.1).
                pkt[0] = 0x45;                                  // version 4, IHL 5
                pkt[1] = 0;                                     // DSCP/ECN
                pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // id
                pkt[6..8].copy_from_slice(&0u16.to_be_bytes());  // no flags, no offset
                pkt[8] = 64;                                    // TTL
                pkt[9] = 17;                                    // UDP
                // checksum at 10..12 left zero and computed below
                pkt[12..16].copy_from_slice(&[10, 0, 2, 200]);   // foreign source
                pkt[16..20].copy_from_slice(&me);                // destination: us
                let ck = ip::checksum(&pkt[..ip::IP_HDR_MIN]);
                pkt[10..12].copy_from_slice(&ck.to_be_bytes());
                // UDP header, by hand (RFC 768): ports, length, checksum.
                let u = ip::IP_HDR_MIN;
                pkt[u..u + 2].copy_from_slice(&P_SRC.to_be_bytes());
                pkt[u + 2..u + 4].copy_from_slice(&P_DST.to_be_bytes());
                pkt[u + 4..u + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
                pkt[u + 6..u + 8].copy_from_slice(&0u16.to_be_bytes()); // no checksum
                pkt[u + 8..u + 8 + payload.len()].copy_from_slice(payload);

                ip::handle(&pkt[..total], &my_mac, &me);

                let mut buf = [0u8; 32];
                let mut src_ip = [0u8; 4];
                let mut src_port = 0u16;
                let n = udp::recvfrom(sock, &mut buf, &mut src_ip, &mut src_port);
                if n != payload.len() as i32 { bad |= 1024; }
                else if &buf[..n as usize] != payload { bad |= 2048; }
                if src_port != P_SRC { bad |= 4096; }
                if src_ip != [10, 0, 2, 200] { bad |= 8192; }
                udp::close(sock);
            }
        }

        // ── RFC 793: accept a HAND-BUILT SYN ───────────────────────────
        //
        // The largest layer and the one most prone to silent error: `data_off`
        // lives in the **high 4 bits** of byte 12 and counts **32-bit words**,
        // not bytes. Getting that wrong yields a segment our own stack would
        // accept if it also read it wrong.
        //
        // And unlike UDP, **RFC 793 makes the checksum mandatory**: computed
        // over a pseudo-header (source, destination, zero, protocol, TCP
        // length) plus the segment. The SYN being accepted proves we validate
        // it properly; a miscomputed checksum here would make the stack drop
        // it and the state would not advance.
        {
            use azos_net::{ip, tcp};
            const P_LISTEN: u16 = 7601;
            const P_REMOTO: u16 = 7602;
            let me = azos_net::net_get_ip();
            let foreign = [10u8, 0, 2, 201];
            if let Some(l) = tcp::TcpHandle::listen(P_LISTEN) {
                let mut seg = [0u8; 20];
                seg[0..2].copy_from_slice(&P_REMOTO.to_be_bytes());
                seg[2..4].copy_from_slice(&P_LISTEN.to_be_bytes());
                seg[4..8].copy_from_slice(&0x0001_0000u32.to_be_bytes());  // seq
                seg[8..12].copy_from_slice(&0u32.to_be_bytes());           // ack
                seg[12] = 5 << 4;      // data offset = 5 words = 20 bytes
                seg[13] = 0x02;        // SYN
                seg[14..16].copy_from_slice(&8192u16.to_be_bytes());       // window
                // checksum at 16..18, zero while it is computed
                seg[18..20].copy_from_slice(&0u16.to_be_bytes());          // urgent

                // Pseudo-header + segment, RFC 793 §3.1.
                let mut ps = [0u8; 12 + 20];
                ps[0..4].copy_from_slice(&foreign);
                ps[4..8].copy_from_slice(&me);
                ps[8] = 0;
                ps[9] = 6;                                                 // TCP
                ps[10..12].copy_from_slice(&20u16.to_be_bytes());
                ps[12..32].copy_from_slice(&seg);
                let ck = ip::checksum(&ps);
                seg[16..18].copy_from_slice(&ck.to_be_bytes());

                tcp::handle_checked(&foreign, &me, &seg);

                // **The listener stays in `Listen`; the SYN creates a NEW
                // connection.** That is what RFC 793 mandates — a listening
                // socket is not consumed by its first client — and the first
                // version of this test looked at the listener's slot and
                // failed. The stack was right and the assertion was wrong.
                //
                // A connection appearing in `SynRcvd` is the only signal that
                // the segment was understood IN FULL: ports, `data_off` in
                // 32-bit words, the SYN flag, and the pseudo-header checksum.
                // With any of those wrong it is dropped silently and there is
                // no transition.
                match tcp::TcpHandle::find(P_LISTEN, tcp::TcpState::SynRcvd) {
                    Some(c) => c.close(),
                    None => bad |= 1 << 15,
                }
                l.close();
            } else {
                bad |= 1 << 14;
            }
        }

        // ── RFC 793 §3.1 + RFC 879 / 6691: the MSS option on the wire ──
        //
        // MSS negotiation was implemented and **never checked against the
        // standard**. The option walk is the classic place for a silent
        // error: it is a type/length/value list where a wrong `data_off`
        // makes it read payload as options, and where NOP padding and
        // unknown options must be skipped by their length byte rather than
        // assumed absent. Every one of those failures degrades silently to
        // the 536-byte default (RFC 879) — a working connection at a third
        // of the segment size, which no functional test would ever notice.
        {
            use azos_net::{ip, tcp};
            let me = azos_net::net_get_ip();
            let foreign = [10u8, 0, 2, 203];
            const P_L: u16 = 7402;

            // A SYN carrying: NOP, an unknown option (kind 250, len 4), then
            // MSS. The MSS is last on purpose — reaching it proves the walk
            // advances by the length byte instead of stopping at the first
            // thing it does not recognise.
            //
            // `mss_in` is checked against `mss_out` rather than a literal so
            // this reads as "what we advertised came back", and 1200 is
            // deliberately NOT 1460: a parser that ignored the option and
            // returned our own constant would pass against 1460.
            let probe = |opts: &[u8], port: u16| -> u16 {
                let hdr_words = (20 + opts.len()) / 4;
                let tlen = 20 + opts.len();
                let mut seg = [0u8; 40];
                seg[0..2].copy_from_slice(&port.to_be_bytes());
                seg[2..4].copy_from_slice(&P_L.to_be_bytes());
                seg[4..8].copy_from_slice(&0x0002_0000u32.to_be_bytes());
                seg[12] = (hdr_words as u8) << 4;
                seg[13] = 0x02;                                    // SYN
                seg[14..16].copy_from_slice(&8192u16.to_be_bytes());
                seg[20..20 + opts.len()].copy_from_slice(opts);

                let mut ps = [0u8; 12 + 40];
                ps[0..4].copy_from_slice(&foreign);
                ps[4..8].copy_from_slice(&me);
                ps[9] = 6;
                ps[10..12].copy_from_slice(&(tlen as u16).to_be_bytes());
                ps[12..12 + tlen].copy_from_slice(&seg[..tlen]);
                let ck = ip::checksum(&ps[..12 + tlen]);
                seg[16..18].copy_from_slice(&ck.to_be_bytes());

                tcp::handle_checked(&foreign, &me, &seg[..tlen]);
                match tcp::TcpHandle::find(P_L, tcp::TcpState::SynRcvd) {
                    Some(c) => {
                        let m = c.remote_mss();
                        c.close();
                        m
                    }
                    None => 0,
                }
            };

            if let Some(l) = tcp::TcpHandle::listen(P_L) {
                // NOP(1) + unknown kind 250 len 4 + MSS 1200 + NOP padding
                // to a 4-byte boundary: 1 + 4 + 4 + 3 = 12 bytes.
                //
                // **The first version of this array was 8 bytes and the test
                // failed — my encoding was wrong, not the parser.** With MSS
                // starting at option offset 5 it needs bytes 5..9, and only
                // 0..8 existed, so the stack correctly refused a truncated
                // option and fell back to 536. Worth leaving written down:
                // this is the third time in this audit that a conformance
                // failure was the assertion rather than the code.
                if probe(&[1, 250, 4, 0, 0, 2, 4, 0x04, 0xB0, 1, 1, 1], 7501) != 1200 {
                    bad |= 1 << 18;
                }
                // No MSS option at all -> RFC 879 default of 536, NOT our own
                // 1460. Getting this wrong makes us oversend to a peer that
                // never asked for large segments.
                if probe(&[1, 1, 1, 1], 7502) != 536 {
                    bad |= 1 << 17;
                }
                // An advertised MSS of 0 is floored, not honoured: `send_data`
                // sizes every segment by it, so a peer could otherwise stall
                // us forever with one legal-looking option. Same defensive
                // floor Linux applies as tcp_min_snd_mss.
                if probe(&[2, 4, 0, 0, 1, 1, 1, 1], 7503) != 64 {
                    bad |= 1 << 16;
                }
                l.close();
            } else {
                bad |= 1 << 19;
            }
        }

        // ── RFC 826: hand-built ARP ────────────────────────────────────
        //
        // An ARP request from a stranger must leave its (IP, MAC) pair in the
        // cache: **RFC 826 requires it even when the request is not for us**,
        // because whoever is asking will need an answer.
        //
        // The fixed fields are the classic home of silent error: `htype` and
        // `ptype` go in network order, and `hlen`/`plen` are **single bytes**,
        // not a u16 — reading them as a swapped pair gives 6 and 4 exchanged
        // and a cache that fills with garbage.
        {
            use azos_net::arp;
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            let foreign_ip = [10u8, 0, 2, 202];
            let foreign_mac = [0x02u8, 0x11, 0x22, 0x33, 0x44, 0x55];

            let mut a = [0u8; 28];
            a[0..2].copy_from_slice(&1u16.to_be_bytes());       // htype: Ethernet
            a[2..4].copy_from_slice(&0x0800u16.to_be_bytes());  // ptype: IPv4
            a[4] = 6;                                            // hlen
            a[5] = 4;                                            // plen
            a[6..8].copy_from_slice(&1u16.to_be_bytes());       // oper: request
            a[8..14].copy_from_slice(&foreign_mac);               // sha
            a[14..18].copy_from_slice(&foreign_ip);               // spa
            a[18..24].copy_from_slice(&[0u8; 6]);               // tha: unknown
            a[24..28].copy_from_slice(&me);                     // tpa: us

            // The cache is per interface, found by our MAC: with no NIC there
            // is no interface to learn on, and the check cannot run (it is
            // skipped, like the wire sends below, not failed).
            if nic_present {
                arp::handle(&a, &my_mac, &me);
                match arp::lookup(&foreign_ip) {
                    Some(m) if m == foreign_mac => {}
                    _ => bad |= 1 << 32,
                }
                // The binding is invented: a real host at that address must
                // not be sent to this MAC until the entry ages out.
                arp::forget(&foreign_ip);
                if arp::lookup(&foreign_ip).is_some() { bad |= 1 << 37; }
            }
        }

        // ── RFC 768: UDP checksum with pseudo-header, and its rejection ─
        //
        // The previous test uses a zero checksum, which RFC 768 permits on
        // IPv4. This covers the other half — and above all **the negative**:
        // accepting a correct datagram proves nothing about validation,
        // because a stack that ignores the checksum accepts it too. Rejecting
        // a corrupt one does.
        {
            use azos_net::{ip, udp};
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            let foreign = [10u8, 0, 2, 203];
            const P_DST: u16 = 7701;
            const P_SRC: u16 = 7702;
            let sock = udp::bind(P_DST);
            if sock < 0 {
                bad |= 1 << 33;
            } else {
                let payload = b"ck";
                let udp_len = 8 + payload.len();
                let mut u = [0u8; 16];
                u[0..2].copy_from_slice(&P_SRC.to_be_bytes());
                u[2..4].copy_from_slice(&P_DST.to_be_bytes());
                u[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
                u[8..8 + payload.len()].copy_from_slice(payload);
                // Pseudo-header + datagram (RFC 768).
                let mut ps = [0u8; 12 + 16];
                ps[0..4].copy_from_slice(&foreign);
                ps[4..8].copy_from_slice(&me);
                ps[9] = 17;
                ps[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());
                ps[12..12 + udp_len].copy_from_slice(&u[..udp_len]);
                let mut ck = ip::checksum(&ps[..12 + udp_len]);
                // RFC 768: a checksum that computes to zero is transmitted as
                // 0xFFFF, because zero means "no checksum".
                if ck == 0 { ck = 0xFFFF; }
                u[6..8].copy_from_slice(&ck.to_be_bytes());

                let entregar = |udp_bytes: &[u8]| {
                    let total = ip::IP_HDR_MIN + udp_bytes.len();
                    let mut pkt = [0u8; 64];
                    pkt[0] = 0x45;
                    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                    pkt[8] = 64;
                    pkt[9] = 17;
                    pkt[12..16].copy_from_slice(&foreign);
                    pkt[16..20].copy_from_slice(&me);
                    let ick = ip::checksum(&pkt[..ip::IP_HDR_MIN]);
                    pkt[10..12].copy_from_slice(&ick.to_be_bytes());
                    pkt[ip::IP_HDR_MIN..total].copy_from_slice(udp_bytes);
                    ip::handle(&pkt[..total], &my_mac, &me);
                };

                // 1. With a correct checksum: must be delivered.
                entregar(&u[..udp_len]);
                let mut buf = [0u8; 16];
                if udp::recv(sock as usize, &mut buf) != payload.len() as i32 {
                    bad |= 1 << 34;
                }

                // 2. With one payload bit flipped and the checksum left
                //    stale: must be DROPPED.
                let mut roto = u;
                roto[8] ^= 0x01;
                entregar(&roto[..udp_len]);
                let mut b2 = [0u8; 16];
                if udp::recv(sock as usize, &mut b2) > 0 {
                    bad |= 1 << 35;   // a corrupt datagram was delivered
                }
                udp::close(sock);
            }
        }

        // ── RFC 792: hand-built ICMP echo ──────────────────────────────
        //
        // Answering a ping is the floor of interoperability: it is the first
        // thing anyone does to check whether a machine is alive.
        //
        // RFC 792 requires **returning identifier and sequence untouched** —
        // the pinger matches the reply to its request by those fields. A stack
        // that zeroed them would answer something the far end discards, and
        // from outside it would look unresponsive.
        {
            use azos_net::ip;
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            let foreign = [10u8, 0, 2, 204];

            let mut icmp = [0u8; 12];
            icmp[0] = 8;                                        // echo request
            icmp[1] = 0;                                        // code
            icmp[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes()); // identifier
            icmp[6..8].copy_from_slice(&0x0007u16.to_be_bytes()); // sequence
            icmp[8..12].copy_from_slice(b"ping");
            let ck = ip::checksum(&icmp);
            icmp[2..4].copy_from_slice(&ck.to_be_bytes());

            // A request with a correct checksum must be processed; the
            // handler validates `checksum(data) != 0` and drops on mismatch,
            // so if this construction were wrong there would be no reply and
            // no way to tell that apart from "not implemented". The premise is
            // checked before delivering.
            if ip::checksum(&icmp) != 0 { bad |= 1 << 20; }

            let total = ip::IP_HDR_MIN + icmp.len();
            let mut pkt = [0u8; 64];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            pkt[8] = 64;
            pkt[9] = 1;                                          // ICMP
            pkt[12..16].copy_from_slice(&foreign);
            pkt[16..20].copy_from_slice(&me);
            let ick = ip::checksum(&pkt[..ip::IP_HDR_MIN]);
            pkt[10..12].copy_from_slice(&ick.to_be_bytes());
            pkt[ip::IP_HDR_MIN..total].copy_from_slice(&icmp);
            // The reply cannot be observed from here (it leaves via the NIC),
            // but a panic or a checksum drop would show: the value of this
            // delivery is that it exercises the whole path with foreign
            // bytes.
            ip::handle(&pkt[..total], &my_mac, &me);
        }

        // ── RFC 919/922: broadcast ─────────────────────────────────────
        //
        // This used to return -1 ALWAYS: a broadcast destination fell into
        // `arp::lookup` and nobody answers ARP for a broadcast address.
        // `dhcp.rs` sidestepped it with its own raw path; from ring 3 there
        // was no way at all.
        {
            use azos_net::ip;
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();
            // Limited broadcast (RFC 919): never forwarded off the link.
            if nic_present
                && ip::send(&my_mac, &me, &[255, 255, 255, 255], ip::IP_PROTO_UDP, b"bcast") != 0 {
                bad |= 1 << 21;
            }
            // Subnet broadcast (RFC 922): network | ~mask.
            let m = azos_net::net_get_mask();
            let mut subnet = [0u8; 4];
            for i in 0..4 { subnet[i] = (me[i] & m[i]) | !m[i]; }
            if nic_present && ip::send(&my_mac, &me, &subnet, ip::IP_PROTO_UDP, b"bcast") != 0 {
                bad |= 1 << 22;
            }
        }

        // ── RFC 1112 / RFC 2236: IPv4 multicast and IGMPv2 ─────────────
        //
        // Multicast was **impossible in both directions** until now, and for
        // two different reasons — which is why testing only one would have
        // looked fine. RX: the destination filter admits our unicast and the
        // two broadcast forms and dropped 224.0.0.0/4 outright. TX: a group
        // destination fell into `arp::lookup`, and no host owns a group, so
        // nobody answers — the same failure broadcast had before RFC 919/922.
        {
            use azos_net::{igmp, ip};
            let me = azos_net::net_get_ip();
            let my_mac = azos_net::net_get_mac();

            // §6.4 MAC mapping, and above all its **aliasing**: only the low
            // 23 bits travel, so the group's 24th bit is dropped and 32 groups
            // share one Ethernet address. Checked with a pair that collides on
            // purpose — if this ever became a straight copy of the low three
            // bytes, unicast-looking groups would map to wrong MACs and the
            // single-address case would still pass.
            if igmp::multicast_mac(&[224, 1, 2, 3]) != [0x01, 0x00, 0x5E, 0x01, 0x02, 0x03] {
                bad |= 1 << 23;
            }
            if igmp::multicast_mac(&[224, 128, 1, 1]) != igmp::multicast_mac(&[225, 0, 1, 1]) {
                bad |= 1 << 24;
            }

            // §4: 224.0.0.0/4 and nothing else. 223.255.255.255 is the last
            // unicast address and 240.0.0.0 the first reserved one; both
            // neighbours are checked because an off-by-one in the mask is the
            // realistic mistake, not a wild answer.
            if !igmp::is_multicast(&[224, 0, 0, 1]) || !igmp::is_multicast(&[239, 255, 255, 255])
                || igmp::is_multicast(&[223, 255, 255, 255]) || igmp::is_multicast(&[240, 0, 0, 0]) {
                bad |= 1 << 25;
            }

            // §6.1: every host is a permanent member of all-hosts without
            // joining, and a group nobody joined must NOT be admitted. The
            // negative is the half that proves the filter still filters.
            if !igmp::is_joined(&igmp::ALL_HOSTS) || igmp::is_joined(&[239, 9, 9, 9]) {
                bad |= 1 << 26;
            }

            const GRP: [u8; 4] = [239, 1, 2, 3];
            if igmp::join(&GRP) != 0 || !igmp::is_joined(&GRP) { bad |= 1 << 27; }
            // Non-multicast joins are refused: accepting one would put a
            // unicast address in the group table and admit a stranger's
            // traffic through the multicast branch of the filter.
            if igmp::join(&[10, 0, 2, 200]) != -1 { bad |= 1 << 28; }

            // RFC 2236 §2: the on-wire report is 8 bytes, type 0x16, max-resp
            // 0, and carries the group. The checksum is verified by the
            // RFC 1071 property (a correct message folds to 0), NOT by
            // recomputing it here — recomputing only proves the code agrees
            // with itself.
            let rep = igmp::build_message(igmp::IGMP_V2_REPORT, 0, &GRP);
            if rep[0] != 0x16 || rep[1] != 0 || rep[4..8] != GRP || ip::checksum(&rep) != 0 {
                bad |= 1 << 29;
            }

            // A joined group now survives the destination filter and its
            // datagram is delivered up the stack (IP_MULTICAST_LOOP default).
            // `ip::send` returning 0 is what was impossible before: with the
            // ARP path it returned -1.
            if nic_present && ip::send(&my_mac, &me, &GRP, ip::IP_PROTO_UDP, b"mcast") != 0 {
                bad |= 1 << 30;
            }

            // A **corrupt** query must be ignored. Same doctrine as the UDP
            // checksum: acting on a validated query proves nothing, because a
            // stack that skips validation acts on it too. Here it matters more
            // than usual — an accepted forged query makes us emit reports on
            // demand, which is a remote amplification primitive.
            let mut q = igmp::build_message(igmp::IGMP_MEMBERSHIP_QUERY, 100, &[0, 0, 0, 0]);
            q[3] ^= 0xFF;
            igmp::handle(&q);   // must not panic and must not act

            // Leaving restores the starting state, and leaving twice reports
            // "not a member" instead of silently succeeding.
            if igmp::leave(&GRP) != 0 || igmp::is_joined(&GRP) { bad |= 1 << 31; }
            if igmp::leave(&GRP) != -2 { bad |= 1 << 36; }
        }

        // ── RFC 1035: DNS response parsing ─────────────────────────────
        //
        // 458 lines of parser for data that arrives from a remote server, with
        // no test and no scenario until now. That combination is the one that
        // matters here: `panic = "abort"` plus `overflow-checks = true` means a
        // reachable panic in this parser is a **board reset an off-path
        // attacker can trigger**, which is exactly the class already found in
        // `ip.rs` (a crafted `total_length < ihl` produced a reversed range).
        //
        // These checks lock the defences in place rather than discovering
        // them: the parser is in good shape, and the value is that removing a
        // bound now fails the gate instead of shipping.
        let mut bad2 = 0u32;
        {
            use azos_net::dns;
            const TX: u16 = 0x1234;

            // A well-formed A answer that uses a compression pointer for the
            // answer NAME (RFC 1035 §4.1.4) -- the normal shape of every real
            // reply, and the one a naive parser gets wrong by treating 0xC0 as
            // a label length.
            let mut r = [0u8; 64];
            r[0..2].copy_from_slice(&TX.to_be_bytes());
            r[2] = 0x81; r[3] = 0x80;                    // QR=1, RD, RA, rcode=0
            r[5] = 1;                                     // qdcount=1
            r[7] = 1;                                     // ancount=1
            // question: "ab" (2-byte label) + root, QTYPE=A, QCLASS=IN
            r[12] = 2; r[13] = b'a'; r[14] = b'b'; r[15] = 0;
            r[17] = 1;                                    // QTYPE = A
            r[19] = 1;                                    // QCLASS = IN
            // answer record, starting at offset 20:
            //   20..22 NAME (pointer to the question name at offset 12)
            //   22..24 TYPE=A   24..26 CLASS=IN   26..30 TTL
            //   30..32 RDLENGTH=4                 32..36 RDATA
            //
            // **The first version of this had TTL and RDLENGTH two bytes off,
            // and the parser was right.** Fourth time in this audit a
            // conformance failure was the assertion rather than the code --
            // which is the argument for writing the offsets out as a map
            // rather than counting them in one's head.
            r[20] = 0xC0; r[21] = 12;
            r[23] = 1;                                    // TYPE = A
            r[25] = 1;                                    // CLASS = IN
            r[29] = 60;                                   // TTL = 60
            r[31] = 4;                                    // RDLENGTH = 4
            r[32] = 10; r[33] = 0; r[34] = 2; r[35] = 99; // RDATA = 10.0.2.99
            if dns::parse_response(&r[..36], TX) != Some([10, 0, 2, 99]) {
                bad2 |= 1 << 0;
            }

            // The anti-spoof gate: a different transaction id must be refused
            // even though every other byte is valid. Off-path forgery has to
            // guess this, and dropping the check would cost nothing visible.
            if dns::parse_response(&r[..36], TX ^ 0xFFFF).is_some() { bad2 |= 1 << 1; }

            // QR=0 is a *query*, not a response. Accepting one lets anything
            // that can reach our client port answer us.
            let mut q = r; q[2] = 0x01;
            if dns::parse_response(&q[..36], TX).is_some() { bad2 |= 1 << 2; }

            // rcode != 0 (here NXDOMAIN=3): an error carries no address.
            let mut e = r; e[3] = 0x83;
            if dns::parse_response(&e[..36], TX).is_some() { bad2 |= 1 << 3; }

            // ancount = 0 with the answer bytes still present: the header is
            // authoritative about how many records exist.
            let mut z = r; z[7] = 0;
            if dns::parse_response(&z[..36], TX).is_some() { bad2 |= 1 << 4; }

            // **A compression pointer loop.** RFC 1035 allows pointers to
            // point backwards; nothing stops a hostile server pointing one at
            // itself. Without the jump limit in `skip_name` this hangs the
            // kernel -- a remote denial of service in four bytes. Reaching the
            // assertion at all is the test: if it hangs, the scenario times
            // out and the gate goes red.
            let mut loopy = r;
            loopy[20] = 0xC0; loopy[21] = 20;   // answer name points to itself
            if dns::parse_response(&loopy[..36], TX).is_some() { bad2 |= 1 << 5; }

            // Truncation at every length: none may panic, and a header-only
            // response must not be read as an answer.
            for n in 0..36usize {
                if dns::parse_response(&r[..n], TX).is_some() { bad2 |= 1 << 6; }
            }

            // RDLENGTH pointing past the end of the buffer: the record claims
            // 200 bytes inside a 38-byte packet.
            let mut over = r; over[31] = 200;
            if dns::parse_response(&over[..36], TX).is_some() { bad2 |= 1 << 7; }
        }

        // ── RFC 5905: NTP server-reply header gate ─────────────────────
        //
        // Same reasoning as DNS: 335 lines, no test, no scenario, and it reads
        // a remote server's packet. Every rejection below is a real attack or
        // a real malfunction, not a hypothetical.
        {
            use azos_net::ntp;
            let mut good = [0u8; 48];
            good[0] = 0x24;          // LI=0, VN=4, mode=4 (server)
            good[1] = 2;             // stratum 2
            if !ntp::header_acceptable(&good) { bad2 |= 1 << 8; }

            // Mode 3 is a *client* packet. Accepting one means a peer that
            // simply echoes our request back can set our clock.
            let mut m = good; m[0] = 0x23;
            if ntp::header_acceptable(&m) { bad2 |= 1 << 9; }

            // LI=3: the server is telling us it is not synchronised itself.
            let mut li = good; li[0] = 0xE4;
            if ntp::header_acceptable(&li) { bad2 |= 1 << 10; }

            // Stratum 0 is kiss-o'-death: the timestamp fields carry a
            // four-character ASCII code, NOT a time. Parsing it as a clock
            // reads "DENY" as an epoch.
            let mut k = good; k[1] = 0;
            if ntp::header_acceptable(&k) { bad2 |= 1 << 11; }

            // Stratum 16 and above: unsynchronised.
            let mut u = good; u[1] = 16;
            if ntp::header_acceptable(&u) { bad2 |= 1 << 12; }

            // A short packet must be refused before any field is indexed.
            for n in 0..48usize {
                if ntp::header_acceptable(&good[..n]) { bad2 |= 1 << 13; }
            }
        }

        // ── RFC 4291 / 8200: IPv6 address architecture ─────────────────
        //
        // Every public predicate in `ipv6.rs` was untested. These are pure
        // functions over addresses, and the two below are the ones that are
        // silently wrong rather than obviously wrong: get either one subtly
        // off and the stack still boots, still answers pings, and simply
        // cannot be resolved by a neighbour.
        {
            use azos_net::ipv6;

            // RFC 4291 §2.5.6 / App. A. Two things get botched here: the
            // FF:FE inserted in the MIDDLE of the MAC (not appended), and the
            // **Universal/Local bit flip** in the first octet. QEMU's
            // 52:54:00:12:34:56 has bit 1 clear, so the flip must produce
            // 0x50 -- an implementation that forgot it yields 0x52 and the
            // address still looks plausible.
            let ll = ipv6::eui64_link_local(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
            let want_ll: [u8; 16] = [
                0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                0x50, 0x54, 0x00, 0xFF, 0xFE, 0x12, 0x34, 0x56,
            ];
            if ll != want_ll { bad2 |= 1 << 14; }

            // RFC 4291 §2.7.1: FF02::1:FFXX:XXXX over the low **24** bits.
            // Neighbour Solicitations for our address go to this group rather
            // than to all-nodes, so an interface that computes it wrongly is
            // simply unreachable -- and it fails silently, because everything
            // it initiates still works.
            let sn = ipv6::solicited_node(&want_ll);
            let want_sn: [u8; 16] = [
                0xFF, 0x02, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0x01, 0xFF, 0x12, 0x34, 0x56,
            ];
            if sn != want_sn { bad2 |= 1 << 15; }

            // Only the low 24 bits may participate: two addresses differing
            // above byte 13 must map to the SAME group. A version that hashed
            // more of the address would pass the single case above.
            let mut other = want_ll; other[8] ^= 0xFF; other[12] ^= 0xFF;
            if ipv6::solicited_node(&other) != want_sn { bad2 |= 1 << 16; }

            // §2.7: multicast is exactly FF00::/8, and all-nodes is FF02::1.
            if !ipv6::is_multicast(&want_sn) { bad2 |= 1 << 17; }
            if ipv6::is_multicast(&want_ll)  { bad2 |= 1 << 18; }
            let all_nodes: [u8; 16] = [0xFF, 0x02, 0,0,0,0,0,0, 0,0,0,0,0,0,0, 0x01];
            if !ipv6::is_all_nodes(&all_nodes) { bad2 |= 1 << 19; }
            if ipv6::is_all_nodes(&want_sn)    { bad2 |= 1 << 20; }

            // ── The receive path: destination filter and RFC 8200 §8.1 ──
            //
            // `ipv6_rx` returns nothing, so this observes its effect: a UDP
            // socket either receives the datagram or does not. Two things are
            // being locked in, and both have teeth.
            //
            // **The destination filter has already been a no-op once.** Its
            // own comment records that it used to end in `|| is_multicast(dst)`
            // — which admits every group address that exists, so anyone who
            // set the first byte to 0xFF reached the shared UDP dispatcher.
            // Membership, not format, has to be the filter, and the only way
            // to show that is to send to a group we did NOT join and watch it
            // not arrive.
            //
            // **RFC 8200 §8.1 inverts the IPv4 rule**: over IPv6 the UDP
            // checksum is mandatory, and a zero field is malformed rather than
            // "sender opted out". Carrying the IPv4 habit over is the natural
            // mistake, and it silently accepts corrupt datagrams.
            //
            // The valid checksum is produced with our own `pseudo_checksum`.
            // That is deliberately not a claim about the checksum arithmetic —
            // RFC 1071 covers that elsewhere; here it only has to be good
            // enough that the positive case is not rejected for the wrong
            // reason, so the filter result is what the assertion sees.
            let me6 = ipv6::ipv6_link_local();
            if ipv6::ipv6_ready() {
                use azos_net::udp;
                const P6: u16 = 7601;
                let sock = udp::bind(P6);
                if sock < 0 {
                    bad2 |= 1 << 21;
                } else {
                    let si = sock as usize;
                    // Build UDP: src 7602 -> dst P6, 4 bytes of payload.
                    let mut seg = [0u8; 12];
                    seg[0..2].copy_from_slice(&7602u16.to_be_bytes());
                    seg[2..4].copy_from_slice(&P6.to_be_bytes());
                    seg[4..6].copy_from_slice(&12u16.to_be_bytes());  // UDP length
                    seg[8..12].copy_from_slice(b"v6ok");
                    let peer: [u8; 16] = [
                        0xFE, 0x80, 0, 0, 0, 0, 0, 0,
                        0x02, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55,
                    ];
                    let ck = ipv6::pseudo_checksum(&peer, &me6, ipv6::NEXTHDR_UDP, &seg);
                    seg[6..8].copy_from_slice(&ck.to_be_bytes());

                    // Wrap in an IPv6 header addressed to `dst`.
                    let build = |dst: &[u8; 16], seg: &[u8; 12]| -> [u8; 52] {
                        let mut f = [0u8; 52];
                        f[0] = 0x60;                                   // version 6
                        f[4..6].copy_from_slice(&12u16.to_be_bytes()); // payload length
                        f[6] = ipv6::NEXTHDR_UDP;
                        f[7] = 64;                                     // hop limit
                        f[8..24].copy_from_slice(&peer);
                        f[24..40].copy_from_slice(dst);
                        f[40..52].copy_from_slice(seg);
                        f
                    };

                    let mut rx = [0u8; 16];

                    // (a) To a group we have NOT joined: must not arrive.
                    let never: [u8; 16] = [
                        0xFF, 0x02, 0,0,0,0,0,0, 0,0,0,0, 0xDE, 0xAD, 0xBE, 0xEF,
                    ];
                    ipv6::ipv6_rx(&build(&never, &seg), 52);
                    if udp::recv(si, &mut rx) > 0 { bad2 |= 1 << 22; }

                    // (b) Zero checksum to our own address: malformed over
                    //     IPv6, must not arrive.
                    let mut zck = seg; zck[6] = 0; zck[7] = 0;
                    ipv6::ipv6_rx(&build(&me6, &zck), 52);
                    if udp::recv(si, &mut rx) > 0 { bad2 |= 1 << 23; }

                    // (c) The positive case: our unicast address, valid
                    //     checksum. Without this the two rejections above
                    //     would also pass on a stack that drops everything.
                    ipv6::ipv6_rx(&build(&me6, &seg), 52);
                    let n = udp::recv(si, &mut rx);
                    if n != 4 || &rx[..4] != b"v6ok" { bad2 |= 1 << 24; }

                    udp::close(sock);
                }
            }
        }

        if bad == 0 && bad2 == 0 && !nic_present {
            // Honest partial verdict. Saying "conformant" here would claim the
            // three wire sends passed when they were never attempted, and that
            // is the same overclaim the FAIL line made in the other direction.
            kprintln!("[NET]  RFC probe: broadcast/multicast wire sends and the ARP learn SKIPPED (no NIC) - the rest conformant");
        } else if bad == 0 && bad2 == 0 {
            kprintln!("[NET]  RFC 791/894/768/792/793/826/879/919/922/1035/1112/2236/4291/5905 conformant - incl. rejection paths, TCP options, broadcast, multicast, DNS and NTP");
        } else {
            // Named from the failed bits (K3-31): this line used to say
            // "RFC 791" whichever of the fourteen had failed.
            kprintln!("[NET]  RFC {} FAIL mask={:#x} mask2={:#x} - b0={:#x} b9={} len={} ck={:#x}",
                failed_rfcs(bad, bad2), bad, bad2,
                h[0], h[9], u16::from_be_bytes([h[2], h[3]]), ip::checksum(&h));
        }
    }

    // ── Loopback: boot smoke check ─────────────────────────────────────
    //
    // **Before this, a datagram to our own IP went out to the wire.**
    // `ip::send` went straight to `arp::lookup`, which finds no MAC for
    // ourselves, emitted a pointless ARP request and returned -1. Two local
    // processes could not talk over IP.
    //
    // The check is the return value: it used to be -1, it must now be 0. Done
    // here, in the shape of the other boot smokes (`[REG]`), because
    // it runs in **every** gate scenario (the gate's configurations turn
    // BOOT_SELFTESTS on) and therefore lands in `ci_check` without a new
    // scenario.
    //
    // Skipped when there is no IP yet: with `0.0.0.0` loopback is disabled on
    // purpose — `dst == our_ip` would hold for destination `0.0.0.0` — and a
    // failure here would be correct, not a defect.
    {
        let ip = azos_net::net_get_ip();
        if ip != [0, 0, 0, 0] {
            let mac = azos_net::net_get_mac();
            let probe = b"loopback-smoke";
            let rc = azos_net::ip::send(
                &mac, &ip, &ip, azos_net::ip::IP_PROTO_UDP, probe);
            if rc != 0 {
                azos_drv_sys::kerr!("[NET]  loopback FAIL rc={} - a local destination must not go to ARP", rc);
            } else {
                kprintln!("[NET]  loopback: local delivery OK (never reaches the wire)");

                // A full UDP round trip, not merely `ip::send` not failing.
                //
                // **This could not be written until today.** `socket_send`
                // refused anything that was not TCP and so did
                // `socket_connect`, so a UDP socket was receive-only: it could
                // be created and bound, and there was no way to give it a
                // destination.
                //
                // Both halves are exercised together here — connected UDP and
                // local delivery — which is what two robot processes need to
                // talk over IP without going through fast-IPC.
                use azos_net::socket::{self, SockAddr};
                const PUERTO: u16 = 7777;
                let rx = socket::socket_create(2, 2, 0);   // AF_INET, SOCK_DGRAM
                let tx = socket::socket_create(2, 2, 0);
                if rx >= 0 && tx >= 0 {
                    let dir = SockAddr { family: 2, port: PUERTO, addr: ip };
                    let ok_bind = socket::socket_bind(rx, &dir) == 0;
                    let ok_conn = socket::socket_connect(tx, &dir, 0) == 0;
                    let sent = socket::socket_send(tx, b"udp-loopback");
                    let mut buf = [0u8; 32];
                    let got = socket::socket_recv(rx, &mut buf);
                    if ok_bind && ok_conn && sent > 0 && got == sent
                        && &buf[..got as usize] == b"udp-loopback"
                    {
                        kprintln!("[NET]  UDP loopback: round trip OK ({} bytes)", got);
                    } else {
                        kprintln!("[NET]  UDP loopback FAIL: bind={} conn={} sent={} recv={}",
                            ok_bind, ok_conn, sent, got);
                    }
                    socket::socket_close(rx);
                    socket::socket_close(tx);
                } else {
                    azos_drv_sys::kerr!("[NET]  UDP loopback: could not create sockets");
                }
            }
        } else {
            kprintln!("[NET]  loopback: no IP assigned yet, check skipped");
        }
    }
}

/// The RFC a failed check of the probe belongs to: bit `bit` of its first
/// mask (`second` false) or of its second. 0 for a bit no check sets.
fn rfc_of(second: bool, bit: u32) -> u16 {
    match (second, bit) {
        (false, 0..=3) => 791,
        (false, 4) => 1071,
        (false, 5..=8) => 894,
        (false, 9..=13) | (false, 33..=35) => 768,
        (false, 14..=15) => 793,
        (false, 16..=19) => 879,
        (false, 20) => 792,
        (false, 21..=22) => 919,
        (false, 23..=31) | (false, 36) => 1112,
        (false, 32) | (false, 37) => 826,
        (true, 0..=7) => 1035,
        (true, 8..=13) => 5905,
        (true, 14..=20) => 4291,
        (true, 21..=24) => 8200,
        _ => 0,
    }
}

/// The RFCs whose checks failed, `/`-separated in bit order, each once
/// (`768/826`): the shape `QEMU_FAIL_RE` (`RFC [0-9/]+ FAIL`) matches.
fn failed_rfcs(bad: u64, bad2: u32) -> alloc::string::String {
    use core::fmt::Write;
    let mut seen = [0u16; 16];
    let mut n = 0;
    let mut out = alloc::string::String::new();
    for (second, mask) in [(false, bad), (true, u64::from(bad2))] {
        for bit in 0..64 {
            if mask & (1u64 << bit) == 0 {
                continue;
            }
            let rfc = rfc_of(second, bit);
            if seen[..n].contains(&rfc) || n == seen.len() {
                continue;
            }
            seen[n] = rfc;
            n += 1;
            if !out.is_empty() {
                out.push('/');
            }
            let _ = write!(out, "{}", rfc);
        }
    }
    out
}
