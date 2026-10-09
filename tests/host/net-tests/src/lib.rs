// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for TCP sequence-number arithmetic.
//!
//! **WHY this and not the rest of `crates/net/net`.** The parsers — Ethernet,
//! IPv4, ICMP, UDP, TCP framing, DNS, NTP, IPv6, ARP, broadcast, multicast —
//! are already driven with hand-built bytes by the boot-time conformance
//! block, fifteen RFCs' worth, in every QEMU scenario. Repeating that here
//! would add a number, not evidence.
//!
//! What has no coverage anywhere is the arithmetic, and it is the part with a
//! failure mode that никогда shows up in a short test: sequence numbers are
//! modulo 2^32, so every comparison must be a wrapping difference. A
//! connection only crosses the wrap point after 4 GiB of traffic, which no
//! scenario here ever sends — and on the wrong side of it a plain `<` silently
//! inverts, or a bare `+` panics under `overflow-checks`.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `beh_test_drivers`.
extern crate beh_test_drivers as azos_drv_irqchip;
extern crate beh_test_drivers as azos_drv_sys;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/seq.rs"]
mod seq;

// The real TCP implementation, pulled in whole.
//
// `tcp.rs` reaches for `crate::seq`, `super::ip`, `azos_sync::SpinLock`,
// `azos_limits::TCP_MAX_CONNS`, `azos_crypto::entropy::hmac_sha256`
// (U06-6, `generate_isn`) and the `wcet` attribute -- and nothing else. Only
// `ip` is stood in for, and only so the frames TCP emits can be recorded;
// everything else here is the code the kernel ships, including the real
// HMAC-SHA256 (`azos_crypto` is a real dependency below, not a shim).
/// The real link layer and the real IPv4 stack.
///
/// Everything below is the code the kernel ships, pulled in with `#[path]`:
/// `ethernet`, `arp`, `checksum`, `ip`, `igmp`, `udp` and `tcp`. The suite
/// therefore drives the stack the way the driver does — a whole Ethernet
/// frame in at the bottom — and reads back the frames it puts on the wire,
/// with real IP headers and real checksums.
///
/// This replaced a recording `ip` shim. The shim was convenient but it meant
/// `tcp`'s segments never met the code that fragments, checksums, routes or
/// ARP-resolves them, and `ip.rs` — the FIRST code a hostile packet touches —
/// was not under test at all.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/ethernet.rs"]
mod ethernet;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/arp.rs"]
mod arp;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/checksum.rs"]
mod checksum;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/ip.rs"]
mod ip;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/igmp.rs"]
mod igmp;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/udp.rs"]
mod udp;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/ipv6.rs"]
mod ipv6;

/// The REAL DNS resolver, not a stub.
///
/// `dns::resolve` sends a query and then spins on `super::net_poll()` until an
/// answer arrives or its deadline passes — the same shape as `dhcp.rs`. In the
/// kernel `net_poll` drains the NIC; here it drains a queue this suite fills,
/// so the whole resolve path runs end to end against crafted answers WITHOUT
/// any seam in production code. That is what puts `handle_response`'s
/// off-path-forgery defences under test.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/dns.rs"]
mod dns;

/// The TFTP client. Its poll loop calls `crate::net_poll`, so the suite plays
/// the server the same way it does for DNS and NTP.
#[allow(dead_code)]
#[path = "../../../../crates/net/tftp/src/client.rs"]
mod tftp_client;

/// E02 — multi-link failover (`crates/net/net/src/multilink.rs`).
///
/// The last module of `crates/net/net` without host coverage. Unlike everything
/// else pulled into this file, it has zero `use` statements and zero global
/// state — no ARP cache, no clock, no `crate::` or `azos_*` dependency at
/// all. It is generic over a caller-supplied `Transport` trait object and a
/// caller-supplied tick counter, so it needs no shim to run here: a test-only
/// mock `Transport` (defined inside the test module below, the normal way to
/// exercise a trait, not a production seam) stands in for WiFi/LoRa/RF.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/multilink.rs"]
mod multilink;

/// The socket table — the layer ring 3 actually talks to.
///
/// Its only dependencies are `tcp` and `udp`, both already running here, so it
/// needs nothing new.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/socket.rs"]
mod socket;

/// The REAL DHCP client.
///
/// This module was on the pending list as "not host-testable without a
/// production seam", because `dhcp_handle_offer` gates on a live `cur_xid()`.
/// It needs no seam: `dhcp_discover` sets the transaction id and puts the
/// DISCOVER on the recording wire, so a test reads the id back off the frame
/// and builds an OFFER that matches — which is exactly what a real server
/// does.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/dhcp.rs"]
mod dhcp;

/// The REAL NTP client.
///
/// Same shape as DNS: `ntp_sync` transmits and then spins on
/// `super::net_poll()`, so the suite plays the far end. Worth having under
/// test because SNTP has exactly ONE anti-spoofing mechanism (RFC 4330 §5) —
/// the server echoing our transmit timestamp back in the originate field —
/// and this module's own comment records that the old code sent an all-zero
/// timestamp, which did not merely skip that check but made it IMPOSSIBLE:
/// any host on the path could set the robot's wall clock to any value after
/// 1970.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/ntp.rs"]
mod ntp;

/// Frames waiting to be delivered to the stack, and the clock they advance.
///
/// This is the other half of `raw`: `raw::FRAMES` is what the stack SENT,
/// `inbound` is what it is about to RECEIVE.
pub mod inbound {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    pub static QUEUE: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());

    /// How far the test clock moves on each `net_poll`. `dns::resolve` waits
    /// 2 s (2e7 ticks), so this bounds an unanswered query at ~20 polls
    /// instead of spinning forever on a clock that never moves.
    pub const TICKS_PER_POLL: u64 = 1_000_000;

    /// Called at the top of every `net_poll`, before the queue is drained.
    ///
    /// This is how a test plays the far end of a conversation it cannot
    /// pre-record: `dns::resolve` transmits and only then can be answered, so
    /// the answer has to be built from the query while `resolve` is still
    /// spinning inside its own poll loop. A plain `fn` pointer rather than a
    /// closure, so it can live in a static without threads.
    pub static ON_POLL: Mutex<Option<fn()>> = Mutex::new(None);

    pub fn on_poll(f: fn()) {
        *ON_POLL.lock().unwrap() = Some(f);
    }

    pub fn reset() {
        QUEUE.lock().unwrap().clear();
        *ON_POLL.lock().unwrap() = None;
    }

    /// Queue a complete Ethernet frame for the next `net_poll`.
    pub fn push_frame(frame: Vec<u8>) {
        QUEUE.lock().unwrap().push_back(frame);
    }

    /// Queue an IPv4 payload, wrapping it in an Ethernet header.
    pub fn push_ipv4(payload: &[u8]) {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst = us
        f.extend_from_slice(&[0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]); // src = peer
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(payload);
        push_frame(f);
    }
}

/// `super::net_poll`, mirroring the real one in `crates/net/net/src/lib.rs`:
/// drain up to 64 frames, parse the Ethernet header, dispatch by ethertype.
///
/// It also advances the test clock, which the real one does not need to do —
/// there the hardware clock moves on its own. Without it a `resolve` that
/// never gets an answer would spin on a deadline it can never reach.
pub fn net_poll() {
    const MAX_DRAIN_PER_CALL: usize = 64;

    // Let a test synthesise inbound traffic from what has just been sent.
    let hook = *inbound::ON_POLL.lock().unwrap();
    if let Some(f) = hook {
        f();
    }

    let mac = net_get_mac();
    let ip = net_get_ip();

    for _ in 0..MAX_DRAIN_PER_CALL {
        let frame = match inbound::QUEUE.lock().unwrap().pop_front() {
            Some(f) => f,
            None => break,
        };
        if let Some((hdr, payload)) = ethernet::parse(&frame) {
            match hdr.ethertype() {
                ethernet::ETH_TYPE_ARP => arp::handle(payload, &mac, &ip),
                ethernet::ETH_TYPE_IP => ip::handle(payload, &mac, &ip),
                ethernet::ETH_TYPE_IPV6 => ipv6::ipv6_rx(payload, payload.len()),
                _ => {}
            }
        }
    }

    let now = azos_drv_sys::timebase::now();
    azos_drv_irqchip::clint::set_test_time(now + inbound::TICKS_PER_POLL);
}

/// `super::net_get_mask`, used by `ip::send` to decide on-link vs gateway.
pub fn net_get_mask() -> [u8; 4] {
    [255, 255, 255, 0]
}

/// `super::net_get_gateway` (U06-4): `ip::send_flags` reads this to pick the
/// next-hop MAC for an off-subnet destination instead of ARPing the
/// destination directly. Settable — unlike `net_get_mask`/`net_get_ip`,
/// which are fixed — so a routing test can configure "no gateway" (all
/// zeros, the pre-fix behaviour) without a second subnet existing here.
/// Default is on-link with `net_get_ip`/`net_get_mask` (`10.0.0.0/24`), the
/// same shape DHCP would hand out.
pub mod gateway_cfg {
    use std::sync::Mutex;
    pub static GATEWAY: Mutex<[u8; 4]> = Mutex::new([10, 0, 0, 1]);
}

pub fn net_get_gateway() -> [u8; 4] {
    *gateway_cfg::GATEWAY.lock().unwrap()
}

/// `super::net_set_ip`, recorded — and it DOES propagate to TCP, exactly as
/// `crates/net/net/src/lib.rs` does.
///
/// The propagation is not decoration. TCP caches its own copy of the address
/// for the checksum pseudo-header, and it used to be written only by
/// `tcp::init`; anything that changed the address later — DHCP above all —
/// left TCP checksumming against the old one and dropping every segment in
/// silence. Reproducing it here means a test can watch a DHCP lease actually
/// reconfigure the TCP layer. What is NOT covered from here is `NET_CFG`
/// itself: that half lives in `lib.rs`, which this suite does not pull in.
pub mod netcfg {
    use std::sync::Mutex;
    pub static SET: Mutex<Vec<([u8; 4], [u8; 4], [u8; 4])>> = Mutex::new(Vec::new());
    pub fn reset() {
        SET.lock().unwrap().clear();
    }
    pub fn last() -> Option<([u8; 4], [u8; 4], [u8; 4])> {
        SET.lock().unwrap().last().copied()
    }
}

pub fn net_set_ip(ip: [u8; 4], mask: [u8; 4], gw: [u8; 4]) {
    netcfg::SET.lock().unwrap().push((ip, mask, gw));
    tcp::set_our_ip(ip);
}

/// `super::net_get_ip`, used by `igmp` to fill the source address of a report.
pub fn net_get_ip() -> [u8; 4] {
    [10, 0, 0, 2]
}

/// ONE lock for the whole network stack.
///
/// `TCP`'s connection table, the ARP cache, the IGMP membership set and the
/// recorded wire are all process-wide statics belonging to one machine. The
/// suite briefly had a separate lock per test module, which serialises
/// nothing between them — and it showed: the TCP tests passed only because
/// the ARP tests had populated the cache for their peer, and failed the
/// moment they ran alone. Two locks over one state machine is the same
/// mistake `fs-tests` records.
#[cfg(test)]
pub(crate) static NET_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What the stack put on the wire, read back at the layer the tests reason at.
///
/// The suite used to record TCP segments by shimming `ip::send`. It now
/// records whole Ethernet frames, because the real `ip.rs` is in the loop, and
/// parses them back down to the transport payload. That means every segment a
/// test inspects has been through the kernel's own IP header construction, its
/// own checksum, and its own ARP resolution — none of which the shim exercised.
pub mod wire {
    pub use crate::ip::{pseudo_checksum, IP_PROTO_TCP};

    /// One datagram, as `ip::send` was asked to send it.
    #[derive(Clone, Debug)]
    pub struct Sent {
        pub dst_ip: [u8; 4],
        pub proto: u8,
        pub payload: Vec<u8>,
    }

    pub fn reset() {
        crate::raw::reset();
    }

    /// Every IPv4 frame on the wire, oldest first, with the Ethernet and IP
    /// headers stripped.
    ///
    /// ARP frames are skipped rather than mis-parsed: `ip::send` resolves
    /// through the real cache now, so a test whose peer is unresolved will see
    /// an ARP request go out ahead of anything else.
    pub fn sent() -> Vec<Sent> {
        crate::raw::all()
            .iter()
            .filter_map(|f| {
                if f.len() < 14 + 20 { return None; }
                if u16::from_be_bytes([f[12], f[13]]) != 0x0800 { return None; }
                let ihl = ((f[14] & 0x0F) as usize) * 4;
                if ihl < 20 || 14 + ihl > f.len() { return None; }
                let total = u16::from_be_bytes([f[16], f[17]]) as usize;
                let end = (14 + total).min(f.len());
                if 14 + ihl > end { return None; }
                Some(Sent {
                    dst_ip: [f[14 + 16], f[14 + 17], f[14 + 18], f[14 + 19]],
                    proto: f[14 + 9],
                    payload: f[14 + ihl..end].to_vec(),
                })
            })
            .collect()
    }

    pub fn sent_count() -> usize {
        sent().len()
    }

    pub fn clear_sent() {
        crate::raw::reset();
    }
}

/// Frames handed to the driver by anything that bypasses `ip::send` — which
/// is ARP, since it builds its own Ethernet frames.
pub mod raw {
    use std::sync::Mutex;

    pub static FRAMES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

    pub fn reset() {
        FRAMES.lock().unwrap().clear();
    }

    pub fn all() -> Vec<Vec<u8>> {
        FRAMES.lock().unwrap().clone()
    }

    pub fn count() -> usize {
        FRAMES.lock().unwrap().len()
    }
}

/// `super::net_raw_send` as `ethernet.rs` and `arp.rs` see it. Returns a
/// positive count on success, which is what both of them test for.
pub fn net_raw_send(frame: &[u8]) -> i32 {
    raw::FRAMES.lock().unwrap().push(frame.to_vec());
    frame.len() as i32
}

/// `crate::net_tx_batch_begin`/`_end` as `tcp.rs` sees them: the depth of
/// open TX batches, so a test can check none is held across a wait.
pub static TX_BATCH_DEPTH: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
pub fn net_tx_batch_begin() {
    TX_BATCH_DEPTH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}
pub fn net_tx_batch_end() {
    TX_BATCH_DEPTH.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
}

/// `super::net_get_mac`, used by `ethernet::send_ipv6`.
pub fn net_get_mac() -> [u8; 6] {
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x02]
}

/// The random source `super::net_random_fill` calls, as a test installs it.
/// `None` — the default, and what every other test runs with — is the kernel
/// with no seeded pool, so each consumer takes its counter fallback.
pub mod random {
    use std::sync::Mutex;
    pub static SOURCE: Mutex<Option<fn(&mut [u8]) -> bool>> = Mutex::new(None);
}

/// `super::net_random_fill`, mirroring `crates/net/net/src/lib.rs`: the installed
/// source's answer, or `false` with none installed.
pub fn net_random_fill(buf: &mut [u8]) -> bool {
    let f = *random::SOURCE.lock().unwrap();
    match f {
        Some(f) => f(buf),
        None => false,
    }
}

/// The waiter queues `tcp`, `arp` and `dns` notify (N7). No hooks are
/// registered here, so every wait is the caller's own `yield_fn`, as before.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/wait.rs"]
mod wait;

#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/tcp.rs"]
mod tcp;

/// Generation-checked TCP handles (a stale one acts on nothing) and the
/// ephemeral port allocator.
#[cfg(test)]
mod tcp_handle;

/// N8: the owner bit that makes `net_poll`'s receive pass single-consumer.
#[allow(dead_code)]
#[path = "../../../../crates/net/net/src/rx_owner.rs"]
mod rx_owner;

#[cfg(test)]
mod rx_owner_tests {
    use super::rx_owner::PassOwner;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    /// A call made while a pass runs (another hart, modelled here by a call
    /// from inside the pass) drains nothing and returns at once; the owner
    /// runs exactly one more pass for it before letting go.
    #[test]
    fn a_call_during_a_pass_does_not_drain_beside_it_and_gets_one_more_pass() {
        static OWNER: PassOwner = PassOwner::new();
        let passes = AtomicU64::new(0);
        let inner_ran = AtomicBool::new(false);
        let r = OWNER.run(|| {
            let n = passes.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                let r2 = OWNER.run(|| { inner_ran.store(true, Ordering::SeqCst); false });
                assert!(!r2, "the contender must return false");
            }
            false
        });
        assert!(!r);
        assert!(!inner_ran.load(Ordering::SeqCst),
            "a second consumer drained beside the pass in progress");
        assert_eq!(passes.load(Ordering::SeqCst), 2,
            "the owner must run one more pass for the request it was left");
        assert_eq!(OWNER.contended(), 1);
    }

    /// No request: one pass. Budget hit: the caller is told, no rerun here.
    #[test]
    fn one_pass_without_a_request_and_budget_hit_is_reported() {
        let owner = PassOwner::new();
        let mut n = 0;
        assert!(!owner.run(|| { n += 1; false }));
        assert_eq!(n, 1);
        assert!(owner.run(|| { n += 1; true }));
        assert_eq!(n, 2);
        assert_eq!(owner.contended(), 0);
    }

    /// Four threads hammering one owner: never two passes at once, and every
    /// call that returned `false` was followed by a pass that started after
    /// it (no stranded request: the pass counter ends past every call's mark).
    #[test]
    fn concurrent_callers_never_overlap_and_no_request_is_lost() {
        let owner = Arc::new(PassOwner::new());
        let inside = Arc::new(AtomicBool::new(false));
        let overlaps = Arc::new(AtomicU64::new(0));
        let started = Arc::new(AtomicU64::new(0));
        let mut hs = Vec::new();
        for _ in 0..4 {
            let (owner, inside, overlaps, started) =
                (owner.clone(), inside.clone(), overlaps.clone(), started.clone());
            hs.push(std::thread::spawn(move || {
                let mut latest_call_mark = 0u64;
                for _ in 0..20_000 {
                    latest_call_mark = started.load(Ordering::SeqCst);
                    owner.run(|| {
                        started.fetch_add(1, Ordering::SeqCst);
                        if inside.swap(true, Ordering::SeqCst) {
                            overlaps.fetch_add(1, Ordering::SeqCst);
                        }
                        std::hint::spin_loop();
                        inside.store(false, Ordering::SeqCst);
                        false
                    });
                }
                latest_call_mark
            }));
        }
        let marks: Vec<u64> = hs.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(overlaps.load(Ordering::SeqCst), 0, "two passes ran at once");
        let total = started.load(Ordering::SeqCst);
        for m in marks {
            assert!(total > m, "a request was left with no pass after it");
        }
    }
}

/// TCP options on the wire: window scaling (RFC 7323), SACK (RFC 2018) and
/// MSS, from SYNs that carry them — the harness in `tcp_rx` sends none.
#[cfg(test)]
mod tcp_options;

/// The send window, congestion control and loss recovery, and the RFC 793
/// replies around a connection; and a simulated link between two endpoints
/// that measures what the window delivers per round trip.
#[cfg(test)]
mod tcp_sender;
#[cfg(test)]
mod tcp_throughput;

/// Path MTU discovery (RFC 1191): Don't Fragment on TCP, Fragmentation Needed
/// believed only for a segment in flight (RFC 5927), and the black-hole
/// fallback when the path says nothing.
#[cfg(test)]
mod tcp_pmtu;

/// The retransmission timer's RTT estimate against a scripted round-trip time,
/// with several segments in flight: measured and printed, not a quality gate.
#[cfg(test)]
mod tcp_rto_estimate;

/// A bulk flow and a small periodic control flow from this stack through one
/// drop-tail queue: the control messages' delay and the bulk throughput,
/// measured and printed, not a quality gate.
#[cfg(test)]
mod tcp_two_flow;

/// Byte-level wire conformance: each protocol's encoder output compared with
/// arrays derived by hand from its RFC, and hand-built server packets fed to
/// its parser.
#[cfg(test)]
mod conformance_igmp;
#[cfg(test)]
mod conformance_dhcp;
#[cfg(test)]
mod conformance_dns;
#[cfg(test)]
mod conformance_ntp;

/// The random-source hook: an installed source drives the DHCP xid, the DNS id
/// and source port, the NTP nonce and the TCP ISN secret.
#[cfg(test)]
mod random_source;

#[cfg(test)]
mod window {
    use super::seq::*;

    /// The ordinary case, so the wrap cases below are not the only evidence.
    #[test]
    fn a_sequence_inside_the_window_is_accepted() {
        assert!(seq_in_window(1000, 1000, 100), "the first byte is in window");
        assert!(seq_in_window(1099, 1000, 100), "the last byte is in window");
        assert!(!seq_in_window(1100, 1000, 100), "one past the end is not");
        assert!(!seq_in_window(999, 1000, 100), "one before the start is not");
    }

    /// **The window straddling the 2^32 wrap.** This is the case a plain
    /// `seq >= start && seq < start + size` gets exactly backwards: with the
    /// window starting near u32::MAX it accepts everything *outside* and
    /// rejects everything in. A connection reaches here after 4 GiB — an OTA
    /// image or a long telemetry session, not a hypothetical.
    #[test]
    fn a_window_across_the_wrap_point_is_handled() {
        let start = u32::MAX - 49;              // window is [MAX-49, MAX] + [0, 49]
        assert!(seq_in_window(start, start, 100), "start is in");
        assert!(seq_in_window(u32::MAX, start, 100), "the byte before wrap is in");
        assert!(seq_in_window(0, start, 100), "the wrap itself is in");
        assert!(seq_in_window(49, start, 100), "the last byte after wrap is in");
        assert!(!seq_in_window(50, start, 100), "one past the end is out");
        assert!(!seq_in_window(start - 1, start, 100), "one before the start is out");
    }

    /// A zero-size window admits nothing. A comparison written as `<=` instead
    /// of `<` would admit exactly one sequence number here, which is how a
    /// closed window silently keeps accepting data.
    #[test]
    fn a_zero_size_window_admits_nothing() {
        assert!(!seq_in_window(1000, 1000, 0));
        assert!(!seq_in_window(0, 0, 0));
        assert!(!seq_in_window(u32::MAX, u32::MAX, 0));
    }

    /// **A FIN occupies one sequence number of its own**, after any payload
    /// the same segment carried. Off by one and the peer retransmits a FIN we
    /// think we acknowledged: our side sits in TimeWait, theirs never reaches
    /// CLOSED.
    #[test]
    fn a_fin_consumes_one_sequence_number_after_its_payload() {
        assert_eq!(fin_next_ack(1000, 0), 1001, "a bare FIN takes one");
        assert_eq!(fin_next_ack(1000, 10), 1011, "payload then the FIN");
        // And across the wrap: a bare `+` here panics under overflow-checks,
        // which is a board reset on a connection that happened to be long.
        assert_eq!(fin_next_ack(u32::MAX, 0), 0);
        // (MAX-4) + 10 wraps to 5, and the FIN itself adds one more: 6.
        // The first version of this line said 5 -- I dropped the FIN's own
        // sequence number from my own arithmetic, which is the very off-by-one
        // the function exists to get right.
        assert_eq!(fin_next_ack(u32::MAX - 4, 10), 6);
    }

    /// An ACK must advance the retransmit window only for bytes actually in
    /// flight. Accepting an older ACK frees a segment the peer never got;
    /// accepting a future one frees data never sent.
    #[test]
    fn only_an_ack_covering_sent_bytes_advances() {
        assert!(!is_ack_advancing(1000, 1000, 0), "nothing in flight, nothing to ack");
        assert!(!is_ack_advancing(1000, 1000, 10), "an ack of the first byte is not progress");
        assert!(is_ack_advancing(1005, 1000, 10), "a partial ack is progress");
        assert!(is_ack_advancing(1010, 1000, 10), "acking the whole segment is progress");
        assert!(!is_ack_advancing(1011, 1000, 10), "past the end is not ours");
        assert!(!is_ack_advancing(999, 1000, 10), "an older ack is not progress");
    }

    /// The same, across the wrap — the case that separates wrapping
    /// subtraction from ordinary comparison.
    #[test]
    fn ack_progress_is_correct_across_the_wrap() {
        let base = u32::MAX - 4;                // segment spans MAX-4 .. 5
        assert!(is_ack_advancing(0, base, 10), "an ack past the wrap is progress");
        assert!(is_ack_advancing(5, base, 10), "the end of the segment");
        assert!(!is_ack_advancing(6, base, 10), "one past the end is not ours");
        assert!(!is_ack_advancing(base, base, 10), "the start is not progress");
    }
}

// ---------------------------------------------------------------------------
// TCP receive path — `tcp::handle_checked`, the entry point for wire bytes.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tcp_rx {
    use super::{tcp, wire};
    use azos_limits::TCP_MAX_CONNS;

    pub const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    pub const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    pub const PEER_IP: [u8; 4] = [10, 0, 0, 9];

    /// The window of an empty receive ring: its free space, `TCP_BUF_SIZE - 1`,
    /// saturated into the 16-bit field. 65535 at the 128 KiB ring, 16383 at
    /// 16 KiB. `TCP_WINDOW_SIZE` in `tcp.rs`, restated because it is private
    /// there.
    pub(crate) const EMPTY_WINDOW: u16 = if azos_limits::TCP_BUF_SIZE - 1 > u16::MAX as usize {
        u16::MAX
    } else {
        (azos_limits::TCP_BUF_SIZE - 1) as u16
    };

    /// Unread KiB that pull the advertised window clearly below `EMPTY_WINDOW`:
    /// what the field's ceiling hides (`TCP_BUF_SIZE - 1 - EMPTY_WINDOW`, none
    /// for a ring of 64 KiB or less) plus 8 KiB, or half the ring if that is
    /// less. 72 KiB at the 128 KiB ring, 8 KiB at 16 KiB.
    pub(crate) const PAST_CLAMP_KIB: usize = {
        let ring = azos_limits::TCP_BUF_SIZE;
        let margin = if ring / 2048 < 8 { ring / 2048 } else { 8 };
        (ring - 1 - EMPTY_WINDOW as usize) / 1024 + margin
    };

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;

    pub(crate) use super::NET_SERIAL as SERIAL;

    /// The MAC the peer answers on. `ip::send` resolves through the REAL ARP
    /// cache, so without an entry every segment this suite expects on the wire
    /// would instead be an ARP request and a frame parked in the pending-ARP
    /// queue — accepted (rc 0) and not yet sent. Either way it is not on the
    /// wire when the assertion looks, which is what matters here.
    pub const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    /// Name a state for an assertion message.
    ///
    /// `TcpState` deliberately does not derive `Debug`: this is a `no_std`
    /// kernel and a derived `Debug` pulls a `core::fmt` impl into the image
    /// for an enum nothing in the kernel ever prints. Naming it here keeps
    /// that cost out of production and the failure messages readable.
    pub(crate) fn st(s: tcp::TcpState) -> &'static str {
        use tcp::TcpState::*;
        match s {
            Closed => "Closed", Listen => "Listen", SynSent => "SynSent",
            SynRcvd => "SynRcvd", Established => "Established",
            FinWait1 => "FinWait1", FinWait2 => "FinWait2",
            CloseWait => "CloseWait", LastAck => "LastAck", TimeWait => "TimeWait",
        }
    }

    /// Empty every slot, then start recording.
    ///
    /// `close()` on an Established connection sends a FIN and moves to
    /// FinWait1 rather than freeing the slot, so it takes two calls to reach
    /// `Closed` — which is what `alloc()` looks for. Closing happens BEFORE
    /// the wire is reset so the FINs it emits do not appear in the test's own
    /// record.
    pub(crate) fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        wire::reset();
        for idx in 0..TCP_MAX_CONNS {
            tcp::close(idx);
            tcp::close(idx);
        }
        // State the precondition instead of inheriting it: a leaked slot makes
        // a later `listen()` return -1, and the failure then lands on whatever
        // test happened to run next.
        for idx in 0..TCP_MAX_CONNS {
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::Closed,
                "slot {idx} was left in {} by the previous test",
                st(tcp::conn_state(idx)),
            );
        }
        wire::reset();
        super::raw::reset();

        // The SOCKET table too, and for the same stated reason as the TCP
        // slots above: state the precondition instead of inheriting it.
        //
        // **This was missing here and worked around one module away.**
        // `mod socket_quota` has its own `begin()` that does exactly this, and
        // its doc says why: the general harness "serialises but does not clear
        // sockets". So every OTHER module using this one inherited whatever
        // the previous test left.
        //
        // `MAX_SOCKETS` is 16 for the whole machine, so a leak makes a LATER
        // test's `socket_create_owned` return -1. On 2026-09-07 that landed on
        // `socket_shutdown_sends_a_fin_and_leaves_the_fd_readable`, which
        // failed inside the suite and passed 5/5 standing alone — the failure
        // attributing itself to whichever test ran next rather than to
        // whichever leaked. A gate that can go red at random for a reason that
        // names the wrong test is worse than one that is red.
        for fd in 0..crate::socket::MAX_SOCKETS {
            crate::socket::socket_close(fd as i32);
        }
        for fd in 0..crate::socket::MAX_SOCKETS {
            assert!(
                crate::socket::socket_owner(fd as i32).is_none(),
                "fd {fd} was left owned by the previous test",
            );
        }

        azos_drv_irqchip::clint::set_test_time(10_000);
        // Resolve the peer explicitly. Inheriting this from whichever ARP test
        // ran first is exactly how these tests passed as a suite and failed
        // alone.
        super::arp::insert(PEER_IP, PEER_MAC);
        tcp::init(OUR_MAC, OUR_IP);
        super::raw::reset();
        g
    }

    /// The slot currently in `want`, if exactly one is.
    ///
    /// A SYN to a listening port does NOT change the listener: it stays in
    /// `Listen` and a fresh slot is allocated for the half-open connection,
    /// the same way BSD does it. Tests therefore have to find the connection
    /// rather than assume it landed on the index `listen()` returned.
    pub(crate) fn slot_in(want: tcp::TcpState) -> Option<usize> {
        (0..TCP_MAX_CONNS).find(|&i| tcp::conn_state(i) == want)
    }

    pub(crate) fn count_in(want: tcp::TcpState) -> usize {
        (0..TCP_MAX_CONNS).filter(|&i| tcp::conn_state(i) == want).count()
    }

    /// Build a segment with a VALID checksum, computed with the kernel's own
    /// `pseudo_checksum` and `tcp_checksum` — a copy of either would let the
    /// crafting side and the verifying side agree on the same wrong value.
    pub(crate) fn segment(
        src_port: u16, dst_port: u16, seq: u32, ack: u32,
        flags: u8, window: u16, payload: &[u8],
    ) -> Vec<u8> {
        let mut s = Vec::with_capacity(20 + payload.len());
        s.extend_from_slice(&src_port.to_be_bytes());
        s.extend_from_slice(&dst_port.to_be_bytes());
        s.extend_from_slice(&seq.to_be_bytes());
        s.extend_from_slice(&ack.to_be_bytes());
        s.push(5 << 4);          // data offset = 5 words = 20 bytes
        s.push(flags);
        s.extend_from_slice(&window.to_be_bytes());
        s.extend_from_slice(&[0, 0]); // checksum placeholder
        s.extend_from_slice(&[0, 0]); // urgent
        s.extend_from_slice(payload);
        let pseudo = wire::pseudo_checksum(
            &PEER_IP, &OUR_IP, wire::IP_PROTO_TCP, s.len() as u16,
        );
        let ck = tcp::tcp_checksum(pseudo, &s);
        s[16..18].copy_from_slice(&ck.to_be_bytes());
        s
    }

    /// One segment in, as one `net_poll` pass: the ACK it holds (N6) leaves
    /// when the pass ends, as the kernel's poller sends it.
    pub(crate) fn deliver(seg: &[u8]) {
        tcp::handle_checked(&PEER_IP, &OUR_IP, seg);
        if tcp::TCP_DELACK_PASS_FLUSH {
            tcp::flush_held_acks(false);
        }
    }

    /// Parsed view of a segment the stack put on the wire.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Out {
        pub seq: u32,
        pub ack: u32,
        pub flags: u8,
        pub window: u16,
        pub payload_len: usize,
    }

    pub(crate) fn outbound() -> Vec<Out> {
        wire::sent()
            .iter()
            .map(|s| {
                let p = &s.payload;
                Out {
                    seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
                    ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
                    flags: p[13],
                    window: u16::from_be_bytes([p[14], p[15]]),
                    payload_len: p.len() - ((p[12] >> 4) as usize) * 4,
                }
            })
            .collect()
    }

    /// Drive a listening socket to Established and return (idx, our_seq,
    /// peer_seq_after_handshake).
    pub(crate) fn establish(port: u16, peer_port: u16, peer_isn: u32) -> (usize, u32, u32) {
        assert!(tcp::listen(port) >= 0, "no free connection slot for the listener");

        deliver(&segment(peer_port, port, peer_isn, 0, SYN, 4096, &[]));
        let synack = *outbound().last().expect("a SYN to a listening port must be answered");
        assert_eq!(synack.flags & (SYN | ACK), SYN | ACK, "expected SYN-ACK");
        assert_eq!(synack.ack, peer_isn.wrapping_add(1), "SYN consumes one sequence number");

        let idx = slot_in(tcp::TcpState::SynRcvd)
            .expect("the SYN must have opened a half-open connection");
        let our_isn = synack.seq;
        deliver(&segment(
            peer_port, port, peer_isn.wrapping_add(1), our_isn.wrapping_add(1),
            ACK, 4096, &[],
        ));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Established,
            "the third leg of the handshake must establish it, got {}",
            st(tcp::conn_state(idx)),
        );
        wire::clear_sent();
        (idx, our_isn.wrapping_add(1), peer_isn.wrapping_add(1))
    }

    // ── The checksum gate ────────────────────────────────────────────────────

    /// Every byte that reaches the state machine has passed this. A segment
    /// with one flipped bit must be dropped in silence — not answered, not
    /// acted on.
    #[test]
    fn a_segment_with_a_bad_checksum_never_reaches_the_state_machine() {
        let _g = begin();
        let idx = tcp::listen(7001) as usize;
        let mut seg = segment(40001, 7001, 1000, 0, SYN, 4096, &[]);
        seg[16] ^= 0x01; // corrupt the stored checksum
        deliver(&seg);
        assert_eq!(wire::sent_count(), 0, "a corrupt segment must not be answered");
        assert!(tcp::conn_state(idx) == tcp::TcpState::Listen, "nor acted on");
    }

    /// The same segment, uncorrupted, must be accepted — otherwise the test
    /// above would pass on a stack that drops everything.
    #[test]
    fn the_same_segment_with_a_good_checksum_is_accepted() {
        let _g = begin();
        let listener = tcp::listen(7002) as usize;
        deliver(&segment(40002, 7002, 1000, 0, SYN, 4096, &[]));
        assert_eq!(wire::sent_count(), 1, "the SYN must be answered");
        assert!(
            tcp::conn_state(listener) == tcp::TcpState::Listen,
            "the listener keeps listening; got {}", st(tcp::conn_state(listener)),
        );
        assert!(
            slot_in(tcp::TcpState::SynRcvd).is_some(),
            "a separate slot must hold the half-open connection",
        );
    }

    // ── Malformed headers ────────────────────────────────────────────────────

    /// RFC 793: the data offset is at least 5 words, and the header cannot
    /// extend past the segment. Both are malformed and must be DROPPED —
    /// clamping a short offset reinterprets option bytes as payload, and
    /// accepting an overlong one processes flags from a header the segment
    /// does not contain.
    #[test]
    fn a_data_offset_outside_the_segment_is_dropped() {
        let _g = begin();
        let idx = tcp::listen(7003) as usize;

        for bad_off in [0u8, 1, 4, 6, 15] {
            let mut s = segment(40003, 7003, 1000, 0, SYN, 4096, &[]);
            s[12] = bad_off << 4;
            // Re-checksum so the ONLY thing wrong is the offset.
            s[16..18].copy_from_slice(&[0, 0]);
            let pseudo = wire::pseudo_checksum(
                &PEER_IP, &OUR_IP, wire::IP_PROTO_TCP, s.len() as u16,
            );
            let ck = tcp::tcp_checksum(pseudo, &s);
            s[16..18].copy_from_slice(&ck.to_be_bytes());
            deliver(&s);
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::Listen,
                "data_off={bad_off} words is malformed for a {}-byte segment, \
                 but the stack moved to {}", s.len(), st(tcp::conn_state(idx)),
            );
        }
        assert_eq!(wire::sent_count(), 0, "malformed segments are dropped, not answered");
    }

    /// A segment shorter than the 20-byte minimum header has no header to
    /// read. The bound matters because `handle` casts the buffer to a
    /// `#[repr(C, packed)]` TcpHdr.
    #[test]
    fn a_segment_shorter_than_the_minimum_header_is_dropped() {
        let _g = begin();
        let idx = tcp::listen(7004) as usize;
        let full = segment(40004, 7004, 1000, 0, SYN, 4096, &[]);
        for n in 0..20usize {
            deliver(&full[..n]);
        }
        assert!(tcp::conn_state(idx) == tcp::TcpState::Listen);
        assert_eq!(wire::sent_count(), 0);
    }

    // ── Handshake ────────────────────────────────────────────────────────────

    /// U13-4: renamed from `..._and_the_isn_is_not_predictable` — the body
    /// only ever pinned the state transition, not unpredictability. That
    /// property now has its own test, below:
    /// `one_observed_isn_no_longer_lets_an_attacker_predict_another`.
    #[test]
    fn a_handshake_with_a_bare_syn_reaches_established() {
        let _g = begin();
        let (idx, _ours, _theirs) = establish(7005, 40005, 0x1000_0000);
        assert!(tcp::conn_state(idx) == tcp::TcpState::Established);
    }

    /// The SYN-ACK offers an MSS option, so its header is longer than the
    /// 20-byte minimum — and it must still carry no payload. A control
    /// segment with a body would desynchronise the peer's sequence tracking.
    #[test]
    fn the_syn_ack_carries_an_mss_option_and_no_payload() {
        let _g = begin();
        tcp::listen(7009);
        deliver(&segment(40009, 7009, 3000, 0, SYN, 4096, &[]));
        let sent = wire::sent();
        let p = &sent.last().expect("SYN-ACK").payload;
        let off = ((p[12] >> 4) as usize) * 4;
        assert!(off > 20, "the SYN-ACK should advertise an MSS option, data_off={off}");
        let out = *outbound().last().unwrap();
        assert_eq!(out.payload_len, 0, "a SYN-ACK must carry no data");
    }

    /// RFC 6528: the initial sequence number is derived from the 4-tuple and a
    /// secret, so two different peers talking to the same port must not get
    /// the same ISN. A guessable ISN is a blind-injection primitive.
    #[test]
    fn different_peers_do_not_receive_the_same_initial_sequence_number() {
        let _g = begin();
        tcp::listen(7006);
        deliver(&segment(40006, 7006, 5000, 0, SYN, 4096, &[]));
        let a = outbound().last().unwrap().seq;

        wire::clear_sent();
        tcp::listen(7006);
        deliver(&segment(40007, 7006, 5000, 0, SYN, 4096, &[]));
        let b = outbound().last().unwrap().seq;

        assert_ne!(a, b, "the ISN must vary with the connection 4-tuple");
    }

    /// U06-6 / U13-4: the real canary for the FNV → HMAC-SHA256 replacement.
    ///
    /// `different_peers_do_not_receive_the_same_initial_sequence_number`
    /// above is satisfied by a plain counter; it does not touch RFC 6528
    /// unpredictability. This test reproduces the EXACT attack the audit
    /// named against the OLD generator: FNV-1a's step `h = (h ^ byte) *
    /// FNV_PRIME` is a bijection of `h` for a *known* byte, which makes the
    /// last four rounds (the secret) invertible by meet-in-the-middle —
    /// guess the last two secret bytes working backward from one observed
    /// ISN, guess the first two working forward from the (fully public)
    /// 4-tuple hash, and any match where the two 65536-entry tables agree
    /// recovers bytes that reproduce that ISN exactly. Under the OLD
    /// generator that recovered secret then predicts ANY OTHER connection's
    /// ISN at the same instant exactly, because the same secret feeds every
    /// 4-tuple. Under HMAC-SHA256 the "recovered secret" is meaningless
    /// (there is nothing left in `tcp.rs` that even has this shape), so
    /// every candidate's prediction is just wrong.
    #[test]
    fn one_observed_isn_no_longer_lets_an_attacker_predict_another() {
        let _g = begin();

        const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
        const FNV_PRIME: u32 = 0x0100_0193;

        fn fwd(h: u32, b: u8) -> u32 {
            (h ^ b as u32).wrapping_mul(FNV_PRIME)
        }
        // Modular inverse of FNV_PRIME mod 2^32 (extended Euclid; FNV_PRIME
        // is odd, so it has one). Computed at test runtime rather than
        // hard-coded so this test does not silently rot if FNV_PRIME above
        // is ever typo'd — the sanity check right below would catch it.
        fn prime_inv() -> u32 {
            let (mut old_r, mut r) = (1i64 << 32, FNV_PRIME as i64);
            let (mut old_s, mut s) = (1i64, 0i64);
            let (mut old_t, mut t) = (0i64, 1i64);
            while r != 0 {
                let q = old_r / r;
                let (nr, ns, nt) = (old_r - q * r, old_s - q * s, old_t - q * t);
                old_r = r; r = nr;
                old_s = s; s = ns;
                old_t = t; t = nt;
            }
            old_t.rem_euclid(1i64 << 32) as u32
        }
        fn bwd(h: u32, b: u8, pinv: u32) -> u32 {
            h.wrapping_mul(pinv) ^ b as u32
        }

        let pinv = prime_inv();
        for &(h, b) in &[(0x1234_5678u32, 7u8), (0u32, 255u8), (u32::MAX, 1u8)] {
            assert_eq!(bwd(fwd(h, b), b, pinv), h, "fwd/bwd must be exact inverses");
        }

        // The public half of the OLD hash: IPs and ports only, no secret.
        // `generate_isn`'s argument order for an inbound SYN is (our_ip,
        // peer_ip, our_port, peer_port) — see `tcp.rs`'s SynRcvd setup.
        fn public_hash(peer_port: u16, our_port: u16) -> u32 {
            let mut h = FNV_OFFSET_BASIS;
            for &b in &OUR_IP { h = fwd(h, b); }
            for &b in &PEER_IP { h = fwd(h, b); }
            for &b in &our_port.to_be_bytes() { h = fwd(h, b); }
            for &b in &peer_port.to_be_bytes() { h = fwd(h, b); }
            h
        }

        // Meet-in-the-middle: recover every 4-byte value that reproduces
        // `observed_h_post` from `pub_hash` through 4 secret rounds, then
        // return each candidate's forward prediction for `pub_hash_b`.
        fn mitm_predict(
            pub_hash_a: u32, observed_h_post_a: u32, pub_hash_b: u32, pinv: u32,
        ) -> Vec<u32> {
            let mut forward = std::collections::HashMap::new();
            for s0 in 0u16..256 {
                let h0 = fwd(pub_hash_a, s0 as u8);
                for s1 in 0u16..256 {
                    forward.insert(fwd(h0, s1 as u8), (s0 as u8, s1 as u8));
                }
            }
            let mut predictions = Vec::new();
            for s3 in 0u16..256 {
                let h3 = bwd(observed_h_post_a, s3 as u8, pinv);
                for s2 in 0u16..256 {
                    let h1 = bwd(h3, s2 as u8, pinv);
                    if let Some(&(s0, s1)) = forward.get(&h1) {
                        let mut h = pub_hash_b;
                        for b in [s0, s1, s2 as u8, s3 as u8] { h = fwd(h, b); }
                        predictions.push(h);
                    }
                }
            }
            predictions
        }

        let now = 12_345_678u64;
        let ticks = now as u32;
        let pub_hash_a = public_hash(48000, 7021);
        let pub_hash_b = public_hash(48001, 7021);

        // ── Positive control: the attack against a SIMULATED old-style FNV
        // generator, so a false pass below (candidates happen to be empty,
        // or none happen to match) cannot be mistaken for the fix working —
        // this proves the meet-in-the-middle machinery itself is correct.
        let sim_secret = [0x11u8, 0x22, 0x33, 0x44];
        let old_fnv_isn = |pub_hash: u32| -> u32 {
            let mut h = pub_hash;
            for &b in &sim_secret { h = fwd(h, b); }
            h.wrapping_add(ticks)
        };
        let sim_isn_a = old_fnv_isn(pub_hash_a);
        let sim_isn_b = old_fnv_isn(pub_hash_b);
        let sim_predictions =
            mitm_predict(pub_hash_a, sim_isn_a.wrapping_sub(ticks), pub_hash_b, pinv);
        assert!(
            sim_predictions.iter().any(|&p| p.wrapping_add(ticks) == sim_isn_b),
            "positive control failed: against a KNOWN FNV generator the attack must \
             recover a secret that predicts the second ISN exactly -- the test's own \
             inversion is broken, not the generator's",
        );

        // ── The real test: the same attack against the REAL generator
        // (`generate_isn`, HMAC-SHA256 since U06-6).
        azos_drv_irqchip::clint::set_test_time(now);
        tcp::listen(7021);
        deliver(&segment(48000, 7021, 9000, 0, SYN, 4096, &[]));
        let isn_a = outbound().last().unwrap().seq;
        wire::clear_sent();
        deliver(&segment(48001, 7021, 9100, 0, SYN, 4096, &[]));
        let isn_b = outbound().last().unwrap().seq;

        let predictions =
            mitm_predict(pub_hash_a, isn_a.wrapping_sub(ticks), pub_hash_b, pinv);
        for &h in &predictions {
            assert_ne!(
                h.wrapping_add(ticks), isn_b,
                "a secret recovered from one observed ISN via the OLD FNV \
                 construction predicted the second connection's REAL ISN \
                 exactly -- the generator is invertible again",
            );
        }
    }
}

#[cfg(test)]
mod tcp_rx_state {
    use super::tcp_rx::*;
    use super::{tcp, wire};
    use azos_limits::TCP_MAX_CONNS;

    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;

    /// Anti-SYN-flood: half-open connections per listener are capped at half
    /// the table. Without it a handful of packets fills every slot with
    /// SynRcvd and no legitimate client can connect again — the table is 8
    /// entries, so the whole stack is one burst away from unusable.
    #[test]
    fn a_syn_flood_cannot_fill_the_connection_table() {
        let _g = begin();
        assert!(tcp::listen(7100) >= 0);

        // Every SYN comes from a different source port, so each is a distinct
        // connection rather than a retransmission.
        for i in 0..(TCP_MAX_CONNS as u16 * 2) {
            deliver(&segment(41000 + i, 7100, 9000 + i as u32, 0, SYN, 4096, &[]));
        }

        let half_open = count_in(tcp::TcpState::SynRcvd);
        assert!(
            half_open <= TCP_MAX_CONNS / 2,
            "{half_open} half-open connections from {} SYNs; the cap is {}",
            TCP_MAX_CONNS * 2, TCP_MAX_CONNS / 2,
        );
        // And the listener is still there to serve someone legitimate.
        assert!(
            slot_in(tcp::TcpState::Listen).is_some(),
            "the flood must not consume the listener itself",
        );
    }

    /// U06-7 / U13-5: a SYN trickle must not deafen the listener for as long
    /// as it lasts.
    ///
    /// The test above only ever delivers ONE burst and never moves the
    /// clock, so it cannot tell "the cap delays a connection" from "the cap
    /// deafens the listener forever" — the two behaviours the audit's own
    /// comment (before this fix) claimed were distinct. This delivers TEN
    /// separate floods, each refilling the half-open cap completely, WITHOUT
    /// ever advancing the clock — so the timer-based half-open reaper
    /// (`tcp_tick`, ~5 s) never once fires and could not be why a legitimate
    /// SYN gets through. Before U06-7 each flood round found the cap already
    /// full and dropped the legitimate SYN outright, every round, forever.
    /// After it, the flood reaps its own oldest half-open slot to make room,
    /// so the legitimate SYN lands in one of the cap's slots every round.
    #[test]
    fn a_sustained_syn_trickle_does_not_deafen_the_listener() {
        let _g = begin();
        assert!(tcp::listen(7101) >= 0);
        let cap = TCP_MAX_CONNS / 2;

        for round in 0..10u32 {
            // Flood: enough fresh 4-tuples to hit the half-open cap again,
            // even though last round's half-open slots were never reaped by
            // time (the clock has not moved since `begin()`).
            for i in 0..cap as u32 {
                let src_port = (40000 + round * 100 + i) as u16;
                deliver(&segment(src_port, 7101, 0x2000_0000 + (round << 16) + i,
                                 0, SYN, 4096, &[]));
            }
            assert!(
                count_in(tcp::TcpState::SynRcvd) <= cap,
                "round {round}: the half-open cap must still hold at {cap}",
            );

            // The legitimate client, from a port no flood segment used.
            wire::clear_sent();
            let legit_port = (49000 + round) as u16;
            deliver(&segment(legit_port, 7101, 0x3000_0000 + round, 0, SYN, 4096, &[]));
            let got_synack = outbound().iter().any(|o| o.flags & (SYN | ACK) == (SYN | ACK));
            assert!(
                got_synack,
                "round {round}: a legitimate SYN drew no SYN-ACK -- a sustained \
                 trickle deafened the listener",
            );
        }
    }

    /// M26: `find_conn`'s one-slot hint must agree with the full scan on
    /// EVERY lookup — a fresh connection, many repeats on the same
    /// 4-tuple, a distinct second connection (a hint miss), and a slot
    /// closed and reused — and it must turn "many consecutive segments on
    /// one connection" into one slot touch each, not a walk of the table.
    #[test]
    fn find_conn_hint_agrees_with_the_full_scan_and_costs_one_touch_per_repeat() {
        let _g = begin();
        let (idx_a, ours_a, mut theirs_a) = establish(7120, 41200, 0x1000_0000);

        // Many consecutive segments on the SAME connection. The hint should
        // hit every time from here on, at one slot touch each — not up to
        // `TCP_MAX_CONNS` touches each, which is what the plain linear scan
        // this replaces would cost every single time.
        let before = tcp::find_conn_slot_touches();
        const REPEATS: u64 = 20;
        for _ in 0..REPEATS {
            deliver(&segment(41200, 7120, theirs_a, ours_a, PSH | ACK, 4096, b"x"));
            theirs_a = theirs_a.wrapping_add(1);
        }
        let touches = tcp::find_conn_slot_touches() - before;
        assert_eq!(
            touches, REPEATS,
            "{REPEATS} consecutive segments on one connection cost {touches} \
             slot touches with the hint; must be exactly {REPEATS} (one hint \
             hit each), not up to {REPEATS} * {TCP_MAX_CONNS}",
        );
        let mut buf = [0u8; 32];
        assert_eq!(tcp::recv(idx_a, &mut buf), REPEATS as i32,
            "precondition: every one of those segments actually landed on A");

        // A distinct second connection: the hint (still pointing at A) must
        // MISS and fall back to the full scan — and land on B, not A.
        let (idx_b, ours_b, theirs_b) = establish(7121, 41201, 0x2000_0000);
        assert_ne!(idx_b, idx_a, "precondition: establish() gave B its own slot");
        deliver(&segment(41201, 7121, theirs_b, ours_b, PSH | ACK, 4096, b"y"));
        let mut buf_b = [0u8; 4];
        assert_eq!(tcp::recv(idx_b, &mut buf_b), 1, "B's segment must land on B");
        assert_eq!(&buf_b[..1], b"y");
        assert_eq!(tcp::recv(idx_a, &mut buf), 0, "and never on A");

        // Close A, then re-establish the SAME 4-tuple. The hint (from the
        // 20 repeats above) may still point at A's old slot; whether or not
        // `alloc()` happens to hand the new SYN that exact slot back, the
        // hint's `state != Closed` re-check must refuse a stale match the
        // instant a slot actually is closed, and the new incarnation's own
        // bytes must be the only ones a caller ever reads back — no bytes
        // surviving from the previous occupant.
        tcp::abort(idx_a);
        assert!(tcp::conn_state(idx_a) == tcp::TcpState::Closed,
            "precondition: abort must close the slot, got {}", st(tcp::conn_state(idx_a)));
        let (idx_a2, ours_a2, theirs_a2) = establish(7120, 41200, 0x1500_0000);
        deliver(&segment(41200, 7120, theirs_a2, ours_a2, PSH | ACK, 4096, b"fresh"));
        let n = tcp::recv(idx_a2, &mut buf) as usize;
        assert_eq!(&buf[..n], b"fresh",
            "the reused slot must deliver only the NEW incarnation's bytes");
    }

    /// RFC 793 §3.4. A RST outside the receive window must be ignored:
    /// otherwise one spoofed segment from anyone who can guess the 4-tuple
    /// tears the flow down.
    ///
    /// **What this does NOT assert, deliberately.** The code accepts any RST
    /// whose sequence falls anywhere in the 65535-byte window, and cites
    /// RFC 5961 while doing so. RFC 5961 §3.2 is stricter than that: only
    /// `SEG.SEQ == RCV.NXT` may be accepted, and an in-window-but-inexact RST
    /// should draw a challenge ACK instead. So an off-path attacker still only
    /// has to land inside a window rather than hit one number. Narrowing that
    /// is a hardening decision (it needs the challenge-ACK machinery), not a
    /// bug fix, so this suite pins today's behaviour rather than silently
    /// "fixing" the gap here.
    #[test]
    fn a_rst_outside_the_window_does_not_close_the_connection() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7101, 41100, 0x2000_0000);

        // Everything below `rcv_nxt` is behind the window; everything past
        // rcv_nxt + 65535 is beyond it.
        for bad in [
            theirs.wrapping_sub(1),
            theirs.wrapping_sub(100_000),
            theirs.wrapping_add(100_000),
            theirs.wrapping_add(1 << 31),
        ] {
            deliver(&segment(41100, 7101, bad, 0, RST, 4096, &[]));
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::Established,
                "a RST at seq {bad} is outside the window from {theirs} and must be \
                 ignored; state is {}", st(tcp::conn_state(idx)),
            );
        }
    }

    /// The same RST at the expected sequence number must work — otherwise the
    /// test above passes on a stack that ignores every RST, which is its own
    /// bug (the slot would leak for the lifetime of the board).
    #[test]
    fn a_rst_at_the_expected_sequence_closes_and_frees_the_slot() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7102, 41200, 0x3000_0000);
        deliver(&segment(41200, 7102, theirs, 0, RST, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Closed,
            "an acceptable RST must close the connection, got {}",
            st(tcp::conn_state(idx)),
        );
    }

    /// Payload reaches the receive buffer and comes back out of `recv` intact
    /// and in order, and the segment is acknowledged.
    #[test]
    fn in_window_data_is_delivered_and_acknowledged() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7103, 41300, 0x4000_0000);

        deliver(&segment(41300, 7103, theirs, ours, PSH | ACK, 4096, b"hello "));
        deliver(&segment(41300, 7103, theirs.wrapping_add(6), ours, PSH | ACK, 4096, b"world"));

        let acks = outbound();
        assert!(!acks.is_empty(), "received data must be acknowledged");
        assert_eq!(
            acks.last().unwrap().ack, theirs.wrapping_add(11),
            "the ACK must cover every byte accepted",
        );

        let mut buf = [0u8; 32];
        let n = tcp::recv(idx, &mut buf);
        assert_eq!(n, 11, "recv returned {n}");
        assert_eq!(&buf[..11], b"hello world");
    }

    /// Data outside the receive window must not be copied into the buffer.
    /// This is the bound that stands between a hostile peer and the rx ring.
    #[test]
    fn out_of_window_data_is_not_delivered() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7104, 41400, 0x5000_0000);

        // Far in the past and far in the future — neither is the next byte.
        deliver(&segment(41400, 7104, theirs.wrapping_sub(50_000), ours, PSH | ACK, 4096, b"PAST"));
        deliver(&segment(41400, 7104, theirs.wrapping_add(500_000), ours, PSH | ACK, 4096, b"FUTURE"));

        let mut buf = [0u8; 32];
        let n = tcp::recv(idx, &mut buf);
        assert!(n <= 0, "out-of-window bytes must not reach the application, got {n}");
    }

    /// The advertised window must track the free space in the receive buffer.
    ///
    /// This pins a fix made earlier in this session: `send_segment` advertised
    /// a CONSTANT window regardless of how full the buffer was, so a peer was
    /// told there was room that did not exist and kept sending into a full
    /// receiver.
    ///
    /// **The buffer has to be filled past 64 KiB for this to say anything**,
    /// which is not obvious and is why the first version of this test passed
    /// on a stack that never shrank the window at all. At `TCP_BUF_SIZE` =
    /// 128 KiB `window_clamp` caps the field at 65535, so the advertised
    /// window is pinned at its maximum until more than 64 KiB is unread —
    /// buffering 2 KiB, as this test first did, moves nothing. The fill is
    /// `PAST_CLAMP_KIB`, 72 KiB at that ring, so the same holds at whatever
    /// ring `.config` sets.
    #[test]
    fn the_advertised_window_shrinks_once_the_buffer_passes_the_clamp() {
        let _g = begin();
        let (idx, ours, mut theirs) = establish(7105, 41500, 0x6000_0000);

        deliver(&segment(41500, 7105, theirs, ours, PSH | ACK, 4096, b"x"));
        theirs = theirs.wrapping_add(1);
        let empty_win = outbound().last().unwrap().window;
        assert_eq!(
            empty_win, (azos_limits::TCP_BUF_SIZE - 2).min(u16::MAX as usize) as u16,
            "a buffer holding one byte advertises its free space, saturated at 65535",
        );
        wire::clear_sent();

        // Push past the clamp: 72 KiB unread at a 128 KiB ring leaves under
        // 64 KiB free.
        let chunk = [0x41u8; 1024];
        for _ in 0..PAST_CLAMP_KIB {
            deliver(&segment(41500, 7105, theirs, ours, PSH | ACK, 4096, &chunk));
            theirs = theirs.wrapping_add(chunk.len() as u32);
        }
        let full_win = outbound().last().unwrap().window;

        assert!(
            full_win < empty_win,
            "the window stayed at {full_win} with {PAST_CLAMP_KIB} KiB unread — a peer told \
             there is room that does not exist will overrun the receiver",
        );

        // And it reopens once the application drains.
        let mut buf = [0u8; 8192];
        let mut drained = 0;
        while tcp::recv(idx, &mut buf) > 0 {
            drained += 1;
            if drained > 64 { break; }
        }
        wire::clear_sent();
        deliver(&segment(41500, 7105, theirs, ours, PSH | ACK, 4096, b"y"));
        assert!(
            outbound().last().unwrap().window > full_win,
            "the window must reopen after the application reads",
        );
    }

    /// A FIN moves an established connection to CloseWait and is acknowledged
    /// at the sequence number after the FIN's own — the FIN occupies one.
    #[test]
    fn a_fin_moves_to_close_wait_and_is_acknowledged_past_itself() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7106, 41600, 0x7000_0000);

        deliver(&segment(41600, 7106, theirs, ours, FIN | ACK, 4096, b"bye"));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::CloseWait,
            "a FIN on an established connection means CloseWait, got {}",
            st(tcp::conn_state(idx)),
        );
        assert_eq!(
            outbound().last().unwrap().ack, theirs.wrapping_add(4),
            "3 payload bytes plus the FIN's own sequence number",
        );
    }

    /// Sequence numbers are modulo 2^32 and the kernel builds with
    /// `overflow-checks = true`, so a peer that positions a flow near the wrap
    /// point is handing the stack arithmetic that panics if any of it is
    /// written with `+` instead of `wrapping_add`. A panic here is
    /// `panic = "abort"`, i.e. a board reset from a remote segment.
    #[test]
    fn a_flow_across_the_sequence_wrap_neither_panics_nor_loses_data() {
        let _g = begin();
        // Peer ISN chosen so the handshake alone crosses 2^32.
        let (idx, ours, theirs) = establish(7107, 41700, u32::MAX - 2);

        deliver(&segment(41700, 7107, theirs, ours, PSH | ACK, 4096, b"AB"));
        deliver(&segment(41700, 7107, theirs.wrapping_add(2), ours, PSH | ACK, 4096, b"CD"));

        let mut buf = [0u8; 16];
        let n = tcp::recv(idx, &mut buf);
        assert_eq!(n, 4, "data spanning the wrap must survive it, got {n}");
        assert_eq!(&buf[..4], b"ABCD");
        assert_eq!(
            outbound().last().unwrap().ack, theirs.wrapping_add(4),
            "the ACK must wrap with the sequence space",
        );
    }

    /// The same, driven hard: every sequence number a hostile peer could pick,
    /// against a connection sitting on the wrap. None may panic.
    #[test]
    fn no_sequence_number_a_peer_can_choose_panics_the_receiver() {
        let _g = begin();
        let (_idx, ours, theirs) = establish(7108, 41800, u32::MAX - 10);

        let nasty = [
            0u32, 1, u32::MAX, u32::MAX - 1, u32::MAX / 2, (u32::MAX / 2) + 1,
            theirs, theirs.wrapping_sub(1), theirs.wrapping_add(1),
            theirs.wrapping_add(1 << 31), theirs.wrapping_sub(1 << 31),
        ];
        for &seq in &nasty {
            for &ackn in &[0u32, ours, ours.wrapping_add(1 << 31), u32::MAX] {
                for &fl in &[ACK, PSH | ACK, FIN | ACK, SYN | ACK, RST, RST | ACK, 0] {
                    deliver(&segment(41800, 7108, seq, ackn, fl, 4096, b"z"));
                }
            }
        }
        // Reaching here without a panic is the assertion. Say so, so the test
        // is not mistaken for one that forgot to assert.
        assert!(true, "no segment in the sweep panicked the receiver");
    }
}

/// Every path that advertises a receive window.
///
/// **Why this module exists separately.** Earlier in this session
/// `send_segment` was found advertising a CONSTANT window, and the fix touched
/// five call sites. A single test covering the in-order-data ACK looked like
/// it pinned that fix — and did not: replacing four of the five with the old
/// constant left it green. Each site is driven here, and each was verified by
/// putting the constant back one line at a time.
///
/// The stakes are the same at every one: a peer told there is room that does
/// not exist keeps sending, and the receiver drops what it cannot hold.
#[cfg(test)]
mod tcp_window_sites {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;

    /// Establish, then buffer `PAST_CLAMP_KIB` unread (more than 64 KiB at the
    /// 128 KiB ring) so the advertised window drops below `EMPTY_WINDOW`, the
    /// `window_clamp` ceiling there, and a constant becomes visible.
    fn established_with_full_buffer(port: u16, peer_port: u16) -> (usize, u32, u32) {
        let (idx, ours, mut theirs) = establish(port, peer_port, 0x8000_0000);
        let chunk = [0x5Au8; 1024];
        for _ in 0..PAST_CLAMP_KIB {
            deliver(&segment(peer_port, port, theirs, ours, PSH | ACK, 4096, &chunk));
            theirs = theirs.wrapping_add(chunk.len() as u32);
        }
        wire::clear_sent();
        (idx, ours, theirs)
    }

    fn last_window() -> u16 {
        outbound().last().expect("a segment should have been sent").window
    }

    /// `send_data` — the ordinary transmit path. Data we send carries our own
    /// receive window, and it is the segment the peer sees most often.
    #[test]
    fn outbound_data_advertises_the_live_window() {
        let _g = begin();
        let (idx, _ours, _theirs) = established_with_full_buffer(7200, 42000);
        assert!(tcp::send_data(idx, b"payload") > 0, "send_data should succeed");
        assert!(
            last_window() < EMPTY_WINDOW,
            "outbound data advertised {} with {PAST_CLAMP_KIB} KiB unread", last_window(),
        );
    }

    /// The window update `recv` sends. This is the segment that tells a peer
    /// it may resume: once the window reaches zero the peer stops sending, so
    /// there is no inbound segment left to piggyback an ACK on.
    ///
    /// Since wave 15 (N6) it is no longer one pure ACK per read:
    /// - a read that opens less than one SMSS sends nothing (RFC 1122
    ///   §4.2.3.3 receiver SWS);
    /// - a larger one, while the peer still has most of its window, is held
    ///   like a delayed ACK and leaves from `tcp_tick` after `TCP_DELACK_MS`
    ///   -- and must then carry the live free space, not a constant;
    /// - draining the ring opens it past `TCP_WINDOW_UPDATE_SHIFT` and goes
    ///   at once, advertising the full clamp.
    ///
    /// **Read only a little.** The first version of this test drained 16 KiB
    /// and then allowed itself `|| n >= 8 * 1024` — a disjunction that let it
    /// pass without looking at the window at all. Reading 4 KiB of 72 leaves
    /// the buffer far enough past the clamp that the advertised value has to
    /// be below the ceiling.
    #[test]
    fn the_window_update_after_a_read_carries_the_new_free_space() {
        let _g = begin();
        let (idx, _ours, _theirs) = established_with_full_buffer(7201, 42100);
        let t0 = azos_drv_irqchip::clint::get_time();

        let mut buf = [0u8; 1024];
        assert_eq!(tcp::recv(idx, &mut buf), 1024, "there should be buffered data to read");
        assert_eq!(wire::sent_count(), 0, "a read that opens less than one SMSS must not advertise");
        let mut buf = [0u8; 3072];
        assert_eq!(tcp::recv(idx, &mut buf), 3072);
        assert_eq!(wire::sent_count(), 0,
            "an update the peer does not need yet is held, not sent per read");

        if azos_limits::TCP_DELACK_MS != 0 {
            azos_drv_irqchip::clint::set_test_time(
                t0 + (azos_limits::TCP_DELACK_MS as u64 + 1)
                    * (azos_drv_sys::timebase::TIMER_FREQ / 1000));
            tcp::tcp_tick();
        }
        assert_eq!(wire::sent_count(), 1, "the held update must leave once, when its delay runs out");
        assert!(
            last_window() < EMPTY_WINDOW,
            "the window update advertised {} with {} KiB still unread",
            last_window(), PAST_CLAMP_KIB - 4,
        );

        // Draining the rest must reopen it all the way, without waiting.
        let mut big = [0u8; 8192];
        while tcp::recv(idx, &mut big) > 0 {}
        assert_eq!(
            last_window(), EMPTY_WINDOW,
            "an emptied buffer must advertise the full clamp again",
        );
    }

    /// The RTO retransmission in `tcp_tick`. A retransmission carrying the
    /// constant would reopen a window we had already closed — and it is sent
    /// exactly when the peer is under pressure.
    #[test]
    fn an_rto_retransmission_advertises_the_live_window() {
        let _g = begin();
        let (idx, _ours, _theirs) = established_with_full_buffer(7202, 42200);
        assert!(tcp::send_data(idx, b"unacked") > 0);
        assert!(tcp::is_unacked(idx), "the segment must still be outstanding");
        wire::clear_sent();

        // Push the clock far past any RTO and let the timer fire.
        azos_drv_irqchip::clint::set_test_time(10_000 + 1_000_000_000);
        tcp::tcp_tick();

        assert!(wire::sent_count() > 0, "an unacknowledged segment must be retransmitted");
        assert!(
            last_window() < EMPTY_WINDOW,
            "the retransmission advertised {} with {PAST_CLAMP_KIB} KiB unread", last_window(),
        );
    }

    /// **TCP deadlines on the kernel timer (wave 15).** `next_deadline` is
    /// exactly when `tcp_tick` retransmits: one tick early nothing leaves,
    /// at the deadline the segment does, and the next deadline is the
    /// backed-off RTO from there. The net poll task sleeps until this value,
    /// so an RTO no longer waits for a periodic tick. Canary: make
    /// `conn_deadline` ignore `flight()` (or add the old 100 ms tick to it)
    /// and the first or second assertion fails.
    #[test]
    fn the_rto_fires_at_next_deadline_and_not_a_tick_before() {
        let _g = begin();
        let (idx, _ours, _theirs) = established_with_full_buffer(7203, 42300);
        let t0 = azos_drv_irqchip::clint::get_time();
        assert!(tcp::send_data(idx, b"unacked") > 0);
        wire::clear_sent();
        let rto = tcp::conn_rtt(idx).unwrap().rto_ticks;
        let d = tcp::next_deadline().expect("data in flight has a deadline");
        assert!(d <= t0 + rto + 1 && d >= t0, "deadline {d} not at the RTO (t0 {t0}, rto {rto})");

        azos_drv_irqchip::clint::set_test_time(d - 1);
        tcp::tcp_tick();
        assert_eq!(wire::sent_count(), 0, "nothing may be retransmitted before the deadline");

        azos_drv_irqchip::clint::set_test_time(d);
        tcp::tcp_tick();
        assert_eq!(wire::sent_count(), 1, "the RTO must fire at its deadline");
        let d2 = tcp::next_deadline().unwrap();
        assert_eq!(d2, d + 2 * rto, "the next deadline is the backed-off RTO");
    }

    /// **Delayed ACK on time (wave 15).** A held window update's deadline is
    /// at most `TCP_DELACK_MS` away, and `tcp_tick` at that tick sends it.
    /// With the poll task sleeping until `next_deadline`, the ACK leaves at
    /// 40 ms (plus the timer's own latency), not at a 100 ms poll tick.
    #[test]
    fn a_held_ack_is_due_within_the_delack_delay() {
        if azos_limits::TCP_DELACK_MS == 0 { return; }
        let _g = begin();
        let (idx, _ours, _theirs) = established_with_full_buffer(7204, 42400);
        let t0 = azos_drv_irqchip::clint::get_time();
        let mut buf = [0u8; 4096];
        assert_eq!(tcp::recv(idx, &mut buf), 4096);
        assert_eq!(wire::sent_count(), 0, "the update is held");
        let delack = azos_limits::TCP_DELACK_MS as u64 * (azos_drv_sys::timebase::TIMER_FREQ / 1000);
        let d = tcp::next_deadline().expect("a held ACK has a deadline");
        assert!(d <= t0 + delack, "held-ACK deadline {d} later than t0 {t0} + {delack}");
        azos_drv_irqchip::clint::set_test_time(d);
        tcp::tcp_tick();
        assert_eq!(wire::sent_count(), 1, "the held ACK must leave at its deadline");
    }

    static KICKS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    fn count_kick() { KICKS.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }

    /// **A deadline armed while the poll task sleeps wakes it (wave 15).**
    /// The task publishes its wake (`poll_sleep_until`); a `send_data` that
    /// starts an RTO earlier than that kicks it, and the same send while it
    /// runs (`poll_running`) does not. Canary: drop `note_conn` from
    /// `send_data` and the first assertion fails (the RTO would wait for
    /// the 60 s ceiling).
    #[test]
    fn an_earlier_deadline_armed_elsewhere_kicks_the_sleeping_poll_task() {
        use std::sync::atomic::Ordering;
        let _g = begin();
        let (idx, ours, theirs) = established_with_full_buffer(7205, 42500);
        tcp::set_timer_kick(count_kick);
        // Asleep until the nearest deadline there is (the keep-alive, 30 s).
        let dl = tcp::next_deadline().expect("an established connection has a keep-alive");
        assert!(tcp::poll_sleep_until(dl), "nothing due earlier yet");
        KICKS.store(0, Ordering::SeqCst);
        assert!(tcp::send_data(idx, b"x") > 0);
        let kicked = KICKS.load(Ordering::SeqCst);
        // Acknowledge it, then the same while the task runs.
        deliver(&segment(42500, 7205, theirs, ours.wrapping_add(1), 0x10, 4096, &[]));
        tcp::poll_running();
        KICKS.store(0, Ordering::SeqCst);
        assert!(tcp::send_data(idx, b"y") > 0);
        let running = KICKS.load(Ordering::SeqCst);
        assert!(kicked >= 1, "an RTO armed under a far wake did not kick the poll task");
        assert_eq!(running, 0, "a deadline armed while the poll task runs needs no kick");
    }

    /// The fast-retransmit path, reached after three duplicate ACKs
    /// (RFC 5681 §3.2) rather than by the timer.
    ///
    /// The peer has to acknowledge something first: `dup_ack_count` only
    /// counts an ACK that repeats `last_ack_recv`, and that field is written
    /// only when an ACK *advances*. The handshake does not set it, so three
    /// ACKs straight after establishing are not duplicates of anything —
    /// which is why the first version of this test saw no retransmission.
    #[test]
    fn a_fast_retransmission_advertises_the_live_window() {
        let _g = begin();
        let (idx, ours, theirs) = established_with_full_buffer(7203, 42300);

        // Round one: send, and let the peer acknowledge it. This is what
        // establishes `last_ack_recv`.
        assert!(tcp::send_data(idx, b"first") > 0);
        let after_first = ours.wrapping_add(5);
        deliver(&segment(42300, 7203, theirs, after_first, ACK, 4096, &[]));
        assert!(!tcp::is_unacked(idx), "the peer acknowledged the first segment");

        // Round two: send again, then repeat the previous ACK three times.
        assert!(tcp::send_data(idx, b"second") > 0);
        assert!(tcp::is_unacked(idx), "the second segment is outstanding");
        wire::clear_sent();
        for _ in 0..3 {
            deliver(&segment(42300, 7203, theirs, after_first, ACK, 4096, &[]));
        }

        assert!(
            wire::sent_count() > 0,
            "three duplicate ACKs must trigger a fast retransmission",
        );
        assert!(
            last_window() < EMPTY_WINDOW,
            "the fast retransmission advertised {} with {PAST_CLAMP_KIB} KiB unread", last_window(),
        );
    }
}

/// The two teardown states that could still hold a slot forever, and the one
/// that made the PEER hold one.
#[cfg(test)]
mod tcp_teardown_bounds {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const FIN: u8 = 0x01;
    const ACK: u8 = 0x10;

    /// Restated deliberately: if either constant moves, these fail and someone
    /// looks at the teardown timers rather than at the tests.
    const TICKS_PER_MS: u64 = 10_000;
    const FIN_WAIT2_TIMEOUT: u64 = 60_000 * TICKS_PER_MS;
    const TIME_WAIT: u64 = 2_000 * TICKS_PER_MS;
    const T0: u64 = 3_000_000;

    /// The sequence of the last segment we put on the wire. `tcp_close` has
    /// its own copy; duplicated rather than made `pub(super)` because these
    /// two modules should be free to diverge on what "last" means without
    /// silently changing each other's meaning.
    fn last_seq() -> u32 {
        outbound().last().expect("a segment should have been sent").seq
    }

    /// Walk to FinWait2: we close, the peer acknowledges our FIN, and then owes
    /// us a FIN of its own.
    fn to_fin_wait2(port: u16, peer: u16, isn: u32) -> usize {
        let (idx, _ours, theirs) = establish(port, peer, isn);
        tcp::close(idx);
        let fin_seq = last_seq();
        deliver(&segment(peer, port, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2,
            "precondition: expected FinWait2, got {}", st(tcp::conn_state(idx)));
        idx
    }

    /// `FinWait2` means the peer owes us a FIN, and nothing obliges it to ever
    /// send one. A peer that crashes here, or whose application simply never
    /// closes, held the slot for the life of the boot — every other teardown
    /// state has a bound and this one did not.
    ///
    /// Both directions asserted: too short and a peer with a slow application
    /// gets cut off mid-work, which is the failure that makes people delete
    /// the timeout again.
    #[test]
    fn a_peer_that_never_sends_its_fin_stops_costing_a_slot() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let idx = to_fin_wait2(7600, 44100, 0x2200_0000);

        azos_drv_irqchip::clint::set_test_time(T0 + FIN_WAIT2_TIMEOUT - 1);
        tcp::tcp_tick();
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2,
            "reclaimed early — a peer one tick inside the budget is still allowed to \
             finish closing, and cutting it off is how this timeout gets deleted again");

        azos_drv_irqchip::clint::set_test_time(T0 + FIN_WAIT2_TIMEOUT);
        tcp::tcp_tick();
        assert!(tcp::conn_state(idx) == tcp::TcpState::Closed,
            "the slot is still held in {} — with eight of them the robot can neither \
             dial out nor accept a connection", st(tcp::conn_state(idx)));
    }

    /// Reaching `FinWait2` must not silence the reclaim: the state is entered
    /// from a segment, not from a tick, so its deadline has to be stamped
    /// there. Asserted separately because a missing stamp reads as a timeout
    /// that fires immediately or never, depending on what `retx_time` happened
    /// to hold.
    #[test]
    fn the_fin_wait2_deadline_is_stamped_on_entry_not_inherited() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, _ours, theirs) = establish(7601, 44101, 0x3300_0000);
        tcp::close(idx);
        let fin_seq = last_seq();

        // The clock runs well past the FinWait2 budget BEFORE we enter the
        // state. This is what makes the test discriminate: a deadline stamped
        // on entry is fresh, while one inherited from whatever `retx_time`
        // held is already older than the budget, and the very first tick
        // reclaims the slot. Without this the two are indistinguishable,
        // because `close()` happens to leave `retx_time` at the current time —
        // the first version of this test asserted at that instant and passed
        // against its own mutant.
        azos_drv_irqchip::clint::set_test_time(T0 + 2 * FIN_WAIT2_TIMEOUT);
        deliver(&segment(44101, 7601, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2,
            "precondition: expected FinWait2, got {}", st(tcp::conn_state(idx)));

        tcp::tcp_tick();
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2,
            "closed on the very first tick after entering FinWait2 — the deadline was \
             inherited from a stale `retx_time` rather than stamped on entry, so a peer \
             that closes late gets no budget at all");
    }

    /// A FIN arriving in `TimeWait` is the peer retransmitting because our
    /// final ACK was lost. Ignoring it is not harmless: it is precisely why
    /// the peer is stuck, sitting in `LastAck` resending a FIN nobody answers
    /// until its budget runs out and it tears the connection down as if we had
    /// vanished.
    #[test]
    fn a_retransmitted_fin_in_time_wait_is_acknowledged_again() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, _ours, theirs) = establish(7602, 44102, 0x4400_0000);
        tcp::close(idx);
        let fin_seq = last_seq();
        deliver(&segment(44102, 7602, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        deliver(&segment(44102, 7602, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait,
            "precondition: expected TimeWait, got {}", st(tcp::conn_state(idx)));

        wire::clear_sent();
        deliver(&segment(44102, 7602, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));

        let out = outbound();
        assert_eq!(out.len(), 1, "the retransmitted FIN drew no reply, so the peer stays \
                                  in LastAck until it gives up on us");
        assert_eq!(out[0].flags & ACK, ACK, "the reply must acknowledge");
        assert_eq!(out[0].ack, theirs.wrapping_add(1),
            "and cover the peer's FIN, or it will keep retransmitting");
    }

    /// The re-ACK must also RESTART the timer, and this is the half a
    /// reply-only test would miss. TIME-WAIT exists to outlive every in-flight
    /// segment of the connection; a retransmitted FIN is proof something is
    /// still in flight, so keeping the original deadline would let the slot be
    /// reused while the peer is still talking to it.
    #[test]
    fn a_retransmitted_fin_restarts_the_time_wait_timer() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, _ours, theirs) = establish(7603, 44103, 0x5500_0000);
        tcp::close(idx);
        let fin_seq = last_seq();
        deliver(&segment(44103, 7603, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        deliver(&segment(44103, 7603, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));

        // Most of the way through TIME-WAIT, the peer retransmits.
        let t1 = T0 + TIME_WAIT - TIME_WAIT / 4;
        azos_drv_irqchip::clint::set_test_time(t1);
        deliver(&segment(44103, 7603, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));

        // The ORIGINAL deadline passes. With a restarted timer the slot lives.
        azos_drv_irqchip::clint::set_test_time(T0 + TIME_WAIT + 1);
        tcp::tcp_tick();
        assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait,
            "the slot was released at its original deadline even though the peer was \
             still retransmitting — TIME-WAIT stopped outliving the segments in flight, \
             which is the only thing it is for");

        // And the restarted one does eventually expire.
        azos_drv_irqchip::clint::set_test_time(t1 + TIME_WAIT + 1);
        tcp::tcp_tick();
        assert!(tcp::conn_state(idx) == tcp::TcpState::Closed,
            "the restarted timer never expired, got {} — a timer that only ever restarts \
             is a slot leak wearing a timer's clothes", st(tcp::conn_state(idx)));
    }

    /// Only a FIN. A stray ACK in TIME-WAIT gets nothing, or two stacks both
    /// in TIME-WAIT would answer each other indefinitely.
    #[test]
    fn a_non_fin_segment_in_time_wait_draws_no_reply() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, _ours, theirs) = establish(7604, 44104, 0x6600_0000);
        tcp::close(idx);
        let fin_seq = last_seq();
        deliver(&segment(44104, 7604, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        deliver(&segment(44104, 7604, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait, "precondition");

        wire::clear_sent();
        deliver(&segment(44104, 7604, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(outbound().is_empty(),
            "a bare ACK in TIME-WAIT was answered — two peers both in TIME-WAIT would \
             then trade acknowledgements with nothing to stop them");
    }
}

/// A FIN is a byte of sequence space and must be retransmitted like any other.
///
/// Until this landed, nothing did. `close()` sent the FIN through
/// `send_segment`, recorded `fin_seq` and the state, and marked nothing
/// outstanding — so no branch of `tcp_tick` ever looked at it again. A single
/// lost FIN parked the slot in `FinWait1` or `LastAck` until reboot, and with
/// eight slots the robot could neither dial out nor accept a connection. It is
/// the class `SYN_MAX_RETRIES` already closed for half-open slots, stopped at
/// the handshake.
///
/// Both tests assert the RETRANSMITTED SEGMENT before they assert any state.
/// That order is the point: a reaper that frees the slot without ever resending
/// passes every state assertion, and it is the more likely wrong
/// implementation of the two.
#[cfg(test)]
mod tcp_fin_retransmit {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const FIN: u8 = 0x01;
    const ACK: u8 = 0x10;

    /// One second per the SYN retry interval, restated deliberately: if the
    /// interval changes these fail and someone looks at the teardown timer.
    const RETRY: u64 = 1_000 * 10_000;
    const T0: u64 = 2_000_000;

    #[test]
    fn an_unacknowledged_fin_is_retransmitted_at_the_sequence_it_first_went_out_at() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, ours, theirs) = establish(7500, 42700, 0x7000_0000);

        tcp::close(idx);
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait1,
            "precondition: an active close must reach FinWait1, got {}",
            st(tcp::conn_state(idx)),
        );
        // The peer acknowledges nothing. This is the lost-FIN case.
        wire::clear_sent();

        azos_drv_irqchip::clint::set_test_time(T0 + RETRY);
        tcp::tcp_tick();

        let out = outbound();
        assert_eq!(out.len(), 1, "the FIN was never resent, got {} segments", out.len());
        assert_eq!(out[0].flags & FIN, FIN, "the resent segment must carry FIN");
        // Asserted, but honestly: `fin_seq` and `snd.nxt` are equal in every
        // reachable state today, so this cannot tell the two apart. It is here
        // to catch a resend at some third value, and to fail loudly if `snd.nxt`
        // ever starts advancing over the FIN as RFC 793 wants.
        assert_eq!(
            out[0].seq, ours,
            "the FIN was resent at a sequence the peer is not waiting on, so it will be \
             discarded and the slot never freed",
        );
        let _ = theirs;
    }

    /// The budget must free the slot, not leave it. An unreclaimable slot is
    /// the failure this timer exists to prevent, so giving up cannot recreate
    /// it.
    #[test]
    fn a_peer_that_never_acknowledges_the_fin_eventually_frees_the_slot() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, _ours, _theirs) = establish(7501, 42701, 0x8000_0000);

        tcp::close(idx);

        let mut resends = 0usize;
        let mut t = T0;
        for _ in 0..12 {
            t += RETRY;
            azos_drv_irqchip::clint::set_test_time(t);
            wire::clear_sent();
            tcp::tcp_tick();
            resends += outbound().iter().filter(|o| o.flags & FIN != 0).count();
        }

        assert!(
            resends >= 2,
            "only {resends} FIN retransmissions before the slot was reaped — a reaper \
             that frees without ever resending passes every state assertion, so the \
             count is what distinguishes it",
        );
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Closed,
            "the slot is still held in {} — an unreclaimable slot is exactly the failure \
             this timer exists to prevent",
            st(tcp::conn_state(idx)),
        );
    }

    /// And a peer that DOES acknowledge must not be retransmitted at.
    #[test]
    fn an_acknowledged_fin_is_not_retransmitted() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, ours, theirs) = establish(7502, 42702, 0x9000_0000);

        tcp::close(idx);
        // The peer acknowledges our FIN: ack covers the FIN's own byte.
        deliver(&segment(42702, 7502, theirs, ours.wrapping_add(1), ACK, 4096, &[]));

        wire::clear_sent();
        azos_drv_irqchip::clint::set_test_time(T0 + 3 * RETRY);
        tcp::tcp_tick();

        assert!(
            outbound().iter().all(|o| o.flags & FIN == 0),
            "a FIN the peer already acknowledged was retransmitted — the timer is firing \
             on state rather than on what is outstanding",
        );
    }
}

/// One `recv` may not copy the whole receive ring while holding the lock.
///
/// The copy is byte-at-a-time and was bounded only by `min(available, caller's
/// buffer)` — a property of the CALLER. Every caller today happens to cap at
/// 4 KiB because `SYS_RECV` does, but nothing stopped a future one asking for
/// the full 128 KiB ring, which is over a million RV64 instructions with
/// `TCP.lock()` held. Since K-C29 step 2 that section is non-preemptible, so
/// the bound became a real-time latency floor chosen by whoever calls `recv`.
///
/// The test asks for MORE than the cap with MORE than the cap available. That
/// is the only input where a capped and an uncapped implementation differ: ask
/// for less and both return the same, ask with less available and both return
/// what there is.
#[cfg(test)]
mod tcp_recv_bound {
    use super::tcp_rx::*;
    use super::tcp;

    const ACK: u8 = 0x10;

    #[test]
    fn one_recv_copies_at_most_its_cap_even_when_more_is_buffered() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7700, 44200, 0xA100_0000);

        // Push well past the 4 KiB cap into the receive ring, in MSS-sized
        // segments so the stack accepts them in order.
        const SEG: usize = 1000;
        const SEGS: usize = 8;              // 8000 bytes, comfortably over 4096
        let payload = [0xABu8; SEG];
        let mut seq = theirs;
        for _ in 0..SEGS {
            deliver(&segment(44200, 7700, seq, ours, ACK, 4096, &payload));
            seq = seq.wrapping_add(SEG as u32);
        }

        let mut buf = [0u8; 16384];         // asking for far more than the cap
        let n = tcp::recv(idx, &mut buf);
        assert!(n > 0, "nothing was buffered; the test measures nothing");
        assert!(
            n as usize <= 4096,
            "one recv copied {n} bytes with the connection lock held. The bound \
             belongs to this function, not to whoever happens to call it — an \
             uncapped copy of the full ring is over a million instructions of \
             non-preemptible time.",
        );

        // And a short read must not lose the rest: the next call gets more.
        let m = tcp::recv(idx, &mut buf);
        assert!(
            m > 0,
            "the capped read dropped the remaining bytes instead of leaving them \
             buffered — a short read is only acceptable because the caller can \
             come back for the rest",
        );
    }
}

/// One task must not be able to take every socket on the machine.
///
/// `MAX_SOCKETS` is 16 for the whole robot, not per task. Until the quota
/// existed, a ring-3 program opening sockets in a loop took all of them, and
/// the denial landed silently on whoever asked next — including the brain
/// link, whose socket carries the e-stop. A safety failure with a
/// resource-accounting cause.
///
/// Both halves are asserted. A quota that starves the kernel's own channels
/// would be a worse bug than the one it fixes, so the kernel-owned exemption
/// is pinned here beside the limit itself.
#[cfg(test)]
mod socket_quota {
    use super::socket;
    use super::NET_SERIAL as SERIAL;

    /// The socket table is global state shared with every other suite in this
    /// file, so isolation is the same shape `socket_table` uses: take the net
    /// serial lock, close every fd, and STATE the precondition rather than
    /// inherit it. The first version of these tests used the TCP `begin()`,
    /// which serialises but does not clear sockets — they then measured a table
    /// another test had filled, and left it full for the two after them.
    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        for fd in 0..socket::MAX_SOCKETS {
            socket::socket_close(fd as i32);
        }
        for fd in 0..socket::MAX_SOCKETS {
            assert!(
                socket::socket_owner(fd as i32).is_none(),
                "fd {fd} was left owned by the previous test",
            );
        }
        g
    }

    #[test]
    fn one_task_cannot_take_every_socket_on_the_machine() {
        let _g = begin();
        const TASK: u32 = 4242;

        let mut got = 0usize;
        for _ in 0..socket::MAX_SOCKETS {
            if socket::socket_create_owned(socket::AF_INET, socket::SOCK_STREAM, 0, TASK) >= 0 {
                got += 1;
            }
        }

        assert_eq!(
            got, socket::MAX_SOCKETS_PER_TASK,
            "one task obtained {got} of the machine's {} sockets. Everything past \
             the quota is a socket the brain link cannot have, and the refusal it \
             gets is indistinguishable from the link being broken.",
            socket::MAX_SOCKETS,
        );
    }

    /// The exemption, asserted separately: charging the kernel's own sockets
    /// against a per-task quota would mean the kernel competing with userspace
    /// for its own e-stop channel.
    #[test]
    fn kernel_owned_sockets_are_not_charged_against_a_task_quota() {
        let _g = begin();

        let mut got = 0usize;
        for _ in 0..socket::MAX_SOCKETS {
            if socket::socket_create(socket::AF_INET, socket::SOCK_STREAM, 0) >= 0 {
                got += 1;
            }
        }

        assert!(
            got > socket::MAX_SOCKETS_PER_TASK,
            "the kernel got only {got} sockets — it is being charged against a \
             per-task quota, so a busy userspace can starve the e-stop channel \
             through the very mechanism meant to protect it",
        );
    }
}

/// RFC 793 §3.4 reset generation.
///
/// Silence is not a neutral answer to a segment that belongs to nobody. After
/// the robot reboots the brain's socket survives: we come up with an empty
/// connection table, its segments match no slot, and saying nothing leaves it
/// retransmitting into a black hole until its own budget expires — minutes on
/// Linux defaults — during which the operator believes they are commanding a
/// robot that is not listening. On a one-hop link a reset ends that in
/// microseconds.
///
/// Every assertion here is on the EMITTED BYTES, and that is what makes these
/// tests non-decorative: the mutant is a `return` immediately before the send,
/// and a test asserting "the slot is gone" or "the state is Closed" passes
/// against it, because the local state changes either way.
#[cfg(test)]
mod tcp_reset {
    use super::tcp_rx::*;
    use super::tcp;

    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;

    /// A segment carrying ACK is answered with `SEQ = SEG.ACK` and no ACK bit.
    ///
    /// The sequence is not a detail: a reset outside the peer's window is
    /// discarded by its own acceptability check, so a reset with the wrong
    /// sequence is exactly as useful as sending nothing.
    #[test]
    fn a_segment_for_no_connection_is_reset_at_the_sequence_it_acknowledged() {
        let _g = begin();
        super::wire::clear_sent();

        deliver(&segment(42600, 7400, 0x1111_1111, 0x2222_2222, ACK | PSH, 4096, b"hi"));

        let out = outbound();
        assert_eq!(out.len(), 1,
            "a segment matching nothing must be answered, got {} replies", out.len());
        let r = out[0];
        assert_eq!(r.flags & RST, RST, "the reply must be a RST");
        assert_eq!(r.flags & ACK, 0,
            "a reset answering an ACK-bearing segment must NOT set ACK — RFC 793 §3.4 \
             gives it a sequence instead");
        assert_eq!(r.seq, 0x2222_2222,
            "SEQ must be the offending segment's ACK. Any other value lands outside the \
             peer's window and is discarded, which is the same as staying silent.");
    }

    /// A SYN to a port with no listener. No ACK came in, so the reset carries
    /// `SEQ = 0` and acknowledges `SEG.SEQ + SEG.LEN` — and a SYN occupies one
    /// byte of sequence space.
    #[test]
    fn a_syn_to_a_dead_port_is_reset_with_the_syn_counted_as_a_byte() {
        let _g = begin();
        super::wire::clear_sent();

        deliver(&segment(42601, 7401, 0x3333_3333, 0, SYN, 4096, &[]));

        let out = outbound();
        assert_eq!(out.len(), 1, "a SYN to a dead port must be refused, not dropped");
        let r = out[0];
        assert_eq!(r.flags & RST, RST, "the reply must be a RST");
        assert_eq!(r.flags & ACK, ACK, "with no inbound ACK, the reset must acknowledge");
        assert_eq!(r.seq, 0, "SEQ must be 0 when the offending segment carried no ACK");
        assert_eq!(r.ack, 0x3333_3334,
            "ACK must cover the SYN's own byte of sequence space. Off by one and the peer \
             discards the reset and keeps waiting out its SYN budget.");
    }

    /// Never answer a reset with a reset. Two stacks that did would trade them
    /// forever, and the loop lives on the wire rather than in either of them —
    /// the kind diagnosed from a capture, not from a log.
    #[test]
    fn an_inbound_reset_draws_no_reply() {
        let _g = begin();
        super::wire::clear_sent();

        deliver(&segment(42602, 7402, 0x4444_4444, 0x5555_5555, RST | ACK, 0, &[]));

        assert!(outbound().is_empty(),
            "a RST was answered with a RST — on the wire that is a loop neither end can \
             break, because each is behaving correctly by its own reading");
    }

    /// `abort()` must reach the peer, not merely free the slot.
    #[test]
    fn abort_tells_the_peer_before_dropping_the_slot() {
        let _g = begin();
        let (idx, ours, _theirs) = establish(7403, 42603, 0x6000_0000);
        super::wire::clear_sent();

        tcp::abort(idx);

        let out = outbound();
        assert_eq!(out.len(), 1, "abort must emit exactly one segment, got {}", out.len());
        assert_eq!(out[0].flags & RST, RST, "and it must be a RST");
        assert_eq!(out[0].seq, ours,
            "carrying snd.nxt — a reset the peer's window check rejects is a reset that \
             never happened");
        assert!(tcp::conn_state(idx) == tcp::TcpState::Closed,
            "and the slot is freed, got {}", st(tcp::conn_state(idx)));
    }
}

/// Unit 5 of the security audit: what a host that is NOT the peer can do to
/// an established connection without seeing it.
#[cfg(test)]
mod tcp_blind_attacker {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    const SYN: u8 = 0x02;
    const PSH: u8 = 0x08;

    /// **A blind attacker's payload must not enter the stream through the
    /// out-of-order queue.**
    ///
    /// U06-1 / U13-1: before the fix in `tcp.rs::handle`, a segment's payload
    /// reached `process_inbound_payload` (and its OOO store, `:2031-2035` in
    /// the audit's line numbers) regardless of whether the ACK field was
    /// acceptable — so landing `seq` inside the ~64 KiB receive window was
    /// enough to hold attacker bytes for later delivery, no ACK guess
    /// required. This is the canary the audit named for it: inject at
    /// `theirs + 4` with an ACK nowhere near ours (an off-path attacker who
    /// has not seen a genuine ACK has no way to land inside SND's window
    /// either), then fill the hole with a genuine segment, and check the
    /// attacker's bytes never arrive and are never SACKed/ACKed as held.
    #[test]
    fn a_blind_injection_via_the_ooo_queue_is_rejected() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7420, 42620, 0x0600_0000);

        // The attacker: right seq (theirs + 4, in window), wrong ACK.
        deliver(&segment(
            42620, 7420, theirs.wrapping_add(4), ours.wrapping_add(100_000),
            PSH | ACK, 4096, b"WXYZ",
        ));
        assert_eq!(
            wire::sent_count(), 0,
            "a segment carrying ACK with an unacceptable ACK value must be \
             dropped in its entirety — no duplicate ACK, no SACK block, \
             nothing that would confirm to a peer (genuine or not) that \
             anything was held",
        );

        // The peer, filling the hole for real.
        deliver(&segment(42620, 7420, theirs, ours, PSH | ACK, 4096, b"ABCD"));

        let mut buf = [0u8; 16];
        let n = tcp::recv(idx, &mut buf);
        assert_eq!(
            n, 4,
            "only the genuine 4 bytes may be delivered — the attacker's \
             WXYZ at theirs+4 must not have been held in the OOO queue, got {n}",
        );
        assert_eq!(&buf[..4], b"ABCD");
        assert_eq!(
            outbound().last().unwrap().ack, theirs.wrapping_add(4),
            "the ACK must not cover theirs+4..theirs+8 — that range was never \
             legitimately received, and acknowledging it would tell a genuine \
             peer holding those bytes that it need not resend them",
        );
    }

    /// **A reset must hit RCV.NXT exactly.** An in-window RST used to be
    /// enough, which made a blind teardown 2^16 guesses instead of 2^32.
    #[test]
    fn an_in_window_reset_that_is_not_exact_is_ignored() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7410, 42610, 0x0100_0000);

        for off in [1u32, 1000, 60_000] {
            deliver(&segment(42610, 7410, theirs.wrapping_add(off), 0, RST, 0, &[]));
            assert!(tcp::conn_state(idx) == tcp::TcpState::Established,
                "a RST at RCV.NXT+{off} tore the connection down, got {}",
                st(tcp::conn_state(idx)));
        }

        // Positive control: the exact sequence still resets.
        deliver(&segment(42610, 7410, theirs, 0, RST, 0, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::Closed,
            "a RST at exactly RCV.NXT must still close, got {}", st(tcp::conn_state(idx)));
    }

    /// **An ACK for data we never sent teaches nothing.** A bare ACK whose
    /// sequence is in window but whose ACK field is beyond SND.NXT used to set
    /// `remote_window` — so window 0 stalled the send side for good.
    #[test]
    fn a_bare_ack_beyond_snd_nxt_cannot_close_our_send_window() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7411, 42611, 0x0200_0000);

        deliver(&segment(42611, 7411, theirs, ours.wrapping_add(100_000), ACK, 0, &[]));
        assert!(tcp::send_data(idx, b"still open") > 0,
            "an ACK beyond SND.NXT advertised window 0 and it was believed");

        // Positive control: the same window 0 with a VALID ACK is honoured.
        wire::clear_sent();
        let (idx2, ours2, theirs2) = establish(7412, 42612, 0x0300_0000);
        deliver(&segment(42612, 7412, theirs2, ours2, ACK, 0, &[]));
        assert_eq!(tcp::send_data(idx2, b"x"), 0,
            "a zero window from an acceptable ACK must still stop the sender");
        let _ = idx2;
    }

    /// **Resets to closed ports are budgeted.** Each one is a 1:1 reflection
    /// toward whatever source the attacker spoofed.
    #[test]
    fn resets_to_a_closed_port_are_rate_limited() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(900_000_000);
        wire::clear_sent();
        for i in 0..1000u32 {
            deliver(&segment(42613, 7499, 0x0400_0000 + i, 0, SYN, 4096, &[]));
        }
        let rsts = outbound().iter().filter(|o| o.flags & RST != 0).count();
        assert!(rsts >= 1, "a dead port must still be refused");
        assert!(rsts <= 10, "1000 SYNs in one instant drew {rsts} resets");

        // A new window admits more — the peer that dials a dead port later
        // is still told at once.
        azos_drv_irqchip::clint::set_test_time(900_000_000 + azos_drv_sys::timebase::TIMER_FREQ);
        wire::clear_sent();
        deliver(&segment(42614, 7499, 0x0500_0000, 0, SYN, 4096, &[]));
        assert_eq!(outbound().iter().filter(|o| o.flags & RST != 0).count(), 1);
    }
}

#[cfg(test)]
/// The zero-window persist timer, RFC 1122 §4.2.2.17.
///
/// The deadlock this breaks: the peer advertises a zero window, we stop
/// sending, and the peer's later window update — a bare ACK, carrying no data
/// — is lost. The peer will never retransmit it, because a segment with no
/// payload and no flags consuming sequence space is not retransmittable. And
/// nothing on our side times out either: the retransmission machinery is
/// gated on `unacked`, and we have nothing outstanding, because the closed
/// window is precisely what stopped us from sending. Both ends then wait for
/// the other, forever, on a connection that is neither idle enough for
/// keepalive nor broken enough for the RTO.
///
/// The sender must break the tie by probing. These tests pin the three
/// properties that make it a persist timer rather than a busy loop: it waits
/// the full interval before the first probe, it probes with a sequence number
/// the peer has already acknowledged (so the probe itself cannot desynchronise
/// the stream), and it backs off.
mod tcp_persist_timer {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const ACK: u8 = 0x10;

    /// `TICKS_PER_MS` and `PERSIST_INITIAL_MS` are private to `tcp.rs`.
    /// Restating them here is deliberate: if either changes, these tests fail
    /// and someone has to look at the timer, which is the point. A test that
    /// imported the constant would agree with any value, including zero.
    const TICKS_PER_MS: u64 = 10_000;
    const PERSIST_INITIAL: u64 = 500 * TICKS_PER_MS;

    /// The backoff ceiling. Stepping the clock by this each iteration is what
    /// makes a probe fire EVERY time: a fixed step of a few initial intervals
    /// stops firing once the doubling passes it, and the first version of the
    /// test below silently got 5 probes where it needed more than 8.
    const PERSIST_MAX: u64 = 60_000 * TICKS_PER_MS;

    /// Base for the test clock. Non-zero, because `persist_time == 0` is the
    /// timer's own "not running" sentinel: starting the clock at 0 would let a
    /// broken implementation pass by accident.
    const T0: u64 = 1_000_000;

    fn close_the_window(port: u16, peer_port: u16, ours: u32, theirs: u32) {
        deliver(&segment(peer_port, port, theirs, ours, ACK, 0, &[]));
    }

    #[test]
    fn a_closed_window_is_probed_once_the_persist_interval_has_elapsed() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, ours, theirs) = establish(7310, 42500, 0xA000_0000);

        close_the_window(7310, 42500, ours, theirs);
        assert_eq!(
            tcp::send_data(idx, b"blocked"), 0,
            "a zero window must stop the sender — otherwise there is no deadlock \
             to break and this test is measuring nothing",
        );

        // First tick only arms the cycle. Probing here would make the timer a
        // reaction to the window closing rather than to the window STAYING
        // closed, and a peer that is legitimately busy would be hammered.
        wire::clear_sent();
        tcp::tcp_tick();
        assert!(outbound().is_empty(), "the first tick must arm, not probe");

        // One tick short of the interval: still silent.
        azos_drv_irqchip::clint::set_test_time(T0 + PERSIST_INITIAL - 1);
        tcp::tcp_tick();
        assert!(
            outbound().is_empty(),
            "probed early — the interval is not being honoured",
        );

        azos_drv_irqchip::clint::set_test_time(T0 + PERSIST_INITIAL);
        tcp::tcp_tick();

        let out = outbound();
        assert_eq!(out.len(), 1, "exactly one probe, got {}", out.len());
        let probe = out[0];
        assert_eq!(probe.flags & ACK, ACK, "the probe must be an ACK");
        assert_eq!(probe.payload_len, 0, "the probe must carry no data");
        assert_eq!(
            probe.seq, ours.wrapping_sub(1),
            "the probe must sit one byte BEHIND snd.nxt, on a sequence number the \
             peer has already acknowledged. A probe at snd.nxt would be new data \
             the peer cannot accept — it just told us its window is zero — and it \
             would be discarded without the window update we are asking for.",
        );
    }

    /// The interval doubles. Without this a stalled peer is probed twice a
    /// second for as long as it is busy, which is the difference between a
    /// persist timer and a poll loop.
    #[test]
    fn the_probe_interval_doubles_while_the_window_stays_closed() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (_idx, ours, theirs) = establish(7311, 42501, 0xB000_0000);
        close_the_window(7311, 42501, ours, theirs);

        tcp::tcp_tick();                                    // arm
        azos_drv_irqchip::clint::set_test_time(T0 + PERSIST_INITIAL);
        wire::clear_sent();
        tcp::tcp_tick();                                    // first probe
        assert_eq!(outbound().len(), 1, "first probe missing");

        // Exactly one further initial interval after the first probe. This is
        // the discriminating instant and the only one: a timer that did not
        // back off is due here, a timer that doubled is not due until one
        // interval later. Checking a tick EARLIER than this proves nothing —
        // both timers are silent there.
        azos_drv_irqchip::clint::set_test_time(T0 + 2 * PERSIST_INITIAL);
        wire::clear_sent();
        tcp::tcp_tick();
        assert!(
            outbound().is_empty(),
            "the interval did not double — the timer is polling at a fixed rate",
        );

        azos_drv_irqchip::clint::set_test_time(T0 + 3 * PERSIST_INITIAL);
        tcp::tcp_tick();
        assert_eq!(outbound().len(), 1, "the second probe never went out");
    }

    /// The two states that look identical from the sender and are not: a peer
    /// that keeps SAYING its window is zero, and a peer that has stopped
    /// saying anything.
    ///
    /// RFC 1122 §4.2.2.17 forbids dropping a connection because its window is
    /// zero -- a peer whose application is slow is healthy, and killing it
    /// recreates the deadlock the persist timer exists to break. It says
    /// nothing about a peer that answers nothing, and the first version of
    /// this timer conflated the two: probing was unbounded in count, full
    /// stop.
    ///
    /// That was not merely incomplete, it was a regression. Moving persist
    /// above the retransmission timer was right, but it also took that path's
    /// `RETX_MAX_ATTEMPTS` teardown away from the one state that still needed
    /// it -- so a peer that advertised `win=0` and then had its cable pulled
    /// probed every 60 s forever, holding one of 16 connection slots, with
    /// keepalive skipped because the persist branch `continue`s past it.
    ///
    /// Both halves are asserted here on purpose. A test that only checked the
    /// teardown would pass against a timer that gives up on a perfectly
    /// healthy peer, which is the worse of the two bugs.
    #[test]
    fn a_peer_that_answers_probes_is_never_dropped_and_one_that_answers_none_is() {
        // ── Half one: answers every probe with a still-closed window. ─────
        {
            let _g = begin();
            azos_drv_irqchip::clint::set_test_time(T0);
            let (idx, ours, theirs) = establish(7314, 42504, 0xE000_0000);
            close_the_window(7314, 42504, ours, theirs);

            let mut t = T0;
            let mut probes = 0usize;
            // Comfortably past PERSIST_MAX_UNANSWERED (8) worth of probes.
            for _ in 0..30 {
                t += PERSIST_MAX + 1;
                azos_drv_irqchip::clint::set_test_time(t);
                wire::clear_sent();
                tcp::tcp_tick();
                if !outbound().is_empty() {
                    probes += 1;
                    // The peer answers: still full, still alive. A `win=0` ACK
                    // is an answer, and answering must cost the peer nothing.
                    deliver(&segment(42504, 7314, theirs, ours, ACK, 0, &[]));
                }
            }
            assert!(probes > 8, "only {probes} probes went out; the loop never reached the bound");
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::Established,
                "a peer that answered every probe was dropped anyway (now {}) -- this is \
                 exactly what RFC 1122 forbids, and it recreates the deadlock the persist \
                 timer exists to break",
                st(tcp::conn_state(idx)),
            );
        }

        // ── Half two: same window, but the peer has gone silent. ──────────
        {
            let _g = begin();
            azos_drv_irqchip::clint::set_test_time(T0);
            let (idx, ours, theirs) = establish(7315, 42505, 0xF000_0000);
            close_the_window(7315, 42505, ours, theirs);

            let mut t = T0;
            for _ in 0..30 {
                t += PERSIST_MAX + 1;
                azos_drv_irqchip::clint::set_test_time(t);
                tcp::tcp_tick();
                // No reply, ever. Cable pulled.
            }
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::Closed,
                "a peer that answered nothing is still holding a connection slot (state {}) \
                 -- with keepalive skipped by the persist branch, nothing else will ever \
                 reclaim it",
                st(tcp::conn_state(idx)),
            );
        }
    }

    /// A reopened window ends the cycle. The state must be cleared rather than
    /// left at its backed-off value: a connection that stalls, recovers, and
    /// stalls again an hour later would otherwise inherit a minute of backoff
    /// from the first, unrelated stall.
    /// A peer can hold our data, acknowledge nothing, and close its window in
    /// the same segment -- `remote_window` is updated by EVERY ACK, but
    /// `unacked` is only cleared by one that ADVANCES. That state used to fall
    /// into the retransmission timer, which retransmitted the segment into a
    /// window the peer had just declared zero.
    ///
    /// The peer has nowhere to put it, so it cannot acknowledge it, so the
    /// retransmit can never succeed. `retx_count` climbs anyway, `cwnd`
    /// collapses and `ssthresh` halves each pass as though this were
    /// congestion, and after `RETX_MAX_ATTEMPTS` the connection is declared
    /// dead and closed. A peer that was merely busy for a few seconds thus
    /// loses its connection, killed by the machinery meant to survive loss.
    ///
    /// RFC 1122 §4.2.2.17 is explicit that a connection must not be dropped for
    /// persisting against a zero window. Probing is what the state calls for,
    /// and a probe carries no data, so it costs the peer nothing to answer and
    /// nothing counts against the retransmission budget.
    #[test]
    fn a_zero_window_probes_instead_of_retransmitting_into_it_and_never_kills_the_connection() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, ours, theirs) = establish(7313, 42503, 0xD000_0000);

        // Data goes out while the window is open, so it is genuinely
        // outstanding -- this is what the earlier persist tests never had.
        assert!(tcp::send_data(idx, b"HOLDME") > 0, "the first send should succeed");
        assert!(tcp::is_unacked(idx), "the segment must be outstanding");

        // The peer answers WITHOUT advancing the ack, and closes its window.
        // `unacked` stays true; `remote_window` becomes 0.
        deliver(&segment(42503, 7313, theirs, ours, ACK, 0, &[]));
        assert!(
            tcp::is_unacked(idx),
            "a non-advancing ACK must leave the segment outstanding, or this \
             test is not reaching the state it exists to cover",
        );

        // Run far past RETX_MAX_ATTEMPTS worth of RTOs. Under the old ordering
        // the retransmission timer owned every one of these passes and the
        // connection was Closed long before the loop ended.
        let mut payload_segments = 0usize;
        let mut probes = 0usize;
        let mut t = T0;
        for _ in 0..40 {
            t += PERSIST_INITIAL;
            azos_drv_irqchip::clint::set_test_time(t);
            wire::clear_sent();
            tcp::tcp_tick();
            for o in outbound() {
                if o.payload_len > 0 { payload_segments += 1; } else { probes += 1; }
            }
        }

        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Established,
            "the connection was torn down (now {}) while the peer was merely \
             busy -- \
             this is the bug: retransmitting into a zero window can never be \
             acknowledged, so the retry budget is spent on a peer that is fine",
            st(tcp::conn_state(idx)),
        );
        assert_eq!(
            payload_segments, 0,
            "{payload_segments} segments carrying data were sent into a window \
             the peer declared zero; it cannot accept them and cannot ack them",
        );
        assert!(
            probes > 0,
            "no probe was sent either -- the connection is now silent in both \
             directions, which is the deadlock the persist timer exists to break",
        );
    }

    #[test]
    fn a_reopened_window_ends_the_persist_cycle_and_resets_the_backoff() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, ours, theirs) = establish(7312, 42502, 0xC000_0000);
        close_the_window(7312, 42502, ours, theirs);

        tcp::tcp_tick();
        azos_drv_irqchip::clint::set_test_time(T0 + PERSIST_INITIAL);
        tcp::tcp_tick();                                    // probe, backoff -> 2x

        // The peer answers the probe with its real window.
        deliver(&segment(42502, 7312, theirs, ours, ACK, 4096, &[]));
        tcp::tcp_tick();                                    // observes the reopen
        assert!(
            tcp::send_data(idx, b"unblocked") > 0,
            "the sender must resume once the window reopens",
        );

        // Second stall. If the backoff had survived the reopen, the first
        // probe would now be due at 2x the initial interval, not at 1x.
        let t1 = T0 + PERSIST_INITIAL;
        let (ours2, theirs2) = (ours.wrapping_add(9), theirs);
        deliver(&segment(42502, 7312, theirs2, ours2, ACK, 0, &[]));
        azos_drv_irqchip::clint::set_test_time(t1);
        wire::clear_sent();
        tcp::tcp_tick();                                    // re-arm at t1
        assert!(outbound().is_empty(), "the re-armed cycle must not probe immediately");

        azos_drv_irqchip::clint::set_test_time(t1 + PERSIST_INITIAL);
        tcp::tcp_tick();
        assert_eq!(
            outbound().len(), 1,
            "the second stall was probed on the doubled interval — the backoff \
             leaked across an intervening recovery",
        );
    }
}

/// Two sends before the peer answers — `socket_send(fd, a); socket_send(fd, b);`,
/// ordinary application behaviour — must not cost the first segment its bytes.
/// `socket_send`/`socket_sendto` (`crates/net/net/src/socket.rs`) call
/// `tcp::send_data` directly, with no gate of their own. The connection holds
/// every byte in flight once, in its send ring, and cuts every retransmission
/// from SND.UNA, so a later send can neither overwrite an earlier segment nor
/// be refused for existing.
#[cfg(test)]
mod tcp_retransmission_slot {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const ACK: u8 = 0x10;

    /// Two sends, no ACK in between, and the first segment is lost. The RTO
    /// must resend from the first segment's sequence, and the bytes it
    /// carries must start with the first segment's.
    #[test]
    fn a_second_send_cannot_destroy_an_unacknowledged_segments_retransmission_data() {
        let _g = begin();
        let (idx, ours, _theirs) = establish(7210, 42400, 0x9000_0000);

        // First segment goes out and — per this test's premise — is lost:
        // the peer never ACKs it.
        assert!(tcp::send_data(idx, b"AAAAA") > 0, "the first send should succeed");
        assert!(tcp::is_unacked(idx), "the first segment must be outstanding");
        wire::clear_sent();

        // Second send, issued before the first is ACKed.
        let _second = tcp::send_data(idx, b"BBBBB");

        // Push the clock past any RTO and let the retransmit timer fire.
        wire::clear_sent();
        azos_drv_irqchip::clint::set_test_time(10_000 + 1_000_000_000);
        tcp::tcp_tick();

        let out = outbound();
        let retransmitted = *out
            .last()
            .expect("the still-unacked first segment must be retransmitted");
        let sent = wire::sent();
        let payload = sent.last().unwrap().payload[20..].to_vec();

        assert_eq!(
            retransmitted.seq, ours,
            "the retransmission must cover the still-unacked FIRST segment (seq {ours}), \
             not whichever segment was sent last",
        );
        // Cut from SND.UNA, a retransmission may carry more than the segment
        // that was lost — here both sends — but it must START with it.
        assert!(
            payload.starts_with(b"AAAAA"),
            "the retransmission must carry the FIRST segment's bytes first; got {payload:?}",
        );
    }

    /// A second `send_data` while the first segment is unacknowledged goes out
    /// behind it: the connection holds every byte in flight in its send ring,
    /// so nothing forces stop-and-wait, and the first segment's bytes are
    /// still there to resend.
    #[test]
    fn a_second_send_while_the_first_is_unacked_goes_out_behind_it() {
        let _g = begin();
        let (idx, ours, _theirs) = establish(7211, 42401, 0x9100_0000);

        assert!(tcp::send_data(idx, b"first") > 0);
        assert!(tcp::is_unacked(idx));
        wire::clear_sent();

        assert_eq!(
            tcp::send_data(idx, b"second"), 6,
            "the window has room: the second send must not wait for the first ACK",
        );
        let out = outbound();
        assert_eq!(out.len(), 1, "and it must be on the wire");
        assert_eq!(out[0].seq, ours.wrapping_add(5), "directly behind the first segment");
        assert!(tcp::is_unacked(idx));
    }

    /// `send_all_with_yield` hands a multi-segment buffer to the stack in full.
    ///
    /// The default remote MSS (536, no MSS option in this test's SYN) splits
    /// 800 bytes into two segments, and the initial cwnd (2 * TCP_MSS) holds
    /// both, so they leave without waiting for an ACK.
    #[test]
    fn send_all_with_yield_still_completes_a_multi_segment_transfer() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7212, 42402, 0x9200_0000);
        let port = 7212u16;
        let peer_port = 42402u16;

        let data: Vec<u8> = (0..800u32).map(|i| (i % 251) as u8).collect();

        // If the window ever fills, this acknowledges everything on the wire
        // so far — an ACK is cumulative, so the last segment's end covers the
        // rest. The peer's own sequence number (`theirs`) never moves: it
        // sends only ACKs here, no data of its own.
        let yield_fn = || {
            if tcp::is_unacked(idx) {
                if let Some(seg) = outbound().last() {
                    let ack_for = seg.seq.wrapping_add(seg.payload_len as u32);
                    deliver(&segment(peer_port, port, theirs, ack_for, ACK, 4096, &[]));
                }
            }
        };

        let sent = tcp::send_all_with_yield(idx, &data, yield_fn);
        assert_eq!(sent, data.len(), "all 800 bytes should have been accepted");
        // `send_all_with_yield` returns once every byte has been HANDED OFF,
        // not once the last segment is acknowledged, so `is_unacked` is not
        // asserted here; that would be testing a guarantee the function never
        // makes.

        // Reassemble what actually went out and check it matches, in order —
        // not just the byte count: which bytes end up at which sequence is the
        // whole point.
        let mut reassembled = Vec::new();
        for s in wire::sent() {
            let off = ((s.payload[12] >> 4) as usize) * 4;
            if s.payload.len() > off {
                reassembled.extend_from_slice(&s.payload[off..]);
            }
        }
        assert_eq!(reassembled, data, "bytes must arrive in order and unmodified");
    }

    /// `send_all_until` (wave 10): the clock-bounded twin completes the same
    /// multi-segment transfer when its wait callback lets the window open.
    #[test]
    fn send_all_until_completes_when_the_wait_opens_the_window() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7213, 42403, 0x9300_0000);
        let port = 7213u16;
        let peer_port = 42403u16;
        let data: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        let mut waits = 0u32;
        let mut held_across_wait = 0u32;
        let wait_fn = || {
            waits += 1;
            // IO-QUEUES N1: the TX batch is closed (its frames announced)
            // around every wait. Canary: drop the end/begin pair around
            // `wait_fn` in `send_all_until` and this counts every wait.
            if crate::TX_BATCH_DEPTH.load(std::sync::atomic::Ordering::SeqCst) != 0 {
                held_across_wait += 1;
            }
            if let Some(seg) = outbound().last() {
                let ack_for = seg.seq.wrapping_add(seg.payload_len as u32);
                deliver(&segment(peer_port, port, theirs, ack_for, ACK, 8192, &[]));
            }
        };
        let sent = tcp::send_all_until(idx, &data, 10_000_000, wait_fn);
        assert_eq!(sent, data.len(), "all 6000 bytes should have been accepted");
        assert!(waits > 0, "6000 bytes exceed the initial cwnd: the window must have closed once");
        assert_eq!(held_across_wait, 0, "a TX batch was held open across a wait");
        assert_eq!(crate::TX_BATCH_DEPTH.load(std::sync::atomic::Ordering::SeqCst), 0,
                   "send_all_until left a TX batch open");
    }

    /// `send_all_until` with a spent budget gives up at the first closed
    /// window WITHOUT calling the wait: the bound is the clock, not a count of
    /// waits. Canary for the deadline check: with it removed the loop calls
    /// the wait (which never opens the window) until the fail-safe cap.
    #[test]
    fn send_all_until_with_no_budget_never_waits() {
        let _g = begin();
        let (idx, _ours, _theirs) = establish(7214, 42404, 0x9400_0000);
        let data: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        let mut waits = 0u32;
        let sent = tcp::send_all_until(idx, &data, 0, || waits += 1);
        assert!(sent > 0, "the first window's worth must still go out");
        assert!(sent < data.len(), "a closed window with no budget must return short ({sent})");
        assert_eq!(waits, 0, "a spent budget must not call the wait");
    }
}

/// The out-of-order segment buffer — four slots of 256 bytes, filled entirely
/// with attacker-supplied bytes and sequence numbers.
#[cfg(test)]
mod tcp_reassembly {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;

    const OOO_MAX_SEGMENTS: usize = 4;
    /// `tcp.rs`'s slot size, `TCP_MSS`.
    const OOO_SEGMENT_MAX_LEN: usize = 1460;

    /// A segment past the expected sequence is held, not delivered, and the
    /// ACK does not move over the hole — acknowledging data we do not have
    /// would tell the peer to discard it.
    #[test]
    fn a_gap_is_held_and_not_acknowledged() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7300, 43000, 0x9000_0000);

        // Skip 4 bytes: send [4..8) while [0..4) is still missing.
        deliver(&segment(43000, 7300, theirs.wrapping_add(4), ours, PSH | ACK, 4096, b"WXYZ"));

        let mut buf = [0u8; 16];
        assert_eq!(tcp::recv(idx, &mut buf), 0, "nothing is contiguous yet");
        if let Some(last) = outbound().last() {
            assert_eq!(
                last.ack, theirs,
                "the ACK must not advance over a hole the receiver cannot fill",
            );
        }
    }

    /// Filling the gap releases the held segment, and the bytes come out in
    /// sequence order rather than arrival order.
    #[test]
    fn filling_the_gap_releases_the_held_segment_in_order() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7301, 43100, 0xA000_0000);

        deliver(&segment(43100, 7301, theirs.wrapping_add(4), ours, PSH | ACK, 4096, b"WXYZ"));
        deliver(&segment(43100, 7301, theirs, ours, PSH | ACK, 4096, b"ABCD"));

        let mut buf = [0u8; 16];
        let n = tcp::recv(idx, &mut buf);
        assert_eq!(n, 8, "both segments should now be contiguous, got {n}");
        assert_eq!(
            &buf[..8], b"ABCDWXYZ",
            "reassembly must order by sequence number, not by arrival",
        );
        assert_eq!(
            outbound().last().unwrap().ack, theirs.wrapping_add(8),
            "the ACK covers everything now contiguous",
        );
    }

    /// The same out-of-order segment sent twice must not occupy two slots.
    ///
    /// There are only four, and a full queue drops what does not fit, so a
    /// peer that repeats itself would otherwise fill the free slots with
    /// copies and leave no room for the segments that close the gaps.
    ///
    /// **The first version of this test could not tell the difference.** It
    /// sent one segment six times and then filled the hole, which delivers the
    /// same bytes whether or not the repeats took slots. Removing the
    /// duplicate check left it green. What discriminates is a distinct segment
    /// that needs the slot a repeat would take: three distinct held segments,
    /// the repeats, then a fourth. (Until 2026-09-14 a full queue evicted its
    /// farthest entry, and the test held four and repeated one, so that each
    /// repeat evicted a real segment.)
    #[test]
    fn a_repeated_out_of_order_segment_does_not_consume_a_second_slot() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7302, 43200, 0xB000_0000);
        let at = |off: u32| theirs.wrapping_add(off);

        // Three distinct held segments, none contiguous with another.
        for (off, body) in [(10u32, b"AAAA"), (20, b"BBBB"), (30, b"CCCC")] {
            deliver(&segment(43200, 7302, at(off), ours, PSH | ACK, 4096, body));
        }
        // Repeat the nearest one. A repeat treated as new takes the last free
        // slot.
        for _ in 0..5 {
            deliver(&segment(43200, 7302, at(10), ours, PSH | ACK, 4096, b"AAAA"));
        }
        // A fourth distinct segment, which fits only if no repeat took a slot.
        deliver(&segment(43200, 7302, at(40), ours, PSH | ACK, 4096, b"DDDD"));

        // Close every gap in turn.
        let f = |n: usize| vec![0x2Eu8; n];
        deliver(&segment(43200, 7302, at(0), ours, PSH | ACK, 4096, &f(10)));
        deliver(&segment(43200, 7302, at(14), ours, PSH | ACK, 4096, &f(6)));
        deliver(&segment(43200, 7302, at(24), ours, PSH | ACK, 4096, &f(6)));
        deliver(&segment(43200, 7302, at(34), ours, PSH | ACK, 4096, &f(6)));

        let mut buf = [0u8; 128];
        let n = tcp::recv(idx, &mut buf);
        assert_eq!(
            n, 44,
            "all four held segments must survive the repeats: 28 filler bytes plus \
             4 x 4 held, got {n}",
        );
        assert_eq!(&buf[10..14], b"AAAA");
        assert_eq!(&buf[20..24], b"BBBB");
        assert_eq!(&buf[30..34], b"CCCC");
        assert_eq!(&buf[40..44], b"DDDD");
    }

    /// The buffer holds four segments, and a held segment is never given up
    /// for a later arrival. A fifth that does not fit is dropped, whether it
    /// lies beyond every held segment, before all of them, or across the start
    /// of one.
    ///
    /// Every held segment has been reported to the peer: with SACK, the ACK
    /// answering it named it in a block. Evicting one is reneging (RFC 2018
    /// §8). With one-MSS slots the sender then holds a whole segment as
    /// delivered that the receiver no longer has, SACK recovery skips it, and
    /// only a retransmission timeout repairs it (`tcp_throughput`, 2026-09-14).
    /// Until then a full queue evicted its farthest entry for any arrival;
    /// that eviction, and the one that evicts only for an arrival nearer than
    /// the farthest entry, are the canaries.
    #[test]
    fn a_full_queue_drops_the_arrival_and_never_a_held_segment() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7303, 43300, 0xC000_0000);
        let at = |off: u32| theirs.wrapping_add(off);
        const FILL: u8 = 0x2E;

        // Four held segments; the nearest starts at +100.
        let held = [(100u32, *b"AAAA"), (400, *b"BBBB"), (800, *b"CCCC"), (1200, *b"DDDD")];
        for (off, body) in &held {
            deliver(&segment(43300, 7303, at(*off), ours, PSH | ACK, 4096, body));
        }
        assert_eq!(held.len(), OOO_MAX_SEGMENTS, "the buffer is now full");

        // Arrivals that do not fit: beyond every held segment, before all of
        // them, and across the start of the one at +400.
        deliver(&segment(43300, 7303, at(5000), ours, PSH | ACK, 4096, b"eeee"));
        deliver(&segment(43300, 7303, at(10), ours, PSH | ACK, 4096, b"ffff"));
        deliver(&segment(43300, 7303, at(398), ours, PSH | ACK, 4096, b"gggggggg"));

        // Close every hole with filler and read the stream back.
        for (from, to) in [(0u32, 100u32), (104, 400), (404, 800), (804, 1200)] {
            deliver(&segment(43300, 7303, at(from), ours, PSH | ACK, 4096, &vec![FILL; (to - from) as usize]));
        }
        let mut buf = [0u8; 2048];
        let n = tcp::recv(idx, &mut buf) as usize;
        assert_eq!(
            n, 1204,
            "all four held segments must still be held once the holes are closed: 1188 filler + \
             4 x 4 held bytes, got {n}",
        );
        for (off, body) in &held {
            let o = *off as usize;
            assert_eq!(&buf[o..o + 4], body, "the segment held at +{off} was given up for a later arrival");
        }
        assert!(
            buf[10..14].iter().all(|&b| b == FILL),
            "the arrival at +10, which did not fit, was delivered instead of the filler",
        );
    }

    /// An out-of-order segment longer than a slot is truncated to the slot,
    /// never written past it — and the acknowledgement must reflect only what
    /// was actually stored, or the peer will never retransmit the remainder.
    #[test]
    fn an_oversized_out_of_order_segment_is_truncated_and_acknowledged_honestly() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7304, 43400, 0xD000_0000);

        let big = [0x77u8; OOO_SEGMENT_MAX_LEN * 2];
        deliver(&segment(43400, 7304, theirs.wrapping_add(4), ours, PSH | ACK, 4096, &big));
        deliver(&segment(43400, 7304, theirs, ours, PSH | ACK, 4096, b"ABCD"));

        // Larger than one slot plus the filler, so a receiver that kept more
        // than a slot could deliver it and fail the bound below.
        let mut buf = [0u8; 4 * OOO_SEGMENT_MAX_LEN];
        let n = tcp::recv(idx, &mut buf) as usize;
        assert!(
            n <= 4 + OOO_SEGMENT_MAX_LEN,
            "a {}-byte segment must not deliver more than one {OOO_SEGMENT_MAX_LEN}-byte \
             slot's worth, got {n}", big.len(),
        );
        let acked = outbound().last().unwrap().ack;
        assert_eq!(
            acked, theirs.wrapping_add(n as u32),
            "the ACK must cover exactly what was stored ({n} bytes) — acknowledging the \
             truncated remainder would make the peer drop bytes we never kept",
        );
    }

    /// An out-of-order segment longer than 256 B, up to one full MSS, is held
    /// whole: once the hole before it is filled, every byte of it comes out,
    /// in place, and the ACK covers it, with nothing resent. Until 2026-09-14
    /// a slot was 256 B, so a held segment kept its first 256 bytes and the
    /// peer had to send the rest again.
    ///
    /// Asserted on the bytes delivered, length and content, not on the ACK
    /// alone: the ACK would also be honest about a truncated segment.
    #[test]
    fn an_out_of_order_segment_up_to_one_mss_is_held_whole_and_delivered_intact() {
        for (k, len) in [257usize, 1000, OOO_SEGMENT_MAX_LEN].into_iter().enumerate() {
            let _g = begin();
            let (port, peer) = (7306 + k as u16, 43600 + 100 * k as u16);
            let (idx, ours, theirs) = establish(port, peer, 0x1100_0000 + k as u32);

            let held: Vec<u8> = (0..len).map(|i| (i % 251) as u8 ^ 0xA5).collect();
            deliver(&segment(peer, port, theirs.wrapping_add(4), ours, PSH | ACK, 4096, &held));
            deliver(&segment(peer, port, theirs, ours, PSH | ACK, 4096, b"ABCD"));

            let mut buf = [0u8; 4 * OOO_SEGMENT_MAX_LEN];
            let n = tcp::recv(idx, &mut buf) as usize;
            assert_eq!(
                n, 4 + len,
                "a {len}-byte segment held out of order must come out whole once the hole is filled: \
                 4 filler + {len} held bytes, got {n}",
            );
            assert_eq!(&buf[..4], b"ABCD", "the filler comes first");
            assert!(buf[4..n] == held[..], "the {len} held bytes must come out as they arrived");
            assert_eq!(
                outbound().last().unwrap().ack, theirs.wrapping_add(4 + len as u32),
                "the ACK covers the filler and the whole held segment",
            );
        }
    }

    /// A peer that only ever sends holes must not be able to make the
    /// receiver deliver anything, and must not panic it.
    #[test]
    fn a_stream_of_holes_delivers_nothing_and_panics_nothing() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7305, 43500, 0xE000_0000);

        for k in 1..200u32 {
            deliver(&segment(
                43500, 7305, theirs.wrapping_add(k.wrapping_mul(997)),
                ours, PSH | ACK, 4096, b"hole",
            ));
        }
        let mut buf = [0u8; 64];
        assert_eq!(
            tcp::recv(idx, &mut buf), 0,
            "not one byte is contiguous, so nothing may be delivered",
        );
        assert!(wire::sent_count() > 0, "the peer is still being told where we are");
    }
}

/// The connection-teardown states. Every one of them was, at some point in
/// this file's history, reachable by a segment bearing any sequence number at
/// all — the comments in `tcp.rs` name each case. These pin the checks.
#[cfg(test)]
mod tcp_close {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const FIN: u8 = 0x01;
    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;

    /// The sequence number of the last segment we put on the wire.
    fn last_seq() -> u32 {
        outbound().last().expect("a segment should have been sent").seq
    }

    /// Active close: we send the FIN, the peer acknowledges it, then sends its
    /// own. FinWait1 -> FinWait2 -> TimeWait.
    #[test]
    fn an_active_close_walks_fin_wait_one_two_and_time_wait() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7400, 44000, 0x1100_0000);

        tcp::close(idx);
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait1,
            "close() on an established connection sends a FIN, got {}",
            st(tcp::conn_state(idx)),
        );
        let fin_seq = last_seq();

        deliver(&segment(44000, 7400, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait2,
            "an ACK of our FIN means FinWait2, got {}", st(tcp::conn_state(idx)),
        );

        wire::clear_sent();
        deliver(&segment(44000, 7400, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::TimeWait,
            "the peer's FIN completes the close, got {}", st(tcp::conn_state(idx)),
        );
        assert_eq!(
            outbound().last().unwrap().ack, theirs.wrapping_add(1),
            "the peer's FIN must be acknowledged past its own sequence number",
        );
    }

    /// A FIN in FinWait2 bearing a sequence outside the window must be
    /// ignored. This state used to accept any sequence whatsoever, so anyone
    /// who could guess the 4-tuple closed the connection on command AND left
    /// `c.ack` pointing at an arbitrary place in the sequence space.
    #[test]
    fn a_forged_fin_cannot_close_a_connection_in_fin_wait_two() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7401, 44100, 0x2200_0000);
        tcp::close(idx);
        let fin_seq = last_seq();
        deliver(&segment(44100, 7401, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2);

        for bad in [
            theirs.wrapping_sub(1),
            theirs.wrapping_sub(100_000),
            theirs.wrapping_add(100_000),
            theirs.wrapping_add(1 << 31),
        ] {
            deliver(&segment(44100, 7401, bad, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::FinWait2,
                "a FIN at seq {bad} is outside the window from {theirs} and must not \
                 close the connection; state is {}", st(tcp::conn_state(idx)),
            );
        }
        // The legitimate one still works.
        deliver(&segment(44100, 7401, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait);
    }

    /// Passive close: the peer closes first, we drain, then close. Established
    /// -> CloseWait -> LastAck -> Closed.
    #[test]
    fn a_passive_close_walks_close_wait_last_ack_and_closed() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7402, 44200, 0x3300_0000);

        deliver(&segment(44200, 7402, theirs, ours, FIN | ACK, 4096, b"tail"));
        assert!(tcp::conn_state(idx) == tcp::TcpState::CloseWait);

        // The peer's last bytes must still be readable — a close is not a
        // reason to lose data already accepted.
        let mut buf = [0u8; 16];
        assert_eq!(tcp::recv(idx, &mut buf), 4);
        assert_eq!(&buf[..4], b"tail");

        wire::clear_sent();
        tcp::close(idx);
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::LastAck,
            "closing from CloseWait sends our FIN, got {}", st(tcp::conn_state(idx)),
        );
        let fin_seq = last_seq();

        deliver(&segment(44200, 7402, theirs.wrapping_add(5),
                         fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Closed,
            "the ACK of our FIN closes it, got {}", st(tcp::conn_state(idx)),
        );
    }

    /// In LastAck, only the acknowledgement of OUR FIN may free the slot.
    ///
    /// Any ACK used to do it. A stale or forged acknowledgement number then
    /// freed the slot while the peer still believed the connection open — and
    /// the slot could be handed to a NEW peer while the old one's segments
    /// were still arriving.
    #[test]
    fn only_the_acknowledgement_of_our_own_fin_frees_the_slot() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7403, 44300, 0x4400_0000);
        deliver(&segment(44300, 7403, theirs, ours, FIN | ACK, 4096, &[]));
        wire::clear_sent();
        tcp::close(idx);
        assert!(tcp::conn_state(idx) == tcp::TcpState::LastAck);
        let fin_seq = last_seq();

        for wrong in [
            0u32,
            fin_seq,
            fin_seq.wrapping_add(2),
            fin_seq.wrapping_sub(1),
            u32::MAX,
        ] {
            deliver(&segment(44300, 7403, theirs.wrapping_add(1), wrong, ACK, 4096, &[]));
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::LastAck,
                "ack {wrong} does not acknowledge our FIN at {fin_seq}; the slot must \
                 stay allocated, state is {}", st(tcp::conn_state(idx)),
            );
        }
        deliver(&segment(44300, 7403, theirs.wrapping_add(1),
                         fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::Closed);
    }

    /// Simultaneous close: the peer's FIN arrives while our own is still
    /// unacknowledged. FinWait1 goes straight to TimeWait — but only for a FIN
    /// inside the window.
    #[test]
    fn a_simultaneous_close_reaches_time_wait_only_from_inside_the_window() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7404, 44400, 0x5500_0000);
        tcp::close(idx);
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait1);

        // Out of window first: nothing may move.
        deliver(&segment(44400, 7404, theirs.wrapping_add(200_000), 0, FIN, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait1,
            "an out-of-window FIN must not force a simultaneous close, got {}",
            st(tcp::conn_state(idx)),
        );

        wire::clear_sent();
        deliver(&segment(44400, 7404, theirs, 0, FIN, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::TimeWait,
            "a FIN in window while our own is unacknowledged is a simultaneous \
             close, got {}", st(tcp::conn_state(idx)),
        );
        assert_eq!(outbound().last().unwrap().ack, theirs.wrapping_add(1));
    }

    /// TimeWait ignores inbound segments; only the timer moves it on. A
    /// connection that could be dragged back out of TimeWait would let the
    /// 4-tuple be reused while the old peer's segments were still in flight.
    #[test]
    fn time_wait_ignores_segments_and_is_closed_by_the_timer() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7405, 44500, 0x6600_0000);
        tcp::close(idx);
        let fin_seq = last_seq();
        deliver(&segment(44500, 7405, theirs, fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::TimeWait);

        for fl in [ACK, PSH | ACK, FIN | ACK, 0] {
            deliver(&segment(44500, 7405, theirs.wrapping_add(1),
                             fin_seq.wrapping_add(1), fl, 4096, b"nope"));
            assert!(
                tcp::conn_state(idx) == tcp::TcpState::TimeWait,
                "nothing on the wire may move a connection out of TimeWait, got {}",
                st(tcp::conn_state(idx)),
            );
        }

        azos_drv_irqchip::clint::set_test_time(10_000 + 1_000_000_000);
        tcp::tcp_tick();
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Closed,
            "the TimeWait timer must eventually free the slot, got {}",
            st(tcp::conn_state(idx)),
        );
    }
}

/// Half-close (RFC 1122 §4.2.2.13): a peer's FIN ends only ITS send
/// direction. `send_data` used to require `state == Established`, so the
/// peer's FIN silently killed OUR direction too, and there was no
/// `shutdown()` to close only our own side. Fixed by letting `CloseWait`
/// share `Established`'s segment processing (`handle`'s merged match arm) and
/// by giving `FinWait1`/`FinWait2` the same inbound-payload handling, reached
/// through the new `tcp::shutdown_write` / `socket::socket_shutdown`.
#[cfg(test)]
mod tcp_half_close {
    use super::tcp_rx::*;
    use super::{tcp, wire};

    const FIN: u8 = 0x01;
    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;

    /// Restated deliberately, matching `tcp_teardown_bounds`: if either
    /// constant moves, these fail and someone looks at the timer.
    const TICKS_PER_MS: u64 = 10_000;
    const FIN_WAIT2_TIMEOUT: u64 = 60_000 * TICKS_PER_MS;
    const KEEPALIVE_INTERVAL: u64 = 30_000 * TICKS_PER_MS;
    const KEEPALIVE_MAX_PROBES: u8 = 3;
    const T0: u64 = 5_000_000;

    fn last_seq() -> u32 {
        outbound().last().expect("a segment should have been sent").seq
    }

    /// The actual bytes of the last segment sent, past its header. Unlike
    /// `Out` (which only records `payload_len`), this is what the canary
    /// discipline demands here: a `send_data` that returns a byte count
    /// without transmitting anything passes a length-only check just as well
    /// as a correct one if the length happens to match, so the assertion has
    /// to be on the bytes that left the stack.
    fn last_payload_bytes() -> Vec<u8> {
        let sent = wire::sent();
        let s = sent.last().expect("a segment should have been sent");
        let off = ((s.payload[12] >> 4) as usize) * 4;
        s.payload[off..].to_vec()
    }

    /// The core of half-close: once the peer's FIN has moved us to
    /// `CloseWait`, `send_data` must still work, and the bytes must actually
    /// reach the wire — not merely be counted in the return value.
    #[test]
    fn send_data_after_the_peers_fin_reaches_the_wire_with_our_bytes() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7700, 45000, 0xA100_0000);

        deliver(&segment(45000, 7700, theirs, ours, FIN | ACK, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::CloseWait,
            "precondition: expected CloseWait, got {}", st(tcp::conn_state(idx)),
        );

        wire::clear_sent();
        let n = tcp::send_data(idx, b"telemetry");
        assert_eq!(n, 9, "send_data must accept our own bytes once only the \
                           peer's direction is closed");
        assert_eq!(
            last_payload_bytes(), b"telemetry",
            "the bytes must actually be on the wire, not just be counted in \
             the return value",
        );
    }

    /// A half-closed connection is not freed, and its outbound data is not
    /// left to rot as `unacked` forever, until BOTH directions have closed.
    ///
    /// Before this, `CloseWait` had no arm in `handle`'s match at all, so an
    /// ACK for data sent from it (unreachable before `send_data` accepted
    /// `CloseWait`) would never clear `unacked` — the RTO timer would have
    /// retransmitted the segment on a schedule and eventually torn the
    /// otherwise-healthy connection down at `RETX_MAX_ATTEMPTS`.
    #[test]
    fn a_connection_in_close_wait_survives_until_we_also_close() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7701, 45100, 0xA200_0000);

        deliver(&segment(45100, 7701, theirs, ours, FIN | ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::CloseWait, "precondition");

        assert!(tcp::send_data(idx, b"still here") > 0);
        assert!(tcp::is_unacked(idx), "the segment must be outstanding");
        let ack_of_send = ours.wrapping_add(b"still here".len() as u32);
        deliver(&segment(45100, 7701, theirs.wrapping_add(1), ack_of_send, ACK, 4096, &[]));

        assert!(
            tcp::conn_state(idx) == tcp::TcpState::CloseWait,
            "an ACK of our data must not move or free a half-closed \
             connection, got {}", st(tcp::conn_state(idx)),
        );
        assert!(
            !tcp::is_unacked(idx),
            "the ACK must have been processed exactly as it would be in \
             Established -- otherwise the retransmission timer eventually \
             kills a connection the peer has fully acknowledged",
        );

        wire::clear_sent();
        tcp::close(idx);
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::LastAck,
            "closing from CloseWait sends our FIN, got {}", st(tcp::conn_state(idx)),
        );
        let fin_seq = last_seq();

        deliver(&segment(45100, 7701, theirs.wrapping_add(1),
                         fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Closed,
            "only the ACK of our own FIN may free a half-closed connection, \
             got {}", st(tcp::conn_state(idx)),
        );
    }

    /// `CloseWait` previously had no bound at all: the peer has already sent
    /// its FIN, so `FinWait2`'s "peer owes us a FIN" reaper does not apply,
    /// and no data ever flowed through it to trip the retransmission timer.
    /// If the peer then vanishes and our own application never gets around
    /// to `close`/`shutdown_write`, the slot must still be reclaimed, the
    /// same failure `FIN_WAIT2_TIMEOUT_MS` exists to prevent on the other
    /// side of a close.
    #[test]
    fn a_close_wait_the_peer_abandons_is_eventually_reclaimed() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, ours, theirs) = establish(7702, 45200, 0xA300_0000);
        deliver(&segment(45200, 7702, theirs, ours, FIN | ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::CloseWait, "precondition");

        let mut t = T0;
        let mut probes = 0usize;
        for _ in 0..(KEEPALIVE_MAX_PROBES as usize + 2) {
            t += KEEPALIVE_INTERVAL + 1;
            azos_drv_irqchip::clint::set_test_time(t);
            wire::clear_sent();
            tcp::tcp_tick();
            if !outbound().is_empty() { probes += 1; }
            if tcp::conn_state(idx) == tcp::TcpState::Closed { break; }
        }

        assert!(probes >= 1, "an idle half-closed connection was never probed");
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Closed,
            "a CloseWait connection whose peer vanished is still held (state \
             {}) -- with only a handful of slots in the table this alone can \
             starve every future connection attempt", st(tcp::conn_state(idx)),
        );
    }

    /// `shutdown_write` closes only our send direction: it sends a FIN, but
    /// the peer has not, and RFC 1122 §4.2.2.13 permits the peer to keep
    /// sending until it does. Before this, `FinWait1`/`FinWait2` ran no
    /// payload handling at all, so such data was silently dropped rather than
    /// delivered and acknowledged.
    #[test]
    fn shutdown_sends_our_fin_and_keeps_the_receive_path_open() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7703, 45300, 0xA400_0000);

        tcp::shutdown_write(idx);
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait1,
            "shutdown_write on an established connection must send a FIN, \
             got {}", st(tcp::conn_state(idx)),
        );
        assert_eq!(
            outbound().last().unwrap().flags & (FIN | ACK), FIN | ACK,
            "the FIN must actually go out on the wire",
        );
        let fin_seq = last_seq();

        // The peer acknowledges our FIN: FinWait2. Our own send direction is
        // now fully closed, but the peer's is not.
        deliver(&segment(45300, 7703, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait2,
            "precondition: expected FinWait2, got {}", st(tcp::conn_state(idx)),
        );

        wire::clear_sent();
        deliver(&segment(45300, 7703, theirs, fin_seq.wrapping_add(1),
                         PSH | ACK, 4096, b"trailing"));
        let mut buf = [0u8; 16];
        assert_eq!(
            tcp::recv(idx, &mut buf), 8,
            "data the peer sends after OUR FIN, but before ITS OWN, must \
             still be delivered -- that is the entire point of a half-close",
        );
        assert_eq!(&buf[..8], b"trailing");
        assert_eq!(
            outbound().last().unwrap().ack, theirs.wrapping_add(8),
            "and it must be acknowledged, or the peer retransmits forever",
        );

        // The peer's own FIN, once its data has been drained, completes the
        // close exactly as it would from a fresh FinWait2.
        wire::clear_sent();
        deliver(&segment(45300, 7703, theirs.wrapping_add(8),
                         fin_seq.wrapping_add(1), FIN | ACK, 4096, &[]));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::TimeWait,
            "the peer's FIN must complete the close once its data is drained, \
             got {}", st(tcp::conn_state(idx)),
        );
    }

    /// `process_inbound_payload` was added to `FinWait1` too, not just
    /// `FinWait2` -- the peer may send data before it has even acknowledged
    /// our FIN, since the two directions are independent. Nothing else in
    /// this module exercises that specific arm: the other tests either
    /// deliver no payload in `FinWait1` at all, or reach `FinWait2` first.
    #[test]
    fn fin_wait1_accepts_data_that_arrives_before_our_fin_is_acknowledged() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7707, 45600, 0xA700_0000);
        tcp::shutdown_write(idx);
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait1, "precondition");

        wire::clear_sent();
        // The peer has not yet acknowledged our FIN (ack=0, unrelated to
        // fin_seq) but sends data anyway -- perfectly legal, the two
        // directions are independent.
        deliver(&segment(45600, 7707, theirs, 0, PSH | ACK, 4096, b"early"));
        let mut buf = [0u8; 16];
        assert_eq!(
            tcp::recv(idx, &mut buf), 5,
            "data arriving in FinWait1, before the peer has even acknowledged \
             our own FIN, must still be delivered",
        );
        assert_eq!(&buf[..5], b"early");
        assert_eq!(
            outbound().last().unwrap().ack, theirs.wrapping_add(5),
            "and acknowledged",
        );
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait1,
            "receiving data must not by itself move the connection out of \
             FinWait1 -- only an ACK of our own FIN does that, got {}",
            st(tcp::conn_state(idx)),
        );
    }

    /// `shutdown_write` and `close` share the FIN-sending transition, so the
    /// existing `FinWait2` bound must still catch a peer that vanishes after
    /// a half-close initiated through the NEW entry point, not just the old
    /// one.
    #[test]
    fn a_half_closed_connection_via_shutdown_whose_peer_vanishes_is_reclaimed() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(T0);
        let (idx, _ours, theirs) = establish(7704, 45400, 0xA500_0000);

        tcp::shutdown_write(idx);
        let fin_seq = last_seq();
        deliver(&segment(45400, 7704, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        assert!(tcp::conn_state(idx) == tcp::TcpState::FinWait2, "precondition");

        azos_drv_irqchip::clint::set_test_time(T0 + FIN_WAIT2_TIMEOUT);
        tcp::tcp_tick();
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Closed,
            "a connection half-closed via shutdown_write, whose peer then \
             vanished without ever sending its own FIN, must still be \
             reclaimed by the existing FinWait2 bound -- shutdown_write must \
             not have opened a new unbounded path into that state, got {}",
            st(tcp::conn_state(idx)),
        );
    }

    /// Unlike `close()`, which force-closes any state it does not recognise,
    /// `shutdown_write` has nothing to do outside `Established`/`CloseWait`
    /// and must leave everything else alone.
    #[test]
    fn shutdown_write_leaves_a_non_established_connection_untouched() {
        let _g = begin();
        assert!(tcp::listen(7705) >= 0);
        let idx = slot_in(tcp::TcpState::Listen).expect("the listener must hold a slot");

        tcp::shutdown_write(idx);
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::Listen,
            "shutdown_write must not force-close a connection with no open \
             send direction to shut down -- unlike close(), it must not \
             destroy state in a case it does not recognise, got {}",
            st(tcp::conn_state(idx)),
        );
    }
}

/// The socket-layer entry point named in the plan: `shutdown(SHUT_WR)`.
/// `crates/net/net/src/socket.rs` had no `shutdown()` at all; `socket_close` was
/// the only way to stop sending, and it also frees the fd, so an application
/// could not drain what the peer sends after its own FIN through a socket it
/// had used to signal "no more from me".
#[cfg(test)]
mod socket_shutdown_wiring {
    use super::tcp_rx::*;
    use super::{socket, tcp, wire};

    const FIN: u8 = 0x01;
    const ACK: u8 = 0x10;
    const PSH: u8 = 0x08;
    const OWNER: u32 = 42;

    fn last_seq() -> u32 {
        outbound().last().expect("a segment should have been sent").seq
    }

    /// `socket_shutdown` must reach `tcp::shutdown_write` (a FIN goes out and
    /// the connection walks to `FinWait1`) AND, unlike `socket_close`, must
    /// leave the fd allocated and readable.
    #[test]
    fn socket_shutdown_sends_a_fin_and_leaves_the_fd_readable() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7706, 45500, 0xA600_0000);

        // Attach a socket fd to the connection this suite already drove to
        // Established: bind a fresh socket to the same port `establish` used
        // (a raw `tcp::listen`, bypassing the socket layer) and accept
        // through it, exactly as `socket_accept_owned` expects to be used.
        let listener = socket::socket_create_owned(socket::AF_INET, socket::SOCK_STREAM, 0, OWNER);
        assert!(listener >= 0);
        let addr = socket::SockAddr { family: socket::AF_INET as u16, port: 7706, addr: [0; 4] };
        assert_eq!(socket::socket_bind(listener, &addr), 0);
        let fd = socket::socket_accept_owned(listener, OWNER);
        assert!(fd >= 0, "tcp::accept should find the slot establish() set up");

        wire::clear_sent();
        assert_eq!(socket::socket_shutdown(fd), 0);
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::FinWait1,
            "socket_shutdown must reach tcp::shutdown_write, got {}",
            st(tcp::conn_state(idx)),
        );
        assert_eq!(
            outbound().last().unwrap().flags & (FIN | ACK), FIN | ACK,
            "the FIN must actually be on the wire",
        );
        assert_eq!(
            socket::socket_owner(fd), Some(OWNER),
            "socket_shutdown must not free the fd -- that is what \
             distinguishes it from socket_close",
        );

        let fin_seq = last_seq();
        deliver(&segment(45500, 7706, theirs, fin_seq.wrapping_add(1), ACK, 4096, &[]));
        deliver(&segment(45500, 7706, theirs, fin_seq.wrapping_add(1),
                         PSH | ACK, 4096, b"data"));

        let mut buf = [0u8; 16];
        assert_eq!(
            socket::socket_recv(fd, &mut buf), 4,
            "the fd must still be readable after socket_shutdown -- data the \
             peer sends before its own FIN must reach the application",
        );
        assert_eq!(&buf[..4], b"data");
    }
}

/// ARP cache poisoning defences (`crates/net/net/src/arp.rs`).
///
/// The cache decides which MAC every outbound IP datagram is addressed to, so
/// an attacker who can write one entry redirects the robot's traffic to
/// themselves. Classic ARP is trivially forgeable — there is no authentication
/// anywhere in RFC 826 — so every defence has to be a rule about which
/// packets are allowed to teach anything.
#[cfg(test)]
mod arp_cache {
    use super::{arp, raw};

    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const PEER_IP: [u8; 4] = [10, 0, 0, 9];
    const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const ATTACKER_MAC: [u8; 6] = [0x02, 0x66, 0x66, 0x66, 0x66, 0x66];

    const OP_REQUEST: u16 = 1;
    const OP_REPLY: u16 = 2;

    use super::NET_SERIAL as SERIAL;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(50_000);
        // A real reset, not an overwrite. This used to plant `PEER_IP -> 00..00`
        // with `insert` so a previous test could not answer for it — which
        // leaned on a request being able to REWRITE an existing binding, the
        // exact behaviour that was the poisoning hole.
        arp::cache_reset_for_test();
        // And the pending-ARP transmit queue: learning `PEER_IP` drains every
        // frame queued for it, so one left by an earlier test went out as an
        // extra frame and `raw::count()` read 2 — 15 of 40 shuffled orders.
        super::ip::arp_txq_reset_for_test();
        g
    }

    /// A well-formed ARP packet. Every field is a parameter because the
    /// defences are all about fields an attacker controls.
    #[allow(clippy::too_many_arguments)]
    fn packet(
        htype: u16, ptype: u16, hlen: u8, plen: u8, oper: u16,
        sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4],
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&htype.to_be_bytes());
        p.extend_from_slice(&ptype.to_be_bytes());
        p.push(hlen);
        p.push(plen);
        p.extend_from_slice(&oper.to_be_bytes());
        p.extend_from_slice(&sha);
        p.extend_from_slice(&spa);
        p.extend_from_slice(&tha);
        p.extend_from_slice(&tpa);
        p
    }

    fn well_formed(oper: u16, sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4]) -> Vec<u8> {
        packet(1, 0x0800, 6, 4, oper, sha, spa, [0; 6], tpa)
    }

    fn deliver(p: &[u8]) {
        arp::handle(p, &OUR_MAC, &OUR_IP);
    }

    /// ARP requests the stack put on the wire asking about `ip`.
    fn requests_sent_for(ip: [u8; 4]) -> usize {
        raw::all().iter().filter(|f| {
            f.len() >= 14 + 28
                && u16::from_be_bytes([f[12], f[13]]) == 0x0806
                && u16::from_be_bytes([f[14 + 6], f[14 + 7]]) == OP_REQUEST
                && f[14 + 24..14 + 28] == ip
        }).count()
    }

    const GATEWAY_IP: [u8; 4] = [10, 0, 0, 1];
    const GATEWAY_MAC: [u8; 6] = [0x02, 0x47, 0x57, 0x00, 0x00, 0x01];

    /// **A request cannot rewrite a binding we already hold.** One 42-byte
    /// frame — op=request, spa=<gateway>, sha=<attacker>, tpa=<us> — used to
    /// replace the gateway's MAC outright, and flush every frame queued for it
    /// to the attacker. The reply arm had been guarded by `ARP_PENDING` for
    /// months; this arm walked around it.
    #[test]
    fn a_request_cannot_rewrite_an_existing_binding() {
        let _g = begin();
        arp::insert(GATEWAY_IP, GATEWAY_MAC);
        deliver(&well_formed(OP_REQUEST, ATTACKER_MAC, GATEWAY_IP, OUR_IP));
        assert_eq!(arp::lookup(&GATEWAY_IP), Some(GATEWAY_MAC),
                   "an unsolicited request must not replace the gateway's MAC");
        assert_eq!(requests_sent_for(GATEWAY_IP), 1,
                   "the conflict is VERIFIED: we ask the question ourselves");

        // Repeating the conflict does not make us re-ask while the first
        // question is fresh — otherwise the attacker drives a broadcast per frame.
        for _ in 0..10 {
            deliver(&well_formed(OP_REQUEST, ATTACKER_MAC, GATEWAY_IP, OUR_IP));
        }
        assert_eq!(requests_sent_for(GATEWAY_IP), 1, "one verification per TTL");
    }

    /// The other half of refusing the overwrite: a peer whose NIC really did
    /// change is not locked out. Its answer to OUR verification question goes
    /// through `ARP_PENDING` like any solicited reply, and wins.
    #[test]
    fn a_verified_conflict_lets_the_genuine_owner_update_its_binding() {
        let _g = begin();
        const NEW_GW_MAC: [u8; 6] = [0x02, 0x47, 0x57, 0x00, 0x00, 0x02];
        arp::insert(GATEWAY_IP, GATEWAY_MAC);
        deliver(&well_formed(OP_REQUEST, NEW_GW_MAC, GATEWAY_IP, OUR_IP));
        assert_eq!(arp::lookup(&GATEWAY_IP), Some(GATEWAY_MAC), "not on the request");
        deliver(&well_formed(OP_REPLY, NEW_GW_MAC, GATEWAY_IP, OUR_IP));
        assert_eq!(arp::lookup(&GATEWAY_IP), Some(NEW_GW_MAC),
                   "but on the answer to the question the conflict made us ask");
    }

    /// **Unsolicited learns cannot evict.** Fifteen requests with distinct
    /// senders filled the 16-entry table, and the LRU then dropped the
    /// entries in constant use — the gateway is the oldest insert there is,
    /// and `get` never refreshes `age`.
    #[test]
    fn a_flood_of_unsolicited_requests_cannot_evict_a_binding_we_asked_for() {
        let _g = begin();
        arp::insert(GATEWAY_IP, GATEWAY_MAC);
        for i in 0..(arp::ARP_CACHE_SIZE as u8 + 8) {
            let sha = [0x02, 0x66, 0x00, 0x00, 0x00, i];
            deliver(&well_formed(OP_REQUEST, sha, [10, 0, 0, 100 + i], OUR_IP));
        }
        assert_eq!(arp::lookup(&GATEWAY_IP), Some(GATEWAY_MAC),
                   "a flood of questions must not push out the gateway");
    }

    /// And once the attacker has filled every free slot, the NEXT legitimate
    /// resolution must evict one of the attacker's entries — not the gateway,
    /// which is the oldest entry in the table and was the LRU's first choice.
    #[test]
    fn a_legitimate_resolution_evicts_unsolicited_junk_before_the_gateway() {
        let _g = begin();
        arp::insert(GATEWAY_IP, GATEWAY_MAC);
        for i in 0..(arp::ARP_CACHE_SIZE as u8) {
            let sha = [0x02, 0x66, 0x00, 0x00, 0x00, i];
            deliver(&well_formed(OP_REQUEST, sha, [10, 0, 0, 100 + i], OUR_IP));
        }
        arp::send_request(&OUR_MAC, &OUR_IP, &PEER_IP);
        deliver(&well_formed(OP_REPLY, PEER_MAC, PEER_IP, OUR_IP));
        assert_eq!(arp::lookup(&PEER_IP), Some(PEER_MAC), "the new peer is cached");
        assert_eq!(arp::lookup(&GATEWAY_IP), Some(GATEWAY_MAC),
                   "and the gateway survives: junk goes first");
    }

    /// A request addressed to us is a legitimate question: we learn the asker
    /// so we can answer, and we answer.
    #[test]
    fn a_request_for_our_address_is_learned_and_answered() {
        let _g = begin();
        deliver(&well_formed(OP_REQUEST, PEER_MAC, PEER_IP, OUR_IP));
        assert_eq!(
            arp::lookup(&PEER_IP), Some(PEER_MAC),
            "the asker must be cached so the reply can be addressed",
        );
        assert_eq!(raw::count(), 1, "a request for our address must be answered");
    }

    /// **An unsolicited reply teaches nothing.** This is the whole of ARP
    /// spoofing: an attacker sends a reply nobody asked for, claiming to be
    /// the gateway. `handle` learns from a reply only when it answers a
    /// question in `ARP_PENDING`.
    #[test]
    fn an_unsolicited_reply_cannot_write_the_cache() {
        let _g = begin();
        deliver(&well_formed(OP_REPLY, ATTACKER_MAC, PEER_IP, OUR_IP));
        assert_ne!(
            arp::lookup(&PEER_IP), Some(ATTACKER_MAC),
            "a reply to a question we never asked must not enter the cache",
        );
    }

    /// A gratuitous ARP — a request not addressed to us — is the other half
    /// of the same attack, and is also ignored.
    #[test]
    fn a_gratuitous_arp_for_someone_else_teaches_nothing() {
        let _g = begin();
        deliver(&well_formed(OP_REQUEST, ATTACKER_MAC, PEER_IP, [10, 0, 0, 55]));
        assert_ne!(arp::lookup(&PEER_IP), Some(ATTACKER_MAC));
        deliver(&well_formed(OP_REPLY, ATTACKER_MAC, PEER_IP, [10, 0, 0, 55]));
        assert_ne!(arp::lookup(&PEER_IP), Some(ATTACKER_MAC));
    }

    /// A reply to a question we DID ask is learned — and the same reply
    /// replayed afterwards must not write the cache again. `take_pending`
    /// retires the question, so an answer is good exactly once; otherwise a
    /// recorded reply could be replayed at any later moment to overwrite a
    /// corrected entry.
    #[test]
    fn an_answer_to_our_own_question_is_good_exactly_once() {
        let _g = begin();
        arp::send_request(&OUR_MAC, &OUR_IP, &PEER_IP);
        raw::reset();

        deliver(&well_formed(OP_REPLY, PEER_MAC, PEER_IP, OUR_IP));
        assert_eq!(
            arp::lookup(&PEER_IP), Some(PEER_MAC),
            "the answer to our own question must be learned",
        );

        // Replay the recorded answer, with the attacker's MAC substituted.
        deliver(&well_formed(OP_REPLY, ATTACKER_MAC, PEER_IP, OUR_IP));
        assert_eq!(
            arp::lookup(&PEER_IP), Some(PEER_MAC),
            "the question was retired; a second answer must not overwrite it",
        );
    }

    /// RFC 826's fixed header defines what the address fields MEAN. Parsing
    /// `sha`/`spa` as a MAC/IPv4 pair without checking it is taking the
    /// sender's word for the layout.
    #[test]
    fn a_packet_that_is_not_ethernet_over_ipv4_is_dropped() {
        let _g = begin();
        let bad = [
            packet(2, 0x0800, 6, 4, OP_REQUEST, ATTACKER_MAC, PEER_IP, [0; 6], OUR_IP),
            packet(1, 0x86DD, 6, 4, OP_REQUEST, ATTACKER_MAC, PEER_IP, [0; 6], OUR_IP),
            packet(1, 0x0800, 8, 4, OP_REQUEST, ATTACKER_MAC, PEER_IP, [0; 6], OUR_IP),
            packet(1, 0x0800, 6, 16, OP_REQUEST, ATTACKER_MAC, PEER_IP, [0; 6], OUR_IP),
        ];
        for p in &bad {
            deliver(p);
        }
        assert_ne!(
            arp::lookup(&PEER_IP), Some(ATTACKER_MAC),
            "a packet whose header does not say Ethernet-over-IPv4 must not be cached",
        );
        assert_eq!(raw::count(), 0, "nor answered");
    }

    /// Senders that cannot legitimately exist: the unspecified address, the
    /// broadcast address, and a source MAC with the multicast bit set (which
    /// RFC 826 forbids — no host owns a multicast MAC).
    #[test]
    fn impossible_senders_are_never_cached() {
        let _g = begin();

        deliver(&well_formed(OP_REQUEST, PEER_MAC, [0, 0, 0, 0], OUR_IP));
        assert_eq!(arp::lookup(&[0, 0, 0, 0]), None, "0.0.0.0 must not be cached");

        deliver(&well_formed(OP_REQUEST, PEER_MAC, [255, 255, 255, 255], OUR_IP));
        assert_eq!(
            arp::lookup(&[255, 255, 255, 255]), None,
            "the broadcast address must not be cached",
        );

        let mcast_mac = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01];
        deliver(&well_formed(OP_REQUEST, mcast_mac, PEER_IP, OUR_IP));
        assert_ne!(
            arp::lookup(&PEER_IP), Some(mcast_mac),
            "a source MAC with the multicast bit set is RFC-illegal",
        );
        assert_eq!(raw::count(), 0, "none of these deserve a reply either");
    }

    /// A packet shorter than the 28-byte fixed layout has no fields to read;
    /// `handle` casts the buffer to a `#[repr(C, packed)]` struct.
    ///
    /// Unlike the other defences here, no canary can demonstrate this one:
    /// removing the length check does not produce a wrong answer, it produces
    /// an out-of-bounds read of whatever follows the frame in memory, which is
    /// undefined behaviour and may look like anything. That is the point of
    /// the bound, and it is why the test drives every length from 0 to 27
    /// rather than one short packet.
    #[test]
    fn a_truncated_packet_is_dropped() {
        let _g = begin();
        let full = well_formed(OP_REQUEST, ATTACKER_MAC, PEER_IP, OUR_IP);
        assert_eq!(full.len(), 28);
        for n in 0..28usize {
            deliver(&full[..n]);
        }
        assert_ne!(arp::lookup(&PEER_IP), Some(ATTACKER_MAC));
        assert_eq!(raw::count(), 0);
    }

    /// U13-7 / M21: the canary for the empty-cache dial after one unsolicited
    /// request.
    ///
    /// `a_request_for_our_address_is_learned_and_answered` above pins the
    /// LEGITIMATE side of this: a request addressed to us is a real question
    /// from a real neighbour, and RFC 826 says to learn the asker. The gap
    /// unit 06 named is the CONSEQUENCE when the claimed sender (`spa`) is
    /// not who it says: with an empty cache, one such request — sent before
    /// we ever ask about that address ourselves — plants a binding that
    /// `lookup` returns exactly as if it had come from a real exchange.
    /// `lookup_solicited` (M21's fix, used by `tcp.rs::resolve_peer_mac` for
    /// every outbound dial) is the property this test pins: it must refuse
    /// that binding, and only a genuine request/reply round trip may satisfy
    /// it.
    #[test]
    fn an_unsolicited_entry_does_not_satisfy_a_solicited_lookup() {
        let _g = begin();
        // The attacker, before we have ever asked about PEER_IP: a request
        // ADDRESSED TO US (so `handle`'s "is this for our address" gate
        // passes) claiming `spa = PEER_IP`, `sha = ATTACKER_MAC`.
        deliver(&well_formed(OP_REQUEST, ATTACKER_MAC, PEER_IP, OUR_IP));
        assert_eq!(
            arp::lookup(&PEER_IP), Some(ATTACKER_MAC),
            "precondition: today's `lookup` does return an unsolicited entry",
        );
        assert_eq!(
            arp::lookup_solicited(&PEER_IP), None,
            "an unsolicited entry must not satisfy a caller that is about to \
             dial that address -- the attacker sent one frame and never had \
             to answer anything",
        );

        // The genuine exchange: our own question, answered by the real peer.
        arp::send_request(&OUR_MAC, &OUR_IP, &PEER_IP);
        deliver(&well_formed(OP_REPLY, PEER_MAC, PEER_IP, OUR_IP));
        assert_eq!(
            arp::lookup_solicited(&PEER_IP), Some(PEER_MAC),
            "a real request/reply round trip must upgrade the entry",
        );
    }

    /// NUD-style reachable-time aging (coordinator ask, alongside M26). A
    /// solicited entry is still USABLE past `ARP_REACHABLE_TICKS` — handed
    /// back rather than refused, since a NIC does not usually change
    /// mid-session — but a caller about to reuse it for a fresh dial fires
    /// a UNICAST probe (straight to the cached MAC, never broadcast) to
    /// re-confirm it, and that probe is rate-limited: a second dial while
    /// still stale, before any reply, must not repeat it.
    #[test]
    fn a_stale_solicited_entry_is_still_usable_but_draws_a_unicast_probe() {
        let _g = begin();
        azos_drv_irqchip::clint::set_test_time(1_000_000);

        // A genuine, solicited resolution.
        arp::send_request(&OUR_MAC, &OUR_IP, &PEER_IP);
        deliver(&well_formed(OP_REPLY, PEER_MAC, PEER_IP, OUR_IP));
        assert_eq!(arp::lookup_solicited(&PEER_IP), Some(PEER_MAC), "precondition");
        raw::reset();

        // Immediately after: fresh, so no probe.
        assert_eq!(
            arp::lookup_solicited_verified(&OUR_MAC, &OUR_IP, &PEER_IP), Some(PEER_MAC),
            "a fresh solicited entry must still be returned",
        );
        assert_eq!(raw::count(), 0, "a fresh entry must not draw a probe");

        // Past the reachable-time window.
        azos_drv_irqchip::clint::set_test_time(
            1_000_000 + 30 * azos_drv_sys::timebase::TIMER_FREQ + 1,
        );
        assert_eq!(
            arp::lookup_solicited_verified(&OUR_MAC, &OUR_IP, &PEER_IP), Some(PEER_MAC),
            "a stale solicited entry must STILL be returned -- usable while \
             it is re-verified in the background",
        );
        let probes = raw::all();
        assert_eq!(
            probes.len(), 1,
            "exactly one probe must go out once the entry ages past reachable-time",
        );
        let f = &probes[0];
        assert_eq!(&f[0..6], &PEER_MAC, "the probe must be UNICAST to the cached MAC, not broadcast");
        assert_eq!(u16::from_be_bytes([f[12], f[13]]), 0x0806, "it must be an ARP frame");
        assert_eq!(u16::from_be_bytes([f[20], f[21]]), OP_REQUEST, "and a REQUEST");
        assert_eq!(&f[14 + 24..14 + 28], &PEER_IP[..], "asking about the same peer");

        // A second call while still stale, before any reply, must not
        // repeat the probe.
        assert_eq!(
            arp::lookup_solicited_verified(&OUR_MAC, &OUR_IP, &PEER_IP), Some(PEER_MAC),
        );
        assert_eq!(raw::count(), 1, "a second call while a probe is outstanding must not re-probe");
    }
}

/// `ip::handle` — the first code in this kernel that touches a hostile packet.
///
/// Everything below it (TCP, UDP, ICMP, IGMP) is reached only through here, so
/// each of these checks is load-bearing for every protocol at once.
#[cfg(test)]
mod ip_input {
    use super::{arp, ip, tcp, wire};
    use super::NET_SERIAL as SERIAL;

    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const PEER_IP: [u8; 4] = [10, 0, 0, 9];
    const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    const PROTO_TCP: u8 = 6;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        for idx in 0..azos_limits::TCP_MAX_CONNS {
            tcp::close(idx);
            tcp::close(idx);
        }
        wire::reset();
        azos_drv_irqchip::clint::set_test_time(70_000);
        arp::insert(PEER_IP, PEER_MAC);
        tcp::init(OUR_MAC, OUR_IP);
        wire::reset();
        g
    }

    /// A well-formed IPv4 packet with a correct header checksum, computed with
    /// the kernel's own `ip::checksum`.
    #[allow(clippy::too_many_arguments)]
    fn packet(
        version_ihl: u8, total_len: Option<u16>, flags_frag: u16,
        proto: u8, src: [u8; 4], dst: [u8; 4], body: &[u8],
    ) -> Vec<u8> {
        let ihl = ((version_ihl & 0x0F) as usize) * 4;
        let hdr_len = ihl.max(20);
        let mut p = vec![0u8; hdr_len];
        p[0] = version_ihl;
        let total = total_len.unwrap_or((hdr_len + body.len()) as u16);
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        p[8] = 64; // ttl
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        let ck = ip::checksum(&p[..hdr_len]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(body);
        p
    }

    fn deliver(p: &[u8]) {
        ip::handle(p, &OUR_MAC, &OUR_IP);
        if tcp::TCP_DELACK_PASS_FLUSH {
            tcp::flush_held_acks(false);
        }
    }

    /// A TCP SYN, checksummed for the given IP endpoints.
    fn syn(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut s = Vec::with_capacity(20);
        s.extend_from_slice(&src_port.to_be_bytes());
        s.extend_from_slice(&dst_port.to_be_bytes());
        s.extend_from_slice(&1000u32.to_be_bytes());
        s.extend_from_slice(&0u32.to_be_bytes());
        s.push(5 << 4);
        s.push(0x02); // SYN
        s.extend_from_slice(&4096u16.to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0]);
        let pseudo = ip::pseudo_checksum(&src_ip, &dst_ip, PROTO_TCP, s.len() as u16);
        let ck = tcp::tcp_checksum(pseudo, &s);
        s[16..18].copy_from_slice(&ck.to_be_bytes());
        s
    }

    fn listening(port: u16) -> usize {
        let idx = tcp::listen(port);
        assert!(idx >= 0, "no free connection slot");
        idx as usize
    }

    fn opened() -> bool {
        (0..azos_limits::TCP_MAX_CONNS)
            .any(|i| tcp::conn_state(i) == tcp::TcpState::SynRcvd)
    }

    /// The path works end to end: an IPv4 packet carrying a TCP SYN reaches
    /// the TCP state machine and is answered. Without this the rejection tests
    /// below would all pass on a stack that drops everything.
    #[test]
    fn a_well_formed_packet_reaches_the_transport_layer() {
        let _g = begin();
        listening(7500);
        deliver(&packet(0x45, None, 0, PROTO_TCP, PEER_IP, OUR_IP,
                        &syn(PEER_IP, OUR_IP, 45000, 7500)));
        assert!(opened(), "a valid packet must reach TCP");
        assert_eq!(wire::sent_count(), 1, "and TCP must answer through the IP layer");
    }

    /// **A remote halt, if the guard is missing.** A crafted header can claim
    /// `total_length` smaller than its own `ihl`. The payload slice is
    /// `&payload[ihl..total]`, and a reversed range panics — which under this
    /// kernel's `panic = "abort"` is a board reset driven by one packet.
    #[test]
    fn a_total_length_below_the_header_length_cannot_halt_the_kernel() {
        let _g = begin();
        listening(7501);
        for total in 0u16..20 {
            deliver(&packet(0x45, Some(total), 0, PROTO_TCP, PEER_IP, OUR_IP,
                            &syn(PEER_IP, OUR_IP, 45001, 7501)));
        }
        // A 6-word header (24 bytes) with a total that lands inside it.
        for total in 20u16..24 {
            deliver(&packet(0x46, Some(total), 0, PROTO_TCP, PEER_IP, OUR_IP,
                            &syn(PEER_IP, OUR_IP, 45001, 7501)));
        }
        assert!(!opened(), "none of these may reach TCP");
        assert_eq!(wire::sent_count(), 0, "nor be answered");
    }

    /// Version, header length and total length bounds.
    #[test]
    fn malformed_lengths_and_versions_are_dropped() {
        let _g = begin();
        listening(7502);
        let body = syn(PEER_IP, OUR_IP, 45002, 7502);

        // Not IPv4.
        deliver(&packet(0x65, None, 0, PROTO_TCP, PEER_IP, OUR_IP, &body));
        // IHL below the 20-byte minimum.
        for ihl in 0u8..5 {
            deliver(&packet(0x40 | ihl, None, 0, PROTO_TCP, PEER_IP, OUR_IP, &body));
        }
        // total_length beyond the bytes actually received.
        deliver(&packet(0x45, Some(9000), 0, PROTO_TCP, PEER_IP, OUR_IP, &body));
        // Shorter than the fixed header.
        let full = packet(0x45, None, 0, PROTO_TCP, PEER_IP, OUR_IP, &body);
        for n in 0..20usize {
            deliver(&full[..n]);
        }

        assert!(!opened(), "no malformed packet may reach TCP");
        assert_eq!(wire::sent_count(), 0);
    }

    /// A header whose checksum does not verify must be dropped before any
    /// field beyond the length bounds is acted on.
    #[test]
    fn a_bad_header_checksum_is_dropped() {
        let _g = begin();
        listening(7503);
        let mut p = packet(0x45, None, 0, PROTO_TCP, PEER_IP, OUR_IP,
                           &syn(PEER_IP, OUR_IP, 45003, 7503));
        p[10] ^= 0xFF;
        deliver(&p);
        assert!(!opened(), "a corrupt header must not reach TCP");
        assert_eq!(wire::sent_count(), 0);
    }

    /// This stack does no reassembly, so a fragment must be dropped rather
    /// than handed on: fragment N>0 would have its payload parsed as a fresh
    /// L4 header, letting an attacker smuggle data past any L4-level check
    /// simply by fragmenting it.
    #[test]
    fn fragments_are_dropped_rather_than_parsed_as_fresh_headers() {
        let _g = begin();
        listening(7504);
        let body = syn(PEER_IP, OUR_IP, 45004, 7504);

        // More-fragments set, offset 0.
        deliver(&packet(0x45, None, 0x2000, PROTO_TCP, PEER_IP, OUR_IP, &body));
        // A non-zero offset, with and without MF.
        deliver(&packet(0x45, None, 0x0001, PROTO_TCP, PEER_IP, OUR_IP, &body));
        deliver(&packet(0x45, None, 0x2001, PROTO_TCP, PEER_IP, OUR_IP, &body));
        assert!(!opened(), "no fragment may reach TCP");

        // Don't Fragment alone is NOT fragmentation, and must still be
        // delivered — dropping it would break path-MTU-discovering peers.
        deliver(&packet(0x45, None, 0x4000, PROTO_TCP, PEER_IP, OUR_IP, &body));
        assert!(opened(), "the DF bit alone does not make a packet a fragment");
    }

    /// On shared media the NIC hands up every frame. Without a destination
    /// filter the stack ingests the neighbours' traffic and feeds it to TCP,
    /// whose connection lookup can match on ports alone.
    #[test]
    fn a_packet_addressed_to_someone_else_is_not_ingested() {
        let _g = begin();
        listening(7505);
        deliver(&packet(0x45, None, 0, PROTO_TCP, PEER_IP, [10, 0, 0, 77],
                        &syn(PEER_IP, [10, 0, 0, 77], 45005, 7505)));
        assert!(!opened(), "10.0.0.77 is not us");
        assert_eq!(wire::sent_count(), 0);
    }

    /// The limited broadcast still has to be accepted: DHCP OFFER/ACK arrive
    /// on 255.255.255.255.
    #[test]
    fn the_limited_broadcast_is_still_accepted() {
        let _g = begin();
        listening(7506);
        deliver(&packet(0x45, None, 0, PROTO_TCP, PEER_IP, [255, 255, 255, 255],
                        &syn(PEER_IP, [255, 255, 255, 255], 45006, 7506)));
        assert!(opened(), "the limited broadcast must be accepted");
    }

    /// So does the subnet directed broadcast — how a /24 neighbour reaches
    /// everyone on the link.
    ///
    /// (A separate test rather than a second `begin()` in the one above:
    /// `NET_SERIAL` is a plain `Mutex`, so taking it twice on one thread
    /// deadlocks. It did, and the suite hung for two minutes.)
    #[test]
    fn the_subnet_directed_broadcast_is_still_accepted() {
        let _g = begin();
        listening(7507);
        deliver(&packet(0x45, None, 0, PROTO_TCP, PEER_IP, [10, 0, 0, 255],
                        &syn(PEER_IP, [10, 0, 0, 255], 45007, 7507)));
        assert!(opened(), "the /24 directed broadcast must be accepted");
    }

    /// An unknown protocol number is ignored, not guessed at.
    #[test]
    fn an_unknown_protocol_number_is_ignored() {
        let _g = begin();
        listening(7508);
        for proto in [0u8, 1 + 1, 99, 200, 255] {
            if proto == 6 { continue; }
            deliver(&packet(0x45, None, 0, proto, PEER_IP, OUR_IP,
                            &syn(PEER_IP, OUR_IP, 45008, 7508)));
        }
        assert!(!opened(), "only protocol 6 reaches TCP");
    }
}

/// UDP and ICMP, both reached only through `ip::handle`.
#[cfg(test)]
mod udp_icmp {
    use super::NET_SERIAL as SERIAL;
    use super::{arp, ip, tcp, udp, wire};

    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const PEER_IP: [u8; 4] = [10, 0, 0, 9];
    const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    const PROTO_ICMP: u8 = 1;
    const PROTO_UDP: u8 = 17;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        for i in 0..udp::UDP_MAX_SOCKETS {
            udp::unbind(i);
        }
        for idx in 0..azos_limits::TCP_MAX_CONNS {
            tcp::close(idx);
            tcp::close(idx);
        }
        wire::reset();
        azos_drv_irqchip::clint::set_test_time(80_000);
        arp::insert(PEER_IP, PEER_MAC);
        tcp::init(OUR_MAC, OUR_IP);
        wire::reset();
        g
    }

    /// Wrap `body` in an IPv4 header with a correct header checksum.
    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        let ck = ip::checksum(&p[..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(body);
        p
    }

    /// A UDP datagram. `length` and `checksum` are overridable because both
    /// are fields an attacker chooses.
    fn datagram(
        src_port: u16, dst_port: u16, payload: &[u8],
        length: Option<u16>, force_checksum: Option<u16>,
    ) -> Vec<u8> {
        let mut d = Vec::with_capacity(8 + payload.len());
        d.extend_from_slice(&src_port.to_be_bytes());
        d.extend_from_slice(&dst_port.to_be_bytes());
        d.extend_from_slice(&length.unwrap_or((8 + payload.len()) as u16).to_be_bytes());
        d.extend_from_slice(&[0, 0]); // checksum placeholder
        d.extend_from_slice(payload);
        match force_checksum {
            Some(c) => d[6..8].copy_from_slice(&c.to_be_bytes()),
            None => {
                let pseudo = ip::pseudo_checksum(&PEER_IP, &OUR_IP, PROTO_UDP, d.len() as u16);
                let ck = tcp::tcp_checksum(pseudo, &d);
                d[6..8].copy_from_slice(&ck.to_be_bytes());
            }
        }
        d
    }

    fn deliver_udp(d: &[u8]) {
        ip::handle(&ipv4(PROTO_UDP, PEER_IP, OUR_IP, d), &OUR_MAC, &OUR_IP);
    }

    #[test]
    fn a_valid_datagram_reaches_the_socket_bound_to_its_port() {
        let _g = begin();
        let sock = udp::bind(6000);
        assert!(sock >= 0, "bind failed");
        deliver_udp(&datagram(45000, 6000, b"payload", None, None));

        let mut buf = [0u8; 32];
        let n = udp::recv(sock as usize, &mut buf);
        assert_eq!(n, 7, "the datagram must reach the bound socket, got {n}");
        assert_eq!(&buf[..7], b"payload");
    }

    /// RFC 768: on IPv4 the UDP checksum is OPTIONAL, and an all-zero field
    /// means the sender computed none. Rejecting those would silently break
    /// address acquisition — `dhcp.rs` transmits this way, and so do many real
    /// DHCP and TFTP servers.
    #[test]
    fn a_datagram_with_no_checksum_is_accepted_because_rfc_768_allows_it() {
        let _g = begin();
        let sock = udp::bind(6001);
        deliver_udp(&datagram(45001, 6001, b"nocsum", None, Some(0)));
        let mut buf = [0u8; 32];
        assert_eq!(
            udp::recv(sock as usize, &mut buf), 6,
            "a zero checksum means 'not computed', not 'invalid'",
        );
    }

    /// A checksum that is present and wrong is a different matter.
    #[test]
    fn a_datagram_with_a_wrong_checksum_is_dropped() {
        let _g = begin();
        let sock = udp::bind(6002);
        let mut d = datagram(45002, 6002, b"corrupt", None, None);
        d[6] ^= 0xFF;
        if d[6..8] == [0, 0] { d[6] ^= 0x01; } // must not become "no checksum"
        deliver_udp(&d);
        let mut buf = [0u8; 32];
        assert!(udp::recv(sock as usize, &mut buf) <= 0, "a corrupt datagram must be dropped");
    }

    /// The length field is the attacker's, not the receiver's. One that claims
    /// more than arrived must be refused rather than believed, and one that
    /// claims less must truncate — trailing bytes past `length` are not part
    /// of the datagram and must not reach the application.
    #[test]
    fn the_length_field_is_not_taken_on_trust() {
        let _g = begin();
        let sock = udp::bind(6003);

        // Claims more than the segment holds.
        deliver_udp(&datagram(45003, 6003, b"short", Some(9000), Some(0)));
        // Claims less than the 8-byte header.
        for bad in 0u16..8 {
            deliver_udp(&datagram(45003, 6003, b"short", Some(bad), Some(0)));
        }
        let mut buf = [0u8; 64];
        assert!(
            udp::recv(sock as usize, &mut buf) <= 0,
            "a datagram whose length field is impossible must be dropped",
        );

        // Claims less than arrived: the tail is not part of the datagram.
        deliver_udp(&datagram(45003, 6003, b"KEEPtail", Some(12), Some(0)));
        let n = udp::recv(sock as usize, &mut buf);
        assert_eq!(n, 4, "only the 4 bytes inside the declared length, got {n}");
        assert_eq!(&buf[..4], b"KEEP");
    }

    /// The largest datagram the link can carry survives the ring intact.
    ///
    /// This is the regression test for a bug that shipped: the slot was a bare
    /// `512` while every caller of `recvfrom` already reserved `ETH_MTU`, so
    /// the ring was the one place on the receive path not sized for a real
    /// datagram. Anything above 512 bytes was truncated and the short read was
    /// reported as a whole datagram.
    ///
    /// It broke TFTP outright — a DATA block is 4 header bytes plus 512 of
    /// payload, so every full block arrived as 508 bytes, which TFTP defines
    /// as the *last* block of a file. Transfers ended early and reported
    /// success. DHCP shares this same ring (`dhcp.rs` binds port 68), so any
    /// reply carrying a long option list was parsed from a truncated buffer.
    ///
    /// The payload is a position-dependent pattern, not a constant fill: a
    /// constant would survive a copy that got the length right and the offset
    /// wrong, and would say nothing about *which* bytes arrived.
    #[test]
    fn the_ring_slot_holds_the_largest_datagram_the_link_can_deliver() {
        let _g = begin();
        let sock = udp::bind(6006);
        assert!(sock >= 0);

        // What a full Ethernet frame leaves for a UDP payload.
        let max_payload =
            crate::ethernet::ETH_FRAME_MAX - 14 - ip::IP_HDR_MIN - 8;
        assert_eq!(max_payload, 1472, "MTU arithmetic changed; the ring must follow");

        let big: Vec<u8> = (0..max_payload).map(|i| (i % 251) as u8).collect();
        deliver_udp(&datagram(45006, 6006, &big, None, None));

        let mut buf = [0u8; 2048];
        let n = udp::recv(sock as usize, &mut buf);
        assert_eq!(
            n, max_payload as i32,
            "a full-MTU datagram must arrive whole; {n} of {max_payload} bytes \
             means the ring slot is smaller than the link",
        );
        assert_eq!(&buf[..max_payload], &big[..], "and byte-for-byte unchanged");
    }

    /// A datagram too large for a slot is dropped whole, and counted.
    ///
    /// Truncating and reporting success is the defect this replaced: handing a
    /// caller a partial datagram while claiming it is complete corrupts
    /// whatever parses it, with nothing anywhere to show it happened. Linux
    /// drops on `sk_rcvbuf` overflow and counts it (`UDP_MIB_RCVBUFERRORS`,
    /// `netstat -su`); this is the same choice.
    ///
    /// Today `net_poll` reads into an `ETH_FRAME_MAX` buffer, so nothing this
    /// large can arrive from the wire and the guard is unreachable in
    /// production. That is the point: it is what stands between silent
    /// truncation and a driver that one day hands up a jumbo frame. `ip::handle`
    /// takes a slice of any length, which is the seam such a driver would
    /// widen, so the test drives it there.
    #[test]
    fn a_datagram_too_large_for_a_slot_is_dropped_whole_not_truncated() {
        let _g = begin();
        let sock = udp::bind(6007);
        assert!(sock >= 0);

        // Counters are global and monotonic — never reset between tests, so
        // only the delta means anything. An absolute assertion here would pass
        // in one suite order and fail in another.
        let (oversize_before, _, _) = udp::rx_drop_stats();

        let huge = vec![0x5Au8; 2000];
        deliver_udp(&datagram(45007, 6007, &huge, None, None));

        let mut buf = [0u8; 4096];
        let n = udp::recv(sock as usize, &mut buf);
        assert_eq!(
            n, 0,
            "nothing may be delivered: {n} bytes means the datagram was \
             truncated and passed off as whole",
        );

        let (oversize_after, _, _) = udp::rx_drop_stats();
        assert_eq!(
            oversize_after, oversize_before + 1,
            "and the drop must be visible to an operator, not silent",
        );
    }

    /// A caller whose buffer is smaller than the datagram gets the truncation
    /// POSIX allows — and it is counted, because we cannot yet signal it.
    ///
    /// `recvmsg` raises `MSG_TRUNC` in `msg_flags` for exactly this case, and
    /// returns the real datagram length when the caller asks for it. We have
    /// no flag to raise: returning the full length from `recvfrom` instead of
    /// the copied length would silently break every caller that slices
    /// `&buf[..n]`, and adding the flag means widening the syscall ABI in all
    /// three places it is declared. Until then the counter is the only
    /// evidence the tail was discarded.
    #[test]
    fn a_delivery_into_a_short_buffer_is_truncated_and_counted() {
        let _g = begin();
        let sock = udp::bind(6008);
        assert!(sock >= 0);

        let (_, _, trunc_before) = udp::rx_drop_stats();

        let body = vec![0xC3u8; 900];
        deliver_udp(&datagram(45008, 6008, &body, None, None));

        let mut small = [0u8; 100];
        let n = udp::recv(sock as usize, &mut small);
        assert_eq!(n, 100, "the caller gets what it asked for, no more");

        let (_, _, trunc_after) = udp::rx_drop_stats();
        assert_eq!(
            trunc_after, trunc_before + 1,
            "the discarded tail must be counted",
        );

        // The rest of the datagram is gone, not held back for a second read:
        // a datagram is delivered once, whole or not at all.
        let mut again = [0u8; 2048];
        assert_eq!(
            udp::recv(sock as usize, &mut again), 0,
            "the remainder must not surface as a second datagram",
        );
    }

    /// Overrunning the ring depth drops, and says so.
    ///
    /// Which end is dropped used to be an open question; it no longer is
    /// (owner decision, 2026-09-05: head-drop — see `UdpRxBuf::push` in
    /// `udp.rs`). This test only pins the counting, which is needed under
    /// either policy and was written before the choice was settled, so it
    /// deliberately does not check which datagrams survive. That is a
    /// separate, sharper test below
    /// (`head_drop_keeps_the_newest_and_drops_the_oldest`) — a count-only
    /// assertion passes identically whether the ring keeps the newest four or
    /// the oldest four, so it cannot be the test that guards the policy.
    #[test]
    fn datagrams_beyond_the_ring_depth_are_dropped_and_counted() {
        let _g = begin();
        let sock = udp::bind(6009);
        assert!(sock >= 0);

        let (_, full_before, _) = udp::rx_drop_stats();

        // The ring holds 4; send 6.
        for i in 0..6u8 {
            deliver_udp(&datagram(45009, 6009, &[i; 8], None, None));
        }

        let (_, full_after, _) = udp::rx_drop_stats();
        assert_eq!(
            full_after, full_before + 2,
            "two datagrams past a ring of four must be counted as dropped",
        );

        let mut buf = [0u8; 64];
        let mut delivered = 0;
        while udp::recv(sock as usize, &mut buf) > 0 {
            delivered += 1;
        }
        assert_eq!(delivered, 4, "and the ring still holds exactly its depth");
    }

    /// Head-drop, decided (2026-09-05): when the ring is full the datagram
    /// evicted is the OLDEST one already queued, never the one that just
    /// arrived.
    ///
    /// This ring carries sensor telemetry (IMU, GPS, baro): a reading from
    /// 200 ms ago is worth nothing next to the one that just arrived, and a
    /// consumer that is momentarily behind must not be handed a stale value
    /// dressed up as current — the number is individually plausible, so
    /// nothing downstream can tell it is old. Tail-drop (refuse the new
    /// arrival, keep the ring as it stood) is what Linux does and is right
    /// for a general-purpose socket that might carry a command instead of a
    /// sample; it is wrong here.
    ///
    /// This is the test the previous one deliberately declined to be: it
    /// asserts on the actual payload bytes that come back, not just a count,
    /// because a count-only assertion cannot distinguish "kept the newest
    /// four" from "kept the oldest four" — both drop exactly two datagrams
    /// out of six. Reverting `UdpRxBuf::push` to tail-drop (refuse the
    /// arrival instead of evicting the head) makes this test fail: it would
    /// deliver payloads 0,1,2,3 instead of the 2,3,4,5 asserted below.
    #[test]
    fn head_drop_keeps_the_newest_and_drops_the_oldest() {
        let _g = begin();
        let sock = udp::bind(6010);
        assert!(sock >= 0);

        // The ring holds 4. Send 6, each payload tagged with its own send
        // order (0..6) so draining can show which datagrams actually
        // survived, not merely how many.
        for i in 0..6u8 {
            deliver_udp(&datagram(45010, 6010, &[i; 8], None, None));
        }

        let mut buf = [0u8; 64];
        let mut received = Vec::new();
        loop {
            let n = udp::recv(sock as usize, &mut buf);
            if n <= 0 { break; }
            received.push(buf[0]);
        }

        assert_eq!(
            received, vec![2u8, 3, 4, 5],
            "a ring of 4 fed datagrams 0..6 must yield the newest four \
             (2,3,4,5) in arrival order; got {received:?}. Finding 0 or 1 in \
             this list means the ring refused an arriving datagram instead of \
             evicting the oldest queued one — that is tail-drop, not the \
             decided head-drop.",
        );
    }

    /// The oversize check still runs, and still wins, before the ring-full
    /// check — unchanged by the head-drop decision above. An oversize
    /// datagram is refused whole and counted as oversize; it must not also
    /// evict a queued datagram, which would mean paying for a refusal with
    /// somebody else's data.
    #[test]
    fn an_oversize_datagram_does_not_evict_anything_even_on_a_full_ring() {
        let _g = begin();
        let sock = udp::bind(6011);
        assert!(sock >= 0);

        // Fill the ring with 4 identifiable datagrams.
        for i in 0..4u8 {
            deliver_udp(&datagram(45011, 6011, &[i; 8], None, None));
        }

        let (oversize_before, full_before, _) = udp::rx_drop_stats();

        // One oversize datagram arrives on top of an already-full ring.
        let huge = vec![0x7Bu8; 2000];
        deliver_udp(&datagram(45011, 6011, &huge, None, None));

        let (oversize_after, full_after, _) = udp::rx_drop_stats();
        assert_eq!(
            oversize_after, oversize_before + 1,
            "the oversize datagram must still be counted as oversize",
        );
        assert_eq!(
            full_after, full_before,
            "an oversize datagram must NOT also register as a ring-full \
             eviction — it is refused before the ring is touched at all, so \
             nothing already queued should be paid for its refusal",
        );

        // Drain: must be exactly the original four, untouched, in order.
        let mut buf = [0u8; 64];
        let mut received = Vec::new();
        loop {
            let n = udp::recv(sock as usize, &mut buf);
            if n <= 0 { break; }
            received.push(buf[0]);
        }
        assert_eq!(
            received, vec![0u8, 1, 2, 3],
            "the oversize datagram must not evict a queued one to make room \
             for a refusal that discards it anyway; got {received:?}",
        );
    }

    /// A datagram shorter than the 8-byte header has no header to read.
    #[test]
    fn a_datagram_shorter_than_its_header_is_dropped() {
        let _g = begin();
        udp::bind(6004);
        let full = datagram(45004, 6004, b"x", None, Some(0));
        for n in 0..8usize {
            deliver_udp(&full[..n]);
        }
        // Reaching here without a panic is the assertion; `dispatch` casts the
        // buffer to a `#[repr(C, packed)]` header.
        assert_eq!(wire::sent_count(), 0);
    }

    /// A datagram for a port nobody bound is dropped in silence — no ICMP port
    /// unreachable, which would otherwise make the robot a scanning oracle.
    #[test]
    fn a_datagram_to_an_unbound_port_is_dropped_silently() {
        let _g = begin();
        deliver_udp(&datagram(45005, 6005, b"nobody home", None, None));
        assert_eq!(
            wire::sent_count(), 0,
            "an unbound port must not answer — a reply would confirm the port is closed",
        );
    }

    // UDP demultiplexing by destination port — and the fact that both
    // handlers are given the SOURCE endpoint, without which a destination port
    // alone identifies nothing and every off-path forgery aims there — is
    // covered end to end by the `dns_resolver` and `ntp_client` modules, which
    // drive the real resolvers through this same dispatch.

    // ── ICMP ─────────────────────────────────────────────────────────────────

    fn echo(icmp_type: u8, body: &[u8], corrupt: bool) -> Vec<u8> {
        let mut m = Vec::with_capacity(8 + body.len());
        m.push(icmp_type);
        m.push(0); // code
        m.extend_from_slice(&[0, 0]); // checksum placeholder
        m.extend_from_slice(&[0x12, 0x34]); // id
        m.extend_from_slice(&[0x00, 0x01]); // seq
        m.extend_from_slice(body);
        let ck = ip::checksum(&m);
        m[2..4].copy_from_slice(&ck.to_be_bytes());
        if corrupt {
            m[2] ^= 0xFF;
        }
        m
    }

    fn deliver_icmp(m: &[u8], dst: [u8; 4]) {
        ip::handle(&ipv4(PROTO_ICMP, PEER_IP, dst, m), &OUR_MAC, &OUR_IP);
    }

    #[test]
    fn an_echo_request_is_answered_with_the_same_payload() {
        let _g = begin();
        deliver_icmp(&echo(8, b"ping-payload", false), OUR_IP);
        let sent = wire::sent();
        assert_eq!(sent.len(), 1, "an echo request must be answered");
        let r = &sent[0].payload;
        assert_eq!(r[0], 0, "the reply is type 0, echo reply");
        assert_eq!(&r[4..8], &[0x12, 0x34, 0x00, 0x01], "id and seq are echoed back");
        assert_eq!(&r[8..], b"ping-payload");
        assert_eq!(
            ip::checksum(r), 0,
            "the reply must carry a valid ICMP checksum of its own",
        );
    }

    /// Echoing a corrupt request would vouch for payload bytes that were never
    /// verified — the reply is signed with our address.
    #[test]
    fn a_corrupt_echo_request_is_not_answered() {
        let _g = begin();
        deliver_icmp(&echo(8, b"tampered", true), OUR_IP);
        assert_eq!(wire::sent_count(), 0, "a corrupt echo request must be dropped");
    }

    /// Only echo request (type 8) is handled. Answering other types turns the
    /// robot into a reflector.
    #[test]
    fn only_echo_requests_are_answered() {
        let _g = begin();
        for t in [0u8, 3, 5, 11, 13, 17, 30, 255] {
            deliver_icmp(&echo(t, b"x", false), OUR_IP);
        }
        assert_eq!(wire::sent_count(), 0, "only type 8 deserves a reply");
    }

    /// A truncated ICMP message has no header. Also: an echo request addressed
    /// to a broadcast address must not be answered — that is the smurf
    /// amplifier, where one spoofed packet draws replies from every host.
    #[test]
    fn truncated_and_broadcast_echo_requests_are_not_answered() {
        let _g = begin();
        let full = echo(8, b"payload", false);
        for n in 0..8usize {
            deliver_icmp(&full[..n], OUR_IP);
        }
        assert_eq!(wire::sent_count(), 0, "a truncated ICMP message must be dropped");

        deliver_icmp(&full, [255, 255, 255, 255]);
        deliver_icmp(&full, [10, 0, 0, 255]);
        assert_eq!(
            wire::sent_count(), 0,
            "a broadcast echo request must not be answered — one spoofed packet \
             would otherwise draw a reply from every host on the link",
        );
    }
}

/// IPv4 multicast membership (RFC 1112 / RFC 2236).
#[cfg(test)]
mod multicast {
    use super::NET_SERIAL as SERIAL;
    use super::{arp, igmp, ip, tcp, wire};

    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const PEER_IP: [u8; 4] = [10, 0, 0, 9];
    const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const PROTO_TCP: u8 = 6;

    const QUERY: u8 = 0x11;
    const V2_REPORT: u8 = 0x16;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        igmp::clear();
        for idx in 0..azos_limits::TCP_MAX_CONNS {
            tcp::close(idx);
            tcp::close(idx);
        }
        wire::reset();
        azos_drv_irqchip::clint::set_test_time(90_000);
        arp::insert(PEER_IP, PEER_MAC);
        tcp::init(OUR_MAC, OUR_IP);
        wire::reset();
        g
    }

    /// An IGMP message with a valid checksum, built here rather than with
    /// `build_message` — the kernel never sends a query, so this suite must
    /// not borrow the kernel's builder to make one.
    fn message(kind: u8, max_resp: u8, group: [u8; 4], corrupt: bool) -> Vec<u8> {
        let mut m = vec![kind, max_resp, 0, 0, group[0], group[1], group[2], group[3]];
        let ck = ip::checksum(&m);
        m[2..4].copy_from_slice(&ck.to_be_bytes());
        if corrupt {
            m[2] ^= 0xFF;
        }
        m
    }

    /// Deliver an IGMP message as it arrives from the wire: inside IPv4.
    fn deliver(m: &[u8], dst: [u8; 4]) {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + m.len()) as u16).to_be_bytes());
        p[8] = 1; // TTL 1, as IGMP requires
        p[9] = igmp::IP_PROTO_IGMP;
        p[12..16].copy_from_slice(&PEER_IP);
        p[16..20].copy_from_slice(&dst);
        let ck = ip::checksum(&p[..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(m);
        ip::handle(&p, &OUR_MAC, &OUR_IP);
    }

    /// Groups named in the IGMP reports we emitted.
    fn reported_groups() -> Vec<[u8; 4]> {
        wire::sent()
            .iter()
            .filter(|s| s.proto == igmp::IP_PROTO_IGMP && s.payload.len() >= 8)
            .filter(|s| s.payload[0] == V2_REPORT)
            .map(|s| [s.payload[4], s.payload[5], s.payload[6], s.payload[7]])
            .collect()
    }

    #[test]
    fn the_multicast_range_is_224_slash_4() {
        for (addr, want) in [
            ([223u8, 255, 255, 255], false),
            ([224, 0, 0, 0], true),
            ([224, 0, 0, 1], true),
            ([239, 255, 255, 255], true),
            ([240, 0, 0, 0], false),
            ([255, 255, 255, 255], false),
            ([10, 0, 0, 1], false),
        ] {
            assert_eq!(
                igmp::is_multicast(&addr), want,
                "{addr:?} multicast? expected {want}",
            );
        }
    }

    /// RFC 1112 §6.4 maps a group to `01:00:5E` plus its LOW 23 BITS. The 24th
    /// is dropped, so 32 groups share one Ethernet address.
    ///
    /// That aliasing is why membership is checked at the IP level and cannot
    /// be delegated to the NIC's MAC filter: hardware filtering alone would
    /// admit traffic for 31 groups nobody joined.
    #[test]
    fn the_mac_mapping_aliases_thirty_two_groups_onto_one_address() {
        assert_eq!(igmp::multicast_mac(&[224, 0, 0, 1]), [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]);
        assert_eq!(
            igmp::multicast_mac(&[224, 128, 1, 1]),
            igmp::multicast_mac(&[225, 0, 1, 1]),
            "the 24th bit is dropped, so these two groups share a MAC",
        );
        assert_ne!(
            [224u8, 128, 1, 1], [225, 0, 1, 1],
            "...even though they are different groups",
        );
        assert_eq!(
            igmp::multicast_mac(&[239, 255, 255, 255])[3] & 0x80, 0,
            "the top bit of the third MAC byte is always cleared",
        );
    }

    /// RFC 1112 §6.1: every host is a permanent member of 224.0.0.1, so it is
    /// joined without asking and must not occupy a table slot.
    #[test]
    fn all_hosts_is_a_permanent_membership_that_costs_no_slot() {
        let _g = begin();
        assert!(igmp::is_joined(&igmp::ALL_HOSTS), "224.0.0.1 is always joined");
        assert_eq!(igmp::join(&igmp::ALL_HOSTS), 0, "joining it succeeds");

        // All MAX_GROUPS slots must still be available.
        for i in 0..igmp::MAX_GROUPS {
            assert_eq!(
                igmp::join(&[239, 1, 0, i as u8]), 0,
                "slot {i} should be free — ALL_HOSTS must not consume one",
            );
        }
    }

    #[test]
    fn join_refuses_a_non_multicast_address_and_a_full_table() {
        let _g = begin();
        assert_eq!(igmp::join(&[10, 0, 0, 5]), -1, "unicast is not a group");
        assert_eq!(igmp::join(&[255, 255, 255, 255]), -1, "nor is broadcast");

        for i in 0..igmp::MAX_GROUPS {
            assert_eq!(igmp::join(&[239, 2, 0, i as u8]), 0);
        }
        assert_eq!(igmp::join(&[239, 2, 0, 99]), -2, "the table is full");
        // A repeat of one already joined still succeeds — independent
        // subscribers on one host is normal.
        assert_eq!(igmp::join(&[239, 2, 0, 0]), 0);
    }

    #[test]
    fn joining_and_leaving_moves_membership() {
        let _g = begin();
        let g = [239, 3, 3, 3];
        assert!(!igmp::is_joined(&g));
        assert_eq!(igmp::join(&g), 0);
        assert!(igmp::is_joined(&g), "a joined group must be joined");
        assert_eq!(igmp::leave(&g), 0);
        assert!(!igmp::is_joined(&g), "a left group must not be");
    }

    /// **The amplification defence.** A query is acted on only if its checksum
    /// verifies. Without that check an off-path attacker makes the robot emit
    /// membership reports at will, using it as a packet source.
    #[test]
    fn a_query_with_a_bad_checksum_draws_no_report() {
        let _g = begin();
        igmp::join(&[239, 4, 4, 4]);
        wire::reset();

        deliver(&message(QUERY, 100, [0, 0, 0, 0], true), igmp::ALL_HOSTS);
        assert!(
            reported_groups().is_empty(),
            "a corrupt query must not make us emit anything",
        );
    }

    /// A valid general query (group 0.0.0.0) draws a report for every joined
    /// group — and for nothing else.
    #[test]
    fn a_general_query_reports_every_joined_group_and_no_others() {
        let _g = begin();
        igmp::join(&[239, 5, 0, 1]);
        igmp::join(&[239, 5, 0, 2]);
        wire::reset();

        deliver(&message(QUERY, 100, [0, 0, 0, 0], false), igmp::ALL_HOSTS);
        let mut got = reported_groups();
        got.sort();
        assert_eq!(
            got, vec![[239, 5, 0, 1], [239, 5, 0, 2]],
            "exactly the joined groups must be reported",
        );
    }

    /// A group-specific query draws a report only if we are actually a member.
    /// Answering for a group we never joined tells a querier the robot is
    /// somewhere it is not.
    ///
    /// **Both queries are addressed to ALL_HOSTS, not to the group.** The
    /// first version sent them to the group address, as a router would — and
    /// `ip::handle` dropped the one for the unjoined group before IGMP ever
    /// saw it. The test therefore passed on the IP admission check, and left
    /// `igmp::handle`'s own membership test unexercised: removing it changed
    /// nothing. Delivering to a destination the IP layer already admits is
    /// what puts the question to the layer this test is about.
    #[test]
    fn a_group_specific_query_is_answered_only_for_a_group_we_joined() {
        let _g = begin();
        igmp::join(&[239, 6, 0, 1]);
        wire::reset();

        deliver(&message(QUERY, 100, [239, 6, 0, 9], false), igmp::ALL_HOSTS);
        assert!(
            reported_groups().is_empty(),
            "we never joined 239.6.0.9 and must not claim to have",
        );

        deliver(&message(QUERY, 100, [239, 6, 0, 1], false), igmp::ALL_HOSTS);
        assert_eq!(reported_groups(), vec![[239, 6, 0, 1]]);
    }

    /// RFC 2236 §6 forbids reporting 224.0.0.1, and `is_joined` returns true
    /// for it — so the exclusion has to be explicit or every query draws a
    /// report the standard prohibits.
    #[test]
    fn the_all_hosts_group_is_never_reported() {
        let _g = begin();
        wire::reset();
        deliver(&message(QUERY, 100, igmp::ALL_HOSTS, false), igmp::ALL_HOSTS);
        assert!(
            !reported_groups().contains(&igmp::ALL_HOSTS),
            "RFC 2236 §6 forbids reporting the all-hosts group",
        );
    }

    /// Anything that is not a membership query is ignored — reports and leaves
    /// from other hosts are not ours to act on.
    #[test]
    fn only_a_membership_query_is_acted_on() {
        let _g = begin();
        igmp::join(&[239, 7, 0, 1]);
        wire::reset();
        for kind in [V2_REPORT, 0x12, 0x17, 0x22, 0x00, 0xFF] {
            deliver(&message(kind, 100, [0, 0, 0, 0], false), igmp::ALL_HOSTS);
        }
        assert!(reported_groups().is_empty(), "only 0x11 is a query");
    }

    /// The property that ties IGMP to `ip::handle`: traffic for a multicast
    /// group is admitted only if the group was actually joined.
    #[test]
    fn multicast_traffic_is_admitted_only_for_a_group_we_joined() {
        let _g = begin();
        let group = [239, 8, 0, 1];
        assert!(tcp::listen(7600) >= 0);

        // Build a TCP SYN addressed to the group.
        let mut s = vec![0u8; 20];
        s[0..2].copy_from_slice(&46000u16.to_be_bytes());
        s[2..4].copy_from_slice(&7600u16.to_be_bytes());
        s[4..8].copy_from_slice(&1000u32.to_be_bytes());
        s[12] = 5 << 4;
        s[13] = 0x02; // SYN
        s[14..16].copy_from_slice(&4096u16.to_be_bytes());
        let pseudo = ip::pseudo_checksum(&PEER_IP, &group, PROTO_TCP, s.len() as u16);
        let ck = tcp::tcp_checksum(pseudo, &s);
        s[16..18].copy_from_slice(&ck.to_be_bytes());

        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + s.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&PEER_IP);
        p[16..20].copy_from_slice(&group);
        let hck = ip::checksum(&p[..20]);
        p[10..12].copy_from_slice(&hck.to_be_bytes());
        p.extend_from_slice(&s);

        let opened = || {
            (0..azos_limits::TCP_MAX_CONNS)
                .any(|i| tcp::conn_state(i) == tcp::TcpState::SynRcvd)
        };

        ip::handle(&p, &OUR_MAC, &OUR_IP);
        assert!(!opened(), "traffic for an unjoined group must not be ingested");

        igmp::join(&group);
        ip::handle(&p, &OUR_MAC, &OUR_IP);
        assert!(opened(), "once joined, the same packet must be accepted");
    }
}

/// Multicast memberships held by sockets (`socket_mcast_join` /
/// `socket_mcast_leave`, behind `SYS_MCAST_JOIN_TYPED` / `SYS_MCAST_LEAVE_TYPED`):
/// the per-socket bound, the refcount that makes two subscribers one membership
/// on the wire, the release on every close path, and delivery of group traffic.
///
/// The syscall layer's half — capabilities, containment, errnos — is in
/// `tests/host/syscall-tests/src/mcast_caps.rs`, which cannot perform a join at
/// all: its NIC stand-ins are `todo!()`, and a first join transmits.
#[cfg(test)]
mod mcast_sockets {
    use super::NET_SERIAL as SERIAL;
    use super::{igmp, ip, socket, udp, wire};
    use socket::{
        McastError, SockAddr, AF_INET, MAX_MCAST_GROUPS_PER_TASK, MAX_MCAST_PER_SOCKET,
        MAX_SOCKETS, SOCK_DGRAM, SOCK_STREAM,
    };

    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    /// What this suite's `net_get_ip` answers.
    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const PEER_IP: [u8; 4] = [10, 0, 0, 9];
    const TASK: u32 = 41;
    const OTHER_TASK: u32 = 42;

    const V2_REPORT: u8 = 0x16;
    const LEAVE_GROUP: u8 = 0x17;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        for fd in 0..MAX_SOCKETS {
            socket::socket_close(fd as i32);
        }
        for i in 0..udp::UDP_MAX_SOCKETS {
            udp::unbind(i);
        }
        // After the closes: a close gives references back, and the table must
        // start empty whatever the previous test left in it.
        igmp::clear();
        wire::reset();
        azos_drv_irqchip::clint::set_test_time(410_000);
        g
    }

    fn udp_sock() -> i32 {
        udp_sock_owned(TASK)
    }

    fn udp_sock_owned(owner: u32) -> i32 {
        let fd = socket::socket_create_owned(AF_INET, SOCK_DGRAM, 0, owner);
        assert!(fd >= 0, "no socket");
        fd
    }

    fn bind(fd: i32, port: u16) {
        let sa = SockAddr { family: AF_INET as u16, port, addr: [0; 4] };
        assert_eq!(socket::socket_bind(fd, &sa), 0, "bind {port}");
    }

    fn join(fd: i32, g: &[u8; 4]) -> Result<(), McastError> {
        socket::socket_mcast_join(fd, g)
    }

    fn leave(fd: i32, g: &[u8; 4]) -> Result<(), McastError> {
        socket::socket_mcast_leave(fd, g)
    }

    /// Groups named by the IGMP messages of `kind` on the wire, oldest first.
    fn igmp_sent(kind: u8) -> Vec<[u8; 4]> {
        wire::sent()
            .iter()
            .filter(|s| s.proto == igmp::IP_PROTO_IGMP && s.payload.len() >= 8)
            .filter(|s| s.payload[0] == kind)
            .map(|s| [s.payload[4], s.payload[5], s.payload[6], s.payload[7]])
            .collect()
    }

    /// A UDP datagram to `group:port` from the peer, as IPv4 hands it up.
    /// Checksum 0: RFC 768's "not computed", which the stack accepts over IPv4.
    fn group_datagram(group: [u8; 4], port: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&47000u16.to_be_bytes());
        u[2..4].copy_from_slice(&port.to_be_bytes());
        u[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        u.extend_from_slice(payload);
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + u.len()) as u16).to_be_bytes());
        p[8] = 1;
        p[9] = ip::IP_PROTO_UDP;
        p[12..16].copy_from_slice(&PEER_IP);
        p[16..20].copy_from_slice(&group);
        let ck = ip::checksum(&p[..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(&u);
        p
    }

    /// Two subscribers are one membership to the network: one report, and the
    /// Leave only when the last one goes. The middle assertion is the one the
    /// refcount exists for — without it the first leave took the group from
    /// under a socket still reading it.
    #[test]
    fn two_sockets_in_one_group_are_one_membership_on_the_wire() {
        let _g = begin();
        let g = [239, 20, 0, 1];
        let (a, b) = (udp_sock(), udp_sock());
        assert_eq!(join(a, &g), Ok(()));
        assert_eq!(join(b, &g), Ok(()));
        assert_eq!(igmp_sent(V2_REPORT), vec![g], "the second subscriber reported again");

        assert_eq!(leave(a, &g), Ok(()));
        assert!(igmp::is_joined(&g), "one socket's leave dropped the group from under the other");
        assert!(igmp_sent(LEAVE_GROUP).is_empty(), "a Leave went out while a subscriber remained");

        assert_eq!(leave(b, &g), Ok(()));
        assert!(!igmp::is_joined(&g), "the last leave left the group joined");
        assert_eq!(igmp_sent(LEAVE_GROUP), vec![g], "the last leave must send exactly one Leave");
    }

    /// A socket holds at most `MAX_MCAST_PER_SOCKET` groups; a repeat join is
    /// neither another group nor another reference.
    #[test]
    fn a_socket_holds_at_most_its_bound_and_a_repeat_join_takes_nothing() {
        let _g = begin();
        let s = udp_sock();
        let groups: Vec<[u8; 4]> =
            (0..=MAX_MCAST_PER_SOCKET as u8).map(|i| [239, 21, 0, i]).collect();
        let extra = groups[MAX_MCAST_PER_SOCKET];
        for g in &groups[..MAX_MCAST_PER_SOCKET] {
            assert_eq!(join(s, g), Ok(()), "{g:?}");
        }
        assert_eq!(join(s, &extra), Err(McastError::SocketFull));
        assert!(!igmp::is_joined(&extra), "a refused join joined anyway");

        wire::reset();
        assert_eq!(join(s, &groups[0]), Ok(()), "a repeat join must succeed");
        assert!(igmp_sent(V2_REPORT).is_empty(), "a repeat join reported again");
        assert_eq!(leave(s, &groups[0]), Ok(()));
        assert!(!igmp::is_joined(&groups[0]), "the repeat join took a reference nothing gives back");

        assert_eq!(join(s, &extra), Ok(()), "the freed entry was not reusable");
    }

    /// Closing a socket gives back its own groups and nobody else's, and the
    /// recycled slot starts with none.
    #[test]
    fn closing_a_socket_gives_its_groups_back_and_only_its_own() {
        let _g = begin();
        let (shared, alone) = ([239, 22, 0, 1], [239, 22, 0, 2]);
        let (a, b) = (udp_sock(), udp_sock());
        assert_eq!(join(a, &shared), Ok(()));
        assert_eq!(join(a, &alone), Ok(()));
        assert_eq!(join(b, &shared), Ok(()));
        wire::reset();

        socket::socket_close(a);
        assert!(!igmp::is_joined(&alone), "a closed socket's group stayed joined");
        assert!(igmp::is_joined(&shared), "closing one subscriber dropped the other's group");
        assert_eq!(igmp_sent(LEAVE_GROUP), vec![alone]);

        let again = udp_sock();
        assert_eq!(again, a, "the allocator should hand back the same slot");
        socket::socket_close(again);
        assert!(igmp::is_joined(&shared), "a recycled slot gave a membership back twice");

        socket::socket_close(b);
        assert!(!igmp::is_joined(&shared));
    }

    /// The task-exit hook gives back the dead task's groups and no other
    /// task's.
    #[test]
    fn the_exit_hook_gives_back_the_dead_tasks_groups() {
        let _g = begin();
        let (mine, theirs) = ([239, 23, 0, 1], [239, 23, 0, 2]);
        let s = udp_sock();
        let other = socket::socket_create_owned(AF_INET, SOCK_DGRAM, 0, TASK + 1);
        assert!(other >= 0);
        assert_eq!(join(s, &mine), Ok(()));
        assert_eq!(join(other, &theirs), Ok(()));

        socket::socket_release_all(TASK);
        assert!(!igmp::is_joined(&mine), "a dead task's group stayed joined");
        assert!(igmp::is_joined(&theirs), "another task's group went with it");
    }

    /// A TCP socket, a free or out-of-range slot, and a group outside
    /// `224.0.0.0/4` or inside `224.0.0.0/24` are refused, and nothing reaches
    /// the wire.
    #[test]
    fn a_join_is_refused_for_a_tcp_socket_a_free_slot_and_an_unjoinable_group() {
        let _g = begin();
        let s = udp_sock();
        let t = socket::socket_create_owned(AF_INET, SOCK_STREAM, 0, TASK);
        assert!(t >= 0);
        let g = [239, 24, 0, 1];
        assert_eq!(join(t, &g), Err(McastError::NotUdp));
        assert_eq!(leave(t, &g), Err(McastError::NotUdp));
        assert_eq!(join(-1, &g), Err(McastError::BadSocket));
        assert_eq!(join(MAX_SOCKETS as i32, &g), Err(McastError::BadSocket));
        let free = (0..MAX_SOCKETS as i32)
            .find(|&fd| socket::socket_owner(fd).is_none())
            .expect("no free slot");
        assert_eq!(join(free, &g), Err(McastError::BadSocket));

        for bad in [
            [10, 0, 0, 1], [255, 255, 255, 255], [223, 255, 255, 255], [240, 0, 0, 0],
            [224, 0, 0, 0], [224, 0, 0, 1], [224, 0, 0, 251], [224, 0, 0, 255],
        ] {
            // On a free slot first: the group is judged before the slot, so a
            // group check that went missing answers `BadSocket` here. On the
            // live socket alone `igmp::acquire` would still refuse the
            // non-multicast half, and hide it.
            assert_eq!(join(free, &bad), Err(McastError::BadGroup), "{bad:?} on a free slot");
            assert_eq!(join(s, &bad), Err(McastError::BadGroup), "{bad:?}");
            assert!(!igmp::is_joined(&bad) || bad == igmp::ALL_HOSTS, "{bad:?} joined");
        }
        assert!(wire::sent().is_empty(), "a refused join put something on the wire");

        // The edges of what IS joinable.
        assert_eq!(join(s, &[224, 0, 1, 0]), Ok(()));
        assert_eq!(join(s, &[239, 255, 255, 255]), Ok(()));
    }

    /// A join refused by a full group table leaves no record behind, and a
    /// socket still shares a group the table already holds without taking the
    /// holder's reference with it on close.
    #[test]
    fn a_full_group_table_refuses_the_join_without_recording_it() {
        let _g = begin();
        for i in 0..igmp::MAX_GROUPS {
            assert_eq!(igmp::join(&[239, 25, 0, i as u8]), 0);
        }
        let s = udp_sock();
        let g = [239, 25, 1, 0];
        assert_eq!(join(s, &g), Err(McastError::TableFull));
        assert_eq!(leave(s, &g), Err(McastError::NotJoined), "a refused join left a record");

        let held = [239, 25, 0, 0];
        assert_eq!(join(s, &held), Ok(()));
        socket::socket_close(s);
        assert!(igmp::is_joined(&held), "the socket's close gave back the kernel's reference");
    }

    /// A socket gives back only what it took: another socket's membership, or
    /// its own twice, is not its to release.
    #[test]
    fn a_socket_cannot_leave_a_group_it_does_not_hold() {
        let _g = begin();
        let g = [239, 26, 0, 1];
        let (a, b) = (udp_sock(), udp_sock());
        assert_eq!(join(a, &g), Ok(()));
        assert_eq!(leave(b, &g), Err(McastError::NotJoined));
        assert!(igmp::is_joined(&g), "a leave by a socket that never joined dropped the group");
        assert_eq!(leave(a, &g), Ok(()));
        assert_eq!(leave(a, &g), Err(McastError::NotJoined), "a second leave was accepted");
    }

    /// Group traffic reaches the socket bound to its port while the group is
    /// joined, and not before the join or after the leave.
    #[test]
    fn group_traffic_reaches_the_bound_socket_only_while_the_group_is_joined() {
        let _g = begin();
        let g = [239, 27, 0, 1];
        const PORT: u16 = 7720;
        let s = udp_sock();
        bind(s, PORT);
        let d = group_datagram(g, PORT, b"group");
        let mut buf = [0u8; 32];

        ip::handle(&d, &OUR_MAC, &OUR_IP);
        assert_eq!(socket::socket_recv(s, &mut buf), 0, "traffic for an unjoined group was delivered");

        assert_eq!(join(s, &g), Ok(()));
        ip::handle(&d, &OUR_MAC, &OUR_IP);
        let n = socket::socket_recv(s, &mut buf);
        assert_eq!(&buf[..n.max(0) as usize], b"group", "a joined group's datagram was not delivered");

        assert_eq!(leave(s, &g), Ok(()));
        ip::handle(&d, &OUR_MAC, &OUR_IP);
        assert_eq!(socket::socket_recv(s, &mut buf), 0, "traffic was still delivered after the leave");
    }

    /// A datagram a local socket sends to a joined group reaches the local
    /// member, and the wire copy for remote members still goes out.
    #[test]
    fn a_datagram_sent_to_a_joined_group_loops_back_to_the_local_member() {
        let _g = begin();
        let g = [239, 28, 0, 1];
        const PORT: u16 = 7721;
        let (rx, tx) = (udp_sock(), udp_sock());
        bind(rx, PORT);
        bind(tx, 7722);
        assert_eq!(join(rx, &g), Ok(()));
        wire::reset();

        let dst = SockAddr { family: AF_INET as u16, port: PORT, addr: g };
        assert_eq!(socket::socket_sendto(tx, b"loop", &dst), 4);
        let mut buf = [0u8; 16];
        let n = socket::socket_recv(rx, &mut buf);
        assert_eq!(&buf[..n.max(0) as usize], b"loop", "a local member missed a local sender's datagram");
        assert!(
            wire::sent().iter().any(|s| s.dst_ip == g && s.proto == ip::IP_PROTO_UDP),
            "the wire copy for remote members did not go out",
        );
    }

    /// Security audit unit 6, finding F4. `igmp`'s table is machine-wide
    /// (`igmp::MAX_GROUPS`) and [`MAX_MCAST_PER_SOCKET`] only bounds one
    /// socket, so a task with several sockets could otherwise fill the whole
    /// table by itself. A task holds at most [`MAX_MCAST_GROUPS_PER_TASK`]
    /// groups across ALL of its sockets, and a repeat join of a group the
    /// task already holds is still idempotent at the bound.
    #[test]
    fn a_task_holds_at_most_its_bound_across_sockets_and_a_repeat_join_takes_nothing() {
        let _g = begin();
        let (a1, a2) = (udp_sock(), udp_sock());
        let half = MAX_MCAST_GROUPS_PER_TASK / 2;
        let groups: Vec<[u8; 4]> =
            (0..=MAX_MCAST_GROUPS_PER_TASK as u8).map(|i| [239, 29, 0, i]).collect();
        for g in &groups[..half] {
            assert_eq!(join(a1, g), Ok(()), "{g:?} on a1");
        }
        for g in &groups[half..MAX_MCAST_GROUPS_PER_TASK] {
            assert_eq!(join(a2, g), Ok(()), "{g:?} on a2");
        }
        let extra = groups[MAX_MCAST_GROUPS_PER_TASK];
        assert_eq!(join(a1, &extra), Err(McastError::SocketFull), "task bound not enforced on a1");
        assert_eq!(join(a2, &extra), Err(McastError::SocketFull), "task bound not enforced on a2");
        assert!(!igmp::is_joined(&extra), "a refused join joined anyway");

        // A repeat join of a group the task already holds — via whichever of
        // its sockets — stays Ok even sitting exactly at the task's bound.
        wire::reset();
        assert_eq!(join(a1, &groups[0]), Ok(()), "a repeat join must succeed at the task's bound");
        assert!(igmp_sent(V2_REPORT).is_empty(), "a repeat join reported again");
    }

    /// The quota is per task, not machine-wide: one task sitting at its bound
    /// must not block a different task's join.
    #[test]
    fn another_tasks_join_succeeds_while_the_first_is_at_its_bound() {
        let _g = begin();
        let a = udp_sock();
        for i in 0..MAX_MCAST_GROUPS_PER_TASK as u8 {
            assert_eq!(join(a, &[239, 29, 1, i]), Ok(()));
        }
        assert_eq!(
            join(a, &[239, 29, 1, MAX_MCAST_GROUPS_PER_TASK as u8]),
            Err(McastError::SocketFull),
        );

        let b = udp_sock_owned(OTHER_TASK);
        assert_eq!(join(b, &[239, 29, 2, 0]), Ok(()), "another task's join was blocked by A's quota");
    }

    /// Closing a socket gives its groups back to `igmp` (already covered by
    /// `closing_a_socket_gives_its_groups_back_and_only_its_own`) AND frees
    /// the room it held against its owner's task quota.
    #[test]
    fn closing_a_socket_frees_its_owners_task_quota() {
        let _g = begin();
        let (a1, a2) = (udp_sock(), udp_sock());
        for i in 0..MAX_MCAST_GROUPS_PER_TASK as u8 {
            assert_eq!(join(a1, &[239, 29, 3, i]), Ok(()));
        }
        let extra = [239, 29, 3, MAX_MCAST_GROUPS_PER_TASK as u8];
        assert_eq!(
            join(a2, &extra), Err(McastError::SocketFull),
            "the task's bound must refuse a join on ANY of its sockets, not just the full one",
        );

        socket::socket_close(a1);
        assert_eq!(join(a2, &extra), Ok(()), "closing a socket must free its owner's task quota");
    }

    /// [`MAX_MCAST_PER_SOCKET`] still bounds a single socket even though the
    /// new task-wide check is in place: a1 alone cannot hold more than four
    /// groups. With a1 at its own bound the task's total (a1's four, a2's
    /// none) also happens to sit at [`MAX_MCAST_GROUPS_PER_TASK`], so a2's
    /// join is refused too — by the task check this time, since a2's own
    /// array still has room.
    #[test]
    fn the_per_socket_bound_still_applies_inside_the_task_bound() {
        let _g = begin();
        let (a1, a2) = (udp_sock(), udp_sock());
        for i in 0..MAX_MCAST_PER_SOCKET as u8 {
            assert_eq!(join(a1, &[239, 29, 4, i]), Ok(()));
        }
        let extra = [239, 29, 4, MAX_MCAST_PER_SOCKET as u8];
        assert_eq!(join(a1, &extra), Err(McastError::SocketFull), "a1's own bound was not enforced");
        assert_eq!(
            join(a2, &extra), Err(McastError::SocketFull),
            "a1 alone used up the task's whole quota, but a2's join was not refused",
        );
        assert!(!igmp::is_joined(&extra), "a refused join joined anyway");
    }
}

/// IPv6: address formation, the receive filter, and ICMPv6.
#[cfg(test)]
mod ipv6_input {
    use super::NET_SERIAL as SERIAL;
    use super::{ipv6, raw, udp};

    const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(100_000);
        ipv6::ipv6_init(&OUR_MAC);
        raw::reset();
        g
    }

    /// Wrap an upper-layer payload in an IPv6 header, as `ipv6_rx` expects it
    /// (the Ethernet header is already stripped by the caller).
    fn datagram(
        next_hdr: u8, src: [u8; 16], dst: [u8; 16],
        payload: &[u8], payload_len: Option<u16>,
    ) -> Vec<u8> {
        let mut f = vec![0u8; 40];
        f[0] = 0x60; // version 6
        f[4..6].copy_from_slice(&payload_len.unwrap_or(payload.len() as u16).to_be_bytes());
        f[6] = next_hdr;
        f[7] = 64; // hop limit
        f[8..24].copy_from_slice(&src);
        f[24..40].copy_from_slice(&dst);
        f.extend_from_slice(payload);
        f
    }

    /// An ICMPv6 echo request with a correct checksum for the given endpoints.
    fn echo(kind: u8, src: [u8; 16], dst: [u8; 16], body: &[u8]) -> Vec<u8> {
        let mut m = vec![kind, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        m.extend_from_slice(body);
        let ck = ipv6::pseudo_checksum(&src, &dst, ipv6::NEXTHDR_ICMPV6, &m);
        m[2] = (ck >> 8) as u8;
        m[3] = ck as u8;
        m
    }

    /// RFC 4291 §2.5.6: insert `FF:FE` in the middle of the MAC, flip the
    /// Universal/Local bit, prepend `FE80::/64`.
    #[test]
    fn the_link_local_address_is_the_eui_64_of_the_mac() {
        let a = ipv6::eui64_link_local(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(&a[0..2], &[0xFE, 0x80], "the FE80::/64 prefix");
        assert_eq!(&a[2..8], &[0; 6], "bytes 2..8 of a link-local address are zero");
        assert_eq!(
            a[8], 0x50,
            "0x52 with the U/L bit flipped is 0x50 — the MAC is administered \
             locally, so the interface id must say so",
        );
        assert_eq!(&a[11..13], &[0xFF, 0xFE], "FF:FE goes in the middle");
        assert_eq!(&a[13..16], &[0x12, 0x34, 0x56], "the low three MAC bytes");

        // The flip is its own inverse, and it is bit 1 of the first octet.
        let b = ipv6::eui64_link_local(&[0x50, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(b[8], 0x52, "a globally-unique MAC flips the other way");
    }

    /// RFC 4291 §2.7.1: `FF02::1:FFXX:XXXX` from the LOW 24 BITS of the
    /// address. Neighbour Solicitations arrive on this group rather than
    /// all-nodes, so an interface that does not accept it cannot be resolved.
    #[test]
    fn the_solicited_node_group_uses_the_low_24_bits() {
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let g = ipv6::solicited_node(&ll);
        assert_eq!(&g[0..2], &[0xFF, 0x02]);
        assert_eq!(&g[2..11], &[0; 9]);
        assert_eq!(g[11], 0x01);
        assert_eq!(g[12], 0xFF);
        assert_eq!(&g[13..16], &ll[13..16], "the low 24 bits are carried across");
        assert!(ipv6::is_multicast(&g));

        // Two addresses differing only above the low 24 bits share the group —
        // the aliasing is in the standard, and is why the group is a hint and
        // not an identity.
        let mut other = ll;
        other[8] ^= 0xFF;
        assert_eq!(
            ipv6::solicited_node(&other), g,
            "only the low 24 bits select the group",
        );
    }

    /// `is_multicast` answers a question about FORMAT; `is_joined_group`
    /// answers one about MEMBERSHIP. Using the first as a receive filter is
    /// the bug the module documents: accepting `addr[0] == 0xFF` admits every
    /// group that exists, so any remote host can pick an arbitrary destination
    /// and still have its datagram dispatched to an upper layer.
    #[test]
    fn membership_is_not_the_same_question_as_multicast_format() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);

        assert!(ipv6::is_joined_group(&ipv6::MCAST_ALL_NODES), "FF02::1 is joined");
        assert!(ipv6::is_joined_group(&ipv6::solicited_node(&ll)), "our own group is");

        // Every one of these IS multicast, and NONE of them is joined.
        let strangers = [
            ipv6::MCAST_ALL_ROUTERS,
            [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09],
            [0xFF, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
            [0xFF; 16],
        ];
        for s in strangers {
            assert!(ipv6::is_multicast(&s), "{s:?} is multicast in format");
            assert!(
                !ipv6::is_joined_group(&s),
                "...but {s:?} is a group we never joined, and format is not membership",
            );
        }
    }

    /// A UDP datagram over IPv6, checksummed for the given endpoints.
    fn udp6(src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16,
            payload: &[u8], zero_checksum: bool) -> Vec<u8> {
        let mut d = Vec::with_capacity(8 + payload.len());
        d.extend_from_slice(&src_port.to_be_bytes());
        d.extend_from_slice(&dst_port.to_be_bytes());
        d.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        d.extend_from_slice(&[0, 0]);
        d.extend_from_slice(payload);
        if !zero_checksum {
            let ck = ipv6::pseudo_checksum(&src, &dst, ipv6::NEXTHDR_UDP, &d);
            d[6] = (ck >> 8) as u8;
            d[7] = ck as u8;
        }
        d
    }

    /// The receive filter admits our unicast address and our two groups, and
    /// nothing else.
    ///
    /// **Observed through UDP, not through an ICMP reply.** The first version
    /// of this test asked whether an echo reply came back — and restoring the
    /// old `|| is_multicast(dst)` filter changed nothing, because
    /// `icmpv6_rx` has its OWN `is_our_addr(dst) || is_all_nodes(dst)` check
    /// that stopped the reply anyway. The test was measuring ICMPv6's guard,
    /// not IPv6's. The module comment names the real consequence — traffic
    /// reaching "the UDP dispatcher below" — so a bound UDP socket is the
    /// observable that only the destination filter gates.
    #[test]
    fn the_receive_filter_admits_only_our_address_and_our_groups() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        for i in 0..udp::UDP_MAX_SOCKETS {
            udp::unbind(i);
        }
        let sock = udp::bind(6100) as usize;

        // Admitted: our own unicast address.
        let d = datagram(ipv6::NEXTHDR_UDP, peer, ll,
                         &udp6(peer, ll, 45100, 6100, b"mine", false), None);
        ipv6::ipv6_rx(&d, d.len());
        let mut buf = [0u8; 32];
        assert_eq!(udp::recv(sock, &mut buf), 4, "a datagram for us must arrive");

        // Refused: multicast groups we never joined, and a stranger's unicast.
        for dst in [
            ipv6::MCAST_ALL_ROUTERS,
            [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09],
            [0xFF; 16],
            [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77],
        ] {
            let d = datagram(ipv6::NEXTHDR_UDP, peer, dst,
                             &udp6(peer, dst, 45100, 6100, b"theirs", false), None);
            ipv6::ipv6_rx(&d, d.len());
            assert!(
                udp::recv(sock, &mut buf) <= 0,
                "a datagram for {dst:?} is not ours; it must never reach the socket \
                 table, which is where a forged source got in when this filter \
                 accepted any multicast address",
            );
        }
    }

    /// **RFC 8200 §8.1 inverts the IPv4 rule.** Over IPv6 the UDP checksum is
    /// MANDATORY, so a zero field is not "the sender opted out" — it is
    /// malformed and must be dropped. The IPv4 suite asserts the opposite for
    /// the same field, and both have to hold at once.
    #[test]
    fn over_ipv6_a_zero_udp_checksum_is_malformed_not_optional() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        for i in 0..udp::UDP_MAX_SOCKETS {
            udp::unbind(i);
        }
        let sock = udp::bind(6101) as usize;

        let d = datagram(ipv6::NEXTHDR_UDP, peer, ll,
                         &udp6(peer, ll, 45101, 6101, b"nocsum", true), None);
        ipv6::ipv6_rx(&d, d.len());
        let mut buf = [0u8; 32];
        assert!(
            udp::recv(sock, &mut buf) <= 0,
            "RFC 8200 makes the checksum mandatory over IPv6 — a zero field is \
             malformed, not an opt-out",
        );

        // And a present-but-wrong checksum is dropped too.
        let mut bad = udp6(peer, ll, 45101, 6101, b"corrupt", false);
        bad[6] ^= 0xFF;
        if bad[6..8] == [0, 0] { bad[6] ^= 0x01; }
        let d = datagram(ipv6::NEXTHDR_UDP, peer, ll, &bad, None);
        ipv6::ipv6_rx(&d, d.len());
        assert!(udp::recv(sock, &mut buf) <= 0, "a wrong checksum must be dropped");

        // The correct one still arrives, so this is not a test that drops all.
        let d = datagram(ipv6::NEXTHDR_UDP, peer, ll,
                         &udp6(peer, ll, 45101, 6101, b"good", false), None);
        ipv6::ipv6_rx(&d, d.len());
        assert_eq!(udp::recv(sock, &mut buf), 4);
    }

    /// The explicit zero-checksum rejection is NOT redundant with the
    /// verification that follows it.
    ///
    /// A zero checksum field normally fails the next check too, which is why
    /// the obvious canary — deleting the explicit test — changes nothing for
    /// an ordinary payload. But the verification asks "does this segment sum
    /// to 0xFFFF", and an attacker chooses the payload: a segment can be
    /// crafted whose sum folds correctly WITH the checksum field left at zero,
    /// and then only the explicit check stands between it and the socket
    /// table. This test searches for exactly such a payload and asserts it is
    /// still refused.
    #[test]
    fn a_crafted_zero_checksum_that_would_verify_is_still_refused() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        for i in 0..udp::UDP_MAX_SOCKETS {
            udp::unbind(i);
        }
        let sock = udp::bind(6102) as usize;

        // Find a two-byte tail that makes the segment verify while its
        // checksum field stays zero.
        let mut crafted = None;
        for probe in 0u32..=0xFFFF {
            let body = [b'A', b'B', (probe >> 8) as u8, probe as u8];
            let d = udp6(peer, ll, 45102, 6102, &body, true);
            if ipv6::pseudo_checksum(&peer, &ll, ipv6::NEXTHDR_UDP, &d) == 0 {
                crafted = Some(d);
                break;
            }
        }
        let crafted = crafted.expect(
            "a segment that verifies with a zero checksum field must exist — \
             if it does not, this test can no longer prove the point",
        );
        assert_eq!(&crafted[6..8], &[0, 0], "the checksum field is genuinely zero");
        assert_eq!(
            ipv6::pseudo_checksum(&peer, &ll, ipv6::NEXTHDR_UDP, &crafted), 0,
            "...and the segment would pass verification on that basis alone",
        );

        let d = datagram(ipv6::NEXTHDR_UDP, peer, ll, &crafted, None);
        ipv6::ipv6_rx(&d, d.len());
        let mut buf = [0u8; 32];
        assert!(
            udp::recv(sock, &mut buf) <= 0,
            "RFC 8200 makes the checksum mandatory: a zero field is malformed \
             however well the rest of the segment sums",
        );
    }

    /// Version and length bounds. A payload length claiming more than arrived
    /// must be refused rather than believed — the slice below it is built from
    /// that number.
    #[test]
    fn malformed_headers_are_dropped() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
        let body = echo(ipv6::ICMPV6_ECHO_REQ, peer, ll, b"ping");

        // Not IPv6.
        let mut d = datagram(ipv6::NEXTHDR_ICMPV6, peer, ll, &body, None);
        d[0] = 0x40;
        ipv6::ipv6_rx(&d, d.len());
        assert_eq!(raw::count(), 0, "version 4 in an IPv6 frame is malformed");

        // A payload length beyond the bytes received.
        let d = datagram(ipv6::NEXTHDR_ICMPV6, peer, ll, &body, Some(9000));
        ipv6::ipv6_rx(&d, d.len());
        assert_eq!(raw::count(), 0, "a length claiming more than arrived must be refused");

        // Shorter than the fixed 40-byte header.
        let d = datagram(ipv6::NEXTHDR_ICMPV6, peer, ll, &body, None);
        for n in 0..40usize {
            ipv6::ipv6_rx(&d, n);
        }
        assert_eq!(raw::count(), 0);
    }

    /// The echo reply carries the request's identifier and sequence, type 129,
    /// and a checksum of its own that verifies.
    #[test]
    fn an_echo_reply_is_well_formed_and_checksummed() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        let req = echo(ipv6::ICMPV6_ECHO_REQ, peer, ll, b"abcdefgh");
        let d = datagram(ipv6::NEXTHDR_ICMPV6, peer, ll, &req, None);
        ipv6::ipv6_rx(&d, d.len());

        let frames = raw::all();
        assert_eq!(frames.len(), 1, "the request must be answered");
        let f = &frames[0];
        assert_eq!(u16::from_be_bytes([f[12], f[13]]), ipv6::ETH_TYPE_IPV6);
        let icmp = &f[14 + 40..];
        assert_eq!(icmp[0], ipv6::ICMPV6_ECHO_REPLY, "type 129");
        assert_eq!(&icmp[4..8], &req[4..8], "identifier and sequence are echoed");
        assert_eq!(&icmp[8..], b"abcdefgh", "and so is the body");
        assert_eq!(
            ipv6::pseudo_checksum(&ll, &peer, ipv6::NEXTHDR_ICMPV6, icmp), 0,
            "a reply must carry a checksum that verifies",
        );
    }

    /// A Neighbour Solicitation is answered only when it asks about an address
    /// we actually hold. Advertising someone else's address is how a node
    /// hijacks traffic on an IPv6 link.
    #[test]
    fn a_neighbour_solicitation_is_answered_only_for_our_own_address() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        // Target: someone else's address. Both solicitations carry the source
        // link-layer option, so the target is the only thing that differs.
        let other = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];
        let ns = solicitation(peer, ll, other, &slla(PEER_MAC));
        assert!(ipv6::icmpv6_rx(&peer, &ll, &ns) == false, "not our address");
        assert_eq!(raw::count(), 0, "and must draw no advertisement");

        // Target: ours.
        let ns = solicitation(peer, ll, ll, &slla(PEER_MAC));
        assert!(ipv6::icmpv6_rx(&peer, &ll, &ns), "our address must be advertised");
        assert_eq!(raw::count(), 1);
    }

    /// The peer's MAC as its solicitations name it.
    const PEER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xAB, 0xCD, 0xEF];

    /// A Source Link-Layer Address option naming `mac`.
    fn slla(mac: [u8; 6]) -> Vec<u8> {
        let mut o = vec![ipv6::ND_OPT_SOURCE_LLA, 1];
        o.extend_from_slice(&mac);
        o
    }

    /// A signed Neighbour Solicitation for `target` followed by `options`.
    fn solicitation(src: [u8; 16], dst: [u8; 16], target: [u8; 16], options: &[u8]) -> Vec<u8> {
        let mut ns = vec![ipv6::ICMPV6_NS, 0, 0, 0, 0, 0, 0, 0];
        ns.extend_from_slice(&target);
        ns.extend_from_slice(options);
        sign(src, dst, &mut ns);
        ns
    }

    /// **The advertisement goes to the solicitor's MAC, not to the whole
    /// link.** It used to leave through `send_ipv6`, which sends a unicast
    /// IPv6 destination to ff:ff:ff:ff:ff:ff. It now names the MAC from the
    /// solicitation's option, carries our own MAC in a Target Link-Layer
    /// Address option, and has hop limit 255 (RFC 4861 §7.1.2 — a receiver
    /// drops any other value).
    ///
    /// Solicited at the solicited-node group, as an unresolved neighbour is.
    #[test]
    fn a_neighbour_advertisement_goes_to_the_solicitors_link_layer_address() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let group = ipv6::solicited_node(&ll);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        let ns = solicitation(peer, group, ll, &slla(PEER_MAC));
        let d = datagram(ipv6::NEXTHDR_ICMPV6, peer, group, &ns, None);
        ipv6::ipv6_rx(&d, d.len());

        let frames = raw::all();
        assert_eq!(frames.len(), 1, "the solicitation must be answered");
        let f = &frames[0];
        assert_eq!(&f[0..6], &PEER_MAC, "Ethernet destination is the solicitor's MAC");
        assert_eq!(&f[6..12], &super::net_get_mac(), "Ethernet source is ours");
        assert_eq!(u16::from_be_bytes([f[12], f[13]]), ipv6::ETH_TYPE_IPV6);

        let ip = &f[14..14 + 40];
        assert_eq!(ip[7], 255, "ND hop limit");
        assert_eq!(&ip[8..24], &ll, "IPv6 source is our link-local");
        assert_eq!(&ip[24..40], &peer, "IPv6 destination is the solicitor");
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 32, "payload length: 24 + one option");

        let na = &f[14 + 40..];
        assert_eq!(na.len(), 32, "the frame is exactly the advertisement");
        assert_eq!(na[0], ipv6::ICMPV6_NA);
        assert_eq!(
            u32::from_be_bytes([na[4], na[5], na[6], na[7]]),
            ipv6::NA_FLAG_SOLICITED | ipv6::NA_FLAG_OVERRIDE,
        );
        assert_eq!(&na[8..24], &ll, "target is our address");
        assert_eq!(na[24], ipv6::ND_OPT_TARGET_LLA, "Target Link-Layer Address option");
        assert_eq!(na[25], 1, "one 8-octet unit");
        assert_eq!(&na[26..32], &super::net_get_mac(), "naming our MAC");
        assert_eq!(
            ipv6::pseudo_checksum(&ll, &peer, ipv6::NEXTHDR_ICMPV6, na), 0,
            "the checksum covers the option",
        );
    }

    /// **No Source Link-Layer Address option, no advertisement.** There is no
    /// MAC to answer, and the fallback was the Ethernet broadcast.
    #[test]
    fn a_solicitation_without_a_source_link_layer_address_draws_no_advertisement() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        let ns = solicitation(peer, ll, ll, &[]);
        assert!(!ipv6::icmpv6_rx(&peer, &ll, &ns));
        // An option of another kind is not the one needed.
        let mut other = slla(PEER_MAC);
        other[0] = ipv6::ND_OPT_TARGET_LLA;
        let ns = solicitation(peer, ll, ll, &other);
        assert!(!ipv6::icmpv6_rx(&peer, &ll, &ns));
        assert_eq!(raw::count(), 0, "zero frames");
    }

    /// A group MAC in the option would make the unicast reply a broadcast or
    /// multicast one again.
    #[test]
    fn a_group_address_in_the_source_option_draws_no_advertisement() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
        for mac in [
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01],
            [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01],
            [0x00; 6],
        ] {
            let ns = solicitation(peer, ll, ll, &slla(mac));
            assert!(!ipv6::icmpv6_rx(&peer, &ll, &ns), "{mac:02x?}");
        }
        assert_eq!(raw::count(), 0);
    }

    /// Malformed options discard the solicitation (RFC 4861 §4.6): a length
    /// of zero — before or after a good option — and an option that runs past
    /// the end of the message.
    #[test]
    fn a_malformed_option_discards_the_solicitation() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        let zero_len = [14u8, 0, 0, 0, 0, 0, 0, 0];
        let mut before = zero_len.to_vec();
        before.extend_from_slice(&slla(PEER_MAC));
        let mut after = slla(PEER_MAC);
        after.extend_from_slice(&zero_len);
        // Claims two 8-octet units, carries one.
        let mut overrun = slla(PEER_MAC);
        overrun[1] = 2;
        // A trailing lone byte cannot hold an option header.
        let mut stub = slla(PEER_MAC);
        stub.push(1);

        for (name, opts) in [("zero before", before), ("zero after", after),
                             ("overrun", overrun), ("stub", stub)] {
            let ns = solicitation(peer, ll, ll, &opts);
            assert!(!ipv6::icmpv6_rx(&peer, &ll, &ns), "{name}");
        }
        assert_eq!(raw::count(), 0);

        // The positive control: the same option alone is answered.
        let ns = solicitation(peer, ll, ll, &slla(PEER_MAC));
        assert!(ipv6::icmpv6_rx(&peer, &ll, &ns));
        assert_eq!(raw::count(), 1);
    }

    /// Fill an ICMPv6 message's checksum (bytes 2-3) over the pseudo-header.
    /// The solicitations above used to go out with a zero checksum and be
    /// answered — which is the defect, not a fixture convenience.
    fn sign(src: [u8; 16], dst: [u8; 16], msg: &mut [u8]) {
        msg[2] = 0;
        msg[3] = 0;
        let ck = ipv6::pseudo_checksum(&src, &dst, ipv6::NEXTHDR_ICMPV6, msg);
        msg[2] = (ck >> 8) as u8;
        msg[3] = ck as u8;
    }

    /// **An echo to all-nodes is not answered.** A spoofed source plus
    /// `ff02::1` made every IPv6 host on the link answer the victim — and this
    /// robot's reply left as an Ethernet broadcast on top. IPv4 refuses the
    /// broadcast twin of this on purpose; the IPv6 path did not.
    #[test]
    fn an_echo_to_all_nodes_is_not_reflected() {
        let _g = begin();
        let victim = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
        let mut req = vec![ipv6::ICMPV6_ECHO_REQ, 0, 0, 0, 0x12, 0x34, 0, 1];
        req.extend_from_slice(&[0xAB; 64]);
        sign(victim, ipv6::MCAST_ALL_NODES, &mut req);
        let d = datagram(ipv6::NEXTHDR_ICMPV6, victim, ipv6::MCAST_ALL_NODES, &req, None);
        ipv6::ipv6_rx(&d, d.len());
        assert_eq!(raw::count(), 0, "a multicast echo must draw no reply");
    }

    /// **A message whose checksum does not verify is dropped, whatever its
    /// type.** RFC 4443 makes the checksum mandatory. The positive control is
    /// the echo test above: the same request, correctly signed, IS answered.
    #[test]
    fn an_icmpv6_message_with_a_bad_checksum_is_dropped() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];

        let mut req = vec![ipv6::ICMPV6_ECHO_REQ, 0, 0, 0, 0x12, 0x34, 0, 1];
        req.extend_from_slice(b"abcdefgh");
        sign(peer, ll, &mut req);
        req[3] ^= 0x01;
        assert!(!ipv6::icmpv6_rx(&peer, &ll, &req), "a corrupt echo is not answered");

        // With the source link-layer option, so the checksum is the only
        // reason this solicitation is not answered.
        let mut ns = solicitation(peer, ll, ll, &slla(PEER_MAC));
        ns[2] ^= 0x80;
        assert!(!ipv6::icmpv6_rx(&peer, &ll, &ns), "nor a corrupt solicitation");
        assert_eq!(raw::count(), 0);
    }

    /// A truncated ICMPv6 message has no type to dispatch on.
    #[test]
    fn a_truncated_icmpv6_message_is_dropped() {
        let _g = begin();
        let ll = ipv6::eui64_link_local(&OUR_MAC);
        let peer = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99];
        let full = echo(ipv6::ICMPV6_ECHO_REQ, peer, ll, b"body");
        for n in 0..4usize {
            assert!(!ipv6::icmpv6_rx(&peer, &ll, &full[..n]));
        }
        // A Neighbour Solicitation shorter than its fixed 24 bytes has no
        // target field to compare.
        let mut ns = vec![ipv6::ICMPV6_NS, 0, 0, 0, 0, 0, 0, 0];
        ns.extend_from_slice(&ll);
        for n in 4..24usize {
            assert!(!ipv6::icmpv6_rx(&peer, &ll, &ns[..n]), "truncated NS at {n}");
        }
        assert_eq!(raw::count(), 0);
    }
}

/// The DNS resolver's off-path forgery defences (`crates/net/net/src/dns.rs`).
///
/// A DNS answer is an unauthenticated UDP datagram, so anyone who can guess or
/// observe the query can try to answer it first and point the robot's next
/// connection wherever they like. `handle_response` accepts a datagram only if
/// ALL of a query being outstanding, the source endpoint, the transaction id,
/// the QR bit, QDCOUNT, and a byte-identical echoed question hold at once.
/// Each of those is a separate test here.
///
/// The whole resolve path runs: `resolve` transmits through the real UDP and
/// IP layers onto the recording wire, and the answer comes back in through
/// `net_poll` -> `ethernet::parse` -> `ip::handle` -> `udp` -> `dns`.
#[cfg(test)]
mod dns_resolver {
    use super::NET_SERIAL as SERIAL;
    use super::{arp, dns, inbound, ip, raw, tcp, wire};

    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const SERVER_IP: [u8; 4] = [10, 0, 0, 53];
    const SERVER_MAC: [u8; 6] = [0x02, 0x53, 0x53, 0x53, 0x53, 0x53];
    const ATTACKER_IP: [u8; 4] = [10, 0, 0, 66];

    const PROTO_UDP: u8 = 17;
    const DNS_SERVER_PORT: u16 = 53;
    /// mDNS's port (RFC 6762), which every query used to leave from.
    const MDNS_PORT: u16 = 5353;
    /// The NTP client port `udp::dispatch` intercepts; no query may use it.
    const NTP_CLIENT_PORT: u16 = 1123;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        inbound::reset();
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(200_000);
        arp::insert(SERVER_IP, SERVER_MAC);
        arp::insert(ATTACKER_IP, SERVER_MAC);
        dns::set_dns_server(SERVER_IP);
        let _ = tcp::conn_state(0); // keep `tcp` linked for the shared lock
        g
    }

    /// The query the resolver just put on the wire: (tx_id, question bytes,
    /// the UDP source port it left from).
    fn sent_query() -> Option<(u16, Vec<u8>, u16)> {
        wire::sent().iter().find_map(|s| {
            if s.proto != PROTO_UDP || s.payload.len() < 8 + 12 { return None; }
            let dst_port = u16::from_be_bytes([s.payload[2], s.payload[3]]);
            if dst_port != DNS_SERVER_PORT { return None; }
            let src_port = u16::from_be_bytes([s.payload[0], s.payload[1]]);
            let dns = &s.payload[8..];
            Some((u16::from_be_bytes([dns[0], dns[1]]), dns[12..].to_vec(), src_port))
        })
    }

    /// UDP source port of every query on the wire, oldest first.
    fn query_source_ports() -> Vec<u16> {
        wire::sent()
            .iter()
            .filter(|s| s.proto == PROTO_UDP && s.payload.len() >= 8 + 12)
            .filter(|s| u16::from_be_bytes([s.payload[2], s.payload[3]]) == DNS_SERVER_PORT)
            .map(|s| u16::from_be_bytes([s.payload[0], s.payload[1]]))
            .collect()
    }

    /// Build a DNS answer datagram to `dst_port` and queue it for the next
    /// `net_poll`.
    #[allow(clippy::too_many_arguments)]
    fn queue_answer(
        src_ip: [u8; 4], src_port: u16, dst_port: u16, tx_id: u16, flags: u16,
        qdcount: u16, question: &[u8], answer_ip: [u8; 4],
    ) {
        let mut d = Vec::new();
        d.extend_from_slice(&tx_id.to_be_bytes());
        d.extend_from_slice(&flags.to_be_bytes());
        d.extend_from_slice(&qdcount.to_be_bytes());
        d.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        d.extend_from_slice(&[0, 0, 0, 0]);       // NSCOUNT, ARCOUNT
        d.extend_from_slice(question);
        // One A record, using a compression pointer to the question name.
        d.extend_from_slice(&[0xC0, 0x0C]);
        d.extend_from_slice(&1u16.to_be_bytes());   // TYPE A
        d.extend_from_slice(&1u16.to_be_bytes());   // CLASS IN
        d.extend_from_slice(&60u32.to_be_bytes());  // TTL
        d.extend_from_slice(&4u16.to_be_bytes());   // RDLENGTH
        d.extend_from_slice(&answer_ip);

        // UDP, then IPv4.
        let mut u = Vec::new();
        u.extend_from_slice(&src_port.to_be_bytes());
        u.extend_from_slice(&dst_port.to_be_bytes());
        u.extend_from_slice(&((8 + d.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]); // checksum: RFC 768 allows none on IPv4
        u.extend_from_slice(&d);

        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + u.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&src_ip);
        p[16..20].copy_from_slice(&OUR_IP);
        let ck = ip::checksum(&p[..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(&u);
        inbound::push_ipv4(&p);
    }

    /// Which of our ports a planned answer is addressed to.
    #[derive(Clone, Copy)]
    enum DstPort {
        /// The port the query left from — where a genuine answer goes.
        Query,
        /// A fixed port, whatever the query drew.
        Fixed(u16),
        /// One above the query's port: wrong by exactly one, whatever was drawn.
        NextToQuery,
    }

    /// How the far end should answer the query it is about to see.
    ///
    /// Data rather than a closure so it can live in a static: `net_poll` calls
    /// a plain `fn` that reads this and builds the datagram.
    #[derive(Clone, Copy)]
    struct AnswerPlan {
        src_ip: [u8; 4],
        src_port: u16,
        dst_port: DstPort,
        /// `None` echoes the real transaction id; `Some` forges one.
        tx_id: Option<u16>,
        /// Echo the real transaction id with every bit inverted: wrong by
        /// construction, whichever id was drawn. Ignored when `tx_id` is set.
        flip_id: bool,
        flags: u16,
        qdcount: u16,
        /// Flip a byte of the echoed question, as a forger who guessed the
        /// name wrongly would.
        corrupt_question: bool,
        answer_ip: [u8; 4],
    }

    /// Answers the far end will send, one per `net_poll`, in order.
    static PLAN: std::sync::Mutex<Vec<AnswerPlan>> = std::sync::Mutex::new(Vec::new());

    fn plan(ps: &[AnswerPlan]) {
        *PLAN.lock().unwrap() = ps.iter().rev().copied().collect();
        inbound::on_poll(answer_from_plan);
    }

    /// The far end: read the query off the wire and send every planned answer
    /// in one round, so they all reach `handle_response` before `resolve`
    /// looks at the result. That is the race the latch exists for.
    fn answer_from_plan() {
        let (id, question, query_port) = match sent_query() {
            Some(v) => v,
            None => return, // nothing asked yet
        };
        // Every planned answer goes out in ONE round, so they all reach
        // `handle_response` inside a single `net_poll` drain. Delivering them
        // in separate rounds cannot exercise the latch at all: `resolve`
        // breaks out of its poll loop the moment the first answer lands, and
        // the second is never delivered — which is exactly why the first
        // version of the race test could not fail.
        let plans: Vec<AnswerPlan> = {
            let mut g = PLAN.lock().unwrap();
            let mut v: Vec<AnswerPlan> = g.drain(..).collect();
            v.reverse();
            v
        };
        for p in plans {
            let mut q = question.clone();
            if p.corrupt_question && !q.is_empty() {
                q[0] ^= 0xFF;
            }
            let dst_port = match p.dst_port {
                DstPort::Query => query_port,
                DstPort::Fixed(port) => port,
                DstPort::NextToQuery => query_port.wrapping_add(1),
            };
            let tx_id = p.tx_id.unwrap_or(if p.flip_id { !id } else { id });
            queue_answer(
                p.src_ip, p.src_port, dst_port, tx_id,
                p.flags, p.qdcount, &q, p.answer_ip,
            );
        }
    }

    fn base_plan() -> AnswerPlan {
        AnswerPlan {
            src_ip: SERVER_IP,
            src_port: DNS_SERVER_PORT,
            dst_port: DstPort::Query,
            tx_id: None,
            flip_id: false,
            flags: 0x8180, // QR=1, RD=1, RA=1, RCODE=0
            qdcount: 1,
            corrupt_question: false,
            answer_ip: [93, 184, 216, 34],
        }
    }

    /// The honest path: the server we asked answers our own question, and the
    /// address comes back. Without this every rejection test below would pass
    /// on a resolver that never accepts anything.
    #[test]
    fn a_genuine_answer_from_the_server_we_asked_is_accepted() {
        let _g = begin();
        plan(&[base_plan()]);
        assert_eq!(
            dns::resolve("host.test"), Some([93, 184, 216, 34]),
            "a well-formed answer from the server we queried must resolve",
        );
    }

    /// **A forged datagram must not consume the query slot.**
    ///
    /// `handle_response` latches the FIRST datagram it accepts and
    /// `resolve` then parses it — and `parse_response` re-checks the
    /// transaction id and the question on its own terms. So a forgery that
    /// slips past `handle_response` cannot POISON the answer; what it does is
    /// take the one-shot latch and block the genuine reply behind it. The
    /// consequence of these checks is denial of resolution, not a wrong
    /// address, and that is what these tests measure: the forgery arrives
    /// first, the real answer second, and the real one must still win.
    ///
    /// (Measured this way because the obvious observable cannot see it: with
    /// the check removed, `resolve` still returns `None` for a bad answer —
    /// `parse_response` rejects it downstream — so a test that only asserts
    /// `None` passes either way. It did, for four of these.)
    #[test]
    fn a_forged_transaction_id_cannot_block_the_genuine_answer() {
        let _g = begin();
        plan(&[
            AnswerPlan { tx_id: Some(0xDEAD), answer_ip: [6, 6, 6, 6], ..base_plan() },
            base_plan(),
        ]);
        assert_eq!(
            dns::resolve("wrongid.test"), Some([93, 184, 216, 34]),
            "a datagram with the wrong transaction id must be discarded, not \
             latched — latching it denies the resolution",
        );
    }

    /// The source endpoint is checked against the server the query actually
    /// went to. The destination port alone identifies nothing — it is the
    /// field every off-path forgery aims at.
    #[test]
    fn an_answer_from_the_wrong_source_is_refused() {
        let _g = begin();
        plan(&[AnswerPlan { src_ip: ATTACKER_IP, answer_ip: [6, 6, 6, 6], ..base_plan() }]);
        assert_eq!(
            dns::resolve("wrongsrc.test"), None,
            "an answer from a host we never asked must be refused",
        );

        // Right host, wrong port.
        raw::reset();
        inbound::reset();
        plan(&[AnswerPlan { src_port: 5354, answer_ip: [6, 6, 6, 6], ..base_plan() }]);
        assert_eq!(
            dns::resolve("wrongport.test"), None,
            "an answer from the right host on the wrong port is still not ours",
        );
    }

    /// The echoed question must be byte-identical to the one we asked. A
    /// forger who guessed the hostname wrongly answers a different question —
    /// and must not take the latch with it.
    #[test]
    fn an_answer_echoing_a_different_question_cannot_block_the_genuine_one() {
        let _g = begin();
        plan(&[
            AnswerPlan { corrupt_question: true, answer_ip: [6, 6, 6, 6], ..base_plan() },
            base_plan(),
        ]);
        assert_eq!(
            dns::resolve("otherq.test"), Some([93, 184, 216, 34]),
            "an answer to a question we did not ask must be discarded",
        );
    }

    /// A datagram with the QR bit clear is a QUERY, and QDCOUNT must be
    /// exactly 1. Neither shape may take the latch.
    #[test]
    fn a_query_shaped_datagram_cannot_block_the_genuine_answer() {
        let _g = begin();
        plan(&[
            AnswerPlan { flags: 0x0100, answer_ip: [6, 6, 6, 6], ..base_plan() },
            base_plan(),
        ]);
        assert_eq!(
            dns::resolve("qrclear.test"), Some([93, 184, 216, 34]),
            "QR=0 means it is a query, not an answer",
        );

        raw::reset();
        inbound::reset();
        plan(&[
            AnswerPlan { qdcount: 2, answer_ip: [6, 6, 6, 6], ..base_plan() },
            base_plan(),
        ]);
        assert_eq!(
            dns::resolve("qdcount.test"), Some([93, 184, 216, 34]),
            "QDCOUNT must be exactly 1",
        );
    }

    /// **First valid answer wins.** Two datagrams that both pass every check
    /// can still race, and the latch decides. Without it a forgery arriving
    /// just behind a genuine reply overwrites it in the window before
    /// `resolve` reads the buffer — which is a poisoning, not merely a denial.
    ///
    /// This needs two answers that are BOTH acceptable, which is why the
    /// forgery tests above cannot reach it: theirs are rejected before the
    /// latch is consulted.
    #[test]
    fn the_first_valid_answer_wins_the_race() {
        let _g = begin();
        plan(&[
            base_plan(),
            AnswerPlan { answer_ip: [6, 6, 6, 6], ..base_plan() },
        ]);
        assert_eq!(
            dns::resolve("race.test"), Some([93, 184, 216, 34]),
            "the second answer must not overwrite the first in the window \
             before `resolve` reads it",
        );
    }

    /// Nothing may be latched while no query is outstanding.
    ///
    /// **This one has no canary, and the reason is worth writing down.**
    /// Removing the `active` check does not change what `resolve` returns:
    /// arming a query clears `response_ready` and `response_len`, so a
    /// datagram latched between queries is wiped before the next one can read
    /// it. The check closes the window rather than a reachable hole — defence
    /// in depth. The test still pins the behaviour, but it cannot prove the
    /// line is load-bearing, and it does not claim to.
    #[test]
    fn an_unprompted_response_cannot_pre_load_the_next_query() {
        let _g = begin();

        // Fire one resolve so a well-formed answer exists on the wire...
        plan(&[base_plan()]);
        assert_eq!(dns::resolve("first.test"), Some([93, 184, 216, 34]));

        // ...then replay that exact answer while nothing is outstanding.
        let (id, question, query_port) = sent_query().expect("a query was sent");
        raw::reset();
        inbound::reset();
        queue_answer(SERVER_IP, DNS_SERVER_PORT, query_port, id, 0x8180, 1, &question, [6, 6, 6, 6]);
        super::net_poll();

        // A different name must not be answered by the replayed datagram.
        inbound::reset();
        assert_eq!(
            dns::resolve("second.test"), None,
            "a response latched outside a query would answer the next question",
        );
    }

    // ── Query source port (RFC 5452 §9.2) ─────────────────────────────────

    /// **Each query leaves from a port of its own, never 5353.**
    ///
    /// RFC 5452 §9.2: an unpredictable source port, from 1024 and up. Every
    /// query used to leave from 5353, which is mDNS's (RFC 6762). Three
    /// unanswered queries: three ports, all >= 1024, none 5353 or the NTP
    /// intercept port, pairwise distinct.
    ///
    /// Distinct is what a draw gives, not a guarantee: two draws over 64 512
    /// ports coincide with probability 1/64 512, so three pairs make this red
    /// about once in 21 500 runs by construction. The host clock and cycle
    /// counter repeat for a fixed test order, so it cannot flicker within one.
    #[test]
    fn each_query_leaves_from_its_own_source_port_never_5353() {
        let _g = begin();
        for name in ["one.test", "two.test", "three.test"] {
            assert_eq!(dns::resolve(name), None, "nobody answers");
        }
        let ports = query_source_ports();
        assert_eq!(ports.len(), 3, "one query per resolve");
        for p in &ports {
            assert!(*p >= 1024, "port {p}: RFC 5452 §9.2 allows 53 or 1024 and above");
            assert_ne!(*p, MDNS_PORT, "5353 is mDNS's port");
            assert_ne!(*p, NTP_CLIENT_PORT, "1123 is intercepted for NTP");
        }
        assert!(
            ports[0] != ports[1] && ports[1] != ports[2] && ports[0] != ports[2],
            "a fixed or repeating source port: {ports:?}",
        );
    }

    /// **A valid answer addressed to the wrong port cannot take the query.**
    ///
    /// Both forgeries are otherwise perfect — the server we asked, the real
    /// transaction id, the real question — and carry 6.6.6.6. One goes to
    /// 5353, where every answer used to be taken; one to the port next to the
    /// query's. The genuine answer comes last. Nothing downstream looks at
    /// the port again, so without the port match the first forgery latches
    /// and 6.6.6.6 is the result: a poisoning, not a denial.
    #[test]
    fn a_valid_answer_to_the_wrong_port_cannot_take_the_query() {
        let _g = begin();
        plan(&[
            AnswerPlan { dst_port: DstPort::Fixed(MDNS_PORT), answer_ip: [6, 6, 6, 6], ..base_plan() },
            AnswerPlan { dst_port: DstPort::NextToQuery, answer_ip: [6, 6, 6, 6], ..base_plan() },
            base_plan(),
        ]);
        assert_eq!(
            dns::resolve("portcheck.test"), Some([93, 184, 216, 34]),
            "an answer is ours only if it comes back to the port the query left from",
        );
    }

    /// **The right port with the wrong transaction id cannot block the
    /// genuine answer.** The id is inverted from the real one, so it is wrong
    /// whatever was drawn.
    ///
    /// Forgery first, genuine second, for the reason the module records:
    /// `parse_response` checks the id again, so a lone forgery comes back
    /// `None` with or without the check in `handle_response`. What the check
    /// prevents is the forgery taking the one-shot latch.
    #[test]
    fn the_right_port_with_the_wrong_id_cannot_block_the_genuine_answer() {
        let _g = begin();
        plan(&[
            AnswerPlan { flip_id: true, answer_ip: [6, 6, 6, 6], ..base_plan() },
            base_plan(),
        ]);
        assert_eq!(
            dns::resolve("portid.test"), Some([93, 184, 216, 34]),
            "right port, wrong id: not an answer to our query",
        );
    }

    /// **The right port and the right id resolve**, and once `resolve` has
    /// returned the port routes nothing to the resolver any more.
    #[test]
    fn the_right_port_and_the_right_id_resolve() {
        let _g = begin();
        plan(&[base_plan()]);
        assert_eq!(dns::resolve("portok.test"), Some([93, 184, 216, 34]));
        let (_, _, query_port) = sent_query().expect("a query was sent");
        assert_ne!(query_port, MDNS_PORT);
        assert_eq!(
            dns::active_port(), 0,
            "no query outstanding: a reply to its port is a datagram to a port nobody holds",
        );
    }

    /// **An outstanding query does not take datagrams meant for a socket.**
    ///
    /// The resolver's intercept in `udp::dispatch` sits ahead of the socket
    /// table, and its port match is what keeps a query from swallowing traffic
    /// addressed to a socket on another port. The far end sends a datagram to
    /// a bound socket first and the genuine answer second; each must arrive
    /// where it was addressed.
    ///
    /// This is the test that pins the dispatch match. Without that match the
    /// tests above stay green: the check under the lock still refuses the
    /// stray, so the answer resolves — but the socket's datagram is gone.
    #[test]
    fn a_datagram_to_a_bound_socket_is_not_taken_by_an_outstanding_query() {
        const SOCKET_PORT: u16 = 40_404;
        let _g = begin();
        for i in 0..super::udp::UDP_MAX_SOCKETS {
            super::udp::unbind(i);
        }
        let sock = super::udp::bind(SOCKET_PORT);
        assert!(sock >= 0, "no UDP socket");

        plan(&[
            AnswerPlan { dst_port: DstPort::Fixed(SOCKET_PORT), answer_ip: [6, 6, 6, 6], ..base_plan() },
            base_plan(),
        ]);
        let resolved = dns::resolve("socket.test");

        let mut buf = [0u8; 512];
        let (mut src_ip, mut src_port) = ([0u8; 4], 0u16);
        let n = super::udp::recvfrom(sock, &mut buf, &mut src_ip, &mut src_port);
        super::udp::unbind(sock as usize);

        assert_eq!(resolved, Some([93, 184, 216, 34]), "the genuine answer still resolves");
        assert!(n > 0, "the datagram to port {SOCKET_PORT} was taken by the query, not delivered");
        assert_eq!((src_ip, src_port), (SERVER_IP, DNS_SERVER_PORT));
    }

    /// Set when the stale-route far end has acted, so it acts once per test.
    static STALE_ROUTE_FIRED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// A DNS answer message (no UDP or IP) with one A record.
    fn answer_message(tx_id: u16, question: &[u8], answer_ip: [u8; 4]) -> Vec<u8> {
        let mut d = Vec::new();
        d.extend_from_slice(&tx_id.to_be_bytes());
        d.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1, RCODE=0
        d.extend_from_slice(&1u16.to_be_bytes());      // QDCOUNT
        d.extend_from_slice(&1u16.to_be_bytes());      // ANCOUNT
        d.extend_from_slice(&[0, 0, 0, 0]);            // NSCOUNT, ARCOUNT
        d.extend_from_slice(question);
        d.extend_from_slice(&[0xC0, 0x0C]);            // pointer to the question name
        d.extend_from_slice(&1u16.to_be_bytes());      // TYPE A
        d.extend_from_slice(&1u16.to_be_bytes());      // CLASS IN
        d.extend_from_slice(&60u32.to_be_bytes());     // TTL
        d.extend_from_slice(&4u16.to_be_bytes());      // RDLENGTH
        d.extend_from_slice(&answer_ip);
        d
    }

    /// The far end for the stale-route test: hands `handle_response` a valid
    /// answer for 6.6.6.6 on a port that is not the query's — the hand-off a
    /// racing `dispatch` would make — then sends the genuine answer by wire.
    fn stale_route_then_genuine() {
        let (id, question, query_port) = match sent_query() {
            Some(v) => v,
            None => return, // nothing asked yet
        };
        if STALE_ROUTE_FIRED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        dns::handle_response(
            &SERVER_IP, DNS_SERVER_PORT, query_port.wrapping_add(1),
            &answer_message(id, &question, [6, 6, 6, 6]),
        );
        queue_answer(SERVER_IP, DNS_SERVER_PORT, query_port, id, 0x8180, 1, &question, [93, 184, 216, 34]);
    }

    /// **A datagram routed on a stale port is refused under the lock.**
    ///
    /// `udp::dispatch` reads `dns::active_port()` without `DNS_QUERY`'s lock.
    /// If one query ends and the next arms on another port between that read
    /// and `handle_response`, a datagram addressed to the old port reaches the
    /// resolver while the new query is outstanding. A single-threaded test
    /// cannot schedule that race through the wire, so the far end makes the
    /// hand-off directly: `handle_response` with a port that is not the
    /// query's, carrying an otherwise valid answer. The re-check under the
    /// lock must refuse it, and the genuine answer must still win.
    #[test]
    fn a_datagram_routed_on_a_stale_port_is_refused_under_the_lock() {
        let _g = begin();
        STALE_ROUTE_FIRED.store(false, std::sync::atomic::Ordering::SeqCst);
        inbound::on_poll(stale_route_then_genuine);
        assert_eq!(
            dns::resolve("stale.test"), Some([93, 184, 216, 34]),
            "a datagram for another port must not take the query's latch",
        );
    }

    /// M24 / U06-8: `resolve` busy-spins `net_poll()` for up to 2 s from a
    /// ring-3 syscall (`SYS_DNS_RESOLVE`) with no yield at all -- a whole
    /// hart pinned in S-mode for the entire window. `resolve_with_yield`
    /// exists so that caller can cooperate with the scheduler instead; this
    /// pins that it actually calls `yield_fn`, not just that it compiles.
    /// Nobody answers, so the loop must run to its full 2 s timeout and
    /// therefore call it at least once.
    #[test]
    fn resolve_with_yield_calls_the_yield_function_while_it_waits() {
        static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        fn count() {
            CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let _g = begin();
        CALLS.store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            dns::resolve_with_yield("nobody-answers.test", count), None,
            "precondition: nobody answers, so this must time out",
        );
        assert!(
            CALLS.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "a 2-second timeout with nobody answering must call yield_fn at \
             least once -- a hart with nothing else to run must still be \
             able to hand off instead of spinning",
        );
    }
}

/// The DHCP client's server-binding defences (`crates/net/net/src/dhcp.rs`).
///
/// DHCP is unauthenticated by design: any host on the link can answer a
/// DISCOVER. What stops a rogue server taking the lease is that the client
/// binds the exchange to the server identifier in the OFFER it accepted, and
/// refuses an ACK from anyone else. Getting this wrong hands an attacker the
/// robot's address, netmask, gateway AND resolver in one exchange.
///
/// **No production seam was needed**, contrary to the note that had this
/// module on the pending-decisions list: `dhcp_discover` puts the DISCOVER on
/// the recording wire with its transaction id, so a test reads the id back off
/// the frame and answers with it — which is what a real server does.
#[cfg(test)]
mod dhcp_client {
    use super::NET_SERIAL as SERIAL;
    use super::{dhcp, netcfg, raw, tcp};

    const SERVER_IP: [u8; 4] = [10, 0, 0, 1];
    const ROGUE_IP: [u8; 4] = [10, 0, 0, 66];
    const OFFERED_IP: [u8; 4] = [10, 0, 0, 42];

    const OFF_OP: usize = 0;
    const OFF_XID: usize = 4;
    const OFF_YIADDR: usize = 16;
    const OFF_COOKIE: usize = 236;
    const OFF_OPTS: usize = 240;
    const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

    const DHCP_OFFER: u8 = 2;
    const DHCP_ACK: u8 = 5;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // The lock serialises tests; it does not reset what the previous one
        // left. `tcp::init` sets the address only, and the `tcp_*` modules end
        // with live slots, so `conn_state(0) == Closed` below held or failed
        // by test ORDER: 25 of 40 `--shuffle-seed` runs at one test thread.
        for idx in 0..azos_limits::TCP_MAX_CONNS {
            tcp::close(idx);
            tcp::close(idx);
        }
        raw::reset();
        netcfg::reset();
        azos_drv_irqchip::clint::set_test_time(300_000);
        tcp::init([0x02, 0, 0, 0, 0, 0x02], [0, 0, 0, 0]);
        g
    }

    /// The transaction id of the DISCOVER just sent, read off the wire the way
    /// a server on the link would read it.
    fn xid_from_the_wire() -> u32 {
        let frames = raw::all();
        let f = frames.last().expect("a DISCOVER must have been transmitted");
        // Ethernet(14) + IP(20) + UDP(8) = 42 bytes before the BOOTP header.
        let b = &f[42..];
        u32::from_be_bytes([b[OFF_XID], b[OFF_XID + 1], b[OFF_XID + 2], b[OFF_XID + 3]])
    }

    /// A BOOTREPLY carrying the given message type and options.
    fn reply(msg_type: u8, xid: u32, yiaddr: [u8; 4], server_id: Option<[u8; 4]>) -> Vec<u8> {
        let mut d = vec![0u8; OFF_OPTS];
        d[OFF_OP] = 2; // BOOTREPLY
        d[OFF_XID..OFF_XID + 4].copy_from_slice(&xid.to_be_bytes());
        d[OFF_YIADDR..OFF_YIADDR + 4].copy_from_slice(&yiaddr);
        d[OFF_COOKIE..OFF_COOKIE + 4].copy_from_slice(&MAGIC_COOKIE);

        d.extend_from_slice(&[53, 1, msg_type]);        // option 53: message type
        d.extend_from_slice(&[1, 4, 255, 255, 255, 0]); // option 1: subnet
        d.extend_from_slice(&[3, 4, 10, 0, 0, 1]);      // option 3: router
        d.extend_from_slice(&[6, 4, 10, 0, 0, 53]);     // option 6: DNS
        if let Some(sid) = server_id {
            d.extend_from_slice(&[54, 4, sid[0], sid[1], sid[2], sid[3]]);
        }
        d.push(255); // OPT_END
        d
    }

    /// The honest exchange, end to end. Without it every rejection below would
    /// pass on a client that refuses everything.
    #[test]
    fn a_complete_exchange_with_one_server_configures_the_interface() {
        let _g = begin();
        dhcp::dhcp_discover();
        let xid = xid_from_the_wire();

        let offer = reply(DHCP_OFFER, xid, OFFERED_IP, Some(SERVER_IP));
        assert_eq!(
            dhcp::dhcp_handle_offer(&offer), Some((OFFERED_IP, SERVER_IP)),
            "a well-formed OFFER must be accepted",
        );

        dhcp::dhcp_request(OFFERED_IP, SERVER_IP);
        let ack = reply(DHCP_ACK, xid, OFFERED_IP, Some(SERVER_IP));
        assert!(dhcp::dhcp_handle_ack(&ack), "the matching ACK must be accepted");

        assert_eq!(
            netcfg::last(), Some((OFFERED_IP, [255, 255, 255, 0], [10, 0, 0, 1])),
            "the lease must reconfigure the interface",
        );
        // And TCP must have taken the new address: it caches its own copy for
        // the checksum pseudo-header, and a stale one drops every segment in
        // silence.
        assert!(
            tcp::conn_state(0) == tcp::TcpState::Closed,
            "sanity: no connection was opened by any of this",
        );
    }

    /// **An OFFER with no server identifier must be refused.** Option 54 is
    /// mandatory (RFC 2131 §4.3.1), and without it there is nothing to bind
    /// the later ACK to — so accepting the OFFER would leave the exchange open
    /// to whoever answers next.
    #[test]
    fn an_offer_without_a_server_identifier_is_refused() {
        let _g = begin();
        dhcp::dhcp_discover();
        let xid = xid_from_the_wire();
        let offer = reply(DHCP_OFFER, xid, OFFERED_IP, None);
        assert_eq!(
            dhcp::dhcp_handle_offer(&offer), None,
            "option 54 is mandatory; without it the exchange cannot be bound",
        );
    }

    /// **The ACK must come from the server whose OFFER we took.** This is the
    /// binding that stops a rogue server on the link stealing the exchange
    /// after a legitimate OFFER.
    #[test]
    fn an_ack_from_a_different_server_is_refused() {
        let _g = begin();
        dhcp::dhcp_discover();
        let xid = xid_from_the_wire();

        assert!(dhcp::dhcp_handle_offer(&reply(DHCP_OFFER, xid, OFFERED_IP, Some(SERVER_IP)))
            .is_some());
        dhcp::dhcp_request(OFFERED_IP, SERVER_IP);
        netcfg::reset();

        let rogue = reply(DHCP_ACK, xid, [10, 0, 0, 200], Some(ROGUE_IP));
        assert!(
            !dhcp::dhcp_handle_ack(&rogue),
            "an ACK from {ROGUE_IP:?} does not answer the OFFER we bound to {SERVER_IP:?}",
        );
        assert_eq!(
            netcfg::last(), None,
            "and it must not have reconfigured anything",
        );
    }

    /// An ACK carrying no server identifier at all is refused for the same
    /// reason — there is nothing to compare against the binding.
    #[test]
    fn an_ack_without_a_server_identifier_is_refused() {
        let _g = begin();
        dhcp::dhcp_discover();
        let xid = xid_from_the_wire();
        assert!(dhcp::dhcp_handle_offer(&reply(DHCP_OFFER, xid, OFFERED_IP, Some(SERVER_IP)))
            .is_some());
        dhcp::dhcp_request(OFFERED_IP, SERVER_IP);
        netcfg::reset();

        assert!(!dhcp::dhcp_handle_ack(&reply(DHCP_ACK, xid, OFFERED_IP, None)));
        assert_eq!(netcfg::last(), None);
    }

    /// The transaction id ties a reply to our own DISCOVER. A reply bearing
    /// someone else's is not ours, however well-formed.
    #[test]
    fn a_reply_with_the_wrong_transaction_id_is_refused() {
        let _g = begin();
        dhcp::dhcp_discover();
        let xid = xid_from_the_wire();

        let wrong = reply(DHCP_OFFER, xid ^ 0xFFFF_FFFF, OFFERED_IP, Some(SERVER_IP));
        assert_eq!(dhcp::dhcp_handle_offer(&wrong), None, "not our transaction");
        // The right one still works, so this is not a test that refuses all.
        assert!(dhcp::dhcp_handle_offer(&reply(DHCP_OFFER, xid, OFFERED_IP, Some(SERVER_IP)))
            .is_some());
    }

    /// Structural checks: a BOOTREQUEST rather than a reply, a missing magic
    /// cookie, and anything shorter than the fixed header.
    #[test]
    fn malformed_replies_are_refused() {
        let _g = begin();
        dhcp::dhcp_discover();
        let xid = xid_from_the_wire();
        let good = reply(DHCP_OFFER, xid, OFFERED_IP, Some(SERVER_IP));

        let mut not_a_reply = good.clone();
        not_a_reply[OFF_OP] = 1; // BOOTREQUEST
        assert_eq!(dhcp::dhcp_handle_offer(&not_a_reply), None, "op=1 is a request");

        let mut no_cookie = good.clone();
        no_cookie[OFF_COOKIE] ^= 0xFF;
        assert_eq!(dhcp::dhcp_handle_offer(&no_cookie), None, "the magic cookie is mandatory");

        for n in 0..OFF_OPTS + 4 {
            assert_eq!(
                dhcp::dhcp_handle_offer(&good[..n.min(good.len())]), None,
                "a {n}-byte datagram is shorter than the fixed header",
            );
        }
    }

    /// An ACK arriving with no OFFER accepted is refused: there is no binding
    /// to check it against, so believing it would mean taking a lease from
    /// whoever spoke first.
    #[test]
    fn an_ack_with_no_accepted_offer_is_refused() {
        let _g = begin();
        dhcp::dhcp_discover();
        let xid = xid_from_the_wire();
        netcfg::reset();
        assert!(
            !dhcp::dhcp_handle_ack(&reply(DHCP_ACK, xid, OFFERED_IP, Some(SERVER_IP))),
            "no OFFER was accepted, so there is nothing this ACK can answer",
        );
        assert_eq!(netcfg::last(), None);
    }
}

/// The socket table (`crates/net/net/src/socket.rs`) — the layer ring 3 talks to.
///
/// **What this module is responsible for, and what it is not.** The ownership
/// GATE lives in `crates/core/syscall/src/handlers.rs`, which asks
/// `socket_owner(fd) == caller_tid` before letting a syscall through. So
/// `socket.rs` does not enforce ownership; it supplies the FACT the gate reads.
/// Its whole security burden is that the fact is true — never stale, never the
/// previous occupant's TID after a slot is recycled. Both of its own comments
/// describe that bug from opposite ends: a stale owner left by `create` means
/// "the task that created the socket could not use it, and the task that used
/// to own the slot could", and one left by `close` is "the ownership check
/// silently passing for the wrong task".
#[cfg(test)]
mod socket_table {
    use super::NET_SERIAL as SERIAL;
    use super::{socket, tcp, udp, wire};
    use socket::{AF_INET, MAX_SOCKETS, SOCK_DGRAM, SOCK_OWNER_KERNEL, SOCK_STREAM};

    const TASK_A: u32 = 7;
    const TASK_B: u32 = 9;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        for fd in 0..MAX_SOCKETS {
            socket::socket_close(fd as i32);
        }
        for i in 0..udp::UDP_MAX_SOCKETS {
            udp::unbind(i);
        }
        for idx in 0..azos_limits::TCP_MAX_CONNS {
            tcp::close(idx);
            tcp::close(idx);
        }
        // State the precondition rather than inherit it.
        for fd in 0..MAX_SOCKETS {
            assert!(
                socket::socket_owner(fd as i32).is_none(),
                "fd {fd} was left owned by the previous test",
            );
        }
        wire::reset();
        azos_drv_irqchip::clint::set_test_time(400_000);
        tcp::init([0x02, 0, 0, 0, 0, 0x02], [10, 0, 0, 2]);
        g
    }

    fn sa(addr: [u8; 4], port: u16) -> socket::SockAddr {
        socket::SockAddr { family: AF_INET as u16, port, addr }
    }

    fn udp_sock(owner: u32) -> i32 {
        socket::socket_create_owned(AF_INET, SOCK_DGRAM, 0, owner)
    }

    fn tcp_sock(owner: u32) -> i32 {
        socket::socket_create_owned(AF_INET, SOCK_STREAM, 0, owner)
    }

    /// **A recycled slot must never answer for its previous occupant.**
    ///
    /// This is the whole point of the module. `NEXT_TID` wraps, so a socket
    /// left behind by a dead task would be inherited wholesale by the next
    /// task that draws the same fd — and the syscall gate, reading a stale
    /// owner, would let the wrong task through.
    ///
    /// **Which half of that is load-bearing, measured rather than assumed.**
    /// Two places guard it: `close_slot` resets the whole entry, and
    /// `socket_create_owned` rewrites every field on the way in. Deleting the
    /// write in `create` fails THREE tests. Deleting the reset in `close`
    /// fails none — `socket_owner` short-circuits on `kind == Free`, and any
    /// reuse goes through `create`, which overwrites the stale TID anyway. So
    /// the reset is defence in depth, not the thing standing between the two
    /// tasks. Both comments in `socket.rs` describe the same bug from
    /// opposite ends, and only one of the ends is currently reachable.
    #[test]
    fn a_recycled_fd_never_reports_its_previous_owner() {
        let _g = begin();
        let fd = udp_sock(TASK_A);
        assert!(fd >= 0);
        assert_eq!(socket::socket_owner(fd), Some(TASK_A));

        socket::socket_close(fd);
        assert_eq!(
            socket::socket_owner(fd), None,
            "a closed slot owns nothing — a stale TID here is the gate passing \
             for a task that never created this socket",
        );

        // The same fd, drawn by a different task.
        let again = udp_sock(TASK_B);
        assert_eq!(again, fd, "the allocator should hand back the same slot");
        assert_eq!(
            socket::socket_owner(again), Some(TASK_B),
            "the new occupant owns it, and only the new occupant",
        );
    }

    /// The exit hook closes everything a dead task owned — and nothing else.
    /// A socket surviving its owner is the same inheritance bug by a slower
    /// route.
    #[test]
    fn the_exit_hook_closes_only_the_dead_tasks_sockets() {
        let _g = begin();
        let a1 = udp_sock(TASK_A);
        let a2 = tcp_sock(TASK_A);
        let b1 = udp_sock(TASK_B);
        let k = socket::socket_create(AF_INET, SOCK_DGRAM, 0); // kernel-owned
        assert!(a1 >= 0 && a2 >= 0 && b1 >= 0 && k >= 0);

        socket::socket_release_all(TASK_A);

        assert_eq!(socket::socket_owner(a1), None, "A's sockets must be closed");
        assert_eq!(socket::socket_owner(a2), None);
        assert_eq!(
            socket::socket_owner(b1), Some(TASK_B),
            "B is still alive and must keep its socket",
        );
        assert_eq!(
            socket::socket_owner(k), Some(SOCK_OWNER_KERNEL),
            "a kernel-owned socket must survive any task exiting",
        );
    }

    /// `socket_release_all` must ignore the sentinel TIDs. Passing the kernel
    /// sentinel would close every kernel socket in the table; passing 0 — which
    /// means "nobody" — would close every unowned one.
    #[test]
    fn the_exit_hook_refuses_the_sentinel_tids() {
        let _g = begin();
        let k = socket::socket_create(AF_INET, SOCK_DGRAM, 0);
        let a = udp_sock(TASK_A);

        socket::socket_release_all(SOCK_OWNER_KERNEL);
        socket::socket_release_all(0);

        assert_eq!(
            socket::socket_owner(k), Some(SOCK_OWNER_KERNEL),
            "the kernel sentinel is not a task and must close nothing",
        );
        assert_eq!(socket::socket_owner(a), Some(TASK_A));
    }

    /// Every entry point bounds its fd. These are the arguments ring 3
    /// supplies, so an unchecked one indexes a 16-entry array with whatever
    /// the caller passed.
    #[test]
    fn every_entry_point_bounds_its_file_descriptor() {
        let _g = begin();
        let addr = sa([10, 0, 0, 9], 9000);
        let mut buf = [0u8; 8];
        let mut src = socket::SockAddr::new();

        for fd in [-1i32, -999, i32::MIN, MAX_SOCKETS as i32, MAX_SOCKETS as i32 + 1, i32::MAX] {
            assert_eq!(socket::socket_owner(fd), None, "owner({fd})");
            assert_eq!(socket::socket_bind(fd, &addr), -1, "bind({fd})");
            assert_eq!(socket::socket_listen(fd, 9000), -1, "listen({fd})");
            assert_eq!(socket::socket_listen_bound(fd), -1, "listen_bound({fd})");
            assert_eq!(socket::socket_accept(fd), -1, "accept({fd})");
            assert_eq!(socket::socket_connect(fd, &addr, 0), -1, "connect({fd})");
            assert_eq!(socket::socket_send(fd, b"x"), -1, "send({fd})");
            assert_eq!(socket::socket_sendto(fd, b"x", &addr), -1, "sendto({fd})");
            assert_eq!(socket::socket_recv(fd, &mut buf), -1, "recv({fd})");
            assert_eq!(socket::socket_recvfrom(fd, &mut buf, &mut src), -1, "recvfrom({fd})");
            socket::socket_close(fd); // must not panic
        }
    }

    /// Only AF_INET, and only the two socket types this stack implements.
    #[test]
    fn unsupported_domains_and_types_are_refused() {
        let _g = begin();
        for domain in [0u32, 1, 3, 10, u32::MAX] {
            assert_eq!(
                socket::socket_create(domain, SOCK_STREAM, 0), -1,
                "domain {domain} is not AF_INET",
            );
        }
        for ty in [0u32, 3, 5, u32::MAX] {
            assert_eq!(
                socket::socket_create(AF_INET, ty, 0), -1,
                "type {ty} is neither SOCK_STREAM nor SOCK_DGRAM",
            );
        }
    }

    /// The table is 16 entries and an exhausted one must report failure, not
    /// hand out a slot it does not have.
    ///
    /// **Superseded in its means, not its property (2026-09-05).** This used to
    /// fill the table from ONE task, which the per-task quota now refuses at
    /// half — that behaviour was the bug, not the property. Filled from the
    /// kernel instead, which is exempt from the quota for the reason given at
    /// `MAX_SOCKETS_PER_TASK`: charging the brain link's own sockets against a
    /// per-task limit would have the kernel competing with userspace for the
    /// channel that carries the e-stop.
    ///
    /// The quota itself is pinned separately in `mod socket_quota`.
    #[test]
    fn an_exhausted_table_refuses_rather_than_overflowing() {
        let _g = begin();
        let mut fds = Vec::new();
        for i in 0..MAX_SOCKETS {
            let fd = socket::socket_create_owned(AF_INET, SOCK_DGRAM, 0, SOCK_OWNER_KERNEL);
            assert!(fd >= 0, "socket {i} should have been created");
            fds.push(fd);
        }
        assert_eq!(
            socket::socket_create_owned(AF_INET, SOCK_DGRAM, 0, SOCK_OWNER_KERNEL), -1,
            "the {MAX_SOCKETS}th+1 socket must be refused",
        );
        // Freeing one makes exactly one available again.
        socket::socket_close(fds[3]);
        let fresh = udp_sock(TASK_B);
        assert_eq!(fresh, fds[3], "the freed slot is the one reused");
        assert_eq!(udp_sock(TASK_A), -1, "and the table is full once more");
    }

    /// TCP-only operations must refuse a UDP socket. `socket_listen` on a
    /// datagram socket is meaningless, and acting on it would drive the TCP
    /// connection table from the wrong kind of handle.
    #[test]
    fn tcp_only_operations_refuse_a_udp_socket() {
        let _g = begin();
        let u = udp_sock(TASK_A);
        assert!(u >= 0);
        assert_eq!(socket::socket_listen(u, 9100), -1, "listen is TCP-only");
        assert_eq!(socket::socket_listen_bound(u), -1, "so is listen_bound");
        assert_eq!(socket::socket_accept(u), -1, "and accept");
    }

    /// `socket_listen_bound` needs a port from a prior `bind`; without one
    /// there is nothing to listen on, and port 0 must not be taken as a
    /// wildcard.
    #[test]
    fn listening_without_a_bound_port_is_refused() {
        let _g = begin();
        let t = tcp_sock(TASK_A);
        assert_eq!(
            socket::socket_listen_bound(t), -1,
            "no bind has happened, so there is no port",
        );
        assert_eq!(socket::socket_bind(t, &sa([0; 4], 9200)), 0);
        assert_eq!(socket::socket_listen_bound(t), 0, "now it can listen");
    }

    /// An unconnected UDP socket has no destination, and `send` must refuse
    /// rather than transmit to 0.0.0.0:0.
    #[test]
    fn sending_without_a_destination_is_refused() {
        let _g = begin();
        let u = udp_sock(TASK_A);
        assert_eq!(socket::socket_bind(u, &sa([0; 4], 9300)), 0);
        assert_eq!(
            socket::socket_send(u, b"nowhere"), -1,
            "no connect() has fixed a destination",
        );
        // And an explicit zero destination is refused too.
        for bad in [
            sa([0, 0, 0, 0], 9000),
            sa([10, 0, 0, 9], 0),
        ] {
            assert_eq!(
                socket::socket_sendto(u, b"x", &bad), -1,
                "{:?}:{} is not a destination", bad.addr, bad.port,
            );
        }
    }

    /// Ephemeral ports stay inside the IANA dynamic range, and are not
    /// reused back to back.
    ///
    /// A counter that wrapped below 49152 would start handing out well-known
    /// ports; a reply meant for an old exchange could then land on a service
    /// socket. Observed where it is actually visible — the UDP source port of
    /// the datagram that goes out — rather than through an accessor, because
    /// there is no accessor and inventing one would have meant changing
    /// production code to watch it.
    #[test]
    fn ephemeral_ports_never_leave_the_dynamic_range() {
        let _g = begin();
        super::arp::insert([10, 0, 0, 9], [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        let mut seen: Vec<u16> = Vec::new();

        for _ in 0..12 {
            let u = udp_sock(TASK_A);
            assert!(u >= 0);
            // No prior bind, so `connect` has to draw an ephemeral port.
            assert_eq!(socket::socket_connect(u, &sa([10, 0, 0, 9], 9400), 0), 0);
            wire::clear_sent();
            assert!(socket::socket_send(u, b"probe") > 0, "the datagram must go out");

            let sent = wire::sent();
            let d = &sent.last().expect("a UDP datagram on the wire").payload;
            let src_port = u16::from_be_bytes([d[0], d[1]]);
            assert!(
                src_port >= 49152,
                "source port {src_port} is below the IANA dynamic range",
            );
            assert!(
                !seen.contains(&src_port),
                "port {src_port} was handed out twice in a row",
            );
            seen.push(src_port);
            socket::socket_close(u);
        }
        assert_eq!(seen.len(), 12, "every round must have produced a datagram");
    }
}

/// The SNTP client (`crates/net/net/src/ntp.rs`).
///
/// This sets the robot's wall clock from an unauthenticated UDP datagram.
/// SNTP has exactly one anti-spoofing mechanism (RFC 4330 §5): the client puts
/// a nonce in the transmit timestamp and the server echoes it back in the
/// originate field, so a reply that does not carry it never saw the request.
/// The module's own comment records that the old code sent an all-zero
/// transmit timestamp — which did not merely skip the check, it made it
/// IMPOSSIBLE, and any host on the path could set the clock to any value
/// after 1970.
///
/// **One line here is not load-bearing, measured not assumed.** Six of the
/// seven checks in `handle_response` fail a test when deleted; `if
/// !ntp.awaiting { return; }` fails none. Arming a request clears
/// `response_ready`, so a reply latched between requests is wiped before the
/// next one can read it — the same shape as `dns.rs`'s `active` check. It
/// closes a window rather than a reachable hole, and this suite does not
/// pretend otherwise.
#[cfg(test)]
mod ntp_client {
    use super::NET_SERIAL as SERIAL;
    use super::{arp, inbound, ip, ntp, raw, wire};

    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const SERVER_IP: [u8; 4] = [10, 0, 0, 123];
    const SERVER_MAC: [u8; 6] = [0x02, 0x12, 0x33, 0x44, 0x55, 0x66];
    const ATTACKER_IP: [u8; 4] = [10, 0, 0, 66];

    const PROTO_UDP: u8 = 17;
    const NTP_PORT: u16 = 123;
    const NTP_CLIENT_PORT: u16 = 1123;
    const NTP_PKT: usize = 48;
    const ORIGINATE: usize = 24;
    const TRANSMIT: usize = 40;

    /// 2020-01-01 in the NTP epoch, comfortably above the plausibility floor.
    const PLAUSIBLE_NTP_SEC: u32 = 3_786_825_600;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        inbound::reset();
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(500_000);
        arp::insert(SERVER_IP, SERVER_MAC);
        arp::insert(ATTACKER_IP, SERVER_MAC);
        ntp::set_ntp_server(SERVER_IP);
        g
    }

    /// The nonce our request carried, read off the wire the way the server
    /// reads it.
    fn nonce_from_the_wire() -> Option<[u8; 8]> {
        wire::sent().iter().find_map(|s| {
            if s.proto != PROTO_UDP || s.payload.len() < 8 + NTP_PKT { return None; }
            if u16::from_be_bytes([s.payload[2], s.payload[3]]) != NTP_PORT { return None; }
            let pkt = &s.payload[8..];
            let mut n = [0u8; 8];
            n.copy_from_slice(&pkt[TRANSMIT..TRANSMIT + 8]);
            Some(n)
        })
    }

    /// How the far end should answer. Data, not a closure, so it lives in a
    /// static — same shape as the DNS harness.
    #[derive(Clone, Copy)]
    struct Reply {
        src_ip: [u8; 4],
        src_port: u16,
        li_vn_mode: u8,
        stratum: u8,
        /// `None` echoes our real nonce; `Some` forges one.
        nonce: Option<[u8; 8]>,
        transmit_sec: u32,
    }

    static PLAN: std::sync::Mutex<Vec<Reply>> = std::sync::Mutex::new(Vec::new());

    fn plan(rs: &[Reply]) {
        *PLAN.lock().unwrap() = rs.iter().rev().copied().collect();
        inbound::on_poll(answer_from_plan);
    }

    fn answer_from_plan() {
        let ours = match nonce_from_the_wire() {
            Some(n) => n,
            None => return,
        };
        let replies: Vec<Reply> = {
            let mut g = PLAN.lock().unwrap();
            let mut v: Vec<Reply> = g.drain(..).collect();
            v.reverse();
            v
        };
        for r in replies {
            let mut pkt = [0u8; NTP_PKT];
            pkt[0] = r.li_vn_mode;
            pkt[1] = r.stratum;
            pkt[ORIGINATE..ORIGINATE + 8].copy_from_slice(&r.nonce.unwrap_or(ours));
            pkt[TRANSMIT..TRANSMIT + 4].copy_from_slice(&r.transmit_sec.to_be_bytes());

            let mut u = Vec::new();
            u.extend_from_slice(&r.src_port.to_be_bytes());
            u.extend_from_slice(&NTP_CLIENT_PORT.to_be_bytes());
            u.extend_from_slice(&((8 + NTP_PKT) as u16).to_be_bytes());
            u.extend_from_slice(&[0, 0]); // RFC 768: no checksum on IPv4
            u.extend_from_slice(&pkt);

            let mut p = vec![0u8; 20];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&((20 + u.len()) as u16).to_be_bytes());
            p[8] = 64;
            p[9] = PROTO_UDP;
            p[12..16].copy_from_slice(&r.src_ip);
            p[16..20].copy_from_slice(&OUR_IP);
            let ck = ip::checksum(&p[..20]);
            p[10..12].copy_from_slice(&ck.to_be_bytes());
            p.extend_from_slice(&u);
            inbound::push_ipv4(&p);
        }
    }

    fn good() -> Reply {
        Reply {
            src_ip: SERVER_IP,
            src_port: NTP_PORT,
            li_vn_mode: 0x24, // LI=0, VN=4, mode=4 (server)
            stratum: 2,
            nonce: None,
            transmit_sec: PLAUSIBLE_NTP_SEC,
        }
    }

    // ── header_acceptable: a pure function, tested directly ──────────────────

    fn header(li_vn_mode: u8, stratum: u8) -> [u8; NTP_PKT] {
        let mut p = [0u8; NTP_PKT];
        p[0] = li_vn_mode;
        p[1] = stratum;
        p
    }

    /// RFC 5905 §7.3. Rejects, in order: anything shorter than a packet; a
    /// mode that is not 4 (server reply); LI = 3, the server declaring itself
    /// unsynchronised; stratum 0, a kiss-o'-death whose timestamp fields carry
    /// an ASCII code rather than a time; and stratum > 15, unsynchronised.
    #[test]
    fn the_header_filter_matches_rfc_5905() {
        assert!(ntp::header_acceptable(&header(0x24, 2)), "LI=0 VN=4 mode=4 stratum=2 is a server reply");

        for n in 0..NTP_PKT {
            assert!(!ntp::header_acceptable(&header(0x24, 2)[..n]), "{n} bytes is short of a packet");
        }
        for mode in [0u8, 1, 2, 3, 5, 6, 7] {
            assert!(
                !ntp::header_acceptable(&header(0x20 | mode, 2)),
                "mode {mode} is not a server reply",
            );
        }
        assert!(
            !ntp::header_acceptable(&header(0xE4, 2)),
            "LI=3 is the server saying it is unsynchronised",
        );
        assert!(
            !ntp::header_acceptable(&header(0x24, 0)),
            "stratum 0 is a kiss-o'-death: its timestamp fields carry ASCII, not a time",
        );
        for s in [16u8, 17, 200, 255] {
            assert!(!ntp::header_acceptable(&header(0x24, s)), "stratum {s} is unsynchronised");
        }
    }

    // ── the full exchange ────────────────────────────────────────────────────

    /// The honest path. Without it every rejection below would pass on a
    /// client that never accepts anything.
    #[test]
    fn a_genuine_reply_from_the_server_we_asked_sets_the_clock() {
        let _g = begin();
        plan(&[good()]);
        let t = ntp::ntp_sync();
        assert_eq!(
            t, PLAUSIBLE_NTP_SEC - 2_208_988_800,
            "the Unix time from a well-formed reply must be adopted",
        );
        assert!(ntp::ntp_is_synced());
    }

    /// **The one anti-spoofing mechanism SNTP has.** A reply that does not
    /// echo our nonce did not come from a host that saw the request.
    #[test]
    fn a_reply_that_does_not_echo_our_nonce_is_refused() {
        let _g = begin();
        plan(&[Reply { nonce: Some([0; 8]), ..good() }]);
        assert_eq!(
            ntp::ntp_sync(), 0,
            "an all-zero originate field is exactly what the old code sent, \
             and it must not be accepted as an echo",
        );

        raw::reset();
        inbound::reset();
        plan(&[Reply { nonce: Some([0xAA; 8]), ..good() }]);
        assert_eq!(ntp::ntp_sync(), 0, "nor any other value we did not send");
    }

    /// The source endpoint is checked against the server we asked.
    #[test]
    fn a_reply_from_the_wrong_source_is_refused() {
        let _g = begin();
        plan(&[Reply { src_ip: ATTACKER_IP, ..good() }]);
        assert_eq!(ntp::ntp_sync(), 0, "a reply from a host we never asked");

        raw::reset();
        inbound::reset();
        plan(&[Reply { src_port: 124, ..good() }]);
        assert_eq!(ntp::ntp_sync(), 0, "right host, wrong port, still not ours");
    }

    /// A timestamp before the plausibility floor is a broken server or a stale
    /// replay, and the clock is LEFT ALONE. The module records that the
    /// comment here once claimed a post-2020 check while the code only
    /// rejected pre-1970 — so the value could be set to any instant in the
    /// 20th century.
    ///
    /// **"Left alone" is asserted literally: an existing sync must survive.**
    /// The first version asserted `!ntp_is_synced()` after a rejected reply,
    /// which is the opposite of the property — and it passed alone while
    /// failing in the suite, because an earlier test had legitimately synced.
    /// Rejecting a reply must not clear a good clock any more than it may set
    /// a bad one.
    #[test]
    fn an_implausible_timestamp_leaves_the_clock_alone() {
        let _g = begin();

        // Establish a known-good sync first, so there is something to protect.
        plan(&[good()]);
        let good_unix = ntp::ntp_sync();
        assert_eq!(good_unix, PLAUSIBLE_NTP_SEC - 2_208_988_800);
        assert!(ntp::ntp_is_synced());

        for sec in [0u32, 0x8000_0000, 2_208_988_800, 3_000_000_000] {
            raw::reset();
            inbound::reset();
            plan(&[Reply { transmit_sec: sec, ..good() }]);
            assert_eq!(
                ntp::ntp_sync(), 0,
                "NTP second {sec} is an all-zero timestamp or an era-0 second before \
                 the plausibility floor, and must be refused",
            );
            assert!(
                ntp::ntp_is_synced(),
                "refusing a bad reply must not throw away the good clock we had",
            );
            // And the sync point itself must not have moved backwards.
            assert!(
                ntp::ntp_now() >= good_unix,
                "NTP second {sec} moved the clock; it must have been ignored entirely",
            );
        }
    }

    /// A header the RFC filter rejects must not reach the rest of the client,
    /// however well the nonce and source match.
    #[test]
    fn a_reply_with_an_unacceptable_header_is_refused() {
        let _g = begin();
        for (li_vn_mode, stratum, why) in [
            (0x23u8, 2u8, "mode 3 is a client packet"),
            (0xE4, 2, "LI=3 is unsynchronised"),
            (0x24, 0, "stratum 0 is a kiss-o'-death"),
            (0x24, 16, "stratum 16 is unsynchronised"),
        ] {
            raw::reset();
            inbound::reset();
            plan(&[Reply { li_vn_mode, stratum, ..good() }]);
            assert_eq!(ntp::ntp_sync(), 0, "{why}");
        }
    }

    /// First valid reply wins: a second one arriving in the same round must
    /// not overwrite the first in the window before `ntp_sync` reads it.
    #[test]
    fn the_first_valid_reply_wins_the_race() {
        let _g = begin();
        plan(&[
            good(),
            Reply { transmit_sec: PLAUSIBLE_NTP_SEC + 86_400, ..good() },
        ]);
        assert_eq!(
            ntp::ntp_sync(), PLAUSIBLE_NTP_SEC - 2_208_988_800,
            "the second reply must not displace the first",
        );
    }

    /// M24 / U06-8: `ntp_sync` busy-spins `net_poll()` for up to
    /// `NTP_MAX_RETRIES * (2 + retry)` seconds from a ring-3 syscall
    /// (`SYS_NTP_SYNC`) with no yield at all. `ntp_sync_with_yield` exists so
    /// that caller can cooperate with the scheduler instead; this pins that
    /// it actually calls `yield_fn`, not just that it compiles. Nobody
    /// answers, so every retry must run to its own timeout and therefore
    /// call it at least once.
    #[test]
    fn ntp_sync_with_yield_calls_the_yield_function_while_it_waits() {
        static CALLS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        fn count() {
            CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        let _g = begin();
        CALLS.store(0, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            ntp::ntp_sync_with_yield(count), 0,
            "precondition: nobody answers, so every retry must time out",
        );
        assert!(
            CALLS.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "every retry timing out with nobody answering must call yield_fn \
             at least once -- a hart with nothing else to run must still be \
             able to hand off instead of spinning",
        );
    }
}

/// The TFTP client (`crates/net/tftp/src/client.rs`).
///
/// TFTP is how this kernel pulls firmware and configuration off the network,
/// so what lands in `dst` becomes what the robot runs. The protocol has no
/// authentication at all; its one structural defence is the TRANSFER ID — the
/// server answers from a fresh ephemeral port, the client locks onto it on the
/// first DATA, and everything from any other port is dropped. Without that
/// lock anyone on the link who sees the RRQ can inject blocks into the file.
#[cfg(test)]
mod tftp {
    use super::NET_SERIAL as SERIAL;
    use super::{arp, inbound, ip, raw, tftp_client, wire};

    /// The transport the fetch loop now takes as an argument, backed by this
    /// crate's own shimmed UDP and poll pump.
    ///
    /// This seam is why the client could move out of `crates/net/net` at all: the
    /// suite supplies a fake wire here exactly as the kernel supplies real
    /// sockets, and neither crate has to depend on the other.
    struct TestUdp;
    impl tftp_client::UdpTransport for TestUdp {
        fn bind(&self, port: u16) -> i32 { super::udp::bind(port) }
        fn unbind(&self, sock: usize) { super::udp::unbind(sock) }
        fn sendto(&self, sock: i32, dst_ip: &[u8; 4], dst_port: u16, data: &[u8]) -> i32 {
            super::udp::sendto(sock, dst_ip, dst_port, data)
        }
        fn recvfrom(&self, sock: i32, buf: &mut [u8],
                    src_ip: &mut [u8; 4], src_port: &mut u16) -> i32 {
            super::udp::recvfrom(sock, buf, src_ip, src_port)
        }
        fn poll(&self) { super::net_poll(); }
    }

    const OUR_IP: [u8; 4] = [10, 0, 0, 2];
    const SERVER_IP: [u8; 4] = [10, 0, 0, 69];
    const SERVER_MAC: [u8; 6] = [0x02, 0x69, 0x69, 0x69, 0x69, 0x69];
    const ATTACKER_IP: [u8; 4] = [10, 0, 0, 66];

    const PROTO_UDP: u8 = 17;
    const SERVER_TID: u16 = 40069;
    const ROGUE_TID: u16 = 40070;

    fn begin() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        inbound::reset();
        raw::reset();
        azos_drv_irqchip::clint::set_test_time(600_000);
        arp::insert(SERVER_IP, SERVER_MAC);
        arp::insert(ATTACKER_IP, SERVER_MAC);
        g
    }

    /// The client's own UDP port, read off the RRQ it just sent.
    fn client_port() -> Option<u16> {
        wire::sent().iter().find_map(|s| {
            if s.proto != PROTO_UDP || s.payload.len() < 8 { return None; }
            Some(u16::from_be_bytes([s.payload[0], s.payload[1]]))
        })
    }

    /// One DATA block the far end will send.
    #[derive(Clone)]
    struct Block {
        src_ip: [u8; 4],
        src_port: u16,
        block: u16,
        payload: Vec<u8>,
    }

    static PLAN: std::sync::Mutex<Vec<Block>> = std::sync::Mutex::new(Vec::new());

    fn plan(bs: Vec<Block>) {
        *PLAN.lock().unwrap() = bs.into_iter().rev().collect();
        inbound::on_poll(answer_from_plan);
    }

    /// The far end: once the RRQ is visible, send the next planned block.
    /// One per poll, so the client ACKs between them as it would on a wire.
    fn answer_from_plan() {
        let dst_port = match client_port() {
            Some(p) => p,
            None => return,
        };
        let b = match PLAN.lock().unwrap().pop() {
            Some(b) => b,
            None => return,
        };

        // TFTP DATA: opcode 3, block number, payload.
        let mut d = Vec::with_capacity(4 + b.payload.len());
        d.extend_from_slice(&3u16.to_be_bytes());
        d.extend_from_slice(&b.block.to_be_bytes());
        d.extend_from_slice(&b.payload);

        let mut u = Vec::new();
        u.extend_from_slice(&b.src_port.to_be_bytes());
        u.extend_from_slice(&dst_port.to_be_bytes());
        u.extend_from_slice(&((8 + d.len()) as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]); // RFC 768: no checksum on IPv4
        u.extend_from_slice(&d);

        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + u.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&b.src_ip);
        p[16..20].copy_from_slice(&OUR_IP);
        let ck = ip::checksum(&p[..20]);
        p[10..12].copy_from_slice(&ck.to_be_bytes());
        p.extend_from_slice(&u);
        inbound::push_ipv4(&p);
    }

    fn data(block: u16, payload: Vec<u8>) -> Block {
        Block { src_ip: SERVER_IP, src_port: SERVER_TID, block, payload }
    }

    /// The honest transfer: two full blocks and a short one to end it.
    /// Without this every rejection below would pass on a client that never
    /// accepts anything.
    #[test]
    fn a_complete_transfer_lands_in_the_destination_buffer() {
        let _g = begin();
        plan(vec![
            data(1, vec![b'A'; 512]),
            data(2, vec![b'B'; 512]),
            data(3, vec![b'C'; 100]), // short block ends the transfer
        ]);

        let mut dst = [0u8; 2048];
        let n = tftp_client::tftp_fetch(&TestUdp, SERVER_IP, "boot.bin", &mut dst)
            .expect("a well-formed transfer must succeed");
        assert_eq!(n, 512 + 512 + 100, "every byte of every block, got {n}");
        assert_eq!(&dst[..512], &[b'A'; 512]);
        assert_eq!(&dst[512..1024], &[b'B'; 512]);
        assert_eq!(&dst[1024..1124], &[b'C'; 100]);
    }

    /// **The transfer-ID lock.** After the first DATA the server's ephemeral
    /// port is fixed; a block arriving from any other port is an injection and
    /// must be dropped, not written into the file the robot is about to run.
    #[test]
    fn blocks_from_a_different_server_port_are_dropped_after_the_tid_locks() {
        let _g = begin();
        plan(vec![
            data(1, vec![b'A'; 512]),
            // Same host, different port: this is the injection.
            Block { src_ip: SERVER_IP, src_port: ROGUE_TID, block: 2, payload: vec![b'X'; 512] },
            data(2, vec![b'B'; 512]),
            data(3, vec![b'C'; 10]),
        ]);

        let mut dst = [0u8; 2048];
        let n = tftp_client::tftp_fetch(&TestUdp, SERVER_IP, "boot.bin", &mut dst).expect("transfer");
        assert_eq!(n, 512 + 512 + 10);
        assert_eq!(
            &dst[512..1024], &[b'B'; 512],
            "block 2 must be the one from the locked TID, not the injected one",
        );
        assert!(
            !dst[..n].contains(&b'X'),
            "not one injected byte may reach the destination buffer",
        );
    }

    /// A block from a different HOST is dropped before the TID is even
    /// consulted.
    #[test]
    fn blocks_from_an_unrelated_host_are_dropped() {
        let _g = begin();
        plan(vec![
            Block { src_ip: ATTACKER_IP, src_port: SERVER_TID, block: 1, payload: vec![b'X'; 512] },
            data(1, vec![b'A'; 512]),
            data(2, vec![b'C'; 10]),
        ]);

        let mut dst = [0u8; 2048];
        let n = tftp_client::tftp_fetch(&TestUdp, SERVER_IP, "boot.bin", &mut dst).expect("transfer");
        assert_eq!(n, 512 + 10);
        assert!(
            !dst[..n].contains(&b'X'),
            "a block from {ATTACKER_IP:?} is not part of this transfer",
        );
    }

    /// **The destination bound.** The file size is the server's choice, and
    /// the buffer is the caller's. A transfer larger than `dst` must be
    /// refused, not written past the end of it.
    #[test]
    fn a_file_larger_than_the_destination_is_refused_not_overrun() {
        let _g = begin();
        plan(vec![
            data(1, vec![b'A'; 512]),
            data(2, vec![b'B'; 512]),
            data(3, vec![b'C'; 512]),
        ]);

        // Room for two blocks, not three.
        let mut dst = [0u8; 1024];
        let r = tftp_client::tftp_fetch(&TestUdp, SERVER_IP, "big.bin", &mut dst);
        assert!(
            r.is_err(),
            "a transfer that does not fit must report failure, not truncate silently",
        );
    }

    /// A duplicate block is re-ACKed but not consumed twice — otherwise a
    /// retransmission (which RFC 1350 makes routine) would double every byte.
    #[test]
    fn a_duplicate_block_is_not_written_twice() {
        let _g = begin();
        plan(vec![
            data(1, vec![b'A'; 512]),
            data(1, vec![b'A'; 512]), // the server retransmits
            data(2, vec![b'B'; 10]),
        ]);

        let mut dst = [0u8; 2048];
        let n = tftp_client::tftp_fetch(&TestUdp, SERVER_IP, "dup.bin", &mut dst).expect("transfer");
        assert_eq!(
            n, 512 + 10,
            "the retransmitted block must be acknowledged, not appended, got {n}",
        );
    }

    /// A server that never answers must give up rather than spin forever.
    #[test]
    fn a_silent_server_reports_no_reply() {
        let _g = begin();
        plan(vec![]);
        let mut dst = [0u8; 512];
        assert!(
            tftp_client::tftp_fetch(&TestUdp, SERVER_IP, "gone.bin", &mut dst).is_err(),
            "no DATA ever arrived, so the fetch must fail",
        );
    }
}

/// `MultiLinkTransport` (`crates/net/net/src/multilink.rs`).
///
/// This is the failover logic between the robot and its operator: it decides
/// which of WiFi / LoRa / RF a command or telemetry byte goes out over. A
/// link "selected" when it is not actually reachable means commands go out
/// on a channel nobody hears; a failover that drops the in-flight write
/// instead of rerouting it silently loses a command; a primary that never
/// gets reclaimed once it recovers means the robot is stuck on its backup
/// radio forever.
///
/// **No `NET_SERIAL` lock here.** Unlike every other module in this file,
/// `multilink.rs` has zero `use` statements and zero global/static state —
/// see its own pull-in comment above. Every test below builds a fresh
/// `MultiLinkTransport` over its own mock links, so nothing here is shared
/// across tests and the crate-wide lock would only serialize work that
/// touches nothing in common.
///
/// Mock links use `Rc<RefCell<MockState>>` rather than plain fields because
/// `add_link` takes `&'a mut dyn Transport` and holds that borrow for the
/// life of the `MultiLinkTransport` — a test still needs to flip `is_up()`
/// or queue an error *after* registering the link, and the only way to do
/// that around an outstanding exclusive borrow is interior mutability. The
/// `Ctrl` handle returned alongside each `MockLink` is a separate value (its
/// own `Rc` clone) so mutating it never touches the field the mux is
/// borrowing.
#[cfg(test)]
mod multilink_transport {
    use super::multilink::{
        MultiLinkTransport, Transport, TransportError,
        MAX_LINKS, TRANSPORT_MAX_CONSEC_FAILURES,
        LINK_PROBE_INTERVAL_TICKS, LINK_QUALITY_GOOD, LINK_QUALITY_DOWN,
    };
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    #[derive(Default)]
    struct MockState {
        up: bool,
        quality: u8,
        /// Consumed by the next `send()`: `Some(e)` makes that one call
        /// fail with `e`; calls after it succeed again.
        next_send_err: Option<TransportError>,
        /// Same idea, for `recv()` — used instead of an empty `rx_queue`
        /// specifically because an empty queue reports `WouldBlock`, which
        /// `recv()` does NOT count as a failure (see `LinkSlot::recv`'s
        /// match arms). Only a real `Err` increments `consec_failures`, so
        /// this is the only way to drive that counter through `recv()`.
        next_recv_err: Option<TransportError>,
        send_count: usize,
        /// One `Vec` per future `recv()` call; empty means `WouldBlock`.
        rx_queue: VecDeque<Vec<u8>>,
        name: &'static str,
    }

    pub(super) struct MockLink(Rc<RefCell<MockState>>);

    impl Transport for MockLink {
        fn send(&mut self, data: &[u8]) -> Result<usize, TransportError> {
            let mut s = self.0.borrow_mut();
            s.send_count += 1;
            if let Some(e) = s.next_send_err.take() {
                return Err(e);
            }
            Ok(data.len())
        }
        fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
            let mut s = self.0.borrow_mut();
            if let Some(e) = s.next_recv_err.take() {
                return Err(e);
            }
            match s.rx_queue.pop_front() {
                Some(bytes) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Ok(n)
                }
                None => Err(TransportError::WouldBlock),
            }
        }
        fn is_up(&self) -> bool { self.0.borrow().up }
        fn link_quality(&self) -> u8 { self.0.borrow().quality }
        fn name(&self) -> &'static str { self.0.borrow().name }
    }

    /// Control handle for a `MockLink`, kept separate from it — see the
    /// module doc comment for why.
    pub(super) struct Ctrl(Rc<RefCell<MockState>>);

    impl Ctrl {
        pub(super) fn set_up(&self, up: bool) { self.0.borrow_mut().up = up; }
        pub(super) fn fail_next_send(&self) {
            self.0.borrow_mut().next_send_err = Some(TransportError::Io);
        }
        pub(super) fn fail_next_recv(&self) {
            self.0.borrow_mut().next_recv_err = Some(TransportError::Io);
        }
        pub(super) fn send_count(&self) -> usize { self.0.borrow().send_count }
        pub(super) fn queue_rx(&self, bytes: &[u8]) {
            self.0.borrow_mut().rx_queue.push_back(bytes.to_vec());
        }
    }

    pub(super) fn mock(name: &'static str, up: bool) -> (MockLink, Ctrl) {
        let state = Rc::new(RefCell::new(MockState {
            up,
            quality: if up { LINK_QUALITY_GOOD } else { LINK_QUALITY_DOWN },
            name,
            ..Default::default()
        }));
        (MockLink(state.clone()), Ctrl(state))
    }

    /// Registration order must not matter — only `priority` decides who is
    /// active on boot. A regression here would mean the last radio wired up
    /// in `kernel/src/main.rs` silently outranks the intended primary.
    #[test]
    fn the_lowest_priority_number_is_active_on_boot_regardless_of_registration_order() {
        let (mut low, _low_ctrl) = mock("low", true);   // priority 5, registered FIRST
        let (mut high, _high_ctrl) = mock("high", true); // priority 1, registered SECOND

        let mut mux = MultiLinkTransport::new();
        mux.add_link(&mut low, 5).unwrap();
        mux.add_link(&mut high, 1).unwrap();

        assert_eq!(
            mux.active_name(), "high",
            "priority 1 must be active even though it was registered after priority 5",
        );
    }

    /// The core failover contract: a link whose hardware reports down must
    /// never be the one the mux hands bytes to. Without this, a physically
    /// disconnected primary (antenna unplugged, driver reset) would keep
    /// being selected and every send would silently go nowhere.
    #[test]
    fn a_dead_link_is_never_selected_as_active() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut backup, _backup_ctrl) = mock("backup", true);

        let mut mux = MultiLinkTransport::new();
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut backup, 2).unwrap();
        assert_eq!(mux.active_name(), "primary");

        primary_ctrl.set_up(false);
        mux.poll();

        assert_eq!(
            mux.active_name(), "backup",
            "primary reports is_up() == false; the mux must fail over to backup",
        );
    }

    /// A single failed send must not strand the caller's data on a dead
    /// link — `send()` retries the SAME call on the next-priority healthy
    /// link within the same call, so one bad write does not cost a byte.
    /// This is the "failover that loses a packet" case: if the fallback
    /// loop were ever skipped, this send would return `Err` even though a
    /// perfectly good backup link was sitting right there.
    #[test]
    fn send_fails_over_within_one_call_when_the_active_link_rejects_the_write() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        primary_ctrl.fail_next_send();
        let n = mux.send(b"hello").expect("secondary must pick up the write");

        assert_eq!(n, 5, "the caller must see all 5 bytes accepted, not a short count");
        assert_eq!(mux.active_name(), "secondary", "the mux must have adopted the link that actually worked");
        assert_eq!(primary_ctrl.send_count(), 1, "primary was tried exactly once");
        assert_eq!(secondary_ctrl.send_count(), 1, "secondary must have received the write");
    }

    /// **Boundary on `TRANSPORT_MAX_CONSEC_FAILURES`.** Two consecutive
    /// failures must NOT mark the active link down; the third must.
    ///
    /// Driven through `recv()`, not `send()`: `send()` opportunistically
    /// retries another healthy link within the SAME call on any single
    /// failure (see the previous test), which would confound a threshold
    /// test — with `recv()` there is no such retry, so any observed switch
    /// can only come from `poll()`'s own down_marked decision, which is
    /// exactly what `TRANSPORT_MAX_CONSEC_FAILURES` gates.
    ///
    /// Secondary is healthy and eligible for the entire test (unlike an
    /// earlier version of this test, which left it down throughout — that
    /// made the "two failures" checkpoint pass no matter what the
    /// threshold was, since there was never an eligible target to switch
    /// to either way; the canary for this test caught exactly that hole).
    /// `poll()` runs at the START of each call, using the failure count as
    /// of the PREVIOUS call, so each checkpoint below is one call behind
    /// the failure that produced it — the comments track that offset.
    #[test]
    fn three_consecutive_failures_but_not_two_marks_the_active_link_down() {
        assert_eq!(TRANSPORT_MAX_CONSEC_FAILURES, 3, "this test is written for the value 3");

        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, secondary_ctrl) = mock("secondary", true); // up throughout

        let mut mux = MultiLinkTransport::new();
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        // consec_failures: 0 -> 1 -> 2. Each poll() at call-start used the
        // PRIOR count (0, then 1), both under threshold, so no switch yet.
        for _ in 0..2 {
            primary_ctrl.fail_next_recv();
            assert_eq!(mux.recv(&mut [0u8; 8]), Err(TransportError::Io));
        }

        // Checkpoint: this call's poll() runs with consec_failures == 2.
        // With the real threshold (3) that must still be "up"; a mux that
        // switched here would prove the threshold is too low.
        assert_eq!(
            mux.recv(&mut [0u8; 8]), Err(TransportError::WouldBlock),
            "nothing queued on whichever link is active",
        );
        assert_eq!(mux.active_name(), "primary", "two failures must not be enough to fail over");

        // Third failure: consec_failures -> 3. This call's poll() still ran
        // with the PRIOR count (2), so no switch within this call either.
        primary_ctrl.fail_next_recv();
        assert_eq!(mux.recv(&mut [0u8; 8]), Err(TransportError::Io));
        assert_eq!(
            mux.active_name(), "primary",
            "the switch for reaching 3 happens on the NEXT poll(), not the call that caused it",
        );

        // One more call: poll() now runs with consec_failures == 3 and
        // must fail over.
        secondary_ctrl.queue_rx(b"ping");
        let mut buf = [0u8; 8];
        let n = mux.recv(&mut buf).expect("must have failed over to secondary by now");
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(mux.active_name(), "secondary", "the third failure must be what triggers the failover");
    }

    // The "an RX-stale link STAYS failed away" property used to be
    // withheld here, because it did not hold: `poll()`'s fail-back loop
    // reclaimed any link whose `is_up()` still returned true without ever
    // consulting the down flag. That is now `LinkDownReason` plus a
    // quarantine that has a length, and the property is pinned — along
    // with the rest of the reason-code contract — in
    // `mod multilink_down_reason` below.

    /// Fail-back must not happen before `LINK_PROBE_INTERVAL_TICKS` have
    /// passed since the primary was registered — a probe fired too early
    /// would bounce the active link back and forth on every poll instead of
    /// at the intended cadence.
    #[test]
    fn a_recovered_primary_is_not_reclaimed_before_the_probe_interval() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, _secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.tick(0);
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        primary_ctrl.set_up(false);
        mux.poll();
        assert_eq!(mux.active_name(), "secondary", "setup: failed over to secondary");

        primary_ctrl.set_up(true); // primary recovers...
        mux.tick(LINK_PROBE_INTERVAL_TICKS - 1); // ...but the probe interval has not elapsed
        mux.poll();

        assert_eq!(
            mux.active_name(), "secondary",
            "one tick short of the probe interval must not be enough to reclaim primary",
        );
    }

    /// The other half of the previous test: once the probe interval DOES
    /// elapse, a recovered higher-priority link must be reclaimed. Without
    /// this the robot would be stuck on its backup radio forever after any
    /// primary blip, silently paying the backup's latency/bandwidth cost.
    #[test]
    fn a_recovered_primary_is_reclaimed_once_the_probe_interval_elapses() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, _secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.tick(0);
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        primary_ctrl.set_up(false);
        mux.poll();
        assert_eq!(mux.active_name(), "secondary", "setup: failed over to secondary");

        primary_ctrl.set_up(true);
        mux.tick(LINK_PROBE_INTERVAL_TICKS);
        mux.poll();

        assert_eq!(
            mux.active_name(), "primary",
            "the probe interval has elapsed and primary is healthy again; it must be reclaimed",
        );
    }

    /// `panic = "abort"` in this kernel, so a reachable panic is a board
    /// reset. `active_idx` and the failover paths are all `Option`-guarded
    /// specifically so an empty or fully-dead mux degrades to `Err`, never
    /// an index panic — exercise both the empty mux (no links registered at
    /// all) and the fully-dead one (links registered, all down).
    #[test]
    fn an_empty_or_fully_dead_mux_returns_not_ready_without_panicking() {
        let mut empty = MultiLinkTransport::new();
        assert_eq!(empty.send(b"x"), Err(TransportError::NotReady));
        assert_eq!(empty.recv(&mut [0u8; 8]), Err(TransportError::NotReady));
        assert_eq!(empty.active_name(), "");
        assert_eq!(empty.active_quality(), LINK_QUALITY_DOWN);
        empty.poll(); // must not panic on an empty link table

        let (mut a, _a_ctrl) = mock("a", false);
        let (mut b, _b_ctrl) = mock("b", false);
        let mut mux = MultiLinkTransport::new();
        mux.add_link(&mut a, 1).unwrap();
        mux.add_link(&mut b, 2).unwrap();

        assert_eq!(mux.send(b"x"), Err(TransportError::NotReady), "both links are down; nowhere to send");
        // recv() (unlike send()) never gates on is_up() — it just reads
        // whatever the active slot's transport hands back, and our mock
        // with an empty rx_queue reports WouldBlock either way. The
        // no-panic property (not the exact error code) is what this test
        // is actually checking.
        assert_eq!(mux.recv(&mut [0u8; 8]), Err(TransportError::WouldBlock));
    }

    /// `MAX_LINKS` bounds a fixed-size array (`[Option<LinkSlot>; MAX_LINKS]`
    /// in `MultiLinkTransport`); `add_link` must refuse a link past that
    /// bound rather than index past the end of it.
    #[test]
    fn a_link_past_max_links_is_rejected_not_indexed_out_of_bounds() {
        assert_eq!(MAX_LINKS, 4, "this test is written for the value 4");

        let (mut l0, _c0) = mock("l0", true);
        let (mut l1, _c1) = mock("l1", true);
        let (mut l2, _c2) = mock("l2", true);
        let (mut l3, _c3) = mock("l3", true);
        let (mut l4, _c4) = mock("l4", true);

        let mut mux = MultiLinkTransport::new();
        assert!(mux.add_link(&mut l0, 0).is_ok());
        assert!(mux.add_link(&mut l1, 1).is_ok());
        assert!(mux.add_link(&mut l2, 2).is_ok());
        assert!(mux.add_link(&mut l3, 3).is_ok());
        assert_eq!(mux.link_count(), MAX_LINKS);

        assert_eq!(
            mux.add_link(&mut l4, 4), Err(()),
            "a fifth link must be refused, not written past the end of the fixed array",
        );
        assert_eq!(mux.link_count(), MAX_LINKS, "the rejected link must not have been counted");
    }
}

/// **Why a link needs a reason code and not a `down` bit.**
///
/// `multilink.rs` detects three quite different faults and used to record
/// all of them in one `down_marked: bool`. Fail-back then reclaimed any
/// link whose `is_up()` still returned true, without reading that bit at
/// all — and because `LINK_PROBE_INTERVAL_TICKS` (2000) is *shorter* than
/// `TRANSPORT_FAILOVER_TIMEOUT_TICKS` (5000), a demoted link's probe was
/// always already overdue. The consequence was not a flap: the very same
/// `poll()` call that failed a link away for RX-staleness handed the
/// traffic straight back to it, so the RX-stale failover path never took
/// effect once, and a half-open link (hardware associated, TCP dead)
/// swallowed every byte the robot sent, forever. On a robot that is the
/// telemetry-and-commands channel going quiet with no failover.
///
/// The fix rests on the observation that the three faults clear on
/// *different* evidence. `is_up()` settles `HardwareDown` and is worth
/// nothing against `RxStale` and `ConsecutiveFailures`, which are only
/// reachable **while the hardware claims to be up** — catching a lying
/// link is their whole purpose. So this module pins, per reason:
///
///   * that a reason which still stands keeps the link out of fail-back
///     (`an_rx_stale_link_is_not_reclaimed_while_the_reason_stands`,
///     `a_link_out_for_send_failures_is_not_reclaimed_on_is_up_alone`);
///   * that it is nevertheless a quarantine and not a retirement — a
///     transient fault that permanently cost the robot its primary radio
///     would be worse than the bug
///     (`an_rx_stale_link_is_re_admitted_once_its_quarantine_is_served`,
///     `a_suspect_link_is_retried_when_nothing_healthy_is_left`);
///   * that RX silence is only evidence on the link something is
///     actually reading (`an_idle_backup_stays_eligible_for_failover`).
///
/// Ticks here are absolute and chosen so each assertion sits on the
/// instant where the fixed and unfixed behaviours differ, not somewhere
/// comfortably past it — the boundary pairs (10_999 vs 11_000) are the
/// point.
#[cfg(test)]
mod multilink_down_reason {
    use super::multilink::{
        LinkDownReason, MultiLinkTransport, TransportError, MAX_LINKS,
        LINK_PROBE_INTERVAL_TICKS, LINK_SUSPECT_QUARANTINE_TICKS,
        TRANSPORT_FAILOVER_TIMEOUT_TICKS, TRANSPORT_MAX_CONSEC_FAILURES,
    };
    // The mock transport and its control handle live in the sibling
    // module: same trait, same fault injection, and a second copy would
    // only be a second thing to keep in step.
    use super::multilink_transport::mock;

    /// `TRANSPORT_FAILOVER_TIMEOUT_TICKS` after this, the primary is
    /// RX-stale. Nonzero on purpose: `refresh_health` gates staleness on
    /// `last_rx_tick > 0`, so a link that has never received anything can
    /// never be stale, and a test that skipped this step would be
    /// measuring a link with the detector switched off.
    const FIRST_RX: u64 = 1_000;
    /// The tick at which RX-staleness fires for the primary.
    const DEMOTED: u64 = FIRST_RX + TRANSPORT_FAILOVER_TIMEOUT_TICKS; // 6_000

    /// **The withheld test.** A link failed away for RX-staleness must
    /// stay away while that reason stands. Under the old single-bit
    /// `down_marked` this assertion failed on the *first* `poll()`: the
    /// fail-back loop reclaimed the link in the same call that demoted it.
    ///
    /// The load-bearing checkpoint is the one at `DEMOTED +
    /// LINK_PROBE_INTERVAL_TICKS`. That is exactly when the ordinary probe
    /// cadence comes due, so it is the instant at which a fail-back gate
    /// written as a bare `if slot.transport.is_up()` — which is what the
    /// code did — takes the link back, and a gate that reads the reason
    /// does not. Assert earlier and the quarantine stamp alone would carry
    /// the test; assert later and the suspect quarantine would.
    #[test]
    fn an_rx_stale_link_is_not_reclaimed_while_the_reason_stands() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, _secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.tick(0);
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        // Arm the staleness detector with one real read. The primary's
        // hardware stays up for the whole test — that is the half-open
        // case, and the whole difficulty: nothing about `is_up()` ever
        // hints that this link is dead.
        mux.tick(FIRST_RX);
        primary_ctrl.queue_rx(b"hi");
        let mut buf = [0u8; 8];
        assert_eq!(
            mux.recv(&mut buf), Ok(2),
            "setup: the primary must actually receive, or staleness never arms",
        );
        assert_eq!(mux.active_name(), "primary", "setup: primary is active");

        mux.tick(DEMOTED);
        mux.poll();
        assert_eq!(
            mux.active_name(), "secondary",
            "RX went silent for a full TRANSPORT_FAILOVER_TIMEOUT_TICKS: the mux \
             must be OFF the primary. Seeing \"primary\" here is the original bug \
             — fail-back reclaiming the link inside the same poll() that demoted it",
        );
        assert_eq!(
            mux.link_down_reason(0), LinkDownReason::RxStale,
            "the primary must be recorded as out for RX-staleness specifically; \
             any other reason means refresh_health attributed the fault wrongly",
        );

        // The ordinary probe cadence comes due. `is_up()` is still true
        // and always was — if that alone were enough, the link would come
        // back here, which is precisely the behaviour being forbidden.
        mux.tick(DEMOTED + LINK_PROBE_INTERVAL_TICKS);
        mux.poll();
        assert_eq!(
            mux.active_name(), "secondary",
            "the probe interval elapsed but nothing disproved RxStale — is_up() \
             cannot, it was true throughout. A mux back on \"primary\" is one \
             whose fail-back gate reads the hardware flag instead of the reason",
        );
        assert_eq!(
            mux.link_down_reason(0), LinkDownReason::RxStale,
            "the reason must still stand: an unserved probe may not clear it",
        );

        // One tick short of the suspect quarantine — still out.
        mux.tick(DEMOTED + LINK_SUSPECT_QUARANTINE_TICKS - 1);
        mux.poll();
        assert_eq!(
            mux.active_name(), "secondary",
            "one tick short of LINK_SUSPECT_QUARANTINE_TICKS must not be enough",
        );
    }

    /// The other half, and the one that keeps the fix from being worse
    /// than the bug: a quarantine must end. If `RxStale` could only be
    /// cleared by evidence the mux is structurally unable to gather —
    /// nothing calls `recv()` on a non-active link — then one half-open
    /// episode would retire the robot's primary radio for the rest of the
    /// mission, silently paying the backup's latency and bandwidth.
    ///
    /// Pinned as a boundary pair, one tick either side of
    /// `LINK_SUSPECT_QUARANTINE_TICKS`, because "eventually comes back"
    /// is not a property — a test that only checked some far-future tick
    /// would pass against a quarantine of any length at all.
    #[test]
    fn an_rx_stale_link_is_re_admitted_once_its_quarantine_is_served() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.tick(0);
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        mux.tick(FIRST_RX);
        primary_ctrl.queue_rx(b"hi");
        let mut buf = [0u8; 8];
        assert_eq!(mux.recv(&mut buf), Ok(2), "setup: arm staleness on primary");

        mux.tick(DEMOTED);
        mux.poll();
        assert_eq!(mux.active_name(), "secondary", "setup: primary demoted for RxStale");

        // Keep the secondary genuinely healthy. Without this it goes
        // RX-stale itself at DEMOTED + TRANSPORT_FAILOVER_TIMEOUT_TICKS —
        // the same tick the quarantine ends — and the primary would come
        // back through the "stranded" path instead, which is a different
        // property with its own test below. This is the confound the
        // boundary assertions would otherwise be measuring.
        mux.tick(9_000);
        secondary_ctrl.queue_rx(b"alive");
        assert_eq!(
            mux.recv(&mut buf), Ok(5),
            "setup: the secondary must keep receiving so it stays healthy",
        );

        mux.tick(DEMOTED + LINK_SUSPECT_QUARANTINE_TICKS - 1);
        mux.poll();
        assert_eq!(
            mux.active_name(), "secondary",
            "one tick before the quarantine is served the primary is still out; \
             seeing \"primary\" means the quarantine is shorter than it claims",
        );
        assert_eq!(mux.link_down_reason(0), LinkDownReason::RxStale);

        mux.tick(DEMOTED + LINK_SUSPECT_QUARANTINE_TICKS);
        mux.poll();
        assert_eq!(
            mux.active_name(), "primary",
            "the quarantine is served and the hardware is up: the higher-priority \
             link must be retried. A mux still on \"secondary\" has retired the \
             primary permanently over one transient fault",
        );
        assert_eq!(
            mux.link_down_reason(0), LinkDownReason::None,
            "re-admission must clear the reason AND the counters behind it \
             (switch_to zeroes consec_failures and last_rx_tick) — otherwise the \
             next refresh_health re-asserts RxStale and the link bounces straight \
             back out",
        );
    }

    /// RX silence on a link **nobody is reading** is not evidence of
    /// anything, and treating it as evidence broke failover outright.
    ///
    /// Nothing in `multilink.rs` ever calls `recv()` on a non-active slot,
    /// so a backup link is silent by construction. The old
    /// `refresh_health` measured staleness on every link regardless, which
    /// marked every idle backup down `TRANSPORT_FAILOVER_TIMEOUT_TICKS`
    /// after it was registered — and `find_healthy` skips links that are
    /// down. The result: the primary's antenna comes off, the mux looks
    /// for somewhere to go, finds nothing, and keeps transmitting into a
    /// link it has itself just marked `HardwareDown`.
    ///
    /// Note the `tick(1_000)` **before** `add_link`: `last_rx_tick` is
    /// seeded from the mux clock, and the `rx_started = last_rx_tick > 0`
    /// guard means links registered at tick 0 have staleness disabled by
    /// accident. A real mux is fed CLINT milliseconds and registers its
    /// radios well after boot, so tick 0 is the unrepresentative case.
    #[test]
    fn an_idle_backup_stays_eligible_for_failover() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, _secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.tick(1_000); // links registered after boot, as on real hardware
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        // Long enough that the backup would have been declared RX-stale
        // if anyone were counting its silence.
        mux.tick(1_000 + TRANSPORT_FAILOVER_TIMEOUT_TICKS + 1_000);
        primary_ctrl.set_up(false);
        mux.poll();

        assert_eq!(
            mux.link_down_reason(1), LinkDownReason::None,
            "the backup has never been read from and never could have been; its \
             silence must not be recorded as RxStale",
        );
        assert_eq!(
            mux.active_name(), "secondary",
            "the primary's hardware is down and a perfectly good backup exists — \
             a mux still on \"primary\" is transmitting into a link it has itself \
             marked HardwareDown, because find_healthy had nothing left to pick",
        );
    }

    /// `ConsecutiveFailures` is the other reason `is_up()` cannot
    /// disprove — the link accepts the write and errors, or accepts the
    /// read and errors, while the driver keeps reporting the interface up.
    /// It must be quarantined on the same terms as `RxStale`.
    ///
    /// Driven through `recv()` rather than `send()`: `send()` retries a
    /// different healthy link within the same call on any single failure,
    /// which would move the active link for reasons that have nothing to
    /// do with the threshold under test.
    #[test]
    fn a_link_out_for_send_failures_is_not_reclaimed_on_is_up_alone() {
        assert_eq!(TRANSPORT_MAX_CONSEC_FAILURES, 3, "written for the value 3");

        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, _secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.tick(0);
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        // Three errors while the hardware never stops claiming to be up.
        mux.tick(2_000);
        for _ in 0..TRANSPORT_MAX_CONSEC_FAILURES {
            primary_ctrl.fail_next_recv();
            assert_eq!(mux.recv(&mut [0u8; 8]), Err(TransportError::Io));
        }

        // poll() acts on the count as of the previous call, so the switch
        // lands on the first poll after the third failure.
        mux.poll();
        assert_eq!(
            mux.link_down_reason(0), LinkDownReason::ConsecutiveFailures,
            "three consecutive errors on a link whose is_up() is true must be \
             attributed to the failure counter, not to the hardware",
        );
        assert_eq!(mux.active_name(), "secondary", "setup: failed over off the primary");

        // Probe cadence due, hardware still (and always) up. A gate that
        // trusts is_up() reclaims here; one that reads the reason does not.
        mux.tick(2_000 + LINK_PROBE_INTERVAL_TICKS);
        mux.poll();
        assert_eq!(
            mux.active_name(), "secondary",
            "is_up() was true the entire time the link was failing, so it cannot \
             be what re-admits it; a mux back on \"primary\" would hand the \
             traffic to a link with three unexplained errors against it",
        );
        assert_eq!(mux.link_down_reason(0), LinkDownReason::ConsecutiveFailures);
    }

    /// A suspect link beats no link. When the active link is itself down
    /// and `find_healthy` comes back empty, the mux is stranded, and a
    /// higher-priority link quarantined for a reason `is_up()` cannot
    /// disprove is the best thing left — so it is retried immediately
    /// rather than after the full quarantine.
    ///
    /// Without this the reason code would be a way to strand the robot:
    /// primary quarantined, backup's antenna falls off, and the mux sits
    /// on the dead backup refusing to touch a primary that may well be
    /// fine.
    #[test]
    fn a_suspect_link_is_retried_when_nothing_healthy_is_left() {
        let (mut primary, primary_ctrl) = mock("primary", true);
        let (mut secondary, secondary_ctrl) = mock("secondary", true);

        let mut mux = MultiLinkTransport::new();
        mux.tick(0);
        mux.add_link(&mut primary, 1).unwrap();
        mux.add_link(&mut secondary, 2).unwrap();

        mux.tick(2_000);
        for _ in 0..TRANSPORT_MAX_CONSEC_FAILURES {
            primary_ctrl.fail_next_recv();
            assert_eq!(mux.recv(&mut [0u8; 8]), Err(TransportError::Io));
        }
        mux.poll();
        assert_eq!(mux.active_name(), "secondary", "setup: primary quarantined");
        assert_eq!(mux.link_down_reason(0), LinkDownReason::ConsecutiveFailures);

        // Now lose the backup, well inside the primary's quarantine.
        mux.tick(5_000);
        assert!(
            5_000 - 2_000 < LINK_SUSPECT_QUARANTINE_TICKS,
            "this test is only meaningful while the quarantine is still running",
        );
        secondary_ctrl.set_up(false);
        mux.poll();

        assert_eq!(
            mux.active_name(), "primary",
            "nothing healthy is left, so the quarantined primary must be retried \
             rather than kept out on principle; a mux still on \"secondary\" is \
             sitting on a link whose hardware is gone",
        );
        assert_eq!(
            mux.link_down_reason(0), LinkDownReason::None,
            "adopting the link must clear the reason and the failure counter \
             behind it, or the next refresh_health throws it straight back out",
        );
    }

    /// `panic = "abort"` in this kernel: a diagnostic accessor must not be
    /// able to reset the board. `link_down_reason` indexes a fixed-size
    /// array, so an out-of-range index must be answered, not indexed.
    #[test]
    fn link_down_reason_answers_out_of_range_indices_without_panicking() {
        let mux = MultiLinkTransport::new();
        assert_eq!(
            mux.link_down_reason(0), LinkDownReason::HardwareDown,
            "an unregistered slot has no hardware behind it",
        );
        assert_eq!(mux.link_down_reason(MAX_LINKS), LinkDownReason::HardwareDown);
        assert_eq!(mux.link_down_reason(usize::MAX), LinkDownReason::HardwareDown);
    }
}

// ── The pending-ARP transmit queue ──────────────────────────────────────
//
// `ip::send` used to answer an unknown destination MAC by firing an ARP
// request and returning -1, so the FIRST datagram to any uncached address was
// lost — every time, guaranteed, on a cold cache. The comment told callers to
// "retry after delay"; none of them did. It now queues the frame and delivers
// it when the reply lands.
//
// Host-side because every property here is deterministic and the interesting
// ones are about TIME and CAPACITY, which a QEMU run cannot pin: the TTL needs
// a clock that can be moved, and "the fifth frame is refused" needs the queue
// filled exactly.
#[cfg(test)]
mod arp_tx_queue {
    use super::{arp, ip, raw, NET_SERIAL as SERIAL};
    use azos_drv_irqchip::clint;

    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const OUR_IP:  [u8; 4] = [10, 0, 0, 2];
    const PEER_MAC: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01];

    /// Take the lock AND state the precondition. `ip`'s queue and `arp`'s
    /// caches are process-wide statics and the runner is multi-threaded —
    /// same hazard, same fix, as `ina219_no_fabricated_battery` in
    /// `drivers-tests`.
    fn begin(now: u64) -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        clint::set_test_time(now);
        // ALL THREE, and the ARP cache is the one that was missing. Without
        // it a test that learns an address makes the next test's `ip::send`
        // resolve instead of queue, and the suite gives different answers
        // depending on which test ran first — measured, 5/1 then 6/0 with no
        // code change in between.
        arp::cache_reset_for_test();
        ip::arp_txq_reset_for_test();
        raw::reset();
        g
    }

    /// A 28-byte ARP reply from `spa`/`sha` addressed to us.
    fn arp_reply(sha: [u8; 6], spa: [u8; 4]) -> Vec<u8> {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&1u16.to_be_bytes());      // htype: Ethernet
        p.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
        p.push(6); p.push(4);                          // hlen, plen
        p.extend_from_slice(&2u16.to_be_bytes());      // oper: REPLY
        p.extend_from_slice(&sha); p.extend_from_slice(&spa);
        p.extend_from_slice(&OUR_MAC); p.extend_from_slice(&OUR_IP);
        p
    }

    /// The same, as a REQUEST from the peer (it is asking about US).
    fn arp_request_from(sha: [u8; 6], spa: [u8; 4]) -> Vec<u8> {
        let mut p = arp_reply(sha, spa);
        p[6..8].copy_from_slice(&1u16.to_be_bytes());  // oper: REQUEST
        p[18..24].copy_from_slice(&[0u8; 6]);          // tha unknown
        p
    }

    /// Every IPv4 frame on the wire whose destination MAC is `mac`.
    fn ipv4_frames_to(mac: [u8; 6]) -> Vec<Vec<u8>> {
        raw::all()
            .into_iter()
            .filter(|f| f.len() >= 14
                && u16::from_be_bytes([f[12], f[13]]) == 0x0800
                && f[..6] == mac)
            .collect()
    }

    fn arp_frames() -> usize {
        raw::all().iter()
            .filter(|f| f.len() >= 14 && u16::from_be_bytes([f[12], f[13]]) == 0x0806)
            .count()
    }

    /// **The packet is accepted, and it is NOT on the wire yet.** Both halves
    /// matter: the old code returned -1 (rejected) and the new code must not
    /// answer by sending to a MAC it does not know.
    #[test]
    fn an_unresolved_destination_is_queued_not_dropped() {
        let _g = begin(1_000_000);
        let dst = [10, 0, 0, 41];
        let rc = ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"hello");
        assert_eq!(rc, 0, "an unresolved destination must be ACCEPTED, not refused");
        assert_eq!(arp_frames(), 1, "the request still goes out");
        assert!(ipv4_frames_to(PEER_MAC).is_empty(),
                "nothing may be sent to a MAC we have not learned yet");
        let (queued, sent, full, expired) = ip::arp_txq_stats();
        assert_eq!((queued, sent, full, expired), (1, 0, 0, 0));
    }

    /// **The reply releases it, with the MAC patched in.** The MAC assertion
    /// is the point: a queue that delivered to the zero placeholder would
    /// satisfy "a frame went out" and put the datagram nowhere.
    #[test]
    fn the_reply_releases_the_frame_with_the_learned_mac() {
        let _g = begin(2_000_000);
        let dst = [10, 0, 0, 42];
        assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"payload"), 0);

        arp::handle(&arp_reply(PEER_MAC, dst), &OUR_MAC, &OUR_IP);

        let out = ipv4_frames_to(PEER_MAC);
        assert_eq!(out.len(), 1, "the queued frame must leave exactly once");
        assert_eq!(&out[0][..6], &PEER_MAC, "destination MAC must be the learned one");
        assert_eq!(&out[0][6..12], &OUR_MAC, "source MAC must be untouched");
        assert!(out[0].ends_with(b"payload"), "the payload must survive the wait");
        let (_, sent, _, _) = ip::arp_txq_stats();
        assert_eq!(sent, 1);
    }

    /// U06-4: an off-subnet destination resolves through the GATEWAY, not
    /// the destination itself — there was no route beyond the local segment
    /// at all, so a host like `dns.rs`'s default `8.8.8.8` drew a broadcast
    /// ARP request nobody on this link could ever answer.
    #[test]
    fn an_off_subnet_destination_arps_the_gateway_not_the_destination() {
        let _g = begin(4_000_000);
        let dst = [8, 8, 8, 8]; // off 10.0.0.0/24, the on-link subnet this shim reports
        let gw = super::net_get_gateway();
        assert_ne!(gw, [0, 0, 0, 0], "precondition: a gateway must be configured");

        assert_eq!(
            ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"far"), 0,
            "an off-subnet destination with a gateway configured must still \
             be accepted (queued), not refused",
        );
        assert_eq!(arp_frames(), 1, "exactly one ARP request must go out");

        // Read the request's target IP (tpa) off the wire: Ethernet header
        // (14 B) + ARP htype/ptype/hlen/plen/oper/sha/spa/tha (24 B).
        let frame = raw::all().into_iter()
            .find(|f| f.len() >= 42 && u16::from_be_bytes([f[12], f[13]]) == 0x0806)
            .expect("an ARP request must have been recorded");
        let tpa = &frame[14 + 24..14 + 28];
        assert_eq!(
            tpa, &gw[..],
            "the ARP request must ask for the GATEWAY's MAC, not the \
             off-subnet destination's",
        );

        // Once the gateway answers, the queued frame is released to the
        // gateway's MAC — the destination address inside the IP header
        // (already written) is unchanged; only the link-layer next hop is.
        arp::handle(&arp_reply(PEER_MAC, gw), &OUR_MAC, &OUR_IP);
        let out = ipv4_frames_to(PEER_MAC);
        assert_eq!(out.len(), 1, "the queued frame must be released to the gateway's MAC");
        assert!(out[0].ends_with(b"far"));
    }

    /// The on-link half of the same property: nothing changes for a
    /// destination inside the configured subnet.
    #[test]
    fn an_on_subnet_destination_still_arps_the_destination_directly() {
        let _g = begin(5_000_000);
        let dst = [10, 0, 0, 44]; // on 10.0.0.0/24
        assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"near"), 0);
        let frame = raw::all().into_iter()
            .find(|f| f.len() >= 42 && u16::from_be_bytes([f[12], f[13]]) == 0x0806)
            .expect("an ARP request must have been recorded");
        let tpa = &frame[14 + 24..14 + 28];
        assert_eq!(
            tpa, &dst[..],
            "an on-link destination must still be ARPed directly, not \
             redirected through the gateway",
        );
    }

    /// A peer that ASKS US a question has told us its address just as surely
    /// as one that answers ours. Refusing to use it would hold the frame
    /// behind an ARP round trip that is no longer needed.
    #[test]
    fn a_request_from_the_peer_also_releases_the_frame() {
        let _g = begin(3_000_000);
        let dst = [10, 0, 0, 43];
        assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"x"), 0);
        arp::handle(&arp_request_from(PEER_MAC, dst), &OUR_MAC, &OUR_IP);
        assert_eq!(ipv4_frames_to(PEER_MAC).len(), 1,
                   "an incoming request carries the address too");
    }

    /// **The deadline is checked AT DRAIN TIME too, and this is the only path
    /// that reaches it.** Written because a canary found the hole: deleting
    /// the drain-time expiry check left every other test in this module green.
    ///
    /// The reason is worth stating. A late REPLY never reaches the queue at
    /// all — `take_pending` has already retired the question, so `arp::handle`
    /// does not learn the MAC. But an incoming REQUEST is trusted with no such
    /// window: a peer that asks about us ten seconds after we queued a frame
    /// for it teaches us its address, and without this check the queue would
    /// answer by putting a ten-second-old datagram on the wire.
    #[test]
    fn a_late_request_does_not_release_an_expired_frame() {
        let _g = begin(6_000_000);
        let dst = [10, 0, 0, 45];
        assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"old"), 0);

        clint::set_test_time(6_000_000 + ip::ARP_TXQ_TTL_TICKS + 1);
        arp::handle(&arp_request_from(PEER_MAC, dst), &OUR_MAC, &OUR_IP);

        assert!(ipv4_frames_to(PEER_MAC).is_empty(),
                "a frame past its deadline must not be released by a late request");
        let (_, sent, _, expired) = ip::arp_txq_stats();
        assert_eq!(sent, 0, "nothing left the queue");
        assert_eq!(expired, 1, "the drop is counted at drain time");
    }

    /// **A frame must not outlive the question it is waiting on**, and the
    /// slot it held must come back before it can refuse a live frame. Those
    /// two are the whole guarantee; there is no reclaim timer and this states
    /// so rather than implying one.
    ///
    /// Note what the first half rests on. The TTL matches
    /// `ARP_PENDING_TTL_TICKS` deliberately, and past it the reply is not even
    /// TRUSTED: `take_pending` has already retired the question, so
    /// `arp::handle` does not learn the MAC and never reaches the queue. Two
    /// independent reasons the late datagram does not go out, which is why the
    /// deadlines are the same number and must stay that way.
    #[test]
    fn a_frame_that_waited_too_long_is_dropped_not_sent_late() {
        let _g = begin(4_000_000);
        let dst = [10, 0, 0, 44];
        assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"stale"), 0);

        clint::set_test_time(4_000_000 + ip::ARP_TXQ_TTL_TICKS + 1);
        arp::handle(&arp_reply(PEER_MAC, dst), &OUR_MAC, &OUR_IP);
        assert!(ipv4_frames_to(PEER_MAC).is_empty(),
                "an expired frame must not be sent late");
        let (_, sent, _, _) = ip::arp_txq_stats();
        assert_eq!(sent, 0, "nothing left the queue");

        // The slot comes back on the next enqueue — the sweep runs there, not
        // on a timer nobody calls. Asserted through a FULL queue so a leaked
        // slot cannot hide: four dead frames plus one live one is five, and
        // only a working sweep accepts the fifth.
        for i in 1..ip::ARP_TXQ_SIZE {
            let d = [10, 0, 0, 44 + i as u8];
            assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &d, ip::IP_PROTO_UDP, b"s"), 0);
        }
        clint::set_test_time(4_000_000 + 2 * ip::ARP_TXQ_TTL_TICKS + 2);
        let live = [10, 0, 0, 99];
        assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &live, ip::IP_PROTO_UDP, b"live"), 0,
                   "the sweep must reclaim the dead slots for a live frame");
        let (_, _, full, expired) = ip::arp_txq_stats();
        assert_eq!(full, 0, "nothing was refused, so no slot leaked");
        assert_eq!(expired, ip::ARP_TXQ_SIZE as u32,
                   "and every drop is COUNTED, not silent");
    }

    /// **Full means refused, not overwritten.** A queue that evicted its
    /// oldest entry to make room would lose a packet the caller was told had
    /// been accepted — the exact lie this queue exists to stop telling. The
    /// refusal is reported to the caller AND counted.
    #[test]
    fn a_full_queue_refuses_rather_than_dropping_what_it_holds() {
        let _g = begin(5_000_000);
        for i in 0..ip::ARP_TXQ_SIZE {
            let dst = [10, 0, 0, 50 + i as u8];
            assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &dst, ip::IP_PROTO_UDP, b"q"), 0,
                       "slot {i} should be free");
        }
        let overflow = [10, 0, 0, 90];
        assert_eq!(ip::send(&OUR_MAC, &OUR_IP, &overflow, ip::IP_PROTO_UDP, b"q"), -1,
                   "a full queue must REFUSE, so the caller knows");
        let (_, _, full, _) = ip::arp_txq_stats();
        assert_eq!(full, 1);

        // And what it already holds is still deliverable — the refusal did not
        // cost an earlier packet.
        let first = [10, 0, 0, 50];
        arp::handle(&arp_reply(PEER_MAC, first), &OUR_MAC, &OUR_IP);
        assert_eq!(ipv4_frames_to(PEER_MAC).len(), 1,
                   "the frame queued first is still there and still leaves");
    }
}

/// `tcp::tick_needed` and the timer kick: what lets the kernel's network
/// poller sleep without a timer in IRQ mode. The poller trusts both: a
/// `false` while a deadline is pending, or a missing kick when a connection
/// leaves `Closed`/`Listen` outside the poller, is a SYN that is never
/// retransmitted.
#[cfg(test)]
mod tcp_tick_needed {
    use super::tcp_rx::*;
    use super::tcp;
    use std::sync::atomic::{AtomicU32, Ordering};

    static KICKS: AtomicU32 = AtomicU32::new(0);
    fn count_kick() { KICKS.fetch_add(1, Ordering::SeqCst); }

    const SYN: u8 = 0x02;

    #[test]
    fn a_listener_alone_needs_no_tick_and_a_syn_to_it_kicks_once() {
        let _g = begin();
        tcp::set_timer_kick(count_kick);
        assert!(!tcp::tick_needed(), "every slot is Closed after begin()");
        assert!(tcp::listen(7600) >= 0);
        assert!(!tcp::tick_needed(), "a listener has no deadline");
        let k0 = KICKS.load(Ordering::SeqCst);
        deliver(&segment(46000, 7600, 0x2200_0000, 0, SYN, 4096, &[]));
        assert!(slot_in(tcp::TcpState::SynRcvd).is_some(), "the SYN opened a half-open connection");
        assert!(tcp::tick_needed(), "a half-open connection's SYN-ACK can need a retransmission");
        assert_eq!(KICKS.load(Ordering::SeqCst) - k0, 1, "leaving Listen must kick the poller once");
    }

    #[test]
    fn connect_kicks_and_needs_a_tick() {
        let _g = begin();
        tcp::set_timer_kick(count_kick);
        let k0 = KICKS.load(Ordering::SeqCst);
        let idx = tcp::connect(PEER_IP, 7601, 46001);
        assert!(idx >= 0, "no free slot for connect");
        assert!(tcp::conn_state(idx as usize) == tcp::TcpState::SynSent);
        assert!(tcp::tick_needed(), "a SynSent connection's SYN can need a retransmission");
        assert_eq!(KICKS.load(Ordering::SeqCst) - k0, 1, "connect must kick the poller once");
    }

    #[test]
    fn an_established_connection_needs_a_tick() {
        let _g = begin();
        let (idx, _ours, _theirs) = establish(7602, 46002, 0x2300_0000);
        assert!(tcp::conn_state(idx) == tcp::TcpState::Established);
        assert!(tcp::tick_needed(), "keep-alive and retransmission run on Established");
    }
}

/// `tcp::accept` hands out a connection whose peer already sent its data and
/// its FIN before the accepting task polled (`CloseWait`): the data is still
/// buffered and must reach the application, then EOF. Only `Established` was
/// accepted, so a short push that half-closed quickly — `tools/ota_send.py`
/// does exactly that — was never accepted at all.
///
/// **Canary**: accept `Established` only: `socket_accept_owned` answers -1.
#[cfg(test)]
mod accept_after_peer_fin {
    use super::tcp_rx::*;
    use super::{socket, tcp};

    const FIN: u8 = 0x01;
    const ACK: u8 = 0x10;
    const OWNER: u32 = 43;

    #[test]
    fn a_connection_the_peer_already_half_closed_is_accepted_and_drained() {
        let _g = begin();
        let (idx, ours, theirs) = establish(7707, 45510, 0xA700_0000);
        deliver(&segment(45510, 7707, theirs, ours, FIN | ACK, 4096, b"payload"));
        assert!(
            tcp::conn_state(idx) == tcp::TcpState::CloseWait,
            "data plus FIN before any accept means CloseWait, got {}",
            st(tcp::conn_state(idx)),
        );
        let listener = socket::socket_create_owned(socket::AF_INET, socket::SOCK_STREAM, 0, OWNER);
        assert!(listener >= 0);
        let addr = socket::SockAddr { family: socket::AF_INET as u16, port: 7707, addr: [0; 4] };
        assert_eq!(socket::socket_bind(listener, &addr), 0);
        let fd = socket::socket_accept_owned(listener, OWNER);
        assert!(fd >= 0, "a half-closed connection with data was not accepted");
        let mut buf = [0u8; 16];
        assert_eq!(socket::socket_recv(fd, &mut buf), 7, "its data must still be readable");
        assert_eq!(&buf[..7], b"payload");
        assert_eq!(socket::socket_recv(fd, &mut buf), -1, "then EOF");
        assert_eq!(socket::socket_accept_owned(listener, OWNER), -1, "accepted once");
    }
}

/// `socket_connect_with_yield` waits for the handshake on the CLOCK
/// (`CONNECT_HANDSHAKE_BUDGET_US`), not on a count of `yield_fn` calls.
///
/// The old bound was 2,000,000 calls. Its duration was whatever the calls
/// happened to cost: under host load a yield count ends early or late against
/// a peer that answers on wall-clock time (gate 187, gate 193).
///
/// **Canary** (both tests): restore the count bound. A peer that answers after
/// 3 s of counter time while each wait costs 1 µs needs 3,000,000 waits, so
/// the first test gets -1; with each wait costing 1 ms and no answer at all,
/// the second sees 2,000,000 waits instead of ~10,000.
#[cfg(test)]
mod connect_handshake_deadline {
    use super::tcp_rx::*;
    use super::{socket, tcp};

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const PEER_PORT: u16 = 7810;
    const TICKS_PER_US: u64 = azos_drv_irqchip::clint::TIMER_FREQ / 1_000_000;

    fn tcp_socket() -> i32 {
        let fd = socket::socket_create(socket::AF_INET, socket::SOCK_STREAM, 0);
        assert!(fd >= 0, "no free socket");
        fd
    }

    fn peer() -> socket::SockAddr {
        socket::SockAddr { family: socket::AF_INET as u16, port: PEER_PORT, addr: PEER_IP }
    }

    /// The peer's SYN-ACK arrives after 3 s of counter time; each wait costs
    /// 1 µs. Inside the 10 s budget: connected.
    #[test]
    fn a_peer_that_answers_inside_the_budget_connects_however_cheap_a_wait_is() {
        let _g = begin();
        let fd = tcp_socket();
        let t0 = azos_drv_irqchip::clint::get_time();
        let answer_at = t0 + 3_000_000 * TICKS_PER_US;
        let mut waits = 0u64;
        let mut answered = false;
        let rc = socket::socket_connect_with_yield(fd, &peer(), 45800, || {
            waits += 1;
            let now = azos_drv_irqchip::clint::get_time() + TICKS_PER_US;
            azos_drv_irqchip::clint::set_test_time(now);
            if !answered && now >= answer_at {
                answered = true;
                let syn = outbound()
                    .into_iter()
                    .rev()
                    .find(|o| o.flags & SYN != 0)
                    .expect("connect must have sent a SYN");
                deliver(&segment(PEER_PORT, 45800, 0xB800_0000, syn.seq.wrapping_add(1),
                                 SYN | ACK, 4096, &[]));
            }
        });
        assert_eq!(rc, 0, "the SYN-ACK came at 3 s, inside the budget ({waits} waits)");
        assert!(answered, "the peer must have answered before connect returned");
        assert!(waits > 2_000_000, "the test must need more waits than the old count ({waits})");
        socket::socket_close(fd);
    }

    /// No peer answers; each wait costs 1 ms. The connect gives up when the
    /// budget is spent: about 10,000 waits, not 2,000,000.
    #[test]
    fn a_silent_peer_is_given_up_on_at_the_budget_not_after_a_count() {
        let _g = begin();
        let fd = tcp_socket();
        let t0 = azos_drv_irqchip::clint::get_time();
        let mut waits = 0u64;
        let rc = socket::socket_connect_with_yield(fd, &peer(), 45801, || {
            waits += 1;
            let now = azos_drv_irqchip::clint::get_time() + 1_000 * TICKS_PER_US;
            azos_drv_irqchip::clint::set_test_time(now);
        });
        let spent_us = (azos_drv_irqchip::clint::get_time() - t0) / TICKS_PER_US;
        assert_eq!(rc, -1, "nobody answered");
        assert!(
            spent_us >= socket::CONNECT_HANDSHAKE_BUDGET_US
                && spent_us <= socket::CONNECT_HANDSHAKE_BUDGET_US + 1_000,
            "gave up after {spent_us} us of counter time, budget {} us",
            socket::CONNECT_HANDSHAKE_BUDGET_US,
        );
        assert!(waits <= 10_001, "{waits} waits: the bound is the clock, not a count");
        assert_eq!(count_in(tcp::TcpState::Established), 0, "nothing may have connected");
        socket::socket_close(fd);
    }
}

/// Entry points for `tests/fuzz/net-fuzz` (cargo-fuzz). Compiled only under the
/// `--cfg fuzzing` cargo-fuzz passes to every crate it builds; it lives here
/// to reuse this crate's shims (inbound queue, raw TX capture, netcfg) and the
/// real `crates/net/net` modules it already pulls in.
#[cfg(fuzzing)]
pub mod fuzz_entry {
    use super::{arp, dhcp, dns, inbound, ip, net_get_ip, net_get_mac, net_poll, raw, tcp, udp};
    use azos_limits::TCP_MAX_CONNS;

    /// Ports with a listener / bound socket, so a segment or datagram gets
    /// past the port lookup into the state machines.
    const TCP_PORTS: [u16; 2] = [80, 7777];
    const UDP_PORTS: [u16; 3] = [7777, 68, 123];

    static SETUP: std::sync::Once = std::sync::Once::new();
    static LISTENERS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());
    static UDP_SOCKS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

    fn setup() {
        tcp::init(net_get_mac(), net_get_ip());
        for p in TCP_PORTS {
            let i = tcp::listen(p);
            assert!(i >= 0, "listen({p})");
            LISTENERS.lock().unwrap().push(i as usize);
        }
        for p in UDP_PORTS {
            let i = udp::bind(p);
            assert!(i >= 0, "bind({p})");
            UDP_SOCKS.lock().unwrap().push(i as usize);
        }
    }

    fn sum16(data: &[u8], mut acc: u32) -> u32 {
        for c in data.chunks(2) {
            acc += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
        acc
    }

    fn fold(mut acc: u32) -> u16 {
        while acc > 0xFFFF { acc = (acc & 0xFFFF) + (acc >> 16); }
        !(acc as u16)
    }

    /// Recompute the IPv4 header checksum and the TCP/UDP/ICMP checksum of an
    /// Ethernet frame, so mutated packets get past checksum validation and
    /// into the parsers behind it. The fuzzer chooses per frame whether this
    /// runs, so the validation itself is fuzzed too.
    fn fix_checksums(f: &mut [u8]) {
        if f.len() < 14 + 20 || f[12..14] != [0x08, 0x00] { return; }
        let ihl = usize::from(f[14] & 0x0F) * 4;
        if ihl < 20 || 14 + ihl > f.len() { return; }
        f[24] = 0; f[25] = 0;
        let c = fold(sum16(&f[14..14 + ihl], 0));
        f[24..26].copy_from_slice(&c.to_be_bytes());
        let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
        let end = (14 + total).min(f.len());
        if end < 14 + ihl { return; }
        let proto = f[23];
        let (src, dst) = ([f[26], f[27], f[28], f[29]], [f[30], f[31], f[32], f[33]]);
        let l4 = 14 + ihl;
        let off = match proto { 6 => 16, 17 => 6, 1 => 2, _ => return };
        if end < l4 + off + 2 { return; }
        f[l4 + off] = 0; f[l4 + off + 1] = 0;
        let len = (end - l4) as u16;
        let mut acc = if proto == 1 { 0 } else {
            let mut a = sum16(&src, 0);
            a = sum16(&dst, a);
            a + u32::from(proto) + u32::from(len)
        };
        acc = sum16(&f[l4..end], acc);
        let mut c = fold(acc);
        if proto == 17 && c == 0 { c = 0xFFFF; }
        f[l4 + off..l4 + off + 2].copy_from_slice(&c.to_be_bytes());
    }

    /// The sequence number one past the last TCP segment this stack sent
    /// (from the raw TX capture): what a peer that heard it would ACK.
    fn next_seq_we_sent() -> Option<u32> {
        for f in raw::all().iter().rev() {
            if f.len() < 14 + 20 || f[12..14] != [0x08, 0x00] || f[23] != 6 { continue; }
            let ihl = usize::from(f[14] & 0x0F) * 4;
            let l4 = 14 + ihl;
            if f.len() < l4 + 20 { continue; }
            let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
            let doff = usize::from(f[l4 + 12] >> 4) * 4;
            let seq = u32::from_be_bytes([f[l4 + 4], f[l4 + 5], f[l4 + 6], f[l4 + 7]]);
            let len = total.saturating_sub(ihl + doff) as u32;
            let syn_fin = u32::from(f[l4 + 13] & 0x02 != 0) + u32::from(f[l4 + 13] & 0x01 != 0);
            return Some(seq.wrapping_add(len).wrapping_add(syn_fin));
        }
        None
    }

    /// Overwrite a TCP segment's acknowledgment number with `ack`.
    fn set_ack(f: &mut [u8], ack: u32) {
        if f.len() < 14 + 20 || f[12..14] != [0x08, 0x00] || f[23] != 6 { return; }
        let l4 = 14 + usize::from(f[14] & 0x0F) * 4;
        if f.len() >= l4 + 12 { f[l4 + 8..l4 + 12].copy_from_slice(&ack.to_be_bytes()); }
    }

    /// A sequence of Ethernet frames through `net_poll`, the kernel's RX
    /// dispatch (ARP / IPv4 / IPv6). Input: repeated `[flags, len_hi, len_lo,
    /// frame...]`; `flags & 2` makes a TCP segment acknowledge what this stack
    /// last sent (the fuzzer cannot guess the keyed ISN, so without it no
    /// handshake completes), `flags & 1` then fixes the checksums. After the
    /// frames: drain the sockets, run a TCP tick, then abort every
    /// connection the frames opened so the next input starts from the same
    /// state (the listeners and bound sockets persist).
    pub fn eth_frames(mut data: &[u8]) {
        SETUP.call_once(setup);
        arp::cache_reset_for_test();
        ip::arp_txq_reset_for_test();
        inbound::reset();
        raw::reset();
        let mut n = 0;
        while data.len() >= 3 && n < 16 {
            let flags = data[0];
            let len = usize::from(u16::from_be_bytes([data[1], data[2]])).min(data.len() - 3).min(2048);
            let mut frame = data[3..3 + len].to_vec();
            data = &data[3 + len..];
            if flags & 2 != 0 {
                if let Some(a) = next_seq_we_sent() { set_ack(&mut frame, a); }
            }
            if flags & 1 != 0 { fix_checksums(&mut frame); }
            inbound::push_frame(frame);
            net_poll();
            n += 1;
        }
        let mut buf = [0u8; 2048];
        for &s in UDP_SOCKS.lock().unwrap().iter() {
            while udp::recv(s, &mut buf) > 0 {}
        }
        for p in TCP_PORTS {
            let c = tcp::accept(p);
            if c >= 0 { let _ = tcp::recv(c as usize, &mut buf); }
        }
        tcp::tcp_tick();
        let listeners = LISTENERS.lock().unwrap().clone();
        for idx in 0..TCP_MAX_CONNS {
            if !listeners.contains(&idx) { tcp::abort(idx); }
        }
        raw::reset();
    }

    /// The UDP payload parsers that `eth_frames` reaches only with a matching
    /// transaction id: DHCP OFFER/ACK and the DNS answer parser, with the
    /// expected id taken from the input so it matches as often as not.
    pub fn dhcp_dns(data: &[u8]) {
        // A reply is parsed only if it carries the xid of the exchange in
        // progress: start one, and stamp its xid into the input (bytes 4..8,
        // `xid` in the BOOTP header) so the option parser is reached.
        raw::reset();
        dhcp::dhcp_discover();
        let mut d = data.to_vec();
        let sent = raw::all();
        if let Some(f) = sent.last() {
            let ihl = usize::from(f.get(14).copied().unwrap_or(0) & 0x0F) * 4;
            let x = 14 + ihl + 8 + 4;
            if d.len() >= 8 && f.len() >= x + 4 { d[4..8].copy_from_slice(&f[x..x + 4]); }
        }
        if let Some((offered, server)) = dhcp::dhcp_handle_offer(&d) {
            dhcp::dhcp_request(offered, server);
        }
        let _ = dhcp::dhcp_handle_ack(&d);
        let _ = dhcp::dhcp_handle_offer(data);
        raw::reset();
        if data.len() >= 2 {
            let id = u16::from_be_bytes([data[0], data[1]]);
            let _ = dns::parse_response(data, id);
            let _ = dns::parse_response(data, id ^ 1);
        }
    }
}

/// N7 (wave 15): a task waiting on the network is woken by the segment that
/// changes what it waits for, instead of sleeping 1 ms and looking again.
///
/// The kernel's hooks are replaced by fakes: "block until the deadline" is
/// where the receive path runs (the peer's ACK is delivered from inside it,
/// as `net_poll` would deliver it while the sender sleeps), and "wake" records
/// whom the receive path woke. A block that ends with no wake recorded is a
/// block that only its deadline would have ended.
#[cfg(test)]
mod net_wait {
    use super::tcp_rx::*;
    use super::{tcp, wait, wire};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    const ACK: u8 = 0x10;
    const TID: u32 = 42;

    static BLOCKS: AtomicU32 = AtomicU32::new(0);
    static WOKEN_IN_BLOCK: AtomicU32 = AtomicU32::new(0);
    static WAKES: AtomicU32 = AtomicU32::new(0);
    /// (local port, peer port, peer's sequence) for the fake block's ACK.
    static PEER: Mutex<Option<(u16, u16, u32)>> = Mutex::new(None);

    fn current() -> u32 { TID }
    fn wake(tid: u32) {
        assert_eq!(tid, TID, "only the registered waiter may be woken");
        WAKES.fetch_add(1, Ordering::SeqCst);
    }
    /// The peer acknowledges everything sent so far while the sender sleeps.
    fn block(_deadline: u64) -> bool {
        BLOCKS.fetch_add(1, Ordering::SeqCst);
        let before = WAKES.load(Ordering::SeqCst);
        let (port, peer_port, theirs) = PEER.lock().unwrap().expect("peer set");
        if let Some(seg) = outbound().last() {
            let ack_for = seg.seq.wrapping_add(seg.payload_len as u32);
            deliver(&segment(peer_port, port, theirs, ack_for, ACK, 8192, &[]));
        }
        if WAKES.load(Ordering::SeqCst) > before {
            WOKEN_IN_BLOCK.fetch_add(1, Ordering::SeqCst);
        }
        true
    }

    /// Hooks off again even if an assertion fails, so no later test sees them.
    struct Hooks;
    impl Hooks {
        fn install() -> Self {
            for c in [&BLOCKS, &WOKEN_IN_BLOCK, &WAKES] { c.store(0, Ordering::SeqCst); }
            wait::set_hooks(current, block, wake);
            Hooks
        }
    }
    impl Drop for Hooks {
        fn drop(&mut self) { wait::clear_hooks(); }
    }

    /// `send_all_until` (the brain link's sender) blocked on a closed window:
    /// every block is ended by the window-opening ACK's wake, and the old
    /// wait (the caller's `wait_fn`, a 1 ms sleep in the kernel) never runs.
    /// Canary: without the notify in `tcp::handle_checked`, WOKEN_IN_BLOCK
    /// stays 0.
    #[test]
    fn a_window_opening_ack_wakes_the_blocked_sender() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7301, 43001, 0x9a00_0000);
        *PEER.lock().unwrap() = Some((7301, 43001, theirs));
        let _h = Hooks::install();
        let data: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
        let mut polls = 0u32;
        let sent = tcp::send_all_until(idx, &data, 10_000_000, || polls += 1);
        assert_eq!(sent, data.len(), "all 6000 bytes should have been accepted");
        let blocks = BLOCKS.load(Ordering::SeqCst);
        println!("[net-wait] send window: {blocks} blocks, {} ended by a wake, {polls} polls",
                 WOKEN_IN_BLOCK.load(Ordering::SeqCst));
        assert!(blocks > 0, "6000 bytes exceed the initial cwnd: the sender must have waited");
        assert_eq!(WOKEN_IN_BLOCK.load(Ordering::SeqCst), blocks,
            "every wait must be ended by the ACK's wake, not by its deadline");
        assert_eq!(polls, 0, "with the hooks in place the 1 ms poll must not run");
        let _ = wire::sent_count();
    }

    /// No waiter armed: a segment costs no wake at all.
    #[test]
    fn a_segment_with_no_waiter_wakes_nobody() {
        let _g = begin();
        let (idx, _ours, theirs) = establish(7302, 43002, 0x9b00_0000);
        let _h = Hooks::install();
        assert!(tcp::send_data(idx, b"x") > 0);
        let seg = *outbound().last().unwrap();
        deliver(&segment(43002, 7302, theirs, seg.seq.wrapping_add(1), ACK, 8192, &[]));
        assert_eq!(WAKES.load(Ordering::SeqCst), 0, "nobody waits, nobody may be woken");
    }

    /// Every slot taken: the next waiter is not armed and its wait is the
    /// caller's own fallback, exactly as before N7.
    #[test]
    fn a_waiter_beyond_the_slots_falls_back_to_its_own_wait() {
        let _g = begin();
        let _h = Hooks::install();
        let held: Vec<_> = (0..wait::NET_WAIT_SLOTS).map(|_| wait::TCP_WAITERS.arm()).collect();
        assert!(held.iter().all(|a| a.is_armed()));
        let extra = wait::TCP_WAITERS.arm();
        assert!(!extra.is_armed(), "no free slot: unarmed");
        let mut fell_back = 0;
        extra.wait(0, &mut || fell_back += 1);
        assert_eq!(fell_back, 1);
        drop(held);
        assert!(wait::TCP_WAITERS.arm().is_armed(), "slots are returned on drop");
    }
}
