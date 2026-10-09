// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A simulated link between two endpoints: what the send window delivers per
//! round trip, and a lost segment recovered end to end.
//!
//! **The two ends.** In the stack-to-stack runs both are this stack, in its
//! one connection table: an active open from `PORT_A` and a passive one on
//! `PORT_B`, both addressed to `PEER_IP`. Nothing uses `ip::send`'s loopback,
//! which is only for our own address; every segment leaves as a frame through
//! the real `ip.rs`, is taken off the recorded wire here, held for the link's
//! delay, and handed to `handle_checked` as if the peer had sent it. The TCP
//! checksum's pseudo-header is a sum of both addresses, so reversing them
//! leaves it valid.
//!
//! In the model runs the receiver is not this stack but a model: it
//! reassembles without limit and acknowledges every segment with SACK blocks,
//! the way Linux does less delayed ACKs and timestamps. That measures the
//! sender without this stack's own out-of-order queue (four slots of one MSS
//! each; 256 B each until 2026-09-14) in the way.
//!
//! **The numbers** are bytes delivered in order to the receiving application
//! per simulated round trip. The link has a fixed delay and, where stated, a
//! bottleneck rate with a drop-tail queue; no jitter, no reordering. The clock
//! is the test clock. None of this is a wire figure.
//!
//! **Loss** is drawn over the data segments the sender puts on the wire, new
//! or resent, before the bottleneck. The default is pseudo-random: each
//! segment is lost independently from a splitmix64 stream, one run per seed in
//! `LOSS_SEEDS`, reported per seed and as mean, min and max. A periodic
//! pattern (every n-th segment) is kept as a secondary row: it never clusters
//! and it halves a flow at fixed intervals, so it measures one loss pattern,
//! not a loss rate.
//!
//! Only API that predates the send window is used here, so the same file runs
//! against the previous `tcp.rs` for a before/after comparison.

use super::tcp_rx::{begin, OUR_IP, PEER_IP};
use super::{tcp, wire};
use azos_limits::TCP_MAX_CONNS;
use std::collections::VecDeque;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

const TICKS_PER_MS: u64 = 10_000;
/// `RTO_MIN_MS`: the soonest any retransmission timeout can fire.
const RTO_MIN: u64 = 200 * TICKS_PER_MS;

const PORT_A: u16 = 47000;
const PORT_B: u16 = 7990;

/// How often the simulation calls `tcp_tick`.
const TICK: u64 = 5 * TICKS_PER_MS;

/// The seeds of the random-loss runs: each is one run, and the table reports
/// every one and their mean, min and max.
const LOSS_SEEDS: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// A seeded pseudo-random stream, splitmix64 (Steele, Lea and Flood, 2014):
/// the same seed gives the same draws on every host, with no dependency.
/// Shared with `tcp_rto_estimate` and `tcp_two_flow`.
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }

    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// True with probability `ppm` in a million.
    pub(crate) fn chance(&mut self, ppm: u64) -> bool {
        self.next() % 1_000_000 < ppm
    }
}

/// Mean, min and max of `v`.
pub(crate) fn spread(v: &[u64]) -> (f64, u64, u64) {
    let mean = v.iter().sum::<u64>() as f64 / v.len().max(1) as f64;
    (mean, v.iter().copied().min().unwrap_or(0), v.iter().copied().max().unwrap_or(0))
}

/// Byte `off` of the stream the sender offers.
fn pattern(off: u64) -> u8 {
    (off % 251) as u8
}

/// The TCP segment in a recorded Ethernet frame.
fn tcp_of(f: &[u8]) -> Option<Vec<u8>> {
    if f.len() < 34 || u16::from_be_bytes([f[12], f[13]]) != 0x0800 || f[14 + 9] != 6 {
        return None;
    }
    let ihl = ((f[14] & 0x0F) as usize) * 4;
    let end = (14 + u16::from_be_bytes([f[16], f[17]]) as usize).min(f.len());
    Some(f[14 + ihl..end].to_vec())
}

/// Everything the stack sent since the last call.
fn take_segments() -> Vec<Vec<u8>> {
    let frames = std::mem::take(&mut *crate::raw::FRAMES.lock().unwrap());
    frames.iter().filter_map(|f| tcp_of(f)).collect()
}

fn src_port(s: &[u8]) -> u16 {
    u16::from_be_bytes([s[0], s[1]])
}

fn payload_of(s: &[u8]) -> &[u8] {
    &s[((s[12] >> 4) as usize) * 4..]
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// The acknowledgement number and SACK blocks of a segment carrying a SACK
/// option; `None` for one without.
fn sack_of(s: &[u8]) -> Option<(u32, Vec<(u32, u32)>)> {
    let end = (((s[12] >> 4) as usize) * 4).min(s.len());
    let mut i = 20;
    while i < end {
        match s[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let len = *s.get(i + 1)? as usize;
                if len < 2 || i + len > end {
                    return None;
                }
                if kind == 5 {
                    let blocks = s[i + 2..i + len].chunks_exact(8).map(|b| (be32(&b[..4]), be32(&b[4..]))).collect();
                    return Some((be32(&s[8..12]), blocks));
                }
                i += len;
            }
        }
    }
    None
}

/// One direction of the link: an optional bottleneck with a drop-tail queue,
/// then a fixed delay. Arrival order is send order. Shared with
/// `tcp_two_flow`.
pub(crate) struct Pipe {
    delay: u64,
    /// Serialisation time per byte at the bottleneck; 0 for none.
    ticks_per_byte: u64,
    queue_limit: usize,
    busy_until: u64,
    /// (leaves the bottleneck, arrives, segment)
    flight: VecDeque<(u64, u64, Vec<u8>)>,
    pub(crate) dropped: usize,
}

impl Pipe {
    pub(crate) fn new(delay: u64, ticks_per_byte: u64, queue_limit: usize) -> Self {
        Pipe { delay, ticks_per_byte, queue_limit, busy_until: 0, flight: VecDeque::new(), dropped: 0 }
    }

    pub(crate) fn push(&mut self, now: u64, seg: Vec<u8>) {
        if self.ticks_per_byte != 0 {
            let waiting = self.flight.iter().rev().take_while(|f| f.0 > now).count();
            if waiting >= self.queue_limit {
                self.dropped += 1;
                return;
            }
        }
        // Ethernet and IPv4 headers ride on top of the segment.
        let leaves = self.busy_until.max(now) + (seg.len() as u64 + 34) * self.ticks_per_byte;
        self.busy_until = leaves;
        self.flight.push_back((leaves, leaves + self.delay, seg));
    }

    pub(crate) fn next_arrival(&self) -> Option<u64> {
        self.flight.front().map(|f| f.1)
    }

    pub(crate) fn pop_due(&mut self, now: u64) -> Option<Vec<u8>> {
        if self.flight.front()?.1 <= now {
            self.flight.pop_front().map(|f| f.2)
        } else {
            None
        }
    }
}

/// A receiver that holds everything, acknowledges every segment, and SACKs
/// what it holds with the most recent range first (RFC 2018 §4).
struct Model {
    iss: u32,
    base: u32,
    synced: bool,
    /// Stream offset of the next byte expected.
    rcv_nxt: u64,
    /// Ranges held past `rcv_nxt`: sorted, disjoint.
    held: Vec<(u64, u64)>,
    recent: u64,
    corrupt: bool,
}

impl Model {
    fn new() -> Self {
        Model { iss: 0x5EED_0000, base: 0, synced: false, rcv_nxt: 0, held: Vec::new(), recent: 0, corrupt: false }
    }

    fn build(&self, seq: u32, ack: u32, flags: u8, window: u16, opts: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(20 + opts.len());
        s.extend_from_slice(&PORT_B.to_be_bytes());
        s.extend_from_slice(&PORT_A.to_be_bytes());
        s.extend_from_slice(&seq.to_be_bytes());
        s.extend_from_slice(&ack.to_be_bytes());
        s.push((((20 + opts.len()) / 4) as u8) << 4);
        s.push(flags);
        s.extend_from_slice(&window.to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0]);
        s.extend_from_slice(opts);
        let pseudo = wire::pseudo_checksum(&PEER_IP, &OUR_IP, wire::IP_PROTO_TCP, s.len() as u16);
        let ck = tcp::tcp_checksum(pseudo, &s);
        s[16..18].copy_from_slice(&ck.to_be_bytes());
        s
    }

    fn on_segment(&mut self, s: &[u8], replies: &mut Vec<Vec<u8>>) {
        let seq = be32(&s[4..8]);
        if s[13] & SYN != 0 {
            self.base = seq.wrapping_add(1);
            self.synced = true;
            // MSS 1460, Window Scale 7, SACK-Permitted.
            let opts = [2, 4, 0x05, 0xB4, 1, 3, 3, 7, 1, 1, 4, 2];
            replies.push(self.build(self.iss, self.base, SYN | ACK, 65535, &opts));
            return;
        }
        let payload = payload_of(s);
        if !self.synced || payload.is_empty() {
            return;
        }
        let start = seq.wrapping_sub(self.base) as u64;
        for (i, &b) in payload.iter().enumerate() {
            if b != pattern(start + i as u64) {
                self.corrupt = true;
            }
        }
        let end = start + payload.len() as u64;
        if end > self.rcv_nxt {
            let mut l = start.max(self.rcv_nxt);
            let mut r = end;
            self.recent = l;
            let mut kept = Vec::with_capacity(self.held.len() + 1);
            for &(a, b) in &self.held {
                if a <= r && l <= b {
                    l = l.min(a);
                    r = r.max(b);
                } else {
                    kept.push((a, b));
                }
            }
            kept.push((l, r));
            kept.sort();
            self.held = kept;
            while let Some(&(a, b)) = self.held.first() {
                if a > self.rcv_nxt {
                    break;
                }
                self.rcv_nxt = self.rcv_nxt.max(b);
                self.held.remove(0);
            }
        }
        let mut blocks = self.held.clone();
        blocks.sort_by_key(|&(a, b)| (!(a <= self.recent && self.recent < b), std::cmp::Reverse(a)));
        let mut opts = Vec::new();
        if !blocks.is_empty() {
            let k = blocks.len().min(4);
            opts.extend_from_slice(&[1, 1, 5, 2 + 8 * k as u8]);
            for &(a, b) in &blocks[..k] {
                opts.extend_from_slice(&self.base.wrapping_add(a as u32).to_be_bytes());
                opts.extend_from_slice(&self.base.wrapping_add(b as u32).to_be_bytes());
            }
        }
        // 1024 << 7: a 128 KiB window, never closing.
        let ack = self.base.wrapping_add(self.rcv_nxt as u32);
        replies.push(self.build(self.iss.wrapping_add(1), ack, ACK, 1024, &opts));
    }
}

#[derive(Clone, Copy)]
enum Receiver {
    Stack,
    Model,
}

/// Which of the data segments the sender puts on the wire, new or resent, are
/// lost.
#[derive(Clone, Copy)]
enum Loss {
    None,
    /// Each one independently, with probability `ppm` in a million, drawn from
    /// a `SplitMix64` seeded with `seed`.
    Random { ppm: u64, seed: u64 },
    /// Every `n`-th one.
    Periodic(usize),
    /// Exactly the ones a test names, by index.
    Script(fn(usize) -> bool),
}

struct Scenario {
    receiver: Receiver,
    rtt_ms: u64,
    /// Bottleneck rate in Mbit/s; 0 for none.
    mbps: u64,
    queue: usize,
    loss: Loss,
    /// Round trips to run once established.
    rtts: u64,
    /// Stop offering after this many bytes.
    limit: u64,
}

#[derive(Debug)]
struct Report {
    delivered: u64,
    /// SACK-bearing ACKs from this stack's receiver that left out bytes an
    /// earlier block had reported and the cumulative ACK had not yet passed:
    /// reneging, seen from the wire.
    reneged: usize,
    data_frames: usize,
    /// Segments from the receiving side with no payload: its ACKs (N6).
    pure_acks: usize,
    lost: usize,
    dropped: usize,
    corrupt: bool,
    /// Ticks from established until `limit` bytes were delivered.
    done_after: Option<u64>,
    /// Ticks from the first lost segment leaving to the first later segment
    /// that carries its first byte again.
    repair_after: Option<u64>,
}

fn run(sc: &Scenario) -> Report {
    let mut now = 50_000_000u64;
    azos_drv_irqchip::clint::set_test_time(now);
    let rtt = sc.rtt_ms * TICKS_PER_MS;
    let ticks_per_byte = if sc.mbps == 0 {
        0
    } else {
        8 * azos_drv_sys::timebase::TIMER_FREQ / (sc.mbps * 1_000_000)
    };
    let mut ab = Pipe::new(rtt / 2, ticks_per_byte, sc.queue);
    let mut ba = Pipe::new(rtt / 2, 0, 0);
    let mut model = match sc.receiver {
        Receiver::Model => Some(Model::new()),
        Receiver::Stack => {
            assert!(tcp::listen(PORT_B) >= 0);
            None
        }
    };
    let a = tcp::connect(PEER_IP, PORT_B, PORT_A);
    assert!(a >= 0, "no slot to dial out");
    let a = a as usize;

    let mut b: Option<usize> = None;
    let mut start: Option<u64> = None;
    let mut offered = 0u64;
    let mut delivered = 0u64;
    let mut stack_corrupt = false;
    let (mut data_frames, mut lost) = (0usize, 0usize);
    let mut pure_acks = 0usize;
    let mut done_after = None;
    let mut lost_at: Option<(u32, u64)> = None;
    let mut repair_after = None;
    // The blocks of the last SACK-bearing ACK from the stack's receiver.
    let mut reported: Vec<(u32, u32)> = Vec::new();
    let mut reneged = 0usize;
    let mut out = [0u8; 1460];
    let mut inb = [0u8; 4096];
    let give_up = now + 120_000 * TICKS_PER_MS;
    let mut loss_rng = SplitMix64::new(match sc.loss {
        Loss::Random { seed, .. } => seed,
        _ => 0,
    });

    loop {
        let established = tcp::conn_state(a) == tcp::TcpState::Established;
        if established && start.is_none() {
            start = Some(now);
        }
        if established {
            while offered < sc.limit {
                let n = ((sc.limit - offered) as usize).min(out.len());
                for (i, o) in out[..n].iter_mut().enumerate() {
                    *o = pattern(offered + i as u64);
                }
                let r = tcp::send_data(a, &out[..n]);
                if r <= 0 {
                    break;
                }
                offered += r as u64;
            }
        }
        match model.as_ref() {
            Some(m) => delivered = m.rcv_nxt,
            None => {
                if b.is_none() {
                    b = (0..TCP_MAX_CONNS)
                        .find(|&i| i != a && tcp::conn_state(i) == tcp::TcpState::Established);
                }
                if let Some(b) = b {
                    loop {
                        let n = tcp::recv(b, &mut inb);
                        if n <= 0 {
                            break;
                        }
                        for (i, &x) in inb[..n as usize].iter().enumerate() {
                            if x != pattern(delivered + i as u64) {
                                stack_corrupt = true;
                            }
                        }
                        delivered += n as u64;
                    }
                }
            }
        }
        for s in take_segments() {
            if src_port(&s) == PORT_A {
                let len = payload_of(&s).len() as u32;
                if len != 0 {
                    let seq = be32(&s[4..8]);
                    if let Some((first, sent_at)) = lost_at {
                        if repair_after.is_none() && first.wrapping_sub(seq) < len {
                            repair_after = Some(now - sent_at);
                        }
                    }
                    let k = data_frames;
                    data_frames += 1;
                    let lose = match sc.loss {
                        Loss::None => false,
                        Loss::Random { ppm, .. } => loss_rng.chance(ppm),
                        Loss::Periodic(n) => k % n == n - 1,
                        Loss::Script(f) => f(k),
                    };
                    if lose {
                        lost += 1;
                        if lost_at.is_none() {
                            lost_at = Some((seq, now));
                        }
                        continue;
                    }
                }
                ab.push(now, s);
            } else {
                if payload_of(&s).is_empty() {
                    pure_acks += 1;
                }
                // The receiver's SACK option names every range it holds (four
                // entries fit four blocks). A range reported earlier that is
                // still above the cumulative ACK must be inside a block now.
                // ACKs without the option (a window update) say nothing.
                if let Some((ack, blocks)) = sack_of(&s) {
                    let rel = |x: u32| x.wrapping_sub(ack) as i32 as i64;
                    let withdrawn = reported.iter().any(|&(a, b)| {
                        let (a, b) = (rel(a).max(0), rel(b));
                        b > a && !blocks.iter().any(|&(l, r)| rel(l) <= a && b <= rel(r))
                    });
                    reneged += withdrawn as usize;
                    reported = blocks;
                }
                ba.push(now, s);
            }
        }

        if let Some(t0) = start {
            if delivered >= sc.limit && done_after.is_none() {
                done_after = Some(now - t0);
                break;
            }
            if now >= t0 + sc.rtts * rtt {
                break;
            }
        }
        if now >= give_up {
            break;
        }

        let next_tick = (now / TICK + 1) * TICK;
        now = [ab.next_arrival(), ba.next_arrival(), Some(next_tick)]
            .into_iter()
            .flatten()
            .min()
            .unwrap()
            .max(now);
        azos_drv_irqchip::clint::set_test_time(now);
        while let Some(s) = ab.pop_due(now) {
            match model.as_mut() {
                Some(m) => {
                    let mut replies = Vec::new();
                    m.on_segment(&s, &mut replies);
                    for r in replies {
                        ba.push(now, r);
                    }
                }
                None => tcp::handle_checked(&PEER_IP, &OUR_IP, &s),
            }
        }
        while let Some(s) = ba.pop_due(now) {
            tcp::handle_checked(&PEER_IP, &OUR_IP, &s);
        }
        // What the kernel's `net_poll` does when its drain ends (N6): the
        // ACKs this pass held leave now.
        if tcp::TCP_DELACK_PASS_FLUSH {
            tcp::flush_held_acks(false);
        }
        if now % TICK == 0 {
            tcp::tcp_tick();
        }
    }

    Report {
        delivered,
        reneged,
        data_frames,
        pure_acks,
        lost,
        dropped: ab.dropped,
        corrupt: stack_corrupt || model.map_or(false, |m| m.corrupt),
        done_after,
        repair_after,
    }
}

/// Bytes delivered per round trip, to this stack and to the model receiver,
/// over a clean link; random loss at a 1% and a 2% mean, one run per seed in
/// `LOSS_SEEDS` and their mean, min and max; a periodic 1-in-100 loss; and a
/// 10 Mbit/s bottleneck with a 32-frame queue. Printed, for the record;
/// asserted only to arrive intact.
///
/// The periodic 1-in-100 rows were the "1% loss" rows until 2026-09-14 (5,526
/// B/RTT to this stack, 14,585 to the model). They stay, relabelled, as the
/// fixed point a change is compared against.
#[test]
fn bytes_delivered_per_round_trip() {
    const RTTS: u64 = 200;
    for (who, receiver) in [("stack", Receiver::Stack), ("model", Receiver::Model)] {
        let one = |name: &str, mbps: u64, queue: usize, loss: Loss| -> u64 {
            let _g = begin();
            let r = run(&Scenario {
                receiver, rtt_ms: 20, mbps, queue, loss, rtts: RTTS, limit: u64::MAX,
            });
            println!(
                "[tcp-throughput] {name:40} {:>7} B/RTT over {RTTS} RTTs of 20 ms \
                 ({} B, {} data frames, {} pure ACKs, {} lost, {} queue drops)",
                r.delivered / RTTS, r.delivered, r.data_frames, r.pure_acks, r.lost, r.dropped,
            );
            assert!(!r.corrupt, "{name}: a byte arrived that the sender never offered at that offset");
            assert!(r.delivered > 0, "{name}: nothing was delivered");
            assert_eq!(
                r.reneged, 0,
                "{name}: the receiver withdrew a range it had reported in a SACK block, so the sender \
                 held as delivered bytes the receiver no longer had",
            );
            r.delivered / RTTS
        };
        one(&format!("{who}, clean"), 0, 0, Loss::None);
        for (pct, ppm) in [(1, 10_000u64), (2, 20_000)] {
            let per_seed: Vec<u64> = LOSS_SEEDS
                .iter()
                .map(|&seed| {
                    one(&format!("{who}, {pct}% random loss, seed {seed}"), 0, 0, Loss::Random { ppm, seed })
                })
                .collect();
            let (mean, min, max) = spread(&per_seed);
            println!(
                "[tcp-throughput] {who}, {pct}% random loss over {} seeds: mean {mean:.0} B/RTT, \
                 min {min}, max {max}",
                LOSS_SEEDS.len(),
            );
        }
        one(&format!("{who}, periodic 1-in-100 loss"), 0, 0, Loss::Periodic(100));
        one(&format!("{who}, 10 Mbit/s, 32-frame queue"), 10, 32, Loss::None);
    }
}

/// N6 (wave 15): a bulk transfer to this stack's receiver costs at most about
/// one pure ACK per two data segments (RFC 1122 §4.2.3.2), not one per segment
/// plus one per `recv` as before, and the window stays as open as it was.
///
/// Measured on this harness, 200 RTTs of 20 ms, clean: 23,648 pure ACKs for
/// 17,481 data frames (1.35 per frame) and 126,961 B/RTT before; 9,851 for
/// 17,268 (0.57) and 125,406 B/RTT after. Canary: `CONFIG_TCP_DELACK_MS=0`
/// (acknowledge every segment at once) fails the ACK bound.
#[test]
fn a_bulk_transfer_is_acknowledged_every_second_segment() {
    if azos_limits::TCP_DELACK_MS == 0 {
        println!("[tcp-throughput] delayed ACK configured off (the canary): the ACK bound below must fail");
    }
    let _g = begin();
    let r = run(&Scenario {
        receiver: Receiver::Stack, rtt_ms: 20, mbps: 0, queue: 0, loss: Loss::None,
        rtts: 200, limit: u64::MAX,
    });
    println!("[tcp-throughput] delayed ACK: {} pure ACKs for {} data frames, {} B/RTT",
             r.pure_acks, r.data_frames, r.delivered / 200);
    assert!(!r.corrupt);
    assert!(r.pure_acks * 10 <= r.data_frames * 6,
        "{} pure ACKs for {} data frames: more than ~one per two segments",
        r.pure_acks, r.data_frames);
    // The window must not close for want of an update: within 2% of what the
    // ring allows per round trip (the per-segment-ACK figure, 126,961).
    assert!(r.delivered / 200 >= 124_000, "{} B/RTT: window updates held too long", r.delivered / 200);
}

/// One data segment in the middle of a transfer is lost. The stream must
/// arrive complete and byte for byte, and the hole must be repaired by the
/// duplicate ACKs of the segments behind it, not by a timeout.
///
/// "Not by a timeout" is measured, not inferred from the total time: with a
/// 20 ms round trip the RTO settles at its 200 ms floor, and a stop-and-wait
/// sender that waits it out still finishes 40 KiB well inside a second. What
/// cannot happen before the floor is a timeout, so the first resend of the
/// lost byte must leave sooner than that.
#[test]
fn a_lost_middle_segment_is_recovered_with_the_stream_intact() {
    let _g = begin();
    fn sixth(k: usize) -> bool {
        k == 5
    }
    let r = run(&Scenario {
        receiver: Receiver::Stack, rtt_ms: 20, mbps: 0, queue: 0, loss: Loss::Script(sixth),
        rtts: 1_000, limit: 40_000,
    });
    println!(
        "[tcp-throughput] lost middle segment: complete after {:?} ticks, lost byte resent after \
         {:?} ticks ({r:?})", r.done_after, r.repair_after,
    );
    assert_eq!(r.lost, 1, "precondition: exactly one segment was lost");
    assert!(!r.corrupt, "the stream was corrupted");
    assert_eq!(r.reneged, 0, "the receiver withdrew a range it had reported in a SACK block");
    assert_eq!(r.delivered, 40_000, "the stream must arrive complete");
    let repair = r.repair_after.expect("the lost segment was never resent");
    assert!(repair < RTO_MIN,
        "the lost segment was resent {} ms after it left: that is a timeout, not a \
         fast retransmit", repair / TICKS_PER_MS);
}
