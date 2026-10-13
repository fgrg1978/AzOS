// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The retransmission timer's round-trip estimate with several segments in
//! flight: the SRTT, RTTVAR and RTO this stack keeps (`tcp::conn_rtt`) against
//! a path whose round-trip time is scripted, so the right answer is known.
//!
//! **What limits the samples.** `tcp.rs` times one segment at a time
//! (RFC 6298 §3). A sample needs the ACK of that one segment, the next
//! measurement starts only with the next new segment sent, and any
//! retransmission ends the measurement in progress (Karn). With N segments in
//! flight that is at most one sample per round trip out of N ACKs, and none
//! across a loss.
//!
//! **Two estimates beside it**, neither driving a timer:
//! - *every ACK*: the same RFC 6298 arithmetic, integer for integer, fed from
//!   every ACK that acknowledges new data, as RFC 7323 timestamps would allow.
//!   The receiver echoes the send time of the segment RFC 7323 §4.3 names,
//!   carried beside the ACK rather than in an option.
//! - *1 ms floor*: the stack's own samples, with the variance term's floor at
//!   the clock granularity G = 1 ms, as RFC 6298 §2.3 writes it — this stack's
//!   formula until 2026-09-14, when the floor became `RTO_VAR_FLOOR_MS`
//!   (200 ms). It separates what the samples cost from what the formula costs.
//!
//! Each has an RFC 6298 §5 timer of its own, never backed off, armed when data
//! leaves with nothing in flight and restarted whenever an ACK restarts the
//! stack's (`RttEstimate::timer_start`): an ACK of new data or, since
//! 2026-09-14, one reporting new SACKed bytes during SACK recovery;
//! an ACK that arrives after it would have expired is counted, and counted
//! again as spurious when a copy of the data that was not lost had already
//! left by then, other than one the stack's own timer resent: that copy would
//! not exist had this estimate's timer been the one running.
//!
//! **The path.** Half the RTT each way, arrival order kept; jitter adds a
//! uniform extra delay to each segment on the way out. The receiver is a model
//! that acknowledges every segment at once with SACK blocks, without window
//! scaling. Two senders: *bulk* writes whenever the window has room and the
//! window is N segments, so with no bottleneck to space them the flight leaves
//! and returns as a burst of N; *paced* writes one segment every RTT/N of the
//! path's slowest RTT into a 44-segment window, so N segments are spread over
//! the round trip. In the lossy runs each data segment on the wire, new or
//! resent, is dropped with probability 2%, drawn from a splitmix64 stream: one
//! run per seed in `LOSS_SEEDS`, each printed, then their mean, min and max.
//! A periodic loss of every 50th data segment, the pattern these runs were
//! first measured with, is kept as a secondary run: it never clusters, and it
//! halves a flow at fixed intervals. `tcp_tick` runs every 5 ms. The clock is
//! the test clock.
//!
//! **Asserted** is only what makes the numbers trustworthy: the stream arrives
//! intact; every sample the stack takes moves its estimate exactly as the
//! harness predicts from the send time of the timed segment; and with one
//! segment in flight and nothing resent, the every-ACK estimate ends where the
//! stack's does. How good the estimate is gets printed.

use super::tcp_rx::{begin, OUR_IP, PEER_IP};
use super::tcp_throughput::{spread, SplitMix64};
use super::{tcp, wire};
use std::collections::{HashMap, VecDeque};

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

const TICKS_PER_MS: u64 = 10_000;
/// How often the simulation calls `tcp_tick`.
const TICK: u64 = 5 * TICKS_PER_MS;

const PORT_A: u16 = 47300;
const PORT_B: u16 = 7993;
const MSS: u64 = 1460;

/// The random-loss runs lose each data segment on the wire with this
/// probability, in a million: 2%.
const LOSS_PPM: u64 = 20_000;
/// One random-loss run per seed.
const LOSS_SEEDS: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
/// The secondary, periodic run loses every `LOSS_EVERY`-th data segment on
/// the wire.
const LOSS_EVERY: usize = 50;

/// Which data segments on the wire, new or resent, are lost.
#[derive(Clone, Copy, PartialEq)]
enum Loss {
    None,
    /// Each one independently, with probability `ppm` in a million, drawn from
    /// a `SplitMix64` seeded with `seed`.
    Random { ppm: u64, seed: u64 },
    /// Every `n`-th one.
    Periodic(usize),
}

impl Loss {
    fn label(&self) -> String {
        match *self {
            Loss::None => "no loss".to_string(),
            Loss::Random { ppm, seed } => format!("{}% random loss, seed {seed}", ppm / 10_000),
            Loss::Periodic(n) => format!("periodic 1-in-{n} loss"),
        }
    }
}
/// The paced sender's window, in segments: the most an unscaled window holds.
const PACED_WINDOW: u64 = 44;

// RFC 6298 as `tcp::update_rtt` computes it.
const RTT_SCALE: u64 = 1000;
const RTO_INITIAL: u64 = 1_000 * TICKS_PER_MS;
const RTO_MIN: u64 = 200 * TICKS_PER_MS;
/// `RTO_VAR_FLOOR_MS`: the least the variance term adds to SRTT.
const VAR_FLOOR: u64 = 200 * TICKS_PER_MS;
/// The clock granularity G, the variance term's only floor before 2026-09-14.
const G: u64 = TICKS_PER_MS;
const RTO_MAX: u64 = 60_000 * TICKS_PER_MS;

fn pattern(off: u64) -> u8 {
    (off % 251) as u8
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn ms(ticks: u64) -> f64 {
    ticks as f64 / TICKS_PER_MS as f64
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

fn payload_of(s: &[u8]) -> &[u8] {
    &s[((s[12] >> 4) as usize) * 4..]
}

/// An RFC 6298 estimate: SRTT and RTTVAR in ticks × `RTT_SCALE`, RTO in ticks,
/// and the least the variance term may add.
#[derive(Clone, Copy, PartialEq, Debug)]
struct Est {
    measured: bool,
    srtt: u64,
    rttvar: u64,
    rto: u64,
    floor: u64,
}

impl Est {
    fn new(floor: u64) -> Self {
        Est { measured: false, srtt: 0, rttvar: 0, rto: RTO_INITIAL, floor }
    }

    /// The stack's estimate, whose floor is `RTO_VAR_FLOOR_MS`.
    fn of(r: tcp::RttEstimate) -> Self {
        Est { measured: r.measured, srtt: r.srtt, rttvar: r.rttvar, rto: r.rto_ticks, floor: VAR_FLOOR }
    }

    /// `tcp::update_rtt`, step for step.
    fn sample(&mut self, ticks: u64) {
        let r = ticks * RTT_SCALE;
        if !self.measured {
            self.srtt = r;
            self.rttvar = r / 2;
            self.measured = true;
        } else {
            let diff = self.srtt.abs_diff(r);
            self.rttvar = (self.rttvar * 3 + diff) / 4;
            self.srtt = (self.srtt * 7 + r) / 8;
        }
        let k = (self.rttvar * 4 / RTT_SCALE).max(self.floor);
        self.rto = (self.srtt / RTT_SCALE + k).clamp(RTO_MIN, RTO_MAX);
    }

    fn srtt_ms(&self) -> f64 {
        ms(self.srtt / RTT_SCALE)
    }

    fn rttvar_ms(&self) -> f64 {
        ms(self.rttvar / RTT_SCALE)
    }
}

/// The round-trip time of the path, in ms, as a function of the time since
/// the connection was established.
#[derive(Clone, Copy)]
enum Shape {
    Constant(u64),
    /// `from` until `at` ms, `to` after.
    Step { from: u64, to: u64, at: u64 },
    /// `base`, plus a uniform 0..=`spread` on each segment's way out.
    Jitter { base: u64, spread: u64 },
}

impl Shape {
    fn label(&self) -> String {
        match *self {
            Shape::Constant(r) => format!("constant {r} ms"),
            Shape::Step { from, to, .. } => format!("step {from} -> {to} ms"),
            Shape::Jitter { base, spread } => format!("jitter {base} + 0..{spread} ms"),
        }
    }

    /// The RTT without jitter at `t` ms.
    fn base(&self, t: u64) -> u64 {
        match *self {
            Shape::Constant(r) => r,
            Shape::Step { from, to, at } => if t < at { from } else { to },
            Shape::Jitter { base, .. } => base,
        }
    }

    fn mean(&self, t: u64) -> f64 {
        match *self {
            Shape::Jitter { base, spread } => base as f64 + spread as f64 / 2.0,
            _ => self.base(t) as f64,
        }
    }

    fn slowest(&self, t: u64) -> u64 {
        match *self {
            Shape::Jitter { base, spread } => base + spread,
            _ => self.base(t),
        }
    }

    fn step(&self) -> Option<(u64, u64)> {
        match *self {
            Shape::Step { to, at, .. } => Some((at, to)),
            _ => None,
        }
    }

    /// The paced sender's interval for `n` segments per round trip of the
    /// slowest RTT the path has, in ticks.
    fn pace(&self, n: u64) -> u64 {
        let rtt = match *self {
            Shape::Constant(r) => r,
            Shape::Step { from, to, .. } => from.max(to),
            Shape::Jitter { base, spread } => base + spread / 2,
        };
        rtt * TICKS_PER_MS / n
    }

    /// How long a run lasts, in ms after establishment.
    fn duration(&self) -> u64 {
        match *self {
            Shape::Constant(r) => (300 * r).clamp(3_000, 60_000),
            Shape::Step { to, at, .. } => at + (100 * to).max(6_000),
            Shape::Jitter { base, spread } => 300 * (base + spread / 2),
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Sender {
    Bulk,
    Paced,
}

/// A receiver that holds everything, acknowledges every segment with the
/// ranges it holds as SACK blocks, and keeps RFC 7323's TS.Recent.
struct Receiver {
    window: u16,
    iss: u32,
    base: u32,
    synced: bool,
    rcv_nxt: u64,
    held: Vec<(u64, u64)>,
    recent: u64,
    /// The send time of the segment the next ACK's timestamp would echo.
    ts_recent: u64,
    corrupt: bool,
    /// Data segments that brought nothing the receiver did not hold.
    duplicates: u64,
}

impl Receiver {
    fn new(window: u16) -> Self {
        Receiver {
            window, iss: 0x0BAD_5EED, base: 0, synced: false, rcv_nxt: 0, held: Vec::new(),
            recent: 0, ts_recent: 0, corrupt: false, duplicates: 0,
        }
    }

    fn build(&self, seq: u32, ack: u32, flags: u8, opts: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(20 + opts.len());
        s.extend_from_slice(&PORT_B.to_be_bytes());
        s.extend_from_slice(&PORT_A.to_be_bytes());
        s.extend_from_slice(&seq.to_be_bytes());
        s.extend_from_slice(&ack.to_be_bytes());
        s.push((((20 + opts.len()) / 4) as u8) << 4);
        s.push(flags);
        s.extend_from_slice(&self.window.to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 0]);
        s.extend_from_slice(opts);
        let pseudo = wire::pseudo_checksum(&PEER_IP, &OUR_IP, wire::IP_PROTO_TCP, s.len() as u16);
        let ck = tcp::tcp_checksum(pseudo, &s);
        s[16..18].copy_from_slice(&ck.to_be_bytes());
        s
    }

    /// The reply to `s`, which left the sender at `sent`, and the send time
    /// that reply's timestamp echo would carry.
    fn on_segment(&mut self, s: &[u8], sent: u64) -> Option<(Vec<u8>, u64)> {
        let seq = be32(&s[4..8]);
        if s[13] & SYN != 0 {
            self.base = seq.wrapping_add(1);
            self.synced = true;
            // MSS 1460 and SACK-Permitted. No Window Scale: the window field
            // is the flight cap in octets.
            let opts = [2, 4, 0x05, 0xB4, 1, 1, 4, 2];
            return Some((self.build(self.iss, self.base, SYN | ACK, &opts), 0));
        }
        let payload = payload_of(s);
        if !self.synced || payload.is_empty() {
            return None;
        }
        let start = seq.wrapping_sub(self.base) as u64;
        let end = start + payload.len() as u64;
        for (i, &b) in payload.iter().enumerate() {
            if b != pattern(start + i as u64) {
                self.corrupt = true;
            }
        }
        if end <= self.rcv_nxt || self.held.iter().any(|&(a, b)| a <= start && end <= b) {
            self.duplicates += 1;
        }
        // RFC 7323 §4.3: TS.Recent follows a segment that starts at or before
        // the last ACK sent, which here is always RCV.NXT, and never one past
        // a hole.
        if start <= self.rcv_nxt && sent >= self.ts_recent {
            self.ts_recent = sent;
        }
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
        let ack = self.base.wrapping_add(self.rcv_nxt as u32);
        Some((self.build(self.iss.wrapping_add(1), ack, ACK, &opts), self.ts_recent))
    }
}

/// A segment on its way to the receiver.
struct Out {
    arrive: u64,
    seg: Vec<u8>,
    sent: u64,
    /// The stack's RTO and the every-ACK RTO when it left.
    rto: u64,
    rto_every: u64,
    /// New data, not a resend.
    first: bool,
}

/// An ACK on its way back.
struct Back {
    arrive: u64,
    seg: Vec<u8>,
    echo: u64,
}

/// A data segment the stack put on the wire.
struct Tx {
    start: u64,
    end: u64,
    sent: u64,
    lost: bool,
    /// Sent by `tcp_tick`: the stack's retransmission timer resent it.
    timer: bool,
}

/// Had a copy of stream offset `una` that was not lost left by `by`? Then a
/// timer that expired at `by` fired while the data or its ACK was on its way.
/// `timer_copies`: whether a copy the stack's own timer resent counts; one sent
/// at `by` itself never does, being the resend of the timeout judged.
fn on_its_way(txs: &[Tx], una: u64, by: u64, timer_copies: bool) -> bool {
    txs.iter().rev().any(|x| {
        x.start <= una && una < x.end && !x.lost && x.sent <= by
            && if x.timer { timer_copies && x.sent < by } else { true }
    })
}

/// What one estimate did over a run.
#[derive(Default)]
struct Track {
    samples: u64,
    last: u64,
    gap: u64,
    gap_rtts: f64,
    /// (ms since establishment, SRTT in ms) at every tick once it had a sample.
    srtt: Vec<(u64, f64)>,
    ticks: u64,
    /// Ticks with the RTO below the slowest RTT of the path.
    below: u64,
    /// New segments whose round trip took longer than the RTO they left under.
    slower: u64,
    /// ACKs restarting the stack's timer that arrived after this estimate's
    /// had expired.
    late: u64,
    spurious_late: u64,
    at_step: Option<u64>,
    /// (ms after the step, samples since the step) when SRTT first came
    /// within 10% of the new RTT.
    adapt: Option<(u64, u64)>,
}

impl Track {
    fn sampled(&mut self, now: u64, rtt_ms: f64) {
        self.samples += 1;
        let gap = now - self.last;
        if gap > self.gap {
            self.gap = gap;
            self.gap_rtts = ms(gap) / rtt_ms;
        }
        self.last = now;
    }

    fn tick(&mut self, t: u64, e: &Est, slowest: u64, step: Option<(u64, u64)>) {
        if !e.measured {
            return;
        }
        self.srtt.push((t, e.srtt_ms()));
        self.ticks += 1;
        if e.rto < slowest {
            self.below += 1;
        }
        if let Some((at, to)) = step {
            if t >= at {
                let s0 = *self.at_step.get_or_insert(self.samples);
                if self.adapt.is_none() && (e.srtt_ms() - to as f64).abs() * 10.0 <= to as f64 {
                    self.adapt = Some((t - at, self.samples - s0));
                }
            }
        }
    }

    fn ack(&mut self, deadline: Option<u64>, now: u64, una: u64, txs: &[Tx]) {
        if let Some(d) = deadline {
            if now > d {
                self.late += 1;
                if on_its_way(txs, una, d, false) {
                    self.spurious_late += 1;
                }
            }
        }
    }

    fn close_gap(&mut self, now: u64, rtt_ms: f64) {
        let gap = now - self.last;
        if gap > self.gap {
            self.gap = gap;
            self.gap_rtts = ms(gap) / rtt_ms;
        }
    }

    /// Mean of |SRTT - reference| / reference over the ticks with a sample, %.
    fn error(&self, reference: &dyn Fn(u64) -> f64) -> f64 {
        if self.srtt.is_empty() {
            return 0.0;
        }
        let sum: f64 = self.srtt.iter().map(|&(t, s)| (s - reference(t)).abs() / reference(t)).sum();
        100.0 * sum / self.srtt.len() as f64
    }
}

#[derive(Default)]
struct Report {
    established: bool,
    corrupt: bool,
    delivered: u64,
    /// Nominal round trips elapsed.
    rtts: f64,
    lost: u64,
    resent: u64,
    duplicates: u64,
    rtos: u64,
    spurious_rtos: u64,
    /// ACKs that acknowledged new data.
    acks: u64,
    /// Measurements ended by a retransmission before their ACK.
    karn: u64,
    segments: u64,
    round_trip_sum: u64,
    round_trip_max: u64,
    stack: Track,
    every: Track,
    g_floor: Track,
    /// Mean SRTT error of stack, every ACK, 1 ms floor, %.
    err: [f64; 3],
    final_stack: Option<Est>,
    final_every: Option<Est>,
}

/// Karn at work: a timed segment stopped being timed without its ACK.
fn observe(timed: &mut Option<u32>, now: Option<u32>, karn: &mut u64) {
    if let Some(s) = *timed {
        if now != Some(s) {
            *karn += 1;
        }
    }
    *timed = now;
}

fn run(shape: Shape, sender: Sender, flight: u64, loss: Loss, trace: bool) -> Report {
    let label = shape.label();
    let mut now = 50_000_000u64;
    azos_drv_irqchip::clint::set_test_time(now);
    let mut rng = 0x2545_F491_4F6C_DD1Du64;
    // Its own stream, apart from the jitter's: a loss draw must not move the
    // delays a jittered run would otherwise have had.
    let mut loss_rng = SplitMix64::new(match loss {
        Loss::Random { seed, .. } => seed,
        _ => 0,
    });
    let window = match sender {
        Sender::Bulk => flight * MSS,
        Sender::Paced => PACED_WINDOW * MSS,
    };
    let mut rx = Receiver::new(window as u16);
    let a = tcp::connect(PEER_IP, PORT_B, PORT_A);
    assert!(a >= 0, "no slot to dial out");
    let a = a as usize;
    let rtt = |a: usize| tcp::conn_rtt(a).expect("a valid slot");

    let mut o = Report::default();
    let mut fwd: VecDeque<Out> = VecDeque::new();
    let mut back: VecDeque<Back> = VecDeque::new();
    let (mut fwd_last, mut back_last) = (0u64, 0u64);
    let mut t0: Option<u64> = None;
    let mut iss1: Option<u32> = None;
    let (mut offered, mut una, mut highest) = (0u64, 0u64, 0u64);
    let pace = shape.pace(flight);
    let mut next_write = 0u64;
    // End offset of each new segment -> when it left.
    let mut first_sent: HashMap<u64, u64> = HashMap::new();
    let mut txs: Vec<Tx> = Vec::new();
    let mut every = Est::new(VAR_FLOOR);
    let mut g_floor = Est::new(G);
    let (mut every_deadline, mut g_floor_deadline): (Option<u64>, Option<u64>) = (None, None);
    let mut timed: Option<u32> = None;
    let mut milestones: Vec<i64> = if trace {
        vec![-1_000, 0, 100, 250, 500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000]
    } else {
        Vec::new()
    };
    let mut buf = [0u8; MSS as usize];
    // Segments taken off the wire around `tcp_tick` and recorded at the top of
    // the next pass, with whether the tick sent them; and the timeouts whose
    // spuriousness is judged once everything sent before them is recorded.
    let mut pending: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut rto_checks: Vec<(u64, u64)> = Vec::new();
    let give_up = now + 200_000 * TICKS_PER_MS;

    loop {
        if t0.is_none() && tcp::conn_state(a) == tcp::TcpState::Established {
            t0 = Some(now);
            next_write = now;
            for tr in [&mut o.stack, &mut o.every, &mut o.g_floor] {
                tr.last = now;
            }
        }
        if t0.is_some() {
            loop {
                if sender == Sender::Paced && now < next_write {
                    break;
                }
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = pattern(offered + i as u64);
                }
                let n = tcp::send_data(a, &buf);
                if n <= 0 {
                    break;
                }
                offered += n as u64;
                next_write += pace;
            }
        }
        observe(&mut timed, rtt(a).timed_seq, &mut o.karn);

        let rto_now = rtt(a).rto_ticks;
        let queued = std::mem::take(&mut pending);
        for (s, by_timer) in queued.into_iter().chain(take_segments().into_iter().map(|s| (s, false))) {
            if u16::from_be_bytes([s[0], s[1]]) != PORT_A {
                continue;
            }
            let seq = be32(&s[4..8]);
            let t = t0.map_or(0, |t0| (now - t0) / TICKS_PER_MS);
            let mut delay = shape.base(t) * TICKS_PER_MS / 2;
            if let Shape::Jitter { spread, .. } = shape {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                delay += rng % (spread * TICKS_PER_MS + 1);
            }
            if s[13] & SYN != 0 {
                iss1 = Some(seq.wrapping_add(1));
                fwd_last = fwd_last.max(now + delay);
                fwd.push_back(Out { arrive: fwd_last, seg: s, sent: now, rto: 0, rto_every: 0, first: false });
                continue;
            }
            let len = payload_of(&s).len() as u64;
            let Some(base) = iss1 else { continue };
            if len == 0 {
                continue;
            }
            let start = seq.wrapping_sub(base) as u64;
            let end = start + len;
            let first = start >= highest;
            if first {
                if una == highest {
                    every_deadline = Some(now + every.rto);
                    g_floor_deadline = Some(now + g_floor.rto);
                }
                first_sent.insert(end, now);
                highest = end;
            } else {
                o.resent += 1;
            }
            let lost = match loss {
                Loss::None => false,
                Loss::Random { ppm, .. } => loss_rng.chance(ppm),
                Loss::Periodic(n) => txs.len() % n == n - 1,
            };
            txs.push(Tx { start, end, sent: now, lost, timer: by_timer });
            if lost {
                o.lost += 1;
                continue;
            }
            fwd_last = fwd_last.max(now + delay);
            fwd.push_back(Out { arrive: fwd_last, seg: s, sent: now, rto: rto_now, rto_every: every.rto, first });
        }

        for (u, at) in rto_checks.drain(..) {
            if on_its_way(&txs, u, at, true) {
                o.spurious_rtos += 1;
            }
        }
        if let Some(t0) = t0 {
            if now >= t0 + shape.duration() * TICKS_PER_MS {
                break;
            }
        }
        assert!(now < give_up, "{label}: the run did not finish");

        let next_tick = (now / TICK + 1) * TICK;
        let wake = (sender == Sender::Paced && t0.is_some() && next_write > now).then_some(next_write);
        now = [fwd.front().map(|w| w.arrive), back.front().map(|b| b.arrive), wake, Some(next_tick)]
            .into_iter()
            .flatten()
            .min()
            .unwrap()
            .max(now);
        azos_drv_irqchip::clint::set_test_time(now);

        while fwd.front().map_or(false, |w| w.arrive <= now) {
            let w = fwd.pop_front().unwrap();
            let Some((reply, echo)) = rx.on_segment(&w.seg, w.sent) else { continue };
            let t = t0.map_or(0, |t0| (now - t0) / TICKS_PER_MS);
            back_last = back_last.max(now + shape.base(t) * TICKS_PER_MS / 2);
            if w.first {
                let round_trip = back_last - w.sent;
                o.segments += 1;
                o.round_trip_sum += round_trip;
                o.round_trip_max = o.round_trip_max.max(round_trip);
                if round_trip > w.rto {
                    o.stack.slower += 1;
                }
                if round_trip > w.rto_every {
                    o.every.slower += 1;
                }
            }
            back.push_back(Back { arrive: back_last, seg: reply, echo });
        }

        while back.front().map_or(false, |b| b.arrive <= now) {
            let bk = back.pop_front().unwrap();
            let ack = be32(&bk.seg[8..12]);
            let pre = rtt(a);
            tcp::handle_checked(&PEER_IP, &OUR_IP, &bk.seg);
            let post = rtt(a);
            if let (Some(base), false) = (iss1, bk.seg[13] & SYN != 0) {
                let off = ack.wrapping_sub(base) as u64;
                // The shadow timers restart whenever this ACK restarted the
                // stack's: an ACK of new data, or new SACK information during
                // SACK recovery.
                let restarted = post.timer_start == now;
                if restarted && una < highest {
                    o.every.ack(every_deadline, now, una, &txs);
                    o.g_floor.ack(g_floor_deadline, now, una, &txs);
                }
                if off > una {
                    o.acks += 1;
                    let mean = shape.mean(t0.map_or(0, |t0| (now - t0) / TICKS_PER_MS));
                    if bk.echo != 0 {
                        every.sample(now - bk.echo);
                        o.every.sampled(now, mean);
                    }
                    // The stack's own sample, if this ACK covers the timed
                    // segment.
                    if let Some(s) = pre.timed_seq {
                        let end = s.wrapping_sub(base) as u64;
                        if end <= off {
                            let sent = *first_sent.get(&end).unwrap_or_else(|| {
                                panic!("{label}: the stack timed a segment ending at {end} that never left as new data")
                            });
                            let mut want = Est::of(pre);
                            want.sample(now - sent);
                            assert_eq!(
                                Est::of(post), want,
                                "{label}: the stack's estimate did not move as a sample of {} ms predicts",
                                ms(now - sent),
                            );
                            g_floor.sample(now - sent);
                            o.stack.sampled(now, mean);
                            o.g_floor.sampled(now, mean);
                            timed = None;
                        }
                    }
                    una = off;
                }
                if restarted {
                    let armed = una < highest;
                    every_deadline = armed.then_some(now + every.rto);
                    g_floor_deadline = armed.then_some(now + g_floor.rto);
                }
            }
            observe(&mut timed, post.timed_seq, &mut o.karn);
        }

        if now % TICK == 0 {
            pending.extend(take_segments().into_iter().map(|s| (s, false)));
            let pre = rtt(a);
            tcp::tcp_tick();
            let post = rtt(a);
            pending.extend(take_segments().into_iter().map(|s| (s, true)));
            if post.rto_ticks > pre.rto_ticks {
                o.rtos += 1;
                rto_checks.push((una, now));
            }
            observe(&mut timed, post.timed_seq, &mut o.karn);

            if let Some(t0) = t0 {
                let t = (now - t0) / TICKS_PER_MS;
                let slowest = shape.slowest(t) * TICKS_PER_MS;
                o.rtts += ms(TICK) / shape.mean(t);
                let st = Est::of(post);
                let step = shape.step();
                o.stack.tick(t, &st, slowest, step);
                o.every.tick(t, &every, slowest, step);
                o.g_floor.tick(t, &g_floor, slowest, step);
                if let Some((at, _)) = step {
                    while let Some(&m) = milestones.first() {
                        if (t as i64) < at as i64 + m {
                            break;
                        }
                        milestones.remove(0);
                        println!(
                            "[rto-estimate]     step {m:+6} ms: path {:>3} | stack SRTT {:6.1} RTTVAR {:6.1} \
                             RTO {:6.1} | every ACK SRTT {:6.1} RTTVAR {:6.1} RTO {:6.1} | 1 ms floor RTO {:6.1}",
                            shape.base(t), st.srtt_ms(), st.rttvar_ms(), ms(st.rto),
                            every.srtt_ms(), every.rttvar_ms(), ms(every.rto), ms(g_floor.rto),
                        );
                    }
                }
            }
        }
    }

    let end_rtt = shape.mean(shape.duration());
    for tr in [&mut o.stack, &mut o.every, &mut o.g_floor] {
        tr.close_gap(now, end_rtt);
    }
    let actual = if o.segments == 0 { 1.0 } else { ms(o.round_trip_sum) / o.segments as f64 };
    let reference = |t: u64| match shape {
        Shape::Jitter { .. } => actual,
        _ => shape.mean(t),
    };
    o.err = [o.stack.error(&reference), o.every.error(&reference), o.g_floor.error(&reference)];
    o.final_stack = Some(Est::of(rtt(a)));
    o.final_every = Some(every);
    o.established = t0.is_some();
    o.corrupt = rx.corrupt;
    o.delivered = rx.rcv_nxt;
    o.duplicates = rx.duplicates;
    o
}

fn pct(n: u64, of: u64) -> f64 {
    if of == 0 { 0.0 } else { 100.0 * n as f64 / of as f64 }
}

fn adapt(a: Option<(u64, u64)>) -> String {
    match a {
        Some((after, samples)) => format!("{after} ms ({samples} samples)"),
        None => "never".to_string(),
    }
}

/// SRTT, RTTVAR and RTO against a constant, a stepped and a jittered RTT, for
/// bulk flights of 1, 4 and 16 segments and a paced flight of 16, without
/// loss, with 2% random loss (one run per seed, then mean, min and max) and
/// with a periodic 1-in-50 loss, beside the every-ACK and 1 ms floor
/// estimates. Printed; asserted only that the stream arrives intact and the
/// instrument reads what the stack computed.
#[test]
fn rto_estimate_against_a_known_rtt_with_a_flight_in_the_air() {
    let shapes = [
        Shape::Constant(2),
        Shape::Constant(20),
        Shape::Constant(100),
        Shape::Constant(300),
        Shape::Step { from: 20, to: 400, at: 6_000 },
        Shape::Step { from: 400, to: 20, at: 40_000 },
        Shape::Jitter { base: 40, spread: 120 },
    ];
    let senders = [(Sender::Bulk, 1u64), (Sender::Bulk, 4), (Sender::Bulk, 16), (Sender::Paced, 16)];
    for shape in shapes {
        for (sender, flight) in senders {
            let kind = if sender == Sender::Bulk { "bulk" } else { "paced" };
            // Per random-loss run: octets, lost, resent, RTOs, spurious RTOs.
            let mut random: Vec<[u64; 5]> = Vec::new();
            let losses = std::iter::once(Loss::None)
                .chain(LOSS_SEEDS.iter().map(|&seed| Loss::Random { ppm: LOSS_PPM, seed }))
                .chain(std::iter::once(Loss::Periodic(LOSS_EVERY)));
            for loss in losses {
                let _g = begin();
                let name = format!("{}, N={flight} {kind}, {}", shape.label(), loss.label());
                let trace = shape.step().is_some() && loss == Loss::None && flight != 4;
                if trace {
                    println!("[rto-estimate] {name}: trajectory around the step (ms)");
                }
                let o = run(shape, sender, flight, loss, trace);
                let (s, e, f) = (&o.stack, &o.every, &o.g_floor);
                println!(
                    "[rto-estimate] {name}: {:.0} RTTs, {} ACKs of new data, {} octets, {} lost, {} resent, \
                     {} RTOs ({} spurious), {} duplicates at the receiver; round trips of new segments: \
                     mean {:.1} ms, max {:.1} ms",
                    o.rtts, o.acks, o.delivered, o.lost, o.resent, o.rtos, o.spurious_rtos, o.duplicates,
                    ms(o.round_trip_sum) / o.segments.max(1) as f64, ms(o.round_trip_max),
                );
                println!(
                    "[rto-estimate]     samples: stack {} ({:.2}/RTT, {:.1}% of ACKs, {} measurements ended \
                     by a retransmission), every ACK {} ({:.2}/RTT) | longest without one: stack {:.0} ms \
                     ({:.1} RTT), every ACK {:.0} ms ({:.1} RTT)",
                    s.samples, s.samples as f64 / o.rtts, pct(s.samples, o.acks), o.karn,
                    e.samples, e.samples as f64 / o.rtts, ms(s.gap), s.gap_rtts, ms(e.gap), e.gap_rtts,
                );
                println!(
                    "[rto-estimate]     mean |SRTT-RTT|/RTT: stack {:.1}%, every ACK {:.1}% | RTO below the \
                     slowest RTT: stack {:.1}%, every ACK {:.1}%, 1 ms floor {:.1}% of the time | new segments \
                     slower than the RTO they left under: stack {}, every ACK {}, of {}",
                    o.err[0], o.err[1], pct(s.below, s.ticks), pct(e.below, e.ticks), pct(f.below, f.ticks),
                    s.slower, e.slower, o.segments,
                );
                println!(
                    "[rto-estimate]     ACKs after the timer would have expired (spurious: the data was on \
                     its way): every ACK {} ({}), 1 ms floor {} ({})",
                    e.late, e.spurious_late, f.late, f.spurious_late,
                );
                if shape.step().is_some() {
                    println!(
                        "[rto-estimate]     SRTT within 10% of the new RTT after: stack {}, every ACK {}",
                        adapt(s.adapt), adapt(e.adapt),
                    );
                }

                assert!(o.established, "{name}: the connection never opened");
                assert!(!o.corrupt, "{name}: a byte arrived that the sender never offered at that offset");
                assert!(o.delivered > 0, "{name}: nothing was delivered");
                assert!(s.samples > 0, "{name}: the stack never took an RTT sample");
                assert!(s.samples <= o.acks && e.samples <= o.acks, "{name}: more samples than ACKs of new data");
                if loss == Loss::None {
                    assert_eq!(o.lost, 0, "{name}: precondition: nothing lost");
                }
                if sender == Sender::Bulk && flight == 1 && loss == Loss::None && o.resent == 0 {
                    assert_eq!(
                        o.final_stack, o.final_every,
                        "{name}: one segment in flight and nothing resent, yet the every-ACK estimate \
                         differs from the stack's: the echoed send times are not the ones the stack timed",
                    );
                }
                if let Loss::Random { .. } = loss {
                    random.push([o.delivered, o.lost, o.resent, o.rtos, o.spurious_rtos]);
                }
            }
            let col = |i: usize| {
                let (mean, min, max) = spread(&random.iter().map(|r| r[i]).collect::<Vec<_>>());
                format!("mean {mean:.1}, min {min}, max {max}")
            };
            println!(
                "[rto-estimate] {}, N={flight} {kind}, {}% random loss over {} seeds: octets {} | lost {} \
                 | resent {} | RTOs {} | spurious RTOs {}",
                shape.label(), LOSS_PPM / 10_000, LOSS_SEEDS.len(), col(0), col(1), col(2), col(3), col(4),
            );
        }
    }
}
