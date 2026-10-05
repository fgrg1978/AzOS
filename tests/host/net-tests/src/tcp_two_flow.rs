// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Two flows from this stack through one drop-tail bottleneck: a bulk
//! transfer and a small periodic control message, each on its own connection.
//! Measured: how long each control message takes from the application's write
//! to delivery at the receiver, and what the bulk flow delivers.
//!
//! **Topology.** Both connections dial `PEER_IP` from this stack. Every
//! segment this stack sends, of either flow, enters one forward
//! `tcp_throughput::Pipe` (the model of that bench's bottleneck row): a
//! 10 Mbit/s bottleneck with a 32-frame drop-tail queue, then 10 ms of delay.
//! ACKs come back over 10 ms with no bottleneck, so the RTT is 20 ms plus
//! queueing. Each receiver is a model: it reassembles without limit and
//! acknowledges every segment at once with SACK blocks (MSS 1460, Window
//! Scale 7, a window that never closes), as a Linux peer without delayed ACKs
//! would. This stack's own receive path is not in the measurement.
//!
//! **The control flow.** `CONTROL_MSG` = 85 B written every
//! `CONTROL_PERIOD_MS` = 100 ms. 85 B is a diff-drive ActuatorCmd sealed for
//! the brain link: a 13 B frame (payload 3 + 2 x 2 channels, `FRAME_OVERHEAD`
//! 6, in `domains/robot/behavior/src/brain_protocol.rs`),
//! `auth_envelope::ENVELOPE_OVERHEAD` 26, and one `encrypt_link` record of
//! `secure_channel::PACKET_OVERHEAD` 46 (`crates/core/crypto/src/secure_channel.rs`).
//! 100 ms is the period of the kernel's behavior loop (`behavior_task` in
//! `kernel/src/tasks/behavior.rs`), which sends one sensor frame per pass. On the robot
//! the actuator command travels brain to robot, and the telemetry this stack
//! sends shares one socket with the camera; here both flows are this stack's
//! senders on separate connections, because this stack's congestion response
//! is what is measured. TCP, as the brain link is.
//!
//! **Loss.** Queue drops always. In the lossy runs, also each data segment of
//! either flow, new or resent, independently with probability 2% before the
//! queue, drawn from `SplitMix64`. The seed also sets the control flow's
//! phase within its period, so the lossless runs differ by seed too.
//!
//! **Run.** `WARMUP_MS` (10 s) from both connections being established, not
//! measured: slow start overshoots the queue once. Then `WINDOW_MS` (120 s)
//! measured: the control messages written in it, and the bulk bytes delivered
//! in it. Then `DRAIN_MS` (10 s) with no new control message, for those in
//! flight to arrive; one still undelivered after it is counted, not given a
//! delay. `tcp_tick` every 5 ms; the clock is the test clock. None of this is
//! a wire figure.
//!
//! **Asserted** is only harness soundness: both streams arrive intact, the
//! control connection takes every message whole, and both flows deliver.

use super::tcp_rx::{begin, OUR_IP, PEER_IP};
use super::tcp_throughput::{spread, Pipe, SplitMix64};
use super::{tcp, wire};
use std::collections::VecDeque;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

const TICKS_PER_MS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 1000;
/// How often the simulation calls `tcp_tick`.
const TICK: u64 = 5 * TICKS_PER_MS;

const BULK_A: u16 = 47600;
const BULK_B: u16 = 7995;
const CONTROL_A: u16 = 47601;
const CONTROL_B: u16 = 7996;

const RTT_MS: u64 = 20;
const BOTTLENECK_MBPS: u64 = 10;
const QUEUE_FRAMES: usize = 32;
const CONTROL_MSG: usize = 85;
const CONTROL_PERIOD_MS: u64 = 100;
const WARMUP_MS: u64 = 10_000;
const WINDOW_MS: u64 = 120_000;
const DRAIN_MS: u64 = 10_000;
/// 2%, in a million.
const LOSS_PPM: u64 = 20_000;
/// One run per seed, per loss model.
const SEEDS: [u64; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn bulk_byte(off: u64) -> u8 {
    (off % 251) as u8
}

fn control_byte(off: u64) -> u8 {
    ((off % 241) as u8) ^ 0x5A
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn src_port(s: &[u8]) -> u16 {
    u16::from_be_bytes([s[0], s[1]])
}

fn dst_port(s: &[u8]) -> u16 {
    u16::from_be_bytes([s[2], s[3]])
}

fn payload_of(s: &[u8]) -> &[u8] {
    &s[((s[12] >> 4) as usize) * 4..]
}

fn ms(ticks: u64) -> f64 {
    ticks as f64 / TICKS_PER_MS as f64
}

/// Everything the stack sent since the last call, as TCP segments.
fn take_segments() -> Vec<Vec<u8>> {
    let frames = std::mem::take(&mut *crate::raw::FRAMES.lock().unwrap());
    frames
        .iter()
        .filter_map(|f| {
            if f.len() < 34 || u16::from_be_bytes([f[12], f[13]]) != 0x0800 || f[14 + 9] != 6 {
                return None;
            }
            let ihl = ((f[14] & 0x0F) as usize) * 4;
            let end = (14 + u16::from_be_bytes([f[16], f[17]]) as usize).min(f.len());
            Some(f[14 + ihl..end].to_vec())
        })
        .collect()
}

/// A receiver on `port` for a sender on `peer`: holds everything,
/// acknowledges every segment, and SACKs what it holds with the most recent
/// range first (RFC 2018 §4).
struct Model {
    port: u16,
    peer: u16,
    byte: fn(u64) -> u8,
    iss: u32,
    base: u32,
    synced: bool,
    rcv_nxt: u64,
    held: Vec<(u64, u64)>,
    recent: u64,
    corrupt: bool,
}

impl Model {
    fn new(port: u16, peer: u16, byte: fn(u64) -> u8, iss: u32) -> Self {
        Model { port, peer, byte, iss, base: 0, synced: false, rcv_nxt: 0, held: Vec::new(), recent: 0, corrupt: false }
    }

    fn build(&self, seq: u32, ack: u32, flags: u8, window: u16, opts: &[u8]) -> Vec<u8> {
        let mut s = Vec::with_capacity(20 + opts.len());
        s.extend_from_slice(&self.port.to_be_bytes());
        s.extend_from_slice(&self.peer.to_be_bytes());
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

    fn on_segment(&mut self, s: &[u8]) -> Option<Vec<u8>> {
        let seq = be32(&s[4..8]);
        if s[13] & SYN != 0 {
            self.base = seq.wrapping_add(1);
            self.synced = true;
            // MSS 1460, Window Scale 7, SACK-Permitted.
            let opts = [2, 4, 0x05, 0xB4, 1, 3, 3, 7, 1, 1, 4, 2];
            return Some(self.build(self.iss, self.base, SYN | ACK, 65535, &opts));
        }
        let payload = payload_of(s);
        if !self.synced || payload.is_empty() {
            return None;
        }
        let start = seq.wrapping_sub(self.base) as u64;
        for (i, &b) in payload.iter().enumerate() {
            if b != (self.byte)(start + i as u64) {
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
        Some(self.build(self.iss.wrapping_add(1), ack, ACK, 1024, &opts))
    }
}

#[derive(Default)]
struct Report {
    /// Write-to-delivery time of each control message written in the window,
    /// in ticks.
    delays: Vec<u64>,
    /// Control messages written in the window and not delivered by the end.
    undelivered: usize,
    /// Bulk bytes delivered in order during the window.
    bulk_bytes: u64,
    bulk_lost: u64,
    control_lost: u64,
    /// Control data segments that carried a byte already sent once.
    control_resent: u64,
    queue_drops: usize,
    /// Retransmission timeouts over the whole run.
    bulk_rtos: u64,
    control_rtos: u64,
    corrupt: bool,
}

fn run(seed: u64, lossy: bool) -> Report {
    let mut now = 50_000_000u64;
    azos_drv_irqchip::clint::set_test_time(now);
    let rtt = RTT_MS * TICKS_PER_MS;
    let ticks_per_byte = 8 * azos_drv_sys::timebase::TIMER_FREQ / (BOTTLENECK_MBPS * 1_000_000);
    let mut fwd = Pipe::new(rtt / 2, ticks_per_byte, QUEUE_FRAMES);
    let mut back = Pipe::new(rtt / 2, 0, 0);
    let mut rng = SplitMix64::new(seed);
    let period = CONTROL_PERIOD_MS * TICKS_PER_MS;
    let phase = rng.next() % period;

    let mut bulk_rx = Model::new(BULK_B, BULK_A, bulk_byte, 0x5EED_0000);
    let mut control_rx = Model::new(CONTROL_B, CONTROL_A, control_byte, 0x5EED_8000);
    let bulk = tcp::connect(PEER_IP, BULK_B, BULK_A);
    let control = tcp::connect(PEER_IP, CONTROL_B, CONTROL_A);
    assert!(bulk >= 0 && control >= 0, "no slot to dial out");
    let (bulk, control) = (bulk as usize, control as usize);
    let rto = |i: usize| tcp::conn_rtt(i).expect("a valid slot").rto_ticks;
    let established = |i: usize| tcp::conn_state(i) == tcp::TcpState::Established;

    let mut o = Report::default();
    // (window start, window end, end of run), once both are established.
    let mut marks: Option<(u64, u64, u64)> = None;
    let mut next_write = 0u64;
    let (mut bulk_offered, mut control_offered) = (0u64, 0u64);
    // (end offset, written at) of each control message written in the window
    // and not yet delivered.
    let mut pending: VecDeque<(u64, u64)> = VecDeque::new();
    let mut control_iss: Option<u32> = None;
    let mut control_highest = 0u64;
    let (mut bulk_at_start, mut bulk_at_end) = (None, None);
    let mut out = [0u8; 1460];
    let give_up = now + (WARMUP_MS + WINDOW_MS + DRAIN_MS + 60_000) * TICKS_PER_MS;

    loop {
        if marks.is_none() && established(bulk) && established(control) {
            let start = now + WARMUP_MS * TICKS_PER_MS;
            let end = start + WINDOW_MS * TICKS_PER_MS;
            marks = Some((start, end, end + DRAIN_MS * TICKS_PER_MS));
            next_write = now + phase;
        }
        if let Some((start, end, _)) = marks {
            loop {
                for (i, b) in out.iter_mut().enumerate() {
                    *b = bulk_byte(bulk_offered + i as u64);
                }
                let r = tcp::send_data(bulk, &out);
                if r <= 0 {
                    break;
                }
                bulk_offered += r as u64;
            }
            while next_write <= now && next_write < end {
                let msg: Vec<u8> = (0..CONTROL_MSG as u64).map(|i| control_byte(control_offered + i)).collect();
                let r = tcp::send_data(control, &msg);
                assert_eq!(r, CONTROL_MSG as i32, "the control connection did not take a whole message");
                control_offered += CONTROL_MSG as u64;
                if now >= start {
                    pending.push_back((control_offered, now));
                }
                next_write += period;
            }
        }

        // Off the wire: the random loss is drawn for each data segment of
        // either flow, and the rest enter the bottleneck.
        for s in take_segments() {
            let sp = src_port(&s);
            if sp != BULK_A && sp != CONTROL_A {
                continue;
            }
            let seq = be32(&s[4..8]);
            if sp == CONTROL_A && s[13] & SYN != 0 {
                control_iss = Some(seq);
            }
            let len = payload_of(&s).len() as u64;
            if len != 0 {
                if let (CONTROL_A, Some(iss)) = (sp, control_iss) {
                    let off = seq.wrapping_sub(iss.wrapping_add(1)) as u64;
                    if off < control_highest {
                        o.control_resent += 1;
                    }
                    control_highest = control_highest.max(off + len);
                }
                if lossy && rng.chance(LOSS_PPM) {
                    if sp == BULK_A {
                        o.bulk_lost += 1;
                    } else {
                        o.control_lost += 1;
                    }
                    continue;
                }
            }
            fwd.push(now, s);
        }

        if let Some((start, end, stop)) = marks {
            if bulk_at_start.is_none() && now >= start {
                bulk_at_start = Some(bulk_rx.rcv_nxt);
            }
            if bulk_at_end.is_none() && now >= end {
                bulk_at_end = Some(bulk_rx.rcv_nxt);
            }
            if now >= stop {
                break;
            }
        }
        assert!(now < give_up, "the run did not finish");

        let next_tick = (now / TICK + 1) * TICK;
        let (write, mark) = match marks {
            Some((start, end, stop)) => (
                (next_write < end).then_some(next_write),
                [start, end, stop].into_iter().filter(|&m| m > now).min(),
            ),
            None => (None, None),
        };
        now = [fwd.next_arrival(), back.next_arrival(), Some(next_tick), write, mark]
            .into_iter()
            .flatten()
            .min()
            .unwrap()
            .max(now);
        azos_drv_irqchip::clint::set_test_time(now);

        while let Some(s) = fwd.pop_due(now) {
            let reply = match dst_port(&s) {
                BULK_B => bulk_rx.on_segment(&s),
                CONTROL_B => control_rx.on_segment(&s),
                _ => None,
            };
            if let Some(r) = reply {
                back.push(now, r);
            }
            while let Some(&(end, at)) = pending.front() {
                if end > control_rx.rcv_nxt {
                    break;
                }
                pending.pop_front();
                o.delays.push(now - at);
            }
        }
        while let Some(s) = back.pop_due(now) {
            tcp::handle_checked(&PEER_IP, &OUR_IP, &s);
        }
        if now % TICK == 0 {
            let pre = (rto(bulk), rto(control));
            tcp::tcp_tick();
            o.bulk_rtos += (rto(bulk) > pre.0) as u64;
            o.control_rtos += (rto(control) > pre.1) as u64;
        }
    }

    o.undelivered = pending.len();
    o.bulk_bytes = bulk_at_end.unwrap_or(0) - bulk_at_start.unwrap_or(0);
    o.queue_drops = fwd.dropped;
    o.corrupt = bulk_rx.corrupt || control_rx.corrupt;
    o
}

/// The nearest-rank `q` quantile of sorted `v`.
fn quantile(v: &[u64], q: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    let rank = ((q * v.len() as f64).ceil() as usize).clamp(1, v.len());
    v[rank - 1]
}

/// Control-message delay (p50, p99, max) and bulk throughput with the
/// congestion response of the tree it runs in, per seed and pooled over the
/// seeds, with queue drops only and with 2% random loss as well. Printed;
/// asserted only that the harness is sound.
#[test]
fn control_message_delay_beside_a_bulk_flow_through_one_queue() {
    for lossy in [false, true] {
        let model = if lossy { "2% random loss and queue drops" } else { "queue drops only" };
        let mut pooled: Vec<u64> = Vec::new();
        let mut undelivered = 0usize;
        let (mut p50s, mut p99s, mut maxes, mut kbps) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for seed in SEEDS {
            let _g = begin();
            let mut o = run(seed, lossy);
            assert!(!o.corrupt, "{model}, seed {seed}: a byte arrived that its sender never offered at that offset");
            assert!(!o.delays.is_empty(), "{model}, seed {seed}: no control message was delivered");
            assert!(o.bulk_bytes > 0, "{model}, seed {seed}: the bulk flow delivered nothing in the window");
            o.delays.sort_unstable();
            let (p50, p99, max) = (quantile(&o.delays, 0.50), quantile(&o.delays, 0.99), *o.delays.last().unwrap());
            let rate = o.bulk_bytes * 8 / (WINDOW_MS / 1000);
            println!(
                "[two-flow] {model}, seed {seed}: control p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms over {} \
                 messages ({} undelivered) | bulk {:.3} Mbit/s | lost: bulk {}, control {} | control resent {} \
                 | queue drops {} | RTOs: bulk {}, control {}",
                ms(p50), ms(p99), ms(max), o.delays.len(), o.undelivered, rate as f64 / 1e6, o.bulk_lost,
                o.control_lost, o.control_resent, o.queue_drops, o.bulk_rtos, o.control_rtos,
            );
            p50s.push(p50);
            p99s.push(p99);
            maxes.push(max);
            kbps.push(rate / 1000);
            undelivered += o.undelivered;
            pooled.extend_from_slice(&o.delays);
        }
        pooled.sort_unstable();
        let per_seed = |v: &[u64]| {
            let (mean, min, max) = spread(v);
            format!("mean {:.1}, min {:.1}, max {:.1}", mean / TICKS_PER_MS as f64, ms(min), ms(max))
        };
        let (rate_mean, rate_min, rate_max) = spread(&kbps);
        println!(
            "[two-flow] {model}, {} seeds pooled ({} messages, {} undelivered): control p50 {:.1} ms, p99 {:.1} ms, \
             max {:.1} ms | per-seed p50 {} ms | per-seed p99 {} ms | per-seed max {} ms | bulk mean {:.3}, \
             min {:.3}, max {:.3} Mbit/s",
            SEEDS.len(), pooled.len(), undelivered, ms(quantile(&pooled, 0.50)), ms(quantile(&pooled, 0.99)),
            ms(*pooled.last().unwrap()), per_seed(&p50s), per_seed(&p99s), per_seed(&maxes),
            rate_mean / 1000.0, rate_min as f64 / 1000.0, rate_max as f64 / 1000.0,
        );
    }
}
