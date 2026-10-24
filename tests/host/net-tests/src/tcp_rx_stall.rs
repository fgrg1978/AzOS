// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! A bulk TRANSFER INTO this stack by a BSD-style sender (the shape of QEMU's
//! SLIRP, which is what `tools/dev/ota_send.py` reaches the guest through) while
//! the application reads slowly, or stops reading for a while and then
//! catches up: does the receive window reopen by itself when the reader
//! consumes?
//!
//! The receiver under test is the real `tcp.rs`; the sender is a model,
//! written to the rules that matter for a receive-window stall:
//!
//! * it sends only full-sized segments (or the tail of the stream): the BSD
//!   sender silly-window rule, which is what makes a receiver that opens its
//!   window by less than one MSS look like a closed one;
//! * it never sends past the right edge the last ACK advertised;
//! * when it has data and cannot send, it arms its persist timer (5 s, then
//!   doubling up to 60 s: `TCPTV_PERSMIN`/`TCPTV_PERSMAX`) and probes with
//!   the bytes the window allows (one byte at a zero window) when it fires.
//!   That timer is the ONLY thing that recovers a window update the receiver
//!   never sent, which is what makes a missed update cost whole seconds.
//!
//! The reader is `recv` in 4 KiB reads (`TCP_RECV_MAX_PER_CALL`, what the OTA
//! task passes) once per `period_ms`, optionally not at all for a while.
//!
//! **What this showed (20-10, `tcp-rx-stall`).** The receive-side machine is
//! sound in every case below, scaled and unscaled: the window reopens on the
//! very first read after the reader resumes (0 ms, not the 40 ms of a delayed
//! ACK), a slow reader never needs the sender's persist timer, and when the
//! reopening ACK is lost the sender's next probe is answered with the open
//! window. So a zero window that lasts for tens of seconds is a ring nobody
//! reads, not a window update this stack forgot.
//!
//! Canary (by hand, reverted): drop `free >= left.saturating_mul(2)` from
//! `urgent` in `recv_inner` -> the paused-reader case reopens 7 ms late (the
//! first read's update is held; a later read reaches the at-once step) and
//! `the_window_reopens_on_the_first_read_after_a_pause` fails on its 0 ms bound.

use super::tcp_rx::*;
use super::{tcp, wire};
use azos_drv_irqchip::clint;

const SYN: u8 = 0x02;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const MSS: usize = 1460;
const TICKS_PER_MS: u64 = azos_drv_sys::timebase::TIMER_FREQ / 1000;

const PERSIST_MIN_MS: u64 = 5_000;
const PERSIST_MAX_MS: u64 = 60_000;

const TOTAL: u64 = 1 << 20;
const READ: usize = azos_limits::TCP_RECV_MAX_PER_CALL;

fn pattern(off: u64) -> u8 {
    (off.wrapping_mul(2654435761) >> 7) as u8
}

fn seg(
    src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8, window: u16,
    opts: &[u8], payload: &[u8],
) -> Vec<u8> {
    assert_eq!(opts.len() % 4, 0);
    let mut s = Vec::with_capacity(20 + opts.len() + payload.len());
    s.extend_from_slice(&src_port.to_be_bytes());
    s.extend_from_slice(&dst_port.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push((((20 + opts.len()) / 4) as u8) << 4);
    s.push(flags);
    s.extend_from_slice(&window.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(opts);
    s.extend_from_slice(payload);
    let pseudo = wire::pseudo_checksum(&PEER_IP, &OUR_IP, wire::IP_PROTO_TCP, s.len() as u16);
    let ck = tcp::tcp_checksum(pseudo, &s);
    s[16..18].copy_from_slice(&ck.to_be_bytes());
    s
}

/// The window-scale shift our SYN-ACK carries (0 when it has no such option).
fn synack_wscale(p: &[u8]) -> u32 {
    let off = ((p[12] >> 4) as usize) * 4;
    let mut i = 20;
    while i < off {
        match p[i] {
            0 => break,
            1 => i += 1,
            3 if i + 2 < off => return p[i + 2] as u32,
            _ => {
                let l = p[i + 1] as usize;
                if l < 2 { break; }
                i += l;
            }
        }
    }
    0
}

#[derive(Clone, Copy)]
struct Reader {
    /// One read every this many ms while running.
    period_ms: u64,
    /// Not reading at all in `[from, to)` ms of the run (a starved task).
    pause: Option<(u64, u64)>,
}

/// Which acknowledgements the wire loses on the way to the sender.
#[derive(Clone, Copy, PartialEq)]
enum Loss {
    None,
    /// Every pure ACK that reopens a window the sender last saw closed and
    /// acknowledges nothing new -- the window update -- before this ms. A
    /// probe's answer acknowledges the probed byte and is never lost.
    WindowUpdatesUntil(u64),
}

struct Out {
    /// Virtual ms until the whole stream was read; `None`: not in the limit.
    done_ms: Option<u64>,
    /// Probes the sender's persist timer sent.
    probes: u32,
    /// The ms of each.
    probe_ms: Vec<u64>,
    /// Times an ACK told the sender the window was (nearly) shut.
    closes: u32,
    /// ms of the first ACK that reopened the window after the pause ended.
    first_reopen_ms: Option<u64>,
    bytes_read: u64,
    corrupted: bool,
}

/// The sender model and the wire between it and the stack.
struct Sim {
    theirs0: u32,
    shift: u32,
    snd_una: u64,
    snd_nxt: u64,
    /// Right edge the last ACK advertised, as a stream offset.
    edge: u64,
    closed: bool,
    persist_at: Option<u64>,
    persist_iv: u64,
    out: Out,
    loss: Loss,
    ms: u64,
    pause_end: u64,
}

impl Sim {
    /// Feed what the stack put on the wire to the sender: its ACK number and
    /// window. `loss` decides which of them never arrive.
    fn feed(&mut self) {
        for s in wire::sent() {
            let p = &s.payload;
            if p.len() < 20 || p.len() != ((p[12] >> 4) as usize) * 4 { continue; }
            let ack = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
            let win = (u16::from_be_bytes([p[14], p[15]]) as u64) << self.shift;
            let rel = ack.wrapping_sub(self.theirs0.wrapping_add(self.snd_una as u32)) as i32;
            let shut = win < MSS as u64;
            let reopens = self.closed && !shut;
            if let Loss::WindowUpdatesUntil(t) = self.loss {
                if reopens && rel == 0 && self.ms < t { continue; }
            }
            if rel > 0 {
                self.snd_una += rel as u64;
                self.persist_iv = PERSIST_MIN_MS;
                self.persist_at = None;
            }
            self.edge = self.snd_una + win;
            if shut && !self.closed { self.out.closes += 1; }
            if reopens && self.ms >= self.pause_end && self.out.first_reopen_ms.is_none() {
                self.out.first_reopen_ms = Some(self.ms);
            }
            self.closed = shut;
        }
        wire::clear_sent();
    }
}

fn run(wscale: Option<u8>, rd: Reader, loss: Loss, limit_ms: u64) -> Out {
    let _g = begin();
    let port = 7950u16;
    let peer_port = 46950u16;
    assert!(tcp::listen(port) >= 0);
    let peer_isn = 0x4000_0000u32;
    let mut syn_opts = vec![2, 4, (MSS >> 8) as u8, MSS as u8];
    if let Some(s) = wscale {
        syn_opts.extend_from_slice(&[1, 3, 3, s]);
    }
    wire::clear_sent();
    deliver(&seg(peer_port, port, peer_isn, 0, SYN, 65535, &syn_opts, &[]));
    let synack = wire::sent().pop().expect("SYN-ACK").payload;
    let ours = u32::from_be_bytes([synack[4], synack[5], synack[6], synack[7]]).wrapping_add(1);
    let idx = slot_in(tcp::TcpState::SynRcvd).expect("half-open");
    let theirs0 = peer_isn.wrapping_add(1);
    deliver(&seg(peer_port, port, theirs0, ours, ACK, 65535, &[], &[]));
    assert!(tcp::conn_state(idx) == tcp::TcpState::Established);
    wire::clear_sent();

    let t0 = 1_000_000u64;
    clint::set_test_time(t0);
    let mut sim = Sim {
        theirs0,
        shift: if wscale.is_some() { synack_wscale(&synack) } else { 0 },
        snd_una: 0,
        snd_nxt: 0,
        // The window of the third leg, unscaled.
        edge: 65535,
        closed: false,
        persist_at: None,
        persist_iv: PERSIST_MIN_MS,
        out: Out { done_ms: None, probes: 0, probe_ms: Vec::new(), closes: 0, first_reopen_ms: None, bytes_read: 0, corrupted: false },
        loss,
        ms: 0,
        pause_end: rd.pause.map_or(0, |p| p.1),
    };
    let mut buf = vec![0u8; READ];

    while sim.ms < limit_ms {
        let ms = sim.ms;
        clint::set_test_time(t0 + ms * TICKS_PER_MS);

        // The application.
        let paused = matches!(rd.pause, Some((a, b)) if ms >= a && ms < b);
        if !paused && ms % rd.period_ms == 0 {
            let n = tcp::recv(idx, &mut buf);
            if n > 0 {
                for (i, &b) in buf[..n as usize].iter().enumerate() {
                    if b != pattern(sim.out.bytes_read + i as u64) { sim.out.corrupted = true; }
                }
                sim.out.bytes_read += n as u64;
                if sim.out.bytes_read == TOTAL { sim.out.done_ms = Some(ms); break; }
            }
        }
        sim.feed();

        // The stack's own timers (a held ACK's deadline).
        tcp::tcp_tick();
        sim.feed();

        // The sender: whole segments, up to the advertised edge.
        loop {
            let remaining = TOTAL - sim.snd_nxt;
            let len = remaining.min(MSS as u64).min(sim.edge.saturating_sub(sim.snd_nxt));
            if len == 0 || (len < MSS as u64 && len != remaining) { break; }
            let payload: Vec<u8> = (0..len).map(|i| pattern(sim.snd_nxt + i)).collect();
            let seq = theirs0.wrapping_add(sim.snd_nxt as u32);
            let flags = if len == remaining { PSH | ACK } else { ACK };
            sim.snd_nxt += len;
            deliver(&seg(peer_port, port, seq, ours, flags, 65535, &[], &payload));
            sim.feed();
        }
        // What the stack could not store was dropped and not acknowledged:
        // the sender is back at what is acknowledged.
        if sim.snd_nxt > sim.snd_una + sim.edge.saturating_sub(sim.snd_una) { sim.snd_nxt = sim.snd_una; }
        sim.snd_nxt = sim.snd_nxt.max(sim.snd_una);

        // The persist timer: data to send, nothing in flight, no whole
        // segment of window.
        let room = sim.edge.saturating_sub(sim.snd_una);
        let rem = TOTAL - sim.snd_una;
        if sim.snd_una == sim.snd_nxt && rem > 0 && room < (MSS as u64).min(rem) {
            match sim.persist_at {
                None => sim.persist_at = Some(ms + sim.persist_iv),
                Some(at) if ms >= at => {
                    sim.out.probes += 1;
                    sim.out.probe_ms.push(ms);
                            let len = if room == 0 { 1 } else { room }.min(rem);
                    let payload: Vec<u8> = (0..len).map(|i| pattern(sim.snd_una + i)).collect();
                    let seq = theirs0.wrapping_add(sim.snd_una as u32);
                    sim.snd_nxt = sim.snd_una + len;
                    deliver(&seg(peer_port, port, seq, ours, ACK, 65535, &[], &payload));
                    sim.feed();
                    sim.persist_iv = (sim.persist_iv * 2).min(PERSIST_MAX_MS);
                    sim.persist_at = Some(ms + sim.persist_iv);
                }
                _ => {}
            }
        } else {
            sim.persist_at = None;
        }
        sim.ms += 1;
    }
    sim.out
}

const ONE_WINDOW_OPTS: [Option<u8>; 2] = [None, Some(0)];

/// A reader slower than the link: every read opens the window, nothing is
/// ever left to the sender's persist timer, and the transfer takes what the
/// reader's own pace takes.
#[test]
fn a_slow_reader_never_needs_the_senders_persist_timer() {
    for ws in ONE_WINDOW_OPTS {
        let rd = Reader { period_ms: 2, pause: None };
        let r = run(ws, rd, Loss::None, 60_000);
        let floor = (TOTAL / READ as u64) * rd.period_ms;
        assert!(!r.corrupted, "wscale {ws:?}: stream corrupted");
        let done = r.done_ms.unwrap_or_else(|| panic!("wscale {ws:?}: stalled at {} of {TOTAL} bytes", r.bytes_read));
        println!("[tcp_rx_stall] slow reader, wscale {ws:?}: {done} ms (reader floor {floor} ms), {} closes, {} probes",
                 r.closes, r.probes);
        assert!(r.closes > 0, "wscale {ws:?}: the reader never kept up, so the window was never shut");
        assert_eq!(r.probes, 0, "wscale {ws:?}: the sender needed its persist timer");
        assert!(done <= floor + 20, "wscale {ws:?}: {done} ms against a reader floor of {floor} ms");
    }
}

/// A reader that stops for 12 s (longer than the 5 s persist timer, so one
/// probe is due and is answered with the closed window) and then resumes: the
/// window reopens on the first read, at once, and the stream finishes in the
/// time the remaining reads take.
#[test]
fn the_window_reopens_on_the_first_read_after_a_pause() {
    for ws in ONE_WINDOW_OPTS {
        let rd = Reader { period_ms: 1, pause: Some((50, 12_000)) };
        let r = run(ws, rd, Loss::None, 60_000);
        assert!(!r.corrupted, "wscale {ws:?}: stream corrupted");
        let done = r.done_ms.unwrap_or_else(|| panic!("wscale {ws:?}: stalled at {} of {TOTAL} bytes", r.bytes_read));
        assert!(r.closes >= 1, "wscale {ws:?}: the pause should have shut the window");
        let reopen = r.first_reopen_ms.unwrap_or_else(|| panic!("wscale {ws:?}: no ACK ever reopened the window"));
        println!("[tcp_rx_stall] paused reader, wscale {ws:?}: reopened at {reopen} ms (resumed at 12000), done {done} ms, {} probes",
                 r.probes);
        assert_eq!(reopen, 12_000, "wscale {ws:?}: the first read after the pause must reopen the window in the same ms \
                                   (a held update waits TCP_DELACK_MS)");
        // 1 MiB less what the ring held when the pause began, at one read a ms.
        assert!(done <= 12_000 + (TOTAL / READ as u64) + 20, "wscale {ws:?}: done at {done} ms");
        assert_eq!(r.probes, 1, "wscale {ws:?}: one probe (5 s) falls inside a 12 s pause, none after it");
    }
}

/// The reopening ACK is lost (the TX ring full, a frame dropped on the way:
/// every window update before 14 s is). The reader is running again from 12 s,
/// the ring is empty, and the only thing that can restart the sender is its
/// persist probe, whose answer must carry the open window: the stream resumes
/// at the first probe after 12 s, and from then on the updates get through.
#[test]
fn a_probe_restarts_a_sender_whose_window_update_was_lost() {
    for ws in ONE_WINDOW_OPTS {
        let rd = Reader { period_ms: 1, pause: Some((50, 12_000)) };
        let r = run(ws, rd, Loss::WindowUpdatesUntil(14_000), 120_000);
        assert!(!r.corrupted, "wscale {ws:?}: stream corrupted");
        let done = r.done_ms.unwrap_or_else(|| panic!("wscale {ws:?}: stalled at {} of {TOTAL} bytes", r.bytes_read));
        println!("[tcp_rx_stall] lost window updates, wscale {ws:?}: done {done} ms, probes at {:?}", r.probe_ms);
        // The probe that restarted it is the first after the reader resumed.
        let restart = *r.probe_ms.iter().find(|&&t| t >= 12_000)
            .unwrap_or_else(|| panic!("wscale {ws:?}: no probe after the pause, yet done at {done} ms"));
        assert!(done >= restart && done <= restart + (TOTAL / READ as u64) + 20,
                "wscale {ws:?}: done at {done} ms, restarted by the probe at {restart} ms");
        assert_eq!(r.probe_ms.last(), Some(&restart), "wscale {ws:?}: probes {:?}: it needed another", r.probe_ms);
    }
}
