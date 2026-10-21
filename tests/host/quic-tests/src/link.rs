// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The driver over real UDP sockets on the loopback: two pumps in one thread,
//! polled in turn the way `rpcsrv`'s link thread polls.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use azos_quic::{Event, Identity, Pump, Role, Sender, Settings, FRAME_MAX};

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn settings() -> Settings {
    Settings { idle_timeout: Duration::from_millis(600), redial: Duration::from_millis(100), queue: 64, streams: 64 }
}

pub struct End {
    pub pump: Option<Pump>,
    pub send: Sender,
    pub events: Vec<Event>,
}

impl End {
    pub fn frames(&self) -> BTreeSet<Vec<u8>> {
        self.events.iter().filter_map(|e| if let Event::Frame(f) = e { Some(f.clone()) } else { None }).collect()
    }

    /// The connection is established: more Ups than Downs so far.
    pub fn up(&self) -> bool {
        self.count(&Event::Up) > self.count(&Event::Down)
    }

    pub fn count(&self, what: &Event) -> usize {
        self.events.iter().filter(|e| *e == what).count()
    }

    pub fn addr(&self) -> SocketAddr {
        self.pump.as_ref().unwrap().local_addr().unwrap()
    }
}

pub fn listener(peer: IpAddr, at: Option<SocketAddr>, s: Settings) -> End {
    let id = Identity::generate().unwrap();
    let local = at.unwrap_or_else(|| SocketAddr::new(LO, 0));
    let (pump, send) = Pump::bind(local, Role::Listen { peer, identity: id }, s).unwrap();
    End { pump: Some(pump), send, events: vec![] }
}

pub fn dialer(remote: SocketAddr, s: Settings) -> End {
    let (pump, send) = Pump::bind(SocketAddr::new(LO, 0), Role::Dial { remote }, s).unwrap();
    End { pump: Some(pump), send, events: vec![] }
}

/// Poll every live end in turn until `done` or `secs` pass.
pub fn spin(ends: &mut [&mut End], secs: f64, mut done: impl FnMut(&[&mut End]) -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs_f64(secs);
    while Instant::now() < end {
        for e in ends.iter_mut() {
            if let Some(p) = e.pump.as_mut() {
                p.drive(Duration::from_millis(1)).unwrap();
                while let Some(ev) = p.pop() {
                    e.events.push(ev);
                }
            }
        }
        if done(ends) {
            return true;
        }
    }
    false
}

fn connected(a: &mut End, b: &mut End) {
    assert!(spin(&mut [a, b], 5.0, |e| e[0].up() && e[1].up()), "the connection never came up");
}

fn pair() -> (End, End) {
    let b = listener(LO, None, settings());
    let a = dialer(b.addr(), settings());
    (a, b)
}

/// A frame whose content says which one it is, of a length that varies from 1 to the maximum.
fn frame(i: usize) -> Vec<u8> {
    let len = 1 + (i * 37) % FRAME_MAX;
    let mut f = vec![(i % 251) as u8; len];
    f[0] = (i >> 8) as u8;
    if len > 1 {
        f[1] = i as u8;
    }
    f
}

#[test]
fn a_dialer_and_a_listener_connect() {
    let (mut a, mut b) = pair();
    assert!(!a.up() && !b.up());
    connected(&mut a, &mut b);
    assert_eq!(a.count(&Event::Up), 1);
    assert_eq!(b.count(&Event::Up), 1);
}

#[test]
fn frames_cross_both_ways_each_on_its_own_stream() {
    let (mut a, mut b) = pair();
    connected(&mut a, &mut b);
    let n = 300;
    let (mut from_a, mut from_b) = (BTreeSet::new(), BTreeSet::new());
    // Sent in bursts so that the queue and the stream limit are both exercised.
    for burst in 0..(n / 30) {
        for k in 0..30 {
            let i = burst * 30 + k;
            let (fa, fb) = (frame(i), frame(i + 10_000));
            assert!(a.send.send(&fa), "frame {i} refused");
            assert!(b.send.send(&fb), "frame {i} refused");
            from_a.insert(fa);
            from_b.insert(fb);
        }
        spin(&mut [&mut a, &mut b], 0.5, |e| e[0].frames().len() == from_b.len() && e[1].frames().len() == from_a.len());
    }
    assert!(spin(&mut [&mut a, &mut b], 5.0, |e| e[0].frames().len() == from_b.len() && e[1].frames().len() == from_a.len()), "frames missing");
    assert_eq!(b.frames(), from_a, "what B received is not what A sent");
    assert_eq!(a.frames(), from_b, "what A received is not what B sent");
    // Each frame arrived once.
    let received = |e: &End| e.events.iter().filter(|x| matches!(x, Event::Frame(_))).count();
    assert_eq!(received(&b), n);
    assert_eq!(received(&a), n);
}

#[test]
fn what_is_not_a_frame_is_not_sent() {
    let (mut a, mut b) = pair();
    assert!(!a.send.send(b"before the connection"), "queued with no connection");
    connected(&mut a, &mut b);
    assert!(!a.send.send(&[]), "an empty frame");
    assert!(!a.send.send(&vec![0u8; FRAME_MAX + 1]), "a frame larger than the engine's");
    assert!(a.send.send(&vec![0u8; FRAME_MAX]));
}

#[test]
fn the_queue_is_bounded() {
    let b = listener(LO, None, Settings { queue: 4, ..settings() });
    let mut a = dialer(b.addr(), Settings { queue: 4, ..settings() });
    let mut b = b;
    connected(&mut a, &mut b);
    // Nothing drives the pumps between these, so nothing leaves the queue.
    let accepted = (0..10).filter(|i| a.send.send(&frame(*i))).count();
    assert_eq!(accepted, 4);
}

/// **Canary:** a pump with no source filter would connect from any address.
#[test]
fn a_datagram_from_another_address_is_dropped_before_quic_sees_it() {
    // The listener answers 127.0.0.2 only; the dialer's datagrams come from 127.0.0.1.
    let mut b = listener(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), None, settings());
    let mut a = dialer(b.addr(), settings());
    assert!(!spin(&mut [&mut a, &mut b], 1.5, |e| e[0].up() || e[1].up()), "connected to an address that is not the peer's");
    assert!(b.events.is_empty());
    // Positive control: the same pair with the right address connects.
    let mut b = listener(LO, None, settings());
    let mut a = dialer(b.addr(), settings());
    connected(&mut a, &mut b);
}

#[test]
fn a_peer_that_closes_is_a_down_at_once() {
    let (mut a, mut b) = pair();
    connected(&mut a, &mut b);
    assert!(a.send.send(b"queued, never sent"));
    a.pump.as_mut().unwrap().close();
    let t = Instant::now();
    assert!(spin(&mut [&mut a, &mut b], 3.0, |e| e[1].count(&Event::Down) == 1), "the listener never saw the close");
    assert!(t.elapsed() < Duration::from_millis(400), "a close should not wait for the idle timeout: {:?}", t.elapsed());
    assert!(!b.up());
    assert!(!b.send.send(b"after the loss"), "queued with no connection");
}

#[test]
fn a_peer_that_goes_silent_is_a_down_at_the_idle_timeout() {
    let (mut a, mut b) = pair();
    connected(&mut a, &mut b);
    // The dialer's process dies: no close, no more packets.
    a.pump = None;
    let t = Instant::now();
    assert!(spin(&mut [&mut b], 5.0, |e| e[0].count(&Event::Down) == 1), "the listener never gave the silent peer up");
    let took = t.elapsed();
    assert!(took >= Duration::from_millis(300), "gave up after {took:?}, before the idle timeout could have passed");
}

#[test]
fn a_dialer_reconnects_after_the_listener_restarts() {
    let (mut a, mut b) = pair();
    connected(&mut a, &mut b);
    let at = b.addr();
    b.pump.as_mut().unwrap().close();
    spin(&mut [&mut a, &mut b], 1.0, |e| e[0].count(&Event::Down) == 1);
    assert_eq!(a.count(&Event::Down), 1);
    drop(b);
    // The same address, a new process: another key, another connection state.
    let mut b2 = listener(LO, Some(at), settings());
    assert!(spin(&mut [&mut a, &mut b2], 5.0, |e| e[0].up() && e[1].up()), "the dialer did not reconnect");
    assert_eq!(a.count(&Event::Up), 2);
    assert!(a.send.send(b"again"));
    assert!(spin(&mut [&mut a, &mut b2], 3.0, |e| e[1].frames().contains(&b"again".to_vec())));
}

#[test]
fn a_listener_takes_the_peers_new_connection_over_its_old_one() {
    let mut b = listener(LO, None, Settings { idle_timeout: Duration::from_secs(30), ..settings() });
    let mut a = dialer(b.addr(), Settings { idle_timeout: Duration::from_secs(30), ..settings() });
    connected(&mut a, &mut b);
    // The dialer restarts without closing; the listener still believes in the old connection.
    a.pump = None;
    let mut a2 = dialer(b.addr(), Settings { idle_timeout: Duration::from_secs(30), ..settings() });
    assert!(spin(&mut [&mut a2, &mut b], 5.0, |e| e[0].up() && e[1].count(&Event::Up) == 2), "the new connection was not taken");
    assert_eq!(b.count(&Event::Down), 1, "the replaced connection is a Down");
    assert!(a2.send.send(b"new"));
    assert!(spin(&mut [&mut a2, &mut b], 3.0, |e| e[1].frames().contains(&b"new".to_vec())));
}
