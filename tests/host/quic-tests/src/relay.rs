// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The relay (`rpcquic`) between two `rpcsrv` stand-ins: plain UDP sockets that
//! send a datagram to their relay and read what the peer's sent.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use azos_quic::relay::{self, Relay};
use azos_quic::{Identity, Role, Settings};

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn udp() -> UdpSocket {
    let s = UdpSocket::bind(SocketAddr::new(LO, 0)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    s
}

fn free_port() -> u16 {
    udp().local_addr().unwrap().port()
}

/// One node: the `rpcsrv` stand-in, and the relay that serves it.
struct Node {
    rpcsrv: UdpSocket,
    relay_at: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<std::io::Result<()>>>,
}

impl Node {
    fn start(role: impl FnOnce() -> Role, quic: SocketAddr) -> Node {
        let rpcsrv = udp();
        let local = udp();
        let relay_at = local.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let r = Relay {
            local,
            rpcsrv: rpcsrv.local_addr().unwrap(),
            quic,
            role: role(),
            settings: Settings { idle_timeout: Duration::from_millis(600), redial: Duration::from_millis(100), queue: 64, streams: 64 },
        };
        let flag = stop.clone();
        let thread = Some(std::thread::spawn(move || relay::run(r, &flag, |_| {})));
        Node { rpcsrv, relay_at, stop, thread }
    }

    /// Datagrams that reach the stand-in within `secs`, until it has `n`.
    fn read(&self, n: usize, secs: f64) -> BTreeSet<Vec<u8>> {
        let end = Instant::now() + Duration::from_secs_f64(secs);
        let mut got = BTreeSet::new();
        let mut buf = [0u8; 2048];
        while got.len() < n && Instant::now() < end {
            if let Ok((len, from)) = self.rpcsrv.recv_from(&mut buf) {
                assert_eq!(from, self.relay_at, "a datagram that did not come from the relay");
                got.insert(buf[..len].to_vec());
            }
        }
        got
    }

    fn stop(&mut self) -> std::io::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap()
    }
}

fn pair() -> (Node, Node) {
    let (qa, qb) = (SocketAddr::new(LO, free_port()), SocketAddr::new(LO, free_port()));
    let b = Node::start(|| Role::Listen { peer: LO, identity: Identity::generate().unwrap() }, qb);
    let a = Node::start(|| Role::Dial { remote: qb }, qa);
    (a, b)
}

/// Send `frames` from `from` until the far stand-in has them all (the first
/// ones may be lost while the connection is coming up, as on the plain link).
fn deliver(from: &Node, to: &Node, frames: &BTreeSet<Vec<u8>>) -> BTreeSet<Vec<u8>> {
    let end = Instant::now() + Duration::from_secs(8);
    let mut got = BTreeSet::new();
    while Instant::now() < end && got.len() < frames.len() {
        for f in frames {
            from.rpcsrv.send_to(f, from.relay_at).unwrap();
        }
        got.extend(to.read(frames.len(), 0.3));
    }
    got
}

#[test]
fn frames_cross_the_relays_both_ways() {
    let (mut a, mut b) = pair();
    let up: BTreeSet<Vec<u8>> = (0..20u8).map(|i| vec![i; 1 + i as usize * 59]).collect();
    let down: BTreeSet<Vec<u8>> = (0..20u8).map(|i| vec![0x80 | i; 1200 - i as usize]).collect();
    assert_eq!(deliver(&a, &b, &up), up);
    assert_eq!(deliver(&b, &a, &down), down);
    a.stop().unwrap();
    b.stop().unwrap();
}

/// **Canary:** a relay that took frames from anyone on the loopback would be a
/// way into the connection for every other program on the node.
#[test]
fn a_datagram_from_a_socket_that_is_not_rpcsrv_is_not_relayed() {
    let (mut a, mut b) = pair();
    // Positive control first: the connection is up and relaying.
    let probe: BTreeSet<Vec<u8>> = [b"probe".to_vec()].into();
    assert_eq!(deliver(&a, &b, &probe), probe);
    let stranger = udp();
    for _ in 0..5 {
        stranger.send_to(b"from a stranger", a.relay_at).unwrap();
    }
    assert!(b.read(1, 1.0).is_empty(), "a stranger's datagram crossed the relay");
    a.stop().unwrap();
    b.stop().unwrap();
}

/// The address `rpcsrv` and the relay name each other by is this host's, on the
/// way to the peer (the stack has no 127.0.0.0/8, so it is never assumed).
#[test]
fn own_ip_is_the_address_toward_the_peer() {
    assert_eq!(relay::own_ip(SocketAddr::new(LO, 9)).unwrap(), LO);
}
