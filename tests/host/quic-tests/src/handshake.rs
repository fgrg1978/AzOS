// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Two quinn-proto endpoints with the adaptor's crypto, joined by a test that
//! carries their datagrams. If a header protection mask, a packet nonce or a
//! key derivation were wrong, this is where the handshake would not finish.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use azos_quic::crypto::{ResetKey, TokenKey};
use azos_quic::crypto::{HandshakeData, QuicServerConfig};
use azos_quic::identity::{client_crypto_with, server_crypto_with, Identity, SERVER_NAME};
use azos_quic::suite;
use bytes::BytesMut;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;
use rustls::CipherSuite;
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event, ServerConfig, StreamEvent, StreamId, TransportConfig,
};

const A: &str = "127.0.0.1:4000";
const B: &str = "127.0.0.1:4433";

struct End {
    ep: Endpoint,
    conn: Option<(ConnectionHandle, Connection)>,
    addr: SocketAddr,
    connected: bool,
    lost: bool,
    /// Frames received, by stream (finished streams only).
    got: Vec<Vec<u8>>,
    open: Vec<StreamId>,
    partial: HashMap<StreamId, Vec<u8>>,
}

fn endpoint(server: Option<Arc<ServerConfig>>) -> Endpoint {
    let cfg = EndpointConfig::new(Arc::new(ResetKey::random().unwrap()));
    Endpoint::new(Arc::new(cfg), server, false, None)
}

fn server_end(p: Arc<CryptoProvider>, id: &Identity) -> End {
    let cfg = ServerConfig::new(server_crypto_with(p, id).unwrap(), Arc::new(TokenKey::random().unwrap()));
    End { ep: endpoint(Some(Arc::new(cfg))), conn: None, addr: B.parse().unwrap(), connected: false, lost: false, got: vec![], open: vec![], partial: HashMap::new() }
}

fn client_end(p: Arc<CryptoProvider>, now: Instant) -> End {
    let mut e = End { ep: endpoint(None), conn: None, addr: A.parse().unwrap(), connected: false, lost: false, got: vec![], open: vec![], partial: HashMap::new() };
    let mut cfg = ClientConfig::new(client_crypto_with(p).unwrap());
    cfg.transport_config(Arc::new(TransportConfig::default()));
    e.conn = Some(e.ep.connect(now, cfg, B.parse().unwrap(), SERVER_NAME).unwrap());
    e
}

impl End {
    /// Everything the end has to say right now, as datagrams to the other.
    fn out(&mut self, now: Instant, wire: &mut Vec<(SocketAddr, Vec<u8>)>) {
        for _ in 0..16 {
            let Some((ch, c)) = self.conn.as_mut() else { return };
            if c.poll_timeout().is_some_and(|t| t <= now) {
                c.handle_timeout(now);
            }
            while let Some(ev) = c.poll_endpoint_events() {
                if let Some(ce) = self.ep.handle_event(*ch, ev) {
                    c.handle_event(ce);
                }
            }
            while let Some(ev) = c.poll() {
                match ev {
                    Event::Connected => self.connected = true,
                    Event::ConnectionLost { .. } => self.lost = true,
                    Event::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                        while let Some(id) = c.streams().accept(Dir::Uni) {
                            self.open.push(id);
                        }
                    }
                    _ => {}
                }
            }
            // Read the streams the peer opened.
            let mut ids = std::mem::take(&mut self.open);
            ids.retain(|&id| {
                let mut rs = c.recv_stream(id);
                let Ok(mut chunks) = rs.read(true) else { return false };
                let mut finished = false;
                loop {
                    match chunks.next(usize::MAX) {
                        Ok(Some(ch)) => self.partial.entry(id).or_default().extend_from_slice(&ch.bytes),
                        Ok(None) => {
                            self.got.push(self.partial.remove(&id).unwrap_or_default());
                            finished = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let _ = chunks.finalize();
                !finished
            });
            self.open = ids;
            let mut buf = Vec::new();
            let mut any = false;
            while let Some(t) = c.poll_transmit(now, 1, &mut buf) {
                wire.push((t.destination, buf[..t.size].to_vec()));
                buf.clear();
                any = true;
            }
            if !any {
                return;
            }
        }
    }

    fn input(&mut self, now: Instant, from: SocketAddr, data: &[u8], wire: &mut Vec<(SocketAddr, Vec<u8>)>) {
        let mut buf = Vec::new();
        match self.ep.handle(now, from, None, None, BytesMut::from(data), &mut buf) {
            Some(DatagramEvent::ConnectionEvent(_, ev)) => {
                if let Some((_, c)) = self.conn.as_mut() {
                    c.handle_event(ev);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                if let Ok((ch, c)) = self.ep.accept(incoming, now, &mut buf, None) {
                    self.conn = Some((ch, c));
                }
            }
            Some(DatagramEvent::Response(t)) => wire.push((t.destination, buf[..t.size].to_vec())),
            None => {}
        }
    }
}

/// Carry datagrams between the two ends until neither has more, advancing a clock.
fn run(c: &mut End, s: &mut End, mut now: Instant, rounds: usize) -> Instant {
    for _ in 0..rounds {
        let (mut to_s, mut to_c) = (Vec::new(), Vec::new());
        c.out(now, &mut to_s);
        s.out(now, &mut to_c);
        let quiet = to_s.is_empty() && to_c.is_empty();
        for (_, d) in to_s {
            let mut back = Vec::new();
            s.input(now, c.addr, &d, &mut back);
            to_c.extend(back);
        }
        for (_, d) in to_c {
            let mut back = Vec::new();
            c.input(now, s.addr, &d, &mut back);
            for (_, b) in back {
                let mut x = Vec::new();
                s.input(now, c.addr, &b, &mut x);
            }
        }
        if quiet && c.connected && s.connected {
            // Settled; let timers (acks) run a little.
            now += Duration::from_millis(30);
        } else {
            now += Duration::from_millis(2);
        }
    }
    now
}

fn pair_with(p: Arc<CryptoProvider>) -> (End, End, Instant) {
    let id = Identity::from_seed(&[7; 32]).unwrap();
    let now = Instant::now();
    let s = server_end(p.clone(), &id);
    let c = client_end(p, now);
    (c, s, now)
}

fn pair() -> (End, End, Instant) {
    pair_with(suite::provider())
}

fn suite_of(e: &End) -> Option<CipherSuite> {
    let (_, c) = e.conn.as_ref()?;
    c.crypto_session().handshake_data()?.downcast::<HandshakeData>().ok()?.suite
}

#[test]
fn the_provider_offers_quic_on_both_suites() {
    let p = suite::provider();
    assert_eq!(p.cipher_suites.len(), 2);
    for cs in &p.cipher_suites {
        assert!(cs.tls13().is_some_and(|s| s.quic_suite().is_some()), "{:?} has no QUIC protection", cs.suite());
    }
}

#[test]
fn a_handshake_completes_and_streams_carry_data_both_ways() {
    let (mut c, mut s, now) = pair();
    let now = run(&mut c, &mut s, now, 200);
    assert!(c.connected && s.connected, "the handshake did not finish");

    let (_, cc) = c.conn.as_mut().unwrap();
    let id = cc.streams().open(Dir::Uni).unwrap();
    cc.send_stream(id).write(b"from the client").unwrap();
    cc.send_stream(id).finish().unwrap();
    let (_, sc) = s.conn.as_mut().unwrap();
    let id = sc.streams().open(Dir::Uni).unwrap();
    sc.send_stream(id).write(&[0x5A; 1200]).unwrap();
    sc.send_stream(id).finish().unwrap();
    run(&mut c, &mut s, now, 200);

    assert_eq!(s.got, vec![b"from the client".to_vec()]);
    assert_eq!(c.got, vec![vec![0x5A; 1200]]);
}

/// **Canary:** the client must check the handshake signature against the key the
/// server presents, or a server could present anyone's public key. This server
/// presents the key of seed 9 and signs with the key of seed 7.
#[test]
fn a_server_that_signs_with_another_key_than_it_presents_does_not_connect() {
    let provider = suite::provider();
    let signer = {
        let mut pkcs8 = vec![0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
        pkcs8.extend_from_slice(&[7; 32]);
        provider.key_provider.load_private_key(PrivatePkcs8KeyDer::from(pkcs8).into()).unwrap()
    };
    let presented = Identity::from_seed(&[9; 32]).unwrap();
    let certified = CertifiedKey::new(vec![CertificateDer::from(presented.spki().to_vec())], signer);
    let mut config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(certified))));
    config.send_tls13_tickets = 0;
    let crypto = Arc::new(QuicServerConfig::new(Arc::new(config)).unwrap());
    let cfg = ServerConfig::new(crypto, Arc::new(TokenKey::random().unwrap()));
    let mut s = End { ep: endpoint(Some(Arc::new(cfg))), conn: None, addr: B.parse().unwrap(), connected: false, lost: false, got: vec![], open: vec![], partial: HashMap::new() };
    let now = Instant::now();
    let mut c = client_end(provider, now);
    run(&mut c, &mut s, now, 200);
    assert!(!c.connected, "connected to a server whose key does not verify its signature");
    assert!(c.lost, "the client should have given the connection up");
}

#[test]
fn a_stream_larger_than_one_packet_is_reassembled() {
    let (mut c, mut s, mut now) = pair();
    now = run(&mut c, &mut s, now, 200);
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7) as u8).collect();
    let id = c.conn.as_mut().unwrap().1.streams().open(Dir::Uni).unwrap();
    let mut off = 0;
    for _ in 0..200 {
        let cc = &mut c.conn.as_mut().unwrap().1;
        off += cc.send_stream(id).write(&data[off..]).unwrap_or(0);
        if off == data.len() {
            cc.send_stream(id).finish().unwrap();
            break;
        }
        now = run(&mut c, &mut s, now, 5);
    }
    assert_eq!(off, data.len(), "the stream never took all the data");
    run(&mut c, &mut s, now, 400);
    assert_eq!(s.got, vec![data]);
}

/// Both suites run a handshake and carry data: the header protection (AES-ECB
/// and ChaCha20 masks) and the packet protection of each are what has to be right
/// for a single packet to be read.
#[test]
fn each_suite_completes_a_handshake_and_moves_data() {
    for want in [CipherSuite::TLS13_AES_128_GCM_SHA256, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256] {
        let (mut c, mut s, mut now) = pair_with(suite::provider_only(want));
        now = run(&mut c, &mut s, now, 200);
        assert!(c.connected && s.connected, "{want:?}: the handshake did not finish");
        assert_eq!(suite_of(&c), Some(want), "the connection should run on the suite offered");
        assert_eq!(suite_of(&s), Some(want));
        let id = c.conn.as_mut().unwrap().1.streams().open(Dir::Uni).unwrap();
        let cc = &mut c.conn.as_mut().unwrap().1;
        cc.send_stream(id).write(&[0xA5; 900]).unwrap();
        cc.send_stream(id).finish().unwrap();
        run(&mut c, &mut s, now, 100);
        assert_eq!(s.got, vec![vec![0xA5; 900]], "{want:?}");
    }
}

/// **Canary:** an adaptor whose packet protection did not authenticate would let
/// a datagram with a flipped bit through.
#[test]
fn a_datagram_altered_on_the_way_is_not_accepted() {
    let (mut c, mut s, mut now) = pair();
    // Handshake, with every datagram from the client to the server damaged in its last byte.
    let mut damaged = 0;
    for _ in 0..300 {
        let (mut to_s, mut to_c) = (Vec::new(), Vec::new());
        c.out(now, &mut to_s);
        s.out(now, &mut to_c);
        damaged += to_s.len();
        for (_, mut d) in to_s {
            let last = d.len() - 1;
            d[last] ^= 1;
            let mut back = Vec::new();
            s.input(now, c.addr, &d, &mut back);
            to_c.extend(back);
        }
        for (_, d) in to_c {
            let mut back = Vec::new();
            c.input(now, s.addr, &d, &mut back);
        }
        now += Duration::from_millis(5);
    }
    assert!(damaged >= 2, "the client sent nothing to damage ({damaged}): the test would pass for any adaptor");
    assert!(!c.connected && !s.connected, "a handshake finished on datagrams that fail authentication");
}
