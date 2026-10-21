// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The driver of quinn-proto over a `std::net::UdpSocket`.
//!
//! quinn-proto is a state machine with no I/O: datagrams go in, datagrams and
//! timer deadlines come out. [`Pump`] is the loop around it for **one peer**: it
//! reads the socket, feeds the endpoint, moves the application's frames in and out
//! of QUIC streams, runs the timers and writes what the connection wants to send.
//! It is synchronous (no executor is vendored) and uses only what the std port of
//! `UdpSocket` has: `bind`, `recv_from` with a read timeout, `send_to`,
//! `set_nonblocking`.
//!
//! **A frame is a stream.** Each frame goes out on a fresh unidirectional stream
//! that is finished with it, so a lost packet delays the frames in it and no
//! others (one long-lived ordered stream would stall every later frame behind one
//! loss), and the receiver needs no framing: the end of the stream is the end of
//! the frame. QUIC retransmits what is lost, so the RPC engine's own resends are
//! duplicates the far node already dedupes.
//!
//! **Roles.** The two ends of a link are not symmetric in QUIC. [`Role::Dial`]
//! connects to the peer's address and reconnects after a loss; [`Role::Listen`]
//! answers the one peer address it is configured with (a datagram from any other
//! source address is dropped before QUIC sees it, like the plain UDP link) and
//! validates the peer's address with a Retry before it spends any state on it.
//! The RPC layer picks them by node id as it does for Noise: the lower id dials.
//!
//! **Threads.** [`Sender`] is the part other threads hold: a frame from the
//! local socket pushes onto its bounded queue and returns. The pump moves the queue
//! into streams the next time it runs, so a frame waits at most one `wait` (the
//! caller's poll interval, the way `rpcsrv`'s link thread polls).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use quinn_proto::{
    ClientConfig, Connection, ConnectionHandle, DatagramEvent, Dir, Endpoint, EndpointConfig, Event as QEvent, IdleTimeout,
    ReadError, ServerConfig, StreamEvent, StreamId, Transmit, TransportConfig, VarInt, WriteError,
};

use crate::crypto::{ResetKey, TokenKey};
use crate::identity::{self, Identity};

/// The most a frame carries: the RPC engine's `FRAME_MAX`.
pub const FRAME_MAX: usize = azos_rpc::wire::FRAME_MAX;

/// QUIC datagram size the connection starts at (and stays at: path MTU
/// discovery needs the don't-fragment bit, which the socket port does not
/// expose). A frame of [`FRAME_MAX`] bytes, a stream header and the packet
/// protection fit in one packet at this size on any Ethernet path.
const MTU: u16 = 1350;

/// Which end of the connection this pump is.
pub enum Role {
    /// Connect to `remote` (the RPC session authenticates the peer, see [`identity`]).
    Dial { remote: SocketAddr },
    /// Answer the peer at `peer`, presenting `identity`.
    Listen { peer: IpAddr, identity: Identity },
}

/// Tunables.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Silence after which a connection is lost (QUIC's idle timeout); a
    /// keep-alive at a third of it keeps a quiet link open. The caller is told
    /// [`Event::Down`] when it expires.
    pub idle_timeout: Duration,
    /// Time between attempts to connect (the dialing role).
    pub redial: Duration,
    /// Frames the outgoing queue holds; a full queue refuses the next one.
    pub queue: usize,
    /// Frames in flight at once in each direction (concurrent streams).
    pub streams: u32,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { idle_timeout: Duration::from_secs(5), redial: Duration::from_millis(500), queue: 64, streams: 64 }
    }
}

/// What the pump tells its owner.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The connection to the peer is established: frames can go.
    Up,
    /// The connection is gone (idle timeout, close from the peer, a failed
    /// handshake): everything queued to send was dropped (the RPC engine resends).
    Down,
    /// A frame from the peer.
    Frame(Vec<u8>),
}

struct Shared {
    out: Mutex<VecDeque<Vec<u8>>>,
    up: AtomicBool,
    cap: usize,
}

impl Shared {
    fn queue(&self) -> std::sync::MutexGuard<'_, VecDeque<Vec<u8>>> {
        self.out.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The handle other threads send frames through.
#[derive(Clone)]
pub struct Sender(Arc<Shared>);

impl Sender {
    /// Queue `frame` for the peer. `false` when there is no connection, the
    /// queue is full or the frame is larger than [`FRAME_MAX`]: the RPC engine
    /// treats it as a lost datagram and resends.
    pub fn send(&self, frame: &[u8]) -> bool {
        if frame.is_empty() || frame.len() > FRAME_MAX || !self.0.up.load(Ordering::Acquire) {
            return false;
        }
        let mut q = self.0.queue();
        if q.len() >= self.0.cap {
            return false;
        }
        q.push_back(frame.to_vec());
        true
    }
}

struct Conn {
    ch: ConnectionHandle,
    c: Connection,
    /// The handshake finished.
    up: bool,
    /// Lost or closed: no frame goes through it any more; it stays until it drains.
    dead: bool,
    /// Frames being received, by stream.
    readers: HashMap<StreamId, Vec<u8>>,
    /// Frames whose stream could not take them whole yet: (stream, frame, written).
    writes: Vec<(StreamId, Vec<u8>, usize)>,
}

/// The loop around one endpoint and its (at most one live) connection.
pub struct Pump {
    socket: UdpSocket,
    endpoint: Endpoint,
    dial: Option<(SocketAddr, ClientConfig)>,
    allowed: IpAddr,
    conns: Vec<Conn>,
    /// The connection frames go through.
    active: Option<ConnectionHandle>,
    shared: Arc<Shared>,
    events: VecDeque<Event>,
    scratch: Vec<u8>,
    inbuf: Vec<u8>,
    next_dial: Instant,
    settings: Settings,
}

fn transport(s: &Settings) -> io::Result<Arc<TransportConfig>> {
    let idle = IdleTimeout::try_from(s.idle_timeout).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(0))
        .max_concurrent_uni_streams(VarInt::from_u32(s.streams))
        .max_idle_timeout(Some(idle))
        .keep_alive_interval(Some(s.idle_timeout / 3))
        .initial_mtu(MTU)
        .min_mtu(MTU.min(1200))
        .mtu_discovery_config(None)
        // Frames only: the datagram extension is not offered.
        .datagram_receive_buffer_size(None)
        .stream_receive_window(VarInt::from_u32(8 * 1024))
        .receive_window(VarInt::from_u32(s.streams.saturating_mul(2 * 1024).max(64 * 1024)))
        .send_window(256 * 1024);
    Ok(Arc::new(t))
}

fn tls_error(e: rustls::Error) -> io::Error {
    io::Error::other(e.to_string())
}

fn entropy_error(e: getrandom04::Error) -> io::Error {
    io::Error::other(format!("entropy: {e}"))
}

impl Pump {
    /// Bind `local` and set up `role`. The returned [`Sender`] is the handle
    /// for the threads that feed frames in.
    pub fn bind(local: SocketAddr, role: Role, settings: Settings) -> io::Result<(Pump, Sender)> {
        let socket = UdpSocket::bind(local)?;
        let transport = transport(&settings)?;
        let reset = Arc::new(ResetKey::random().map_err(entropy_error)?);
        let mut ep_cfg = EndpointConfig::new(reset);
        ep_cfg.max_udp_payload_size(1472).map_err(|e| io::Error::other(e.to_string()))?;
        let (server, dial, allowed) = match role {
            Role::Dial { remote } => {
                let mut cfg = ClientConfig::new(identity::client_crypto().map_err(tls_error)?);
                cfg.transport_config(transport.clone());
                (None, Some((remote, cfg)), remote.ip())
            }
            Role::Listen { peer, identity } => {
                let token = Arc::new(TokenKey::random().map_err(entropy_error)?);
                let mut cfg = ServerConfig::new(identity::server_crypto(&identity).map_err(tls_error)?, token);
                cfg.transport = transport.clone();
                cfg.max_incoming(4).incoming_buffer_size(16 * 1024).incoming_buffer_size_total(64 * 1024);
                (Some(Arc::new(cfg)), None, peer)
            }
        };
        let endpoint = Endpoint::new(Arc::new(ep_cfg), server, false, None);
        let shared = Arc::new(Shared { out: Mutex::new(VecDeque::new()), up: AtomicBool::new(false), cap: settings.queue });
        let pump = Pump {
            socket,
            endpoint,
            dial,
            allowed,
            conns: Vec::new(),
            active: None,
            shared: shared.clone(),
            events: VecDeque::new(),
            scratch: Vec::new(),
            inbuf: vec![0; 2048],
            next_dial: Instant::now(),
            settings,
        };
        Ok((pump, Sender(shared)))
    }

    /// The address the socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The next thing that happened, oldest first.
    pub fn pop(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Close the connection (the peer is told) and stop sending.
    pub fn close(&mut self) {
        let now = Instant::now();
        for c in &mut self.conns {
            c.c.close(now, VarInt::from_u32(0), bytes::Bytes::from_static(b"closed"));
        }
        self.flush(now);
    }

    /// Run once: send what is queued, wait up to `wait` for datagrams (less, if a
    /// timer is due sooner), feed them in, run the timers and write what the
    /// connection wants to send. Results are read with [`Pump::pop`].
    pub fn drive(&mut self, wait: Duration) -> io::Result<()> {
        let now = Instant::now();
        self.maybe_dial(now);
        self.flush(now);
        let wait = self.wait_for(now, wait);
        self.receive(wait)?;
        self.flush(Instant::now());
        Ok(())
    }

    /// How long the socket may be waited on: the caller's `wait`, cut to the next
    /// timer, and nothing while frames are queued behind a stream limit.
    fn wait_for(&mut self, now: Instant, wait: Duration) -> Duration {
        let mut wait = wait;
        for c in &mut self.conns {
            if let Some(t) = c.c.poll_timeout() {
                wait = wait.min(t.saturating_duration_since(now));
            }
        }
        if self.dial.is_some() && self.active.is_none() {
            wait = wait.min(self.next_dial.saturating_duration_since(now));
        }
        // A read timeout of zero is "forever" to the socket; a millisecond is the floor.
        wait.max(Duration::from_millis(1))
    }

    /// The dialing role connects when it has no live connection.
    fn maybe_dial(&mut self, now: Instant) {
        let Some((remote, cfg)) = &self.dial else { return };
        if self.conns.iter().any(|c| !c.dead) || now < self.next_dial {
            return;
        }
        self.next_dial = now + self.settings.redial;
        if let Ok((ch, c)) = self.endpoint.connect(now, cfg.clone(), *remote, identity::SERVER_NAME) {
            self.conns.push(Conn { ch, c, up: false, dead: false, readers: HashMap::new(), writes: Vec::new() });
            self.active = Some(ch);
        }
    }

    fn send_one(&self, t: &Transmit, data: &[u8]) {
        // A datagram the socket will not take now is a lost datagram: QUIC resends.
        let _ = self.socket.send_to(&data[..t.size], t.destination);
    }

    fn receive(&mut self, wait: Duration) -> io::Result<()> {
        let mut first = true;
        loop {
            if first {
                self.socket.set_read_timeout(Some(wait))?;
            }
            match self.socket.recv_from(&mut self.inbuf) {
                Ok((n, from)) => {
                    if first {
                        // Take what else is already there without waiting for more.
                        self.socket.set_nonblocking(true)?;
                        first = false;
                    }
                    self.datagram(Instant::now(), from, n);
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => break,
                // An ICMP error for an earlier send, on the platforms that report it here.
                Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused | io::ErrorKind::Interrupted) => {}
                Err(e) => {
                    if !first {
                        let _ = self.socket.set_nonblocking(false);
                    }
                    return Err(e);
                }
            }
        }
        if !first {
            self.socket.set_nonblocking(false)?;
        }
        Ok(())
    }

    fn datagram(&mut self, now: Instant, from: SocketAddr, n: usize) {
        if from.ip() != self.allowed {
            return;
        }
        let data = BytesMut::from(&self.inbuf[..n]);
        self.scratch.clear();
        match self.endpoint.handle(now, from, None, None, data, &mut self.scratch) {
            None => {}
            Some(DatagramEvent::Response(t)) => self.send_one(&t, &self.scratch),
            Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                if let Some(c) = self.conns.iter_mut().find(|c| c.ch == ch) {
                    c.c.handle_event(ev);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                self.scratch.clear();
                if self.dial.is_some() {
                    // A dialing end expects nobody to call.
                    let t = self.endpoint.refuse(incoming, &mut self.scratch);
                    self.send_one(&t, &self.scratch);
                } else if !incoming.remote_address_validated() && incoming.may_retry() {
                    // Not yet proven to receive at that address: a Retry costs the
                    // server nothing and a spoofed source never answers it.
                    if let Ok(t) = self.endpoint.retry(incoming, &mut self.scratch) {
                        self.send_one(&t, &self.scratch);
                    }
                } else {
                    match self.endpoint.accept(incoming, now, &mut self.scratch, None) {
                        Ok((ch, c)) => {
                            // The peer connecting again means the old connection is gone
                            // (it restarted): the new one replaces it.
                            for old in self.conns.iter_mut().filter(|o| !o.dead) {
                                old.c.close(now, VarInt::from_u32(0), bytes::Bytes::from_static(b"replaced"));
                            }
                            self.conns.push(Conn { ch, c, up: false, dead: false, readers: HashMap::new(), writes: Vec::new() });
                            self.go_down_if_active_replaced(ch);
                        }
                        Err(e) => {
                            if let Some(t) = e.response {
                                self.send_one(&t, &self.scratch);
                            }
                        }
                    }
                }
            }
        }
    }

    /// A new connection takes over from the active one: the old one's frames are
    /// gone, which the owner hears as a Down.
    fn go_down_if_active_replaced(&mut self, new: ConnectionHandle) {
        if self.active.is_some_and(|a| a != new) && self.shared.up.swap(false, Ordering::AcqRel) {
            self.shared.queue().clear();
            self.events.push_back(Event::Down);
        }
        self.active = Some(new);
    }

    /// Everything that can move without waiting: timers, the endpoint's events,
    /// the connection's events, the queued frames into streams, and the
    /// connection's datagrams out.
    fn flush(&mut self, now: Instant) {
        for _ in 0..64 {
            let mut moved = false;
            for i in 0..self.conns.len() {
                moved |= self.step(i, now);
            }
            if !moved {
                break;
            }
        }
        for i in 0..self.conns.len() {
            loop {
                self.scratch.clear();
                let Some(t) = self.conns[i].c.poll_transmit(now, 1, &mut self.scratch) else { break };
                self.send_one(&t, &self.scratch);
            }
        }
        self.conns.retain(|c| !c.c.is_drained());
        if let Some(a) = self.active {
            if !self.conns.iter().any(|c| c.ch == a) {
                self.active = None;
            }
        }
    }

    /// One pass over connection `i`; whether anything moved.
    fn step(&mut self, i: usize, now: Instant) -> bool {
        let mut moved = false;
        let conn = &mut self.conns[i];
        if conn.c.poll_timeout().is_some_and(|t| t <= now) {
            conn.c.handle_timeout(now);
            moved = true;
        }
        while let Some(ev) = conn.c.poll_endpoint_events() {
            moved = true;
            if let Some(ce) = self.endpoint.handle_event(conn.ch, ev) {
                conn.c.handle_event(ce);
            }
        }
        let is_active = self.active == Some(conn.ch);
        while let Some(ev) = conn.c.poll() {
            moved = true;
            match ev {
                QEvent::Connected => {
                    conn.up = true;
                    if is_active {
                        self.shared.up.store(true, Ordering::Release);
                        self.events.push_back(Event::Up);
                    }
                }
                QEvent::ConnectionLost { .. } => {
                    conn.dead = true;
                    if is_active && self.shared.up.swap(false, Ordering::AcqRel) {
                        self.shared.queue().clear();
                        self.events.push_back(Event::Down);
                    }
                }
                QEvent::Stream(StreamEvent::Opened { dir: Dir::Uni }) => {
                    while let Some(id) = conn.c.streams().accept(Dir::Uni) {
                        read_frame(conn, id, &mut self.events);
                    }
                }
                QEvent::Stream(StreamEvent::Readable { id }) => read_frame(conn, id, &mut self.events),
                _ => {}
            }
        }
        if conn.up && !conn.dead && is_active {
            moved |= write_frames(conn, &self.shared);
        }
        moved
    }
}

/// Read what stream `id` has; when it has ended, that is a frame.
fn read_frame(conn: &mut Conn, id: StreamId, events: &mut VecDeque<Event>) {
    let buf = conn.readers.entry(id).or_default();
    let mut rs = conn.c.recv_stream(id);
    let Ok(mut chunks) = rs.read(true) else {
        conn.readers.remove(&id);
        return;
    };
    let mut done = false;
    let mut bad = false;
    loop {
        match chunks.next(usize::MAX) {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.bytes.len() > FRAME_MAX {
                    bad = true;
                    break;
                }
                buf.extend_from_slice(&chunk.bytes);
            }
            Ok(None) => {
                done = true;
                break;
            }
            Err(ReadError::Blocked) => break,
            Err(ReadError::Reset(_)) => {
                bad = true;
                break;
            }
        }
    }
    let _ = chunks.finalize();
    if done {
        let frame = conn.readers.remove(&id).unwrap_or_default();
        if !frame.is_empty() {
            events.push_back(Event::Frame(frame));
        }
    } else if bad {
        conn.readers.remove(&id);
        // A frame larger than any frame is not one: stop the sender.
        let _ = conn.c.recv_stream(id).stop(VarInt::from_u32(1));
    }
}

/// Put queued frames on fresh streams, and finish the writes that were blocked.
/// Whether anything moved.
fn write_frames(conn: &mut Conn, shared: &Shared) -> bool {
    let mut moved = false;
    let mut pending = std::mem::take(&mut conn.writes);
    pending.retain_mut(|(id, frame, off)| match conn.c.send_stream(*id).write(&frame[*off..]) {
        Ok(n) => {
            *off += n;
            if *off == frame.len() {
                let _ = conn.c.send_stream(*id).finish();
                moved = true;
                false
            } else {
                true
            }
        }
        Err(WriteError::Blocked) => true,
        Err(_) => false,
    });
    conn.writes = pending;
    loop {
        let mut q = shared.queue();
        let Some(frame) = q.front() else { break };
        let Some(id) = conn.c.streams().open(Dir::Uni) else { break };
        let frame = frame.clone();
        q.pop_front();
        drop(q);
        moved = true;
        match conn.c.send_stream(id).write(&frame) {
            Ok(n) if n == frame.len() => {
                let _ = conn.c.send_stream(id).finish();
            }
            Ok(n) => conn.writes.push((id, frame, n)),
            Err(WriteError::Blocked) => conn.writes.push((id, frame, 0)),
            Err(_) => {}
        }
    }
    moved
}
