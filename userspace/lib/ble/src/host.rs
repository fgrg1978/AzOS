// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The host: a controller behind a `Uart` port, brought up and run.
//!
//! One [`Host`] owns the whole conversation: it initialises the controller
//! (reset, event masks, address, buffer sizes), keeps the two flow-control
//! disciplines (one command in flight and the controller's command credit; the
//! controller's ACL buffers, returned by `Number Of Completed Packets`), runs
//! advertising, scanning and connections in both roles, reassembles and
//! fragments L2CAP, answers the signalling channel, runs the ATT bearer and the
//! SMP pairing of every connection, and tells the upper layer what happened
//! ([`Event`]).
//!
//! # Data flow
//!
//! ```text
//!   RxQueue ──Chunk──▶ rx_chunk ─▶ H4 deframer ─▶ event / ACL ─▶ Upper::event
//!   TxQueue ◀─Chunk── pump_tx  ◀─ tx ring     ◀─ commands, ACL fragments
//! ```
//!
//! [`Host::run`] is the one step a service calls when its rings have something
//! or its timer fired; the pieces ([`Host::rx_chunk`], [`Host::tick`],
//! [`Host::pump_tx`]) are public for a caller that wants them apart. Calls the
//! upper layer makes (`start_advertising`, `att_send`, ...) only queue; the next
//! `tick` or `run` puts the bytes on the transmit ring. The upper layer is
//! called back **from inside** `rx_chunk` and `tick`, with borrowed payloads and
//! no way back into the host: what it wants to do in answer it does after the
//! call returns.

use crate::att::{self, Bearer, Pdu as AttPdu};
use crate::h4::{self, Deframer, Kind};
use crate::hci::{self, AdvParams, Cmd, ConnComplete, ConnParams, ScanParams};
use crate::l2cap::{self, Reassembled, Reassembler, Signal};
use crate::smp::{self, Actions, Ctx, Role, Smp};
use crate::{le16, Error, PeerAddr, Platform, CMD_QUEUE, L2CAP_MTU, MAX_CONN, TX_RING};
use azos_devif::uart::{Chunk, ChunkSink, ChunkSource, CHUNK_BREAK, CHUNK_DATA, CHUNK_FRAMING, CHUNK_OVERRUN, CHUNK_PARITY};

/// Milliseconds a command may stay unanswered.
pub const COMMAND_TIMEOUT_MS: u64 = 5_000;
/// Milliseconds of silence after which a half packet is dropped.
pub const PARTIAL_TIMEOUT_MS: u64 = 250;
/// Outbound L2CAP frames waiting for the controller's buffers.
const SDU_QUEUE: usize = 4;

/// How the host behaves; the policy, not the environment.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Pairing: capabilities, bonding, MITM protection.
    pub smp: smp::Config,
    /// A static random address to set and use; `None` uses the public address
    /// the controller reports.
    pub random_address: Option<[u8; 6]>,
    /// Parameters of the connections this host creates.
    pub conn: ConnParams,
}

/// What stopped the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    /// A command of the initialisation failed.
    Init { opcode: u16, status: u8 },
    /// The controller never answered a command.
    CommandTimeout { opcode: u16 },
    /// The controller reports no LE buffers.
    NoLeBuffers,
    /// The controller said it had a hardware error.
    Hardware(u8),
}

/// What the host tells the upper layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// The controller is initialised; `addr` is the address in use.
    Ready { addr: [u8; 6] },
    /// The host stopped; [`Host::restart`] starts it again.
    Failed(HostError),
    /// A command the upper layer caused failed.
    CommandFailed { opcode: u16, status: u8 },
    /// A scan result.
    Advert(hci::AdvReport<'a>),
    Connected { conn: u16, role: Role, peer: PeerAddr, interval: u16, latency: u16, timeout: u16 },
    /// A connection attempt ended without a link.
    ConnectFailed { status: u8 },
    Disconnected { conn: u16, reason: u8 },
    ConnectionUpdated { conn: u16, interval: u16, latency: u16, timeout: u16 },
    /// The ATT MTU exchange finished; `mtu` is in force.
    Mtu { conn: u16, mtu: u16 },
    /// An ATT PDU the host did not answer itself (decode with
    /// [`att::Pdu::parse`]); a request must be answered with [`Host::att_send`].
    Att { conn: u16, pdu: &'a [u8] },
    /// Numeric comparison: show `value` (six digits) and answer with
    /// [`Host::confirm_numeric`].
    Numeric { conn: u16, value: u32 },
    /// The link is encrypted.
    Encrypted { conn: u16 },
    /// Encryption failed or was refused by the controller (`status`).
    EncryptionFailed { conn: u16, status: u8 },
    /// Pairing ended well: store `keys` and offer them through [`Upper::ltk`].
    Paired { conn: u16, keys: smp::Keys },
    /// Pairing ended in failure with an [`smp::reason`].
    PairingFailed { conn: u16, reason: u8 },
    /// The peripheral asks the central to secure the link: answer with
    /// [`Host::pair`], or [`Host::encrypt`] with a stored key.
    SecurityRequest { conn: u16 },
}

/// The upper layer: GATT, or the bring-up harness.
pub trait Upper {
    fn event(&mut self, ev: Event<'_>);

    /// The key stored for `peer` (the key store, a later front). Asked when the
    /// controller wants the key of an encrypted reconnection. No key by default.
    fn ltk(&mut self, _peer: &PeerAddr) -> Option<[u8; 16]> {
        None
    }
}

/// Why a call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// The controller is not initialised (or stopped).
    NotReady,
    /// No such connection.
    NoConnection,
    /// A transaction of that kind is in flight.
    Busy,
    /// The PDU does not fit the MTU.
    TooBig,
    /// Not allowed in this state (a response nobody asked for).
    NotAllowed,
    /// The queue towards the controller is full; try after the next `tick`.
    QueueFull,
    /// A parameter is out of range.
    Invalid,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Init,
    Ready,
    Dead,
}

struct Conn {
    used: bool,
    handle: u16,
    role: Role,
    peer: PeerAddr,
    own: PeerAddr,
    encrypted: bool,
    /// ACL fragments sent and not yet reported complete.
    inflight: u8,
    re: Reassembler,
    att: Bearer,
    smp: Smp,
    /// Identifier of the next signalling request.
    sig_id: u8,
}

impl Conn {
    const fn empty() -> Conn {
        Conn {
            used: false,
            handle: 0,
            role: Role::Initiator,
            peer: PeerAddr { kind: 0, addr: [0; 6] },
            own: PeerAddr { kind: 0, addr: [0; 6] },
            encrypted: false,
            inflight: 0,
            re: Reassembler::new(),
            att: Bearer::new(),
            smp: Smp::new(),
            sig_id: 1,
        }
    }
}

/// A frame waiting for ACL buffers.
#[derive(Clone, Copy)]
struct Pending {
    handle: u16,
    cid: u16,
    len: u16,
    data: [u8; L2CAP_MTU],
}

struct TxRing {
    buf: [u8; TX_RING],
    head: usize,
    len: usize,
}

impl TxRing {
    const fn new() -> TxRing {
        TxRing { buf: [0; TX_RING], head: 0, len: 0 }
    }

    fn free(&self) -> usize {
        TX_RING - self.len
    }

    /// The whole of `b` or nothing.
    fn push(&mut self, b: &[u8]) -> bool {
        if b.len() > self.free() {
            return false;
        }
        for &x in b {
            self.buf[(self.head + self.len) % TX_RING] = x;
            self.len += 1;
        }
        true
    }

    fn peek(&self) -> Option<Chunk> {
        if self.len == 0 {
            return None;
        }
        let n = self.len.min(CHUNK_DATA);
        let mut d = [0u8; CHUNK_DATA];
        for (i, slot) in d.iter_mut().enumerate().take(n) {
            *slot = self.buf[(self.head + i) % TX_RING];
        }
        Some(Chunk::new(&d[..n], 0))
    }

    fn consume(&mut self, n: usize) {
        let n = n.min(self.len);
        self.head = (self.head + n) % TX_RING;
        self.len -= n;
    }
}

/// Everything but the deframer and the platform, so that a packet borrowed
/// from the first can be handled by the rest.
struct Core {
    cfg: Config,
    phase: Phase,
    init_left: u8,
    tx: TxRing,
    cmds: [Option<Cmd>; CMD_QUEUE],
    cmd_head: usize,
    cmd_len: usize,
    /// Command in flight: opcode and when it expires.
    inflight: Option<(u16, u64)>,
    /// Commands the controller will accept.
    ncmd: u8,
    public_addr: [u8; 6],
    acl_len: usize,
    acl_credits: u8,
    acl_total: u8,
    conns: [Conn; MAX_CONN],
    sdus: [Option<Pending>; SDU_QUEUE],
    sdu_head: usize,
    sdu_len: usize,
    /// Bytes of the front frame already sent.
    sdu_sent: usize,
    /// Undecodable events dropped.
    bad_events: u32,
}

/// The host.
pub struct Host<P: Platform> {
    fr: Deframer,
    plat: P,
    last_rx_ms: u64,
    core: Core,
}

impl<P: Platform> Host<P> {
    /// A host whose initialisation is queued: the first `tick` or `run` sends
    /// the reset.
    pub fn new(plat: P, cfg: Config) -> Host<P> {
        let mut h = Host {
            fr: Deframer::new(),
            plat,
            last_rx_ms: 0,
            core: Core {
                cfg,
                phase: Phase::Init,
                init_left: 0,
                tx: TxRing::new(),
                cmds: [None; CMD_QUEUE],
                cmd_head: 0,
                cmd_len: 0,
                inflight: None,
                ncmd: 1,
                public_addr: [0; 6],
                acl_len: 0,
                acl_credits: 0,
                acl_total: 0,
                conns: [const { Conn::empty() }; MAX_CONN],
                sdus: [None; SDU_QUEUE],
                sdu_head: 0,
                sdu_len: 0,
                sdu_sent: 0,
                bad_events: 0,
            },
        };
        h.core.queue_init();
        h
    }

    /// Start over after [`Event::Failed`]: connections are reported gone and
    /// the controller is reset and initialised again.
    pub fn restart(&mut self, up: &mut dyn Upper) {
        for c in self.core.conns.iter_mut().filter(|c| c.used) {
            c.smp.wipe();
            c.used = false;
            up.event(Event::Disconnected { conn: c.handle, reason: hci::status::LOCAL_HOST_TERMINATED });
        }
        self.fr.reset();
        let cfg = self.core.cfg;
        self.core = Host::new(NoPlatform, cfg).core;
    }

    /// The step: drain `src`, run the timers, fill `sink`.
    pub fn run(&mut self, src: &mut dyn ChunkSource, sink: &mut dyn ChunkSink, now_ms: u64, up: &mut dyn Upper) {
        while let Some(c) = src.pop() {
            self.rx_chunk(&c, now_ms, up);
        }
        self.tick(now_ms, up);
        self.pump_tx(sink);
    }

    /// Take a chunk the receive ring delivered.
    pub fn rx_chunk(&mut self, c: &Chunk, now_ms: u64, up: &mut dyn Upper) {
        self.last_rx_ms = now_ms;
        if c.flags & (CHUNK_OVERRUN | CHUNK_BREAK | CHUNK_FRAMING | CHUNK_PARITY) != 0 {
            // Bytes were lost or damaged: the half packet is not to be trusted.
            self.fr.reset();
        }
        for &b in c.bytes() {
            if let Some(kind) = self.fr.push(b) {
                self.core.on_packet(kind, self.fr.body(), now_ms, &mut self.plat, up);
            }
        }
    }

    /// Timers, then the queues towards the controller.
    pub fn tick(&mut self, now_ms: u64, up: &mut dyn Upper) {
        if self.fr.partial() && now_ms.saturating_sub(self.last_rx_ms) >= PARTIAL_TIMEOUT_MS {
            self.fr.reset();
        }
        self.core.timers(now_ms, up);
        self.core.service(now_ms);
    }

    /// Move the bytes ready for the controller into `sink` (the transmit ring);
    /// what the ring has no room for stays for the next call.
    pub fn pump_tx(&mut self, sink: &mut dyn ChunkSink) {
        while let Some(c) = self.core.tx.peek() {
            if !sink.push(&c) {
                break;
            }
            self.core.tx.consume(c.len as usize);
        }
    }

    /// Framing counters (garbage dropped, packets delivered).
    pub fn framing(&self) -> h4::Stats {
        self.fr.stats
    }

    /// Whether the controller is initialised.
    pub fn ready(&self) -> bool {
        self.core.phase == Phase::Ready
    }

    /// The address in use, once ready.
    pub fn address(&self) -> PeerAddr {
        self.core.own()
    }

    /// The ATT MTU in force on a connection.
    pub fn mtu(&self, conn: u16) -> Option<u16> {
        self.core.conn(conn).map(|c| c.att.mtu())
    }

    /// Whether the link of a connection is encrypted.
    pub fn encrypted(&self, conn: u16) -> bool {
        self.core.conn(conn).is_some_and(|c| c.encrypted)
    }

    // ── Advertising, scanning, connections ─────────────────────────────────

    /// Advertise `data` (and answer scans with `scan_rsp`), at the intervals of
    /// `params`. A connectable advertisement ends with a connection.
    pub fn start_advertising(&mut self, params: AdvParams, data: &[u8], scan_rsp: &[u8]) -> Result<(), SendError> {
        if data.len() > 31 || scan_rsp.len() > 31 {
            return Err(SendError::Invalid);
        }
        let c = &mut self.core;
        c.need_ready(4)?;
        let (mut d, mut s) = ([0u8; 31], [0u8; 31]);
        d[..data.len()].copy_from_slice(data);
        s[..scan_rsp.len()].copy_from_slice(scan_rsp);
        let params = AdvParams { own_addr_type: c.own().kind, ..params };
        c.queue(Cmd::LeSetAdvParams(params));
        c.queue(Cmd::LeSetAdvData { len: data.len() as u8, data: d });
        c.queue(Cmd::LeSetScanRspData { len: scan_rsp.len() as u8, data: s });
        c.queue(Cmd::LeSetAdvEnable(true));
        Ok(())
    }

    pub fn stop_advertising(&mut self) -> Result<(), SendError> {
        self.core.need_ready(1)?;
        self.core.queue(Cmd::LeSetAdvEnable(false));
        Ok(())
    }

    /// Scan; every advertisement arrives as [`Event::Advert`].
    pub fn start_scan(&mut self, params: ScanParams) -> Result<(), SendError> {
        let c = &mut self.core;
        c.need_ready(2)?;
        let params = ScanParams { own_addr_type: c.own().kind, ..params };
        c.queue(Cmd::LeSetScanParams(params));
        c.queue(Cmd::LeSetScanEnable { enable: true, filter_duplicates: true });
        Ok(())
    }

    pub fn stop_scan(&mut self) -> Result<(), SendError> {
        self.core.need_ready(1)?;
        self.core.queue(Cmd::LeSetScanEnable { enable: false, filter_duplicates: false });
        Ok(())
    }

    /// Create a connection to `peer` as the central, with the configured
    /// parameters. The answer is [`Event::Connected`] or [`Event::ConnectFailed`].
    pub fn connect(&mut self, peer: PeerAddr) -> Result<(), SendError> {
        let c = &mut self.core;
        c.need_ready(1)?;
        let own_addr_type = c.own().kind;
        c.queue(Cmd::LeCreateConnection { peer, own_addr_type, params: c.cfg.conn });
        Ok(())
    }

    pub fn cancel_connect(&mut self) -> Result<(), SendError> {
        self.core.need_ready(1)?;
        self.core.queue(Cmd::LeCreateConnectionCancel);
        Ok(())
    }

    pub fn disconnect(&mut self, conn: u16, reason: u8) -> Result<(), SendError> {
        let c = &mut self.core;
        c.need_ready(1)?;
        c.conn(conn).ok_or(SendError::NoConnection)?;
        c.queue(Cmd::Disconnect { handle: conn, reason });
        Ok(())
    }

    /// Ask for other connection parameters: the central tells its controller,
    /// the peripheral asks the central over the signalling channel.
    pub fn update_connection(&mut self, conn: u16, params: ConnParams) -> Result<(), SendError> {
        if !params.valid() {
            return Err(SendError::Invalid);
        }
        let c = &mut self.core;
        c.need_ready(1)?;
        let (role, id) = {
            let cn = c.conn_mut(conn).ok_or(SendError::NoConnection)?;
            let id = cn.sig_id;
            cn.sig_id = cn.sig_id.wrapping_add(1).max(1);
            (cn.role, id)
        };
        match role {
            Role::Initiator => {
                c.queue(Cmd::LeConnectionUpdate { handle: conn, params });
            }
            Role::Responder => {
                let sig = Signal::ConnectionParameterUpdateReq {
                    id,
                    interval_min: params.interval_min,
                    interval_max: params.interval_max,
                    latency: params.latency,
                    timeout: params.timeout,
                };
                let mut b = [0u8; 16];
                let n = sig.encode(&mut b).map_err(|_| SendError::Invalid)?;
                if !c.send_sdu(conn, l2cap::CID_SIGNALLING, &b[..n]) {
                    return Err(SendError::QueueFull);
                }
            }
        }
        Ok(())
    }

    // ── ATT ────────────────────────────────────────────────────────────────

    /// Send an ATT PDU on a connection, under the bearer's rules (one request
    /// in flight, one indication in flight, the MTU, a response only to a
    /// request received).
    pub fn att_send(&mut self, conn: u16, pdu: &AttPdu, now_ms: u64) -> Result<(), SendError> {
        self.core.att_send(conn, pdu, now_ms)
    }

    /// Start the MTU exchange (once per connection).
    pub fn exchange_mtu(&mut self, conn: u16, now_ms: u64) -> Result<(), SendError> {
        self.core.att_send(conn, &AttPdu::ExchangeMtuReq { mtu: att::LOCAL_MTU }, now_ms)
    }

    // ── Security ───────────────────────────────────────────────────────────

    /// Pair, as the central.
    pub fn pair(&mut self, conn: u16, now_ms: u64, up: &mut dyn Upper) -> Result<(), SendError> {
        let c = &mut self.core;
        c.need_ready(0)?;
        let ctx = c.ctx(conn).ok_or(SendError::NoConnection)?;
        if ctx.role != Role::Initiator {
            return Err(SendError::NotAllowed);
        }
        let i = c.index(conn).ok_or(SendError::NoConnection)?;
        let a = c.conns[i].smp.start(&ctx, now_ms);
        c.apply(i, a, up);
        Ok(())
    }

    /// Encrypt the link with a key kept from an earlier pairing, as the central.
    pub fn encrypt(&mut self, conn: u16, ltk: [u8; 16]) -> Result<(), SendError> {
        let c = &mut self.core;
        c.need_ready(1)?;
        let cn = c.conn(conn).ok_or(SendError::NoConnection)?;
        if cn.role != Role::Initiator {
            return Err(SendError::NotAllowed);
        }
        c.queue(Cmd::LeStartEncryption { handle: conn, rand: [0; 8], ediv: 0, ltk });
        Ok(())
    }

    /// Ask the central to secure the link, as the peripheral.
    pub fn security_request(&mut self, conn: u16) -> Result<(), SendError> {
        let c = &mut self.core;
        let cn = c.conn(conn).ok_or(SendError::NoConnection)?;
        if cn.role != Role::Responder {
            return Err(SendError::NotAllowed);
        }
        let auth = c.cfg.smp.bonding as u8 | smp::auth::SC | if c.cfg.smp.mitm { smp::auth::MITM } else { 0 };
        let s = smp::Pdu::SecurityRequest(auth).encode();
        if c.send_sdu(conn, l2cap::CID_SMP, s.bytes()) {
            Ok(())
        } else {
            Err(SendError::QueueFull)
        }
    }

    /// The user's verdict on the digits of [`Event::Numeric`].
    pub fn confirm_numeric(&mut self, conn: u16, ok: bool, up: &mut dyn Upper) -> Result<(), SendError> {
        let c = &mut self.core;
        let ctx = c.ctx(conn).ok_or(SendError::NoConnection)?;
        let i = c.index(conn).ok_or(SendError::NoConnection)?;
        let a = c.conns[i].smp.user_confirm(&ctx, ok);
        c.apply(i, a, up);
        Ok(())
    }
}

/// The platform of a core being rebuilt in [`Host::restart`]: never asked.
struct NoPlatform;

impl Platform for NoPlatform {
    fn random(&mut self, out: &mut [u8]) {
        out.fill(0);
    }
}

impl Core {
    fn queue_init(&mut self) {
        let mut init = [Some(Cmd::Reset); 6];
        init[1] = Some(Cmd::SetEventMask(hci::EVENT_MASK));
        init[2] = Some(Cmd::LeSetEventMask(hci::LE_EVENT_MASK));
        init[3] = Some(Cmd::ReadBdAddr);
        init[4] = Some(Cmd::LeReadBufferSize);
        init[5] = self.cfg.random_address.map(Cmd::LeSetRandomAddress);
        for c in init.into_iter().flatten() {
            self.queue(c);
            self.init_left += 1;
        }
    }

    /// The address in use.
    fn own(&self) -> PeerAddr {
        match self.cfg.random_address {
            Some(a) => PeerAddr { kind: 1, addr: a },
            None => PeerAddr { kind: 0, addr: self.public_addr },
        }
    }

    fn need_ready(&self, room: usize) -> Result<(), SendError> {
        if self.phase != Phase::Ready {
            return Err(SendError::NotReady);
        }
        if CMD_QUEUE - self.cmd_len < room {
            return Err(SendError::QueueFull);
        }
        Ok(())
    }

    fn queue(&mut self, c: Cmd) -> bool {
        if self.cmd_len == CMD_QUEUE {
            return false;
        }
        self.cmds[(self.cmd_head + self.cmd_len) % CMD_QUEUE] = Some(c);
        self.cmd_len += 1;
        true
    }

    fn index(&self, handle: u16) -> Option<usize> {
        self.conns.iter().position(|c| c.used && c.handle == handle)
    }

    fn conn(&self, handle: u16) -> Option<&Conn> {
        self.index(handle).map(|i| &self.conns[i])
    }

    fn conn_mut(&mut self, handle: u16) -> Option<&mut Conn> {
        self.index(handle).map(|i| &mut self.conns[i])
    }

    fn ctx(&self, handle: u16) -> Option<Ctx> {
        self.conn(handle).map(|c| Ctx { role: c.role, own: c.own, peer: c.peer, cfg: self.cfg.smp })
    }

    /// Queue one L2CAP frame for the connection; `false` when the queue is full.
    fn send_sdu(&mut self, handle: u16, cid: u16, payload: &[u8]) -> bool {
        if self.sdu_len == SDU_QUEUE || payload.len() > L2CAP_MTU {
            return false;
        }
        let mut data = [0u8; L2CAP_MTU];
        data[..payload.len()].copy_from_slice(payload);
        self.sdus[(self.sdu_head + self.sdu_len) % SDU_QUEUE] =
            Some(Pending { handle, cid, len: payload.len() as u16, data });
        self.sdu_len += 1;
        true
    }

    fn att_send(&mut self, conn: u16, pdu: &AttPdu, now_ms: u64) -> Result<(), SendError> {
        if self.phase != Phase::Ready {
            return Err(SendError::NotReady);
        }
        let mut b = [0u8; L2CAP_MTU];
        let n = pdu.encode(&mut b).map_err(|_| SendError::TooBig)?;
        if self.sdu_len == SDU_QUEUE {
            return Err(SendError::QueueFull);
        }
        let c = self.conn_mut(conn).ok_or(SendError::NoConnection)?;
        c.att.sending(pdu, n, now_ms).map_err(|r| match r {
            att::Refusal::Busy => SendError::Busy,
            att::Refusal::TooBig => SendError::TooBig,
            att::Refusal::NotAllowed => SendError::NotAllowed,
        })?;
        self.send_sdu(conn, att::CID_ATT, &b[..n]);
        Ok(())
    }

    // ── Receive ────────────────────────────────────────────────────────────

    fn on_packet(&mut self, kind: Kind, body: &[u8], now_ms: u64, plat: &mut dyn Platform, up: &mut dyn Upper) {
        match kind {
            Kind::Event => self.on_event(body, up),
            Kind::Acl => self.on_acl(body, now_ms, plat, up),
        }
    }

    fn fail(&mut self, e: HostError, up: &mut dyn Upper) {
        self.phase = Phase::Dead;
        self.cmd_len = 0;
        self.inflight = None;
        up.event(Event::Failed(e));
    }

    fn on_event(&mut self, body: &[u8], up: &mut dyn Upper) {
        let Ok(ev) = hci::Event::parse(body) else {
            self.bad_events += 1;
            return;
        };
        match ev {
            hci::Event::CommandComplete { ncmd, opcode, ret } => {
                self.ncmd = ncmd;
                if opcode == 0 {
                    return;
                }
                if matches!(self.inflight, Some((o, _)) if o == opcode) {
                    self.inflight = None;
                }
                let status = ret.first().copied().unwrap_or(hci::status::UNKNOWN_COMMAND);
                self.command_done(opcode, status, ret, up);
            }
            hci::Event::CommandStatus { status, ncmd, opcode } => {
                self.ncmd = ncmd;
                if matches!(self.inflight, Some((o, _)) if o == opcode) {
                    self.inflight = None;
                }
                if status != 0 {
                    self.command_done(opcode, status, &[], up);
                }
            }
            hci::Event::HardwareError(code) => self.fail(HostError::Hardware(code), up),
            hci::Event::NumCompletedPackets(list) => {
                for i in 0..list.len() {
                    let Some((h, n)) = list.get(i) else { continue };
                    if let Some(c) = self.conn_mut(h) {
                        let back = (n.min(u8::MAX as u16) as u8).min(c.inflight);
                        c.inflight -= back;
                        self.acl_credits = (self.acl_credits + back).min(self.acl_total);
                    }
                }
            }
            hci::Event::DisconnectionComplete { status, handle, reason } => {
                if status != 0 {
                    return;
                }
                let Some(i) = self.index(handle) else { return };
                let c = &mut self.conns[i];
                self.acl_credits = (self.acl_credits + c.inflight).min(self.acl_total);
                c.smp.wipe();
                c.re.clear();
                c.used = false;
                up.event(Event::Disconnected { conn: handle, reason });
            }
            hci::Event::LeConnectionComplete(cc) => self.on_connected(cc, up),
            hci::Event::LeAdvertisingReport(reports) => {
                for i in 0..reports.len() {
                    if let Some(r) = reports.get(i) {
                        up.event(Event::Advert(r));
                    }
                }
            }
            hci::Event::LeConnectionUpdateComplete { status, handle, interval, latency, timeout } => {
                if status == 0 && self.index(handle).is_some() {
                    up.event(Event::ConnectionUpdated { conn: handle, interval, latency, timeout });
                }
            }
            hci::Event::EncryptionChange { status, handle, enabled } => {
                let Some(i) = self.index(handle) else { return };
                let ok = status == 0 && enabled != 0;
                self.conns[i].encrypted = ok;
                if ok {
                    up.event(Event::Encrypted { conn: handle });
                } else {
                    up.event(Event::EncryptionFailed { conn: handle, status });
                }
                if let Some(ctx) = self.ctx(handle) {
                    let a = self.conns[i].smp.encryption_changed(&ctx, ok);
                    self.apply(i, a, up);
                }
            }
            hci::Event::LeLtkRequest { handle, rand, ediv } => {
                let Some(i) = self.index(handle) else { return };
                let mut key = self.conns[i].smp.ltk_request(&rand, ediv);
                if key.is_none() && ediv == 0 && rand == [0; 8] {
                    key = up.ltk(&self.conns[i].peer);
                }
                match key {
                    Some(ltk) => self.queue(Cmd::LeLtkReply { handle, ltk }),
                    None => self.queue(Cmd::LeLtkNegativeReply { handle }),
                };
            }
            hci::Event::Other(_) => {}
        }
    }

    /// A command finished with `status` (complete, or refused by its status).
    fn command_done(&mut self, opcode: u16, status: u8, ret: &[u8], up: &mut dyn Upper) {
        let init = self.phase == Phase::Init;
        if status != 0 {
            if init {
                self.fail(HostError::Init { opcode, status }, up);
            } else {
                up.event(Event::CommandFailed { opcode, status });
            }
            return;
        }
        match opcode {
            hci::OP_READ_BD_ADDR if ret.len() >= 7 => self.public_addr.copy_from_slice(&ret[1..7]),
            hci::OP_LE_READ_BUFFER_SIZE if ret.len() >= 4 => {
                self.acl_len = (le16(ret, 1) as usize).min(h4::ACL_DATA_MAX);
                self.acl_total = ret[3];
                self.acl_credits = ret[3];
                if self.acl_len == 0 || self.acl_total == 0 {
                    self.fail(HostError::NoLeBuffers, up);
                    return;
                }
            }
            _ => {}
        }
        if init {
            self.init_left -= 1;
            if self.init_left == 0 {
                self.phase = Phase::Ready;
                up.event(Event::Ready { addr: self.own().addr });
            }
        }
    }

    fn on_connected(&mut self, cc: ConnComplete, up: &mut dyn Upper) {
        if cc.status != 0 {
            up.event(Event::ConnectFailed { status: cc.status });
            return;
        }
        let own = self.own();
        let Some(i) = self.conns.iter().position(|c| !c.used) else {
            self.queue(Cmd::Disconnect { handle: cc.handle, reason: hci::status::LOCAL_HOST_TERMINATED });
            return;
        };
        let role = if cc.role == 0 { Role::Initiator } else { Role::Responder };
        let c = &mut self.conns[i];
        *c = Conn::empty();
        c.used = true;
        c.handle = cc.handle;
        c.role = role;
        c.peer = cc.peer;
        c.own = own;
        up.event(Event::Connected {
            conn: cc.handle,
            role,
            peer: cc.peer,
            interval: cc.interval,
            latency: cc.latency,
            timeout: cc.timeout,
        });
    }

    fn on_acl(&mut self, body: &[u8], now_ms: u64, plat: &mut dyn Platform, up: &mut dyn Upper) {
        let Ok((hdr, data)) = l2cap::parse_acl(body) else {
            self.bad_events += 1;
            return;
        };
        let Some(i) = self.index(hdr.handle) else { return };
        match self.conns[i].re.push(hdr.pb, data) {
            Reassembled::Frame { cid, len } => {
                let mut f = [0u8; L2CAP_MTU];
                f[..len].copy_from_slice(self.conns[i].re.frame(len));
                self.on_frame(i, cid, &f[..len], now_ms, plat, up);
            }
            Reassembled::Pending | Reassembled::Dropped => {}
        }
    }

    fn on_frame(&mut self, i: usize, cid: u16, f: &[u8], now_ms: u64, plat: &mut dyn Platform, up: &mut dyn Upper) {
        match cid {
            att::CID_ATT => self.on_att(i, f, now_ms, up),
            l2cap::CID_SIGNALLING => self.on_signalling(i, f),
            l2cap::CID_SMP => self.on_smp(i, f, now_ms, plat, up),
            _ => {}
        }
    }

    fn on_att(&mut self, i: usize, f: &[u8], now_ms: u64, up: &mut dyn Upper) {
        let handle = self.conns[i].handle;
        let pdu = match AttPdu::parse(f) {
            Ok(p) => p,
            Err(e) => {
                // A request nobody can decode is answered; the rest is ignored.
                let opc = f.first().copied().unwrap_or(0);
                let request = opc & 0x40 == 0 && opc & 1 == 0 && opc != 0;
                if request || att::class_of(opc) == Some(att::Class::Request) {
                    let code = if e == Error::Unknown { att::err::REQUEST_NOT_SUPPORTED } else { att::err::INVALID_PDU };
                    let rsp = AttPdu::ErrorRsp { request: opc, handle: 0, code };
                    let mut b = [0u8; 5];
                    if let Ok(n) = rsp.encode(&mut b) {
                        self.send_sdu(handle, att::CID_ATT, &b[..n]);
                    }
                }
                return;
            }
        };
        match self.conns[i].att.received(&pdu) {
            Ok(true) => {}
            Ok(false) => return,
            Err(()) => return,
        }
        match pdu {
            AttPdu::ExchangeMtuReq { mtu } => {
                let answer = match self.conns[i].att.peer_mtu(mtu) {
                    Some(local) => AttPdu::ExchangeMtuRsp { mtu: local },
                    None => AttPdu::ErrorRsp {
                        request: att::op::EXCHANGE_MTU_REQ,
                        handle: 0,
                        code: att::err::REQUEST_NOT_SUPPORTED,
                    },
                };
                let exchanged = matches!(answer, AttPdu::ExchangeMtuRsp { .. });
                if self.att_send(handle, &answer, now_ms).is_ok() && exchanged {
                    up.event(Event::Mtu { conn: handle, mtu: self.conns[i].att.mtu() });
                }
            }
            AttPdu::ExchangeMtuRsp { .. } | AttPdu::ErrorRsp { request: att::op::EXCHANGE_MTU_REQ, .. } => {
                up.event(Event::Mtu { conn: handle, mtu: self.conns[i].att.mtu() });
            }
            _ => up.event(Event::Att { conn: handle, pdu: f }),
        }
    }

    fn on_signalling(&mut self, i: usize, f: &[u8]) {
        let handle = self.conns[i].handle;
        let role = self.conns[i].role;
        let Ok(sig) = Signal::parse(f) else { return };
        let mut out = [0u8; 16];
        let answer = match sig {
            Signal::ConnectionParameterUpdateReq { id, interval_min, interval_max, latency, timeout } => {
                if role != Role::Initiator {
                    // Only the central may be asked.
                    Some(Signal::CommandReject { id, reason: l2cap::sig::REASON_NOT_UNDERSTOOD })
                } else {
                    let p = ConnParams { interval_min, interval_max, latency, timeout };
                    let ok = p.valid();
                    if ok {
                        self.queue(Cmd::LeConnectionUpdate { handle, params: p });
                    }
                    let result =
                        if ok { l2cap::sig::UPDATE_ACCEPTED } else { l2cap::sig::UPDATE_REJECTED };
                    Some(Signal::ConnectionParameterUpdateRsp { id, result })
                }
            }
            Signal::LeCreditConnectionReq { id, .. } => {
                Some(Signal::LeCreditConnectionRsp { id, result: l2cap::sig::RESULT_PSM_NOT_SUPPORTED })
            }
            Signal::DisconnectionReq { id, .. } => {
                Some(Signal::CommandReject { id, reason: l2cap::sig::REASON_NOT_UNDERSTOOD })
            }
            // A request code (even) this host has no use for is rejected; a
            // response and a credit grant (which has no answer) are not.
            Signal::Other { code, id } if code % 2 == 0 && code != 0 && code != l2cap::sig::FLOW_CONTROL_CREDIT => {
                Some(Signal::CommandReject { id, reason: l2cap::sig::REASON_NOT_UNDERSTOOD })
            }
            _ => None,
        };
        if let Some(a) = answer {
            if let Ok(n) = a.encode(&mut out) {
                self.send_sdu(handle, l2cap::CID_SIGNALLING, &out[..n]);
            }
        }
    }

    fn on_smp(&mut self, i: usize, f: &[u8], now_ms: u64, plat: &mut dyn Platform, up: &mut dyn Upper) {
        let handle = self.conns[i].handle;
        let Some(ctx) = self.ctx(handle) else { return };
        match smp::Pdu::parse(f) {
            Ok(smp::Pdu::SecurityRequest(_)) => {
                if ctx.role == Role::Initiator {
                    up.event(Event::SecurityRequest { conn: handle });
                }
            }
            Ok(pdu) => {
                let a = self.conns[i].smp.on_pdu(&ctx, &pdu, now_ms, plat);
                self.apply(i, a, up);
            }
            // Key distribution is not negotiated; a peer that sends it anyway
            // is not answered. Anything else is not something we do.
            Err(Error::Unknown) if (smp::code::ENCRYPTION_INFORMATION..=0x0A).contains(&f[0]) => {}
            Err(Error::Unknown) if f[0] == smp::code::KEYPRESS_NOTIFICATION => {}
            Err(e) => {
                let why = if e == Error::Unknown { smp::reason::COMMAND_NOT_SUPPORTED } else { smp::reason::INVALID_PARAMETERS };
                let s = smp::Pdu::PairingFailed(why).encode();
                self.send_sdu(handle, l2cap::CID_SMP, s.bytes());
            }
        }
    }

    /// Carry out what the pairing machine asked for.
    fn apply(&mut self, i: usize, a: Actions, up: &mut dyn Upper) {
        let handle = self.conns[i].handle;
        for s in a.send.iter().flatten() {
            self.send_sdu(handle, l2cap::CID_SMP, s.bytes());
        }
        if let Some(value) = a.numeric {
            up.event(Event::Numeric { conn: handle, value });
        }
        if let Some(ltk) = a.start_encryption {
            self.queue(Cmd::LeStartEncryption { handle, rand: [0; 8], ediv: 0, ltk });
        }
        if let Some(reason) = a.failed {
            up.event(Event::PairingFailed { conn: handle, reason });
        }
        if let Some(keys) = a.keys {
            up.event(Event::Paired { conn: handle, keys });
        }
    }

    // ── Timers and the queues towards the controller ───────────────────────

    fn timers(&mut self, now_ms: u64, up: &mut dyn Upper) {
        if let Some((opcode, deadline)) = self.inflight {
            if now_ms >= deadline {
                self.fail(HostError::CommandTimeout { opcode }, up);
                return;
            }
        }
        for i in 0..MAX_CONN {
            if !self.conns[i].used {
                continue;
            }
            let handle = self.conns[i].handle;
            if self.conns[i].smp.expired(now_ms) {
                up.event(Event::PairingFailed { conn: handle, reason: smp::reason::TIMEOUT });
                self.queue(Cmd::Disconnect { handle, reason: hci::status::LOCAL_HOST_TERMINATED });
            }
            if self.conns[i].att.expired(now_ms) {
                // A transaction that never finished: the specification closes the bearer.
                self.queue(Cmd::Disconnect { handle, reason: hci::status::LOCAL_HOST_TERMINATED });
                self.conns[i].att = Bearer::new();
            }
        }
    }

    fn service(&mut self, now_ms: u64) {
        self.pump_cmd(now_ms);
        self.pump_acl();
    }

    fn pump_cmd(&mut self, now_ms: u64) {
        if self.inflight.is_some() || self.ncmd == 0 || self.cmd_len == 0 {
            return;
        }
        let Some(cmd) = self.cmds[self.cmd_head] else { return };
        let mut params = [0u8; hci::CMD_PARAM_MAX];
        let (opcode, n) = cmd.encode(&mut params);
        let mut pkt = [0u8; 4 + hci::CMD_PARAM_MAX];
        let Some(len) = h4::command(opcode, &params[..n], &mut pkt) else { return };
        if !self.tx.push(&pkt[..len]) {
            return;
        }
        self.cmds[self.cmd_head] = None;
        self.cmd_head = (self.cmd_head + 1) % CMD_QUEUE;
        self.cmd_len -= 1;
        self.inflight = Some((opcode, now_ms + COMMAND_TIMEOUT_MS));
        self.ncmd = 0;
    }

    fn pump_acl(&mut self) {
        while self.sdu_len > 0 && self.acl_credits > 0 {
            let Some(front) = self.sdus[self.sdu_head] else { break };
            let Some(ci) = self.index(front.handle) else {
                // The connection went away with the frame still queued.
                self.pop_sdu();
                continue;
            };
            let mut frame = [0u8; 4 + L2CAP_MTU];
            let Some(total) = l2cap::frame(front.cid, &front.data[..front.len as usize], &mut frame) else {
                self.pop_sdu();
                continue;
            };
            let off = self.sdu_sent;
            let n = (total - off).min(self.acl_len);
            let mut pkt = [0u8; 5 + h4::ACL_DATA_MAX];
            let pb = if off == 0 { l2cap::PB_FIRST } else { l2cap::PB_CONTINUATION };
            let Some(len) = h4::acl(front.handle, pb, &frame[off..off + n], &mut pkt) else {
                self.pop_sdu();
                continue;
            };
            if !self.tx.push(&pkt[..len]) {
                break;
            }
            self.acl_credits -= 1;
            self.conns[ci].inflight += 1;
            self.sdu_sent += n;
            if self.sdu_sent == total {
                self.pop_sdu();
            }
        }
    }

    fn pop_sdu(&mut self) {
        self.sdus[self.sdu_head] = None;
        self.sdu_head = (self.sdu_head + 1) % SDU_QUEUE;
        self.sdu_len -= 1;
        self.sdu_sent = 0;
    }
}
