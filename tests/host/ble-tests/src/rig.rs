// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The scripted controller and the radio between two of them.
//!
//! A [`Side`] is the controller behind one host's Uart port: it parses the H4
//! the host writes, answers the commands the way a conforming controller does
//! (command complete or status, with the credit field), and can be made to
//! misbehave (no credit, no answer, garbage, a late buffer return). The [`Rig`]
//! joins two hosts to two sides and carries ACL data and the link events
//! between them (connection, encryption, disconnection).

use azos_ble::hci::{self, status};
use azos_ble::smp::Role;
use azos_ble::{Config, Event, Host, PeerAddr, Platform, Upper};
use azos_devif::uart::{Chunk, ChunkSink, ChunkSource, CHUNK_DATA};
use std::collections::VecDeque;

/// xorshift64*: the platform's entropy.
pub struct Rng(pub u64);

impl Platform for Rng {
    fn random(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            *b = (self.0.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8;
        }
    }
}

/// What the upper layer saw, owned.
#[derive(Clone, Debug, PartialEq)]
pub enum Ev {
    Ready([u8; 6]),
    Failed(azos_ble::host::HostError),
    CommandFailed(u16, u8),
    Advert { peer: PeerAddr, kind: u8, data: Vec<u8>, rssi: i8 },
    Connected { conn: u16, role: Role, peer: PeerAddr },
    ConnectFailed(u8),
    Disconnected(u16, u8),
    ConnectionUpdated { conn: u16, interval: u16 },
    Mtu(u16, u16),
    Att(u16, Vec<u8>),
    Numeric(u16, u32),
    Encrypted(u16),
    EncryptionFailed(u16, u8),
    Paired(u16, azos_ble::smp::Keys),
    PairingFailed(u16, u8),
    SecurityRequest(u16),
}

/// The upper layer of the tests: records events, holds the key store.
#[derive(Default)]
pub struct Rec {
    pub events: Vec<Ev>,
    /// Keys the "store" holds, by peer.
    pub store: Vec<(PeerAddr, [u8; 16])>,
}

impl Upper for Rec {
    fn event(&mut self, ev: Event<'_>) {
        self.events.push(match ev {
            Event::Ready { addr } => Ev::Ready(addr),
            Event::Failed(e) => Ev::Failed(e),
            Event::CommandFailed { opcode, status } => Ev::CommandFailed(opcode, status),
            Event::Advert(r) => Ev::Advert { peer: r.peer, kind: r.kind, data: r.data.to_vec(), rssi: r.rssi },
            Event::Connected { conn, role, peer, .. } => Ev::Connected { conn, role, peer },
            Event::ConnectFailed { status } => Ev::ConnectFailed(status),
            Event::Disconnected { conn, reason } => Ev::Disconnected(conn, reason),
            Event::ConnectionUpdated { conn, interval, .. } => Ev::ConnectionUpdated { conn, interval },
            Event::Mtu { conn, mtu } => Ev::Mtu(conn, mtu),
            Event::Att { conn, pdu } => Ev::Att(conn, pdu.to_vec()),
            Event::Numeric { conn, value } => Ev::Numeric(conn, value),
            Event::Encrypted { conn } => Ev::Encrypted(conn),
            Event::EncryptionFailed { conn, status } => Ev::EncryptionFailed(conn, status),
            Event::Paired { conn, keys } => Ev::Paired(conn, keys),
            Event::PairingFailed { conn, reason } => Ev::PairingFailed(conn, reason),
            Event::SecurityRequest { conn } => Ev::SecurityRequest(conn),
        });
    }

    fn ltk(&mut self, peer: &PeerAddr) -> Option<[u8; 16]> {
        self.store.iter().find(|(p, _)| p == peer).map(|(_, k)| *k)
    }
}

impl Rec {
    pub fn take(&mut self) -> Vec<Ev> {
        std::mem::take(&mut self.events)
    }

    pub fn find<T>(&self, f: impl Fn(&Ev) -> Option<T>) -> Option<T> {
        self.events.iter().find_map(f)
    }
}

/// The receive ring as the host sees it: chunks of up to 32 bytes.
pub struct Src<'a>(pub &'a mut VecDeque<u8>, pub &'a mut VecDeque<u32>);

impl ChunkSource for Src<'_> {
    fn pop(&mut self) -> Option<Chunk> {
        if self.0.is_empty() {
            return None;
        }
        let n = self.0.len().min(CHUNK_DATA);
        let v: Vec<u8> = self.0.drain(..n).collect();
        let flags = self.1.pop_front().unwrap_or(0);
        Some(Chunk::new(&v, flags))
    }
}

/// The transmit ring: takes everything, or only `room` bytes more when limited.
pub struct Sink<'a> {
    pub out: &'a mut Vec<u8>,
    pub room: Option<usize>,
}

impl ChunkSink for Sink<'_> {
    fn push(&mut self, c: &Chunk) -> bool {
        if let Some(r) = self.room.as_mut() {
            if (c.len as usize) > *r {
                return false;
            }
            *r -= c.len as usize;
        }
        self.out.extend_from_slice(c.bytes());
        true
    }
}

/// A command the host sent.
#[derive(Clone, Debug, PartialEq)]
pub struct Sent {
    pub op: u16,
    pub params: Vec<u8>,
}

/// One controller.
pub struct Side {
    /// Bytes for the host (events and ACL data).
    pub rx: VecDeque<u8>,
    /// Flags to put on the chunk that starts at the front of `rx`'s next chunk.
    pub rx_flags: VecDeque<u32>,
    /// Bytes the host wrote, not yet parsed.
    pub from_host: Vec<u8>,
    pub cmds: Vec<Sent>,
    /// ACL fragments the host wrote: handle, pb flags, data.
    pub acl: Vec<(u16, u8, Vec<u8>)>,
    pub addr: [u8; 6],
    pub acl_len: u16,
    pub acl_num: u8,
    /// Credit the controller gives in command events.
    pub ncmd: u8,
    /// Do not answer commands at all.
    pub mute: bool,
    /// Status to answer these opcodes with.
    pub fail: Vec<(u16, u8)>,
    /// Keep the returned buffers instead of reporting them.
    pub hold_ncp: bool,
    pub held: u8,
    pub adv_enabled: bool,
    pub handle: Option<u16>,
    /// Host wrote something that was not a command or ACL packet.
    pub junk: u32,
    /// Waiting for the host's answer to an LTK request.
    pub pending_ltk_for: Option<u16>,
}

impl Side {
    pub fn new(addr: [u8; 6]) -> Side {
        Side {
            rx: VecDeque::new(),
            rx_flags: VecDeque::new(),
            from_host: vec![],
            cmds: vec![],
            acl: vec![],
            addr,
            acl_len: 27,
            acl_num: 4,
            ncmd: 1,
            mute: false,
            fail: vec![],
            hold_ncp: false,
            held: 0,
            adv_enabled: false,
            handle: None,
            junk: 0,
            pending_ltk_for: None,
        }
    }

    pub fn event(&mut self, code: u8, params: &[u8]) {
        self.rx.push_back(0x04);
        self.rx.push_back(code);
        self.rx.push_back(params.len() as u8);
        self.rx.extend(params.iter().copied());
    }

    pub fn le_event(&mut self, sub: u8, params: &[u8]) {
        let mut p = vec![sub];
        p.extend_from_slice(params);
        self.event(hci::EVT_LE_META, &p);
    }

    pub fn cc(&mut self, op: u16, ret: &[u8]) {
        let mut p = vec![self.ncmd];
        p.extend_from_slice(&op.to_le_bytes());
        p.extend_from_slice(ret);
        self.event(hci::EVT_COMMAND_COMPLETE, &p);
    }

    pub fn cs(&mut self, op: u16, st: u8) {
        let mut p = vec![st, self.ncmd];
        p.extend_from_slice(&op.to_le_bytes());
        self.event(hci::EVT_COMMAND_STATUS, &p);
    }

    pub fn acl_to_host(&mut self, handle: u16, pb: u8, data: &[u8]) {
        self.rx.push_back(0x02);
        let hf = handle | (pb as u16) << 12;
        self.rx.extend(hf.to_le_bytes());
        self.rx.extend((data.len() as u16).to_le_bytes());
        self.rx.extend(data.iter().copied());
    }

    /// Frame `payload` on `cid` and deliver it to the host in fragments of `frag` bytes.
    pub fn frame_to_host(&mut self, handle: u16, cid: u16, payload: &[u8], frag: usize) {
        let mut f = (payload.len() as u16).to_le_bytes().to_vec();
        f.extend_from_slice(&cid.to_le_bytes());
        f.extend_from_slice(payload);
        for (i, part) in f.chunks(frag).enumerate() {
            self.acl_to_host(handle, if i == 0 { 0 } else { 1 }, part);
        }
    }

    pub fn conn_complete(&mut self, handle: u16, role: u8, peer: PeerAddr) {
        let mut p = vec![0];
        p.extend_from_slice(&handle.to_le_bytes());
        p.push(role);
        p.push(peer.kind);
        p.extend_from_slice(&peer.addr);
        p.extend_from_slice(&24u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes());
        p.extend_from_slice(&400u16.to_le_bytes());
        p.push(0);
        self.le_event(hci::LE_CONNECTION_COMPLETE, &p);
        self.handle = Some(handle);
    }

    /// Parse what the host wrote and answer. Returns the commands that need
    /// the radio (the rig handles them).
    pub fn process(&mut self) -> Vec<Sent> {
        let mut radio = vec![];
        loop {
            let b = &self.from_host;
            if b.is_empty() {
                break;
            }
            match b[0] {
                0x01 => {
                    if b.len() < 4 || b.len() < 4 + b[3] as usize {
                        break;
                    }
                    let n = 4 + b[3] as usize;
                    let c = Sent { op: u16::from_le_bytes([b[1], b[2]]), params: b[4..n].to_vec() };
                    self.from_host.drain(..n);
                    self.cmds.push(c.clone());
                    if !self.mute {
                        if let Some(r) = self.answer(&c) {
                            radio.push(r);
                        }
                    }
                }
                0x02 => {
                    if b.len() < 5 || b.len() < 5 + u16::from_le_bytes([b[3], b[4]]) as usize {
                        break;
                    }
                    let len = u16::from_le_bytes([b[3], b[4]]) as usize;
                    let hf = u16::from_le_bytes([b[1], b[2]]);
                    let data = b[5..5 + len].to_vec();
                    self.from_host.drain(..5 + len);
                    assert!(len <= self.acl_len as usize, "ACL fragment past the controller's buffer length");
                    self.acl.push((hf & 0x0FFF, (hf >> 12) as u8 & 3, data));
                }
                _ => {
                    self.junk += 1;
                    self.from_host.remove(0);
                }
            }
        }
        radio
    }

    fn answer(&mut self, c: &Sent) -> Option<Sent> {
        let st = self.fail.iter().find(|(o, _)| *o == c.op).map(|(_, s)| *s).unwrap_or(0);
        match c.op {
            hci::OP_READ_BD_ADDR => {
                let mut r = vec![st];
                r.extend_from_slice(&self.addr);
                self.cc(c.op, &r);
            }
            hci::OP_LE_READ_BUFFER_SIZE => {
                let mut r = vec![st];
                r.extend_from_slice(&self.acl_len.to_le_bytes());
                r.push(self.acl_num);
                self.cc(c.op, &r);
            }
            hci::OP_LE_SET_ADV_ENABLE => {
                if st == 0 {
                    self.adv_enabled = c.params[0] != 0;
                }
                self.cc(c.op, &[st]);
            }
            hci::OP_LE_CREATE_CONNECTION | hci::OP_DISCONNECT | hci::OP_LE_START_ENCRYPTION | hci::OP_LE_CONNECTION_UPDATE => {
                self.cs(c.op, st);
                if st == 0 {
                    return Some(c.clone());
                }
            }
            hci::OP_LE_LTK_REPLY | hci::OP_LE_LTK_NEGATIVE_REPLY => {
                self.cc(c.op, &[st, c.params[0], c.params[1]]);
                return Some(c.clone());
            }
            _ => self.cc(c.op, &[st]),
        }
        None
    }

    /// Report the buffers of `handle` back to the host.
    pub fn complete(&mut self, handle: u16, n: u16) {
        let mut p = vec![1];
        p.extend_from_slice(&handle.to_le_bytes());
        p.extend_from_slice(&n.to_le_bytes());
        self.event(hci::EVT_NUM_COMPLETED_PACKETS, &p);
    }
}

/// Two hosts, two controllers, one radio.
pub struct Rig {
    pub a: Host<Rng>,
    pub b: Host<Rng>,
    pub ca: Side,
    pub cb: Side,
    pub ua: Rec,
    pub ub: Rec,
    pub now: u64,
    /// Applied to every complete L2CAP frame crossing the air (from side, cid,
    /// payload): a man in the middle.
    pub tamper: Option<Box<dyn FnMut(usize, u16, &mut Vec<u8>)>>,
    /// Frames that crossed the air: from side, cid, payload.
    pub air: Vec<(usize, u16, Vec<u8>)>,
    /// The central's key waiting for the peripheral's reply to LTK request.
    central_ltk: Option<[u8; 16]>,
    /// Handles of the link, by side.
    pub ha: u16,
    pub hb: u16,
    partial: [Vec<u8>; 2],
}

pub const ADDR_A: [u8; 6] = [0xCE, 0xBF, 0x37, 0x37, 0x12, 0x56];
pub const ADDR_B: [u8; 6] = [0xC1, 0xCF, 0x2D, 0x70, 0x13, 0xA7];

pub fn cfg(io: u8, mitm: bool) -> Config {
    Config {
        smp: azos_ble::smp::Config { io_cap: io, bonding: true, mitm, pairable: true },
        random_address: None,
        conn: hci::ConnParams { interval_min: 24, interval_max: 40, latency: 0, timeout: 400 },
    }
}

impl Rig {
    pub fn new(cfg_a: Config, cfg_b: Config) -> Rig {
        Rig {
            a: Host::new(Rng(0x1234_5678_9abc_def1), cfg_a),
            b: Host::new(Rng(0x0fed_cba9_8765_4321), cfg_b),
            ca: Side::new(ADDR_A),
            cb: Side::new(ADDR_B),
            ua: Rec::default(),
            ub: Rec::default(),
            now: 1000,
            tamper: None,
            air: vec![],
            central_ltk: None,
            ha: 0x0001,
            hb: 0x0002,
            partial: [vec![], vec![]],
        }
    }

    /// Run everything until nothing moves.
    pub fn settle(&mut self) {
        for _ in 0..400 {
            let mut moved = false;
            moved |= step_host(&mut self.a, &mut self.ca, &mut self.ua, self.now);
            moved |= step_host(&mut self.b, &mut self.cb, &mut self.ub, self.now);
            let ra = self.ca.process();
            let rb = self.cb.process();
            moved |= !ra.is_empty() || !rb.is_empty();
            for c in ra {
                self.radio(0, c);
            }
            for c in rb {
                self.radio(1, c);
            }
            moved |= self.forward_acl();
            if !moved {
                return;
            }
        }
        panic!("the rig never settled");
    }

    /// Bring both hosts to Ready.
    pub fn init(&mut self) {
        self.settle();
        assert!(self.a.ready() && self.b.ready(), "hosts not ready: {:?} {:?}", self.ua.events, self.ub.events);
    }

    /// Side B advertises, side A connects to it. A is the central.
    pub fn connect(&mut self) {
        self.b.start_advertising(adv_params(), b"\x02\x01\x06", b"").unwrap();
        self.settle();
        self.a.connect(PeerAddr { kind: 0, addr: ADDR_B }).unwrap();
        self.settle();
    }

    fn radio(&mut self, from: usize, c: Sent) {
        match c.op {
            hci::OP_LE_CREATE_CONNECTION => {
                if self.cb.adv_enabled {
                    self.cb.adv_enabled = false;
                    self.ca.conn_complete(self.ha, 0, PeerAddr { kind: 0, addr: ADDR_B });
                    self.cb.conn_complete(self.hb, 1, PeerAddr { kind: 0, addr: ADDR_A });
                } else {
                    // Nobody to connect to: the attempt fails.
                    let mut p = vec![0x3E];
                    p.extend_from_slice(&[0; 17]);
                    self.ca.le_event(hci::LE_CONNECTION_COMPLETE, &p);
                }
            }
            hci::OP_DISCONNECT => {
                let (me, other, mh, oh) = if from == 0 { (0, 1, self.ha, self.hb) } else { (1, 0, self.hb, self.ha) };
                let ev = |h: u16, reason: u8| {
                    let mut p = vec![0];
                    p.extend_from_slice(&h.to_le_bytes());
                    p.push(reason);
                    p
                };
                let local = ev(mh, status::LOCAL_HOST_TERMINATED);
                let remote = ev(oh, status::REMOTE_USER_TERMINATED);
                let (s_me, s_other) = if me == 0 { (&mut self.ca, &mut self.cb) } else { (&mut self.cb, &mut self.ca) };
                s_me.event(hci::EVT_DISCONNECTION_COMPLETE, &local);
                s_other.event(hci::EVT_DISCONNECTION_COMPLETE, &remote);
                let _ = other;
            }
            hci::OP_LE_START_ENCRYPTION => {
                // The central asks; the peripheral's controller asks its host.
                let mut ltk = [0u8; 16];
                ltk.copy_from_slice(&c.params[12..28]);
                self.central_ltk = Some(ltk);
                let mut p = vec![];
                p.extend_from_slice(&self.hb.to_le_bytes());
                p.extend_from_slice(&c.params[2..10]);
                p.extend_from_slice(&c.params[10..12]);
                self.cb.le_event(hci::LE_LTK_REQUEST, &p);
                self.cb.pending_ltk_for = Some(self.hb);
            }
            hci::OP_LE_LTK_REPLY | hci::OP_LE_LTK_NEGATIVE_REPLY => {
                let same = c.op == hci::OP_LE_LTK_REPLY && self.central_ltk == Some(c.params[2..18].try_into().unwrap());
                let st = if same { 0 } else { 0x06 };
                for (s, h) in [(&mut self.ca, self.ha), (&mut self.cb, self.hb)] {
                    let mut p = vec![st];
                    p.extend_from_slice(&h.to_le_bytes());
                    p.push(if same { 1 } else { 0 });
                    s.event(hci::EVT_ENCRYPTION_CHANGE, &p);
                }
                self.central_ltk = None;
            }
            hci::OP_LE_CONNECTION_UPDATE => {
                for (s, h) in [(&mut self.ca, self.ha), (&mut self.cb, self.hb)] {
                    let mut p = vec![0];
                    p.extend_from_slice(&h.to_le_bytes());
                    p.extend_from_slice(&c.params[2..4]);
                    p.extend_from_slice(&c.params[6..8]);
                    p.extend_from_slice(&c.params[8..10]);
                    s.le_event(hci::LE_CONNECTION_UPDATE_COMPLETE, &p);
                }
            }
            _ => {}
        }
    }

    /// Carry ACL fragments across. A frame is reassembled at the air interface,
    /// shown to the tamper hook and fragmented again to the receiver's buffer length.
    fn forward_acl(&mut self) -> bool {
        let mut moved = false;
        for from in 0..2 {
            let (src, dst, dh) = if from == 0 { (&mut self.ca, &mut self.cb, self.hb) } else { (&mut self.cb, &mut self.ca, self.ha) };
            let frags: Vec<_> = src.acl.drain(..).collect();
            for (h, pb, data) in frags {
                moved = true;
                // Report the buffer back at once unless held.
                if src.hold_ncp {
                    src.held += 1;
                } else {
                    src.complete(h, 1);
                }
                if pb == 0 {
                    self.partial[from].clear();
                }
                self.partial[from].extend_from_slice(&data);
                let buf = &self.partial[from];
                if buf.len() < 4 || buf.len() < 4 + u16::from_le_bytes([buf[0], buf[1]]) as usize {
                    continue;
                }
                let cid = u16::from_le_bytes([buf[2], buf[3]]);
                let mut payload = buf[4..].to_vec();
                self.partial[from].clear();
                self.air.push((from, cid, payload.clone()));
                if let Some(t) = self.tamper.as_mut() {
                    t(from, cid, &mut payload);
                }
                let mut f = (payload.len() as u16).to_le_bytes().to_vec();
                f.extend_from_slice(&cid.to_le_bytes());
                f.extend_from_slice(&payload);
                for (i, part) in f.chunks(dst.acl_len as usize).enumerate() {
                    dst.acl_to_host(dh, if i == 0 { 0 } else { 1 }, part);
                }
            }
        }
        moved
    }
}

pub fn adv_params() -> hci::AdvParams {
    hci::AdvParams { interval_min: 0x0800, interval_max: 0x0800, kind: hci::ADV_IND, own_addr_type: 0, channel_map: 7 }
}

/// Run one host against its controller for one round; true when bytes moved.
pub fn step_host(h: &mut Host<Rng>, c: &mut Side, up: &mut Rec, now: u64) -> bool {
    let before = (c.rx.len(), c.from_host.len());
    let mut flags = std::mem::take(&mut c.rx_flags);
    h.run(&mut Src(&mut c.rx, &mut flags), &mut Sink { out: &mut c.from_host, room: None }, now, up);
    c.rx_flags = flags;
    before != (c.rx.len(), c.from_host.len()) || !c.from_host.is_empty()
}
