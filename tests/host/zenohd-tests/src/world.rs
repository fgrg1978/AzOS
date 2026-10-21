// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The world around the gateway: a model of the kernel (decision journal,
//! warrants, the refusal switch), the service endpoint it calls, and the
//! router that speaks to it.

use crate::gw::{self, Config, Gw, Host, Invoked, Link, Warrant};
use crate::route::{Export, Iface};
use azos_decision::{Rule, Verdict};
use azos_decisions::{DecisionsIdl, Filter, ProvenanceRecord, Service, Source};
use azos_idl::{azos_interface, MsgDesc};
use azos_zenoh::codec::Writer;
use azos_zenoh::network::{NetworkMsg, WireExpr};
use azos_zenoh::transport::{
    decode_batch, encode_frame, split_stream, stream_prefix, Init, Lease, Open, Resolution, SizeParams,
    Transport as Msg, WhatAmI, VERSION,
};
use azos_zenoh::Zid;

// ── the service: a lamp with an effect ──────────────────────────────────────

/// An interface with an irreversible-looking effect (`set`) and a reader
/// (`get`), the shape of what a ROS 2 node asks the gateway for.
#[azos_interface(id = 0x4C41_4D50, level = 1, words = 4)]
pub trait Lamp {
    /// Set the level; the reply is the level before.
    #[once_only]
    #[on_failure(safe_state)]
    fn set(&mut self, level: u32) -> u32;
    /// The level.
    #[idempotent]
    fn get(&self) -> u32;
}

#[derive(Default)]
pub struct LampState {
    pub level: u32,
    pub sets: u32,
}

impl Lamp for LampState {
    fn set(&mut self, level: u32) -> u32 {
        self.sets += 1;
        core::mem::replace(&mut self.level, level)
    }
    fn get(&self) -> u32 {
        self.level
    }
}

pub const LAMP_COPY: Iface = Iface { id: LampIdl::ID, level: LampIdl::LEVEL, ops: &LampIdl::OPS };
pub static LAMP: Iface = LAMP_COPY;

/// The decisions the model holds, as a `Source`.
pub struct Held(pub Vec<ProvenanceRecord>);

impl Source for Held {
    fn total(&self) -> u64 {
        self.0.iter().map(|p| p.seq).max().unwrap_or(0)
    }
    fn query(&self, f: &Filter, out: &mut [u64]) -> usize {
        let mut n = 0;
        for p in self.0.iter().filter(|p| p.seq > f.after && f.matches(p)) {
            if n == out.len() {
                break;
            }
            out[n] = p.seq;
            n += 1;
        }
        n
    }
    fn lookup(&self, id: u64) -> Option<ProvenanceRecord> {
        self.0.iter().find(|p| p.seq == id).copied()
    }
}

// ── the kernel ───────────────────────────────────────────────────────────────

/// The subject the model writes the gateway's refusals under (its task id).
pub const ME: u32 = 7;
/// The subject of a derive record: the gateway's Domain, not its task id.
pub const DOMAIN: u32 = 70;

pub struct Kernel {
    pub now: u64,
    /// Every record ever written; `retain` of them are held (served).
    pub journal: Vec<ProvenanceRecord>,
    pub retain: usize,
    pub next: u64,
    /// Does the kernel admit the gateway's warrant?
    pub grant: bool,
    /// Does it refuse the call through a warrant it did admit?
    pub refuse_call: bool,
    /// Does it keep admissions (Kconfig `DECISION_RECORDS_DEV`), or only refusals?
    pub keep_admits: bool,
    pub lamp: LampState,
    pub warrants: Vec<Warrant>,
    pub invokes: u32,
    pub decisions_calls: u32,
    /// Records of other tasks (a refusal, a derive of their own), written while
    /// the op runs.
    pub foreign_during_op: bool,
    /// Another task's derive, written between the gateway's mark and its own derive.
    pub foreign_derive_first: bool,
    pub log: Vec<String>,
}

impl Kernel {
    pub fn new() -> Kernel {
        Kernel {
            now: 1_000_000_000,
            journal: Vec::new(),
            retain: usize::MAX,
            next: 1,
            grant: true,
            refuse_call: false,
            keep_admits: true,
            lamp: LampState::default(),
            warrants: Vec::new(),
            invokes: 0,
            decisions_calls: 0,
            foreign_during_op: false,
            foreign_derive_first: false,
            log: Vec::new(),
        }
    }

    /// Write a decision record the way the kernel does; its id.
    pub fn record(&mut self, rule: Rule, verdict: Verdict, subject: u32) -> u64 {
        self.record_n(rule, verdict, subject, [self.next, 0, 0])
    }

    /// [`record`](Self::record) with its three numbers.
    pub fn record_n(&mut self, rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) -> u64 {
        let mut p = ProvenanceRecord::new(rule as u8, verdict as u8, subject, n);
        p.seq = self.next;
        p.clock_ns = self.now;
        self.next += 1;
        self.journal.push(p);
        p.seq
    }

    fn held(&self) -> Held {
        let skip = self.journal.len().saturating_sub(self.retain);
        Held(self.journal[skip..].to_vec())
    }
}

impl Host for Kernel {
    fn now_ns(&mut self) -> u64 {
        self.now
    }

    fn log(&mut self, line: &str) {
        self.log.push(line.to_string());
    }

    fn invoke(&mut self, _endpoint: u32, req: &mut MsgDesc, w: &Warrant) -> Invoked {
        self.invokes += 1;
        self.warrants.push(*w);
        if !self.grant {
            // The kernel refuses the warrant and writes the refusal; nothing is
            // minted and nothing reaches the server.
            self.record(Rule::CapDenial, Verdict::Deny, ME);
            return Invoked { result: Err(-1), expiry_ns: 0 };
        }
        // The warrant is minted: the derive record is the Domain's, and its
        // third number is the expiry the gateway asked for.
        let expiry_ns = self.now + w.life_ns;
        if self.foreign_derive_first {
            self.record_n(Rule::CapDerive, Verdict::Admit, DOMAIN + 2, [0, 0, expiry_ns + 7]);
        }
        if self.keep_admits {
            self.record_n(Rule::CapDerive, Verdict::Admit, DOMAIN, [0, 0, expiry_ns]);
        }
        if self.foreign_during_op {
            self.record(Rule::CapDenial, Verdict::Deny, ME + 1);
            self.record_n(Rule::CapDerive, Verdict::Admit, DOMAIN + 1, [0, 0, expiry_ns + 1]);
        }
        if self.refuse_call {
            self.record(Rule::CapDenial, Verdict::Deny, ME);
            return Invoked { result: Err(-1), expiry_ns };
        }
        let mut rep = MsgDesc::default();
        let _ = LampIdl::dispatch(&mut self.lamp, req, &mut rep);
        *req = rep;
        Invoked { result: Ok(()), expiry_ns }
    }

    fn decisions(&mut self, req: &mut MsgDesc) -> Result<(), i64> {
        self.decisions_calls += 1;
        let mut svc = Service(self.held());
        let mut rep = MsgDesc::default();
        let _ = DecisionsIdl::dispatch(&mut svc, req, &mut rep);
        *req = rep;
        Ok(())
    }
}

// ── the link ─────────────────────────────────────────────────────────────────

/// What the gateway wrote: one entry per link write, the stream prefix off.
#[derive(Default)]
pub struct Wire {
    pub batches: Vec<Vec<u8>>,
    pub broken: bool,
}

impl Link for Wire {
    fn send(&mut self, bytes: &[u8]) -> bool {
        if self.broken {
            return false;
        }
        let (batch, rest) = split_stream(bytes).expect("a whole batch per write");
        assert!(rest.is_empty(), "one batch per write");
        self.batches.push(batch.to_vec());
        true
    }
}

impl Wire {
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.batches)
    }
}

/// The network messages of every FRAME in `batches`, each re-encoded to bytes
/// and decoded again where the test looks at them (`with_nets`).
pub fn with_nets<R>(batches: &[Vec<u8>], f: impl FnOnce(&[NetworkMsg<'_>]) -> R) -> R {
    let mut all = Vec::new();
    for b in batches {
        for m in decode_batch(b) {
            if let Msg::Frame(fr) = m.expect("the gateway writes decodable messages") {
                for n in fr.messages() {
                    all.push(n.expect("a decodable network message"));
                }
            }
        }
    }
    f(&all)
}

// ── the router ───────────────────────────────────────────────────────────────

pub fn zid(b: u8) -> Zid {
    Zid::new(&[b; 8]).unwrap()
}

/// Our ZenohID.
pub const MINE: [u8; 16] = [
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];

pub fn config() -> Config {
    Config {
        zid: Zid::new(&MINE).unwrap(),
        initial_sn: 0x1234,
        lease_ms: 10_000,
        timeout_max_ms: 2_000,
        query_rate: 100,
        topic: "azos/decisions",
        me: ME,
    }
}

pub fn lamp_exports() -> Vec<Export> {
    vec![Export { iface: &LAMP, endpoint: 3, key: "azos/lamp/**".to_string() }]
}

fn stream(batch: &[u8]) -> Vec<u8> {
    let mut v = stream_prefix(batch.len()).unwrap().to_vec();
    v.extend_from_slice(batch);
    v
}

/// The bytes of one transport message, stream-framed.
pub fn router_msg(m: &Msg<'_>) -> Vec<u8> {
    let mut w = Writer::new();
    m.encode(&mut w).unwrap();
    stream(w.as_slice())
}

/// The bytes of one FRAME carrying `msgs`, stream-framed.
pub fn router_frame(sn: u64, msgs: &[NetworkMsg<'_>]) -> Vec<u8> {
    let mut w = Writer::new();
    encode_frame(&mut w, true, sn, None, msgs).unwrap();
    stream(w.as_slice())
}

pub fn init_ack(cookie: &[u8]) -> Vec<u8> {
    router_msg(&Msg::Init(Init {
        version: VERSION,
        whatami: WhatAmI::Router,
        zid: zid(0x11),
        size: Some(SizeParams { resolution: Resolution::DEFAULT, batch_size: 2048 }),
        cookie: Some(cookie),
        qos: false,
        patch: 0,
    }))
}

pub fn open_ack(lease_s: u64) -> Vec<u8> {
    router_msg(&Msg::Open(Open { lease: Lease { value: lease_s, seconds: true }, initial_sn: 5, cookie: None, qos: false }))
}

/// A session brought up: the gateway, its kernel, its wire (emptied).
pub fn up_with(cfg: Config, exports: Vec<Export>) -> (Gw, Kernel, Wire) {
    let (mut k, mut wire) = (Kernel::new(), Wire::default());
    let mut g = Gw::new(cfg, exports);
    g.start(&mut k, &mut wire);
    g.on_bytes(&mut k, &mut wire, &init_ack(&[1, 2, 3, 4]));
    g.on_bytes(&mut k, &mut wire, &open_ack(10));
    assert_eq!(g.state(), gw::State::Up);
    wire.take();
    (g, k, wire)
}

pub fn up() -> (Gw, Kernel, Wire) {
    up_with(config(), lamp_exports())
}

/// Decode a gateway write's first message as the transport message it is.
pub fn first_transport(batch: &[u8]) -> Msg<'_> {
    decode_batch(batch).next().unwrap().unwrap()
}

pub fn words(w: &[u64]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub fn plain(k: &str) -> WireExpr<'_> {
    WireExpr::plain(k)
}
