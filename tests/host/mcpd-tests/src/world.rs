// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The world around the bridge: a model of the kernel (decision journal,
//! warrants, the refusal switches), the service endpoints it calls, the
//! operator who signs warrants, and the MCP client that speaks to it.

use crate::bridge::{Bridge, Config, Host, Invoked, Link, Warrant};
use crate::catalog::{Export, Iface};
use crate::warrant::{to_hex, Keys};
use azos_abi::error::Errno;
use azos_decision::{Rule, Verdict};
use azos_decisions::{DecisionsIdl, Filter, ProvenanceRecord, Service, Source};
use azos_idl::{azos_interface, MsgDesc};
use azos_mcp::json::Value;
use azos_rpc::wire::{cav, put_token, Caveat, Token, TOKEN_MAX};

// ── the services ─────────────────────────────────────────────────────────────

/// A lamp: a reader and an irreversible effect.
#[azos_interface(id = 0x4C41_4D50, level = 1, words = 4)]
pub trait Lamp {
    /// Op 1. Set the level; the reply is the level before. Cannot be undone.
    #[once_only]
    #[on_failure(safe_state)]
    #[deadline_ns = 50_000_000]
    fn set(&mut self, level: u32) -> u32;
    /// Op 2. The level.
    #[idempotent]
    fn get(&self) -> u32;
    /// Op 3. A word wider than a JSON integer, to test the reply form.
    #[idempotent]
    fn wide(&self) -> u64;
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
    fn wide(&self) -> u64 {
        u64::MAX - 1
    }
}

/// An interface with an op that declares nothing about its delivery, and one
/// that takes a capability: neither is a tool.
#[azos_interface(id = 0x4F44_4421, level = 1, words = 4)]
pub trait Odd {
    fn plain(&mut self) -> u32;
    #[idempotent]
    fn ok(&self) -> u32;
}

pub struct OddState;

impl Odd for OddState {
    fn plain(&mut self) -> u32 {
        7
    }
    fn ok(&self) -> u32 {
        8
    }
}

pub static LAMP: Iface = Iface { name: "lamp", id: LampIdl::ID, level: LampIdl::LEVEL, ops: &LampIdl::OPS };
pub static ODD: Iface = Iface { name: "odd", id: OddIdl::ID, level: OddIdl::LEVEL, ops: &OddIdl::OPS };
pub static DECISIONS: Iface = Iface {
    name: "decisions",
    id: azos_decisions::DECISIONS_ID,
    level: DecisionsIdl::LEVEL,
    ops: &DecisionsIdl::OPS,
};

/// Op numbers, as the op tables number them.
pub const SET: u16 = 1;
pub const GET: u16 = 2;

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

/// The subject the model writes the bridge's refusals under (its task id).
pub const ME: u32 = 7;
/// The subject of a derive record: the bridge's Domain, not its task id.
pub const DOMAIN: u32 = 70;
/// The endpoint pool indexes of the exports.
pub const EP_LAMP: u32 = 3;
pub const EP_ODD: u32 = 4;
pub const EP_DECISIONS: u32 = 1;

pub struct Kernel {
    pub now: u64,
    pub journal: Vec<ProvenanceRecord>,
    pub next: u64,
    /// Does the kernel admit the bridge's warrant?
    pub grant: bool,
    /// Does it refuse the call through a warrant it did admit?
    pub refuse_call: bool,
    /// Does another task's derive land between the bridge's mark and its own?
    pub foreign_derive_first: bool,
    /// Does the server die while it holds the call?
    pub peer_dies: bool,
    /// Does it keep admissions (Kconfig `DECISION_RECORDS_DEV`), or only refusals?
    pub keep_admits: bool,
    pub lamp: LampState,
    pub warrants: Vec<Warrant>,
    pub invokes: u32,
    pub log: Vec<String>,
}

impl Kernel {
    pub fn new() -> Kernel {
        Kernel {
            now: 1_000_000_000,
            journal: Vec::new(),
            next: 1,
            grant: true,
            refuse_call: false,
            foreign_derive_first: false,
            peer_dies: false,
            keep_admits: true,
            lamp: LampState::default(),
            warrants: Vec::new(),
            invokes: 0,
            log: Vec::new(),
        }
    }

    /// Write a decision record the way the kernel does; its id.
    pub fn record_n(&mut self, rule: Rule, verdict: Verdict, subject: u32, n: [u64; 3]) -> u64 {
        let mut p = ProvenanceRecord::new(rule as u8, verdict as u8, subject, n);
        p.seq = self.next;
        p.clock_ns = self.now;
        self.next += 1;
        self.journal.push(p);
        p.seq
    }
}

impl Host for Kernel {
    fn now_ns(&mut self) -> u64 {
        self.now
    }

    fn log(&mut self, line: &str) {
        self.log.push(line.to_string());
    }

    fn invoke(&mut self, endpoint: u32, req: &mut MsgDesc, w: &Warrant) -> Invoked {
        self.invokes += 1;
        self.warrants.push(*w);
        if !self.grant {
            // The kernel refuses the warrant and writes the refusal; nothing is
            // minted and nothing reaches the server.
            self.record_n(Rule::CapDenial, Verdict::Deny, ME, [0, 0, 0]);
            return Invoked { result: Err(-1), expiry_ns: 0 };
        }
        // The warrant is minted: the derive record is the Domain's, and its
        // third number is the expiry the bridge asked for.
        let expiry_ns = self.now + w.life_ns;
        if self.foreign_derive_first {
            self.record_n(Rule::CapDerive, Verdict::Admit, DOMAIN + 2, [0, 0, expiry_ns + 7]);
        }
        if self.keep_admits {
            self.record_n(Rule::CapDerive, Verdict::Admit, DOMAIN, [0, 0, expiry_ns]);
        }
        if self.refuse_call {
            self.record_n(Rule::CapDenial, Verdict::Deny, ME, [0, 0, 0]);
            return Invoked { result: Err(-1), expiry_ns };
        }
        if self.peer_dies {
            return Invoked { result: Err(Errno::EPEERDIED.to_syscall_ret()), expiry_ns };
        }
        let mut rep = MsgDesc::default();
        let _ = match endpoint {
            EP_LAMP => LampIdl::dispatch(&mut self.lamp, req, &mut rep),
            EP_ODD => OddIdl::dispatch(&mut OddState, req, &mut rep),
            _ => {
                let mut svc = Service(Held(self.journal.clone()));
                DecisionsIdl::dispatch(&mut svc, req, &mut rep)
            }
        };
        *req = rep;
        Invoked { result: Ok(()), expiry_ns }
    }

    fn decisions(&mut self, req: &mut MsgDesc) -> Result<(), i64> {
        let mut svc = Service(Held(self.journal.clone()));
        let mut rep = MsgDesc::default();
        let _ = DecisionsIdl::dispatch(&mut svc, req, &mut rep);
        *req = rep;
        Ok(())
    }
}

// ── the operator ─────────────────────────────────────────────────────────────

/// The board's epoch the bridge runs in.
pub const EPOCH: u32 = 0x5EED_0001;
/// The root key the operator provisioned.
pub const ROOT: [u8; 32] = [0x42; 32];

pub fn keys() -> Keys {
    Keys::new(ROOT).unwrap()
}

/// The hex of a token.
pub fn hex(t: &Token) -> String {
    let mut b = [0u8; TOKEN_MAX];
    let mut at = 0;
    put_token(t, &mut b, &mut at).unwrap();
    to_hex(&b[..at])
}

/// An op mask naming these op numbers.
pub fn mask(ops: &[u16]) -> u64 {
    ops.iter().fold(0, |m, &o| m | 1 << o)
}

/// An agent's warrant: `principal`, for `iface` in the epoch `epoch`, with
/// these caveats in this order.
pub fn agent_token(principal: u32, epoch: u32, iface: u32, caveats: &[(u8, u64)]) -> Token {
    let mut t = Token::mint(&keys().agent(principal), epoch, principal, iface);
    for &(k, a) in caveats {
        t.attenuate(Caveat::new(k, a)).unwrap();
    }
    t
}

/// An agent's usual warrant: the ops in `ops`, lapsing at `expiry`.
pub fn agent(principal: u32, iface: u32, ops: &[u16], expiry: u64) -> Token {
    agent_token(principal, EPOCH, iface, &[(cav::EXPIRY, expiry), (cav::OP_MASK, mask(ops))])
}

/// A human's one-shot warrant to confirm `proposal`.
pub fn human(principal: u32, proposal: u32, expiry: u64) -> Token {
    human_token(
        principal,
        proposal,
        &[(cav::EXPIRY, expiry), (cav::OP_MASK, mask(&[crate::catalog::CONFIRM_OP])), (cav::QUOTA, 1)],
    )
}

pub fn human_token(principal: u32, proposal: u32, caveats: &[(u8, u64)]) -> Token {
    let mut t = Token::mint(&keys().human(principal), proposal, principal, crate::catalog::CONTROL_ID);
    for &(k, a) in caveats {
        t.attenuate(Caveat::new(k, a)).unwrap();
    }
    t
}

/// The operator's warrant the console shows at boot: `principal`, until `expiry`.
pub fn admin(principal: u32, expiry: u64) -> Token {
    let mut t = Token::mint(&keys().admin(principal), EPOCH, principal, crate::catalog::CONTROL_ID);
    t.attenuate(Caveat::new(cav::EXPIRY, expiry)).unwrap();
    t.attenuate(Caveat::new(cav::OP_MASK, mask(&[crate::catalog::GRANT_OP]))).unwrap();
    t
}

// ── the link and the client ──────────────────────────────────────────────────

/// What the bridge wrote: one entry per link write (one line each).
#[derive(Default)]
pub struct Wire {
    pub lines: Vec<String>,
    pub broken: bool,
}

impl Link for Wire {
    fn send(&mut self, bytes: &[u8]) -> bool {
        if self.broken {
            return false;
        }
        let s = std::str::from_utf8(bytes).expect("the bridge writes UTF-8");
        assert!(s.ends_with('\n') && s.matches('\n').count() == 1, "one line per write: {s:?}");
        self.lines.push(s.trim_end().to_string());
        true
    }
}

pub fn config() -> Config {
    Config { epoch: EPOCH, call_rate: 100, warrant_max_ns: 2_000_000_000, proposal_ttl_ns: 60_000_000_000, grant_max_ns: 3_600_000_000_000, me: ME }
}

pub fn exports() -> Vec<Export> {
    vec![
        Export { iface: &LAMP, endpoint: EP_LAMP },
        Export { iface: &ODD, endpoint: EP_ODD },
        Export { iface: &DECISIONS, endpoint: EP_DECISIONS },
    ]
}

/// The bridge, its kernel, its wire, and the client's counter.
pub struct Session {
    pub bridge: Bridge,
    pub k: Kernel,
    pub wire: Wire,
    next_id: i64,
}

impl Session {
    /// Bytes as the client writes them.
    pub fn raw(&mut self, bytes: &[u8]) {
        self.bridge.on_bytes(&mut self.k, &mut self.wire, bytes);
    }

    /// One line the client writes.
    pub fn line(&mut self, json: &str) {
        let mut b = json.as_bytes().to_vec();
        b.push(b'\n');
        self.raw(&b);
    }

    /// What the bridge wrote since the last take, as JSON.
    pub fn take(&mut self) -> Vec<Value> {
        std::mem::take(&mut self.wire.lines).iter().map(|l| Value::parse(l).expect("the bridge writes JSON")).collect()
    }

    /// A request; the one answer.
    pub fn request(&mut self, method: &str, params: &str) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.line(&format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#));
        let mut out = self.take();
        assert_eq!(out.len(), 1, "one answer to {method}: {out:?}");
        let a = out.remove(0);
        assert_eq!(a.get("id").and_then(Value::as_i64), Some(id));
        a
    }

    pub fn notify(&mut self, method: &str) {
        self.line(&format!(r#"{{"jsonrpc":"2.0","method":"{method}"}}"#));
        assert!(self.take().is_empty(), "a notification is not answered");
    }

    /// `tools/call` with these arguments (JSON text) and this warrant.
    pub fn call(&mut self, name: &str, arguments: &str, warrant: Option<&Token>) -> Value {
        let h = warrant.map(hex);
        self.call_hex(name, arguments, h.as_deref())
    }

    /// `tools/call` with the warrant as the hex the client holds.
    pub fn call_hex(&mut self, name: &str, arguments: &str, warrant: Option<&str>) -> Value {
        let meta = match warrant {
            Some(h) => format!(r#","_meta":{{"azos/warrant":"{h}"}}"#),
            None => String::new(),
        };
        self.request("tools/call", &format!(r#"{{"name":"{name}","arguments":{arguments}{meta}}}"#))
    }
}

/// A session before the handshake.
pub fn bare(cfg: Config, keys: Keys, exports: Vec<Export>) -> Session {
    Session { bridge: Bridge::new(cfg, keys, exports), k: Kernel::new(), wire: Wire::default(), next_id: 0 }
}

/// A session after the handshake.
pub fn session_with(cfg: Config, keys: Keys, exports: Vec<Export>) -> Session {
    let mut s = bare(cfg, keys, exports);
    let init = s.request(
        "initialize",
        r#"{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"scripted","version":"1"}}"#,
    );
    assert!(init.get("result").is_some(), "{init:?}");
    s.notify("notifications/initialized");
    s
}

pub fn session() -> Session {
    session_with(config(), keys(), exports())
}

/// The `result` of an answer.
pub fn result(a: &Value) -> &Value {
    a.get("result").unwrap_or_else(|| panic!("a result: {a:?}"))
}

/// The `structuredContent` of a `tools/call` answer.
pub fn structured(a: &Value) -> &Value {
    result(a).get("structuredContent").unwrap_or_else(|| panic!("structuredContent: {a:?}"))
}

pub fn is_error(a: &Value) -> bool {
    result(a).get("isError").and_then(Value::as_bool).unwrap()
}

pub fn status(a: &Value) -> &str {
    structured(a).get("status").and_then(Value::as_str).unwrap()
}

pub fn reason(a: &Value) -> &str {
    structured(a).get("reason").and_then(Value::as_str).unwrap_or("")
}

pub fn receipt(a: &Value) -> i64 {
    structured(a).get("receipt").and_then(Value::as_i64).unwrap()
}

pub fn field_i64(a: &Value, key: &str) -> i64 {
    structured(a).get(key).and_then(Value::as_i64).unwrap_or_else(|| panic!("{key}: {a:?}"))
}
