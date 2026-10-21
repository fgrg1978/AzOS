// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Two nodes, a link between them, and a service on the far one.

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP, MSG_VERSION};
use azos_idl::{azos_interface, Cap, IdlError, Lent, Transport};
use azos_rpc::chan::{self, Channel};
use azos_rpc::wire::{cav, frags_for, get_header, put_header, Asm, Caveat, Header, Kind, CAVEATS_MAX, FRAG_BODY, HEADER_BYTES, HELLO_MAX};
use azos_rpc::{Config, Host, Link, NodeId, Policy, Rpc, Service, Started};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

pub const A: NodeId = 1;
pub const B: NodeId = 2;
/// A node no policy lists, holding a key no policy pins.
pub const C: NodeId = 3;

/// The static private key of node `n` in this world (the test's secrets).
pub fn sk(n: NodeId) -> [u8; 32] {
    [0x40 + n as u8; 32]
}

/// Its public key, the `noise_pk` a topology pins for the node.
pub fn pk(n: NodeId) -> [u8; 32] {
    chan::static_public_key(&sk(n))
}

pub fn pk_hex(n: NodeId) -> String {
    pk(n).iter().map(|b| format!("{b:02x}")).collect()
}

/// A policy from the tests' short form: `peer <class> <node> <64 hex digits>`
/// and `export <name> <index> <class>` lines, the facts the kernel's tree
/// gives the server (`topology/peers`, `topology/exports`), added as the
/// server adds them.
pub fn policy_of(text: &str) -> Policy {
    let mut p = Policy::NONE;
    for l in text.lines() {
        let f: Vec<&str> = l.split(' ').filter(|w| !w.is_empty()).collect();
        match f.as_slice() {
            ["peer", class, node, key] => {
                let k: Vec<u8> = (0..key.len() / 2).filter_map(|i| u8::from_str_radix(&key[2 * i..2 * i + 2], 16).ok()).collect();
                if let (Ok(node), Ok(k)) = (node.parse(), <[u8; 32]>::try_from(k.as_slice())) {
                    p.add_peer(class.as_bytes(), node, &k);
                }
            }
            ["export", name, index, class] => {
                if let Ok(i) = index.parse() {
                    p.add_export(name.as_bytes(), i, class.as_bytes());
                }
            }
            _ => {}
        }
    }
    p
}

/// A `peer` line of a policy: `class` lists `node`, pinned to the key of `key_of`.
pub fn peer(class: &str, node: NodeId, key_of: NodeId) -> String {
    format!("peer {class} {node} {}\n", pk_hex(key_of))
}
/// The pool index B's `probe` endpoint is at, in B's view.
pub const PROBE_INDEX: u32 = 7;
/// B's clock is A's plus this: a deadline in A's time means nothing on B.
pub const SKEW_NS: u64 = 1_000_000_000_000;
pub const MS: u64 = 1_000_000;

pub const RW: u16 = CapPerms::RW.bits() as u16;

// ── the interface the far node serves ───────────────────────────────────

/// What a MemObj capability names in the interface.
pub struct Mem;
/// What an endpoint capability names in the interface.
pub struct Ep;

#[azos_interface(id = 0x5250_4301, level = 1)]
pub trait Probe {
    /// Same answer however often it runs.
    #[idempotent]
    fn read(&mut self, key: u32) -> u32;
    /// Adds to a counter and answers it: running it twice shows.
    #[at_most_once]
    fn bump(&mut self, by: u32) -> u32;
    /// An actuation.
    #[once_only]
    #[on_failure(safe_state)]
    fn fire(&mut self, n: u32) -> u32;
    /// Says nothing about being resent.
    fn plain(&mut self, x: u32) -> u32;
    /// Takes the pages of a memory object; answers their sum.
    #[at_most_once]
    fn store(&mut self, blob: Cap<Mem>) -> u32;
    /// Lends a memory object holding `n` bytes of 0x5A.
    #[idempotent]
    fn fetch(&mut self, n: u32) -> Lent<Mem>;
    /// Takes an endpoint capability, which cannot cross.
    #[idempotent]
    fn give(&mut self, e: Cap<Ep>) -> u32;
}

// ── a node's host ───────────────────────────────────────────────────────

#[derive(Clone)]
pub enum Obj {
    Ep { parent: Option<u32>, rights: u16, badge: u32, expiry: u64 },
    Mem { data: Vec<u8>, parent: Option<u32>, expiry: u64 },
}

impl Obj {
    fn parent(&self) -> Option<u32> {
        match self {
            Obj::Ep { parent, .. } | Obj::Mem { parent, .. } => *parent,
        }
    }
    fn expiry(&self) -> u64 {
        match self {
            Obj::Ep { expiry, .. } | Obj::Mem { expiry, .. } => *expiry,
        }
    }
}

/// What a call into the real service looked like to it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub badge: u32,
    pub deadline: u64,
    pub clock_id: u32,
    pub flags: u32,
    pub cap_modes: Vec<u8>,
    pub cap_rights: Vec<u16>,
    pub cap_expiry: Vec<u64>,
    pub cap_handles: Vec<u32>,
}

pub struct HostState {
    pub off: u64,
    pub clock: Rc<Cell<u64>>,
    pub objs: HashMap<u32, Obj>,
    next: u32,
    pub eps: HashMap<u32, u32>,
    pub calls: Vec<Seen>,
    pub derives: Vec<(u32, u32, u16, u32, u64)>,
    /// The caveats of each warrant (`kind`, `argument`): the source's, then the
    /// derive's, as the kernel keeps them; a `QUOTA` argument is the uses left.
    pub caveats: HashMap<u32, Vec<(u8, u64)>>,
    pub closed: Vec<u32>,
    pub log: String,
    /// The service behind the endpoint is dead: the kernel completes a call
    /// with `-EPEERDIED`.
    pub dead: bool,
    /// The next call finds the warrant lapsed (`-EPERM`) once.
    pub lapse_once: bool,
    pub mem_failures: bool,
    /// `mo_create` succeeds this many more times, then fails.
    pub mem_fail_after: Option<u32>,
    /// A freed handle number is handed out again, the lowest first: the kernel
    /// reuses table slots, and a handle closed twice may close another object.
    pub recycle: bool,
    base: u32,
    /// This node's static key (`None`: the host holds none).
    pub sk: Option<[u8; 32]>,
    /// Ephemeral keys handed out so far (each one is different).
    pub ents: u64,
    /// The entropy pool is dry.
    pub dry: bool,
    node: NodeId,
}

impl HostState {
    pub fn now(&self) -> u64 {
        self.clock.get() + self.off
    }

    pub fn alloc(&mut self, o: Obj) -> u32 {
        let h = if self.recycle {
            (self.base + 1..).find(|h| !self.objs.contains_key(h)).unwrap()
        } else {
            self.next += 1;
            self.next
        };
        self.objs.insert(h, o);
        h
    }

    pub fn new_mem(&mut self, data: Vec<u8>) -> u32 {
        self.alloc(Obj::Mem { data, parent: None, expiry: 0 })
    }

    /// `h` is held and has not lapsed.
    pub fn alive(&self, h: u32) -> bool {
        self.objs.get(&h).is_some_and(|o| o.expiry() == 0 || o.expiry() > self.now())
    }

    /// The kernel's resolve of the warrant `h` for a call (`gate` in
    /// `crates/core/ipc/src/cap.rs`): the call names no op, so an `OP_MASK` is
    /// never discharged, and a kind with no evaluator (`NODE`, `DECLASSIFY`)
    /// refuses; a spent `QUOTA` refuses; a use takes one count from each
    /// `QUOTA`, last.
    pub fn gate(&mut self, h: u32) -> bool {
        let Some(list) = self.caveats.get_mut(&h) else { return true };
        if list.iter().any(|&(k, a)| matches!(k, cav::OP_MASK | cav::NODE | cav::DECLASSIFY) || (k == cav::QUOTA && a == 0)) {
            return false;
        }
        list.iter_mut().filter(|c| c.0 == cav::QUOTA).for_each(|c| c.1 -= 1);
        true
    }

    pub fn children(&self, h: u32) -> Vec<u32> {
        self.objs.iter().filter(|(_, o)| o.parent() == Some(h)).map(|(k, _)| *k).collect()
    }

    pub fn close_tree(&mut self, h: u32) {
        for c in self.children(h) {
            self.close_tree(c);
        }
        if self.objs.remove(&h).is_some() {
            self.caveats.remove(&h);
            self.closed.push(h);
        }
    }

    /// The warrants (endpoint children) held.
    pub fn warrants(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.objs.iter().filter(|(_, o)| matches!(o, Obj::Ep { parent: Some(_), .. })).map(|(k, _)| *k).collect();
        v.sort();
        v
    }

    /// Memory objects held.
    pub fn mems(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.objs.iter().filter(|(_, o)| matches!(o, Obj::Mem { .. })).map(|(k, _)| *k).collect();
        v.sort();
        v
    }
}

pub struct FakeHost {
    pub st: Rc<RefCell<HostState>>,
    pub svc: Rc<RefCell<ProbeImpl>>,
}

/// The real service.
pub struct ProbeImpl {
    pub st: Rc<RefCell<HostState>>,
    pub counter: u32,
    pub fired: u32,
    pub reads: u32,
    /// The pages `store` was given, as it read them through its handle.
    pub stored: Vec<Vec<u8>>,
}

impl Probe for ProbeImpl {
    fn read(&mut self, key: u32) -> u32 {
        self.reads += 1;
        key.wrapping_mul(2)
    }
    fn bump(&mut self, by: u32) -> u32 {
        self.counter += by;
        self.counter
    }
    fn fire(&mut self, n: u32) -> u32 {
        self.fired += n;
        self.fired
    }
    fn plain(&mut self, x: u32) -> u32 {
        x
    }
    fn store(&mut self, blob: Cap<Mem>) -> u32 {
        let st = self.st.borrow();
        match st.objs.get(&blob.raw()) {
            Some(Obj::Mem { data, .. }) => {
                self.stored.push(data.clone());
                data.iter().map(|&b| b as u32).sum()
            }
            _ => u32::MAX,
        }
    }
    fn fetch(&mut self, n: u32) -> Lent<Mem> {
        let h = self.st.borrow_mut().new_mem(vec![0x5A; n as usize]);
        Lent::dup(h, RW)
    }
    fn give(&mut self, _e: Cap<Ep>) -> u32 {
        7
    }
}

impl Host for FakeHost {
    fn now_ns(&mut self) -> u64 {
        self.st.borrow().now()
    }
    fn log(&mut self, line: &[u8]) {
        self.st.borrow_mut().log.push_str(&String::from_utf8_lossy(line));
    }
    fn endpoint(&mut self, index: u32) -> Option<u32> {
        let st = self.st.borrow();
        st.eps.get(&index).copied().filter(|h| st.objs.contains_key(h))
    }
    fn derive(&mut self, ep: u32, rights: u16, badge: u32, expiry_ns: u64, caveats: &[Caveat]) -> Result<u32, i64> {
        let mut st = self.st.borrow_mut();
        let now = st.now();
        let Some(Obj::Ep { rights: pr, badge: pb, expiry: pe, .. }) = st.objs.get(&ep).cloned() else {
            return Err(Errno::ECAPSTALE.to_syscall_ret());
        };
        if pe != 0 && pe <= now {
            return Err(Errno::ECAPSTALE.to_syscall_ret());
        }
        // The source is unbadged, has DUP, and the copy only narrows.
        if pb != 0 || badge == 0 || pr & CapPerms::DUP.bits() as u16 == 0 || rights & !pr != 0 {
            return Err(Errno::EPERM.to_syscall_ret());
        }
        if expiry_ns != 0 && expiry_ns <= now {
            return Err(Errno::EDEADLINE.to_syscall_ret());
        }
        // `ENDPOINT_DERIVE`: at most the kernel's count, of kinds it knows.
        if caveats.len() > CAVEATS_MAX {
            return Err(Errno::EINVAL.to_syscall_ret());
        }
        if caveats.iter().any(|c| !cav::known(c.kind)) {
            return Err(Errno::ECAPPERMS.to_syscall_ret());
        }
        let expiry = match (pe, expiry_ns) {
            (0, e) | (e, 0) => e,
            (a, b) => a.min(b),
        };
        let h = st.alloc(Obj::Ep { parent: Some(ep), rights, badge, expiry });
        st.derives.push((h, ep, rights, badge, expiry));
        let mut list = st.caveats.get(&ep).cloned().unwrap_or_default();
        list.extend(caveats.iter().map(|c| (c.kind, c.arg)));
        st.caveats.insert(h, list);
        Ok(h)
    }
    fn close(&mut self, h: u32) {
        self.st.borrow_mut().close_tree(h);
    }
    fn call(&mut self, ep: u32, msg: &mut MsgDesc) -> i64 {
        let mut req = *msg;
        {
            let mut st = self.st.borrow_mut();
            if !st.alive(ep) {
                return Errno::EPERM.to_syscall_ret();
            }
            let Some(Obj::Ep { rights, badge, .. }) = st.objs.get(&ep).cloned() else { return Errno::ECAPKIND.to_syscall_ret() };
            if rights & CapPerms::WRITE.bits() as u16 == 0 {
                return Errno::ECAPPERMS.to_syscall_ret();
            }
            if !st.gate(ep) {
                return Errno::EPERM.to_syscall_ret();
            }
            if st.lapse_once {
                st.lapse_once = false;
                return Errno::EPERM.to_syscall_ret();
            }
            let mut seen = Seen {
                badge,
                deadline: msg.deadline,
                clock_id: msg.clock_id,
                flags: msg.flags,
                cap_modes: vec![],
                cap_rights: vec![],
                cap_expiry: vec![],
                cap_handles: vec![],
            };
            for k in 0..msg.n_caps as usize {
                let c = msg.caps[k];
                seen.cap_modes.push(c.mode);
                seen.cap_rights.push(c.rights);
                seen.cap_expiry.push(c.expiry_ns);
                seen.cap_handles.push(c.handle);
                // The kernel's DUP: a child of the sender's object for the server.
                if c.mode == CAP_MODE_DUP {
                    let Some(Obj::Mem { data, expiry, .. }) = st.objs.get(&c.handle).cloned() else {
                        return Errno::ECAPKIND.to_syscall_ret();
                    };
                    let e = match (expiry, c.expiry_ns) {
                        (0, e) | (e, 0) => e,
                        (a, b) => a.min(b),
                    };
                    let child = st.alloc(Obj::Mem { data, parent: Some(c.handle), expiry: e });
                    req.caps[k].handle = child;
                }
            }
            st.calls.push(seen);
            if st.dead {
                return Errno::EPEERDIED.to_syscall_ret();
            }
        }
        let mut rep = MsgDesc::default();
        let r = ProbeIdl::dispatch(&mut *self.svc.borrow_mut(), &req, &mut rep);
        if r.is_err() {
            // The dispatcher left an error reply in `rep`.
        }
        // A DUP in the reply is a child, in this task's table, of the server's own.
        {
            let mut st = self.st.borrow_mut();
            for k in 0..rep.n_caps as usize {
                let c = rep.caps[k];
                if let Some(Obj::Mem { data, .. }) = st.objs.get(&c.handle).cloned() {
                    rep.caps[k].handle = st.alloc(Obj::Mem { data, parent: Some(c.handle), expiry: c.expiry_ns });
                }
            }
        }
        *msg = rep;
        0
    }
    fn mo_size(&mut self, h: u32) -> Option<usize> {
        match self.st.borrow().objs.get(&h) {
            Some(Obj::Mem { data, .. }) => Some(data.len()),
            _ => None,
        }
    }
    fn mo_read(&mut self, h: u32, out: &mut [u8]) -> Option<usize> {
        match self.st.borrow().objs.get(&h) {
            Some(Obj::Mem { data, .. }) => {
                let n = data.len().min(out.len());
                out[..n].copy_from_slice(&data[..n]);
                Some(n)
            }
            _ => None,
        }
    }
    fn mo_create(&mut self, data: &[u8]) -> Result<u32, i64> {
        let mut st = self.st.borrow_mut();
        if st.mem_failures {
            return Err(Errno::ENOMEM.to_syscall_ret());
        }
        match st.mem_fail_after {
            Some(0) => return Err(Errno::ENOMEM.to_syscall_ret()),
            Some(n) => st.mem_fail_after = Some(n - 1),
            None => {}
        }
        let pages = data.len().div_ceil(4096).max(1);
        let mut v = data.to_vec();
        v.resize(pages * 4096, 0);
        Ok(st.new_mem(v))
    }
    fn static_key(&mut self) -> Option<[u8; 32]> {
        self.st.borrow().sk
    }
    fn entropy(&mut self, out: &mut [u8; 32]) -> bool {
        let mut st = self.st.borrow_mut();
        if st.dry {
            return false;
        }
        st.ents += 1;
        *out = [0x90 ^ st.node as u8; 32];
        out[..8].copy_from_slice(&st.ents.to_le_bytes());
        true
    }
}

// ── the link ────────────────────────────────────────────────────────────

/// What the link does with a frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fate {
    Deliver,
    Drop,
    Dup,
}

#[derive(Clone, Debug)]
pub struct Sent {
    pub from: NodeId,
    pub kind: Kind,
    pub frag: u16,
    pub remaining_ns: u64,
}

pub struct Net {
    pub q: [VecDeque<Vec<u8>>; 2],
    pub log: Vec<Sent>,
    /// Every frame sent, as it went on the wire (sender, bytes).
    pub raw: Vec<(NodeId, Vec<u8>)>,
    pub rule: Box<dyn FnMut(&Sent) -> Fate>,
}

impl Net {
    /// Frames of `kind` sent from `from`, delivered or not.
    pub fn count(&self, from: NodeId, kind: Kind) -> usize {
        self.log.iter().filter(|s| s.from == from && s.kind == kind && s.frag == 0).count()
    }
}

pub struct MemLink {
    pub me: NodeId,
    pub net: Rc<RefCell<Net>>,
}

impl Link for MemLink {
    fn send(&mut self, peer: NodeId, frame: &[u8]) -> bool {
        let (h, _) = get_header(frame).expect("the engine sends well-formed frames");
        let s = Sent { from: self.me, kind: h.kind, frag: h.frag_idx, remaining_ns: h.remaining_ns };
        let mut net = self.net.borrow_mut();
        // A peer this world does not have (a node id the policy lists and no one runs).
        if peer == 0 || peer > 2 {
            return false;
        }
        net.log.push(s.clone());
        net.raw.push((self.me, frame.to_vec()));
        let fate = (net.rule)(&s);
        let to = (peer - 1) as usize;
        match fate {
            Fate::Drop => {}
            Fate::Deliver => net.q[to].push_back(frame.to_vec()),
            Fate::Dup => {
                net.q[to].push_back(frame.to_vec());
                net.q[to].push_back(frame.to_vec());
            }
        }
        true
    }
}

// ── the world ───────────────────────────────────────────────────────────

pub type Node = Rpc<FakeHost, MemLink>;

pub struct Side {
    pub rpc: Box<Node>,
    pub asm: Box<Asm>,
    pub st: Rc<RefCell<HostState>>,
    pub svc: Rc<RefCell<ProbeImpl>>,
}

pub struct World {
    pub clock: Rc<Cell<u64>>,
    pub net: Rc<RefCell<Net>>,
    pub a: Side,
    pub b: Side,
}

pub fn cfg(node: NodeId, epoch: u32) -> Config {
    Config {
        node,
        epoch,
        warrant_ttl_ns: 10_000 * MS,
        dedupe_window: 4,
        retries: 3,
        rto_ns: 100 * MS,
        ping_ns: 1_000 * MS,
        miss_limit: 3,
    }
}

pub static CATALOG: [Service; 1] = [Service { name: b"probe", id: ProbeIdl::ID, ops: &ProbeIdl::OPS }];

/// A's policy: B is in `fleet`, pinned to B's key.
pub fn policy_a() -> String {
    peer("fleet", B, B)
}
/// B's policy: A is in `fleet`, pinned to A's key; `probe` is exported to the class.
pub fn policy_b() -> String {
    peer("fleet", A, A) + "export probe 7 fleet\n"
}

fn side(node: NodeId, cfg: Config, off: u64, clock: &Rc<Cell<u64>>, net: &Rc<RefCell<Net>>, policy: &str, serves: bool) -> Side {
    let st = Rc::new(RefCell::new(HostState {
        off,
        clock: clock.clone(),
        objs: HashMap::new(),
        next: 100 * node,
        eps: HashMap::new(),
        calls: vec![],
        derives: vec![],
        caveats: HashMap::new(),
        closed: vec![],
        log: String::new(),
        dead: false,
        lapse_once: false,
        mem_failures: false,
        mem_fail_after: None,
        recycle: false,
        base: 100 * node,
        sk: Some(sk(node)),
        ents: 0,
        dry: false,
        node,
    }));
    if serves {
        let root = st.borrow_mut().alloc(Obj::Ep {
            parent: None,
            rights: (CapPerms::WRITE.bits() | CapPerms::DUP.bits()) as u16,
            badge: 0,
            expiry: 0,
        });
        st.borrow_mut().eps.insert(PROBE_INDEX, root);
    }
    let svc = Rc::new(RefCell::new(ProbeImpl { st: st.clone(), counter: 0, fired: 0, reads: 0, stored: vec![] }));
    let host = FakeHost { st: st.clone(), svc: svc.clone() };
    let mut rpc = Box::new(Rpc::new(host, MemLink { me: node, net: net.clone() }, &CATALOG));
    rpc.configure(cfg);
    rpc.set_policy(policy_of(&policy));
    Side { rpc, asm: Box::new(Asm::new()), st, svc }
}

impl World {
    pub fn new() -> World {
        World::with(&policy_a(), &policy_b())
    }

    pub fn with(policy_a: &str, policy_b: &str) -> World {
        World::with_cfg(policy_a, policy_b, |_| {})
    }

    /// [`World::with`], with B's settings adjusted by `tweak`.
    pub fn with_cfg(policy_a: &str, policy_b: &str, tweak: impl Fn(&mut Config)) -> World {
        let clock = Rc::new(Cell::new(5_000_000_000));
        let net = Rc::new(RefCell::new(Net {
            q: [VecDeque::new(), VecDeque::new()],
            log: vec![],
            raw: vec![],
            rule: Box::new(|_| Fate::Deliver),
        }));
        let mut cb = cfg(B, 1);
        tweak(&mut cb);
        let a = side(A, cfg(A, 1), 0, &clock, &net, policy_a, false);
        let b = side(B, cb, SKEW_NS, &clock, &net, policy_b, true);
        World { clock, net, a, b }
    }

    pub fn rule(&self, f: impl FnMut(&Sent) -> Fate + 'static) {
        self.net.borrow_mut().rule = Box::new(f);
    }

    pub fn heal(&self) {
        self.rule(|_| Fate::Deliver);
    }

    /// Deliver every queued frame, and whatever the answers queue, until quiet.
    pub fn pump(&mut self) {
        for _ in 0..10_000 {
            let fa = self.net.borrow_mut().q[0].pop_front();
            let fb = self.net.borrow_mut().q[1].pop_front();
            if fa.is_none() && fb.is_none() {
                return;
            }
            if let Some(f) = fa {
                self.a.rpc.on_frame(&mut self.a.asm, &f);
            }
            if let Some(f) = fb {
                self.b.rpc.on_frame(&mut self.b.asm, &f);
            }
        }
        panic!("the link never went quiet");
    }

    pub fn advance(&mut self, ns: u64) {
        self.clock.set(self.clock.get() + ns);
    }

    pub fn tick(&mut self) {
        self.a.rpc.tick();
        self.b.rpc.tick();
    }

    /// Run time forward `ns`, ticking every 10 ms and delivering frames.
    pub fn run_for(&mut self, ns: u64) {
        let mut left = ns;
        while left > 0 {
            let step = (10 * MS).min(left);
            self.advance(step);
            left -= step;
            self.tick();
            self.pump();
        }
    }

    /// Bring the session up (A dials).
    pub fn establish(&mut self) {
        for _ in 0..50 {
            self.tick();
            self.pump();
            if self.a.rpc.session_with(B).is_some_and(|s| s.state == azos_rpc::State::Up)
                && self.b.rpc.session_with(A).is_some_and(|s| s.state == azos_rpc::State::Up)
            {
                return;
            }
            self.advance(110 * MS);
        }
        panic!("the session never came up");
    }

    /// A local caller on A calls the proxy endpoint with `msg`: the way the
    /// server's accept loop drives `begin` and `poll`.
    pub fn call_a(&mut self, msg: &mut MsgDesc) {
        self.pump();
        let mut call = match self.a.rpc.begin(msg, 0x77) {
            Started::Done(d) => {
                *msg = d;
                return;
            }
            Started::Pending(c) => c,
        };
        for i in 0..200_000u64 {
            self.pump();
            if let Some(d) = self.a.rpc.poll(&mut call) {
                *msg = d;
                self.pump();
                return;
            }
            self.advance(MS);
            if i % 10 == 0 {
                self.tick();
            }
        }
        panic!("the call never finished");
    }

    /// A MemObj in A's table holding `data`.
    pub fn a_mem(&mut self, data: Vec<u8>) -> u32 {
        self.a.st.borrow_mut().new_mem(data)
    }

    /// Frames of `kind` that `from` sent.
    pub fn sent(&self, from: NodeId, kind: Kind) -> usize {
        self.net.borrow().count(from, kind)
    }
}

/// The generated stub over a world: what a caller on A uses.
pub struct Via<'a>(pub &'a RefCell<World>);

impl Transport for Via<'_> {
    fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
        self.0.borrow_mut().call_a(msg);
        Ok(())
    }
}

pub fn probe(w: &RefCell<World>) -> ProbeClient<Via<'_>> {
    ProbeClient::new(Via(w))
}

/// A request for `op` of the interface with `words` (after the header), built
/// by hand: for what no stub would send.
pub fn raw_req(id: u32, op: u16, words: &[u64]) -> MsgDesc {
    let mut m = MsgDesc { version: MSG_VERSION, n_words: (1 + words.len()) as u8, ..MsgDesc::default() };
    m.words[0] = azos_idl::header(id, 1, op);
    m.words[1..1 + words.len()].copy_from_slice(words);
    m
}

pub fn dup_cap(handle: u32) -> CapDesc {
    CapDesc { handle, mode: azos_abi::ipc_msg::CAP_MODE_MOVE, _pad: 0, rights: 0, expiry_ns: 0 }
}

// ── a peer that is not an engine ────────────────────────────────────────

/// A node that is a test double, not an engine: it holds a static key and a
/// channel to B, made with the public handshake and channel API, so a test can
/// say exactly which frames arrive at B (a request the stub would never send, a
/// fragment of the wrong size, a Bye) and read the answers. What reaches B is
/// sealed under keys B really agreed, so B's checks are the ones tested.
pub struct Forger {
    pub node: NodeId,
    pub epoch: u32,
    pub session: u32,
    pub chan: Channel,
}

impl Forger {
    /// Dial B as `node` with the static key `key` (a node's own key is
    /// [`sk`]), from boot epoch `epoch` with Hello nonce `nonce`, and confirm
    /// the session with a Ping, as an engine does. `None` when B does not
    /// answer, or the answer does not verify.
    pub fn try_dial(w: &mut World, node: NodeId, key: [u8; 32], epoch: u32, nonce: u64) -> Option<Forger> {
        let pro = chan::prologue(node, B, epoch, nonce);
        let mut eph = [0xE0u8; 32];
        eph[..8].copy_from_slice(&nonce.to_le_bytes());
        let mut hello = [0u8; HELLO_MAX];
        let (hs, n) = chan::dial(&key, &pk(B), &pro, &eph, &[0u8], &mut hello)?;
        let mut f = vec![0u8; HEADER_BYTES + n];
        put_header(&Header::new(Kind::Hello, 0, nonce, node, epoch), &mut f);
        f[HEADER_BYTES..].copy_from_slice(&hello[..n]);
        w.b.rpc.on_frame(&mut w.b.asm, &f);
        let ack = w.net.borrow_mut().q[0].pop_front()?;
        let (h, body) = get_header(&ack)?;
        if h.kind != Kind::HelloAck {
            return None;
        }
        let mut reply = [0u8; 64];
        let (chan, _) = chan::finish_dial(hs, &pk(B), body, &mut reply)?;
        let session = u32::from_le_bytes(reply[..4].try_into().unwrap());
        let mut me = Forger { node, epoch, session, chan };
        let ping = me.seal(Kind::Ping, 1, &[]);
        me.send(w, &ping);
        w.net.borrow_mut().q[0].clear();
        Some(me)
    }

    /// [`Forger::try_dial`] as node `node` with its own key, from epoch 9.
    pub fn dial(w: &mut World, node: NodeId) -> Forger {
        Forger::try_dial(w, node, sk(node), 9, 0x1000_0001).expect("B answers a node whose key it pins")
    }

    /// The token a request for interface `iface` carries when this node sends
    /// it to B: started under the session key, narrowed to B.
    pub fn token(&self, iface: u32) -> azos_rpc::wire::Token {
        let mut t = azos_rpc::wire::Token::mint(self.chan.mac_key().unwrap(), self.session, self.node, iface);
        t.attenuate(azos_rpc::wire::Caveat::new(azos_rpc::wire::cav::NODE, u64::from(B))).unwrap();
        t
    }

    /// `body` as the message `kind` numbered `seq`, in sealed frames.
    pub fn seal(&mut self, kind: Kind, seq: u64, body: &[u8]) -> Vec<Vec<u8>> {
        let cnt = frags_for(body.len());
        (0..cnt)
            .map(|i| {
                let (lo, hi) = (i * FRAG_BODY, ((i + 1) * FRAG_BODY).min(body.len()));
                let mut h = Header::new(kind, self.session, seq, self.node, self.epoch);
                h.frag_idx = i as u16;
                h.frag_cnt = cnt as u16;
                let mut out = vec![0u8; azos_rpc::wire::FRAME_MAX];
                let n = self.chan.seal(&mut h, &body[lo..hi], &mut out).unwrap();
                out.truncate(n);
                out
            })
            .collect()
    }

    /// Deliver `frames` to B.
    pub fn send(&mut self, w: &mut World, frames: &[Vec<u8>]) {
        for f in frames {
            w.b.rpc.on_frame(&mut w.b.asm, f);
        }
    }

    /// The next frame B queued for this node, opened.
    pub fn answer(&mut self, w: &mut World) -> Option<(Header, Vec<u8>)> {
        let f = w.net.borrow_mut().q[0].pop_front()?;
        let (h, _) = get_header(&f)?;
        let mut out = vec![0u8; FRAG_BODY];
        let n = self.chan.open(&h, &f, &mut out)?;
        out.truncate(n);
        Some((h, out))
    }

    /// Send `frames` (a request) and take the first status word of the answer.
    pub fn status(&mut self, w: &mut World, frames: &[Vec<u8>]) -> u64 {
        self.send(w, frames);
        let (h, body) = self.answer(w).expect("an answer");
        assert_eq!(h.kind, Kind::Rep);
        azos_rpc::wire::get_desc(&body, &mut 0).unwrap().words[0]
    }
}
