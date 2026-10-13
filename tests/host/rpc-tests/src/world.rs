// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Two nodes, a link between them, and a service on the far one.

use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_abi::ipc_msg::{CapDesc, MsgDesc, CAP_MODE_DUP, MSG_VERSION};
use azos_idl::{azos_interface, Cap, IdlError, Lent, Transport};
use azos_rpc::wire::{get_header, Asm, Kind};
use azos_rpc::{Claimed, Config, Host, Link, NodeId, Policy, Rpc, Service, Started};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

pub const A: NodeId = 1;
pub const B: NodeId = 2;
/// The pool index B's `probe` endpoint is at, in B's `/proc/rpc`.
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

    pub fn children(&self, h: u32) -> Vec<u32> {
        self.objs.iter().filter(|(_, o)| o.parent() == Some(h)).map(|(k, _)| *k).collect()
    }

    pub fn close_tree(&mut self, h: u32) {
        for c in self.children(h) {
            self.close_tree(c);
        }
        if self.objs.remove(&h).is_some() {
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
        key * 2
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
    fn derive(&mut self, ep: u32, rights: u16, badge: u32, expiry_ns: u64) -> Result<u32, i64> {
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
        let expiry = match (pe, expiry_ns) {
            (0, e) | (e, 0) => e,
            (a, b) => a.min(b),
        };
        let h = st.alloc(Obj::Ep { parent: Some(ep), rights, badge, expiry });
        st.derives.push((h, ep, rights, badge, expiry));
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

pub type Node = Rpc<FakeHost, MemLink, Claimed>;

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

pub const POLICY_A: &str = "peer fleet 2\n";
pub const POLICY_B: &str = "peer fleet 1\nexport probe 7 fleet\n";

fn side(node: NodeId, cfg: Config, off: u64, clock: &Rc<Cell<u64>>, net: &Rc<RefCell<Net>>, policy: &str, serves: bool) -> Side {
    let st = Rc::new(RefCell::new(HostState {
        off,
        clock: clock.clone(),
        objs: HashMap::new(),
        next: 100 * node,
        eps: HashMap::new(),
        calls: vec![],
        derives: vec![],
        closed: vec![],
        log: String::new(),
        dead: false,
        lapse_once: false,
        mem_failures: false,
        mem_fail_after: None,
        recycle: false,
        base: 100 * node,
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
    let mut rpc = Box::new(Rpc::new(host, MemLink { me: node, net: net.clone() }, Claimed, &CATALOG));
    rpc.configure(cfg);
    rpc.set_policy(Policy::parse(policy.as_bytes()));
    Side { rpc, asm: Box::new(Asm::new()), st, svc }
}

impl World {
    pub fn new() -> World {
        World::with(POLICY_A, POLICY_B)
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
