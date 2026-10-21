// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Two RPC engines (`userspace/lib/rpc`, the engine `rpcsrv` runs) on QUIC.
//!
//! Each node is the engine, a fake kernel host (the warrant table and the
//! service behind the exported endpoint), and a [`Pump`] on a real loopback UDP
//! socket. The engines run on the wall clock, as on a device, and the nodes are
//! polled in turn from one thread. The static Noise keys are the ones a topology
//! would pin, so every session is the real handshake inside the QUIC
//! connection and every frame is sealed twice.

use std::cell::RefCell;
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};

use azos_abi::error::Errno;
use azos_abi::ipc_msg::MsgDesc;
use azos_idl::{azos_interface, IdlError, Transport};
use azos_quic::{Event, Identity, Pump, Role, Sender, Settings};
use azos_rpc::chan;
use azos_rpc::wire::Asm;
use azos_rpc::{Config, Host, Link, NodeId, Policy, Rpc, Service, Started, State};

const A: NodeId = 1;
const B: NodeId = 2;
const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The pool index of B's `echo` endpoint, as B's `/proc/rpc` would name it.
const ECHO_INDEX: u32 = 7;

#[azos_interface(id = 0x5155_4901, level = 1)]
pub trait Echo {
    /// Same answer however often it runs.
    #[idempotent]
    fn twice(&mut self, x: u32) -> u32;
    /// Adds to a counter and answers it: running it twice shows.
    #[at_most_once]
    fn bump(&mut self, by: u32) -> u32;
}

struct Counter {
    n: u32,
    ran: u32,
}

impl Echo for Counter {
    fn twice(&mut self, x: u32) -> u32 {
        self.ran += 1;
        x * 2
    }

    fn bump(&mut self, by: u32) -> u32 {
        self.ran += 1;
        self.n += by;
        self.n
    }
}

static CATALOG: [Service; 1] = [Service { name: b"echo", id: EchoIdl::ID, ops: &EchoIdl::OPS }];

fn sk(n: NodeId) -> [u8; 32] {
    [0x40 + n as u8; 32]
}

fn hex(k: &[u8; 32]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

/// A policy from the tests' short form: `peer <class> <node> <64 hex digits>`
/// and `export <name> <index> <class>` lines, the facts the kernel's tree
/// gives the server (`topology/peers`, `topology/exports`), added as the
/// server adds them.
fn policy_of(text: &str) -> Policy {
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

/// A's view: B is in `fleet`, pinned to the public half of node `b_key`'s key.
fn policy_a(b_key: NodeId) -> String {
    format!("peer fleet {B} {}\n", hex(&chan::static_public_key(&sk(b_key))))
}

/// B's view: A is in `fleet`, pinned to the public half of node `a_key`'s key;
/// `echo` is exported to the class.
fn policy_b(a_key: NodeId) -> String {
    format!("peer fleet {A} {}\nexport echo {ECHO_INDEX} fleet\n", hex(&chan::static_public_key(&sk(a_key))))
}

/// What the kernel keeps for one node: the capability table (a root endpoint,
/// the warrants derived from it) and the real service.
struct Kern {
    node: NodeId,
    t0: Instant,
    key: [u8; 32],
    serves: bool,
    next: u32,
    /// Warrants: handle -> badge.
    warrants: HashMap<u32, u32>,
    svc: Counter,
}

const ROOT: u32 = 900;

impl Host for Kern {
    fn now_ns(&mut self) -> u64 {
        1_000_000_000 + self.t0.elapsed().as_nanos() as u64
    }

    fn log(&mut self, _line: &[u8]) {}

    fn endpoint(&mut self, index: u32) -> Option<u32> {
        (self.serves && index == ECHO_INDEX).then_some(ROOT)
    }

    fn derive(&mut self, ep: u32, _rights: u16, badge: u32, _expiry_ns: u64, _caveats: &[azos_rpc::wire::Caveat]) -> Result<u32, i64> {
        if ep != ROOT || badge == 0 {
            return Err(Errno::EPERM.to_syscall_ret());
        }
        self.next += 1;
        self.warrants.insert(self.next, badge);
        Ok(self.next)
    }

    fn close(&mut self, h: u32) {
        self.warrants.remove(&h);
    }

    fn call(&mut self, ep: u32, msg: &mut MsgDesc) -> i64 {
        if !self.warrants.contains_key(&ep) {
            return Errno::EPERM.to_syscall_ret();
        }
        let mut rep = MsgDesc::default();
        let _ = EchoIdl::dispatch(&mut self.svc, msg, &mut rep);
        *msg = rep;
        0
    }

    fn mo_size(&mut self, _h: u32) -> Option<usize> {
        None
    }

    fn mo_read(&mut self, _h: u32, _out: &mut [u8]) -> Option<usize> {
        None
    }

    fn mo_create(&mut self, _data: &[u8]) -> Result<u32, i64> {
        Err(Errno::ENOMEM.to_syscall_ret())
    }

    fn static_key(&mut self) -> Option<[u8; 32]> {
        Some(self.key)
    }

    fn entropy(&mut self, out: &mut [u8; 32]) -> bool {
        for chunk in out.chunks_mut(8) {
            let mut h = RandomState::new().build_hasher();
            h.write_u32(self.node);
            chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
        }
        true
    }
}

/// Timings that make the engine's own loss detection slow or fast, so a test
/// says which mechanism it is exercising.
#[derive(Clone, Copy)]
struct Timing {
    rto_ms: u64,
    ping_ms: u64,
}

const FAST: Timing = Timing { rto_ms: 60, ping_ms: 250 };

fn config(node: NodeId, epoch: u32, t: Timing) -> Config {
    Config {
        node,
        epoch,
        warrant_ttl_ns: 20_000_000_000,
        dedupe_window: 4,
        retries: 2,
        rto_ns: t.rto_ms * 1_000_000,
        ping_ns: t.ping_ms * 1_000_000,
        miss_limit: 2,
    }
}

/// The engine's link in this test: frames go to the peer's QUIC connection. (In the
/// system the engine, `rpcsrv`, is `no_std` and sends datagrams to the `rpcquic`
/// relay instead; what crosses QUIC is the same sealed frames.)
struct PumpLink {
    sender: Sender,
    peer: NodeId,
}

impl Link for PumpLink {
    fn send(&mut self, peer: NodeId, frame: &[u8]) -> bool {
        peer == self.peer && self.sender.send(frame)
    }
}

struct Node {
    rpc: Box<Rpc<Kern, PumpLink>>,
    asm: Box<Asm>,
    pump: Option<Pump>,
    last_tick: Instant,
    ups: u32,
    downs: u32,
}

/// How a node is built: what differs between the tests.
struct Spec {
    node: NodeId,
    key: NodeId,
    policy: String,
    epoch: u32,
    timing: Timing,
}

impl Node {
    fn new(s: Spec, pump: Pump, sender: Sender, peer: NodeId) -> Node {
        let kern = Kern { node: s.node, t0: Instant::now(), key: sk(s.key), serves: s.node == B, next: 100 * s.node, warrants: HashMap::new(), svc: Counter { n: 0, ran: 0 } };
        let mut rpc = Box::new(Rpc::new(kern, PumpLink { sender, peer }, &CATALOG));
        rpc.configure(config(s.node, s.epoch, s.timing));
        rpc.set_policy(policy_of(&s.policy));
        Node { rpc, asm: Box::new(Asm::new()), pump: Some(pump), last_tick: Instant::now(), ups: 0, downs: 0 }
    }

    /// What `rpcsrv`'s link thread does: read the link, hand frames to the engine, tick.
    fn step(&mut self) {
        if let Some(p) = self.pump.as_mut() {
            p.drive(Duration::from_millis(1)).unwrap();
            while let Some(ev) = p.pop() {
                match ev {
                    Event::Frame(f) => self.rpc.on_frame(&mut self.asm, &f),
                    Event::Up => self.ups += 1,
                    Event::Down => self.downs += 1,
                }
            }
        }
        if self.last_tick.elapsed() >= Duration::from_millis(20) {
            self.last_tick = Instant::now();
            self.rpc.tick();
        }
    }

    fn session_up(&self, peer: NodeId) -> bool {
        self.rpc.session_with(peer).is_some_and(|s| s.state == State::Up)
    }
}

struct Duo {
    a: Node,
    b: Node,
}

fn settings() -> Settings {
    Settings { idle_timeout: Duration::from_millis(600), redial: Duration::from_millis(100), queue: 64, streams: 64 }
}

fn listener_pump(at: Option<SocketAddr>) -> (Pump, Sender) {
    let id = Identity::generate().unwrap();
    Pump::bind(at.unwrap_or_else(|| SocketAddr::new(LO, 0)), Role::Listen { peer: LO, identity: id }, settings()).unwrap()
}

fn spec_b(a_key: NodeId, t: Timing) -> Spec {
    Spec { node: B, key: B, policy: policy_b(a_key), epoch: 2, timing: t }
}

/// A node A that pins `b_key` for B, and a B that pins `a_key` for A.
fn duo_with(a_key: NodeId, b_key: NodeId, t: Timing) -> Duo {
    let (pb, sb) = listener_pump(None);
    let at = pb.local_addr().unwrap();
    let (pa, sa) = Pump::bind(SocketAddr::new(LO, 0), Role::Dial { remote: at }, settings()).unwrap();
    let a = Spec { node: A, key: A, policy: policy_a(b_key), epoch: 1, timing: t };
    Duo { a: Node::new(a, pa, sa, B), b: Node::new(spec_b(a_key, t), pb, sb, A) }
}

impl Duo {
    fn step(&mut self) {
        self.a.step();
        self.b.step();
    }

    fn until(&mut self, secs: f64, mut done: impl FnMut(&Duo) -> bool) -> bool {
        let end = Instant::now() + Duration::from_secs_f64(secs);
        while Instant::now() < end {
            self.step();
            if done(self) {
                return true;
            }
        }
        false
    }

    fn establish(&mut self) {
        assert!(self.until(8.0, |d| d.a.session_up(B) && d.b.session_up(A)), "the RPC session never came up over QUIC");
    }

    /// A local caller on A calls the proxy endpoint: the way the server's accept
    /// loop drives `begin` and `poll`. `after_begin` runs once the request is
    /// begun and before the first poll.
    fn call_a(&mut self, msg: &mut MsgDesc, after_begin: impl FnOnce(&mut Duo)) {
        let mut call = match self.a.rpc.begin(msg, 0x77) {
            Started::Done(d) => {
                *msg = d;
                return;
            }
            Started::Pending(c) => c,
        };
        after_begin(self);
        let end = Instant::now() + Duration::from_secs(20);
        while Instant::now() < end {
            self.step();
            if let Some(d) = self.a.rpc.poll(&mut call) {
                *msg = d;
                return;
            }
        }
        panic!("the call never finished");
    }
}

/// The generated stub over the pair.
struct Via<'a>(&'a RefCell<Duo>);

impl Transport for Via<'_> {
    fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
        self.0.borrow_mut().call_a(msg, |_| {});
        Ok(())
    }
}

fn echo(d: &RefCell<Duo>) -> EchoClient<Via<'_>> {
    EchoClient::new(Via(d))
}

/// The request the stub makes for `twice(x)`, so a test can hold the call open
/// between `begin` and `poll`.
fn request(x: u32) -> MsgDesc {
    struct Capture(Rc<RefCell<Option<MsgDesc>>>);
    impl Transport for Capture {
        fn call(&self, msg: &mut MsgDesc) -> Result<(), IdlError> {
            *self.0.borrow_mut() = Some(*msg);
            Err(IdlError::NoConnection)
        }
    }
    let slot = Rc::new(RefCell::new(None));
    let _ = EchoClient::new(Capture(slot.clone())).twice(x);
    let m = slot.borrow_mut().take().expect("the stub made a request");
    m
}

fn up() -> RefCell<Duo> {
    let mut d = duo_with(A, B, FAST);
    d.establish();
    RefCell::new(d)
}

#[test]
fn a_noise_session_comes_up_inside_the_quic_connection_and_a_call_is_served() {
    let d = up();
    {
        let d = d.borrow();
        assert!(d.a.ups >= 1 && d.b.ups >= 1, "both ends should have seen the QUIC connection come up");
    }
    let mut c = echo(&d);
    assert_eq!(c.twice(21), Ok(42));
    assert_eq!(c.bump(5), Ok(5));
    assert_eq!(c.bump(2), Ok(7));
    let d = d.borrow();
    assert_eq!(d.b.rpc.host.svc.ran, 3, "each call ran once on the far node");
    assert!(!d.b.rpc.host.warrants.is_empty() && d.b.rpc.host.warrants.values().all(|&badge| badge != 0), "the service is reached through a warrant badged with the session");
}

/// The authentication is Noise's, whatever QUIC lets through: B's topology pins
/// another key for A, so A completes the QUIC handshake and never gets a session.
///
/// **Canary:** the same pair with the right key (the test above) is served.
#[test]
fn a_peer_with_the_wrong_noise_key_connects_quic_and_gets_no_session() {
    let mut d = duo_with(3, B, FAST);
    assert!(d.until(5.0, |d| d.a.ups >= 1 && d.b.ups >= 1), "QUIC should connect: it authenticates nobody");
    assert!(!d.until(1.5, |d| d.a.session_up(B) || d.b.session_up(A)), "a session came up for a key the topology does not pin");
    let d = RefCell::new(d);
    assert_eq!(echo(&d).twice(1), Err(IdlError::NoConnection));
    assert_eq!(d.borrow().b.rpc.host.svc.ran, 0, "nothing was served");
}

/// A far node that goes away (the connection is lost, nothing tells the engine) is
/// `NoConnection` for the caller after the engine's own resends: the relay cannot
/// tell `rpcsrv` of a loss, so this is the behaviour of the system.
#[test]
fn a_far_node_that_goes_silent_is_no_connection_by_the_engines_own_retries() {
    let mut d = duo_with(A, B, FAST);
    d.establish();
    let mut m = request(4);
    d.call_a(&mut m, |d| {
        d.b.pump = None;
    });
    assert_eq!(m.words[0], IdlError::NoConnection.status());
}

/// The far node restarts at the same address: the pump redials, the engine
/// dials its Noise session again over the new connection, and calls work.
#[test]
fn after_a_loss_the_link_and_the_session_come_back_and_calls_are_served_again() {
    let mut d = duo_with(A, B, FAST);
    d.establish();
    let at = d.b.pump.as_ref().unwrap().local_addr().unwrap();
    d.b.pump.as_mut().unwrap().close();
    d.b.pump = None;
    assert!(d.until(5.0, |d| d.a.downs >= 1), "A never saw the connection go");
    // Nothing tells the engine (the relay cannot); its probes break the session.
    assert!(d.until(10.0, |d| !d.a.session_up(B)), "the engine never gave up the session over the lost connection");
    // B comes back: same address, a new process (new TLS key, new engine, another boot epoch).
    let (pb, sb) = listener_pump(Some(at));
    d.b = Node::new(Spec { epoch: 99, ..spec_b(A, FAST) }, pb, sb, A);
    assert!(d.until(10.0, |d| d.a.session_up(B) && d.b.session_up(A)), "the session did not come back");
    assert!(d.a.ups >= 2, "the dialer should have connected twice");
    let d = RefCell::new(d);
    assert_eq!(echo(&d).bump(3), Ok(3), "a restarted far node starts its counter again");
}
