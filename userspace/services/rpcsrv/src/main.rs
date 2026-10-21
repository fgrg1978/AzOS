// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `RPCSRV.ELF`: the AzOS RPC server (transparent RPC, Phase 9 step 1).
//!
//! A ring-3 program whose topology row is its whole authority: `READ` on the
//! proxy endpoints it serves (`endpoint.rpc-<service>`, the local face of a
//! service on another node), the lend right (`WRITE` + `transfer`) on the
//! endpoints its `export` key offers to the peer classes, and the
//! datagram socket its profile lists. The engine, the frame format, the
//! sessions, the warrants and the provenance are `userspace/lib/rpc`, tested
//! on the host over two servers (`tests/host/rpc-tests`); this file is the
//! host it runs on and the two loops around it.
//!
//! When the endpoint behind an export is closed or revoked the engine tells the
//! peers that hold authority over it ([`Rpc::revoke_export`]) and a peer's notice
//! closes what this node re-minted from that peer's replies;
//! a peer that does not answer within `RPC_REVOKE_BOUND_MS` has its
//! session broken.
//!
//! Two threads share the engine behind one lock:
//!
//! * the **local** thread accepts the calls made on the proxy endpoints
//!   (`ipc_accept_v2`), sends each across ([`Rpc::begin`]), waits for it
//!   ([`Rpc::poll`]) and replies;
//! * the **link** thread reads datagrams ([`Rpc::on_frame`]: a peer's request
//!   is run against the real endpoint through the peer's warrant, an answer
//!   is handed to the waiting call) and keeps the housekeeping ([`Rpc::tick`]).
//!
//! The link is UDP on the network the kernel's stack serves, to the one peer
//! `RPC_PEER_ADDR`:`RPC_UDP_PORT`; a datagram from any other source address is
//! dropped before the engine sees it. With `RPC_QUIC` the one peer is the `rpcquic`
//! relay on this host (`userspace/services/rpcquic`, a std program): the same sealed
//! datagrams, carried between the two nodes on QUIC streams by a process that
//! holds the QUIC stack so this one does not. **Every session is authenticated**: the
//! handshake is Noise IK with the static keys the topology pins in its `peer`
//! rows (`/proc/rpc`), so the source address and the node id a frame states
//! decide nothing, and every frame after it is sealed. The node's own static
//! key is its DICE identity, `HKDF(device seed, measurement of this image)`,
//! which the kernel derives and issues on its `linkkey` endpoint
//! (`azos_rpc::keys`), and the ephemeral keys come from the kernel's `entropy`
//! endpoint: a task row without both runs nothing. The server prints its own
//! public key at start, which is what the other node's topology pins; an image
//! other than the one that key was pinned for gets another key and no session.

#![no_std]
#![no_main]

use azos_decisions::{DecisionsIdl, DECISIONS_ID};
use azos_libsys as sys;
use azos_rpc::wire::{Asm, Caveat, CAVEATS_MAX, FRAME_MAX};
use azos_rpc::{Config, Host, Link, MsgDesc, NodeId, Policy, Rpc, Service, Started};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The interfaces this server carries: each is an endpoint a row may export
/// and a proxy a node may serve. Every op declares how it is delivered
/// (`Decisions`: all idempotent).
static CATALOG: [Service; 1] = [Service { name: b"decisions", id: DECISIONS_ID, ops: &DecisionsIdl::OPS }];

/// What the kernel gives the engine, and the two secrets it asks for (the
/// node's static key and the entropy endpoint), zeros until `_start` fills
/// them: the image holds no bytes for it.
struct Kernel {
    entropy_ep: u32,
    has_key: bool,
    static_sk: [u8; 32],
}

fn put(line: &[u8]) {
    let _ = sys::console_write(sys::STDOUT, line);
}

/// `bytes` as lowercase hex.
fn put_hex(bytes: &[u8]) {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().take(32).enumerate() {
        out[2 * i] = D[(b >> 4) as usize];
        out[2 * i + 1] = D[(b & 15) as usize];
    }
    put(&out[..2 * bytes.len().min(32)]);
}

impl Host for Kernel {
    fn now_ns(&mut self) -> u64 {
        sys::vdso_now_ns()
    }

    fn log(&mut self, line: &[u8]) {
        put(line);
    }

    fn endpoint(&mut self, index: u32) -> Option<u32> {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), index);
        (h > 0).then_some(h as u32)
    }

    fn derive(&mut self, ep: u32, rights: u16, badge: u32, expiry_ns: u64, caveats: &[Caveat]) -> Result<u32, i64> {
        if caveats.len() > CAVEATS_MAX {
            return Err(sys::E_INVAL as i64);
        }
        let mut list = [(0u8, 0u64); CAVEATS_MAX];
        for (slot, c) in list.iter_mut().zip(caveats) {
            *slot = (c.kind, c.arg);
        }
        let h = sys::endpoint_derive(ep, rights as u8, badge, expiry_ns, &list[..caveats.len()]);
        if h > 0 { Ok(h as u32) } else { Err(h as i64) }
    }

    fn close(&mut self, h: u32) {
        let _ = sys::close_typed(h);
    }

    fn call(&mut self, ep: u32, msg: &mut MsgDesc) -> i64 {
        sys::ipc_call_v2(ep, msg) as i64
    }

    fn mo_size(&mut self, h: u32) -> Option<usize> {
        let mut info = [0u8; sys::SHM_INFO_BYTES];
        if sys::shm_acquire_typed(h, &mut info) < 0 {
            return None;
        }
        Some(u32::from_le_bytes([info[0], info[1], info[2], info[3]]) as usize * sys::PAGE_SIZE)
    }

    fn mo_read(&mut self, h: u32, out: &mut [u8]) -> Option<usize> {
        let va = sys::shm_map_typed(h);
        if va <= 0 {
            return None;
        }
        // SAFETY: the kernel just mapped the whole region at `va`, and the
        // engine asks for no more than the size `mo_size` reported.
        unsafe { core::ptr::copy_nonoverlapping(va as *const u8, out.as_mut_ptr(), out.len()) };
        Some(out.len())
    }

    fn mo_create(&mut self, data: &[u8]) -> Result<u32, i64> {
        let pages = data.len().div_ceil(sys::PAGE_SIZE).max(1);
        let h = sys::shm_create_typed(pages as u64, sys::SHM_RW);
        if h <= 0 {
            return Err(h as i64);
        }
        let va = sys::shm_map_typed(h as u32);
        if va <= 0 {
            let _ = sys::close_typed(h as u32);
            return Err(va as i64);
        }
        // SAFETY: a fresh region of `pages` pages, mapped read-write at `va`;
        // `data` fits in it. The rest of it is zero from the kernel.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, data.len()) };
        Ok(h as u32)
    }

    fn static_key(&mut self) -> Option<[u8; 32]> {
        self.has_key.then_some(self.static_sk)
    }

    fn entropy(&mut self, out: &mut [u8; 32]) -> bool {
        sys::dev::entropy_read(self.entropy_ep, out).is_ok()
    }
}

/// The datagram socket and the one peer it talks to.
struct Udp {
    sock: AtomicU32,
    peer_node: NodeId,
    peer: [u8; sys::SOCKADDR_LEN],
}

impl Link for Udp {
    fn send(&mut self, peer: NodeId, frame: &[u8]) -> bool {
        // One configured link: a frame for another node has no address.
        peer == self.peer_node && sys::sendto_typed(self.sock.load(Ordering::Relaxed), frame, Some(&self.peer)) >= 0
    }
}

type Server = Rpc<Kernel, Udp>;

/// The engine and the lock that makes the two threads take turns on it.
struct Shared {
    locked: AtomicBool,
    rpc: UnsafeCell<Server>,
}

// SAFETY: every access to `rpc` is inside `with`, which holds `locked`.
unsafe impl Sync for Shared {}

/// The settings, with this boot's `epoch`.
fn config(epoch: u32) -> Config {
    Config {
        node: azos_limits::RPC_NODE_ID as NodeId,
        epoch,
        warrant_ttl_ns: azos_limits::RPC_WARRANT_TTL_MS as u64 * 1_000_000,
        dedupe_window: azos_limits::RPC_DEDUPE_WINDOW as usize,
        retries: azos_limits::RPC_RETRIES as u8,
        rto_ns: azos_limits::RPC_RTO_MS as u64 * 1_000_000,
        ping_ns: azos_limits::RPC_PING_MS as u64 * 1_000_000,
        miss_limit: azos_limits::RPC_MISS_LIMIT as u8,
    }
}

static SHARED: Shared = Shared {
    locked: AtomicBool::new(false),
    // All zeros until `_start` configures it: the image holds no bytes for it.
    rpc: UnsafeCell::new(Rpc::new(
        Kernel { entropy_ep: 0, has_key: false, static_sk: [0; 32] },
        Udp { sock: AtomicU32::new(0), peer_node: 0, peer: [0; sys::SOCKADDR_LEN] },
        &CATALOG,
    )),
};

/// Run `f` on the engine, alone.
fn with<R>(f: impl FnOnce(&mut Server) -> R) -> R {
    while SHARED.locked.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        sys::yield_now();
    }
    // SAFETY: `locked` is held; no other reference to the engine exists.
    let r = f(unsafe { &mut *SHARED.rpc.get() });
    SHARED.locked.store(false, Ordering::Release);
    r
}

/// The link thread's reassembly state: its own, never shared.
struct AsmCell(UnsafeCell<Asm>);
// SAFETY: only the link thread touches it.
unsafe impl Sync for AsmCell {}
static ASM: AsmCell = AsmCell(UnsafeCell::new(Asm::new()));

#[repr(align(16))]
struct Stack(UnsafeCell<[u8; 16 * 1024]>);
// SAFETY: handed to the one thread that runs on it.
unsafe impl Sync for Stack {}
static LINK_STACK: Stack = Stack(UnsafeCell::new([0; 16 * 1024]));

/// Read `/proc/rpc` (the signed topology's peer classes and exports, for a
/// reader that serves a proxy endpoint).
fn view(buf: &mut [u8]) -> usize {
    let h = sys::open_root(b"/proc/rpc\0", 0);
    if h < 0 {
        return 0;
    }
    let h = h as u32;
    let mut got = 0;
    while got < buf.len() {
        let n = sys::file_read_typed(h, &mut buf[got..]);
        if n <= 0 {
            break;
        }
        got += n as usize;
    }
    let _ = sys::close_typed(h);
    got
}

/// `a.b.c.d` as its four bytes.
fn ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut it = s.split('.');
    for o in out.iter_mut() {
        *o = it.next()?.parse().ok()?;
    }
    it.next().is_none().then_some(out)
}

extern "C" fn link_thread(_a0: u64, _stack: u64, _arg: u64) -> ! {
    let (sock, peer) = with(|r| (r.link.sock.load(Ordering::Relaxed), r.link.peer));
    let mut buf = [0u8; FRAME_MAX];
    let tick_ns = azos_limits::RPC_RTO_MS as u64 * 1_000_000 / 2;
    let mut last = sys::vdso_now_ns();
    loop {
        let mut from = [0u8; sys::SOCKADDR_LEN];
        let n = sys::recvfrom_typed(sock, &mut buf, Some(&mut from));
        // The tick is due whether or not frames keep arriving: steady traffic
        // (or a flood) must not starve the probes and the Hello resends.
        let now = sys::vdso_now_ns();
        if now.saturating_sub(last) >= tick_ns {
            last = now;
            with(|r| r.tick());
        }
        if n > 0 {
            // Family, port and address: the first 8 bytes of a `sockaddr_in`.
            // Anything from elsewhere is not the peer's, whatever node id it states.
            if from[..8] == peer[..8] {
                // SAFETY: only this thread uses `ASM`.
                let asm = unsafe { &mut *ASM.0.get() };
                with(|r| r.on_frame(asm, &buf[..n as usize]));
            }
            continue;
        }
        sys::sleep(1);
    }
}

#[no_mangle]
pub extern "C" fn _start(_a0: usize, a1: usize) -> ! {
    sys::startup_init(a1);
    put(b"[rpcsrv] AzOS RPC server\n");
    let epoch = (sys::vdso_now_ns() as u32 ^ (sys::getpid() as u32).rotate_left(16)) | 1;
    let mut text = [0u8; 2048];
    let n = view(&mut text);
    // The identity: the DICE static key of this image, and the entropy for the
    // ephemeral keys. Without either no session can be authenticated,
    // and the server does not run unauthenticated.
    let Some(entropy_ep) = sys::dev::lookup(sys::dev::key::ENTROPY, 0) else {
        put(b"[rpcsrv] no entropy endpoint in the row: no handshake can run\n");
        sys::exit(2);
    };
    let Some(key_ep) = sys::dev::lookup(sys::dev::key::LINK_KEY, 0) else {
        put(b"[rpcsrv] no linkkey endpoint in the row: no node identity, refusing to run\n");
        sys::exit(2);
    };
    let key = azos_rpc::keys::NodeKey::acquire(|| {
        use sys::dev::LinkKeyCall;
        sys::dev::value(sys::dev::LinkKeyClient::new(sys::dev::Ep(key_ep)).node_key())
    });
    let Ok(key) = key else {
        put(b"[rpcsrv] the kernel issues no node key (no board seed, or this image was not measured): no node identity, refusing to run\n");
        sys::exit(2);
    };
    let mut sk = key.secret();
    put(b"[rpcsrv] node public key ");
    put_hex(&key.public());
    put(b"\n");
    drop(key);
    let policy = Policy::parse(&text[..n]);
    if azos_limits::RPC_PEER_NODE != 0 && policy.noise_pk(azos_limits::RPC_PEER_NODE as NodeId).is_none() {
        put(b"[rpcsrv] the topology pins no Noise key for the peer node: no session can be authenticated, refusing to run\n");
        sys::exit(2);
    }
    // The socket: the stack's address (it may still be coming up), the link port.
    let sock = sys::socket_typed(2, 2, 0);
    if sock < 0 {
        put(b"[rpcsrv] no socket\n");
        sys::exit(2);
    }
    let local = loop {
        let ip = sys::net_getip();
        if ip != 0 {
            break (ip as u32).to_be_bytes();
        }
        sys::sleep(100);
    };
    // The transport (RPC_QUIC): the frames go straight to the peer as datagrams, or to the
    // `rpcquic` relay on this host, which carries them over QUIC. The stack delivers a datagram
    // sent to its own address to the socket bound at that port (it has no 127.0.0.0/8), so the
    // relay is addressed at `local`. Either way the other end of this socket is one address, and
    // everything from any other is dropped; what the relay changes is who the sealed frames pass
    // through, not who is believed.
    let (link_ip, link_port) = if azos_limits::RPC_QUIC {
        (local, azos_limits::RPC_QUIC_RELAY_PORT as u16)
    } else {
        let Some(peer_ip) = ipv4(azos_limits::RPC_PEER_ADDR) else {
            put(b"[rpcsrv] RPC_PEER_ADDR is not a dotted quad\n");
            sys::exit(2);
        };
        (peer_ip, azos_limits::RPC_UDP_PORT as u16)
    };
    if sys::bind_typed(sock as u32, &sys::sockaddr_in(local, azos_limits::RPC_UDP_PORT as u16)) != 0 {
        put(b"[rpcsrv] cannot bind the link port\n");
        sys::exit(2);
    }
    with(|r| {
        r.configure(config(epoch));
        r.set_revoke_bound(azos_limits::RPC_REVOKE_BOUND_MS as u64 * 1_000_000);
        r.host.entropy_ep = entropy_ep;
        r.host.static_sk = sk;
        r.host.has_key = true;
        r.link.peer_node = azos_limits::RPC_PEER_NODE as NodeId;
        r.set_policy(policy);
        r.link.sock.store(sock as u32, Ordering::Relaxed);
        r.link.peer = sys::sockaddr_in(link_ip, link_port);
    });
    azos_rpc::chan::wipe(&mut sk);
    let top = LINK_STACK.0.get() as usize + 16 * 1024;
    if sys::thread_create(link_thread, top, 0, core::ptr::null_mut()) < 0 {
        put(b"[rpcsrv] cannot start the link thread\n");
        sys::exit(2);
    }
    loop {
        let mut req = MsgDesc::default();
        let call = sys::ipc_accept_v2(&mut req);
        if call < 0 {
            // Nothing arrived (a spurious wake): wait again.
            sys::yield_now();
            continue;
        }
        // The badge of the capability the call came through, 0 when the call
        // was not badged: who is asking, for the provenance.
        let subject = if req.flags & azos_abi::ipc_msg::MSG_BADGED != 0 { req.badge as u32 } else { 0 };
        let rep = match with(|r| r.begin(&req, subject)) {
            Started::Done(d) => d,
            Started::Pending(mut call) => loop {
                if let Some(d) = with(|r| r.poll(&mut call)) {
                    break d;
                }
                sys::sleep(1);
            },
        };
        let _ = sys::ipc_reply_v2(call as u64, &rep);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::exit(70);
}
