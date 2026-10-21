// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `MCPD.ELF`: the AzOS MCP bridge.
//!
//! A ring-3 program whose topology row is its whole authority: a call
//! capability with the lend right (`WRITE` + `transfer`) on each endpoint it
//! fronts (the bridge derives an attenuated, badged, expiring, one-use copy for
//! every call), on `endpoint.decisions` (the receipts), `READ` on `entropy`
//! (this boot's epoch and the heap's randomness) and the stream socket its
//! profile lists. What it serves is `/proc/mcp`: the endpoints the row can
//! call. The engine, the tool catalog, the warrant rules and the answer format
//! are `bridge.rs`, `catalog.rs`, `warrant.rs` and `receipt.rs`, tested on the
//! host over a scripted MCP client (`tests/host/mcpd-tests`); this file is the
//! host they run on and the loop around them.
//!
//! One thread. The native stack has no listening socket for ring 3, so the
//! bridge **dials out** (`MCP_PEER_ADDR`:`MCP_PORT`) and serves the MCP server
//! role over the stream: a relay or the agent's host listens, the bridge
//! connects, and the JSON-RPC lines flow as the stdio transport frames them.
//! A lost link is redialled with a growing wait.
//!
//! The root of the warrants is the image's own DICE key (`LinkKey::node_key`,
//! the board seed measured with this image), the way `RPCSRV.ELF` gets its
//! node identity: it never leaves this task, so this task is the only issuer.
//! At boot it prints an operator's warrant on the console; with it the operator
//! issues the others through the bridge itself (`azos.grant_agent`). Without a
//! board seed the bridge refuses to run: it could sign nothing.

#![no_std]
#![no_main]

extern crate alloc;

mod bridge;
mod catalog;
mod receipt;
mod warrant;

use alloc::format;
use alloc::vec::Vec;
use azos_abi::cap::CapPerms;
use azos_abi::invoke::ENDPOINT_DERIVE;
use azos_decisions::{DecisionsIdl, DECISIONS_ID};
use azos_idl::MsgDesc;
use azos_libsys as sys;
use azos_rpc::wire::cav;
use azos_ualloc::UserAlloc;
use bridge::{Bridge, Config, Host, Invoked, Link, Warrant};
use catalog::Iface;

/// The interfaces the bridge can front: the endpoint name a row uses for each,
/// its id and level, and its op table. One more interface is one more line.
static CATALOG: [Iface; 1] =
    [Iface { name: "decisions", id: DECISIONS_ID, level: DecisionsIdl::LEVEL, ops: &DecisionsIdl::OPS }];

/// The heap (the codec allocates): the hardened allocator, like every ring-3
/// program that has one (`azos_ualloc`, Kconfig `USER_ALLOC_*`).
#[global_allocator]
static ALLOC: UserAlloc = UserAlloc::new();

/// Where the kernel exports the view.
const VIEW: &[u8] = b"/proc/mcp\0";
/// A procfs file is at most this (`azos_fs::procfs::PROCFS_MAX_FILE`).
const VIEW_MAX: usize = 2048;
/// The principal id the operator's warrant is issued to: the console.
const OPERATOR: u32 = 1;
/// The call right a warrant carries: `WRITE`, nothing else.
const CALL: u64 = CapPerms::WRITE.bits() as u64;
/// Longest wait between redials, ms.
const REDIAL_MAX_MS: u64 = 5_000;
/// Idle wait of the loop, ms.
const IDLE_MS: u64 = 1;

fn put(line: &str) {
    let _ = sys::console_write(sys::STDOUT, line.as_bytes());
}

/// The kernel as the engine sees it.
struct Kernel {
    /// Pool index -> handle, looked up once.
    handles: Vec<(u32, u32)>,
    decisions: u32,
}

impl Kernel {
    fn handle(&mut self, index: u32) -> Option<u32> {
        if let Some(&(_, h)) = self.handles.iter().find(|(i, _)| *i == index) {
            return Some(h);
        }
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), index);
        if h <= 0 {
            return None;
        }
        self.handles.push((index, h as u32));
        Some(h as u32)
    }
}

impl Host for Kernel {
    fn now_ns(&mut self) -> u64 {
        sys::vdso_now_ns()
    }

    fn log(&mut self, line: &str) {
        put(line);
    }

    fn invoke(&mut self, endpoint: u32, req: &mut MsgDesc, w: &Warrant) -> Invoked {
        let refused = |rc: i64, expiry_ns| Invoked { result: Err(rc), expiry_ns };
        let Some(ep) = self.handle(endpoint) else { return refused(-1, 0) };
        // The warrant: the interface's endpoint, call right only, badged with
        // the principal's Domain id, lapsing with the client's warrant, one
        // use (`QUOTA` 1: the copy answers one call and the handle is closed
        // after it). The op mask is not on it: an endpoint call names no op for
        // the kernel to test it against, and a copy that carries one refuses
        // every call. The bridge tested the mask before it got here. The kernel
        // decides whether the row may derive it; the call through it, whether
        // the server is reached; both leave their decision records.
        let expiry_ns = sys::vdso_now_ns() + w.life_ns;
        let mut d = MsgDesc { version: azos_idl::MSG_VERSION, n_words: 4, ..MsgDesc::default() };
        d.words[0] = CALL | 1 << 8 | (w.badge as u64) << 32;
        d.words[1] = expiry_ns;
        d.words[2] = cav::QUOTA as u64;
        d.words[3] = 1;
        let h = sys::invoke_desc(ep, ENDPOINT_DERIVE, &mut d);
        if h <= 0 {
            return refused(h as i64, 0);
        }
        req.deadline = sys::vdso_now_ns() + w.deadline_ns;
        let rc = sys::ipc_call_v2(h as u32, req);
        let _ = sys::close_typed(h as u32);
        Invoked { result: if rc == 0 { Ok(()) } else { Err(rc as i64) }, expiry_ns }
    }

    fn decisions(&mut self, req: &mut MsgDesc) -> Result<(), i64> {
        match sys::ipc_call_v2(self.decisions, req) {
            0 => Ok(()),
            rc => Err(rc as i64),
        }
    }
}

/// The peer link: one stream socket.
struct Tcp(u32);

impl Link for Tcp {
    fn send(&mut self, bytes: &[u8]) -> bool {
        let (mut at, mut waited) = (0, 0);
        while at < bytes.len() {
            let n = sys::send_typed(self.0, &bytes[at..]);
            if n > 0 {
                at += n as usize;
                waited = 0;
            } else {
                // A full window answers 0 (and a segment that did not leave
                // -1); a dead connection stays so and the wait gives up.
                waited += 1;
                if waited > 200 {
                    return false;
                }
                sys::sleep(1);
            }
        }
        true
    }
}

/// A file or procfs view, whole, up to `buf.len()` bytes.
fn read_file(path: &[u8], buf: &mut [u8]) -> usize {
    let h = sys::open_root(path, 0);
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

/// A TCP connection to `ip:port`, or `None`.
fn dial(ip: [u8; 4], port: u16) -> Option<u32> {
    let cap = sys::socket_typed(2, 1, 0);
    if cap < 0 {
        return None;
    }
    if sys::connect_typed(cap as u32, &sys::sockaddr_in(ip, port)) < 0 {
        let _ = sys::close_typed(cap as u32);
        return None;
    }
    Some(cap as u32)
}

#[sys::main(panic_exit = 70)]
fn main() -> ! {
    put("[mcpd] AzOS MCP bridge\n");
    let mut text = [0u8; VIEW_MAX];
    let n = read_file(VIEW, &mut text);
    let view = catalog::parse_view(&text[..n], &CATALOG);
    if view.skipped != 0 {
        put(&format!("[mcpd] {} endpoint line(s) skipped (no op table here, or not a line)\n", view.skipped));
    }
    let Some(dec_index) = view.decisions else {
        put("[mcpd] the row holds no call capability on endpoint.decisions: no receipts, refusing to run\n");
        sys::exit(2);
    };
    let decisions = sys::cap_lookup(sys::ty::ENDPOINT.raw(), dec_index);
    if decisions <= 0 {
        put("[mcpd] cannot resolve the decisions endpoint\n");
        sys::exit(2);
    }
    let Some(peer) = ipv4(azos_limits::MCP_PEER_ADDR) else {
        put("[mcpd] MCP_PEER_ADDR is not a dotted quad\n");
        sys::exit(2);
    };
    let port = azos_limits::MCP_PORT as u16;
    // This boot's epoch.
    let mut rnd = [0u8; 4];
    let seeded = sys::dev::lookup(sys::dev::key::ENTROPY, 0).is_some_and(|ep| sys::dev::entropy_read(ep, &mut rnd).is_ok());
    if !seeded {
        put("[mcpd] no entropy endpoint in the row: no boot epoch, refusing to run\n");
        sys::exit(2);
    }
    // The root of the warrants: this image's DICE key.
    let Some(key_ep) = sys::dev::lookup(sys::dev::key::LINK_KEY, 0) else {
        put("[mcpd] no linkkey endpoint in the row: no root for the warrants, refusing to run\n");
        sys::exit(2);
    };
    let key = azos_rpc::keys::NodeKey::acquire(|| {
        use sys::dev::LinkKeyCall;
        sys::dev::value(sys::dev::LinkKeyClient::new(sys::dev::Ep(key_ep)).node_key())
    });
    let Ok(key) = key else {
        put("[mcpd] the kernel issues no node key (no board seed, or this image was not measured): refusing to run\n");
        sys::exit(2);
    };
    let mut root = key.secret();
    drop(key);
    let keys = warrant::Keys::new(root);
    azos_crypto::ct::secure_zero(&mut root);
    let Some(keys) = keys else { sys::exit(2) };
    let cfg = Config {
        epoch: u32::from_le_bytes(rnd),
        call_rate: azos_limits::MCP_CALL_RATE as u32,
        warrant_max_ns: azos_limits::MCP_WARRANT_MAX_MS as u64 * 1_000_000,
        proposal_ttl_ns: azos_limits::MCP_PROPOSAL_TTL_MS as u64 * 1_000_000,
        grant_max_ns: azos_limits::MCP_GRANT_MAX_MS as u64 * 1_000_000,
        // Our decisions are written under the process id (one thread).
        me: sys::getpid() as u32,
    };
    put(&format!("[mcpd] {} interface(s) fronted, epoch {:#x}\n", view.exports.len(), cfg.epoch));
    // The operator's warrant, for the console: whoever reads it is the operator.
    let until = sys::vdso_now_ns() + azos_limits::MCP_ENROL_TTL_MS as u64 * 1_000_000;
    let enrol = warrant::mint_admin(&keys, cfg.epoch, OPERATOR, until);
    put(&format!(
        "[mcpd] operator warrant (principal {OPERATOR}, until {until} ns): {}\n",
        warrant::token_hex(&enrol)
    ));
    let mut kernel = Kernel { handles: Vec::new(), decisions: decisions as u32 };
    let mut bridge = Bridge::new(cfg, keys, view.exports);
    let mut wait = 250;
    let mut buf = [0u8; 1024];
    loop {
        let Some(sock) = dial(peer, port) else {
            sys::sleep(wait);
            wait = (wait * 2).min(REDIAL_MAX_MS);
            continue;
        };
        wait = 250;
        let mut link = Tcp(sock);
        bridge.reset();
        loop {
            let n = sys::recv_typed(sock, &mut buf);
            if n > 0 {
                if !bridge.on_bytes(&mut kernel, &mut link, &buf[..n as usize]) {
                    break;
                }
            } else if n < 0 {
                break;
            } else {
                sys::sleep(IDLE_MS);
            }
        }
        let s = bridge.stats;
        put(&format!(
            "[mcpd] link lost: {} calls ({} served, {} refused, {} failed, {} busy), {} proposed, {} confirmed, {} committed\n",
            s.calls, s.served, s.refused, s.failed, s.busy, s.proposed, s.confirmed, s.committed
        ));
        let _ = sys::close_typed(sock);
        sys::sleep(wait);
    }
}
