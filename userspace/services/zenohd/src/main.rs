// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `ZENOHD.ELF`: the AzOS Zenoh gateway.
//!
//! A ring-3 program whose topology row is its whole authority: a call
//! capability on `endpoint.decisions` (`WRITE` + `transfer`, the lend right:
//! the gateway derives an attenuated, badged, expiring copy for every query;
//! also the receipts and the topics) and `READ` on `entropy` (its ZenohID and
//! the heap's randomness), and the stream socket its profile lists. It opens no
//! file and maps no view of the topology: its configuration is Kconfig
//! (`ZENOH_ROUTER_*`, `ZENOH_DECISIONS_KEY`, the limits), compiled in. The
//! engine, the key rule and the answer format are `gw.rs` and `route.rs`,
//! tested on the host over a scripted router (`tests/host/zenohd-tests`); this
//! file is the host they run on and the loop around them.
//!
//! One thread: it reads the router link (TCP to `ZENOH_ROUTER_ADDR`:
//! `ZENOH_ROUTER_PORT`), feeds the engine, ticks it, and sleeps a millisecond
//! when the link is idle. A lost link is redialled with a growing wait. It is
//! not the warrant transport between nodes: that is `rpcsrv`.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

extern crate alloc;

mod gw;
mod route;

use alloc::format;
use alloc::vec::Vec;
use azos_abi::cap::CapPerms;
use azos_abi::invoke::{pledge_case, pledge_class, CLASS_NET, CLASS_READ, CLASS_WRITE};
use azos_abi::syscall_nr::{CASE_AUTHORITY, CASE_BLOCK_WAKE};
use azos_decisions::{DecisionsIdl, DECISIONS_ID};
use azos_libsys as sys;
use azos_ualloc::UserAlloc;
use azos_zenoh::Zid;
use gw::{Config, Gw, Host, Invoked, Link, State, Warrant};
use route::Iface;

use azos_idl::MsgDesc;

/// The interface the gateway fronts. One more interface is one more static
/// and one more Kconfig key.
static DECISIONS: Iface = Iface { id: DECISIONS_ID, level: DecisionsIdl::LEVEL, ops: &DecisionsIdl::OPS };

/// The heap (the codec allocates): the hardened allocator, like every ring-3
/// program that has one (`azos_ualloc`, Kconfig `USER_ALLOC_*`).
#[global_allocator]
static ALLOC: UserAlloc = UserAlloc::new();

/// The call right a warrant carries: `WRITE`, nothing else.
const CALL: u16 = CapPerms::WRITE.bits() as u16;
/// What the gateway asks of the kernel once its identity is made: both cases (a
/// query derives a warrant, calls through it and closes it; the heap maps and
/// unmaps; a handle is looked up the first time an export is used), and of
/// `invoke` only the ops of the data path (the console line, the uptime
/// fallback, the router link). No file, no endpoint or port of its own, no
/// driver, no wait on a child, no Linux number: `DOMAIN_PLEDGE` takes them
/// away for good.
const STEADY: u32 = pledge_case(CASE_AUTHORITY)
    | pledge_case(CASE_BLOCK_WAKE)
    | pledge_class(CLASS_READ)
    | pledge_class(CLASS_WRITE)
    | pledge_class(CLASS_NET);
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
        // The warrant: the export's endpoint, call right only, badged with the
        // gateway's id of the query, lapsing with the query. The kernel decides whether the
        // row may derive it; the call through it, whether the server is
        // reached; both leave their decision records.
        let expiry_ns = sys::vdso_now_ns() + w.life_ns;
        let h = sys::cap_derive(ep, CALL, w.badge, expiry_ns);
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

/// The router link: one stream socket.
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

/// The pool index of the one endpoint this row holds with the call right and
/// the lend right (`WRITE` + `DUP`): `endpoint.decisions`, the source of the
/// per-query warrants. Ring 3 has no by-name lookup, so the row is what names
/// it; the choice is [`route::sole_lendable`], tested on the host.
fn lendable_endpoint() -> Result<u32, usize> {
    let lend = CapPerms::WRITE.union(CapPerms::DUP).bits() as u16;
    let held = (0..azos_limits::IPC_ENDPOINTS as u32).filter_map(|i| {
        let h = sys::cap_lookup(sys::ty::ENDPOINT.raw(), i);
        if h <= 0 {
            return None;
        }
        sys::cap_info(h as u32).ok().map(|c| (i, CapPerms::from_bits_truncate(c.rights).bits() as u16))
    });
    route::sole_lendable(held, lend)
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
    put("[zenohd] AzOS Zenoh gateway\n");
    let dec_index = match lendable_endpoint() {
        Ok(i) => i,
        Err(0) => {
            put("[zenohd] the row holds no call and lend right on endpoint.decisions: no receipts, refusing to run\n");
            sys::exit(2);
        }
        Err(n) => {
            put(&format!("[zenohd] the row holds {n} lendable endpoints, not the one decisions endpoint: refusing to run\n"));
            sys::exit(2);
        }
    };
    let decisions = sys::cap_lookup(sys::ty::ENDPOINT.raw(), dec_index);
    if decisions <= 0 {
        put("[zenohd] cannot resolve the decisions endpoint\n");
        sys::exit(2);
    }
    let mut exports = Vec::new();
    let key = azos_limits::ZENOH_DECISIONS_KEY;
    if !key.is_empty() {
        let Some(e) = route::export(&DECISIONS, dec_index, key) else {
            put("[zenohd] ZENOH_DECISIONS_KEY is not a key expression\n");
            sys::exit(2);
        };
        exports.push(e);
    }
    let Some(router) = ipv4(azos_limits::ZENOH_ROUTER_ADDR) else {
        put("[zenohd] ZENOH_ROUTER_ADDR is not a dotted quad\n");
        sys::exit(2);
    };
    let port = azos_limits::ZENOH_ROUTER_PORT as u16;
    // The identity: a ZenohID of 16 random bytes and the first frame number.
    let mut rnd = [0u8; 20];
    let seeded = sys::dev::lookup(sys::dev::key::ENTROPY, 0).is_some_and(|ep| sys::dev::entropy_read(ep, &mut rnd).is_ok());
    if !seeded {
        put("[zenohd] no entropy endpoint in the row: no ZenohID, refusing to run\n");
        sys::exit(2);
    }
    let Ok(zid) = Zid::new(&rnd[..16]) else { sys::exit(2) };
    let cfg = Config {
        zid,
        initial_sn: u32::from_le_bytes([rnd[16], rnd[17], rnd[18], rnd[19]]) as u64,
        lease_ms: azos_limits::ZENOH_LEASE_MS as u64,
        timeout_max_ms: azos_limits::ZENOH_QUERY_TIMEOUT_MS as u64,
        query_rate: azos_limits::ZENOH_QUERY_RATE as u32,
        topic: azos_limits::ZENOH_DECISION_TOPIC,
        // Our decisions are written under the process id (one thread).
        me: sys::getpid() as u32,
    };
    // Setup is over; a failure leaves the call set as wide as it was.
    if sys::pledge(STEADY) < 0 {
        put("[zenohd] cannot narrow to the steady state: running with the full call set\n");
    }
    let mut kernel = Kernel { handles: Vec::new(), decisions: decisions as u32 };
    let mut gw = Gw::new(cfg, exports);
    let mut wait = 250;
    let mut buf = [0u8; 2 + gw::BATCH as usize];
    loop {
        let Some(sock) = dial(router, port) else {
            sys::sleep(wait);
            wait = (wait * 2).min(REDIAL_MAX_MS);
            continue;
        };
        wait = 250;
        let mut link = Tcp(sock);
        gw.reset();
        gw.start(&mut kernel, &mut link);
        while gw.state() != State::Dead {
            let n = sys::recv_typed(sock, &mut buf);
            if n > 0 {
                gw.on_bytes(&mut kernel, &mut link, &buf[..n as usize]);
            } else if n < 0 {
                break;
            }
            gw.tick(&mut kernel, &mut link);
            if n <= 0 {
                sys::sleep(IDLE_MS);
            }
        }
        let s = gw.stats;
        put(&format!(
            "[zenohd] link lost: {} queries ({} served, {} refused, {} bad, {} busy), {} topics\n",
            s.queries, s.served, s.refused, s.bad, s.busy, s.published
        ));
        let _ = sys::close_typed(sock);
        sys::sleep(wait);
    }
}
