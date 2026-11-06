// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `ipc-roundtrip` SERVER loop, shared by two binaries.
//!
//! This benchmark's peer is an exec'd image, not a `fork()`ed child,
//! because a forked child can never be addressed by
//! capability: it inherits no capability table, and an endpoint's owner is
//! fixed when the capability is SEEDED, by image name. So the loop that used
//! to run in `vsbench`'s own child now runs in `VSSRV.ELF`.
//!
//! **One source, two builds.** `userspace/bench/vssrv` pulls this file with
//! `#[path]`, the same idiom the kernel's own files use for their host test
//! crates. Copying the loop — or, worse, copying only `IPC_SENTINEL` — is how
//! a benchmark's two halves start measuring different protocols, which
//! has already happened once to this lane.

use azos_libsys as sys;

use crate::ipc_proto::{frame, port, ring, IPC_SENTINEL};

/// Serve round trips until the sentinel arrives or `bound` are served.
///
/// Written the way a real server is: `SYS_IPC_REPLY_ACCEPT` answers one
/// request and takes the next in a single ring crossing, so a round trip is
/// TWO traps (the client's call, the server's reply-and-accept) rather than
/// three. That is seL4's `Call` + `ReplyRecv` pair, which is the figure its
/// published IPC numbers describe; a server that replies and then accepts as
/// two calls pays a whole extra trap per exchange for nothing.
///
/// **This changed what `ipc-roundtrip` measures on 2026-09-18.** The server
/// used to reply and accept separately (3,706 instructions per round trip at
/// one hart, 4,021 before the TID lookup change). Recorded here,
/// because a lane that quietly measures a different protocol is how a "win"
/// is born.
pub fn serve_loop(bound: u64) -> ! {
    let mut served = 0u64;
    // A request already taken by the previous `reply_accept`.
    let mut next: Option<sys::FastRequest> = None;
    while served < bound {
        let req = match next.take() {
            Some(r) => r,
            None => match sys::fast_ipc_accept_req() {
                // `delivered == false` means the kernel did not copy the
                // payload out, so `words` is undefined -- not zero, not
                // stale. Replying would answer with garbage, so drop it and
                // let the client's own failure path report it.
                Some(r) if r.delivered => r,
                // No caller waiting yet. Yield rather than spin: a spin here
                // would be charged to the client as latency.
                _ => { sys::yield_now(); continue; }
            },
        };
        let w = req.words[0];
        // Wave 6: the ring lanes. The capability to the ring's page arrived
        // with this call (moved, `a5`); map it, answer, serve the ring until
        // the client stops it, then take fast calls again.
        if w == ring::RING_SETUP {
            let va = sys::shm_map_typed(req.moved_cap);
            let first = if va > 0 { w.wrapping_add(1) } else { va as u64 };
            sys::fast_ipc_reply(req.handle, [first, 0, 0, 0]);
            if va > 0 { ring_serve(va as usize); }
            continue;
        }
        if w == frame::FRAME_SETUP {
            let va = sys::shm_map_typed(req.moved_cap);
            let mut p = None;
            if va > 0 {
                let r = sys::SpscBytes { base: va as usize, cap: frame::FRAME_RING_SLOTS, slot_bytes: frame::FRAME_SLOT_BYTES };
                p = Some(sys::BytesProducer::new(r));
            }
            let first = if va > 0 { w.wrapping_add(1) } else { va as u64 };
            sys::fast_ipc_reply(req.handle, [first, 0, 0, 0]);
            if let Some(p) = p { frame_produce(p, req.words[1]); }
            continue;
        }
        if w == port::PORT_SETUP {
            sys::fast_ipc_reply(req.handle, [w.wrapping_add(1), 0, 0, 0]);
            port_serve();
            continue;
        }
        let answer = [w.wrapping_add(1), 0, 0, 0];
        // Answer the sentinel before leaving, so the client's last call
        // completes instead of failing on a vanished peer. It takes the
        // plain reply: nothing follows it.
        if w == IPC_SENTINEL {
            sys::fast_ipc_reply(req.handle, answer);
            break;
        }
        served += 1;
        // `Ok(Some)` carries the next request. `Ok(None)`: replied, but
        // nothing arrived in the bounded wait. `Err`: the reply reached no
        // one and nothing was accepted; either way the loop's own `accept`
        // is the way to the next request.
        if let Ok(Some(r)) = sys::fast_ipc_reply_accept(req.handle, answer) {
            if r.delivered { next = Some(r); }
        }
    }
    sys::exit(0);
    #[allow(unreachable_code)]
    loop {}
}

/// The server side of `ipc-roundtrip-port`: the runtime on a port with only
/// this server's calls bound, answering `w + 1` until `PORT_END`. A port
/// that cannot be made or bound says so and serves nothing: the client's
/// calls then reach the ordinary loop again.
fn port_serve() {
    use azos_srv::sys::Port;
    struct Echo {
        done: bool,
    }
    impl azos_srv::Handler<Port> for Echo {
        fn call(&mut self, _k: &mut Port, _h: u64, req: &sys::MsgDesc, rep: &mut sys::MsgDesc) {
            let w = req.words[0];
            rep.n_words = 1;
            rep.words[0] = w.wrapping_add(1);
            self.done = w == port::PORT_END;
        }
    }
    let Ok(p) = Port::create() else {
        sys::println(b"[vssrv] ipc-roundtrip-port: no port");
        return;
    };
    if let Err(e) = p.bind_served(1) {
        sys::println(match e {
            azos_srv::sys::ServedError::NoEndpoint => b"[vssrv] ipc-roundtrip-port: no endpoint to serve".as_slice(),
            azos_srv::sys::ServedError::Refused { .. } => b"[vssrv] ipc-roundtrip-port: endpoint.bench would not bind".as_slice(),
        });
    } else {
        let mut srv = azos_srv::Server::new(p);
        let mut h = Echo { done: false };
        while !h.done {
            srv.turn(&mut h);
        }
    }
    let _ = sys::port_destroy_typed(p.cap);
}

/// The server side of the ring lanes: pop requests, answer as the tag says.
fn ring_serve(base: usize) {
    let req = sys::SpscRing { base, cap: ring::RING_CAP };
    let resp = sys::SpscRing { base: base + ring::RING_RESP_OFFSET, cap: ring::RING_CAP };
    let mut st = sys::RingStats::default();
    let (mut items, mut ops0) = (0u64, 0u64);
    loop {
        let v = sys::ring_pop(&req, &mut st);
        match v >> 56 {
            ring::TAG_PING => sys::ring_push(&resp, v.wrapping_add(1), &mut st),
            ring::TAG_STREAM => {
                if items == 0 { ops0 = st.waits + st.wakes; }
                items += 1;
            }
            ring::TAG_STREAM_END => {
                let ops = (st.waits + st.wakes).saturating_sub(ops0);
                sys::ring_push(&resp, (items << 32) | (ops & 0xFFFF_FFFF), &mut st);
                sys::ring_push(&resp, hart(), &mut st);
                items = 0;
            }
            ring::TAG_STOP => {
                sys::ring_push(&resp, ring::RING_STOP_ACK, &mut st);
                return;
            }
            _ => {}
        }
    }
}

// ── The driver-request A/B (wave 11, SHMRING) ─────────────────────────────

/// The producer of the frame-stream lane: `n` frames, sleeping on the tail
/// whenever the ring is full (a ring-3 producer may wait; the kernel's never
/// does), then a stats frame with this side's `(waits, wakes)`.
fn frame_produce(mut p: sys::BytesProducer, n: u64) {
    let mut st = sys::RingStats::default();
    let mut i = 0u64;
    while i <= n {
        if p.is_full() {
            if let sys::RingSleep::Wait { addr, expected } = p.producer_sleep() {
                st.waits += 1;
                let _ = sys::futex_wait_addr(addr, expected, sys::RING_WAIT_NS);
                p.producer_woke();
            }
            continue;
        }
        let r = if i < n {
            p.push_with(0, |dst, room| frame::frame_fill(dst, room, i))
        } else {
            let mut s = [0u8; frame::FRAME_STATS_BYTES];
            s[..8].copy_from_slice(&st.waits.to_le_bytes());
            s[8..].copy_from_slice(&st.wakes.to_le_bytes());
            p.push(0, &s)
        };
        if r == sys::Publish::Wake {
            st.wakes += 1;
            let _ = sys::futex_wake_addr(p.ring().base, 1);
        }
        i += 1;
    }
}

/// This task's hart, slot 4 of `DOMAIN_TASKINFO` (as `vsbench`'s `current_cpu`).
fn hart() -> u64 {
    let mut buf = [0u8; sys::TASKINFO_BYTES];
    if sys::taskinfo(&mut buf) != sys::TASKINFO_BYTES as isize { return u64::MAX; }
    u64::from_le_bytes([buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39]])
}
