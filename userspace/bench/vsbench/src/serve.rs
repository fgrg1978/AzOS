// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `ipc-roundtrip` SERVER loop, shared by two binaries.
//!
//! RFC-0040 gap 2 stage 4 moved this benchmark's peer from a `fork()`ed child
//! to an exec'd image, because a forked child can never be addressed by
//! capability: it inherits no capability table, and an endpoint's owner is
//! fixed when the capability is SEEDED, by image name. So the loop that used
//! to run in `vsbench`'s own child now runs in `VSSRV.ELF`.
//!
//! **One source, two builds.** `userspace/bench/vssrv` pulls this file with
//! `#[path]`, the same idiom the kernel's own files use for their host test
//! crates. Copying the loop — or, worse, copying only `IPC_SENTINEL` — is how
//! a benchmark's two halves start measuring different protocols, which
//! RFC-0045 already records happening once to this lane.

use azos_libsys as sys;

use crate::ipc_proto::{drv, frame, ring, IPC_SENTINEL};

/// Serve round trips until the sentinel arrives or `bound` are served.
///
/// Written the way a real server is: `SYS_IPC_FAST_REPLY_ACCEPT` answers one
/// request and takes the next in a single ring crossing, so a round trip is
/// TWO traps (the client's call, the server's reply-and-accept) rather than
/// three. That is seL4's `Call` + `ReplyRecv` pair, which is the figure its
/// published IPC numbers describe; a server that replies and then accepts as
/// two calls pays a whole extra trap per exchange for nothing.
///
/// **This changed what `ipc-roundtrip` measures on 2026-09-18.** The server
/// used to reply and accept separately (3,706 instructions per round trip at
/// one hart, 4,021 before the TID lookup change). Recorded in RFC-0045,
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
        // Wave 11 (SHMRING): the driver-request A/B. Today's path: register
        // as the power-monitor driver, answer, serve `words[1]` requests from
        // 610, unregister. The ring: as `RING_SETUP`, on 64-byte slots.
        if w == drv::DRV_SETUP {
            let reg = drv_register();
            let first = if reg >= 0 { w.wrapping_add(1) } else { 0x100 + reg.unsigned_abs() as u64 };
            sys::fast_ipc_reply(req.handle, [first, 0, 0, 0]);
            if reg >= 0 { drv_serve(req.words[1], req.words[2]); }
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
        if w == drv::DRVRING_SETUP {
            let va = sys::shm_map_typed(req.moved_cap);
            let first = if va > 0 { w.wrapping_add(1) } else { va as u64 };
            sys::fast_ipc_reply(req.handle, [first, 0, 0, 0]);
            if va > 0 { drvring_serve(va as usize); }
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

/// `azos_driver_server`'s wire structs (`#[repr(C)]`), mirrored as
/// `ina_drv` does, so this image has no kernel dependency.
#[repr(C)]
struct DriverRequest { token: u64, client_tid: u32, op: u32, in_len: u16, out_cap: u16, input: [u8; 64] }
#[repr(C)]
struct DriverReply { token: u64, status: i32, out_len: u16, _pad: u16, output: [u8; 64] }

const DRV_KIND: u32 = azos_abi::drv_kind::DRV_KIND_POWER_MON;

/// Register as `DRV_KIND_POWER_MON` with this image's `drv.17`
/// capability. Non-negative on success, or the refusal (`EBUSY`: a real
/// power-monitor driver already serves the kind on this boot).
fn drv_register() -> isize {
    let reg = sys::cap_lookup(sys::CapKind::DriverRegistry as u8, DRV_KIND);
    if reg < 0 { return reg; }
    match sys::drv_srv_register_typed(reg as u32, 0, 0, 0) {
        0 => reg,
        rc => rc,
    }
}

/// Serve `n` requests as a ring-3 driver does (`ina_drv`'s loop): each
/// reply rides on the next `SYS_DRIVER_REPLY_WAIT`, which parks while the
/// queue is empty. The kernel's proxy asks `power_op::READ_TS`; the answer
/// is a fixed record of the size that op returns. The last reply is
/// published alone (524), so no request is taken that would go unanswered.
///
/// `slack` more requests are served if they come (wave 13): the client
/// retries a read the kernel's proxy timed out, and the timed-out request
/// may still have reached this loop. Once `n` are served, one empty park of
/// [`DRV_TAIL_PARK_MS`] ends the loop, so the slack costs the lane's end at
/// most that.
///
/// The kind is NOT released here: on one hart the client has been woken but
/// has not yet run, and its reply is taken through the kind's registry slot,
/// which an unregister would clear under it (the last read then timed out).
/// The registration ends with this task (`driver_release_all` on exit).
/// The park that ends [`drv_serve`] once its `n` requests are served.
const DRV_TAIL_PARK_MS: u32 = 100;

fn drv_serve(n: u64, slack: u64) {
    use azos_abi::drv_kind::power_op;
    let mut req = DriverRequest { token: 0, client_tid: 0, op: 0, in_len: 0, out_cap: 0, input: [0; 64] };
    let mut reply = DriverReply { token: 0, status: 0, out_len: 0, _pad: 0, output: [0; 64] };
    let (mut served, mut idle) = (0u64, 0u32);
    let mut owed = false;
    let mut tail_idle = false;
    while served < n.saturating_add(slack) && idle < 4 && !tail_idle {
        let rp = if owed { &reply as *const DriverReply as *const u8 } else { core::ptr::null() };
        let park = if served >= n { DRV_TAIL_PARK_MS } else { 1000 };
        match sys::drv_srv_reply_wait(DRV_KIND, rp, &mut req as *mut DriverRequest as *mut u8, park) {
            0 => {
                reply.token = req.token;
                reply.status = if req.op == power_op::READ_TS { 0 } else { -1 };
                reply.out_len = if req.op == power_op::READ_TS { power_op::POWER_TS_BYTES as u16 } else { 0 };
                reply.output[0] = served as u8;
                owed = true;
                served += 1;
            }
            // Published (if owed) and the park ran out: nobody is asking.
            -1 => { owed = false; if served >= n { tail_idle = true } else { idle += 1 } }
            // Refused with nothing done: the reply is still owed.
            _ => { if served >= n { tail_idle = true } else { idle += 1 } }
        }
    }
    if owed { let _ = sys::drv_srv_reply(DRV_KIND, &reply as *const DriverReply as *const u8); }
}

/// The server side of the slot-ring lanes: answer every word `+ 1`; on
/// `TAG_STATS` answer this side's kernel entries since the last one, its
/// hart, and the times it was preempted since the last one (wave 13: a
/// preemption of the SERVER between two answers of a batch also costs the
/// batch a round, and the client's own count cannot see it).
fn drvring_serve(base: usize) {
    let req = sys::SpscSlots::<{ drv::DRV_WORDS }> { base, cap: drv::DRV_RING_CAP };
    let resp = sys::SpscSlots::<{ drv::DRV_WORDS }> { base: base + drv::DRV_RESP_OFFSET, cap: drv::DRV_RING_CAP };
    let mut st = sys::RingStats::default();
    let mut it = [0u64; drv::DRV_WORDS];
    let mut pre0 = preempted();
    loop {
        let waits_before = st.waits;
        sys::slots_pop(&req, &mut it, &mut st);
        match it[0] >> 56 {
            drv::TAG_CALL => {
                for w in it.iter_mut() { *w = w.wrapping_add(1); }
                sys::slots_push(&resp, &it, &mut st);
            }
            drv::TAG_STATS => {
                let mut a = [0u64; drv::DRV_WORDS];
                a[0] = waits_before;
                a[1] = st.wakes;
                a[2] = st.timeouts;
                a[3] = hart();
                let pre = preempted();
                a[4] = pre.wrapping_sub(pre0);
                pre0 = pre;
                sys::slots_push(&resp, &a, &mut st);
                st = sys::RingStats::default();
            }
            drv::TAG_STOP => {
                let mut a = [0u64; drv::DRV_WORDS];
                a[0] = drv::DRV_STOP_ACK;
                sys::slots_push(&resp, &a, &mut st);
                return;
            }
            _ => {}
        }
    }
}

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
                let _ = sys::notify_wait(addr, expected, sys::RING_WAIT_NS);
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
            let _ = sys::notify_wake(p.ring().base, 1);
        }
        i += 1;
    }
}

/// This task's hart, slot 4 of `SYS_TASKINFO` (as `vsbench`'s `current_cpu`).
/// Times this task was preempted (`SYS_TASKINFO` field 3).
fn preempted() -> u64 {
    let mut buf = [0u8; sys::TASKINFO_BYTES];
    if sys::taskinfo(&mut buf) != sys::TASKINFO_BYTES as isize { return 0; }
    u64::from_le_bytes([buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31]])
}

fn hart() -> u64 {
    let mut buf = [0u8; sys::TASKINFO_BYTES];
    if sys::taskinfo(&mut buf) != sys::TASKINFO_BYTES as isize { return u64::MAX; }
    u64::from_le_bytes([buf[32], buf[33], buf[34], buf[35], buf[36], buf[37], buf[38], buf[39]])
}
