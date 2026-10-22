// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The brain link: handshake, framing, sealing, TX carry and RX stream, plus
//! the I2 head-of-line hold-off probe that runs on that socket.

use crate::*;

/// Phase G1: behavior task — subsumption engine running indefinitely.
///
/// Each tick (~100 ms = 10 yields):
/// 1. Collect SensorState (camera, IMU, odometry, encoders)
/// 2. If remote enabled: TCP send VlaObservation, recv VlaAction/VlaGoal
/// 3. If ML enabled: mlp_infer → MlpResult
/// 4. Arbitrate L0→L3 — first valid output wins
/// 5. Publish motor command + update odometry
/// Poll period of the brain link's network waits, in ms (Kconfig
/// `BRAIN_NET_WAIT_POLL_MS`).
const NET_WAIT_POLL_MS: u64 = azos_limits::BRAIN_NET_WAIT_POLL_MS as u64;

/// How long one blocking brain-link send may wait on a closed TCP window, in
/// µs (Kconfig `BRAIN_SEND_BUDGET_US`, the motor watchdog's order). Only the
/// Noise handshake's frames send this way, from the brain-tx task's dial;
/// every message of an established session goes through its queue (wave 15,
/// B1).
const BRAIN_SEND_BUDGET_US: u64 = azos_limits::BRAIN_SEND_BUDGET_US as u64;

/// One network wait of the behavior task: SLEEP `NET_WAIT_POLL_MS`, never
/// yield (the K-C27 class). A yield hands the hart only to tasks at the
/// caller's priority or above, so behavior (14) yield-polling an ARP reply,
/// a DHCP offer, a handshake frame or a window update starved every lower
/// task on its hart for the whole budget, and a bound counted in yields
/// expires early under host load. Every caller bounds the wait with a clock
/// deadline. The wake lands at the programmed deadline on an idle hart and
/// at the next scheduler tick at the latest on a busy one.
pub(crate) fn net_wait_sleep() {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    azos_sched::task_block(azos_sched::WaitReason::Timer(
        now() + TIMER_FREQ * NET_WAIT_POLL_MS / 1000,
    ));
}

/// `send_all_until` with the behavior task's budget and sleeping wait.
fn send_sleeping(fd: azos_net::tcp::TcpHandle, bytes: &[u8]) -> usize {
    fd.send_all_until(bytes, BRAIN_SEND_BUDGET_US, net_wait_sleep)
}

/// `send_all_with_yield`, for the camera task: one of the waits still
/// bounded by a yield count rather than by time.
pub(crate) fn send_yielding(fd: azos_net::tcp::TcpHandle, bytes: &[u8]) -> usize {
    fd.send_all_with_yield(bytes, azos_sched::task_yield)
}

/// Receive exactly `buf.len()` bytes from TCP `fd`, sleeping between polls
/// (`net_wait_sleep`), up to `deadline` (CLINT ticks). Returns true iff the
/// buffer filled. Used to read the handshake frames off the stream.
fn tcp_recv_exact(fd: azos_net::tcp::TcpHandle, buf: &mut [u8], deadline: u64) -> bool {
    let mut got = 0usize;
    while got < buf.len() {
        if azos_drv_sys::timebase::now() >= deadline {
            return false;
        }
        let n = fd.recv(&mut buf[got..]);
        if n > 0 {
            got += n as usize;
        } else {
            net_wait_sleep();
        }
    }
    true
}

/// Receive one whole handshake frame (length prefix included) into `buf`
/// before `deadline`. Returns its wire size, or `None` on a timeout, a closed
/// socket, or a length the handshake cannot carry.
fn recv_handshake_frame(
    fd: azos_net::tcp::TcpHandle,
    buf: &mut [u8; azos_behavior::encrypt_link::FRAME_HEAD
        + azos_behavior::encrypt_link::HANDSHAKE_MSG_MAX],
    deadline: u64,
) -> Option<usize> {
    use azos_behavior::encrypt_link::{frame_len, FRAME_HEAD, HANDSHAKE_MSG_MAX};
    if !tcp_recv_exact(fd, &mut buf[..FRAME_HEAD], deadline) {
        return None;
    }
    let total = frame_len(&buf[..FRAME_HEAD], HANDSHAKE_MSG_MAX).ok()?;
    if !tcp_recv_exact(fd, &mut buf[FRAME_HEAD..total], deadline) {
        return None;
    }
    Some(total)
}

/// Drive the Noise handshake, as the initiator, on an established TCP socket:
/// the robot dials the brain and speaks first. `Noise_IK` toward the brain's
/// static key pinned in the signed topology (`[peer.brain]`), `Noise_XX` with
/// keys derived from the link key otherwise (`azos_crypto::secure_channel`).
/// Returns the established `Link` or `None` on failure (timeout, bad key, a
/// brain that does not hold the link key, send error). Every failure closes
/// nothing here: the caller closes the socket, and there is no REJECT frame to
/// send, because the connection simply ends.
///
/// Deadline is a generous 5 s wall-clock: the X25519 work is slow under QEMU
/// TCG (~830k cycles measured per DH) and SLIRP NAT thread-starves the
/// emulated harts, so a tight deadline would make the handshake flaky for the
/// same reason the TCP handshake deadline had to move 500ms→2s.
pub(crate) fn brain_handshake(
    fd: azos_net::tcp::TcpHandle,
    psk: [u8; 32],
    salt: u64,
) -> Option<azos_behavior::encrypt_link::Link>
{
    use azos_behavior::encrypt_link::{
        brain_pinned_key, derive_ephemeral_priv, Initiator, FRAME_HEAD, HANDSHAKE_MSG_MAX,
        HANDSHAKE_OUT_MAX,
    };
    let pinned = brain_pinned_key();
    let mut eph = derive_ephemeral_priv(&psk, salt)?;
    let mut ini = match Initiator::new(&psk, pinned.as_ref()) {
        Ok(i) => i,
        Err(e) => {
            azos_crypto::ct::secure_zero(&mut eph);
            azos_drv_sys::kwarn!("[BRAIN] hs: cannot start: {:?}", e);
            return None;
        }
    };
    let deadline = azos_drv_sys::timebase::now()
        + azos_drv_sys::timebase::TIMER_FREQ * 5;
    let mut out = [0u8; HANDSHAKE_OUT_MAX];
    let mut inb = [0u8; FRAME_HEAD + HANDSHAKE_MSG_MAX];
    let ok = (|| {
        let mut n = match ini.step(None, &eph, &mut out) {
            Ok(n) => n,
            Err(e) => {
                azos_drv_sys::kwarn!("[BRAIN] hs: first message: {:?}", e);
                return false;
            }
        };
        loop {
            if n > 0 && send_sleeping(fd, &out[..n]) < n {
                kprintln!("[BRAIN] hs: send failed");
                return false;
            }
            if ini.is_done() {
                return true;
            }
            let Some(total) = recv_handshake_frame(fd, &mut inb, deadline) else {
                kprintln!("[BRAIN] hs: no answer from the brain");
                return false;
            };
            n = match ini.step(Some(&inb[..total]), &eph, &mut out) {
                Ok(n) => n,
                Err(e) => {
                    azos_drv_sys::kwarn!("[BRAIN] hs: refused: {:?}", e);
                    return false;
                }
            };
        }
    })();
    azos_crypto::ct::secure_zero(&mut eph);
    if !ok {
        return None;
    }
    let pattern = ini.pattern_byte() as char;
    let link = ini.finish().ok()?;
    // A session id already seen this boot means both ephemerals repeated.
    // The lock covers the lookup only, never socket I/O.
    if !BRAIN_SESSION_ID_CACHE.lock().insert_if_new(&link.session_id()) {
        azos_drv_sys::kwarn!("[BRAIN] hs: session id repeated");
        return None;
    }
    kprintln!("[BRAIN] hs: Noise_{} established", pattern);
    Some(link)
}

/// Session ids one boot remembers, to refuse a repeated session.
/// RAM only: a reboot starts empty, and the cross-boot case rests on the
/// ephemeral key's entropy. The control connection and the camera connection
/// (C1) both record here, so one reconnect of the pair spends two ids.
const BRAIN_SESSION_IDS: usize = 16;

/// The session ids seen this boot, by every brain-link handshake.
static BRAIN_SESSION_ID_CACHE: azos_sync::SpinLock<
    azos_behavior::encrypt_link::SessionIdCache<BRAIN_SESSION_IDS>,
> = azos_sync::SpinLock::new(azos_behavior::encrypt_link::SessionIdCache::new());

/// Wall-clock rekey interval of the brain link, in seconds. The crate's
/// `REKEY_INTERVAL_SECS` everywhere except under `link-rekey-smoke`, where it
/// is short enough for one QEMU boot to see the kernel send rekey messages
/// (`link: encrypted end to end` in `tools/ci_check.sh`).
#[cfg(not(feature = "link-rekey-smoke"))]
pub(crate) const BRAIN_LINK_REKEY_SECS: u64 = azos_behavior::encrypt_link::REKEY_INTERVAL_SECS;
#[cfg(feature = "link-rekey-smoke")]
pub(crate) const BRAIN_LINK_REKEY_SECS: u64 = 5;

/// Largest brain-protocol packet sealed as one message. A camera frame is the
/// only packet near it.
pub(crate) const BRAIN_TX_PKT_MAX: usize = 8 * 1024;
const BRAIN_TX_WIRE_MAX: usize =
    azos_behavior::encrypt_link::sealed_len_max(BRAIN_TX_PKT_MAX);

/// Seal a brain-protocol `frame` as one Noise message of `link`, and queue the
/// wire bytes for the `brain-tx` task on `lane` (wave 15, B1). Never waits for
/// the socket. Returns the wire bytes queued, 0 when the frame was refused (no
/// room on its lane: dropped before sealing and counted) or could not be
/// built. Every byte on the socket is a message of the session.
///
/// The seal may put a rekey message in front (generation limits, or
/// `request_rekey` from the behavior loop's wall-clock timer). Admission is
/// decided with the largest sealed size BEFORE sealing, so a refused frame
/// spends no message counter. The scratch is the behavior task's
/// (`behavior_tx()`), and only the behavior task calls this.
pub(crate) fn enqueue_framed(
    lane: azos_behavior::brain_tx::Lane,
    frame: &[u8],
    link: &mut azos_behavior::encrypt_link::Link,
) -> usize {
    if frame.len() > BRAIN_TX_PKT_MAX {
        return 0;
    }
    let BehaviorTx { wire, framed } = behavior_tx();
    let max = azos_behavior::encrypt_link::sealed_len_max(frame.len())
        + azos_multi_stream::HEADER_LEN;
    if !brain_txq_admits(lane, max) {
        return 0;
    }
    let n = match link.seal_message(frame, wire) {
        Ok(m) => frame_wire(&wire[..m], framed),
        Err(_) => 0,
    };
    if n == 0 {
        return 0;
    }
    // Admitted above and only `brain-tx` ran since (it only frees room).
    if brain_txq_push(lane, &framed[..n]) { n } else { 0 }
}

/// The behavior task's sealing scratch (.bss: a camera message is ~8.5 KiB
/// and does not belong on a task stack).
pub(crate) struct BehaviorTx {
    wire: [u8; BRAIN_TX_WIRE_MAX],
    framed: [u8; BRAIN_TX_CARRY_MAX],
}

fn behavior_tx() -> &'static mut BehaviorTx {
    static mut BEHAVIOR_TX: BehaviorTx = BehaviorTx {
        wire: [0u8; BRAIN_TX_WIRE_MAX],
        framed: [0u8; BRAIN_TX_CARRY_MAX],
    };
    // SAFETY: only the behavior task seals for the control connection, and
    // no caller holds the reference across another call.
    unsafe { &mut *core::ptr::addr_of_mut!(BEHAVIOR_TX) }
}

// ── Wave 15 (B1): the control connection's transmit queue ──────────────────
//
// The behavior task (`enqueue_framed`) only queues; the `brain-tx` task
// (`brain_tx_task`, Kconfig BRAIN_TX_PRIORITY, below behavior on its hart)
// drains the queue to the socket, sleeping BRAIN_NET_WAIT_POLL_MS on a closed
// window. The lock is held for copies and ONE non-blocking `send_data` call,
// never for a wait. The socket's lifecycle stays the behavior task's: it
// opens a session with `brain_tx_begin`, ends it with `brain_tx_end` (then
// closes the socket itself), and reads `brain_tx_stalled`.
// Lane policy and stall rule: `azos_behavior::brain_tx::TxQueue`.

const BRAIN_TXQ_BYTES: usize = azos_limits::BRAIN_TX_QUEUE_BYTES as usize;
const BRAIN_TXQ_RESERVE: usize = azos_limits::BRAIN_TX_CONTROL_RESERVE_BYTES as usize;
const _: () = assert!(
    BRAIN_TXQ_RESERVE < BRAIN_TXQ_BYTES,
    "BRAIN_TX_CONTROL_RESERVE_BYTES must leave room for telemetry in BRAIN_TX_QUEUE_BYTES",
);

struct BrainTxShared {
    q: azos_behavior::brain_tx::TxQueue<BRAIN_TXQ_BYTES>,
    /// The socket brain-tx sends on.
    fd: Option<azos_net::tcp::TcpHandle>,
    /// The behavior task writes `fd` directly for a moment (the I2 probe):
    /// brain-tx sends nothing.
    paused: bool,
}

static BRAIN_TXQ: azos_sync::SpinLock<BrainTxShared> = azos_sync::SpinLock::new(BrainTxShared {
    q: azos_behavior::brain_tx::TxQueue::new(BRAIN_TXQ_RESERVE),
    fd: None,
    paused: false,
});

/// The brain-tx task's tid, for [`brain_tx_kick`]; 0 before it runs.
static BRAIN_TX_TID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn brain_txq_admits(lane: azos_behavior::brain_tx::Lane, len: usize) -> bool {
    let mut s = BRAIN_TXQ.lock();
    if s.q.admits(lane, len) {
        true
    } else {
        s.q.refused(lane);
        false
    }
}

/// Would `lane` admit a message of up to `len` wire bytes now? Asked before
/// work that only makes sense if it will be queued (the camera capture); a
/// `false` is counted as a refused message on `lane`, like one refused at
/// [`enqueue_framed`].
pub(crate) fn brain_tx_has_room(lane: azos_behavior::brain_tx::Lane, len: usize) -> bool {
    brain_txq_admits(lane, len)
}

/// Largest wire size of one sealed brain-link message (a camera frame).
pub(crate) const CAMERA_WIRE_MAX: usize = BRAIN_TX_CARRY_MAX;

fn brain_txq_push(lane: azos_behavior::brain_tx::Lane, bytes: &[u8]) -> bool {
    BRAIN_TXQ.lock().q.push(lane, bytes, azos_drv_sys::timebase::now())
}

/// A session starts on `fd`: no byte queued for an earlier one may reach it.
pub(crate) fn brain_tx_begin(fd: azos_net::tcp::TcpHandle) {
    let mut s = BRAIN_TXQ.lock();
    s.q.reset();
    s.fd = Some(fd);
    s.paused = false;
}

/// The session ends now: queued bytes are forgotten and brain-tx stops
/// using the socket before the caller closes it.
pub(crate) fn brain_tx_end() {
    {
        let mut s = BRAIN_TXQ.lock();
        s.q.reset();
        s.fd = None;
        s.paused = false;
    }
    // The session's inline camera sender goes with it (B2).
    camera_inline_consumer(false);
}

/// The socket has taken none of the queued bytes for `BRAIN_TX_STALL_MS`.
pub(crate) fn brain_tx_stalled() -> (bool, usize) {
    let s = BRAIN_TXQ.lock();
    (s.q.is_stalled(), s.q.pending_len())
}

/// The behavior tick's flush point: wake brain-tx if it parks.
pub(crate) fn brain_tx_kick() {
    let tid = BRAIN_TX_TID.load(Ordering::Acquire);
    if tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(
            tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    }
}

/// One `[BRAIN-TX]` line with the queue's per-boot counters, when a session
/// ends (`why`): messages admitted per lane, telemetry frames dropped for
/// want of room, control messages refused, bytes still queued.
pub(crate) fn brain_tx_report(why: &str) {
    let (adm, dropped, refused, pending) = {
        let s = BRAIN_TXQ.lock();
        (s.q.admitted, s.q.telemetry_dropped, s.q.control_refused, s.q.pending_len())
    };
    kprintln!("[BRAIN-TX] {}: queued control={} telemetry={} dropped telemetry={} control={} pending={} B",
              why, adm[0], adm[1], dropped, refused, pending);
}

// ── Wave 15 (B1): connection setup runs in brain-tx, not in behavior ──────
//
// Dialling the brain (ARP, SYN, up to 2 s for Established) and the Noise
// handshake (up to 5 s) are waits on the network. The behavior
// task only asks for a session (`brain_dial_request`) and adopts the one
// brain-tx publishes (`brain_dial_take`); it never waits for the wire. The
// DHCP lease (`dhcp=1` in CONFIG.INI) is taken here too, before the first
// dial.

/// What a dial produced, for the behavior task to adopt.
pub(crate) enum DialOutcome {
    /// An established connection on `fd`, with its Noise link.
    Ready { fd: azos_net::tcp::TcpHandle, link: azos_behavior::encrypt_link::Link },
    /// The dial or the handshake failed; the socket is closed. Ask again.
    Failed,
}

struct ConnShared {
    /// The behavior task's request: `(ip, port)`; brain-tx takes it.
    want: Option<([u8; 4], u16)>,
    /// brain-tx is dialling.
    busy: bool,
    outcome: Option<DialOutcome>,
}

static BRAIN_CONN: azos_sync::SpinLock<ConnShared> =
    azos_sync::SpinLock::new(ConnShared { want: None, busy: false, outcome: None });

/// Ask brain-tx for a session to `ip:port`, unless one is being dialled or
/// waits to be adopted. Never waits.
pub(crate) fn brain_dial_request(ip: [u8; 4], port: u16) {
    {
        let mut c = BRAIN_CONN.lock();
        if c.busy || c.want.is_some() || c.outcome.is_some() {
            return;
        }
        c.want = Some((ip, port));
    }
    brain_tx_kick();
}

/// The outcome of the last dial, once brain-tx has one. Never waits.
pub(crate) fn brain_dial_take() -> Option<DialOutcome> {
    BRAIN_CONN.lock().outcome.take()
}

/// brain-tx's half: take a request, dial, publish. Returns whether it dialled.
fn brain_dial_serve(salt: &mut u64) -> bool {
    let req = {
        let mut c = BRAIN_CONN.lock();
        match c.want.take() {
            Some(r) => { c.busy = true; r }
            None => return false,
        }
    };
    let outcome = brain_dial(req.0, req.1, salt);
    let mut c = BRAIN_CONN.lock();
    c.busy = false;
    c.outcome = Some(outcome);
    drop(c);
    true
}

/// One dial: TCP connect, Established, then the Noise handshake. Runs in
/// brain-tx; every wait sleeps.
fn brain_dial(
    ip: [u8; 4],
    port: u16,
    salt: &mut u64,
) -> DialOutcome {
    // Local port 0: the stack's ephemeral allocator (RFC 6335 dynamic
    // range, `CONFIG_TCP_EPHEMERAL_PORT_*`) picks a port no live or
    // TIME-WAIT connection holds. A fixed port names the same 4-tuple on
    // every redial, and `tcp::connect` refuses a 4-tuple whose previous
    // connection is still closing; a fresh port reconnects at once and
    // leaves that connection to finish.
    // connect_with_yield resolves ARP first (sleeping between polls,
    // bounded by CONNECT_ARP_BUDGET_US), then sends SYN.
    let Some(fd) = azos_net::tcp::TcpHandle::connect_with_yield(ip, port, 0, net_wait_sleep) else {
        kprintln!("[BRAIN] connect failed rc=-1");
        return DialOutcome::Failed;
    };
    // `tcp::connect` only sends SYN. Wait for Established, sleeping 10 ms
    // per poll, for 2 s: longer than RTO_INITIAL_MS (1000) so one lost SYN
    // or SYN-ACK is retransmitted before giving up.
    let deadline = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ * 2;
    let mut waited = 0u32;
    while azos_drv_sys::timebase::now() < deadline
        && fd.state() != azos_net::tcp::TcpState::Established
    {
        let next = azos_drv_sys::timebase::now() + azos_drv_sys::timebase::TIMER_FREQ / 100;
        azos_sched::task_block(azos_sched::WaitReason::Timer(next));
        waited += 1;
    }
    let st = fd.state();
    if st != azos_net::tcp::TcpState::Established {
        kprintln!("[BRAIN] handshake stalled (state={}) after {} polls / 2s", st as u8, waited);
        fd.close();
        return DialOutcome::Failed;
    }
    kprintln!("[BRAIN] connected fd={} (handshake took {} polls)", fd.slot(), waited);

    // The initiator handshake runs before any packet is sent. No fallback of
    // any kind: no link key, or a failed handshake, closes the connection.
    let Some(psk) = azos_behavior::encrypt_link::link_key_copy() else {
        kprintln!("[BRAIN] no link key — closing (the link is always a Noise session)");
        fd.close();
        return DialOutcome::Failed;
    };
    *salt = salt.wrapping_add(1);
    let now = azos_drv_sys::timebase::now();
    match brain_handshake(fd, psk, now ^ *salt) {
        Some(l) => {
            kprintln!("[BRAIN] encrypted link established");
            DialOutcome::Ready { fd, link: l }
        }
        None => {
            azos_drv_sys::kwarn!("[BRAIN] encrypted-link handshake failed — closing");
            fd.close();
            DialOutcome::Failed
        }
    }
}

/// The `brain-tx` task: dials the brain for the behavior task (connect and
/// the Noise handshake) and drains the control connection's queue to its
/// socket. Never returns. Not in the RT band: it waits on the network.
pub(crate) fn brain_tx_task(_: usize) {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    BRAIN_TX_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    kprintln!("[BRAIN-TX] sender started (queue {} B, control reserve {} B)",
              BRAIN_TXQ_BYTES, BRAIN_TXQ_RESERVE);
    // DHCP auto-discovery (if dhcp=1 in CONFIG.INI), before the first dial;
    // this used to run at the top of the behavior task.
    if azos_config::CFG_NET_DHCP.load(Ordering::Relaxed) != 0 {
        kprintln!("[BEHAVIOR] Running DHCP auto-discovery...");
        let ok = azos_net::dhcp::dhcp_start(net_wait_sleep);
        if !ok {
            azos_drv_sys::kwarn!("[BEHAVIOR] DHCP failed — using static IP config");
        }
    }
    // Seeded from the clock so a reboot does not redial a 4-tuple the brain
    // may still hold open. The handshake's salt is a domain apart from the
    // camera task's (from 1 << 63).
    let mut salt: u64 = 1 << 62;
    loop {
        brain_dial_serve(&mut salt);
        let mut pending = false;
        loop {
            // One socket call per lock hold.
            let mut s = BRAIN_TXQ.lock();
            let Some(fd) = s.fd else { break };
            if s.paused || s.q.is_empty() {
                break;
            }
            let took = s.q.drain_bounded(
                |b| match fd.send_data(b) {
                    n if n > 0 => n as usize,
                    _ => 0,
                },
                now,
                BRAIN_TX_STALL_TICKS,
                1,
            );
            pending = !s.q.is_empty();
            if took == 0 {
                break;
            }
        }
        let park_ms = if pending { NET_WAIT_POLL_MS } else { azos_limits::BRAIN_TX_IDLE_PARK_MS as u64 };
        azos_sched::task_block(azos_sched::WaitReason::Timer(now() + TIMER_FREQ * park_ms / 1000));
    }
}

/// One sending task's transmit state on a brain-link connection: the sealed
/// message still owed to its socket, and the scratch the seal is built in. .bss: a camera message is ~8.5 KiB and does not belong
/// on a 16 KiB task stack. The camera task owns one for its own connection
/// (C1); the control connection queues instead (`enqueue_framed`, wave 15).
pub(crate) struct BrainTx {
    pub(crate) carry: azos_behavior::brain_tx::TxCarry<BRAIN_TX_CARRY_MAX>,
    wire: [u8; BRAIN_TX_WIRE_MAX],
}

impl BrainTx {
    pub(crate) const fn new() -> Self {
        BrainTx {
            carry: azos_behavior::brain_tx::TxCarry::new(),
            wire: [0u8; BRAIN_TX_WIRE_MAX],
        }
    }
}

/// Seal `frame` as one Noise message into `tx`'s carry, and push what the socket takes. Bytes an earlier call left
/// unsent go first; while any remain, `frame` is skipped without being sealed:
/// no message counter and no pending rekey is spent on a message that could not
/// follow them. Returns the bytes the socket took and whether `frame` was
/// sealed.
pub(crate) fn seal_framed(
    fd: azos_net::tcp::TcpHandle,
    frame: &[u8],
    l: &mut azos_behavior::encrypt_link::Link,
    tx: &mut BrainTx,
    send: fn(azos_net::tcp::TcpHandle, &[u8]) -> usize,
) -> (usize, bool) {
    let BrainTx { carry, wire } = tx;
    let mut sent = tx_drain(fd, carry, send);
    if !carry.is_empty() {
        return (sent, false);
    }
    let sealed = carry
        .seal_with(azos_drv_sys::timebase::now(), |out| {
            match l.seal_message(frame, wire) {
                Ok(n) => frame_wire(&wire[..n], out),
                Err(_) => 0,
            }
        })
        .is_ok();
    if sealed {
        sent += tx_drain(fd, carry, send);
    }
    (sent, sealed)
}

/// Largest message the kernel accepts from the brain. Commands
/// are a few dozen bytes; a larger frame is a violation, refused before any of
/// it is read.
const BRAIN_RX_MSG_MAX: usize = 2048;
/// The body limit of the receive side: a message and its tag.
const BRAIN_RX_BODY_MAX: usize = azos_behavior::encrypt_link::max_body_for(BRAIN_RX_MSG_MAX);
/// One whole frame plus one `recv()` worth of the next.
const BRAIN_RX_CARRY_MAX: usize = azos_behavior::encrypt_link::FRAME_HEAD + BRAIN_RX_BODY_MAX + 512;

/// Receive side of the encrypted brain link across `recv()` calls: the
/// unconsumed tail of a frame torn between two reads. Frames are opened in
/// place in this buffer, so there is no second copy of a message. With the
/// transport's strict message counter a frame dropped at a read boundary would
/// end the session, so the tail is kept.
///
/// With Kconfig multi-stream the records travel inside `[stream][len]` frames
/// that TCP cuts and coalesces the same way; `demux` walks them across reads
/// and only the control stream's bytes reach the carry ([`feed_wire`]).
///
/// [`feed_wire`]: BrainRxStream::feed_wire
pub(crate) struct BrainRxStream {
    carry: [u8; BRAIN_RX_CARRY_MAX],
    carry_len: usize,
    demux: azos_multi_stream::StreamDemux,
}

impl BrainRxStream {
    const fn new() -> Self {
        BrainRxStream {
            carry: [0u8; BRAIN_RX_CARRY_MAX],
            carry_len: 0,
            demux: azos_multi_stream::StreamDemux::new(),
        }
    }

    /// Forget any tail from a previous session.
    pub(crate) fn reset(&mut self) {
        self.carry_len = 0;
        self.demux.reset();
    }

    /// [`feed`](Self::feed) one `recv()`'s bytes as they come off the socket:
    /// with `multi_stream`, through the stream demultiplexer first, every
    /// control-stream piece of the read in order (other streams are skipped).
    /// Returns the brain-protocol bytes appended to `out`.
    pub(crate) fn feed_wire(
        &mut self,
        link: &mut azos_behavior::encrypt_link::Link,
        input: &[u8],
        multi_stream: bool,
        out: &mut [u8],
    ) -> Result<usize, azos_behavior::encrypt_link::RecordError> {
        if !multi_stream {
            return self.feed(link, input, out);
        }
        let mut demux = self.demux;
        let mut filled = 0usize;
        let walked = demux.feed(input, |sid, piece| {
            if sid != azos_multi_stream::STREAM_CONTROL {
                return Ok(());
            }
            filled += self.feed(link, piece, out.get_mut(filled..).unwrap_or(&mut []))?;
            Ok(())
        });
        self.demux = demux;
        walked.map(|()| filled)
    }

    /// Append `input`, open every whole frame, and append each message (a
    /// run of brain-protocol packets) to `out`. Returns the bytes written;
    /// `Err` for a terminal transport event, which the caller answers by
    /// closing.
// REQ-012
    pub(crate) fn feed(
        &mut self,
        link: &mut azos_behavior::encrypt_link::Link,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, azos_behavior::encrypt_link::RecordError> {
        use azos_behavior::encrypt_link::{Opened, RecordError, RecordKind, FRAME_HEAD};
        let end = self.carry_len + input.len();
        if end > self.carry.len() {
            return Err(RecordError::BadHeader);
        }
        self.carry[self.carry_len..end].copy_from_slice(input);
        self.carry_len = end;
        let mut off = 0usize;
        let mut filled = 0usize;
        loop {
            match link.open_frame(&mut self.carry[off..self.carry_len], BRAIN_RX_BODY_MAX) {
                Ok(Opened { kind: RecordKind::Rekey, consumed }) => off += consumed,
                Ok(Opened { kind: RecordKind::Data { len }, consumed }) => {
                    let msg = &self.carry[off + FRAME_HEAD..off + FRAME_HEAD + len];
                    off += consumed;
                    // An authenticated message the command parser has no
                    // room for is dropped here.
                    if let Some(dst) = out.get_mut(filled..filled + msg.len()) {
                        dst.copy_from_slice(msg);
                        filled += msg.len();
                    }
                }
                Err(RecordError::Incomplete) => break,
                Err(e) => return Err(e),
            }
        }
        self.carry.copy_within(off..self.carry_len, 0);
        self.carry_len -= off;
        Ok(filled)
    }
}

/// The behavior task's `BrainRxStream` (.bss, ~2.6 KiB).
pub(crate) fn brain_rx_stream() -> &'static mut BrainRxStream {
    static mut BRAIN_RX: BrainRxStream = BrainRxStream::new();
    // SAFETY: only the behavior task reads the brain socket, and no caller
    // holds the reference across another call.
    unsafe { &mut *core::ptr::addr_of_mut!(BRAIN_RX) }
}

/// Largest sealed brain-link message on the wire, multi-stream header included.
const BRAIN_TX_CARRY_MAX: usize = azos_multi_stream::HEADER_LEN + BRAIN_TX_WIRE_MAX;

/// `BRAIN_TX_STALL_MS` in CLINT ticks — see `azos_behavior::brain_tx`.
const BRAIN_TX_STALL_TICKS: u64 = azos_behavior::brain_tx::BRAIN_TX_STALL_MS
    * azos_drv_sys::timebase::TIMER_FREQ / 1000;

/// Offer `carry`'s pending bytes to the socket through `send`; returns the
/// bytes taken. Marks the carry stalled once nothing has been taken for
/// `BRAIN_TX_STALL_TICKS`; the sending task then ends the session.
pub(crate) fn tx_drain(
    fd: azos_net::tcp::TcpHandle,
    carry: &mut azos_behavior::brain_tx::TxCarry<BRAIN_TX_CARRY_MAX>,
    send: fn(azos_net::tcp::TcpHandle, &[u8]) -> usize,
) -> usize {
    carry.drain(
        |bytes| send(fd, bytes),
        azos_drv_sys::timebase::now,
        BRAIN_TX_STALL_TICKS,
    )
}

/// Frame link bytes for the wire into `out`: one multi-stream frame
/// on STREAM_CONTROL when that framing is on — one frame per sealed message,
/// which is the unit the brain's control-stream reader opens — or the bytes
/// unchanged. Returns the framed length, 0 when `out` is too small.
pub(crate) fn frame_wire(inner: &[u8], out: &mut [u8]) -> usize {
    if azos_config::CFG_MULTI_STREAM.load(Ordering::Relaxed) {
        use azos_multi_stream as ms;
        ms_policy_log_once();
        ms::wrap(ms::STREAM_CONTROL, inner, out).unwrap_or(0)
    } else {
        match out.get_mut(..inner.len()) {
            Some(dst) => {
                dst.copy_from_slice(inner);
                inner.len()
            }
            None => 0,
        }
    }
}

/// One-shot log of the compiled multi-stream scheduling policy (qemu only).
fn ms_policy_log_once() {
    #[cfg(feature = "qemu")]
    {
        use core::sync::atomic::{AtomicBool, Ordering as O};
        static MS_POLICY_LOGGED: AtomicBool = AtomicBool::new(false);
        if !MS_POLICY_LOGGED.swap(true, O::Relaxed) {
            azos_drv_sys::kprintln!(
                "[MS] sched policy: {} (compile-time)",
                if azos_limits::MULTISTREAM_SCHED_PRIORITY { "priority" } else { "fifo" },
            );
        }
    }
}
