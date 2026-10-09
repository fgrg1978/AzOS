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
/// RFC-0019 handshake's frames send this way, from the brain-tx task's dial;
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

/// `send_all_with_yield`, for the camera task: still a yield count (see the
/// wave 10 INV2 report's list of the waits left counted in yields).
pub(crate) fn send_yielding(fd: azos_net::tcp::TcpHandle, bytes: &[u8]) -> usize {
    fd.send_all_with_yield(bytes, azos_sched::task_yield)
}

/// Receive exactly `buf.len()` bytes from TCP `fd`, sleeping between polls
/// (`net_wait_sleep`), up to `deadline` (CLINT ticks). Returns true iff the
/// buffer filled. Used to read the fixed-size RFC-0019 handshake frames off
/// the stream.
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

/// Drive the RFC-0019 responder handshake on an established TCP socket. The
/// brain (initiator) sends HELLO first; we reply HELLO+proof and wait for
/// CONFIRM. Returns the established `EncryptLink` or `None` on failure
/// (timeout, bad proof, send error).
///
/// Deadline is a generous 5 s wall-clock: the X25519 work is slow under QEMU
/// TCG (~830k cycles measured) and SLIRP NAT thread-starves the emulated
/// harts, so a tight deadline would make the handshake flaky for the same
/// reason the TCP handshake deadline had to move 500ms→2s.
///
/// Every refusal on this side — a malformed, small-order or reflected HELLO,
/// a session id already in `BRAIN_SESSION_ID_CACHE`, a CONFIRM whose proof
/// fails — sends the
/// RFC-0019 REJECT frame before returning `None`, one frame whatever the
/// cause. The CONFIRM slot is read two bytes first, so a REJECT from the
/// brain is taken as one instead of waiting out the deadline for 34 bytes.
pub(crate) fn brain_responder_handshake(
    fd: azos_net::tcp::TcpHandle,
    psk: [u8; 32],
    salt: u64,
) -> Option<azos_behavior::encrypt_link::EncryptLink>
{
    use azos_behavior::encrypt_link::{
        EncryptLink, HandshakeError, derive_ephemeral_priv,
        HELLO_INIT_BYTES, HELLO_REPLY_BYTES, CONFIRM_BYTES, REJECT_BYTES, REJECT_FRAME,
    };
    let refuse = |why: &str| {
        azos_drv_sys::kwarn!("[BRAIN] hs: {} — sending REJECT", why);
        let _ = send_sleeping(fd, &REJECT_FRAME);
    };
    let eph = match derive_ephemeral_priv(&psk, salt) {
        Some(e) => e,
        None => { refuse("entropy pool unseeded (link-encrypt-enforced)"); return None; }
    };
    let mut link = EncryptLink::new(psk, eph);
    let deadline = azos_drv_sys::timebase::now()
        + azos_drv_sys::timebase::TIMER_FREQ * 5;

    // 1. brain → kernel: [0x02][HELLO][brain_e_pub] (34 B)
    let mut hello = [0u8; HELLO_INIT_BYTES];
    if !tcp_recv_exact(fd, &mut hello, deadline) {
        kprintln!("[BRAIN] hs: recv HELLO timed out");
        return None;
    }
    // 2. kernel → brain: [0x02][HELLO][kernel_e_pub][proof_k] (66 B)
    let mut reply = [0u8; HELLO_REPLY_BYTES];
    if link.handle_initiator_hello(&hello, &mut reply).is_err() {
        refuse("HELLO rejected");
        return None;
    }
    // A session id already seen this boot means both ephemerals repeated.
    // The lock covers the lookup only, never socket I/O.
    let fresh = match link.session_id() {
        Some(sid) => BRAIN_SESSION_ID_CACHE.lock().insert_if_new(&sid),
        None => false,
    };
    if !fresh {
        refuse("session id repeated");
        return None;
    }
    let sent = send_sleeping(fd, &reply);
    kprintln!("[BRAIN] hs: reply want={} sent={}", HELLO_REPLY_BYTES, sent);
    if sent <= 0 {
        return None;
    }
    // 3. brain → kernel: [0x02][CONFIRM][proof_b] (34 B), or [0x02][REJECT] (2 B)
    let mut confirm = [0u8; CONFIRM_BYTES];
    if !tcp_recv_exact(fd, &mut confirm[..REJECT_BYTES], deadline) {
        kprintln!("[BRAIN] hs: recv CONFIRM timed out");
        return None;
    }
    let frame_len = if confirm[..REJECT_BYTES] == REJECT_FRAME {
        REJECT_BYTES
    } else if tcp_recv_exact(fd, &mut confirm[REJECT_BYTES..], deadline) {
        CONFIRM_BYTES
    } else {
        kprintln!("[BRAIN] hs: recv CONFIRM timed out");
        return None;
    };
    match link.handle_initiator_confirm(&confirm[..frame_len]) {
        Ok(()) => Some(link),
        Err(HandshakeError::PeerRejected) => {
            azos_drv_sys::kwarn!("[BRAIN] hs: brain sent REJECT");
            None
        }
        Err(_) => {
            refuse("CONFIRM proof rejected");
            None
        }
    }
}

/// Session ids one boot remembers, to refuse a repeated RFC-0019 session.
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
/// is short enough for one QEMU boot to see the kernel send REKEY records
/// (`link: rfc-0019 end to end` in `tools/ci_check.sh`).
#[cfg(not(feature = "link-rekey-smoke"))]
pub(crate) const BRAIN_LINK_REKEY_SECS: u64 = azos_behavior::encrypt_link::REKEY_INTERVAL_SECS;
#[cfg(feature = "link-rekey-smoke")]
pub(crate) const BRAIN_LINK_REKEY_SECS: u64 = 5;

/// Largest brain-protocol packet sealed as one message: the auth envelope's
/// inner limit. A camera frame is the only packet near it.
pub(crate) const BRAIN_TX_PKT_MAX: usize = azos_behavior::auth_envelope::MAX_INNER_BYTES;
const BRAIN_TX_ENV_MAX: usize =
    BRAIN_TX_PKT_MAX + azos_behavior::auth_envelope::ENVELOPE_OVERHEAD;
const BRAIN_TX_WIRE_MAX: usize =
    azos_behavior::encrypt_link::sealed_len_max(BRAIN_TX_ENV_MAX);

/// Wrap a brain-protocol `frame` in the auth envelope, then (RFC-0019) seal
/// it as one message when `link` is established, and queue the wire bytes
/// for the `brain-tx` task on `lane` (wave 15, B1). Never waits for the
/// socket. Returns the wire bytes queued, 0 when the frame was refused (no
/// room on its lane: dropped before sealing and counted) or could not be
/// built. Routing every session message through here keeps the wire
/// uniform — never a mix of plaintext and encrypted frames, which the
/// brain's single-mode reader could not demultiplex.
///
/// The seal may put a REKEY record in front (generation limits, or
/// `request_rekey` from the behavior loop's wall-clock timer) and splits an
/// envelope above 2048 B into several records. Admission is decided with
/// the largest sealed size BEFORE sealing, so a refused frame spends no
/// record counter. The scratch is the behavior task's (`behavior_tx()`), and
/// only the behavior task calls this.
pub(crate) fn enqueue_framed(
    lane: azos_behavior::brain_tx::Lane,
    frame: &[u8],
    link: &mut Option<azos_behavior::encrypt_link::EncryptLink>,
    salt: &mut u64,
) -> usize {
    if frame.len() > BRAIN_TX_PKT_MAX {
        return 0;
    }
    let BehaviorTx { env, wire, framed } = behavior_tx();
    let env_len = azos_behavior::auth_envelope::wrap(frame, env);
    if env_len == 0 {
        return 0;
    }
    let max = match link {
        Some(_) => azos_behavior::encrypt_link::sealed_len_max(env_len),
        None => env_len,
    } + azos_multi_stream::HEADER_LEN;
    if !brain_txq_admits(lane, max) {
        return 0;
    }
    let n = match link.as_mut() {
        None => frame_wire(&env[..env_len], framed),
        Some(l) => {
            let mut next_nonce = || {
                let nr = azos_behavior::encrypt_link::fresh_nonce_rand(*salt);
                *salt = salt.wrapping_add(1);
                nr
            };
            match l.seal_message(&env[..env_len], &mut next_nonce, wire) {
                Ok(m) => frame_wire(&wire[..m], framed),
                Err(_) => 0,
            }
        }
    };
    if n == 0 {
        return 0;
    }
    // Admitted above and only `brain-tx` ran since (it only frees room).
    if brain_txq_push(lane, &framed[..n]) { n } else { 0 }
}

/// Seal the RFC-0019 REJECT record and queue it on the control lane (the
/// end of a session on a terminal record-layer event). Returns whether it
/// was queued; the caller then ends the session with
/// [`brain_tx_end_after_flush`].
pub(crate) fn enqueue_reject(l: &mut azos_behavior::encrypt_link::EncryptLink, salt: &mut u64) -> bool {
    use azos_behavior::brain_tx::Lane;
    let max = azos_behavior::encrypt_link::ENC_OVERHEAD + azos_multi_stream::HEADER_LEN;
    if !brain_txq_admits(Lane::Control, max) {
        return false;
    }
    let nr = azos_behavior::encrypt_link::fresh_nonce_rand(*salt);
    *salt = salt.wrapping_add(1);
    let mut rec = [0u8; azos_behavior::encrypt_link::ENC_OVERHEAD];
    let rn = l.seal_reject(&nr, &mut rec);
    if rn == 0 {
        return false;
    }
    let mut out = [0u8; azos_behavior::encrypt_link::ENC_OVERHEAD + azos_multi_stream::HEADER_LEN];
    let n = frame_wire(&rec[..rn], &mut out);
    n != 0 && brain_txq_push(Lane::Control, &out[..n])
}

/// The behavior task's sealing scratch (.bss: a camera message is ~8.5 KiB
/// and does not belong on a task stack).
pub(crate) struct BehaviorTx {
    env: [u8; BRAIN_TX_ENV_MAX],
    wire: [u8; BRAIN_TX_WIRE_MAX],
    framed: [u8; BRAIN_TX_CARRY_MAX],
}

fn behavior_tx() -> &'static mut BehaviorTx {
    static mut BEHAVIOR_TX: BehaviorTx = BehaviorTx {
        env: [0u8; BRAIN_TX_ENV_MAX],
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
// closes the socket itself) or `brain_tx_end_after_flush` (brain-tx closes
// it once the queue is out — the REJECT path), and reads `brain_tx_stalled`.
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
    /// brain-tx closes `fd` once the queue is out (or stalls).
    close_when_drained: bool,
    /// The behavior task writes `fd` directly for a moment (the I2 probe):
    /// brain-tx sends nothing.
    paused: bool,
}

static BRAIN_TXQ: azos_sync::SpinLock<BrainTxShared> = azos_sync::SpinLock::new(BrainTxShared {
    q: azos_behavior::brain_tx::TxQueue::new(BRAIN_TXQ_RESERVE),
    fd: None,
    close_when_drained: false,
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

/// A session starts on `fd`: no byte queued for an earlier one may reach
/// it. A previous session still flushing (`brain_tx_end_after_flush`) is
/// closed now.
pub(crate) fn brain_tx_begin(fd: azos_net::tcp::TcpHandle) {
    let old = {
        let mut s = BRAIN_TXQ.lock();
        let old = if s.close_when_drained { s.fd } else { None };
        s.q.reset();
        s.fd = Some(fd);
        s.close_when_drained = false;
        s.paused = false;
        old
    };
    // A handle, not a slot: if the old session's slot was freed (its RST)
    // and re-issued -- to `fd` itself, the common case -- this closes
    // nothing.
    if let Some(old) = old {
        if old != fd {
            old.close();
        }
    }
}

/// The session ends now: queued bytes are forgotten and brain-tx stops
/// using the socket before the caller closes it.
pub(crate) fn brain_tx_end() {
    let mut s = BRAIN_TXQ.lock();
    s.q.reset();
    s.fd = None;
    s.close_when_drained = false;
    s.paused = false;
}

/// The session ends once what is queued is on the wire (or the queue
/// stalls): brain-tx closes the socket. The caller must not close it.
pub(crate) fn brain_tx_end_after_flush() {
    let mut s = BRAIN_TXQ.lock();
    if s.fd.is_some() {
        s.close_when_drained = true;
    }
}

/// The socket has taken none of the queued bytes for `BRAIN_TX_STALL_MS`.
pub(crate) fn brain_tx_stalled() -> (bool, usize) {
    let s = BRAIN_TXQ.lock();
    (s.q.is_stalled(), s.q.pending_len())
}

/// The I2 probe writes the socket directly: only with nothing queued, and
/// brain-tx stays off it until [`brain_tx_resume`]. `false`: try later.
#[cfg(feature = "qemu")]
pub(crate) fn brain_tx_quiesce() -> bool {
    let mut s = BRAIN_TXQ.lock();
    if s.q.is_empty() {
        s.paused = true;
        true
    } else {
        false
    }
}

#[cfg(feature = "qemu")]
pub(crate) fn brain_tx_resume() {
    BRAIN_TXQ.lock().paused = false;
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
// Dialling the brain (ARP, SYN, up to 2 s for Established) and the RFC-0019
// responder handshake (up to 5 s) are waits on the network. The behavior
// task only asks for a session (`brain_dial_request`) and adopts the one
// brain-tx publishes (`brain_dial_take`); it never waits for the wire. The
// DHCP lease (`dhcp=1` in CONFIG.INI) is taken here too, before the first
// dial.

/// What a dial produced, for the behavior task to adopt.
pub(crate) enum DialOutcome {
    /// An established connection on `fd`, with its RFC-0019 link when the
    /// link is encrypted (`None`: plaintext or HMAC-only).
    Ready { fd: azos_net::tcp::TcpHandle, link: Option<azos_behavior::encrypt_link::EncryptLink> },
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

/// One dial: TCP connect, Established, then the RFC-0019 handshake when the
/// link is encrypted. Runs in brain-tx; every wait sleeps.
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

    // RFC-0019: with `link_encrypt=1` in CONFIG.INI (or the compiled-in
    // `link-encrypt-enforced`, which a file on the USB-exposed volume must
    // not be able to disarm) the responder handshake runs before any packet
    // is sent. No silent fallback: no LINK.KEY, or a failed handshake, closes
    // the connection rather than sending plaintext.
    if !(azos_config::CFG_LINK_ENCRYPT.load(Ordering::Relaxed)
        || cfg!(feature = "link-encrypt-enforced"))
    {
        return DialOutcome::Ready { fd, link: None };
    }
    let Some(psk) = azos_behavior::auth_envelope::link_key_copy() else {
        kprintln!("[BRAIN] CFG_LINK_ENCRYPT set but no LINK.KEY — \
                   closing (RFC-0019: no plaintext fallback)");
        fd.close();
        return DialOutcome::Failed;
    };
    *salt = salt.wrapping_add(1);
    let now = azos_drv_sys::timebase::now();
    match brain_responder_handshake(fd, psk, now ^ *salt) {
        Some(l) => {
            kprintln!("[BRAIN] RFC-0019 encrypted link established");
            DialOutcome::Ready { fd, link: Some(l) }
        }
        None => {
            azos_drv_sys::kwarn!("[BRAIN] RFC-0019 handshake failed — closing");
            fd.close();
            DialOutcome::Failed
        }
    }
}

/// The `brain-tx` task: dials the brain for the behavior task (connect and
/// the RFC-0019 handshake) and drains the control connection's queue to its
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
    // behavior task's nonce salt (counts up from 0) and the camera task's
    // (from 1 << 63).
    let mut salt: u64 = 1 << 62;
    loop {
        brain_dial_serve(&mut salt);
        let mut pending = false;
        loop {
            // One socket call per lock hold.
            let mut s = BRAIN_TXQ.lock();
            let Some(fd) = s.fd else { break };
            if s.paused || s.q.is_empty() && !s.close_when_drained {
                break;
            }
            let mut dead = false;
            let took = s.q.drain_bounded(
                |b| match fd.send_data(b) {
                    n if n > 0 => n as usize,
                    n => { dead |= n < 0; 0 }
                },
                now,
                BRAIN_TX_STALL_TICKS,
                1,
            );
            if s.close_when_drained && (s.q.is_empty() || s.q.is_stalled() || dead) {
                s.q.reset();
                s.fd = None;
                s.close_when_drained = false;
                drop(s);
                fd.close();
                break;
            }
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
/// message still owed to its socket, and the scratch the envelope and the
/// seal are built in. .bss: a camera message is ~8.5 KiB and does not belong
/// on a 16 KiB task stack. The camera task owns one for its own connection
/// (C1); the control connection queues instead (`enqueue_framed`, wave 15).
pub(crate) struct BrainTx {
    pub(crate) carry: azos_behavior::brain_tx::TxCarry<BRAIN_TX_CARRY_MAX>,
    env: [u8; BRAIN_TX_ENV_MAX],
    wire: [u8; BRAIN_TX_WIRE_MAX],
}

impl BrainTx {
    pub(crate) const fn new() -> Self {
        BrainTx {
            carry: azos_behavior::brain_tx::TxCarry::new(),
            env: [0u8; BRAIN_TX_ENV_MAX],
            wire: [0u8; BRAIN_TX_WIRE_MAX],
        }
    }
}

/// Seal `frame`, inside the auth envelope, as one RFC-0019 message into
/// `tx`'s carry, and push what the socket takes. Bytes an earlier call left
/// unsent go first; while any remain, `frame` is skipped without being sealed:
/// no record counter and no pending REKEY is spent on a message that could not
/// follow them. Returns the bytes the socket took and whether `frame` was
/// sealed.
pub(crate) fn seal_framed(
    fd: azos_net::tcp::TcpHandle,
    frame: &[u8],
    l: &mut azos_behavior::encrypt_link::EncryptLink,
    salt: &mut u64,
    tx: &mut BrainTx,
    send: fn(azos_net::tcp::TcpHandle, &[u8]) -> usize,
) -> (usize, bool) {
    let BrainTx { carry, env, wire } = tx;
    let mut sent = tx_drain(fd, carry, send);
    if !carry.is_empty() {
        return (sent, false);
    }
    let env_len = azos_behavior::auth_envelope::wrap(frame, env);
    if env_len == 0 {
        return (sent, false);
    }
    let sealed = carry
        .seal_with(azos_drv_sys::timebase::now(), |out| {
            let mut next_nonce = || {
                let nr = azos_behavior::encrypt_link::fresh_nonce_rand(*salt);
                *salt = salt.wrapping_add(1);
                nr
            };
            match l.seal_message(&env[..env_len], &mut next_nonce, wire) {
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

/// One `recv()` worth of bytes plus one whole record.
const BRAIN_RX_CARRY_MAX: usize = azos_behavior::encrypt_link::ENC_MAX_PAYLOAD
    + azos_behavior::encrypt_link::ENC_OVERHEAD + 512;

/// Receive side of the encrypted brain link across `recv()` calls: the
/// unconsumed tail of a record torn between two reads, and the message being
/// reassembled from MORE records. With strict record counters a record
/// dropped at a read boundary would end the session, so the tail is kept.
pub(crate) struct BrainRxStream {
    carry: [u8; BRAIN_RX_CARRY_MAX],
    carry_len: usize,
    msg: [u8; azos_behavior::encrypt_link::MAX_MESSAGE_BYTES],
    msg_len: usize,
    record: [u8; azos_behavior::encrypt_link::ENC_MAX_PAYLOAD],
}

impl BrainRxStream {
    const fn new() -> Self {
        BrainRxStream {
            carry: [0u8; BRAIN_RX_CARRY_MAX],
            carry_len: 0,
            msg: [0u8; azos_behavior::encrypt_link::MAX_MESSAGE_BYTES],
            msg_len: 0,
            record: [0u8; azos_behavior::encrypt_link::ENC_MAX_PAYLOAD],
        }
    }

    /// Forget any tail from a previous session.
    pub(crate) fn reset(&mut self) {
        self.carry_len = 0;
        self.msg_len = 0;
    }

    /// Append `input`, open every whole record, and unwrap each completed
    /// message's auth envelope into `out`. Returns the brain-protocol bytes
    /// written; `Err` for a terminal record-layer event, which the caller
    /// answers with `seal_reject` and a close.
    pub(crate) fn feed(
        &mut self,
        link: &mut azos_behavior::encrypt_link::EncryptLink,
        input: &[u8],
        out: &mut [u8],
    ) -> Result<usize, azos_behavior::encrypt_link::RecordError> {
        use azos_behavior::encrypt_link::{Opened, RecordError, RecordKind};
        let end = self.carry_len + input.len();
        if end > self.carry.len() {
            return Err(RecordError::BufferTooSmall);
        }
        self.carry[self.carry_len..end].copy_from_slice(input);
        self.carry_len = end;
        let mut off = 0usize;
        let mut filled = 0usize;
        loop {
            match link.open_record(&self.carry[off..self.carry_len], &mut self.record) {
                Ok(Opened { kind: RecordKind::Rekey, consumed }) => off += consumed,
                Ok(Opened { kind: RecordKind::Data { len, more }, consumed }) => {
                    off += consumed;
                    let Some(dst) = self.msg.get_mut(self.msg_len..self.msg_len + len) else {
                        return Err(RecordError::MessageTooLarge);
                    };
                    dst.copy_from_slice(&self.record[..len]);
                    self.msg_len += len;
                    if !more {
                        // An authenticated message the command parser has no
                        // room for is dropped here, as before this layer.
                        if let Some((n, _)) = azos_behavior::auth_envelope::unwrap_consuming(
                            &self.msg[..self.msg_len], &mut out[filled..],
                        ) {
                            filled += n;
                        }
                        self.msg_len = 0;
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

/// The behavior task's `BrainRxStream` (.bss, ~21 KiB).
pub(crate) fn brain_rx_stream() -> &'static mut BrainRxStream {
    static mut BRAIN_RX: BrainRxStream = BrainRxStream::new();
    // SAFETY: only the behavior task reads the brain socket, and no caller
    // holds the reference across another call.
    unsafe { &mut *core::ptr::addr_of_mut!(BRAIN_RX) }
}

/// Largest sealed brain-link message on the wire, RFC-0021 header included.
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

/// Frame link bytes for the wire into `out`: one RFC-0021 multi-stream frame
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

/// One-shot log of the compiled RFC-0021 scheduling policy (qemu only).
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

/// I2 experiment probe (qemu only): measure the control-stream head-of-line
/// hold-off behind a bulk STREAM_CAMERA frame, under the COMPILE-TIME policy
/// (`azos_limits::MULTISTREAM_SCHED_PRIORITY`). FIFO sends the whole bulk
/// before the control frame; PRIORITY chunks the bulk and lets the control
/// frame jump ahead after the first chunk. Emits one `[I2]` line. Run once.
#[cfg(feature = "qemu")]
pub(crate) fn i2_holdoff_probe(fd: azos_net::tcp::TcpHandle) {
    use azos_drv_sys::wcet::read_cycles;
    use azos_multi_stream as ms;
    use azos_sched::task_yield;

    // K-C5: this probe pushes synthetic bulk straight onto the brain socket,
    // outside both the envelope and the AEAD layers. QEMU-only, but the
    // `qemu,link-encrypt-enforced` combination CI builds would otherwise
    // carry a policy-violating sender. Down by policy, like the UART bridge.
    if azos_behavior::auth_envelope::link_policy_denial().is_some() {
        return;
    }

    const BULK: usize = 16 * 1024;     // ~11 MSS segments
    const CHUNK: usize = 1460;         // one MSS
    static mut BULKBUF: [u8; BULK] = [0x5Au8; BULK];
    static mut WIRE: [u8; CHUNK + ms::HEADER_LEN] = [0u8; CHUNK + ms::HEADER_LEN];

    // A small control frame (content irrelevant — measuring the hold-off, the
    // stub drains it; it need not parse as a brain packet).
    let ctrl = [0x42u8; 32];
    let mut ctrl_wire = [0u8; 32 + ms::HEADER_LEN];
    let ctrl_len = ms::wrap(ms::STREAM_CONTROL, &ctrl, &mut ctrl_wire).unwrap_or(0);

    let bulk = unsafe { &*core::ptr::addr_of!(BULKBUF) };
    let wire = unsafe { &mut *core::ptr::addr_of_mut!(WIRE) };
    let priority = azos_limits::MULTISTREAM_SCHED_PRIORITY;

    // t0 = both bulk and control "ready". Measure when control finishes.
    let t0 = read_cycles();
    let mut off = 0usize;
    let mut ctrl_done = false;
    let mut ctrl_holdoff = 0u64;
    while off < BULK {
        let n = (BULK - off).min(CHUNK);
        let w = ms::wrap(ms::STREAM_CAMERA_BASE, &bulk[off..off + n], wire).unwrap_or(0);
        let _ = fd.send_all_with_yield(&wire[..w], task_yield);
        off += n;
        if priority && !ctrl_done {
            // Control jumps ahead after the first bulk chunk.
            let _ = fd.send_all_with_yield(&ctrl_wire[..ctrl_len], task_yield);
            ctrl_holdoff = read_cycles().wrapping_sub(t0);
            ctrl_done = true;
        }
    }
    if !ctrl_done {
        // FIFO: control waits for the entire bulk frame.
        let _ = fd.send_all_with_yield(&ctrl_wire[..ctrl_len], task_yield);
        ctrl_holdoff = read_cycles().wrapping_sub(t0);
    }
    let bulk_total = read_cycles().wrapping_sub(t0);
    kprintln!(
        "[I2] mode={} bulk_bytes={} chunk={} ctrl_holdoff_cyc={} bulk_total_cyc={}",
        if priority { "priority" } else { "fifo" },
        BULK, CHUNK, ctrl_holdoff, bulk_total,
    );
}
