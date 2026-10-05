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
/// Poll period of the behavior task's network waits, in ms.
const NET_WAIT_POLL_MS: u64 = 1;

/// How long one brain-link send may wait on a closed TCP window, in µs. The
/// order of the motor watchdog (500 ms without a command SAFE-STOPs): a send
/// held longer than this stops the robot anyway. A sealed message that does
/// not fit keeps its tail in the carry and resumes on the next call.
const BRAIN_SEND_BUDGET_US: u64 = 500_000;

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
fn send_sleeping(fd: usize, bytes: &[u8]) -> usize {
    azos_net::tcp::send_all_until(fd, bytes, BRAIN_SEND_BUDGET_US, net_wait_sleep)
}

/// `send_all_with_yield`, for the camera task: still a yield count (see the
/// wave 10 INV2 report's list of the waits left counted in yields).
pub(crate) fn send_yielding(fd: usize, bytes: &[u8]) -> usize {
    azos_net::tcp::send_all_with_yield(fd, bytes, azos_sched::task_yield)
}

/// Receive exactly `buf.len()` bytes from TCP `fd`, sleeping between polls
/// (`net_wait_sleep`), up to `deadline` (CLINT ticks). Returns true iff the
/// buffer filled. Used to read the fixed-size RFC-0019 handshake frames off
/// the stream.
fn tcp_recv_exact(fd: usize, buf: &mut [u8], deadline: u64) -> bool {
    let mut got = 0usize;
    while got < buf.len() {
        if azos_drv_sys::timebase::now() >= deadline {
            return false;
        }
        let n = azos_net::tcp::recv(fd, &mut buf[got..]);
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
    fd: usize,
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
/// it as one message when `link` is established, and push every byte to the
/// wire. Returns bytes sent (>0 on success). Routing every TCP send through
/// this keeps the wire uniform — never a mix of plaintext and encrypted
/// frames, which the brain's single-mode reader could not demultiplex.
///
/// The seal may put a REKEY record in front (generation limits, or
/// `request_rekey` from the behavior loop's wall-clock timer) and splits an
/// envelope above 2048 B into several records. The buffers are the behavior
/// task's (`brain_tx()`), and only the behavior task calls this.
///
/// On an established link the sealed bytes go through `brain_tx_carry()`:
/// whatever an earlier call left unsent goes first, and while any of it
/// remains this `frame` is skipped without being sealed — no record counter
/// and no pending REKEY is spent on a message that could not follow it. On an
/// unkeyed or HMAC-only link a short send drops the rest of the frame, as it
/// always has; those frames carry no record counter.
pub(crate) fn send_framed(
    fd: usize,
    frame: &[u8],
    link: &mut Option<azos_behavior::encrypt_link::EncryptLink>,
    salt: &mut u64,
) -> i32 {
    if frame.len() > BRAIN_TX_PKT_MAX {
        return 0;
    }
    let Some(l) = link.as_mut() else {
        let env = &mut brain_tx().env;
        let env_len = azos_behavior::auth_envelope::wrap(frame, env);
        if env_len == 0 {
            return 0;
        }
        return send_wire(fd, &env[..env_len]);
    };
    seal_framed(fd, frame, l, salt, brain_tx(), send_sleeping).0 as i32
}

/// One sending task's transmit state on a brain-link connection: the sealed
/// message still owed to its socket, and the scratch the envelope and the
/// seal are built in. .bss: a camera message is ~8.5 KiB and does not belong
/// on a 16 KiB task stack. The behavior task owns one for the control
/// connection (`brain_tx()`), the camera task one for its own (C1).
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
    fd: usize,
    frame: &[u8],
    l: &mut azos_behavior::encrypt_link::EncryptLink,
    salt: &mut u64,
    tx: &mut BrainTx,
    send: fn(usize, &[u8]) -> usize,
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

/// The behavior task's transmit state on the control connection.
pub(crate) fn brain_tx() -> &'static mut BrainTx {
    static mut BRAIN_TX: BrainTx = BrainTx::new();
    // SAFETY: only the behavior task sends on the brain socket, and no caller
    // holds the reference across another call.
    unsafe { &mut *core::ptr::addr_of_mut!(BRAIN_TX) }
}

/// The sealed brain-link message still owed to the control socket (RFC-0019),
/// as wire bytes after the RFC-0021 wrap, so a short send resumes mid-frame.
pub(crate) fn brain_tx_carry() -> &'static mut azos_behavior::brain_tx::TxCarry<BRAIN_TX_CARRY_MAX> {
    &mut brain_tx().carry
}

/// Offer the control carry's pending bytes to the socket; see `tx_drain`.
pub(crate) fn brain_tx_drain(fd: usize) -> usize {
    tx_drain(fd, brain_tx_carry(), send_sleeping)
}

/// Offer `carry`'s pending bytes to the socket through `send`; returns the
/// bytes taken. Marks the carry stalled once nothing has been taken for
/// `BRAIN_TX_STALL_TICKS`; the sending task then ends the session.
pub(crate) fn tx_drain(
    fd: usize,
    carry: &mut azos_behavior::brain_tx::TxCarry<BRAIN_TX_CARRY_MAX>,
    send: fn(usize, &[u8]) -> usize,
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

/// Push unsealed link bytes (an unkeyed or HMAC-only link), inside one
/// RFC-0021 multi-stream frame on STREAM_CONTROL when that framing is on.
/// Sealed bytes never come here: they go through `brain_tx_carry()`.
fn send_wire(fd: usize, inner: &[u8]) -> i32 {
    // Outermost: RFC-0021 multi-stream framing on STREAM_CONTROL when enabled,
    // so the brain demuxes control vs camera/lidar BEFORE decode. Composes
    // outside the AEAD layer.
    if azos_config::CFG_MULTI_STREAM.load(Ordering::Relaxed) {
        use azos_multi_stream as ms;
        // RFC-0021 scheduling policy is a COMPILE-TIME choice (Kconfig
        // MULTISTREAM_SCHED_PRIORITY → azos_limits const; the unused
        // branch is const-eliminated, zero hot-path overhead). Baseline =
        // FIFO (control + bulk share the link in send order). When PRIORITY
        // is selected, experiment I2 will interleave STREAM_CONTROL ahead of
        // bulk-stream chunks HERE. One-shot log surfaces the compiled policy.
        ms_policy_log_once();
        static mut MS_BUF: [u8; azos_multi_stream::HEADER_LEN + BRAIN_TX_WIRE_MAX] =
            [0u8; azos_multi_stream::HEADER_LEN + BRAIN_TX_WIRE_MAX];
        // SAFETY: only the behavior task sends on the brain socket.
        let ms_buf = unsafe { &mut *core::ptr::addr_of_mut!(MS_BUF) };
        match ms::wrap(ms::STREAM_CONTROL, inner, ms_buf) {
            Ok(ms_len) => send_sleeping(fd, &ms_buf[..ms_len]) as i32,
            Err(_) => 0,
        }
    } else {
        send_sleeping(fd, inner) as i32
    }
}

/// I2 experiment probe (qemu only): measure the control-stream head-of-line
/// hold-off behind a bulk STREAM_CAMERA frame, under the COMPILE-TIME policy
/// (`azos_limits::MULTISTREAM_SCHED_PRIORITY`). FIFO sends the whole bulk
/// before the control frame; PRIORITY chunks the bulk and lets the control
/// frame jump ahead after the first chunk. Emits one `[I2]` line. Run once.
#[cfg(feature = "qemu")]
pub(crate) fn i2_holdoff_probe(fd: usize) {
    use azos_drv_sys::wcet::read_cycles;
    use azos_multi_stream as ms;
    use azos_net::tcp::send_all_with_yield;
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
        let _ = send_all_with_yield(fd, &wire[..w], task_yield);
        off += n;
        if priority && !ctrl_done {
            // Control jumps ahead after the first bulk chunk.
            let _ = send_all_with_yield(fd, &ctrl_wire[..ctrl_len], task_yield);
            ctrl_holdoff = read_cycles().wrapping_sub(t0);
            ctrl_done = true;
        }
    }
    if !ctrl_done {
        // FIFO: control waits for the entire bulk frame.
        let _ = send_all_with_yield(fd, &ctrl_wire[..ctrl_len], task_yield);
        ctrl_holdoff = read_cycles().wrapping_sub(t0);
    }
    let bulk_total = read_cycles().wrapping_sub(t0);
    kprintln!(
        "[I2] mode={} bulk_bytes={} chunk={} ctrl_holdoff_cyc={} bulk_total_cyc={}",
        if priority { "priority" } else { "fifo" },
        BULK, CHUNK, ctrl_holdoff, bulk_total,
    );
}
