// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The RFC-0019 encrypted brain link, client side (wave 9, owner decision P3).
//!
//! Before this, `brain_client` verified the HMAC envelope directly under the
//! pre-shared key and kept its replay floor only in RAM, per connection: a
//! frame recorded on one connection replayed on the next one, and across a
//! restart of the client. Now every connection runs the same handshake and
//! record layer as the kernel's own brain link
//! (`kernel/src/tasks/brain_link.rs::brain_responder_handshake`, `crates/net/encrypt-link`):
//!
//!   * the brain (TCP server) is the crypto INITIATOR and speaks first; this
//!     client is the RESPONDER — the same role inversion the crate's module
//!     doc describes for the kernel;
//!   * the ephemeral X25519 key and the record nonce seed are fresh bytes
//!     from the kernel entropy pool (`SYS_ENTROPY_READ_TYPED`), drawn per
//!     connection; with no seeded pool the client does not run the link at
//!     all (`entropy_init` in `main.rs`);
//!   * session keys derive from that exchange and the PSK proofs, so a
//!     record from an earlier session fails the MAC of the next one: the
//!     envelope's RAM replay floor is no longer the only defence;
//!   * the envelope still wraps every frame inside the records, in both
//!     directions, as on the kernel's link;
//!   * rekey: the crate's per-generation limits, plus a wall-clock trigger
//!     (`REKEY_INTERVAL_SECS`, or shorter from CONFIG.INI — see
//!     `rekey_interval_from_config` in `main.rs`); a REKEY from the brain is
//!     followed on receive.
//!
//! There is no plaintext or HMAC-only fallback, and nothing here reads
//! CONFIG.INI's `link_encrypt`: that file lives on the USB-exported FAT
//! volume, so a runtime switch would be an attacker-writable downgrade.

use azos_encrypt_link as el;
use azos_libsys as sys;

use crate::auth_envelope_core as env;

/// Bytes the receive side carries between `recv` calls: one full record of
/// the largest size plus a read's worth of the next.
const RX_CARRY_MAX: usize = el::ENC_MAX_PAYLOAD + el::ENC_OVERHEAD + 512;
/// Largest message (one envelope) this client reassembles. Commands are a
/// few dozen bytes; a larger authenticated message is a violation here.
const RX_MSG_MAX: usize = 2048;
/// Largest brain-protocol frame one envelope may carry to this client.
const RX_INNER_MAX: usize = 256;
/// Largest frame this client seals: a sensor frame inside its envelope.
const TX_ENV_MAX: usize = crate::SENSOR_FRAME_SIZE + env::ENVELOPE_OVERHEAD;
const TX_WIRE_MAX: usize = el::sealed_len_max(TX_ENV_MAX);

/// Polls of 10 ms the handshake waits for each peer message: 5 s, the
/// kernel's own handshake deadline.
const HS_POLLS: u32 = 500;
const HS_POLL_MS: u64 = 10;

/// Session ids seen by this process; a repeated one is refused, as the
/// kernel's `BRAIN_SESSION_ID_CACHE` does.
const SESSION_IDS: usize = 8;

/// Why a session ended; printed by the caller.
#[derive(Clone, Copy)]
pub enum LinkEnd {
    Closed,
    Record(el::RecordError),
}

struct Session {
    link: Option<el::EncryptLink>,
    nonce_seed: [u8; 32],
    nonce_ctr: u64,
    /// Envelope send nonce: starts at the connection's monotonic time and
    /// rises by one per frame, like `auth_envelope`'s kernel sender.
    tx_env_nonce: u64,
    /// Envelope replay floor for this session's received frames.
    rx_floor: u64,
    carry: [u8; RX_CARRY_MAX],
    carry_len: usize,
    msg: [u8; RX_MSG_MAX],
    msg_len: usize,
    record: [u8; el::ENC_MAX_PAYLOAD],
    wire: [u8; TX_WIRE_MAX],
    /// Next wall-clock rekey, in `vdso_now_ns` nanoseconds (0: no clock).
    rekey_at_ns: u64,
    rekey_interval_ns: u64,
}

impl Session {
    const fn new() -> Self {
        Session {
            link: None,
            nonce_seed: [0; 32],
            nonce_ctr: 0,
            tx_env_nonce: 0,
            rx_floor: 0,
            carry: [0; RX_CARRY_MAX],
            carry_len: 0,
            msg: [0; RX_MSG_MAX],
            msg_len: 0,
            record: [0; el::ENC_MAX_PAYLOAD],
            wire: [0; TX_WIRE_MAX],
            rekey_at_ns: 0,
            rekey_interval_ns: 0,
        }
    }
}

// .bss, not the 16 KiB user stack: ~7 KiB of buffers plus the link state.
static mut SESSION: Session = Session::new();
static mut SESSION_ID_CACHE: el::SessionIdCache<SESSION_IDS> = el::SessionIdCache::new();

fn session() -> &'static mut Session {
    // SAFETY: single-threaded process; no caller holds the reference across
    // another call that takes it.
    unsafe { &mut *core::ptr::addr_of_mut!(SESSION) }
}

/// 8 bytes of record nonce prefix: SHA-256 over the session's fresh seed and
/// a counter, so a prefix never repeats inside a session and the seed never
/// leaves the process.
fn next_nonce(seed: &[u8; 32], ctr: &mut u64) -> [u8; 8] {
    let mut h = azos_crypto::sha256::Sha256::new();
    h.update(b"AZOS-U-NONCE-V1");
    h.update(seed);
    h.update(&ctr.to_le_bytes());
    *ctr = ctr.wrapping_add(1);
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// Wipe `buf` in a way the optimiser may not drop.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid `&mut u8`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Receive exactly `buf.len()` bytes within `HS_POLLS` polls.
fn recv_exact(sock: u32, buf: &mut [u8]) -> bool {
    let mut got = 0usize;
    let mut polls = 0u32;
    while got < buf.len() {
        let n = sys::recv_typed(sock, &mut buf[got..]);
        if n < 0 {
            return false;
        }
        if n == 0 {
            polls += 1;
            if polls >= HS_POLLS {
                return false;
            }
            sys::sleep(HS_POLL_MS);
            continue;
        }
        got += n as usize;
    }
    true
}

/// Send all of `buf`, waiting out a full socket for at most `HS_POLLS` polls.
fn send_all(sock: u32, buf: &[u8]) -> bool {
    let mut off = 0usize;
    let mut polls = 0u32;
    while off < buf.len() {
        let n = sys::send_typed(sock, &buf[off..]);
        if n < 0 {
            return false;
        }
        if n == 0 {
            polls += 1;
            if polls >= HS_POLLS {
                return false;
            }
            sys::sleep(HS_POLL_MS);
            continue;
        }
        off += n as usize;
    }
    true
}

fn say(msg: &[u8]) {
    sys::println(msg);
}

fn say_num(prefix: &[u8], v: i64) {
    let mut line = crate::Line::new();
    line.push(prefix);
    line.push_i64(v);
    line.push(b"\n");
    sys::print(line.bytes());
}

/// Run the responder handshake on a freshly connected socket. On `true` the
/// session is established and [`seal_frame`]/[`feed`] may be used.
///
/// `entropy_cap` is the `Cap<Entropy>` handle; `psk` the brain-link key.
/// Every refusal on this side sends the RFC-0019 REJECT frame first, one
/// frame whatever the cause, as the kernel does.
pub fn handshake(sock: u32, entropy_cap: u32, psk: &[u8; env::KEY_BYTES],
                 rekey_interval_ns: u64) -> bool {
    let s = session();
    s.link = None; // Drop wipes the previous session's keys.
    s.carry_len = 0;
    s.msg_len = 0;
    s.rx_floor = 0;

    let mut eph = [0u8; 32];
    let rc = sys::entropy_read_typed(entropy_cap, &mut eph);
    if rc != 32 {
        say_num(b"[brain_client] link: entropy read refused rc=", rc as i64);
        return false;
    }
    let rc = sys::entropy_read_typed(entropy_cap, &mut s.nonce_seed);
    if rc != 32 {
        wipe(&mut eph);
        say_num(b"[brain_client] link: entropy read refused rc=", rc as i64);
        return false;
    }
    s.nonce_ctr = 0;
    let mut link = el::EncryptLink::new(*psk, eph);
    wipe(&mut eph);

    let refuse = |why: &[u8]| {
        let mut line = crate::Line::new();
        line.push(b"[brain_client] link: handshake refused (");
        line.push(why);
        line.push(b") - sending REJECT\n");
        sys::print(line.bytes());
        let _ = send_all(sock, &el::REJECT_FRAME);
    };

    // 1. brain -> client: [0x02][HELLO][brain_e_pub]
    let mut hello = [0u8; el::HELLO_INIT_BYTES];
    if !recv_exact(sock, &mut hello) {
        say(b"[brain_client] link: no HELLO from the brain");
        return false;
    }
    // 2. client -> brain: [0x02][HELLO][client_e_pub][proof]
    let mut reply = [0u8; el::HELLO_REPLY_BYTES];
    if link.handle_initiator_hello(&hello, &mut reply).is_err() {
        refuse(b"HELLO");
        return false;
    }
    let fresh = match link.session_id() {
        // SAFETY: single-threaded; see `session()`.
        Some(sid) => unsafe { (*core::ptr::addr_of_mut!(SESSION_ID_CACHE)).insert_if_new(&sid) },
        None => false,
    };
    if !fresh {
        refuse(b"session id repeated");
        return false;
    }
    if !send_all(sock, &reply) {
        say(b"[brain_client] link: handshake reply not sent");
        return false;
    }
    // 3. brain -> client: [0x02][CONFIRM][proof], or [0x02][REJECT]
    let mut confirm = [0u8; el::CONFIRM_BYTES];
    if !recv_exact(sock, &mut confirm[..el::REJECT_BYTES]) {
        say(b"[brain_client] link: no CONFIRM from the brain");
        return false;
    }
    let len = if confirm[..el::REJECT_BYTES] == el::REJECT_FRAME {
        el::REJECT_BYTES
    } else if recv_exact(sock, &mut confirm[el::REJECT_BYTES..]) {
        el::CONFIRM_BYTES
    } else {
        say(b"[brain_client] link: no CONFIRM from the brain");
        return false;
    };
    match link.handle_initiator_confirm(&confirm[..len]) {
        Ok(()) => {}
        Err(el::HandshakeError::PeerRejected) => {
            say(b"[brain_client] link: the brain sent REJECT");
            return false;
        }
        Err(_) => {
            refuse(b"CONFIRM");
            return false;
        }
    }

    let sid = link.session_id().unwrap_or([0; el::SESSION_ID_BYTES]);
    s.link = Some(link);
    let now = sys::vdso_now_ns();
    s.tx_env_nonce = if now == 0 { 1 } else { now };
    s.rekey_interval_ns = rekey_interval_ns;
    s.rekey_at_ns = if now == 0 { 0 } else { now.saturating_add(rekey_interval_ns) };

    let mut line = crate::Line::new();
    line.push(b"[brain_client] link: RFC-0019 session established sid=");
    for b in &sid[..4] {
        let hex = b"0123456789abcdef";
        line.push(&[hex[(b >> 4) as usize], hex[(b & 0xF) as usize]]);
    }
    line.push(b"\n");
    sys::print(line.bytes());
    true
}

/// Envelope-wrap `frame`, seal it as one message, send it. `false` ends the
/// session.
pub fn seal_frame(sock: u32, psk: &[u8; env::KEY_BYTES], frame: &[u8]) -> bool {
    let s = session();
    let Session { link, nonce_seed, nonce_ctr, tx_env_nonce, wire,
                  rekey_at_ns, rekey_interval_ns, .. } = s;
    let Some(l) = link.as_mut() else { return false };

    // Wall-clock rekey (RFC-0019): the crate has no clock; this is the
    // caller's half, as `BRAIN_LINK_REKEY_SECS` is on the kernel's link.
    if *rekey_at_ns != 0 {
        let now = sys::vdso_now_ns();
        if now >= *rekey_at_ns {
            l.request_rekey();
            *rekey_at_ns = now.saturating_add(*rekey_interval_ns);
        }
    }

    let mut envb = [0u8; TX_ENV_MAX];
    let n = env::wrap(psk, env::DIR_TX, *tx_env_nonce, frame, &mut envb);
    if n == 0 {
        return false;
    }
    *tx_env_nonce = tx_env_nonce.wrapping_add(1);
    let gen = l.tx_generation();
    let w = match l.seal_message(&envb[..n], || next_nonce(nonce_seed, nonce_ctr), wire) {
        Ok(w) => w,
        Err(_) => return false,
    };
    if l.tx_generation() != gen {
        say_num(b"[brain_client] link: REKEY sent, tx generation ", l.tx_generation() as i64);
    }
    send_all(sock, &wire[..w])
}

/// Feed received wire bytes: open every whole record, reassemble messages,
/// verify each message's envelope, and hand each inner frame to `on_frame`.
/// `Err` is a terminal record-layer event: the caller calls [`reject`] and
/// closes.
pub fn feed(psk: &[u8; env::KEY_BYTES], input: &[u8],
            mut on_frame: impl FnMut(&[u8])) -> Result<(), LinkEnd> {
    let s = session();
    let Session { link, carry, carry_len, msg, msg_len, record, rx_floor, .. } = s;
    let Some(l) = link.as_mut() else { return Err(LinkEnd::Closed) };
    let end = *carry_len + input.len();
    if end > carry.len() {
        return Err(LinkEnd::Record(el::RecordError::BufferTooSmall));
    }
    carry[*carry_len..end].copy_from_slice(input);
    *carry_len = end;

    let mut off = 0usize;
    let mut result = Ok(());
    loop {
        match l.open_record(&carry[off..*carry_len], record) {
            Ok(el::Opened { kind: el::RecordKind::Rekey, consumed }) => {
                off += consumed;
                say_num(b"[brain_client] link: peer REKEY, rx generation ", l.rx_generation() as i64);
            }
            Ok(el::Opened { kind: el::RecordKind::Data { len, more }, consumed }) => {
                off += consumed;
                let Some(dst) = msg.get_mut(*msg_len..*msg_len + len) else {
                    result = Err(LinkEnd::Record(el::RecordError::MessageTooLarge));
                    break;
                };
                dst.copy_from_slice(&record[..len]);
                *msg_len += len;
                if !more {
                    let mut inner = [0u8; RX_INNER_MAX];
                    match env::verify_and_unwrap(psk, env::DIR_RX, *rx_floor,
                                                 &msg[..*msg_len], &mut inner) {
                        Some((nonce, n)) => {
                            *rx_floor = nonce;
                            on_frame(&inner[..n]);
                        }
                        None => say(b"[brain_client] REFUSED unwrapped frame"),
                    }
                    *msg_len = 0;
                }
            }
            Err(el::RecordError::Incomplete) => break,
            Err(e) => {
                result = Err(LinkEnd::Record(e));
                break;
            }
        }
    }
    carry.copy_within(off..*carry_len, 0);
    *carry_len -= off;
    result
}

/// After a terminal record-layer event: one authenticated REJECT record if
/// the session can still seal one, then drop the session (its `Drop` wipes
/// the keys). The caller closes the socket.
pub fn reject(sock: u32) {
    let s = session();
    let Session { link, nonce_seed, nonce_ctr, .. } = s;
    if let Some(l) = link.as_mut() {
        let nr = next_nonce(nonce_seed, nonce_ctr);
        let mut rec = [0u8; el::ENC_OVERHEAD];
        let n = l.seal_reject(&nr, &mut rec);
        if n != 0 {
            let _ = send_all(sock, &rec[..n]);
        }
    }
    end();
}

/// Forget the session: keys wiped by `EncryptLink`'s `Drop`, buffers reset.
pub fn end() {
    let s = session();
    s.link = None;
    s.carry_len = 0;
    s.msg_len = 0;
    wipe(&mut s.nonce_seed);
}

/// Name a record-layer error for the console.
pub fn end_name(e: LinkEnd) -> &'static [u8] {
    match e {
        LinkEnd::Closed => b"closed",
        LinkEnd::Record(el::RecordError::BadMac) => b"bad MAC",
        LinkEnd::Record(el::RecordError::BadCounter) => b"bad counter",
        LinkEnd::Record(el::RecordError::MessageTooLarge) => b"message too large",
        LinkEnd::Record(el::RecordError::BufferTooSmall) => b"buffer too small",
        LinkEnd::Record(el::RecordError::RekeyOverdue) => b"rekey overdue",
        LinkEnd::Record(el::RecordError::PeerRejected) => b"the brain sent a REJECT record",
        LinkEnd::Record(_) => b"record refused",
    }
}
