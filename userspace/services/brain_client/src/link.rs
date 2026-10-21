// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The brain link, client side (wave 9, owner decision P3; Noise since owner
//! decision D9).
//!
//! Every connection runs the same handshake and transport as the kernel's own
//! brain link
//! (`kernel/src/tasks/brain_link.rs::brain_handshake`,
//! `crates/core/crypto/src/secure_channel.rs`):
//!
//!   * this client is the TCP client and the Noise INITIATOR: it speaks
//!     first. `Noise_IK` toward the brain's static key pinned in the signed
//!     topology (`[peer.brain]`, read through the `linkkey` endpoint),
//!     `Noise_XX` with keys derived from the link key otherwise;
//!   * the ephemeral X25519 key is fresh bytes from the kernel entropy pool
//!     (the kernel-hosted `entropy` endpoint), drawn per connection; with no
//!     seeded pool the client does not run the link at all (`entropy_init` in
//!     `main.rs`);
//!   * session keys come from the handshake, so a frame from an earlier
//!     session fails the AEAD of the next one, and inside a session the
//!     transport's message counter refuses a replay: there is no second
//!     replay floor and no second MAC;
//!   * a message is one brain-protocol frame, in both directions;
//!   * rekey: the module's per-generation limits, plus a wall-clock trigger
//!     (`REKEY_INTERVAL_SECS`, or shorter from CONFIG.INI — see
//!     `rekey_interval_from_config` in `main.rs`); a rekey from the brain is
//!     followed on receive.
//!
//! There is no plaintext or MAC-only fallback and no runtime switch: a file on
//! the USB-exported FAT volume must not be an attacker-writable downgrade.

use azos_crypto::secure_channel as sc;
use azos_libsys as sys;

/// Largest message this client accepts from the brain.
/// Commands are a few dozen bytes; a larger frame is a violation here,
/// refused before any of it is read.
const RX_MSG_MAX: usize = 2048;
/// The receive side's body limit: a message and its tag.
const RX_BODY_MAX: usize = sc::max_body_for(RX_MSG_MAX);
/// Bytes the receive side carries between `recv` calls: one whole frame plus a
/// read's worth of the next.
const RX_CARRY_MAX: usize = sc::FRAME_HEAD + RX_BODY_MAX + 512;
/// Largest message this client seals: a sensor frame.
const TX_WIRE_MAX: usize = sc::sealed_len_max(crate::SENSOR_FRAME_SIZE);

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
    Record(sc::RecordError),
}

struct Session {
    link: Option<sc::Link>,
    carry: [u8; RX_CARRY_MAX],
    carry_len: usize,
    wire: [u8; TX_WIRE_MAX],
    /// Next wall-clock rekey, in `vdso_now_ns` nanoseconds (0: no clock).
    rekey_at_ns: u64,
    rekey_interval_ns: u64,
}

impl Session {
    const fn new() -> Self {
        Session {
            link: None,
            carry: [0; RX_CARRY_MAX],
            carry_len: 0,
            wire: [0; TX_WIRE_MAX],
            rekey_at_ns: 0,
            rekey_interval_ns: 0,
        }
    }
}

// .bss, not the 16 KiB user stack: ~5 KiB of buffers plus the link state.
static mut SESSION: Session = Session::new();
static mut SESSION_ID_CACHE: sc::SessionIdCache<SESSION_IDS> = sc::SessionIdCache::new();

fn session() -> &'static mut Session {
    // SAFETY: single-threaded process; no caller holds the reference across
    // another call that takes it.
    unsafe { &mut *core::ptr::addr_of_mut!(SESSION) }
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

/// Run the initiator handshake on a freshly connected socket. On `true` the
/// session is established and [`seal_frame`]/[`feed`] may be used.
///
/// `entropy_cap` is the entropy endpoint's handle; `psk` the brain-link key;
/// `pinned` the brain's static key from the signed topology (`None`:
/// `Noise_XX`). Every failure returns `false` and the caller closes the
/// socket: there is no REJECT frame, the connection just ends.
pub fn handshake(sock: u32, entropy_cap: u32, psk: &[u8; sc::PSK_BYTES],
                 pinned: Option<&[u8; 32]>, rekey_interval_ns: u64) -> bool {
    let s = session();
    s.link = None; // Drop wipes the previous session's keys.
    s.carry_len = 0;

    let mut eph = [0u8; 32];
    if let Err(outcome) = sys::dev::entropy_read(entropy_cap, &mut eph) {
        say_num(b"[brain_client] link: entropy read refused outcome=", outcome as i64);
        return false;
    }
    let ini = sc::Initiator::new(psk, pinned);
    let mut ini = match ini {
        Ok(i) => i,
        Err(_) => {
            wipe(&mut eph);
            say(b"[brain_client] link: cannot start the handshake");
            return false;
        }
    };

    let mut out = [0u8; sc::HANDSHAKE_OUT_MAX];
    let mut inb = [0u8; sc::FRAME_HEAD + sc::HANDSHAKE_MSG_MAX];
    let mut ok = false;
    let mut step = ini.step(None, &eph, &mut out);
    loop {
        let n = match step {
            Ok(n) => n,
            Err(_) => {
                say(b"[brain_client] link: handshake refused");
                break;
            }
        };
        if n > 0 && !send_all(sock, &out[..n]) {
            say(b"[brain_client] link: handshake message not sent");
            break;
        }
        if ini.is_done() {
            ok = true;
            break;
        }
        // The brain's frame: the length prefix, then the body.
        let total = if recv_exact(sock, &mut inb[..sc::FRAME_HEAD]) {
            sc::frame_len(&inb[..sc::FRAME_HEAD], sc::HANDSHAKE_MSG_MAX).ok()
        } else {
            None
        };
        let Some(total) = total else {
            say(b"[brain_client] link: no answer from the brain");
            break;
        };
        if !recv_exact(sock, &mut inb[sc::FRAME_HEAD..total]) {
            say(b"[brain_client] link: no answer from the brain");
            break;
        }
        step = ini.step(Some(&inb[..total]), &eph, &mut out);
    }
    wipe(&mut eph);
    if !ok {
        return false;
    }
    let pattern = ini.pattern_byte();
    let Ok(link) = ini.finish() else { return false };
    let sid = link.session_id();
    // SAFETY: single-threaded; see `session()`.
    if !unsafe { (*core::ptr::addr_of_mut!(SESSION_ID_CACHE)).insert_if_new(&sid) } {
        say(b"[brain_client] link: session id repeated - refused");
        return false;
    }
    s.link = Some(link);
    let now = sys::vdso_now_ns();
    s.rekey_interval_ns = rekey_interval_ns;
    s.rekey_at_ns = if now == 0 { 0 } else { now.saturating_add(rekey_interval_ns) };

    let mut line = crate::Line::new();
    line.push(b"[brain_client] link: Noise_");
    line.push(&[pattern]);
    line.push(b" session established sid=");
    for b in &sid[..4] {
        let hex = b"0123456789abcdef";
        line.push(&[hex[(b >> 4) as usize], hex[(b & 0xF) as usize]]);
    }
    line.push(b"\n");
    sys::print(line.bytes());
    true
}

/// Seal `frame` as one message and send it. `false` ends the session.
pub fn seal_frame(sock: u32, frame: &[u8]) -> bool {
    let s = session();
    let Session { link, wire, rekey_at_ns, rekey_interval_ns, .. } = s;
    let Some(l) = link.as_mut() else { return false };

    // Wall-clock rekey: the module has no clock; this is the caller's half, as
    // `BRAIN_LINK_REKEY_SECS` is on the kernel's link.
    if *rekey_at_ns != 0 {
        let now = sys::vdso_now_ns();
        if now >= *rekey_at_ns {
            l.request_rekey();
            *rekey_at_ns = now.saturating_add(*rekey_interval_ns);
        }
    }

    let gen = l.tx_generation();
    let w = match l.seal_message(frame, wire) {
        Ok(w) => w,
        Err(_) => return false,
    };
    if l.tx_generation() != gen {
        say_num(b"[brain_client] link: REKEY sent, tx generation ", l.tx_generation() as i64);
    }
    send_all(sock, &wire[..w])
}

/// Feed received wire bytes: open every whole frame in place and hand each
/// message (one brain-protocol frame) to `on_frame`. `Err` is a terminal
/// transport event: the caller ends the session ([`end`]) and closes.
pub fn feed(input: &[u8], mut on_frame: impl FnMut(&[u8])) -> Result<(), LinkEnd> {
    let s = session();
    let Session { link, carry, carry_len, .. } = s;
    let Some(l) = link.as_mut() else { return Err(LinkEnd::Closed) };
    let end = *carry_len + input.len();
    if end > carry.len() {
        return Err(LinkEnd::Record(sc::RecordError::BadHeader));
    }
    carry[*carry_len..end].copy_from_slice(input);
    *carry_len = end;

    let mut off = 0usize;
    let mut result = Ok(());
    loop {
        match l.open_frame(&mut carry[off..*carry_len], RX_BODY_MAX) {
            Ok(sc::Opened { kind: sc::RecordKind::Rekey, consumed }) => {
                off += consumed;
                say_num(b"[brain_client] link: peer REKEY, rx generation ", l.rx_generation() as i64);
            }
            Ok(sc::Opened { kind: sc::RecordKind::Data { len }, consumed }) => {
                let msg = &carry[off + sc::FRAME_HEAD..off + sc::FRAME_HEAD + len];
                off += consumed;
                on_frame(msg);
            }
            Err(sc::RecordError::Incomplete) => break,
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

/// Forget the session: keys wiped by `Link`'s `Drop`, buffers reset.
pub fn end() {
    let s = session();
    s.link = None;
    s.carry_len = 0;
}

/// Name a transport error for the console.
pub fn end_name(e: LinkEnd) -> &'static [u8] {
    match e {
        LinkEnd::Closed => b"closed",
        LinkEnd::Record(sc::RecordError::BadMac) => b"bad MAC",
        LinkEnd::Record(sc::RecordError::BadHeader) => b"bad frame length",
        LinkEnd::Record(sc::RecordError::RekeyOverdue) => b"rekey overdue",
        LinkEnd::Record(_) => b"frame refused",
    }
}
