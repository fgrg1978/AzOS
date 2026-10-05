// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! HMAC-SHA-256 authenticated envelope for the brain↔kernel TCP stream.
//!
//! Pairs with `AzOSRobotBrain/secure_channel.py` byte-for-byte. Wrapping
//! a brain protocol packet adds 26 bytes of overhead (8B nonce + 16B
//! truncated HMAC + 2B inner length).
//!
//! ## Threat model
//!
//! Without this layer the brain↔kernel TCP stream is plaintext on a
//! presumed-trusted LAN. Any peer on the segment can:
//! - Forge an ESTOP packet (`PKT_ESTOP=0x88`) and stop every robot.
//! - Replay an old "FORWARD 100" actuator command indefinitely.
//! - Inject malformed packets to crash the kernel parser.
//!
//! With this layer the attacker would need the pre-shared key to
//! produce a valid HMAC. The replay-protection (monotonically
//! increasing nonce) ensures even captured-and-replayed authentic
//! packets are rejected.
//!
//! ## Wire format
//!
//! ```text
//! Offset  Size  Field
//! 0x00    8     Nonce (monotonic u64, big-endian)
//! 0x08    16    HMAC-SHA-256 over (dir || nonce || len || inner) trunc 16
//! 0x18    2     Inner length (LE u16)
//! 0x1A    N     Inner brain protocol packet
//! ```
//!
//! `dir` is a 3-byte ASCII direction label that is **prepended to the MAC
//! input but never transmitted** — the receiver knows which direction it is
//! reading from and supplies the label itself. The envelope layout is
//! therefore byte-identical to before; only the MAC value changes.
//!
//! ## Direction labels
//!
//! ```text
//!   C2S  =  brain  → kernel   (the direction the kernel UNWRAPs)
//!   S2C  =  kernel → brain    (the direction the kernel WRAPs)
//! ```
//!
//! `C`/`S` follow the RFC-0019 *crypto* roles used by
//! `azos_crypto::secure_channel` — brain = initiator = "client",
//! kernel = responder = "server" — which are the inverse of the TCP roles
//! (the kernel is the TCP client; it dials the brain). Both layers use the
//! same convention so there is one thing to remember, not two.
//!
//! Without this label both peers computed the MAC over identical input with
//! the same key, so a frame the kernel *sent* was a valid frame *inbound*
//! at the kernel. The MAC proved "someone holding the PSK produced these
//! bytes", not "the brain produced these bytes"; anyone able to echo a TCP
//! segment could reflect the kernel's own traffic back at it and have it
//! authenticate. It was not exploitable only because kernel→brain packet
//! types (`0x01`/`0x02`/`0x03`) and brain→kernel types
//! (`0x80`/`0x83`/`0x88`) are disjoint, so the dispatcher ignored the
//! reflected frame *after* believing it. That is a naming convention
//! holding a cryptographic flaw closed.
//!
//! ## Key management
//!
//! The 32-byte symmetric key is loaded from `/fat/LINK.KEY`
//! (raw bytes). When the file is missing, the channel falls back to
//! plaintext mode and logs a warning — explicit opt-in.
//!
//! **Unless `link-encrypt-enforced` is compiled in** (K-C5), in which case
//! there is no fallback and no HMAC-only mode either: see
//! [`link_policy_denial`] and the `LINK_ENCRYPT_ENFORCED` const below.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use azos_crypto::ct::{ct_eq, secure_zero};
use azos_crypto::sha256::{Sha256, Digest};
use wcet_macro::wcet;

// ── Constants ───────────────────────────────────────────────────────────

pub const KEY_BYTES:         usize = 32;
pub const NONCE_BYTES:       usize = 8;
pub const HMAC_BYTES:        usize = 16;
pub const LEN_BYTES:         usize = 2;
pub const ENVELOPE_OVERHEAD: usize = NONCE_BYTES + HMAC_BYTES + LEN_BYTES;
pub const MAX_INNER_BYTES:   usize = 8 * 1024;

const SHA256_BLOCK_SIZE: usize = 64;
const SHA256_DIGEST_LEN: usize = 32;
const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5C;

/// Direction label bound into the MAC of frames the kernel RECEIVES
/// (brain → kernel). Not transmitted; see the wire-format note above.
pub const DIR_RX: &[u8; 3] = b"C2S";
/// Direction label bound into the MAC of frames the kernel SENDS
/// (kernel → brain). Not transmitted.
pub const DIR_TX: &[u8; 3] = b"S2C";

// ── HMAC-SHA-256 over arbitrary-length key ──────────────────────────────
//
// Performance optimisation: the (K ⊕ ipad) and (K ⊕ opad) blocks depend
// only on the key, not on the data. We precompute them once at init()
// time and reuse on every wrap/unwrap. With a 32-byte key padded to 64
// bytes, this saves 128 byte XORs per HMAC call (256 cycles on RV64),
// which adds up: at 100 packets/sec and 2 HMACs/packet (wrap+verify),
// the kernel was burning ~50K cycles/sec just rebuilding ipad/opad.

/// Pre-computed (K ⊕ ipad) — populated by `init()`.
static mut IKEY_BLOCK: [u8; SHA256_BLOCK_SIZE] = [0u8; SHA256_BLOCK_SIZE];
/// Pre-computed (K ⊕ opad) — populated by `init()`.
static mut OKEY_BLOCK: [u8; SHA256_BLOCK_SIZE] = [0u8; SHA256_BLOCK_SIZE];

/// HMAC-SHA-256 using the pre-computed ikey/okey blocks. Caller must
/// only use this AFTER `init()` has been called (gated by KEY_LOADED).
fn hmac_sha256_precomputed(data_parts: &[&[u8]]) -> Digest {
    // SAFETY: IKEY_BLOCK/OKEY_BLOCK are written once at init() before
    // any wrap/unwrap can be issued; from then on read-only.
    let ikey = unsafe { &*core::ptr::addr_of!(IKEY_BLOCK) };
    let okey = unsafe { &*core::ptr::addr_of!(OKEY_BLOCK) };

    // Inner: SHA-256(ikey || data_parts...)
    let mut h = Sha256::new();
    h.update(ikey);
    for part in data_parts { h.update(part); }
    let inner = h.finalize();

    // Outer: SHA-256(okey || inner)
    let mut h = Sha256::new();
    h.update(okey);
    h.update(&inner);
    h.finalize()
}

// The `ct_eq` that used to live here was one of only two copies in the tree
// that carried the `black_box` barrier. Rather than keep five divergent
// copies, it moved to `azos_crypto::ct::ct_eq` (imported above) with
// the barrier retained, and the three unhardened copies now call it too.

// ── State (key + replay window) ─────────────────────────────────────────

/// Pre-shared link key. All zeros = unconfigured (channel plaintext).
static mut LINK_KEY: [u8; KEY_BYTES] = [0u8; KEY_BYTES];

/// Highest accepted nonce (replay-protection high-water mark).
static HIGHEST_RX_NONCE: AtomicU64 = AtomicU64::new(0);

/// Send-side counter. Initialised by `init` from the entropy pool when it is
/// seeded, from the CLINT clock otherwise, to avoid collisions across reboots
/// without persisting the counter to disk.
static SEND_NONCE: AtomicU64 = AtomicU64::new(0);

/// True once `init()` has been called with a valid 32-byte key.
static mut KEY_LOADED: bool = false;

// ── K-C5: encrypted mode is mandatory when the policy is compiled in ────
//
// ## Why the gate is HERE, per packet, and not only at establishment
//
// `wrap` and `unwrap_consuming` are the choke point for the brain-protocol
// dispatch path in both directions: `send_framed` calls `wrap` on every TX
// frame, and the RX drain loop in `kernel/src/tasks/behavior.rs` calls
// `unwrap_consuming` on every inbound one, encrypted or not.
//
// A gate at handshake time only proves that *a* handshake was attempted at
// connect; it says nothing about the frame in front of you. The kernel's
// brain loop keeps the session as an `Option<EncryptLink>` and both
// `send_framed` and the RX loop `match` on it — every `None` arm is a path
// that skips the AEAD layer entirely. Those arms are reachable today whenever
// `CFG_LINK_ENCRYPT` is 0 (which is the DEFAULT), and they would stay
// reachable after any future edit that forgets the establishment check.
// Putting the gate on the frame makes "is this byte allowed on this link?" a
// question asked about the byte, not about the connection it arrived on.
//
// ## Paths in kernel/src/tasks/behavior.rs that do NOT pass through here
//
// Audited 2026-08-22, re-audited and CLOSED at their call sites 2026-08-23.
// They are outside this crate, so their gates live in the kernel; each calls
// `link_policy_denial()` (no-op when the policy is off) — if a new brain-link
// sender or receiver appears, it must be added here and gated the same way:
//
//   * the UART bridge (PKT_SENSOR/PKT_CAMERA out, PKT_ACTUATOR in): a full
//     brain-protocol plane with no envelope in either direction — gated as a
//     whole by `bridge_policy_permits()` in kernel/src/tasks/behavior.rs, with a one-shot refusal
//     announcement mirroring `announce_denial`.
//   * `i2_holdoff_probe` (`#[cfg(feature = "qemu")]`, synthetic bulk to the
//     brain socket): early-returns under the policy.
//
// So the honest claim for this gate is: **no envelope frame is produced or
// accepted while no AEAD session exists.** It is not per-frame provenance —
// the registry is session-scoped, not a witness threaded through each call —
// and it does not cover a caller that never calls `wrap` at all. What it does
// cover is exactly what K-C5 is about: the replayable HMAC-only and plaintext
// modes of the brain-protocol path.
//
// ## What it costs, in operations
//
//   enforced:  1 acquire load + compare + branch (the AEAD-session check)
//              + 1 volatile bool read (`is_authenticated`, already there)
//   off:       0 — `LINK_ENCRYPT_ENFORCED` is a `const`, so the arms below
//              are const-folded out and the binary is byte-identical to
//              before this change.
//
// Against the ~3 SHA-256 compressions (≈192 rounds, ≈1500 RV64 ops for a
// minimum-size frame) that `hmac_sha256_precomputed` spends immediately
// after, and the AES-128-CTR + 32-byte HMAC the AEAD layer spends around it.
// Under 0.2%. There was no throughput argument for the cheaper placement.

/// Compile-time link policy — `true` in a build made with
/// `azos_encrypt_link/link-encrypt-enforced`.
///
/// A `const`, not a function call: every `if !LINK_ENCRYPT_ENFORCED` arm
/// below is resolved by const-propagation, so in an enforced build the
/// plaintext identity-passthrough path is not merely unreachable — there is
/// no branch left in the binary that reaches it.
///
/// The policy itself depends on **no file, no config key and no disk
/// state**, deliberately. The secure-boot scenario in this tree once passed
/// green while running no Ed25519 at all, because the public key was
/// `.gitignore`d, `build.rs` fell back to `[0u8; 32]`, and verification
/// short-circuited on the zero key — a gate whose *enabling condition* came
/// off disk failed open and looked fine. `cfg!` cannot do that: the feature
/// is either in the build or it is not, and
/// `tests/host/encrypt-link-tests` asserts the const's value in **both** feature
/// states so a renamed or mis-forwarded feature fails the suite instead of
/// silently disarming the gate.
const LINK_ENCRYPT_ENFORCED: bool = azos_encrypt_link::link_encrypt_enforced();

/// Is `link-encrypt-enforced` compiled into this build?
///
/// Mirrors `azos_ota::secure_boot_enforced_at_compile_time()` so the
/// boot gate and the shell report the policy the same way for all three
/// enforcement features.
pub const fn link_encrypt_enforced_at_compile_time() -> bool {
    LINK_ENCRYPT_ENFORCED
}

/// Why a frame is refused by the link policy.
///
/// These are the two things a field technician has to be able to tell apart,
/// and they have different fixes — which is the whole reason this is an enum
/// with a message rather than a bare `false`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkDenial {
    /// No key material on the robot at all. Provision `/fat/LINK.KEY`.
    NoKey,
    /// Key present, but this frame is not inside an encrypted session:
    /// `link_encrypt=0` in `/fat/CONFIG.INI`, or the RFC-0019 handshake
    /// failed, or the brain dropped the connection. None of those is a
    /// cable fault.
    NoAeadSession,
}

impl LinkDenial {
    pub const fn as_str(self) -> &'static str {
        match self {
            LinkDenial::NoKey => "no /fat/LINK.KEY on this robot",
            LinkDenial::NoAeadSession => "no established RFC-0019 AEAD session",
        }
    }
    const fn slot(self) -> u32 {
        match self { LinkDenial::NoKey => 0, LinkDenial::NoAeadSession => 1 }
    }
}

/// Why the current frame is refused, or `None` if the policy permits it.
///
/// Always `None` when the policy is not compiled in, so this const-folds to
/// nothing in a default build.
pub fn link_policy_denial() -> Option<LinkDenial> {
    if !LINK_ENCRYPT_ENFORCED {
        return None;
    }
    if !is_authenticated() {
        return Some(LinkDenial::NoKey);
    }
    // Deliberately `envelope_frame_permitted()` and not a second reading of
    // `aead_session_established()`: this is the predicate the host-side suite
    // in `tests/host/encrypt-link-tests` exercises, and a reimplementation here
    // would mean the tests assert on a parallel copy of the gate rather than
    // on the one the packet path actually consults.
    if !azos_encrypt_link::envelope_frame_permitted() {
        return Some(LinkDenial::NoAeadSession);
    }
    None
}

/// One announcement bit per (direction, reason) pair — see [`announce_denial`].
static DENIAL_ANNOUNCED: AtomicU32 = AtomicU32::new(0);

/// Shout the first time each distinct refusal happens.
///
/// Without this the enforced build is **silent**: `wrap` returns 0, nothing
/// reaches the socket, `unwrap` returns `None`, nothing is dispatched — and
/// on the console that is indistinguishable from an unplugged cable or a
/// dead brain. The symptom a technician actually sees in the field has to
/// name the policy and the reason, or "robot won't talk to the brain" sends
/// them looking at the wrong layer for an afternoon.
///
/// One-shot per (direction, reason), not per frame: at 100 pkt/s an
/// unconditional log would flood the UART and, on a build with
/// `--features wcet`, blow the 100 µs budget on `wrap`/`unwrap` every tick.
/// A recurring symptom that changes reason (key provisioned but handshake
/// still failing) still produces a new line.
#[cold]
#[inline(never)]
fn announce_denial(tx: bool, why: LinkDenial) {
    // Bit index = direction × 2 + reason. Computed from the enum, never from
    // string bytes: indexing a `&str` here would be a reachable panic on the
    // packet path, and `panic = "abort"` means a reachable panic resets the
    // board — a physical-safety event on a robot, from a diagnostic.
    let slot = 1u32 << ((tx as u32) * 2 + why.slot());
    if DENIAL_ANNOUNCED.fetch_or(slot, Ordering::Relaxed) & slot != 0 {
        return;
    }
    azos_drv_sys::kerr!(
        "[SECCHAN] FATAL: brain link {} refused — {} — link-encrypt-enforced \
         is compiled in, so no plaintext and no HMAC-only fallback exists. \
         The link is DOWN BY POLICY, not by cabling.",
        if tx { "transmit" } else { "receive" }, why.as_str());
}

/// Reset the one-shot announcement bits.
///
/// Nothing in this crate calls it; it exists for the kernel, which has two
/// reasons to:
///
/// 1. **After the boot bench sweep.** `azos_bench::auth` calls `wrap`
///    unkeyed, and under `qemu,link-encrypt-enforced` `behavior_task` runs
///    `run_all` post-boot — so the benchmark burns the `(tx, NoKey)` slot and
///    the first *real* TX denial then prints nothing. That is precisely the
///    silence [`announce_denial`] exists to prevent, caused by a synthetic
///    microbench. (The bench's own numbers are meaningless under the policy
///    too: it would be timing the rejection path.)
/// 2. **On each successful handshake**, so a denial hours later is reported
///    again rather than swallowed by a bit set at boot.
pub fn reset_denial_announcements() {
    DENIAL_ANNOUNCED.store(0, Ordering::Relaxed);
}

// ── Public API ──────────────────────────────────────────────────────────

/// Install the link key. Returns true if successful, false if `key.len() != 32`.
///
/// SAFETY: callers must ensure no in-flight wrap/unwrap is racing with
/// this call (typically only invoked at boot).
pub unsafe fn init(key: &[u8]) -> bool {
    if key.len() != KEY_BYTES { return false; }
    let dst = &mut *core::ptr::addr_of_mut!(LINK_KEY);
    dst.copy_from_slice(key);

    // Pre-compute (K ⊕ ipad) and (K ⊕ opad) once — see optimisation note
    // above hmac_sha256_precomputed. Saves ~256 cycles per HMAC call.
    let mut k_pad = [0u8; SHA256_BLOCK_SIZE];
    k_pad[..KEY_BYTES].copy_from_slice(key);
    let ikey = &mut *core::ptr::addr_of_mut!(IKEY_BLOCK);
    let okey = &mut *core::ptr::addr_of_mut!(OKEY_BLOCK);
    for i in 0..SHA256_BLOCK_SIZE {
        ikey[i] = k_pad[i] ^ HMAC_IPAD;
        okey[i] = k_pad[i] ^ HMAC_OPAD;
    }
    // Wipe the local zero-padded copy of the PSK. The `LINK_KEY`,
    // `IKEY_BLOCK` and `OKEY_BLOCK` statics necessarily persist for the
    // life of the kernel (that is the whole point of the precomputation),
    // but this stack copy has no reason to outlive the loop above.
    //
    // KNOWN, NOT FIXED HERE: IKEY_BLOCK/OKEY_BLOCK are `K ^ 0x36…` and
    // `K ^ 0x5C…` — trivially reversible — so the PSK effectively sits in
    // three permanent .bss copies rather than one. Removing them means
    // giving up the precomputation (~256 cycles/HMAC, ~50K cycles/s at
    // 100 pkt/s) or storing SHA-256 midstates instead, which is a
    // performance/structure decision for the owner, not a drive-by change.
    secure_zero(k_pad.as_mut_slice());

    KEY_LOADED = true;
    // Start the send nonce where a reboot is unlikely to reuse values: from
    // the entropy pool when it is seeded, from the clock otherwise. The pool
    // value is kept below 2^62 so the counter cannot wrap within a boot.
    // `init` runs at boot before the first task exists, so the pool is reached
    // without the critical section `encrypt_link::pool_fill` takes.
    let mut pool = [0u8; 8];
    let start = if azos_crypto::entropy::fill(&mut pool) {
        u64::from_le_bytes(pool) >> 2
    } else {
        azos_drv_sys::timebase::now()
    };
    SEND_NONCE.store(start, Ordering::Release);
    HIGHEST_RX_NONCE.store(0, Ordering::Release);
    true
}

/// Zero the link key material and mark the channel unkeyed.
///
/// Added 2026-09-26 (security finding #29 — partial): before this function
/// existed there was NO way to zero `LINK_KEY`/`IKEY_BLOCK`/`OKEY_BLOCK` at
/// all — they are `static mut`, so nothing ever `Drop`s them, and only the
/// local stack-scratch copy inside `init()` was ever wiped. Call this on an
/// intentional link teardown or before re-keying (no call site wired yet —
/// this lands the primitive, wiring a caller is a follow-up).
///
/// Does NOT close the structural issue `init()`'s own comment names:
/// `IKEY_BLOCK`/`OKEY_BLOCK` are `K ^ 0x36…`/`K ^ 0x5C…` — trivially
/// reversible from either one alone — so while this function is live the
/// PSK still sits in three derivable copies; this only shortens the window
/// after a caller decides the key should no longer be resident, the same
/// way `secure_zero`'s own doc describes shrinking a window rather than
/// defending against an attacker who reads RAM while the key is still live.
/// Removing the reversibility needs SHA-256 midstate storage instead of the
/// precomputed pad blocks (~256 cycles/HMAC saved today) — an explicit
/// owner call per the performance/structure tradeoff `init()` already
/// documents, not something this change decides unilaterally.
///
/// SAFETY: same requirement as `init` — no in-flight wrap/unwrap may be
/// racing this call.
pub unsafe fn deinit() {
    let key = &mut *core::ptr::addr_of_mut!(LINK_KEY);
    secure_zero(key.as_mut_slice());
    let ikey = &mut *core::ptr::addr_of_mut!(IKEY_BLOCK);
    secure_zero(ikey.as_mut_slice());
    let okey = &mut *core::ptr::addr_of_mut!(OKEY_BLOCK);
    secure_zero(okey.as_mut_slice());
    KEY_LOADED = false;
}

/// Copy of the loaded link key, or `None` if unkeyed.
///
/// The same 32-byte secret doubles as the RFC-0019 handshake PSK (one
/// provisioned key — see RFC-0019 §"Opt-in flags"), so the kernel's
/// encrypt-link path reads it from here rather than re-opening
/// `/fat/LINK.KEY`. Returns a copy (not a reference) so callers can't
/// alias the static; the copy lives only long enough to seed an
/// `EncryptLink`.
pub fn link_key_copy() -> Option<[u8; KEY_BYTES]> {
    if !is_authenticated() {
        return None;
    }
    // SAFETY: LINK_KEY is written once by init() at boot before any task
    // that could call this is spawned; read-only thereafter.
    let k = unsafe { &*core::ptr::addr_of!(LINK_KEY) };
    Some(*k)
}

/// True if the channel has been keyed (otherwise wrap/unwrap fall back
/// to identity for backwards compatibility).
pub fn is_authenticated() -> bool {
    // SAFETY: KEY_LOADED is set only by init() at boot; all subsequent
    // reads are racy-but-safe (a slightly-stale view is correctness-equiv).
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(KEY_LOADED)) }
}

/// Wrap an inner brain protocol packet with the HMAC envelope.
///
/// Writes nonce + hmac + len + inner into `out`, returning the number of
/// bytes written. Returns 0 if `out` is too small or `inner` exceeds the
/// max inner-packet size. If the channel has no key configured,
/// returns the inner unchanged (legacy plaintext mode).
#[wcet(100_us)]
pub fn wrap(inner: &[u8], out: &mut [u8]) -> usize {
    // K-C5 gate, TX half. Refusing here rather than at the socket means a
    // caller cannot construct wire bytes it is not allowed to send: there is
    // no "produce the envelope now, decide whether to encrypt later" split
    // for a future edit to get wrong.
    if LINK_ENCRYPT_ENFORCED {
        if let Some(why) = link_policy_denial() {
            announce_denial(true, why);
            return 0;
        }
    }
    // Legacy plaintext identity-passthrough. `LINK_ENCRYPT_ENFORCED` is a
    // `const`, so with the policy compiled in this whole arm — including the
    // copy that would put an unauthenticated brain packet on the wire — is
    // const-folded away and does not exist in the binary.
    if !LINK_ENCRYPT_ENFORCED && !is_authenticated() {
        if out.len() < inner.len() { return 0; }
        out[..inner.len()].copy_from_slice(inner);
        return inner.len();
    }
    if inner.len() > MAX_INNER_BYTES { return 0; }
    let total = ENVELOPE_OVERHEAD + inner.len();
    if out.len() < total { return 0; }

    let nonce = SEND_NONCE.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let nonce_b = nonce.to_be_bytes();
    let len_b   = (inner.len() as u16).to_le_bytes();

    // Direction-bound MAC: the label is hashed but NOT sent. The brain
    // verifies with the same label because it knows it is reading the
    // kernel→brain direction. A frame we emit therefore cannot be reflected
    // back at us and pass `unwrap`, which binds DIR_RX instead.
    let mac = hmac_sha256_precomputed(&[DIR_TX, &nonce_b, &len_b, inner]);

    out[0..NONCE_BYTES].copy_from_slice(&nonce_b);
    out[NONCE_BYTES..NONCE_BYTES + HMAC_BYTES].copy_from_slice(&mac[..HMAC_BYTES]);
    out[NONCE_BYTES + HMAC_BYTES..NONCE_BYTES + HMAC_BYTES + LEN_BYTES]
        .copy_from_slice(&len_b);
    out[ENVELOPE_OVERHEAD..ENVELOPE_OVERHEAD + inner.len()]
        .copy_from_slice(inner);
    total
}

/// Unwrap an envelope. Returns `Some(inner_len)` and writes the inner
/// packet into `out`, or `None` on:
///   - frame too short
///   - HMAC mismatch
///   - replay (nonce <= highest accepted)
///
/// When the channel has no key configured, returns `Some(frame.len())`
/// and copies frame → out unchanged (legacy plaintext mode).
#[wcet(100_us)]
pub fn unwrap<'a>(frame: &'a [u8], out: &mut [u8]) -> Option<usize> {
    unwrap_consuming(frame, out).map(|(n, _)| n)
}

/// As [`unwrap`], but also reports **how many bytes of `frame` the envelope
/// occupied**, so a caller holding several coalesced envelopes can advance to
/// the next one.
///
/// TCP is a byte stream: the brain's `send()` boundaries are not the kernel's
/// `recv()` boundaries, so two envelopes written by two separate brain sends
/// routinely arrive in one read. `unwrap` alone cannot express that — it
/// returns only the inner length, so the caller has no way to know that bytes
/// remain, and every envelope after the first was silently discarded. A
/// `PKT_ESTOP` coalesced behind any other command was lost with no error and
/// no log.
///
/// This is the same defect as K-C3/C4 (which was fixed for coalesced
/// *brain-protocol frames inside one envelope*) reappearing one layer out. The
/// inner fix cannot help: those bytes never reach the inner parser.
///
/// In legacy plaintext mode there is no framing to consume, so the whole slice
/// is reported as one unit — the caller's loop then terminates naturally.
#[wcet(100_us)]
pub fn unwrap_consuming<'a>(frame: &'a [u8], out: &mut [u8]) -> Option<(usize, usize)> {
    // K-C5 gate, RX half — the important one. This is the last point before
    // attacker-supplied bytes become a dispatched brain-protocol packet (and
    // `PKT_ESTOP` / `PKT_ACTUATOR` are motion commands). Under the policy,
    // nothing is accepted while no AEAD session exists — so everything the RX
    // loop hands us on its `link: None` arm is refused, whether or not it
    // carries a valid PSK HMAC. (Session-scoped, not per-frame provenance:
    // this does not prove *these* bytes came out of `decrypt_consuming`, only
    // that a live session exists. That is what closes K-C5, because the
    // replayable modes are exactly the sessionless ones.)
    if LINK_ENCRYPT_ENFORCED {
        if let Some(why) = link_policy_denial() {
            announce_denial(false, why);
            return None;
        }
    }
    // See `wrap`: const-folded out entirely in an enforced build, so an
    // unkeyed kernel cannot accept raw bytes as a brain packet.
    if !LINK_ENCRYPT_ENFORCED && !is_authenticated() {
        if out.len() < frame.len() { return None; }
        out[..frame.len()].copy_from_slice(frame);
        return Some((frame.len(), frame.len()));
    }
    if frame.len() < ENVELOPE_OVERHEAD { return None; }

    let nonce_b: &[u8] = &frame[0..NONCE_BYTES];
    let mac_b:   &[u8] = &frame[NONCE_BYTES..NONCE_BYTES + HMAC_BYTES];
    let len_b:   &[u8] = &frame[NONCE_BYTES + HMAC_BYTES..NONCE_BYTES + HMAC_BYTES + LEN_BYTES];
    let n = u16::from_le_bytes([len_b[0], len_b[1]]) as usize;
    if n > MAX_INNER_BYTES { return None; }
    if frame.len() < ENVELOPE_OVERHEAD + n { return None; }
    if out.len() < n { return None; }

    let inner = &frame[ENVELOPE_OVERHEAD..ENVELOPE_OVERHEAD + n];

    // DIR_RX, not DIR_TX: we only ever accept frames travelling
    // brain → kernel. See the direction note in the module header.
    let expected = hmac_sha256_precomputed(&[DIR_RX, nonce_b, len_b, inner]);
    if !ct_eq(&expected[..HMAC_BYTES], mac_b) { return None; }

    // Replay defence — strictly monotonic nonce, enforced atomically:
    // `fetch_max` returns the PREVIOUS high-water mark, so exactly one
    // caller can win a given nonce value even if two harts unwrap
    // concurrently (the old load/compare/store sequence had a window
    // where both could accept the same replayed frame).
    //
    // K-C5 (RESOLVED — the mark stays, and here is why it is still the
    // only replay defence in the stack).
    //
    // HIGHEST_RX_NONCE lives in RAM only. It survives TCP reconnects while
    // the kernel is up but resets to 0 on reboot, so in HMAC-only mode a
    // recorded frame replays into the window between reboot and the first
    // legitimate brain frame (brain nonces derive from time_ns, so any
    // recorded nonce beats a zeroed mark).
    //
    // The owner chose "require encrypted mode" over "persist the mark":
    // zero flash wear, no rollback policy, and a keyless boot leaves the
    // robot with no link — fail-closed. `link-encrypt-enforced` implements
    // that; the gate is at the top of this function and of `wrap`.
    //
    // That closes the REBOOT gap, because a frame recorded before the reboot
    // is encrypted under the previous session's `rx_mac_key` and fails the
    // AEAD MAC before it ever reaches this layer (pinned by
    // `aead-link-tests::frame_from_a_previous_session_does_not_decrypt_in_a_new_one`).
    // It does NOT make this check redundant: `SecureChannel::decrypt_consuming`
    // tracks no receive counter at all — read it — so within one live session
    // a captured AEAD frame decrypts and verifies every time it is replayed.
    // The `fetch_max` below is the ONLY thing that rejects it. Deleting it
    // because "the AEAD handles replay now" would reopen in-session replay of
    // ESTOP and actuator commands.
    //
    // Adding a receive-counter high-water mark to `SecureChannel` instead was
    // considered and rejected: the brain resets `_tx_counter` to 0 on rekey
    // (`AzOSRobotBrain/secure_channel.py`, `_rekey_counter`), so a strict
    // monotonic check there would reject every frame after the first rekey.
    // Rekey is dormant today, which makes it a landmine rather than a bug.
    let mut nonce_arr = [0u8; 8];
    nonce_arr.copy_from_slice(nonce_b);
    let nonce = u64::from_be_bytes(nonce_arr);
    let prev = HIGHEST_RX_NONCE.fetch_max(nonce, Ordering::AcqRel);
    if nonce <= prev { return None; }

    out[..n].copy_from_slice(inner);
    // Consumed = overhead + payload, NOT frame.len(): anything beyond this is
    // the next coalesced envelope and belongs to the caller's next iteration.
    Some((n, ENVELOPE_OVERHEAD + n))
}
