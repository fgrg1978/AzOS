// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The emergency-stop latch, its release authority and safe mode.
//!
//! Moved out of `domains/robot/behavior/src/safety.rs` (wave 11, DOMAIN): the
//! latch is cross-cutting. Every domain with an actuator needs it, and the
//! paths that arm it are not robot code: the ring-3 `SYS_ROBOT_ESTOP`, the
//! GPIO kill switch and the stack/timer checks of `sys_wdt`, and the boot
//! replay of the flight recorder. `azos_behavior::safety` re-exports this
//! module, so every robot caller still reaches it under its old path.
//!
//! What stays robot-specific is registered here at boot, not called by name:
//! [`register_on_latch_hook`] lets the robot domain make the brain's cached
//! remote action the stop when the latch arms (see [`estop_activate`]).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use azos_sync::SpinLock;

// ---------------------------------------------------------------------------
// Remote emergency stop (set by PKT_ESTOP, cleared by MODE_CMD)
// ---------------------------------------------------------------------------
static ESTOP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Work that must happen whenever the latch arms, registered by the domain
/// that owns it. Run by [`estop_activate`] after the latch store.
static ON_LATCH_HOOKS: crate::hooks::HookTable = crate::hooks::HookTable::new();

/// Register work [`estop_activate`] runs every time the latch arms, after the
/// latch is set. Called once at boot by each domain that needs one; panics if
/// the table is full (a boot that cannot register its stop work must not run).
pub fn register_on_latch_hook(hook: fn()) {
    ON_LATCH_HOOKS.register(hook);
}

/// Activate remote emergency stop.
pub fn estop_activate() {
    // Latch FIRST: from this store on, `motor_envelope` clamps every motor
    // write from every path to zero.
    ESTOP_ACTIVE.store(true, Ordering::Release);
    // **And the cached remote action becomes the stop.**
    //
    // The latch alone is only true while it holds. `last_action` survives it:
    // the behaviour tick copies it into `state.remote_action` every pass, and
    // L2 re-emits any action younger than 2 s. So `ACTUATOR(100,100)` →
    // `PKT_ESTOP` → `MODE 0xFF` inside that window put the robot back to full
    // speed ON THE CLEAR, with no command sent after the stop — the operator's
    // act of releasing the e-stop was what moved the machine.
    //
    // `remote_actuation_from` already fixed exactly this for an `ActuatorCmd`
    // carrying `FLAG_EMERGENCY`, and its doc says why in as many words. It was
    // fixed for one entry point out of five. Putting it HERE instead covers
    // all of them at once — the two brain-link handlers, the ring-3 syscall,
    // the physical kill switch, and whatever is added next — which is the only
    // arrangement under which the next entry point cannot forget it. The GPIO
    // kill switch already forgot `estop_activate` itself once.
    //
    // Safe to take a lock here: all four callers are ordinary task context and
    // already flush the logger and hold the console lock. Nothing calls this
    // from the panic handler or an ISR.
    //
    // The cached action belongs to the robot domain, so it is replaced by the
    // hook that domain registers (`azos_behavior::safety::
    // install_estop_hooks`), run here, inside the one function every entry
    // point calls. An image without the robot domain has no cached action.
    crate::hooks::run(&ON_LATCH_HOOKS);
    ESTOP_REFUSED_CLEARS.store(0, Ordering::Relaxed);
    // And the operator's clear is spent. The stamp exists so a ring-3 stop can
    // say it undid a clear that was still in effect (`ring3_estop_record`);
    // left standing across an arming, it also marked stops that merely
    // happened within 10 s of a clear ANOTHER source had already answered.
    // Owner decision, 2026-09-16.
    //
    // Ordering with the ring-3 record: `actuation.rs` latches first and builds
    // the record afterwards, so the record must read the stamp from before
    // this call — `ring3_estop_record` takes it as an argument for that
    // reason, and the hook passes `estop_cleared_at()` read before latching.
    ESTOP_CLEARED_AT.store(0, Ordering::Release);
}

/// Refused e-stop clears since the latch last armed — see
/// [`note_refused_estop_clear`].
static ESTOP_REFUSED_CLEARS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Count one refused e-stop clear; `Some(ordinal)` when it should be recorded.
///
/// The ordinal is 1-based and is what the caller puts in the record's detail
/// field, so a single entry says "this was the 100th" rather than "it happened
/// again". `brain_protocol::refusal_is_worth_recording` holds the policy and
/// the reasoning.
pub fn note_refused_estop_clear() -> Option<u32> {
    let prior = ESTOP_REFUSED_CLEARS.fetch_add(1, Ordering::Relaxed);
    if refusal_is_worth_recording(prior) {
        Some(prior.saturating_add(1))
    } else {
        None
    }
}

/// Deactivate remote emergency stop. **Not `pub`** — see
/// [`estop_release`]/[`ReleaseAuthority`] below, added by the owner decision
/// of 2026-09-25: the brain may REQUEST a release, it may never CLEAR the
/// latch, so the unchecked clear itself must not be reachable from outside
/// this module. Body unchanged from the pre-2026-09-25 `pub fn
/// estop_deactivate`.
fn estop_deactivate_unchecked() {
    ESTOP_ACTIVE.store(false, Ordering::Release);
    // Stamp the clear, so a stop that lands right after it can say so in its
    // record — see [`ring3_estop_record`]. `max(1)`: zero is "never cleared".
    ESTOP_CLEARED_AT.store(azos_drv_sys::timebase::now().max(1), Ordering::Release);
    // A fresh arming starts a fresh refusal count, so the next incident's
    // first refused clear is recorded rather than metered away by the last
    // one's tally.
    ESTOP_REFUSED_CLEARS.store(0, Ordering::Relaxed);
}

/// CLINT tick of the last release; zero if the latch has never been cleared
/// this boot.
static ESTOP_CLEARED_AT: AtomicU64 = AtomicU64::new(0);

/// When the e-stop was last cleared (CLINT ticks), or 0 if never.
pub fn estop_cleared_at() -> u64 {
    ESTOP_CLEARED_AT.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Release authority (owner decision, 2026-09-25)
// ---------------------------------------------------------------------------
//
// **The finding.** `MODE_ID_ESTOP_RESET` over TCP/UART and the geofence probe
// that latched its own breach could all clear the latch on their own say-so —
// the brain, in particular, is the same model the envelope exists to bound,
// clearing the one control that bounds it. Decision: a release requires an
// authority the model does NOT hold. The brain may REQUEST a release; it may
// never CLEAR the latch.
//
// **Three authorities were named as acceptable; this module implements one
// fully and leaves the seam for the other two:**
//
//  1. A physical input — a second, explicit gesture on the GPIO kill switch
//     polled by `crates/core/actuation/src/sys_wdt.rs`. Not implemented here:
//     that crate (and the driver access under it) is out of this change's
//     file ownership. A physical route would add its own proof constructor
//     beside `verify_operator_release` below, gated the same way.
//  2. An operator **capability** — a `Cap<T>` kind (`crates/core/ipc/src/cap.rs`,
//     `objref.rs`) held only by a topology-declared operator task, checked on
//     a ring-3 syscall. Not implemented here: there is no ring-3 consumer to
//     check it against — `SYS_ROBOT_RESUME`/`SYS_ROBOT_PAUSE` are still
//     dispatch-table stubs, and wiring a real one touches
//     `crates/core/syscall`/`crates/core/sched`, both out of this change's file
//     ownership. A capability route would also add its own proof constructor
//     beside `verify_operator_release`, reading the caller's `CapTable`.
//  3. **A signed operator command (implemented).** Ed25519 verify already
//     exists (`azos_crypto::ed25519`, used by secure boot) and needs no
//     new crate. The operator holds a key the brain never receives; the
//     kernel verifies a signature over a fixed context plus a monotonic
//     nonce, appended to the *existing* `PKT_MODE`/`MODE_ID_ESTOP_RESET`
//     payload beyond its historical 1 byte — the wire format does not
//     change, a longer payload does.
//
// **Boot-replay note.** `logger::estop_action_latches` reads action code 3 as
// "released", every other code (including 4, "refused") as "still latched".
// A brain-only request that this module refuses MUST be recorded under 4,
// never 3 — writing 3 without actually clearing would make a reboot replay
// the latch as released when it was not. Callers in `kernel/src/tasks/behavior.rs` are
// responsible for this; see the two `PKT_MODE` dispatch sites.

/// Proof that the caller holds authority to release the e-stop latch.
///
/// The single private field means this can only be constructed inside this
/// module: [`verify_operator_release`] today, and whichever function a future
/// physical-input or capability route adds (see the module note above). No
/// other function in this crate, and nothing outside it, can produce one.
/// [`estop_release`] is the only public function that consumes one, and it is
/// now the ONLY way to clear [`ESTOP_ACTIVE`] — there is no `pub` path to
/// [`estop_deactivate_unchecked`] left in the kernel.
#[derive(Clone, Copy, Debug)]
pub struct ReleaseAuthority(());

#[cfg(test)]
impl ReleaseAuthority {
    /// Test-only proof constructor. This entire `impl` is `cfg(test)`, so it
    /// is compiled into `tests/host/behavior-tests` (which pulls this file in
    /// with `#[path]`, so its `cfg(test)` is that crate's) and into this
    /// crate's own `cargo test` — never into `kernel/src/main.rs`, which
    /// depends on `azos_behavior` as an ordinary non-test crate. This is
    /// deliberately not a `pub` bypass: the canary in the gate row greps the
    /// kernel binary for the symbol and expects it ABSENT.
    pub fn for_test() -> Self {
        ReleaseAuthority(())
    }
}

/// Release the e-stop latch. **The only public way to clear it.**
///
/// Replaces the old `pub fn estop_deactivate`: a caller can no longer clear
/// the latch with nothing, it must already hold a [`ReleaseAuthority`], which
/// outside a test only [`verify_operator_release`] (or a future physical /
/// capability route) can produce.
pub fn estop_release(_proof: ReleaseAuthority) {
    estop_deactivate_unchecked();
}

/// Fixed context bound into every operator-release signature, so a signature
/// produced for something else entirely (an OTA image, a different robot's
/// release) cannot be replayed here even under the same key.
pub const RELEASE_CONTEXT: &[u8] = b"AZOS-ESTOP-RELEASE-v1";

/// Length in bytes of the message actually signed: the fixed context plus an
/// 8-byte big-endian nonce.
pub const RELEASE_MSG_LEN: usize = RELEASE_CONTEXT.len() + 8;

/// Ed25519 signature length, re-exported so callers (the two `kernel/src/tasks/behavior.rs`
/// dispatch sites) do not need to depend on `azos_crypto` directly just
/// to size a buffer.
pub const RELEASE_SIG_BYTES: usize = azos_crypto::ed25519::ED25519_SIGNATURE_SIZE;

/// Wire length of the operator-release proof appended to a `PKT_MODE`
/// payload beyond the historical 1-byte `mode_id`: an 8-byte big-endian nonce
/// plus a 64-byte Ed25519 signature. A payload of exactly `MODE_PAYLOAD_SIZE`
/// (1 byte, `crate::brain_protocol`) is — and remains — a bare request; only
/// a payload at least this much LONGER can carry a proof.
pub const RELEASE_PROOF_BYTES: usize = 8 + RELEASE_SIG_BYTES;

/// The operator authority's Ed25519 public key, or `None` if never
/// provisioned. `None` is the fail-closed default: with no key, every release
/// attempt is refused regardless of what signature it offers — there is no
/// "verification skipped" branch, only "no key, so no proof can exist."
static OPERATOR_PUBKEY: SpinLock<Option<[u8; 32]>> = SpinLock::new(None);

/// Install the operator authority's Ed25519 public key at boot.
///
/// Returns `false`, and leaves the authority unset, for an all-zero key —
/// closing the same failure shape as secure boot's zero-key trap
/// (`crates/core/ota/build.rs`'s silent `[0u8; 32]` fallback, see
/// `azos_crypto::ed25519`'s module doc): a provisioning step that
/// silently no-ops here must not make release *easier* by falling back to a
/// key nobody holds the private half of — a fallback that already fooled one
/// gate in this tree into "verifying" against a key that verifies anything
/// signed with an all-zero private scalar. It must make release impossible
/// until a real key is provisioned.
pub fn operator_authority_init(pubkey: &[u8; 32]) -> bool {
    if pubkey.iter().all(|&b| b == 0) {
        return false;
    }
    *OPERATOR_PUBKEY.lock() = Some(*pubkey);
    true
}

/// Whether an operator authority key is currently provisioned.
pub fn operator_authority_provisioned() -> bool {
    OPERATOR_PUBKEY.lock().is_some()
}

/// Test-only: clear the provisioned key and the release-nonce floor, so each
/// test in `tests/host/behavior-tests/src/estop_release_authority.rs` states its
/// own precondition instead of inheriting whatever an earlier test (run in
/// the same process, in unspecified order) left behind. `cfg(test)` for the
/// same reason as [`ReleaseAuthority::for_test`] — absent from every kernel
/// binary, present only where this file compiles under `cargo test`.
#[cfg(test)]
pub fn test_reset_operator_authority() {
    *OPERATOR_PUBKEY.lock() = None;
    RELEASE_NONCE_FLOOR.store(0, Ordering::Relaxed);
}

fn operator_pubkey() -> Option<[u8; 32]> {
    *OPERATOR_PUBKEY.lock()
}

/// Monotonic floor for accepted release nonces. Kept separately from
/// `auth_envelope::HIGHEST_RX_NONCE`: this proof can arrive with or without
/// that envelope (the brain link may run plaintext, or `link-encrypt-enforced`
/// may not be compiled in), and must not trust a counter it does not own.
///
/// **Persisted, not just in-memory (owner decision, 2026-09-26).** Found by
/// the wave-1 coordinator: a captured signed release replays after a reset,
/// because this was a plain process-lifetime counter — a reboot put it back
/// to 0, and any proof an attacker had ever observed on the wire (over a
/// plaintext link, or leaked some other way) would verify again. There is no
/// TRNG on any target board, so a fresh,
/// unpredictable per-boot CHALLENGE is not available as an alternative fix —
/// the kernel cannot generate one no attacker could also predict. Persistence
/// is the only closeable option: [`verify_operator_release`] durably records
/// every advance through `crate::logger::log_release_nonce_floor_durable`
/// BEFORE it moves this atomic (see that function's doc for the exact
/// order), and [`release_nonce_floor_seed`] raises it at boot from
/// `logger::replay_boot`'s scan of the previous session(s)' record — see
/// `domains/robot/safety-core::boot_latch` for the call, made before
/// `operator_authority_init` can accept a key.
static RELEASE_NONCE_FLOOR: AtomicU64 = AtomicU64::new(0);

/// Raise [`RELEASE_NONCE_FLOOR`] to at least `floor`, never lowering it.
///
/// Called once at boot (`domains/robot/safety-core::boot_latch::seed_release_
/// nonce_floor`), before `operator_authority_init` can accept a key or a
/// brain frame can reach [`verify_operator_release`] — see
/// [`RELEASE_NONCE_FLOOR`]'s own doc for why persistence, not
/// challenge-response, is this project's fix. `fetch_max`, so calling this
/// more than once, or with a floor lower than one a test or an earlier call
/// already established, is always safe.
pub fn release_nonce_floor_seed(floor: u64) {
    RELEASE_NONCE_FLOOR.fetch_max(floor, Ordering::AcqRel);
}

/// Why an operator-release proof was refused.
///
/// Three variants because they have different causes, though kernel callers
/// still collapse ALL of them into the **same** flight-recorder code
/// (`action_code = 4`, the existing "refused MODE clear" — see the module
/// note above on why it must not be 3), which is the "shared error code" the
/// gate rows check for: a forged proof, an absent key, and a durability
/// failure are all indistinguishable from the flight recorder's point of
/// view — the latch stayed armed either way. `kernel/src/tasks/behavior.rs`'s two dispatch sites
/// already `.ok()` the whole `Result`, so adding a variant here needs no
/// change there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReleaseDenial {
    /// No operator key is provisioned on this robot — every release is
    /// refused regardless of the signature offered.
    NoAuthorityKey,
    /// A key is provisioned, but the signature does not verify under it, or
    /// its nonce is not strictly newer than the last one this boot accepted.
    BadOrReplayedProof,
    /// The signature verified and the nonce was fresh, but the durable
    /// record of it could not be written while a recorder IS active — see
    /// [`verify_operator_release`]'s doc for why this refuses rather than
    /// proceeding un-persisted.
    NonceNotDurable,
}

/// Build the exact bytes an operator signs to authorise one release.
fn release_message(nonce: u64) -> [u8; RELEASE_MSG_LEN] {
    let mut msg = [0u8; RELEASE_MSG_LEN];
    msg[..RELEASE_CONTEXT.len()].copy_from_slice(RELEASE_CONTEXT);
    msg[RELEASE_CONTEXT.len()..].copy_from_slice(&nonce.to_be_bytes());
    msg
}

/// Mirrors `brain_protocol::mode_estop_record`'s refusal action code (4,
/// "refused MODE clear"). That function already returns this exact value for
/// "wrong mode id, still armed"; the two `kernel/src/tasks/behavior.rs` `PKT_MODE`
/// dispatch sites need the identical number for "right mode id, no valid
/// release proof" — see [`ReleaseDenial`]'s doc for why both must be
/// indistinguishable to the flight recorder. A frozen mirror, not a shared
/// constant, because `brain_protocol.rs` is outside this change's file
/// ownership — same pattern as `abi::CapHandle::MAX_CAPS_PER_TASK_MIRROR`.
pub const ESTOP_ACTION_REFUSED_MIRROR: u8 = 4;

/// Verify an operator-signed release proof and, if it checks out, return the
/// [`ReleaseAuthority`] to clear the latch with.
///
/// Fails closed on every path — no key provisioned, bad signature, a nonce
/// that is not strictly newer than the last one accepted, or (2026-09-26) a
/// durable record of this nonce that could not be written while a recorder
/// IS active, are all a [`ReleaseDenial`], never a proof.
///
/// **Order, and why it changed on 2026-09-26.** Signature checked BEFORE the
/// nonce floor is even READ, mirroring `auth_envelope::unwrap_consuming`'s
/// order: an attacker without the private key cannot burn nonces to deny a
/// legitimate operator's next release. But between the floor check and the
/// floor actually MOVING, this now inserts a durable write
/// (`crate::logger::log_release_nonce_floor_durable`) — and that write must
/// happen BEFORE the in-memory `fetch_max`, not after: the failure this
/// closes is a captured proof replaying across a RESET, and a reset can
/// follow this call within milliseconds (it is, after all, releasing an
/// e-stop). If the in-memory floor moved first and the write then failed or
/// the board reset before it landed, THIS boot would correctly refuse a
/// replay of `nonce` — right up until the next reboot, when the disk (the
/// only thing that survives one) would show the floor exactly where it was
/// BEFORE this call, and the same captured proof would verify again. Durable
/// first means a crash between the two leaves the disk AHEAD of or equal to
/// memory, never behind it.
///
/// **Fails closed when a recorder is active and its write fails**, rather
/// than proceeding un-persisted: an active recorder that cannot currently
/// take a write is exactly the state in which persistence cannot be
/// verified to have happened, and this proof exists to make persistence not
/// optional. **Proceeds when NO recorder is active at all**
/// (`logger::logger_active() == false` — no disk, no mount, a host build
/// with nothing registered): there is deliberately nowhere for the write to
/// go, so refusing every release until a recorder exists would make the
/// signed-release mechanism strictly WORSE than the unchecked `pub fn
/// estop_deactivate` it replaced on such a build. This is a real gap on that
/// build — a captured proof CAN replay after a reset with no recorder wired
/// — recorded here rather than hidden: provisioning storage closes it, the
/// same way provisioning a key closes [`ReleaseDenial::NoAuthorityKey`].
pub fn verify_operator_release(
    nonce: u64,
    sig: &[u8; RELEASE_SIG_BYTES],
) -> Result<ReleaseAuthority, ReleaseDenial> {
    let key = operator_pubkey().ok_or(ReleaseDenial::NoAuthorityKey)?;
    let msg = release_message(nonce);
    if !azos_crypto::ed25519::sig_verify(&key, sig, &msg) {
        return Err(ReleaseDenial::BadOrReplayedProof);
    }
    let prev = RELEASE_NONCE_FLOOR.load(Ordering::Acquire);
    if nonce <= prev {
        return Err(ReleaseDenial::BadOrReplayedProof);
    }
    if crate::logger::logger_active() {
        crate::logger::log_release_nonce_floor_durable(nonce)
            .map_err(|_| ReleaseDenial::NonceNotDurable)?;
    }
    // A second release racing this one between the `load` above and this
    // `fetch_max` is vanishingly unlikely (two operator signatures in the
    // same instant) but must still be caught, not silently waved through
    // with a nonce that is no longer the newest accepted.
    let advanced = RELEASE_NONCE_FLOOR.fetch_max(nonce, Ordering::AcqRel);
    if nonce <= advanced {
        return Err(ReleaseDenial::BadOrReplayedProof);
    }
    Ok(ReleaseAuthority(()))
}

/// `SAFETY_ESTOP` action code of a stop latched by a ring-3 program through
/// `SYS_ROBOT_ESTOP`, with [`ring3_estop_record`]'s `detail`.
///
/// It used to write 4, which is also a refused MODE clear, with `detail = 0`:
/// the record could not say which program stopped the machine, nor tell a stop
/// from a refusal. 6 was free, and `logger::estop_action_latches` reads every
/// code but 3 and 7 as latched, so boot replay restores this one unchanged.
pub const ESTOP_ACTION_RING3: u8 = 6;

/// `SAFETY_ESTOP` action code of a stop latched by a geofence breach.
///
/// `logger::estop_action_latches` reads every code but 3 and 7 as latched, so
/// boot replay restores this one like any other source: a machine reset while
/// outside its fence comes back stopped, which is the point of recording it.
/// `detail` carries how many metres beyond the fence the position was.
pub const ESTOP_ACTION_GEOFENCE: u8 = 8;

/// `SAFETY_ESTOP` action code of a stop latched by `sys-wdt`'s stack-canary
/// check (U08-1, owner decision 2026-09-26). Before this decision the two
/// `sys_wdt.rs` "SAFE STOP"s called `azos_robot::motor_stop` directly and
/// nothing else — no latch, so `rt_motor_task` rewrote both wheels from the
/// next `MotorCmd` within one control tick (`motor_envelope`'s `estop_is_
/// active()` check is what a latch-less stop has nothing to hold onto), and
/// no record. `detail` carries how many canaries were found overwritten
/// (`total - ok`).
pub const ESTOP_ACTION_STACK_OVERFLOW: u8 = 9;

/// `SAFETY_ESTOP` action code of a stop latched by `sys-wdt`'s timer-liveness
/// check finding the timer frozen for `WDT_FROZEN_THRESHOLD` consecutive
/// passes (U08-1, same decision as [`ESTOP_ACTION_STACK_OVERFLOW`]).
/// `detail` carries the stall count at the moment it latched.
pub const ESTOP_ACTION_TIMER_FROZEN: u8 = 10;

/// `SAFETY_ESTOP` action code of a stop latched at boot because the config
/// authority this device had is gone (wave 11, RFC-0054 finding 7): it
/// accepted a signed `CONFIG.INI` before (the floor in its device record is
/// >= 1) and this boot's `CONFIG.INI`/`CONFIG.SIG` is absent, tampered,
/// another device's, the v1 format, or an older counter (a replay). `detail`
/// carries `azos_config::AuthorityLoss::code`. Latches like any other
/// source, so the machine stays stopped across resets until an operator
/// releases it — fixing the files alone does not move it.
pub const ESTOP_ACTION_CONFIG_AUTHORITY: u8 = 11;

/// `SAFETY_ESTOP` action code of a stop latched by RC link loss (wave 15,
/// `kernel/src/tasks/rc_safety.rs`): the receiver's own failsafe bit, or no
/// fresh frame for Kconfig `RC_LINK_TIMEOUT_MS` after a link was established.
/// `detail` is 0 for the receiver's bit, else the frame age in ms. Latches
/// like every source but 3 and 7 (`logger::estop_action_latches`).
pub const ESTOP_ACTION_RC_LINK_LOSS: u8 = 12;

/// `SAFETY_ESTOP` action code of a stop latched by the RC kill switch (wave
/// 15, Kconfig `RC_KILL_CHANNEL`). `detail` is the switch channel's pulse
/// width in microseconds.
pub const ESTOP_ACTION_RC_KILL: u8 = 13;

/// Top bit of a ring-3 stop's `detail`: the latch was taken within
/// [`ESTOP_RELATCH_WINDOW_TICKS`] of an operator clear. The low 31 bits carry
/// the latching tid.
pub const ESTOP_DETAIL_RELATCHED: u32 = 0x8000_0000;

/// How soon after an operator clear a ring-3 stop is recorded as re-latching
/// it: 10 s. It changes only the record, never whether the stop happens.
pub const ESTOP_RELATCH_WINDOW_TICKS: u64 = azos_drv_sys::timebase::TIMER_FREQ * 10;

/// What a ring-3 stop latched at `now` by task `tid` writes to the flight
/// recorder, as `(action_code, detail)` for `SAFETY_ESTOP`.
///
/// **A stop is never refused**, including one that re-latches seconds after an
/// operator cleared the latch: the program doing it may be the only thing that
/// saw why the machine should stay stopped. What an operator-clear-then-relatch
/// needs is to be attributable — which task, and whether it undid a clear — so
/// that a program fighting the operator is visible in the record rather than
/// indistinguishable from any other stop.
pub fn ring3_estop_record(tid: u32, cleared_at: u64, now: u64) -> (u8, u32) {
    let relatched = relatched_within_window(
        cleared_at, now, ESTOP_RELATCH_WINDOW_TICKS);
    let flag = if relatched { ESTOP_DETAIL_RELATCHED } else { 0 };
    (ESTOP_ACTION_RING3, (tid & !ESTOP_DETAIL_RELATCHED) | flag)
}

/// Check if remote ESTOP is active — or safe mode is: every actuation
/// chokepoint that honours the e-stop (the motor gate and envelope, the
/// direction-pin halt, the payload, the flight loop's ESC throttle, L0's
/// `safety_check`) holds the machine in safe mode through this one call.
pub fn estop_is_active() -> bool {
    ESTOP_ACTIVE.load(Ordering::Acquire) || SAFE_MODE.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Safe mode (owner decision, 2026-09-28)
// ---------------------------------------------------------------------------

/// The boot's attempts are exhausted (`azos_ota::recovery`, armed by
/// `kernel/src/boot/ota.rs`'s `boot_count_loaded`): hold every actuator for the
/// whole boot. Entered once, early in boot, before any actuator is energised;
/// nothing clears it — not [`estop_release`], not anything else. A new boot
/// with a good image is the only way out. Kept apart from [`ESTOP_ACTIVE`] so
/// it writes no e-stop record, is not replayed by the boot latch, and cannot
/// be released by an operator's signed release.
static SAFE_MODE: AtomicBool = AtomicBool::new(false);

/// Enter safe mode for the rest of this boot.
pub fn safe_mode_enter() {
    SAFE_MODE.store(true, Ordering::Release);
}

/// Is this boot in safe mode?
pub fn safe_mode_active() -> bool {
    SAFE_MODE.load(Ordering::Acquire)
}

// ---------------------------------------------------------------------------
// Pure halves of the records above (moved from `brain_protocol.rs`, wave 11)
// ---------------------------------------------------------------------------

/// Is this refused e-stop clear worth a flight-recorder entry?
///
/// `prior` is how many refusals have already happened since the latch armed;
/// the answer is yes for the 1st, 10th, 100th, 1000th and so on.
///
/// **Why a count and not a rate.** A peer that keeps sending `PKT_MODE` with
/// the wrong id while the e-stop is armed changes no state and is refused
/// every time — and each refusal used to cost a synchronous flush plus a
/// console line that busy-waits on the UART. `ring3_estop` in
/// `kernel/src/tasks/behavior.rs` already carries the same argument for ring 3: an
/// unmetered record is a path to evict the real e-stop record from the
/// recorder with copies of itself, and the attacker pays nothing because the
/// machine is already stopped.
///
/// A time-based limiter would still admit one record per interval for as long
/// as the peer cares to keep going, and gives it a window to time against.
/// Powers of ten bound the whole run at `log10(n)` records while keeping what
/// an investigator actually needs — that it happened, and roughly how often.
///
/// No clock, no state: the counter lives with the latch in
/// `safety::note_refused_estop_clear`, and this is the pure half the host
/// tests drive, for the same reason `mode_estop_record` below is.
pub const fn refusal_is_worth_recording(prior: u32) -> bool {
    let n = match prior.checked_add(1) {
        Some(v) => v,
        None => return false,
    };
    let mut p: u32 = 1;
    while p < n {
        p = match p.checked_mul(10) {
            Some(v) => v,
            None => return false,
        };
    }
    p == n
}

/// Did a stop latched at `now` re-latch an operator clear stamped at
/// `cleared_at`? True when the clear came first and at most `window` ticks
/// earlier, inclusive.
///
/// `cleared_at == 0` is "never cleared" and is never a re-latch. A clear
/// stamped after `now` is not one either: it came after this stop and
/// released it.
///
/// Pure for the reason [`refusal_is_worth_recording`] is: the stamp lives with
/// the latch in `safety::estop_deactivate`, and the record it feeds is
/// `safety::ring3_estop_record`.
pub const fn relatched_within_window(cleared_at: u64, now: u64, window: u64) -> bool {
    cleared_at != 0 && now >= cleared_at && now - cleared_at <= window
}