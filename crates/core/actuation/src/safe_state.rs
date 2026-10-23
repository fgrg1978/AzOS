// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Deadline-or-safe-state (innovation B2), the half of the effect gate that
//! outlives the call: what the kernel does when a device does not commit an
//! effect by its deadline, and when an effect fails.
//!
//! # The contract
//!
//! A reversible effect with a declared deadline (the op's `#[deadline_ns]`,
//! carried in [`crate::effect_gate::Timing`]) is **watched** from the moment
//! the gate admits it until the device op returns. If the op has not returned
//! by `deadline_ns`, the KERNEL drives the device to its declared safe state
//! (the `safe_state` op of the topology's `[device.*]` row) through its own
//! hold on the device, not through the driver: the driver is the thing that
//! stalled. That is one `Rule::SafeState` record, whether the drive worked
//! (verdict admit) or could not be done (refuse: no such op for the kind, or
//! the kind's driver says no).
//!
//! # The hold (owner decision 16-10)
//!
//! From the drive on the device is **held**: a further reversible effect is
//! refused with a receipt, and only stops pass. A stop does NOT lift the
//! hold, from whichever path (the ring-3 op, the PID loop, `rt_motor_task`,
//! the e-stop): a device that stalled once is not trusted again because
//! somebody told it to stop. The hold lasts at least `B2_HOLD_MIN_MS` (Kconfig)
//! from the last drive, and afterwards only [`release`] lifts it, with the
//! operator's signed warrant, the same proof and the same key path that
//! release the e-stop latch (`estop::verify_operator_release`: Ed25519, a
//! nonce strictly newer than the last accepted one, persisted). A release
//! that arrives inside the minimum hold, or with a warrant that does not
//! verify, is refused, and every refusal and every release is one
//! `Rule::SafeState` record. The operator reaches [`release`] on the brain
//! link and the UART bridge, as a `PKT_MODE` reset frame that names the
//! device ([`release_from_frame`]). The hold is volatile (it does not survive a
//! reboot, which re-initialises the device); the records are in the flight
//! recorder.
//!
//! An op that returns, but late, is a miss too: the caller that finds its own
//! watch overdue at completion is the one that drives the device, after its
//! op, so the stop is the last write.
//!
//! A reversible effect whose op FAILS (the device reports it did not take
//! it) is undone by the `compensate` op of the row, run by the kernel:
//! `Rule::Compensation`, admit when it ran, refuse when the row declares no
//! inverse or the kind's driver refuses it.
//!
//! # Who runs what
//!
//! * **The watch** is a small table of in-flight effects
//!   (Kconfig `EFFECT_WATCH_SLOTS`), lock-free: a slot is claimed by one
//!   compare-and-swap, filled, and published with a release store;
//!   completion and the sweep race for it with one compare-and-swap each, and
//!   the winner is the only one that handles the miss, so there is exactly
//!   one record per missed effect. A full table refuses the effect (fail
//!   closed): an effect that cannot be watched is not issued.
//! * **The timer is the system watchdog's pass** ([`sweep`], called by
//!   `sys_wdt` on every pass), not the scheduler's timer heap, which a stalled
//!   or starved scheduler would take down with the thing being watched. The
//!   price is the pass period: a stalled device is driven to its safe state
//!   within `deadline + one pass` (500 ms), not at the deadline. A device
//!   whose deadline is shorter than the pass period is covered by the late
//!   completion above only when the stalled op returns.
//! * **The drivers** are per kind ([`register`]): a function that drives a
//!   device of the kind to a safe-state op, one that runs a compensating op,
//!   and one that lifts what the drive holds in the device layer. They run in
//!   the watchdog's task (a real-time task) or in the caller's context, so
//!   they must not block or take a lock the stalled driver may hold (the
//!   motor's drive is `azos_robot::motor_safe_state`, which takes none and
//!   may run on any hart at any time).
//! * **The device layer holds the drive too.** The motor's drive holds the
//!   wheel's pins and PWM channel at the coast (`azos_drv_gpio::hold`,
//!   `azos_drv_actuator::pwm_hold`): a command that was admitted before the
//!   hold and is still on its way to the pins, or any path that does not
//!   cross this gate, cannot write over it. [`release`] lifts that hold with
//!   the device's (the kind's release driver), after its own.
//!
//! # Cost
//!
//! Per watched effect: one slot claim (a compare-and-swap), three relaxed
//! stores, one release store, one compare-and-swap to complete, two clock
//! reads. Unwatched effects (stops, effects with no deadline) pay none of it.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use azos_decision::{Rule, Verdict};

use crate::effect_gate::Effect;
use crate::estop::{verify_operator_release_of, ReleaseDenial, ReleaseTarget, RELEASE_PROOF_BYTES, RELEASE_SIG_BYTES};

/// Effect kinds the tables below hold: the kinds that have a safe state, which
/// today is the motor (`effect_gate::KIND_MOTOR`, 1) alone. The SoC kinds
/// (`KIND_CLOCK`..`KIND_POWER_DOMAIN`) are above it: they are recorded, never
/// watched, held or driven, and the compile-time check below keeps it that way
/// (a SoC subject is a provider/op wire word, which would alias a motor-style
/// device number if the table ever grew over those kinds).
pub const MAX_KINDS: usize = crate::effect_gate::KIND_MOTOR as usize + 1;
const _: () = {
    use crate::effect_gate::{KIND_CLOCK, KIND_POWER_DOMAIN};
    assert!(KIND_CLOCK as usize >= MAX_KINDS && KIND_POWER_DOMAIN as usize >= MAX_KINDS);
};
/// Devices of one kind the held mask holds.
pub const MAX_SUBJECTS: u16 = 32;

/// Watch table size (Kconfig `EFFECT_WATCH_SLOTS`).
const SLOTS: usize = azos_limits::EFFECT_WATCH_SLOTS as usize;

/// Device state codes of a `Rule::SafeState` record.
pub const STATE_COMMANDED: u64 = 1;
pub const STATE_SAFE: u64 = 2;
/// Cause codes (the low byte of the record's third number; the asking task is
/// above it).
pub const CAUSE_DEADLINE: u64 = 1;
pub const CAUSE_HELD: u64 = 2;
/// Causes of a release record (`Rule::SafeState`, the third number is the
/// milliseconds the device had been held, above the cause byte): the hold was
/// lifted / refused inside the minimum hold / refused for want of a valid
/// warrant.
pub const CAUSE_RELEASED: u64 = 3;
pub const CAUSE_RELEASE_TOO_EARLY: u64 = 4;
pub const CAUSE_RELEASE_NO_WARRANT: u64 = 5;

/// Status codes of a `Rule::Compensation` record.
pub const COMP_RAN: u64 = 0;
pub const COMP_NO_INVERSE: u64 = 1;
pub const COMP_REFUSED: u64 = 2;

// ── Kind drivers ────────────────────────────────────────────────────────

/// Drive device `subject` of a kind with `op` (a kind-specific code, from 1;
/// 0 is "none declared" and never reaches a driver). `true` when it was done.
pub type DriveFn = fn(subject: u16, op: u8) -> bool;

/// Lift what the safe-state drive of device `subject` holds in the device
/// layer (the motor: its pins and channel). `true` when there was a device.
pub type ReleaseFn = fn(subject: u16) -> bool;

/// The drivers of one kind: the safe-state drive, the compensating op, the
/// release.
type Drivers = (DriveFn, DriveFn, ReleaseFn);

/// The drivers of each kind, written once at boot and read only when a device
/// is driven (a miss or a failure) or released, under a lock the stalled path
/// does not hold: the lock is taken for the copy of three function pointers,
/// never across a call.
static DRIVERS: azos_sync::SpinLock<[Option<Drivers>; MAX_KINDS]> =
    azos_sync::SpinLock::new([None; MAX_KINDS]);
/// A bit per kind with drivers registered: the admission asks it on every
/// watched effect, so it is an atomic and not the lock.
static REGISTERED: AtomicU32 = AtomicU32::new(0);

/// Register how the kernel drives a device of `kind` to a safe state, how it
/// runs a compensating op and how it lifts the drive's hold in the device
/// layer (the kernel, at boot). `kind` must be below [`MAX_KINDS`].
pub fn register(kind: u8, safe_state: DriveFn, compensate: DriveFn, release: ReleaseFn) {
    assert!((kind as usize) < MAX_KINDS);
    DRIVERS.lock()[kind as usize] = Some((safe_state, compensate, release));
    REGISTERED.fetch_or(1 << kind, Ordering::Release);
}

fn drivers(kind: u8) -> Option<Drivers> {
    DRIVERS.lock().get(kind as usize).copied().flatten()
}

/// Is a safe-state driver registered for `kind`? Only then is a watch worth
/// arming: nothing could answer a miss.
pub fn can_drive(kind: u8) -> bool {
    (kind as usize) < MAX_KINDS && REGISTERED.load(Ordering::Acquire) & (1 << kind) != 0
}

// ── Devices held in their safe state ────────────────────────────────────

/// Per kind and device, the timer tick the kernel last drove it to its safe
/// state, or 0 when it is not held. The hold is not a bit but a time: the
/// minimum hold is measured from it.
static HELD_SINCE: [[AtomicU64; MAX_SUBJECTS as usize]; MAX_KINDS] =
    [const { [const { AtomicU64::new(0) }; MAX_SUBJECTS as usize] }; MAX_KINDS];

/// Per kind and device, the safe-state op of its last drive: a hold that
/// comes back while [`release`] lifts the device layer's is driven again with
/// it.
static HELD_OP: [[AtomicU8; MAX_SUBJECTS as usize]; MAX_KINDS] =
    [const { [const { AtomicU8::new(0) }; MAX_SUBJECTS as usize] }; MAX_KINDS];

fn held_cell(kind: u8, subject: u16) -> Option<&'static AtomicU64> {
    HELD_SINCE.get(kind as usize)?.get(subject as usize)
}

/// Does the device sit in its safe state after a missed deadline?
pub fn held(kind: u8, subject: u16) -> bool {
    matches!(held_cell(kind, subject), Some(c) if c.load(Ordering::Acquire) != 0)
}

/// Hold the device from now: (re)start its minimum hold, and note the op it
/// is driven with. Called before the kernel drives it, so no effect is
/// admitted in between.
fn hold(w: &Watched) {
    if let Some(c) = held_cell(w.kind, w.subject) {
        HELD_OP[w.kind as usize][w.subject as usize].store(w.safe_op, Ordering::Relaxed);
        c.store(now().max(1), Ordering::SeqCst);
    }
}

/// The minimum hold, timer ticks (Kconfig `B2_HOLD_MIN_MS`).
fn hold_min_ticks() -> u64 {
    ns_to_ticks(azos_limits::B2_HOLD_MIN_MS as u64 * 1_000_000)
}

/// Why a release was refused. Each of these but `NotHeld` is also one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    /// The device is not held (or is out of the tables' range): nothing to
    /// release, nothing recorded.
    NotHeld,
    /// Inside the minimum hold; `remaining_ms` is what is left of it.
    TooEarly { remaining_ms: u64 },
    /// The warrant does not verify (no key, bad signature, replayed nonce, or
    /// the nonce could not be made durable).
    NoWarrant(ReleaseDenial),
}

/// Lift the hold of device `subject` of `kind`, with the operator's signed
/// warrant (`nonce`, `sig`: the message and the key of the e-stop release).
///
/// The order is the cheap, key-free refusals first: not held, then inside the
/// minimum hold. Only a release that could be accepted spends the warrant's
/// nonce, so a warrant sent too early is not burned. A refusal of a held
/// device and a release are each one `Rule::SafeState` record (verdict refuse
/// / admit); the release record is written after the hold is lifted.
pub fn release(kind: u8, subject: u16, nonce: u64, sig: &[u8; RELEASE_SIG_BYTES]) -> Result<(), ReleaseError> {
    let cell = held_cell(kind, subject).ok_or(ReleaseError::NotHeld)?;
    let since = cell.load(Ordering::Acquire);
    if since == 0 {
        return Err(ReleaseError::NotHeld);
    }
    let device = (kind as u32) << 16 | subject as u32;
    let t = now();
    let held_ms = ticks_to_ms(t.saturating_sub(since));
    let refuse = |cause: u64| {
        azos_decision::record_receipt(
            Rule::SafeState,
            Verdict::Refuse,
            device,
            [STATE_SAFE, STATE_SAFE, held_ms << 8 | cause],
        );
    };
    let min = hold_min_ticks();
    if t.saturating_sub(since) < min {
        refuse(CAUSE_RELEASE_TOO_EARLY);
        return Err(ReleaseError::TooEarly { remaining_ms: ticks_to_ms(min - t.saturating_sub(since)) });
    }
    if let Err(d) = verify_operator_release_of(ReleaseTarget::Hold { kind, subject }, nonce, sig) {
        refuse(CAUSE_RELEASE_NO_WARRANT);
        return Err(ReleaseError::NoWarrant(d));
    }
    // A new miss that re-held the device while the warrant was checked moved
    // `since`: that hold has not run its minimum, and the warrant is spent.
    if cell.compare_exchange(since, 0, Ordering::AcqRel, Ordering::Relaxed).is_err() {
        refuse(CAUSE_RELEASE_TOO_EARLY);
        return Err(ReleaseError::TooEarly { remaining_ms: ticks_to_ms(min) });
    }
    // The device layer's hold goes after the gate's, so no reversible effect
    // is admitted while the device still refuses it. A miss that held the
    // device again in between may have driven it BEFORE this lifted the
    // device layer's hold: that hold is driven again, as it was.
    release_device(kind, subject);
    if held(kind, subject) {
        let op = HELD_OP[kind as usize][subject as usize].load(Ordering::Relaxed);
        drive_safe(&Watched { kind, class: 0, subject, tid: 0, safe_op: op, deadline: 0 });
    }
    azos_decision::record_receipt(
        Rule::SafeState,
        Verdict::Admit,
        device,
        [STATE_SAFE, STATE_COMMANDED, held_ms << 8 | CAUSE_RELEASED],
    );
    Ok(())
}

/// Lift what the drive of the device holds in the device layer (the kind's
/// release driver). `false` when the kind has none, or it had no such device.
fn release_device(kind: u8, subject: u16) -> bool {
    match drivers(kind) {
        Some((_, _, r)) => r(subject),
        None => false,
    }
}

/// Length of the body of a hold-release frame: the operator-release proof
/// (8-byte big-endian nonce, Ed25519 signature) and the device it releases
/// (kind, then subject big-endian).
pub const HOLD_RELEASE_BODY_BYTES: usize = RELEASE_PROOF_BYTES + 3;

/// The operator channel of [`release`]: the body of a `PKT_MODE` frame whose
/// mode id is the reserved e-stop reset id (the caller checks the id and
/// passes the bytes after it). A body of exactly [`HOLD_RELEASE_BODY_BYTES`]
/// is a hold release and nothing else: it never reaches the e-stop latch or
/// degraded mode, so one warrant cannot do both. Any other length is not
/// this frame (`None`): the bare reset request and the e-stop release proof
/// keep their historical shapes.
///
/// The warrant is checked as the e-stop release's is
/// (`verify_operator_release_of`, called by [`release`]), in that one place
/// with the same key and the same persisted nonce floor, but it is signed for
/// this device (`ReleaseTarget::Hold`, its kind and subject, on this robot):
/// it releases neither the latch nor another device.
pub fn release_from_frame(body: &[u8]) -> Option<Result<(), ReleaseError>> {
    if body.len() != HOLD_RELEASE_BODY_BYTES {
        return None;
    }
    let nonce = u64::from_be_bytes(body[..8].try_into().ok()?);
    let mut sig = [0u8; RELEASE_SIG_BYTES];
    sig.copy_from_slice(&body[8..RELEASE_PROOF_BYTES]);
    let kind = body[RELEASE_PROOF_BYTES];
    let subject = u16::from_be_bytes([body[RELEASE_PROOF_BYTES + 1], body[RELEASE_PROOF_BYTES + 2]]);
    Some(release(kind, subject, nonce, &sig))
}

/// Test-only: forget every hold (the tests run in one process).
#[cfg(test)]
pub fn clear_holds_for_test() {
    for kind in HELD_SINCE.iter() {
        for c in kind.iter() {
            c.store(0, Ordering::Release);
        }
    }
}

// ── The watch table ─────────────────────────────────────────────────────

const FREE: u64 = 0;
const ARMED: u64 = 1;
const DRIVING: u64 = 2;
const CLAIMED: u64 = 3;

/// One in-flight effect. `state` is `generation << 2 | FREE/ARMED/DRIVING/
/// CLAIMED`; the generation moves on whenever the slot is freed, so a late
/// completion of an effect whose slot was recycled finds a different state
/// and knows the effect was handled without it.
struct Slot {
    state: AtomicU64,
    /// Absolute deadline, timer ticks.
    deadline: AtomicU64,
    /// `kind << 56 | class << 48 | subject << 32 | tid`.
    who: AtomicU64,
    /// The op to drive on a miss.
    op: AtomicU64,
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            state: AtomicU64::new(FREE),
            deadline: AtomicU64::new(0),
            who: AtomicU64::new(0),
            op: AtomicU64::new(0),
        }
    }
}

static TABLE: [Slot; SLOTS] = [const { Slot::new() }; SLOTS];

/// What a watched effect needs to be handled, kept by the caller and in its
/// slot (the sweep reads the slot's copy).
#[derive(Clone, Copy, Debug)]
struct Watched {
    kind: u8,
    class: u8,
    subject: u16,
    tid: u32,
    safe_op: u8,
    deadline: u64,
}

impl Watched {
    fn pack(&self) -> u64 {
        (self.kind as u64) << 56 | (self.class as u64) << 48 | (self.subject as u64) << 32 | self.tid as u64
    }
    fn unpack(who: u64, op: u64, deadline: u64) -> Watched {
        Watched {
            kind: (who >> 56) as u8,
            class: (who >> 48) as u8,
            subject: (who >> 32) as u16,
            tid: who as u32,
            safe_op: op as u8,
            deadline,
        }
    }
    fn device(&self) -> u32 {
        (self.kind as u32) << 16 | self.subject as u32
    }
}

/// A watch the caller holds until its op returns.
#[derive(Clone, Copy, Debug)]
pub struct Ticket {
    slot: usize,
    gen: u64,
    w: Watched,
}

#[inline]
fn now() -> u64 {
    azos_drv_sys::timebase::now()
}

/// Timer ticks as milliseconds, capped so it fits above the cause byte of a
/// record's third number.
fn ticks_to_ms(ticks: u64) -> u64 {
    (ticks as u128 * 1000 / azos_drv_sys::timebase::TIMER_FREQ as u128).min(u64::MAX as u128 >> 8) as u64
}

/// Nanoseconds as timer ticks, saturating (a deadline too far away to matter
/// is never reached).
fn ns_to_ticks(ns: u64) -> u64 {
    match ns.checked_mul(azos_drv_sys::timebase::TIMER_FREQ) {
        Some(v) => v / 1_000_000_000,
        None => ((ns as u128 * azos_drv_sys::timebase::TIMER_FREQ as u128) / 1_000_000_000) as u64,
    }
}

/// Watch effect `e` until [`complete`] or [`cancel`]: `deadline_ns` from now,
/// `safe_op` the op to drive on a miss. `None` when the table is full or the
/// device is out of the tables' range: the effect must not be issued.
pub fn arm(e: &Effect, deadline_ns: u64, safe_op: u8) -> Option<Ticket> {
    if (e.kind as usize) >= MAX_KINDS || e.subject >= MAX_SUBJECTS {
        return None;
    }
    let w = Watched {
        kind: e.kind,
        class: e.class as u8,
        subject: e.subject,
        tid: e.tid,
        safe_op,
        deadline: now().saturating_add(ns_to_ticks(deadline_ns)),
    };
    for (i, s) in TABLE.iter().enumerate() {
        let st = s.state.load(Ordering::Acquire);
        if st & 3 != FREE {
            continue;
        }
        let gen = st >> 2;
        if s.state.compare_exchange(st, gen << 2 | CLAIMED, Ordering::Acquire, Ordering::Relaxed).is_err() {
            continue;
        }
        s.deadline.store(w.deadline, Ordering::Relaxed);
        s.who.store(w.pack(), Ordering::Relaxed);
        s.op.store(safe_op as u64, Ordering::Relaxed);
        s.state.store(gen << 2 | ARMED, Ordering::Release);
        return Some(Ticket { slot: i, gen, w });
    }
    None
}

/// The effect was not issued after all (its record could not be committed):
/// take the watch down. A watch the sweep already took is the sweep's.
pub fn cancel(t: Ticket) {
    let s = &TABLE[t.slot];
    let _ = s.state.compare_exchange(t.gen << 2 | ARMED, (t.gen + 1) << 2 | FREE,
                                     Ordering::AcqRel, Ordering::Relaxed);
}

/// The device op returned. In time: the watch comes down and nothing is
/// recorded; returns `true`. Overdue: the miss is handled here unless the
/// sweep already did (one handler wins the slot), the device is driven to its
/// safe state AFTER the op, and `false` comes back.
pub fn complete(t: Ticket) -> bool {
    let s = &TABLE[t.slot];
    let armed = t.gen << 2 | ARMED;
    if now() <= t.w.deadline {
        if s.state.compare_exchange(armed, (t.gen + 1) << 2 | FREE, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return true;
        }
        // The sweep took it between the clock read and here: a miss it handled.
    } else if s.state.compare_exchange(armed, t.gen << 2 | DRIVING, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
        handle_miss(&t.w);
        s.state.store((t.gen + 1) << 2 | FREE, Ordering::Release);
        return false;
    }
    // Someone else handled the miss, possibly BEFORE this op's last write: the
    // op could have landed after the drive, so the device is driven again,
    // with no new record, and the minimum hold counts from this drive.
    hold(&t.w);
    drive_safe(&t.w);
    false
}

/// The system watchdog's pass: drive every device whose watched effect is
/// overdue at `now` (timer ticks) to its safe state. Returns how many.
/// Called from the watchdog's task, never from an interrupt.
pub fn sweep(now: u64) -> u32 {
    let mut n = 0;
    for s in TABLE.iter() {
        let st = s.state.load(Ordering::Acquire);
        if st & 3 != ARMED || now <= s.deadline.load(Ordering::Relaxed) {
            continue;
        }
        if s.state.compare_exchange(st, (st & !3) | DRIVING, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            continue;
        }
        let w = Watched::unpack(
            s.who.load(Ordering::Relaxed), s.op.load(Ordering::Relaxed),
            s.deadline.load(Ordering::Relaxed));
        handle_miss(&w);
        s.state.store(((st >> 2) + 1) << 2 | FREE, Ordering::Release);
        n += 1;
    }
    n
}

/// Effects being watched now (diagnostic, and the tests').
pub fn watching() -> usize {
    TABLE.iter().filter(|s| s.state.load(Ordering::Relaxed) & 3 != FREE).count()
}

/// Drive the device of `w` to its safe state. `false` when the kind has no
/// driver, or it refused.
fn drive_safe(w: &Watched) -> bool {
    match drivers(w.kind) {
        Some((f, _, _)) if w.safe_op != 0 => f(w.subject, w.safe_op),
        _ => false,
    }
}

/// A watched effect missed its deadline: hold the device, drive it, record.
/// Called by exactly one party per effect.
fn handle_miss(w: &Watched) {
    hold(w);
    let driven = drive_safe(w);
    azos_decision::record_receipt(
        Rule::SafeState,
        if driven { Verdict::Admit } else { Verdict::Refuse },
        w.device(),
        [STATE_COMMANDED, STATE_SAFE, (w.tid as u64) << 8 | CAUSE_DEADLINE],
    );
}

/// An effect asked for a device held in its safe state: refused. The receipt
/// is a `Rule::SafeState` record; 0 when decision records are off.
pub fn refuse_held(e: &Effect) -> u64 {
    azos_decision::record_receipt(
        Rule::SafeState,
        Verdict::Refuse,
        (e.kind as u32) << 16 | e.subject as u32,
        [STATE_SAFE, STATE_COMMANDED, (e.tid as u64) << 8 | CAUSE_HELD],
    )
}

/// Run the compensating op `op` of a reversible effect whose device op failed;
/// one `Rule::Compensation` record either way. `op` 0: the row declares no
/// inverse. Returns whether it ran.
pub fn compensate(e: &Effect, op: u8) -> bool {
    let (ran, status) = match drivers(e.kind) {
        _ if op == 0 => (false, COMP_NO_INVERSE),
        Some((_, f, _)) if f(e.subject, op) => (true, COMP_RAN),
        _ => (false, COMP_REFUSED),
    };
    azos_decision::record_receipt(
        Rule::Compensation,
        if ran { Verdict::Admit } else { Verdict::Refuse },
        e.tid,
        [(e.kind as u64) << 8 | e.class as u64, op as u64, status],
    );
    ran
}
