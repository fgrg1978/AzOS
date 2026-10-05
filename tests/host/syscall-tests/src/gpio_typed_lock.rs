// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The typed GPIO path: what it authorises, and *where* it touches hardware.
//
// `crates/core/ipc/src/gpio_cap.rs` used to call `azos_drv_gpio::gpio::*` from
// inside the closure `cap_store::with_table` runs while holding the task's
// cap-table `SpinLock`. `SpinLock::lock` disables preemption before it spins
// (`crates/core/sync/src/spinlock.rs`), so the driver transfer ran with preemption
// off, and nested the GPIO backend's own lock (`crates/drivers/gpio/src/gpio.rs:38`
// simulation, `:151` JH7110 MMIO) inside the cap-table one. The module now
// resolves the capability to a pin inside the closure and
// `crates/core/syscall/src/handlers.rs` calls the driver after `with_table` has
// returned.
//
// **The whole point of this file is that the behaviour did not change**, so
// most of it is the old contract restated where a host can check it: which
// permission each operation demands (both directions — a read that started
// demanding WRITE would be just as wrong as a write that stopped demanding
// it), the `BadPin` range check, RFC-0036 containment, the errno mapping, and
// the flight-recorder hook every refusal goes through. One test is new:
// `the_driver_is_not_called_while_the_cap_table_lock_is_held`.
//
// **How the new property is observed.** The driver stand-in
// (`shims/drivers`'s `gpio` module) takes an installable probe. The probe
// stands where the driver stands and asks, from a second thread, whether the
// caller's cap table can be locked. A thread that gets it immediately means
// the lock was free at the instant of the driver call; a thread still blocked
// after the timeout means it was not. The timeout is only reached in the
// failing direction — the passing direction answers in microseconds.

use super::harness::serial;
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use azos_ipc::cap::{targets::Gpio, Cap, CapPerms};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering::SeqCst};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

// ── Probe plumbing ────────────────────────────────────────────────────────

/// Every driver call the probe saw, in order: `(op, pin, arg)`.
static CALLS: Mutex<Vec<(GpioOp, u32, u32)>> = Mutex::new(Vec::new());
/// What the probe returns as the driver's return code.
static RC: AtomicI32 = AtomicI32::new(0);
/// Whether the probe should also sample the cap-table lock.
static OBSERVE: AtomicBool = AtomicBool::new(false);
/// The TID whose cap table the probe samples.
static OBS_TID: AtomicU32 = AtomicU32::new(0);
/// One entry per sampled driver call.
static OBSERVED: Mutex<Vec<LockObs>> = Mutex::new(Vec::new());

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockObs {
    /// The cap table locked immediately from another thread.
    Free,
    /// Still blocked after the timeout — someone up the stack holds it.
    Held,
    /// `with_table` returned `None`: the TID does not resolve to a slot. A
    /// wiring fault in the test, kept distinct from `Free`/`Held` so it can
    /// never be silently read as either.
    TidUnresolvable,
}

/// Is `tid`'s cap table lockable right now?
///
/// From a second thread, because the probe runs on a stack that may already
/// hold the lock — asking on this one would deadlock rather than answer.
fn observe_table_lock(tid: u32) -> LockObs {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let resolved = azos_ipc::cap_store::with_table(tid, |_t| ()).is_some();
        let _ = tx.send(resolved);
    });
    match rx.recv_timeout(Duration::from_millis(750)) {
        Ok(true) => LockObs::Free,
        Ok(false) => LockObs::TidUnresolvable,
        Err(_) => LockObs::Held,
    }
}

fn probe(op: GpioOp, pin: u32, arg: u32) -> i32 {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, pin, arg));
    if OBSERVE.load(SeqCst) {
        let obs = observe_table_lock(OBS_TID.load(SeqCst));
        OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).push(obs);
    }
    RC.load(SeqCst)
}

/// Installs the probe and guarantees its removal — including on a panicking
/// assertion. A probe left behind would turn every other GPIO stub in this
/// crate into a silent success, which is exactly what `src/lib.rs`'s
/// "`todo!()`, never a plausible return value" rule exists to prevent.
struct ProbeGuard;

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        set_gpio_probe(None);
        OBSERVE.store(false, SeqCst);
    }
}

fn arm(rc: i32) -> ProbeGuard {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    RC.store(rc, SeqCst);
    OBSERVE.store(false, SeqCst);
    set_gpio_probe(Some(probe));
    ProbeGuard
}

fn calls() -> Vec<(GpioOp, u32, u32)> {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn observed() -> Vec<LockObs> {
    OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// ── Caller identity ───────────────────────────────────────────────────────

/// Bind `tid` in the cap-store's task pool AND make it the current task.
///
/// Two task tables, and they are not the same one: `cap_store` resolves TIDs
/// through `shims/ipc_sched` (`ipc_task_pool` here), while the handler asks
/// `azos_sched::current_task_tid()`, this crate's own `shims/sched`. Same
/// reason, and the same shape, as `driver_server_guards.rs:636`.
/// The `user_pt` sentinel is set for the same reason and with the same caveat
/// as there: nothing on the typed path branches on it — these handlers have no
/// `cap_check` at all — so it is scene-setting, not a gate under test.
fn bind_typed_caller(tid: u32, slot: usize) {
    ipc_task_pool::shim_bind(tid, slot);
    azos_sched::set_current_task_tid(tid);
    azos_sched::set_current_user_pt(0x1000);
}

fn raw(cap: Cap<Gpio>) -> u64 {
    cap.raw().as_raw() as u64
}

/// Errno as the syscall returns it (negated).
fn err(e: azos_abi::error::Errno) -> i64 {
    e.to_syscall_ret()
}

// ── The permission demanded per operation, both directions ────────────────

/// READ authorises a read and nothing else.
///
/// The positive half is not decoration. A canary that only removes a
/// permission requirement is caught by the negative half; a resolver that
/// became *stricter* — `gpio_pin_for_read` asking for WRITE — is caught only
/// here. `driver_server_guards.rs:691` documents the same trap against
/// itself.
#[test]
fn a_read_only_capability_reads_and_cannot_write_or_set_direction() {
    use azos_abi::error::Errno;
    const TID: u32 = 6301;
    const PIN: u32 = 9;

    let _g = serial();
    let _p = arm(1);
    bind_typed_caller(TID, 40);
    let cap = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::READ)
        .expect("mint Cap<Gpio>(PIN) with READ");

    assert_eq!(
        sys_gpio_read_typed(raw(cap)),
        1,
        "a READ cap must still read"
    );
    assert_eq!(
        sys_gpio_write_typed(raw(cap), 1),
        err(Errno::ECAPPERMS),
        "a write through a READ-only cap must be refused"
    );
    assert_eq!(
        sys_gpio_set_dir_typed(raw(cap), 1),
        err(Errno::ECAPPERMS),
        "a direction change is a WRITE — a READ-only cap must not do it"
    );

    // And the two refusals never reached hardware.
    assert_eq!(calls(), vec![(GpioOp::Read, PIN, 0)]);
    ipc_task_pool::shim_kill(TID);
}

/// WRITE authorises a write and a direction change, and not a read.
#[test]
fn a_write_only_capability_writes_and_sets_direction_but_cannot_read() {
    use azos_abi::error::Errno;
    const TID: u32 = 6302;
    const PIN: u32 = 11;

    let _g = serial();
    let _p = arm(0);
    bind_typed_caller(TID, 41);
    let cap = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::WRITE)
        .expect("mint Cap<Gpio>(PIN) with WRITE");

    assert_eq!(sys_gpio_write_typed(raw(cap), 1), 0);
    assert_eq!(sys_gpio_set_dir_typed(raw(cap), 1), 0);
    assert_eq!(
        sys_gpio_read_typed(raw(cap)),
        err(Errno::ECAPPERMS),
        "a read through a WRITE-only cap must be refused"
    );

    assert_eq!(
        calls(),
        vec![(GpioOp::Write, PIN, 1), (GpioOp::SetDirection, PIN, 1)]
    );
    ipc_task_pool::shim_kill(TID);
}

/// The driver is told the pin the CAPABILITY names, and only the low bit of
/// the value — the argument is not a second channel to the hardware.
#[test]
fn the_driver_gets_the_pin_from_the_capability_and_the_low_bit_of_the_value() {
    const TID: u32 = 6303;
    const PIN: u32 = 23;

    let _g = serial();
    let _p = arm(0);
    bind_typed_caller(TID, 42);
    let cap = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::RW)
        .expect("mint");

    // 0xFFFF_FFFE is even: the low bit is 0, so the pin must be driven low.
    assert_eq!(sys_gpio_write_typed(raw(cap), 0xFFFF_FFFE), 0);
    assert_eq!(sys_gpio_set_dir_typed(raw(cap), 0), 0);

    assert_eq!(
        calls(),
        vec![(GpioOp::Write, PIN, 0), (GpioOp::SetDirection, PIN, 0)]
    );
    ipc_task_pool::shim_kill(TID);
}

// ── The range check, and the errno it owns ────────────────────────────────

/// A cap whose stored resource is out of range answers `EINVAL` and never
/// reaches the driver.
///
/// `gpio_grant_cap` refuses such a pin, so the cap is minted through
/// `cap_store::grant` directly — the corrupt-table / wrongly-granted-slot case
/// `GpioCapError::BadPin` exists for. The distinction that matters is
/// `EINVAL`, not merely "refused": both GPIO backends also reject an
/// out-of-range pin (`crates/drivers/gpio/src/gpio.rs:43`/`51`/`58`, `:175`/`:188`/
/// `:194`), so a range check moved out to the driver call site would still
/// fail closed — as `EIO`. This test is what pins which of the two the caller
/// sees.
#[test]
fn a_pin_outside_the_range_is_einval_and_never_reaches_the_driver() {
    use azos_abi::error::Errno;
    const TID: u32 = 6304;
    const BAD_PIN: u32 = 999;

    let _g = serial();
    let _p = arm(0);
    bind_typed_caller(TID, 43);
    let cap: Cap<Gpio> = azos_ipc::cap_store::grant::<Gpio>(TID, CapPerms::RW, BAD_PIN)
        .expect("mint an out-of-range Cap<Gpio> the way a corrupt table would");

    assert_eq!(sys_gpio_read_typed(raw(cap)), err(Errno::EINVAL));
    assert_eq!(sys_gpio_write_typed(raw(cap), 1), err(Errno::EINVAL));
    assert_eq!(sys_gpio_set_dir_typed(raw(cap), 1), err(Errno::EINVAL));
    assert_eq!(calls(), vec![], "an out-of-range pin must not reach hardware");

    ipc_task_pool::shim_kill(TID);
}

// ── Argument validation happens AFTER the capability is settled ───────────

/// A bad `dir` is `EINVAL` — but a caller without WRITE learns nothing about
/// its argument.
///
/// The order is capability, then pin range, then `dir`. Reversing it would
/// turn `sys_gpio_set_dir_typed` into an oracle: `EINVAL` vs `ECAPPERMS`
/// would tell an unauthorised caller which of its two mistakes it made.
#[test]
fn a_bad_direction_is_einval_but_the_capability_is_checked_first() {
    use azos_abi::error::Errno;
    const TID: u32 = 6305;
    const PIN: u32 = 4;

    let _g = serial();
    let _p = arm(0);
    bind_typed_caller(TID, 44);
    let writable = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::WRITE)
        .expect("mint WRITE");
    let readable = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::READ)
        .expect("mint READ");

    assert_eq!(
        sys_gpio_set_dir_typed(raw(writable), 2),
        err(Errno::EINVAL),
        "dir must be 0 or 1"
    );
    assert_eq!(
        sys_gpio_set_dir_typed(raw(readable), 2),
        err(Errno::ECAPPERMS),
        "the same bad dir through an unauthorised cap must answer the CAP error"
    );
    assert_eq!(calls(), vec![], "a rejected direction must not reach hardware");

    ipc_task_pool::shim_kill(TID);
}

/// A driver refusal is `EIO`, distinct from every capability errno.
#[test]
fn a_driver_refusal_is_eio() {
    use azos_abi::error::Errno;
    const TID: u32 = 6306;
    const PIN: u32 = 5;

    let _g = serial();
    let _p = arm(-1);
    bind_typed_caller(TID, 45);
    let cap = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::RW).expect("mint");

    assert_eq!(sys_gpio_read_typed(raw(cap)), err(Errno::EIO));
    assert_eq!(sys_gpio_write_typed(raw(cap), 1), err(Errno::EIO));
    assert_eq!(sys_gpio_set_dir_typed(raw(cap), 1), err(Errno::EIO));

    ipc_task_pool::shim_kill(TID);
}

// ── RFC-0036 containment, and the recorder ────────────────────────────────

/// Degraded mode denies the WRITE and leaves the READ live — and it is not
/// recorded as a capability denial.
///
/// The check lives inside `CapTable::get` (its step after `get_uncontained`), i.e.
/// on the inside half of the split, which is where it has to stay: it reads
/// the same `need` the permission check used. `Contained` is filtered by
/// `note_typed_denial`'s `is_denial()` guard, so one containment episode
/// cannot bury the recorder in its own traffic —
/// `cap_denial_record.rs:274` states the same rule for the motor family.
#[test]
fn containment_denies_the_write_keeps_the_read_and_records_nothing() {
    use azos_abi::error::Errno;
    const TID: u32 = 6307;
    const PIN: u32 = 6;

    let _g = serial();
    let _p = arm(1);
    bind_typed_caller(TID, 46);
    let cap = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::RW).expect("mint");

    arm_typed();

    azos_ipc::cap::degraded_set(true);
    let write = sys_gpio_write_typed(raw(cap), 1);
    let read = sys_gpio_read_typed(raw(cap));
    azos_ipc::cap::degraded_set(false);

    assert_eq!(write, err(Errno::EAGAIN), "containment must refuse the write");
    assert_eq!(read, 1, "containment must leave READ live");
    assert_eq!(
        calls(),
        vec![(GpioOp::Read, PIN, 0)],
        "the contained write must not have reached hardware"
    );
    assert_eq!(
        seen_typed(),
        Vec::new(),
        "containment of a capability HOLDER is the safety system working, not a denial"
    );

    ipc_task_pool::shim_kill(TID);
}

/// Every refused dereference still passes through `errno_for_gpio_err`, so it
/// still reaches the flight recorder.
///
/// This is the property the restructure could most easily have dropped in
/// silence: a handler that returned `EINVAL` on its own instead of routing the
/// `GpioCapError` through the mapper would answer plausibly and record
/// nothing, and no errno assertion above would notice.
#[test]
fn every_refused_dereference_reaches_the_recorder() {
    use azos_abi::error::Errno;
    const TID: u32 = 6308;
    const PIN: u32 = 7;

    let _g = serial();
    let _p = arm(0);
    bind_typed_caller(TID, 47);

    arm_typed();

    // Missing perms.
    let ro = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::READ).expect("mint");
    assert_eq!(sys_gpio_write_typed(raw(ro), 1), err(Errno::ECAPPERMS));
    // Stale: the null handle a caller passing 0 produces.
    assert_eq!(sys_gpio_read_typed(0), err(Errno::ECAPSTALE));
    // Wrong kind: a PWM slot reinterpreted as a GPIO cap.
    let pwm = azos_ipc::pwm_cap::pwm_grant_cap(TID, 1, CapPerms::RW).expect("mint Pwm");
    let disguised: Cap<Gpio> = Cap::from_raw(pwm.raw());
    assert_eq!(sys_gpio_read_typed(raw(disguised)), err(Errno::ECAPKIND));

    // GPIO is recorder code 2 — the same code the untyped path uses; the
    // reason codes are `CapError::code()`.
    assert_eq!(
        seen_typed(),
        vec![(2, 3), (2, 1), (2, 2)],
        "a refused typed GPIO dereference must still be recorded"
    );
    assert_eq!(calls(), vec![], "no refusal reached hardware");

    ipc_task_pool::shim_kill(TID);
}

/// Every typed denial this module's recorder saw: `(kind code, reason code)`.
static TYPED_SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason_code: u32) {
    TYPED_SEEN
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((kind_code, reason_code));
}

/// Clear the log and install this module's recorder.
fn arm_typed() {
    TYPED_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(typed_recorder);
}

fn seen_typed() -> Vec<(u8, u32)> {
    TYPED_SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// ── The new property ──────────────────────────────────────────────────────

/// **The driver is not called while the cap-table lock is held.**
///
/// The probe stands inside the driver and asks a second thread to lock the
/// caller's cap table. `Free` means the guard `cap_store::with_table` takes
/// had already been dropped when the hardware was touched.
///
/// The assertion that the driver was reached *at all* is half the test: with
/// the driver never called, "the lock was not held during the call" is
/// vacuously satisfiable.
///
/// **What this does NOT establish.** It says the cap-table `Mutex` was
/// lockable from another thread at the instant of the driver call. It does
/// not say preemption was enabled: this suite's `SpinLock` is a
/// `std::sync::Mutex` stand-in with no `PreemptGuard` and no interrupts to
/// disable (`tests/host/cap-tests/shims/sync/src/lib.rs:28`). That the real
/// `lock()` disables preemption is read from `crates/core/sync/src/spinlock.rs`,
/// not measured here.
///
/// **Canary.** Move the driver call back inside the `with_table` closure —
/// separately in each of the three handlers, because the three observations
/// below are three different instants and a red on one says nothing about the
/// others. Verified: read-only gives `[Held, Free, Free]`, write-only
/// `[Free, Held, Free]`, set-dir-only `[Free, Free, Held]`, and nothing else
/// in the crate notices any of them.
#[test]
fn the_driver_is_not_called_while_the_cap_table_lock_is_held() {
    const TID: u32 = 6309;
    const PIN: u32 = 12;

    let _g = serial();
    // `0` is both "the pin reads low" and "the driver accepted the write", so
    // all three operations succeed on one probe return code.
    let _p = arm(0);
    bind_typed_caller(TID, 48);
    let cap = azos_ipc::gpio_cap::gpio_grant_cap(TID, PIN, CapPerms::RW).expect("mint");

    OBS_TID.store(TID, SeqCst);
    OBSERVE.store(true, SeqCst);

    assert_eq!(sys_gpio_read_typed(raw(cap)), 0);
    assert_eq!(sys_gpio_write_typed(raw(cap), 1), 0);
    assert_eq!(sys_gpio_set_dir_typed(raw(cap), 1), 0);

    OBSERVE.store(false, SeqCst);

    assert_eq!(calls().len(), 3, "the driver was not reached — nothing was observed");
    assert_eq!(
        observed(),
        vec![LockObs::Free, LockObs::Free, LockObs::Free],
        "a driver call ran with the caller's cap-table lock held, so with \
         preemption disabled — see this test's canary note"
    );

    ipc_task_pool::shim_kill(TID);
}
