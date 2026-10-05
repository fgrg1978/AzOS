// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The guard properties of the untyped hardware calls, asserted through their
// typed twins.
//
// RFC-0040 gap 1 retires the untyped GPIO, PWM, I2C and sensor calls (200-202,
// 210-213, 220, 221, 332) from dispatch, and their handlers go with the host
// tests that reach them (`hw_cap_guards.rs`, `unit6_contain.rs`). Each property
// below was pinned only through an untyped call; it is asserted here through
// the typed call that stays:
//
// | property, and the untyped test that pinned it                              | here                                                          |
// |----------------------------------------------------------------------------|---------------------------------------------------------------|
// | a motor-bound PWM channel is refused to a holder                           | `typed_pwm_calls_refuse_a_motor_bound_channel_to_a_cap_holder` |
// |   (`the_untyped_pwm_syscalls_refuse_a_motor_bound_channel_to_a_cap_holder`) |                                                               |
// | a channel no motor claims gets past that guard                             | `a_typed_duty_on_a_channel_with_no_motor_reaches_the_driver`  |
// |   (`a_channel_with_no_motor_reaches_the_driver`)                           |                                                               |
// | PWM writes are contained, and live once cleared                            | `typed_pwm_writes_are_contained`,                             |
// |   (`pwm_writes_are_contained`, `pwm_*_reaches_the_driver_once_cleared`)    | `a_contained_typed_pwm_write_reaches_the_driver_once_cleared` |
// | kind, permission and instance of a PWM capability                          | `typed_pwm_calls_refuse_a_read_only_or_foreign_capability`    |
// |   (`pwm_*_refuses_a_capability_of_the_wrong_kind` / `_for_a_different_channel`) |                                                          |
// | a motor-bound direction pin is refused to a holder                         | `typed_gpio_writes_refuse_a_motor_bound_pin_to_a_cap_holder`  |
// |   (`the_motor_guards_keep_their_answer_while_contained`, GPIO half)        |                                                               |
// | an I2C holder is admitted                                                  | `a_typed_i2c_read_from_a_holder_reaches_the_driver`           |
// |   (`i2c_read_a_capability_holder_is_admitted_and_reaches_the_pointer_guard`) |                                                             |
// | I2C instance, permission, containment and the argument check               | `typed_i2c_calls_answer_for_the_capability_they_resolve`      |
// |   (`i2c_read_refuses_a_capability_for_a_different_bus_or_address`,         |                                                               |
// |    `i2c_write_refuses_a_read_only_capability`,                             |                                                               |
// |    `i2c_write_is_contained_after_its_argument_check`)                      |                                                               |
// | a sensor holder is admitted; kind and permission                           | `typed_sensor_read_answers_for_the_capability_it_resolves`    |
// |   (`sensor_read_a_capability_holder_is_admitted_and_reaches_the_match`,    |                                                               |
// |    `sensor_read_refuses_a_capability_of_the_wrong_kind` / `_for_a_different_sensor_type`) |                                     |
//
// The GPIO permission and containment half already has typed tests
// (`gpio_typed_lock.rs`), the driver registry its own (`driver_server_guards.rs`,
// `driver_register_is_contained_and_unregister_is_live`), and the motor calls
// theirs (`unit6_contain.rs`, `motor_angle_gate.rs`).
//
// **One difference the table does not show.** The typed GPIO write resolves its
// capability, containment included, before the motor-bound guard, so a
// contained holder of a motor pin is answered `-EAGAIN` where the untyped call
// answered `E_PERM`. Both refuse and neither reaches the driver.
//
// **How "admitted" is observed.** The typed GPIO calls reach the driver through
// `handlers.rs`, so the GPIO probe sees them. The typed PWM and I2C operations
// reach it inside `crates/core/ipc` (`pwm_cap.rs`, `i2c_cap.rs`), which this crate
// builds against `shims/ipc_drivers`, where every entry is the MMIO stand-in's
// `todo!()`. So for those an admitted call panics, a refused one returns its
// errno, and the admitted halves are `#[should_panic]` tests.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_abi::error::Errno;
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use azos_ipc::cap::targets;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// The cap-store pool slot the callers here are bound to. 11-13, 20-23, 40-48
/// and 51-60 are taken by other files in this crate.
const SLOT: usize = 61;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7b00_0001);

/// Puts back every process static a test here can touch, panic or not.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        azos_ipc::cap::degraded_set(false);
        set_gpio_probe(None);
        azos_robot::motor::shim_clear_motor_channels();
        azos_robot::motor::shim_clear_motor_pins();
        azos_ipc::cap_store::reset(self.tid);
        ipc_task_pool::shim_kill(self.tid);
    }
}

/// A fresh ring-3 caller with an empty capability table. Two task tables:
/// `cap_store` resolves TIDs through `ipc_task_pool`, the handlers ask this
/// crate's `shims/sched` (see `gpio_typed_lock.rs`). The typed calls have no
/// kernel bypass, so `user_pt` only matters where a handler copies user memory;
/// a test that copies sets it itself.
fn caller() -> Scene {
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_task_tid(tid);
    azos_sched::set_current_user_pt(0x1000);
    Scene { tid }
}

/// A capability minted straight into `tid`'s table, as the raw handle a
/// syscall takes.
fn grant<T: azos_ipc::cap::CapTarget>(tid: u32, perms: CapPerms, resource: u32) -> u64 {
    azos_ipc::cap_store::grant::<T>(tid, perms, resource)
        .expect("capability table full")
        .raw()
        .as_raw() as u64
}

fn err(e: Errno) -> i64 {
    e.to_syscall_ret()
}

// ── The GPIO probe ────────────────────────────────────────────────────────

static GPIO_CALLS: Mutex<Vec<(GpioOp, u32, u32)>> = Mutex::new(Vec::new());

fn gpio_probe(op: GpioOp, pin: u32, arg: u32) -> i32 {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, pin, arg));
    0
}

fn gpio_calls() -> Vec<(GpioOp, u32, u32)> {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn install_gpio_probe() {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_gpio_probe(Some(gpio_probe));
}

/// The five typed PWM writes on `cap`, named.
fn every_pwm_write(cap: u64) -> [(&'static str, i64); 5] {
    [
        ("enable", sys_pwm_enable_typed(cap)),
        ("disable", sys_pwm_disable_typed(cap)),
        ("set_period", sys_pwm_set_period_typed(cap, 20_000_000)),
        ("set_duty", sys_pwm_set_duty_typed(cap, 500)),
        ("set_duty_pct", sys_pwm_set_duty_pct_typed(cap, 50)),
    ]
}

// ── PWM ───────────────────────────────────────────────────────────────────

/// **A PWM channel bound to a motor is refused to a caller holding its
/// capability**, through all five typed writes. The grant is the point: a
/// caller holding nothing is refused anyway. A write that got past the guard
/// would reach the MMIO stand-in and panic, so `E_PERM` from each is the whole
/// assertion.
///
/// **Canary.** Delete `if blocked { return E_PERM; }` from
/// `sys_pwm_dispatch_inner`: the enable reaches the stand-in and the test
/// panics.
#[test]
fn typed_pwm_calls_refuse_a_motor_bound_channel_to_a_cap_holder() {
    const MOTOR_CH: u32 = 2;
    let _g = serial();
    let s = caller();
    azos_robot::motor::shim_bind_motor_channel(MOTOR_CH);
    let cap = grant::<targets::Pwm>(s.tid, CapPerms::RW, MOTOR_CH);

    for (name, r) in every_pwm_write(cap) {
        assert_eq!(r, E_PERM, "{name} on a motor-bound channel");
    }
}

/// **A channel no motor claims gets past the guard.** With no probe the duty
/// write reaches the MMIO stand-in, so the panic is the assertion that the
/// call was admitted.
///
/// **Canary.** Make `pwm_channel_is_motor_bound` answer `true`: the call
/// returns `E_PERM` and does not panic.
#[test]
#[should_panic(expected = "MMIO stand-in")]
fn a_typed_duty_on_a_channel_with_no_motor_reaches_the_driver() {
    const FREE_CH: u32 = 5;
    let _g = serial();
    let s = caller();
    azos_robot::motor::shim_clear_motor_channels();
    let cap = grant::<targets::Pwm>(s.tid, CapPerms::RW, FREE_CH);
    let r = sys_pwm_set_duty_typed(cap, 500);
    panic!("the duty write did not reach the driver: returned {r}");
}

/// **The five typed PWM writes are contained.** Each answers `-EAGAIN` from a
/// holder of a free channel while degraded mode is contained; a write past
/// containment would reach the MMIO stand-in and panic.
///
/// **Canary.** Resolve with `get_uncontained` in `sys_pwm_dispatch_inner` and
/// `pwm_cap::resolve_channel`: the contained enable reaches the stand-in and
/// the test panics.
#[test]
fn typed_pwm_writes_are_contained() {
    let _g = serial();
    let s = caller();
    azos_robot::motor::shim_clear_motor_channels();
    let cap = grant::<targets::Pwm>(s.tid, CapPerms::RW, 3);

    azos_ipc::cap::degraded_set(true);
    for (name, r) in every_pwm_write(cap) {
        assert_eq!(r, err(Errno::EAGAIN), "{name} while contained");
    }
}

/// **The same holder's write is live once containment clears**: contained it
/// answers `-EAGAIN`, cleared it reaches the MMIO stand-in, whose panic is the
/// assertion.
///
/// **Canary.** Refuse every PWM write in `sys_pwm_dispatch_inner`: the cleared
/// enable returns and nothing panics.
#[test]
#[should_panic(expected = "MMIO stand-in")]
fn a_contained_typed_pwm_write_reaches_the_driver_once_cleared() {
    let _g = serial();
    let s = caller();
    azos_robot::motor::shim_clear_motor_channels();
    let cap = grant::<targets::Pwm>(s.tid, CapPerms::RW, 3);

    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_pwm_enable_typed(cap), err(Errno::EAGAIN), "not refused while contained");
    azos_ipc::cap::degraded_set(false);
    let r = sys_pwm_enable_typed(cap);
    panic!("the cleared enable did not reach the driver: returned {r}");
}

/// **A PWM capability answers for its kind and its permission.** A READ-only
/// capability, a GPIO capability and the forged handle are refused with their
/// errno; an admitted call would panic in the MMIO stand-in instead.
///
/// **Canary.** Resolve with `READ` in `pwm_cap::resolve_channel` and in
/// `sys_pwm_dispatch_inner`: the READ-only enable reaches the stand-in and the
/// test panics.
#[test]
fn typed_pwm_calls_refuse_a_read_only_or_foreign_capability() {
    let _g = serial();
    let s = caller();
    azos_robot::motor::shim_clear_motor_channels();
    let read_only = grant::<targets::Pwm>(s.tid, CapPerms::READ, 3);
    let gpio = grant::<targets::Gpio>(s.tid, CapPerms::RW, 3);

    assert_eq!(sys_pwm_enable_typed(read_only), err(Errno::ECAPPERMS), "READ-only enable");
    assert_eq!(sys_pwm_set_duty_pct_typed(read_only, 50), err(Errno::ECAPPERMS), "READ-only duty");
    assert_eq!(sys_pwm_enable_typed(gpio), err(Errno::ECAPKIND), "a GPIO capability");
    assert_eq!(sys_pwm_enable_typed(0), err(Errno::ECAPSTALE), "the forged handle");
}

// ── GPIO ──────────────────────────────────────────────────────────────────

/// **A motor's direction pin is refused to a caller holding its capability**,
/// write and set-direction, contained or not; the driver sees nothing. Not
/// contained the guard answers `E_PERM`; contained the capability is refused
/// first with `-EAGAIN` (see the module note).
///
/// **Canary.** Delete `if gpio_pin_is_motor_bound(pin) { return E_PERM; }` from
/// `sys_gpio_write_typed`: the uncontained write reaches the probe.
#[test]
fn typed_gpio_writes_refuse_a_motor_bound_pin_to_a_cap_holder() {
    const MOTOR_PIN: u32 = 6;
    let _g = serial();
    let s = caller();
    install_gpio_probe();
    azos_robot::motor::shim_bind_motor_pin(MOTOR_PIN);
    let cap = grant::<targets::Gpio>(s.tid, CapPerms::RW, MOTOR_PIN);

    assert_eq!(sys_gpio_write_typed(cap, 1), E_PERM, "write");
    assert_eq!(sys_gpio_set_dir_typed(cap, 1), E_PERM, "set_dir");
    azos_ipc::cap::degraded_set(true);
    assert_eq!(sys_gpio_write_typed(cap, 1), err(Errno::EAGAIN), "write while contained");
    assert_eq!(sys_gpio_set_dir_typed(cap, 1), err(Errno::EAGAIN), "set_dir while contained");
    assert!(gpio_calls().is_empty(), "the GPIO driver saw {:?}", gpio_calls());
}

// ── I2C ───────────────────────────────────────────────────────────────────

/// **A holder of `(bus, addr)` with READ is admitted.** The read reaches the
/// I2C stand-in, which panics: the panic is the assertion.
///
/// **Canary.** Ask `WRITE` in `i2c_cap::i2c_read_cap`: the call returns
/// `-ECAPPERMS` and does not panic.
#[test]
#[should_panic(expected = "MMIO stand-in")]
fn a_typed_i2c_read_from_a_holder_reaches_the_driver() {
    let _g = serial();
    let s = caller();
    let cap = azos_ipc::i2c_cap::i2c_grant_cap(s.tid, 0, 0x40, CapPerms::READ).expect("mint");
    let r = sys_i2c_read_typed(cap.raw().as_raw() as u64, 0, 0x1000, 4);
    panic!("the holder's read did not reach the driver: returned {r}");
}

/// **An I2C capability answers for its permission, its kind and containment,
/// after the argument check.** A READ capability does not write; a GPIO
/// capability does not read; a contained write is `-EAGAIN`; a zero length is
/// `-EINVAL` whatever the handle. None of them reaches the driver (which would
/// panic). Kernel context for the writes, so the handler copies from a host
/// buffer: the typed calls have no kernel bypass.
///
/// **Canary.** Resolve with `get_uncontained` in `i2c_cap::i2c_write_cap`: the
/// contained write reaches the stand-in and the test panics.
#[test]
fn typed_i2c_calls_answer_for_the_capability_they_resolve() {
    let _g = serial();
    let s = caller();
    let read_only = azos_ipc::i2c_cap::i2c_grant_cap(s.tid, 0, 0x40, CapPerms::READ).expect("mint");
    let rw = azos_ipc::i2c_cap::i2c_grant_cap(s.tid, 0, 0x41, CapPerms::RW).expect("mint");
    let gpio = grant::<targets::Gpio>(s.tid, CapPerms::RW, 0x40);
    let data = [0x10u8, 0x20];

    azos_sched::set_current_user_pt(0);
    assert_eq!(
        sys_i2c_write_typed(read_only.raw().as_raw() as u64, data.as_ptr() as u64, 2),
        err(Errno::ECAPPERMS),
        "a READ capability wrote"
    );
    azos_ipc::cap::degraded_set(true);
    assert_eq!(
        sys_i2c_write_typed(rw.raw().as_raw() as u64, data.as_ptr() as u64, 2),
        err(Errno::EAGAIN),
        "a contained write"
    );
    azos_ipc::cap::degraded_set(false);
    azos_sched::set_current_user_pt(0x1000);
    assert_eq!(sys_i2c_read_typed(gpio, 0, 0x1000, 4), err(Errno::ECAPKIND), "a GPIO capability read");
    assert_eq!(sys_i2c_read_typed(0, 0, 0x1000, 4), err(Errno::ECAPSTALE), "the forged handle");
    assert_eq!(sys_i2c_read_typed(0, 0, 0x1000, 0), err(Errno::EINVAL), "the argument check answers first");
}

// ── Sensor ────────────────────────────────────────────────────────────────

/// **A sensor capability answers for its kind and its permission, and a
/// holder is admitted.** A READ capability for the range sensor gets past the
/// capability to the dispatch, whose null-buffer guard answers `-1` before any
/// driver; a WRITE-only one, a GPIO one and the forged handle are refused with
/// their errno.
///
/// **Canary.** Ask `WRITE` in `sensor_cap::sensor_type_of`: the holder's read
/// reads `-ECAPPERMS`.
#[test]
fn typed_sensor_read_answers_for_the_capability_it_resolves() {
    const RANGE: u32 = 3;
    let _g = serial();
    let s = caller();
    let read = grant::<targets::Sensor>(s.tid, CapPerms::READ, RANGE);
    let write_only = grant::<targets::Sensor>(s.tid, CapPerms::WRITE, RANGE);
    let gpio = grant::<targets::Gpio>(s.tid, CapPerms::RW, RANGE);

    assert_eq!(sys_sensor_read_typed(read, 0, 4), -1, "the holder was not admitted");
    assert_eq!(sys_sensor_read_typed(write_only, 0, 4), err(Errno::ECAPPERMS), "WRITE-only");
    assert_eq!(sys_sensor_read_typed(gpio, 0, 4), err(Errno::ECAPKIND), "a GPIO capability");
    assert_eq!(sys_sensor_read_typed(0, 0, 4), err(Errno::ECAPSTALE), "the forged handle");
}
