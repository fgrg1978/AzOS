// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `Gpio`, `I2c` and `Pwm` interfaces the kernel hosts
// (D6 part A) -- `crates/core/syscall/src/devices.rs`, and
// `crates/core/syscall/src/khost.rs::serve` in front of them. They are the
// typed calls' tests restated for the endpoint op: which op class each op
// demands (both directions: a read that started demanding WRITE is as wrong as
// a write that stopped demanding it), the resource the badge names and its
// range, the motor guards (a pin or a channel a wheel uses is refused to a
// holder), containment, and that a refusal reaches the flight recorder while
// containment does not.
//
// Included inside `mod handlers { .. }`, like `entropy_guards.rs`, and
// driven through the servers directly: the `Caller` carries what the kernel
// reads off the capability (badge and rights), so a test states the
// capability's content instead of minting one.
//
// "Admitted" is observed at the driver: the stand-ins in `shims/drivers` take
// a probe (`set_gpio_probe`, `set_pwm_probe`, `set_i2c_*_probe`) that records
// every call, so "refused before the driver was touched" is asserted.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::i2c::{self, Bytes};
use azos_devif::{gpio, key, outcome, Gpio, GpioIdl, I2c, Out, Pwm};
use azos_drv_actuator::pwm::{set_pwm_probe, PwmOp};
use azos_drv_bus::i2c::{set_i2c_detect_probe, set_i2c_read_probe, set_i2c_write_probe};
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use azos_idl::{header, MsgDesc, Writer, MSG_VERSION};
use crate::devices::{GpioServer, I2cServer, PwmServer};
use crate::khost::Caller;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering::SeqCst};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

/// Cap-store pool slot for this file; no other file in this crate binds 46.
const SLOT: usize = 46;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e46_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, SeqCst)
}

// ── Probe plumbing ────────────────────────────────────────────────────────

/// Every driver call, in order: `(what, resource, arg)`.
static CALLS: Mutex<Vec<(&'static str, u32, u32)>> = Mutex::new(Vec::new());
/// The driver's return code for GPIO and PWM calls.
static RC: AtomicI32 = AtomicI32::new(0);
/// Sample the caller's cap-table lock at each driver call?
static OBSERVE: AtomicBool = AtomicBool::new(false);
static OBS_TID: AtomicU32 = AtomicU32::new(0);
static OBSERVED: Mutex<Vec<LockObs>> = Mutex::new(Vec::new());
/// `(kind code, reason code)` of every typed capability denial recorded.
static DENIALS: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockObs {
    Free,
    Held,
    TidUnresolvable,
}

/// Is `tid`'s cap table lockable right now? From a second thread: the probe
/// runs on a stack that may already hold the lock, and asking on this one
/// would deadlock rather than answer.
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

fn note(what: &'static str, res: u32, arg: u32) {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((what, res, arg));
    if OBSERVE.load(SeqCst) {
        let o = observe_table_lock(OBS_TID.load(SeqCst));
        OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).push(o);
    }
}

fn gpio_probe(op: GpioOp, pin: u32, arg: u32) -> i32 {
    note(
        match op {
            GpioOp::Read => "gpio.read",
            GpioOp::Write => "gpio.write",
            GpioOp::SetDirection => "gpio.dir",
        },
        pin,
        arg,
    );
    // `RC` is the level a read answers; a write or a direction change
    // succeeds unless `RC` is negative (a driver fault).
    let rc = RC.load(SeqCst);
    if op == GpioOp::Read || rc < 0 { rc } else { 0 }
}

fn pwm_probe(op: PwmOp, ch: u32, arg: u32) -> i32 {
    note(
        match op {
            PwmOp::Enable => "pwm.enable",
            PwmOp::Disable => "pwm.disable",
            PwmOp::SetPeriod => "pwm.period",
            PwmOp::SetDuty => "pwm.duty",
            PwmOp::SetDutyPct => "pwm.pct",
        },
        ch,
        arg,
    );
    RC.load(SeqCst)
}

fn i2c_read_probe(bus: u8, addr: u8, reg: u8, buf: &mut [u8]) -> i32 {
    note("i2c.read", i2c::badge(bus, addr), reg as u32);
    if RC.load(SeqCst) < 0 {
        return -1;
    }
    for (i, b) in buf.iter_mut().enumerate() {
        *b = reg.wrapping_add(i as u8);
    }
    buf.len() as i32
}

fn i2c_write_probe(bus: u8, addr: u8, data: &[u8]) -> i32 {
    note("i2c.write", i2c::badge(bus, addr), data.len() as u32);
    RC.load(SeqCst)
}

fn i2c_detect_probe(bus: u8, addr: u8) -> bool {
    note("i2c.detect", i2c::badge(bus, addr), 0);
    addr == 0x68
}

fn typed_recorder(kind_code: u8, reason_code: u32) {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

fn calls() -> Vec<(&'static str, u32, u32)> {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn denials() -> Vec<(u8, u32)> {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A caller with an empty table, the probes armed and nothing recorded, and
/// no motor bound to a channel or a pin. Dropping it disarms the probes.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        set_gpio_probe(None);
        set_pwm_probe(None);
        set_i2c_read_probe(None);
        set_i2c_write_probe(None);
        set_i2c_detect_probe(None);
        azos_ipc::cap::degraded_set(false);
        azos_robot::motor::shim_clear_motor_channels();
        azos_robot::motor::shim_clear_motor_pins();
        OBSERVE.store(false, SeqCst);
        ipc_task_pool::shim_kill(self.tid);
    }
}

fn scene(rc: i32) -> Scene {
    CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    RC.store(rc, SeqCst);
    set_gpio_probe(Some(gpio_probe));
    set_pwm_probe(Some(pwm_probe));
    set_i2c_read_probe(Some(i2c_read_probe));
    set_i2c_write_probe(Some(i2c_write_probe));
    set_i2c_detect_probe(Some(i2c_detect_probe));
    azos_robot::motor::shim_clear_motor_channels();
    azos_robot::motor::shim_clear_motor_pins();
    let tid = fresh_tid();
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
    set_cap_deny_typed_recorder(typed_recorder);
    Scene { tid }
}

fn caller(s: &Scene, badge: u32, rights: CapPerms) -> Caller {
    Caller { tid: s.tid, badge, rights }
}

/// Endpoint's recorder code: the refusal of a kernel-hosted op is recorded
/// under the endpoint, with the reason (`CapError::MissingPerms` = 3).
const ENDPOINT_CODE: u8 = azos_abi::cap::ty::ENDPOINT.denial_code();
const MISSING_PERMS: u32 = 3;

// ── Gpio ──────────────────────────────────────────────────────────────────

/// `READ` reads and nothing else; `WRITE` drives and sets the direction and
/// cannot read. Each refusal answers `DENIED` before the driver.
///
/// **Canary.** Ask `WRITE` of `read` (or `READ` of `write`): the matching line
/// fails.
#[test]
fn a_gpio_endpoint_demands_the_op_class_in_both_directions() {
    let _g = serial();
    let s = scene(1);
    let mut ro = GpioServer(caller(&s, 6, CapPerms::READ));
    assert_eq!(ro.read(), Out::ok(1));
    assert_eq!(ro.write(1), Out::err(outcome::DENIED));
    assert_eq!(ro.set_dir(gpio::DIR_OUTPUT), Out::err(outcome::DENIED));
    assert_eq!(calls(), vec![("gpio.read", 6, 0)], "only the read reached the driver");

    CALLS.lock().unwrap().clear();
    let mut wo = GpioServer(caller(&s, 6, CapPerms::WRITE));
    assert_eq!(wo.write(1), Out::ok(()));
    assert_eq!(wo.set_dir(gpio::DIR_OUTPUT), Out::ok(()));
    assert_eq!(wo.read(), Out::err(outcome::DENIED));
    assert_eq!(calls(), vec![("gpio.write", 6, 1), ("gpio.dir", 6, 1)]);
}

/// The driver is told the pin the badge names and the low bit of the level.
///
/// **Canary.** Pass `level` unmasked: the driver sees 3.
#[test]
fn the_driver_gets_the_pin_from_the_badge_and_the_low_bit_of_the_level() {
    let _g = serial();
    let s = scene(0);
    let mut g = GpioServer(caller(&s, 17, CapPerms::RW));
    assert_eq!(g.write(3), Out::ok(()));
    assert_eq!(g.write(2), Out::ok(()));
    assert_eq!(g.set_dir(gpio::DIR_INPUT), Out::ok(()));
    assert_eq!(calls(), vec![("gpio.write", 17, 1), ("gpio.write", 17, 0), ("gpio.dir", 17, 0)]);
}

/// A pin the board does not have is `BAD_ARGUMENT` and never reaches the
/// driver; a bad direction is `BAD_ARGUMENT` too, but the op class is checked
/// first, so a caller without `WRITE` learns nothing about its argument.
///
/// **Canary.** Move the range check after the driver call: the driver sees
/// pin 64.
#[test]
fn a_pin_out_of_range_and_a_bad_direction_never_reach_the_driver() {
    let _g = serial();
    let s = scene(0);
    let mut g = GpioServer(caller(&s, 64, CapPerms::RW));
    assert_eq!(g.read(), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(g.write(1), Out::err(outcome::BAD_ARGUMENT));
    let mut ok = GpioServer(caller(&s, 3, CapPerms::RW));
    assert_eq!(ok.set_dir(2), Out::err(outcome::BAD_ARGUMENT));
    let mut ro = GpioServer(caller(&s, 3, CapPerms::READ));
    assert_eq!(ro.set_dir(2), Out::err(outcome::DENIED), "the class is checked before the argument");
    assert_eq!(calls(), vec![]);
}

/// A driver refusal is `FAULT`, for a read as for a write.
#[test]
fn a_gpio_driver_fault_is_fault() {
    let _g = serial();
    let s = scene(-5);
    let mut g = GpioServer(caller(&s, 3, CapPerms::RW));
    assert_eq!(g.read(), Out::err(outcome::FAULT));
    assert_eq!(g.write(1), Out::err(outcome::FAULT));
    assert_eq!(g.set_dir(gpio::DIR_OUTPUT), Out::err(outcome::FAULT));
}

/// **A direction pin of a motor is not reachable here**: a holder of the pin's
/// endpoint is refused `write` and `set_dir`, and the driver sees nothing.
/// Reading it is observation and stays open.
///
/// **Canary.** Delete the `gpio_pin_is_motor_bound` checks: the writes reach
/// the driver.
#[test]
fn a_motor_direction_pin_is_refused_to_a_holder_of_its_endpoint() {
    let _g = serial();
    let s = scene(0);
    azos_robot::motor::shim_bind_motor_pin(2);
    let mut g = GpioServer(caller(&s, 2, CapPerms::RW));
    assert_eq!(g.write(1), Out::err(outcome::REFUSED));
    assert_eq!(g.set_dir(gpio::DIR_OUTPUT), Out::err(outcome::REFUSED));
    assert_eq!(calls(), vec![]);
    assert_eq!(g.read(), Out::ok(0));
    let mut other = GpioServer(caller(&s, 3, CapPerms::RW));
    assert_eq!(other.write(1), Out::ok(()), "a pin no motor claims is not refused");
}

/// Containment (brain-triggered degraded mode) refuses the acting ops of a holder, leaves the read
/// live, and records nothing: a holder contained is the safety system
/// working, not a denial.
///
/// **Canary.** Ignore containment in `Caller::allows`: the contained write
/// reaches the driver.
#[test]
fn containment_denies_the_write_keeps_the_read_and_records_nothing() {
    let _g = serial();
    let s = scene(1);
    let mut g = GpioServer(caller(&s, 6, CapPerms::RW));
    azos_ipc::cap::degraded_set(true);
    let write = g.write(1);
    let read = g.read();
    azos_ipc::cap::degraded_set(false);
    assert_eq!(write, Out::err(outcome::DENIED));
    assert_eq!(read, Out::ok(1));
    assert_eq!(calls(), vec![("gpio.read", 6, 0)]);
    assert_eq!(denials(), vec![]);
}

/// **A refusal is recorded**, once per refused op, under the endpoint kind with
/// the reason: the flight recorder's "capability denied" record the typed
/// calls wrote. A refusal that answered plausibly and recorded nothing would
/// pass every assertion above.
///
/// **Canary.** Return from `Caller::gate` without `deny`: the list is empty.
#[test]
fn every_refused_op_reaches_the_recorder() {
    let _g = serial();
    let s = scene(0);
    let mut ro = GpioServer(caller(&s, 7, CapPerms::READ));
    assert_eq!(ro.write(1), Out::err(outcome::DENIED));
    let none = GpioServer(caller(&s, 7, CapPerms::NONE));
    assert_eq!(none.read(), Out::err(outcome::DENIED));
    assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS), (ENDPOINT_CODE, MISSING_PERMS)]);
    assert_eq!(calls(), vec![]);
}

/// The wire: a request in the IDL's form, served through `khost::serve` by
/// host key, in both the message form and the register form (four words).
///
/// **Canary.** Route `key::GPIO` to the wrong arm: the status word is not 0.
#[test]
fn gpio_is_served_through_its_host_key_in_both_forms() {
    let _g = serial();
    let s = scene(0);
    let who = caller(&s, 9, CapPerms::RW);
    let mut req = MsgDesc { version: MSG_VERSION, ..MsgDesc::default() };
    {
        let mut w = Writer::new(&mut req);
        w.word(header(GpioIdl::ID, GpioIdl::LEVEL, GpioIdl::OP_WRITE));
        w.word(1);
        w.finish();
    }
    let mut rep = MsgDesc::default();
    crate::khost::serve(key::GPIO, &who, &req, &mut rep);
    assert_eq!((rep.words[0], rep.words[1] as u32), (azos_idl::STATUS_OK, outcome::OK));
    let regs = crate::khost::serve_regs(key::GPIO, &who, [req.words[0], 0, 0, 0]);
    assert_eq!((regs[0], regs[1] as u32), (azos_idl::STATUS_OK, outcome::OK));
    assert_eq!(calls(), vec![("gpio.write", 9, 1), ("gpio.write", 9, 0)]);
}

/// **The driver is not called while the caller's cap-table lock is held**: a
/// capability table is read under its lock to learn the badge and the rights,
/// and the lock is released before the op touches hardware (a driver transfer
/// under a preemption-disabling lock would nest the driver's own).
///
/// The probe stands inside the driver and asks a second thread to lock the
/// caller's table; the call also has to REACH the driver, or "not held during
/// the call" is vacuous.
///
/// **Canary.** Run the op inside `cap_store::read_table`'s closure in
/// `khost::caller`: the observation reads `Held`.
#[test]
fn the_driver_is_not_called_while_the_cap_table_lock_is_held() {
    let _g = serial();
    let s = scene(0);
    let cap = azos_ipc::endpoint::kernel_endpoint_cap(s.tid, CapPerms::RW, key::GPIO, 12).expect("grant");
    let who = crate::khost::caller(s.tid, cap.raw().0).expect("the capability resolves");
    assert_eq!((who.badge, who.rights), (12, CapPerms::RW));

    OBS_TID.store(s.tid, SeqCst);
    OBSERVE.store(true, SeqCst);
    let mut g = GpioServer(who);
    assert_eq!(g.read(), Out::ok(0));
    assert_eq!(g.write(1), Out::ok(()));
    assert_eq!(g.set_dir(gpio::DIR_OUTPUT), Out::ok(()));
    OBSERVE.store(false, SeqCst);

    assert_eq!(calls().len(), 3, "the driver was not reached: nothing was observed");
    assert_eq!(observed(), vec![LockObs::Free; 3], "a driver call ran with the caller's cap-table lock held");
}

fn observed() -> Vec<LockObs> {
    OBSERVED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

// ── I2c ───────────────────────────────────────────────────────────────────

/// The badge is `bus << 8 | address`, and the driver is told exactly that bus,
/// that address and that register: a capability for the IMU cannot talk to
/// anything else on the bus.
///
/// **Canary.** Swap the halves in `unbadge`: the driver sees address 0.
#[test]
fn the_i2c_badge_names_the_device_and_the_register_travels_in_the_call() {
    let _g = serial();
    let s = scene(0);
    let mut d = I2cServer(caller(&s, i2c::badge(1, 0x40), CapPerms::READ));
    let r = d.read(0x75, 4);
    assert!(r.is_ok());
    let mut got = [0u8; 4];
    assert_eq!(r.value.copy_to(&mut got), 4);
    assert_eq!(got, [0x75, 0x76, 0x77, 0x78], "the bytes the driver filled arrive in order");
    assert_eq!(calls(), vec![("i2c.read", i2c::badge(1, 0x40), 0x75)]);
}

/// Reads need `READ`, writes `WRITE`, the probe `READ`; the lengths and the
/// register are checked after the class and before the bus.
///
/// **Canary.** Allow `len == 0`: the zero-length read reaches the bus. Check
/// `reg` as `u8` after the cast: register 0x175 reads register 0x75.
#[test]
fn i2c_classes_and_argument_bounds() {
    let _g = serial();
    let s = scene(0);
    let mut ro = I2cServer(caller(&s, i2c::badge(0, 0x68), CapPerms::READ));
    assert_eq!(ro.write(Bytes::from_slice(&[0x6B, 0])), Out::err(outcome::DENIED));
    assert_eq!(ro.detect(), Out::ok(1));
    assert_eq!(ro.read(0x100, 1).code, outcome::BAD_ARGUMENT);
    assert_eq!(ro.read(0, 0).code, outcome::BAD_ARGUMENT);
    assert_eq!(ro.read(0, i2c::MAX_BYTES as u32 + 1).code, outcome::BAD_ARGUMENT);
    assert!(ro.read(0, i2c::MAX_BYTES as u32).is_ok());
    assert_eq!(calls(), vec![("i2c.detect", i2c::badge(0, 0x68), 0), ("i2c.read", i2c::badge(0, 0x68), 0)]);

    CALLS.lock().unwrap().clear();
    let mut wo = I2cServer(caller(&s, i2c::badge(0, 0x68), CapPerms::WRITE));
    assert_eq!(wo.read(0, 1).code, outcome::DENIED);
    assert_eq!(wo.detect().code, outcome::DENIED);
    assert_eq!(wo.write(Bytes::default()).code, outcome::BAD_ARGUMENT, "an empty write is not a transfer");
    assert!(wo.write(Bytes::from_slice(&[0x6B, 0, 1])).is_ok());
    assert_eq!(calls(), vec![("i2c.write", i2c::badge(0, 0x68), 3)]);
}

/// A bus fault is `FAULT`; a short answer from the driver is a short answer
/// (the count says how much is meaningful), never padded with garbage.
#[test]
fn an_i2c_bus_fault_is_fault() {
    let _g = serial();
    let s = scene(-1);
    let mut d = I2cServer(caller(&s, i2c::badge(0, 0x68), CapPerms::RW));
    assert_eq!(d.read(0, 2).code, outcome::FAULT);
    assert_eq!(d.write(Bytes::from_slice(&[1])).code, outcome::FAULT);
}

/// Containment refuses the write and leaves the read and the probe live.
#[test]
fn containment_refuses_an_i2c_write_and_leaves_reads_live() {
    let _g = serial();
    let s = scene(0);
    let mut d = I2cServer(caller(&s, i2c::badge(0, 0x68), CapPerms::RW));
    azos_ipc::cap::degraded_set(true);
    let w = d.write(Bytes::from_slice(&[1, 2]));
    let r = d.read(0, 1);
    let p = d.detect();
    azos_ipc::cap::degraded_set(false);
    assert_eq!(w.code, outcome::DENIED);
    assert!(r.is_ok() && p.is_ok());
    assert_eq!(calls().iter().filter(|c| c.0 == "i2c.write").count(), 0);
    assert_eq!(denials(), vec![]);
}

// ── Pwm ───────────────────────────────────────────────────────────────────

fn every_pwm_op(p: &mut PwmServer) -> [(&'static str, Out<()>); 5] {
    [
        ("enable", p.enable()),
        ("disable", p.disable()),
        ("set_period", p.set_period(1_000_000)),
        ("set_duty", p.set_duty(500_000)),
        ("set_duty_pct", p.set_duty_pct(40)),
    ]
}

/// Every PWM op acts, so every op needs `WRITE`: a `READ`-only holder is
/// refused all five before the driver, each refusal recorded.
///
/// **Canary.** Ask `READ` of one op: it is served to the read-only holder.
#[test]
fn every_pwm_op_needs_write() {
    let _g = serial();
    let s = scene(0);
    let mut ro = PwmServer(caller(&s, 4, CapPerms::READ));
    for (name, out) in every_pwm_op(&mut ro) {
        assert_eq!(out, Out::err(outcome::DENIED), "{name}");
    }
    assert_eq!(calls(), vec![]);
    assert_eq!(denials().len(), 5, "one record per refused op");

    let mut wo = PwmServer(caller(&s, 4, CapPerms::WRITE));
    for (name, out) in every_pwm_op(&mut wo) {
        assert_eq!(out, Out::ok(()), "{name}");
    }
    assert_eq!(
        calls(),
        vec![
            ("pwm.enable", 4, 0),
            ("pwm.disable", 4, 0),
            ("pwm.period", 4, 1_000_000),
            ("pwm.duty", 4, 500_000),
            ("pwm.pct", 4, 40),
        ]
    );
}

/// A channel the PWM domain does not have is `BAD_ARGUMENT`, before the driver.
#[test]
fn a_pwm_channel_the_board_lacks_is_a_bad_argument() {
    let _g = serial();
    let s = scene(0);
    let channels = azos_drv_actuator::pwm_domain::PWM_DOMAIN.channels;
    let mut p = PwmServer(caller(&s, channels, CapPerms::WRITE));
    assert_eq!(p.enable(), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(calls(), vec![]);
}

/// **A channel a wheel drives is refused to a holder**, for every op: the duty
/// register is below the actuation gate. A channel no motor claims is not.
///
/// **Canary.** Delete the guard: the motor channel's ops reach the driver.
#[test]
fn a_motor_bound_pwm_channel_is_refused_to_a_holder() {
    let _g = serial();
    let s = scene(0);
    azos_robot::motor::shim_bind_motor_channel(1);
    let mut p = PwmServer(caller(&s, 1, CapPerms::WRITE));
    for (name, out) in every_pwm_op(&mut p) {
        assert_eq!(out, Out::err(outcome::REFUSED), "{name}");
    }
    assert_eq!(calls(), vec![]);
    let mut free = PwmServer(caller(&s, 2, CapPerms::WRITE));
    assert_eq!(free.set_duty_pct(10), Out::ok(()), "a channel no motor claims is served");
}

/// Containment refuses a PWM write, unrecorded.
#[test]
fn containment_refuses_pwm_writes_unrecorded() {
    let _g = serial();
    let s = scene(0);
    let mut p = PwmServer(caller(&s, 4, CapPerms::WRITE));
    azos_ipc::cap::degraded_set(true);
    let out = every_pwm_op(&mut p);
    azos_ipc::cap::degraded_set(false);
    for (name, o) in out {
        assert_eq!(o, Out::err(outcome::DENIED), "{name}");
    }
    assert_eq!(calls(), vec![]);
    assert_eq!(denials(), vec![]);
}

/// **The buzzer's PWM channel has one holder.** The ring-3 buzzer host is kept up
/// while the driver is placed in the kernel, and both drive the one channel: its
/// `Pwm` writes to that channel are refused (every op, unrecorded and before the
/// driver) while the kernel host holds it, so a standby start-up or the timed step
/// of a sound left over from before a move cannot cut or change what the kernel
/// host plays. A move hands the channel back and forth; other channels are not
/// affected.
///
/// **Canary.** Delete the holder check in `PwmServer::run`: the writes of the
/// non-holder reach the driver.
#[test]
fn the_buzzer_channel_is_written_only_by_its_holder() {
    let _g = serial();
    let s = scene(0);
    let ch = azos_drv_actuator::buzzer_channel::CHANNEL;
    let mut p = PwmServer(caller(&s, ch, CapPerms::WRITE));

    // The kernel host holds the channel (the state before any promotion to ring 3).
    azos_drv_actuator::buzzer_channel::set_ring3_holds_channel(false);
    for (name, out) in every_pwm_op(&mut p) {
        assert_eq!(out, Out::err(outcome::REFUSED), "{name}");
    }
    assert_eq!(calls(), vec![], "a refused write never reaches the driver");
    assert_eq!(denials(), vec![], "it is not a capability denial");

    // A demotion hands it to the ring-3 host.
    azos_drv_actuator::buzzer_channel::set_ring3_holds_channel(true);
    for (name, out) in every_pwm_op(&mut p) {
        assert_eq!(out, Out::ok(()), "{name}");
    }
    assert_eq!(calls().len(), 5);

    // A promotion takes it back: the old holder's next (stale) step is refused.
    azos_drv_actuator::buzzer_channel::set_ring3_holds_channel(false);
    let before = calls().len();
    assert_eq!(p.disable(), Out::err(outcome::REFUSED));
    assert_eq!(calls().len(), before);

    // Another channel is not the buzzer's.
    let mut other = PwmServer(caller(&s, ch - 1, CapPerms::WRITE));
    assert_eq!(other.set_duty_pct(10), Out::ok(()));
}
