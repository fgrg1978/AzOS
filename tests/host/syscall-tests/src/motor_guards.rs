// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the `Motor` interface the kernel hosts (D6 part A) --
// `crates/core/syscall/src/motor_host.rs`. They restate the typed motor calls'
// tests for the endpoint ops:
//
// * the halt rule: while an e-stop is latched or containment is armed, a stop
//   (speed 0, brake, coast) is CARRIED OUT and forward and backward are refused
//   in the motor layer, with the pins untouched and duty 0 written; the
//   capability check in front of it does not refuse the stop first;
// * the pair rule: a PID op commands the whole drivetrain, so it needs `WRITE`
//   on BOTH wheels' endpoints and is contained; `pid_enabled` observes and
//   needs `READ` on any wheel;
// * the wheel is the badge, there is no id argument that could disagree;
// * `estop` needs `WRITE` on the wheel used and is never contained.
//
// Included inside `mod handlers { .. }`. The real motor layer
// (`domains/robot/robot/src/motor.rs`, `shims/robot`) runs under a halt query
// and a gate that read the test's e-stop latch together with the containment
// level, the two conditions the kernel's `actuation_halt` and `actuation_gate`
// answer on; that wiring is covered by the kernel build.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::motor::{DIR_BACKWARD, DIR_BRAKE, DIR_COAST, DIR_FORWARD};
use azos_devif::{key, outcome, Motor, Out};
use azos_drv_actuator::pwm::{set_pwm_probe, PwmOp};
use azos_drv_gpio::gpio::{set_gpio_probe, GpioOp};
use crate::khost::Caller;
use crate::motor_host::{set_effect_gate, MotorEffect, MotorServer};
use azos_robot::MotorDir;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering::SeqCst};
use std::sync::Mutex;

/// Cap-store pool slot for this file; no other file in this crate binds 47.
const SLOT: usize = 47;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e47_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, SeqCst)
}

// ── The halt rule's inputs ────────────────────────────────────────────────

static ESTOP: AtomicBool = AtomicBool::new(false);

fn test_halt() -> bool {
    ESTOP.load(SeqCst) || azos_ipc::cap::degraded_active()
}

/// The kernel's gate answers 0 for a latched e-stop and at the CONTAINED
/// degrade level (speed cap 0 %), and passes the request otherwise.
fn test_gate(_id: u32, speed_pct: u32) -> u32 {
    if test_halt() { 0 } else { speed_pct }
}

/// A gate that allows everything, to show the halt zeroes the duty alone.
fn open_gate(_id: u32, speed_pct: u32) -> u32 {
    speed_pct
}

// ── The effect gate (write-ahead receipts, B1) ───────────────────────────────
//
// A stand-in for the kernel's gate (`azos_actuation::effect_gate`, covered by
// `actuation-tests`): it keeps what it was asked to record, and, when told to,
// refuses a motion op the way the real one refuses it on a full ring. A stop
// (`toward_safe`) is never refused.

static GATE_SEEN: Mutex<Vec<MotorEffect>> = Mutex::new(Vec::new());
static GATE_REFUSES: AtomicBool = AtomicBool::new(false);

fn recording_gate(e: &MotorEffect, op: &mut dyn FnMut() -> bool) -> bool {
    GATE_SEEN.lock().unwrap_or_else(|x| x.into_inner()).push(*e);
    if GATE_REFUSES.load(SeqCst) && !e.toward_safe {
        return false;
    }
    op();
    true
}

/// What no gate at all does: run the op.
fn pass_gate(_e: &MotorEffect, op: &mut dyn FnMut() -> bool) -> bool {
    op();
    true
}

fn gate_seen() -> Vec<(u32, u32, u32, u32, bool)> {
    GATE_SEEN.lock().unwrap_or_else(|x| x.into_inner()).iter()
        .map(|e| (e.wheel, e.tid, e.dir, e.pct, e.toward_safe)).collect()
}

fn install_recording_gate(refuses: bool) {
    GATE_SEEN.lock().unwrap_or_else(|x| x.into_inner()).clear();
    GATE_REFUSES.store(refuses, SeqCst);
    set_effect_gate(recording_gate);
}

// ── Probes ───────────────────────────────────────────────────────────────

static GPIO_CALLS: Mutex<Vec<(GpioOp, u32, u32)>> = Mutex::new(Vec::new());
static PWM_CALLS: Mutex<Vec<(PwmOp, u32, u32)>> = Mutex::new(Vec::new());
/// `(kind code, reason code)` of every typed capability denial recorded.
static DENIALS: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn gpio_probe(op: GpioOp, pin: u32, arg: u32) -> i32 {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, pin, arg));
    0
}

/// Records the call; a duty write reports the percentage it was given as the
/// applied one, which is what the real simulated channel does.
fn pwm_probe(op: PwmOp, ch: u32, arg: u32) -> i32 {
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).push((op, ch, arg));
    if op == PwmOp::SetDutyPct { arg as i32 } else { 0 }
}

fn typed_recorder(kind: u8, reason: u32) {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).push((kind, reason));
}

fn gpio_calls() -> Vec<(GpioOp, u32, u32)> {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn pwm_calls() -> Vec<(PwmOp, u32, u32)> {
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn denials() -> Vec<(u8, u32)> {
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn clear_probes() {
    GPIO_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    PWM_CALLS.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

const WHEELS: [(u32, u32, u32); 2] = [(4, 20, 21), (5, 22, 23)];
const ENDPOINT_CODE: u8 = azos_abi::cap::ty::ENDPOINT.denial_code();
const MISSING_PERMS: u32 = 3;

/// Puts back every process static a test here can touch, panic or not.
struct Scene {
    tid: u32,
    pid_enabled: bool,
}

impl Drop for Scene {
    fn drop(&mut self) {
        set_effect_gate(pass_gate);
        GATE_REFUSES.store(false, SeqCst);
        ESTOP.store(false, SeqCst);
        azos_ipc::cap::degraded_set(false);
        set_gpio_probe(None);
        set_pwm_probe(None);
        azos_drv_actuator::motor_pid::motor_pid_enable(self.pid_enabled);
        azos_ipc::cap_store::reset(self.tid);
        ipc_task_pool::shim_kill(self.tid);
    }
}

/// A ring-3 caller with an empty table, both wheels initialised on the real
/// motor layer under the test's halt query and gate, the probes armed and the
/// logs empty of the initialisation.
fn scene() -> Scene {
    let tid = fresh_tid();
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
    ESTOP.store(false, SeqCst);
    azos_ipc::cap::degraded_set(false);
    azos_robot::motor::set_motor_halt(test_halt);
    azos_robot::motor::set_motor_gate(test_gate);
    set_gpio_probe(Some(gpio_probe));
    set_pwm_probe(Some(pwm_probe));
    for (id, (ch, a, b)) in WHEELS.iter().enumerate() {
        assert_eq!(azos_robot::motor_init(id as u32, *ch, *a, *b), 0);
    }
    clear_probes();
    DENIALS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(typed_recorder);
    let pid_enabled = azos_drv_actuator::motor_pid::motor_pid_enabled();
    Scene { tid, pid_enabled }
}

fn who(s: &Scene, wheel: u32, rights: CapPerms) -> MotorServer {
    MotorServer(Caller { tid: s.tid, badge: wheel, rights })
}

/// A server for a caller that really holds `motor.<wheel>` with `rights` in
/// its table (the pair rule reads the table).
fn holding(s: &Scene, wheel: u32, rights: CapPerms) -> MotorServer {
    let cap = azos_ipc::endpoint::kernel_endpoint_cap(s.tid, rights, key::MOTOR, wheel).expect("grant");
    MotorServer(crate::khost::caller(s.tid, cap.raw().0).expect("the capability resolves"))
}

fn pins(wheel: usize, a: u32, b: u32) -> Vec<(GpioOp, u32, u32)> {
    vec![(GpioOp::Write, WHEELS[wheel].1, a), (GpioOp::Write, WHEELS[wheel].2, b)]
}

fn duty(wheel: usize, pct: u32) -> Vec<(PwmOp, u32, u32)> {
    vec![(PwmOp::SetDutyPct, WHEELS[wheel].0, pct)]
}

fn recorded(wheel: u32, dir: MotorDir, speed: u32) -> bool {
    matches!(azos_robot::motor_state(wheel), Some((d, s)) if d == dir && s == speed)
}

#[derive(Clone, Copy, Debug)]
enum Halt {
    Estop,
    Contained,
}

fn arm(h: Halt) {
    match h {
        Halt::Estop => ESTOP.store(true, SeqCst),
        Halt::Contained => azos_ipc::cap::degraded_set(true),
    }
}

fn disarm() {
    ESTOP.store(false, SeqCst);
    azos_ipc::cap::degraded_set(false);
}

// ── Per-wheel ops: the halt rule ───────────────────────────────────────────

/// **The kernel's own writes are held to the same rule.** A kernel-context
/// forward or backward -- `rt_motor_task` asks `Forward` at 0 % every tick
/// under an e-stop -- is refused without touching the pins, reports duty 0 so
/// the control loop's readback still reads 0, and leaves the recorded
/// direction alone.
///
/// **Canary.** Delete the refusal branch in `motor_set_reporting`: the call
/// returns `(0, Some(0))` and the probe sees the pins.
#[test]
fn a_kernel_direction_change_is_refused_while_halted() {
    for cause in [Halt::Estop, Halt::Contained] {
        let _g = serial();
        let _s = scene();
        arm(cause);
        for (dir, ask) in [(MotorDir::Forward, 0), (MotorDir::Forward, 60), (MotorDir::Backward, 60)] {
            clear_probes();
            assert_eq!(
                azos_robot::motor_set_reporting(0, dir, ask),
                (azos_robot::MOTOR_REFUSED_HALTED, Some(0)),
                "{cause:?}: ask {ask}"
            );
            assert!(gpio_calls().is_empty(), "{cause:?}: the pins were written: {:?}", gpio_calls());
            assert_eq!(pwm_calls(), duty(0, 0), "{cause:?}");
        }
        assert!(recorded(0, MotorDir::Coast, 0), "{cause:?}: motor_init records Coast");
    }
}

/// **`speed` gives the halt rule's answer.** While halted: a forward is
/// `REFUSED` with the pins untouched and duty 0 written, and a stop is carried
/// out -- while contained too, where a capability resolved WITH containment
/// would refuse it. Authority is unchanged: a READ-only capability is still
/// refused the stop.
///
/// **Canaries.** Ask `allows(WRITE)` (containment-aware) in `command`: the
/// contained stop reads `DENIED`. Answer `OK` for the halt rule's refusal: the
/// forward reads served. Delete the refusal branch in `motor_set_reporting`:
/// the probe sees the pins.
#[test]
fn speed_gives_the_halt_rules_answer_while_halted() {
    for cause in [Halt::Estop, Halt::Contained] {
        let _g = serial();
        let s = scene();
        arm(cause);

        let mut w = who(&s, 0, CapPerms::RW);
        assert_eq!(w.speed(60), Out::err(outcome::REFUSED), "{cause:?}: forward");
        assert!(gpio_calls().is_empty(), "{cause:?}: the pins were written: {:?}", gpio_calls());
        assert_eq!(pwm_calls(), duty(0, 0), "{cause:?}: a refused forward writes duty 0");

        clear_probes();
        assert_eq!(w.speed(0), Out::ok(()), "{cause:?}: the stop is carried out");
        assert_eq!(gpio_calls(), pins(0, 0, 0), "{cause:?}");

        let mut ro = who(&s, 0, CapPerms::READ);
        assert_eq!(ro.speed(0), Out::err(outcome::DENIED), "{cause:?}: a READ-only capability stopped a wheel");
    }
}

/// **`direction` applies the halt rule.** After a brake while not halted, a
/// forward and a reverse are refused without touching the pins, each writing
/// duty 0, and the motor table still records the brake; a coast and a brake
/// are carried out at duty 0; a kernel-context brake asking 80 % through a gate
/// that allows everything still lands at duty 0; once cleared the reverse
/// writes the pins at duty 50. The endpoint names one wheel and is enough: no
/// pair rule.
///
/// **Canaries.** Resolve with containment: the contained coast reads
/// `DENIED`. Refuse every direction while halted: the brake reads `REFUSED`.
/// Take the duty from the gate while halted: the kernel brake reports 80.
#[test]
fn direction_applies_the_halt_rule() {
    for cause in [Halt::Estop, Halt::Contained] {
        let _g = serial();
        let s = scene();
        let mut w = who(&s, 0, CapPerms::RW);
        assert_eq!(w.direction(DIR_BRAKE), Out::ok(()), "{cause:?}: brake before halting");
        clear_probes();

        arm(cause);
        assert_eq!(w.direction(DIR_FORWARD), Out::err(outcome::REFUSED), "{cause:?}: forward");
        assert_eq!(w.direction(DIR_BACKWARD), Out::err(outcome::REFUSED), "{cause:?}: reverse");
        assert!(gpio_calls().is_empty(), "{cause:?}: the pins were written: {:?}", gpio_calls());
        assert_eq!(pwm_calls(), [duty(0, 0), duty(0, 0)].concat(), "{cause:?}");
        assert!(recorded(0, MotorDir::Brake, 0), "{cause:?}: the table records a direction that was not applied");

        clear_probes();
        assert_eq!(w.direction(DIR_COAST), Out::ok(()), "{cause:?}: coast while halted");
        assert_eq!(gpio_calls(), pins(0, 0, 0), "{cause:?}");
        assert_eq!(pwm_calls(), duty(0, 0), "{cause:?}");
        assert!(recorded(0, MotorDir::Coast, 0), "{cause:?}");

        clear_probes();
        assert_eq!(w.direction(DIR_BRAKE), Out::ok(()), "{cause:?}: brake while halted");
        assert_eq!(gpio_calls(), pins(0, 1, 1), "{cause:?}");
        assert_eq!(pwm_calls(), duty(0, 0), "{cause:?}");
        assert!(recorded(0, MotorDir::Brake, 0), "{cause:?}");

        azos_robot::motor::set_motor_gate(open_gate);
        clear_probes();
        assert_eq!(
            azos_robot::motor_set_reporting(0, MotorDir::Brake, 80),
            (0, Some(0)),
            "{cause:?}: kernel brake"
        );
        assert_eq!(gpio_calls(), pins(0, 1, 1), "{cause:?}");
        azos_robot::motor::set_motor_gate(test_gate);

        disarm();
        clear_probes();
        assert_eq!(w.direction(DIR_BACKWARD), Out::ok(()), "{cause:?}: reverse once cleared");
        assert_eq!(gpio_calls(), pins(0, 0, 1), "{cause:?}");
        assert_eq!(pwm_calls(), duty(0, 50), "{cause:?}");
        assert!(recorded(0, MotorDir::Backward, 50), "{cause:?}");
    }
}

/// **The wheel is the badge, and the class is checked before the argument.**
/// A READ-only endpoint is refused with one record and reaches no wheel; the
/// endpoint of wheel 1 drives wheel 1 (its channel and pins) and not wheel 0;
/// a badge past the drivetrain names no wheel.
///
/// **Canaries.** Command wheel 0 whatever the badge names: the wheel-1 line
/// writes wheel 0's pins. Resolve with `READ`: the READ-only line is served.
#[test]
fn the_wheel_comes_from_the_badge_and_the_class_is_checked_first() {
    let _g = serial();
    let s = scene();
    let mut ro = who(&s, 0, CapPerms::READ);
    assert_eq!(ro.direction(DIR_BACKWARD), Out::err(outcome::DENIED), "READ-only");
    assert_eq!(ro.drive(DIR_BACKWARD, 30), Out::err(outcome::DENIED));
    assert_eq!(ro.direction(9), Out::err(outcome::DENIED), "the class is checked before the argument");
    assert!(gpio_calls().is_empty() && pwm_calls().is_empty(), "a refused call reached a wheel");
    assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS); 3], "one record per refused call");

    let mut right = who(&s, 1, CapPerms::RW);
    assert_eq!(right.direction(DIR_BACKWARD), Out::ok(()));
    assert_eq!(gpio_calls(), pins(1, 0, 1));
    assert_eq!(pwm_calls(), duty(1, 50));

    clear_probes();
    let mut stray = who(&s, 2, CapPerms::RW);
    assert_eq!(stray.speed(0), Out::err(outcome::BAD_ARGUMENT), "a badge past the drivetrain names no wheel");
    assert!(gpio_calls().is_empty() && pwm_calls().is_empty());
}

/// **`drive` carries direction and magnitude, and refuses what it cannot
/// carry out.** A direction past coast or a speed over 100 is `BAD_ARGUMENT`
/// with no pin, no duty and no motor-table change; an honest reverse at 30 %
/// writes the pins at duty 30.
///
/// **Canary.** Map any other direction to coast: the dir=4 line is served and
/// the probes see the pins. Clamp instead of refusing the 101: it is served.
#[test]
fn drive_refuses_what_it_cannot_carry_out_and_honours_the_magnitude() {
    let _g = serial();
    let s = scene();
    let mut w = who(&s, 0, CapPerms::RW);
    assert_eq!(w.direction(DIR_BRAKE), Out::ok(()), "precondition");
    let before = azos_robot::motor_state(0);
    clear_probes();
    for (dir, pct) in [(4, 10), (u32::MAX, 10), (DIR_FORWARD, 101)] {
        assert_eq!(w.drive(dir, pct), Out::err(outcome::BAD_ARGUMENT), "dir {dir} pct {pct}");
    }
    assert!(gpio_calls().is_empty() && pwm_calls().is_empty(), "a refused drive reached the wheel");
    assert!(azos_robot::motor_state(0) == before, "a refused drive changed the motor table");
    assert_eq!(denials(), vec![], "an argument refusal is not a capability denial");

    assert_eq!(w.drive(DIR_BACKWARD, 30), Out::ok(()));
    assert_eq!(gpio_calls(), pins(0, 0, 1));
    assert_eq!(pwm_calls(), duty(0, 30));
    assert!(recorded(0, MotorDir::Backward, 30));
}

// ── Reading the encoder ───────────────────────────────────────────────────

/// `angle` needs `READ`, reads the wheel the badge names, and stays live while
/// contained; a refusal reads no encoder at all.
///
/// **Canary.** Read before the gate: the refused call counts a read.
#[test]
fn angle_reads_the_named_wheel_and_a_refusal_reads_nothing() {
    let _g = serial();
    let s = scene();
    azos_robot::shim_set_encoder(1234, -5678);
    let reads = azos_robot::shim_encoder_reads();
    assert_eq!(who(&s, 0, CapPerms::WRITE).angle(), Out::err(outcome::DENIED), "WRITE-only");
    assert_eq!(azos_robot::shim_encoder_reads(), reads, "a refused call read the encoders");
    assert_eq!(who(&s, 0, CapPerms::READ).angle(), Out::ok(1234));
    assert_eq!(who(&s, 1, CapPerms::READ).angle(), Out::ok(-5678));
    azos_ipc::cap::degraded_set(true);
    assert_eq!(who(&s, 1, CapPerms::READ).angle(), Out::ok(-5678), "a read stays live while contained");
    azos_ipc::cap::degraded_set(false);
    assert_eq!(who(&s, 2, CapPerms::READ).angle(), Out::err(outcome::BAD_ARGUMENT));
}

// ── The pair-wide ops ──────────────────────────────────────────────────────

fn every_pid_write(m: &mut MotorServer) -> [(&'static str, u32); 5] {
    [
        ("pid_target", m.pid_target(10, 10).code),
        ("pid_tick", m.pid_tick(0, 0, 0).code),
        ("pid_enable", m.pid_enable(false).code),
        ("pid_gains", m.pid_gains(1, 0, 0).code),
        ("pid_reset", m.pid_reset().code),
    ]
}

/// **A pair holder drives the controller.** `WRITE` on both wheels' endpoints:
/// every op is served, `pid_enabled` reads what `pid_enable` set, and `tick`
/// answers a pair.
#[test]
fn the_pair_holder_drives_the_controller() {
    let _g = serial();
    let s = scene();
    let _right = holding(&s, 1, CapPerms::RW);
    let mut left = holding(&s, 0, CapPerms::RW);
    assert_eq!(left.pid_enable(false), Out::ok(()));
    assert_eq!(left.pid_enabled(), Out::ok(false));
    assert_eq!(left.pid_enable(true), Out::ok(()));
    assert_eq!(left.pid_enabled(), Out::ok(true));
    assert_eq!(left.pid_gains(2, 1, 0), Out::ok(()));
    assert_eq!(left.pid_target(100, 100), Out::ok(()));
    assert_eq!(left.pid_reset(), Out::ok(()));
    assert!(left.pid_tick(0, 0, 0).is_ok());
    assert_eq!(denials(), vec![]);
}

/// **One wheel is not the pair.** `WRITE` on one wheel's endpoint and `READ`
/// (or nothing) on the other: every pair-wide op is `DENIED`, each refusal
/// recorded, and the refused `pid_enable(false)` left the controller enabled.
///
/// **Canary.** Skip the other wheel's check in `pair`: the lone holder is
/// served.
#[test]
fn one_wheel_is_not_the_pair() {
    let _g = serial();
    let s = scene();
    azos_drv_actuator::motor_pid::motor_pid_enable(true);
    for other in [None, Some(CapPerms::READ)] {
        DENIALS.lock().unwrap().clear();
        azos_ipc::cap_store::reset(s.tid);
        let mut left = holding(&s, 0, CapPerms::RW);
        if let Some(p) = other {
            let _ = holding(&s, 1, p);
        }
        for (name, code) in every_pid_write(&mut left) {
            assert_eq!(code, outcome::DENIED, "{name} with one wheel (other: {other:?})");
        }
        assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS); 5], "one record per refused op");
        assert_eq!(left.pid_enabled(), Out::ok(true), "a refused pid_enable(false) disabled the controller");
    }
}

/// **`pid_enabled` is the one observation:** `READ` on any wheel, refused to
/// a `WRITE`-only capability, and the writes refuse a `READ`-only pair.
#[test]
fn a_read_only_pair_can_read_and_not_write() {
    let _g = serial();
    let s = scene();
    let _r = holding(&s, 1, CapPerms::READ);
    let mut l = holding(&s, 0, CapPerms::READ);
    assert!(l.pid_enabled().is_ok(), "the READ was refused");
    for (name, code) in every_pid_write(&mut l) {
        assert_eq!(code, outcome::DENIED, "{name} with READ");
    }
    assert_eq!(who(&s, 0, CapPerms::WRITE).pid_enabled(), Out::err(outcome::DENIED), "enabled with WRITE only");
}

/// **The PID ops stay contained, disabling the loop included.** None of them
/// leaves a wheel stopped: `pid_enable(false)` only clears `PID_ENABLED`,
/// after which `rt_motor_task` applies the motor command open-loop, and a zero
/// target or a reset is overwritten by the loop's next tick. The READ stays
/// live, nothing is recorded (containment is the safety system working), and
/// the same caller is served once cleared.
///
/// **Canary.** Resolve the pair with `holds` instead of `gate`: the contained
/// disable is served.
#[test]
fn the_pid_ops_stay_contained_disable_included() {
    let _g = serial();
    let s = scene();
    let _r = holding(&s, 1, CapPerms::RW);
    let mut l = holding(&s, 0, CapPerms::RW);
    azos_drv_actuator::motor_pid::motor_pid_enable(true);

    azos_ipc::cap::degraded_set(true);
    for (name, code) in every_pid_write(&mut l) {
        assert_eq!(code, outcome::DENIED, "{name} while contained");
    }
    assert!(l.pid_enabled().is_ok(), "the READ went dark while contained");
    assert_eq!(denials(), vec![], "containment is not a denial");

    azos_ipc::cap::degraded_set(false);
    assert_eq!(l.pid_enable(true), Out::ok(()), "the pair holder was refused once cleared");
}

/// A target past the loop's `i16` is refused, not truncated, and the
/// controller keeps what it had.
#[test]
fn a_pid_target_past_i16_is_refused_not_truncated() {
    let _g = serial();
    let s = scene();
    let _r = holding(&s, 1, CapPerms::RW);
    let mut l = holding(&s, 0, CapPerms::RW);
    assert_eq!(l.pid_target(32768, 0), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(l.pid_target(0, -32769), Out::err(outcome::BAD_ARGUMENT));
    assert_eq!(l.pid_target(32767, -32768), Out::ok(()));
    assert_eq!(l.pid_target(0, 0), Out::ok(()));
}

/// The register form (four words each way): `pid_tick` is header + three
/// arguments in, status + outcome + two duties out.
///
/// **Canary.** Declare the interface without `words = 4`: the macro refuses to
/// compile it. Route `key::MOTOR` to the wrong arm: the status word is not 0.
#[test]
fn a_pid_tick_fits_the_register_form() {
    use azos_devif::MotorIdl;
    let _g = serial();
    let s = scene();
    let _r = holding(&s, 1, CapPerms::RW);
    let l = holding(&s, 0, CapPerms::RW);
    let who = l.0;
    let words = [
        azos_idl::header(MotorIdl::ID, MotorIdl::LEVEL, MotorIdl::OP_PID_TICK),
        7,
        9,
        123,
    ];
    let rep = crate::khost::serve_regs(key::MOTOR, &who, words);
    assert_eq!((rep[0], rep[1] as u32), (azos_idl::STATUS_OK, outcome::OK));
}

// ── The emergency stop ─────────────────────────────────────────────────────

static ESTOPS: AtomicU32 = AtomicU32::new(0);

fn count_estop() {
    ESTOPS.fetch_add(1, SeqCst);
}

/// **An e-stop from a holder of WRITE on a wheel is carried out while
/// contained.** Containment is armed when something has gone wrong, which is
/// when a stop is issued; refusing it there would leave a program that may
/// drive unable to stop. A capability without `WRITE` is one refusal and one
/// record per call, and no stop. With no handler armed the answer is a fault:
/// success for an emergency nothing carried out is not an answer.
///
/// **Canaries.** Resolve with `gate` (containment-aware): the contained stop
/// is `DENIED`. Ask `READ`: the READ line is served. Answer `OK` without a
/// handler: the last line reads served.
#[test]
fn an_estop_is_carried_out_while_contained() {
    let _g = serial();
    let s = scene();
    set_estop_handler(count_estop);
    ESTOPS.store(0, SeqCst);

    let mut ro = who(&s, 1, CapPerms::READ);
    assert_eq!(ro.estop(), Out::err(outcome::DENIED), "a READ-only wheel");
    assert_eq!(who(&s, 0, CapPerms::NONE).estop(), Out::err(outcome::DENIED), "no right at all");
    assert_eq!(denials(), vec![(ENDPOINT_CODE, MISSING_PERMS); 2], "one record per refused call");
    assert_eq!(ESTOPS.load(SeqCst), 0, "a refused e-stop was carried out");

    azos_ipc::cap::degraded_set(true);
    DENIALS.lock().unwrap().clear();
    assert_eq!(who(&s, 1, CapPerms::WRITE).estop(), Out::ok(()), "refused while contained");
    assert_eq!(ESTOPS.load(SeqCst), 1);
    assert_eq!(denials(), vec![], "an e-stop that was carried out wrote a denial");
    azos_ipc::cap::degraded_set(false);

    __estop_handler_clear_for_tests();
    assert_eq!(who(&s, 0, CapPerms::WRITE).estop(), Out::err(outcome::FAULT), "no handler armed");
}

// ── Write-ahead receipts: the gate in front of the three motion ops ───────

/// **The gate is asked the right question.** Each per-wheel op reaches the
/// effect gate with the wheel the badge names, the caller's task, the
/// direction and duty it asked, and whether it moves toward rest: `speed(0)`
/// is a coast, a brake or coast is toward rest at ANY duty, a duty of 0 is
/// toward rest in any direction, and `direction` asks a fixed 50.
///
/// **Canaries.** Bypass `through_gate` in an op: that op leaves no entry.
/// Compute `toward_safe` from the direction alone: `drive(FORWARD, 0)` reads
/// unsafe. Change `direction`'s 50: the last two entries differ.
#[test]
fn each_motion_op_asks_the_effect_gate_what_it_does() {
    let _g = serial();
    let s = scene();
    install_recording_gate(false);
    let mut w0 = who(&s, 0, CapPerms::RW);
    let mut w1 = who(&s, 1, CapPerms::RW);
    let t = s.tid;

    assert_eq!(w0.speed(0), Out::ok(()));
    assert_eq!(w0.speed(60), Out::ok(()));
    assert_eq!(w1.drive(DIR_BACKWARD, 40), Out::ok(()));
    assert_eq!(w1.drive(DIR_BRAKE, 80), Out::ok(()));
    assert_eq!(w1.drive(DIR_FORWARD, 0), Out::ok(()));
    assert_eq!(w0.direction(DIR_BACKWARD), Out::ok(()));
    assert_eq!(w0.direction(DIR_COAST), Out::ok(()));
    assert_eq!(
        gate_seen(),
        vec![
            (0, t, DIR_COAST, 0, true),
            (0, t, DIR_FORWARD, 60, false),
            (1, t, DIR_BACKWARD, 40, false),
            (1, t, DIR_BRAKE, 80, true),
            (1, t, DIR_FORWARD, 0, true),
            (0, t, DIR_BACKWARD, 50, false),
            (0, t, DIR_COAST, 50, true),
        ]
    );
    // The ops still reached the wheels: the gate runs them, it does not replace them.
    assert!(!gpio_calls().is_empty() && !pwm_calls().is_empty());
}

/// **Each motion op hands the gate its contract (B2).** The op's IDL
/// deadline and server bound reach the gate as the deadline and the placement
/// latency; wheel 1 has no `[device.motor.N]` row, so its safe state defaults
/// to a coast with no commit time and no inverse. Wheel 0's row (see
/// `subtree_policy::CAPS`) adds its commit time, its `stop` inverse, the
/// call budget of its ring-3 driver when that is the larger placement latency,
/// and a `brake` safe state, which the kernel cannot drive lock-free and so
/// reaches the gate as the unsupported op (the miss is then recorded as a
/// safe state not reached). A stop carries no contract at all (it is never
/// refused or watched).
///
/// **Canary.** Hand every op `MotorTiming::NONE`, take the deadline from the
/// wrong op's row (`OP_DRIVE` in `speed`), or ignore the row: the equality
/// fails.
#[test]
fn each_motion_op_hands_the_gate_its_contract_and_a_stop_hands_none() {
    use crate::motor_host::{MotorTiming, OP_COAST, OP_STOP, OP_UNSUPPORTED};
    use azos_devif::motor::MotorIdl;
    super::subtree_policy::topology();
    let _g = serial();
    let s = scene();
    install_recording_gate(false);
    let mut w0 = who(&s, 0, CapPerms::RW);
    let mut w1 = who(&s, 1, CapPerms::RW);

    assert_eq!(w1.speed(60), Out::ok(()));
    assert_eq!(w1.drive(DIR_BACKWARD, 40), Out::ok(()));
    assert_eq!(w1.direction(DIR_FORWARD), Out::ok(()));
    assert_eq!(w1.speed(0), Out::ok(()));
    assert_eq!(w0.speed(60), Out::ok(()));
    let seen: Vec<MotorTiming> = GATE_SEEN.lock().unwrap_or_else(|x| x.into_inner()).iter().map(|e| e.timing).collect();
    let contract = |op: u16| {
        let i = &MotorIdl::OPS[(op - 1) as usize];
        MotorTiming { deadline_ns: i.deadline_ns, placement_ns: i.budget_us as u64 * 1_000, commit_ns: 0, safe_op: OP_COAST, compensate_op: 0 }
    };
    assert_eq!((contract(MotorIdl::OP_SPEED).deadline_ns, contract(MotorIdl::OP_SPEED).placement_ns), (2_000_000, 200_000),
        "the motor interface's declared contract moved");
    let row = MotorTiming {
        placement_ns: 900_000, // the driver's call budget, above the server bound
        commit_ns: 400_000,
        safe_op: OP_UNSUPPORTED,
        compensate_op: OP_STOP,
        ..contract(MotorIdl::OP_SPEED)
    };
    assert_eq!(seen, vec![
        contract(MotorIdl::OP_SPEED), contract(MotorIdl::OP_DRIVE), contract(MotorIdl::OP_DIRECTION),
        MotorTiming::NONE,
        row,
    ]);
}

/// **The kernel's drive of a wheel to its safe state** writes both direction
/// pins low and the duty 0 for the ops it implements, whichever wheel; it
/// refuses an op it does not implement (a row naming `brake`: there is no
/// lock-free brake) and a wheel the interface does not have, writing nothing.
///
/// **Canary.** Accept every op: the unsupported one writes pins.
#[test]
fn the_kernels_drive_to_a_safe_state_is_a_coast_and_refuses_what_it_cannot_do() {
    use crate::motor_host::{drive_safe, OP_COAST, OP_STOP, OP_UNSUPPORTED};
    let _g = serial();
    let _s = scene();
    for wheel in [0u16, 1] {
        for op in [OP_COAST, OP_STOP] {
            clear_probes();
            assert!(drive_safe(wheel, op));
            let w = wheel as usize;
            assert_eq!(gpio_calls(), pins(w, 0, 0), "wheel {wheel} op {op}");
            assert_eq!(pwm_calls(), duty(w, 0), "wheel {wheel} op {op}");
        }
    }
    clear_probes();
    assert!(!drive_safe(0, OP_UNSUPPORTED) && !drive_safe(0, 0) && !drive_safe(2, OP_COAST));
    assert!(gpio_calls().is_empty() && pwm_calls().is_empty(), "a refused drive wrote to the wheel");
}

/// **The kernel's safe-state drive keeps the motor table honest.** A wheel
/// commanded forward reads back coast at duty 0 after the drive, also when the
/// drive found the table owned by a command (the update waits for the next
/// holder, and a command arriving then starts from the coast), and a wheel
/// that was never initialised is refused, writing nothing.
///
/// **Canary.** Drop the table update in `motor_safe_state`: the first read
/// still says forward 50.
#[test]
fn the_kernels_drive_to_a_safe_state_leaves_the_motor_table_saying_coast() {
    use crate::motor_host::{drive_safe, OP_COAST};
    let _g = serial();
    let _s = scene();
    assert_eq!(azos_robot::motor_set_reporting(0, MotorDir::Forward, 50).0, 0);
    assert_eq!(azos_robot::motor_state(0), Some((MotorDir::Forward, 50)));
    assert!(drive_safe(0, OP_COAST));
    assert_eq!(azos_robot::motor_state(0), Some((MotorDir::Coast, 0)));

    // The table is owned by another command: the drive does not wait for it.
    assert_eq!(azos_robot::motor_set_reporting(1, MotorDir::Backward, 30).0, 0);
    clear_probes();
    azos_robot::with_motor_table_held_for_test(|| assert!(drive_safe(1, OP_COAST)));
    assert_eq!(gpio_calls(), pins(1, 0, 0));
    assert_eq!(pwm_calls(), duty(1, 0));
    assert_eq!(azos_robot::motor_state(1), Some((MotorDir::Coast, 0)));
    // ... and the settled table is the base of the next command.
    assert_eq!(azos_robot::motor_set_reporting(1, MotorDir::Backward, 30).0, 0);
    assert_eq!(azos_robot::motor_state(1), Some((MotorDir::Backward, 30)));

    // A wheel nobody initialised: refused, nothing written.
    clear_probes();
    assert!(!azos_robot::motor_safe_state(3));
    assert!(gpio_calls().is_empty() && pwm_calls().is_empty());
}

/// **A refusal reaches no wheel.** A gate that refuses a motion op: the three
/// ops answer `REFUSED`, no pin and no duty is written, and the motor table
/// still holds what it held. A stop is still carried out.
///
/// **Canary.** Answer `Ok(())` instead of `REFUSED` where an op's gate
/// refusal is turned into a reply (`speed`, `drive` or `direction`): that op's
/// first assertion fails.
#[test]
fn a_refused_motion_op_reaches_no_wheel_and_a_stop_still_does() {
    let _g = serial();
    let s = scene();
    install_recording_gate(true);
    let mut w = who(&s, 0, CapPerms::RW);

    assert_eq!(w.speed(60), Out::err(outcome::REFUSED), "speed");
    assert_eq!(w.drive(DIR_FORWARD, 30), Out::err(outcome::REFUSED), "drive");
    assert_eq!(w.direction(DIR_BACKWARD), Out::err(outcome::REFUSED), "direction");
    assert!(gpio_calls().is_empty(), "a refused op wrote the pins: {:?}", gpio_calls());
    assert!(pwm_calls().is_empty(), "a refused op wrote the duty: {:?}", pwm_calls());
    assert!(recorded(0, MotorDir::Coast, 0), "a refused op changed the motor table");
    assert_eq!(gate_seen().len(), 3, "each refused op was put to the gate once");

    assert_eq!(w.speed(0), Out::ok(()), "a stop is never refused");
    assert_eq!(w.direction(DIR_BRAKE), Out::ok(()), "a brake is never refused");
    assert_eq!(w.drive(DIR_COAST, 70), Out::ok(()), "a coast is never refused");
    assert!(!gpio_calls().is_empty() && matches!(azos_robot::motor_state(0), Some((MotorDir::Coast, _))));
}

/// **A halted machine commits no record for a motion op.** While an e-stop is
/// latched or containment holds, the motor layer refuses forward and backward
/// itself: nothing moves, so the gate is not asked, the caller still reads
/// `REFUSED` with duty 0 written, and a task spamming motion ops cannot fill
/// the recorder's ring with pinned records. A stop is still put to the gate
/// and carried out. Once the halt lifts, motion goes through the gate again.
///
/// **Canary.** Delete the `motor_halted()` pre-check in `through_gate`: the
/// halted motion ops appear in the gate's list.
#[test]
fn a_halted_machine_commits_no_record_for_a_motion_op() {
    for cause in [Halt::Estop, Halt::Contained] {
        let _g = serial();
        let s = scene();
        install_recording_gate(false);
        let mut w = who(&s, 0, CapPerms::RW);
        arm(cause);

        assert_eq!(w.speed(60), Out::err(outcome::REFUSED), "{cause:?}: speed");
        assert_eq!(w.drive(DIR_BACKWARD, 30), Out::err(outcome::REFUSED), "{cause:?}: drive");
        assert_eq!(w.direction(DIR_FORWARD), Out::err(outcome::REFUSED), "{cause:?}: direction");
        assert!(gate_seen().is_empty(), "{cause:?}: a refused motion op was recorded: {:?}", gate_seen());
        assert!(gpio_calls().is_empty(), "{cause:?}: the pins were written");
        assert_eq!(pwm_calls(), [duty(0, 0), duty(0, 0), duty(0, 0)].concat(), "{cause:?}: each refusal writes duty 0");

        clear_probes();
        assert_eq!(w.speed(0), Out::ok(()), "{cause:?}: the stop is carried out");
        assert_eq!(gate_seen(), vec![(0, s.tid, DIR_COAST, 0, true)], "{cause:?}: a stop is recorded");
        assert_eq!(gpio_calls(), pins(0, 0, 0), "{cause:?}");

        disarm();
        assert_eq!(w.speed(60), Out::ok(()), "{cause:?}: motion after the halt lifts");
        assert_eq!(gate_seen().len(), 2, "{cause:?}: the gate sees motion again");
    }
}
