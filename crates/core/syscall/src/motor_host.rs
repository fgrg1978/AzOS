// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Motor` interface the kernel hosts: one wheel of the drivetrain and the
//! drivetrain's PID loop, served on the `motor.0` / `motor.1` endpoints
//! (`azos_devif::Motor`). It replaces the typed motor calls (550-555, 560, 576,
//! 578, 584) and `SYS_ROBOT_ESTOP`; the authority is the same, stated as
//! op classes on the endpoint capability.
//!
//! * **Per-wheel ops** (`speed`, `drive`, `direction`) need `WRITE` and are
//!   resolved WITHOUT the containment step: whether a command may move the
//!   wheel is decided one level down, in `azos_robot::motor_set_reporting`.
//!   While an e-stop is latched or containment is armed it carries out brake
//!   and coast and refuses forward and backward (owner decision 2026-09-13), so
//!   refusing a stop here would leave a task that may drive unable to stop.
//! * **Pair-wide ops** (the PID loop) command the whole drivetrain in one
//!   operation, so they need `WRITE` on BOTH wheels' endpoints and a contained
//!   system refuses them (disabling the loop included: it leaves the wheels as
//!   they were and lets `rt_motor_task` apply the open-loop command).
//! * `estop` needs `WRITE` on any wheel and is never refused for containment.
//!
//! * **Write-ahead receipts** (innovation B1): the three per-wheel ops reach the
//!   motor layer through the effect gate ([`set_effect_gate`], installed by
//!   `azos_actuation::gate::install`), which commits the op's record to the
//!   flight recorder first and refuses a motion op when it cannot. An op toward
//!   a safe state (a stop, brake, coast) is never refused, and a motion op the
//!   halt rule refuses anyway is not recorded (nothing moves). A refusal answers
//!   `REFUSED` and nothing reaches the wheel. The receipt (a decision record
//!   id) lives in the decision journal for `why`; the `Motor` reply carries an
//!   outcome code only. `estop` is not an effect of this kind: it is the stop
//!   itself and waits for no record.
//!
//! * **Deadline or safe state** (innovation B2): each of those ops also hands
//!   the gate its contract: the op's IDL `#[deadline_ns]`, the server's
//!   placement latency (the op's `#[budget_us]`, or the call budget of the
//!   ring-3 driver the wheel's `[device.motor.N]` row names) and the row's
//!   `commit_ns`, `safe_state` and `compensate` ([`MotorTiming`]). The gate refuses
//!   an op whose contract cannot be met, watches an admitted one, and has
//!   the kernel drive the wheel to its safe state ([`drive_safe`], the
//!   motor layer's own lock-free safe-state entry, never the wheel's locks or
//!   the driver) when the watch finds it overdue. A wheel held there takes
//!   stops only, and no stop lifts the hold: it lasts `B2_HOLD_MIN_MS` and
//!   then ends only with the operator's signed release
//!   (`azos_actuation::safe_state::release`), so this module keeps no
//!   listener for stops. A wheel's row is optional: with none, the wheel's
//!   safe state is a coast and there is no commit time and no inverse.
//!
//! The wheel is the endpoint's badge; there is no id argument that could
//! disagree with it. Every refusal by class is recorded as a capability
//! denial (`Caller::deny`), a refusal by the halt rule is not (it is the
//! safety system working).

#[cfg(not(feature = "use-robot"))]
use crate::no_robot::{robot as azos_robot};
use azos_abi::cap::CapPerms;
use azos_devif::motor::{DIR_BACKWARD, DIR_BRAKE, DIR_COAST, DIR_FORWARD, WHEELS};
use azos_devif::{key, outcome, Out};
use azos_robot::{motor_halted, motor_release, motor_safe_state, motor_set_reporting, motor_stop_reporting, MotorDir, MOTOR_REFUSED_HALTED};


use crate::khost::Caller;

/// What a motor op declares about its timing and its wheel's inverse ops
/// (the gate's `Timing`; this crate cannot name the actuation crate). The
/// ops are this module's `OP_*` codes, 0 for none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MotorTiming {
    /// The op's `#[deadline_ns]`.
    pub deadline_ns: u64,
    /// The server's placement latency.
    pub placement_ns: u64,
    /// The wheel row's `commit_ns` (0: none declared).
    pub commit_ns: u64,
    /// The op that drives the wheel to its safe state.
    pub safe_op: u8,
    /// The op that undoes a failed command (0: none declared).
    pub compensate_op: u8,
}

impl MotorTiming {
    /// A stop declares nothing: it is never refused or watched.
    pub const NONE: MotorTiming =
        MotorTiming { deadline_ns: 0, placement_ns: 0, commit_ns: 0, safe_op: 0, compensate_op: 0 };
}

/// A motor op as the effect gate sees it: which wheel, who asked, what was
/// asked (`dir` is a `DIR_*` code, `pct` the duty) and whether it moves the
/// wheel toward its safe state (brake, coast, duty 0), which is never refused.
#[derive(Clone, Copy)]
pub struct MotorEffect {
    pub wheel: u32,
    pub tid: u32,
    pub dir: u32,
    pub pct: u32,
    pub toward_safe: bool,
    pub timing: MotorTiming,
}

/// The effect gate: commit the effect's record, then run `op`; `false` when
/// the effect was refused and `op` did not run. `op` returns whether the
/// wheel took the command (`false`: a fault, which the gate undoes with the
/// row's `compensate` op).
pub type EffectGate = fn(&MotorEffect, &mut dyn FnMut() -> bool) -> bool;

azos_common::ro_hook! {
    /// The installed gate, 0 until `azos_actuation::gate::install` runs. Without
    /// one the op runs unrecorded, as the motor layer's own gate, halt query and
    /// recorder do before their install: the loader refuses to start a ring-3
    /// image while `gate_installed()` is false, so no ring-3 op can reach this
    /// before the gate is in.
    static EFFECT_GATE: EffectGate;
}

/// Install the effect gate (the kernel, at boot, once).
pub fn set_effect_gate(gate: EffectGate) {
    EFFECT_GATE.set(gate);
}

/// Safe-state / compensating ops of a wheel (the codes of [`drive_safe`]).
/// `coast` and `stop` are the motor layer's lock-free safe state; a row naming
/// any other op (`brake`: there is no lock-free brake) gets
/// [`OP_UNSUPPORTED`], which the driver refuses, so the miss is recorded as a
/// safe state the kernel could not reach instead of being taken for one.
pub const OP_COAST: u8 = 1;
pub const OP_STOP: u8 = 2;
pub const OP_UNSUPPORTED: u8 = 255;

/// The op a row names, as a code; 0 for none.
fn op_code(name: &[u8]) -> u8 {
    match name {
        b"" => 0,
        b"coast" => OP_COAST,
        b"stop" => OP_STOP,
        _ => OP_UNSUPPORTED,
    }
}

/// Drive `wheel` to its safe state with `op`, without a lock the stalled path
/// may hold: `azos_robot::motor_safe_state` writes both direction pins low and
/// the duty 0 through the lock-free GPIO and PWM writers, from the pin wiring
/// the motor layer published at init, and brings the motor table in step. The
/// kernel's own hold on the wheel, used by the watch
/// (`azos_actuation::safe_state`) when the wheel's op missed its deadline and
/// for a failed command's inverse. `false` for an op this module does not
/// implement or a wheel that is not initialised.
pub fn drive_safe(wheel: u16, op: u8) -> bool {
    if (wheel as u32) >= WHEELS || !matches!(op, OP_COAST | OP_STOP) {
        return false;
    }
    motor_safe_state(wheel as u32)
}

/// Lift the hold [`drive_safe`] put on `wheel`'s pins and channel: the
/// kernel's release of the device, after the operator's signed warrant
/// (`azos_actuation::safe_state::release`). `false` for a wheel that is not
/// initialised.
pub fn release_safe(wheel: u16) -> bool {
    (wheel as u32) < WHEELS && motor_release(wheel as u32)
}

/// The contract of per-wheel op `op` (an `OP_*` of `azos_devif::motor::MotorIdl`)
/// on `wheel`: the IDL's deadline and server bound, then the wheel's row.
fn timing_of(toward_safe: bool, wheel: u32, op: u16) -> MotorTiming {
    if toward_safe {
        return MotorTiming::NONE;
    }
    let info = &azos_devif::motor::MotorIdl::OPS[(op - 1) as usize];
    let mut t = MotorTiming {
        deadline_ns: info.deadline_ns,
        placement_ns: info.budget_us as u64 * 1_000,
        commit_ns: 0,
        safe_op: OP_COAST,
        compensate_op: 0,
    };
    let Some(topo) = azos_topology::state::get() else { return t };
    let name = [b'm', b'o', b't', b'o', b'r', b'.', b'0' + wheel as u8];
    let Some(row) = topo.devices().iter().find(|d| d.name.as_bytes() == &name[..]) else { return t };
    t.commit_ns = row.commit_ns;
    if !row.safe_state.is_empty() {
        t.safe_op = op_code(row.safe_state.as_bytes());
    }
    t.compensate_op = op_code(row.compensate.as_bytes());
    // A ring-3 driver is called through its endpoint: its row's call budget
    // is what one call costs from here, if that is more than the server bound.
    if !row.driver.is_empty() {
        if let Some(task) = topo.find_task(&row.driver) {
            if task.place.host == azos_topology::placement::Host::Ring3 {
                t.placement_ns = t.placement_ns.max(task.place.call_budget_us as u64 * 1_000);
            }
        }
    }
    t
}

/// Run `op` through the effect gate: `Ok` with its result, or `Err` when the
/// gate refused and `op` did not run. `op` returns its result and whether the
/// wheel took the command.
fn through_gate<R>(e: &MotorEffect, op: impl FnOnce() -> (R, bool)) -> Result<R, ()> {
    let Some(gate) = EFFECT_GATE.get() else {
        return Ok(op().0);
    };
    // The halt rule is checked BEFORE a record is committed. While it holds
    // (a latched e-stop or containment), the motor layer refuses a motion op
    // itself: nothing moves, so there is no effect to record, and a record
    // would pin ring space for an op that does not happen (a halted task could
    // fill the ring with them and make other tasks' motion `RingFull`). The op
    // still runs, for the motor layer's own answer: it writes duty 0 and
    // returns `MOTOR_REFUSED_HALTED`. The halt query is read twice, here and
    // in the motor layer. A latch landing between the reads leaves a record
    // without an effect (harmless); a latch lifted between them (the
    // operator's clear, in the same microseconds as a motion op) lets one op
    // through with no record: a window of a few instructions, accepted.
    if !e.toward_safe && motor_halted() {
        return Ok(op().0);
    }
    let (mut op, mut out) = (Some(op), None);
    let issued = gate(e, &mut || match op.take().map(|f| f()) {
        Some((r, landed)) => { out = Some(r); landed }
        None => false,
    });
    match out {
        Some(r) if issued => Ok(r),
        _ => Err(()),
    }
}

/// Did the motor layer take the command? A fault is a wheel it does not have
/// or a halt after a panic; the halt rule's own refusal moved nothing by
/// design and is not a failure.
fn took(rc: i32) -> bool {
    rc >= 0 || rc == MOTOR_REFUSED_HALTED
}

/// Does `dir` at `pct` move a wheel toward rest?
fn toward_safe(dir: u32, pct: u32) -> bool {
    pct == 0 || dir == DIR_BRAKE || dir == DIR_COAST
}

/// The `Motor` interface served for one caller.
pub struct MotorServer(pub Caller);

/// An op's outcome from the motor layer's return code: `0` and positive are
/// served, the halt rule's refusal is `REFUSED`, any other negative is a fault
/// (a wheel the layer has not initialised).
fn outcome_of(rc: i32) -> u32 {
    if rc == MOTOR_REFUSED_HALTED {
        outcome::REFUSED
    } else if rc < 0 {
        outcome::FAULT
    } else {
        outcome::OK
    }
}

/// The return code the `[ACTSMOKE]` markers have always printed: the halt
/// rule's refusal as the contained-write errno, anything else as it came.
#[cfg(feature = "actuation-smoke")]
fn marker_rc(rc: i32) -> i64 {
    if rc == MOTOR_REFUSED_HALTED { crate::handlers::E_CONTAINED } else { rc as i64 }
}

fn direction_of(dir: u32) -> Option<MotorDir> {
    match dir {
        DIR_FORWARD => Some(MotorDir::Forward),
        DIR_BACKWARD => Some(MotorDir::Backward),
        DIR_BRAKE => Some(MotorDir::Brake),
        DIR_COAST => Some(MotorDir::Coast),
        _ => None,
    }
}

impl MotorServer {
    /// The wheel the badge names.
    fn wheel(&self) -> Result<u32, u32> {
        if self.0.badge < WHEELS {
            Ok(self.0.badge)
        } else {
            Err(outcome::BAD_ARGUMENT)
        }
    }

    /// The gate of a per-wheel command: `WRITE` held (containment is NOT asked
    /// here, the halt rule is the motor layer's), and the badge names a wheel.
    fn command<T: Default>(&self) -> Result<u32, Out<T>> {
        if !self.0.holds(CapPerms::WRITE) {
            self.0.deny(CapPerms::WRITE);
            return Err(Out::err(outcome::DENIED));
        }
        self.wheel().map_err(Out::err)
    }

    /// The gate of a pair-wide op: `WRITE` (containment refuses it) on this
    /// wheel's endpoint AND on the other wheel's in the same table.
    fn pair<T: Default>(&self) -> Result<(), Out<T>> {
        self.0.gate::<T>(CapPerms::WRITE)?;
        let other = match self.wheel() {
            Ok(w) => 1 - w,
            Err(c) => return Err(Out::err(c)),
        };
        if !self.0.also_holds(key::MOTOR, other, CapPerms::WRITE) {
            self.0.deny_missing();
            return Err(Out::err(outcome::DENIED));
        }
        Ok(())
    }
}

impl azos_devif::Motor for MotorServer {
    fn speed(&mut self, pct: u32) -> Out<()> {
        let id = match self.command::<()>() {
            Ok(id) => id,
            Err(o) => return o,
        };
        let dir = if pct == 0 { DIR_COAST } else { DIR_FORWARD };
        let effect = MotorEffect { wheel: id, tid: self.0.tid, dir, pct, toward_safe: toward_safe(dir, pct),
                                   timing: timing_of(toward_safe(dir, pct), id, azos_devif::motor::MotorIdl::OP_SPEED) };
        let Ok((rc, applied)) = through_gate(&effect, || {
            let r = if pct == 0 {
                motor_stop_reporting(id)
            } else {
                motor_set_reporting(id, MotorDir::Forward, pct)
            };
            (r, took(r.0))
        }) else {
            return Out::err(outcome::REFUSED);
        };
        crate::motor_commander::note(id, self.0.tid, applied);

        // The marker that says ring 3 COMMANDED a motor, not merely that it
        // ran. **It reports the duty the write itself left on the channel, not
        // the value that was asked for**, read inside the critical section
        // that performs the write (`motor_set_reporting`): a second look at
        // the channel would race `rt_motor_task`, which drives the same two
        // wheels every control tick. The gap between `ask` and `duty` is where
        // the safety envelope shows up. Only under `actuation-smoke`, and off
        // in every shipped build: a UART write costs ~160 us per 64 bytes
        // under QEMU, on the actuation path.
        #[cfg(feature = "actuation-smoke")]
        {
            let duty = applied.map(|d| d as i64).unwrap_or(-1);
            azos_drv_sys::kprintln!(
                "[ACTSMOKE] ring3 motor id={} ask={} duty={} rc={}",
                id, pct, duty, marker_rc(rc));
        }
        #[cfg(not(feature = "actuation-smoke"))]
        let _ = applied;
        Out::new(outcome_of(rc), ())
    }

    fn drive(&mut self, dir: u32, pct: u32) -> Out<()> {
        let id = match self.command::<()>() {
            Ok(id) => id,
            Err(o) => return o,
        };
        let Some(d) = direction_of(dir) else { return Out::err(outcome::BAD_ARGUMENT) };
        if pct > 100 {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let effect = MotorEffect { wheel: id, tid: self.0.tid, dir, pct, toward_safe: toward_safe(dir, pct),
                                   timing: timing_of(toward_safe(dir, pct), id, azos_devif::motor::MotorIdl::OP_DRIVE) };
        let Ok((rc, applied)) = through_gate(&effect, || {
            let r = motor_set_reporting(id, d, pct);
            (r, took(r.0))
        }) else {
            return Out::err(outcome::REFUSED);
        };
        crate::motor_commander::note(id, self.0.tid, applied);
        #[cfg(feature = "actuation-smoke")]
        {
            let duty = applied.map(|v| v as i64).unwrap_or(-1);
            azos_drv_sys::kprintln!(
                "[ACTSMOKE] ring3 motor id={} dir={} ask={} duty={} rc={}",
                id, dir, pct, duty, marker_rc(rc));
        }
        #[cfg(not(feature = "actuation-smoke"))]
        let _ = applied;
        Out::new(outcome_of(rc), ())
    }

    fn direction(&mut self, dir: u32) -> Out<()> {
        let id = match self.command::<()>() {
            Ok(id) => id,
            Err(o) => return o,
        };
        // A direction past coast is refused before anything reaches the motor
        // layer (owner decision, gap 1 Q5): no pin written, no marker printed.
        let Some(d) = direction_of(dir) else { return Out::err(outcome::BAD_ARGUMENT) };
        let effect = MotorEffect { wheel: id, tid: self.0.tid, dir, pct: 50, toward_safe: toward_safe(dir, 50),
                                   timing: timing_of(toward_safe(dir, 50), id, azos_devif::motor::MotorIdl::OP_DIRECTION) };
        let Ok((rc, applied)) = through_gate(&effect, || {
            let r = motor_set_reporting(id, d, 50);
            (r, took(r.0))
        }) else {
            return Out::err(outcome::REFUSED);
        };
        crate::motor_commander::note(id, self.0.tid, applied);
        // The same readback marker as `speed`, and reflex is why it has to be
        // here too: it backs up on an obstacle, and reverse is a direction
        // command, so the speed marker sees only reflex's stops. The duty is
        // what the write left, not the 50 asked: a latched e-stop or a
        // tightened envelope shows up as a smaller number, not a missing line.
        #[cfg(feature = "actuation-smoke")]
        {
            let duty = applied.map(|v| v as i64).unwrap_or(-1);
            azos_drv_sys::kprintln!(
                "[ACTSMOKE] ring3 motor id={} dir={} duty={} rc={}", id, dir, duty, marker_rc(rc));
        }
        #[cfg(not(feature = "actuation-smoke"))]
        let _ = applied;
        Out::new(outcome_of(rc), ())
    }

    fn angle(&self) -> Out<i64> {
        if let Err(o) = self.0.gate::<i64>(CapPerms::READ) {
            return o;
        }
        let wheel = match self.wheel() {
            Ok(w) => w,
            Err(c) => return Out::err(c),
        };
        let (left, right) = azos_robot::encoder_read();
        Out::ok(if wheel == 0 { left } else { right })
    }

    fn pid_target(&mut self, left: i32, right: i32) -> Out<()> {
        if let Err(o) = self.pair::<()>() {
            return o;
        }
        // Refused rather than truncated: a target past the loop's `i16` is a
        // different speed than the one the caller asked for.
        let (Ok(l), Ok(r)) = (i16::try_from(left), i16::try_from(right)) else {
            return Out::err(outcome::BAD_ARGUMENT);
        };
        azos_drv_actuator::motor_pid::motor_pid_set_target(l, r);
        Out::ok(())
    }

    fn pid_tick(&mut self, ticks_left: i64, ticks_right: i64, now: u64) -> Out<[i32; 2]> {
        if let Err(o) = self.pair::<[i32; 2]>() {
            return o;
        }
        let (l, r) = azos_drv_actuator::motor_pid::motor_pid_tick(ticks_left, ticks_right, now);
        Out::ok([l, r])
    }

    fn pid_enable(&mut self, on: bool) -> Out<()> {
        if let Err(o) = self.pair::<()>() {
            return o;
        }
        azos_drv_actuator::motor_pid::motor_pid_enable(on);
        Out::ok(())
    }

    fn pid_enabled(&self) -> Out<bool> {
        if let Err(o) = self.0.gate::<bool>(CapPerms::READ) {
            return o;
        }
        Out::ok(azos_drv_actuator::motor_pid::motor_pid_enabled())
    }

    fn pid_gains(&mut self, kp: i32, ki: i32, kd: i32) -> Out<()> {
        if let Err(o) = self.pair::<()>() {
            return o;
        }
        azos_drv_actuator::motor_pid::motor_pid_set_gains(kp, ki, kd);
        Out::ok(())
    }

    fn pid_reset(&mut self) -> Out<()> {
        if let Err(o) = self.pair::<()>() {
            return o;
        }
        azos_drv_actuator::motor_pid::motor_pid_reset();
        Out::ok(())
    }

    fn estop(&mut self) -> Out<()> {
        // `WRITE` on the endpoint used, and no containment step: an e-stop is
        // issued exactly when something has gone wrong, which is when
        // containment is likely armed, and refusing the stop to the task
        // entitled to drive would be the worst answer the call can give.
        if !self.0.holds(CapPerms::WRITE) {
            self.0.deny(CapPerms::WRITE);
            return Out::err(outcome::DENIED);
        }
        // A missing handler fails CLOSED: success for an emergency nothing
        // carried out is not an answer.
        if crate::handlers::run_estop_handler() {
            Out::ok(())
        } else {
            Out::err(outcome::FAULT)
        }
    }
}
