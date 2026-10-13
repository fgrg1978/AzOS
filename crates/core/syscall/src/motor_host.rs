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
//! The wheel is the endpoint's badge; there is no id argument that could
//! disagree with it. Every refusal by class is recorded as a capability
//! denial (`Caller::deny`), a refusal by the halt rule is not (it is the
//! safety system working).

#[cfg(not(feature = "use-robot"))]
use crate::no_robot::{robot as azos_robot};
use azos_abi::cap::CapPerms;
use azos_devif::motor::{DIR_BACKWARD, DIR_BRAKE, DIR_COAST, DIR_FORWARD, WHEELS};
use azos_devif::{key, outcome, Out};
use azos_robot::{motor_set_reporting, motor_stop_reporting, MotorDir, MOTOR_REFUSED_HALTED};

use crate::khost::Caller;

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
        let (rc, applied) = if pct == 0 {
            motor_stop_reporting(id)
        } else {
            motor_set_reporting(id, MotorDir::Forward, pct)
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
        let (rc, applied) = motor_set_reporting(id, d, pct);
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
        let (rc, applied) = motor_set_reporting(id, d, 50);
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
