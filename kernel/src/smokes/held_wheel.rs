// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! B2 ktest: a wheel the kernel holds in its safe state after a missed
//! deadline stays at rest under the kernel's own control loop. The hold
//! outlasts every stop and lifts only with the operator's warranted release
//! (`azos_actuation::safe_state`), but `rt_motor_task` rewrites both wheels
//! from `CH_MOTOR_CMD` every control tick, so a loop that did not ask
//! undid the safe-state drive within one tick.
//!
//! The test holds wheel 1 the way a miss does: a watch armed with a deadline
//! already past, swept by the safe-state sweep. Then the loop's write for
//! wheel 1 must be a coast at duty 0 whatever it computed
//! (`rt_motor::control_command`, which `control_apply_wheel` calls for every
//! write of the loop), and wheel 0, which is not held, keeps its command. It
//! is not judged on the wheels themselves: in the ktest boot the control loop
//! left no non-zero duty on a free wheel either with 40 % published for both
//! (measured 2026-10-23), so the wheels cannot tell a held wheel from a free
//! one there. Wheel 1 stays held for the rest of the boot: no
//! ktest drives it.
//!
//! **Canary**, by hand: make `control_command` return its arguments: `not ok`.

use azos_actuation::effect_gate::{Class, Effect, KIND_MOTOR};
use azos_actuation::safe_state;
use azos_robot::MotorDir;

const HELD: u32 = 1;
const FREE: u32 = 0;

azos_ktest::ktest_late! {
    fn rt_motor_coasts_a_held_wheel() {
        if !safe_state::can_drive(KIND_MOTOR) {
            return Err("no safe-state driver is registered for the motor kind");
        }
        let me = azos_sched::current_task_tid();
        let e = Effect { kind: KIND_MOTOR, class: Class::Reversible, subject: HELD as u16, tid: me, a0: 0, a1: 40 };
        if safe_state::arm(&e, 0, azos_syscall::motor_host::OP_COAST).is_none() {
            return Err("the safe-state watch table is full");
        }
        safe_state::sweep(azos_drv_sys::timebase::now().saturating_add(1));
        crate::ktest::wait("the overdue watch never held wheel 1", || safe_state::held(KIND_MOTOR, HELD as u16))?;

        if azos_safety_core::rt_motor::control_command(HELD, MotorDir::Forward, 40) != (MotorDir::Coast, 0) {
            return Err("the control loop's write for a held wheel is not a coast at duty 0");
        }
        if azos_safety_core::rt_motor::control_command(FREE, MotorDir::Forward, 40) != (MotorDir::Forward, 40) {
            return Err("the control loop's write for a wheel that is not held was changed");
        }

        Ok(())
    }
}
