// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 15 ktest (owner decision): a task that dies commanding a wheel leaves
//! it at a SAFE STOP. A probe task drives wheel 0 at 30 % through the motor
//! layer and notes itself as the wheel's commander, exactly as the typed
//! motor calls do for a ring-3 caller (`motor_commander::note_current`), and
//! returns; its exit hook (`kernel/src/boot/sched.rs`) must take the wheel
//! and have the motor layer confirm duty 0. The hook also writes the
//! `SAFETY_ESTOP` / action 14 record and its `[MOTOR] commander ... SAFE
//! STOP` line. Canary `commander-exit-nostop-canary`: the wheel is taken and
//! never stopped, so the test reports `not ok`.
//!
//! The duty is read from the stop's own report, not from the channel
//! afterwards: `rt_motor_task` writes the same wheel every control tick
//! while its command channel is live, so a later read could be its duty.

use core::sync::atomic::{AtomicU32, Ordering};

const WHEEL: u32 = 0;
/// Mid-band: the probe only writes the wheel and returns.
const PROBE_PRIO: u32 = 10;
/// The probe's write was refused (the motor layer applied nothing).
const REFUSED: u32 = u32::MAX;

static TID: AtomicU32 = AtomicU32::new(0);
static APPLIED: AtomicU32 = AtomicU32::new(REFUSED);

fn commander(_: usize) {
    let me = azos_sched::current_task_tid();
    let (_rc, applied) = azos_robot::motor_set_reporting(WHEEL, azos_robot::MotorDir::Forward, 30);
    azos_syscall::motor_commander::note(WHEEL, me, applied);
    APPLIED.store(applied.unwrap_or(REFUSED), Ordering::Release);
    TID.store(me, Ordering::Release);
}

azos_ktest::ktest_late! {
    fn motor_commander_exit_stops_its_wheels() {
        if !azos_limits::MOTOR_COMMANDER_EXIT_STOP {
            return Err("Kconfig MOTOR_COMMANDER_EXIT_STOP is off in this build");
        }
        azos_sched::task_create_affinity("cmdr-probe", commander, 0, PROBE_PRIO, 1);
        crate::ktest::wait("the commander probe never ran", || TID.load(Ordering::Acquire) != 0)?;
        let tid = TID.load(Ordering::Acquire);
        match APPLIED.load(Ordering::Acquire) {
            REFUSED | 0 => return Err("the probe's 30 % write was refused: no wheel to stop"),
            _ => {}
        }
        crate::ktest::wait("the commander's exit never took its wheel", || {
            azos_syscall::motor_commander::last_exit_stop().0 == tid
        })?;
        let (_, stopped) = azos_syscall::motor_commander::last_exit_stop();
        if azos_syscall::motor_commander::commander(WHEEL) == tid {
            Err("the dead task still commands the wheel")
        } else if stopped & (1 << WHEEL) == 0 {
            Err("the dead commander's wheel was not set to duty 0")
        } else {
            Ok(())
        }
    }
}
