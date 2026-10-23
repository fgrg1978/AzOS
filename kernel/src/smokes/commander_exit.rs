// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Wave 15 ktest (owner decision): a task that dies commanding a wheel leaves
//! it at a SAFE STOP. A probe task drives wheel 0 at 30 % through the
//! kernel's io_ring motor entry (`KERNEL_IORING_OPS.motor_wheel`, as its own
//! ring's owner), which is the `Motor` interface's `speed` op
//! (`motor_host::wheel_speed`: the effect gate, the motor layer, the
//! commander note), and returns; its exit hook (`kernel/src/boot/sched.rs`)
//! must take the wheel and have the motor layer confirm duty 0. A ring entry
//! that skipped that path names no commander, and the test reports `not ok`. The hook also writes the
//! `SAFETY_ESTOP` / action 14 record and its `[MOTOR] commander ... SAFE
//! STOP` line. Canary `commander-exit-nostop-canary`: the wheel is taken and
//! never stopped, so the test reports `not ok`.
//!
//! The stop comes first of all in that hook, before the file writeback (which
//! can wait on the disk) and the device and display releases: the hook notes
//! when the releases of a task have run ([`note_released`]) and when its
//! wheels were stopped ([`note_stopped`]), and a stop that finds its own
//! task's releases already done is late. Runtime canary
//! `commander-exit-late`: the hook stops the wheels after the releases, and
//! the test reports `not ok`.
//!
//! The duty is read from the stop's own report, not from the channel
//! afterwards: `rt_motor_task` writes the same wheel every control tick
//! while its command channel is live, so a later read could be its duty. For
//! the same reason the probe's own write is judged by the commander it named
//! (a wheel is noted only at a non-zero applied duty), read right after it.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const WHEEL: u32 = 0;
/// Mid-band: the probe only writes the wheel and returns.
const PROBE_PRIO: u32 = 10;
static TID: AtomicU32 = AtomicU32::new(0);
/// The probe's ring entry completed (not refused) and left the probe named as
/// the wheel's commander.
static NOTED: AtomicBool = AtomicBool::new(false);
/// The last task whose exit hook has run its releases.
static RELEASED: AtomicU32 = AtomicU32::new(0);
/// The last stop the hook noted: `(tid << 1) | 1` when it came after that
/// task's own releases, `tid << 1` when it came first.
static STOPPED: AtomicU64 = AtomicU64::new(0);

/// The exit hook of `tid` has run its releases (writeback, devices, display).
pub(crate) fn note_released(tid: u32) {
    RELEASED.store(tid, Ordering::Release);
}

/// The exit hook of `tid` has stopped the wheels it commanded. A TID is never
/// reused while its hook runs, so a match is this task's own releases.
pub(crate) fn note_stopped(tid: u32) {
    let late = RELEASED.load(Ordering::Acquire) == tid;
    STOPPED.store(((tid as u64) << 1) | late as u64, Ordering::Release);
}

fn commander(_: usize) {
    let me = azos_sched::current_task_tid();
    let done = (azos_syscall::ioring_ops::KERNEL_IORING_OPS.motor_wheel)(me, WHEEL, 30);
    let noted = matches!(done, Ok(rc) if rc >= 0) && azos_syscall::motor_commander::commander(WHEEL) == me;
    NOTED.store(noted, Ordering::Release);
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
        if !NOTED.load(Ordering::Acquire) {
            return Err("the probe's 30 % ring entry named no commander (refused, or it skipped the typed op's path)");
        }
        crate::ktest::wait("the commander's exit never took its wheel", || {
            azos_syscall::motor_commander::last_exit_stop().0 == tid
        })?;
        crate::ktest::wait("the commander's exit hook never noted its stop", || {
            STOPPED.load(Ordering::Acquire) >> 1 == tid as u64
        })?;
        let (_, stopped) = azos_syscall::motor_commander::last_exit_stop();
        if azos_syscall::motor_commander::commander(WHEEL) == tid {
            Err("the dead task still commands the wheel")
        } else if stopped & (1 << WHEEL) == 0 {
            Err("the dead commander's wheel was not set to duty 0")
        } else if STOPPED.load(Ordering::Acquire) & 1 != 0 {
            Err("the dead commander's wheel was stopped after its releases, not first")
        } else {
            Ok(())
        }
    }
}
