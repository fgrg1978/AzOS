// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `SYS_MOTOR_MOVE_TYPED` (584) — W2-B4 task 2 (audit U11-12).
//!
//! U11-12: `userspace/services/reflex`'s obstacle-avoidance backup and
//! `userspace/services/brain_client`'s reverse path both go through
//! `SYS_MOTOR_DIRECTION_TYPED` (576), which always drives at a kernel-fixed
//! 50 % duty (`crates/core/syscall/src/handlers.rs::motor_direction_reporting`,
//! `motor_set_reporting(id, d, 50)`); `SYS_MOTOR_SPEED_TYPED` (560) takes a
//! speed but always drives `Forward`. Neither can express "back up at 30 %".
//! This handler is the `(direction, speed)` call that closes the gap — see
//! `crates/core/abi/src/syscall_nr.rs::SYS_MOTOR_MOVE_TYPED` for the full ABI doc.
//!
//! ## Why this is its own file rather than another function in `handlers.rs`
//!
//! `crates/core/syscall/src/{dispatch,handlers}.rs` are owned by another front in
//! this wave; this crate's owner (W2-B4) is granted exactly one new syscall
//! number and one new file to hold its handler
//! (`crates/core/syscall/src/motor_cmd.rs`), wiring into `dispatch.rs`/`lib.rs`
//! delivered as unified diffs instead of edited in place. See the diffs in
//! this front's handoff report.
//!
//! ## Same gate/record path as every other typed motor call
//!
//! Resolves the `Cap<Motor>` exactly as `sys_motor_direction_typed` /
//! `sys_motor_speed_typed` do — `azos_ipc::motor_cap::motor_speed_cap_id`,
//! `WRITE`, no pair rule (one wheel, matching the untyped ancestor
//! `SYS_MOTOR_SPEED` (232) this migrates authority-preserving from) — denies
//! through the same `note_typed_denial` choke point every other typed motor
//! handler uses, and drives through the exact function every other motor
//! write drives through: `azos_robot::motor_set_reporting`. The halt
//! rule (latched e-stop / armed containment) and the `gate_speed` safety
//! envelope both live inside that call and are not restated here — this
//! handler adds no new path to the motor layer, only a new ABI shape onto
//! the existing one.
//!
//! `crate::handlers::motor_rc_ret` and `crate::handlers::errno_for_motor_err`
//! are plain (non-`pub(crate)`) functions in that sibling module, so this
//! file cannot call them and reimplements their ~10 lines instead, built from
//! the two pieces of that module that ARE `pub(crate)` and therefore visible
//! here: [`crate::handlers::E_CONTAINED`] and
//! [`crate::handlers::note_typed_denial`]. Kept byte-for-byte equivalent to
//! the two private originals (`crates/core/syscall/src/handlers.rs:2017-2019`,
//! `:3637-3655` in the tree this was written against) — a change to either
//! copy should change both, or a future edit that touches both files at once
//! should widen `handlers.rs`'s visibility and delete the duplicate here.

#[cfg(not(feature = "domain-robot"))]
use crate::no_robot::{robot as azos_robot};
use azos_abi::cap::{CapHandle, CapKind};
use azos_abi::error::Errno;
use azos_ipc::cap::{targets::Motor, Cap, CapError};
use azos_ipc::motor_cap::MotorCapError;
use azos_robot::{motor_set_reporting, MotorDir, MOTOR_REFUSED_HALTED};

/// Equivalent of `crate::handlers::motor_rc_ret` (private there — see module
/// doc). `crate::handlers::E_CONTAINED` is `pub(crate)`, so this reaches it
/// directly rather than restating `Errno::EAGAIN.to_syscall_ret()`.
#[inline]
fn motor_rc_ret(rc: i32) -> i64 {
    if rc == MOTOR_REFUSED_HALTED { crate::handlers::E_CONTAINED } else { rc as i64 }
}

/// Equivalent of `crate::handlers::errno_for_motor_err` (private there — see
/// module doc). `crate::handlers::note_typed_denial` is `pub(crate)`, so the
/// denial still reaches the SAME recorder every other typed motor call uses,
/// under the SAME `CapKind::Motor` accounting.
fn errno_for_motor_err(e: MotorCapError) -> i64 {
    let MotorCapError::Cap(c) = e;
    crate::handlers::note_typed_denial(CapKind::Motor, c);
    match e {
        MotorCapError::Cap(CapError::Stale) => Errno::ECAPSTALE.to_syscall_ret(),
        MotorCapError::Cap(CapError::WrongKind) => Errno::ECAPKIND.to_syscall_ret(),
        MotorCapError::Cap(CapError::MissingPerms) => Errno::ECAPPERMS.to_syscall_ret(),
        MotorCapError::Cap(CapError::Contained) => Errno::EAGAIN.to_syscall_ret(),
        MotorCapError::Cap(CapError::NoSpace) => Errno::EMFILE.to_syscall_ret(),
    }
}

/// `SYS_MOTOR_MOVE_TYPED` (584): `a0 = cap` (`Cap<Motor>`), `a1 = direction`
/// (0 forward, 1 backward, 2 brake, 3 coast), `a2 = speed_pct` (0..=100).
///
/// In order: a refused capability answers `-ECAPSTALE` / `-ECAPKIND` /
/// `-ECAPPERMS` and writes one `SAFETY_CAP_DENIED_TYPED` record; a direction
/// outside `0..=3` or a `speed_pct` over 100 answers `-EINVAL` with no
/// record and nothing reaches the motor layer; otherwise
/// `motor_set_reporting(id, dir, speed_pct)` decides, exactly as
/// `motor_direction_reporting` / `sys_motor_speed_typed` do.
pub fn sys_motor_move_typed(cap_raw: u64, dir: u64, speed_pct: u64) -> i64 {
    let cap: Cap<Motor> = Cap::from_raw(CapHandle::from_raw(cap_raw as u32));
    let tid = azos_sched::current_task_tid();
    let id = match azos_ipc::cap_store::with_table(tid, |t| {
        azos_ipc::motor_cap::motor_speed_cap_id(t, cap)
    }) {
        Some(Ok(id)) => id,
        Some(Err(e)) => return errno_for_motor_err(e),
        None => return Errno::EINVAL.to_syscall_ret(),
    };
    let d = match dir {
        0 => MotorDir::Forward,
        1 => MotorDir::Backward,
        2 => MotorDir::Brake,
        3 => MotorDir::Coast,
        _ => return Errno::EINVAL.to_syscall_ret(),
    };
    if speed_pct > 100 {
        return Errno::EINVAL.to_syscall_ret();
    }
    let (rc, applied) = motor_set_reporting(id, d, speed_pct as u32);
    crate::motor_commander::note(id, tid, applied);
    let r = motor_rc_ret(rc);

    // Same `[ACTSMOKE]` shape as `sys_motor_speed_typed` /
    // `motor_direction_reporting`: only under the actuation-smoke feature,
    // off in every shipped build, and printed from the applied duty
    // `motor_set_reporting` itself measured, not from the arguments (see
    // those functions' docs for why: a stub returning 0 without driving
    // anything would otherwise print an identical line).
    #[cfg(feature = "actuation-smoke")]
    {
        let duty = applied.map(|v| v as i64).unwrap_or(-1);
        azos_drv_sys::kprintln!(
            "[ACTSMOKE] ring3 motor id={} dir={} ask={} duty={} rc={}",
            id, dir, speed_pct, duty, r);
    }
    #[cfg(not(feature = "actuation-smoke"))]
    let _ = applied;
    r
}
