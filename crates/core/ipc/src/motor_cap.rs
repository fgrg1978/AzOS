// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Cap<Motor> typed wrappers — RFC-0003 W5 batch 5.4.
//!
//! **Granularity decision (2026-08-24, user decision, migration
//! phase P1).** `Cap<Motor>` is scoped **per physical motor**:
//! `motor_grant_cap(tid, motor_id, perms)` mints a cap whose `resource`
//! IS `motor_id` (0 = left wheel, 1 = right wheel on the current
//! two-wheel drivetrain). This used to hard-code `resource = 0` for
//! every grant, on the theory that "there is one motor controller per
//! robot" — true of the *PID loop* (`azos_drv_actuator::motor_pid`,
//! which has no per-wheel API at all: `motor_pid_set_target` takes both
//! `speed_l`/`speed_r` in one call), but wrong for the *authority* a cap
//! should represent: the legacy path already grants and checks
//! `Motor(0)`/`Motor(1)` separately (`kernel/src/tasks/loader.rs` autorun seed,
//! `crates/core/syscall/src/handlers.rs::sys_motor_enable/speed`), and
//! `crates/core/ipc/src/io_ring.rs`'s `OP_MOTOR_SPEED` deliberately requires
//! write on **both** ids before driving the pair — see
//! `motor_speed_requires_write_on_both_wheels` there. Collapsing the
//! typed side to one shared resource id would have silently *widened*
//! authority relative to the legacy path it's meant to replace: a task
//! holding a cap minted for "the left wheel" would functionally control
//! both. Per-motor granularity preserves wheel-level isolation and
//! keeps the migration authority-preserving, not authority-expanding.
//!
//! Every operation below that actuates the shared PID loop (`WRITE`:
//! `set_target`, `tick`, `enable`, `set_gains`, `reset`) therefore
//! requires WRITE on **both** `Motor(0)` and `Motor(1)` — see
//! [`require_pair_write`] — mirroring `OP_MOTOR_SPEED`'s rule exactly.
//! The one READ-only query (`motor_enabled_cap`, `SYS_MOTOR_ENABLED_TYPED`
//! 553) is not an actuation and is deliberately left single-cap: it
//! reports shared state, and a task's own single-wheel READ authority is
//! enough to observe it — least-privilege, not a safety property, so no
//! pairing rule applies there.

use crate::cap::{Cap, CapError, CapKind, CapPerms, CapTable};
use azos_drv_actuator::motor_pid::{
    motor_pid_enable, motor_pid_enabled, motor_pid_reset, motor_pid_set_gains,
    motor_pid_set_target, motor_pid_tick,
};

/// Errors returned by the typed `motor_*_cap` functions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MotorCapError {
    Cap(CapError),
}

impl From<CapError> for MotorCapError {
    fn from(e: CapError) -> Self {
        Self::Cap(e)
    }
}

/// Motors on the drivetrain a `Cap<Motor>` can name: 0 (left) and 1 (right).
///
/// Not `azos_robot::MAX_MOTORS` (4): that sizes the motor table, and ids
/// 2 and 3 are slots no drivetrain wheel occupies. The pair rule below is
/// written for exactly these two, so the grant bound and the pair bound read
/// the same constant.
pub const DRIVETRAIN_MOTORS: u32 = 2;

/// Topology-loader / autorun-seed entry: grant `tid` a `Cap<Motor>` scoped
/// to one physical motor. `motor_id` becomes the slot's `resource`.
///
/// **Refuses any id outside the drivetrain** (`None`, as for a full table).
/// Such a cap used to mint and then fail every pair-wide check, which left
/// the single-wheel path deciding what it meant: `motor_speed_cap_id` hands
/// the id straight to `motor_set_reporting`, whose table has four slots. A
/// capability for a motor the drivetrain does not have is authority over
/// whatever gets wired to that slot next; it is not minted.
pub fn motor_grant_cap(
    tid: u32,
    motor_id: u32,
    perms: CapPerms,
) -> Option<Cap<crate::cap::targets::Motor>> {
    if motor_id >= DRIVETRAIN_MOTORS {
        return None;
    }
    crate::cap_store::grant::<crate::cap::targets::Motor>(tid, perms, motor_id)
}

/// Does this table hold WRITE on BOTH drivetrain wheels?
///
/// The capless half of the pair rule. [`require_pair_write`] below is the
/// cap-bearing half: it dereferences a `Cap<Motor>` to learn which wheel the
/// caller named and then requires the complement. The driver-bridge path
/// (`SYS_DRV_INVOKE` with `DRV_KIND_MOTOR_PID`) has **no cap handle at all** —
/// it asks the table directly — so it needs the rule stated without one.
///
/// One function, two callers, so the rule cannot drift: `require_pair_write`
/// consults this after resolving its cap, and
/// `crates/core/syscall/src/handlers.rs::drv_invoke_authorized` consults it for the
/// motor ops that command the drivetrain.
///
/// `holds_kind_resource_with` also refuses a WRITE while RFC-0036 containment
/// is armed, so both paths inherit degraded mode from this one place.
pub fn table_holds_drivetrain_write(table: &CapTable) -> bool {
    table.holds_kind_resource_with(CapKind::Motor, 0, CapPerms::WRITE)
        && table.holds_kind_resource_with(CapKind::Motor, 1, CapPerms::WRITE)
}

/// Shared gate for every pair-wide (WRITE) motor operation.
///
/// Validates `cap` itself via `table.get` — forgery/stale/wrong-kind/
/// missing-perms/degraded-containment, exactly like every other typed
/// wrapper — and then requires that the SAME table also holds WRITE on the
/// complementary wheel (`0`↔`1`), via
/// [`CapTable::holds_kind_resource_with`]. Both checks run under the one
/// `table` borrow the caller already holds (`cap_store::with_table`), so
/// there is no second lock and no second scan.
///
/// A `resource` outside `{0, 1}` — which [`motor_grant_cap`] no longer mints,
/// but a table filled some other way could hold — always fails closed: there
/// is no "other wheel" to require, so the pair can never be satisfied. This is
/// deliberately NOT "any second Motor cap will do": see
/// `holds_kind_resource_with`'s resource-specific filter.
fn require_pair_write(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
) -> Result<(), MotorCapError> {
    let resource = table.get(cap, CapPerms::WRITE)?;
    // The cap must name a wheel this drivetrain has. Checked before the pair
    // question rather than folded into it: an out-of-range id has no
    // complement, so "the pair is unsatisfiable" and "the id is wrong" are
    // different facts and only one of them is about permissions.
    if resource >= DRIVETRAIN_MOTORS {
        return Err(MotorCapError::Cap(CapError::MissingPerms));
    }
    // Both wheels, via the shared rule. `table.get` above already proved the
    // named wheel; asking for both again costs one extra scan and keeps the
    // bridge and the typed path reading the same function.
    if !table_holds_drivetrain_write(table) {
        return Err(MotorCapError::Cap(CapError::MissingPerms));
    }
    Ok(())
}

/// Wave 12: the flight family's authority (`SYS_FLIGHT_TYPED`, arm/disarm):
/// the pair-wide WRITE gate every drivetrain command passes, without
/// commanding anything — the presented `cap` WRITE on a wheel of the
/// drivetrain AND both wheels in `table`, the console's `flight arm` check
/// (`table_holds_drivetrain_write`).
pub fn drivetrain_write_check(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
) -> Result<(), CapError> {
    require_pair_write(table, cap).map_err(|MotorCapError::Cap(e)| e)
}

/// Dereference a `Cap<Motor>` to the wheel it names, for DIRECT actuation.
///
/// # Why this exists, and why it is not pair-wide
///
/// The typed motor family (550-555) and the untyped one (230-234) are not two
/// versions of one API — they are disjoint surfaces. The typed calls write
/// shared PID state that `rt_motor_task` consumes; the untyped ones actuate a
/// single wheel through `azos_robot::motor_set`. So there was no typed way
/// to say "stop this wheel now", and `userspace/services/reflex` — whose whole job is
/// exactly that — could not move off the untyped path without becoming a
/// setpoint request that depends on the PID loop converging.
///
/// `SYS_MOTOR_SPEED_TYPED` closes that, and this is its dereference.
///
/// **Single wheel, no [`require_pair_write`], deliberately.** Its untyped twin
/// `SYS_MOTOR_SPEED` (retired in RFC-0040 gap 1) gated on one wheel, so
/// demanding both here would have made the typed call STRICTER than the call
/// it replaced. That is the same divergence avoided in
/// `drv_resource::motor_bridge_op_needs_pair`, where `MOTOR_OP_ENABLED` is
/// excluded because its typed twin is READ-only. A migration that quietly
/// changes the authority it migrates is not a migration.
///
/// The pair rule stays where it belongs: on the five PID calls, which command
/// the whole drivetrain in one operation and where "one wheel" is not a thing
/// the caller can even express.
///
/// Returns the motor id. `WRITE` because commanding a wheel is a write.
///
/// **Resolved without the containment step, and the refusal is one level
/// down.** Whether a command may move the wheel is decided in
/// `azos_robot::motor_set_reporting`, which both motor families reach:
/// while an e-stop is latched or containment is armed it admits brake and
/// coast and refuses forward and backward without writing the direction pins
/// (owner decision 2026-09-13). Refusing here with `get` would refuse this
/// call's stop (`speed_pct == 0`, a coast) while `SYS_MOTOR_SPEED`'s identical
/// stop went through. Forgery, kind and `WRITE` are still checked in full —
/// see `CapTable::get_uncontained`.
pub fn motor_speed_cap_id(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
) -> Result<u32, MotorCapError> {
    Ok(table.get_uncontained(cap, CapPerms::WRITE)?)
}

/// Typed `motor_pid_set_target`: pair-wide WRITE (see module doc).
pub fn motor_set_target_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
    speed_l: i16,
    speed_r: i16,
) -> Result<(), MotorCapError> {
    require_pair_write(table, cap)?;
    motor_pid_set_target(speed_l, speed_r);
    Ok(())
}

/// Typed `motor_pid_tick`: pair-wide WRITE (the PID loop updates its
/// integrator for both wheels at once). Returns `(pwm_l, pwm_r)`.
pub fn motor_tick_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
    ticks_l: i64,
    ticks_r: i64,
    now: u64,
) -> Result<(i32, i32), MotorCapError> {
    require_pair_write(table, cap)?;
    Ok(motor_pid_tick(ticks_l, ticks_r, now))
}

/// Typed `motor_pid_enable`: pair-wide WRITE. `en = false` disables,
/// `true` enables.
pub fn motor_enable_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
    en: bool,
) -> Result<(), MotorCapError> {
    require_pair_write(table, cap)?;
    motor_pid_enable(en);
    Ok(())
}

/// Typed `motor_pid_enabled`: single-cap READ (not an actuation — see
/// module doc for why this one function does not pair-check).
pub fn motor_enabled_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
) -> Result<bool, MotorCapError> {
    let _ = table.get(cap, CapPerms::READ)?;
    Ok(motor_pid_enabled())
}

/// Typed `motor_pid_set_gains`: pair-wide WRITE.
pub fn motor_set_gains_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
    kp: i32,
    ki: i32,
    kd: i32,
) -> Result<(), MotorCapError> {
    require_pair_write(table, cap)?;
    motor_pid_set_gains(kp, ki, kd);
    Ok(())
}

/// Typed `motor_pid_reset`: pair-wide WRITE. Clears integrator + previous
/// error.
pub fn motor_reset_cap(
    table: &CapTable,
    cap: Cap<crate::cap::targets::Motor>,
) -> Result<(), MotorCapError> {
    require_pair_write(table, cap)?;
    motor_pid_reset();
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────
//
// `azos_drv_actuator::motor_pid` is real hardware-simulation state (RV64-only
// via its `azos_sync::SpinLock`/`azos_arch` chain in the full crate
// graph), so these tests only run when this file is pulled in — same trick
// as `cap.rs` — by a host test crate that supplies host stand-ins for
// `azos_sync`/`azos_sched`/`azos_drv_actuator`. See
// `tests/host/topology-tests` (RFC-0003 migration phase P1).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::targets::{Gpio, Motor};

    #[test]
    fn pair_write_requires_both_wheels() {
        let mut t = CapTable::empty();
        let left: Cap<Motor> = motor_grant_cap_into(&mut t, 0, CapPerms::RW);
        // Only the left wheel is held — every pair-wide op must deny.
        assert_eq!(
            motor_set_target_cap(&t, left, 10, 10),
            Err(MotorCapError::Cap(CapError::MissingPerms))
        );
        assert_eq!(
            motor_enable_cap(&t, left, true),
            Err(MotorCapError::Cap(CapError::MissingPerms))
        );

        // Grant the right wheel too — now the pair is complete.
        let _right: Cap<Motor> = motor_grant_cap_into(&mut t, 1, CapPerms::RW);
        assert_eq!(motor_set_target_cap(&t, left, 10, 10), Ok(()));
        assert_eq!(motor_enable_cap(&t, left, true), Ok(()));
    }

    #[test]
    fn pair_write_denies_read_only_grants() {
        let mut t = CapTable::empty();
        let left: Cap<Motor> = motor_grant_cap_into(&mut t, 0, CapPerms::READ);
        let _right: Cap<Motor> = motor_grant_cap_into(&mut t, 1, CapPerms::READ);
        // Both wheels present, but neither carries WRITE.
        assert_eq!(
            motor_set_target_cap(&t, left, 0, 0),
            Err(MotorCapError::Cap(CapError::MissingPerms))
        );
    }

    #[test]
    fn out_of_range_motor_id_can_never_satisfy_the_pair() {
        let mut t = CapTable::empty();
        // A cap minted for a motor id the drivetrain does not have.
        let odd: Cap<Motor> = motor_grant_cap_into(&mut t, 7, CapPerms::RW);
        assert_eq!(
            motor_set_target_cap(&t, odd, 0, 0),
            Err(MotorCapError::Cap(CapError::MissingPerms))
        );
    }

    #[test]
    fn enabled_query_is_single_cap_not_pair_wide() {
        let mut t = CapTable::empty();
        // Only the left wheel granted — READ query still succeeds.
        let left: Cap<Motor> = motor_grant_cap_into(&mut t, 0, CapPerms::READ);
        assert!(motor_enabled_cap(&t, left).is_ok());
    }

    #[test]
    fn wrong_kind_still_rejected_before_pairing_logic() {
        let mut t = CapTable::empty();
        let gpio: Cap<Gpio> = t.grant(CapPerms::RW, 0).unwrap();
        let forged: Cap<Motor> = Cap::from_raw(gpio.raw());
        assert_eq!(
            motor_set_target_cap(&t, forged, 0, 0),
            Err(MotorCapError::Cap(CapError::WrongKind))
        );
    }

    /// Test-only helper: grant directly into a `CapTable` (these tests
    /// exercise the table-level functions, not `cap_store`/TIDs).
    fn motor_grant_cap_into(
        table: &mut CapTable,
        motor_id: u32,
        perms: CapPerms,
    ) -> Cap<Motor> {
        table.grant(perms, motor_id).unwrap()
    }
}
