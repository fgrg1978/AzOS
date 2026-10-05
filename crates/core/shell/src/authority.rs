// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-command authority for the console — W2-B4 task 1 (audit U11-5).
//!
//! U11-5 named the defect precisely: "a shell command carries the kernel's
//! full authority; the syscall path carries four checks the shell has none
//! of." The four checks a ring-3 program gets are seccomp, capability lookup,
//! the fast-IPC/typed-cap gate, and an audit record. The shell had none.
//!
//! ## The one fact that decides the whole design
//!
//! The shell is a **kernel task** (`kernel/src/tasks/system.rs`,
//! `task_create("shell", shell_task, 0, 13)`, no user page table). The
//! untyped capability check every syscall handler calls,
//! `crates/core/syscall::handlers::cap_check`, opens with:
//!
//! ```text
//! if azos_sched::current_user_pt() == 0 { return true; }
//! ```
//!
//! That is "kernel tasks have full access" — correct for the syscall path
//! (a kernel task never reaches it; only ring 3 issues syscalls), but it
//! means calling `cap_check` FROM the shell would always return `true` and
//! prove nothing. This module does not call `cap_check`. It calls the same
//! `CapTable` machinery `cap_check` itself calls once past that bypass line:
//! `azos_ipc::cap_store::with_table` plus the exact predicate the typed
//! motor path already uses, `azos_ipc::motor_cap::
//! table_holds_drivetrain_write`. That is "the same function the syscall
//! path uses" in the sense that matters — the actual authority predicate,
//! not the wrapper that special-cases the caller this module IS.
//!
//! ## Which rows are checked
//!
//! `azos_ipc::cap_seed` names, in its own module doc, which `CapKind`s
//! have a production minter: `Gpio`, `Pwm`, `Motor`, `I2c`, `Channel`,
//! `Sensor`, `DriverRegistry`, `MmioRegion`, `Endpoint`, and — since wave 3
//! (2026-09-26) — `Power` and `AiSession` (`cap.rs::power_grant_cap`/
//! `ai_session_grant_cap`). Owner decision: one authority per irreversible
//! effect, so `pm suspend` checks the capability the table actually names
//! instead of standing in on `Cap<Motor>` WRITE (see [`seed_console_authority`]).
//! The console's one `Cap<AiSession>` command, `model load`, went with the
//! in-kernel MLP it loaded weights into (wave 10: the MLP runs in the ring-3
//! ML service), so the console no longer holds that capability.
//!
//! `flight arm`, `pm suspend`, `reboot` and `shutdown` are checked on every
//! build (`reboot`/`shutdown` since wave 11: ring 3's `power reboot`/`power
//! shutdown` always needed `Cap<Power>` WRITE, and the console's unchecked
//! forms were the way around it). Like `pm suspend`, they are therefore also
//! refused during a containment episode (see "Known imprecision"). `behavior
//! disable`, `sched_hz <hz>`, `config set watchdog_ms` and `ota rollback`
//! need `Cap<Power>` WRITE too, which has had a minter since wave 3; they are
//! checked under the production console lockdown (`CONFIG_CONSOLE_LOCKDOWN`,
//! wave 11), not by default: the predicate also answers "no" during an
//! RFC-0036 containment episode (see "Known imprecision" at the end), so
//! checking them on every build would refuse `behavior disable` in the middle
//! of one. The table and the decision live in `authority_policy.rs`,
//! host-tested by `tests/host/shell-tests`.
//!
//! ## Seeding
//!
//! [`seed_console_authority`] mints the console's own `Cap<Motor>` pair
//! through `motor_cap::motor_grant_cap` — the SAME minter
//! `kernel/src/tasks/loader.rs`'s autorun block calls for a ring-3 task's topology
//! row, just called for the shell's own TID instead of a program it is about
//! to `exec` — and, since wave 3, `Cap<Power>` WRITE through
//! `cap::power_grant_cap`, the same shape.
//! The console had implicit, unrecorded, unrevocable authority before;
//! after this it holds explicit, checkable, revocable capabilities like any
//! other holder, and can be seeded with less on a build that wants a
//! console with no drivetrain/power authority at all (call
//! sites: none yet — today it is unconditional, matching the "physical
//! console" trust model U11-5 accepts; a board Kconfig gate is future work,
//! not required to make the check real).

use azos_abi::cap::{CapKind, CapPerms};
use azos_ipc::cap::CapError;
use azos_ipc::{cap, cap_store, motor_cap};

pub use crate::authority_policy::AUTHORITY_TABLE;
use crate::authority_policy as policy;

/// The production console lockdown switch (Kconfig `CONSOLE_LOCKDOWN`).
pub const LOCKDOWN: bool = azos_limits::CONSOLE_LOCKDOWN;

/// Is `row` checked on this build?
pub fn row_enforced(row: &policy::AuthorityRow) -> bool {
    policy::enforced(row, LOCKDOWN)
}

/// Seed the console's own capability table. Call once, from the shell task,
/// before the command loop starts.
///
/// What it mints is `authority_policy::console_seed_kinds(LOCKDOWN)`: nothing
/// under the console lockdown (owner round 36), so every checked command is
/// refused there, `flight arm`, `pm suspend`, `reboot` and `shutdown` included.
pub fn seed_console_authority() {
    let tid = azos_sched::current_task_tid();
    let kinds = policy::console_seed_kinds(LOCKDOWN);
    if kinds.is_empty() {
        azos_drv_sys::kwarn!(
            "[AUTHORITY] console lockdown: Cap<Motor>/Cap<Power> withheld — flight arm, \
             pm suspend, reboot, shutdown and the lockdown rows are refused");
    }
    for &kind in kinds {
        match kind {
            CapKind::Motor => {
                for id in 0..motor_cap::DRIVETRAIN_MOTORS {
                    let _ = motor_cap::motor_grant_cap(tid, id, CapPerms::WRITE);
                }
            }
            // Wave 3 (2026-09-26): the console's OWN authority, not a stand-in
            // on `Cap<Motor>` — same shape, same TID, the minters `cap.rs`
            // gained this wave.
            CapKind::Power => {
                let _ = cap::power_grant_cap(tid, CapPerms::WRITE);
            }
            // Wave 12 (owner round 48): the full `/proc` task view, through
            // the topology's own minter so the target spelling is one.
            CapKind::Task => {
                let _ = azos_ipc::cap_seed::seed_one_cap(tid, CapKind::Task, CapPerms::READ, "tasks");
            }
            _ => {}
        }
    }
}

/// Does the console currently hold `Cap<Motor>` WRITE on both drivetrain
/// wheels? The exact predicate `crates/core/ipc/src/motor_cap.rs`'s typed
/// dereference and the driver-bridge path both consult.
pub fn console_holds_drivetrain_write() -> bool {
    let tid = azos_sched::current_task_tid();
    cap_store::with_table(tid, |t| motor_cap::table_holds_drivetrain_write(t)).unwrap_or(false)
}

/// Write one `SAFETY_CAP_DENIED_TYPED` record for a refused command and
/// print a refusal line. The printed string ("AUTHORITY ... REFUSED") is
/// failure-only: `flight arm`'s success path (`cmd_flight`) never prints it,
/// so a gate row can grep for it as proof of the negative case without also
/// matching the positive one.
fn record_denial(cmd: &str, kind: CapKind) {
    azos_drv_sys::kconsoleln!(
        "[AUTHORITY] {} REFUSED: console lacks Cap<{:?}> WRITE", cmd, kind);
    let _ = azos_actuation::logger::log_safety_violation_durable(
        azos_actuation::logger::SAFETY_CAP_DENIED_TYPED,
        kind.denial_code(),
        CapError::MissingPerms.code(),
    );
}

/// `flight arm`'s authority gate — task 1's specified RED ("a console
/// without `Cap<Motor>` cannot `flight arm`"). Returns `true` iff the
/// command may proceed.
#[cfg(feature = "domain-robot")]
pub fn check_flight_arm() -> bool {
    if console_holds_drivetrain_write() {
        true
    } else {
        record_denial("flight arm", CapKind::Motor);
        false
    }
}

/// Does the console currently hold `Cap<Power>` WRITE? Same shape as
/// [`console_holds_drivetrain_write`], for `cap::table_holds_power_write`.
pub fn console_holds_power_write() -> bool {
    let tid = azos_sched::current_task_tid();
    cap_store::with_table(tid, |t| cap::table_holds_power_write(t)).unwrap_or(false)
}

/// `pm suspend`'s authority gate. Wave 3 (2026-09-26): checks the console's
/// OWN `Cap<Power>` WRITE — the stopgap that checked `Cap<Motor>` WRITE
/// instead is gone now that `Cap<Power>` has a minter (see the module doc).
pub fn check_pm_suspend() -> bool {
    if console_holds_power_write() {
        true
    } else {
        record_denial("pm suspend", CapKind::Power);
        false
    }
}

/// The `Cap<Power>` WRITE gate of the four rows the console lockdown adds
/// (`authority_policy::CMD_BEHAVIOR_DISABLE` and its siblings). Off the
/// lockdown it proceeds without looking; under it, as [`check_pm_suspend`].
/// Returns `true` iff the command may proceed.
pub fn check_power_row(cmd: &'static str) -> bool {
    // Look the capability up only when the row is enforced: off the lockdown
    // nothing changes, not even a table read.
    let enforced = policy::row(cmd).map(row_enforced).unwrap_or(false);
    if policy::may_proceed(cmd, LOCKDOWN, enforced && console_holds_power_write()) {
        true
    } else {
        record_denial(cmd, CapKind::Power);
        false
    }
}

// No `#[cfg(test)]` module here: `azos_sched`/`azos_ipc`/
// `azos_drv_*`/`azos_behavior` are the REAL kernel crates and do
// not host-compile (arch-specific asm, MMIO). The decision itself (which row
// is enforced, under which switch) is host-tested through
// `authority_policy.rs` in `tests/host/shell-tests`; what only QEMU can show is
// the capability lookup. The lockdown's four rows: a `CONSOLE_LOCKDOWN=y`
// kernel with the seed call below commented out refuses all four
// (`[AUTHORITY] <cmd> REFUSED`), the same edit on a default kernel lets them
// through (run by hand 2026-10-02, riscv64). The RED→GREEN proof for
// the two always-checked rows is the QEMU canary: comment out the
// `authority::seed_console_authority()` call in `shell_run`, boot, run
// `flight arm`/`pm suspend`, observe `[AUTHORITY] <cmd> REFUSED` and that
// the command's own success line does NOT print (`[FLIGHT]`/`esc_arm` for
// `flight arm`, `[PM] Entering suspend...` for `pm suspend`); restore the
// call, reboot, observe both proceed. Third
// bucket: deleting `table_holds_power_write`'s (or its siblings') import is
// a compile error, not a runtime failure — the canary's third bucket.
//
// **Known imprecision, not fixed here.** `table_holds_drivetrain_write`/
// `table_holds_power_write` both answer on the
// *contained* predicate (`holds_kind_resource_with`, which also refuses a
// WRITE while RFC-0036 containment is armed — see
// `crates/core/ipc/src/motor_cap.rs`'s own doc on that function). During a
// containment episode this reads identically to "no capability", so
// `record_denial` writes a `SAFETY_CAP_DENIED_TYPED` record with
// `MissingPerms` even though the real cause is containment, not a missing
// grant — a shape `logger.rs`'s own doc on that record says containment
// must never produce (`CapError::Contained` is filtered by `is_denial()`
// on every OTHER path that writes this record). This module cannot filter
// it the same way because these predicates return `bool`, not
// `Result<(), CapError>` — unlike the single-cap `get`/`get_uncontained`,
// they do not distinguish "absent" from "contained". Fixing this needs a
// `crates/core/ipc` change (not this front's) or a second, containment-aware
// call here. Rare in practice — the false denial fires only inside an
// already-degraded episode — but it is a real small mismeasurement of
// "why", not just "whether".
