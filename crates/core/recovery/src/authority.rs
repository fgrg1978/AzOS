// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Per-command authority for the recovery console (audit U11-5).
//!
//! The console is a kernel task, and `handlers::cap_check` lets every kernel
//! task through (`current_user_pt() == 0`), so it cannot be asked. This module
//! calls the machinery `cap_check` itself calls past that bypass: the console's
//! own `CapTable` (`azos_ipc::cap_store`) and the same predicates the kernel's
//! endpoint servers use. The table and the decision are `authority_policy.rs`
//! (host-tested by `tests/host/shell-tests`); only the capability lookup lives
//! here.
//!
//! The commands this console has that the table names: `reboot` and
//! `shutdown` (checked on every build), `ota rollback` and `config set
//! watchdog_ms` (checked under `CONSOLE_LOCKDOWN`, where the console does not
//! exist; kept for a build that gives the console a signed row). The ring-3
//! forms of these (`power`, `ota`, `config` endpoints) are checked by the
//! kernel-hosted interfaces, over the calling image's capability.
//!
//! [`seed_console_authority`] mints what `authority_policy::console_seed_kinds`
//! and `console_seed_ifaces` name, through the same minters the topology uses
//! for a ring-3 row.

use azos_abi::cap::{CapKind, CapPerms};
use azos_ipc::cap::CapError;
use azos_ipc::{cap_store, endpoint};

use crate::authority_policy as policy;

/// The production console lockdown switch (Kconfig `CONSOLE_LOCKDOWN`).
pub const LOCKDOWN: bool = azos_limits::CONSOLE_LOCKDOWN;

/// Is `row` checked on this build?
pub fn row_enforced(row: &policy::AuthorityRow) -> bool {
    policy::enforced(row, LOCKDOWN)
}

/// Seed the console's own capability table. Call once, from the recovery task,
/// before the command loop starts.
///
/// What it mints is `authority_policy::console_seed_kinds(LOCKDOWN)` and
/// `console_seed_ifaces(LOCKDOWN)`: nothing under the console lockdown (owner
/// round 36), so every checked command is refused there, `reboot` and
/// `shutdown` included.
pub fn seed_console_authority() {
    let tid = azos_sched::current_task_tid();
    let kinds = policy::console_seed_kinds(LOCKDOWN);
    if kinds.is_empty() {
        azos_drv_sys::kwarn!(
            "[AUTHORITY] console lockdown: the task view and the power, config and ota endpoints \
             withheld — reboot, shutdown and the lockdown rows are refused");
    }
    for &kind in kinds {
        match kind {
            // Wave 12 (owner round 48): the full task view, through
            // the topology's own minter so the target spelling is one.
            azos_ipc::cap::ty::TASK => {
                let _ = azos_ipc::cap_seed::seed_one_cap(tid, CapKind::Domain, CapPerms::READ, "tasks");
            }
            _ => {}
        }
    }
    // The console's OWN authority over the irreversible effects it still
    // offers: `WRITE` on the endpoints of `reboot`/`shutdown`, `config set` and
    // `ota rollback`, the rights the ring-3 tools hold from their rows.
    for &iface in policy::console_seed_ifaces(LOCKDOWN) {
        let _ = endpoint::kernel_endpoint_cap(tid, CapPerms::WRITE, iface, 0);
    }
}

/// Write one `SAFETY_CAP_DENIED_TYPED` record for a refused command and
/// print a refusal line. The printed string ("AUTHORITY ... REFUSED") is
/// failure-only: a command's success path never prints it, so a gate row can grep for it as proof of the negative case without also
/// matching the positive one.
fn record_denial(cmd: &str) {
    azos_drv_sys::kconsoleln!(
        "[AUTHORITY] {} REFUSED: console lacks the endpoint right WRITE", cmd);
    let _ = azos_actuation::logger::log_safety_violation_durable(
        azos_actuation::logger::SAFETY_CAP_DENIED_TYPED,
        CapKind::Endpoint.denial_code(),
        CapError::MissingPerms.code(),
    );
}

/// Does the console currently hold `WRITE` on the endpoint the kernel hosts
/// under `iface`?
fn console_holds_write(iface: u16) -> bool {
    let tid = azos_sched::current_task_tid();
    cap_store::with_table(tid, |t| endpoint::table_holds_host_right(t, iface, CapPerms::WRITE)).unwrap_or(false)
}

/// The endpoint `WRITE` gate of a table row (`authority_policy::CMD_REBOOT`
/// and its siblings). A row checked on every build looks the capability up;
/// a lockdown-only row proceeds without looking off the lockdown. Returns
/// `true` iff the command may proceed.
pub fn check_power_row(cmd: &'static str) -> bool {
    // Look the capability up only when the row is enforced: off the lockdown
    // nothing changes, not even a table read.
    let row = policy::row(cmd);
    let enforced = row.map(row_enforced).unwrap_or(false);
    let holds = enforced && row.is_some_and(|r| console_holds_write(r.iface));
    if policy::may_proceed(cmd, LOCKDOWN, holds) {
        true
    } else {
        record_denial(cmd);
        false
    }
}

// No `#[cfg(test)]` module here: `azos_sched`/`azos_ipc`/
// `azos_drv_*`/`azos_behavior` are the REAL kernel crates and do
// not host-compile (arch-specific asm, MMIO). The decision itself (which row
// is enforced, under which switch) is host-tested through
// `authority_policy.rs` in `tests/host/shell-tests`; what only QEMU can show is
// the capability lookup. The RED->GREEN proof for `reboot`/`shutdown` is the
// QEMU canary: comment out the `authority::seed_console_authority()` call in
// `recovery_run`, boot, run `reboot`, observe `[AUTHORITY] reboot REFUSED` and
// that `System reboot...` does NOT print; restore the call, observe it proceed.
//
// **Known imprecision, not fixed here.** `table_holds_host_right` answers on the
// *contained* predicate (`holds_kind_resource_with`, which also refuses a
// WRITE while degraded-mode containment is armed — see
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
