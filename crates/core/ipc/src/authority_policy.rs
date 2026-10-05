// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The per-command authority table of consequential commands and the
//! decisions made over it, with no dependency but `azos_abi`.
//!
//! Both consoles consume it (RFC-0055 S5): the recovery console
//! (`crates/core/shell/src/authority.rs`, over the console's own capability
//! table) and the ring-3 tool images, through the typed syscall of each
//! command's family (`crates/core/syscall/src/power.rs` for the power family,
//! `crates/core/syscall/src/families.rs` for flight/behavior/config/OTA),
//! over the CALLING image's table. It lives in `azos_ipc`, the lowest crate
//! both sides already depend on, and stays dependency-free so
//! `tests/host/shell-tests` can pull it by `#[path]` and run the decisions on
//! the host. Whether a command is enforced and whether it may proceed are
//! decided HERE; the callers only supply the facts this file cannot see (the
//! Kconfig switch, whether a table holds the kind).

use azos_abi::cap::CapKind;

/// One row of the authority table U11-5 asked for: which `CapKind` a
/// consequential command needs, and whether that need is checked on every
/// build or only under the production console lockdown
/// (`CONFIG_CONSOLE_LOCKDOWN`, config/Kconfig.mitigations).
pub struct AuthorityRow {
    pub cmd: &'static str,
    pub kind: CapKind,
    pub need_write: bool,
    /// Checked on every build. `false`: checked only under the lockdown.
    pub always: bool,
}

/// `flight arm` and `pm suspend` have been checked on every build since wave 3;
/// `reboot` and `shutdown` since wave 11 (see [`CMD_REBOOT`]).
pub const CMD_FLIGHT_ARM: &str = "flight arm";
/// See [`CMD_FLIGHT_ARM`].
pub const CMD_PM_SUSPEND: &str = "pm suspend";
/// The four rows the console lockdown adds. Each needs `Cap<Power>` WRITE,
/// which has had a production minter (`cap::power_grant_cap`) since wave 3.
pub const CMD_BEHAVIOR_DISABLE: &str = "behavior disable";
/// See [`CMD_BEHAVIOR_DISABLE`].
pub const CMD_SCHED_HZ_SET: &str = "sched_hz set";
/// See [`CMD_BEHAVIOR_DISABLE`].
pub const CMD_CONFIG_SET_WATCHDOG: &str = "config set (watchdog_ms)";
/// See [`CMD_BEHAVIOR_DISABLE`].
pub const CMD_OTA_ROLLBACK: &str = "ota rollback";

/// Every consequential shell command U11-5 named, with the `CapKind` its
/// action maps to.
pub const AUTHORITY_TABLE: &[AuthorityRow] = &[
    AuthorityRow { cmd: CMD_FLIGHT_ARM, kind: CapKind::Motor, need_write: true, always: true },
    AuthorityRow { cmd: CMD_BEHAVIOR_DISABLE, kind: CapKind::Power, need_write: true, always: false },
    AuthorityRow { cmd: CMD_SCHED_HZ_SET, kind: CapKind::Power, need_write: true, always: false },
    AuthorityRow { cmd: CMD_CONFIG_SET_WATCHDOG, kind: CapKind::Power, need_write: true, always: false },
    AuthorityRow { cmd: CMD_PM_SUSPEND, kind: CapKind::Power, need_write: true, always: true },
    AuthorityRow { cmd: CMD_OTA_ROLLBACK, kind: CapKind::Power, need_write: true, always: false },
    AuthorityRow { cmd: CMD_REBOOT, kind: CapKind::Power, need_write: true, always: true },
    AuthorityRow { cmd: CMD_SHUTDOWN, kind: CapKind::Power, need_write: true, always: true },
];

/// The row for `cmd`, if the table names it.
pub fn row(cmd: &str) -> Option<&'static AuthorityRow> {
    AUTHORITY_TABLE.iter().find(|r| r.cmd == cmd)
}

/// Is `row`'s capability checked on a build whose lockdown switch is `lockdown`?
pub fn enforced(row: &AuthorityRow, lockdown: bool) -> bool {
    row.always || lockdown
}

/// The capability kinds the console is seeded with at boot
/// (`authority::seed_console_authority`): `Cap<Motor>` WRITE on both
/// drivetrain wheels, `Cap<Power>` WRITE, and (wave 12, owner round 48)
/// `Cap<Task>` READ on `"tasks"`, the full `/proc` task view a console `cat
/// /proc/tasks` reads through (without it, the console's own subtree only).
///
/// **None under the console lockdown** (owner round 36, wave 11). The lockdown
/// used to add four checked rows while still handing the console both
/// capabilities, so every checked command — `flight arm` and `pm suspend`
/// included — still passed its check. Withheld, the console holds no
/// authority over an irreversible effect: every row is refused, recorded,
/// and a console session can no longer arm the drivetrain, suspend, reboot
/// or power off the board. Default n, so a development build is unchanged.
pub const fn console_seed_kinds(lockdown: bool) -> &'static [CapKind] {
    if lockdown {
        &[]
    } else {
        &[CapKind::Motor, CapKind::Power, CapKind::Task]
    }
}

/// May the command proceed? `holds`: the console holds `row.kind` WRITE.
/// A command the table does not name is not a consequential one: it proceeds.
pub fn may_proceed(cmd: &str, lockdown: bool, holds: bool) -> bool {
    match row(cmd) {
        Some(r) => !enforced(r, lockdown) || holds,
        None => true,
    }
}

// ── The ring-3 forms (RFC-0055 S5) ──────────────────────────────────────────
//
// An authority-table command gets a ring-3 form only once a typed syscall for
// its family exists; until then it stays a recovery-console command. The
// enforcement point moves from "the console's own table" to "the calling
// image's table at the typed syscall", and the ring-3 check is ALWAYS made:
// the `always`/lockdown distinction above exists because the console is
// seeded with the capabilities by default, while a ring-3 image holds only
// what its topology row grants.

/// `reboot`: an orderly reboot (the console's `reboot`, ring 3's `power
/// reboot`, syscall 271). An `AUTHORITY_TABLE` row checked on every build, as
/// `pm suspend`: ring 3 has always needed `Cap<Power>` WRITE for it, and the
/// console's `reboot` used to be the one way to the same effect without it.
pub const CMD_REBOOT: &str = "reboot";
/// `shutdown`: an orderly power-off (the console's `shutdown`, ring 3's
/// `power shutdown`, syscall 270). See [`CMD_REBOOT`].
pub const CMD_SHUTDOWN: &str = "shutdown";
/// `power sched_hz` with no argument: read the scheduler rate.
pub const CMD_SCHED_HZ_GET: &str = "sched_hz";

/// What one ring-3 operation needs: the command it is (for the refusal line,
/// the same words the console prints), the kind, and whether `WRITE` (else
/// `READ`) is needed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring3Need {
    /// The command, as the console spells it.
    pub cmd: &'static str,
    /// The capability kind the calling image must hold.
    pub kind: CapKind,
    /// `WRITE` is needed; `false` = `READ`.
    pub need_write: bool,
}

/// The kind and right a row of the table needs, for the ring-3 form. A row's
/// `always` flag is not consulted: ring 3 always checks.
const fn need_of(r: &AuthorityRow) -> Ring3Need {
    Ring3Need { cmd: r.cmd, kind: r.kind, need_write: r.need_write }
}

/// What `SYS_POWER_TYPED` operation `op` needs, or `None` for an operation
/// the family does not have. Every operation but the rate read takes its row
/// from [`AUTHORITY_TABLE`], so the console and ring 3 can never disagree on
/// which capability they need.
pub fn power_op_need(op: u64) -> Option<Ring3Need> {
    use azos_abi::power::*;
    let table_row = |cmd: &str| row(cmd).map(need_of);
    match op {
        POWER_OP_SUSPEND => table_row(CMD_PM_SUSPEND),
        POWER_OP_SCHED_HZ_SET => table_row(CMD_SCHED_HZ_SET),
        POWER_OP_REBOOT => table_row(CMD_REBOOT),
        POWER_OP_SHUTDOWN => table_row(CMD_SHUTDOWN),
        POWER_OP_SCHED_HZ_GET => Some(Ring3Need { cmd: CMD_SCHED_HZ_GET, kind: CapKind::Power, need_write: false }),
        _ => None,
    }
}

// Wave 12: the ring-3 operations the console runs without a table row (it
// does not gate them), named for the refusal line and the record.
/// `SYS_FLIGHT_TYPED`'s disarm.
pub const CMD_FLIGHT_DISARM: &str = "flight disarm";
/// `SYS_BEHAVIOR_TYPED`'s enable.
pub const CMD_BEHAVIOR_ENABLE: &str = "behavior enable";
/// `SYS_BEHAVIOR_TYPED`'s mask read.
pub const CMD_BEHAVIOR_STATUS: &str = "behavior status";
/// `SYS_CONFIG_TYPED`'s read.
pub const CMD_CONFIG_GET: &str = "config get";
/// `SYS_CONFIG_TYPED`'s write, of any key.
pub const CMD_CONFIG_SET: &str = "config set";
/// `SYS_OTA_TYPED`'s status word.
pub const CMD_OTA_STATUS: &str = "ota status";

/// What `SYS_FLIGHT_TYPED` operation `op` needs (wave 12). Both operations
/// are pair-wide `Cap<Motor>` WRITE: arming takes the table's `flight arm`
/// row; disarming, which the console does not gate, needs the same right
/// from ring 3 (a task that may not arm the drivetrain may not disarm it in
/// flight either).
pub fn flight_op_need(op: u64) -> Option<Ring3Need> {
    use azos_abi::families::*;
    match op {
        FLIGHT_OP_ARM => row(CMD_FLIGHT_ARM).map(need_of),
        FLIGHT_OP_DISARM => Some(Ring3Need { cmd: CMD_FLIGHT_DISARM, kind: CapKind::Motor, need_write: true }),
        _ => None,
    }
}

/// What `SYS_BEHAVIOR_TYPED` operation `op` needs (wave 12): `behavior
/// disable` from the table; `enable` the same `Cap<Power>` WRITE; the mask
/// read `READ`.
pub fn behavior_op_need(op: u64) -> Option<Ring3Need> {
    use azos_abi::families::*;
    match op {
        BEHAVIOR_OP_DISABLE => row(CMD_BEHAVIOR_DISABLE).map(need_of),
        BEHAVIOR_OP_ENABLE => Some(Ring3Need { cmd: CMD_BEHAVIOR_ENABLE, kind: CapKind::Power, need_write: true }),
        BEHAVIOR_OP_STATUS => Some(Ring3Need { cmd: CMD_BEHAVIOR_STATUS, kind: CapKind::Power, need_write: false }),
        _ => None,
    }
}

/// What `SYS_CONFIG_TYPED` operation `op` needs (wave 12). Setting ANY key
/// needs `Cap<Power>` WRITE from ring 3 — the table's `config set
/// (watchdog_ms)` row names the one key the console checks, and only under
/// its lockdown; a ring-3 tool is checked on every call, for every key,
/// because every key reaches `apply_config_to_subsystems` (network, rates,
/// layers, watchdog). Reading needs `READ`.
pub fn config_op_need(op: u64) -> Option<Ring3Need> {
    use azos_abi::families::*;
    match op {
        CONFIG_OP_SET => row(CMD_CONFIG_SET_WATCHDOG)
            .map(|r| Ring3Need { cmd: CMD_CONFIG_SET, kind: r.kind, need_write: r.need_write }),
        CONFIG_OP_GET => Some(Ring3Need { cmd: CMD_CONFIG_GET, kind: CapKind::Power, need_write: false }),
        _ => None,
    }
}

/// What `SYS_OTA_TYPED` operation `op` needs (wave 12): `ota rollback` from
/// the table; the status word `READ`.
pub fn ota_op_need(op: u64) -> Option<Ring3Need> {
    use azos_abi::families::*;
    match op {
        OTA_OP_ROLLBACK => row(CMD_OTA_ROLLBACK).map(need_of),
        OTA_OP_STATUS => Some(Ring3Need { cmd: CMD_OTA_STATUS, kind: CapKind::Power, need_write: false }),
        _ => None,
    }
}

/// The `AUTHORITY_TABLE` commands that have a ring-3 form, and the typed
/// syscall that carries it. A command absent here is recovery-console only;
/// `tests/host/shell-tests` refuses an entry whose syscall is not a typed one.
/// Wave 12: every row has one.
pub const RING3_FORMS: &[(&str, u64)] = &[
    (CMD_PM_SUSPEND, azos_abi::syscall_nr::SYS_POWER_TYPED),
    (CMD_SCHED_HZ_SET, azos_abi::syscall_nr::SYS_POWER_TYPED),
    (CMD_REBOOT, azos_abi::syscall_nr::SYS_POWER_TYPED),
    (CMD_SHUTDOWN, azos_abi::syscall_nr::SYS_POWER_TYPED),
    (CMD_FLIGHT_ARM, azos_abi::syscall_nr::SYS_FLIGHT_TYPED),
    (CMD_BEHAVIOR_DISABLE, azos_abi::syscall_nr::SYS_BEHAVIOR_TYPED),
    (CMD_CONFIG_SET_WATCHDOG, azos_abi::syscall_nr::SYS_CONFIG_TYPED),
    (CMD_OTA_ROLLBACK, azos_abi::syscall_nr::SYS_OTA_TYPED),
];
