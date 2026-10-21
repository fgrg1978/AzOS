// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The per-command authority table of consequential commands and the
//! decisions made over it, with no dependency but `azos_abi`.
//!
//! The recovery console consumes it, over the console's own
//! capability table. The ring-3 tool images are checked per op by the
//! kernel-hosted interfaces they call (`crates/core/syscall/src/power.rs` for
//! the power family, `crates/core/syscall/src/families.rs` for
//! flight/behavior/config/OTA), over the CALLING image's capability: the same
//! commands, the same endpoint and the same right. It lives in `azos_ipc`,
//! the lowest crate both sides already depend on, and stays small so
//! `tests/host/shell-tests` can pull it by `#[path]` and run the decisions on
//! the host. Whether a command is enforced and whether it may proceed are
//! decided HERE; the callers only supply the facts this file cannot see (the
//! Kconfig switch, whether a table holds the endpoint right).

use azos_abi::cap::ty;
use azos_abi::cap::CapType;
use azos_devif::key;

/// One row of the authority table U11-5 asked for: which kernel-hosted
/// endpoint (host key, `azos_devif::key`) a consequential command needs the
/// `WRITE` right on, and whether that need is checked on every build or only
/// under the production console lockdown (`CONFIG_CONSOLE_LOCKDOWN`,
/// config/Kconfig.mitigations).
pub struct AuthorityRow {
    pub cmd: &'static str,
    /// The host key of the endpoint the command acts through.
    pub iface: u16,
    pub need_write: bool,
    /// Checked on every build. `false`: checked only under the lockdown.
    pub always: bool,
}

/// The two rows the console lockdown adds beside `reboot` and `shutdown`
/// (see [`CMD_REBOOT`]); each needs `WRITE` on its interface's endpoint.
/// `config set` of ANY key needs it from ring 3; the console checks only
/// `watchdog_ms`.
pub const CMD_CONFIG_SET_WATCHDOG: &str = "config set (watchdog_ms)";
/// See [`CMD_CONFIG_SET_WATCHDOG`].
pub const CMD_OTA_ROLLBACK: &str = "ota rollback";

/// Every consequential shell command U11-5 named, with the endpoint its
/// action maps to.
pub const AUTHORITY_TABLE: &[AuthorityRow] = &[
    AuthorityRow { cmd: CMD_CONFIG_SET_WATCHDOG, iface: key::CONFIG, need_write: true, always: false },
    AuthorityRow { cmd: CMD_OTA_ROLLBACK, iface: key::OTA, need_write: true, always: false },
    AuthorityRow { cmd: CMD_REBOOT, iface: key::POWER, need_write: true, always: true },
    AuthorityRow { cmd: CMD_SHUTDOWN, iface: key::POWER, need_write: true, always: true },
];

/// The row for `cmd`, if the table names it.
pub fn row(cmd: &str) -> Option<&'static AuthorityRow> {
    AUTHORITY_TABLE.iter().find(|r| r.cmd == cmd)
}

/// Is `row`'s endpoint right checked on a build whose lockdown switch is `lockdown`?
pub fn enforced(row: &AuthorityRow, lockdown: bool) -> bool {
    row.always || lockdown
}

/// The capability kinds the console is seeded with at boot
/// (`authority::seed_console_authority`): (wave 12, owner round 48)
/// `Cap<Task>` READ on `"tasks"`, the full task view. The endpoints it is
/// seeded with are [`console_seed_ifaces`].
///
/// **None under the console lockdown** (owner round 36, wave 11). The lockdown
/// used to add four checked rows while still handing the console both
/// capabilities, so every checked command — `flight arm` and `pm suspend`
/// included — still passed its check. Withheld, the console holds no
/// authority over an irreversible effect: every row is refused, recorded,
/// and a console session can no longer arm the drivetrain, suspend, reboot
/// or power off the board. Default n, so a development build is unchanged.
pub const fn console_seed_kinds(lockdown: bool) -> &'static [CapType] {
    if lockdown {
        &[]
    } else {
        &[ty::TASK]
    }
}

/// The kernel-hosted endpoints (host keys) the console is seeded with at boot,
/// `WRITE` on each: the interfaces of its consequential commands. None under
/// the lockdown, for the reason [`console_seed_kinds`] gives.
pub const fn console_seed_ifaces(lockdown: bool) -> &'static [u16] {
    if lockdown {
        &[]
    } else {
        &[key::POWER, key::CONFIG, key::OTA]
    }
}

/// May the command proceed? `holds`: the console holds `WRITE` on `row.iface`.
/// A command the table does not name is not a consequential one: it proceeds.
pub fn may_proceed(cmd: &str, lockdown: bool, holds: bool) -> bool {
    match row(cmd) {
        Some(r) => !enforced(r, lockdown) || holds,
        None => true,
    }
}

/// `reboot`: an orderly reboot (the console's `reboot`, ring 3's `power
/// reboot`). An `AUTHORITY_TABLE` row checked on every build, as `pm suspend`:
/// ring 3 has always needed the `power` endpoint's `WRITE` for it, and the
/// console's `reboot` used to be the one way to the same effect without it.
pub const CMD_REBOOT: &str = "reboot";
/// `shutdown`: an orderly power-off (the console's `shutdown`, ring 3's
/// `power shutdown`). See [`CMD_REBOOT`].
pub const CMD_SHUTDOWN: &str = "shutdown";
