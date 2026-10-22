// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the console's per-command authority decision.
//!
//! Pulls `crates/core/ipc/src/authority_policy.rs` by `#[path]`: the real
//! `azos_recovery` and `azos_ipc` link the scheduler and driver crates and
//! do not build for the host, and the decision lives in that one small file
//! so it can be tested here instead of only in QEMU. The ring-3 forms of the
//! same commands are checked per op by the kernel-hosted interfaces
//! (`tests/host/syscall-tests`, `power_guards.rs`, `family_guards.rs`).
//!
//! Canary (run by hand, 2026-10-02): make `authority_policy::enforced`
//! return `row.always` (ignore the lockdown switch). The lockdown tests below
//! fail; the default-build tests still pass.

#[path = "../../../../crates/core/ipc/src/authority_policy.rs"]
pub mod authority_policy;

#[cfg(test)]
mod tests {
    use super::authority_policy::*;
    use azos_devif::key;

    /// The two commands the lockdown adds, the two checked on every build.
    const LOCKDOWN_ONLY: [&str; 2] = [CMD_CONFIG_SET_WATCHDOG, CMD_OTA_ROLLBACK];
    const ALWAYS: [&str; 2] = [CMD_REBOOT, CMD_SHUTDOWN];

    #[test]
    fn the_table_names_four_commands_and_each_once() {
        assert_eq!(AUTHORITY_TABLE.len(), 4);
        for cmd in LOCKDOWN_ONLY.iter().chain(ALWAYS.iter()) {
            assert_eq!(AUTHORITY_TABLE.iter().filter(|r| r.cmd == *cmd).count(), 1, "{cmd}");
        }
    }

    #[test]
    fn every_row_needs_write_on_its_interfaces_endpoint() {
        for (cmd, iface) in [
            (CMD_CONFIG_SET_WATCHDOG, key::CONFIG),
            (CMD_OTA_ROLLBACK, key::OTA),
            (CMD_REBOOT, key::POWER),
            (CMD_SHUTDOWN, key::POWER),
        ] {
            let r = row(cmd).unwrap();
            assert_eq!(r.iface, iface, "{cmd}");
            assert!(r.need_write, "{cmd}");
        }
        for cmd in LOCKDOWN_ONLY {
            assert!(!row(cmd).unwrap().always, "{cmd} is checked on every build; the default build must not change");
        }
    }

    #[test]
    fn without_the_lockdown_the_lockdown_rows_proceed_without_the_capability() {
        for cmd in LOCKDOWN_ONLY {
            assert!(!enforced(row(cmd).unwrap(), false), "{cmd}");
            assert!(may_proceed(cmd, false, false), "{cmd}");
        }
    }

    #[test]
    fn under_the_lockdown_the_lockdown_rows_need_the_capability() {
        for cmd in LOCKDOWN_ONLY {
            assert!(enforced(row(cmd).unwrap(), true), "{cmd}");
            assert!(!may_proceed(cmd, true, false), "{cmd} proceeded without the endpoint's WRITE");
            assert!(may_proceed(cmd, true, true), "{cmd} refused although the console holds it");
        }
    }

    /// Wave 11: the console's `reboot` and `shutdown` need `WRITE` on the
    /// `power` endpoint on every build, as ring 3's `power reboot` /
    /// `power shutdown` always did.
    ///
    /// **Canary (by hand, 2026-10-03).** Delete the `CMD_REBOOT` row from
    /// `AUTHORITY_TABLE`: red here on "reboot is not a table row" (and on the
    /// table-length test); set its `always` to `false`: red on "a default
    /// console reboots without the capability".
    #[test]
    fn reboot_and_shutdown_need_the_power_endpoint_on_every_build() {
        for cmd in [CMD_REBOOT, CMD_SHUTDOWN] {
            let r = row(cmd).unwrap_or_else(|| panic!("{cmd} is not a table row"));
            assert_eq!((r.iface, r.need_write, r.always), (key::POWER, true, true), "{cmd}");
            assert!(!may_proceed(cmd, false, false), "a default console {cmd}s without the capability");
            assert!(may_proceed(cmd, false, true), "{cmd} refused although the console holds it");
        }
    }

    #[test]
    fn reboot_and_shutdown_are_checked_either_way() {
        for lockdown in [false, true] {
            for cmd in ALWAYS {
                assert!(enforced(row(cmd).unwrap(), lockdown), "{cmd} lockdown={lockdown}");
                assert!(!may_proceed(cmd, lockdown, false), "{cmd} lockdown={lockdown}");
                assert!(may_proceed(cmd, lockdown, true), "{cmd} lockdown={lockdown}");
            }
        }
    }

    /// Owner round 36: under the lockdown the console is seeded with nothing,
    /// so every row of the table meets a console that holds none of the
    /// endpoints it names and is refused. Off the lockdown it gets every
    /// endpoint a row names, and nothing else (no task view: owner
    /// 2026-10-21).
    ///
    /// **Canary (by hand, 2026-10-02).** Make `console_seed_ifaces` ignore
    /// `lockdown`: red on "the lockdown seeded the console".
    #[test]
    fn under_the_lockdown_the_console_is_seeded_with_nothing() {
        assert!(console_seed_ifaces(true).is_empty(), "the lockdown seeded the console");
        let open = console_seed_ifaces(false);
        for r in AUTHORITY_TABLE {
            assert!(open.contains(&r.iface), "{} needs endpoint {}, which the default seed lacks", r.cmd, r.iface);
            let holds = console_seed_ifaces(true).contains(&r.iface);
            assert!(!may_proceed(r.cmd, true, holds), "{} proceeds under the lockdown", r.cmd);
        }
        let mut named: Vec<u16> = AUTHORITY_TABLE.iter().map(|r| r.iface).collect();
        named.sort_unstable();
        named.dedup();
        assert_eq!(open.len(), named.len(), "the console is seeded with an endpoint no row names");
    }

    #[test]
    fn a_command_the_table_does_not_name_proceeds() {
        assert!(row("help").is_none());
        assert!(may_proceed("help", true, false));
    }

    /// The OTA status word round-trips and saturates the boot count.
    #[test]
    fn the_ota_status_word_round_trips() {
        use azos_abi::families::{ota_status_pack, ota_status_unpack};
        assert_eq!(ota_status_unpack(ota_status_pack(1, 0, 3, 0b10)), (1, 0, 3, 0b10));
        assert_eq!(ota_status_unpack(ota_status_pack(2, 1, 1 << 20, 0)).2, u16::MAX);
    }
}
