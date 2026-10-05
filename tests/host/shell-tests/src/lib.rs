// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for the console's per-command authority decision.
//!
//! Pulls `crates/core/ipc/src/authority_policy.rs` by `#[path]`: the real
//! `azos_shell` and `azos_ipc` link the scheduler and driver crates and
//! do not build for the host, and the decision lives in that one
//! dependency-free file so it can be tested here instead of only in QEMU. Both
//! consoles consume it: the recovery console and the ring-3 typed calls
//! (RFC-0055 S5).
//!
//! Canary (run by hand, 2026-10-02): make `authority_policy::enforced`
//! return `row.always` (ignore the lockdown switch). The lockdown tests below
//! fail; the default-build tests still pass.

#[path = "../../../../crates/core/ipc/src/authority_policy.rs"]
pub mod authority_policy;

#[cfg(test)]
mod tests {
    use super::authority_policy::*;
    use azos_abi::cap::CapKind;

    /// The four commands the lockdown adds, the four checked on every build.
    const LOCKDOWN_ONLY: [&str; 4] =
        [CMD_BEHAVIOR_DISABLE, CMD_SCHED_HZ_SET, CMD_CONFIG_SET_WATCHDOG, CMD_OTA_ROLLBACK];
    const ALWAYS: [&str; 4] = [CMD_FLIGHT_ARM, CMD_PM_SUSPEND, CMD_REBOOT, CMD_SHUTDOWN];

    #[test]
    fn the_table_names_eight_commands_and_each_once() {
        assert_eq!(AUTHORITY_TABLE.len(), 8);
        for cmd in LOCKDOWN_ONLY.iter().chain(ALWAYS.iter()) {
            assert_eq!(AUTHORITY_TABLE.iter().filter(|r| r.cmd == *cmd).count(), 1, "{cmd}");
        }
    }

    #[test]
    fn the_lockdown_rows_need_power_write() {
        for cmd in LOCKDOWN_ONLY {
            let r = row(cmd).unwrap();
            assert_eq!(r.kind, CapKind::Power, "{cmd}");
            assert!(r.need_write, "{cmd}");
            assert!(!r.always, "{cmd} is checked on every build; the default build must not change");
        }
    }

    #[test]
    fn without_the_lockdown_the_four_rows_proceed_without_the_capability() {
        for cmd in LOCKDOWN_ONLY {
            assert!(!enforced(row(cmd).unwrap(), false), "{cmd}");
            assert!(may_proceed(cmd, false, false), "{cmd}");
        }
    }

    #[test]
    fn under_the_lockdown_the_four_rows_need_the_capability() {
        for cmd in LOCKDOWN_ONLY {
            assert!(enforced(row(cmd).unwrap(), true), "{cmd}");
            assert!(!may_proceed(cmd, true, false), "{cmd} proceeded without Cap<Power> WRITE");
            assert!(may_proceed(cmd, true, true), "{cmd} refused although the console holds it");
        }
    }

    /// Wave 11: the console's `reboot` and `shutdown` need `Cap<Power>` WRITE
    /// on every build, as `pm suspend` does and as ring 3's `power reboot` /
    /// `power shutdown` always did.
    ///
    /// **Canary (by hand, 2026-10-03).** Delete the `CMD_REBOOT` row from
    /// `AUTHORITY_TABLE`: red here on "reboot is not a table row" (and on the
    /// table-length and ring-3-agreement tests); set its `always` to `false`:
    /// red on "a default console reboots without the capability".
    #[test]
    fn reboot_and_shutdown_need_cap_power_write_on_every_build() {
        let suspend = row(CMD_PM_SUSPEND).unwrap();
        for cmd in [CMD_REBOOT, CMD_SHUTDOWN] {
            let r = row(cmd).unwrap_or_else(|| panic!("{cmd} is not a table row"));
            assert_eq!((r.kind, r.need_write, r.always),
                       (suspend.kind, suspend.need_write, suspend.always),
                       "{cmd} is not checked as pm suspend is");
            assert!(!may_proceed(cmd, false, false), "a default console {cmd}s without the capability");
            assert!(may_proceed(cmd, false, true), "{cmd} refused although the console holds it");
        }
    }

    #[test]
    fn flight_arm_and_pm_suspend_are_checked_either_way() {
        for lockdown in [false, true] {
            for cmd in ALWAYS {
                assert!(enforced(row(cmd).unwrap(), lockdown), "{cmd} lockdown={lockdown}");
                assert!(!may_proceed(cmd, lockdown, false), "{cmd} lockdown={lockdown}");
                assert!(may_proceed(cmd, lockdown, true), "{cmd} lockdown={lockdown}");
            }
        }
    }

    /// Owner round 36: under the lockdown the console is seeded with nothing,
    /// so every row of the table — each needs `Cap<Motor>` or `Cap<Power>` —
    /// meets a console that holds neither and is refused. Off the lockdown it
    /// gets both kinds every row names, and (wave 12) the full `/proc` task
    /// view, `Cap<Task>`, which no row names.
    ///
    /// **Canary (by hand, 2026-10-02).** Make `console_seed_kinds` ignore
    /// `lockdown`: red on "the lockdown seeded the console".
    #[test]
    fn under_the_lockdown_the_console_is_seeded_with_nothing() {
        assert!(console_seed_kinds(true).is_empty(), "the lockdown seeded the console");
        let open = console_seed_kinds(false);
        for r in AUTHORITY_TABLE {
            assert!(open.contains(&r.kind), "{} needs {:?}, which the default seed lacks", r.cmd, r.kind);
            let holds = console_seed_kinds(true).contains(&r.kind);
            assert!(!may_proceed(r.cmd, true, holds), "{} proceeds under the lockdown", r.cmd);
        }
        assert!(open.contains(&CapKind::Task), "the default console lacks the full task view");
    }

    #[test]
    fn a_command_the_table_does_not_name_proceeds() {
        assert!(row("help").is_none());
        assert!(may_proceed("help", true, false));
    }

    // ── RFC-0055 S5: the ring-3 forms ─────────────────────────────────────

    /// A command gets a ring-3 form only with a TYPED syscall for its family
    /// (one that takes the capability in `a0`). Canary: add
    /// `(CMD_FLIGHT_ARM, SYS_SHUTDOWN)` to `RING3_FORMS`: this fails.
    #[test]
    fn a_ring3_form_needs_a_typed_syscall_of_its_family() {
        use azos_abi::syscall_nr::CAP_TYPED_SYSCALLS;
        for (cmd, nr) in RING3_FORMS {
            assert!(row(cmd).is_some(), "{cmd} is not an authority-table command");
            assert!(CAP_TYPED_SYSCALLS.contains(nr), "{cmd}: syscall {nr} takes no capability");
        }
        // Wave 12: every table command has one (the four families that were
        // recovery-console only got their typed calls).
        for r in AUTHORITY_TABLE {
            assert!(RING3_FORMS.iter().any(|(c, _)| *c == r.cmd), "{} has no ring-3 form", r.cmd);
        }
        use azos_abi::syscall_nr::*;
        for (cmd, nr) in [(CMD_FLIGHT_ARM, SYS_FLIGHT_TYPED), (CMD_BEHAVIOR_DISABLE, SYS_BEHAVIOR_TYPED),
                          (CMD_CONFIG_SET_WATCHDOG, SYS_CONFIG_TYPED), (CMD_OTA_ROLLBACK, SYS_OTA_TYPED)] {
            assert!(RING3_FORMS.contains(&(cmd, nr)), "{cmd} is not carried by syscall {nr}");
        }
    }

    /// Wave 12: each family's operations, the right each needs, and the
    /// table rows they take it from. **Canary.** Make `flight_op_need`'s
    /// disarm `need_write: false`: red, naming it.
    #[test]
    fn the_family_operations_need_what_the_console_table_says() {
        use azos_abi::families::*;
        // Table-backed operations agree with their rows.
        for (need, cmd) in [
            (flight_op_need(FLIGHT_OP_ARM), CMD_FLIGHT_ARM),
            (behavior_op_need(BEHAVIOR_OP_DISABLE), CMD_BEHAVIOR_DISABLE),
            (ota_op_need(OTA_OP_ROLLBACK), CMD_OTA_ROLLBACK),
        ] {
            let (n, r) = (need.unwrap(), row(cmd).unwrap());
            assert_eq!((n.cmd, n.kind, n.need_write), (r.cmd, r.kind, r.need_write), "{cmd}");
        }
        // `config set` of any key: the watchdog row's kind and right.
        let set = config_op_need(CONFIG_OP_SET).unwrap();
        let wd = row(CMD_CONFIG_SET_WATCHDOG).unwrap();
        assert_eq!((set.cmd, set.kind, set.need_write), (CMD_CONFIG_SET, wd.kind, wd.need_write));
        // The console's ungated operations: writes need WRITE, reads READ.
        let disarm = flight_op_need(FLIGHT_OP_DISARM).unwrap();
        assert_eq!((disarm.kind, disarm.need_write), (CapKind::Motor, true), "flight disarm");
        let enable = behavior_op_need(BEHAVIOR_OP_ENABLE).unwrap();
        assert_eq!((enable.kind, enable.need_write), (CapKind::Power, true), "behavior enable");
        for (n, cmd) in [(behavior_op_need(BEHAVIOR_OP_STATUS), CMD_BEHAVIOR_STATUS),
                         (config_op_need(CONFIG_OP_GET), CMD_CONFIG_GET),
                         (ota_op_need(OTA_OP_STATUS), CMD_OTA_STATUS)] {
            let n = n.unwrap();
            assert_eq!((n.cmd, n.kind, n.need_write), (cmd, CapKind::Power, false), "{cmd}");
        }
        // Unknown operations name no right.
        for bad in [0u64, 4, 99, u64::MAX] {
            assert_eq!(flight_op_need(bad), None);
            assert_eq!(behavior_op_need(bad), None);
            assert_eq!(config_op_need(bad), None);
            assert_eq!(ota_op_need(bad), None);
        }
        assert_eq!(flight_op_need(3), None);
        assert_eq!(config_op_need(3), None);
        assert_eq!(ota_op_need(3), None);
        // The status word round-trips and saturates the boot count.
        assert_eq!(ota_status_unpack(ota_status_pack(1, 0, 3, 0b10)), (1, 0, 3, 0b10));
        assert_eq!(ota_status_unpack(ota_status_pack(2, 1, 1 << 20, 0)).2, u16::MAX);
    }

    /// Every power operation needs `Cap<Power>`; only the rate read is `READ`.
    /// The table commands take their need from the table itself.
    #[test]
    fn every_power_operation_needs_cap_power_and_the_table_rows_agree() {
        use azos_abi::power::*;
        for op in [POWER_OP_SUSPEND, POWER_OP_REBOOT, POWER_OP_SHUTDOWN, POWER_OP_SCHED_HZ_SET] {
            let n = power_op_need(op).unwrap();
            assert_eq!(n.kind, CapKind::Power, "{}", n.cmd);
            assert!(n.need_write, "{}", n.cmd);
        }
        let get = power_op_need(POWER_OP_SCHED_HZ_GET).unwrap();
        assert_eq!((get.kind, get.need_write), (CapKind::Power, false));
        for (op, cmd) in [(POWER_OP_SUSPEND, CMD_PM_SUSPEND), (POWER_OP_SCHED_HZ_SET, CMD_SCHED_HZ_SET),
                          (POWER_OP_REBOOT, CMD_REBOOT), (POWER_OP_SHUTDOWN, CMD_SHUTDOWN)] {
            let r = row(cmd).unwrap();
            let n = power_op_need(op).unwrap();
            assert_eq!((n.cmd, n.kind, n.need_write), (r.cmd, r.kind, r.need_write));
        }
        for bad in [0u64, 6, 99, u64::MAX] {
            assert_eq!(power_op_need(bad), None, "op {bad}");
        }
    }
}
