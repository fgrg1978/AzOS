// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The failure contract of the interfaces that actuate or own the machine
//! (`motor`, `power`, `block`): the op tables the macro generated, read back.

use azos_devif::block::BlockIdl;
use azos_devif::motor::MotorIdl;
use azos_devif::power::PowerIdl;
use azos_idl::{OnFailure, OpInfo};

fn op<'a>(t: &'a [OpInfo], name: &str) -> &'a OpInfo {
    t.iter().find(|o| o.name == name).unwrap_or_else(|| panic!("no op {name}"))
}

/// Every op of the three interfaces declares its policy, and an irreversible
/// (`once_only`) one always does: the macro refuses the rest at compile time,
/// this pins the interfaces themselves.
#[test]
fn every_op_declares_a_policy() {
    for (iface, t) in [("motor", &MotorIdl::OPS[..]), ("power", &PowerIdl::OPS[..]), ("block", &BlockIdl::OPS[..])] {
        for o in t {
            assert!(o.on_failure.is_some(), "{iface}::{} declares no on_failure", o.name);
            assert!(!o.once_only() || o.on_failure.is_some());
        }
    }
}

/// An op that can leave a wheel running drives the drivetrain to its safe
/// state; the e-stop escalates; the readers degrade.
#[test]
fn motor_policies() {
    let t = &MotorIdl::OPS[..];
    for n in ["speed", "drive", "direction", "pid_target", "pid_tick", "pid_enable", "pid_gains", "pid_reset"] {
        assert_eq!(op(t, n).on_failure, Some(OnFailure::SafeState), "{n}");
    }
    assert_eq!(op(t, "estop").on_failure, Some(OnFailure::Escalate));
    for n in ["angle", "pid_enabled"] {
        assert_eq!(op(t, n).on_failure, Some(OnFailure::Degrade), "{n}");
        assert!(op(t, n).idempotent());
    }
    // The e-stop is allowed longer than a reader (it writes the durable record) but is bounded.
    assert!(op(t, "estop").deadline_ns > op(t, "angle").deadline_ns);
    for o in t {
        assert!(o.deadline_ns > 0 && o.budget_us > 0, "{} is unbounded", o.name);
        // The CPU budget fits in the deadline.
        assert!(u64::from(o.budget_us) * 1000 <= o.deadline_ns, "{}", o.name);
    }
}

#[test]
fn power_policies() {
    let t = &PowerIdl::OPS[..];
    for n in ["shutdown", "reboot"] {
        assert_eq!(op(t, n).on_failure, Some(OnFailure::Escalate), "{n}");
        // They do not return when served: no deadline to declare, a bounded request.
        assert_eq!(op(t, n).deadline_ns, 0, "{n}");
        assert!(op(t, n).budget_us > 0, "{n}");
    }
    for o in t.iter().filter(|o| o.name != "shutdown" && o.name != "reboot") {
        assert_eq!(o.on_failure, Some(OnFailure::Degrade), "{}", o.name);
    }
    assert_eq!(op(t, "suspend").deadline_ns, 0, "a suspend lasts until the next interrupt");
}

#[test]
fn block_policy() {
    let o = op(&BlockIdl::OPS[..], "sectors");
    assert_eq!((o.on_failure, o.deadline_ns > 0, o.budget_us > 0, o.idempotent()), (Some(OnFailure::Degrade), true, true, true));
}
