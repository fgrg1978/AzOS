// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `PowerAssert` row of the registry: its own key and topology name, apart
//! from `power` (whose `WRITE` is the shutdown), with no resource, and the
//! classes its ops declare. The server is `crates/core/syscall/src/power_assert.rs`
//! (`tests/host/syscall-tests`, `power_assert_guards`); the ledger behind it is
//! `azos_energy::assertion` (`tests/host/energy-tests`, `assertion`).

use azos_devif::{by_key, key, parse_target, power_assert, PowerAssertIdl, POWER_ASSERT_ID, POWER_ID};

/// **Canary.** Name the row `power`, or give it `power`'s key: red.
#[test]
fn the_assertion_interface_is_not_the_power_interface() {
    assert_eq!(key::POWER_ASSERT, 27);
    let i = by_key(key::POWER_ASSERT).expect("a row for the key");
    assert_eq!((i.name, i.id), ("powerassert", POWER_ASSERT_ID));
    assert_ne!(i.id, POWER_ID);
    assert_ne!(key::POWER_ASSERT, key::POWER);
    assert_eq!(parse_target("powerassert").map(|(i, b)| (i.key, b)), Some((key::POWER_ASSERT, 0)));
    assert!(parse_target("powerassert.0").is_none(), "no resource");
}

/// Three ops; `hold` is sent at most once (a lost answer is not a second hold).
#[test]
fn the_ops_declare_their_contract() {
    let names: Vec<&str> = PowerAssertIdl::OPS.iter().map(|o| o.name).collect();
    assert_eq!(names, ["hold", "release", "stats"]);
    assert_eq!(PowerAssertIdl::OPS[0].flags, azos_idl::OP_AT_MOST_ONCE);
    assert_ne!(power_assert::REASON_PACKAGE, 0, "0 names no reason and is refused");
}
