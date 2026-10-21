// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `DevicePower` endpoints (`endpoint.pm-<device>`): the drivers' rows
//! serve them, the power service's row calls them, and the kernel badges the
//! calling grant with the device's key and the op classes of its rights, so
//! that the service finds each endpoint by the key its row stamped.

use azos_abi::cap::{CapKind, CapPerms};
use azos_devif::power::runtime::{self, badge_key, ENDPOINT_PREFIX, DEVICES};
use azos_topology::MaybeStr;

use crate::cap_seed::seed_one_cap;
use crate::cap_store;
use crate::cap_seed_bridge_tests::fresh_tid;

const SERVERS: [(&str, &[u8]); 2] = [("gpio", b"GPIODRV.ELF"), ("ina", b"INADRV.ELF")];

fn grants_of<'a>(
    topo: &'a azos_topology::Topology,
    target: &'a str,
) -> impl Iterator<Item = (&'a [u8], CapPerms)> + 'a {
    topo.tasks().iter().flat_map(move |r| {
        topo.caps_of(r)
            .iter()
            .filter(move |c| c.kind == CapKind::Endpoint && c.target.as_str() == target)
            .map(move |c| (r.name.as_bytes(), c.perms))
    })
}

/// Every device that serves `DevicePower` has exactly one row that serves its
/// endpoint (the driver's) and one that calls it (`POWER.ELF`, with `EXEC`),
/// and no endpoint with the prefix names a device the service does not know.
///
/// **Canary.** Rename a device in `runtime::DEVICES`, or drop either row's
/// grant in `builder.rs`: this goes red. The `ina` pair exists only where
/// the monitor has a ring-3 row.
#[test]
fn every_device_has_one_server_row_and_the_power_row_calls_it() {
    let topo = azos_topology::default_minimal();
    for (name, server) in SERVERS {
        assert!(DEVICES.contains(&name), "{name} is not in runtime::DEVICES");
        let target = format!("{ENDPOINT_PREFIX}{name}");
        let grants: Vec<_> = grants_of(&topo, &target).collect();
        if name == "ina" && !azos_topology::builder::INADRV_ROW {
            assert!(grants.is_empty(), "{target} is granted though no row serves it: {grants:?}");
            continue;
        }
        let serving: Vec<_> = grants.iter().filter(|(_, p)| p.contains(CapPerms::READ)).collect();
        assert_eq!(serving.len(), 1, "{target}: one server, got {grants:?}");
        assert_eq!(serving[0].0, server, "{target} is served by the device's own driver row");
        let calling: Vec<_> = grants.iter().filter(|(_, p)| !p.contains(CapPerms::READ)).collect();
        assert_eq!(calling.len(), 1, "{target}: one caller, got {grants:?}");
        assert_eq!(calling[0].0, b"POWER.ELF", "{target} is called by the power service");
        assert_eq!(calling[0].1, CapPerms::EXEC, "the power service controls the device, nothing more");
    }
    // No stray endpoint in the family.
    for r in topo.tasks() {
        for c in topo.caps_of(r) {
            if c.kind == CapKind::Endpoint && c.target.as_str().starts_with(ENDPOINT_PREFIX) {
                assert!(runtime::endpoint_key(c.target.as_str()).is_some(), "{} names no device", c.target.as_str());
            }
        }
    }
}

/// Seeding `POWER.ELF`'s row gives it, for each device, one endpoint capability
/// whose badge carries the device's key and the classes read and exec, and no
/// class of acting for a caller (`WRITE`); the driver's own grant is unbadged.
/// The keys differ, so the service tells the devices apart by them.
///
/// **Canary.** Remove the `grant_badge` arm of `cap_seed.rs`: the badge is 0,
/// every key lookup fails and this goes red.
#[test]
fn the_power_row_is_badged_with_each_devices_key_and_its_classes() {
    let _g = crate::harness::serial();
    crate::endpoint::__endpoint_reset_for_tests();
    let topo = azos_topology::default_minimal();
    let row = topo.find_task(&MaybeStr::from_bytes(b"POWER.ELF")).expect("POWER.ELF row");
    let tid = fresh_tid();
    for c in topo.caps_of(row) {
        let _ = seed_one_cap(tid, c.kind, c.perms, c.target.as_str());
    }
    let mut keys = Vec::new();
    for (name, _) in SERVERS {
        if name == "ina" && !azos_topology::builder::INADRV_ROW {
            continue;
        }
        let key = runtime::device_key(name).unwrap();
        let found = cap_store::with_table(tid, |t| {
            t.lookup_where(crate::cap::ty::ENDPOINT, |_, b, _| badge_key(b) == key).map(|h| {
                let badge = t.ext_of(h).map_or(0, |e| e.badge);
                badge
            })
        })
        .flatten()
        .unwrap_or_else(|| panic!("no capability carries the key of {name}"));
        assert_eq!(
            (found & 0xFF) as u8,
            runtime::CLASS_READ | runtime::CLASS_EXEC,
            "{name}: observe and control, not act for a caller"
        );
        keys.push(key);
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), if azos_topology::builder::INADRV_ROW { 2 } else { 1 }, "one key per device");
}

/// The serving grant is not badged (a server's own capability carries none),
/// and a calling grant of another endpoint is not badged either.
#[test]
fn only_the_calling_grant_of_a_device_endpoint_carries_a_badge() {
    let _g = crate::harness::serial();
    crate::endpoint::__endpoint_reset_for_tests();
    let server = fresh_tid();
    assert!(seed_one_cap(server, CapKind::Endpoint, CapPerms::READ, "endpoint.pm-gpio").is_some());
    assert!(cap_store::with_table(server, |t| {
        t.lookup_where(crate::cap::ty::ENDPOINT, |_, b, _| b != 0).is_none()
    })
    .unwrap());
    let other = fresh_tid();
    assert!(seed_one_cap(other, CapKind::Endpoint, CapPerms::WRITE, "endpoint.demo-not-pm").is_some());
    assert!(cap_store::with_table(other, |t| {
        t.lookup_where(crate::cap::ty::ENDPOINT, |_, b, _| b != 0).is_none()
    })
    .unwrap());
    // A device the family does not know is a plain endpoint, unbadged.
    let third = fresh_tid();
    assert!(seed_one_cap(third, CapKind::Endpoint, CapPerms::EXEC, "endpoint.pm-nothing").is_some());
    assert!(cap_store::with_table(third, |t| {
        t.lookup_where(crate::cap::ty::ENDPOINT, |_, b, _| b != 0).is_none()
    })
    .unwrap());
}
