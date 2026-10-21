// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The trusted surface's call right on `endpoint.input`: the compositor's row
//! holds `WRITE | EXEC` on it, the kernel stamps that grant with
//! `azos_devif::input::TRUSTED_BADGE`, and no other row holds one. The input
//! server (`tests/host/inputd-tests`) refuses every other caller the focus
//! after the Secure Attention Key, so this badge is the whole of the
//! compositor's claim to hand it on.

use azos_abi::cap::{CapKind, CapPerms};
use azos_devif::input::{self, TRUSTED_BADGE};

use crate::cap_seed::seed_one_cap;
use crate::cap_seed_bridge_tests::fresh_tid;
use crate::cap_store;

/// The badge of the one endpoint capability `tid` holds (0 when it has none or
/// the capability carries no badge).
fn badge_of_input_cap(tid: u32) -> u32 {
    cap_store::with_table(tid, |t| {
        t.lookup_where(crate::cap::ty::ENDPOINT, |_, _, _| true).map(|h| t.ext_of(h).map_or(0, |e| e.badge))
    })
    .flatten()
    .expect("the grant minted an endpoint capability")
}

/// **The kernel stamps the trusted badge on the calling grant that carries
/// `EXEC`, and on no other grant of the endpoint.** `WRITE | EXEC` is the
/// compositor's; `WRITE` alone (`TOOLBOX.ELF`'s) and the server's own
/// `READ | WRITE` (with the right to lend) are unbadged, and `EXEC` on another
/// task-hosted endpoint is not the input server's.
///
/// **Canary.** Remove the `azos_devif::input::grant_badge` arm of
/// `cap_seed.rs`: the first assertion reads badge 0 and goes red. Make
/// `grant_badge` ignore `READ`: the server's grant is badged and the third goes
/// red.
#[test]
fn the_trusted_call_right_carries_the_trusted_badge_and_no_other_grant_does() {
    let _g = crate::harness::serial();
    crate::endpoint::__endpoint_reset_for_tests();
    let trusted = fresh_tid();
    assert!(seed_one_cap(trusted, CapKind::Endpoint, CapPerms::WRITE.union(CapPerms::EXEC), "endpoint.input").is_some());
    assert_eq!(badge_of_input_cap(trusted), TRUSTED_BADGE);

    let plain = fresh_tid();
    assert!(seed_one_cap(plain, CapKind::Endpoint, CapPerms::WRITE, "endpoint.input").is_some());
    assert_eq!(badge_of_input_cap(plain), 0, "the plain call right is unbadged");

    let server = fresh_tid();
    let serving = CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::DELEGATE);
    assert!(seed_one_cap(server, CapKind::Endpoint, serving, "endpoint.input").is_some());
    assert_eq!(badge_of_input_cap(server), 0, "the serving grant is unbadged");

    let other = fresh_tid();
    assert!(seed_one_cap(other, CapKind::Endpoint, CapPerms::WRITE.union(CapPerms::EXEC), "endpoint.demo-not-input").is_some());
    assert_eq!(badge_of_input_cap(other), 0, "EXEC on another endpoint means nothing here");

    // The badge is no warrant's: the server cannot mistake the trusted surface
    // for a holder of a grant, nor a holder for the trusted surface.
    assert_eq!(input::generation_of(TRUSTED_BADGE), None);
}

/// **Only the compositor's row holds the trusted call right.** Every row of the
/// built-in topology that holds `EXEC` on `endpoint.input` is `COMPSRV.ELF`,
/// and it holds it exactly when the build has a compositor (Kconfig
/// `COMPOSITOR`); the input server's gate (`gated`) is that same fact.
///
/// **Canary.** Give `INPUT_CALL` (the toolbox's) `EXEC` in `builder.rs`: the
/// toolbox holds the trusted badge and this goes red.
#[test]
fn only_the_compositors_row_holds_the_trusted_call_right() {
    let topo = azos_topology::default_minimal();
    let mut holders = Vec::new();
    for r in topo.tasks() {
        for c in topo.caps_of(r) {
            if c.kind == CapKind::Endpoint && c.target.as_str() == input::ENDPOINT && input::grant_badge(c.perms.bits()).is_some() {
                holders.push(String::from_utf8_lossy(r.name.as_bytes()).into_owned());
            }
        }
    }
    if azos_topology::builder::COMPOSITOR_ROW {
        assert_eq!(holders, ["COMPSRV.ELF"], "one holder: the compositor");
    } else {
        assert!(holders.is_empty(), "no compositor row, no trusted surface: {holders:?}");
    }
}
