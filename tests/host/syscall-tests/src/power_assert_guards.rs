// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the kernel-hosted `PowerAssert` interface (system power
// assertions, the `powerassert` endpoint) --
// `crates/core/syscall/src/power_assert.rs::Server`.
//
// Included inside `mod handlers { .. }` like `power_guards.rs`. The ledger is
// Kconfig ENERGY's, off on the host (this crate's `energy` feature), so an op
// whose right is held answers `UNSUPPORTED`; one whose right is missing is
// refused first (`DENIED`) with one `SAFETY_CAP_DENIED_TYPED` record. The
// ledger itself is tested in `tests/host/energy-tests` (`assertion`).
//
// **Canary** (run by hand). Gate `hold` on `READ` instead of `WRITE`: the
// read-only row of `each_op_demands_its_class` fails.

use super::harness::serial;
use azos_abi::cap::{ty, CapPerms};
use azos_devif::{outcome, PowerAssert};
use crate::khost::Caller;
use std::sync::atomic::{AtomicU32, Ordering};

/// Cap-store pool slot for this file; no other file in this crate binds 55.
const SLOT: usize = 55;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e55_0001);
static ENDPOINT_RECORDS: AtomicU32 = AtomicU32::new(0);

fn recorder(kind_code: u8, _reason: u32) {
    if kind_code == ty::ENDPOINT.denial_code() {
        ENDPOINT_RECORDS.fetch_add(1, Ordering::SeqCst);
    }
}

fn setup() -> u32 {
    crate::handlers::set_cap_deny_typed_recorder(recorder);
    ENDPOINT_RECORDS.store(0, Ordering::SeqCst);
    azos_ipc::cap::degraded_set(false);
    let tid = NEXT_TID.fetch_add(1, Ordering::SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_user_pt(0);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn server(tid: u32, rights: CapPerms) -> crate::power_assert::Server {
    crate::power_assert::Server(Caller { tid, badge: 0, rights })
}

/// `hold` and `release` act (`WRITE`), `stats` observes (`READ`): a caller
/// without the class is refused and recorded, one with it reaches the ledger
/// (here: answers `UNSUPPORTED`, the host build has no ENERGY).
#[test]
fn each_op_demands_its_class() {
    let _g = serial();
    for (rights, hold, stats) in [
        (CapPerms::WRITE, outcome::UNSUPPORTED, outcome::DENIED),
        (CapPerms::READ, outcome::DENIED, outcome::UNSUPPORTED),
        (CapPerms::RW, outcome::UNSUPPORTED, outcome::UNSUPPORTED),
    ] {
        let tid = setup();
        let mut s = server(tid, rights);
        assert_eq!(s.hold(1, 1_000).code, hold, "hold with {rights:?}");
        assert_eq!(s.release(1).code, hold, "release with {rights:?}");
        assert_eq!(s.stats(0).code, stats, "stats with {rights:?}");
        let denied = [hold, hold, stats].iter().filter(|&&c| c == outcome::DENIED).count() as u32;
        assert_eq!(ENDPOINT_RECORDS.load(Ordering::SeqCst), denied, "one record per refusal, with {rights:?}");
    }
}

/// A contained system refuses the acting class and keeps observation live.
#[test]
fn containment_refuses_a_hold() {
    let _g = serial();
    let tid = setup();
    let mut s = server(tid, CapPerms::RW);
    azos_ipc::cap::degraded_set(true);
    let held = s.hold(1, 1_000).code;
    let read = s.stats(0).code;
    azos_ipc::cap::degraded_set(false);
    assert_eq!(held, outcome::DENIED);
    assert_eq!(read, outcome::UNSUPPORTED);
}
