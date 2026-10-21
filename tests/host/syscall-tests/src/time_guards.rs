// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for the warrant step of `SYS_SCHEDCTL` (D6 part A),
// `handlers::time_warrant_recording`, which resolves the handle a caller
// presents against its own table.
//
// * the warrant is a capability to the `time` endpoint with `WRITE`; a fair
//   caller needs none (the step is only asked for RT and DL);
// * a stale handle, a capability to another interface and one without `WRITE`
//   are three different refusals, and containment is a fourth.

use super::harness::serial;
use azos_abi::cap::CapPerms;
use azos_devif::key;
use azos_ipc::cap::CapError;
use std::sync::atomic::{AtomicU32, Ordering::SeqCst};

/// Cap-store pool slot for this file; no other file in this crate binds 61.
const SLOT: usize = 61;

static NEXT_TID: AtomicU32 = AtomicU32::new(0x7e61_0001);

fn scene() -> u32 {
    azos_ipc::endpoint::__endpoint_reset_for_tests();
    let tid = NEXT_TID.fetch_add(1, SeqCst);
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    azos_sched::set_current_task_tid(tid);
    tid
}

fn grant(tid: u32, key: u16, perms: CapPerms) -> u32 {
    azos_ipc::endpoint::kernel_endpoint_cap(tid, perms, key, 0)
        .expect("cap table full")
        .raw()
        .as_raw()
}

/// **The warrant is a `time` endpoint with `WRITE`.**
///
/// **Canary.** Accept any endpoint in `time_warrant_recording` (drop the
/// `host_key_of_ref` comparison): the sensor-endpoint line reads `Ok`.
#[test]
fn the_warrant_is_a_time_endpoint_with_write() {
    let _g = serial();
    let tid = scene();
    let warrant = grant(tid, key::TIME, CapPerms::WRITE);
    let other = grant(tid, key::SENSOR, CapPerms::RW);

    assert_eq!(crate::handlers::time_warrant_recording(tid, warrant), Ok(()));
    assert_eq!(
        crate::handlers::time_warrant_recording(tid, other),
        Err(CapError::WrongKind),
        "an endpoint of another interface is no warrant"
    );
    assert_eq!(
        crate::handlers::time_warrant_recording(tid, 0),
        Err(CapError::Stale),
        "the null handle names nothing"
    );
    assert_eq!(
        crate::handlers::time_warrant_recording(tid, 0x7FFF_FFF1),
        Err(CapError::Stale),
        "a forged handle names nothing"
    );
}

/// **A time endpoint without `WRITE` is `MissingPerms`, and containment
/// refuses a holder.**
#[test]
fn a_warrant_without_write_or_while_contained_is_refused() {
    let _g = serial();
    let tid = scene();
    let read_only = grant(tid, key::TIME, CapPerms::READ);
    assert_eq!(
        crate::handlers::time_warrant_recording(tid, read_only),
        Err(CapError::MissingPerms)
    );

    let warrant = grant(tid, key::TIME, CapPerms::RW);
    azos_ipc::cap::degraded_set(true);
    let r = crate::handlers::time_warrant_recording(tid, warrant);
    azos_ipc::cap::degraded_set(false);
    assert_eq!(r, Err(CapError::Contained));
}

/// **A warrant derived from a revoked one is refused before the sweep frees
/// it.** `time_warrant_recording` reads the slot kind-erased, so it asks the
/// table whether the slot is void as `get` does.
///
/// **Canary.** Drop the `is_void` test in `time_warrant_recording`: the
/// descendant line reads `Ok`.
#[test]
fn a_warrant_derived_from_a_revoked_one_is_refused_before_the_sweep() {
    use azos_abi::cap::CapHandle;
    use azos_ipc::cap_store::{self, CapXfer};
    let _g = serial();
    let parent = scene();
    let child = NEXT_TID.fetch_add(1, SeqCst);
    ipc_task_pool::shim_bind(child, SLOT + 1);
    cap_store::reset(child);

    let root = grant(parent, key::TIME, CapPerms::RW_DELEGATE);
    let mut out = [CapHandle(0); 1];
    let x = CapXfer { rights: Some(CapPerms::WRITE), ..CapXfer::new(CapHandle::from_raw(root), true) };
    cap_store::move_caps(parent, child, &[x], true, &mut out).expect("the copy is made");
    let derived = out[0].as_raw();
    assert_eq!(crate::handlers::time_warrant_recording(child, derived), Ok(()), "live before the revoke");

    // Revoke the root and keep the sweep from running: the copy still holds
    // its slot.
    cap_store::with_table(parent, |t| {
        assert!(t.revoke_raw(CapHandle::from_raw(root)));
        assert!(azos_ipc::cap::sweep_take());
    })
    .unwrap();
    assert_eq!(cap_store::occupied(child), 1, "nothing swept yet");
    assert_eq!(
        crate::handlers::time_warrant_recording(child, derived),
        Err(CapError::Revoked),
        "a descendant of a revoked warrant is no warrant"
    );

    azos_ipc::cap::sweep_owed();
    cap_store::sweep();
    assert_eq!(crate::handlers::time_warrant_recording(child, derived), Err(CapError::Stale));
}
