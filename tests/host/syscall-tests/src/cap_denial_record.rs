// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// The capability layer's refusals, and whether anything hears them.
//
// `SAFETY_CAP_DENIED` was a defined flight-recorder event code with NO
// production call site: only `tests/host/behavior-tests` ever named it. So the
// refusal worked and nothing recorded that it had happened — on a machine
// whose black box is specified to hold security events, the event saying "an
// untrusted program reached for an actuator and was refused" was the one
// missing. It is also the one event the denied caller has every reason not to
// report itself.
//
// `cap_check` now calls an installed hook on the deny path. These tests drive
// the real `cap_check` (this crate `include!`s `handlers.rs`, so it is the
// shipping function, not a copy) and observe the hook.
//
// **The negative half is the point.** A test that only asserts "a denial is
// recorded" passes just as happily against a hook fired on every check,
// granted or not — which would fill the recorder with routine traffic and
// bury the events it exists for. So the grant case is asserted to produce
// NOTHING, and both halves run against the same installed hook.

use super::harness::serial;
use azos_abi::cap::{CapKind, CapPerms, ty, CapType};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// The cap-store pool slot the callers here are bound to. 22 and 51-58 are
/// taken by other files in this crate.
const SLOT: usize = 59;

/// Every denial the hook saw, in order: (kind code, detail word).
static SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, target: u32, need_write: bool) {
    SEEN.lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((kind_code, target | if need_write { 0x8000_0000 } else { 0 }));
}

/// TIDs no other test in this crate uses, so a table one test filled is never
/// read by another.
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7300_0001);
fn fresh_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::SeqCst)
}

/// Install `tid` as an unprivileged caller with an empty capability table, and
/// arm the recorder.
///
/// `set_current_user_pt(0)` means "kernel task" to `cap_check`, which returns
/// true before looking at any table — so a non-zero sentinel is required for
/// these tests to reach the code under test at all. Nothing dereferences it.
fn as_user_with_recorder(tid: u32) {
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(recorder);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    azos_sched::set_current_task_tid(tid);
}

fn seen() -> Vec<(u8, u32)> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[test]
fn a_denied_capability_is_recorded_with_its_kind_and_target() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);

    assert!(!cap_check(ty::IRQ, 3, true), "no grant, must be denied");

    // An interrupt line is a Device, kind code 7 (`CapKind::denial_code`, the
    // discriminant, written into the recording); the detail word carries the line with
    // the write bit set, because a refused WRITE is a refused command and a
    // refused read is not.
    assert_eq!(seen(), vec![(7u8, 3u32 | 0x8000_0000)]);
}

#[test]
fn the_write_bit_separates_a_refused_command_from_a_refused_read() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);

    assert!(!cap_check(ty::IRQ, 7, false));
    assert_eq!(seen(), vec![(7u8, 7u32)], "read denial must NOT set the top bit");
}

#[test]
fn a_granted_capability_records_nothing() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);
    assert!(azos_ipc::cap_store::with_table(tid, |t| t.grant_raw(ty::IRQ, CapPerms::RW, 3))
        .flatten()
        .is_some());

    assert!(cap_check(ty::IRQ, 3, true), "granted, must be allowed");

    // The half that discriminates: a hook wired to every check rather than to
    // the deny arm would put an entry here, and the test above would still
    // pass. The recorder exists to hold security events, and a granted write
    // is the most ordinary thing this kernel does.
    assert_eq!(seen(), Vec::new());
}

#[test]
fn a_kernel_caller_records_nothing_because_it_is_never_denied() {
    let _g = serial();
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_recorder(recorder);
    // `user_pt == 0` is how `cap_check` recognises an in-kernel caller.
    azos_sched::set_current_user_pt(0);

    assert!(cap_check(ty::IRQ, 3, true));
    assert_eq!(seen(), Vec::new());
}

/// **A caller whose TID names no live task is refused and recorded**, like a
/// caller holding nothing: `cap_store::with_table` answers `None` and the
/// refusal still reaches the black box.
///
/// **Canary.** Return before `record_cap_denial` when `with_table` is `None`:
/// `seen()` is empty.
#[test]
fn a_caller_with_no_capability_table_is_refused_and_recorded() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);
    ipc_task_pool::shim_kill(tid);

    assert!(!cap_check(ty::IRQ, 4, false));
    assert_eq!(seen(), vec![(7u8, 4u32)]);
}

/// The `SAFETY_CAP_DENIED` record names the resource the capability table
/// stores, for every kind (typed capability calls): the objectless kinds record 0, every
/// other kind its id. An MMIO refusal records the device's HANDLE (MMIO region index;
/// it recorded a region's base while the resource was an index into a board
/// table, and no lookup stands between the table and the record any more).
/// Literals on purpose: computed values would move with the code they pin.
///
/// **Canary.** Make `record_cap_denial` record anything but the resource: the
/// lines below read another number.
#[test]
fn a_denial_records_the_resource_the_table_stores_for_every_kind() {
    let _g = serial();
    let tid = fresh_tid();
    as_user_with_recorder(tid);

    assert!(!cap_check(ty::IRQ, 9, false));
    assert!(!cap_check(ty::MMIO, 0x0001_0003, true));
    assert!(!cap_check(ty::MMIO, u32::MAX, false));
    assert!(!cap_check(ty::DRIVER_REGISTRY, 1, true));
    assert_eq!(
        seen(),
        vec![(7u8, 9u32), (7, 0x0001_0003 | 0x8000_0000), (7, u32::MAX), (7, 1 | 0x8000_0000)],
        "the write bit rides the target's top bit, as it always has"
    );
}

// ── The TYPED path: `SAFETY_CAP_DENIED_TYPED` ─────────────────────────────
//
// `cap_check` above is the ONLY caller of the untyped recorder, and no
// `*_TYPED` handler goes through `cap_check`. So every refusal of a `Cap<T>`
// used to be recorded nowhere — an errno and silence. As each family migrates
// to `Cap<T>` that silence widens, one family at a time, and the gate stays
// green the whole way. These tests are what stops that.

/// Every typed denial the hook saw, in order: (kind code, reason code).
static SEEN_TYPED: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn typed_recorder(kind_code: u8, reason_code: u32) {
    SEEN_TYPED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((kind_code, reason_code));
}

fn arm_typed() {
    SEEN_TYPED.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(typed_recorder);
}

fn seen_typed() -> Vec<(u8, u32)> {
    SEEN_TYPED.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A typed refusal reaches the recorder, tagged with the family it was for and
/// why it failed.
///
/// Driven through `errno_for_cap_err` — the shipping function, since this
/// crate `include!`s `handlers.rs` — because that is the choke point the
/// production path actually takes.
#[test]
fn a_typed_denial_is_recorded_with_its_kind_and_reason() {
    use azos_abi::cap::CapKind;
    use azos_ipc::cap::CapError;

    let _g = serial();
    arm_typed();

    let _ = errno_for_cap_err(ty::IRQ, CapError::Stale);
    let _ = errno_for_cap_err(ty::IRQ, CapError::WrongKind);
    let _ = errno_for_cap_err(ty::IRQ, CapError::MissingPerms);

    assert_eq!(
        seen_typed(),
        vec![(7, 1), (7, 2), (7, 3)],
        "an interrupt line records as the Device kind code, the SAME code the untyped path \
         uses, with one distinct reason per CapError"
    );
}

/// **The record names the generic kind, not the class.** An interrupt line,
/// a device's registers and a driver slot are all `Device` (7); the detail word
/// carries the resource. `Null` is 0, "no object".
///
/// **Canary.** Make `CapType::denial_code` return the class-bearing type
/// byte: the three rows below split.
#[test]
fn typed_and_untyped_agree_on_the_kind_code_for_every_shared_family() {
    assert_eq!(CapType::NULL.denial_code(), 0, "Null");
    for kind in [ty::IRQ, ty::MMIO, ty::DRIVER_REGISTRY] {
        assert_eq!(kind.denial_code(), 7, "{kind:?} records under a code other than its kind's");
    }
}

/// No two `CapKind`s share a recorder code.
#[test]
fn every_cap_kind_has_its_own_recorder_code() {
    use azos_abi::cap::CapKind;
    let kinds = [
        CapKind::Null, CapKind::Endpoint, CapKind::MemObj, CapKind::Queue,
        CapKind::Port, CapKind::Domain, CapKind::Node, CapKind::Device, CapKind::Log,
    ];
    assert_eq!(kinds.len(), 9, "a CapKind variant was added without a code here");
    let mut codes: Vec<u8> = kinds.iter().map(|k| k.denial_code()).collect();
    let total = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), total, "two CapKind variants share a recorder code");
}

/// **Containment is not a denial, and recording it would be net-negative.**
///
/// `CapTable::get` returns `Contained` when degraded mode is armed and the
/// caller asks for WRITE — a refusal aimed at a task that HOLDS the
/// capability. It is the safety system working. Recorded as a denial, one
/// containment episode would bury every real record under thousands of its
/// own, at the exact moment the recording matters most.
///
/// This is new surface, not inherited: `cap_check`'s presence test never
/// consults degraded mode, so the untyped path cannot produce this event at all.
///
/// **Canary.** Delete the `is_denial()` guard in `note_typed_denial`: this
/// must go red while the test above stays green.
#[test]
fn containment_is_not_recorded_as_a_capability_denial() {
    use azos_abi::cap::CapKind;
    use azos_ipc::cap::CapError;

    let _g = serial();
    arm_typed();

    let _ = errno_for_cap_err(ty::IRQ, CapError::Contained);
    assert_eq!(
        seen_typed(),
        vec![],
        "degraded mode refusing a write from a capability HOLDER is not a denial"
    );

    // Positive control on the same family and the same installed hook, so a
    // green above cannot mean "the hook was never armed".
    let _ = errno_for_cap_err(ty::IRQ, CapError::MissingPerms);
    assert_eq!(seen_typed(), vec![(7, 3)], "the hook was not armed");
}

/// **A call through a revoked endpoint capability, after the resolve cache
/// (Kconfig IPC_RESOLVE_CACHE) held it, is refused and recorded once.**
/// `endpoint_dest_at` is what `SYS_IPC_FAST_CALL_EP` (the fast path and the
/// arm) and `SYS_IPC_CALL_V2` resolve through: two calls, a miss that keeps
/// the destination and a hit, record nothing; after the revoke the hit
/// misses, and the full resolution refuses the call and records the one
/// `Endpoint` denial.
///
/// **Canaries.** Skip the slot word compare in `resolve_cache::hit`: the
/// revoked call resolves. Record the miss's refusal twice: two records.
#[test]
fn a_revoked_endpoint_after_a_cached_hit_is_refused_and_recorded_once() {
    use azos_ipc::cap::{targets::Endpoint, Cap, CapError};
    use azos_ipc::endpoint::{endpoint_named_cap, endpoint_release_all, resolve_cache};

    /// The server's pool slot: any but `SLOT`, rebound here.
    const SERVER_SLOT: usize = 60;
    let _g = serial();
    let server = fresh_tid();
    ipc_task_pool::shim_bind(server, SERVER_SLOT);
    azos_ipc::cap_store::reset(server);
    let tid = fresh_tid();
    as_user_with_recorder(tid);
    resolve_cache::clear(SLOT);
    arm_typed();

    assert!(endpoint_named_cap(server, CapPerms::READ, b"rc.deny").is_some());
    let cap: Cap<Endpoint> = endpoint_named_cap(tid, CapPerms::WRITE, b"rc.deny").unwrap();
    let raw = cap.raw().as_raw();
    for _ in 0..2 {
        assert_eq!(endpoint_dest_at(SLOT, tid, raw).map(|d| d.owner), Some(server));
    }
    if resolve_cache::ENABLED {
        assert_eq!(resolve_cache::cached(SLOT), Some((tid, raw)), "precondition: the destination was kept");
    }
    assert_eq!(seen_typed(), vec![], "a granted call recorded a denial");

    azos_ipc::cap_store::revoke(tid, cap);
    assert_eq!(endpoint_dest_at(SLOT, tid, raw), None, "a revoked capability resolved");
    assert_eq!(
        seen_typed(),
        vec![(ty::ENDPOINT.denial_code(), CapError::Stale.code())],
        "the refusal was not recorded exactly once"
    );

    endpoint_release_all(server);
    azos_ipc::cap_store::reset(server);
    azos_ipc::cap_store::reset(tid);
    resolve_cache::clear(SLOT);
}
