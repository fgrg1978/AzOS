// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `SYS_CAP_CLOSE` on an `Endpoint` capability.
//
// It answered `ECAPKIND` while its own doc said a handle with nothing to
// release "is just deleted", so ring 3 could not drop an endpoint handle (a
// badged copy it derived on a server's endpoint, or the handle `beep` looks up
// to a kernel-hosted endpoint, which lived until the task exited). These tests
// drive the real `sys_close_typed` (this file is `include!`d into `mod handlers`)
// and ask the state it leaves, not the return value alone:
//
//   * a call right (`WRITE`) is deleted and counted out of the endpoint's
//     senders; the server and the other holders go on;
//   * a derived badged copy goes alone: its source stays, and a copy made from
//     it stays (a close is a delete, not a revoke);
//   * a second close is `ECAPSTALE`, recorded;
//   * the LAST `READ` capability of a task that serves the endpoint ends the
//     role by the path of a server's death: a named endpoint stays unclaimed
//     (callers get `Unserved`), an anonymous one is freed (callers get
//     `Stale`). The `PEER_DIED` completion of the calls queued on it is
//     asserted where the call queues are (`endpoint.rs`,
//     `a_server_giving_up_one_endpoint_ends_its_calls_peer_died`);
//   * with another `READ` capability left, or for a `READ` capability of an
//     endpoint the caller does not serve, only the slot goes.

use super::harness::serial;
use azos_abi::cap::{ty, CapPerms};
use azos_abi::error::Errno;
use azos_ipc::cap::{targets::Endpoint, Cap, CapError};
use azos_ipc::endpoint::{
    endpoint_create_cap, endpoint_dest_for, endpoint_named_cap, endpoint_owner_ref, endpoint_release_all,
    senders_of, EndpointCapError, UNCLAIMED,
};
use std::sync::Mutex;

/// Cap-store pool slots no other file binds.
const SLOT_CLIENT: usize = 40;
const SLOT_SERVER: usize = 41;
const SLOT_HEIR: usize = 42;
/// TIDs no other file uses.
const CLIENT: u32 = 6501;
const SERVER: u32 = 6502;
const HEIR: u32 = 6503;

static SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, reason_code: u32) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

/// The `Endpoint` denials recorded since `scene`. The recorder hook is global
/// and a test outside `serial()` may record its own kinds meanwhile; only this
/// file's kind counts.
fn seen() -> Vec<(u8, u32)> {
    let all = SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone();
    all.into_iter().filter(|(kind, _)| *kind == ty::ENDPOINT.denial_code()).collect()
}

fn stale_denial() -> (u8, u32) {
    (ty::ENDPOINT.denial_code(), CapError::Stale.code())
}

/// Both tasks bound and empty, the call-right counts hooked; the caller is
/// `CLIENT`, a ring-3 task.
fn scene() {
    ipc_task_pool::shim_bind(CLIENT, SLOT_CLIENT);
    ipc_task_pool::shim_bind(SERVER, SLOT_SERVER);
    azos_ipc::cap_store::reset(CLIENT);
    azos_ipc::cap_store::reset(SERVER);
    azos_ipc::cap::senders::set_hooks(azos_ipc::endpoint::sender_delta, azos_ipc::endpoint::flush_notices);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(recorder);
    azos_sched::set_current_user_pt(0xBAD0_0000);
    act_as(CLIENT);
}

fn act_as(tid: u32) {
    azos_sched::set_current_task_tid(tid);
}

fn teardown() {
    endpoint_release_all(SERVER);
    azos_ipc::cap_store::reset(SERVER);
    azos_ipc::cap_store::reset(CLIENT);
}

fn err(e: Errno) -> i64 {
    e.to_syscall_ret()
}

fn raw(c: Cap<Endpoint>) -> u64 {
    u64::from(c.raw().as_raw())
}

fn live(tid: u32, handle: u64) -> bool {
    azos_ipc::cap_store::read_table(tid, |t| t.peek_raw(azos_abi::cap::CapHandle::from_raw(handle as u32)).is_some())
        .unwrap_or(false)
}

/// The endpoint `name` the server accepts on, and a client's call right to it.
fn served(name: &[u8]) -> (u32, Cap<Endpoint>) {
    let server: Cap<Endpoint> = endpoint_named_cap(SERVER, CapPerms::READ, name).expect("server grant");
    let r = azos_ipc::cap_store::read_table(SERVER, |t| t.peek_raw(server.raw()).map(|(_, _, r)| r)).flatten().unwrap();
    let call = endpoint_named_cap(CLIENT, CapPerms::WRITE.union(CapPerms::DUP), name).expect("client grant");
    (r, call)
}

/// **A call right closes: the slot is gone, the count of senders falls, and
/// the server and every other holder go on.** A second close of the same
/// handle is stale and recorded.
///
/// **Canaries.** Route the `Endpoint` arm around the delete (return 0 only):
/// the handle stays live. Skip the sender count in `CapTable::clear_at`: the
/// count stays 2.
#[test]
fn closing_a_call_right_deletes_it_and_a_second_close_is_stale() {
    let _g = serial();
    scene();
    let (r, call) = served(b"ec.call");
    let other = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"ec.call").unwrap();
    assert_eq!(senders_of(r), Some(2));

    assert_eq!(sys_close_typed(raw(call)), 0);
    assert!(!live(CLIENT, raw(call)), "the closed handle is still in the table");
    assert_eq!(senders_of(r), Some(1), "the closed call right is still counted");
    assert_eq!(endpoint_dest_for(CLIENT, call.raw().as_raw()), Err(EndpointCapError::Cap(CapError::Stale)));
    assert_eq!(endpoint_dest_for(CLIENT, other.raw().as_raw()), Ok(SERVER), "another holder lost its right");
    assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "closing a call right touched the server");
    assert_eq!(seen(), vec![], "a close was recorded as a denial");

    assert_eq!(sys_close_typed(raw(call)), err(Errno::ECAPSTALE));
    assert_eq!(seen(), vec![stale_denial()]);
    assert_eq!(senders_of(r), Some(1), "a second close counted out again");
    teardown();
}

/// **A derived badged copy closes alone**: its source still calls, the server
/// is untouched, and when the source is closed in turn the copies made from it
/// survive (a delete, not a revoke).
///
/// **Canaries.** Close with `revoke_raw`, or build with `delete-revokes-canary`:
/// the sibling copy goes stale. Close the source instead of the copy: the
/// source assertion fails.
#[test]
fn closing_a_derived_badged_copy_leaves_its_source_and_its_children() {
    let _g = serial();
    scene();
    let (r, source) = served(b"ec.derive");
    let rights = CapPerms::WRITE.union(CapPerms::DUP);
    let copy = azos_ipc::endpoint::mint_badged(CLIENT, source.raw(), 7, rights).expect("derive");
    let sibling = azos_ipc::endpoint::mint_badged(CLIENT, source.raw(), 9, CapPerms::WRITE).expect("second copy");
    assert_eq!(senders_of(r), Some(3));

    assert_eq!(sys_close_typed(u64::from(copy.as_raw())), 0);
    assert!(!live(CLIENT, u64::from(copy.as_raw())), "the copy is still in the table");
    assert_eq!(senders_of(r), Some(2));
    assert_eq!(endpoint_dest_for(CLIENT, copy.as_raw()), Err(EndpointCapError::Cap(CapError::Stale)));
    assert_eq!(endpoint_dest_for(CLIENT, source.raw().as_raw()), Ok(SERVER), "the source went with its copy");
    assert_eq!(endpoint_dest_for(CLIENT, sibling.as_raw()), Ok(SERVER), "a sibling copy went with it");

    // Close the source: the sibling copy made from it stays.
    assert_eq!(sys_close_typed(raw(source)), 0);
    assert_eq!(endpoint_dest_for(CLIENT, sibling.as_raw()), Ok(SERVER), "a close of the source revoked its copy");
    assert_eq!(sys_close_typed(u64::from(sibling.as_raw())), 0);
    assert_eq!(senders_of(r), Some(0));
    assert_eq!(sys_close_typed(u64::from(copy.as_raw())), err(Errno::ECAPSTALE));
    teardown();
}

/// **A capability to a dead server's endpoint can still be closed**: the slot
/// is the caller's, whatever became of the endpoint.
#[test]
fn a_capability_to_a_dead_servers_endpoint_closes() {
    let _g = serial();
    scene();
    let (_r, call) = served(b"ec.dead");
    endpoint_release_all(SERVER);
    assert_eq!(endpoint_dest_for(CLIENT, call.raw().as_raw()), Err(EndpointCapError::Cap(CapError::Stale)));
    assert_eq!(sys_close_typed(raw(call)), 0);
    assert!(!live(CLIENT, raw(call)));
    teardown();
}

/// **The last serving capability ends the role by the path of a server's
/// death.** A named endpoint stays, unclaimed: its callers' capabilities
/// answer `Unserved` and a successor with the topology's `READ` grant claims
/// it. The call right the server also held goes with the close (`RW` is one
/// slot).
///
/// **Canaries.** Delete the slot without `endpoint_orphan_ref`: the owner
/// stays `SERVER` and the caller's call still resolves to a task that cannot
/// accept.
#[test]
fn closing_the_last_serving_grant_of_a_named_endpoint_leaves_it_unclaimed() {
    let _g = serial();
    scene();
    let server: Cap<Endpoint> = endpoint_named_cap(SERVER, CapPerms::RW, b"ec.named").expect("server grant");
    let call = endpoint_named_cap(CLIENT, CapPerms::WRITE, b"ec.named").expect("client grant");
    let r = azos_ipc::endpoint::endpoint_ref_by_name(b"ec.named").unwrap();
    assert_eq!(endpoint_dest_for(CLIENT, call.raw().as_raw()), Ok(SERVER));

    act_as(SERVER);
    assert_eq!(sys_close_typed(raw(server)), 0);

    assert!(!live(SERVER, raw(server)));
    assert_eq!(endpoint_owner_ref(r), Ok(UNCLAIMED), "the closed server still serves");
    assert_eq!(endpoint_dest_for(CLIENT, call.raw().as_raw()), Err(EndpointCapError::Unserved));
    assert_eq!(seen(), vec![]);
    // The name is claimable again, by a task the topology grants it to.
    assert!(endpoint_named_cap(SERVER, CapPerms::READ, b"ec.named").is_some());
    assert_eq!(endpoint_dest_for(CLIENT, call.raw().as_raw()), Ok(SERVER));
    teardown();
}

/// **An anonymous endpoint is freed when its server closes its last `READ`
/// capability**: no name could find it again, so every capability to it goes
/// stale.
#[test]
fn closing_the_last_serving_grant_of_an_anonymous_endpoint_frees_it() {
    let _g = serial();
    scene();
    let server = endpoint_create_cap(SERVER, CapPerms::RW).expect("create");
    let r = azos_ipc::cap_store::read_table(SERVER, |t| t.peek_raw(server.raw()).map(|(_, _, r)| r)).flatten().unwrap();
    assert_eq!(endpoint_owner_ref(r), Ok(SERVER));

    act_as(SERVER);
    assert_eq!(sys_close_typed(raw(server)), 0);

    assert_eq!(endpoint_owner_ref(r), Err(EndpointCapError::Cap(CapError::Stale)), "the endpoint outlived its server's close");
    assert_eq!(sys_close_typed(raw(server)), err(Errno::ECAPSTALE));
    teardown();
}

/// **While another `READ` capability to the endpoint remains in the table, the
/// role stays** and only the closed slot goes, in either order; the close that
/// leaves none ends it.
///
/// **Canary.** Drop the `holds_packed_ref` test in `close_endpoint`: the first
/// close orphans the endpoint.
#[test]
fn a_second_serving_capability_keeps_the_role_until_it_is_the_last() {
    let _g = serial();
    scene();
    let all = CapPerms::READ.union(CapPerms::WRITE).union(CapPerms::DUP);
    let first: Cap<Endpoint> = endpoint_named_cap(SERVER, all, b"ec.two").expect("server grant");
    let r = azos_ipc::endpoint::endpoint_ref_by_name(b"ec.two").unwrap();
    let second = azos_ipc::endpoint::mint_badged(SERVER, first.raw(), 5, CapPerms::READ).expect("a serving copy");

    act_as(SERVER);
    assert_eq!(sys_close_typed(raw(first)), 0);
    assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "the role ended with a serving copy still held");
    assert!(live(SERVER, u64::from(second.as_raw())), "the copy went with its source");

    assert_eq!(sys_close_typed(u64::from(second.as_raw())), 0);
    assert_eq!(endpoint_owner_ref(r), Ok(UNCLAIMED), "the last serving capability closed and the role stayed");
    teardown();
}

/// **A `READ` capability to an endpoint the caller does not serve releases
/// only its slot**: the successor of an open swap holds the `READ` grant and
/// claims nothing, and a task holding the kernel's own `gpio` endpoint with
/// `READ` does not serve it either.
///
/// **Canary.** Drop the owner test in `endpoint_orphan_ref`: the old server's
/// endpoint is unclaimed by a close it did not make.
#[test]
fn a_read_capability_of_an_endpoint_the_caller_does_not_serve_only_goes() {
    let _g = serial();
    scene();
    ipc_task_pool::shim_bind(HEIR, SLOT_HEIR);
    azos_ipc::cap_store::reset(HEIR);
    let _server: Cap<Endpoint> = endpoint_named_cap(SERVER, CapPerms::READ, b"ec.swap").expect("server grant");
    let r = azos_ipc::endpoint::endpoint_ref_by_name(b"ec.swap").unwrap();
    assert_eq!(azos_ipc::endpoint::endpoint_swap_open(SERVER), 1);
    let heir: Cap<Endpoint> = endpoint_named_cap(HEIR, CapPerms::READ, b"ec.swap").expect("successor grant");
    assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "precondition: the grant claims nothing");

    act_as(HEIR);
    assert_eq!(sys_close_typed(raw(heir)), 0);
    assert!(!live(HEIR, raw(heir)));
    assert_eq!(endpoint_owner_ref(r), Ok(SERVER), "the successor's close unclaimed the old server's endpoint");
    assert_eq!(azos_ipc::endpoint::endpoint_swap_cancel(SERVER), 1);

    let hosted = azos_ipc::endpoint::kernel_endpoint_cap(CLIENT, CapPerms::READ, azos_devif::key::GPIO, 12).expect("grant");
    let host_r = azos_ipc::cap_store::read_table(CLIENT, |t| t.peek_raw(hosted.raw()).map(|(_, _, r)| r)).flatten().unwrap();
    act_as(CLIENT);
    assert_eq!(sys_close_typed(raw(hosted)), 0);
    assert!(!live(CLIENT, raw(hosted)));
    assert!(azos_ipc::endpoint::host_key_of_ref(host_r).is_some(), "the kernel's endpoint went with a close");
    azos_ipc::cap_store::reset(HEIR);
    teardown();
}
