// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `Cap<Socket>` (567-570): a socket as a capability.
//
// The socket table here is the real one (`shims/net` pulls
// `crates/net/net/src/socket.rs` whole), so ownership, the per-task quota and
// index reuse are the shipping behaviour. What a host cannot do is put a
// datagram on a wire — `net_poll` and the NIC are `todo!()` — so these tests
// stop at the capability check, at the untyped handler's own first refusal, or
// at a close. The send and receive paths themselves are driven from ring 3 by
// `abitest`.
//
// "Got past the capability check" is observed as the untyped handler's `-1`
// for a null buffer or address: both handlers test that before touching the
// network, and it is a different answer from any capability errno.

use super::harness::serial;
use azos_abi::cap::CapKind;
use azos_abi::error::Errno;
use azos_ipc::cap::targets::{Port, Socket};
use azos_ipc::cap::{Cap, CapError, CapHandle, CapPerms};
use std::sync::Mutex;

// ── The typed flight-recorder hook ────────────────────────────────────────

static SEEN: Mutex<Vec<(u8, u32)>> = Mutex::new(Vec::new());

fn recorder(kind_code: u8, reason_code: u32) {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).push((kind_code, reason_code));
}

fn seen() -> Vec<(u8, u32)> {
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn denial(e: CapError) -> (u8, u32) {
    (CapKind::Socket.denial_code(), e.code())
}

fn err(e: Errno) -> i64 {
    e.to_syscall_ret()
}

// ── The caller ────────────────────────────────────────────────────────────

/// The cap-store pool slot the caller is bound to.
const SLOT: usize = 52;

/// Releases every socket the task holds and clears degraded mode on the way
/// out, panic or not: the socket table and the degraded flag are process
/// statics the next test would inherit.
struct Scene {
    tid: u32,
}

impl Drop for Scene {
    fn drop(&mut self) {
        release_sockets_of(self.tid);
        azos_ipc::cap::degraded_set(false);
    }
}

/// Close every socket `tid` owns, straight on the table — the kernel's
/// exit-time `socket_release_all` is not part of what `shims/net` exports.
fn release_sockets_of(tid: u32) {
    for fd in 0..azos_net::MAX_SOCKETS as i32 {
        if azos_net::socket_owner(fd) == Some(tid) {
            azos_net::socket_close(fd);
        }
    }
}

fn ring3_caller(tid: u32) -> Scene {
    // Two task tables: `cap_store` resolves TIDs through `ipc_task_pool`, the
    // handlers ask this crate's `shims/sched`. See `gpio_typed_lock.rs`.
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    release_sockets_of(tid);
    // A non-zero page table makes the caller ring 3. Nothing below copies
    // through it: every buffer passed is null on purpose.
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(tid);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(recorder);
    Scene { tid }
}

fn udp_typed() -> i64 {
    super::sys_socket_typed(
        azos_net::socket::AF_INET as u64,
        azos_net::socket::SOCK_DGRAM as u64,
        azos_net::socket::IPPROTO_UDP as u64,
    )
}

fn udp_plain() -> i64 {
    super::sys_socket(
        azos_net::socket::AF_INET as u64,
        azos_net::socket::SOCK_DGRAM as u64,
        azos_net::socket::IPPROTO_UDP as u64,
    )
}

fn socket_cap(raw: i64) -> Cap<Socket> {
    Cap::from_raw(CapHandle::from_raw(raw as u32))
}

/// The socket index a live `Cap<Socket>` names.
fn socket_of(tid: u32, raw: i64) -> i32 {
    azos_ipc::cap_store::with_table(tid, |t| t.get(socket_cap(raw), CapPerms::NONE))
        .expect("tid does not resolve")
        .expect("not a live Cap<Socket>") as i32
}

fn owned_by(tid: u32) -> usize {
    (0..azos_net::MAX_SOCKETS as i32)
        .filter(|&fd| azos_net::socket_owner(fd) == Some(tid))
        .count()
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// A create mints a readable, writable capability for a socket the caller
/// owns.
#[test]
fn a_create_mints_both_permissions_for_a_socket_the_caller_owns() {
    const TID: u32 = 6501;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = udp_typed();
    assert!(raw >= 0, "socket_typed returned {raw}");
    let cap = socket_cap(raw);
    let (r, w) = azos_ipc::cap_store::with_table(TID, |t| {
        (t.get(cap, CapPerms::READ).is_ok(), t.get(cap, CapPerms::WRITE).is_ok())
    })
    .unwrap();
    assert_eq!((r, w), (true, true), "minted read={r} write={w}");
    assert_eq!(azos_net::socket_owner(socket_of(TID, raw)), Some(TID));
}

/// A close revokes and frees the socket, and repeating it cannot close the
/// next socket the task creates.
#[test]
fn close_typed_revokes_then_frees_and_a_second_close_is_stale() {
    const TID: u32 = 6502;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = udp_typed();
    let fd = socket_of(TID, raw);
    assert_eq!(super::sys_close_typed(raw as u64), 0);
    assert_eq!(azos_net::socket_owner(fd), None, "close_typed returned 0 and socket {fd} is still held");

    let again = udp_typed();
    let fd2 = socket_of(TID, again);
    assert_eq!(super::sys_close_typed(raw as u64), err(Errno::ECAPSTALE));
    assert_eq!(super::sys_recv_typed(raw as u64, 0, 4), err(Errno::ECAPSTALE));
    assert_eq!(azos_net::socket_owner(fd2), Some(TID),
               "a second close of a revoked handle closed the task's next socket");
    assert_eq!(seen(), vec![denial(CapError::Stale); 2]);
}

/// The untyped shutdown leaves a socket a capability names alone, and still
/// closes one nothing names.
#[test]
fn the_untyped_shutdown_leaves_a_named_socket_alone() {
    const TID: u32 = 6503;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = udp_typed();
    let fd = socket_of(TID, raw);
    let plain = udp_plain();
    assert!(plain >= 0, "the untyped socket failed: {plain}");

    assert_eq!(super::sys_sock_close(fd as u64), -1, "shutdown of a capability-named socket was not refused");
    assert_eq!(azos_net::socket_owner(fd), Some(TID));

    // Positive control: the guard is about the capability, not about closing.
    assert_eq!(super::sys_sock_close(plain as u64), 0, "a socket nothing names did not close");
    assert_eq!(azos_net::socket_owner(plain as i32), None);
}

/// A full capability table refuses the grant, and the socket created for it
/// does not stay behind holding one of the task's slots.
#[test]
fn a_refused_grant_closes_the_socket_it_just_created() {
    const TID: u32 = 6504;
    let _g = serial();
    let _s = ring3_caller(TID);

    let mut n = 0u32;
    while azos_ipc::cap_store::grant::<Port>(TID, CapPerms::RW, 9000 + n).is_some() {
        n += 1;
        assert!(n as usize <= azos_ipc::cap::MAX_CAPS_PER_TASK, "the cap table never filled");
    }
    assert_eq!(udp_typed(), err(Errno::EMFILE));
    assert_eq!(owned_by(TID), 0, "the socket created for an ungranted capability was left open");
}

/// Send and connect need WRITE, receive needs READ — both directions, so a
/// check that became stricter fails as surely as one that was dropped.
#[test]
fn send_and_connect_need_write_and_recv_needs_read() {
    const TID: u32 = 6505;
    let _g = serial();
    let _s = ring3_caller(TID);

    let fd = udp_plain();
    assert!(fd >= 0);
    let ro = azos_ipc::cap_store::grant::<Socket>(TID, CapPerms::READ, fd as u32).unwrap();
    let wo = azos_ipc::cap_store::grant::<Socket>(TID, CapPerms::WRITE, fd as u32).unwrap();
    let ro = ro.raw().as_raw() as u64;
    let wo = wo.raw().as_raw() as u64;

    assert_eq!(super::sys_send_typed(ro, 0, 4), err(Errno::ECAPPERMS));
    assert_eq!(super::sys_connect_typed(ro, 0, 16), err(Errno::ECAPPERMS));
    assert_eq!(super::sys_recv_typed(ro, 0, 4), -1, "READ did not reach the receive handler");

    assert_eq!(super::sys_recv_typed(wo, 0, 4), err(Errno::ECAPPERMS));
    assert_eq!(super::sys_send_typed(wo, 0, 4), -1, "WRITE did not reach the send handler");
    assert_eq!(super::sys_connect_typed(wo, 0, 16), -1, "WRITE did not reach the connect handler");

    assert_eq!(seen(), vec![denial(CapError::MissingPerms); 3]);
}

/// Containment refuses the two writes, leaves the receive and the close live,
/// and records nothing: the task holds the capability.
#[test]
fn containment_refuses_send_and_connect_and_leaves_recv_and_close() {
    const TID: u32 = 6506;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = udp_typed();
    assert!(raw >= 0);
    azos_ipc::cap::degraded_set(true);
    assert_eq!(super::sys_send_typed(raw as u64, 0, 4), err(Errno::EAGAIN));
    assert_eq!(super::sys_connect_typed(raw as u64, 0, 16), err(Errno::EAGAIN));
    assert_eq!(super::sys_recv_typed(raw as u64, 0, 4), -1, "containment reached the receive, which is READ");
    assert!(seen().is_empty(), "containment recorded as a denial: {:?}", seen());
    assert_eq!(super::sys_close_typed(raw as u64), 0, "containment blocked the close");
}

/// Handle 0 is stale on every call of the family and recorded as a Socket
/// denial.
#[test]
fn a_forged_handle_is_stale_on_every_call_and_recorded() {
    const TID: u32 = 6507;
    let _g = serial();
    let _s = ring3_caller(TID);

    assert_eq!(super::sys_send_typed(0, 0, 4), err(Errno::ECAPSTALE));
    assert_eq!(super::sys_recv_typed(0, 0, 4), err(Errno::ECAPSTALE));
    assert_eq!(super::sys_connect_typed(0, 0, 16), err(Errno::ECAPSTALE));
    assert_eq!(seen(), vec![denial(CapError::Stale); 3]);
}

/// **OVSwrap review F2: a moved or stale `Cap<Socket>` closes only the
/// holder's handle, never someone else's socket.** A `Cap<Socket>` holds a
/// bare socket index; a move copies it into the receiver's table without
/// re-stamping the socket's owner. B holds such a handle on A's socket:
///
/// 1. while A is alive, B's `close_typed` releases B's handle (0) and A's
///    socket stays open and A's;
/// 2. after A exits and C's new socket takes the same index, B's `close_typed`
///    on a second such handle releases it (0) and C's socket stays open and
///    C's.
///
/// The second close of a released handle is stale, as for any handle.
///
/// **Canary (by hand, 2026-10-02).** Drop the `socket_access_ok(fd)` test in
/// `sys_close_typed`'s Socket arm (close unconditionally, as before): step 1
/// fails on "B's close of a moved handle closed A's socket".
#[test]
fn a_moved_or_stale_socket_handle_closes_only_the_holders_handle() {
    const A: u32 = 6511;
    const B: u32 = 6512;
    const C: u32 = 6513;
    let _g = serial();
    let bind = |tid: u32, slot: usize| {
        ipc_task_pool::shim_bind(tid, slot);
        azos_ipc::cap_store::reset(tid);
        release_sockets_of(tid);
    };
    let gift = |to: u32, fd: i32| -> u64 {
        azos_ipc::cap_store::grant::<Socket>(to, CapPerms::RW, fd as u32)
            .expect("cap table full")
            .raw()
            .as_raw() as u64
    };
    bind(B, 53);
    bind(C, 54);
    let _s = ring3_caller(A);
    let raw = udp_typed();
    assert!(raw >= 0, "socket_typed returned {raw}");
    let fd = socket_of(A, raw);

    // 1. A is alive.
    let moved = gift(B, fd);
    azos_sched::set_current_task_tid(B);
    assert_eq!(super::sys_close_typed(moved), 0, "the holder could not release its handle");
    assert_eq!(azos_net::socket_owner(fd), Some(A), "B's close of a moved handle closed A's socket");
    assert_eq!(super::sys_close_typed(moved), err(Errno::ECAPSTALE), "a released handle still resolved");

    // 2. A exits; C's socket takes the index.
    let stale = gift(B, fd);
    release_sockets_of(A);
    azos_sched::set_current_task_tid(C);
    let raw_c = udp_typed();
    assert!(raw_c >= 0, "socket_typed returned {raw_c}");
    assert_eq!(socket_of(C, raw_c), fd, "precondition: C's socket reuses A's index");
    azos_sched::set_current_task_tid(B);
    assert_eq!(super::sys_close_typed(stale), 0);
    assert_eq!(azos_net::socket_owner(fd), Some(C), "a stale handle closed C's socket");

    release_sockets_of(C);
    azos_ipc::cap_store::reset(B);
    azos_ipc::cap_store::reset(C);
    azos_sched::set_current_task_tid(A);
}
