// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `Cap<Socket>` multicast (571-572): group membership through a capability.
//
// Every call here is refused BEFORE the IGMP table is reached, and that is a
// limit of this crate rather than a choice of coverage: `shims/net` stands in
// for `net_get_ip`, `net_get_mac`, `net_get_mask` and `net_raw_send` with
// `todo!()`, and the first join of a group transmits a Membership Report
// through all four. The per-socket bound, the refcount, the release on every
// close path and the delivery of group traffic are tested in
// `tests/host/net-tests` (`mod mcast_sockets`), where those four are recorders.
//
// "Got past the capability check" is observed as the socket layer's own
// refusal of a group it never joins (-EINVAL), the way `socket_caps.rs`
// observes it as a handler's -1 for a null buffer.

use super::harness::serial;
use azos_abi::cap::CapKind;
use azos_abi::error::Errno;
use azos_ipc::cap::targets::{Port, Socket};
use azos_ipc::cap::{CapError, CapPerms};
use azos_net::socket::McastError;
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
const SLOT: usize = 53;

/// `239.1.2.3` as `a1` carries it: a group the socket layer accepts.
const GROUP: u64 = 0xEF01_0203;
/// `10.0.0.1`: not a group. Refused by the socket layer, after the capability.
const UNICAST: u64 = 0x0A00_0001;

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
    ipc_task_pool::shim_bind(tid, SLOT);
    azos_ipc::cap_store::reset(tid);
    release_sockets_of(tid);
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(tid);
    SEEN.lock().unwrap_or_else(|e| e.into_inner()).clear();
    set_cap_deny_typed_recorder(recorder);
    Scene { tid }
}

fn typed_socket(sock_type: u32) -> i64 {
    super::sys_socket_typed(
        azos_net::socket::AF_INET as u64,
        sock_type as u64,
        0,
    )
}

fn plain_udp() -> i64 {
    super::sys_socket(
        azos_net::socket::AF_INET as u64,
        azos_net::socket::SOCK_DGRAM as u64,
        azos_net::socket::IPPROTO_UDP as u64,
    )
}

fn grant(tid: u32, perms: CapPerms, fd: u32) -> u64 {
    azos_ipc::cap_store::grant::<Socket>(tid, perms, fd)
        .expect("grant refused")
        .raw()
        .as_raw() as u64
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// Handle 0 is stale on both calls and recorded as a Socket denial.
#[test]
fn a_forged_handle_is_stale_on_join_and_leave_and_recorded() {
    const TID: u32 = 6601;
    let _g = serial();
    let _s = ring3_caller(TID);

    assert_eq!(super::sys_mcast_join_typed(0, GROUP), err(Errno::ECAPSTALE));
    assert_eq!(super::sys_mcast_leave_typed(0, GROUP), err(Errno::ECAPSTALE));
    assert_eq!(seen(), vec![denial(CapError::Stale); 2]);
}

/// A live capability of another kind is refused on both calls, and recorded.
#[test]
fn a_handle_of_another_kind_is_refused_on_both_calls_and_recorded() {
    const TID: u32 = 6602;
    let _g = serial();
    let _s = ring3_caller(TID);

    let port = azos_ipc::cap_store::grant::<Port>(TID, CapPerms::RW, 9100).unwrap();
    let port = port.raw().as_raw() as u64;
    assert_eq!(super::sys_mcast_join_typed(port, GROUP), err(Errno::ECAPKIND));
    assert_eq!(super::sys_mcast_leave_typed(port, GROUP), err(Errno::ECAPKIND));
    assert_eq!(seen(), vec![denial(CapError::WrongKind); 2]);
}

/// Join needs WRITE; leave needs neither WRITE nor READ. Both directions of
/// both, so a check that became stricter fails as surely as one dropped.
#[test]
fn join_needs_write_and_leave_needs_no_permission() {
    const TID: u32 = 6603;
    let _g = serial();
    let _s = ring3_caller(TID);

    let fd = plain_udp();
    assert!(fd >= 0, "socket failed: {fd}");
    let ro = grant(TID, CapPerms::READ, fd as u32);
    let wo = grant(TID, CapPerms::WRITE, fd as u32);

    assert_eq!(super::sys_mcast_join_typed(ro, UNICAST), err(Errno::ECAPPERMS));
    assert_eq!(super::sys_mcast_join_typed(wo, UNICAST), err(Errno::EINVAL),
               "WRITE did not reach the socket layer");
    assert_eq!(super::sys_mcast_leave_typed(ro, GROUP), err(Errno::EINVAL),
               "a READ-only capability did not reach the leave");
    assert_eq!(super::sys_mcast_leave_typed(wo, GROUP), err(Errno::EINVAL),
               "a WRITE-only capability did not reach the leave");
    assert_eq!(seen(), vec![denial(CapError::MissingPerms)]);
}

/// Containment refuses the join and leaves the leave live — giving a
/// membership back is cleanup — and records nothing: the task holds the
/// capability.
#[test]
fn containment_refuses_the_join_and_leaves_the_leave_live() {
    const TID: u32 = 6604;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = typed_socket(azos_net::socket::SOCK_DGRAM);
    assert!(raw >= 0, "socket_typed failed: {raw}");
    azos_ipc::cap::degraded_set(true);
    assert_eq!(super::sys_mcast_join_typed(raw as u64, UNICAST), err(Errno::EAGAIN));
    assert_eq!(super::sys_mcast_leave_typed(raw as u64, GROUP), err(Errno::EINVAL),
               "containment reached the leave");
    assert!(seen().is_empty(), "containment recorded as a denial: {:?}", seen());
}

/// A group outside `224.0.0.0/4`, inside `224.0.0.0/24`, or wider than 32
/// bits is refused before the socket is looked at.
///
/// **The capability names a free slot on purpose.** A group check that were
/// skipped falls through to the slot and answers `-EBADF` — an assertion that
/// fails — instead of joining, which would transmit through this crate's
/// `todo!()` stand-ins. The last assertion is the positive control: a real
/// group does reach the slot.
#[test]
fn groups_outside_the_joinable_range_are_refused_before_the_socket() {
    const TID: u32 = 6605;
    let _g = serial();
    let _s = ring3_caller(TID);

    let free = (0..azos_net::MAX_SOCKETS as u32)
        .find(|&fd| azos_net::socket_owner(fd as i32).is_none())
        .expect("no free socket slot");
    let cap = grant(TID, CapPerms::RW, free);

    for (group, what) in [
        (UNICAST, "unicast"),
        (0xFFFF_FFFF, "limited broadcast"),
        (0xDFFF_FFFF, "223.255.255.255"),
        (0xF000_0000, "240.0.0.0"),
        (0xE000_0000, "224.0.0.0"),
        (0xE000_0001, "224.0.0.1, joined implicitly"),
        (0xE000_00FB, "224.0.0.251, link-local control"),
        (0xE000_00FF, "224.0.0.255"),
        ((1u64 << 32) | GROUP, "a group with a 33rd bit"),
    ] {
        assert_eq!(super::sys_mcast_join_typed(cap, group), err(Errno::EINVAL), "join {what}");
    }
    assert_eq!(super::sys_mcast_leave_typed(cap, (1u64 << 32) | GROUP), err(Errno::EINVAL),
               "leave of a group with a 33rd bit");
    assert_eq!(super::sys_mcast_join_typed(cap, GROUP), err(Errno::EBADF),
               "a real group did not reach the socket behind the capability");
    assert!(seen().is_empty(), "a group refusal recorded as a denial: {:?}", seen());
}

/// A socket that is not UDP is refused with `-EINVAL` on both calls.
///
/// The refusal happens under the socket lock before IGMP; the test that shows
/// it is not skipped is in `tests/host/net-tests`. What this one pins is the errno
/// the syscall hands back for it.
#[test]
fn a_socket_that_is_not_udp_is_refused_on_both_calls() {
    const TID: u32 = 6606;
    let _g = serial();
    let _s = ring3_caller(TID);

    let raw = typed_socket(azos_net::socket::SOCK_STREAM);
    assert!(raw >= 0, "socket_typed(SOCK_STREAM) failed: {raw}");
    assert_eq!(super::sys_mcast_join_typed(raw as u64, GROUP), err(Errno::EINVAL));
    assert_eq!(super::sys_mcast_leave_typed(raw as u64, GROUP), err(Errno::EINVAL));
    assert!(seen().is_empty());
}

/// Every socket-layer refusal maps to the errno `syscall_nr.rs` documents.
/// Exhaustive by construction: the `match` below stops compiling when a
/// variant is added.
#[test]
fn every_multicast_refusal_maps_to_its_documented_errno() {
    let _g = serial();
    for e in [
        McastError::BadSocket,
        McastError::NotUdp,
        McastError::BadGroup,
        McastError::SocketFull,
        McastError::TableFull,
        McastError::NotJoined,
    ] {
        let want = match e {
            McastError::BadSocket => Errno::EBADF,
            McastError::NotUdp | McastError::BadGroup | McastError::NotJoined => Errno::EINVAL,
            McastError::SocketFull => Errno::EQUOTA,
            McastError::TableFull => Errno::ENOSPC,
        };
        assert_eq!(super::errno_for_mcast_err(e), err(want), "{e:?}");
    }
}
