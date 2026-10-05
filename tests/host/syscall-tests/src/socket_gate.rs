// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// Host tests for `socket_access_ok` in `crates/core/syscall/src/handlers.rs`
// (target 3, ~line 861).
//
// Its own doc records the vulnerability it closed: before this gate,
// `azos_net::SOCKS` was one flat 16-entry array and every `socket_*`
// syscall validated only `fd < MAX_SOCKETS` -- so "any task could enumerate
// fd 0..15 and read another task's inbound TCP stream, inject bytes into
// its outbound stream, or tear down its connection. That includes the OTA
// channel and the brain link." These tests drive the real gate against the
// real socket table (`azos_net::socket`, pulled in whole -- see
// `tests/host/syscall-tests/shims/net`), with `azos_sched::current_user_pt`
// / `current_task_tid` standing in for "who is calling right now" (see
// `tests/host/syscall-tests/shims/sched`).

// `azos_net::SOCKS` and the "current task" shim are both process statics
// and `cargo test` runs test fns in parallel, so every test here takes the
// crate-wide serial lock. It moved out of this file when the mmap/munmap
// tests arrived: they touch the same "current task" registers, and two
// modules with two locks do not exclude each other. See `src/harness.rs`.
use super::harness::serial;

fn open_socket_owned_by(tid: u32) -> i32 {
    let fd = azos_net::socket_create_owned(
        azos_net::socket::AF_INET,
        azos_net::socket::SOCK_DGRAM,
        azos_net::socket::IPPROTO_UDP,
        tid,
    );
    assert!(fd >= 0, "socket_create_owned failed (table full?)");
    fd
}

/// Kernel callers (`user_pt == 0`) bypass entirely -- structurally, the real
/// callers of `azos_net::socket_*` from kernel context
/// (`kernel/src/main.rs`, `crates/core/shell`) never traverse this gate at all,
/// but the handlers that DO call it must still let a kernel-context caller
/// through. Bypass holds even for an fd that owns nothing and even one
/// past `MAX_SOCKETS` -- the range check is skipped entirely, not merely
/// satisfied.
#[test]
fn kernel_context_bypasses_the_gate_entirely() {
    let _g = serial();
    azos_sched::set_current_user_pt(0);
    assert!(socket_access_ok(0));
    assert!(socket_access_ok(azos_net::MAX_SOCKETS as u64 + 999));
}

/// The out-of-range check runs before narrowing `fd as i32` /
/// `fd as u16` — a raw register value at or above `MAX_SOCKETS` must be
/// denied for a user caller, not wrap into a bogus in-range index.
#[test]
fn user_context_denies_an_out_of_range_fd() {
    let _g = serial();
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(1);
    assert!(!socket_access_ok(azos_net::MAX_SOCKETS as u64));
    assert!(!socket_access_ok(u64::MAX));
}

/// `current_task_tid() == 0` must never grant access, even to a socket
/// somehow stamped with owner 0: a real TID is never 0 (0 is the
/// "no current task" sentinel per the function's own doc), so treating it
/// as a valid identity would make "no task" equivalent to "every socket
/// nobody else has claimed."
#[test]
fn tid_zero_is_never_granted_access() {
    let _g = serial();
    let fd = open_socket_owned_by(7);
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(0);
    assert!(!socket_access_ok(fd as u64));
    azos_net::socket_close(fd);
}

/// The positive case: the task that created the socket may touch it.
#[test]
fn the_owning_task_may_access_its_own_socket() {
    let _g = serial();
    let fd = open_socket_owned_by(42);
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(42);
    assert!(socket_access_ok(fd as u64));
    azos_net::socket_close(fd);
}

/// The core vulnerability this gate closed: a DIFFERENT task must be
/// denied, even though the fd is in range and genuinely owned by someone.
/// Before this gate existed, this is exactly the fd-enumeration attack the
/// module doc describes -- guessing 0..15 and landing on someone else's
/// live connection.
#[test]
fn a_different_task_is_denied_access_to_someone_elses_socket() {
    let _g = serial();
    let fd = open_socket_owned_by(42);
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(43);
    assert!(!socket_access_ok(fd as u64));
    azos_net::socket_close(fd);
}

/// An in-range fd that nobody has claimed (`socket_owner` returns `None`)
/// must be denied, not treated as fair game. `socket_owner` returning
/// `None` for a free slot is exactly what makes denial the default for
/// anything a user task did not create, per the function's own doc.
#[test]
fn an_unclaimed_in_range_fd_is_denied() {
    let _g = serial();
    // Never created -> free slot -> socket_owner(fd) == None.
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(1);
    assert!(!socket_access_ok(0));
}

/// Closing a socket must revoke access for its former owner -- `socket_close`
/// resets the slot to unowned, so a stale "I created this" belief must not
/// survive the close.
#[test]
fn access_is_revoked_once_the_socket_is_closed() {
    let _g = serial();
    let fd = open_socket_owned_by(42);
    azos_sched::set_current_user_pt(0x1000);
    azos_sched::set_current_task_tid(42);
    assert!(socket_access_ok(fd as u64));
    azos_net::socket_close(fd);
    assert!(!socket_access_ok(fd as u64), "a closed socket must not still grant its former owner access");
}
