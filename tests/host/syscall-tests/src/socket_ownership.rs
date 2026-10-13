// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
// `sys_bind`, the worker behind the `bind` op of a socket node.
// `socket_gate.rs` tests the gate function `socket_access_ok` on its own;
// this file tests that the handler calls it, before anything else, and that
// what it refuses leaves the socket as it was.
//
// The socket table is the real one (`shims/net` pulls `socket.rs`, `udp.rs`
// and `tcp.rs`).
//
// "Is this socket bound?" is observed through `socket_listen_bound`, which
// refuses a TCP socket whose stored port is 0. So a bind that was really
// refused leaves the owner unable to listen, and one that went through does
// not.

use super::harness::serial;
use azos_arch_api::PagePerms;
use azos_net::socket::{AF_INET, IPPROTO_TCP, SOCK_STREAM};

const A: u32 = 31;
const B: u32 = 32;
/// Where the ring-3 `sockaddr_in` lives. Clear of the other guard files.
const ADDR_VA: usize = 0x0073_0000;
/// Never mapped by this file.
const UNMAPPED_VA: usize = 0x0074_0000;

/// Closes every socket A and B own on the way out, panic or not: the socket
/// and TCP tables are process statics the next test would inherit.
struct Scene;

impl Drop for Scene {
    fn drop(&mut self) {
        for fd in 0..azos_net::MAX_SOCKETS as i32 {
            if matches!(azos_net::socket_owner(fd), Some(A) | Some(B)) {
                azos_net::socket_close(fd);
            }
        }
    }
}

/// Ring 3, one user page table for both tasks (the handlers under test read
/// only the address through it), `sockaddr_in` for 0.0.0.0:`port` at
/// [`ADDR_VA`].
fn scene(port: u16) -> Scene {
    let pt = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    let phys = azos_mm::pmm::alloc_page().expect("arena exhausted").as_usize();
    azos_mm::vmm::map(pt, ADDR_VA, phys, PagePerms::USER_RW).expect("map");
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    unsafe { core::ptr::copy_nonoverlapping(sa.as_ptr(), phys as *mut u8, 16) };
    azos_sched::set_current_user_pt(pt);
    Scene
}

fn as_task(tid: u32) {
    azos_sched::set_current_task_tid(tid);
}

fn tcp_socket_of(tid: u32) -> u64 {
    as_task(tid);
    let fd = super::sys_socket(AF_INET as u64, SOCK_STREAM as u64, IPPROTO_TCP as u64);
    assert!(fd >= 0, "socket() for tid {tid} failed: {fd}");
    assert_eq!(azos_net::socket_owner(fd as i32), Some(tid));
    fd as u64
}

// ── NODE_BIND ──────────────────────────────────────────────────────────────

/// Refusal: A binds B's socket. `-1`, and B's socket is still unbound — B's
/// own listen is refused for port 0. Then B binds and listens, which shows
/// the socket was usable and A's `-1` was the gate.
#[test]
fn bind_refuses_another_tasks_socket_and_leaves_it_unbound() {
    let _g = serial();
    let _s = scene(7101);
    let b_fd = tcp_socket_of(B);

    as_task(A);
    assert_eq!(super::sys_bind(b_fd, ADDR_VA as u64, 16), -1, "A bound B's socket");

    as_task(B);
    assert_eq!(azos_net::socket_listen_bound(b_fd as i32), -1, "A's refused bind still set the port");
    assert_eq!(super::sys_bind(b_fd, ADDR_VA as u64, 16), 0, "the owner could not bind");
    assert_eq!(azos_net::socket_listen_bound(b_fd as i32), 0, "the owner could not listen once bound");
}

/// Refusal: no user sockaddr, or one that does not map, on a socket the
/// caller owns. `-1`, and nothing was stored.
#[test]
fn bind_refuses_a_null_or_unmapped_address_and_stores_nothing() {
    let _g = serial();
    let _s = scene(7102);
    let fd = tcp_socket_of(A);
    assert_eq!(super::sys_bind(fd, 0, 16), -1, "null sockaddr");
    assert_eq!(super::sys_bind(fd, UNMAPPED_VA as u64, 16), -1, "unmapped sockaddr");
    assert_eq!(azos_net::socket_listen_bound(fd as i32), -1, "a refused bind stored a port");
}

/// Refusal: descriptors that cannot name a socket — at the table size, the
/// value that once overflowed `sys_connect`'s port arithmetic, and one that
/// narrows to a small `i32` — are `-1`, with no panic.
#[test]
fn bind_refuses_out_of_range_descriptors() {
    let _g = serial();
    let _s = scene(7103);
    as_task(A);
    let max = azos_net::MAX_SOCKETS as u64;
    for fd in [max, 16384, u64::MAX, (1u64 << 32) | 1] {
        assert_eq!(super::sys_bind(fd, ADDR_VA as u64, 16), -1, "bind fd={fd:#x}");
        assert_eq!(azos_net::socket_listen_bound(fd as i32), -1, "listen fd={fd:#x}");
    }
}

/// Refusal: a ring-3 caller with no resolvable TID owns nothing, not even a
/// socket stamped for the kernel.
#[test]
fn a_ring3_caller_without_a_tid_cannot_bind_a_kernel_socket() {
    let _g = serial();
    let _s = scene(7104);
    let k = azos_net::socket_create_owned(AF_INET, SOCK_STREAM, IPPROTO_TCP, azos_net::SOCK_OWNER_KERNEL);
    assert!(k >= 0);
    as_task(0);
    let rc = super::sys_bind(k as u64, ADDR_VA as u64, 16);
    azos_net::socket_close(k);
    assert_eq!(rc, -1, "tid 0 in ring 3 bound a kernel socket");
}
