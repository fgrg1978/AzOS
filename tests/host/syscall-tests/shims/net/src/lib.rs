// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host stand-in for `azos_net`, used only by `tests/host/syscall-tests`.
//!
//! **`socket` is the real stack, not a stand-in.** Target 3
//! (`socket_access_ok`, `crates/core/syscall/src/handlers.rs:861`) reads
//! `azos_net::MAX_SOCKETS` and calls `azos_net::socket_owner`, both
//! defined for real in `crates/net/net/src/socket.rs`. `socket.rs` itself needs
//! only `tcp` and `udp` (per `tests/host/net-tests`' own doc comment on the same
//! pull), which need `ip`, which needs `ethernet`/`arp`/`igmp`, which need
//! `checksum`. All eight are pulled in with `#[path]`, the same set
//! `tests/host/net-tests` already proves compiles together on a host target —
//! this crate duplicates that module list rather than depending on
//! `net-tests` (whose pulled modules are private to it).
//!
//! Everything else `handlers.rs` needs from `azos_net` — `net_info`,
//! `net_ping`, `net_poll`, `net_set_ip`, `net_get_mac` — touches the NIC
//! driver and is not part of this crate's three test targets, so it is
//! `todo!()`.

// The driver class crates the compiled sources name, all served by the
// one host stand-in `beh_test_drivers`.
extern crate beh_test_drivers as azos_drv_sys;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/checksum.rs"]
mod checksum;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/ethernet.rs"]
mod ethernet;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/arp.rs"]
mod arp;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/igmp.rs"]
mod igmp;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/ip.rs"]
mod ip;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/ipv6.rs"]
mod ipv6;

// `pub`: `SYS_DNS_RESOLVE` (266) calls `dns::resolve_with_yield`.
#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/dns.rs"]
pub mod dns;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/ntp.rs"]
mod ntp;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/seq.rs"]
mod seq;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/udp.rs"]
mod udp;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/tcp.rs"]
mod tcp;

/// N7 waiter queues (`sys_accept` arms `TCP_WAITERS`). No hooks are
/// registered here, so every wait is the caller's fallback, as before.
#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/wait.rs"]
pub mod wait;

#[allow(dead_code)]
#[path = "../../../../../../crates/net/net/src/socket.rs"]
pub mod socket;

// The real, callable surface `handlers.rs` uses at the crate root.
pub use socket::{
    socket_bind, socket_listen_bound, socket_create_owned, socket_accept_owned,
    socket_send, socket_recv, socket_close, socket_owner, SockAddr, MAX_SOCKETS,
    SOCK_OWNER_KERNEL,
};

pub fn net_info() {
    shim_fwd::hit("net_info".into(), |_| ())
}
pub fn net_ping(dst_ip: [u8; 4]) -> i32 {
    shim_fwd::hit(format!("net_ping {dst_ip:?}"), |f| f.ping)
}
/// `todo!()` unless a test armed it with [`shim_arm_net_poll`]; armed, it
/// only counts (`sys_accept` polls once per look).
pub fn net_poll() {
    let mut g = NET_POLLS.lock().unwrap_or_else(|e| e.into_inner());
    match g.as_mut() {
        Some(n) => *n += 1,
        None => todo!("NIC stand-in: not reached by any test in this crate"),
    }
}

static NET_POLLS: std::sync::Mutex<Option<u64>> = std::sync::Mutex::new(None);

/// Test-only control surface: make [`net_poll`] count from 0 (`false`: back
/// to `todo!()`).
pub fn shim_arm_net_poll(armed: bool) {
    *NET_POLLS.lock().unwrap_or_else(|e| e.into_inner()) = if armed { Some(0) } else { None };
}

/// Test-only control surface: polls counted since [`shim_arm_net_poll`].
pub fn shim_net_polls() -> Option<u64> {
    *NET_POLLS.lock().unwrap_or_else(|e| e.into_inner())
}
pub fn net_set_ip(_ip: [u8; 4], _mask: [u8; 4], _gw: [u8; 4]) {
    todo!("NIC stand-in: not reached by any test in this crate")
}
/// Default-route stand-in (ip.rs routes off-subnet traffic via the gateway
/// since 2026-09-26); no test in this crate sends off-subnet.
pub fn net_get_gateway() -> [u8; 4] {
    todo!("NIC stand-in: not reached by any test in this crate")
}
pub fn net_get_ip() -> [u8; 4] {
    shim_fwd::hit("net_get_ip".into(), |f| f.ip)
}
pub fn net_get_mac() -> [u8; 6] {
    shim_fwd::hit("net_get_mac".into(), |f| f.mac)
}
pub fn net_raw_send(_frame: &[u8]) -> i32 {
    todo!("NIC stand-in: not reached by any test in this crate")
}
pub fn net_get_mask() -> [u8; 4] {
    todo!("NIC stand-in: not reached by any test in this crate")
}

/// `crate::net_random_fill` for the net files pulled in above: the kernel with
/// no seeded entropy pool, so each consumer takes its counter fallback.
pub fn net_random_fill(_buf: &mut [u8]) -> bool {
    false
}

/// An armed recorder for the NIC queries the info syscalls forward to.
/// Unarmed, each is the NIC stand-in's `todo!()` exactly as before, so a
/// test that reaches the NIC without meaning to still panics.
/// `harness.rs::reset_state` disarms it.
pub mod shim_fwd {
    use std::sync::Mutex;

    #[derive(Default, Debug)]
    pub struct Fwd {
        pub ip: [u8; 4],
        pub mac: [u8; 6],
        pub ping: i32,
        pub log: Vec<String>,
    }

    static ARMED: Mutex<Option<Fwd>> = Mutex::new(None);

    pub fn arm(f: Fwd) {
        *ARMED.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    pub fn disarm() -> Option<Fwd> {
        ARMED.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    pub(crate) fn hit<R>(what: String, f: impl FnOnce(&Fwd) -> R) -> R {
        let mut g = ARMED.lock().unwrap_or_else(|e| e.into_inner());
        match g.as_mut() {
            Some(a) => {
                a.log.push(what);
                f(a)
            }
            None => todo!("NIC stand-in: not reached by any test in this crate"),
        }
    }
}
