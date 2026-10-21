// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `net-clients` task: the stack's own clients of the network. Today one,
//! the SNTP client that steers the wall clock (Kconfig `NTP_CLIENT`).
//!
//! Not in the real-time band and not the poller: `net_poll_task` keeps the
//! receive path and the TCP timers moving; this task sleeps between
//! exchanges and, during one, waits for the answer with the stack's wait
//! hooks (`azos_net::wait`) or, failing those, a one-millisecond sleep
//! (`azos_syscall::net_host::nap`).
//!
//! **One exchange**: the server is the lease's (DHCP option 42,
//! `ntp::set_leased_server`) while the lease names one, else the address of
//! Kconfig `NTP_SERVER` (a dotted quad as it is, a name through the resolver,
//! before every exchange: its cache keeps an answer five minutes). The
//! SNTP exchange (`ntp::ntp_sync_with_yield`) hands its four timestamps to the
//! clock discipline, which decides whether to slew, step or filter. After a
//! success the task sleeps `NTP_INTERVAL_S`; after a failure 16 s, doubling up
//! to that period.

use crate::*;
use azos_drv_sys::timebase::{now, TIMER_FREQ};

/// Longest a configured lease is waited for before the first exchange: the
/// lease may name the time server, and it sets the address the exchange is
/// sent from.
const DHCP_WAIT_S: u64 = 60;

/// The Net interface's name limit (`azos_devif::net::NAME_MAX`) bounds the
/// configured name, which `toolbox host` can then also look up.
const _: () = assert!(azos_limits::NTP_SERVER.len() <= azos_devif::net::NAME_MAX, "NTP_SERVER: at most 48 characters");

/// Sleep `s` seconds (a wake that comes early does not shorten it).
fn sleep_s(s: u64) {
    let until = now() + TIMER_FREQ * s;
    while now() < until {
        azos_sched::task_block(azos_sched::WaitReason::Timer(until));
    }
}

/// Longest pause between two looks for an interface that is not there yet.
const NIC_POLL_MAX_S: u64 = 30;

/// Wait for what an exchange needs: an interface (which may come up after this
/// task starts, or be hot-plugged: looked for with a backoff of 1 s doubling
/// up to [`NIC_POLL_MAX_S`], with no end), then an address and, when the
/// configuration asks for DHCP, its lease (for up to [`DHCP_WAIT_S`]).
fn wait_for_network() {
    let mut pause = 1;
    let mut announced = false;
    while !azos_drv_net::net_device::is_ready() {
        if !announced {
            kprintln!("[NET-CLIENTS] no network interface yet: the SNTP client waits for one");
            announced = true;
        }
        sleep_s(pause);
        pause = (pause * 2).min(NIC_POLL_MAX_S);
    }
    let lease_wanted = azos_config::CFG_NET_DHCP.load(Ordering::Relaxed) != 0;
    let mut waited = 0;
    loop {
        let lease_done = !lease_wanted || azos_net::dhcp::dhcp_state() == azos_net::dhcp::DhcpState::Bound;
        let has_ip = azos_net::net_get_ip() != [0, 0, 0, 0];
        if has_ip && (lease_done || waited >= DHCP_WAIT_S) {
            return;
        }
        sleep_s(1);
        waited += 1;
    }
}

/// Make the configured server's address the client's, unless a lease names
/// one. A name that does not resolve keeps the address found before.
fn refresh_server() {
    if azos_net::ntp::leased_server().is_some() {
        return;
    }
    let name = azos_limits::NTP_SERVER;
    if name.is_empty() {
        return;
    }
    let addr = azos_net::ntp::parse_ipv4(name)
        .or_else(|| azos_net::dns::resolve_with_yield(name, azos_syscall::net_host::nap));
    match addr {
        Some(a) => azos_net::ntp::set_ntp_server(a),
        None => azos_drv_sys::kwarn!("[NTP] cannot resolve {}", name),
    }
}

/// The `net-clients` task body. Never returns: without an interface it waits
/// for one ([`wait_for_network`]).
pub(crate) fn net_clients_task(_: usize) {
    let interval = azos_limits::NTP_INTERVAL_S as u64;
    wait_for_network();
    kprintln!("[NET-CLIENTS] SNTP client: server {}, every {} s",
              if azos_limits::NTP_SERVER.is_empty() { "from the lease" } else { azos_limits::NTP_SERVER },
              interval);
    let mut failed_wait = azos_net::ntp::RETRY_FIRST_S;
    loop {
        refresh_server();
        let wait = if azos_net::ntp::ntp_sync_with_yield(azos_syscall::net_host::nap) != 0 {
            failed_wait = azos_net::ntp::RETRY_FIRST_S;
            interval
        } else {
            let w = failed_wait.min(interval);
            failed_wait = azos_net::ntp::retry_after_s(failed_wait, interval);
            w
        };
        sleep_s(wait);
    }
}
