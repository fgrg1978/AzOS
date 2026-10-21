// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `Net` interface the kernel hosts (`endpoint = "net"`): the stack's
//! resolver and the state of its SNTP client.
//!
//! `resolve` is [`azos_net::dns`]'s lookup, run on the caller's own stack and
//! sleeping in [`nap`] while it waits for the answer; `ntp_status` reads
//! [`azos_net::ntp::status`]. Both observe, so both need `READ`. The callers
//! are toolbox's `host` and `ntp` applets.

use azos_abi::cap::CapPerms;
use azos_devif::net::{FAMILY_V4, FAMILY_V6, NAME_MAX};
use azos_devif::{outcome, Address, NtpStatus, Out, Query};

use crate::khost::Caller;

/// Sleep about a millisecond, or until woken: the wait function of a task that
/// waits on the stack (`dns::resolve_with_yield`, `ntp::ntp_sync_with_yield`).
/// `task_yield` is not one: on an idle hart it returns at once and the wait
/// becomes a spin.
pub fn nap() {
    let now = azos_drv_sys::timebase::now();
    azos_sched::task_block(azos_sched::WaitReason::Timer(now + azos_drv_sys::timebase::TIMER_FREQ / 1000));
}

/// [`azos_net::ntp::status`] in the interface's units.
fn ntp_status() -> NtpStatus {
    let s = azos_net::ntp::status();
    let ms = azos_abi::time::ticks_to_ns(s.age_ticks, azos_drv_sys::timebase::TIMER_FREQ) / 1_000_000;
    NtpStatus {
        server: s.server.map_or(0, u32::from_be_bytes),
        synced: s.synced as u32,
        last_unix_sec: s.last_unix_sec,
        age_ms: ms,
        exchanges: s.exchanges,
        failures: s.failures,
    }
}

/// The `Net` interface served for one caller.
pub struct Server(pub Caller);

impl azos_devif::Net for Server {
    /// In order: the right; the family and the name; then the lookup.
    fn resolve(&self, query: Query) -> Out<Address> {
        if let Err(refused) = self.0.gate::<Address>(CapPerms::READ) {
            return refused;
        }
        let mut buf = [0u8; NAME_MAX];
        let n = query.name(&mut buf);
        let Ok(name) = core::str::from_utf8(&buf[..n]) else {
            return Out::err(outcome::BAD_ARGUMENT);
        };
        if n == 0 {
            return Out::err(outcome::BAD_ARGUMENT);
        }
        let found = match query.family {
            FAMILY_V4 => azos_net::dns::resolve_with_yield(name, nap).map(Address::v4),
            FAMILY_V6 => azos_net::dns::resolve_aaaa_with_yield(name, nap).map(Address::v6),
            _ => return Out::err(outcome::BAD_ARGUMENT),
        };
        match found {
            Some(a) => Out::ok(a),
            None => Out::err(outcome::NO_RESOURCE),
        }
    }

    fn ntp_status(&self) -> Out<NtpStatus> {
        if let Err(refused) = self.0.gate::<NtpStatus>(CapPerms::READ) {
            return refused;
        }
        Out::ok(ntp_status())
    }
}
