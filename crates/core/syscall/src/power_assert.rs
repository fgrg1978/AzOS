// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `PowerAssert` interface the kernel hosts on the `powerassert`
//! endpoint (`azos_devif::power_assert`): system power assertions. The owner
//! of an assertion is the calling task, never a number the caller passes; the
//! ledger is `azos_sched::energy`'s (Kconfig `ENERGY`, else every op answers
//! `UNSUPPORTED`).

use azos_abi::cap::CapPerms;
use azos_devif::{outcome, Out};

use crate::khost::Caller;

/// The `PowerAssert` interface served for one caller.
pub struct Server(pub Caller);

#[cfg(feature = "energy")]
fn code(e: azos_sched::energy::AssertError) -> u32 {
    use azos_sched::energy::AssertError;
    match e {
        AssertError::Reason | AssertError::Ttl => outcome::BAD_ARGUMENT,
        AssertError::Quota | AssertError::Full => outcome::BUSY,
        AssertError::NoAssertion => outcome::NO_RESOURCE,
    }
}

impl azos_devif::PowerAssert for Server {
    fn hold(&mut self, reason: u32, ttl_ms: u32) -> Out<u32> {
        if let Err(o) = self.0.gate(CapPerms::WRITE) {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            match azos_sched::energy::assert_hold(self.0.tid, reason, ttl_ms) {
                Ok(id) => Out::ok(id),
                Err(e) => Out::err(code(e)),
            }
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = (reason, ttl_ms);
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn release(&mut self, id: u32) -> Out<()> {
        if let Err(o) = self.0.gate(CapPerms::WRITE) {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            match azos_sched::energy::assert_release(self.0.tid, id) {
                Ok(()) => Out::ok(()),
                Err(e) => Out::err(code(e)),
            }
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = id;
            Out::err(outcome::UNSUPPORTED)
        }
    }

    fn stats(&self, sel: u32) -> Out<u64> {
        if let Err(o) = self.0.gate(CapPerms::READ) {
            return o;
        }
        #[cfg(feature = "energy")]
        {
            match azos_sched::energy::assert_stat(sel) {
                Some(v) => Out::ok(v),
                None => Out::err(outcome::BAD_ARGUMENT),
            }
        }
        #[cfg(not(feature = "energy"))]
        {
            let _ = sel;
            Out::err(outcome::UNSUPPORTED)
        }
    }
}
