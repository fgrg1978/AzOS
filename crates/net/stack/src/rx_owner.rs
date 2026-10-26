// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! One consumer of the NIC receive ring at a time (wave 15 N8).
//!
//! `net_poll` is called from the net-poll task and, inline, from many other
//! places: the OTA listener's loops, the shell, DHCP/DNS/NTP waits, boot
//! smokes, the recv/accept syscalls when the poll task is not running. Each
//! call used to pop frames one at a time under the driver lock and process
//! them with no lock held, so two calls on two harts could take two frames of
//! one connection and hand them to TCP out of ring order. Seen 2026-10-09 on
//! the OTA row: the handshake's final ACK and the first data segment, 45 us
//! apart, popped by the OTA loop and the poll task; both read the connection
//! as `SynRcvd`, the first moved it to `Established` and stepped `snd.nxt`,
//! and the second failed `SEG.ACK == ISS + 1` against the stepped value and
//! drew a reset.
//!
//! [`PassOwner::run`] makes the whole pass (pop + dispatch) single-owner,
//! NAPI-style: a caller that finds a pass in progress does not wait for it
//! and does not drain; it leaves a request and returns, and the owner runs one
//! more pass for it before it lets go. So frames reach the stack in ring
//! order, a caller never blocks on another hart's pass, and a frame that
//! arrives while the owner is finishing is not stranded.
//!
//! **No lost request.** The contender stores `again` and then reads `busy`;
//! the owner stores `busy = false` and then reads `again` (all `SeqCst`). One
//! of the two sees the other's store: either the owner runs again, or the
//! contender finds the pass free and takes it itself (or both, and one wins).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The owner bit of one receive path, plus a "run once more" request.
pub struct PassOwner {
    busy: AtomicBool,
    again: AtomicBool,
    /// Calls that found a pass in progress and left it a request.
    contended: AtomicU64,
}

impl PassOwner {
    pub const fn new() -> Self {
        PassOwner {
            busy: AtomicBool::new(false),
            again: AtomicBool::new(false),
            contended: AtomicU64::new(0),
        }
    }

    /// Run `pass` as the only pass in progress, then again for every caller
    /// that came in meanwhile. Returns what the last pass returned (`true`:
    /// its budget ran out with frames possibly left), or `false` when
    /// another caller owns the pass: that owner runs one more for this call.
    pub fn run<F: FnMut() -> bool>(&self, mut pass: F) -> bool {
        loop {
            if self.busy
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                self.contended.fetch_add(1, Ordering::Relaxed);
                self.again.store(true, Ordering::SeqCst);
                if self.busy.load(Ordering::SeqCst) {
                    return false;
                }
                // The owner let go before it could have seen the request:
                // take the pass ourselves.
                continue;
            }
            let more = pass();
            self.busy.store(false, Ordering::SeqCst);
            if more {
                return true;
            }
            if !self.again.swap(false, Ordering::SeqCst) {
                return false;
            }
        }
    }

    /// Calls that found a pass in progress, since boot.
    pub fn contended(&self) -> u64 {
        self.contended.load(Ordering::Relaxed)
    }
}
