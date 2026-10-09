// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `NetDevice` — one trait per NIC backend, and the single selection point
//! `crates/net/net` calls through instead of asking `eth::eth_is_ready()` at
//! every one of its three call sites (send, recv, and the MAC/ready read at
//! `net_init`).
//!
//! # What this replaces
//!
//! Before this module, `crates/net/net/src/lib.rs` did:
//! ```ignore
//! if azos_drv_net::eth::eth_is_ready() {
//!     azos_drv_net::eth::eth_send(frame)
//! } else {
//!     azos_drv_virtio::virtio::net::send(frame) // mapped from Result<(),()>
//! }
//! ```
//! duplicated at three call sites, with `eth_is_ready()` — a real,
//! non-inlined cross-crate call on QEMU builds, where it always returns
//! `false` — paid on every single frame. [`select`] below runs that decision
//! exactly once, at `net_init()`; [`send`]/[`recv`]/[`mac`]/[`is_ready`] then
//! read a relaxed `AtomicU8` and jump straight to the chosen backend's
//! `NetDevice` method.
//!
//! # Why an enum-selected static, not `&'static dyn NetDevice`
//!
//! This workspace builds with `lto = false`, so a call through `dyn
//! NetDevice` cannot be devirtualised across the `crates/net/net` ↔
//! `crates/drivers/net` boundary — every `send`/`recv` on the network hot path
//! would keep a real vtable indirection forever. The two-backend enum
//! dispatch below compiles to a compare-and-branch on a byte the caller
//! already has to load, and every method on [`EthNetDevice`] /
//! [`VirtioNetDevice`] is `#[inline]`, so the whole chain — `crates/net/net`'s
//! `net_raw_send` down to the backend's own `send`/`eth_send` — is eligible
//! to inline into one function body despite the crate boundary. See the
//! module doc on why that boundary matters at all: cross-crate calls need an
//! explicit `#[inline]` under `lto = false` or they stay real calls.
//!
//! # How close this is to a ring-3 swap
//!
//! [`NetDevice`] mirrors the shape `azos_drv_api::Driver` already
//! uses for its userspace forwarder (`UserDriverProxy`): every method takes
//! `&self`, operates on borrowed fixed-size byte slices (never an owned
//! buffer or an unbounded `Vec`), returns a small `Copy` error enum instead
//! of `Result<(),()>` or an `i32` sentinel, and never blocks — `recv` polls
//! once and returns `Ok(0)` for "nothing queued" rather than spinning, which
//! is exactly the "bounded poll" contract a ring-3 forwarder needs (it
//! cannot afford to block the kernel-side caller on a user-mode process that
//! may never respond). What is still missing for an actual
//! `UserDriverProxy`-backed `NetDevice`: `Driver::handle_request` is a single
//! `(op, input, output)` entry point, so a userspace NIC driver would need
//! its own small `op` encoding (send=0, recv=1, mac=2, is_ready=3) and a
//! `NetDevice` impl on top of `UserDriverProxy` translating one to the
//! other — the same kind of thin adapter `EthNetDevice`/`VirtioNetDevice`
//! already are over their free-function APIs below. Nothing here registers a
//! NIC into `runtime::REGISTRY` (`crates/drivers/base/src/runtime.rs`) or
//! `sys_drv_invoke` — that wiring is unbuilt, not merely hidden behind this
//! trait.

use azos_drv_api::net::{NetDevice, NetError};

// ── Selection, done once ────────────────────────────────────────────────

use core::sync::atomic::{AtomicU8, Ordering};

const BACKEND_NONE: u8 = 0;
const BACKEND_ETH: u8 = 1;
const BACKEND_VIRTIO: u8 = 2;

static ACTIVE_BACKEND: AtomicU8 = AtomicU8::new(BACKEND_NONE);

/// Pure decision table, split out of [`select`] so it is testable on the
/// host without real hardware: `select` is a two-line caller that feeds it
/// live `is_ready()` reads. Board Ethernet wins when both are ready, which
/// matches the priority the pre-trait `if eth_is_ready() {...} else {...}`
/// chain at all three old call sites used.
const fn pick(eth_ready: bool, virtio_ready: bool) -> u8 {
    if eth_ready {
        BACKEND_ETH
    } else if virtio_ready {
        BACKEND_VIRTIO
    } else {
        BACKEND_NONE
    }
}

/// Choose the active backend. Call once, at `net_init()` — after this,
/// [`send`]/[`recv`]/[`mac`]/[`is_ready`] read the cached choice instead of
/// re-probing either device. Returns `true` iff a backend was selected.
pub fn select() -> bool {
    let backend = pick(
        crate::eth::EthNetDevice.is_ready(),
        azos_drv_virtio::virtio::net::VirtioNetDevice.is_ready(),
    );
    ACTIVE_BACKEND.store(backend, Ordering::Release);
    backend != BACKEND_NONE
}

/// Send through the backend chosen by [`select`].
#[inline]
pub fn send(frame: &[u8]) -> Result<usize, NetError> {
    match ACTIVE_BACKEND.load(Ordering::Relaxed) {
        BACKEND_ETH => crate::eth::EthNetDevice.send(frame),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.send(frame),
        _ => Err(NetError::NotReady),
    }
}

/// Receive through the backend chosen by [`select`]. `Ok(0)` — not an
/// error — when nothing is selected or nothing is queued.
#[inline]
pub fn recv(buf: &mut [u8]) -> Result<usize, NetError> {
    match ACTIVE_BACKEND.load(Ordering::Relaxed) {
        BACKEND_ETH => crate::eth::EthNetDevice.recv(buf),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.recv(buf),
        _ => Ok(0),
    }
}

/// Hand up to `max` received frames to `f` through the backend chosen by
/// [`select`] (`NetDevice::recv_batch`): by reference on virtio-net, one
/// copy each on board Ethernet. 0 when nothing is selected or queued.
#[inline]
pub fn recv_batch(max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
    match ACTIVE_BACKEND.load(Ordering::Relaxed) {
        BACKEND_ETH => crate::eth::EthNetDevice.recv_batch(max, f),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.recv_batch(max, f),
        _ => 0,
    }
}

/// MAC of the backend chosen by [`select`]; all-zero if none.
#[inline]
pub fn mac() -> [u8; 6] {
    match ACTIVE_BACKEND.load(Ordering::Relaxed) {
        BACKEND_ETH => crate::eth::EthNetDevice.mac(),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.mac(),
        _ => [0u8; 6],
    }
}

/// Open a TX batch on the backend chosen by [`select`] (see
/// `NetDevice::tx_batch_begin`): sends until [`tx_batch_end`] may share one
/// doorbell. No-op without a backend, and on board Ethernet.
#[inline]
pub fn tx_batch_begin() {
    match ACTIVE_BACKEND.load(Ordering::Relaxed) {
        BACKEND_ETH => crate::eth::EthNetDevice.tx_batch_begin(),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.tx_batch_begin(),
        _ => {}
    }
}

/// Close the batch [`tx_batch_begin`] opened and announce what it queued.
#[inline]
pub fn tx_batch_end() {
    match ACTIVE_BACKEND.load(Ordering::Relaxed) {
        BACKEND_ETH => crate::eth::EthNetDevice.tx_batch_end(),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.tx_batch_end(),
        _ => {}
    }
}

/// The virtio-net queue counters (frames, doorbells issued and skipped,
/// drops, interrupts) when virtio-net is the active backend.
pub fn virtio_queue_stats() -> Option<azos_drv_virtio::virtio::net::NetQueueStats> {
    match ACTIVE_BACKEND.load(Ordering::Relaxed) {
        BACKEND_VIRTIO => Some(azos_drv_virtio::virtio::net::queue_stats()),
        _ => None,
    }
}

/// Whether [`select`] found a usable backend.
#[inline]
pub fn is_ready() -> bool {
    ACTIVE_BACKEND.load(Ordering::Relaxed) != BACKEND_NONE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Discriminates.** Board Ethernet must win when both backends read
    /// ready — this is the priority the old `if eth_is_ready() {...} else
    /// {...}` chain encoded at all three call sites it used to occupy.
    /// Flip the branch order in `pick` and this fails.
    #[test]
    fn eth_wins_when_both_are_ready() {
        assert_eq!(pick(true, true), BACKEND_ETH);
    }

    /// **Discriminates.** VirtIO is the QEMU fallback: with no board
    /// Ethernet, it must still be picked. A `pick` that only ever returns
    /// `BACKEND_ETH` (a stub that ignores its second argument) fails this.
    #[test]
    fn virtio_is_picked_when_only_it_is_ready() {
        assert_eq!(pick(false, true), BACKEND_VIRTIO);
    }

    /// **Discriminates.** Neither ready must not silently default to a
    /// backend that does not exist.
    #[test]
    fn neither_ready_selects_none() {
        assert_eq!(pick(false, false), BACKEND_NONE);
    }
}
