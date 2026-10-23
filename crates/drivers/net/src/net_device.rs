// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! `NetDevice` — one trait per NIC backend, and the table of the NICs that
//! came up: `crates/net/net` calls through it, by NIC number, instead of
//! asking `eth::eth_is_ready()` at every one of its three call sites (send,
//! recv, and the MAC/ready read at `net_init`).
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
//! exactly once, at `net_init()`, and numbers the NICs that are ready (board
//! Ethernet first, then virtio-net); [`send`]/[`recv`]/[`mac`] then read a
//! relaxed `AtomicU8` for the NIC they were given and jump straight to that
//! backend's `NetDevice` method. One backend of each kind exists in the tree
//! (`virtio::net` keeps its rings in statics), so the table holds at most
//! [`MAX_NICS`] NICs today; a second NIC of a kind is a new backend value
//! here, not a change to the callers.
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
//! # A NIC that appears after boot (USB)
//!
//! The NICs above are probed once. A USB network function (CDC-ECM/NCM,
//! `azos_usb::class::cdc`) comes and goes with its cable, so it is not probed:
//! its driver [`register_usb`]s a `&'static dyn NetDevice` when the function is
//! ready and [`unregister_usb`]s it when the device is gone. Registration
//! takes the first free number of the table (after the NICs [`select`]
//! numbered, so no number moves) and returns it; a [`select`] run while one is
//! registered numbers it last. One USB NIC at a time. The dispatch is through
//! the registered trait object, not an enum arm of its own: a USB NIC is bound
//! by the bus, not by the call, and the extra indirection is the smaller part
//! of a frame's cost on it. It is polled (no interrupt reaches this table), so
//! [`irq_driven`] is false while it is registered.
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
use azos_sync::SpinLock;

// ── Selection, done once ────────────────────────────────────────────────

use core::sync::atomic::{AtomicU8, Ordering};

const BACKEND_NONE: u8 = 0;
const BACKEND_ETH: u8 = 1;
const BACKEND_VIRTIO: u8 = 2;
const BACKEND_DWMAC: u8 = 3;
const BACKEND_E1000E: u8 = 4;
const BACKEND_IGC: u8 = 5;
const BACKEND_USB: u8 = 6;

/// NICs the table holds: one per backend kind.
pub const MAX_NICS: usize = 6;

/// The backend of each NIC, in the order [`select`] numbered them.
static NIC_BACKEND: [AtomicU8; MAX_NICS] = [const { AtomicU8::new(BACKEND_NONE) }; MAX_NICS];

/// Pure decision table, split out of [`select`] so it is testable on the
/// host without real hardware: `select` is a short caller that feeds it
/// live `is_ready()` reads. Every ready backend becomes a NIC, the physical
/// ones first (board Ethernet, the Cadence MAC then the Synopsys one: no board
/// has both; then the PCI Intel NICs, e1000e before igc), virtio-net, and a USB NIC last: board Ethernet is the
/// one the pre-table `if eth_is_ready() {...} else {...}` chain preferred, and
/// NIC 0 is the stack's primary interface.
const fn pick(
    eth_ready: bool,
    dwmac_ready: bool,
    e1000e_ready: bool,
    igc_ready: bool,
    virtio_ready: bool,
    usb_ready: bool,
) -> [u8; MAX_NICS] {
    let mut out = [BACKEND_NONE; MAX_NICS];
    let mut n = 0;
    if eth_ready {
        out[n] = BACKEND_ETH;
        n += 1;
    }
    if dwmac_ready {
        out[n] = BACKEND_DWMAC;
        n += 1;
    }
    if e1000e_ready {
        out[n] = BACKEND_E1000E;
        n += 1;
    }
    if igc_ready {
        out[n] = BACKEND_IGC;
        n += 1;
    }
    if virtio_ready {
        out[n] = BACKEND_VIRTIO;
        n += 1;
    }
    if usb_ready {
        out[n] = BACKEND_USB;
    }
    out
}

/// The registered USB NIC (see the module doc).
static USB_NIC: SpinLock<Option<&'static dyn NetDevice>> = SpinLock::new(None);

/// The registered USB NIC, copied out so the call runs without the lock.
#[inline]
fn usb_nic() -> Option<&'static dyn NetDevice> {
    *USB_NIC.lock()
}

/// Register the NIC of a USB network function once it is ready; the number
/// the stack addresses it by. `None` when a USB NIC is registered already or
/// the table is full.
pub fn register_usb(dev: &'static dyn NetDevice) -> Option<usize> {
    let mut slot = USB_NIC.lock();
    if slot.is_some() {
        return None;
    }
    let nic = NIC_BACKEND.iter().position(|b| b.load(Ordering::Acquire) == BACKEND_NONE)?;
    *slot = Some(dev);
    NIC_BACKEND[nic].store(BACKEND_USB, Ordering::Release);
    Some(nic)
}

/// The USB NIC is gone (its device was unplugged or its function failed): its
/// number stops naming anything.
pub fn unregister_usb() {
    let mut slot = USB_NIC.lock();
    for b in NIC_BACKEND.iter() {
        let _ = b.compare_exchange(BACKEND_USB, BACKEND_NONE, Ordering::AcqRel, Ordering::Acquire);
    }
    *slot = None;
}

/// Is the board's Synopsys MAC up? Only the VisionFive 2 has one.
#[cfg(feature = "vf2")]
fn dwmac_ready() -> bool {
    crate::dwmac::board::DwmacNetDevice.is_ready()
}
#[cfg(not(feature = "vf2"))]
fn dwmac_ready() -> bool {
    false
}

/// The Intel NIC is a backend only in an image that compiles its driver
/// (Kconfig `DRV_E1000E`).
#[inline]
fn e1000e_ready() -> bool {
    #[cfg(feature = "e1000e")]
    { crate::e1000e::E1000eNetDevice.is_ready() }
    #[cfg(not(feature = "e1000e"))]
    { false }
}

/// The Intel I225/I226 NIC is a backend only in an image that compiles its
/// driver (Kconfig `DRV_IGC`).
#[inline]
fn igc_ready() -> bool {
    #[cfg(feature = "igc")]
    { crate::igc::IgcNetDevice.is_ready() }
    #[cfg(not(feature = "igc"))]
    { false }
}

/// Number the NICs that are ready. Call once, at `net_init()` — after this,
/// the functions below read the cached table instead of re-probing either
/// device. Returns how many NICs there are.
pub fn select() -> usize {
    let picked = pick(
        crate::eth::EthNetDevice.is_ready(),
        dwmac_ready(),
        e1000e_ready(),
        igc_ready(),
        azos_drv_virtio::virtio::net::VirtioNetDevice.is_ready(),
        usb_nic().is_some_and(|d| d.is_ready()),
    );
    for (slot, backend) in NIC_BACKEND.iter().zip(picked) {
        slot.store(backend, Ordering::Release);
    }
    count()
}

/// How many NICs [`select`] found.
#[inline]
pub fn count() -> usize {
    NIC_BACKEND.iter().filter(|b| b.load(Ordering::Relaxed) != BACKEND_NONE).count()
}

/// Whether [`select`] found at least one NIC.
#[inline]
pub fn is_ready() -> bool {
    count() != 0
}

#[inline]
fn backend(nic: usize) -> u8 {
    match NIC_BACKEND.get(nic) {
        Some(b) => b.load(Ordering::Relaxed),
        None => BACKEND_NONE,
    }
}

/// Send through NIC `nic`.
#[inline]
pub fn send(nic: usize, frame: &[u8]) -> Result<usize, NetError> {
    match backend(nic) {
        BACKEND_ETH => crate::eth::EthNetDevice.send(frame),
        #[cfg(feature = "vf2")]
        BACKEND_DWMAC => crate::dwmac::board::DwmacNetDevice.send(frame),
        #[cfg(feature = "e1000e")]
        BACKEND_E1000E => crate::e1000e::E1000eNetDevice.send(frame),
        #[cfg(feature = "igc")]
        BACKEND_IGC => crate::igc::IgcNetDevice.send(frame),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.send(frame),
        BACKEND_USB => usb_nic().map_or(Err(NetError::NotReady), |d| d.send(frame)),
        _ => Err(NetError::NotReady),
    }
}

/// Receive through NIC `nic`. `Ok(0)` — not an error — when there is no such
/// NIC or nothing is queued.
#[inline]
pub fn recv(nic: usize, buf: &mut [u8]) -> Result<usize, NetError> {
    match backend(nic) {
        BACKEND_ETH => crate::eth::EthNetDevice.recv(buf),
        #[cfg(feature = "vf2")]
        BACKEND_DWMAC => crate::dwmac::board::DwmacNetDevice.recv(buf),
        #[cfg(feature = "e1000e")]
        BACKEND_E1000E => crate::e1000e::E1000eNetDevice.recv(buf),
        #[cfg(feature = "igc")]
        BACKEND_IGC => crate::igc::IgcNetDevice.recv(buf),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.recv(buf),
        BACKEND_USB => usb_nic().map_or(Ok(0), |d| d.recv(buf)),
        _ => Ok(0),
    }
}

/// Hand up to `max` received frames of NIC `nic` to `f`
/// (`NetDevice::recv_batch`): by reference on virtio-net, one copy each on
/// board Ethernet. 0 when there is no such NIC or nothing is queued.
#[inline]
pub fn recv_batch(nic: usize, max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
    match backend(nic) {
        BACKEND_ETH => crate::eth::EthNetDevice.recv_batch(max, f),
        #[cfg(feature = "vf2")]
        BACKEND_DWMAC => crate::dwmac::board::DwmacNetDevice.recv_batch(max, f),
        #[cfg(feature = "e1000e")]
        BACKEND_E1000E => crate::e1000e::E1000eNetDevice.recv_batch(max, f),
        #[cfg(feature = "igc")]
        BACKEND_IGC => crate::igc::IgcNetDevice.recv_batch(max, f),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.recv_batch(max, f),
        BACKEND_USB => usb_nic().map_or(0, |d| d.recv_batch(max, f)),
        _ => 0,
    }
}

/// MAC of NIC `nic`; all-zero if there is no such NIC.
#[inline]
pub fn mac(nic: usize) -> [u8; 6] {
    match backend(nic) {
        BACKEND_ETH => crate::eth::EthNetDevice.mac(),
        #[cfg(feature = "vf2")]
        BACKEND_DWMAC => crate::dwmac::board::DwmacNetDevice.mac(),
        #[cfg(feature = "e1000e")]
        BACKEND_E1000E => crate::e1000e::E1000eNetDevice.mac(),
        #[cfg(feature = "igc")]
        BACKEND_IGC => crate::igc::IgcNetDevice.mac(),
        BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.mac(),
        BACKEND_USB => usb_nic().map_or([0u8; 6], |d| d.mac()),
        _ => [0u8; 6],
    }
}

/// How often, in ticks, a transmit ring that holds frames is looked at
/// ([`tx_watch`], `recovery::TX_LOOK_US`); the stack's poller keeps to it.
pub fn tx_look_ticks() -> u64 {
    azos_drv_api::recovery::TX_LOOK_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000
}

/// Look at every NIC's transmit ring (`NetDevice::tx_watch`): take back
/// what the devices sent, reset a NIC whose ring is past its budget, and
/// return the earliest tick by which a ring that still holds frames must be
/// looked at again (`None`: no ring holds any).
pub fn tx_watch() -> Option<u64> {
    let mut due: Option<u64> = None;
    for nic in 0..MAX_NICS {
        let d = match backend(nic) {
            BACKEND_ETH => crate::eth::EthNetDevice.tx_watch(),
            #[cfg(feature = "vf2")]
            BACKEND_DWMAC => crate::dwmac::board::DwmacNetDevice.tx_watch(),
            #[cfg(feature = "e1000e")]
            BACKEND_E1000E => crate::e1000e::E1000eNetDevice.tx_watch(),
            #[cfg(feature = "igc")]
            BACKEND_IGC => crate::igc::IgcNetDevice.tx_watch(),
            BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.tx_watch(),
            BACKEND_USB => usb_nic().and_then(|d| d.tx_watch()),
            _ => None,
        };
        due = match (due, d) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    due
}

/// Open a TX batch on every NIC (see `NetDevice::tx_batch_begin`): sends
/// until [`tx_batch_end`] may share one doorbell. No-op without a NIC, and on
/// the Cadence board Ethernet.
#[inline]
pub fn tx_batch_begin() {
    for nic in 0..MAX_NICS {
        match backend(nic) {
            BACKEND_ETH => crate::eth::EthNetDevice.tx_batch_begin(),
            #[cfg(feature = "vf2")]
            BACKEND_DWMAC => crate::dwmac::board::DwmacNetDevice.tx_batch_begin(),
            #[cfg(feature = "e1000e")]
            BACKEND_E1000E => crate::e1000e::E1000eNetDevice.tx_batch_begin(),
            #[cfg(feature = "igc")]
            BACKEND_IGC => crate::igc::IgcNetDevice.tx_batch_begin(),
            BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.tx_batch_begin(),
            BACKEND_USB => {
                if let Some(d) = usb_nic() {
                    d.tx_batch_begin();
                }
            }
            _ => {}
        }
    }
}

/// Close the batch [`tx_batch_begin`] opened and announce what it queued.
#[inline]
pub fn tx_batch_end() {
    for nic in 0..MAX_NICS {
        match backend(nic) {
            BACKEND_ETH => crate::eth::EthNetDevice.tx_batch_end(),
            #[cfg(feature = "vf2")]
            BACKEND_DWMAC => crate::dwmac::board::DwmacNetDevice.tx_batch_end(),
            #[cfg(feature = "e1000e")]
            BACKEND_E1000E => crate::e1000e::E1000eNetDevice.tx_batch_end(),
            #[cfg(feature = "igc")]
            BACKEND_IGC => crate::igc::IgcNetDevice.tx_batch_end(),
            BACKEND_VIRTIO => azos_drv_virtio::virtio::net::VirtioNetDevice.tx_batch_end(),
            BACKEND_USB => {
                if let Some(d) = usb_nic() {
                    d.tx_batch_end();
                }
            }
            _ => {}
        }
    }
}

/// Switch the board Ethernet to interrupt mode on interrupt source `line`
/// (the number the kernel's dispatcher will pass to [`irq`]); call before the
/// line is unmasked. `false` when the board has no interrupt-capable NIC.
#[cfg(feature = "vf2")]
pub fn enable_irq(line: u32) -> bool {
    crate::dwmac::board::enable_irq(line)
}

/// Interrupt-path hook: `line` is what the interrupt controller reported.
/// `true` when it was a NIC's: the device is acknowledged and its receive
/// gate open, and the caller wakes whatever drains the ring. Lock-free.
#[inline]
pub fn irq(line: u32) -> bool {
    #[cfg(feature = "vf2")]
    if crate::dwmac::board::irq(line) {
        return true;
    }
    azos_drv_virtio::virtio::net::mmio_irq(line)
}

/// Interrupt-path hook for the PCI NICs' MSI: `token` is what the interrupt
/// controller reported for the vector (`MsiRoute::isr_token`). `true` when it
/// is the vector of the Intel e1000e or igc NIC (acknowledged at the device,
/// receive causes counted); the caller then wakes whatever drains the ring.
/// `false` in an image with neither driver. Lock-free; every ISA's MSI
/// dispatcher calls this one function, whichever PCI NICs the image holds.
#[inline]
pub fn pci_msi_irq(token: u32) -> bool {
    #[cfg(feature = "e1000e")]
    if crate::e1000e::msi_irq(token) {
        return true;
    }
    #[cfg(feature = "igc")]
    if crate::igc::msi_irq(token) {
        return true;
    }
    let _ = token;
    false
}

/// Whether a PCI NIC of the Intel drivers (e1000e, igc) came up: the PCI
/// bring-up stage binds them, so this is read after it.
#[inline]
pub fn pci_nic_ready() -> bool {
    e1000e_ready() || igc_ready()
}

/// Whether the receive path is interrupt-driven: every NIC of the table
/// raises an interrupt that wakes the poller (virtio-net over MSI or its
/// MMIO line, the Synopsys MAC over its line, the Intel NIC over MSI), so the
/// poller need not run on a timer. One polled NIC (the Cadence board
/// Ethernet, or any of the others without a route) makes the poller run on
/// its timer. `false` with no NIC.
pub fn irq_driven() -> bool {
    let mut any = false;
    for nic in 0..MAX_NICS {
        let irq = match backend(nic) {
            BACKEND_NONE => continue,
            BACKEND_VIRTIO => azos_drv_virtio::virtio::net::irq_driven(),
            #[cfg(feature = "vf2")]
            BACKEND_DWMAC => crate::dwmac::board::irq_driven(),
            #[cfg(feature = "e1000e")]
            BACKEND_E1000E => crate::e1000e::irq_driven(),
            #[cfg(feature = "igc")]
            BACKEND_IGC => crate::igc::irq_driven(),
            _ => false,
        };
        if !irq {
            return false;
        }
        any = true;
    }
    any
}

/// Receive interrupts taken so far, whichever NIC took them.
pub fn rx_irq_count() -> u32 {
    #[cfg(feature = "e1000e")]
    let intel = crate::e1000e::rx_irq_count();
    #[cfg(not(feature = "e1000e"))]
    let intel = 0;
    #[cfg(feature = "igc")]
    let igc = crate::igc::rx_irq_count();
    #[cfg(not(feature = "igc"))]
    let igc = 0;
    azos_drv_virtio::virtio::net::rx_irq_count().wrapping_add(intel).wrapping_add(igc)
}

/// Whether a NIC's receive interrupt is an MSI (rather than a wired line).
pub fn msi_armed() -> bool {
    #[cfg(feature = "e1000e")]
    if crate::e1000e::irq_driven() {
        return true;
    }
    #[cfg(feature = "igc")]
    if crate::igc::irq_driven() {
        return true;
    }
    azos_drv_virtio::virtio::net::msi_armed()
}

/// The virtio-net queue counters (frames, doorbells issued and skipped,
/// drops, interrupts) when virtio-net is one of the NICs.
pub fn virtio_queue_stats() -> Option<azos_drv_virtio::virtio::net::NetQueueStats> {
    (0..MAX_NICS)
        .any(|nic| backend(nic) == BACKEND_VIRTIO)
        .then(azos_drv_virtio::virtio::net::queue_stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Discriminates.** Board Ethernet is NIC 0 when both backends read
    /// ready — the priority the old `if eth_is_ready() {...} else {...}`
    /// chain encoded — and virtio-net is no longer shadowed: it is NIC 1.
    /// Flip the order in `pick`, or drop the second push, and this fails.
    #[test]
    fn both_ready_makes_two_nics_with_eth_first() {
        assert_eq!(pick(true, false, false, false, true, false), [BACKEND_ETH, BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
    }

    /// **Discriminates.** VirtIO is the QEMU fallback: with no board
    /// Ethernet, it must still be NIC 0. A `pick` that only ever returns
    /// `BACKEND_ETH` (a stub that ignores its second argument) fails this.
    #[test]
    fn virtio_alone_is_nic_zero() {
        assert_eq!(pick(false, false, false, false, true, false), [BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
    }

    /// **Discriminates.** Board Ethernet alone is NIC 0 with nothing after it.
    #[test]
    fn eth_alone_is_nic_zero() {
        assert_eq!(pick(true, false, false, false, false, false), [BACKEND_ETH, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
    }

    /// **Discriminates.** The VisionFive 2: the Synopsys MAC is NIC 0 and
    /// virtio-net is not shadowed behind it. Drop the `dwmac_ready` push in
    /// `pick`, or put it after virtio, and this fails.
    #[test]
    fn dwmac_is_board_ethernet_and_virtio_follows() {
        assert_eq!(pick(false, true, false, false, true, false), [BACKEND_DWMAC, BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(false, true, false, false, false, false), [BACKEND_DWMAC, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
    }

    /// **Discriminates.** Neither ready must not silently default to a
    /// backend that does not exist.
    #[test]
    fn neither_ready_selects_none() {
        assert_eq!(pick(false, false, false, false, false, false), [BACKEND_NONE; MAX_NICS]);
    }

    /// **Discriminates.** The Intel NIC is NIC 0 on a PC (alone), and ahead
    /// of virtio-net when both are present (a physical NIC is the primary
    /// interface, the virtual one the extra); with board Ethernet it is
    /// NIC 1. A `pick` that leaves it out, or puts virtio first, fails.
    #[test]
    fn e1000e_is_a_physical_nic_ahead_of_virtio() {
        assert_eq!(pick(false, false, true, false, false, false), [BACKEND_E1000E, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(false, false, true, false, true, false), [BACKEND_E1000E, BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(true, false, true, false, true, false), [BACKEND_ETH, BACKEND_E1000E, BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
    }

    /// **Discriminates.** The I225/I226 NIC is NIC 0 on a PC (alone), ahead of
    /// virtio-net, and behind an e1000e when a machine has both Intel NICs
    /// (the order of `pick`); with board Ethernet it is NIC 1. A `pick` that
    /// leaves it out, or puts it after virtio, fails.
    #[test]
    fn igc_is_a_physical_nic_after_e1000e_and_ahead_of_virtio() {
        assert_eq!(pick(false, false, false, true, false, false), [BACKEND_IGC, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(false, false, false, true, true, false), [BACKEND_IGC, BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(false, false, true, true, true, false), [BACKEND_E1000E, BACKEND_IGC, BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(true, false, true, true, true, false), [BACKEND_ETH, BACKEND_E1000E, BACKEND_IGC, BACKEND_VIRTIO, BACKEND_NONE, BACKEND_NONE]);
    }

    /// **Discriminates.** A NIC number past the table, or one `select` left
    /// empty, is "no NIC": sends are refused and receives are empty, not a
    /// panic on an out-of-range index.
    #[test]
    fn an_unnumbered_nic_is_refused_not_a_panic() {
        assert_eq!(send(MAX_NICS, &[0u8; 60]), Err(NetError::NotReady));
        assert_eq!(recv(MAX_NICS + 7, &mut [0u8; 8]), Ok(0));
        assert_eq!(mac(MAX_NICS), [0u8; 6]);
    }

    /// **Discriminates.** A USB NIC is numbered after the others (a physical
    /// NIC stays the primary interface, and a hot-plugged one never moves a
    /// number), and alone it is NIC 0. A `pick` that leaves it out or puts it
    /// first fails.
    #[test]
    fn usb_follows_the_nics_probed_at_boot() {
        assert_eq!(pick(false, false, false, false, false, true), [BACKEND_USB, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(false, false, false, false, true, true), [BACKEND_VIRTIO, BACKEND_USB, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(true, false, true, false, true, true), [BACKEND_ETH, BACKEND_E1000E, BACKEND_VIRTIO, BACKEND_USB, BACKEND_NONE, BACKEND_NONE]);
        assert_eq!(pick(true, true, true, true, true, true).iter().filter(|b| **b != BACKEND_NONE).count(), 6, "the table holds every backend at once");
    }

    use core::sync::atomic::AtomicUsize;

    /// A NIC that counts what is asked of it.
    struct Probe {
        sent: AtomicUsize,
        batches: AtomicUsize,
    }

    impl NetDevice for Probe {
        fn send(&self, frame: &[u8]) -> Result<usize, NetError> {
            self.sent.fetch_add(1, Ordering::SeqCst);
            Ok(frame.len())
        }
        fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
            buf[..3].copy_from_slice(&[7, 8, 9]);
            Ok(3)
        }
        fn mac(&self) -> [u8; 6] {
            [2, 0, 0, 0, 0, 9]
        }
        fn is_ready(&self) -> bool {
            true
        }
        fn tx_batch_begin(&self) {
            self.batches.fetch_add(1, Ordering::SeqCst);
        }
        fn tx_batch_end(&self) {
            self.batches.fetch_add(10, Ordering::SeqCst);
        }
    }

    /// **Discriminates.** A registered USB NIC takes the first free number,
    /// every call addressed to that number reaches it, a second registration
    /// is refused, and once it is unregistered the number names nothing. Drop
    /// the `BACKEND_USB` arm of any dispatch function, or leave the table
    /// entry behind in `unregister_usb`, and this fails. (One test touches the
    /// shared table, so the suite cannot race on it.)
    #[test]
    fn a_registered_usb_nic_is_reached_by_its_number_until_it_is_gone() {
        static PROBE: Probe = Probe { sent: AtomicUsize::new(0), batches: AtomicUsize::new(0) };
        let before = count();
        let nic = register_usb(&PROBE).expect("a free number");
        assert_eq!(nic, before, "the first free number: nothing already numbered moves");
        assert!(register_usb(&PROBE).is_none(), "one USB NIC at a time");
        assert_eq!(count(), before + 1);
        assert_eq!(send(nic, &[0u8; 60]), Ok(60));
        assert_eq!(PROBE.sent.load(Ordering::SeqCst), 1);
        let mut buf = [0u8; 8];
        assert_eq!(recv(nic, &mut buf), Ok(3));
        assert_eq!(&buf[..3], &[7, 8, 9]);
        let mut got = 0;
        assert_eq!(recv_batch(nic, 4, &mut |f| got += f.len()), 4, "the default loop: one frame per recv");
        assert_eq!(got, 12);
        assert_eq!(mac(nic), [2, 0, 0, 0, 0, 9]);
        tx_batch_begin();
        tx_batch_end();
        assert_eq!(PROBE.batches.load(Ordering::SeqCst), 11);
        assert!(!irq_driven(), "a polled NIC makes the poller run on its timer");
        unregister_usb();
        assert_eq!(count(), before);
        assert_eq!(send(nic, &[0u8; 60]), Err(NetError::NotReady));
        assert_eq!(recv(nic, &mut buf), Ok(0));
        assert_eq!(mac(nic), [0u8; 6]);
        // And it can come back.
        assert_eq!(register_usb(&PROBE), Some(nic));
        unregister_usb();
    }
}
