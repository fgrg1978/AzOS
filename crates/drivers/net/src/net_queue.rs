// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The table of the NICs that came up, and the one place the stack reaches
//! them: each NIC is a queue pair ([`NetQueue`]: post, ring, reap), numbered
//! in the order [`select`] found them (board Ethernet first, then virtio-net),
//! and `crates/net/stack` addresses it by that number.
//!
//! # What the table decides, and the driver does not
//!
//! A driver publishes frames into its submission ring ([`NetQueue::post`])
//! and rings the device's doorbell on request ([`NetQueue::ring`]). When it
//! rings is [`submit`]'s: one [`TxDoorbell`] per NIC applies the same rule to
//! every backend (at once outside a batch, at the end of one or at
//! `NET_TX_BATCH_MAX` frames inside it, and when the ring is full), so the
//! batching that four drivers each kept a copy of is written once.
//! [`batch_begin`] and [`batch_end`] bracket a flush point; [`flush`] is one
//! without a batch (a frame that must leave now).
//!
//! # Why an enum-selected static, not `&'static dyn NetQueue`
//!
//! This workspace builds with `lto = false`, so a call through `dyn
//! NetQueue` cannot be devirtualised across the `crates/net/stack` ↔
//! `crates/drivers/net` boundary — every call on the network hot path would
//! keep a real vtable indirection forever. The enum dispatch below
//! ([`on_nic!`]) compiles to a compare-and-branch on a byte the caller
//! already has to load, and every method of the zero-sized queue types is
//! `#[inline]`, so the chain from the stack's `net_raw_send` to the backend's
//! `post` is eligible to inline into one function body despite the crate
//! boundary. One backend of each kind exists in the tree (the virtio-net
//! rings are statics), so the table holds at most [`MAX_NICS`] NICs.
//!
//! # A NIC that appears after boot (USB)
//!
//! A USB network function (CDC-ECM/NCM, `azos_usb::class::cdc`) comes and
//! goes with its cable, so it is not probed: its driver [`register_usb`]s a
//! `&'static dyn NetQueue` when the function is ready and [`unregister_usb`]s
//! it when the device is gone. Registration takes the first free number of
//! the table (after the NICs [`select`] numbered, so no number moves) and
//! returns it. One USB NIC at a time. The dispatch is through the registered
//! trait object, not an enum arm of its own: a USB NIC is bound by the bus,
//! not by the call, and the extra indirection is the smaller part of a
//! frame's cost on it. It is polled (no interrupt reaches this table), so
//! [`irq_driven`] is false while it is registered.
//!
//! # A ring-3 host
//!
//! [`NetQueue`] takes `&self` on every method, borrows fixed-size byte
//! slices, returns a small `Copy` error enum and never blocks — `reap_rx`
//! polls once and reports 0 for "nothing queued" — which is the bounded
//! contract a caller of a ring-3 host needs; a ring-3 NIC driver would be a
//! producer of the same queue pair after the DMA-and-IRQ object lands.

use azos_drv_api::net::{NetError, NetQueue, TxDoorbell};
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
static USB_NIC: SpinLock<Option<&'static dyn NetQueue>> = SpinLock::new(None);

/// The registered USB NIC, copied out so the call runs without the lock.
#[inline]
fn usb_nic() -> Option<&'static dyn NetQueue> {
    *USB_NIC.lock()
}

/// Register the NIC of a USB network function once it is ready; the number
/// the stack addresses it by. `None` when a USB NIC is registered already or
/// the table is full.
pub fn register_usb(dev: &'static dyn NetQueue) -> Option<usize> {
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
    crate::dwmac::board::DwmacNetQueue.is_ready()
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
    { crate::e1000e::E1000eNetQueue.is_ready() }
    #[cfg(not(feature = "e1000e"))]
    { false }
}

/// The Intel I225/I226 NIC is a backend only in an image that compiles its
/// driver (Kconfig `DRV_IGC`).
#[inline]
fn igc_ready() -> bool {
    #[cfg(feature = "igc")]
    { crate::igc::IgcNetQueue.is_ready() }
    #[cfg(not(feature = "igc"))]
    { false }
}

/// Number the NICs that are ready. Call once, at `net_init()` — after this,
/// the functions below read the cached table instead of re-probing either
/// device. Returns how many NICs there are.
pub fn select() -> usize {
    let picked = pick(
        crate::eth::EthNetQueue.is_ready(),
        dwmac_ready(),
        e1000e_ready(),
        igc_ready(),
        azos_drv_virtio::virtio::net::VirtioNetQueue.is_ready(),
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

/// Run `$e` with `$d` bound to the queue pair of NIC `$nic`; `$none` when
/// there is no such NIC.
macro_rules! on_nic {
    ($nic:expr, $d:ident => $e:expr, else $none:expr) => {
        match backend($nic) {
            BACKEND_ETH => { let $d = &crate::eth::EthNetQueue; $e }
            #[cfg(feature = "vf2")]
            BACKEND_DWMAC => { let $d = &crate::dwmac::board::DwmacNetQueue; $e }
            #[cfg(feature = "e1000e")]
            BACKEND_E1000E => { let $d = &crate::e1000e::E1000eNetQueue; $e }
            #[cfg(feature = "igc")]
            BACKEND_IGC => { let $d = &crate::igc::IgcNetQueue; $e }
            BACKEND_VIRTIO => { let $d = &azos_drv_virtio::virtio::net::VirtioNetQueue; $e }
            BACKEND_USB => match usb_nic() { Some($d) => $e, None => $none },
            _ => $none,
        }
    };
}

/// Frames posted inside a batch before the doorbell rings anyway (Kconfig
/// `NET_TX_BATCH_MAX`).
const TX_BATCH_MAX: u16 = azos_limits::NET_TX_BATCH_MAX as u16;

/// The doorbell policy of each NIC, by number.
static DOORBELL: [TxDoorbell; MAX_NICS] = [const { TxDoorbell::new() }; MAX_NICS];

/// Post `frame` on NIC `nic` and ring its doorbell if the rule says so.
#[inline]
pub fn submit(nic: usize, frame: &[u8]) -> Result<usize, NetError> {
    let r = on_nic!(nic, d => d.post(frame), else Err(NetError::NotReady));
    if let Some(db) = DOORBELL.get(nic) {
        match r {
            Ok(_) if db.posted(TX_BATCH_MAX) => ring(nic),
            Err(NetError::QueueFull) => {
                db.rang();
                ring(nic);
            }
            _ => {}
        }
    }
    r
}

/// Ring NIC `nic`'s doorbell now.
#[inline]
fn ring(nic: usize) {
    on_nic!(nic, d => d.ring(), else ())
}

/// Announce everything posted on NIC `nic` so far: a flush point for a frame
/// that must not wait for its batch.
#[inline]
pub fn flush(nic: usize) {
    if let Some(db) = DOORBELL.get(nic) {
        db.rang();
    }
    ring(nic);
}

/// Open a batch on NIC `nic`: frames posted until [`batch_end`] share one
/// doorbell (at most `NET_TX_BATCH_MAX` frames wait). Never hold one across a
/// block or a yield. Nests.
#[inline]
pub fn batch_begin(nic: usize) {
    if let Some(db) = DOORBELL.get(nic) {
        db.begin();
    }
}

/// Close a batch of NIC `nic` and announce what it posted.
#[inline]
pub fn batch_end(nic: usize) {
    if let Some(db) = DOORBELL.get(nic) {
        db.end();
        ring(nic);
    }
}

/// Hand up to `max` received frames of NIC `nic` to `f` (`NetQueue::reap_rx`):
/// by reference on virtio-net, one copy each on board Ethernet. 0 when there
/// is no such NIC or nothing is queued. Outside a batch the buffers it
/// re-posted are announced before it returns.
#[inline]
pub fn reap_rx(nic: usize, max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
    let n = on_nic!(nic, d => d.reap_rx(max, f), else 0);
    if n != 0 && DOORBELL.get(nic).is_some_and(|db| !db.batching()) {
        ring(nic);
    }
    n
}

/// MAC of NIC `nic`; all-zero if there is no such NIC.
#[inline]
pub fn mac(nic: usize) -> [u8; 6] {
    on_nic!(nic, d => d.mac(), else [0u8; 6])
}

/// Canary `net-kick-per-frame`: every NIC rings per frame, batches ignored
/// (and virtio-net ignores its device's NO_NOTIFY).
pub fn set_kick_every_frame(on: bool) {
    for db in DOORBELL.iter() {
        db.set_every_frame(on);
    }
    azos_drv_virtio::virtio::net::set_kick_every_frame(on);
}

/// How often, in ticks, a transmit ring that holds frames is looked at
/// ([`reap_tx`], `recovery::TX_LOOK_US`); the stack's poller keeps to it.
pub fn tx_look_ticks() -> u64 {
    azos_drv_api::recovery::TX_LOOK_US * azos_drv_sys::timebase::TIMER_FREQ / 1_000_000
}

/// Reap every NIC's transmit completions (`NetQueue::reap_tx`): take back what
/// the devices sent, reset a NIC whose ring is past its budget, and return the
/// earliest tick by which a ring that still holds frames must be looked at
/// again (`None`: no ring holds any).
pub fn reap_tx() -> Option<u64> {
    let mut due: Option<u64> = None;
    for nic in 0..MAX_NICS {
        let d = on_nic!(nic, d => d.reap_tx(), else None);
        due = match (due, d) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }
    due
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
        assert_eq!(submit(MAX_NICS, &[0u8; 60]), Err(NetError::NotReady));
        assert_eq!(reap_rx(MAX_NICS + 7, 4, &mut |_| {}), 0);
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
        posted: AtomicUsize,
        rings: AtomicUsize,
    }

    impl NetQueue for Probe {
        fn is_ready(&self) -> bool {
            true
        }
        fn mac(&self) -> [u8; 6] {
            [2, 0, 0, 0, 0, 9]
        }
        fn post(&self, frame: &[u8]) -> Result<usize, NetError> {
            self.posted.fetch_add(1, Ordering::SeqCst);
            Ok(frame.len())
        }
        fn ring(&self) {
            self.rings.fetch_add(1, Ordering::SeqCst);
        }
        fn reap_rx(&self, max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
            for _ in 0..max {
                f(&[7, 8, 9]);
            }
            max
        }
    }

    /// **Discriminates.** A registered USB NIC takes the first free number,
    /// every call addressed to that number reaches it, a second registration
    /// is refused, and once it is unregistered the number names nothing. A
    /// frame outside a batch rings at once; inside one the frames share the
    /// doorbell rung at its end. Drop the `BACKEND_USB` arm of `on_nic!`, or
    /// leave the table entry behind in `unregister_usb`, and this fails.
    /// (One test touches the shared table, so the suite cannot race on it.)
    #[test]
    fn a_registered_usb_nic_is_reached_by_its_number_until_it_is_gone() {
        static PROBE: Probe = Probe { posted: AtomicUsize::new(0), rings: AtomicUsize::new(0) };
        let before = count();
        let nic = register_usb(&PROBE).expect("a free number");
        assert_eq!(nic, before, "the first free number: nothing already numbered moves");
        assert!(register_usb(&PROBE).is_none(), "one USB NIC at a time");
        assert_eq!(count(), before + 1);
        assert_eq!(submit(nic, &[0u8; 60]), Ok(60));
        assert_eq!((PROBE.posted.load(Ordering::SeqCst), PROBE.rings.load(Ordering::SeqCst)), (1, 1), "outside a batch: ring at once");
        let mut got = 0;
        assert_eq!(reap_rx(nic, 4, &mut |f| got += f.len()), 4);
        assert_eq!(got, 12);
        assert_eq!(PROBE.rings.load(Ordering::SeqCst), 2, "outside a batch the re-posted buffers are announced");
        assert_eq!(mac(nic), [2, 0, 0, 0, 0, 9]);
        batch_begin(nic);
        for _ in 0..3 {
            submit(nic, &[0u8; 60]).unwrap();
        }
        reap_rx(nic, 1, &mut |_| {});
        assert_eq!((PROBE.posted.load(Ordering::SeqCst), PROBE.rings.load(Ordering::SeqCst)), (4, 2), "inside a batch nothing rings");
        batch_end(nic);
        assert_eq!(PROBE.rings.load(Ordering::SeqCst), 3, "one doorbell for the batch");
        assert!(!irq_driven(), "a polled NIC makes the poller run on its timer");
        unregister_usb();
        assert_eq!(count(), before);
        assert_eq!(submit(nic, &[0u8; 60]), Err(NetError::NotReady));
        assert_eq!(reap_rx(nic, 4, &mut |_| {}), 0);
        assert_eq!(mac(nic), [0u8; 6]);
        // And it can come back.
        assert_eq!(register_usb(&PROBE), Some(nic));
        unregister_usb();
    }
}
