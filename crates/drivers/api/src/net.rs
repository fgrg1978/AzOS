// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The network device class: the queue pair every NIC backend implements.

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

/// Typed error from a [`NetQueue`] operation. Small and `Copy`, one word,
/// no payload: the bounded contract a caller of a ring-3 host needs, per
/// the module doc of `azos_drv_net::net_queue`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// No backend selected yet, or the selected one has not completed
    /// bring-up (`is_ready()` was false at the time of the call).
    NotReady,
    /// `frame` was empty or longer than the backend's fixed TX buffer.
    BadLength,
    /// The backend's TX descriptor ring had no free slot right now — a
    /// transient condition, not a device failure.
    QueueFull,
}

/// One queue pair of a NIC: a submission ring the stack posts frames to and a
/// completion ring it reaps received frames from. Every method is a single
/// non-blocking attempt. A driver publishes into its rings and rings the
/// device's doorbell only when told to; when to ring is the caller's policy
/// ([`TxDoorbell`], applied once in `azos_drv_net::net_queue`), not each
/// driver's.
pub trait NetQueue: Send + Sync {
    /// Whether the queue pair has completed bring-up.
    fn is_ready(&self) -> bool;
    /// The interface's MAC address; all-zero before the queue pair is ready.
    fn mac(&self) -> [u8; 6];
    /// Publish `frame` (a full Ethernet frame, header included) on the
    /// submission ring without announcing it. On success returns
    /// `frame.len()`. A full ring is `Err(QueueFull)`.
    fn post(&self, frame: &[u8]) -> Result<usize, NetError>;
    /// The doorbell: announce every frame posted since the last ring, and the
    /// receive buffers re-posted by [`reap_rx`](Self::reap_rx).
    fn ring(&self);
    /// Hand up to `max` received frames to `f`, in arrival order, and return
    /// how many. Each slice is valid only during its `f` call; a driver that
    /// owns its receive buffers passes them in place and re-posts them (not
    /// announced) afterwards. `f` may post.
    fn reap_rx(&self, max: usize, f: &mut dyn FnMut(&[u8])) -> usize;
    /// Reap the transmit completions and look at the ring's budget
    /// (`recovery::TxWatch`, Kconfig `NET_TX_TIMEOUT_MS`): take back the
    /// frames the device sent, and reset the device (the timeout policy) if
    /// the ring is past its budget. Returns the tick by which the ring must be
    /// looked at again while frames are outstanding (`recovery::TX_LOOK_US`
    /// from now), `None` when there are none. The network poller calls it on
    /// every pass. Default: no budget to watch.
    fn reap_tx(&self) -> Option<u64> {
        None
    }
}

/// When a queue pair's doorbell rings: one rule for every NIC.
///
/// A frame posted outside a batch is announced at once (no frame may wait for
/// a flush point that is not coming). Inside a batch ([`begin`](Self::begin)
/// .. [`end`](Self::end)) frames wait for the end, or for `bound` of them,
/// whichever comes first. A full submission ring is announced too, so the
/// device can free it. Lock-free; batches nest and may be open on several
/// harts at once, and any `end` announces everything posted so far, so a
/// frame never waits for another hart's batch.
pub struct TxDoorbell {
    depth: AtomicU16,
    pending: AtomicU16,
    every_frame: AtomicBool,
}

impl TxDoorbell {
    pub const fn new() -> Self {
        TxDoorbell { depth: AtomicU16::new(0), pending: AtomicU16::new(0), every_frame: AtomicBool::new(false) }
    }

    /// Open a batch.
    pub fn begin(&self) {
        let _ = self.depth.fetch_update(Ordering::AcqRel, Ordering::Acquire, |d| d.checked_add(1));
    }

    /// Close a batch: the doorbell rings now.
    pub fn end(&self) {
        let _ = self.depth.fetch_update(Ordering::AcqRel, Ordering::Acquire, |d| d.checked_sub(1));
        self.pending.store(0, Ordering::Release);
    }

    /// A frame was posted: `true` when the doorbell rings for it now.
    pub fn posted(&self, bound: u16) -> bool {
        let pending = self.pending.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        let ring = self.every_frame.load(Ordering::Relaxed) || self.depth.load(Ordering::Acquire) == 0 || pending >= bound;
        if ring {
            self.pending.store(0, Ordering::Release);
        }
        ring
    }

    /// The doorbell rang for another reason (a full ring, a flush point).
    pub fn rang(&self) {
        self.pending.store(0, Ordering::Release);
    }

    /// Is a batch open?
    pub fn batching(&self) -> bool {
        self.depth.load(Ordering::Acquire) != 0 && !self.every_frame.load(Ordering::Relaxed)
    }

    /// Canary `net-kick-per-frame`: every frame rings, batches ignored.
    pub fn set_every_frame(&self, on: bool) {
        self.every_frame.store(on, Ordering::Relaxed);
    }
}

/// Largest Ethernet frame a backend hands up (header + 1500-byte payload,
/// no FCS, no VLAN tag).
pub const ETH_FRAME_MAX: usize = 1514;
