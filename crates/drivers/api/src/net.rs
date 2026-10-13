// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The network device class: what every NIC backend implements.

/// Typed error from a [`NetDevice`] operation. Small and `Copy`, one word,
/// no payload — the same shape `azos_drv_api::DriverError` uses for
/// the ring-3 invocation path, deliberately, per the module doc of
/// `azos_drv_net::net_device`.
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

/// One network interface. Both methods that touch the wire are a single
/// non-blocking attempt: `recv` polls once and reports `Ok(0)` for "nothing
/// queued" rather than spinning, and `send` returns `Err(QueueFull)` instead
/// of waiting for a descriptor to free up. See `azos_drv_net::net_device` for why that
/// matters beyond style — it is the same contract a ring-3 forwarder needs.
pub trait NetDevice: Send + Sync {
    /// Queue `frame` (a full Ethernet frame, header included) for
    /// transmission. On success, returns `frame.len()`.
    fn send(&self, frame: &[u8]) -> Result<usize, NetError>;
    /// Copy at most one received frame into `buf`. `Ok(0)` means no frame
    /// was queued, not an error.
    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError>;
    /// The interface's MAC address — all-zero before the backend is ready.
    fn mac(&self) -> [u8; 6];
    /// Whether the backend has completed bring-up.
    fn is_ready(&self) -> bool;
    /// Open a TX batch: until the matching [`tx_batch_end`](Self::tx_batch_end)
    /// the backend may publish frames (and re-post RX buffers) without
    /// telling the device each time. Default: nothing — every `send` is
    /// announced at once.
    fn tx_batch_begin(&self) {}
    /// Close a batch and announce everything it queued: a flush point.
    fn tx_batch_end(&self) {}
    /// Hand up to `max` received frames to `f`, in arrival order, and
    /// return how many. Each slice is valid only during its `f` call. A
    /// backend that owns its RX buffers passes them in place (virtio-net:
    /// one lock to pop the batch, none while `f` runs, one to re-post).
    /// Default: [`recv`](Self::recv) into a stack buffer, one copy per frame.
    fn recv_batch(&self, max: usize, f: &mut dyn FnMut(&[u8])) -> usize {
        let mut buf = [0u8; ETH_FRAME_MAX];
        let mut n = 0;
        while n < max {
            match self.recv(&mut buf) {
                Ok(len) if len > 0 => { f(&buf[..len.min(buf.len())]); n += 1; }
                _ => break,
            }
        }
        n
    }
}

/// Largest Ethernet frame a backend hands up (header + 1500-byte payload,
/// no FCS, no VLAN tag): the size of [`NetDevice::recv_batch`]'s default
/// buffer.
pub const ETH_FRAME_MAX: usize = 1514;
