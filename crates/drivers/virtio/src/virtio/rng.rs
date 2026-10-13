// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
/// VirtIO entropy source (device id 4) — polled read for seeding the kernel pool.
///
/// One request queue (0). The driver posts a buffer the device may write
/// (`VIRTQ_DESC_F_WRITE`), notifies, and polls the used ring for the number of
/// bytes the device wrote. No interrupt is used, as with the net and block
/// drivers.
///
/// Only QEMU has this device, and only QEMU maps the VirtIO MMIO window
/// (`kernel/src/main.rs`, the `not(any(vf2, k1))` block of MMIO mappings), so
/// on the boards `read_seed` reports `NotPresent` without touching that
/// address range.

use super::{Virtq, VIRTQ_DESC_F_WRITE, virtq_alloc_desc};

/// Outcome of [`read_seed`]. Three states on purpose: "no device" and "device
/// present but unusable" must stay distinguishable up to the boot line, where
/// only the second one is a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedRead {
    /// The whole buffer was filled from the device; the value is its length.
    Read(usize),
    /// No entropy device on this platform or at any VirtIO MMIO slot.
    NotPresent,
    /// A device answered the probe but did not deliver the bytes. The driver
    /// latches itself dead: a later call returns `Failed` without retrying.
    Failed(&'static str),
}

/// Arm descriptor for one read of `len` bytes into the buffer at `addr`.
///
/// The descriptor is a single device-writable buffer with no chain. Returns
/// `None` when the queue has no free descriptor.
///
/// # Safety
/// `vq` must be an initialised queue, and `addr` must name `len` bytes that
/// stay valid for as long as the device owns the descriptor.
pub unsafe fn arm_read(vq: &mut Virtq, addr: u64, len: u32) -> Option<usize> {
    let idx = virtq_alloc_desc(vq)?;
    let d = vq.desc.add(idx);
    (*d).addr  = addr;
    (*d).len   = len;
    (*d).flags = VIRTQ_DESC_F_WRITE;
    (*d).next  = 0;
    Some(idx)
}

/// Take the entropy device whose virtio-mmio transport is at `base` (the
/// hardware bus binding `virtio-rng` to it, `kernel/src/boot/hwbus.rs`). The
/// device is brought up by the first [`read_seed`], as before; `Err` for a
/// window that is not an entropy device or when one is taken already.
#[cfg(any(feature = "vf2", feature = "k1"))]
pub fn bind(_base: usize) -> Result<(), ()> { Err(()) }

/// See the board build's.
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub fn bind(base: usize) -> Result<(), ()> {
    device::bind(base)
}

/// Let go of the device at `base`: only before the first [`read_seed`] has
/// brought it up (a device with its queue set up and its buffer mapped is
/// not given back).
#[cfg(any(feature = "vf2", feature = "k1"))]
pub fn unbind(_base: usize) -> Result<(), ()> { Err(()) }

/// See the board build's.
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub fn unbind(base: usize) -> Result<(), ()> {
    device::unbind(base)
}

/// Fill `out` with bytes from the VirtIO entropy device.
///
/// The first call probes and initialises the device; later calls reuse it.
/// Bounded by a wall-clock budget per call (see `device::TIMEOUT_US`).
#[cfg(any(feature = "vf2", feature = "k1"))]
pub fn read_seed(out: &mut [u8]) -> SeedRead {
    let _ = out;
    SeedRead::NotPresent
}

/// Fill `out` with bytes from the VirtIO entropy device.
///
/// The first call probes and initialises the device; later calls reuse it.
/// Bounded by a wall-clock budget per call (see `device::TIMEOUT_US`).
#[cfg(not(any(feature = "vf2", feature = "k1")))]
pub fn read_seed(out: &mut [u8]) -> SeedRead {
    device::read_seed(out)
}

#[cfg(not(any(feature = "vf2", feature = "k1")))]
mod device {
    use super::{arm_read, SeedRead};
    use super::super::{
        Dma, VirtioDev, Virtq, VIRTIO_DEV_RNG,
        probe, init as virtio_init, virtq_init, virtq_submit, virtq_poll_with_len,
        virtq_free_desc, mmio_read, mmio_write, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_DRIVER_OK,
    };
    use azos_dma::Direction;
    use azos_sync::SpinLock;

    /// Staging buffer size; longer requests take several round trips.
    const BUF_BYTES: usize = 64;

    /// The staging buffer alone in its cache lines: behind a non-coherent
    /// device the CPU flushes it around each read, and a neighbouring field
    /// of the state must not share a line with what the device writes.
    #[repr(C, align(128))]
    struct Buf([u8; BUF_BYTES]);

    /// Budget for one `read_seed` call. Same reasoning as `BLK_TIMEOUT_US`
    /// in blk.rs: a wall-clock deadline bounds a dead device on any clock
    /// rate, where a spin count would not. QEMU's backend answers in well
    /// under a millisecond.
    pub(super) const TIMEOUT_US: u64 = 500_000;

    struct RngState {
        /// The transport the bus bound (0: none, and `read_seed` reports
        /// `NotPresent`).
        base:  usize,
        dev:   VirtioDev,
        vq:    Virtq,
        /// Driver-owned DMA target. `static` storage, so a completion that
        /// lands after a timeout writes here and nowhere else.
        buf:   Buf,
        /// The device's DMA domain and the bus address of `buf`.
        dma:     Dma,
        buf_bus: u64,
        ready: bool,
        dead:  bool,
    }

    // SAFETY: the raw pointers inside are only used under `RNG`'s lock.
    unsafe impl Send for RngState {}

    static RNG: SpinLock<RngState> = SpinLock::new(RngState {
        base:  0,
        dev:   VirtioDev::zeroed(),
        vq:    Virtq::zeroed(),
        buf:   Buf([0u8; BUF_BYTES]),
        dma:     Dma::fallback(),
        buf_bus: 0,
        ready: false,
        dead:  false,
    });

    /// Take the device at `base`: it must be an entropy device and the driver
    /// must not hold one.
    pub(super) fn bind(base: usize) -> Result<(), ()> {
        let mut st = RNG.lock();
        let mut dev = VirtioDev::zeroed();
        if st.base != 0 || unsafe { probe(base, &mut dev) }.is_err() || dev.device_id != VIRTIO_DEV_RNG {
            return Err(());
        }
        st.base = base;
        Ok(())
    }

    pub(super) fn unbind(base: usize) -> Result<(), ()> {
        let mut st = RNG.lock();
        if st.base != base || st.ready || st.dead {
            return Err(());
        }
        st.base = 0;
        Ok(())
    }

    pub(super) fn read_seed(out: &mut [u8]) -> SeedRead {
        let mut guard = RNG.lock();
        let st = &mut *guard;
        if st.dead {
            return SeedRead::Failed("device latched dead by an earlier failure");
        }

        if !st.ready {
            if st.base == 0 {
                return SeedRead::NotPresent;
            }
            let mut found = None;
            {
                let mut dev = VirtioDev::zeroed();
                if unsafe { probe(st.base, &mut dev) }.is_ok() && dev.device_id == VIRTIO_DEV_RNG {
                    found = Some(dev);
                }
            }
            let Some(mut dev) = found else { return SeedRead::NotPresent; };

            if unsafe { virtio_init(&mut dev) }.is_err() {
                st.dead = true;
                return SeedRead::Failed("device did not accept FEATURES_OK");
            }
            // The device's DMA domain, and the staging buffer mapped through
            // it (the device writes it).
            st.dma = Dma::mmio();
            let dma = st.dma;
            match dma.map(st.buf.0.as_ptr(), BUF_BYTES, Direction::FromDevice) {
                Ok(bus) => st.buf_bus = bus,
                Err(()) => {
                    st.dead = true;
                    return SeedRead::Failed("staging buffer not mappable");
                }
            }
            // A device that probes but offers no request queue cannot be read:
            // that is a failure of a present device, not an absent one.
            if unsafe { virtq_init(&mut dev, 0, &mut st.vq, &dma) }.is_err() || dma.enable().is_err() {
                st.dead = true;
                return SeedRead::Failed("request queue 0 could not be set up");
            }
            // The device serves requests only after DRIVER_OK.
            unsafe {
                let s = mmio_read(dev.base, VIRTIO_MMIO_STATUS);
                mmio_write(dev.base, VIRTIO_MMIO_STATUS, s | VIRTIO_STATUS_DRIVER_OK);
            }
            st.dev = dev;
            st.ready = true;
        }

        let deadline = azos_drv_sys::timebase::now()
            + TIMEOUT_US * azos_drv_irqchip::clint::TIMER_FREQ / 1_000_000;
        let mut filled = 0;
        while filled < out.len() {
            let want = (out.len() - filled).min(BUF_BYTES);
            let addr = st.buf_bus;
            // Behind a non-coherent device: nothing stale of ours in the
            // lines the device is about to write.
            unsafe { st.dma.sync_for_device(st.buf.0.as_ptr(), BUF_BYTES, Direction::FromDevice) };
            let Some(idx) = (unsafe { arm_read(&mut st.vq, addr, want as u32) }) else {
                st.dead = true;
                return SeedRead::Failed("no free descriptor");
            };
            unsafe { virtq_submit(&st.dev, 0, idx, &mut st.vq) };

            let got: Result<usize, &'static str> = loop {
                match unsafe { virtq_poll_with_len(&mut st.vq) } {
                    // `len` is device-written: cap it at what was offered.
                    Some((id, len)) if id == idx => break Ok(len.min(want)),
                    Some(_) => break Err("foreign completion id"),
                    None => {
                        if azos_drv_sys::timebase::now() >= deadline {
                            break Err("read timeout");
                        }
                    }
                }
            };
            match got {
                Ok(n) => {
                    unsafe { virtq_free_desc(&mut st.vq, idx) };
                    unsafe { st.dma.sync_for_cpu(st.buf.0.as_ptr(), BUF_BYTES, Direction::FromDevice) };
                    out[filled..filled + n].copy_from_slice(&st.buf.0[..n]);
                    filled += n;
                }
                Err(why) => {
                    // The descriptor stays with the device (VirtIO has no
                    // cancel); it points only at `buf`, and the driver is
                    // latched dead so nothing reuses either.
                    st.dead = true;
                    return SeedRead::Failed(why);
                }
            }
        }
        // The staging copy of the seed has no reason to outlive the call.
        for b in st.buf.0.iter_mut() { *b = 0; }
        SeedRead::Read(filled)
    }
}
