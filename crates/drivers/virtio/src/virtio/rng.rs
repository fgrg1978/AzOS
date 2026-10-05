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
        VirtioDev, Virtq, VIRTIO_DEV_RNG,
        probe, init as virtio_init, virtq_init, virtq_submit, virtq_poll_with_len,
        virtq_free_desc, mmio_read, mmio_write, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_DRIVER_OK,
    };
    use azos_sync::SpinLock;

    // VirtIO-MMIO transport window, as in net.rs and blk.rs — sourced from
    // `virtio::mod`'s ISA-selected `VIRTIO_MMIO_*` rather than a local
    // literal (was `0x1000_1000` / `0x1000` / `8` here only).
    use super::super::VIRTIO_MMIO_BASE;
    use super::super::VIRTIO_MMIO_STRIDE;
    use super::super::VIRTIO_MMIO_COUNT as VIRTIO_MMIO_SLOTS;

    /// Staging buffer size; longer requests take several round trips.
    const BUF_BYTES: usize = 64;

    /// Budget for one `read_seed` call. Same reasoning as `BLK_TIMEOUT_US`
    /// in blk.rs: a wall-clock deadline bounds a dead device on any clock
    /// rate, where a spin count would not. QEMU's backend answers in well
    /// under a millisecond.
    pub(super) const TIMEOUT_US: u64 = 500_000;

    struct RngState {
        dev:   VirtioDev,
        vq:    Virtq,
        /// Driver-owned DMA target. `static` storage, so a completion that
        /// lands after a timeout writes here and nowhere else.
        buf:   [u8; BUF_BYTES],
        ready: bool,
        dead:  bool,
    }

    // SAFETY: the raw pointers inside are only used under `RNG`'s lock.
    unsafe impl Send for RngState {}

    static RNG: SpinLock<RngState> = SpinLock::new(RngState {
        dev:   VirtioDev::zeroed(),
        vq:    Virtq::zeroed(),
        buf:   [0u8; BUF_BYTES],
        ready: false,
        dead:  false,
    });

    pub(super) fn read_seed(out: &mut [u8]) -> SeedRead {
        let mut guard = RNG.lock();
        let st = &mut *guard;
        if st.dead {
            return SeedRead::Failed("device latched dead by an earlier failure");
        }

        if !st.ready {
            let mut found = None;
            for i in 0..VIRTIO_MMIO_SLOTS {
                let mut dev = VirtioDev::zeroed();
                let base = VIRTIO_MMIO_BASE + i * VIRTIO_MMIO_STRIDE;
                if unsafe { probe(base, &mut dev) }.is_err() { continue; }
                if dev.device_id == VIRTIO_DEV_RNG {
                    found = Some(dev);
                    break;
                }
            }
            let Some(mut dev) = found else { return SeedRead::NotPresent; };

            if unsafe { virtio_init(&mut dev) }.is_err() {
                st.dead = true;
                return SeedRead::Failed("device did not accept FEATURES_OK");
            }
            // A device that probes but offers no request queue cannot be read:
            // that is a failure of a present device, not an absent one.
            if unsafe { virtq_init(&mut dev, 0, &mut st.vq) }.is_err() {
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
            let addr = crate::virtio::dma_addr_of(st.buf.as_ptr());
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
                    out[filled..filled + n].copy_from_slice(&st.buf[..n]);
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
        for b in st.buf.iter_mut() { *b = 0; }
        SeedRead::Read(filled)
    }
}
