// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera pipeline (wave 15, B2): one capture task captures and
//! JPEG-encodes each frame once into a frame ring
//! (`azos_cam_ring::FanoutRing`); its one consumer is the brain link's
//! sender, the `camera-tx` task (`behavior_camera_port` set) or else the
//! behavior task's inline path. The sender takes the newest frame it has not
//! taken; it never waits for a capture.
//!
//! With a USB camera (Kconfig `USB_UVC`) the producer is the video class
//! driver, which writes the camera's own frames into the same ring from the
//! `usb` task (`azos_cam_ring::FrameSink`); the capture task then stays idle.
//! A camera that sends raw YUY2 is converted to the JPEG the link carries when
//! the sender reads the frame (luma only, [`yuyv_to_jpeg`]).
//!
//! The capture task never waits on the consumer: under the default
//! `CAMERA_RING_OVERWRITE_OLDEST` a slow TCP sender only loses frames it
//! would have skipped anyway. It captures only while the sender is attached,
//! every `CAMERA_TX_CAPTURE_PERIOD_MS`.

use crate::kprintln;
use azos_cam_ring::{FanoutRing, Policy};
use azos_drv_sensor::csi::{self, JPEG_MAX_SIZE};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The ring's one consumer: the brain link's sender.
const LINK: usize = 0;

const POLICY: Policy = if azos_limits::CAMERA_RING_BACKPRESSURE {
    Policy::Backpressure
} else {
    Policy::OverwriteOldest
};

/// Bytes of a slot: a JPEG, and with a USB camera also a raw YUY2 frame of the
/// JPEG path's capture size.
#[cfg(feature = "usb-uvc")]
const SLOT_BYTES: usize = if JPEG_MAX_SIZE > 2 * csi::JPEG_CAP_W * csi::JPEG_CAP_H {
    JPEG_MAX_SIZE
} else {
    2 * csi::JPEG_CAP_W * csi::JPEG_CAP_H
};
#[cfg(not(feature = "usb-uvc"))]
const SLOT_BYTES: usize = JPEG_MAX_SIZE;

pub(crate) type CamRing = FanoutRing<{ azos_limits::CAMERA_RING_SLOTS as usize }, SLOT_BYTES, 1>;

/// Kconfig `CAMERA_RING_SLOTS` x one JPEG each (a raw frame with `USB_UVC`), .bss.
pub(crate) static CAM_RING: CamRing = CamRing::new(POLICY);

/// The capture task's tid (0 until it runs): an attach wakes it from an
/// idle block.
static CAPTURE_TID: AtomicU32 = AtomicU32::new(0);

pub(crate) fn camera_consumer_attach() {
    let was = CAM_RING.any_attached();
    CAM_RING.attach(LINK);
    // A USB camera starts streaming when somebody reads.
    #[cfg(feature = "usb-uvc")]
    crate::boot::usb::uvc_kick();
    let tid = CAPTURE_TID.load(Ordering::Acquire);
    if !was && tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(
            tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    }
}

pub(crate) fn camera_consumer_detach() {
    CAM_RING.detach(LINK);
}

/// The producer's one step: capture and encode a frame into the ring.
/// `false`: refused (`CAMERA_RING_BACKPRESSURE`) or no frame (camera off,
/// or its scratch buffer busy).
pub(crate) fn camera_capture_once() -> bool {
    // The ring has one source at a time: a USB camera's frames, not a test
    // pattern next to them.
    #[cfg(feature = "usb-uvc")]
    if crate::boot::usb::uvc_is_source() {
        return false;
    }
    if !csi::csi_is_ready() || !csi::csi_is_powered() {
        return false;
    }
    let Some(slot) = CAM_RING.claim() else { return false };
    let (n, acq) = csi::csi_capture_jpeg_stamped(&mut slot[..]);
    if n == 0 {
        CAM_RING.abort();
        return false;
    }
    CAM_RING.commit(n, acq);
    true
}

/// The sender's next frame: `f` runs on the JPEG bytes and the frame's
/// acquisition stamp (timebase ticks) while the frame is pinned. The sender
/// takes the newest frame it has not taken (a lagging sender skips to it).
/// `None`: nothing new; never waits.
pub(crate) fn camera_with_frame<R>(f: impl FnOnce(&[u8], u64) -> R) -> Option<R> {
    if canary!("camera-encode-per-consumer") {
        return own_encode(f);
    }
    let frame = CAM_RING.acquire_latest(LINK)?;
    #[cfg(feature = "usb-uvc")]
    if frame.info().format == azos_cam_ring::FrameFormat::Yuyv {
        return yuyv_to_jpeg(frame.bytes(), frame.info(), frame.stamp(), f);
    }
    Some(f(frame.bytes(), frame.stamp()))
}

/// A raw YUY2 frame of a USB camera as the JPEG the link carries: its luma,
/// decimated to the JPEG path's capture size, through the same grayscale
/// encoder. `None` when the scratch is busy (the other reader) or the frame
/// does not add up.
#[cfg(feature = "usb-uvc")]
fn yuyv_to_jpeg<R>(yuyv: &[u8], info: azos_cam_ring::FrameInfo, stamp: u64, f: impl FnOnce(&[u8], u64) -> R) -> Option<R> {
    /// The luma plane and the JPEG built from it, behind a sleeping lock
    /// (the encode is long): a task stack is far too small for either.
    static SCRATCH: azos_sync::kmutex::Mutex<([u8; csi::JPEG_CAP_W * csi::JPEG_CAP_H], [u8; JPEG_MAX_SIZE])> =
        azos_sync::kmutex::Mutex::new(([0; csi::JPEG_CAP_W * csi::JPEG_CAP_H], [0; JPEG_MAX_SIZE]));
    let mut g = SCRATCH.try_lock()?;
    let (luma, jpeg) = &mut *g;
    let (w, h) = azos_cam_ring::yuyv_luma(yuyv, info.width as usize, info.height as usize, luma, csi::JPEG_CAP_W, csi::JPEG_CAP_H)?;
    let n = csi::encode_gray_jpeg(&luma[..w * h], w, h, jpeg);
    (n != 0).then(|| f(&jpeg[..n], stamp))
}

/// Runtime canary `camera-encode-per-consumer`: the consumer captures and
/// encodes a frame of its own, as both did before B2.
#[cold]
fn own_encode<R>(f: impl FnOnce(&[u8], u64) -> R) -> Option<R> {
    static BUSY: AtomicBool = AtomicBool::new(false);
    static mut SCRATCH: [u8; JPEG_MAX_SIZE] = [0; JPEG_MAX_SIZE];
    if BUSY.swap(true, Ordering::Acquire) {
        return None;
    }
    // SAFETY: BUSY gives one consumer at a time the buffer.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(SCRATCH) };
    let (n, acq) = csi::csi_capture_jpeg_stamped(buf);
    let r = (n != 0).then(|| f(&buf[..n], acq));
    BUSY.store(false, Ordering::Release);
    r
}

/// Boot: start the capture task. It idles until the sender attaches.
pub(crate) fn camera_capture_init() {
    azos_sched::task_create("cam-capture", camera_capture_task, 0, azos_sched::DEFAULT_PRIORITY);
}

/// The producer: while the sender is attached, one capture every
/// `CAMERA_TX_CAPTURE_PERIOD_MS`; otherwise blocked until an attach wakes it.
fn camera_capture_task(_: usize) {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    CAPTURE_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    kprintln!("[CAM] capture task up: ring of {} x {} B, {}",
              CamRing::capacity(), CamRing::slot_size(),
              match POLICY { Policy::OverwriteOldest => "overwrite-oldest", Policy::Backpressure => "backpressure" });
    loop {
        if CAM_RING.any_attached() {
            camera_capture_once();
            let end = now() + azos_limits::CAMERA_TX_CAPTURE_PERIOD_MS as u64 * (TIMER_FREQ / 1000);
            while now() < end {
                azos_sched::task_block(azos_sched::WaitReason::Timer(end));
            }
        } else {
            // No consumer: no wake-up until the sender attaches
            // (`camera_consumer_attach` wakes this).
            while !CAM_RING.any_attached() {
                azos_sched::task_block(azos_sched::WaitReason::Timer(u64::MAX));
            }
        }
    }
}

/// `(produced, refused, overwritten, JPEG encodes)`, for a status line.
pub(crate) fn camera_ring_stats() -> (u64, u64, u64, u32) {
    (CAM_RING.produced(), CAM_RING.refused(), CAM_RING.overwritten(), csi::csi_jpeg_encodes())
}

// B2's property: the JPEG is encoded once per frame. The test drives the
// pipeline's own functions (the producer step and the link read `camera_packet`
// makes) for four frames and compares the encode counter with the ring's.
// Runtime canary `camera-encode-per-consumer` (the consumer encodes a frame of
// its own, as both did before B2): two encodes per frame, `not ok`.
#[cfg(feature = "ktest")]
azos_ktest::ktest! {
    fn camera_one_encode_per_frame() {
        const FRAMES: u32 = 4;
        if !csi::csi_is_ready() {
            csi::csi_init(csi::DEFAULT_WIDTH, csi::DEFAULT_HEIGHT, csi::PixFmt::Gray8);
        }
        if !csi::csi_is_powered() {
            csi::csi_power_on();
        }
        camera_consumer_attach();
        let (e0, p0) = (csi::csi_jpeg_encodes(), CAM_RING.produced());
        let (mut link, mut captured) = (0u32, 0u32);
        for _ in 0..FRAMES {
            captured += camera_capture_once() as u32;
            link += camera_with_frame(|jpeg, _| jpeg.len() > 2 && jpeg[..2] == [0xFF, 0xD8])
                .unwrap_or(false) as u32;
        }
        camera_consumer_detach();
        let encodes = csi::csi_jpeg_encodes().wrapping_sub(e0);
        let frames = CAM_RING.produced() - p0;
        kprintln!("# camera: {} frames, {} encodes, link took {}", frames, encodes, link);
        if captured != FRAMES || frames != FRAMES as u64 {
            Err("the producer did not capture every frame")
        } else if link != FRAMES {
            Err("the consumer missed a frame")
        } else if encodes as u64 != frames {
            Err("more than one JPEG encode per frame")
        } else {
            Ok(())
        }
    }
}
