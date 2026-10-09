// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera pipeline (wave 15, B2): one capture task captures and
//! JPEG-encodes each frame once into a fan-out ring
//! (`azos_cam_ring::FanoutRing`); every consumer reads it with a cursor of
//! its own.
//!
//! * [`CamConsumer::Link`]: the brain link's sender, the `camera-tx` task
//!   (`behavior_camera_port` set) or else the behavior task's inline path.
//!   Takes the newest frame it has not taken; never waits for a capture.
//! * [`CamConsumer::Stream`]: the shared-memory stream (`stream.camera`,
//!   Kconfig `STREAM_CAMERA_RING`), fed by the capture task itself right
//!   after each capture, so the stream needs no task of its own.
//!
//! The capture task never waits on a consumer: under the default
//! `CAMERA_RING_OVERWRITE_OLDEST` a slow TCP sender only loses frames it
//! would have skipped anyway. It captures only while a consumer is attached,
//! at the shortest period an attached consumer asks for
//! (`STREAM_CAMERA_PERIOD_MS`, `CAMERA_TX_CAPTURE_PERIOD_MS`).

use crate::kprintln;
use azos_cam_ring::{FanoutRing, Policy};
use azos_drv_sensor::csi::{self, JPEG_MAX_SIZE};
use core::sync::atomic::{AtomicBool, Ordering};

/// A reader of the camera frame ring.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CamConsumer {
    Link = 0,
    Stream = 1,
}
const CONSUMERS: usize = 2;

const POLICY: Policy = if azos_limits::CAMERA_RING_BACKPRESSURE {
    Policy::Backpressure
} else {
    Policy::OverwriteOldest
};

type CamRing = FanoutRing<{ azos_limits::CAMERA_RING_SLOTS as usize }, JPEG_MAX_SIZE, CONSUMERS>;

/// Kconfig `CAMERA_RING_SLOTS` x one JPEG each, .bss.
static CAM_RING: CamRing = CamRing::new(POLICY);

pub(crate) fn camera_consumer_attach(c: CamConsumer) {
    CAM_RING.attach(c as usize);
}

pub(crate) fn camera_consumer_detach(c: CamConsumer) {
    CAM_RING.detach(c as usize);
}

/// The producer's one step: capture and encode a frame into the ring.
/// `false`: refused (`CAMERA_RING_BACKPRESSURE`) or no frame (camera off,
/// or its scratch buffer busy).
pub(crate) fn camera_capture_once() -> bool {
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

/// Consumer `c`'s next frame: `f` runs on the JPEG bytes and the frame's
/// acquisition stamp (timebase ticks) while the frame is pinned. The link
/// takes the newest frame it has not taken (a lagging sender skips to it);
/// the stream takes them in order. `None`: nothing new; never waits.
pub(crate) fn camera_with_frame<R>(c: CamConsumer, f: impl FnOnce(&[u8], u64) -> R) -> Option<R> {
    if canary!("camera-encode-per-consumer") {
        return own_encode(f);
    }
    let frame = match c {
        CamConsumer::Link => CAM_RING.acquire_latest(c as usize),
        CamConsumer::Stream => CAM_RING.acquire_next(c as usize),
    }?;
    Some(f(frame.bytes(), frame.stamp()))
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

/// The capture period: the shortest any attached consumer asks for; with
/// none attached, how often to look again.
fn capture_period_ms() -> u64 {
    let stream = azos_limits::STREAM_CAMERA_PERIOD_MS as u64;
    let link = azos_limits::CAMERA_TX_CAPTURE_PERIOD_MS as u64;
    match (CAM_RING.is_attached(CamConsumer::Stream as usize), CAM_RING.is_attached(CamConsumer::Link as usize)) {
        (true, true) => stream.min(link),
        (true, false) => stream,
        (false, true) => link,
        (false, false) => stream.min(link),
    }
}

/// The producer. Created by `streams_init` when the image has a consumer.
pub(crate) fn camera_capture_task(_: usize) {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    kprintln!("[CAM] capture task up: ring of {} x {} B, {}",
              CamRing::capacity(), CamRing::slot_size(),
              match POLICY { Policy::OverwriteOldest => "overwrite-oldest", Policy::Backpressure => "backpressure" });
    loop {
        let stream = crate::tasks::camera_stream_wanted();
        if stream {
            camera_consumer_attach(CamConsumer::Stream);
        } else {
            camera_consumer_detach(CamConsumer::Stream);
        }
        if CAM_RING.any_attached() && camera_capture_once() && stream {
            crate::tasks::camera_stream_consume();
        }
        let end = now() + capture_period_ms() * (TIMER_FREQ / 1000);
        while now() < end {
            azos_sched::task_block(azos_sched::WaitReason::Timer(end));
        }
    }
}

/// `(produced, refused, overwritten, JPEG encodes)`, for a status line.
pub(crate) fn camera_ring_stats() -> (u64, u64, u64, u32) {
    (CAM_RING.produced(), CAM_RING.refused(), CAM_RING.overwritten(), csi::csi_jpeg_encodes())
}

// B2's property: with both consumers on, the JPEG is encoded once per frame.
// The test drives the pipeline's own functions (the producer step, the link
// read `camera_packet` makes, the stream's publish) for four frames and
// compares the encode counter with the ring's. Runtime canary
// `camera-encode-per-consumer` (each consumer encodes its own frame again,
// the shape before B2): three encodes per frame, `not ok`.
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
        camera_consumer_attach(CamConsumer::Link);
        camera_consumer_attach(CamConsumer::Stream);
        let (e0, p0) = (csi::csi_jpeg_encodes(), CAM_RING.produced());
        let (mut link, mut stream, mut captured) = (0u32, 0u32, 0u32);
        for _ in 0..FRAMES {
            captured += camera_capture_once() as u32;
            link += camera_with_frame(CamConsumer::Link, |jpeg, _| jpeg.len() > 2 && jpeg[..2] == [0xFF, 0xD8])
                .unwrap_or(false) as u32;
            stream += crate::tasks::camera_stream_consume() as u32;
        }
        camera_consumer_detach(CamConsumer::Link);
        camera_consumer_detach(CamConsumer::Stream);
        let encodes = csi::csi_jpeg_encodes().wrapping_sub(e0);
        let frames = CAM_RING.produced() - p0;
        kprintln!("# camera: {} frames, {} encodes, link took {}, stream took {}", frames, encodes, link, stream);
        if captured != FRAMES || frames != FRAMES as u64 {
            Err("the producer did not capture every frame")
        } else if link != FRAMES || stream != FRAMES {
            Err("a consumer missed a frame")
        } else if encodes as u64 != frames {
            Err("more than one JPEG encode per frame with both consumers on")
        } else {
            Ok(())
        }
    }
}
