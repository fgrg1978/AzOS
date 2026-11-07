// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera pipeline: one capture task captures and JPEG-encodes each frame
//! once into the frame class's pool (`azos_syscall::frame_host`); the brain
//! link's sender, the `camera-tx` task (`behavior_camera_port` set) or else
//! the behavior task's inline path, is one reader of it, and a ring-3 task
//! that opened the `Frame` interface is another. The sender takes the newest
//! frame it has not taken; it never waits for a capture.
//!
//! With a USB camera (Kconfig `USB_UVC`) the producer is the video class
//! driver, which writes the camera's own frames into the same pool from the
//! `usb` task (`azos_cam_ring::FrameSink`); the capture task then stays idle.
//! A camera that sends raw YUY2 is converted to the JPEG the link carries when
//! the sender reads the frame (luma only, [`yuyv_to_jpeg`]).
//!
//! The capture task never waits on a reader: under the default
//! `FRAME_POOL_OVERWRITE_OLDEST` a slow TCP sender only loses frames it
//! would have skipped anyway. It captures only while a reader is attached,
//! every `CAMERA_TX_CAPTURE_PERIOD_MS`.
//!
//! The pool's buffers are kernel-owned contiguous memory objects made when the
//! first reader attaches ([`lend_buffers`]); a frame's stamp is the vDSO clock in nanoseconds.

use crate::kprintln;
use azos_cam_ring::{NoRoom, Policy};
use azos_syscall::frame_host::{self as frames, LINK, POOL};
use azos_drv_sensor::csi::{self, JPEG_MAX_SIZE};
use azos_drv_sys::timebase::vdso_ns;
use azos_ipc::memobj::{memobj_create_kernel, MemPerms, MemSpec, MAX_MEMOBJ_PAGES};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// What a frame buffer holds: the JPEG, and with a USB camera also a raw YUY2
/// frame of the JPEG path's capture size.
const _: () = assert!(frames::BYTES >= JPEG_MAX_SIZE, "FRAME_BYTES is below a JPEG of the capture path");
#[cfg(feature = "usb-uvc")]
const _: () = assert!(frames::BYTES >= 2 * csi::JPEG_CAP_W * csi::JPEG_CAP_H, "FRAME_BYTES is below a raw frame of the USB camera");

/// Pages of one frame buffer, and how many buffers one memory object holds.
const BUFFER_PAGES: usize = frames::BYTES.div_ceil(azos_arch::PAGE_SIZE);
const _: () = assert!(BUFFER_PAGES <= MAX_MEMOBJ_PAGES, "FRAME_BYTES is more than one memory object holds");
const PER_OBJECT: usize = MAX_MEMOBJ_PAGES / BUFFER_PAGES;
/// Memory objects the pool may take from the table: a quarter of it, the rest
/// being the kernel's own regions and the tasks' objects.
const OBJECT_BUDGET: usize = if azos_mm::memobj::MAX_MEMOBJS >= 4 { azos_mm::memobj::MAX_MEMOBJS / 4 } else { 1 };

/// Lend the pool its buffers, once, when the first reader attaches
/// (`frames::set_lend`): kernel-owned contiguous memory objects, as many
/// buffers in each as fit, at most [`OBJECT_BUDGET`] objects. A pool that gets
/// fewer buffers than its readers need is refused: the objects made are given
/// back, a `cam-capture` record says so, and the camera has no readers.
fn lend_buffers() {
    static TRIED: AtomicBool = AtomicBool::new(false);
    if TRIED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut bases = [0usize; frames::SLOTS];
    let mut objects = [0u32; OBJECT_BUDGET];
    let (mut n, mut made) = (0, 0);
    while n < frames::SLOTS && made < OBJECT_BUDGET {
        let here = (frames::SLOTS - n).min(PER_OBJECT);
        let Some((obj, phys)) = memobj_create_kernel(here * BUFFER_PAGES, &MemSpec::contig(MemPerms::ReadWrite, false)) else {
            break;
        };
        objects[made] = obj;
        made += 1;
        let base = azos_mm::addr::phys_to_virt(phys) as usize;
        for k in 0..here {
            bases[n + k] = base + k * BUFFER_PAGES * azos_arch::PAGE_SIZE;
        }
        n += here;
    }
    match POOL.install(&bases[..n]) {
        Ok(used) => kprintln!("[CAM] frame pool: {} buffers of {} B, {}", used, frames::BYTES, match POOL.policy() {
            Policy::OverwriteOldest => "overwrite-oldest",
            Policy::Backpressure => "backpressure",
        }),
        Err(NoRoom) => {
            for obj in &objects[..made] {
                let _ = azos_ipc::memobj::memobj_release_ref(azos_ipc::memobj::MEMOBJ_KERNEL_OWNER, *obj);
            }
            azos_syscall::frame_host::refuse_pool(n);
            azos_drv_sys::kerr!("[CAM] no memory for the frame pool ({} of {} buffers): refused, the camera has no readers", n, frames::SLOTS);
        }
    }
}

/// The capture task's tid (0 until it runs): an attach wakes it from an
/// idle block.
static CAPTURE_TID: AtomicU32 = AtomicU32::new(0);

/// A reader attached: a USB camera starts streaming when somebody reads, and
/// the capture task, idle while nobody reads, wakes with the first reader.
fn wake_producers(first: bool) {
    #[cfg(feature = "usb-uvc")]
    crate::boot::usb::uvc_kick();
    let tid = CAPTURE_TID.load(Ordering::Acquire);
    if first && tid != 0 {
        azos_sched::scheduler::wake_task_by_tid(
            tid, &|r| matches!(r, azos_sched::WaitReason::Timer(_)));
    }
}

pub(crate) fn camera_consumer_attach() {
    frames::attach(LINK);
}

pub(crate) fn camera_consumer_detach() {
    POOL.detach(LINK);
}

/// The producer's one step: capture and encode a frame into the ring.
/// `false`: refused (`FRAME_POOL_BACKPRESSURE`) or no frame (camera off,
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
    let Some(slot) = POOL.claim() else { return false };
    let (n, acq) = csi::csi_capture_jpeg_stamped(&mut slot[..]);
    if n == 0 {
        POOL.abort();
        return false;
    }
    if canary!("frame-blank") {
        slot[..n].fill(0);
    }
    POOL.commit(n, vdso_ns(acq));
    true
}

/// The sender's next frame: `f` runs on the JPEG bytes and the frame's
/// acquisition stamp (vDSO nanoseconds) while the sender holds a reference. The sender
/// takes the newest frame it has not taken (a lagging sender skips to it).
/// `None`: nothing new; never waits.
pub(crate) fn camera_with_frame<R>(f: impl FnOnce(&[u8], u64) -> R) -> Option<R> {
    if canary!("camera-encode-per-consumer") {
        return own_encode(f);
    }
    let frame = POOL.acquire(LINK)?;
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
    frames::set_lend(lend_buffers);
    frames::set_producer_wake(wake_producers);
    azos_sched::task_create("cam-capture", camera_capture_task, 0, azos_sched::DEFAULT_PRIORITY);
}

/// The producer: while the sender is attached, one capture every
/// `CAMERA_TX_CAPTURE_PERIOD_MS`; otherwise blocked until an attach wakes it.
fn camera_capture_task(_: usize) {
    use azos_drv_sys::timebase::{now, TIMER_FREQ};
    CAPTURE_TID.store(azos_sched::current_task_tid(), Ordering::Release);
    kprintln!("[CAM] capture task up");
    loop {
        if POOL.any_attached() {
            camera_capture_once();
            let end = now() + azos_limits::CAMERA_TX_CAPTURE_PERIOD_MS as u64 * (TIMER_FREQ / 1000);
            while now() < end {
                azos_sched::task_block(azos_sched::WaitReason::Timer(end));
            }
        } else {
            // No consumer: no wake-up until the sender attaches
            // (`camera_consumer_attach` wakes this).
            while !POOL.any_attached() {
                azos_sched::task_block(azos_sched::WaitReason::Timer(u64::MAX));
            }
        }
    }
}

/// `(produced, refused, overwritten, JPEG encodes)`, for a status line.
pub(crate) fn camera_ring_stats() -> (u64, u64, u64, u32) {
    (POOL.produced(), POOL.refused(), POOL.overwritten(), csi::csi_jpeg_encodes())
}

// B2's property: the JPEG is encoded once per frame. The test drives the
// pipeline's own functions (the producer step and the link read `camera_packet`
// makes) for four frames and compares the encode counter with the pool's.
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
        let (e0, p0) = (csi::csi_jpeg_encodes(), POOL.produced());
        let (mut link, mut captured) = (0u32, 0u32);
        for _ in 0..FRAMES {
            captured += camera_capture_once() as u32;
            link += camera_with_frame(|jpeg, _| jpeg.len() > 2 && jpeg[..2] == [0xFF, 0xD8])
                .unwrap_or(false) as u32;
        }
        camera_consumer_detach();
        let held = POOL.references();
        let encodes = csi::csi_jpeg_encodes().wrapping_sub(e0);
        let produced = POOL.produced() - p0;
        kprintln!("# camera: {} frames, {} encodes, link took {}", produced, encodes, link);
        if captured != FRAMES || produced != FRAMES as u64 {
            Err("the producer did not capture every frame")
        } else if link != FRAMES {
            Err("the consumer missed a frame")
        } else if held != 0 {
            Err("a reader still holds a reference after its read")
        } else if encodes as u64 != produced {
            Err("more than one JPEG encode per frame")
        } else {
            Ok(())
        }
    }
}
