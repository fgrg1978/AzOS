// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Kernel-produced sensor streams (wave 11, SHMRING): the producers of
//! `azos_ipc::stream_ring`.
//!
//! * LiDAR (Kconfig `STREAM_LIDAR_RING`): the LD19 parser's revolution swap
//!   publishes the completed scan ([`lidar_scan_hook`]). Nothing feeds the
//!   parser on any board yet; under `LIDAR_SIM` (QEMU) [`lidar_sim_task`]
//!   does, with generated packets.
//! * Camera (Kconfig `STREAM_CAMERA_RING`): a consumer of the camera frame
//!   ring (`cam_capture.rs`); the capture task publishes each frame it
//!   captured while a task has the stream mapped ([`camera_stream_consume`]),
//!   every `STREAM_CAMERA_PERIOD_MS`.
//!
//! The authority model, the drop policy and the trust boundary are in
//! `crates/core/ipc/src/stream_ring.rs`'s doc; `SYS_SENSOR_READ_TYPED` stays
//! the path with every stream off.

use crate::kprintln;
use azos_ipc::stream_ring::{self, Publish, Stream};

fn ticks_to_ns(t: u64) -> u64 {
    azos_abi::time::ticks_to_ns(t, azos_drv_sys::timebase::TIMER_FREQ)
}

fn sleep_ms(ms: u64) {
    let now = azos_drv_sys::timebase::now;
    let end = now() + ms * (azos_drv_sys::timebase::TIMER_FREQ / 1000);
    while now() < end {
        azos_sched::task_block(azos_sched::WaitReason::Timer(end));
    }
}

/// Ring the consumer's doorbell when the ring says it may be asleep.
fn after_publish(r: Option<(Publish, u32, u32)>) {
    if let Some((Publish::Wake, region, offset)) = r {
        azos_syscall::vdso_notify::notify_wake_kernel(region, offset, 1);
    }
}

/// The LD19 parser's revolution hook: publish the scan just completed.
/// Runs where the byte was fed; never blocks.
fn lidar_scan_hook(front: usize, count: usize, acq_ticks: u64) {
    after_publish(stream_ring::stream_publish(Stream::Lidar, ticks_to_ns(acq_ticks), |dst, room| {
        // SAFETY: `dst` is `room` bytes of the ring's slot; `front` is the
        // buffer the swap just published (see `lidar_write_scan_raw`).
        unsafe { azos_drv_sensor::lidar::lidar_write_scan_raw(front, count, dst, room) }
    }));
}

/// Boot: create the enabled streams' regions, install the topology minter
/// for `stream.<name>` (before any task is seeded) and the producers. Prints
/// one line per enabled stream; prints nothing with every stream off.
pub(crate) fn streams_init() {
    let lidar = Stream::Lidar.enabled();
    let camera = Stream::Camera.enabled();
    if lidar || camera {
        azos_ipc::cap_seed::set_shm_stream_minter(stream_ring::stream_seed_mint);
    }
    for s in [Stream::Lidar, Stream::Camera] {
        if !s.enabled() {
            continue;
        }
        let (slots, slot_bytes) = s.geometry();
        match stream_ring::stream_region(s) {
            Some(r) => kprintln!("[STREAM] {}: ring of {} x {} B in kernel region {:#x}",
                                 s.target(), slots, slot_bytes, r),
            None => kprintln!("[STREAM] {}: FAIL no region (out of contiguous frames)", s.target()),
        }
    }
    if lidar || azos_limits::LIDAR_SIM {
        azos_drv_sensor::lidar::lidar_init();
    }
    if lidar {
        azos_drv_sensor::lidar::set_scan_hook(lidar_scan_hook);
    }
    if azos_limits::LIDAR_SIM {
        azos_sched::task_create("lidar-sim", lidar_sim_task, 0, azos_sched::DEFAULT_PRIORITY);
    }
    // The camera's one producer (wave 15, B2), for the stream and, on a
    // robot image, the brain link's sender.
    #[cfg(any(feature = "domain-robot", feature = "camera"))]
    if camera || cfg!(feature = "domain-robot") {
        azos_sched::task_create("cam-capture", crate::tasks::camera_capture_task, 0,
                                    azos_sched::DEFAULT_PRIORITY);
    }
}

/// Kconfig `LIDAR_SIM`: a full synthetic revolution (30 LD19 packets) every
/// 100 ms, through the real parser. Revolution `r` publishes when the first
/// packet of `r + 1` arrives (the parser's wrap detection).
fn lidar_sim_task(_: usize) {
    use azos_drv_sensor::lidar::{ld19_synth_packet, lidar_feed, LD19_PACKET_BYTES, SYNTH_PACKETS_PER_REV};
    let mut pkt = [0u8; LD19_PACKET_BYTES];
    let mut rev = 0u32;
    kprintln!("[LIDAR-SIM] feeding the LD19 parser: {} packets per revolution, every 100 ms",
              SYNTH_PACKETS_PER_REV);
    loop {
        for p in 0..SYNTH_PACKETS_PER_REV {
            ld19_synth_packet(rev, p, &mut pkt);
            lidar_feed(&pkt);
        }
        rev = rev.wrapping_add(1);
        sleep_ms(100);
    }
}

/// Does this image have the camera stream (Kconfig `STREAM_CAMERA_RING`)?
#[cfg(any(feature = "domain-robot", feature = "camera"))]
pub(crate) fn camera_stream_built() -> bool {
    Stream::Camera.enabled()
}

/// Does `stream.camera` have a reader now? The capture task attaches the
/// stream's cursor only then: nothing is captured for nobody.
#[cfg(any(feature = "domain-robot", feature = "camera"))]
pub(crate) fn camera_stream_wanted() -> bool {
    Stream::Camera.enabled() && stream_ring::stream_has_consumer(Stream::Camera)
}

/// The stream's read of the camera frame ring: its next frame, copied from
/// the pinned ring slot into the stream's slot under the stream's lock (the
/// one copy; the capture and the encode ran outside it), stamped at
/// acquisition. `false`: no new frame. With the stream off the frame is
/// taken and published nowhere.
#[cfg(any(feature = "domain-robot", feature = "camera"))]
pub(crate) fn camera_stream_consume() -> bool {
    use crate::tasks::{camera_with_frame, CamConsumer};
    camera_with_frame(CamConsumer::Stream, |src, acq| {
        after_publish(stream_ring::stream_publish(Stream::Camera, ticks_to_ns(acq), |dst, room| {
            let k = src.len().min(room);
            // SAFETY: `dst` is `room` bytes of the stream's slot.
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, k) };
            k
        }));
    })
    .is_some()
}
