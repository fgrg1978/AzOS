// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera stream task: sealed camera frames over the brain link.

use crate::*;

/// Largest camera payload: header plus JPEG, inside one sealed packet.
const CAMERA_PAYLOAD_MAX: usize =
    BRAIN_TX_PKT_MAX - azos_behavior::brain_protocol::FRAME_OVERHEAD;

/// Largest JPEG one camera packet carries: what a USB camera's driver is
/// told a Motion-JPEG frame may be at most (`uvc::Want::max_jpeg`).
#[cfg(feature = "usb-uvc")]
pub(crate) const CAMERA_JPEG_MAX: usize =
    CAMERA_PAYLOAD_MAX - azos_behavior::brain_protocol::CAMERA_HDR_SIZE;

/// Frames `camera_packet` could not send because the JPEG is bigger than a
/// packet. The ring's slot is bigger than a packet, so a frame that fits the
/// one need not fit the other; this is where that shows.
static CAMERA_OVERSIZE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Frames dropped for not fitting a camera packet, for a status line.
pub(crate) fn camera_oversize() -> u32 {
    CAMERA_OVERSIZE.load(core::sync::atomic::Ordering::Relaxed)
}

/// Scratch for one camera packet: the payload being captured into and the
/// framed packet. .bss for the same reason as `BrainTx`; each sending task
/// owns one.
struct CameraPkt {
    payload: [u8; CAMERA_PAYLOAD_MAX],
    pkt: [u8; BRAIN_TX_PKT_MAX],
}

impl CameraPkt {
    const fn new() -> Self {
        CameraPkt { payload: [0u8; CAMERA_PAYLOAD_MAX], pkt: [0u8; BRAIN_TX_PKT_MAX] }
    }
}

/// The brain link's next camera frame, framed as a `PKT_CAMERA` packet in
/// `cam.pkt`: the newest frame of the camera frame ring this consumer has
/// not taken (wave 15, B2: captured and encoded once by the capture task,
/// capped at `JPEG_CAP_W`×`JPEG_CAP_H`). Returns the packet's length, 0 when
/// there is no new frame or it does not fit the packet; never waits for a
/// capture. The raw GRAY8 frame has no packet: at 320×240 it exceeds both
/// `BRAIN_TX_PKT_MAX` and the brain-protocol length field.
fn camera_packet(cam: &mut CameraPkt) -> usize {
    use azos_behavior::brain_protocol::{
        build_packet, encode_camera_header, CAMERA_FMT_JPEG, CAMERA_HDR_SIZE, FRAME_OVERHEAD,
        PKT_CAMERA,
    };
    let room = &mut cam.payload[CAMERA_HDR_SIZE..];
    // The size the header states is the JPEG's own: a USB camera's frames are
    // not the CSI path's capture size.
    let mut size = None;
    let jpeg_len = camera_with_frame(|jpeg, _acq| {
        if jpeg.len() > room.len() {
            // Counted, and said once: the brain would otherwise just see no
            // camera.
            if CAMERA_OVERSIZE.fetch_add(1, core::sync::atomic::Ordering::Relaxed) == 0 {
                crate::kprintln!(
                    "[CAM] a {} B JPEG does not fit a camera packet ({} B): frames of this size are dropped",
                    jpeg.len(), room.len());
            }
            return 0;
        }
        room[..jpeg.len()].copy_from_slice(jpeg);
        size = azos_cam_ring::jpeg_size(jpeg);
        jpeg.len()
    })
    .unwrap_or(0);
    if jpeg_len == 0 {
        return 0;
    }
    let (w, h) = size.unwrap_or_else(|| {
        let (w, h) = azos_drv_sensor::csi::csi_resolution();
        (
            (w as usize).min(azos_drv_sensor::csi::JPEG_CAP_W) as u16,
            (h as usize).min(azos_drv_sensor::csi::JPEG_CAP_H) as u16,
        )
    });
    let mut hdr = [0u8; CAMERA_HDR_SIZE];
    encode_camera_header(&mut hdr, w, h, CAMERA_FMT_JPEG);
    cam.payload[..CAMERA_HDR_SIZE].copy_from_slice(&hdr);
    let payload_len = CAMERA_HDR_SIZE + jpeg_len;
    build_packet(
        PKT_CAMERA, &cam.payload[..payload_len], &mut cam.pkt[..payload_len + FRAME_OVERHEAD],
    )
}

/// Set once `camera-tx` is created: it then owns the ring's link cursor,
/// and the behavior task's inline path never touches it.
pub(crate) static CAMERA_TX_TASK: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// The behavior task's inline sender attaches the ring's link cursor while
/// its link can carry camera frames, and detaches it when the link ends
/// (`brain_tx_end`). A no-op when `camera-tx` owns the cursor.
pub(crate) fn camera_inline_consumer(on: bool) {
    if CAMERA_TX_TASK.load(Ordering::Acquire) {
        return;
    }
    if on {
        camera_consumer_attach();
    } else {
        camera_consumer_detach();
    }
}

/// One camera frame on the control connection's established Noise link,
/// when no camera connection is configured: `camera_packet` through
/// `enqueue_framed` on the telemetry lane, sealed as one message into the
/// `brain-tx` queue. Nothing is captured
/// unless the queue has room for the largest frame above the control
/// reserve (wave 15, B1). Returns the wire bytes queued, 0 when there was no
/// frame or no room.
pub(crate) fn send_camera_sealed(
    link: &mut azos_behavior::encrypt_link::Link,
) -> usize {
    use azos_behavior::brain_tx::Lane;
    static mut CAM: CameraPkt = CameraPkt::new();
    if !brain_tx_has_room(Lane::Telemetry, CAMERA_WIRE_MAX) {
        return 0;
    }
    // SAFETY: only the behavior task calls this function.
    let cam: &mut CameraPkt = unsafe { &mut *core::ptr::addr_of_mut!(CAM) };
    let pkt_len = camera_packet(cam);
    if pkt_len == 0 {
        return 0;
    }
    enqueue_framed(Lane::Telemetry, &cam.pkt[..pkt_len], link)
}

/// C1: camera frames on a brain connection of their own, to
/// `behavior_camera_port` on the brain host. When to dial, send and close is
/// `azos_behavior::camera_tx` (host-tested); this task gives that policy
/// the socket, the clock and the capture.
///
/// Created below the behavior task's priority on its hart, so a slow camera
/// socket, a capture or the X25519 handshake never delays a sensor send or an
/// e-stop read. It never reads its socket: after the handshake the brain
/// writes nothing on this connection and ends it by closing.
pub(crate) fn camera_tx_task(_: usize) {
    use azos_behavior::camera_tx::{self, CameraTx, Inputs, Socket, Step};
    use azos_drv_sys::timebase::{now as get_time, TIMER_FREQ};
    static mut TX: BrainTx = BrainTx::new();
    static mut CAM: CameraPkt = CameraPkt::new();
    // SAFETY: only this task references these statics.
    let tx: &mut BrainTx = unsafe { &mut *core::ptr::addr_of_mut!(TX) };
    let cam: &mut CameraPkt = unsafe { &mut *core::ptr::addr_of_mut!(CAM) };
    let ticks_per_ms = TIMER_FREQ / 1000;
    let mut policy = CameraTx::new();
    let mut fd: Option<azos_net::tcp::TcpHandle> = None;
    let mut link: Option<azos_behavior::encrypt_link::Link> = None;
    let mut rekey_deadline: u64 = 0;
    // Ephemeral keys derive from the clock, the cycle count and a salt: a salt
    // domain apart from the brain-tx task's (1 << 62).
    let mut salt: u64 = 1 << 63;
    kprintln!("[CAM-TX] camera connection task up (port {})",
              azos_config::BEHAVIOR_CAMERA_PORT.load(Ordering::Relaxed));
    loop {
        let now_ms = get_time() / ticks_per_ms;
        let port = azos_config::BEHAVIOR_CAMERA_PORT.load(Ordering::Relaxed);
        let inputs = Inputs {
            now_ms,
            enabled: azos_behavior::remote_is_enabled() && port != 0 && port <= 0xFFFF
                && azos_behavior::encrypt_link::link_key_installed(),
            control: camera_tx::control_session(),
        };
        let socket = Socket {
            established: fd.is_some_and(|h| h.state() == azos_net::tcp::TcpState::Established),
            carry_empty: tx.carry.is_empty(),
            stalled: tx.carry.is_stalled(),
        };
        match policy.step(&inputs, &socket) {
            Step::Wait { until_ms } => {
                azos_sched::task_block(azos_sched::WaitReason::Timer(
                    until_ms.saturating_mul(ticks_per_ms),
                ));
            }
            Step::Dial { generation } => match {
                // Attach before the dial: the capture task has a frame by
                // the time the handshake is done.
                camera_consumer_attach();
                camera_dial(port as u16, &mut salt)
            } {
                Some((f, l)) => {
                    fd = Some(f);
                    link = Some(l);
                    tx.carry.reset();
                    rekey_deadline = get_time() + BRAIN_LINK_REKEY_SECS * TIMER_FREQ;
                    policy.dialed(generation, now_ms);
                    kprintln!("[CAM-TX] connected fd={} (control session {})", f.slot(), generation);
                }
                None => {
                    camera_consumer_detach();
                    policy.dial_failed(get_time() / ticks_per_ms)
                }
            },
            Step::Frame => {
                let sealed = match (link.as_mut(), fd) {
                    (Some(l), Some(fd)) => {
                        // Wall-clock rekey, as on the control connection; the
                        // link counts messages and bytes itself.
                        if get_time() >= rekey_deadline {
                            l.request_rekey();
                            rekey_deadline = get_time() + BRAIN_LINK_REKEY_SECS * TIMER_FREQ;
                        }
                        camera_send_frame(fd, l, tx, cam)
                    }
                    _ => false,
                };
                policy.frame_done(now_ms, sealed);
            }
            Step::Drain => {
                if let Some(fd) = fd {
                    tx_drain(fd, &mut tx.carry, send_yielding);
                }
                azos_sched::task_block(azos_sched::WaitReason::Timer(
                    get_time() + TIMER_FREQ / 100,
                ));
            }
            Step::Close(why) => {
                // A stale handle (the slot freed by a RST and re-issued
                // since) closes nothing.
                if let Some(fd) = fd {
                    fd.close();
                }
                kprintln!("[CAM-TX] closed ({:?}) after {} frames", why, policy.frames());
                let (produced, refused, overwritten, encodes) = camera_ring_stats();
                kprintln!("[CAM] ring: {} frames captured, {} JPEG encodes, {} refused, {} passed over (newest-frame reader), {} too big for a packet",
                          produced, encodes, refused, overwritten, camera_oversize());
                fd = None;
                link = None;
                tx.carry.reset();
                camera_consumer_detach();
                policy.closed(get_time() / ticks_per_ms);
            }
        }
    }
}

/// Dial the camera connection and run its Noise handshake. Returns the
/// socket and the session, or `None` with the socket closed.
fn camera_dial(
    port: u16,
    salt: &mut u64,
) -> Option<(azos_net::tcp::TcpHandle, azos_behavior::encrypt_link::Link)> {
    use azos_drv_sys::timebase::{now as get_time, TIMER_FREQ};
    use azos_net::tcp;
    let psk = azos_behavior::encrypt_link::link_key_copy()?;
    // Local port 0: the stack's ephemeral allocator picks one no live or
    // TIME-WAIT connection holds.
    let Some(fd) = tcp::TcpHandle::connect_with_yield(
        azos_behavior::remote_server_ip(), port, 0, azos_sched::task_yield,
    ) else {
        kprintln!("[CAM-TX] connect failed rc=-1");
        return None;
    };
    // A TCP handshake is a wait: sleep-poll at 10 ms, as the control dial does.
    let deadline = get_time() + TIMER_FREQ * 2;
    while get_time() < deadline
        && fd.state() != tcp::TcpState::Established
    {
        azos_sched::task_block(azos_sched::WaitReason::Timer(
            get_time() + TIMER_FREQ / 100,
        ));
    }
    if fd.state() != tcp::TcpState::Established {
        kprintln!("[CAM-TX] connect stalled");
        fd.close();
        return None;
    }
    *salt = salt.wrapping_add(1);
    match brain_handshake(fd, psk, get_time() ^ *salt) {
        Some(l) => Some((fd, l)),
        None => {
            azos_drv_sys::kwarn!("[CAM-TX] encrypted-link handshake failed — closing");
            fd.close();
            None
        }
    }
}

/// One frame on the camera connection: `camera_packet`, sealed into this
/// task's own carry. Returns whether a frame was sealed; none is taken from
/// the ring while the previous message is still owed to the socket (the
/// capture task keeps capturing meanwhile).
fn camera_send_frame(
    fd: azos_net::tcp::TcpHandle,
    l: &mut azos_behavior::encrypt_link::Link,
    tx: &mut BrainTx,
    cam: &mut CameraPkt,
) -> bool {
    tx_drain(fd, &mut tx.carry, send_yielding);
    if !tx.carry.is_empty() {
        return false;
    }
    let pkt_len = camera_packet(cam);
    if pkt_len == 0 {
        return false;
    }
    seal_framed(fd, &cam.pkt[..pkt_len], l, tx, send_yielding).1
}
