// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The camera stream task: sealed camera frames over the brain link.

use crate::*;

/// Largest camera payload: header plus JPEG, inside one sealed packet.
const CAMERA_PAYLOAD_MAX: usize =
    BRAIN_TX_PKT_MAX - azos_behavior::brain_protocol::FRAME_OVERHEAD;

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

/// Capture one JPEG (`csi_capture_jpeg`, capped at `JPEG_CAP_W`×`JPEG_CAP_H`)
/// and frame it as a `PKT_CAMERA` packet in `cam.pkt`. Returns the packet's
/// length, 0 when there was no frame. The raw GRAY8 frame has no packet: at
/// 320×240 it exceeds both the envelope's inner limit and the brain-protocol
/// length field.
fn camera_packet(cam: &mut CameraPkt) -> usize {
    use azos_behavior::brain_protocol::{
        build_packet, encode_camera_header, CAMERA_FMT_JPEG, CAMERA_HDR_SIZE, FRAME_OVERHEAD,
        PKT_CAMERA,
    };
    let jpeg_len = azos_drv_sensor::csi::csi_capture_jpeg(&mut cam.payload[CAMERA_HDR_SIZE..]);
    if jpeg_len == 0 {
        return 0;
    }
    let (w, h) = azos_drv_sensor::csi::csi_resolution();
    let mut hdr = [0u8; CAMERA_HDR_SIZE];
    encode_camera_header(
        &mut hdr,
        (w as usize).min(azos_drv_sensor::csi::JPEG_CAP_W) as u16,
        (h as usize).min(azos_drv_sensor::csi::JPEG_CAP_H) as u16,
        CAMERA_FMT_JPEG,
    );
    cam.payload[..CAMERA_HDR_SIZE].copy_from_slice(&hdr);
    let payload_len = CAMERA_HDR_SIZE + jpeg_len;
    build_packet(
        PKT_CAMERA, &cam.payload[..payload_len], &mut cam.pkt[..payload_len + FRAME_OVERHEAD],
    )
}

/// One camera frame on the control connection's established RFC-0019 link,
/// when no camera connection is configured: `camera_packet` through
/// `send_framed` — envelope, then sealed as a multi-record message. Returns
/// bytes sent, 0 when there was no frame.
pub(crate) fn send_camera_sealed(
    fd: usize,
    link: &mut Option<azos_behavior::encrypt_link::EncryptLink>,
    salt: &mut u64,
) -> i32 {
    static mut CAM: CameraPkt = CameraPkt::new();
    if link.is_none() {
        return 0;
    }
    // A sealed message still owed to the socket goes first; while any of it
    // remains, no frame is captured and nothing is sealed.
    let drained = brain_tx_drain(fd) as i32;
    if !brain_tx_carry().is_empty() {
        return drained;
    }
    // SAFETY: only the behavior task calls this function.
    let cam: &mut CameraPkt = unsafe { &mut *core::ptr::addr_of_mut!(CAM) };
    let pkt_len = camera_packet(cam);
    if pkt_len == 0 {
        return 0;
    }
    send_framed(fd, &cam.pkt[..pkt_len], link, salt)
}

/// C1: camera frames on a brain connection of their own, to
/// `behavior_camera_port` on the brain host. When to dial, send and close is
/// `azos_behavior::camera_tx` (host-tested); this task gives that policy
/// the socket, the clock and the capture.
///
/// Created below the behavior task's priority on its hart, so a slow camera
/// socket, a capture or the X25519 handshake never delays a sensor send or an
/// e-stop read. It never reads its socket: after the handshake the brain
/// writes nothing on this connection but a REJECT, and closes after that.
/// It never re-arms `auth_envelope`'s denial announcements either; that belongs
/// to the control handshake.
pub(crate) fn camera_tx_task(_: usize) {
    use azos_behavior::camera_tx::{self, CameraTx, Inputs, LinkMode, Socket, Step};
    use azos_drv_sys::timebase::{now as get_time, TIMER_FREQ};
    static mut TX: BrainTx = BrainTx::new();
    static mut CAM: CameraPkt = CameraPkt::new();
    // SAFETY: only this task references these statics.
    let tx: &mut BrainTx = unsafe { &mut *core::ptr::addr_of_mut!(TX) };
    let cam: &mut CameraPkt = unsafe { &mut *core::ptr::addr_of_mut!(CAM) };
    let ticks_per_ms = TIMER_FREQ / 1000;
    let mut policy = CameraTx::new();
    let mut fd: i32 = -1;
    let mut link: Option<azos_behavior::encrypt_link::EncryptLink> = None;
    let mut rekey_deadline: u64 = 0;
    // Ephemeral keys and record nonces derive from the clock, the cycle count
    // and a salt: a salt domain apart from the behavior task's, which counts
    // up from 0.
    let mut salt: u64 = 1 << 63;
    let mut port_seq: u16 = ((get_time() >> 3) % 16_384) as u16;
    kprintln!("[CAM-TX] camera connection task up (port {})",
              azos_config::BEHAVIOR_CAMERA_PORT.load(Ordering::Relaxed));
    loop {
        let now_ms = get_time() / ticks_per_ms;
        let port = azos_config::BEHAVIOR_CAMERA_PORT.load(Ordering::Relaxed);
        let mode = if !azos_behavior::auth_envelope::is_authenticated() {
            LinkMode::Unkeyed
        } else if azos_config::CFG_LINK_ENCRYPT.load(Ordering::Relaxed)
            || cfg!(feature = "link-encrypt-enforced")
        {
            LinkMode::Encrypted
        } else {
            LinkMode::HmacOnly
        };
        let inputs = Inputs {
            now_ms,
            enabled: azos_behavior::remote_is_enabled() && port != 0 && port <= 0xFFFF,
            mode,
            control: camera_tx::control_session(),
        };
        let socket = Socket {
            established: fd >= 0
                && azos_net::tcp::conn_state(fd as usize)
                    == azos_net::tcp::TcpState::Established,
            carry_empty: tx.carry.is_empty(),
            stalled: tx.carry.is_stalled(),
        };
        match policy.step(&inputs, &socket) {
            Step::Wait { until_ms } => {
                azos_sched::task_block(azos_sched::WaitReason::Timer(
                    until_ms.saturating_mul(ticks_per_ms),
                ));
            }
            Step::Dial { generation } => match camera_dial(port as u16, &mut port_seq, &mut salt) {
                Some((f, l)) => {
                    fd = f;
                    link = Some(l);
                    tx.carry.reset();
                    rekey_deadline = get_time() + BRAIN_LINK_REKEY_SECS * TIMER_FREQ;
                    policy.dialed(generation, now_ms);
                    kprintln!("[CAM-TX] connected fd={} (control session {})", f, generation);
                }
                None => policy.dial_failed(get_time() / ticks_per_ms),
            },
            Step::Frame => {
                let sealed = match link.as_mut() {
                    Some(l) => {
                        // RFC-0019 wall-clock rekey, as on the control
                        // connection; the link counts records and bytes itself.
                        if get_time() >= rekey_deadline {
                            l.request_rekey();
                            rekey_deadline = get_time() + BRAIN_LINK_REKEY_SECS * TIMER_FREQ;
                        }
                        camera_send_frame(fd as usize, l, &mut salt, tx, cam)
                    }
                    None => false,
                };
                policy.frame_done(now_ms, sealed);
            }
            Step::Drain => {
                tx_drain(fd as usize, &mut tx.carry, send_yielding);
                azos_sched::task_block(azos_sched::WaitReason::Timer(
                    get_time() + TIMER_FREQ / 100,
                ));
            }
            Step::Close(why) => {
                if fd >= 0 {
                    azos_net::tcp::close(fd as usize);
                }
                kprintln!("[CAM-TX] closed ({:?}) after {} frames", why, policy.frames());
                fd = -1;
                link = None;
                tx.carry.reset();
                policy.closed(get_time() / ticks_per_ms);
            }
        }
    }
}

/// Dial the camera connection and run its RFC-0019 handshake. Returns the
/// socket and the session, or `None` with the socket closed.
fn camera_dial(
    port: u16,
    port_seq: &mut u16,
    salt: &mut u64,
) -> Option<(i32, azos_behavior::encrypt_link::EncryptLink)> {
    use azos_drv_sys::timebase::{now as get_time, TIMER_FREQ};
    use azos_net::tcp;
    let psk = azos_behavior::auth_envelope::link_key_copy()?;
    let src_port = 49_152 + *port_seq % 16_384;
    *port_seq = port_seq.wrapping_add(1);
    let fd = tcp::connect_with_yield(
        azos_behavior::remote_server_ip(), port, src_port, azos_sched::task_yield,
    );
    if fd < 0 {
        kprintln!("[CAM-TX] connect failed rc={}", fd);
        return None;
    }
    // A TCP handshake is a wait: sleep-poll at 10 ms, as the control dial does.
    let deadline = get_time() + TIMER_FREQ * 2;
    while get_time() < deadline
        && tcp::conn_state(fd as usize) != tcp::TcpState::Established
    {
        azos_sched::task_block(azos_sched::WaitReason::Timer(
            get_time() + TIMER_FREQ / 100,
        ));
    }
    if tcp::conn_state(fd as usize) != tcp::TcpState::Established {
        kprintln!("[CAM-TX] connect stalled");
        tcp::close(fd as usize);
        return None;
    }
    *salt = salt.wrapping_add(1);
    match brain_responder_handshake(fd as usize, psk, get_time() ^ *salt) {
        Some(l) => Some((fd, l)),
        None => {
            azos_drv_sys::kwarn!("[CAM-TX] RFC-0019 handshake failed — closing");
            tcp::close(fd as usize);
            None
        }
    }
}

/// One frame on the camera connection: `camera_packet`, sealed into this
/// task's own carry. Returns whether a frame was sealed; none is captured
/// while the previous message is still owed to the socket.
fn camera_send_frame(
    fd: usize,
    l: &mut azos_behavior::encrypt_link::EncryptLink,
    salt: &mut u64,
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
    seal_framed(fd, &cam.pkt[..pkt_len], l, salt, tx, send_yielding).1
}
