// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The behavior task (the control loop that talks to the brain).

use crate::*;

/// K-C5: may the UART bridge carry brain-protocol frames right now?
///
/// The bridge is a full brain-protocol plane — PKT_SENSOR/PKT_CAMERA out,
/// PKT_ACTUATOR (motion commands, including the emergency flag) in — with no
/// envelope and no AEAD in either direction. Under `link-encrypt-enforced`
/// it is therefore down BY POLICY, both directions: accepting unauthenticated
/// actuator frames over a wire would void the whole per-packet gate.
///
/// In a default build `link_policy_denial()` const-folds to `None` and this
/// is a constant `true`. The refusal is announced once, mirroring
/// `auth_envelope::announce_denial`'s rationale: a silently dead bridge is
/// indistinguishable from a cabling fault on the console.
fn bridge_policy_permits() -> bool {
    match azos_behavior::auth_envelope::link_policy_denial() {
        None => true,
        Some(why) => {
            use core::sync::atomic::AtomicBool;
            static SAID: AtomicBool = AtomicBool::new(false);
            if !SAID.swap(true, Ordering::Relaxed) {
                azos_drv_sys::kerr!(
                    "[SECCHAN] FATAL: UART bridge refused — {} — \
                     link-encrypt-enforced is compiled in and the bridge \
                     carries neither envelope nor AEAD. The bridge is DOWN \
                     BY POLICY, both directions.",
                    why.as_str());
            }
            false
        }
    }
}

pub(crate) fn behavior_task(_: usize) {
    use azos_behavior::*;

    kprintln!("[BEHAVIOR] ========================================");
    kprintln!("[BEHAVIOR]  Phase G1: Subsumption Behavior Engine");
    kprintln!("[BEHAVIOR]  Layers: L0=estop L1=avoid L2=vla L3=explore");
    kprintln!("[BEHAVIOR] ========================================");

    // DHCP auto-discovery (if dhcp=1 in CONFIG.INI)
    if azos_config::CFG_NET_DHCP.load(Ordering::Relaxed) != 0 {
        kprintln!("[BEHAVIOR] Running DHCP auto-discovery...");
        let ok = azos_net::dhcp::dhcp_start(net_wait_sleep);
        if !ok {
            azos_drv_sys::kwarn!("[BEHAVIOR] DHCP failed — using static IP config");
        }
    }

    // TCP connection state (local to this task)
    let mut tcp_fd: i32 = -1;
    let mut tcp_connected = false;
    // Local port of the next brain dial, from the dynamic range (RFC 6335).
    // A fixed port names the same 4-tuple on every redial, and `tcp::connect`
    // refuses a 4-tuple whose previous connection is still closing; a fresh
    // port reconnects at once and leaves that connection to finish. Seeded
    // from the clock so a reboot does not redial a 4-tuple the brain may still
    // hold open.
    let mut brain_port_seq: u16 = (azos_drv_sys::timebase::now() % 16_384) as u16;
    // RFC-0019 encrypted link: established per TCP connection (fresh ephemeral
    // keys each time → forward secrecy ON A SEEDED BOOT ONLY — see
    // `derive_ephemeral_priv`'s doc; an unseeded, non-enforced build still
    // establishes a link with no such property), `None` when plaintext/HMAC-only.
    // `enc_salt` feeds the ephemeral-key + nonce derivation so successive
    // connections/packets don't reuse entropy.
    let mut link: Option<azos_behavior::encrypt_link::EncryptLink> = None;
    let mut enc_salt: u64 = 0;
    // RFC-0019: the wall-clock deadline for the established link's next rekey.
    // Session ids seen this boot are `BRAIN_SESSION_ID_CACHE`, shared with the
    // camera connection.
    let mut link_rekey_deadline: u64 = 0;

    // Camera frame sending: every CAMERA_SEND_INTERVAL behavior cycles (~2 Hz at 10 Hz loop)
    const CAMERA_SEND_INTERVAL: u32 = 5;
    let mut camera_cycle: u32 = 0;

    // RFC-0027 I1: auto-emit `wcet_report()` + `jitter_report()` every N
    // behavior loop iterations so the bench harness collects per-function
    // WCET data without depending on shell-injection of `wcet\r\n` (which
    // can be dropped by SMP TCG UART IRQ routing).  behavior_task is the
    // most reliably-running task during bench (visible via [BRAIN] log
    // entries) — sys-wdt was the original target but it never reaches its
    // loop body under QEMU TCG.
    //
    // The behavior loop runs at ~10 Hz, so 300 iterations ≈ 30 s — short
    // enough that a 40 s steady scenario sees at least one auto-report.
    // Gated `cfg(feature = "qemu")` for the same reason as the bound
    // zeroing in `crates/drivers/sys/src/wcet.rs` — on real hardware the shell
    // works reliably and the operator can dump on demand.
    // RFC-0027 I1: auto-report uses a real-mtime deadline rather than an
    // iteration count.  Empirical observation 2026-05-29 bench: under QEMU
    // TCG the behavior loop's `task_block(WaitReason::Timer)` is sleeping
    // ~13 s instead of the intended 100 ms, so an iteration counter would
    // either fire too rarely (threshold=300 → never in a 40 s bench) or
    // not fire at all.  An mtime-based deadline is robust to whatever the
    // actual iteration rate turns out to be: when sleep is fixed, the
    // ~10 s cadence keeps the report rate sane; when sleep is broken, it
    // still fires on every iteration that exceeds the deadline.
    #[cfg(feature = "qemu")]
    const WCET_AUTOREPORT_INTERVAL_SEC: u64 = 10;
    #[cfg(feature = "qemu")]
    let mut wcet_autoreport_deadline: u64 = azos_drv_sys::timebase::now();
    // 2026-05-30: also fire `azos_bench::run_all` ONCE shortly after
    // boot to emit a synthetic [BENCH-RES] baseline.  Shell-injected
    // `bench` command via the harness FIFO has proven unreliable end-to-
    // end (auto-report fires but shell-input does not reach the parser
    // under QEMU TCG SMP), so we trigger from a task that demonstrably
    // runs.  100 iterations per microbench keeps the run under 1 s and
    // avoids dominating bench scenario time.
    #[cfg(feature = "qemu")]
    let mut bench_run_all_done: bool = false;
    #[cfg(feature = "qemu")]
    const BENCH_RUN_ALL_ITERS: u64 = 100;

    // Per-step timing (`[BSTEP]`, printed with the WCET auto-report).
    let mut step_stats = behavior_step::StepStats::new();
    let step_period = azos_drv_sys::timebase::TIMER_FREQ / 10;

    // The MLP runs in the ring-3 ML service, which this task starts and then
    // asks once per cycle (`behavior_ml`, `azos_behavior::ml_link`).
    #[cfg(not(feature = "no-ml"))]
    let mut ml_link = behavior_ml::MlLink::new();
    #[cfg(not(feature = "no-ml"))]
    if ML_ENABLED.load(Ordering::Acquire) {
        behavior_ml::launch();
    }

    loop {
        let step_t0 = azos_drv_sys::timebase::now();
        #[cfg(not(feature = "no-ml"))]
        let mut ml_ticks: u64 = 0;
        // ── 0. Retire any in-flight payload pulse ────────────────────────
        // The camera shutter is a deadline rather than a busy-wait — see
        // `payload::payload_cam_trigger` for why a packet handler must not
        // spin for 50 ms. This is the pass that lowers the line; it is a
        // single relaxed load when nothing is in flight.
        azos_behavior::payload::payload_tick();

        // ── 1. Read sensor state from SENSOR_BUS ─────────────────────────
        // Sensor tasks (imu_task, odom_task, sensor_slow_task) write to
        // the bus at their own rates. We just take a snapshot here.
        let now = azos_drv_sys::timebase::now();
        let mut state = SensorState::new();
        azos_behavior::sensor_bus::SENSOR_BUS.snapshot(&mut state);
        state.timestamp = now;

        // Camera capture (still inline — camera task is future AQ3)
        #[cfg(not(feature = "no-ml"))]
        {
            let t_cap = azos_drv_sys::timebase::now();
            let tick = azos_safety_core::watchdog::ticks();
            let pattern = (tick % 3) as u8;
            // The frame only feeds `cam_pixels` (camera-tx sends it). Its
            // features were computed here every cycle and discarded; the MLP
            // takes the range readings, not the frame.
            let frame = azos_camera::cam_capture(pattern);
            state.cam_pixels[..32].copy_from_slice(&frame.pixels);
            state.cam_w = 8;
            state.cam_h = 4;
            state.cam_valid = true;
            ml_ticks += azos_drv_sys::timebase::now().wrapping_sub(t_cap);
        }

        // ── 2. Brain Protocol: TCP send/recv ─────────────────────────────
        if azos_behavior::remote_is_enabled() {
            // Network polling is handled by the dedicated net-poll task (Phase U1).

            // Connect if not yet connected
            if !tcp_connected {
                let ip   = azos_behavior::remote_server_ip();
                let port = azos_behavior::remote_server_port();
                if port > 0 {
                    // connect_with_yield resolves ARP first, then sends SYN —
                    // avoids the "first SYN dropped silently due to ARP miss
                    // → close-and-reconnect loop" pattern that previously cost
                    // ~1.5-2 s on every initial connection under SLIRP/QEMU.
                    let src_port = 49_152 + brain_port_seq % 16_384;
                    brain_port_seq = brain_port_seq.wrapping_add(1);
                    // The ARP wait sleeps between polls (`net_wait_sleep`):
                    // `resolve_peer_mac` bounds it by CONNECT_ARP_BUDGET_US.
                    tcp_fd = azos_net::tcp::connect_with_yield(
                        ip, port, src_port, net_wait_sleep,
                    );
                    if tcp_fd >= 0 {
                        // `tcp::connect` only sends SYN; it returns immediately
                        // with state = SynSent.  We MUST wait for the handshake
                        // to advance to Established before sending the first
                        // StatusPacket — otherwise `send_data` returns -1, the
                        // end-of-iteration `conn_state` check marks the link as
                        // dead, the next iteration calls `connect` again and
                        // we burn TCP_MAX_CONNS slots in a loop without ever
                        // pushing a single byte to the brain.  Yield-poll with
                        // a hard cap so a peer that refuses to ACK doesn't
                        // hang the behavior task forever.
                        //
                        // Cap by WALL-CLOCK time, not yield count.  yield is
                        // cheap (just gives CPU to the next ready task), so a
                        // pure yield count caps quickly without giving the
                        // SYN-ACK time to physically arrive via the virtio-net
                        // interrupt.
                        //
                        // Empirical observation 2026-05-29 bench: ~33% of
                        // handshake attempts under QEMU TCG SMP-4 stall in
                        // SynSent.  Trace: SLIRP NAT under TCG thread-starves
                        // when 4 emulated harts run on one host thread, so an
                        // occasional SYN or SYN-ACK is dropped.  TCP's normal
                        // retransmit at `RTO_INITIAL_MS = 1000` (defined in
                        // `crates/net/net/src/tcp.rs:135`) would recover, but the
                        // previous 500 ms deadline here was SHORTER than RTO
                        // → no retransmit chance, deterministic failure on any
                        // dropped SYN.  Bumped to TIMER_FREQ * 2 (= 2 s wall)
                        // so the TCP layer gets at least one SYN retransmit
                        // before we give up.  The wait is paid once per
                        // (re)connection, so the worst-case cost is +1.5 s on
                        // the first behavior iteration when there's loss.
                        let handshake_deadline = azos_drv_sys::timebase::now()
                            + azos_drv_sys::timebase::TIMER_FREQ * 2;
                        // SLEEP-poll, never yield-poll. This used to be a
                        // `task_yield()` busy-loop: ~200k yields per 2 s
                        // window at behavior's priority. Under strict
                        // priority dispatch a yield re-enqueues the yielder,
                        // so every same-or-lower-priority task sharing this
                        // hart got NOTHING for the whole 2 s except the
                        // 100 ms retry gap — measured as watchdog storms on
                        // rt-motor's heartbeat path and as the phase-A
                        // throughput floor (~0.8 s/exchange while a brainless
                        // scenario retried forever; the 22-08 audit's
                        // "unidentified remaining bottleneck"). A TCP
                        // handshake is a WAIT, not work: poll the state at
                        // 10 ms — same 2 s deadline, 200 polls, and the hart
                        // belongs to whoever has real work in between.
                        let mut waited = 0u32;
                        while azos_drv_sys::timebase::now() < handshake_deadline
                            && azos_net::tcp::conn_state(tcp_fd as usize)
                               != azos_net::tcp::TcpState::Established
                        {
                            let next_poll = azos_drv_sys::timebase::now()
                                + azos_drv_sys::timebase::TIMER_FREQ / 100;
                            azos_sched::task_block(
                                azos_sched::WaitReason::Timer(next_poll));
                            waited += 1;
                        }
                        let st_after = azos_net::tcp::conn_state(tcp_fd as usize);
                        if st_after != azos_net::tcp::TcpState::Established {
                            // Handshake didn't complete in 2 s; close the
                            // half-open socket and let the next iteration
                            // retry after the 100 ms loop sleep.
                            kprintln!("[BRAIN] handshake stalled (state={}) after {} polls / 2s",
                                      st_after as u8, waited);
                            azos_net::tcp::close(tcp_fd as usize);
                            tcp_fd = -1;
                        } else {
                        tcp_connected = true;
                        azos_behavior::remote_set_connected(true);
                        azos_behavior::remote_set_socket(tcp_fd);
                        // Deactivate offline mode — brain is back
                        azos_behavior::offline::offline_deactivate();
                        kprintln!("[BRAIN] connected fd={} (handshake took {} polls)",
                                  tcp_fd, waited);

                        // ── RFC-0019 encrypted-link handshake ──────────────
                        // If `link_encrypt=1` in CONFIG.INI, run the responder
                        // handshake NOW, before any packet is sent (the brain,
                        // as initiator, speaks first). No silent fallback: if
                        // the flag is set but no LINK.KEY is present, or the
                        // handshake fails, drop the connection rather than send
                        // plaintext.
                        //
                        // K-C5: under `link-encrypt-enforced` the handshake is
                        // unconditional — the `cfg!` is OR'ed here rather than
                        // written into CFG_LINK_ENCRYPT, because that flag is
                        // re-applied by config_apply from a CONFIG.INI that
                        // lives on the USB-exposed FAT volume: a file must not
                        // be able to disarm a compiled-in policy.
                        link = None;
                        if azos_config::CFG_LINK_ENCRYPT.load(Ordering::Relaxed)
                            || cfg!(feature = "link-encrypt-enforced")
                        {
                            match azos_behavior::auth_envelope::link_key_copy() {
                                Some(psk) => {
                                    enc_salt = enc_salt.wrapping_add(1);
                                    match brain_responder_handshake(
                                        tcp_fd as usize, psk, now ^ enc_salt,
                                    ) {
                                        Some(l) => {
                                            link = Some(l);
                                            brain_rx_stream().reset();
                                            // No bytes sealed under an earlier
                                            // session may reach this one.
                                            brain_tx_carry().reset();
                                            link_rekey_deadline = now
                                                + BRAIN_LINK_REKEY_SECS
                                                    * azos_drv_sys::timebase::TIMER_FREQ;
                                            kprintln!("[BRAIN] RFC-0019 encrypted link established");
                                            // K-C5: re-arm the one-shot denial
                                            // announcements — a denial hours
                                            // after this handshake must print
                                            // again, not be swallowed by a bit
                                            // set before it.
                                            azos_behavior::auth_envelope::reset_denial_announcements();
                                        }
                                        None => {
                                            azos_drv_sys::kwarn!("[BRAIN] RFC-0019 handshake failed — closing");
                                            azos_net::tcp::close(tcp_fd as usize);
                                            tcp_fd = -1;
                                            tcp_connected = false;
                                            azos_behavior::remote_set_connected(false);
                                        }
                                    }
                                }
                                None => {
                                    kprintln!("[BRAIN] CFG_LINK_ENCRYPT set but no LINK.KEY — \
                                               closing (RFC-0019: no plaintext fallback)");
                                    azos_net::tcp::close(tcp_fd as usize);
                                    tcp_fd = -1;
                                    tcp_connected = false;
                                    azos_behavior::remote_set_connected(false);
                                }
                            }
                        }

                        // Send StatusPacket immediately on connect (only if the
                        // link is still up — the handshake above may have
                        // dropped it). `send_framed` wraps + optionally encrypts.
                        if tcp_connected {
                            let uptime_s = (now / azos_drv_sys::timebase::TIMER_FREQ) as u32;
                            let mut st_payload = [0u8; STATUS_PAYLOAD_SIZE];
                            encode_status_packet(
                                &mut st_payload,
                                1,              // mode: running
                                8,              // tasks_ok
                                8,              // canary_ok
                                uptime_s,
                                // The type the envelope runs (Kconfig robot
                                // type, ROBOT_TYPE_ID), not a fixed "wheeled".
                                azos_behavior::safety::safety_robot_type(),
                            );
                            let mut st_frame = [0u8; STATUS_FRAME_SIZE];
                            let st_len = build_packet(PKT_STATUS, &st_payload, &mut st_frame);
                            let st_sent = send_framed(
                                tcp_fd as usize, &st_frame[..st_len], &mut link, &mut enc_salt,
                            );
                            kprintln!("[BRAIN] status sent: frame={} wire={} enc={}",
                                      st_len, st_sent, link.is_some() as u8);
                            // C1: a camera connection may pair with this
                            // session now; it closes when the session ends
                            // (`remote_set_connected(false)`).
                            azos_behavior::camera_tx::control_session_ready();
                        }
                        }  // end of `else` (handshake reached Established)
                    } else {
                        kprintln!("[BRAIN] connect failed rc={}", tcp_fd);
                    }
                }
            }

            if tcp_connected && tcp_fd >= 0 {
                // RFC-0019 wall-clock rekey. The link counts records and
                // bytes itself; the interval needs a clock, which is here.
                if let Some(l) = link.as_mut() {
                    if now >= link_rekey_deadline {
                        l.request_rekey();
                        link_rekey_deadline = now
                            + BRAIN_LINK_REKEY_SECS
                                * azos_drv_sys::timebase::TIMER_FREQ;
                    }
                }

                // Build SensorPacket payload
                let ts_ms = now / (azos_drv_sys::timebase::TIMER_FREQ / 1000);
                let range_front = state.cam_dist_front;
                let range_right = state.cam_dist_right;
                let mut sp_payload = [0u8; SENSOR_PAYLOAD_SIZE];
                encode_sensor_packet(
                    &mut sp_payload,
                    ts_ms,
                    state.accel_mg,
                    state.gyro_mdps,
                    state.battery_mv,
                    state.odom_dist_mm as i32,
                    state.odom_heading_cdeg as i32,
                    state.enc_left,
                    state.enc_right,
                    range_front,
                    range_right,
                    state.sensor_flags,
                );

                // Frame and send. Wrap the framed packet in the auth envelope
                // (identity passthrough when no LINK.KEY is loaded).
                let mut sp_frame = [0u8; SENSOR_FRAME_SIZE];
                let sp_len = build_packet(PKT_SENSOR, &sp_payload, &mut sp_frame);
                // Wrap + (RFC-0019) encrypt + send-all in one place. #39 fix
                // (loop until the full frame is on the wire) lives inside
                // send_framed via send_all_with_yield.
                // I2 experiment: one-shot head-of-line hold-off probe under the
                // compile-time multi-stream policy. Only when multi-stream is on.
                #[cfg(feature = "qemu")]
                {
                    use core::sync::atomic::AtomicBool;
                    static I2_DONE: AtomicBool = AtomicBool::new(false);
                    // The probe writes its frames raw, outside the sealed-record
                    // carry, so it runs only on a link with no RFC-0019 session:
                    // raw bytes inside a sealed stream would end the session.
                    if azos_config::CFG_MULTI_STREAM.load(Ordering::Relaxed)
                        && link.is_none()
                        && !I2_DONE.swap(true, Ordering::Relaxed)
                    {
                        i2_holdoff_probe(tcp_fd as usize);
                    }
                }
                let sent = send_framed(
                    tcp_fd as usize, &sp_frame[..sp_len], &mut link, &mut enc_salt,
                );
                // One-shot diagnostic on first sensor send attempt (qemu only).
                // Localises whether the sensor pump never reaches send (= task
                // stuck up-stream), or sends 0 bytes (= wrap/encrypt/TCP issue).
                #[cfg(feature = "qemu")]
                {
                    use core::sync::atomic::AtomicBool;
                    static SENSOR_LOGGED: AtomicBool = AtomicBool::new(false);
                    if !SENSOR_LOGGED.swap(true, Ordering::Relaxed) {
                        kprintln!("[BRAIN] first sensor send: frame={} wire={} enc={}",
                                  sp_len, sent, link.is_some() as u8);
                    }
                }
                if sent > 0 {
                    azos_behavior::remote_inc_sent();
                }

                // A camera frame every CAMERA_SEND_INTERVAL passes (~2 Hz),
                // here only when no camera connection is configured
                // (`behavior_camera_port` = 0); otherwise `camera_tx_task`
                // sends it on its own connection (C1). Only on an encrypted
                // link, through `send_camera_sealed`: JPEG in PKT_CAMERA, auth
                // envelope, sealed as a multi-record message. No plaintext
                // camera frame is sent at all: raw GRAY8 at 320×240 overflows
                // the brain protocol's u16 length field, and the brain's
                // plaintext reader refuses any payload above 4 KiB and drops
                // the connection.
                camera_cycle += 1;
                if camera_cycle >= CAMERA_SEND_INTERVAL {
                    camera_cycle = 0;
                    if link.is_some()
                        && azos_config::BEHAVIOR_CAMERA_PORT.load(Ordering::Relaxed) == 0
                        && azos_drv_sensor::csi::csi_is_ready()
                    {
                        let _cam_sent =
                            send_camera_sealed(tcp_fd as usize, &mut link, &mut enc_salt);
                    }
                }

                // Check connection state
                let conn_state = azos_net::tcp::conn_state(tcp_fd as usize);
                if conn_state != azos_net::tcp::TcpState::Established {
                    tcp_connected = false;
                    tcp_fd = -1;
                    // Drop the encrypted channel — a reconnect performs a fresh
                    // RFC-0019 handshake with new ephemeral keys (forward secrecy
                    // when the pool is seeded; see `derive_ephemeral_priv`'s doc —
                    // an enforced build now refuses the reconnect outright instead
                    // of silently establishing an unseeded one).
                    link = None;
                    azos_behavior::remote_set_connected(false);
                    // Activate offline mode — patrol without brain
                    azos_behavior::offline::offline_activate();
                }

                // Receive ActuatorCmd (framed: up to 6 + 3 + 2*8 = 25 bytes).
                // When the brain↔kernel link is authenticated, frames are
                // wrapped in a 26-byte HMAC envelope (auth_envelope), so the
                // raw recv buffer must hold envelope + inner = 26 + 25 = 51 B.
                // When unkeyed, `unwrap` falls back to identity → same size.
                // Round up for headroom.
                // Sized for the deepest nesting: AEAD(46) + envelope(26) +
                // inner(64). When encrypted we decrypt the AEAD frame to the
                // HMAC envelope first, then unwrap that to the inner packet.
                const RECV_INNER_MAX: usize = 64;
                const RECV_ENV_MAX: usize = RECV_INNER_MAX
                    + azos_behavior::auth_envelope::ENVELOPE_OVERHEAD;
                const RECV_RAW_MAX: usize = RECV_ENV_MAX
                    + azos_behavior::encrypt_link::ENC_OVERHEAD
                    + azos_multi_stream::HEADER_LEN + 16;
                let mut raw_buf = [0u8; RECV_RAW_MAX];
                // Sized for several coalesced inner packets, not one: the drain
                // loop below concatenates every envelope it decodes.
                let mut recv_buf = [0u8; RECV_INNER_MAX * 4];
                let n_raw = azos_net::tcp::recv(tcp_fd as usize, &mut raw_buf);
                // A terminal RFC-0019 record-layer event seen while draining.
                let mut link_terminal: Option<azos_behavior::encrypt_link::RecordError> = None;
                // Returns inner_len on success / identity-fallback (unkeyed);
                // 0 on HMAC mismatch, replay, size error or a terminal record.
                let n = if n_raw > 0 {
                    // RFC-0021 demux first (outermost): strip [stream_id][len]
                    // and keep only STREAM_CONTROL payloads for the brain path.
                    // Non-control streams (camera/lidar) are ignored here.
                    let ctrl: &[u8] = if azos_config::CFG_MULTI_STREAM.load(Ordering::Relaxed) {
                        match azos_multi_stream::unwrap(&raw_buf[..n_raw as usize]) {
                            Some((sid, _, payload))
                                if sid == azos_multi_stream::STREAM_CONTROL => payload,
                            _ => &[],
                        }
                    } else {
                        &raw_buf[..n_raw as usize]
                    };
                    if ctrl.is_empty() {
                        0
                    } else {
                        // Drain EVERY coalesced envelope, not just the first.
                        //
                        // K-C3/C4 fixed this for brain-protocol frames sharing
                        // one envelope; the loop below is the same fix one
                        // layer out, for envelopes sharing one recv(). TCP
                        // gives no reason for the brain's send() boundaries to
                        // survive as recv() boundaries, so two commands written
                        // separately routinely arrive together — and the old
                        // code decoded frame 1 and dropped the rest with no
                        // error and no log. An ESTOP behind any other command
                        // was silently lost, which on a robot is the one packet
                        // that must never be.
                        //
                        // Inner packets are concatenated into `recv_buf`; the
                        // existing K-C3/C4 parser below then walks them all,
                        // since the brain protocol is self-delimiting
                        // (MAGIC + len + CRC).
                        match link.as_mut() {
                            // RFC-0019: records → messages → envelopes. A
                            // record torn across two recv() calls is carried
                            // to the next tick by `BrainRxStream`.
                            Some(l) => match brain_rx_stream().feed(l, ctrl, &mut recv_buf) {
                                Ok(filled) => filled as i32,
                                Err(e) => {
                                    link_terminal = Some(e);
                                    0
                                }
                            },
                            None => {
                                let mut off = 0usize;      // cursor into `ctrl`
                                let mut filled = 0usize;   // bytes written to recv_buf
                                while off < ctrl.len() && filled < recv_buf.len() {
                                    match azos_behavior::auth_envelope::unwrap_consuming(
                                        &ctrl[off..], &mut recv_buf[filled..],
                                    ) {
                                        // A zero-advance would spin forever on a
                                        // malformed frame; treat it as end-of-data
                                        // rather than trusting the decoder to move.
                                        Some((n, eaten)) if eaten > 0 => {
                                            filled += n;
                                            off += eaten;
                                        }
                                        _ => break,
                                    }
                                }
                                filled as i32
                            }
                        }
                    }
                } else {
                    n_raw
                };
                if let Some(e) = link_terminal {
                    // Terminal record-layer event (bad MAC or counter, overdue
                    // rekey, the brain's REJECT): answer with one authenticated
                    // REJECT unless there is nothing left to seal it with,
                    // close, and reconnect next tick with a fresh handshake.
                    azos_drv_sys::kwarn!("[BRAIN] RFC-0019 record layer: {:?} — closing", e);
                    if let Some(l) = link.as_mut() {
                        // Best effort, through the carry: the REJECT record goes
                        // out only behind a fully sent message, never into the
                        // middle of one, and is skipped when the socket will not
                        // take the rest. The session ends either way.
                        brain_tx_drain(tcp_fd as usize);
                        let nr = azos_behavior::encrypt_link::fresh_nonce_rand(enc_salt);
                        enc_salt = enc_salt.wrapping_add(1);
                        let sealed = brain_tx_carry().seal_with(
                            azos_drv_sys::timebase::now(),
                            |out| {
                                let mut rec = [0u8; azos_behavior::encrypt_link::ENC_OVERHEAD];
                                let rn = l.seal_reject(&nr, &mut rec);
                                if rn == 0 { 0 } else { frame_wire(&rec[..rn], out) }
                            },
                        );
                        if sealed.is_ok() {
                            brain_tx_drain(tcp_fd as usize);
                        }
                    }
                    azos_net::tcp::close(tcp_fd as usize);
                    tcp_connected = false;
                    tcp_fd = -1;
                    link = None;
                    brain_tx_carry().reset();
                    azos_behavior::remote_set_connected(false);
                    azos_behavior::offline::offline_activate();
                }
                // RFC-0019, fail closed: a sealed message the socket has taken
                // no byte of for BRAIN_TX_STALL_MS ends the session like a
                // terminal record — close, drop the link, offline — and the
                // next tick dials a fresh handshake. No REJECT: it could only
                // queue behind the bytes that are not moving.
                if link.is_some() && brain_tx_carry().is_stalled() {
                    azos_drv_sys::kwarn!("[BRAIN] RFC-0019 tx stalled: {} sealed bytes unsent for {} ms — closing",
                              brain_tx_carry().pending_len(),
                              azos_behavior::brain_tx::BRAIN_TX_STALL_MS);
                    azos_net::tcp::close(tcp_fd as usize);
                    tcp_connected = false;
                    tcp_fd = -1;
                    link = None;
                    brain_tx_carry().reset();
                    azos_behavior::remote_set_connected(false);
                    azos_behavior::offline::offline_activate();
                }
                if n >= 6 {
                    let n = n as usize;
                    let mut cursor = 0usize;
                    // K-C3/C4: a single decoded `recv_buf` can hold several coalesced
                    // brain-protocol frames — the brain writes one frame per command,
                    // but nothing stops two or more (e.g. CONFIG + ACTUATOR + ESTOP)
                    // from landing in the same tick's recv()/decrypt cycle. Parsing
                    // only the frame at offset 0 silently dropped every frame after
                    // it, including an ESTOP. Loop consuming every complete frame,
                    // resyncing on the next MAGIC pair when one fails length/CRC
                    // (corrupt, or torn mid-frame across two separate recv() calls —
                    // reassembling raw bytes across ticks is a larger, envelope-layer
                    // change and is out of scope here).
                    while cursor < n {
                        let (pkt_type, rel_pay_start, pay_len, total) =
                            match parse_packet(&recv_buf[cursor..n]) {
                                Some(f) => f,
                                None => match recv_buf[cursor + 1..n]
                                    .windows(2)
                                    .position(|w| {
                                        w[0] == azos_behavior::brain_protocol::MAGIC[0]
                                            && w[1] == azos_behavior::brain_protocol::MAGIC[1]
                                    })
                                {
                                    Some(off) => { cursor += 1 + off; continue; }
                                    None => break,
                                },
                            };
                        azos_behavior::remote_inc_recv();
                        let pay_start = cursor + rel_pay_start;
                        cursor += total;
                        if pkt_type == PKT_ACTUATOR {
                            let payload = &recv_buf[pay_start..pay_start + pay_len];
                            if let Some(cmd) = decode_actuator_cmd(payload) {
                                // RFC-0035: record command confidence so the motor
                                // envelope can tighten the cap for low-confidence
                                // (e.g. reactive-LLM) commands.
                                azos_behavior::safety::cmd_set_low_confidence(
                                    cmd.is_low_confidence());
                                // Which path handled the brain's emergency
                                // is the first question when reading this log:
                                // the kernel's own link and the ring-3 client
                                // both connect to the same peer and both
                                // receive this frame, so "the motors stopped"
                                // says nothing about which one stopped them.
                                #[cfg(feature = "actuation-smoke")]
                                if cmd.is_emergency() {
                                    kprintln!("[ACTSMOKE] brainlink emergency (tcp)");
                                }
                                // ONE decision function, shared with the UART
                                // bridge below. They were copies, and the copy
                                // is why the emergency fix — replacing the
                                // CACHED action, not just publishing zeros —
                                // lived here and not there for months. All of
                                // the reasoning that used to sit inline (why
                                // the stop must become the standing action, why
                                // `CMD_STOP` and not `CMD_NONE`, why an
                                // ordinary command is routed through L0-L3
                                // instead of published direct) now lives once,
                                // next to the code it governs, in
                                // `remote_actuation_from`.
                                let plan = azos_behavior::remote_actuation_from(
                                    &cmd, azos_behavior::last_action(), now);
                                if plan.publish_stop {
                                    azos_robot::motor_cmd_publish(0, 0);
                                }
                                azos_behavior::set_last_action(plan.action);
                                state.remote_action = plan.action;
                            }
                        } else if pkt_type == PKT_PREDICT {
                            // RFC-0034 speculative actuation — capability v1: the
                            // brain→kernel predictive CHANNEL. Receive + decode +
                            // log the predicted next command (observable proof the
                            // channel works). Acting on it early (through the
                            // Fase-1 envelope, gated by SPECULATIVE_ACTUATION) is
                            // the HW-measured layer, deferred — see RFC-0034.
                            let payload = &recv_buf[pay_start..pay_start + pay_len];
                            if let Some(p) = azos_behavior::decode_predict_cmd(payload) {
                                let (pl, pr) = p.cmd.diff_drive();
                                kprintln!("[PREDICT] next l={} r={} conf={}", pl, pr, p.confidence);
                            }
                        } else if pkt_type == PKT_CONFIG {
                            let payload = &recv_buf[pay_start..pay_start + pay_len];
                            if let Some(cfg) = decode_config_cmd(payload) {
                                match cfg.config_key {
                                    CFG_KEY_BUZZER => match cfg.value {
                                        BUZZER_BEEP  => { let _ = azos_drv_actuator::buzzer::buzzer_beep(); }
                                        BUZZER_SIREN => { let _ = azos_drv_actuator::buzzer::buzzer_alert(); }
                                        BUZZER_OFF   => { let _ = azos_drv_actuator::buzzer::buzzer_off(); }
                                        _ => {}
                                    },
                                    CFG_KEY_CAMERA => {
                                        if cfg.value == CAMERA_PWR_ON {
                                            azos_drv_sensor::csi::csi_power_on();
                                        } else if cfg.value == CAMERA_PWR_OFF {
                                            azos_drv_sensor::csi::csi_power_off();
                                        }
                                    },
                                    _ => {} // other config keys handled in future phases
                                }
                            }
                        } else if pkt_type == PKT_PAYLOAD {
                            // E04: payload command (spray / gripper / cam trigger)
                            let payload = &recv_buf[pay_start..pay_start + pay_len];
                            if let Some(cmd) = decode_payload_cmd(payload) {
                                azos_behavior::payload::payload_exec(cmd);
                            }
                        } else if pkt_type == PKT_ESTOP {
                            // **ALREADY LATCHED IS ALREADY DONE.** Identical guard, and
                            // identical reasoning, to `ring3_estop`'s — which was written for
                            // a ring-3 loop and left the two paths a REMOTE peer can reach
                            // without it. Every repeat of this body costs a synchronous
                            // `log_safety_violation_durable`, two motor writes, an ESC disarm
                            // and a console line that busy-waits on the UART; the state is
                            // already exactly what the frame asks for, so a peer sending
                            // `PKT_ESTOP` every frame buys unmetered flash writes and console
                            // stalls for nothing, and evicts the record that says why the
                            // machine stopped. Both reasons the ring-3 guard checked hold here
                            // too: `motor_envelope` opens with `if estop_is_active()`, and the
                            // only `esc_arm()` in the tree is an operator shell command.
                            // `cursor` is advanced before this dispatch chain, so `continue`
                            // alone moves on to the next coalesced frame.
                            if azos_behavior::safety::estop_is_active() {
                                continue;
                            }
                            // Remote emergency stop — highest priority.
                            // The sequence lives in one place; see
                            // `actuation::latch_and_stop` for why the latch
                            // precedes the wheels.
                            azos_safety_core::actuation::latch_and_stop();
                            azos_drv_sys::kwarn!("[BRAIN] ESTOP received — motors stopped");
                            // Durable, not deferred: the motors are already
                            // stopped, so the flush costs nothing that was going
                            // to be spent on control, and an e-stop is the event
                            // most likely to be followed by the reset that would
                            // erase an unflushed record.
                            let _ = azos_behavior::logger::log_safety_violation_durable(
                                azos_behavior::logger::SAFETY_ESTOP, 0, 0);
                        } else if pkt_type == PKT_DEGRADE {
                            // RFC-0036: brain-triggered degraded mode. reason 0
                            // clears; any non-zero reason arms capability
                            // containment (user-task writes denied at the cap
                            // chokepoint; in-kernel safe-stop unaffected).
                            let payload = &recv_buf[pay_start..pay_start + pay_len];
                            // **An absent reason byte ARMS, it does not clear.**
                            //
                            // This read `unwrap_or(DEGRADE_CLEAR)`, so a truncated
                            // frame disarmed containment — and since `degraded_set`
                            // writes the same atomic as the graded level, it also
                            // reset a CONTAINED level to FULL. Its sibling 0x8B, on
                            // the same atomic and the same malformed input, fails
                            // closed. Two handlers, one state, opposite answers.
                            let malformed_degrade = payload.is_empty();
                            let reason = payload.first().copied()
                                .unwrap_or(DEGRADE_REASON_MALFORMED);
                            if reason == DEGRADE_CLEAR {
                                azos_ipc::cap::degraded_set(false);
                                azos_drv_sys::kwarn!("[BRAIN] degraded mode cleared");
                                azos_behavior::logger::log_safety_violation(
                                    azos_behavior::logger::SAFETY_DEGRADE, 0, 0);
                            } else {
                                azos_ipc::cap::degraded_set(true);
                                if malformed_degrade {
                                    azos_drv_sys::kwarn!("[BRAIN] degraded mode armed — reason byte missing");
                                } else {
                                    azos_drv_sys::kwarn!("[BRAIN] degraded mode armed — reason {}", reason);
                                }
                                azos_behavior::logger::log_safety_violation(
                                    azos_behavior::logger::SAFETY_DEGRADE, 1, reason as u32);
                            }
                        } else if pkt_type == PKT_SEMANTIC_LEVEL {
                            // RFC-0037: graded degrade-level command. 1-byte
                            // payload = level index (0=FULL…3=CONTAINED). Missing
                            // payload → fail-closed (CONTAINED).
                            let payload = &recv_buf[pay_start..pay_start + pay_len];
                            let malformed = payload.is_empty();
                            let level = payload.first().copied()
                                .unwrap_or(azos_ipc::cap::DEGRADE_LEVEL_CONTAINED);
                            // Read the outgoing level BEFORE the store: the
                            // record carries the transition, not just the
                            // destination, and after the store it is gone.
                            let previous = azos_ipc::cap::degrade_level();
                            azos_ipc::cap::degrade_level_set(level);
                            // `degrade_level_set` clamps, so record what took
                            // effect rather than what the wire asked for.
                            let effective = azos_ipc::cap::degrade_level();
                            kprintln!("[BRAIN] semantic level set to {}", effective);
                            if let Some((v, a, d)) =
                                azos_behavior::logger::semantic_level_record(
                                    malformed, effective, previous)
                            {
                                azos_behavior::logger::log_safety_violation(v, a, d);
                            }
                        } else if pkt_type == PKT_MODE {
                            let payload = &recv_buf[pay_start..pay_start + pay_len];
                            if let Some(mode) = decode_mode_cmd(payload) {
                                // **An e-stop cleared remotely is a security event, and it is the one the
                                // recorder used to miss.** Activating one records `SAFETY_ESTOP`; clearing
                                // one printed a console line and nothing else, so a black box read after an
                                // incident showed the machine being stopped and never released.
                                //
                                // Owner decision, 2026-09-06: only `MODE_ID_ESTOP_RESET` may clear — see its
                                // doc comment in `brain_protocol.rs` for why that value and not `0`. Every
                                // other mode id changes mode and leaves the e-stop exactly as it was. Before
                                // this gate, `decode_mode_cmd` handed back a byte NOTHING validated, and any
                                // value cleared the e-stop.
                                //
                                // The decision (and the `action_code` it logs) lives in
                                // `mode_estop_record`/`mode_degrade_record`, not inline here — those are the
                                // functions the host tests call, so a test that only re-derived this `if`
                                // locally would keep passing even if this gate were later deleted.
                                if let Some((should_clear, action_code)) =
                                    azos_behavior::brain_protocol::mode_estop_record(
                                        mode.mode_id, azos_behavior::safety::estop_is_active())
                                {
                                    if should_clear {
                                        // Owner decision, 2026-09-25: MODE_ID_ESTOP_RESET from the
                                        // brain is a REQUEST, never a clear — see the module note on
                                        // `safety::ReleaseAuthority`. The wire format is unchanged (a
                                        // bare 1-byte payload is still exactly the historical request);
                                        // a payload at least `RELEASE_PROOF_BYTES` longer carries an
                                        // operator-signed release proof (nonce || Ed25519 sig) that the
                                        // brain itself cannot produce, because it does not hold the key.
                                        let proof = if payload.len()
                                            >= 1 + azos_behavior::safety::RELEASE_PROOF_BYTES
                                        {
                                            let nonce = u64::from_be_bytes(
                                                payload[1..9].try_into().unwrap());
                                            let mut sig = [0u8;
                                                azos_behavior::safety::RELEASE_SIG_BYTES];
                                            sig.copy_from_slice(&payload[9..9
                                                + azos_behavior::safety::RELEASE_SIG_BYTES]);
                                            azos_behavior::safety::verify_operator_release(
                                                nonce, &sig).ok()
                                        } else {
                                            None
                                        };
                                        if let Some(proof) = proof {
                                            azos_behavior::safety::estop_release(proof);
                                            azos_drv_sys::kwarn!("[BRAIN] ESTOP cleared by verified operator authority");
                                            let _ = azos_behavior::logger::log_safety_violation_durable(
                                                azos_behavior::logger::SAFETY_ESTOP, action_code, mode.mode_id as u32);
                                        } else if let Some(n) =
                                            azos_behavior::safety::note_refused_estop_clear()
                                        {
                                            // Same metering, and the same shared flight-recorder code
                                            // (see `safety::ReleaseDenial`'s doc), as a wrong mode id
                                            // below: to the recorder a brain-only request and a
                                            // forged/absent proof both mean "stayed armed".
                                            azos_drv_sys::kwarn!("[BRAIN] ESTOP_RESET recorded as a REQUEST — no verified operator authority, ESTOP stays armed (refusal #{})", n);
                                            let _ = azos_behavior::logger::log_safety_violation_durable(
                                                azos_behavior::logger::SAFETY_ESTOP,
                                                azos_behavior::safety::ESTOP_ACTION_REFUSED_MIRROR,
                                                (n << 8) | mode.mode_id as u32);
                                        }
                                    } else if let Some(n) =
                                        azos_behavior::safety::note_refused_estop_clear()
                                    {
                                    // **A REFUSED CLEAR IS METERED, and that is the same
                                    // argument `ring3_estop` makes in `domains/robot/safety-core/src/actuation.rs`.**
                                    //
                                    // This recorded DURABLY — a synchronous flush — and printed a
                                    // console line, once per frame, for a refusal that changes no
                                    // state. A peer can coalesce 36 seven-byte MODE frames into one
                                    // 256-byte read and repeat every tick: an unmetered path to
                                    // evict the real e-stop record from the flight recorder with
                                    // copies of itself, plus flash wear and a console stall, and it
                                    // costs the peer nothing because the machine is already stopped.
                                    // Ring 3 had exactly this and it was closed; the brain link is
                                    // the same defect with a different actor.
                                    //
                                    // The 1st, 10th, 100th ... refusal is recorded, with its ordinal
                                    // in the detail field, so an investigator still sees that it
                                    // happened and roughly how often — bounded at log10(n) records
                                    // for the whole run.
                                        azos_drv_sys::kwarn!("[BRAIN] MODE mode_id={} is not the reset id — ESTOP stays armed (refusal #{})", mode.mode_id, n);
                                        let _ = azos_behavior::logger::log_safety_violation_durable(
                                            azos_behavior::logger::SAFETY_ESTOP, action_code,
                                            (n << 8) | mode.mode_id as u32);
                                    }
                                }
                                // RFC-0036: a MODE command also clears degraded mode — gated on the SAME
                                // reserved id (owner decision, 2026-09-06). Left ungated this is the
                                // identical defect on the sibling piece of state this handler touches: any
                                // mode change would silently lift capability containment too. The
                                // documented, dedicated way to clear degraded mode remains `PKT_DEGRADE`
                                // reason 0 (`DEGRADE_CLEAR`); this MODE path has always been a secondary one.
                                if let Some((should_clear, action_code, detail)) =
                                    azos_behavior::brain_protocol::mode_degrade_record(
                                        mode.mode_id, azos_ipc::cap::degraded_active())
                                {
                                    if should_clear {
                                        azos_ipc::cap::degraded_set(false);
                                        azos_drv_sys::kwarn!("[BRAIN] degraded mode cleared by MODE command");
                                    }
                                    azos_behavior::logger::log_safety_violation(
                                        azos_behavior::logger::SAFETY_DEGRADE, action_code, detail);
                                }
                            }
                        } else {
                            // RFC-0039: a type this build does not act on.
                            // Recorded rather than dropped in silence — see
                            // `SAFETY_UNKNOWN_PKT`.
                            azos_behavior::logger::log_safety_violation(
                                azos_behavior::logger::SAFETY_UNKNOWN_PKT,
                                pkt_type, pay_len as u32);
                        }
                    }
                }
            }
        }

        // ── 2b. Brain Protocol: UART bridge send/recv ────────────────────
        // Alternative to TCP: send brain protocol packets over UART1 to
        // ESP32-C3 WiFi bridge.  Used when Ethernet is unavailable.
        if !tcp_connected && azos_drv_bus::uart_bridge::bridge_is_ready()
            && bridge_policy_permits()
        {
            // Build and send SensorPacket via UART1
            let ts_ms = now / (azos_drv_sys::timebase::TIMER_FREQ / 1000);
            let range_front = state.cam_dist_front;
            let range_right = state.cam_dist_right;
            let mut sp_payload = [0u8; SENSOR_PAYLOAD_SIZE];
            encode_sensor_packet(
                &mut sp_payload,
                ts_ms,
                state.accel_mg,
                state.gyro_mdps,
                state.battery_mv,
                state.odom_dist_mm as i32,
                state.odom_heading_cdeg as i32,
                state.enc_left,
                state.enc_right,
                range_front,
                range_right,
                state.sensor_flags,
            );
            let mut sp_frame = [0u8; SENSOR_FRAME_SIZE];
            let sp_len = build_packet(PKT_SENSOR, &sp_payload, &mut sp_frame);
            let sent = azos_drv_bus::uart_bridge::bridge_send(&sp_frame[..sp_len]);
            if sent > 0 {
                azos_behavior::remote_inc_sent();
            }

            // NO CAMERA OVER THIS BRIDGE — it does not fit, and pretending
            // it does cost the safety arbitration.
            //
            // The arithmetic, which is the whole argument: UART1 runs at
            // 115200 baud 8N1 = 11,520 B/s, and one frame is
            // `JPEG_MAX_SIZE` + header + framing = 19,211 B. That is **1.67
            // seconds per frame** on a link whose owner, `behavior_task`,
            // runs its control loop at 10 Hz. `bridge_send` blocks per byte,
            // so a single frame froze the task for ~16 ticks and took L0-L3
            // arbitration down with it — the e-stop layer included — while
            // RX went undrained the whole time.
            //
            // It also carried ~57.6 KiB of `.bss` for three buffers
            // (`JPEG_MAX_SIZE` + two framed copies) that existed only for
            // this path, and the comment they came with is the tell: they had
            // been on the stack, blowing the guard page, and nobody noticed
            // because "it only runs when `!tcp_connected && bridge_is_ready()`,
            // which CI never reaches".
            //
            // This is not an optimisation left undone. 19,211 B does not cross
            // an 11,520 B/s link inside a 100 ms budget by any implementation,
            // so the path is removed rather than made faster. The bridge keeps
            // what fits: a 70-byte `SensorPacket` is ~6 ms, and inbound
            // commands are smaller still. Camera frames go over TCP, which is
            // where the working path already sends them (`PKT_CAMERA` in the
            // TCP branch above), or they do not go.

            // Receive ActuatorCmd from UART1
            let mut recv_buf = [0u8; 32];
            let n = azos_drv_bus::uart_bridge::bridge_recv(&mut recv_buf);
            if n >= 6 {
                let n = n as usize;
                let mut cursor = 0usize;
                // K-C3/C4: same coalesced-frame issue as the TCP path above — a
                // single bridge_recv() can return several concatenated frames
                // (e.g. CONFIG + ACTUATOR + ESTOP); consume every complete frame,
                // resyncing on the next MAGIC pair when one fails length/CRC.
                while cursor < n {
                    let (pkt_type, rel_pay_start, pay_len, total) =
                        match parse_packet(&recv_buf[cursor..n]) {
                            Some(f) => f,
                            None => match recv_buf[cursor + 1..n]
                                .windows(2)
                                .position(|w| {
                                    w[0] == azos_behavior::brain_protocol::MAGIC[0]
                                        && w[1] == azos_behavior::brain_protocol::MAGIC[1]
                                })
                            {
                                Some(off) => { cursor += 1 + off; continue; }
                                None => break,
                            },
                        };
                    azos_behavior::remote_inc_recv();
                    let pay_start = cursor + rel_pay_start;
                    cursor += total;
                    if pkt_type == PKT_ACTUATOR {
                        let payload = &recv_buf[pay_start..pay_start + pay_len];
                        if let Some(cmd) = decode_actuator_cmd(payload) {
                            // RFC-0035: record command confidence (UART path).
                            azos_behavior::safety::cmd_set_low_confidence(
                                cmd.is_low_confidence());
                            // ONE decision function, shared with the TCP path
                            // above. These two were copies, and the copy is
                            // what let the emergency fix live on one side and
                            // not the other for months — see
                            // `remote_actuation_from`, which also carries the
                            // reasoning that used to be duplicated here.
                            //
                            // STILL NOT DRIVEN BY ANY SCENARIO: the bridge is
                            // `cfg(feature = "vf2")` and reads a UART that does
                            // not exist on QEMU's virt machine, so this branch
                            // cannot be exercised from the gate at all. What IS
                            // covered is the decision itself, on the host —
                            // `tests/host/behavior-tests`, module
                            // `remote_actuation`. The transport waits for the
                            // board.
                            let plan = azos_behavior::remote_actuation_from(
                                &cmd, azos_behavior::last_action(), now);
                            if plan.publish_stop {
                                azos_robot::motor_cmd_publish(0, 0);
                            }
                            azos_behavior::set_last_action(plan.action);
                            state.remote_action = plan.action;
                        }
                    } else if pkt_type == PKT_PREDICT {
                        // RFC-0034 speculative actuation — capability v1 (UART
                        // path): receive + decode + log the predictive channel.
                        // Early-apply is HW-deferred (see RFC-0034).
                        let payload = &recv_buf[pay_start..pay_start + pay_len];
                        if let Some(p) = azos_behavior::decode_predict_cmd(payload) {
                            let (pl, pr) = p.cmd.diff_drive();
                            kprintln!("[PREDICT] next l={} r={} conf={}", pl, pr, p.confidence);
                        }
                    } else if pkt_type == PKT_CONFIG {
                        let payload = &recv_buf[pay_start..pay_start + pay_len];
                        if let Some(cfg) = decode_config_cmd(payload) {
                            match cfg.config_key {
                                CFG_KEY_BUZZER => match cfg.value {
                                    BUZZER_BEEP  => { let _ = azos_drv_actuator::buzzer::buzzer_beep(); }
                                    BUZZER_SIREN => { let _ = azos_drv_actuator::buzzer::buzzer_alert(); }
                                    BUZZER_OFF   => { let _ = azos_drv_actuator::buzzer::buzzer_off(); }
                                    _ => {}
                                },
                                CFG_KEY_CAMERA => {
                                    if cfg.value == CAMERA_PWR_ON {
                                        azos_drv_sensor::csi::csi_power_on();
                                    } else if cfg.value == CAMERA_PWR_OFF {
                                        azos_drv_sensor::csi::csi_power_off();
                                    }
                                },
                                _ => {}
                            }
                        }
                    } else if pkt_type == PKT_PAYLOAD {
                        // E04: payload command via UART bridge
                        let payload = &recv_buf[pay_start..pay_start + pay_len];
                        if let Some(cmd) = decode_payload_cmd(payload) {
                            azos_behavior::payload::payload_exec(cmd);
                        }
                    } else if pkt_type == PKT_ESTOP {
                        // Same guard as the TCP twin above — see its comment for why a
                        // repeated PKT_ESTOP is an unmetered durable write and not a
                        // second stop. `cursor` is advanced before this chain here too.
                        if azos_behavior::safety::estop_is_active() {
                            continue;
                        }
                        // Same one sequence as the TCP path above.
                        azos_safety_core::actuation::latch_and_stop();
                        azos_drv_sys::kwarn!("[BRAIN] ESTOP received (UART) — motors stopped");
                        let _ = azos_behavior::logger::log_safety_violation_durable(
                            azos_behavior::logger::SAFETY_ESTOP, 1, 0);
                    } else if pkt_type == PKT_DEGRADE {
                        // RFC-0036: brain-triggered degraded mode (UART bridge).
                        let payload = &recv_buf[pay_start..pay_start + pay_len];
                        // **An absent reason byte ARMS, it does not clear.**
                        //
                        // This read `unwrap_or(DEGRADE_CLEAR)`, so a truncated
                        // frame disarmed containment — and since `degraded_set`
                        // writes the same atomic as the graded level, it also
                        // reset a CONTAINED level to FULL. Its sibling 0x8B, on
                        // the same atomic and the same malformed input, fails
                        // closed. Two handlers, one state, opposite answers.
                        let malformed_degrade = payload.is_empty();
                        let reason = payload.first().copied()
                            .unwrap_or(DEGRADE_REASON_MALFORMED);
                        // **Recorded, exactly as the TCP twin records it.** This branch
                        // lifted and armed capability containment with a console line and
                        // nothing else, while its twin writes `SAFETY_DEGRADE` on both
                        // arms — so a black box read after an incident on the bridge showed
                        // no arm and no clear at all. Two transports into the same piece of
                        // safety state must leave the same evidence, or the recorder's
                        // silence means "it did not happen" on one and "nobody wrote it
                        // down" on the other. Deferred, not durable, on both: containment
                        // is not the event a reset is about to erase.
                        if reason == DEGRADE_CLEAR {
                            azos_ipc::cap::degraded_set(false);
                            azos_drv_sys::kwarn!("[BRAIN] degraded mode cleared (UART)");
                            azos_behavior::logger::log_safety_violation(
                                azos_behavior::logger::SAFETY_DEGRADE, 0, 0);
                        } else {
                            azos_ipc::cap::degraded_set(true);
                            if malformed_degrade {
                                azos_drv_sys::kwarn!("[BRAIN] degraded mode armed (UART) — reason byte missing");
                            } else {
                                azos_drv_sys::kwarn!("[BRAIN] degraded mode armed (UART) — reason {}", reason);
                            }
                            azos_behavior::logger::log_safety_violation(
                                azos_behavior::logger::SAFETY_DEGRADE, 1, reason as u32);
                        }
                    } else if pkt_type == PKT_SEMANTIC_LEVEL {
                        // RFC-0037: graded degrade-level command (UART bridge).
                        // 1-byte payload = level index (0=FULL…3=CONTAINED).
                        // Missing payload → fail-closed (CONTAINED).
                        let payload = &recv_buf[pay_start..pay_start + pay_len];
                        let malformed = payload.is_empty();
                        let level = payload.first().copied()
                            .unwrap_or(azos_ipc::cap::DEGRADE_LEVEL_CONTAINED);
                        let previous = azos_ipc::cap::degrade_level();
                        azos_ipc::cap::degrade_level_set(level);
                        let effective = azos_ipc::cap::degrade_level();
                        kprintln!("[BRAIN] semantic level set to {} (UART)", effective);
                        if let Some((v, a, d)) =
                            azos_behavior::logger::semantic_level_record(
                                malformed, effective, previous)
                        {
                            azos_behavior::logger::log_safety_violation(v, a, d);
                        }
                    } else if pkt_type == PKT_MODE {
                        let payload = &recv_buf[pay_start..pay_start + pay_len];
                        if let Some(mode) = decode_mode_cmd(payload) {
                            // **An e-stop cleared remotely is a security event, and it is the one the
                            // recorder used to miss.** Activating one records `SAFETY_ESTOP`; clearing one
                            // printed a console line and nothing else, so a black box read after an
                            // incident showed the machine being stopped and never released.
                            //
                            // Owner decision, 2026-09-06: only `MODE_ID_ESTOP_RESET` may clear — see its
                            // doc comment in `brain_protocol.rs` for why that value and not `0`. Every other
                            // mode id changes mode and leaves the e-stop exactly as it was. This is the
                            // `feature = "vf2"` UART bridge — it is compiled OUT of every QEMU build, so it
                            // is also the site a QEMU-only check would never catch missing this gate.
                            //
                            // Same shared `mode_estop_record`/`mode_degrade_record` the TCP site calls — see
                            // its twin of this branch for why the decision does not live inline here.
                            if let Some((should_clear, action_code)) =
                                azos_behavior::brain_protocol::mode_estop_record(
                                    mode.mode_id, azos_behavior::safety::estop_is_active())
                            {
                                if should_clear {
                                    // Owner decision, 2026-09-25: same change as the TCP twin — a
                                    // REQUEST, not a clear, unless the payload carries a verified
                                    // operator release proof. See `safety::ReleaseAuthority`'s
                                    // module note and the TCP site's twin of this branch.
                                    let proof = if payload.len()
                                        >= 1 + azos_behavior::safety::RELEASE_PROOF_BYTES
                                    {
                                        let nonce = u64::from_be_bytes(
                                            payload[1..9].try_into().unwrap());
                                        let mut sig = [0u8;
                                            azos_behavior::safety::RELEASE_SIG_BYTES];
                                        sig.copy_from_slice(&payload[9..9
                                            + azos_behavior::safety::RELEASE_SIG_BYTES]);
                                        azos_behavior::safety::verify_operator_release(
                                            nonce, &sig).ok()
                                    } else {
                                        None
                                    };
                                    if let Some(proof) = proof {
                                        azos_behavior::safety::estop_release(proof);
                                        azos_drv_sys::kwarn!("[BRAIN] ESTOP cleared by verified operator authority (UART)");
                                        let _ = azos_behavior::logger::log_safety_violation_durable(
                                            azos_behavior::logger::SAFETY_ESTOP, action_code, mode.mode_id as u32);
                                    } else if let Some(n) =
                                        azos_behavior::safety::note_refused_estop_clear()
                                    {
                                        azos_drv_sys::kwarn!("[BRAIN] ESTOP_RESET recorded as a REQUEST — no verified operator authority, ESTOP stays armed (UART, refusal #{})", n);
                                        let _ = azos_behavior::logger::log_safety_violation_durable(
                                            azos_behavior::logger::SAFETY_ESTOP,
                                            azos_behavior::safety::ESTOP_ACTION_REFUSED_MIRROR,
                                            (n << 8) | mode.mode_id as u32);
                                    }
                                } else if let Some(n) =
                                    azos_behavior::safety::note_refused_estop_clear()
                                {
                                    // Metered exactly as the TCP twin — see its comment. The bridge
                                    // is the cheaper line to flood, not the dearer one.
                                    azos_drv_sys::kwarn!("[BRAIN] MODE mode_id={} is not the reset id — ESTOP stays armed (UART, refusal #{})", mode.mode_id, n);
                                    let _ = azos_behavior::logger::log_safety_violation_durable(
                                        azos_behavior::logger::SAFETY_ESTOP, action_code,
                                        (n << 8) | mode.mode_id as u32);
                                }
                            }
                            // RFC-0036: MODE also clears degraded mode — gated on the SAME reserved id
                            // (owner decision, 2026-09-06). See the TCP site's twin of this branch for why.
                            if let Some((should_clear, action_code, detail)) =
                                azos_behavior::brain_protocol::mode_degrade_record(
                                    mode.mode_id, azos_ipc::cap::degraded_active())
                            {
                                if should_clear {
                                    azos_ipc::cap::degraded_set(false);
                                    azos_drv_sys::kwarn!("[BRAIN] degraded mode cleared by MODE command (UART)");
                                }
                                azos_behavior::logger::log_safety_violation(
                                    azos_behavior::logger::SAFETY_DEGRADE, action_code, detail);
                            }
                        }
                    } else {
                        // RFC-0039, UART bridge: same record as the network
                        // path. Both chains ended without an `else`, so this
                        // one dropped unknown types in silence too.
                        azos_behavior::logger::log_safety_violation(
                            azos_behavior::logger::SAFETY_UNKNOWN_PKT,
                            pkt_type, pay_len as u32);
                    }
                }
            }
        }

        // Inject latest remote action into state
        let last_act = azos_behavior::last_action();
        if last_act.valid {
            state.remote_action = last_act;
        }

        // ── 3. ML inference (if enabled) ─────────────────────────────────
        //
        // In the ring-3 ML service: the two range readings go out, a class
        // comes back within `behavior_ml::ML_REPLY_TIMEOUT_US`, and a cycle
        // with no class decides STOP through L1 (`ml_link`'s doc says why) —
        // a boot that never started the service too (owner decision
        // 2026-09-28, fail closed), recorded once per run of missing verdicts.
        #[allow(unused_mut)]
        let mut mlp_result = MlpResult::none();
        #[cfg(not(feature = "no-ml"))]
        let t_inf = azos_drv_sys::timebase::now();
        #[cfg(not(feature = "no-ml"))]
        let mut ml_outcome = None;
        #[cfg(not(feature = "no-ml"))]
        if ML_ENABLED.load(Ordering::Acquire) && state.cam_valid {
            let outcome = ml_link.cycle(state.cam_dist_front, state.cam_dist_right);
            mlp_result = ml_link.verdict(outcome);
            ml_outcome = Some(outcome);
        }
        #[cfg(not(feature = "no-ml"))]
        {
            ml_ticks += azos_drv_sys::timebase::now().wrapping_sub(t_inf);
            step_stats.ml.add(ml_ticks);
        }

        // ── 3b. Geofence breach latches the stop ─────────────────────────
        //
        // L0 already commands (0, 0) while the reading says Outside, and that
        // alone released the machine as soon as it stopped saying so — a fix
        // going stale was enough. Owner decision 2026-09-16: a breach latches
        // the e-stop and is recorded, so it takes an operator to move again.
        // One record per breach: the latch itself is the guard.
        if let Some(overshoot_m) = azos_behavior::safety::geofence_breach_latch(&state) {
            let _ = azos_behavior::logger::log_safety_violation_durable(
                azos_behavior::logger::SAFETY_ESTOP,
                azos_behavior::safety::ESTOP_ACTION_GEOFENCE, overshoot_m);
            azos_drv_sys::kwarn!("[SAFETY] geofence breach — motors stopped, envelope latched \
                       ({} m beyond the fence)", overshoot_m);
        }

        // ── 4. Arbitrate ─────────────────────────────────────────────────
        let output = arbitrate(&state, &mlp_result);

        // ── 5. Publish motor command ─────────────────────────────────────
        if output.cmd.valid {
            let sl = output.cmd.speed_l.clamp(-100, 100);
            let sr = output.cmd.speed_r.clamp(-100, 100);
            azos_robot::motor_cmd_publish(sl, sr);

            // Trajectory recording
            let ts_ms = now / 10_000;
            let class_byte = if mlp_result.valid { mlp_result.class } else { 0xFF };
            azos_robot::traj_record(ts_ms, sl, sr, class_byte,
                                        state.odom_dist_mm, state.odom_heading_cdeg);
        }

        // RFC-0027 I1: periodic WCET auto-report (see WCET_AUTOREPORT_INTERVAL_SEC
        // declaration above for rationale). The reports and the bench print
        // through `kconsoleln!` (a person asking for them at the console sees
        // them at any log level), so this unattended trigger runs only in a
        // build that keeps info lines.
        #[cfg(feature = "qemu")]
        if azos_drv_sys::uart::LOG_LEVEL >= azos_drv_sys::uart::level::INFO {
            let now_t = azos_drv_sys::timebase::now();
            if now_t >= wcet_autoreport_deadline {
                wcet_autoreport_deadline = now_t
                    + WCET_AUTOREPORT_INTERVAL_SEC * azos_drv_sys::timebase::TIMER_FREQ;
                azos_drv_sys::wcet::wcet_report();
                azos_drv_sys::wcet::jitter_report();
                step_stats.report();
                #[cfg(not(feature = "no-ml"))]
                ml_link.report();
            }
            // One-shot synthetic bench run.  See bench_run_all_done
            // declaration for rationale.
            if !bench_run_all_done {
                bench_run_all_done = true;
                azos_bench::run_all(BENCH_RUN_ALL_ITERS);
                // K-C5: the auth bench calls `wrap` unkeyed, and under
                // `link-encrypt-enforced` that burns the one-shot (tx, NoKey)
                // announcement slot — the first REAL denial would then print
                // nothing. Re-arm after the synthetic sweep.
                azos_behavior::auth_envelope::reset_denial_announcements();
            }
        }

        // ── Sleep 100ms using IO-wait (not busy yield) ─────────────────
        let step_end = azos_drv_sys::timebase::now();
        step_stats.step(step_end.wrapping_sub(step_t0), step_period);
        #[cfg(not(feature = "no-ml"))]
        if let Some(outcome) = ml_outcome {
            ml_link.observe(outcome, &output, step_end.wrapping_sub(step_t0), step_period);
        }
        let sleep_deadline = step_end
            + azos_drv_sys::timebase::TIMER_FREQ / 10;
        azos_sched::task_block(azos_sched::WaitReason::Timer(sleep_deadline));
    }
}
