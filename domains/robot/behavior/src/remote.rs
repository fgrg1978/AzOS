// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! VLA protocol — binary encode/decode for Robot ↔ Server communication.
//!
//! Three packet types:
//! - VlaObservation (Robot → Server): 100 bytes (for 8×4 camera)
//! - VlaAction     (Server → Robot): 32 bytes
//! - VlaGoal       (Server → Robot): 68 bytes

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use azos_sync::SpinLock;
use crate::types::*;

// ── Packet sizes and magic constants ─────────────────────────────────────────

pub const OBS_HEADER_SIZE:  usize = 12;
pub const OBS_PIXELS_SIZE:  usize = 32;   // 8 × 4 grayscale
pub const OBS_SENSORS_SIZE: usize = 56;
pub const OBS_TOTAL:        usize = 100;  // header + pixels + sensors

pub const ACTION_PACKET_SIZE: usize = 32;
pub const GOAL_PACKET_SIZE:   usize = 68;

pub const OBS_MAGIC:  [u8; 4] = *b"RVLA";
pub const ACT_MAGIC:  [u8; 4] = *b"VACT";
pub const GOAL_MAGIC: [u8; 4] = *b"VGOL";

// ── Remote state ─────────────────────────────────────────────────────────────

/// Remote connection info for display.
#[derive(Clone, Copy)]
pub struct RemoteInfo {
    pub enabled:      bool,
    pub server_ip:    [u8; 4],
    pub server_port:  u16,
    pub packets_sent: u32,
    pub packets_recv: u32,
    pub connected:    bool,
    pub socket_fd:    i32,
}

static REMOTE_ENABLED: AtomicBool = AtomicBool::new(false);
static REMOTE_IP:  SpinLock<[u8; 4]> = SpinLock::new([0u8; 4]);
static REMOTE_PORT: AtomicU32 = AtomicU32::new(0);
static PACKETS_SENT: AtomicU32 = AtomicU32::new(0);
static PACKETS_RECV: AtomicU32 = AtomicU32::new(0);
static REMOTE_CONNECTED: AtomicBool = AtomicBool::new(false);
static REMOTE_SOCKET_FD: SpinLock<i32> = SpinLock::new(-1);

static CURRENT_GOAL: SpinLock<VlaGoal> = SpinLock::new(VlaGoal::new());
static LAST_ACTION:  SpinLock<VlaAction> = SpinLock::new(VlaAction::new());

// ── Encode / Decode ──────────────────────────────────────────────────────────

/// Helper: write u16 LE at offset.
fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    let b = v.to_le_bytes();
    buf[off]     = b[0];
    buf[off + 1] = b[1];
}

/// Helper: write i32 LE at offset.
fn put_i32(buf: &mut [u8], off: usize, v: i32) {
    let b = v.to_le_bytes();
    buf[off]     = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
}

/// Helper: write i64 LE at offset.
fn put_i64(buf: &mut [u8], off: usize, v: i64) {
    // copy_from_slice vectorises to a single store on RV64; the
    // hand-rolled byte-by-byte loop did not always inline the bounds
    // check elision the optimiser does for slice ops.
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Helper: read u16 LE from offset.
fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Helper: read i16 LE from offset.
fn get_i16(buf: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([buf[off], buf[off + 1]])
}

/// Helper: read u32 LE from offset.
fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Encode a VlaObservation packet (Robot → Server).
///
/// Serializes the full `SensorState` including camera pixels into the 100-byte
/// wire format.
pub fn encode_observation(state: &SensorState, buf: &mut [u8; OBS_TOTAL]) {
    // Header (12 bytes)
    buf[0..4].copy_from_slice(&OBS_MAGIC);
    put_u16(buf, 4, 1);                        // version
    put_u16(buf, 6, state.cam_w as u16);        // frame_w
    put_u16(buf, 8, state.cam_h as u16);        // frame_h
    put_u16(buf, 10, 0);                        // _pad

    // Pixels (32 bytes at offset 12)
    let n_pixels = (state.cam_w as usize) * (state.cam_h as usize);
    let n = n_pixels.min(OBS_PIXELS_SIZE);
    buf[12..12 + n].copy_from_slice(&state.cam_pixels[..n]);
    // Zero-fill remainder if camera is smaller
    for i in n..OBS_PIXELS_SIZE { buf[12 + i] = 0; }

    // Sensors (56 bytes at offset 44)
    let o = 44;
    put_i32(buf, o,      state.accel_mg[0]);
    put_i32(buf, o + 4,  state.accel_mg[1]);
    put_i32(buf, o + 8,  state.accel_mg[2]);
    put_i32(buf, o + 12, state.gyro_mdps[0]);
    put_i32(buf, o + 16, state.gyro_mdps[1]);
    put_i32(buf, o + 20, state.gyro_mdps[2]);
    put_i64(buf, o + 24, state.odom_dist_mm);
    put_i64(buf, o + 32, state.odom_heading_cdeg);
    put_i32(buf, o + 40, state.enc_left as i32);
    put_i32(buf, o + 44, state.enc_right as i32);
    put_i32(buf, o + 48, state.velocity_mm_s);
    put_u16(buf, o + 52, state.battery_mv);
    put_u16(buf, o + 54, 0);                    // _reserved
}

/// Decode a VlaAction packet (Server → Robot).
///
/// Returns `Some(VlaAction)` if magic and version match, `None` otherwise.
pub fn decode_action_packet(buf: &[u8; ACTION_PACKET_SIZE], timestamp: u64) -> Option<VlaAction> {
    if buf[0..4] != ACT_MAGIC { return None; }

    let cmd       = buf[4];
    let n_actions = buf[5] as usize;
    let _pad      = get_u16(buf, 6);
    let _ = (_pad, n_actions);

    let mut actions = [0i16; 6];
    for i in 0..6 {
        actions[i] = get_i16(buf, 8 + i * 2);
    }

    Some(VlaAction {
        cmd,
        actions,
        received_at: timestamp,
        valid: true,
    })
}

/// Decode a VlaGoal packet (Server → Robot).
///
/// Returns `Some(VlaGoal)` if magic matches, `None` otherwise.
pub fn decode_goal_packet(buf: &[u8; GOAL_PACKET_SIZE]) -> Option<VlaGoal> {
    if buf[0..4] != GOAL_MAGIC { return None; }

    let goal_id  = get_u32(buf, 4);
    let goal_len = get_u32(buf, 8) as u8;
    let text_len = (goal_len as usize).min(56) as u8;

    let mut text = [0u8; 56];
    text[..text_len as usize].copy_from_slice(&buf[12..12 + text_len as usize]);

    Some(VlaGoal {
        goal_id,
        text,
        text_len,
        valid: true,
    })
}

// ── Remote configuration ─────────────────────────────────────────────────────

/// Configure the VLA server address.
///
/// Memory ordering: store the IP/port FIRST, then publish ENABLED with
/// Release semantics. Readers that observe ENABLED=true via Acquire are
/// guaranteed to see the IP/port writes that preceded it. The previous
/// version used Relaxed for the port store, which allowed a reader to
/// observe ENABLED=true with a stale port value (publishing race).
pub fn remote_configure(ip: [u8; 4], port: u16) {
    *REMOTE_IP.lock() = ip;
    REMOTE_PORT.store(port as u32, Ordering::Release);
    REMOTE_ENABLED.store(true, Ordering::Release);
}

/// Enable or disable the remote VLA connection.
pub fn remote_set_enabled(enabled: bool) {
    REMOTE_ENABLED.store(enabled, Ordering::Release);
}

/// Check if remote VLA is enabled.
pub fn remote_is_enabled() -> bool {
    REMOTE_ENABLED.load(Ordering::Acquire)
}

/// Get the configured server IP.
pub fn remote_server_ip() -> [u8; 4] {
    *REMOTE_IP.lock()
}

/// Get the configured server port.
/// Acquire pairs with the Release in `remote_configure` so the port
/// observed here is consistent with REMOTE_ENABLED.
pub fn remote_server_port() -> u16 {
    REMOTE_PORT.load(Ordering::Acquire) as u16
}

/// Record that a packet was sent.
pub fn remote_inc_sent() {
    PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
}

/// Record that a packet was received.
pub fn remote_inc_recv() {
    PACKETS_RECV.fetch_add(1, Ordering::Relaxed);
}

/// Set connection state.
pub fn remote_set_connected(connected: bool) {
    REMOTE_CONNECTED.store(connected, Ordering::Relaxed);
    if !connected {
        // Every drop of the brain link comes through here; the camera
        // connection belongs to the control session and closes with it.
        crate::camera_tx::control_session_ended();
    }
}

/// Store TCP socket FD.
pub fn remote_set_socket(fd: i32) {
    *REMOTE_SOCKET_FD.lock() = fd;
}

/// Get TCP socket FD.
pub fn remote_socket() -> i32 {
    *REMOTE_SOCKET_FD.lock()
}

/// Get remote connection info for status display.
///
/// `enabled` and `server_port` use Acquire to pair with the Release
/// stores in `remote_configure`; counters are Relaxed (statistics with
/// no synchronisation role).
pub fn remote_info() -> RemoteInfo {
    RemoteInfo {
        enabled:      REMOTE_ENABLED.load(Ordering::Acquire),
        server_ip:    *REMOTE_IP.lock(),
        server_port:  REMOTE_PORT.load(Ordering::Acquire) as u16,
        packets_sent: PACKETS_SENT.load(Ordering::Relaxed),
        packets_recv: PACKETS_RECV.load(Ordering::Relaxed),
        connected:    REMOTE_CONNECTED.load(Ordering::Relaxed),
        socket_fd:    *REMOTE_SOCKET_FD.lock(),
    }
}

// ── Goal management ──────────────────────────────────────────────────────────

/// Get the current active goal.
pub fn current_goal() -> VlaGoal {
    *CURRENT_GOAL.lock()
}

/// Set the current active goal.
pub fn set_current_goal(goal: VlaGoal) {
    *CURRENT_GOAL.lock() = goal;
}

/// Get the last received action (for status display).
pub fn last_action() -> VlaAction {
    *LAST_ACTION.lock()
}

/// Store the last received action.
pub fn set_last_action(action: VlaAction) {
    *LAST_ACTION.lock() = action;
}

/// Increment packets sent counter (public alias).
pub fn inc_sent() { remote_inc_sent(); }
/// Increment packets received counter (public alias).
pub fn inc_recv() { remote_inc_recv(); }


// ── What a remote ActuatorCmd means, decided ONCE ───────────────────────
//
// **Lives here and not in `brain_protocol.rs`, on purpose.** That file is the
// WIRE FORMAT and it compiles standalone: `tests/host/regression-tests` and
// `tests/host/behavior-tests` both pull it in with `#[path]` without the rest of
// this crate, and its own comment records the invariant — "no `use crate::*`
// imports". Putting this function there broke both suites, because it needs
// `VlaAction`, which is behaviour state and not wire format. This module
// already owns `last_action`/`set_last_action`, which is exactly the state the
// decision reasons about, so the bridge belongs here.
//
// **This exists because the two call sites had drifted.** The kernel handles
// an `ActuatorCmd` in two places — the TCP brain link and the UART bridge —
// and they were copies. When the emergency path was found to last exactly one
// behaviour tick, the fix (replacing the CACHED action, not just publishing
// zeros) was applied to the TCP copy and the UART copy kept the bug for
// months. One class, two instances, and nothing could tell them apart because
// the logic lived inline in a 1000-line task loop where neither could be
// tested.
//
// Pure on purpose: no locks, no publishing, no globals. It takes what the
// frame said and what the last action was, and returns what should happen.
// The caller does the two side effects. That is what makes it host-testable,
// and the UART side is testable ONLY this way — its transport is
// `cfg(feature = "vf2")` and reads a UART that does not exist on QEMU's virt
// machine, so no scenario can drive it.

/// What the caller must do with a decoded remote `ActuatorCmd`.
#[derive(Clone, Copy)]
pub struct RemoteActuation {
    /// Install this as both `last_action` and the tick's `remote_action`.
    pub action: VlaAction,
    /// Publish `(0, 0)` straight to `CH_MOTOR_CMD`, bypassing L0-L3.
    ///
    /// True only for an emergency, and that IS the override-all-layers
    /// semantic: an ordinary remote command is routed through the subsumption
    /// stack so L1 can veto it, but a stop must not be vetoable.
    pub publish_stop: bool,
}

/// Scale factor from protocol percent to the milli-units `layer_remote_vla`
/// expects. It divides by 10 to get the percent it commands, so a command fed
/// in unscaled ran the robot at a tenth of what was asked.
pub const REMOTE_PCT_TO_MILLI: i32 = 10;

/// The standing action a stop must install — the ONE place it is built.
///
/// Extracted from `remote_actuation_from` so that `safety::estop_activate`
/// installs the identical thing. It was inline, and the consequence was that
/// `FLAG_EMERGENCY` (an `ActuatorCmd` flag) replaced the cached action while
/// `PKT_ESTOP` (a whole packet type, and the harder-hitting of the two) did
/// not — the second instance of a defect whose first instance is documented
/// three lines below.
///
/// `CMD_STOP` with a FRESH `received_at`, both deliberately: L2 invalidates an
/// action older than 2 s and then ABSTAINS, which hands the wheels to L1 and
/// L3, and abstaining is not stopping.
pub fn stop_action(now: u64) -> VlaAction {
    let mut stop = VlaAction::new();
    stop.cmd         = CMD_STOP;
    stop.received_at = now;
    stop.valid       = true;
    stop
}

/// Decide what a remote `ActuatorCmd` should do. Pure.
///
/// **An emergency replaces the cached action, it does not merely zero the
/// wheels.** Publishing `(0,0)` alone lasted one tick: `last_action` still
/// held the previous command with its old timestamp, so `layer_remote_vla`
/// saw a still-unexpired action ~100 ms later and re-published it. The stop
/// has to become the standing action or it is not a stop.
///
/// **And it is `CMD_STOP`, never a zeroed `CMD_MOTOR` or `CMD_NONE`.** L2
/// matches on `cmd`; `CMD_NONE` makes the layer ABSTAIN, and abstaining hands
/// control to L1 and L3 — both of which drive. Abstaining is not stopping.
pub fn remote_actuation_from(cmd: &crate::brain_protocol::ActuatorCmd, prev: VlaAction, now: u64) -> RemoteActuation {
    if cmd.is_emergency() {
        return RemoteActuation { action: stop_action(now), publish_stop: true };
    }

    let (sl, sr) = cmd.diff_drive();
    // Built from the PREVIOUS action rather than from a fresh one: the other
    // `actions[]` slots belong to whatever else feeds this structure, and a
    // remote drive command has no business clearing them.
    let mut action = prev;
    action.cmd         = CMD_MOTOR;
    action.actions[0]  = (sl * REMOTE_PCT_TO_MILLI) as i16;
    action.actions[1]  = (sr * REMOTE_PCT_TO_MILLI) as i16;
    action.received_at = now;
    action.valid       = true;
    RemoteActuation { action, publish_stop: false }
}
