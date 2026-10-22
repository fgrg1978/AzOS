// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Brain Client — userspace ELF that bridges sensor data to the brain server.
//!
//! Runs as a user-mode process on the VF2. Reads sensors via syscalls,
//! builds brain protocol packets, sends over TCP to the macOS brain server,
//! receives ActuatorCmd packets, and applies motor commands.
//!
//! Flow:
//!   loop {
//!     1. sensor read (IMU)         → accel/gyro
//!     2. sensor read (ODOM)        → distance/heading
//!     3. sensor read (ENC)         → encoder ticks
//!     4. sensor read (RANGE)       → front/right mm
//!     5. sensor read (BATT)        → battery mV
//!     6. Build SensorPacket (64 bytes)
//!     7. Frame it: MAGIC + TYPE + LEN + PAYLOAD + CRC8
//!     8. seal it (encrypted-link record, HMAC envelope inside), TCP send
//!     9. TCP recv → open records → verify envelope → parse ActuatorCmd
//!    10. the `motor` endpoints' speed / direction, per wheel; a forward
//!        command also as one io_ring motor entry
//!    11. yield / sleep
//!   }
//!
//! Every connection starts with the encrypted-link handshake (`link.rs`): the brain
//! speaks first, this client answers as the responder, with a fresh
//! ephemeral key from the kernel entropy pool. No handshake, no link.

#![no_std]
#![no_main]

use azos_libsys as sys;
use sys::dev::{MotorCall, MotorClient, Regs};

// The brain link, client side: the same Noise session as the kernel's own link
// (wave 9, owner decision P3; Noise since D9). Every frame this client sends
// or receives is a message of that session, so there is no second MAC.
mod link;

// ── Protocol constants (must match brain_protocol.rs + protocol.py) ──────────
const MAGIC: [u8; 2] = *b"BR";
const PKT_SENSOR: u8 = 0x01;
const PKT_ACTUATOR: u8 = 0x80;
const PKT_CONFIG: u8 = 0x83;

const SENSOR_PAYLOAD_SIZE: usize = 64;
const FRAME_OVERHEAD: usize = 6;        // MAGIC(2) + TYPE(1) + LEN(2) + CRC(1)
const SENSOR_FRAME_SIZE: usize = SENSOR_PAYLOAD_SIZE + FRAME_OVERHEAD; // 70

// Sensor types — re-exported from libsys
use sys::{
    SENSOR_TYPE_IMU, SENSOR_TYPE_ODOM, SENSOR_TYPE_ENCODER,
    SENSOR_TYPE_RANGE, SENSOR_TYPE_BATTERY, SENSOR_TYPE_GPIO_FLAGS,
};

// Actuator command layout
const ACT_HDR_SIZE: usize = 3;          // type(1) + n_channels(1) + flags(1)
const FLAG_EMERGENCY: u8 = 0x01;

// CRC-8/MAXIM polynomial
const CRC8_POLY: u8 = 0x31;

// Network
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;

// Timing
const SENSOR_PERIOD_MS: u64 = 50;       // 20 Hz sensor rate
const CONNECT_RETRY_MS: u64 = 2000;     // retry connection every 2s
/// The WIRE buffer one `recv` fills: sealed frames, reassembled across reads
/// by `link::feed`, so this bounds a read, not a frame.
const RECV_RAW_SIZE: usize = 512;
// Wall-clock rekey interval: one hour, the kernel link's default.
// CONFIG.INI may only SHORTEN it (`brain_client_rekey_secs`); the clamp is
// `azos_crypto::secure_channel::rekey_interval_secs`, host-tested there.

// Motor IDs
const MOTOR_LEFT: u64 = 0;
const MOTOR_RIGHT: u64 = 1;

// ── Motor capabilities ──────────────────────────────────────────────────────

/// The two `motor` endpoint handles, looked up once at startup.
///
/// Looked up once rather than per command: `cap_lookup` is a syscall, and the
/// actuation path runs at the 20 Hz sensor rate with a brain round trip inside
/// it. A handle does not go stale while its holder lives - the generation
/// field exists so that a handle to a REVOKED slot is detected, and nothing
/// revokes these.
///
/// The caps come from the topology's `autorun` task
/// (`crates/core/topology/src/builder.rs:45-46`, `motor.0` / `motor.1`), minted
/// into this task's table by the boot seed at `kernel/src/tasks/loader.rs`.
/// brain_client is the autorun ELF of `$AZOS_OUT/build/disk-braincli.img`
/// (`Makefile:331`), so the seed runs for this process.
static mut CAP_LEFT: u32 = 0;
static mut CAP_RIGHT: u32 = 0;

/// Look up the motor capabilities. Returns false if either is missing.
///
/// **No fallback.** A silent fallback would make
/// the typed path untestable - a boot would look identical whether or not
/// `motor.speed` works - and it would hide the one condition that
/// must not be silent: a client that accepts actuator commands it cannot
/// carry out, including the emergency stop.
fn motor_caps_init() -> bool {
    let (Some(l), Some(r)) = (
        sys::dev::lookup(sys::dev::key::MOTOR, MOTOR_LEFT as u32),
        sys::dev::lookup(sys::dev::key::MOTOR, MOTOR_RIGHT as u32),
    ) else {
        return false;
    };
    // SAFETY: single-threaded ring-3 program; written once before `run()`
    // reaches its connect loop and never again.
    unsafe {
        CAP_LEFT = l;
        CAP_RIGHT = r;
    }
    true
}

/// Stop both motors immediately.
///
/// Through the `Motor` interface's `speed` (register form): the wheel is the
/// endpoint's badge, so this cannot command a motor the topology did not
/// grant. Unlike `pid_target`, which writes PID state for the kernel's motor
/// task to consume, it actuates.
fn motor_stop() {
    // SAFETY: written once by `motor_caps_init`, read by value so no
    // reference to a `static mut` is ever formed.
    let (l, r) = unsafe { (CAP_LEFT, CAP_RIGHT) };
    let _ = MotorClient::new(Regs(l)).speed(0);
    let _ = MotorClient::new(Regs(r)).speed(0);
}

// ── Sensor capabilities ─────────────────────────────────────────────────────

/// The `sensor` endpoint handles `read_all` reads, looked up once at startup, the
/// way the motor handles are. -1 for a sensor the topology did not grant,
/// which is then left unread instead of refused and recorded every tick.
static mut CAP_IMU: isize = -1;
static mut CAP_ODOM: isize = -1;
static mut CAP_ENC: isize = -1;
static mut CAP_RANGE: isize = -1;
static mut CAP_BATT: isize = -1;
static mut CAP_FLAGS: isize = -1;

fn sensor_caps_init() {
    let look = |t: u64| sys::dev::lookup(sys::dev::key::SENSOR, t as u32).map_or(-1, |c| c as isize);
    // SAFETY: single-threaded ring-3 program; written once before `run()`
    // reaches its connect loop and never again.
    unsafe {
        CAP_IMU = look(SENSOR_TYPE_IMU);
        CAP_ODOM = look(SENSOR_TYPE_ODOM);
        CAP_ENC = look(SENSOR_TYPE_ENCODER);
        CAP_RANGE = look(SENSOR_TYPE_RANGE);
        CAP_BATT = look(SENSOR_TYPE_BATTERY);
        CAP_FLAGS = look(SENSOR_TYPE_GPIO_FLAGS);
    }
}

/// Read the sensor behind the `sensor` endpoint `cap`: the bytes of the
/// record, or -1 for one never granted or not ready.
fn read_sensor(cap: isize, buf: &mut [u8]) -> isize {
    if cap < 0 {
        return -1;
    }
    match sys::dev::sensor_read(cap as u32, buf) {
        Ok(s) => s.len as isize,
        Err(_) => -1,
    }
}

// ── The io_ring: the motor entry and the receive poll ───────────────────────
//
// One ring carries both. The ring page is `io_ring::IoRing` in
// `crates/core/ipc/src/io_ring.rs`; `sys::ioring::Ring` is the ring-3 view of
// it (it enters no syscall: every submit below is `sys::ioring_submit_typed`).

/// `user_data` tags: a completion says which entry it is.
const TAG_MOTOR: u64 = 1;
const TAG_RECV: u64 = 2;
const TAG_REGISTER: u64 = 3;

/// The ring's `Cap<IoRing>` and the address of its page in this task, set once
/// by `motor_ring_init`. `RING_VA == 0` means there is no ring.
static mut RING_CAP: u32 = 0;
static mut RING_VA: usize = 0;

/// The ring, if there is one.
fn ring() -> Option<sys::ioring::Ring> {
    // SAFETY: written once by `motor_ring_init` before `run()` reaches its
    // connect loop; read by value.
    let (cap, va) = unsafe { (RING_CAP, RING_VA) };
    (va != 0).then_some(sys::ioring::Ring { cap, va })
}

/// Create the ring. On failure print a `FAILED:` line and carry on
/// without it: the typed calls carry every command, the emergency stop
/// included, so exiting would remove the path that actually has to work.
fn motor_ring_init() {
    let mut addr = [0u8; 8];
    let cap = sys::ioring_create_typed(&mut addr);
    let mut line = Line::new();
    if cap <= 0 {
        line.push(b"[brain_client] FAILED: io_ring create -> rc=");
        line.push_i64(cap as i64);
    } else {
        match sys::ioring::Ring::open(cap as u32, addr) {
            Ok(r) => {
                // SAFETY: single-threaded ring-3 program; written once before
                // `run()` reaches its connect loop and never again.
                unsafe {
                    RING_CAP = r.cap;
                    RING_VA = r.va;
                }
                return;
            }
            Err(_) => {
                line.push(b"[brain_client] FAILED: io_ring create wrote no page address, va=");
                line.push_i64(u64::from_le_bytes(addr) as i64);
            }
        }
    }
    line.push(b"\n");
    sys::print(line.bytes());
}

/// Submit what is pushed and take the completion tagged `tag`:
/// `Some((user_data, result, flags))`, or `None` for a submit the kernel
/// refused or no such completion. **Every completion is consumed, every
/// time**, the ones of other tags (an entry an earlier refused submit left
/// behind) included. The kernel runs an entry only if its completion has room
/// (`cq_tail - cq_head < 32`), so a client that never advanced `cq_head` would
/// drive for 32 commands and then stop executing entries at all.
fn ring_submit(ring: &sys::ioring::Ring, tag: u64) -> Option<sys::ioring::Cqe> {
    let rc = sys::ioring_submit_typed(ring.cap);
    if rc < 0 {
        let mut line = Line::new();
        line.push(b"[brain_client] ioring submit rc=");
        line.push_i64(rc as i64);
        line.push(b"\n");
        sys::print(line.bytes());
        return None;
    }
    let mut mine = None;
    while let Some(cqe) = ring.pop() {
        if cqe.0 == tag {
            mine = Some(cqe);
        }
    }
    mine
}

/// Submit one `OP_MOTOR_SPEED` entry for both wheels and print the
/// completion as `[brain_client] ioring motor cqe result=<r> flags=<f>`.
///
/// The kernel decides the entry the way it decides the typed call: this
/// image's seccomp row must list the `motor.speed` op, this task must
/// hold `motor.0` and `motor.1` with WRITE, and each wheel goes through the
/// motor layer, so a latched e-stop refuses it (`-EAGAIN`, `CQE_F_REFUSED`).
fn motor_ring_submit(left: u32, right: u32) {
    let Some(ring) = ring() else { return };
    // `param0` the left wheel's percentage, `param1` the right's, both driven
    // forward, 0 coasts.
    if !ring.push(sys::ioring::OP_MOTOR_SPEED, left, right, 0, TAG_MOTOR) {
        return;
    }
    if let Some((_, result, flags)) = ring_submit(&ring, TAG_MOTOR) {
        let mut line = Line::new();
        line.push(b"[brain_client] ioring motor cqe result=");
        line.push_i64(result as i64);
        line.push(b" flags=");
        line.push_i64(flags as i64);
        line.push(b"\n");
        sys::print(line.bytes());
    }
}

// ── The receive buffer: registered once, named by slot ─────────────────────

/// The registered buffer's slot and the address it is mapped at here; 0 for
/// none (`recv_buf_init` failed, and the poll uses the typed call).
const RECV_SLOT: u16 = 0;
static mut RECV_VA: usize = 0;

/// Register the receive buffer: one page this task creates and maps,
/// `RECV_RAW_SIZE` bytes of it pinned on the ring as slot [`RECV_SLOT`]. The
/// kernel then fills it on every `OP_NET_RECV` entry with no user range
/// checked and nothing copied; this task reads the bytes where they land.
///
/// On failure print a `FAILED:` line and keep the typed poll, loudly: the link
/// must keep receiving commands.
fn recv_buf_init() {
    let Some(ring) = ring() else { return };
    let mut line = Line::new();
    let shm = sys::shm_create_typed(1, sys::SHM_RW);
    if shm <= 0 {
        line.push(b"[brain_client] FAILED: receive buffer create -> rc=");
        line.push_i64(shm as i64);
        line.push(b"\n");
        sys::print(line.bytes());
        return;
    }
    let va = sys::shm_map_typed(shm as u32);
    if va <= 0 {
        line.push(b"[brain_client] FAILED: receive buffer map -> rc=");
        line.push_i64(va as i64);
        line.push(b"\n");
        sys::print(line.bytes());
        return;
    }
    if !ring.push_register(shm as u32, 0, RECV_RAW_SIZE as u32, RECV_SLOT, TAG_REGISTER) {
        return;
    }
    match ring_submit(&ring, TAG_REGISTER) {
        Some((_, 0, 0)) => {
            // SAFETY: single-threaded ring-3 program; written once before the
            // connect loop.
            unsafe { RECV_VA = va as usize };
        }
        other => {
            line.push(b"[brain_client] FAILED: receive buffer register -> ");
            match other {
                Some((_, result, flags)) => {
                    line.push(b"result=");
                    line.push_i64(result as i64);
                    line.push(b" flags=");
                    line.push_i64(flags as i64);
                }
                None => line.push(b"no completion"),
            }
            line.push(b"\n");
            sys::print(line.bytes());
        }
    }
}

/// Poll the brain link without waiting: one `OP_NET_RECV` entry into the
/// registered buffer. `Some(n)`: `n` bytes are in [`recv_bytes`], or `n <= 0`
/// as `sys::recv_typed` answers (nothing queued, or a link that ended); `None`
/// when there is no registered buffer and the caller polls with the typed call.
fn recv_ring(sock: u32) -> Option<isize> {
    // SAFETY: written once by `recv_buf_init`; read by value.
    if unsafe { RECV_VA } == 0 {
        return None;
    }
    let ring = ring()?;
    if !ring.push_fixed(sys::ioring::OP_NET_RECV, sock, RECV_SLOT, 0, RECV_RAW_SIZE as u32, 0, TAG_RECV) {
        return Some(-1);
    }
    Some(match ring_submit(&ring, TAG_RECV) {
        // A refusal carries `-Errno` as its result: negative, as the typed call's.
        Some((_, result, _)) => result as isize,
        None => -1,
    })
}

/// The `n` bytes the last [`recv_ring`] left in the registered buffer.
fn recv_bytes(n: isize) -> &'static [u8] {
    // SAFETY: `RECV_VA` is this task's mapping of the registered buffer, at
    // least `RECV_RAW_SIZE` bytes, and the kernel writes it only inside
    // `ioring_submit_typed`, which has returned.
    unsafe { core::slice::from_raw_parts(RECV_VA as *const u8, (n.max(0) as usize).min(RECV_RAW_SIZE)) }
}

/// One console line assembled in a buffer, so it goes out in a single
/// `write()` — see `run()` for how a line built from several prints is sliced.
struct Line {
    buf: [u8; 96],
    n: usize,
}

impl Line {
    fn new() -> Self {
        Self { buf: [0; 96], n: 0 }
    }

    fn push(&mut self, s: &[u8]) {
        for &b in s {
            if self.n < self.buf.len() {
                self.buf[self.n] = b;
                self.n += 1;
            }
        }
    }

    fn push_i64(&mut self, v: i64) {
        if v < 0 {
            self.push(b"-");
        }
        let mut u = v.unsigned_abs();
        let mut d = [0u8; 20];
        let mut k = 0;
        loop {
            d[k] = b'0' + (u % 10) as u8;
            u /= 10;
            k += 1;
            if u == 0 {
                break;
            }
        }
        while k > 0 {
            k -= 1;
            self.push(&d[k..k + 1]);
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.buf[..self.n]
    }
}

// ── SockAddr (matches kernel's read_sockaddr: family LE + port BE + addr) ────
#[repr(C)]
struct SockAddr {
    family: u16,        // AF_INET = 2, little-endian
    port: [u8; 2],      // big-endian
    addr: [u8; 4],      // IPv4
    _pad: [u8; 8],
}

impl SockAddr {
    fn new(ip: [u8; 4], port: u16) -> Self {
        Self {
            family: AF_INET as u16,
            port: port.to_be_bytes(),
            addr: ip,
            _pad: [0; 8],
        }
    }

    fn as_bytes(&self) -> &[u8; 16] {
        unsafe { &*(self as *const Self as *const [u8; 16]) }
    }
}

// ── CRC-8/MAXIM ─────────────────────────────────────────────────────────────

fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ CRC8_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ── Little-endian helpers ────────────────────────────────────────────────────

fn put_u16_le(buf: &mut [u8], off: usize, v: u16) {
    let b = v.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
}

fn put_i32_le(buf: &mut [u8], off: usize, v: i32) {
    let b = v.to_le_bytes();
    buf[off..off + 4].copy_from_slice(&b);
}

fn put_u64_le(buf: &mut [u8], off: usize, v: u64) {
    let b = v.to_le_bytes();
    buf[off..off + 8].copy_from_slice(&b);
}

fn put_i64_le(buf: &mut [u8], off: usize, v: i64) {
    let b = v.to_le_bytes();
    buf[off..off + 8].copy_from_slice(&b);
}

fn get_i16_le(buf: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([buf[off], buf[off + 1]])
}

// ── Sensor reading ──────────────────────────────────────────────────────────

struct SensorData {
    accel_mg: [i32; 3],
    gyro_mdps: [i32; 3],
    battery_mv: u16,
    odom_dist_mm: i32,
    odom_heading_cdeg: i32,
    enc_left: i64,
    enc_right: i64,
    range_front: u16,
    range_right: u16,
    sensor_flags: u16,
}

impl SensorData {
    fn new() -> Self {
        Self {
            accel_mg: [0; 3],
            gyro_mdps: [0; 3],
            battery_mv: 0,
            odom_dist_mm: 0,
            odom_heading_cdeg: 0,
            enc_left: 0,
            enc_right: 0,
            range_front: 0,
            range_right: 0,
            sensor_flags: 0,
        }
    }

    fn read_all(&mut self) {
        // IMU: 24 bytes = 6 × i32 LE
        let mut imu_buf = [0u8; 24];
        if read_sensor(unsafe { CAP_IMU }, &mut imu_buf) >= 24 {
            for i in 0..3 {
                self.accel_mg[i] = i32::from_le_bytes([
                    imu_buf[i * 4], imu_buf[i * 4 + 1],
                    imu_buf[i * 4 + 2], imu_buf[i * 4 + 3],
                ]);
                self.gyro_mdps[i] = i32::from_le_bytes([
                    imu_buf[12 + i * 4], imu_buf[13 + i * 4],
                    imu_buf[14 + i * 4], imu_buf[15 + i * 4],
                ]);
            }
        }

        // Odometry: 16 bytes = dist_mm(i64) + heading_cdeg(i64)
        let mut odom_buf = [0u8; 16];
        if read_sensor(unsafe { CAP_ODOM }, &mut odom_buf) >= 16 {
            let dist = i64::from_le_bytes([
                odom_buf[0], odom_buf[1], odom_buf[2], odom_buf[3],
                odom_buf[4], odom_buf[5], odom_buf[6], odom_buf[7],
            ]);
            let hdg = i64::from_le_bytes([
                odom_buf[8], odom_buf[9], odom_buf[10], odom_buf[11],
                odom_buf[12], odom_buf[13], odom_buf[14], odom_buf[15],
            ]);
            self.odom_dist_mm = dist as i32;
            self.odom_heading_cdeg = hdg as i32;
        }

        // Encoders: 16 bytes = enc_l(i64) + enc_r(i64)
        let mut enc_buf = [0u8; 16];
        if read_sensor(unsafe { CAP_ENC }, &mut enc_buf) >= 16 {
            self.enc_left = i64::from_le_bytes([
                enc_buf[0], enc_buf[1], enc_buf[2], enc_buf[3],
                enc_buf[4], enc_buf[5], enc_buf[6], enc_buf[7],
            ]);
            self.enc_right = i64::from_le_bytes([
                enc_buf[8], enc_buf[9], enc_buf[10], enc_buf[11],
                enc_buf[12], enc_buf[13], enc_buf[14], enc_buf[15],
            ]);
        }

        // Rangefinder: 4 bytes = front_mm(u16) + right_mm(u16)
        let mut range_buf = [0u8; 4];
        if read_sensor(unsafe { CAP_RANGE }, &mut range_buf) >= 4 {
            self.range_front = u16::from_le_bytes([range_buf[0], range_buf[1]]);
            self.range_right = u16::from_le_bytes([range_buf[2], range_buf[3]]);
        }

        // Battery: 2 bytes = mv(u16)
        let mut batt_buf = [0u8; 2];
        if read_sensor(unsafe { CAP_BATT }, &mut batt_buf) >= 2 {
            self.battery_mv = u16::from_le_bytes([batt_buf[0], batt_buf[1]]);
        }

        // GPIO sensor flags (PIR/sound/IR)
        let mut flags_buf = [0u8; 2];
        if read_sensor(unsafe { CAP_FLAGS }, &mut flags_buf) >= 2 {
            self.sensor_flags = u16::from_le_bytes([flags_buf[0], flags_buf[1]]);
        } else {
            self.sensor_flags = 0;
        }
    }
}

// ── Packet building ─────────────────────────────────────────────────────────

/// Build SensorPacket payload (64 bytes, matches brain_protocol.rs).
fn build_sensor_payload(buf: &mut [u8; SENSOR_PAYLOAD_SIZE], sensors: &SensorData) {
    let ts_ms = sys::uptime() as u64;

    // Common header (34 bytes)
    put_u64_le(buf, 0, ts_ms);                    // timestamp_ms
    put_i32_le(buf, 8, sensors.accel_mg[0]);       // accel_x
    put_i32_le(buf, 12, sensors.accel_mg[1]);      // accel_y
    put_i32_le(buf, 16, sensors.accel_mg[2]);      // accel_z
    put_i32_le(buf, 20, sensors.gyro_mdps[0]);     // gyro_x
    put_i32_le(buf, 24, sensors.gyro_mdps[1]);     // gyro_y
    put_i32_le(buf, 28, sensors.gyro_mdps[2]);     // gyro_z
    put_u16_le(buf, 32, sensors.battery_mv);       // battery_mv

    // Wheeled extra (30 bytes)
    put_i32_le(buf, 34, sensors.odom_dist_mm);     // odom_dist_mm
    put_i32_le(buf, 38, sensors.odom_heading_cdeg); // odom_hdg_cdeg
    put_i64_le(buf, 42, sensors.enc_left);         // encoder_l
    put_i64_le(buf, 50, sensors.enc_right);        // encoder_r
    put_u16_le(buf, 58, sensors.range_front);      // range_front
    put_u16_le(buf, 60, sensors.range_right);      // range_right
    put_u16_le(buf, 62, sensors.sensor_flags);     // sensor_flags
}

/// Frame a payload: MAGIC(2) + TYPE(1) + LEN(2 LE) + PAYLOAD + CRC8(1).
fn build_frame(
    frame: &mut [u8],
    pkt_type: u8,
    payload: &[u8],
) -> usize {
    let payload_len = payload.len();
    let total = FRAME_OVERHEAD + payload_len;

    frame[0] = MAGIC[0];
    frame[1] = MAGIC[1];
    frame[2] = pkt_type;
    put_u16_le(frame, 3, payload_len as u16);

    frame[5..5 + payload_len].copy_from_slice(payload);

    let crc = crc8(&frame[..5 + payload_len]);
    frame[5 + payload_len] = crc;

    total
}

/// Parse a received frame. Returns (pkt_type, payload_start, payload_len) or None.
fn parse_frame(buf: &[u8], len: usize) -> Option<(u8, usize, usize)> {
    if len < FRAME_OVERHEAD {
        return None;
    }
    if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] {
        return None;
    }
    let pkt_type = buf[2];
    let payload_len = u16::from_le_bytes([buf[3], buf[4]]) as usize;
    let expected_total = FRAME_OVERHEAD + payload_len;
    if len < expected_total {
        return None;
    }
    // Verify CRC
    let crc_idx = 5 + payload_len;
    let computed = crc8(&buf[..crc_idx]);
    if computed != buf[crc_idx] {
        return None;
    }
    Some((pkt_type, 5, payload_len))
}

// ── ActuatorCmd decode ──────────────────────────────────────────────────────

fn apply_actuator_cmd(payload: &[u8]) {
    if payload.len() < ACT_HDR_SIZE {
        return;
    }
    let _act_type = payload[0];
    let n_channels = payload[1] as usize;
    let flags = payload[2];

    if flags & FLAG_EMERGENCY != 0 {
        // **An emergency, told to the kernel AS an emergency.**
        //
        // This used to be `motor_stop()` alone — two `speed(0)` calls the
        // kernel cannot tell apart from "please go at 0%". The
        // difference is not cosmetic: an ordinary zero does not latch, so the
        // next command from anywhere drives again; it does not disarm the ESC;
        // and it leaves NOTHING in the flight recorder, so an incident review
        // cannot see that the brain ever called for a stop. Measured on this
        // exact path: the emergency arrived, the wheels went to zero, and the
        // whole boot log held no e-stop record of any kind.
        //
        // `estop` latches, stops the drivetrain, disarms and records.
        // SAFETY: written once by `motor_caps_init`; read by value.
        let cap_l = unsafe { CAP_LEFT };
        let _ = MotorClient::new(Regs(cap_l)).estop();
        // The direct stop stays as a FALLBACK, not as belt-and-braces: if the
        // kernel refuses the call (no motor capability) or has not armed the
        // handler, this program still does the most it is allowed to do rather
        // than nothing. It is a no-op once the latch is on.
        motor_stop();
        return;
    }

    let ch_data = &payload[ACT_HDR_SIZE..];
    if n_channels >= 2 && ch_data.len() >= 4 {
        // The brain sends signed i16 speeds; the kernel cannot take one.
        //
        // The `speed` op reads an UNSIGNED percentage and drives forward;
        // `motor_set` then clamps with
        // `speed_pct.min(100)`. The old code was `get_i16_le(..) as u64`, so a
        // brain command of -50 ("back up") sign-extended to 0xFFFF...CE and
        // clamped to 100 — the robot drove FULL SPEED FORWARD on a reverse
        // command. Same defect as `userspace/services/reflex`'s motor_backup(); both
        // trusted a libsys doc that claimed the kernel interpreted the sign.
        //
        // Split the sign off explicitly. Direction and speed cannot be sent
        // in one `speed`/`direction` call, so a reverse command becomes
        // `direction(BACKWARD)` at the kernel's fixed 50% and the
        // brain's magnitude is not honoured on that path. A forward command
        // keeps its exact magnitude.
        // SAFETY: written once by `motor_caps_init` before the connect loop;
        // read by value, so no reference to a `static mut` is formed.
        let (cap_l, cap_r) = unsafe { (CAP_LEFT, CAP_RIGHT) };
        let (left, right) = (get_i16_le(ch_data, 0), get_i16_le(ch_data, 2));
        apply_motor_cmd(cap_l, left);
        apply_motor_cmd(cap_r, right);

        // The same command again, as one io_ring entry for both wheels, so the
        // ring's motor path meets the same e-stop latch as the typed calls.
        //
        // Forward only. `OP_MOTOR_SPEED` has no direction and refuses a speed
        // above 100 instead of clamping it, so `-40 as u32` would complete as
        // `-EINVAL`: a refusal that says nothing about the latch, from the
        // sign-extension described above. A reverse command has no ring twin.
        if left >= 0 && right >= 0 {
            motor_ring_submit(left as u32, right as u32);
        }
    }
}

/// Drive one motor from a signed brain command, without ever handing the
/// kernel a sign-extended negative. See `apply_actuator_cmd`.
///
/// Both branches take the wheel from the endpoint `ep`, so neither can name a
/// motor the topology did not grant:
///
/// * Forward goes through `speed` at the requested percentage.
/// * Reverse goes through `direction`, which sets the direction at the
///   kernel's fixed 50%. Not `pid_enable`, which arms the PID loop.
fn apply_motor_cmd(ep: u32, speed: i16) {
    let mut wheel = MotorClient::new(Regs(ep));
    if speed < 0 {
        // Reverse at the kernel's fixed 50% - see above.
        let _ = wheel.direction(sys::dev::motor::DIR_BACKWARD);
    } else {
        // Forward at the requested percentage; the kernel clamps to 100.
        let _ = wheel.speed(speed as u32);
    }
}

// ── Main loop ───────────────────────────────────────────────────────────────

/// Open the brain link as a `Cap<Socket>` and return the raw handle, or -1.
///
/// A handle rather than a socket index: every call below takes it, the kernel
/// refuses an untyped shutdown of the socket behind it, and closing the same
/// handle twice is refused as stale instead of closing whatever socket took
/// the number next. This client reconnects forever, which is exactly the
/// program that used to leak a socket per reconnect.
fn connect_to_brain(ip: [u8; 4], port: u16) -> isize {
    let cap = sys::socket_typed(AF_INET, SOCK_STREAM, 0);
    if cap < 0 {
        return -1;
    }

    // `sys::connect_typed` takes `&[u8; 16]` directly: the kernel's
    // `read_sockaddr` copies exactly 16 bytes and never reads the `addrlen`
    // argument, so the length is not the caller's to get wrong.
    let addr = SockAddr::new(ip, port);
    let ret = sys::connect_typed(cap as u32, addr.as_bytes());
    if ret < 0 {
        sys::close_typed(cap as u32);
        return -1;
    }
    cap
}

fn brain_client_loop(sock: u32) {
    let mut sensors = SensorData::new();
    let mut payload = [0u8; SENSOR_PAYLOAD_SIZE];
    let mut frame = [0u8; SENSOR_FRAME_SIZE];
    let mut recv_raw = [0u8; RECV_RAW_SIZE]; // the typed poll's buffer, when none is registered.

    loop {
        // 1. Read all sensors
        sensors.read_all();

        // 2. Build, seal and send SensorPacket
        build_sensor_payload(&mut payload, &sensors);
        let frame_len = build_frame(&mut frame, PKT_SENSOR, &payload);
        if !link::seal_frame(sock, &frame[..frame_len]) {
            // Connection lost
            sys::print(b"[brain_client] Send failed, disconnecting\n");
            link::end();
            break;
        }

        // 3. Check for incoming commands (non-blocking receive). Frames are
        // opened in `link::feed` BEFORE this client's own MAGIC/TYPE/LEN/CRC8
        // framing sees a byte; a frame that fails the AEAD ends the session.
        let (n, wire): (isize, &[u8]) = match recv_ring(sock) {
            Some(n) => (n, recv_bytes(n)),
            None => {
                let n = sys::recv_typed(sock, &mut recv_raw);
                (n, &recv_raw[..n.max(0) as usize])
            }
        };
        if n > 0 {
            let fed = link::feed(wire, |inner| {
                if let Some((pkt_type, pay_start, pay_len)) = parse_frame(inner, inner.len()) {
                    let payload_slice = &inner[pay_start..pay_start + pay_len];
                    match pkt_type {
                        PKT_ACTUATOR => apply_actuator_cmd(payload_slice),
                        PKT_CONFIG => {
                            // Config commands handled by kernel behavior_task
                            // (buzzer, LED, etc.) — forward via IPC in future
                        }
                        _ => {}
                    }
                }
            });
            if let Err(e) = fed {
                let mut line = Line::new();
                line.push(b"[brain_client] link: transport ");
                line.push(link::end_name(e));
                line.push(b" - closing\n");
                sys::print(line.bytes());
                link::end();
                break;
            }
        } else if n < 0 {
            // Error or connection closed
            sys::print(b"[brain_client] Recv error, disconnecting\n");
            link::end();
            break;
        }

        // 4. Sleep until next sensor period
        sys::sleep(SENSOR_PERIOD_MS);
    }
}

/// Parse `behavior_server_ip` / `behavior_server_port` out of
/// `/fat/CONFIG.INI`. Returns `None` if the file cannot be read or the keys
/// are absent, so the caller can keep its compiled-in default.
/// Format `[brain_client] Brain server A.B.C.D:PORT (CONFIG.INI|default)\n`
/// into `out`, returning the byte count. Built as one buffer so it can go out
/// in a single `write()` and cannot be interleaved mid-line.
fn fmt_addr_line(out: &mut [u8; 96], ip: [u8; 4], port: u16, from_cfg: bool) -> usize {
    let mut n = 0usize;
    let push = |b: u8, n: &mut usize, out: &mut [u8; 96]| {
        if *n < out.len() { out[*n] = b; *n += 1; }
    };
    for &b in b"[brain_client] Brain server " { push(b, &mut n, out); }
    for (i, o) in ip.iter().enumerate() {
        if i > 0 { push(b'.', &mut n, out); }
        let mut v = *o as u32;
        let mut d = [0u8; 3];
        let mut k = 0;
        if v == 0 { d[0] = b'0'; k = 1; }
        while v > 0 { d[k] = b'0' + (v % 10) as u8; v /= 10; k += 1; }
        while k > 0 { k -= 1; push(d[k], &mut n, out); }
    }
    push(b':', &mut n, out);
    let mut v = port as u32;
    let mut d = [0u8; 5];
    let mut k = 0;
    if v == 0 { d[0] = b'0'; k = 1; }
    while v > 0 { d[k] = b'0' + (v % 10) as u8; v /= 10; k += 1; }
    while k > 0 { k -= 1; push(d[k], &mut n, out); }
    let tag: &[u8] = if from_cfg { b" (from CONFIG.INI)\n" } else { b" (compiled-in default)\n" };
    for &b in tag { push(b, &mut n, out); }
    n
}

// ── V1.9: the auth envelope's key, read the same way the kernel reads it ──

/// The entropy endpoint's handle, looked up once by [`entropy_init`].
static mut ENTROPY_CAP: u32 = 0;

/// Look up the entropy endpoint and prove the pool answers, before the first
/// dial.
///
/// Returns the refusal's outcome code on failure: `NO_RESOURCE` when the task
/// holds no capability to the kernel-hosted `entropy` endpoint, `NOT_READY`
/// when the pool is unseeded (no entropy source fed it at boot, and nothing
/// seeds it later in the same boot), or what the interface answered. Every
/// handshake draws its ephemeral key from this pool, so without it there is
/// no link to run.
fn entropy_init() -> Result<(), u32> {
    let Some(ep) = sys::dev::lookup(sys::dev::key::ENTROPY, 0) else {
        return Err(sys::dev::outcome::NO_RESOURCE);
    };
    let mut probe = [0u8; 32];
    let r = sys::dev::entropy_read(ep, &mut probe);
    for b in probe.iter_mut() {
        // SAFETY: valid `&mut u8`; volatile so the wipe is not elided.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    r?;
    // SAFETY: single-threaded process; written once, before the first dial.
    unsafe { ENTROPY_CAP = ep; }
    Ok(())
}

/// The link key, once loaded by [`link_key_init`]. `None` until then (or if
/// the task holds no `linkkey` endpoint, or the kernel answers no key/all-zero)
/// — `run()` refuses to start the receive loop in that case; see its own
/// call site.
static mut LINK_KEY: Option<[u8; 32]> = None;

/// The brain's pinned static Noise key from the signed topology's
/// `[peer.brain]` row, loaded with the link key. `None`: nothing pinned, the
/// link is `Noise_XX`.
static mut BRAIN_PK: Option<[u8; 32]> = None;

/// Load the 32 raw bytes of the brain-link PSK, the SAME reserved sector the
/// kernel's own link reads (`kernel/src/main.rs`), and the brain's pinned
/// static key from the same endpoint.
///
/// U06-9 (2026-09-26): this used to open `/fat/LINK.KEY` directly — the
/// SAME bytes the kernel's own load read, back off the exported FAT volume
/// the reserved sector exists to take them off of. The kernel stopped
/// keeping a FAT copy that day (`kernel/src/reserved_tail.rs`,
/// `LINK_KEY`), so this now goes through
/// the kernel-hosted `linkkey` endpoint instead: look up the endpoint the
/// topology grants the autorun task (singleton, like the motor/sensor caps
/// above — resource `0`), then read through it.
///
/// Returns `false` if the task holds no `linkkey` endpoint, the kernel answers
/// short, or the key is all-zero (the same zero-key trap
/// `safety::operator_authority_init` already refuses — a provisioning step
/// that silently no-ops must not make this EASIER to bypass than a real key
/// would).
fn link_key_init() -> bool {
    let Some(ep) = sys::dev::lookup(sys::dev::key::LINK_KEY, 0) else { return false };
    let mut buf = [0u8; 32];
    if sys::dev::link_key_read(ep, &mut buf).is_err() { return false; }
    if buf.iter().all(|&b| b == 0) { return false; }
    // A failed call is not "nothing pinned": it would downgrade `IK` to `XX`.
    let Ok(pinned) = sys::dev::brain_pk_read(ep) else { return false };
    // SAFETY: single-threaded process; written once here, before
    // `brain_client_loop` (the only reader) can run.
    unsafe {
        LINK_KEY = Some(buf);
        BRAIN_PK = pinned;
    }
    true
}

fn read_brain_addr() -> Option<([u8; 4], u16)> {
    // The trailing NUL is load-bearing: the kernel reads this path with
    // copy_cstr_from_user, i.e. it scans for a terminator rather than using
    // the slice length. Without one the kernel walks past the literal into
    // whatever the linker put next.
    //
    // `sys::cstr!` appends it at compile time so it cannot be forgotten
    // again; `sys::open` also now rejects an unterminated slice outright
    // instead of letting the kernel scan.
    //
    // `open_at` hands back a `Cap<File>` with READ (flags 0), and `read` and
    // `close` take that handle: NODE_OPENAT, NODE_READ and
    // SYS_CAP_CLOSE, so this file and the brain-link socket cannot be
    // mistaken for each other by number.
    let file = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
    if file < 0 { return None; }
    let mut buf = [0u8; 1024];
    let n = sys::read(file as u64, &mut buf);
    sys::close(file as u64);
    if n <= 0 { return None; }
    let data = &buf[..n as usize];

    let ip = find_value(data, b"behavior_server_ip").and_then(parse_ipv4)?;
    // A missing port is not fatal: the IP is the part that was wrong.
    let port = find_value(data, b"behavior_server_port")
        .and_then(parse_u16)
        .unwrap_or(9000);
    Some((ip, port))
}

/// `brain_client_rekey_secs` from `/fat/CONFIG.INI`, through
/// `azos_crypto::secure_channel::rekey_interval_secs`: the one-hour default when the
/// key is absent or unreadable, never longer, never under its 5 s floor.
fn rekey_interval_from_config() -> u64 {
    use azos_crypto::secure_channel::rekey_interval_secs;
    let file = sys::open_root(sys::cstr!(b"/fat/CONFIG.INI"), 0);
    if file < 0 { return rekey_interval_secs(None); }
    let mut buf = [0u8; 1024];
    let n = sys::read(file as u64, &mut buf);
    sys::close(file as u64);
    if n <= 0 { return rekey_interval_secs(None); }
    let requested = find_value(&buf[..n as usize], b"brain_client_rekey_secs")
        .and_then(parse_u16)
        .map(|v| v as u64);
    rekey_interval_secs(requested)
}

/// Value of `key=` on its own line, up to end-of-line. Whitespace-trimmed.
fn find_value<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0usize;
    while i < data.len() {
        // Start of a line.
        let line_start = i;
        while i < data.len() && data[i] != b'\n' { i += 1; }
        let mut line_end = i;
        if i < data.len() { i += 1; } // step over the newline
        // Trim trailing CR/space.
        while line_end > line_start
            && (data[line_end - 1] == b'\r' || data[line_end - 1] == b' ')
        {
            line_end -= 1;
        }
        let line = &data[line_start..line_end];
        if line.len() > key.len()
            && &line[..key.len()] == key
            && line[key.len()] == b'='
        {
            return Some(&line[key.len() + 1..]);
        }
    }
    None
}

fn parse_ipv4(v: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut octet = 0usize;
    let mut acc: u32 = 0;
    let mut digits = 0;
    for &b in v {
        if b == b'.' {
            if digits == 0 || octet >= 3 { return None; }
            out[octet] = acc as u8;
            octet += 1; acc = 0; digits = 0;
        } else if b.is_ascii_digit() {
            acc = acc * 10 + (b - b'0') as u32;
            if acc > 255 { return None; }
            digits += 1;
        } else {
            break;
        }
    }
    if octet != 3 || digits == 0 { return None; }
    out[3] = acc as u8;
    Some(out)
}

fn parse_u16(v: &[u8]) -> Option<u16> {
    let mut acc: u32 = 0;
    let mut digits = 0;
    for &b in v {
        if b.is_ascii_digit() {
            acc = acc * 10 + (b - b'0') as u32;
            if acc > 65535 { return None; }
            digits += 1;
        } else { break; }
    }
    if digits == 0 { None } else { Some(acc as u16) }
}



fn run() {
    sys::println(b"[brain_client] Starting brain protocol client");

    // Before the network, before anything: every motor write below - the
    // emergency stop, the disconnect stop, the panic-handler stop - now goes
    // through the typed call, which needs a handle. Without one this process
    // would accept actuator packets and carry none of them out, and its panic
    // handler would stop nothing while the log still said it had. Refusing to
    // start is the only honest outcome.
    sensor_caps_init();
    if !motor_caps_init() {
        sys::println(b"[brain_client] FATAL no motor capabilities - refusing to run");
        sys::exit(1);
    }
    // After the motor capabilities: every entry on the ring is checked
    // against them.
    motor_ring_init();
    recv_buf_init();

    // V1.9: refuse to start without the link key (or without the brain's
    // pinned key, when the topology pins one). The link is only ever a Noise
    // session keyed from it; without it there is nothing to run, and this is
    // the gate's autorun and the one ring-3 network client that drives the
    // motors, so "refuse to start" is the honest outcome here, same
    // reasoning as the motor capability check two lines up.
    if !link_key_init() {
        sys::println(b"[brain_client] FATAL link key (or the brain key) unavailable - refusing to run");
        sys::exit(1);
    }

    // Wave 9 (P3/P9): every connection runs the Noise handshake with an
    // ephemeral key drawn from the kernel entropy pool. An unseeded pool is
    // refused by the kernel (`NOT_READY`) and does not become seeded later in
    // the boot, so the only honest outcome is not to run the link — the same
    // rule the kernel's own handshake applies on an enforced build.
    if let Err(rc) = entropy_init() {
        let mut line = Line::new();
        line.push(b"[brain_client] FATAL entropy refused outcome=");
        line.push_i64(rc as i64);
        line.push(b" - no fresh keys, refusing to run the link\n");
        sys::print(line.bytes());
        sys::exit(1);
    }
    let rekey_secs = rekey_interval_from_config();

    // Brain server address, read from /fat/CONFIG.INI.
    //
    // This used to be a hardcoded 192.168.1.2 with a "TODO: read from
    // CONFIG.INI" beside it, which meant the client could never reach
    // anything under QEMU (SLIRP puts the host at 10.0.2.2) and silently
    // burned its retry loop against an address that does not exist. The
    // symptom was misleading in a specific way: the log said "Connected!"
    // and then "Send failed", which reads like a transport bug rather than
    // a client aimed at the wrong place.
    //
    // Falls back to the old literal if the file is missing or unparseable,
    // so a deployment that relied on the compiled-in default still behaves
    // as before.
    let from_cfg = read_brain_addr();
    let (brain_ip, brain_port) = from_cfg.unwrap_or(([192, 168, 1, 2], 9000));
    // One write() for the whole line. The UART guard the kernel takes covers
    // a single write; a line assembled from several print calls can still be
    // sliced by another hart's kprintln between them, which is exactly how
    // this line first came out as "Brain server [IPC] service_heartbeat = 0".
    {
        let mut line = [0u8; 96];
        let n = fmt_addr_line(&mut line, brain_ip, brain_port, from_cfg.is_some());
        sys::print(&line[..n]);
    }

    loop {
        sys::print(b"[brain_client] Connecting to brain server...\n");

        let sock = connect_to_brain(brain_ip, brain_port);
        if sock < 0 {
            sys::print(b"[brain_client] Connection failed, retrying...\n");
            sys::sleep(CONNECT_RETRY_MS);
            continue;
        }

        sys::println(b"[brain_client] Connected!");
        let (key, pinned) = unsafe { (LINK_KEY, BRAIN_PK) };
        let Some(key) = key else { sys::exit(1) };
        if link::handshake(sock as u32, unsafe { ENTROPY_CAP }, &key, pinned.as_ref(),
                           rekey_secs.saturating_mul(1_000_000_000)) {
            brain_client_loop(sock as u32);
        } else {
            link::end();
        }

        // Cleanup: revokes the handle and closes the socket in one call.
        sys::close_typed(sock as u32);

        // Stop motors on disconnect
        motor_stop();

        sys::print(b"[brain_client] Disconnected, reconnecting...\n");
        sys::sleep(CONNECT_RETRY_MS);
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn _start() -> ! {
    run();
    sys::exit(0);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys::print(b"[brain_client] PANIC!\n");
    motor_stop();
    sys::exit(1);
}
