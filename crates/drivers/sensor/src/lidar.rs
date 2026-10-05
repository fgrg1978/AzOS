// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! LD19 (LD-06) 2D LiDAR UART driver.
//!
//! The LD19 is a 360° 2D LiDAR with 12m range, connected via UART at 230400 baud.
//! It outputs scan packets continuously at ~10 Hz (full revolution).
//!
//! Packet format (47 bytes):
//!   Header: 0x54 (1B)
//!   VerLen: 0x2C (1B) — version(4b) + point_count(4b), always 12 points
//!   Speed:  u16 LE — rotation speed in degrees/sec × 100
//!   Start angle: u16 LE — start angle in centidegrees
//!   Data:   12 × [distance_mm: u16 LE, intensity: u8] = 36B
//!   End angle: u16 LE — end angle in centidegrees
//!   Timestamp: u16 LE — ms timestamp
//!   CRC8:   u8
//!
//! This driver parses raw UART bytes into scan points and accumulates
//! a full 360° scan buffer that can be read via SYS_SENSOR_READ.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const LD19_HEADER: u8 = 0x54;
const LD19_VERLEN: u8 = 0x2C;
const LD19_POINTS_PER_PACKET: usize = 12;
const LD19_PACKET_SIZE: usize = 47;
/// Centi-degrees in a full revolution (LD19 reports angles in 0.01° units).
const LD19_FULL_TURN_CDEG: u16 = 36000;

/// Maximum scan points in a full revolution buffer.
pub const SCAN_BUF_MAX_POINTS: usize = 360;

/// Each scan point is 4 bytes: angle_cdeg(u16 LE) + distance_mm(u16 LE).
pub const SCAN_POINT_SIZE: usize = 4;

/// Maximum scan data size in bytes.
pub const SCAN_DATA_MAX_BYTES: usize = SCAN_BUF_MAX_POINTS * SCAN_POINT_SIZE;

/// CRC-8 table for LD19 (polynomial 0x4D).
const CRC_TABLE: [u8; 256] = crc8_table();

// ---------------------------------------------------------------------------
// Scan buffer (global, lock-free double buffer)
// ---------------------------------------------------------------------------

/// A single scan point.
#[derive(Copy, Clone, Default)]
pub struct ScanPoint {
    pub angle_cdeg: u16,
    pub distance_mm: u16,
}

/// **U05-13 fix (2026-09-26): a true double buffer, swapped by index.**
///
/// The module doc called this a "lock-free double buffer", but a revolution
/// wrap used to `copy_from_slice` the whole back buffer INTO the front
/// buffer's storage (`SCAN_FRONT[..count].copy_from_slice(&SCAN_BACK[..count])`)
/// while `lidar_read_scan` could be reading `SCAN_FRONT` from a concurrent
/// syscall — a reader could observe a torn mix of two scans, not a memcpy
/// racing nothing. Two fixed buffers now hold storage for BOTH roles;
/// `FRONT_IDX` (0 or 1) says which one is currently "front", and a swap is
/// a single atomic store to `FRONT_IDX` — no bytes move. A concurrent
/// reader either sees the old index (a complete, consistent old scan) or
/// the new one (a complete, consistent new scan); it can no longer observe
/// a buffer half-overwritten by the copy that used to do the swap.
static mut SCAN_BUF: [[ScanPoint; SCAN_BUF_MAX_POINTS]; 2] =
    [[ScanPoint { angle_cdeg: 0, distance_mm: 0 }; SCAN_BUF_MAX_POINTS]; 2];
/// Packs (front buffer index, point count) into one word so a reader gets a
/// consistent PAIR, not two independently-racy loads: reading the index and
/// the count as two separate atomics would let a swap land between them and
/// pair a fresh index with a stale (or not-yet-written) count. Layout:
/// bit 16 = front index (0/1), bits 0..15 = count (max 360, fits easily).
static FRONT_DESC: AtomicU32 = AtomicU32::new(0);
#[inline(always)]
fn front_desc_pack(idx: usize, count: usize) -> u32 {
    ((idx as u32) << 16) | (count as u32)
}
#[inline(always)]
fn front_desc_unpack(desc: u32) -> (usize, usize) {
    (((desc >> 16) & 1) as usize, (desc & 0xFFFF) as usize)
}
static SCAN_BACK_COUNT: AtomicU32 = AtomicU32::new(0);
/// Per buffer: timebase ticks when its FIRST packet of the revolution was
/// parsed — the oldest point in the scan, so a scan's age is never
/// understated. Written when that packet lands in the back buffer, before the
/// swap publishes it.
static SCAN_ACQ: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static SCAN_READY: AtomicBool = AtomicBool::new(false);
static LIDAR_INITIALIZED: AtomicBool = AtomicBool::new(false);

// Packet reassembly state
static mut PKT_BUF: [u8; LD19_PACKET_SIZE] = [0; LD19_PACKET_SIZE];
static mut PKT_IDX: usize = 0;
static mut LAST_END_ANGLE: u16 = 0;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize the LiDAR driver. Called once at boot.
pub fn lidar_init() {
    unsafe {
        PKT_IDX = 0;
        LAST_END_ANGLE = 0;
        SCAN_BACK_COUNT.store(0, Ordering::Relaxed);
    }
    FRONT_DESC.store(0, Ordering::Relaxed);
    SCAN_READY.store(false, Ordering::Release);
    LIDAR_INITIALIZED.store(true, Ordering::Release);
}

/// Check if LiDAR is initialized.
pub fn lidar_is_initialized() -> bool {
    LIDAR_INITIALIZED.load(Ordering::Acquire)
}

/// Feed raw UART bytes from the LiDAR. Call from UART0 IRQ handler or poll loop.
///
/// Parses LD19 packets and accumulates scan points. When a full revolution
/// is detected (angle wraps around), swaps the double buffer.
pub fn lidar_feed(data: &[u8]) {
    if !lidar_is_initialized() { return; }

    for &byte in data {
        unsafe { feed_byte(byte); }
    }
}

/// Read the latest complete scan into a user buffer.
///
/// Writes pairs of (angle_cdeg: u16 LE, distance_mm: u16 LE) into `buf`.
/// Returns the number of bytes written, or 0 if no scan available.
pub fn lidar_read_scan(buf: &mut [u8]) -> usize {
    lidar_read_scan_stamped(buf).0
}

/// [`lidar_read_scan`] and the scan's acquisition time: timebase ticks when
/// the first packet of that revolution was parsed (0 with no scan).
pub fn lidar_read_scan_stamped(buf: &mut [u8]) -> (usize, u64) {
    if !SCAN_READY.load(Ordering::Acquire) {
        return (0, 0);
    }

    let (front, count) = front_desc_unpack(FRONT_DESC.load(Ordering::Acquire));
    let acq = SCAN_ACQ[front].load(Ordering::Relaxed);
    (lidar_copy_front(buf, front, count), acq)
}

fn lidar_copy_front(buf: &mut [u8], front: usize, count: usize) -> usize {
    let needed = count * SCAN_POINT_SIZE;
    if buf.len() < needed {
        return 0;
    }
    unsafe {
        for i in 0..count {
            let pt = &SCAN_BUF[front][i];
            let off = i * SCAN_POINT_SIZE;
            buf[off..off + 2].copy_from_slice(&pt.angle_cdeg.to_le_bytes());
            buf[off + 2..off + 4].copy_from_slice(&pt.distance_mm.to_le_bytes());
        }
    }

    needed
}

/// Called at every revolution swap with `(front buffer, points, acquisition
/// ticks)` of the scan just completed: what a kernel stream publishes
/// (wave 11, SHMRING; `azos_ipc::stream_ring`). Runs in the context that
/// fed the byte (the UART path or the QEMU feeder), so it must not block.
pub type ScanHook = fn(usize, usize, u64);

static SCAN_HOOK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Install the revolution hook ([`ScanHook`]). Once, at boot.
pub fn set_scan_hook(f: ScanHook) {
    SCAN_HOOK.store(f as usize, Ordering::Release);
}

/// Write scan `front` (`count` points, as handed to a [`ScanHook`]) in the
/// `SYS_SENSOR_READ` LiDAR record format to `dst`, at most `room` bytes.
/// Returns the bytes written (whole points only).
///
/// # Safety
/// `dst` must be valid for `room` bytes of writes. Called from the hook, for
/// the buffer the swap just made front: the parser writes the OTHER buffer
/// until the next swap, so this one is stable for the call.
pub unsafe fn lidar_write_scan_raw(front: usize, count: usize, dst: *mut u8, room: usize) -> usize {
    let n = count.min(SCAN_BUF_MAX_POINTS).min(room / SCAN_POINT_SIZE);
    let buf = &*core::ptr::addr_of!(SCAN_BUF);
    for (i, pt) in buf[front & 1][..n].iter().enumerate() {
        let a = pt.angle_cdeg.to_le_bytes();
        let d = pt.distance_mm.to_le_bytes();
        let o = dst.add(i * SCAN_POINT_SIZE);
        core::ptr::write_volatile(o, a[0]);
        core::ptr::write_volatile(o.add(1), a[1]);
        core::ptr::write_volatile(o.add(2), d[0]);
        core::ptr::write_volatile(o.add(3), d[1]);
    }
    n * SCAN_POINT_SIZE
}

/// Packets per synthetic revolution: 30 x 12 points = a full 360-point scan.
pub const SYNTH_PACKETS_PER_REV: u32 = (SCAN_BUF_MAX_POINTS / LD19_POINTS_PER_PACKET) as u32;

/// A valid LD19 packet for the QEMU feeder (Kconfig `LIDAR_SIM`) and the host
/// tests: packet `pkt` of revolution `rev`, `start = pkt * 1200` cdeg, and
/// point `i` of the revolution carrying `distance_mm = synth_distance(rev, i)`
/// so a consumer can check a scan is whole and in order.
pub fn ld19_synth_packet(rev: u32, pkt: u32, out: &mut [u8; LD19_PACKET_SIZE]) {
    let start = (pkt * 1200) as u16;
    let end = start + 1100;
    out[0] = LD19_HEADER;
    out[1] = LD19_VERLEN;
    out[2..4].copy_from_slice(&3600u16.to_le_bytes()); // 10 rev/s
    out[4..6].copy_from_slice(&start.to_le_bytes());
    for i in 0..LD19_POINTS_PER_PACKET {
        let d = synth_distance(rev, pkt * LD19_POINTS_PER_PACKET as u32 + i as u32);
        out[6 + i * 3..8 + i * 3].copy_from_slice(&d.to_le_bytes());
        out[8 + i * 3] = 200; // intensity
    }
    out[42..44].copy_from_slice(&end.to_le_bytes());
    out[44..46].copy_from_slice(&((rev * 100) as u16).to_le_bytes());
    out[46] = crc8_compute(&out[..LD19_PACKET_SIZE - 1]);
}

/// The distance [`ld19_synth_packet`] gives point `index` (0..360) of
/// revolution `rev`: `rev` mod 64 in the top 6 bits, `index` in the low 10.
pub const fn synth_distance(rev: u32, index: u32) -> u16 {
    (((rev & 0x3F) << 10) | (index & 0x3FF)) as u16
}

/// Packet size of an LD19 packet, for feeders.
pub const LD19_PACKET_BYTES: usize = LD19_PACKET_SIZE;

/// Number of points in the latest complete scan.
pub fn lidar_scan_count() -> usize {
    front_desc_unpack(FRONT_DESC.load(Ordering::Acquire)).1
}

// ---------------------------------------------------------------------------
// Internal: packet parsing
// ---------------------------------------------------------------------------

unsafe fn feed_byte(byte: u8) {
    let idx = PKT_IDX;

    // Sync to header
    if idx == 0 {
        if byte == LD19_HEADER {
            PKT_BUF[0] = byte;
            PKT_IDX = 1;
        }
        return;
    }

    // Verify second byte (verlen)
    if idx == 1 && byte != LD19_VERLEN {
        PKT_IDX = 0;
        return;
    }

    PKT_BUF[idx] = byte;
    PKT_IDX = idx + 1;

    if PKT_IDX >= LD19_PACKET_SIZE {
        PKT_IDX = 0;
        process_packet();
    }
}

unsafe fn process_packet() {
    // Verify CRC
    let crc = crc8_compute(&PKT_BUF[..LD19_PACKET_SIZE - 1]);
    if crc != PKT_BUF[LD19_PACKET_SIZE - 1] {
        return; // bad CRC
    }

    // Parse header fields
    let start_angle = u16::from_le_bytes([PKT_BUF[4], PKT_BUF[5]]);
    let end_angle = u16::from_le_bytes([PKT_BUF[42], PKT_BUF[43]]);

    // CRC-8 catches bit-flips but not out-of-range values. Reject a packet
    // whose angles exceed a full turn: the u32 arithmetic below stays exact,
    // but a bogus angle would still poison the interpolated scan points.
    if start_angle >= LD19_FULL_TURN_CDEG || end_angle >= LD19_FULL_TURN_CDEG {
        return;
    }

    // Detect revolution wrap: end_angle < last_end_angle → new scan.
    // The buffer currently being WRITTEN (the "back" one, index
    // `1 - front`) becomes the new front by flipping `FRONT_DESC` in one
    // atomic store — no bytes move, so a concurrent `lidar_read_scan` can
    // never observe a half-copied buffer (U05-13).
    if end_angle < LAST_END_ANGLE && SCAN_BACK_COUNT.load(Ordering::Relaxed) > 0 {
        let count = SCAN_BACK_COUNT.load(Ordering::Relaxed) as usize;
        let old_front = front_desc_unpack(FRONT_DESC.load(Ordering::Relaxed)).0;
        let new_front = 1 - old_front;
        FRONT_DESC.store(front_desc_pack(new_front, count), Ordering::Release);
        SCAN_BACK_COUNT.store(0, Ordering::Relaxed);
        SCAN_READY.store(true, Ordering::Release);
        // Wave 11 (SHMRING): the completed revolution to whoever streams it.
        let hook = SCAN_HOOK.load(Ordering::Acquire);
        if hook != 0 {
            // SAFETY: only `set_scan_hook` stores a non-zero value, a `ScanHook`.
            let f: ScanHook = core::mem::transmute::<usize, ScanHook>(hook);
            f(new_front, count, SCAN_ACQ[new_front].load(Ordering::Relaxed));
        }
    }
    LAST_END_ANGLE = end_angle;

    // Interpolate angles for the 12 points in this packet
    // Computed in u32: `LD19_FULL_TURN_CDEG + end_angle` overflows u16.
    let angle_step: u32 = if end_angle >= start_angle {
        (end_angle as u32 - start_angle as u32) / LD19_POINTS_PER_PACKET as u32
    } else {
        (LD19_FULL_TURN_CDEG as u32 + end_angle as u32 - start_angle as u32)
            / LD19_POINTS_PER_PACKET as u32
    };

    // Parse 12 data points (each 3 bytes: distance_mm u16 LE + intensity u8).
    // Written into whichever buffer is currently NOT the front — the
    // producer never touches the buffer a concurrent reader might be
    // looking at (see the swap above).
    let write_idx = 1 - front_desc_unpack(FRONT_DESC.load(Ordering::Relaxed)).0;
    let back_idx = SCAN_BACK_COUNT.load(Ordering::Relaxed) as usize;
    if back_idx == 0 {
        // The revolution's first packet: its acquisition time. Published to
        // readers by the `Release` store of the swap that later makes this
        // buffer the front.
        SCAN_ACQ[write_idx].store(azos_drv_sys::timebase::now(), Ordering::Relaxed);
    }
    let data_start = 6; // offset of first point in packet

    for i in 0..LD19_POINTS_PER_PACKET {
        let pt_idx = back_idx + i;
        if pt_idx >= SCAN_BUF_MAX_POINTS {
            break;
        }

        let off = data_start + i * 3;
        let distance_mm = u16::from_le_bytes([PKT_BUF[off], PKT_BUF[off + 1]]);
        // intensity at PKT_BUF[off + 2] — ignored for now

        let angle_cdeg =
            ((start_angle as u32 + i as u32 * angle_step) % LD19_FULL_TURN_CDEG as u32) as u16;

        SCAN_BUF[write_idx][pt_idx] = ScanPoint { angle_cdeg, distance_mm };
    }

    let new_count = (back_idx + LD19_POINTS_PER_PACKET).min(SCAN_BUF_MAX_POINTS);
    SCAN_BACK_COUNT.store(new_count as u32, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// CRC-8 (polynomial 0x4D, used by LD19)
// ---------------------------------------------------------------------------

fn crc8_compute(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &b in data {
        crc = CRC_TABLE[(crc ^ b) as usize];
    }
    crc
}

const fn crc8_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i: usize = 0;
    while i < 256 {
        let mut crc = i as u8;
        let mut j = 0;
        while j < 8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x4D;
            } else {
                crc <<= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}
