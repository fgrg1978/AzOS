// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
#![no_std]

//! F27 — Tracing + Profiling tooling.
//!
//! In-kernel fixed-size ring buffer of tracing events. Designed for
//! post-mortem debugging and lightweight perf profiling.
//!
//! # Design
//! - 512-entry power-of-two ring (mask instead of modulo for speed).
//! - 32-byte fixed record: 8-byte CLINT timestamp + 2-byte event type + 22 bytes payload.
//! - `TRACE_ENABLED` gate makes the hot path a single relaxed atomic load
//!   + early return when disabled (≤10 cycles on RISC-V).
//! - Dump to UART or FAT32 on demand (shell command / panic path).
//!
//! # Binary file format
//! ```text
//! [0..4]   magic  "TRC1"        (4 B)
//! [4..6]   version u16 LE       = 1
//! [6..8]   reserved u16         = 0
//! [8..16]  start_ts u64 LE      (CLINT ticks, dump time)
//! [16..]   N × 32-byte records (oldest → newest at dump time)
//! ```

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use azos_sync::SpinLock;

// ───────────────────────────────────────────────────────────────────────────
// Event type identifiers — every u16 literal is a named constant.
// ───────────────────────────────────────────────────────────────────────────

pub const TRACE_EVT_SYSCALL_ENTER: u16 = 1;
pub const TRACE_EVT_SYSCALL_EXIT:  u16 = 2;
pub const TRACE_EVT_IRQ_ENTER:     u16 = 3;
pub const TRACE_EVT_IRQ_EXIT:      u16 = 4;
pub const TRACE_EVT_TASK_SWITCH:   u16 = 5;
pub const TRACE_EVT_TASK_WAKE:     u16 = 6;
pub const TRACE_EVT_IO_START:      u16 = 7;
pub const TRACE_EVT_IO_END:        u16 = 8;
pub const TRACE_EVT_USER_EVENT:    u16 = 9;

// ───────────────────────────────────────────────────────────────────────────
// Ring buffer layout.
// ───────────────────────────────────────────────────────────────────────────

/// Power-of-two ring capacity (mask = capacity − 1).
pub const TRACE_RING_CAPACITY: usize = 512;
pub const TRACE_RING_MASK:     usize = TRACE_RING_CAPACITY - 1;

/// On-wire record size — timestamp + event type + data = 32 bytes.
pub const TRACE_RECORD_SIZE: usize = 32;
/// Payload bytes after the fixed (ts u64 + type u16 + pad u16) header.
pub const TRACE_DATA_BYTES:  usize = 20;

/// File format constants.
pub const TRACE_FILE_MAGIC:   &[u8; 4] = b"TRC1";
pub const TRACE_FILE_VERSION: u16      = 1;
pub const TRACE_FILE_HEADER_BYTES: usize = 16;

/// Default file path for `dump_fat32()` when no explicit path is passed.
pub const TRACE_DEFAULT_PATH: &[u8] = b"/TRACE/TRACE000.BIN";

// ───────────────────────────────────────────────────────────────────────────
// Event record.
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct TraceEvent {
    pub ts:         u64,
    pub event_type: u16,
    pub data:       [u8; TRACE_DATA_BYTES],
}

impl TraceEvent {
    pub const fn zeroed() -> Self {
        Self { ts: 0, event_type: 0, data: [0; TRACE_DATA_BYTES] }
    }

    /// Encode into a fixed 32-byte slot (little-endian).
    pub fn encode(&self, out: &mut [u8; TRACE_RECORD_SIZE]) {
        out[0..8].copy_from_slice(&self.ts.to_le_bytes());
        out[8..10].copy_from_slice(&self.event_type.to_le_bytes());
        out[10] = 0; out[11] = 0;
        out[12..32].copy_from_slice(&self.data);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Ring buffer.
// ───────────────────────────────────────────────────────────────────────────

struct TraceRing {
    events: [TraceEvent; TRACE_RING_CAPACITY],
    head:   usize,  // next write slot (mod MASK)
    count:  usize,  // records stored (capped at capacity)
}

impl TraceRing {
    const fn new() -> Self {
        Self {
            events: [TraceEvent::zeroed(); TRACE_RING_CAPACITY],
            head:   0,
            count:  0,
        }
    }

    fn push(&mut self, ev: TraceEvent) {
        self.events[self.head] = ev;
        self.head = (self.head + 1) & TRACE_RING_MASK;
        if self.count < TRACE_RING_CAPACITY {
            self.count += 1;
        }
    }

    /// Copy ring contents (oldest → newest) into `out`. Returns records copied.
    fn snapshot(&self, out: &mut [TraceEvent]) -> usize {
        let n = core::cmp::min(self.count, out.len());
        // Oldest record index = head - count (wrapped).
        let start = if self.count < TRACE_RING_CAPACITY {
            0
        } else {
            self.head
        };
        for i in 0..n {
            out[i] = self.events[(start + i) & TRACE_RING_MASK];
        }
        n
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Global state.
// ───────────────────────────────────────────────────────────────────────────

static TRACE_RING:    SpinLock<TraceRing> = SpinLock::new(TraceRing::new());
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_DROPPED: AtomicU64  = AtomicU64::new(0);
static TRACE_TOTAL:   AtomicU64  = AtomicU64::new(0);

// ───────────────────────────────────────────────────────────────────────────
// Public API.
// ───────────────────────────────────────────────────────────────────────────

/// Initialise the tracer (does not enable it; call `enable()`).
pub fn init() {
    TRACE_TOTAL.store(0, Ordering::Relaxed);
    TRACE_DROPPED.store(0, Ordering::Relaxed);
}

/// Turn tracing on — event calls start recording.
pub fn enable()  { TRACE_ENABLED.store(true,  Ordering::Release); }
/// Turn tracing off — event calls become no-ops (single atomic load).
pub fn disable() { TRACE_ENABLED.store(false, Ordering::Release); }
/// Is tracing currently active?
pub fn is_enabled() -> bool { TRACE_ENABLED.load(Ordering::Acquire) }

/// Record an event. The hot path is a single relaxed load + early-return when
/// disabled, so keep this cheap at call sites.
#[inline]
pub fn record(event_type: u16, data: &[u8]) {
    if !TRACE_ENABLED.load(Ordering::Relaxed) { return; }
    let mut ev = TraceEvent {
        ts: azos_drv_sys::timebase::now(),
        event_type,
        data: [0; TRACE_DATA_BYTES],
    };
    let n = core::cmp::min(data.len(), TRACE_DATA_BYTES);
    ev.data[..n].copy_from_slice(&data[..n]);

    TRACE_RING.lock().push(ev);
    TRACE_TOTAL.fetch_add(1, Ordering::Relaxed);
}

/// Mark that an event was dropped before making it into the ring
/// (used by callers that guard themselves due to spinlock contention).
pub fn record_dropped() {
    TRACE_DROPPED.fetch_add(1, Ordering::Relaxed);
}

// ───────────────────────────────────────────────────────────────────────────
// Statistics.
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct TraceStats {
    pub total_events:   u64,
    pub dropped_events: u64,
    pub in_buffer:      u32,
    pub capacity:       u32,
    pub enabled:        bool,
}

pub fn stats() -> TraceStats {
    TraceStats {
        total_events:   TRACE_TOTAL.load(Ordering::Relaxed),
        dropped_events: TRACE_DROPPED.load(Ordering::Relaxed),
        in_buffer:      TRACE_RING.lock().count as u32,
        capacity:       TRACE_RING_CAPACITY as u32,
        enabled:        is_enabled(),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Dump to FAT32.
// ───────────────────────────────────────────────────────────────────────────

/// Dump the ring to a FAT32 file. Returns bytes written on success.
pub fn dump_fat32(path: &[u8]) -> Result<u32, azos_fs::FsError> {
    use azos_fs::{
        fat32_mount_volume, fat32_open, fat32_write, fat32_fsync,
        fat32_close, fat32_mkdir, open_flags,
    };

    let vol = fat32_mount_volume()?;
    let _ = fat32_mkdir(vol, b"/TRACE");

    let flags = open_flags::WRITE | open_flags::CREATE | open_flags::TRUNCATE;
    let file = fat32_open(vol, path, flags)?;

    // File header.
    let mut hdr = [0u8; TRACE_FILE_HEADER_BYTES];
    hdr[0..4].copy_from_slice(TRACE_FILE_MAGIC);
    hdr[4..6].copy_from_slice(&TRACE_FILE_VERSION.to_le_bytes());
    hdr[6..8].copy_from_slice(&0u16.to_le_bytes());
    hdr[8..16].copy_from_slice(&azos_drv_sys::timebase::now().to_le_bytes());
    let mut total = fat32_write(file, &hdr)? as u32;

    // Snapshot + encode + write records.
    let mut snap: [TraceEvent; TRACE_RING_CAPACITY] =
        [TraceEvent::zeroed(); TRACE_RING_CAPACITY];
    let n = TRACE_RING.lock().snapshot(&mut snap);

    let mut buf = [0u8; TRACE_RECORD_SIZE];
    for ev in snap.iter().take(n) {
        ev.encode(&mut buf);
        total += fat32_write(file, &buf)? as u32;
    }

    let _ = fat32_fsync(file);
    let _ = fat32_close(file);
    Ok(total)
}

// ───────────────────────────────────────────────────────────────────────────
// Convenience helpers for hot-path callers.
// ───────────────────────────────────────────────────────────────────────────

/// Shortcut: record a syscall entry with the syscall number as first byte.
#[inline]
pub fn trace_syscall_enter(syscall_num: u32) {
    record(TRACE_EVT_SYSCALL_ENTER, &syscall_num.to_le_bytes());
}

#[inline]
pub fn trace_syscall_exit(syscall_num: u32, retval: i64) {
    let mut data = [0u8; 12];
    data[0..4].copy_from_slice(&syscall_num.to_le_bytes());
    data[4..12].copy_from_slice(&retval.to_le_bytes());
    record(TRACE_EVT_SYSCALL_EXIT, &data);
}

#[inline]
pub fn trace_irq(enter: bool, irq: u32) {
    let kind = if enter { TRACE_EVT_IRQ_ENTER } else { TRACE_EVT_IRQ_EXIT };
    record(kind, &irq.to_le_bytes());
}

#[inline]
pub fn trace_task_switch(from_tid: u32, to_tid: u32) {
    let mut data = [0u8; 8];
    data[0..4].copy_from_slice(&from_tid.to_le_bytes());
    data[4..8].copy_from_slice(&to_tid.to_le_bytes());
    record(TRACE_EVT_TASK_SWITCH, &data);
}

#[inline]
pub fn trace_task_wake(tid: u32) {
    record(TRACE_EVT_TASK_WAKE, &tid.to_le_bytes());
}

#[inline]
pub fn trace_user_event(code: u32, payload: &[u8]) {
    let mut data = [0u8; TRACE_DATA_BYTES];
    data[0..4].copy_from_slice(&code.to_le_bytes());
    let n = core::cmp::min(payload.len(), TRACE_DATA_BYTES - 4);
    data[4..4 + n].copy_from_slice(&payload[..n]);
    record(TRACE_EVT_USER_EVENT, &data);
}

// ───────────────────────────────────────────────────────────────────────────
// trace_event! macro — ergonomic wrapper.
// ───────────────────────────────────────────────────────────────────────────

#[macro_export]
macro_rules! trace_event {
    ($kind:expr) => {
        $crate::record($kind, &[]);
    };
    ($kind:expr, $data:expr) => {
        $crate::record($kind, $data);
    };
}
