// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `ipc-roundtrip` wire protocol: the one constant both halves must agree
//! on.
//!
//! **Its own file because the two halves are two binaries.** The server is an exec'd image, `VSSRV.ELF`, not a `fork()`ed child, and it is
//! built from its own crate. This file is pulled into both with `#[path]`, so
//! there is exactly one definition. Declaring it twice is how a benchmark's
//! client and server start measuring different protocols — which has already
//! happened to this lane once.
//!
//! The server loop lives in `serve.rs` beside this, and only `VSSRV.ELF`
//! compiles it: the client never serves, so carrying the loop would leave
//! `SYS_IPC_ACCEPT`/`_REPLY`/`_REPLY_ACCEPT` in `VSBENCH.ELF`'s seccomp
//! profile as authority nothing needs.

/// First word of the request that tells the server to stop.
///
/// The number of round trips that actually reach the server is not known in
/// advance, so client and server would otherwise disagree and the last call
/// would block on a peer that had already exited. The sentinel makes
/// termination an explicit part of the protocol instead of something both
/// sides infer.
pub const IPC_SENTINEL: u64 = u64::MAX;

/// The shm-ring lanes' protocol (wave 6), for the same reason as the
/// sentinel: one definition, two binaries.
///
/// `allow(dead_code)`: the Linux build of `vsbench` compiles this file and has
/// no ring lanes; both AzOS binaries use every item.
#[allow(dead_code)]
pub mod ring {
    /// First word of the fast call that MOVES the ring's `Cap<Shm>` to the
    /// server (in `a5`). The server maps it, answers `RING_SETUP + 1`, and
    /// serves the ring until [`TAG_STOP`]. Not near `u64::MAX`: the reply's
    /// first word shares `a0` with the error code, so `+ 1` must stay positive.
    pub const RING_SETUP: u64 = 0x5249_4E47_0000_0001; // "RING"
    /// Slots per ring; two rings share one page.
    pub const RING_CAP: u32 = 128;
    /// The response ring's offset in the page; the request ring is at 0.
    pub const RING_RESP_OFFSET: usize = 2048;
    /// Echo `v + 1` on the response ring.
    pub const TAG_PING: u64 = 1;
    /// Count, answer nothing.
    pub const TAG_STREAM: u64 = 2;
    /// Answer `(items << 32) | kernel entries` since the first stream item,
    /// then the server's hart.
    pub const TAG_STREAM_END: u64 = 3;
    /// Answer [`RING_STOP_ACK`] and go back to serving fast calls.
    pub const TAG_STOP: u64 = 4;
    pub const RING_STOP_ACK: u64 = 0x5354_4F50; // "STOP"
    /// `tag` in the top byte, `v` below it.
    pub const fn ring_tag(tag: u64, v: u64) -> u64 { (tag << 56) | (v & ((1 << 56) - 1)) }
}

/// The frame-stream lane (wave 11, SHMRING): scan-sized frames one way, on
/// the byte-slot ring a kernel stream uses (`azos_rings::region::SpscBytes`, the
/// same `BytesProducer`).
#[allow(dead_code)]
pub mod frame {
    /// Fast call `[FRAME_SETUP, n, 0, 0]` whose `a5` MOVES the ring's
    /// `Cap<Shm>`: the server maps it, sets the ring up (producer side),
    /// answers `FRAME_SETUP + 1`, publishes `n` frames waiting whenever the
    /// ring is full, then one stats frame, and goes back to fast calls.
    pub const FRAME_SETUP: u64 = 0x4652_4D00_0000_0001; // "FRM"
    /// Slots in the frame ring (the LiDAR stream's).
    pub const FRAME_RING_SLOTS: u32 = 16;
    /// One LiDAR revolution: 360 points of 4 bytes.
    pub const FRAME_BYTES: usize = 1440;
    /// Bytes per slot: the frame and the 16-byte slot header, on 64-byte lines.
    pub const FRAME_SLOT_BYTES: u32 = 1472;
    /// The ring's span: header + 16 slots.
    pub const FRAME_RING_BYTES: usize = 256 + 16 * 1472;
    /// The stats frame's length: `(waits, wakes)` of the producer, two u64s.
    pub const FRAME_STATS_BYTES: usize = 16;
    /// Word `k` of frame `i`: a pattern a torn or misplaced frame breaks.
    #[inline(always)]
    pub const fn frame_word(i: u64, k: usize) -> u64 { (i << 16) | k as u64 }
    /// Write frame `i` (word by word: the slot payload is 8-byte aligned) at
    /// `dst`, at most `room` bytes. The producer's fill.
    #[inline(always)]
    pub fn frame_fill(dst: *mut u8, room: usize, i: u64) -> usize {
        let len = FRAME_BYTES.min(room) & !7;
        let d = dst as *mut u64;
        for k in 0..len / 8 {
            // SAFETY: `dst` has `room` bytes inside the slot, 8-aligned.
            unsafe { d.add(k).write(frame_word(i, k)) };
        }
        len
    }
    /// Is `buf` (length `len`) frame `i`? First and last word, and the length.
    #[inline(always)]
    pub fn frame_ok(buf: &[u8], len: u32, i: u64) -> bool {
        let w = |k: usize| u64::from_le_bytes([buf[k * 8], buf[k * 8 + 1], buf[k * 8 + 2], buf[k * 8 + 3],
                                               buf[k * 8 + 4], buf[k * 8 + 5], buf[k * 8 + 6], buf[k * 8 + 7]]);
        len as usize == FRAME_BYTES && w(0) == frame_word(i, 0) && w(FRAME_BYTES / 8 - 1) == frame_word(i, FRAME_BYTES / 8 - 1)
    }
}
