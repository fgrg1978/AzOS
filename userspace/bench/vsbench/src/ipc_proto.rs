// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The `ipc-roundtrip` wire protocol: the one constant both halves must agree
//! on.
//!
//! **Its own file because the two halves are two binaries.** Since RFC-0040
//! gap 2 stage 4 the server is `VSSRV.ELF`, not a `fork()`ed child, and it is
//! built from its own crate. This file is pulled into both with `#[path]`, so
//! there is exactly one definition. Declaring it twice is how a benchmark's
//! client and server start measuring different protocols — which RFC-0045
//! records happening to this lane once already.
//!
//! The server loop lives in `serve.rs` beside this, and only `VSSRV.ELF`
//! compiles it: the client never serves, so carrying the loop would leave
//! `SYS_IPC_FAST_ACCEPT`/`_REPLY`/`_REPLY_ACCEPT` in `VSBENCH.ELF`'s seccomp
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

/// The driver-request A/B (wave 11, SHMRING): today's driver path against a
/// shared-memory slot ring, same peer (`VSSRV.ELF`), same 64-byte request.
///
/// `allow(dead_code)`: the Linux build compiles this file and uses only the
/// ring half (its server is a forked child, not `VSSRV.ELF`).
#[allow(dead_code)]
pub mod drv {
    /// Fast call `[DRV_SETUP, n, 0, 0]`: the server registers as the
    /// power-monitor driver (`DRV_KIND_POWER_MON`, its topology row's
    /// `drv.17`), answers `DRV_SETUP + 1` (or the negative refusal), serves
    /// exactly `n` driver requests from `SYS_DRIVER_REPLY_WAIT` (610), and
    /// goes back to fast calls. The client's requests are
    /// `SYS_SENSOR_READ_TYPED(sensor.9)`, which the kernel turns into a
    /// `UserDriverProxy` call: the path a ring-3 client has to a ring-3
    /// driver today.
    pub const DRV_SETUP: u64 = 0x4452_5600_0000_0001; // "DRV"
    /// Fast call whose `a5` MOVES the slot ring's `Cap<Shm>` to the server,
    /// which serves it until [`TAG_STOP`] (as `ring::RING_SETUP`).
    pub const DRVRING_SETUP: u64 = 0x4452_5652_0000_0001; // "DRVR"
    /// Words per slot: a driver request's 64-byte payload.
    pub const DRV_WORDS: usize = 8;
    /// Slots per ring; two rings share one page (256 + 16 x 64 bytes each).
    pub const DRV_RING_CAP: u32 = 16;
    /// The reply ring's offset in the page; the request ring is at 0.
    pub const DRV_RESP_OFFSET: usize = 2048;
    /// Word 0 of a request: the tag in the top byte, a sequence number below.
    /// Answer: every word `+ 1` (so the whole slot is checked).
    pub const TAG_CALL: u64 = 1;
    /// Answer the server's `(waits, wakes, timeouts, hart)` in words 0..4:
    /// its kernel entries since the previous `TAG_STATS` was answered, not
    /// counting the wait for this request itself (the stats exchange is not
    /// part of the lane it closes).
    pub const TAG_STATS: u64 = 3;
    /// Answer [`DRV_STOP_ACK`] in word 0 and go back to serving fast calls.
    pub const TAG_STOP: u64 = 4;
    pub const DRV_STOP_ACK: u64 = 0x5354_4F50; // "STOP"
    /// Requests per `drvring-batch8` submission.
    pub const DRV_BATCH: u64 = 8;
    /// The request for sequence number `i`: tag in word 0, a pattern in the
    /// rest, so a torn or misplaced slot shows in the answer. Built as a
    /// literal and checked by a fold, not `[0; 8]` + `==`: those lower to
    /// byte-wise `memset`/`memcmp` here, ~700 instructions per request that
    /// would be charged to the ring (measured, first draft of this lane).
    #[inline(always)]
    pub fn drv_req(tag: u64, i: u64) -> [u64; DRV_WORDS] {
        [(tag << 56) | (i & ((1 << 56) - 1)), i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7]
    }
    /// Is `a` the answer to [`drv_req`]`(TAG_CALL, i)` (every word `+ 1`)?
    #[inline(always)]
    pub fn drv_is_answer(a: &[u64; DRV_WORDS], i: u64) -> bool {
        let q = drv_req(TAG_CALL, i);
        let mut d = 0u64;
        let mut k = 0;
        while k < DRV_WORDS { d |= a[k] ^ q[k].wrapping_add(1); k += 1; }
        d == 0
    }
}

/// The frame-stream lane (wave 11, SHMRING): scan-sized frames one way, on
/// the byte-slot ring a kernel stream uses (`azos_spsc::SpscBytes`, the
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
