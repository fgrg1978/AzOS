// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_multi_stream` (RFC-0021).
//!
//! Two groups:
//!   * `tests`        — wire-format round-trip and rejection tests.
//!   * `i2_holdoff`   — RFC-0028 (experiment I2) head-of-line hold-off cost
//!                      model. Deterministic: counts work (wire bytes and
//!                      TCP segments), never wall clock.

#[cfg(test)]
mod tests {
    use azos_multi_stream::{
        wrap, unwrap, camera_stream_id, is_camera_stream,
        WrapError,
        HEADER_LEN, MAX_PAYLOAD_LEN,
        STREAM_CONTROL, STREAM_CAMERA_BASE, STREAM_CAMERA_LAST,
        STREAM_CAMERA_COUNT, STREAM_LIDAR, STREAM_AUDIO,
    };

    // ── Helper ────────────────────────────────────────────────────────────────

    /// Wrap then unwrap and check round-trip equality.
    fn roundtrip(stream_id: u8, payload: &[u8]) {
        let mut buf = vec![0u8; HEADER_LEN + payload.len()];
        let written = wrap(stream_id, payload, &mut buf).expect("wrap should succeed");
        assert_eq!(written, HEADER_LEN + payload.len());

        let (got_id, got_len, got_payload) = unwrap(&buf[..written]).expect("unwrap should succeed");
        assert_eq!(got_id, stream_id);
        assert_eq!(got_len, payload.len());
        assert_eq!(got_payload, payload);
    }

    // ── 1. Round-trip: STREAM_CONTROL ────────────────────────────────────────

    #[test]
    fn roundtrip_control_stream() {
        let payload = b"\x01\x00\x05\x00\xDE\xAD\xBE\xEF\x00";
        roundtrip(STREAM_CONTROL, payload);
    }

    // ── 2. Round-trip: first camera stream ───────────────────────────────────

    #[test]
    fn roundtrip_camera_stream_0() {
        let payload = vec![0xFFu8; 128];
        roundtrip(STREAM_CAMERA_BASE, &payload);
    }

    // ── 3. Round-trip: last camera stream ────────────────────────────────────

    #[test]
    fn roundtrip_camera_stream_last() {
        let payload = b"frame-data-last-cam";
        roundtrip(STREAM_CAMERA_LAST, payload);
    }

    // ── 4. Round-trip: LIDAR stream ──────────────────────────────────────────

    #[test]
    fn roundtrip_lidar_stream() {
        let payload = b"lidar-point-cloud";
        roundtrip(STREAM_LIDAR, payload);
    }

    // ── 5. Round-trip: AUDIO stream ──────────────────────────────────────────

    #[test]
    fn roundtrip_audio_stream() {
        let payload = b"pcm-samples";
        roundtrip(STREAM_AUDIO, payload);
    }

    // ── 6. Round-trip: zero-length payload ───────────────────────────────────

    #[test]
    fn roundtrip_zero_length_payload() {
        roundtrip(STREAM_CONTROL, b"");
    }

    // ── 7. Length-extension rejection ────────────────────────────────────────

    #[test]
    fn length_extension_rejected_by_unwrap() {
        // Build a frame that claims 10 bytes but only has 3 bytes of payload.
        let mut frame = vec![0u8; HEADER_LEN + 3];
        frame[0] = STREAM_CONTROL;
        // LEN field says 10.
        let len_le = 10u16.to_le_bytes();
        frame[1] = len_le[0];
        frame[2] = len_le[1];
        // Only 3 bytes of payload present — should be rejected.
        assert!(unwrap(&frame).is_none(), "must reject length-extension frame");
    }

    // ── 8. Too-short frame (no complete header) ───────────────────────────────

    #[test]
    fn malformed_frame_shorter_than_header() {
        assert!(unwrap(&[]).is_none(), "empty slice must be rejected");
        assert!(unwrap(&[STREAM_CONTROL]).is_none(), "1-byte slice must be rejected");
        assert!(unwrap(&[STREAM_CONTROL, 0]).is_none(), "2-byte slice must be rejected");
    }

    // ── 9. Header-only frame (LEN=0) ─────────────────────────────────────────

    #[test]
    fn header_only_frame_unwraps_to_empty_payload() {
        let frame = [STREAM_CAMERA_BASE, 0x00, 0x00]; // LEN = 0
        let (id, len, payload) = unwrap(&frame).expect("valid empty-payload frame");
        assert_eq!(id, STREAM_CAMERA_BASE);
        assert_eq!(len, 0);
        assert!(payload.is_empty());
    }

    // ── 10. PayloadTooLarge error from wrap ───────────────────────────────────

    #[test]
    fn wrap_rejects_payload_exceeding_max_len() {
        // MAX_PAYLOAD_LEN + 1 bytes.
        let oversized = vec![0u8; MAX_PAYLOAD_LEN + 1];
        let mut buf = vec![0u8; HEADER_LEN + MAX_PAYLOAD_LEN + 1];
        let err = wrap(STREAM_CONTROL, &oversized, &mut buf).unwrap_err();
        assert_eq!(err, WrapError::PayloadTooLarge);
    }

    // ── 11. OutputTooSmall error from wrap ────────────────────────────────────

    #[test]
    fn wrap_rejects_output_buffer_too_small() {
        let payload = b"hello";
        let mut buf = [0u8; HEADER_LEN]; // room for header only, not payload
        let err = wrap(STREAM_CONTROL, payload, &mut buf).unwrap_err();
        assert_eq!(err, WrapError::OutputTooSmall);
    }

    // ── 12. camera_stream_id() helper ─────────────────────────────────────────

    #[test]
    fn camera_stream_id_mapping() {
        assert_eq!(camera_stream_id(0), Some(STREAM_CAMERA_BASE));
        assert_eq!(camera_stream_id(STREAM_CAMERA_COUNT - 1), Some(STREAM_CAMERA_LAST));
        assert_eq!(camera_stream_id(STREAM_CAMERA_COUNT), None);
        assert_eq!(camera_stream_id(255), None);
    }

    // ── 13. is_camera_stream() helper ─────────────────────────────────────────

    #[test]
    fn is_camera_stream_boundaries() {
        assert!(!is_camera_stream(STREAM_CONTROL));
        assert!(is_camera_stream(STREAM_CAMERA_BASE));
        assert!(is_camera_stream(STREAM_CAMERA_LAST));
        assert!(!is_camera_stream(STREAM_LIDAR));
        assert!(!is_camera_stream(STREAM_AUDIO));
    }

    // ── 14. LEN field endianness ──────────────────────────────────────────────

    #[test]
    fn len_field_is_little_endian() {
        // A 256-byte payload → LEN = 0x0100 → little-endian bytes [0x00, 0x01].
        const PAYLOAD_LEN: usize = 256;
        let payload = vec![0xBBu8; PAYLOAD_LEN];
        let mut buf = vec![0u8; HEADER_LEN + PAYLOAD_LEN];
        wrap(STREAM_LIDAR, &payload, &mut buf).unwrap();
        assert_eq!(buf[1], 0x00, "len low byte"); // 256 & 0xFF = 0
        assert_eq!(buf[2], 0x01, "len high byte"); // 256 >> 8 = 1
    }

    // ── 15. stream_id passthrough for unknown IDs ─────────────────────────────

    #[test]
    fn unknown_stream_id_passthrough() {
        // The multiplexer does not validate stream_id values; unknown IDs
        // round-trip unchanged so future streams can be added without
        // updating the wrap/unwrap code.
        let future_id: u8 = 0xF0;
        let payload = b"future-stream";
        roundtrip(future_id, payload);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RFC-0028 / experiment I2 — head-of-line hold-off cost model
// ═══════════════════════════════════════════════════════════════════════════
//
// WHY THIS EXISTS
// ---------------
// The I2 verdict rests on a ratio between two `ctrl_holdoff_cyc` samples read
// from `rdcycle` under QEMU TCG SMP-4. RFC-0027 established that `rdcycle`
// under TCG is not a stopwatch (the emulator time-slices other harts inside
// the measured interval), so any threshold expressed in cycles is a claim
// about the host, not about the kernel.
//
// These tests re-derive the same quantity **deterministically** by counting
// work instead of time, using the real `wrap()` encoder from the production
// crate. They answer: how much must go on the wire before the STREAM_CONTROL
// frame is complete, under each policy?
//
// COST MODEL (matches `i2_holdoff_probe` in `kernel/src/tasks/brain_link.rs`)
// --------------------------------------------------------------
// `send_data` never emits more than `TCP_MSS = 1460` payload bytes per
// segment (`crates/net/net/src/tcp.rs`: `TCP_MSS`, `send_data`,
// `send_all_with_yield`), so putting `L` bytes on the wire takes
// `ceil(L / 1460)` segments. How many round trips that is depends on the
// congestion window: one per segment only while the window is one segment.
//
// That distinction is the whole result: the RFC's ≥ 10× target was derived
// from the **byte** ratio (16384 / 1460 ≈ 11.2), but the mechanism it cites
// (TCP segments) makes the **segment** ratio the real one, and the
// 3-byte multi-stream header pushes each 1460-byte chunk to 1463 bytes —
// two segments instead of one. See `holdoff_segment_ratio_is_below_the_rfc_target`.
#[cfg(test)]
mod i2_holdoff {
    use azos_multi_stream::{wrap, HEADER_LEN, STREAM_CAMERA_BASE, STREAM_CONTROL};

    /// `crates/net/net/src/tcp.rs`: `const TCP_MSS: usize = 1460`.
    const TCP_MSS: usize = 1460;

    /// Probe geometry, mirroring `i2_holdoff_probe` in `kernel/src/tasks/brain_link.rs`.
    const BULK: usize = 16 * 1024;
    const CHUNK: usize = 1460;
    const CTRL_PAYLOAD: usize = 32;

    /// Cost of one `send_all_with_yield(buf)` call: the number of segments it
    /// takes to drain `len` bytes.
    fn segments(len: usize) -> usize {
        if len == 0 { 0 } else { len.div_ceil(TCP_MSS) }
    }

    /// What actually precedes (and includes) the control frame on the wire.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Holdoff {
        /// Wire bytes emitted up to and including the control frame's last byte.
        bytes: usize,
        /// TCP segments for the same span.
        segments: usize,
        /// Multi-stream header bytes included in `bytes`.
        header_bytes: usize,
    }

    /// Replay the probe's send sequence through the real `wrap()` encoder.
    ///
    /// `priority == false` → FIFO: the whole bulk frame goes out in chunks,
    /// then the control frame. `priority == true` → the control frame jumps
    /// ahead after the first bulk chunk. Identical control flow to
    /// `i2_holdoff_probe`; only the injection point differs.
    fn holdoff(bulk_len: usize, chunk: usize, priority: bool) -> Holdoff {
        let bulk = vec![0x5Au8; bulk_len];
        let mut wire = vec![0u8; HEADER_LEN + chunk];
        let mut bytes = 0usize;
        let mut segs = 0usize;
        let mut headers = 0usize;

        let mut off = 0usize;
        while off < bulk_len {
            let n = (bulk_len - off).min(chunk);
            let w = wrap(STREAM_CAMERA_BASE, &bulk[off..off + n], &mut wire)
                .expect("bulk chunk must wrap");
            bytes += w;
            segs += segments(w);
            headers += HEADER_LEN;
            off += n;
            if priority {
                break; // control jumps ahead after the first chunk
            }
        }

        let ctrl = [0x42u8; CTRL_PAYLOAD];
        let mut ctrl_wire = [0u8; CTRL_PAYLOAD + HEADER_LEN];
        let cw = wrap(STREAM_CONTROL, &ctrl, &mut ctrl_wire).expect("ctrl must wrap");
        bytes += cw;
        segs += segments(cw);
        headers += HEADER_LEN;

        Holdoff { bytes, segments: segs, header_bytes: headers }
    }

    // ── 16. Exact wire geometry of the probe under each policy ───────────────

    #[test]
    fn holdoff_geometry_is_exact_for_the_probe_configuration() {
        let fifo = holdoff(BULK, CHUNK, false);
        let prio = holdoff(BULK, CHUNK, true);

        // 16384 = 11 × 1460 + 324  →  12 chunk frames.
        // Wrapped: 11 × 1463 + 1 × 327, plus the 35-byte control frame.
        assert_eq!(fifo.bytes, 11 * (CHUNK + HEADER_LEN) + (324 + HEADER_LEN)
                               + (CTRL_PAYLOAD + HEADER_LEN));
        assert_eq!(fifo.bytes, 16_455);
        assert_eq!(prio.bytes, (CHUNK + HEADER_LEN) + (CTRL_PAYLOAD + HEADER_LEN));
        assert_eq!(prio.bytes, 1_498);

        // Segments: a 1463-byte frame does NOT fit one 1460-byte MSS.
        assert_eq!(segments(CHUNK + HEADER_LEN), 2, "the 3 B header spills a chunk into 2 segments");
        assert_eq!(fifo.segments, 11 * 2 + 1 + 1);
        assert_eq!(fifo.segments, 24);
        assert_eq!(prio.segments, 2 + 1);
        assert_eq!(prio.segments, 3);
    }

    // ── 17. The byte ratio — the number the RFC's 10× target came from ───────

    #[test]
    fn holdoff_byte_ratio_is_about_eleven() {
        let fifo = holdoff(BULK, CHUNK, false);
        let prio = holdoff(BULK, CHUNK, true);
        let ratio = fifo.bytes as f64 / prio.bytes as f64;
        // ≈ 16384/1460 ≈ 11.2 — this is the figure the RFC's ≥ 10× target was
        // derived from, and it is the WRONG cost model for a sender that
        // counts in segments.
        assert!((10.9..11.1).contains(&ratio), "byte ratio was {ratio}");
    }

    // ── 18. The segment ratio — the cost model that actually applies ─────────

    #[test]
    fn holdoff_segment_ratio_is_below_the_rfc_target() {
        let fifo = holdoff(BULK, CHUNK, false);
        let prio = holdoff(BULK, CHUNK, true);
        let ratio = fifo.segments as f64 / prio.segments as f64;

        assert_eq!(ratio, 8.0, "24 segments vs 3");
        // RFC-0028's kill criterion #1 is "ratio < 10× → reject". At the
        // probe's own geometry the design CANNOT reach 10×: the ceiling is
        // 8.0×. The QEMU A/B measured a median of 8.4–8.6× across 14 paired
        // boots, which is this ceiling, not noise around 10×.
        assert!(ratio < 10.0, "10× is unreachable at 16 KiB / 1460 B chunks");
    }

    // ── 19. Per-chunk header overhead is negligible on the bulk stream ───────

    #[test]
    fn per_chunk_header_overhead_stays_under_one_percent() {
        let fifo = holdoff(BULK, CHUNK, false);
        // 13 headers (12 bulk chunks + 1 control frame) = 39 B on 16 KiB.
        assert_eq!(fifo.header_bytes, 13 * HEADER_LEN);
        let overhead = fifo.header_bytes as f64 / BULK as f64;
        assert!(overhead < 0.01, "header overhead was {overhead}");
        // …but see test 18: cheap in BYTES, expensive in SEGMENTS. 39 bytes of
        // header cost 11 extra ACK round trips because of MSS spill.
    }

    // ── 20. Smallest bulk frame at which the 10× target becomes reachable ────

    #[test]
    fn ten_x_needs_a_bulk_frame_larger_than_the_one_measured() {
        // Scan bulk sizes in MSS steps; find the first that reaches 10×.
        let mut first_ten_x = None;
        let mut n = 1usize;
        while n <= 32 {
            let bulk_len = n * CHUNK;
            let f = holdoff(bulk_len, CHUNK, false);
            let p = holdoff(bulk_len, CHUNK, true);
            if f.segments as f64 / p.segments as f64 >= 10.0 {
                first_ten_x = Some(bulk_len);
                break;
            }
            n += 1;
        }
        let threshold = first_ten_x.expect("10× must be reachable at some size");
        assert!(
            threshold > BULK,
            "10× is reached at {threshold} B, which must exceed the probe's {BULK} B",
        );
        // Concretely: 15 chunks (21_900 B ≈ 21 KiB). The experiment picked a
        // 16 KiB bulk frame for a target its own geometry could not meet.
        assert_eq!(threshold, 15 * CHUNK);
    }

    // ── 21. The win does grow with frame size (the re-open path) ─────────────

    #[test]
    fn ratio_grows_with_frame_size_for_real_camera_frames() {
        // RFC-0028 cites real camera frames at 50–200 KiB.
        for (bulk_len, min_ratio) in [(50 * 1024, 20.0), (200 * 1024, 90.0)] {
            let f = holdoff(bulk_len, CHUNK, false);
            let p = holdoff(bulk_len, CHUNK, true);
            let ratio = f.segments as f64 / p.segments as f64;
            assert!(
                ratio >= min_ratio,
                "{bulk_len} B bulk gave {ratio}×, expected ≥ {min_ratio}×",
            );
        }
    }

    // ── 22. Chunk size: header-aware chunking LOWERS the ratio ───────────────

    #[test]
    fn header_aware_chunk_size_lowers_the_holdoff_ratio() {
        // RFC-0028 §Unresolved questions asks what chunk size to use. The
        // obvious "fix" for the MSS spill — shrink the payload so the wrapped
        // frame is exactly one MSS — makes the RATIO worse, because the
        // priority arm's floor (1 chunk + 1 control frame) does not shrink
        // proportionally. Fewer round trips overall, smaller inversion win.
        let fitted = CHUNK - HEADER_LEN; // 1457 payload → 1460 on the wire
        assert_eq!(segments(fitted + HEADER_LEN), 1);

        let spill_ratio = {
            let f = holdoff(BULK, CHUNK, false);
            let p = holdoff(BULK, CHUNK, true);
            f.segments as f64 / p.segments as f64
        };
        let fitted_ratio = {
            let f = holdoff(BULK, fitted, false);
            let p = holdoff(BULK, fitted, true);
            f.segments as f64 / p.segments as f64
        };

        assert!(
            fitted_ratio < spill_ratio,
            "fitted {fitted_ratio}× should be below spilling {spill_ratio}×",
        );
        // Absolute cost still drops: 24 → 13 segments for the FIFO arm.
        assert_eq!(holdoff(BULK, fitted, false).segments, 13);
        assert_eq!(holdoff(BULK, fitted, true).segments, 2);
    }

    // ── 23. FIFO cost tracks the full frame; priority cost is constant ───────

    #[test]
    fn priority_holdoff_is_independent_of_bulk_frame_size() {
        // This is the structural claim worth keeping from RFC-0028: under
        // priority the control hold-off is bounded by one chunk, whatever the
        // bulk frame size, while FIFO grows linearly with it.
        let sizes = [4 * 1024, 16 * 1024, 64 * 1024];
        let prio: Vec<usize> = sizes.iter().map(|&b| holdoff(b, CHUNK, true).segments).collect();
        assert!(prio.iter().all(|&s| s == prio[0]), "priority hold-off must be flat: {prio:?}");

        let fifo: Vec<usize> = sizes.iter().map(|&b| holdoff(b, CHUNK, false).segments).collect();
        assert!(fifo[0] < fifo[1] && fifo[1] < fifo[2], "FIFO hold-off must grow: {fifo:?}");
    }
}
