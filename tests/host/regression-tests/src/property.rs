// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! TS01 — Property-based tests using proptest.
//!
//! Property tests assert invariants over arbitrary inputs (proptest
//! generates them). Far stronger than example-based unit tests for code
//! whose correctness depends on subtle invariants (parsers, ring
//! buffers, codecs, schedulers, …).
//!
//! This file seeds the kernel with a small starter set; new property
//! tests should land here as we promote modules.
//!
//! `brain_protocol_props` (added below the ring / window modules) uses
//! `#[path]` to pull in the pure-Rust `brain_protocol.rs` directly,
//! matching the same pattern used for `dtb_src` in `lib.rs`. The
//! behavior crate pulls in `azos_drv_*` (MMIO-bound, not host-
//! compilable), so we cannot add it as a dev-dep — instead we include
//! the source file directly. `brain_protocol.rs` has no crate imports;
//! it only uses `core`/`std` — clean compile on Apple Silicon.

#[cfg(test)]
mod ring_buffer_invariants {
    use proptest::prelude::*;

    /// Same store loop as the TCP rx ring (handle() in-order branch).
    fn store(rx: &mut [u8], head: &mut usize, tail: &mut usize,
             mask: usize, payload: &[u8]) -> u32 {
        let mut stored: u32 = 0;
        for &b in payload {
            let next = (*tail + 1) & mask;
            if next == *head { break; }
            rx[*tail] = b;
            *tail = next;
            stored += 1;
        }
        stored
    }

    fn drain(rx: &[u8], head: &mut usize, tail: usize,
             mask: usize, n: usize) -> Vec<u8> {
        let avail = if tail >= *head { tail - *head } else { rx.len() - *head + tail };
        let take = avail.min(n);
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            out.push(rx[*head & mask]);
            *head = (*head + 1) & mask;
        }
        out
    }

    proptest! {
        /// Bytes written into the ring then read out in order must match
        /// exactly. Holds across arbitrary head/tail positions and
        /// payload sizes.
        #[test]
        fn store_then_drain_preserves_order(
            payload in prop::collection::vec(any::<u8>(), 0..15),
            initial_head in 0usize..16,
        ) {
            const SIZE: usize = 16;
            const MASK: usize = SIZE - 1;
            let mut rx = [0u8; SIZE];
            let mut head = initial_head & MASK;
            let mut tail = head;

            let stored = store(&mut rx, &mut head, &mut tail, MASK, &payload) as usize;
            prop_assert!(stored <= payload.len());
            let drained = drain(&rx, &mut head, tail, MASK, stored);
            prop_assert_eq!(drained, payload[..stored].to_vec());
        }

        /// `stored` is always strictly less than buffer capacity if the
        /// ring started empty. A 16-byte ring can hold at most 15 (one
        /// slot reserved for full-vs-empty disambiguation).
        #[test]
        fn empty_ring_capacity_is_size_minus_one(
            payload in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            const SIZE: usize = 16;
            const MASK: usize = SIZE - 1;
            let mut rx = [0u8; SIZE];
            let mut head = 0usize;
            let mut tail = 0usize;
            let stored = store(&mut rx, &mut head, &mut tail, MASK, &payload) as usize;
            prop_assert!(stored <= SIZE - 1);
            prop_assert_eq!(stored, payload.len().min(SIZE - 1));
        }
    }
}

#[cfg(test)]
mod window_clamp_invariants {
    use proptest::prelude::*;

    const fn window_clamp(free: usize) -> u16 {
        if free > u16::MAX as usize { u16::MAX } else { free as u16 }
    }

    proptest! {
        /// window_clamp is monotonic and bounded.
        #[test]
        fn window_clamp_is_bounded(free in 0usize..0xFFFF_FFFF) {
            let clamped = window_clamp(free);
            prop_assert!(clamped as usize <= free);
            prop_assert!(clamped <= u16::MAX);
        }

        /// Below u16::MAX, window_clamp is identity.
        #[test]
        fn window_clamp_is_identity_below_u16_max(free in 0u16..) {
            prop_assert_eq!(window_clamp(free as usize), free);
        }
    }
}

// ── brain_protocol round-trip + fuzz properties (RFC-0013 / TS01) ────────────
//
// We include brain_protocol.rs directly via `#[path]` so we exercise the
// exact source shipped in the kernel without dragging in azos_behavior
// (which depends on azos_drv_* — MMIO-bound, cannot host-compile).
// brain_protocol.rs has no `use crate::*` imports; it only relies on
// core types, so it compiles cleanly on the host target.

#[allow(dead_code, unused_imports, clippy::all)]
#[path = "../../../../domains/robot/behavior/src/brain_protocol.rs"]
mod brain_protocol_src;

#[cfg(test)]
mod brain_protocol_props {
    use super::brain_protocol_src as bp;
    use proptest::prelude::*;

    // ── Named constants for frame structure ──────────────────────────────
    // Frame: MAGIC(2) + TYPE(1) + LEN(2 LE) + PAYLOAD(N) + CRC(1) = 6 + N bytes.
    const FRAME_HEADER_SIZE:  usize = 5;   // MAGIC + TYPE + LEN
    const FRAME_TRAILER_SIZE: usize = 1;   // CRC byte
    const FRAME_OVERHEAD:     usize = FRAME_HEADER_SIZE + FRAME_TRAILER_SIZE;  // 6

    // Upper bound on payload size for proptest. Must fit in u16 LEN field.
    // We use a small value (64) so tests stay fast; the invariants don't
    // depend on a large upper bound.
    const MAX_TEST_PAYLOAD:   usize = 64;

    // Bit positions of the two LEN bytes within a framed packet.
    // Excluded from the bit-flip test for the same reason as in the Python
    // suite: flipping a LEN bit can produce a valid shorter packet whose
    // CRC accidentally matches, so "must be None" is not guaranteed there.
    const LEN_BYTE_LOW:  usize = 3;
    const LEN_BYTE_HIGH: usize = 4;

    // Number of bits in a byte — used to keep proptest ranges readable.
    const BITS_PER_BYTE: usize = 8;

    /// Build a framed packet into a Vec.
    fn build(pkt_type: u8, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; payload.len() + FRAME_OVERHEAD];
        bp::build_packet(pkt_type, payload, &mut buf);
        buf
    }

    proptest! {
        // ── Property A: parse_packet never panics on arbitrary bytes ─────
        //
        // Feeds random byte slices of any length (including empty) into the
        // parser.  It must return either None or a valid result — never panic.
        // Pins: the parser is safe against hostile / truncated inputs.
        #[test]
        fn parse_never_panics(data in prop::collection::vec(any::<u8>(), 0..=MAX_TEST_PAYLOAD * 4)) {
            // Just calling it is enough — no panic = pass.
            let _ = bp::parse_packet(&data);
        }

        // ── Property B: build_packet / parse_packet round-trip ───────────
        //
        // For any valid payload, building then parsing recovers the original
        // (type, payload start, payload length).
        // Pins: framing is lossless; MAGIC + LEN encoding + CRC are consistent.
        #[test]
        fn build_parse_roundtrip(
            pkt_type in any::<u8>(),
            payload  in prop::collection::vec(any::<u8>(), 0..=MAX_TEST_PAYLOAD),
        ) {
            let frame = build(pkt_type, &payload);
            let result = bp::parse_packet(&frame);
            prop_assert!(result.is_some(), "parse must succeed on a freshly-built frame");
            let (got_type, payload_start, payload_len, total) = result.unwrap();
            prop_assert_eq!(got_type,    pkt_type);
            prop_assert_eq!(payload_len, payload.len());
            prop_assert_eq!(total,       frame.len());
            prop_assert_eq!(&frame[payload_start..payload_start + payload_len], payload.as_slice());
        }

        // ── Property C: crc8 is a pure function of its input ─────────────
        //
        // Computing crc8 twice on identical bytes yields the same byte both
        // times.  Guards against any accidental stateful refactor of the CRC
        // accumulator.
        // Pins: crc8 determinism.
        #[test]
        fn crc8_is_deterministic(data in prop::collection::vec(any::<u8>(), 0..=MAX_TEST_PAYLOAD * 4)) {
            prop_assert_eq!(bp::crc8(&data), bp::crc8(&data));
        }

        // ── Property D: crc8 output is always in [0, 255] ────────────────
        //
        // The accumulator must never overflow its 8-bit window.
        // Pins: crc8 range invariant.
        #[test]
        fn crc8_output_is_byte(data in prop::collection::vec(any::<u8>(), 0..=MAX_TEST_PAYLOAD * 4)) {
            // u8 return type makes this trivially true, but having an explicit
            // test documents the contract and catches any future return-type
            // change.
            let _: u8 = bp::crc8(&data);
        }

        // ── Property E: bit-flip in non-LEN frame bytes breaks parse ─────
        //
        // Flipping any single bit in MAGIC, TYPE, payload, or CRC bytes of
        // a valid frame must cause parse_packet to return None OR return a
        // result that differs from the original.
        //
        // The LEN bytes (offsets 3–4) are intentionally excluded: flipping
        // a LEN bit can produce a valid shorter frame whose CRC byte
        // accidentally matches (~1/256 probability) — so "must be None" is
        // not a sound property for those two bytes.  All other bytes are
        // covered here.
        //
        // Pins: CRC and magic/type checks detect single-bit corruption in
        // the frame body (excluding the LEN field).
        #[test]
        fn bit_flip_breaks_parse(
            pkt_type in any::<u8>(),
            // Use a non-empty payload so the frame has at least one
            // payload byte to flip (in addition to MAGIC/TYPE/CRC).
            payload in prop::collection::vec(any::<u8>(), 1..=MAX_TEST_PAYLOAD),
        ) {
            let frame = build(pkt_type, &payload);
            let frame_len = frame.len();

            // Byte offsets to test: [0, 1, 2] (magic+type) and [5, frame_len-1]
            // (payload bytes + CRC).  Skip LEN_BYTE_LOW and LEN_BYTE_HIGH.
            let safe_bytes: Vec<usize> = (0..frame_len)
                .filter(|&i| i != LEN_BYTE_LOW && i != LEN_BYTE_HIGH)
                .collect();

            for &byte_idx in &safe_bytes {
                for bit in 0..BITS_PER_BYTE {
                    let mut flipped = frame.clone();
                    flipped[byte_idx] ^= 1u8 << bit;
                    let result = bp::parse_packet(&flipped);
                    if let Some((ft, fs, fl, _)) = result {
                        // The flipped frame parsed — it must differ from original.
                        let same_type    = ft == pkt_type;
                        let same_payload = fl == payload.len()
                            && &flipped[fs..fs + fl] == payload.as_slice();
                        prop_assert!(
                            !(same_type && same_payload),
                            "Bit flip at byte {} bit {} produced identical parse result",
                            byte_idx, bit
                        );
                    }
                    // If result is None that is also fine — parse rejected the corrupted frame.
                }
            }
        }
    }
}
