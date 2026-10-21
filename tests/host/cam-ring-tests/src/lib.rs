// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for `azos_cam_ring` (S1/S6, and the B2 fan-out ring).

#[cfg(test)]
mod fanout_tests;

#[cfg(test)]
mod tests {
    use azos_cam_ring::FrameRing;

    // ── Constants ─────────────────────────────────────────────────────────────

    /// Small ring size used for most tests: 4 slots.
    const TEST_N: usize = 4;
    /// Slot byte capacity for most tests.
    const TEST_SZ: usize = 64;
    /// A smaller payload used as test frame content.
    const TEST_PAYLOAD_LEN: usize = 16;
    /// Test byte pattern for frame content.
    const TEST_BYTE_PATTERN: u8 = 0xA5;

    // ── 1. Claim/commit roundtrip ─────────────────────────────────────────────

    #[test]
    fn claim_commit_peek_release_roundtrip() {
        let ring: FrameRing<TEST_N, TEST_SZ> = FrameRing::new();

        // Ring starts empty.
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);

        // Producer claims a slot and writes a pattern.
        let slot = ring.claim_write().expect("ring should have free slot");
        for b in slot[..TEST_PAYLOAD_LEN].iter_mut() {
            *b = TEST_BYTE_PATTERN;
        }
        ring.commit_write(TEST_PAYLOAD_LEN);

        // Ring now has one frame.
        assert_eq!(ring.len(), 1);
        assert!(!ring.is_empty());

        // Consumer peeks and validates.
        let (len, data) = ring.peek_read().expect("ring should have one frame");
        assert_eq!(len, TEST_PAYLOAD_LEN);
        for b in &data[..len] {
            assert_eq!(*b, TEST_BYTE_PATTERN);
        }

        // Release and verify ring is empty again.
        ring.release_read();
        assert!(ring.is_empty());
    }

    // ── 2. Full-ring back-pressure ─────────────────────────────────────────────

    #[test]
    fn full_ring_claim_returns_none() {
        let ring: FrameRing<TEST_N, TEST_SZ> = FrameRing::new();

        // Fill all N slots.
        for i in 0..TEST_N {
            let slot = ring.claim_write()
                .unwrap_or_else(|| panic!("slot {} should be available", i));
            slot[0] = i as u8;
            ring.commit_write(1);
        }

        // Ring is now full.
        assert!(ring.is_full());
        assert_eq!(ring.len(), TEST_N);

        // Further claim must fail.
        assert!(ring.claim_write().is_none());

        // After releasing one slot the producer can write again.
        ring.release_read();
        assert!(!ring.is_full());
        assert!(ring.claim_write().is_some());
    }

    // ── 3. Multi-frame ordering ───────────────────────────────────────────────

    #[test]
    fn frames_are_delivered_in_fifo_order() {
        const FRAME_COUNT: usize = 4;
        const SLOT_SZ: usize = 8;
        let ring: FrameRing<FRAME_COUNT, SLOT_SZ> = FrameRing::new();

        // Produce FRAME_COUNT frames, each tagged with its sequence number.
        for seq in 0..FRAME_COUNT {
            let slot = ring.claim_write().expect("slot must be free");
            slot[0] = seq as u8;
            ring.commit_write(1);
        }

        // Consume and verify order.
        for expected_seq in 0..FRAME_COUNT {
            let (len, data) = ring.peek_read().expect("frame must be available");
            assert_eq!(len, 1);
            assert_eq!(data[0], expected_seq as u8,
                "expected frame {} got {}", expected_seq, data[0]);
            ring.release_read();
        }

        assert!(ring.is_empty());
    }

    // ── 4. Empty ring peek returns None ───────────────────────────────────────

    #[test]
    fn peek_on_empty_ring_returns_none() {
        let ring: FrameRing<TEST_N, TEST_SZ> = FrameRing::new();
        assert!(ring.peek_read().is_none());
    }

    // ── 5. commit_write clamps oversized len ─────────────────────────────────

    #[test]
    fn commit_clamps_len_to_slot_size() {
        const SMALL_SZ: usize = 8;
        let ring: FrameRing<2, SMALL_SZ> = FrameRing::new();

        let slot = ring.claim_write().expect("slot free");
        // Write the whole slot.
        slot.fill(0xFF);
        // Commit with a length larger than the slot — must be clamped.
        ring.commit_write(SMALL_SZ + 99);

        let (len, _data) = ring.peek_read().expect("frame must be readable");
        assert_eq!(len, SMALL_SZ, "len must be clamped to SZ");
        ring.release_read();
    }

    // ── 6. Producer/consumer after wrap-around ────────────────────────────────

    #[test]
    fn indices_wrap_around_correctly() {
        const RING_N: usize = 4;
        const RING_SZ: usize = 4;
        let ring: FrameRing<RING_N, RING_SZ> = FrameRing::new();

        // Cycle through the ring more than once to exercise index wrap-around.
        const CYCLES: usize = 3;
        for cycle in 0..CYCLES {
            for slot_no in 0..RING_N {
                // Produce.
                let slot = ring.claim_write()
                    .expect("slot must be free at start of round");
                slot[0] = (cycle * RING_N + slot_no) as u8;
                ring.commit_write(1);

                // Consume immediately so ring never exceeds depth 1.
                let (len, data) = ring.peek_read().expect("frame must appear immediately");
                assert_eq!(len, 1);
                assert_eq!(data[0], (cycle * RING_N + slot_no) as u8);
                ring.release_read();
            }
        }
        assert!(ring.is_empty());
    }

    // ── 7. Capacity and slot_size accessors ───────────────────────────────────

    #[test]
    fn capacity_and_slot_size_accessors() {
        type Ring = FrameRing<8, 256>;
        assert_eq!(Ring::capacity(), 8);
        assert_eq!(Ring::slot_size(), 256);
    }

    // ── 8. Multiple frames queued before any release ─────────────────────────

    #[test]
    fn batch_produce_then_batch_consume() {
        const BATCH: usize = 4;
        const SZ: usize = 16;
        let ring: FrameRing<BATCH, SZ> = FrameRing::new();

        // Produce all frames before consuming any.
        for i in 0u8..BATCH as u8 {
            let slot = ring.claim_write().expect("slot free");
            slot[0] = i;
            slot[1] = i.wrapping_mul(2);
            ring.commit_write(2);
        }
        assert_eq!(ring.len(), BATCH);

        // Now consume them all.
        for i in 0u8..BATCH as u8 {
            let (len, data) = ring.peek_read().expect("frame present");
            assert_eq!(len, 2);
            assert_eq!(data[0], i);
            assert_eq!(data[1], i.wrapping_mul(2));
            ring.release_read();
        }
        assert!(ring.is_empty());
    }

    // ── 9. Single-slot ring edge case ─────────────────────────────────────────

    #[test]
    fn single_slot_ring_alternates_correctly() {
        // N=1 is the minimal valid power-of-two size.
        let ring: FrameRing<1, 32> = FrameRing::new();

        for round in 0u8..4 {
            let slot = ring.claim_write().expect("slot free");
            slot[0] = round;
            ring.commit_write(1);

            assert!(ring.is_full());
            assert!(ring.claim_write().is_none(), "ring must be full");

            let (len, data) = ring.peek_read().expect("frame present");
            assert_eq!(len, 1);
            assert_eq!(data[0], round);
            ring.release_read();

            assert!(ring.is_empty());
        }
    }

    // ── 11. usize wraparound boundary ─────────────────────────────────────────
    //
    // Test 6 above ("indices_wrap_around_correctly") only exercises the slot
    // *mask* wrapping (index % N); producer_idx/consumer_idx themselves never
    // leave single digits. These tests instead start the ring right at the
    // `usize::MAX -> 0` rollover (via the test-only `with_start_index`) to
    // check the claim in the module doc comment: that
    // `producer_idx.wrapping_sub(consumer_idx)` still yields the correct
    // value, and that the producer still cannot lap the consumer, once the
    // raw counters have actually wrapped.

    /// Positive half: fill a ring positioned exactly at the wraparound
    /// boundary, confirm `is_full`/`len` read correctly across the rollover,
    /// then drain it and confirm data/order integrity survived the wrap.
    #[test]
    fn wrap_boundary_full_then_drain() {
        const RING_N: usize = 4;
        const RING_SZ: usize = 4;
        // producer_idx and consumer_idx both start two increments before the
        // usize::MAX -> 0 rollover, so filling the ring (N=4 commits) crosses
        // the boundary partway through.
        let start = usize::MAX - 1;
        let ring: FrameRing<RING_N, RING_SZ> = FrameRing::with_start_index(start);

        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);

        // Fill all N slots, crossing usize::MAX -> 0 while doing so.
        for i in 0..RING_N {
            let slot = ring.claim_write()
                .unwrap_or_else(|| panic!("slot {} should be available pre-wrap check", i));
            slot[0] = 0xB0 + i as u8;
            ring.commit_write(1);
            // len() must be correct on both sides of the rollover.
            assert_eq!(ring.len(), i + 1, "len() wrong at fill step {}", i);
        }

        // Ring must report full exactly at N, straddling the wraparound.
        assert!(ring.is_full());
        assert_eq!(ring.len(), RING_N);
        assert!(!ring.is_empty());

        // Drain and verify FIFO order + payload survived the index wrap.
        for i in 0..RING_N {
            let (len, data) = ring.peek_read()
                .unwrap_or_else(|| panic!("frame {} must be present post-wrap", i));
            assert_eq!(len, 1);
            assert_eq!(data[0], 0xB0 + i as u8, "payload {} corrupted across wrap", i);
            ring.release_read();
        }
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
    }

    /// Negative half: at the same boundary, once the ring reports full the
    /// producer MUST NOT be able to claim another slot (no lapping / no
    /// silent overwrite of the not-yet-read frame), even though the raw
    /// counters have wrapped through `usize::MAX`.
    #[test]
    fn wrap_boundary_negative_no_overwrite() {
        const RING_N: usize = 2;
        const RING_SZ: usize = 4;
        let start = usize::MAX; // next commit_write immediately wraps to 0.
        let ring: FrameRing<RING_N, RING_SZ> = FrameRing::with_start_index(start);

        // Fill the ring (crosses the wrap on the very first commit_write).
        for i in 0..RING_N {
            let slot = ring.claim_write().expect("slot must be free while filling");
            slot[0] = 0xC0 + i as u8;
            ring.commit_write(1);
        }
        assert!(ring.is_full());

        // The critical negative assertion: producer is blocked, not
        // overwriting. If the wraparound arithmetic were wrong this would
        // spuriously return Some(..) and silently corrupt the unread frame
        // at slot 0.
        assert!(
            ring.claim_write().is_none(),
            "producer must not lap the consumer immediately after usize wraparound"
        );

        // Consume one frame; producer must become unblocked and the content
        // must still be the value written before the wrap.
        let (len, data) = ring.peek_read().expect("frame 0 must be present");
        assert_eq!(len, 1);
        assert_eq!(data[0], 0xC0);
        ring.release_read();

        assert!(!ring.is_full());
        let slot = ring.claim_write().expect("slot freed after release_read");
        slot[0] = 0xD0;
        ring.commit_write(1);

        // Final drain: confirm both remaining frames (the pre-wrap survivor
        // and the newly written post-wrap frame) come out in FIFO order.
        let (len, data) = ring.peek_read().expect("second pre-wrap frame present");
        assert_eq!(len, 1);
        assert_eq!(data[0], 0xC1);
        ring.release_read();

        let (len, data) = ring.peek_read().expect("post-wrap frame present");
        assert_eq!(len, 1);
        assert_eq!(data[0], 0xD0);
        ring.release_read();

        assert!(ring.is_empty());
    }

    // ── 10. is_full reflects ring state correctly ─────────────────────────────

    #[test]
    fn is_full_transitions() {
        let ring: FrameRing<2, 8> = FrameRing::new();

        assert!(!ring.is_full());

        let slot = ring.claim_write().unwrap();
        slot[0] = 1;
        ring.commit_write(1);
        assert!(!ring.is_full());

        let slot = ring.claim_write().unwrap();
        slot[0] = 2;
        ring.commit_write(1);
        assert!(ring.is_full());

        ring.release_read();
        assert!(!ring.is_full());
        ring.release_read();
        assert!(ring.is_empty());
    }
}
