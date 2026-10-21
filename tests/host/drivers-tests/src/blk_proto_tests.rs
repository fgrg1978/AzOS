// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host tests of virtio-blk's wire facts and queue arithmetic
//! (`crates/drivers/virtio/src/virtio/blk_proto.rs`, the real file).

use crate::virtio::blk_proto::*;
use azos_drv_api::block::HwStatus;

#[test]
fn a_discard_segment_is_sector_count_and_the_unmap_flag_little_endian() {
    let s = discard_segment(0x0102_0304_0506_0708, 0x0A0B_0C0D);
    assert_eq!(&s[0..8], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(&s[8..12], &[0x0D, 0x0C, 0x0B, 0x0A]);
    assert_eq!(&s[12..16], &[1, 0, 0, 0], "unmap: the device may free the backing store");
    assert_eq!(s.len(), DISCARD_SEG_BYTES);
}

#[test]
fn the_request_types_and_feature_bits_are_the_spec_values() {
    assert_eq!((T_IN, T_OUT, T_FLUSH, T_DISCARD), (0, 1, 4, 11));
    assert_eq!((F_RO, F_FLUSH, F_MQ, F_DISCARD), (1 << 5, 1 << 9, 1 << 12, 1 << 13));
    // num_queues is the le16 at byte 34: the upper half of the word at 32.
    assert_eq!(CFG_NUM_QUEUES_WORD + 2, 34);
    assert_eq!(num_queues_of(0x0007_0001), 7);
}

#[test]
fn queues_follow_the_device_the_configuration_and_the_cpus() {
    // No F_MQ: queue 0 alone, whatever the config word says.
    assert_eq!(queues_used(false, 8, 4, 4), 1);
    // F_MQ: the smallest of what the device offers, wants and the CPUs.
    assert_eq!(queues_used(true, 8, 4, 16), 4);
    assert_eq!(queues_used(true, 2, 4, 16), 2);
    assert_eq!(queues_used(true, 8, 4, 3), 3);
    // A device that offers F_MQ and says zero still has queue 0.
    assert_eq!(queues_used(true, 0, 4, 4), 1);
    assert_eq!(queues_used(true, 8, 1, 4), 1);
}

#[test]
fn slots_are_bounded_by_the_descriptors_of_the_queues() {
    // A 16-entry queue holds five three-descriptor requests.
    assert_eq!(slots_usable(8, 1, 16), 5);
    assert_eq!(slots_usable(4, 1, 16), 4);
    assert_eq!(slots_usable(8, 2, 16), 8);
    assert_eq!(slots_usable(1, 4, 16), 1);
    // Whatever the queue size, at least one request fits.
    assert_eq!(slots_usable(8, 1, 2), 1);
}

#[test]
fn a_queue_never_holds_more_slots_than_its_descriptors() {
    for queues in 1..=4usize {
        for configured in 1..=8usize {
            let slots = slots_usable(configured, queues, 16);
            for q in 0..queues {
                let mine = (0..slots).filter(|&t| queue_of(t, queues) == q).count();
                assert!(mine * DESCS_PER_REQUEST <= 16, "queues={queues} slots={slots}: queue {q} has {mine}");
            }
        }
    }
}

#[test]
fn a_task_is_offered_the_slots_of_its_own_queue_first() {
    let (queues, slots) = (2usize, 6usize);
    for pref in 0..queues {
        let own: Vec<usize> = (0..slots).filter(|&t| tag_preferred(t, queues, pref)).collect();
        assert!(own.iter().all(|&t| queue_of(t, queues) == pref));
        assert_eq!(own.len(), 3);
    }
    // One queue: every slot is preferred by queue 0.
    assert!((0..5).all(|t| tag_preferred(t, 1, 0)));
}

#[test]
fn discard_needs_the_feature_and_at_least_one_segment() {
    assert_eq!(max_discard(true, 4096, 1), 4096);
    assert_eq!(max_discard(true, 4096, 0), 0, "a device that takes no segment has no discard");
    assert_eq!(max_discard(false, 4096, 1), 0);
}

#[test]
fn the_status_byte_of_a_command_maps_to_what_the_layer_is_told() {
    assert_eq!(status_of(true, S_OK), HwStatus::Ok);
    assert_eq!(status_of(false, S_OK), HwStatus::Ok);
    // "I have no such command" is a flush or a discard the device lacks,
    // never a read or a write that failed.
    assert_eq!(status_of(false, S_UNSUPP), HwStatus::Unsupported);
    assert_eq!(status_of(true, S_UNSUPP), HwStatus::Io);
    assert_eq!(status_of(true, 1), HwStatus::Io);
    assert_eq!(status_of(false, S_PENDING), HwStatus::Io, "the sentinel is never a success");
}

#[test]
fn a_discard_and_a_flush_get_the_long_budget_and_data_the_short_one() {
    assert_eq!(budget_us(OP_DATA), BLK_TIMEOUT_US);
    // A slow discard on real flash must not latch the driver dead (a hint
    // would then disable swap and FAT32 until reboot).
    assert_eq!(budget_us(OP_DISCARD), BLK_LONG_TIMEOUT_US);
    assert_eq!(budget_us(OP_FLUSH), BLK_LONG_TIMEOUT_US);
    assert!(budget_us(OP_DISCARD) > budget_us(OP_DATA));
}

// ── The budget is time the guest ran ────────────────────────────────────

mod stall {
    use azos_drv_api::block::StallClock;

    /// Units are arbitrary ticks: a command has `BUDGET` of them, two looks
    /// further apart than `GAP` are a guest that did not run.
    const BUDGET: u64 = 500;
    const GAP: u64 = 50;

    /// A command submitted at `at`: what the driver stores for it.
    fn submit(c: &StallClock, at: u64) -> (u64, u64) {
        c.observe(at, GAP);
        (at + BUDGET, c.credit())
    }

    #[test]
    fn a_dead_device_is_found_at_the_budget_when_the_guest_kept_running() {
        let c = StallClock::new();
        let (deadline, base) = submit(&c, 1_000);
        // The reaper looks every tick of 10.
        for now in (1_010..1_500).step_by(10) {
            c.observe(now, GAP);
            assert!(!c.expired(now, deadline, base), "expired early at {now}");
        }
        c.observe(1_500, GAP);
        assert!(c.expired(1_500, deadline, base));
    }

    #[test]
    fn a_stopped_guest_does_not_spend_the_budget() {
        let c = StallClock::new();
        let (deadline, base) = submit(&c, 1_000);
        c.observe(1_010, GAP);
        // Stopped by the host: the clock is 2000 ahead at the next look.
        let now = 3_010;
        assert_eq!(c.observe(now, GAP), 2_000);
        // The old test, wall-clock, latched the device dead here.
        assert!(now >= deadline);
        assert!(!c.expired(now, deadline, base));
        // The device then answers (not modelled) or does not: the rest of the
        // budget it had is the 490 it was not given before the stop.
        let mut at = now;
        while !c.expired(at, deadline, base) {
            at += 10;
            c.observe(at, GAP);
            assert!(at < now + 1_000, "never expired");
        }
        assert_eq!(at, now + 490, "the device gets exactly the budget the guest ran");
    }

    #[test]
    fn two_stops_during_one_command_are_both_forgiven() {
        let c = StallClock::new();
        let (deadline, base) = submit(&c, 0);
        c.observe(10, GAP);
        c.observe(1_010, GAP);
        c.observe(1_020, GAP);
        let now = 5_020;
        c.observe(now, GAP);
        assert!(!c.expired(now, deadline, base));
    }

    #[test]
    fn idle_time_before_a_submit_is_not_credited_to_it() {
        let c = StallClock::new();
        c.observe(10, GAP);
        // Nothing in flight for a long time, then a command.
        let (deadline, base) = submit(&c, 100_000);
        assert!(c.expired(100_000 + BUDGET, deadline, base));
        assert!(!c.expired(100_000 + BUDGET - 1, deadline, base));
    }

    #[test]
    fn only_a_gap_above_the_threshold_is_credited() {
        let c = StallClock::new();
        assert_eq!(c.observe(1_000, GAP), 0, "the first look has nothing before it");
        assert_eq!(c.observe(1_000 + GAP, GAP), 0);
        assert_eq!(c.observe(1_000 + 2 * GAP + 1, GAP), GAP + 1);
        assert_eq!(c.credit(), GAP + 1);
    }

    #[test]
    fn a_look_that_goes_back_in_time_credits_nothing() {
        let c = StallClock::new();
        c.observe(1_000, GAP);
        assert_eq!(c.observe(900, GAP), 0);
        // And does not move the last look back: the next gap is from 1000.
        assert_eq!(c.observe(1_040, GAP), 0);
    }
}
