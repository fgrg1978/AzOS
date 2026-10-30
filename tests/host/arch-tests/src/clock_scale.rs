// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! aarch64's clock arithmetic (`arch/aarch64/src/timer.rs`) at the counter
//! rates it meets: HVF's host rate, the Pi 3's, the Pi 5's and TCG's.

use azos_arch_api::clock_scale::Scale;

const TIMER_FREQ: u64 = 1_000_000_000;
const RATES: [u64; 4] = [24_000_000, 19_200_000, 54_000_000, 1_000_000_000];
const YEAR_S: u64 = 365 * 86_400;

fn exact_ticks(counter: u64, hz: u64) -> u128 {
    counter as u128 * TIMER_FREQ as u128 / hz as u128
}

#[test]
fn the_clock_stays_exact_to_its_bound_after_a_century() {
    for hz in RATES {
        let s = Scale::new(hz, TIMER_FREQ).unwrap();
        let counter = 100 * YEAR_S * hz;
        let got = s.apply(counter) as u128;
        let exact = exact_ticks(counter, hz);
        assert!(got <= exact, "{hz} Hz rounds up");
        assert!(exact - got <= (counter >> 32) as u128 + 1, "{hz} Hz: off by {} ticks", exact - got);
        // In seconds, the error of a hundred years is below a tenth of a second.
        assert!((exact - got) < (TIMER_FREQ / 10) as u128, "{hz} Hz: off by {} ticks", exact - got);
    }
}

#[test]
fn the_product_leaves_64_bits_at_584_years_whatever_the_counter_rate() {
    for hz in RATES {
        let s = Scale::new(hz, TIMER_FREQ).unwrap();
        let years_584 = 584 * YEAR_S * hz;
        assert!(exact_ticks(years_584, hz) <= u64::MAX as u128);
        assert_eq!(s.apply(years_584) as u128 >> 63, 1, "{hz} Hz is not near the top at 584 years");
        // A 1 GHz counter itself ends there; a slower one runs past the clock.
        let years_585 = (585 * YEAR_S) as u128 * hz as u128;
        if let Ok(counter) = u64::try_from(years_585) {
            assert!(exact_ticks(counter, hz) > u64::MAX as u128);
            assert_eq!(s.apply(counter), u64::MAX, "{hz} Hz does not saturate");
        }
    }
}

#[test]
fn a_distance_converted_back_is_never_short() {
    for hz in RATES {
        let to_ticks = Scale::new(hz, TIMER_FREQ).unwrap();
        let to_counter = Scale::new_up(TIMER_FREQ, hz).unwrap();
        for ticks in [1, 41, 42, 1_000, 1_000_000, 10_000_000, TIMER_FREQ, 3600 * TIMER_FREQ] {
            let counter = to_counter.apply_ceil(ticks);
            // From an aligned instant, so only the rounding of the two scales shows.
            let got = exact_ticks(counter, hz) as u64;
            assert!(got >= ticks, "{hz} Hz: {ticks} ticks came back as {got}");
            let one_count = TIMER_FREQ / hz + 1;
            assert!(got - ticks <= one_count + ticks / (1 << 20), "{hz} Hz: {ticks} ticks came back as {got}");
            assert!(to_ticks.apply(counter) + 1 + (counter >> 32) >= ticks);
        }
    }
}

#[test]
fn a_rate_that_matches_is_the_identity_both_ways() {
    let same = TIMER_FREQ;
    assert_eq!(Scale::new(same, TIMER_FREQ), Some(Scale::IDENTITY));
    assert_eq!(Scale::new_up(same, TIMER_FREQ), Some(Scale::IDENTITY));
    assert_eq!(Scale::IDENTITY.apply(u64::MAX), u64::MAX);
    assert_eq!(Scale::new(0, TIMER_FREQ), None);
    assert_eq!(Scale::new_up(TIMER_FREQ, 0), None);
}
