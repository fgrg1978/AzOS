// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Host-side tests for azos_flight_math (D04 trig + wind estimator).

#[cfg(test)]
mod trig_tests {
    use azos_flight_math::trig::{cos1000, sin1000};

    #[test]
    fn cardinal_sines() {
        assert_eq!(sin1000(0), 0);
        assert_eq!(sin1000(9_000), 1000); // sin 90°
        assert_eq!(sin1000(18_000), 0); // sin 180°
        assert_eq!(sin1000(27_000), -1000); // sin 270°
    }

    #[test]
    fn cardinal_cosines() {
        assert_eq!(cos1000(0), 1000); // cos 0°
        assert_eq!(cos1000(9_000), 0); // cos 90°
        assert_eq!(cos1000(18_000), -1000); // cos 180°
    }

    #[test]
    fn negative_and_wrapped_angles_match() {
        // sin(-90°) == sin(270°)
        assert_eq!(sin1000(-9_000), sin1000(27_000));
        // sin(450°) == sin(90°)
        assert_eq!(sin1000(45_000), sin1000(9_000));
    }

    #[test]
    fn sin_45_is_about_707() {
        let s = sin1000(4_500);
        assert!((700..=715).contains(&s), "sin45 ≈ 0.707, got {}", s);
    }
}

#[cfg(test)]
mod wind_tests {
    use azos_flight_math::trig::{sin1000, TRIG_SCALE};
    use azos_flight_math::wind::{
        body_horizontal_to_ned, commanded_accel_ned, ned_horizontal_to_body, WindEstimator,
        GRAVITY_MMSS, TILT_BIAS_MAX_CDEG, WIND_ACC_MAX_MMSS,
    };

    /// Drive the estimator to steady state with a constant measured residual.
    fn settle(est: &mut WindEstimator, meas_n: i32, meas_e: i32) {
        // ~10 τ at 100 Hz ensures convergence.
        for _ in 0..2_000 {
            est.update(meas_n, meas_e, 0, 0, 10);
        }
    }

    #[test]
    fn zero_residual_gives_zero_wind() {
        let mut est = WindEstimator::new();
        for _ in 0..100 {
            est.update(0, 0, 0, 0, 10);
        }
        assert_eq!(est.wind_accel_ne(), (0, 0));
    }

    #[test]
    fn converges_to_constant_residual() {
        let mut est = WindEstimator::new();
        // Measured 1000 mm/s² north, nothing commanded → wind is 1000 north.
        settle(&mut est, 1_000, 0);
        let (n, e) = est.wind_accel_ne();
        assert!((980..=1_000).contains(&n), "north wind ≈ 1000, got {}", n);
        assert!(e.abs() <= 2, "east wind ≈ 0, got {}", e);
    }

    #[test]
    fn estimate_is_clamped() {
        let mut est = WindEstimator::new();
        // Absurd residual (10 g) must clamp, not be attributed wholesale to wind.
        settle(&mut est, 10 * GRAVITY_MMSS, 0);
        let (n, _) = est.wind_accel_ne();
        assert_eq!(n, WIND_ACC_MAX_MMSS);
    }

    #[test]
    fn commanded_accel_forward_at_zero_yaw_is_north() {
        // Positive pitch, zero yaw → pure north acceleration, ~g·sin(pitch).
        let (n, e) = commanded_accel_ned(0, 1_000, 0); // pitch 10°
        let expected = GRAVITY_MMSS * sin1000(1_000) / TRIG_SCALE;
        assert_eq!(n, expected);
        assert_eq!(e, 0);
    }

    #[test]
    fn commanded_accel_right_at_90_yaw_is_south() {
        // Positive roll (accelerate right), heading east (yaw 90°): right→south.
        let (n, e) = commanded_accel_ned(1_000, 0, 9_000);
        let mag = GRAVITY_MMSS * sin1000(1_000) / TRIG_SCALE;
        assert!(e.abs() <= 1, "east ≈ 0, got {}", e);
        assert_eq!(n, -mag); // body-right at heading east points world-south
    }

    #[test]
    fn body_ned_roundtrip() {
        // Rotating to NED and back must recover the original vector.
        for &yaw in &[0, 4_500, 9_000, 13_500, 18_000, 27_000] {
            let (n, e) = body_horizontal_to_ned(800, -300, yaw);
            let (fwd, right) = ned_horizontal_to_body(n, e, yaw);
            assert!((fwd - 800).abs() <= 4, "fwd roundtrip yaw={} got {}", yaw, fwd);
            assert!((right + 300).abs() <= 4, "right roundtrip yaw={} got {}", yaw, right);
        }
    }

    #[test]
    fn tilt_bias_opposes_wind() {
        let mut est = WindEstimator::new();
        // Wind pushing north → craft should pitch backward (negative pitch) to
        // accelerate south against it, at zero heading.
        settle(&mut est, 1_000, 0);
        let (roll, pitch) = est.tilt_bias_cdeg(0);
        assert!(pitch < 0, "expected negative (south) pitch bias, got {}", pitch);
        assert!(roll.abs() <= 2, "expected ~0 roll bias, got {}", roll);
    }

    #[test]
    fn tilt_bias_is_clamped() {
        let mut est = WindEstimator::new();
        settle(&mut est, WIND_ACC_MAX_MMSS, 0);
        let (_, pitch) = est.tilt_bias_cdeg(0);
        assert!(pitch.abs() <= TILT_BIAS_MAX_CDEG);
    }
}

#[cfg(test)]
mod position_tests {
    use azos_flight_math::position::{PositionController, POS_TILT_MAX_CDEG};
    use azos_flight_math::wind::commanded_accel_ned;

    /// Closed-loop point-mass simulation (SITL-lite). The controller's tilt
    /// output is fed through the SAME `a = g·sin(tilt)` physics the controller
    /// inverts, integrated to velocity and position. `wind_acc_ne` is a
    /// constant disturbance acceleration added every step (mm/s²).
    ///
    /// Returns the final `(north, east)` position (mm) after `steps` ticks.
    fn simulate(
        ctrl: &mut PositionController,
        target: (i32, i32),
        wind_acc_ne: (i32, i32),
        wind_ff_cdeg: (i32, i32),
        yaw_cdeg: i32,
        steps: usize,
        dt_ms: u32,
    ) -> (i32, i32) {
        let mut pos = (0i32, 0i32);
        let mut vel = (0i32, 0i32);
        for _ in 0..steps {
            let (roll, pitch) = ctrl.update(target, pos, vel, yaw_cdeg, wind_ff_cdeg, dt_ms);
            // Physics: tilt → NED acceleration, plus the wind disturbance.
            let (an, ae) = commanded_accel_ned(roll, pitch, yaw_cdeg);
            let an = an + wind_acc_ne.0;
            let ae = ae + wind_acc_ne.1;
            // Integrate (dt in ms): vel += a·dt/1000; pos += vel·dt/1000.
            vel.0 += an * dt_ms as i32 / 1_000;
            vel.1 += ae * dt_ms as i32 / 1_000;
            pos.0 += vel.0 * dt_ms as i32 / 1_000;
            pos.1 += vel.1 * dt_ms as i32 / 1_000;
        }
        pos
    }

    const DT_MS: u32 = 20; // 50 Hz
    const STEPS_10S: usize = 500;

    #[test]
    fn converges_to_north_setpoint_no_wind() {
        let mut ctrl = PositionController::new();
        // Hold 5 m north, no wind, no feed-forward, heading north.
        let (n, e) = simulate(&mut ctrl, (5_000, 0), (0, 0), (0, 0), 0, STEPS_10S, DT_MS);
        assert!((n - 5_000).abs() <= 150, "north should reach 5000±150mm, got {}", n);
        assert!(e.abs() <= 150, "east should stay ~0, got {}", e);
    }

    #[test]
    fn converges_to_diagonal_setpoint() {
        let mut ctrl = PositionController::new();
        let (n, e) = simulate(&mut ctrl, (3_000, -2_000), (0, 0), (0, 0), 0, STEPS_10S, DT_MS);
        assert!((n - 3_000).abs() <= 150, "north 3000±150, got {}", n);
        assert!((e + 2_000).abs() <= 150, "east -2000±150, got {}", e);
    }

    #[test]
    fn integral_rejects_constant_wind() {
        let mut ctrl = PositionController::new();
        // Constant 1500 mm/s² wind pushing east; no feed-forward. The velocity
        // loop's I term must drive the steady-state error to ~0 — disturbance
        // rejection is slower than a step response, so allow more time.
        const STEPS_30S: usize = 1_500;
        let (n, e) = simulate(&mut ctrl, (0, 0), (0, 1_500), (0, 0), 0, STEPS_30S, DT_MS);
        assert!(n.abs() <= 200, "north ~0 under wind, got {}", n);
        assert!(e.abs() <= 200, "east should converge to ~0 despite wind, got {}", e);
    }

    #[test]
    fn wind_feedforward_speeds_disturbance_rejection() {
        // 1500 mm/s² wind pushing east, heading north. The FF tilt that cancels
        // it is a NEGATIVE roll bias (roll right = +east; to counter east wind
        // we lean left → negative roll). accel_to_tilt(-1500) ≈ -876 cdeg.
        let wind = (0, 1_500);
        const CORRECT_FF_ROLL: i32 = -876;

        let mut no_ff = PositionController::new();
        let (_, e_no_ff) = simulate(&mut no_ff, (0, 0), wind, (0, 0), 0, STEPS_10S, DT_MS);

        let mut good = PositionController::new();
        let (_, e_good) = simulate(&mut good, (0, 0), wind, (CORRECT_FF_ROLL, 0), 0, STEPS_10S, DT_MS);

        // Wrong-signed FF must make drift WORSE — this is what certifies the
        // sign convention (a sign error here = pushing the wrong way = crash).
        let mut bad = PositionController::new();
        let (_, e_bad) = simulate(&mut bad, (0, 0), wind, (-CORRECT_FF_ROLL, 0), 0, STEPS_10S, DT_MS);

        // Correct FF at least halves the 10 s drift vs feedback-alone, and
        // wrong-signed FF is strictly worse than feedback-alone.
        assert!(
            e_good.abs() * 2 < e_no_ff.abs(),
            "correct FF should at least halve drift: good={} no_ff={}",
            e_good,
            e_no_ff
        );
        assert!(
            e_bad.abs() > e_no_ff.abs(),
            "wrong-signed FF must worsen drift: bad={} no_ff={}",
            e_bad,
            e_no_ff
        );
    }

    #[test]
    fn holds_origin_when_already_there() {
        let mut ctrl = PositionController::new();
        let (n, e) = simulate(&mut ctrl, (0, 0), (0, 0), (0, 0), 0, 100, DT_MS);
        assert!(n.abs() <= 10 && e.abs() <= 10, "should stay put, got ({},{})", n, e);
    }

    #[test]
    fn converges_under_nonzero_heading() {
        // Same 5 m north target but facing east (yaw 90°): the NED→body
        // rotation must still steer correctly to world-north.
        let mut ctrl = PositionController::new();
        let (n, e) = simulate(&mut ctrl, (5_000, 0), (0, 0), (0, 0), 9_000, STEPS_10S, DT_MS);
        assert!((n - 5_000).abs() <= 200, "north 5000±200 at yaw90, got {}", n);
        assert!(e.abs() <= 200, "east ~0 at yaw90, got {}", e);
    }

    #[test]
    fn tilt_output_is_clamped() {
        let mut ctrl = PositionController::new();
        // Huge setpoint (1 km) — first-step tilt must respect the clamp.
        let (roll, pitch) = ctrl.update((1_000_000, 0), (0, 0), (0, 0), 0, (0, 0), DT_MS);
        assert!(roll.abs() <= POS_TILT_MAX_CDEG, "roll clamp, got {}", roll);
        assert!(pitch.abs() <= POS_TILT_MAX_CDEG, "pitch clamp, got {}", pitch);
    }
}

#[cfg(test)]
mod scan_tests {
    use azos_flight_math::scan::{cap_scan, SLAM_MAX_BEAMS};

    /// Pin the provenance: the task this cap exists for is "nav's own
    /// SCAN_MAX_POINTS resolution", not an arbitrary round number. If that
    /// constant ever changes, this test should force a conscious update
    /// rather than silently tracking it.
    #[test]
    fn cap_matches_nav_scan_resolution() {
        assert_eq!(SLAM_MAX_BEAMS, 360);
    }

    /// The discriminating case: more beams than the cap on both slices.
    /// Only `SLAM_MAX_BEAMS` beams should survive. This is the case a
    /// completely absent cap would fail (it would pass the full length
    /// through instead).
    #[test]
    fn excess_beams_are_capped() {
        let ranges = vec![100u16; SLAM_MAX_BEAMS + 500];
        let angles = vec![0i32; SLAM_MAX_BEAMS + 500];
        let (r, a) = cap_scan(&ranges, &angles);
        assert_eq!(r.len(), SLAM_MAX_BEAMS);
        assert_eq!(a.len(), SLAM_MAX_BEAMS);
    }

    /// The non-discriminating case, included deliberately: fewer beams
    /// than the cap on both slices. A completely absent cap passes this
    /// one too — it is not, by itself, evidence the cap exists. It's here
    /// to confirm `excess_beams_are_capped` above is the one actually
    /// doing the discriminating, not an artifact of some other clamp.
    #[test]
    fn under_cap_scan_is_unchanged() {
        let ranges = vec![100u16; 10];
        let angles = vec![0i32; 10];
        let (r, a) = cap_scan(&ranges, &angles);
        assert_eq!(r.len(), 10);
        assert_eq!(a.len(), 10);
    }

    /// A scan at exactly the cap must not be reduced further (off-by-one
    /// guard on the cap itself).
    #[test]
    fn exact_cap_is_not_reduced() {
        let ranges = vec![100u16; SLAM_MAX_BEAMS];
        let angles = vec![0i32; SLAM_MAX_BEAMS];
        let (r, a) = cap_scan(&ranges, &angles);
        assert_eq!(r.len(), SLAM_MAX_BEAMS);
        assert_eq!(a.len(), SLAM_MAX_BEAMS);
    }

    /// Mismatched slice lengths: the shorter one governs, on both sides of
    /// the cap threshold — this is `slam_update_scan`'s own
    /// `ranges.len().min(angles_cdeg.len())` behavior, preserved by the cap.
    #[test]
    fn shorter_slice_wins_under_the_cap() {
        let ranges = vec![100u16; 20];
        let angles = vec![0i32; 10];
        let (r, a) = cap_scan(&ranges, &angles);
        assert_eq!(r.len(), 10);
        assert_eq!(a.len(), 10);

        let ranges = vec![100u16; 10];
        let angles = vec![0i32; 20];
        let (r, a) = cap_scan(&ranges, &angles);
        assert_eq!(r.len(), 10);
        assert_eq!(a.len(), 10);
    }

    /// Mismatched lengths that both exceed the cap: cap wins over the
    /// shorter-slice rule, not just over the raw length.
    #[test]
    fn cap_wins_even_when_shorter_slice_also_exceeds_it() {
        let ranges = vec![100u16; SLAM_MAX_BEAMS + 200];
        let angles = vec![0i32; SLAM_MAX_BEAMS + 500];
        let (r, a) = cap_scan(&ranges, &angles);
        assert_eq!(r.len(), SLAM_MAX_BEAMS);
        assert_eq!(a.len(), SLAM_MAX_BEAMS);
    }
}
