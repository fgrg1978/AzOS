// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Motor mixer — exact mirror of flight/src/lib.rs mixer_compute (D04).
//!
//! Converts (throttle, roll, pitch, yaw) → per-motor throttle for every
//! supported frame geometry.  All values are integers; throttle range 0-1000.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of motors supported.
pub const MAX_MOTORS: usize = 8;
/// Full throttle (100.0 %).
pub const THROTTLE_MAX: u16 = 1000;

// ── Types ─────────────────────────────────────────────────────────────────────

/// Multirotor geometry.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum FrameType {
    QuadX,
    QuadPlus,
    Hex,
    Octo,
    Tri,
    Y6,
    HexX,
    Coax,
}

/// Mixer output.
#[derive(Clone, Copy, Debug)]
pub struct MixerOutput {
    pub motors: [u16; MAX_MOTORS],
    pub count:  u8,
}

impl MixerOutput {
    pub const fn new() -> Self {
        MixerOutput { motors: [0; MAX_MOTORS], count: 0 }
    }
}

// ── Mixer ─────────────────────────────────────────────────────────────────────

fn clamp_throttle(v: i32) -> u16 {
    if v <= 0 { 0 }
    else if v >= THROTTLE_MAX as i32 { THROTTLE_MAX }
    else { v as u16 }
}

/// Compute per-motor throttle values.
pub fn mixer_compute(
    frame: FrameType,
    throttle: i32,
    roll: i32,
    pitch: i32,
    yaw: i32,
) -> MixerOutput {
    let mut out = MixerOutput::new();

    match frame {
        FrameType::QuadX => {
            out.count = 4;
            out.motors[0] = clamp_throttle(throttle - roll + pitch - yaw);
            out.motors[1] = clamp_throttle(throttle + roll + pitch + yaw);
            out.motors[2] = clamp_throttle(throttle + roll - pitch - yaw);
            out.motors[3] = clamp_throttle(throttle - roll - pitch + yaw);
        }
        FrameType::QuadPlus => {
            out.count = 4;
            out.motors[0] = clamp_throttle(throttle + pitch - yaw);
            out.motors[1] = clamp_throttle(throttle + roll  + yaw);
            out.motors[2] = clamp_throttle(throttle - roll  + yaw);
            out.motors[3] = clamp_throttle(throttle - pitch - yaw);
        }
        FrameType::Hex => {
            out.count = 6;
            out.motors[0] = clamp_throttle(throttle + pitch - yaw);
            out.motors[1] = clamp_throttle(throttle + roll / 2 + pitch / 2 + yaw);
            out.motors[2] = clamp_throttle(throttle + roll / 2 - pitch / 2 - yaw);
            out.motors[3] = clamp_throttle(throttle - pitch + yaw);
            out.motors[4] = clamp_throttle(throttle - roll / 2 - pitch / 2 - yaw);
            out.motors[5] = clamp_throttle(throttle - roll / 2 + pitch / 2 + yaw);
        }
        FrameType::Octo => {
            out.count = 8;
            const S45: i32 = 707;
            const CORRECTIONS: [(i32, i32, i32); 8] = [
                ( 0,     1000,  -1),
                ( S45,   S45,    1),
                ( 1000,  0,     -1),
                ( S45,  -S45,    1),
                ( 0,    -1000,  -1),
                (-S45,  -S45,    1),
                (-1000,  0,     -1),
                (-S45,   S45,    1),
            ];
            for (i, &(cr, cp, cy)) in CORRECTIONS.iter().enumerate() {
                out.motors[i] = clamp_throttle(throttle + roll * cr / 1000
                    + pitch * cp / 1000 + yaw * cy);
            }
        }
        FrameType::Tri => {
            out.count = 3;
            out.motors[0] = clamp_throttle(throttle - roll + pitch - yaw / 2);
            out.motors[1] = clamp_throttle(throttle + roll + pitch + yaw / 2);
            out.motors[2] = clamp_throttle(throttle - pitch);
        }
        FrameType::Y6 => {
            out.count = 6;
            const S120: i32 = 866;
            const C120: i32 = -500;
            let t = throttle / 2;
            out.motors[0] = clamp_throttle(t + pitch - yaw);
            out.motors[1] = clamp_throttle(t + pitch + yaw);
            out.motors[2] = clamp_throttle(t - roll * S120 / 1000 + pitch * C120 / 1000 - yaw);
            out.motors[3] = clamp_throttle(t - roll * S120 / 1000 + pitch * C120 / 1000 + yaw);
            out.motors[4] = clamp_throttle(t + roll * S120 / 1000 + pitch * C120 / 1000 - yaw);
            out.motors[5] = clamp_throttle(t + roll * S120 / 1000 + pitch * C120 / 1000 + yaw);
        }
        FrameType::HexX => {
            out.count = 6;
            const ARMS: [(i32, i32, i32); 6] = [
                ( 500,  866, -1),
                ( 1000, 0,    1),
                ( 500, -866, -1),
                (-500, -866,  1),
                (-1000, 0,   -1),
                (-500,  866,  1),
            ];
            for (i, &(sr, cp, cy)) in ARMS.iter().enumerate() {
                out.motors[i] = clamp_throttle(throttle + roll * sr / 1000
                    + pitch * cp / 1000 + yaw * cy);
            }
        }
        FrameType::Coax => {
            out.count = 8;
            const S45: i32 = 707;
            let arms: [(i32, i32); 4] = [
                (-S45,  S45),
                ( S45,  S45),
                ( S45, -S45),
                (-S45, -S45),
            ];
            for (i, &(ar, ap)) in arms.iter().enumerate() {
                let t = throttle / 2;
                out.motors[i * 2]     = clamp_throttle(t + roll * ar / 1000 + pitch * ap / 1000 - yaw);
                out.motors[i * 2 + 1] = clamp_throttle(t + roll * ar / 1000 + pitch * ap / 1000 + yaw);
            }
        }
    }

    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Hover: all motors equal when roll=pitch=yaw=0.
    #[test]
    fn quad_x_hover_equal_motors() {
        let out = mixer_compute(FrameType::QuadX, 500, 0, 0, 0);
        assert_eq!(out.count, 4);
        assert!(out.motors[..4].iter().all(|&m| m == 500),
            "QuadX hover: motors {:?}", &out.motors[..4]);
    }

    /// Pure roll: motors 0,3 low, motors 1,2 high (or vice versa).
    #[test]
    fn quad_x_roll_symmetry() {
        let out = mixer_compute(FrameType::QuadX, 500, 100, 0, 0);
        assert_eq!(out.count, 4);
        // M1 = T - R, M2 = T + R → M1 + M2 should equal 2T (if not clamped)
        assert_eq!(out.motors[0] + out.motors[1], 1000);
        // M3 + M4 = 2T as well
        assert_eq!(out.motors[2] + out.motors[3], 1000);
    }

    /// Pure pitch: left-right symmetry holds (no roll asymmetry).
    #[test]
    fn quad_x_pitch_symmetry() {
        let out = mixer_compute(FrameType::QuadX, 500, 0, 100, 0);
        assert_eq!(out.count, 4);
        // With roll=0: front-right (M0) == front-left (M1) and rear-left (M2) == rear-right (M3)
        assert_eq!(out.motors[0], out.motors[1], "Front motors should match at zero roll");
        assert_eq!(out.motors[2], out.motors[3], "Rear motors should match at zero roll");
        // Front pair (M0/M1) higher than rear pair (M2/M3) for positive pitch
        assert!(out.motors[0] > out.motors[2], "Positive pitch: front > rear");
    }

    /// Yaw: opposite CW/CCW pairs cancel in sum.
    #[test]
    fn quad_x_yaw_sum_constant() {
        let out = mixer_compute(FrameType::QuadX, 500, 0, 0, 100);
        assert_eq!(out.count, 4);
        let sum: u32 = out.motors[..4].iter().map(|&m| m as u32).sum();
        assert_eq!(sum, 2000); // 4 × 500
    }

    /// QuadX saturation: inputs that would drive below 0 clamp to 0.
    #[test]
    fn quad_x_clamp_floor() {
        let out = mixer_compute(FrameType::QuadX, 100, 200, 0, 0);
        // M1 = 100 - 200 = -100 → 0
        assert_eq!(out.motors[0], 0);
        // M2 = 100 + 200 = 300
        assert_eq!(out.motors[1], 300);
    }

    #[test]
    fn quad_x_clamp_ceil() {
        let out = mixer_compute(FrameType::QuadX, 900, 200, 0, 0);
        // M2 = 900 + 200 = 1100 → 1000
        assert_eq!(out.motors[1], THROTTLE_MAX);
        // M1 = 900 - 200 = 700
        assert_eq!(out.motors[0], 700);
    }

    /// Tri: only 3 motors active.
    #[test]
    fn tri_motor_count() {
        let out = mixer_compute(FrameType::Tri, 500, 0, 0, 0);
        assert_eq!(out.count, 3);
    }

    /// Tri hover: motors 0 and 1 carry pitch; motor 2 carries -pitch.
    #[test]
    fn tri_hover_front_rear() {
        let out = mixer_compute(FrameType::Tri, 500, 0, 0, 0);
        // With roll=pitch=yaw=0: M0 = T+P=500, M1 = T+P=500, M2 = T-P=500
        assert_eq!(out.motors[0], 500);
        assert_eq!(out.motors[1], 500);
        assert_eq!(out.motors[2], 500);
    }

    /// Y6: 6 motors, co-axial pairs sum to same throttle.
    #[test]
    fn y6_hover_coaxial_pairs() {
        let out = mixer_compute(FrameType::Y6, 500, 0, 0, 0);
        assert_eq!(out.count, 6);
        // At hover (no pitch/roll), front top = front bottom (yaw=0 too)
        assert_eq!(out.motors[0], out.motors[1]);
    }

    /// Y6: yaw authority splits top vs bottom within each arm.
    #[test]
    fn y6_yaw_top_bottom_split() {
        let out = mixer_compute(FrameType::Y6, 500, 0, 0, 50);
        // Front top (M0) = t + pitch - yaw; front bottom (M1) = t + pitch + yaw
        // With t=250, pitch=0, yaw=50: M0=200, M1=300
        assert!(out.motors[0] < out.motors[1],
            "Y6 yaw: top({}) should be < bottom({})", out.motors[0], out.motors[1]);
    }

    /// HexX: 6 motors; all equal at hover.
    #[test]
    fn hexx_hover_equal() {
        let out = mixer_compute(FrameType::HexX, 500, 0, 0, 0);
        assert_eq!(out.count, 6);
        assert!(out.motors[..6].iter().all(|&m| m == 500),
            "HexX hover motors: {:?}", &out.motors[..6]);
    }

    /// HexX: roll moves left motors up, right motors down.
    #[test]
    fn hexx_roll_direction() {
        let out = mixer_compute(FrameType::HexX, 500, 200, 0, 0);
        // ARMS[1] = (1000, 0, +1): right arm, max positive roll → highest
        // ARMS[4] = (-1000, 0, -1): left arm, max negative roll → lowest
        assert!(out.motors[1] > 500, "HexX roll: M1 should be > 500");
        assert!(out.motors[4] < 500, "HexX roll: M4 should be < 500");
    }

    /// Coax: 8 motors total.
    #[test]
    fn coax_motor_count() {
        let out = mixer_compute(FrameType::Coax, 500, 0, 0, 0);
        assert_eq!(out.count, 8);
    }

    /// Coax hover: all motors equal at T/2.
    #[test]
    fn coax_hover_equal() {
        let out = mixer_compute(FrameType::Coax, 500, 0, 0, 0);
        assert!(out.motors.iter().all(|&m| m == 250),
            "Coax hover motors: {:?}", &out.motors);
    }

    /// Coax: yaw splits top vs bottom per arm.
    #[test]
    fn coax_yaw_direction() {
        let out = mixer_compute(FrameType::Coax, 500, 0, 0, 50);
        // M0 (top arm0) = t - yaw; M1 (bottom arm0) = t + yaw
        assert!(out.motors[0] < out.motors[1],
            "Coax yaw: top({}) < bottom({})", out.motors[0], out.motors[1]);
    }

    /// QuadPlus hover check.
    #[test]
    fn quad_plus_hover() {
        let out = mixer_compute(FrameType::QuadPlus, 500, 0, 0, 0);
        assert_eq!(out.count, 4);
        assert!(out.motors[..4].iter().all(|&m| m == 500));
    }

    /// Octo hover: all 8 motors equal.
    #[test]
    fn octo_hover() {
        let out = mixer_compute(FrameType::Octo, 500, 0, 0, 0);
        assert_eq!(out.count, 8);
        assert!(out.motors.iter().all(|&m| m == 500),
            "Octo hover motors: {:?}", &out.motors);
    }

    /// Full throttle: no motor should exceed THROTTLE_MAX.
    #[test]
    fn all_frames_no_overflow() {
        let frames = [
            FrameType::QuadX, FrameType::QuadPlus, FrameType::Hex,
            FrameType::Octo,  FrameType::Tri,      FrameType::Y6,
            FrameType::HexX,  FrameType::Coax,
        ];
        for frame in frames {
            let out = mixer_compute(frame, 1000, 200, 200, 200);
            for m in out.motors.iter() {
                assert!(*m <= THROTTLE_MAX,
                    "{:?}: motor {} > THROTTLE_MAX", frame, m);
            }
        }
    }
}
