// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! L1 only brakes or limits, and a lost companion session arms each profile's
//! own containment (`containment.rs`, `link_watch.rs`, the engine's
//! `behave.rs`, the flight failsafe's handoff).

use crate::behave::*;
use crate::containment::*;
use crate::failsafe::{handoff_action, FailsafeAction, HANDOFF_HOLD_US};
use crate::link_watch::*;

const PROFILES: [Profile; 4] = [Profile::Wheeled, Profile::Ackermann, Profile::Drone, Profile::Humanoid];

fn at(now_ms: u64) -> Inputs {
    Inputs { now_ms, ..Inputs::default() }
}

fn range_cases() -> Vec<Option<u16>> {
    vec![None, Some(0), Some(50), Some(OBSTACLE_STOP_MM), Some(300), Some(OBSTACLE_TURN_MM), Some(650), Some(2_000)]
}

/// **L1 never starts motion from standstill**: with no companion command and
/// no session, whatever the rangefinders and the verdict say, nothing is
/// published, under every profile and every layer set. A robot booted 30 cm
/// from a wall stays where it is.
///
/// **Canary.** Let L1's turn stand as a command of its own: the clear-road case
/// is fine, the wall publishes (60, 20), red.
#[test]
fn l1_never_starts_motion_from_standstill() {
    for _profile in PROFILES {
        for layers in [Layers::ALL, Layers::AVOID_ONLY] {
            for front in range_cases() {
                for right in range_cases() {
                    for ml in [Ml::Off, Ml::Go, Ml::Turn, Ml::Stop, Ml::Missing] {
                        let i = Inputs { front_mm: front, right_mm: right, ml, ..at(5_000) };
                        assert_eq!(arbitrate(layers, &i), None, "front {front:?} right {right:?} ml {ml:?}");
                    }
                }
            }
        }
    }
}

/// **L1 never raises a wheel above what was asked, and never reverses it**: a
/// companion command of (20, 20) comes out of L1 no faster per wheel and never
/// negative, over every distance, verdict and prediction.
///
/// **Canary.** Publish L1's limit instead of bounding the command by it: the
/// turn at 60 replaces the 20.
#[test]
fn l1_never_exceeds_what_the_companion_asked() {
    let remote = Some(Remote { left: 20, right: 20, at_ms: 1_000 });
    let mut limited = false;
    for _profile in PROFILES {
        for front in range_cases() {
            for right in range_cases() {
                for ml in [Ml::Off, Ml::Go, Ml::Turn, Ml::Stop, Ml::Missing] {
                    for predict in [None, Some(Predict { left: 0, right: 0, confidence: 255, at_ms: 1_050 })] {
                        let i = Inputs { front_mm: front, right_mm: right, ml, predict, remote, session_up: true, ..at(1_100) };
                        let ((l, r), _) = arbitrate(Layers::ALL, &i).expect("the companion asked");
                        assert!((0..=20).contains(&l) && (0..=20).contains(&r), "({l}, {r}) for {front:?} {right:?} {ml:?}");
                        limited |= (l, r) != (20, 20);
                    }
                }
            }
        }
    }
    assert!(limited, "the sweep includes cases where L1 brakes");
}

/// **A reversal is never what L1 turns a command into**: a companion spin
/// (60, -60) under the turn bound is a stop, not motion forward.
#[test]
fn l1_never_turns_a_spin_into_forward_motion() {
    let remote = Some(Remote { left: -50, right: 50, at_ms: 1_000 });
    let i = Inputs { front_mm: Some(300), remote, session_up: true, ..at(1_100) };
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((0, 0), Winner::Avoid)));
}

/// **Each profile's loss does its own thing.** Wheeled and Ackermann stop;
/// the drone does not stop its drive and hands over to the flight failsafe;
/// the humanoid holds posture, which stops its joints.
///
/// **Canary.** `drone-cut-canary`: the drone stops its drive. `ground-drives-canary`:
/// the wheeled robot does not.
#[test]
fn each_profile_arms_its_own_containment() {
    for p in [Profile::Wheeled, Profile::Ackermann] {
        assert_eq!(p.effects(), Effects { stop_drive: true, posture_hold: false, flight_handoff: false }, "{p:?}");
    }
    let drone = Profile::Drone.effects();
    assert!(!drone.stop_drive, "motors are never cut in the air by a lost link");
    assert!(drone.flight_handoff && !drone.posture_hold);
    assert_eq!(Profile::Humanoid.effects(), Effects { stop_drive: true, posture_hold: true, flight_handoff: false });
    assert_eq!(Profile::from_id(1), Some(Profile::Drone));
    assert_eq!(Profile::from_id(4), None);
}

/// **A drone's lost link holds, then lands, and the motors keep running**:
/// the handoff the kernel requests is a hold for the hold time, then a landing;
/// no step of it disarms.
///
/// **Canary.** `handoff-disarm-canary`: the end of the hold disarms.
#[test]
fn a_drones_lost_link_holds_then_lands_and_never_disarms() {
    assert!(Profile::Drone.effects().flight_handoff);
    for held in [0, 1, HANDOFF_HOLD_US - 1] {
        assert!(handoff_action(true, held) == FailsafeAction::PosHold);
    }
    for held in [HANDOFF_HOLD_US, HANDOFF_HOLD_US * 10] {
        assert!(handoff_action(true, held) == FailsafeAction::Land);
    }
    assert!(handoff_action(false, HANDOFF_HOLD_US) == FailsafeAction::None, "the pilot's flight is the pilot's");
}

/// **The kernel arms on a reported loss, once, and not for a link that was
/// never up**: a robot driven by its operator with no companion is not
/// contained.
#[test]
fn a_reported_loss_arms_once_and_only_for_a_session_that_was_up() {
    let w = LinkWatch::new();
    assert_eq!(w.report(&[LINK_LOST], 10), None, "never up: nothing to lose");
    assert_eq!(w.report(&[LINK_UP], 20), None);
    assert_eq!(w.report(&[LINK_LOST], 30), Some(Loss::Session));
    assert_eq!(w.report(&[LINK_LOST], 40), None, "once");
    w.report(&[LINK_UP], 50);
    assert_eq!(w.report(&[LINK_VERDICT_LOST], 60), Some(Loss::Verdict));
    assert_eq!(w.tick(1_000_000, 10), None, "nothing is watched after a loss");
}

/// **An engine that stops reporting is a lost session**: a session reported up
/// and then silent for longer than the bound arms; beats keep it off; a report
/// the kernel cannot read arms.
///
/// **Canary.** `link-silence-canary`: the silence is never noticed.
#[test]
fn a_silent_engine_arms_containment() {
    let w = LinkWatch::new();
    assert_eq!(w.tick(1_000_000, 10), None, "never up");
    w.report(&[LINK_UP], 100);
    assert_eq!(w.tick(110, 10), None);
    assert_eq!(w.tick(111, 10), Some(Loss::Silent));
    assert_eq!(w.tick(5_000, 10), None, "once");
    w.report(&[LINK_UP], 200);
    w.report(&[LINK_UP], 205);
    assert_eq!(w.tick(214, 10), None, "a beat keeps it off");
    assert_eq!(w.report(&[], 220), Some(Loss::Malformed));
    assert_eq!(w.report(&[9], 221), Some(Loss::Malformed));
}

/// **The flight handoff keeps the time of its first request and lapses when
/// the link is back.**
#[test]
fn the_flight_handoff_keeps_its_first_time() {
    flight_handoff_clear();
    assert_eq!(flight_handoff_since(), None);
    flight_handoff_request(100);
    flight_handoff_request(500);
    assert_eq!(flight_handoff_since(), Some(100));
    flight_handoff_clear();
    assert_eq!(flight_handoff_since(), None);
}

/// **A verdict that had been coming and goes missing for long enough is a
/// loss, once**; one that comes back resets the count; a model that never
/// answered is held at a stop by L1 but is no loss.
#[test]
fn a_verdict_missing_for_long_enough_is_lost_once() {
    let mut never = VerdictWatch::new();
    assert!(!never.step(Ml::Missing, 0));
    assert!(!never.step(Ml::Missing, VERDICT_LOSS_MS * 5), "never had one");
    let mut v = VerdictWatch::new();
    assert!(!v.step(Ml::Go, 0));
    assert!(!v.step(Ml::Missing, 10));
    assert!(!v.step(Ml::Missing, 10 + VERDICT_LOSS_MS - 1));
    assert!(v.step(Ml::Missing, 10 + VERDICT_LOSS_MS));
    assert!(!v.step(Ml::Missing, 10 + VERDICT_LOSS_MS * 3), "once per stretch");
    assert!(!v.step(Ml::Go, VERDICT_LOSS_MS * 4));
    assert!(!v.step(Ml::Missing, VERDICT_LOSS_MS * 4 + 1));
    assert!(v.step(Ml::Missing, VERDICT_LOSS_MS * 5 + 1));
}
