// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The ring-3 behaviour engine's arbiter (`userspace/services/brain_client/src/behave.rs`).

use crate::behave::*;

fn at(now_ms: u64) -> Inputs {
    Inputs { now_ms, ..Inputs::default() }
}

/// **An obstacle outranks the brain**: a close one stops, a nearer-than-turn
/// one in front turns away, on either rangefinder for the stop.
///
/// **Canary.** Check the brain before the obstacle: the first case drives.
#[test]
fn an_obstacle_outranks_the_brain() {
    let remote = Some(Remote { left: 80, right: 80, at_ms: 1_000 });
    let mut i = Inputs { front_mm: Some(100), remote, session_up: true, ..at(1_100) };
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((0, 0), Winner::Avoid)));
    i.front_mm = Some(300);
    assert_eq!(arbitrate(Layers::ALL, &i), Some((TURN, Winner::Avoid)));
    i.front_mm = Some(900);
    i.right_mm = Some(OBSTACLE_STOP_MM - 1);
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((0, 0), Winner::Avoid)));
    i.right_mm = Some(OBSTACLE_STOP_MM);
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((80, 80), Winner::Remote)));
}

/// **The brain drives while its command is fresh, clamped**; a stale one
/// falls to exploring, and exploring needs the session.
///
/// **Canary.** Compare the age with `<` against `at_ms` alone: the stale
/// command still drives.
#[test]
fn the_brain_drives_while_fresh_then_explore_needs_the_session() {
    let remote = Some(Remote { left: 150, right: -150, at_ms: 1_000 });
    let mut i = Inputs { remote, session_up: true, ..at(1_000 + REMOTE_MAX_AGE_MS) };
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((100, -100), Winner::Remote)));
    i.now_ms += 1;
    assert_eq!(arbitrate(Layers::ALL, &i), Some((EXPLORE, Winner::Explore)));
    i.session_up = false;
    assert_eq!(arbitrate(Layers::ALL, &i), None, "no layer drives: nothing is published");
}

/// **A disabled layer never wins.**
#[test]
fn a_disabled_layer_never_wins() {
    let remote = Some(Remote { left: 50, right: 50, at_ms: 0 });
    let i = Inputs { front_mm: Some(50), remote, session_up: true, ..at(10) };
    let no_avoid = Layers { avoid: false, ..Layers::ALL };
    assert_eq!(arbitrate(no_avoid, &i), Some(((50, 50), Winner::Remote)));
    let only_explore = Layers { avoid: false, remote: false, explore: true };
    assert_eq!(arbitrate(only_explore, &i), Some((EXPLORE, Winner::Explore)));
    let none = Layers { avoid: false, remote: false, explore: false };
    assert_eq!(arbitrate(none, &i), None);
}

/// **An e-stop replaces the brain's standing command**: after it, the remote
/// layer asks a stop, never the command that preceded the e-stop, so clearing
/// the latch does not resume it.
///
/// **Canary.** Make `Remote::stop` keep the previous speeds: the drive comes
/// back.
#[test]
fn an_estop_replaces_the_standing_command() {
    let driving = Remote { left: 80, right: 80, at_ms: 1_000 };
    let i = Inputs { remote: Some(driving), ..at(1_100) };
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((80, 80), Winner::Remote)));
    let i = Inputs { remote: Some(Remote::stop(1_200)), ..at(1_300) };
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((0, 0), Winner::Remote)));
}

/// **An engine that cannot read its switches never drives on its own**: with
/// only the obstacle layer, a clear road and a fresh brain command drive
/// nothing, and an obstacle still stops.
///
/// **Canary.** Let `AVOID_ONLY` keep the remote layer: the brain drives.
#[test]
fn the_fallback_layers_only_stop_or_turn_away() {
    let remote = Some(Remote { left: 50, right: 50, at_ms: 0 });
    let clear = Inputs { remote, session_up: true, ..at(10) };
    assert_eq!(arbitrate(Layers::AVOID_ONLY, &clear), None);
    let blocked = Inputs { front_mm: Some(100), ..clear };
    assert_eq!(arbitrate(Layers::AVOID_ONLY, &blocked), Some(((0, 0), Winner::Avoid)));
}

fn predicted(left: i32, right: i32, confidence: u8, at_ms: u64) -> Option<Predict> {
    Some(Predict { left, right, confidence, at_ms })
}

/// **A prediction changes L1's choice**: a predicted stop widens the
/// turn-away distance by [`PREDICT_OBSTACLE_MARGIN_MM`] and a predicted turn
/// by [`PREDICT_TURN_MARGIN_MM`], so the robot turns away from an obstacle
/// the rangefinders do not yet call close, and a prediction the brain is not
/// sure of, or that went stale, changes nothing.
///
/// **Canary.** Ignore the prediction's confidence: the unsure one turns.
#[test]
fn a_prediction_biases_l1() {
    let remote = Some(Remote { left: 80, right: 80, at_ms: 1_000 });
    let base = Inputs { front_mm: Some(OBSTACLE_TURN_MM + 100), remote, session_up: true, ..at(1_100) };
    assert_eq!(arbitrate(Layers::ALL, &base), Some(((80, 80), Winner::Remote)));

    let stop = Inputs { predict: predicted(0, 0, 200, 1_050), ..base };
    assert_eq!(arbitrate(Layers::ALL, &stop), Some((TURN, Winner::Avoid)), "a predicted stop turns the robot away early");
    let turn = Inputs { predict: predicted(70, 20, 200, 1_050), front_mm: Some(OBSTACLE_TURN_MM + PREDICT_TURN_MARGIN_MM), ..base };
    assert_eq!(arbitrate(Layers::ALL, &turn), Some(((80, 80), Winner::Remote)), "a predicted turn reaches less far than a predicted stop");
    let turn = Inputs { front_mm: Some(OBSTACLE_TURN_MM + PREDICT_TURN_MARGIN_MM - 1), ..turn };
    assert_eq!(arbitrate(Layers::ALL, &turn), Some((TURN, Winner::Avoid)));

    let unsure = Inputs { predict: predicted(0, 0, PREDICT_MIN_CONFIDENCE - 1, 1_050), ..base };
    assert_eq!(arbitrate(Layers::ALL, &unsure), Some(((80, 80), Winner::Remote)));
    let stale = Inputs { predict: predicted(0, 0, 255, 1_100 - PREDICT_MAX_AGE_MS - 1), ..base };
    assert_eq!(arbitrate(Layers::ALL, &stale), Some(((80, 80), Winner::Remote)));
    let off = Layers { avoid: false, ..Layers::ALL };
    assert_eq!(arbitrate(off, &stop), Some(((80, 80), Winner::Remote)), "with L1 off there is nothing to bias");
}

/// **A prediction never raises speed**: over every prediction, every distance
/// and every driver, each wheel of the command is in the direction of, and no
/// faster than, what the layers chose without it; a cycle that would not
/// drive still does not, and a stop stays a stop. (The kernel's cap and the
/// envelope sit under whatever this publishes either way.)
///
/// **Canary.** Return the hinted wheel as it is from `under`: the turn at 60
/// replaces a brain command of 30, red.
#[test]
fn a_prediction_never_raises_speed() {
    let drivers = [
        (None, false),
        (Some(Remote { left: 30, right: 30, at_ms: 1_000 }), true),
        (Some(Remote { left: 100, right: -100, at_ms: 1_000 }), true),
        (Some(Remote { left: -40, right: -40, at_ms: 1_000 }), true),
        (Some(Remote { left: 0, right: 0, at_ms: 1_000 }), true),
    ];
    let mut changed = false;
    for (remote, session_up) in drivers {
        for front in [None, Some(50), Some(100), Some(300), Some(500), Some(650), Some(900)] {
            for ml in [Ml::Off, Ml::Go, Ml::Turn, Ml::Stop, Ml::Missing] {
                let plain = Inputs { front_mm: front, remote, session_up, ml, ..at(1_100) };
                let want = arbitrate(Layers::ALL, &plain);
                for l in (-200..=200).step_by(20) {
                    for r in (-200..=200).step_by(20) {
                        for conf in [0u8, 127, 128, 255] {
                            let i = Inputs { predict: predicted(l, r, conf, 1_100), ..plain };
                            let got = arbitrate(Layers::ALL, &i);
                            let Some(((wl, wr), _)) = want else {
                                assert_eq!(got, None, "a prediction made a silent cycle drive");
                                continue;
                            };
                            let ((gl, gr), _) = got.expect("a driving cycle keeps driving");
                            for (g, w) in [(gl, wl), (gr, wr)] {
                                assert!(g == 0 || (g > 0) == (w > 0), "{g} turns the wheel round from {w}");
                                assert!(g.abs() <= w.abs(), "{g} is faster than {w}: hint ({l},{r}) {conf}, front {front:?}");
                            }
                            changed |= (gl, gr) != (wl, wr);
                        }
                    }
                }
            }
        }
    }
    assert!(changed, "the sweep never exercised a changing prediction");
}

/// The payload: an actuator command and a confidence byte; an emergency, a
/// short channel list and a wrong length are not predictions.
#[test]
fn a_prediction_decodes_from_its_payload() {
    let mut p = vec![ACTUATOR_DIFF_DRIVE, 2, 0];
    p.extend_from_slice(&(-20i16).to_le_bytes());
    p.extend_from_slice(&45i16.to_le_bytes());
    p.push(200);
    assert_eq!(Predict::decode(&p, 7), predicted(-20, 45, 200, 7));
    let mut emergency = p.clone();
    emergency[2] = 1;
    assert_eq!(Predict::decode(&emergency, 7), None);
    assert_eq!(Predict::decode(&p[..p.len() - 1], 7), None);
    assert_eq!(Predict::decode(&[ACTUATOR_DIFF_DRIVE, 1, 0, 5, 0, 200], 7), None);
    let mut quad = p.clone();
    quad[0] = 1;
    assert_eq!(Predict::decode(&quad, 7), None, "a command for another kind of machine");
    assert_eq!(Predict::decode(&[], 7), None);
}

/// **The model's turn never starts motion or raises a wheel**: with no layer
/// driving, a `Turn` verdict publishes nothing; with the brain at (20,20) it
/// stays at (20,20) or below, wheel by wheel; and over a sweep it never exceeds
/// what the layers chose without it.
///
/// **Canary.** Return `TURN` for `Ml::Turn` before the layers are asked (the
/// old `avoid`): the first assertion drives, red.
#[test]
fn a_model_turn_only_limits() {
    let silent = Inputs { front_mm: Some(3_000), right_mm: Some(3_000), ml: Ml::Turn, ..at(1_000) };
    assert_eq!(arbitrate(Layers::AVOID_ONLY, &silent), None, "no session and nothing else drives");
    assert_eq!(arbitrate(Layers::ALL, &silent), None);
    let brain = Some(Remote { left: 20, right: 20, at_ms: 1_000 });
    let slow = Inputs { remote: brain, session_up: true, ..silent };
    assert_eq!(arbitrate(Layers::ALL, &slow), Some(((20, 20), Winner::Remote)));
    let fast = Inputs { remote: Some(Remote { left: 80, right: 80, at_ms: 1_000 }), ..slow };
    assert_eq!(arbitrate(Layers::ALL, &fast), Some((TURN, Winner::Avoid)), "it limits a faster command");
    for remote in [None, brain, Some(Remote { left: -30, right: -30, at_ms: 1_000 }), Some(Remote { left: 100, right: -100, at_ms: 1_000 })] {
        for front in [None, Some(100), Some(300), Some(900)] {
            let off = Inputs { front_mm: front, remote, session_up: remote.is_some(), ml: Ml::Go, ..at(1_000) };
            let on = Inputs { ml: Ml::Turn, ..off };
            match (arbitrate(Layers::ALL, &off), arbitrate(Layers::ALL, &on)) {
                (None, got) => assert_eq!(got, None),
                (Some(((wl, wr), _)), Some(((gl, gr), _))) => {
                    for (g, w) in [(gl, wl), (gr, wr)] {
                        assert!(g == 0 || (g > 0) == (w > 0), "{g} turns {w} round");
                        assert!(g.abs() <= w.abs(), "{g} is faster than {w}");
                    }
                }
                (some, none) => panic!("{some:?} became {none:?}"),
            }
        }
    }
}

/// **A prediction never turns a spin into motion forward**: (100,-100) with a
/// predicted stop stops the command instead of (60,0).
///
/// **Canary.** Drop the reversal rule from `bounded`: (60,0) drives, red.
#[test]
fn a_prediction_never_turns_a_spin_into_forward_motion() {
    let spin = Some(Remote { left: 100, right: -100, at_ms: 1_000 });
    let i = Inputs { front_mm: Some(500), remote: spin, session_up: true, predict: predicted(0, 0, 255, 1_000), ..at(1_000) };
    assert_eq!(arbitrate(Layers::ALL, &i), Some(((0, 0), Winner::Avoid)));
}
