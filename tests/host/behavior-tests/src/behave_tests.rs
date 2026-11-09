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
